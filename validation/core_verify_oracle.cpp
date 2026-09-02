// validation/core_verify_oracle.cpp -- Bitcoin Core as the reference AND the
// signer for tests/fuzz_verify_diff.c (2026-09-02). One command per stdin line:
//   key <i>                                   -> <pub33> <xonly32>
//   leafhash <script>                         -> <hash32>
//   branch <a32> <b32>                        -> <hash32>
//   tweak <i> <root32|->                      -> <xonly32> <parity>
//   signecdsa <i> <sigv 0|1> <hashtype> <amount> <tx> <nIn> <scriptcode>  -> <sig+ht>
//   signschnorr <i> <sigv 2|3> <hashtype> <tx> <nIn> <spent> <root32|-> <leaf32|-> <codesep> <annex|->  -> <sig>
//   verify <flags-hex> <tx> <nIn> <spent>     -> <ok> <err>
// <spent> = for every input: 8-byte LE amount, compact-size, scriptPubKey; all hex.
// Keys are deterministic: privkey_i = SHA256("bmc-fuzz-key-<i>").
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <key.h>
#include <pubkey.h>
#include <hash.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using B = std::vector<unsigned char>;
// libbitcoin_util's check.cpp wants this from the client-version unit; the oracle has no version
std::string FormatFullVersion(){ return "core_verify_oracle"; }
static B unhex(const std::string& h){ if (h == "-") return {}; return ParseHex(h); }
static std::string hex(const B& v){ return v.empty() ? "-" : HexStr(v); }
static uint256 u256(const std::string& h){ B b = ParseHex(h); if (b.size() != 32) throw std::runtime_error("need 32 bytes"); return uint256(b); }   /* BYTE order, not the display (reversed) order of the hex parser */
static std::string h256(const uint256& u){ return HexStr(u); }
static CKey keyof(int i){ std::string s = "bmc-fuzz-key-" + std::to_string(i); uint256 h = Hash(std::span<const unsigned char>((const unsigned char*)s.data(), s.size())); CKey k; k.Set(h.begin(), h.end(), true); return k; }
static CMutableTransaction txof(const std::string& h){ CMutableTransaction m; DataStream ss{ParseHex(h)}; ss >> TX_WITH_WITNESS(m); return m; }
static std::vector<CTxOut> spentof(const std::string& h){
    std::vector<CTxOut> v; B b = unhex(h); size_t p = 0;
    while (p + 9 <= b.size()){ uint64_t a = 0; for (int i = 0; i < 8; i++) a |= (uint64_t)b[p+i] << (8*i); p += 8;
        uint64_t n = b[p++]; if (n == 0xfd){ n = b[p] | (b[p+1] << 8); p += 2; } CScript spk(b.begin() + p, b.begin() + p + n); p += n; v.emplace_back((CAmount)a, spk); }
    return v;
}
int main(){
    ECC_Context ecc;
    std::string line;
    while (std::getline(std::cin, line)){
        std::istringstream in(line); std::string cmd; in >> cmd;
        try {
        if (cmd == "key"){ int i; in >> i; CKey k = keyof(i); CPubKey p = k.GetPubKey(); XOnlyPubKey x(p); std::cout << HexStr(p) << ' ' << HexStr(x) << '\n'; }
        else if (cmd == "leafhash"){ std::string s; in >> s; B b = unhex(s); std::cout << h256(ComputeTapleafHash(0xc0, b)) << '\n'; }
        else if (cmd == "branch"){ std::string a, b; in >> a >> b; std::cout << h256(ComputeTapbranchHash(u256(a), u256(b))) << '\n'; }
        else if (cmd == "tweak"){ int i; std::string r; in >> i >> r; XOnlyPubKey x(keyof(i).GetPubKey()); uint256 root; auto t = x.CreateTapTweak(r == "-" ? nullptr : &(root = u256(r))); std::cout << HexStr(t->first) << ' ' << (t->second ? 1 : 0) << '\n'; }
        else if (cmd == "signecdsa"){ int i, sv, ht; uint64_t amt; std::string tx, sc; unsigned nIn; in >> i >> sv >> ht >> amt >> tx >> nIn >> sc;
            CMutableTransaction m = txof(tx); B scb = unhex(sc); CScript scode(scb.begin(), scb.end());
            uint256 h = SignatureHash(scode, m, nIn, ht, (CAmount)amt, sv == 1 ? SigVersion::WITNESS_V0 : SigVersion::BASE, nullptr);
            B sig; keyof(i).Sign(h, sig); sig.push_back((unsigned char)ht); std::cout << hex(sig) << '\n'; }
        else if (cmd == "signschnorr"){ int i, sv, ht; std::string tx, spent, root, leaf, annex; unsigned nIn; uint32_t codesep; in >> i >> sv >> ht >> tx >> nIn >> spent >> root >> leaf >> codesep >> annex;
            CMutableTransaction m = txof(tx); PrecomputedTransactionData td; td.Init(m, spentof(spent), true);
            ScriptExecutionData ex; ex.m_annex_init = true; ex.m_annex_present = annex != "-";
            if (ex.m_annex_present){ B ab = unhex(annex); ex.m_annex_hash = (HashWriter{} << ab).GetSHA256(); }
            if (sv == 3){ ex.m_tapleaf_hash_init = true; ex.m_tapleaf_hash = u256(leaf); ex.m_codeseparator_pos_init = true; ex.m_codeseparator_pos = codesep; }
            uint256 h; if (!SignatureHashSchnorr(h, ex, m, nIn, (uint8_t)ht, sv == 3 ? SigVersion::TAPSCRIPT : SigVersion::TAPROOT, td, MissingDataBehavior::FAIL)){ std::cout << "E sighash\n"; continue; }
            B sig(64); uint256 aux; uint256 rootu; const uint256* rp = nullptr;
            if (sv == 2){ rootu = root == "-" ? uint256() : u256(root); rp = &rootu; }
            if (!keyof(i).SignSchnorr(h, sig, rp, aux)){ std::cout << "E sign\n"; continue; }
            if (ht != 0) sig.push_back((unsigned char)ht); std::cout << hex(sig) << '\n'; }
        else if (cmd == "verify"){ std::string fl, tx, spent; unsigned nIn; in >> fl >> tx >> nIn >> spent;
            CMutableTransaction m = txof(tx); std::vector<CTxOut> sp = spentof(spent); if (nIn >= m.vin.size() || nIn >= sp.size()){ std::cout << "E nIn\n"; continue; }
            CAmount amt = sp[nIn].nValue; CScript spk = sp[nIn].scriptPubKey; PrecomputedTransactionData td; td.Init(m, std::vector<CTxOut>(sp), true);
            MutableTransactionSignatureChecker checker(&m, nIn, amt, td, MissingDataBehavior::FAIL);
            ScriptError err = SCRIPT_ERR_OK; bool ok = VerifyScript(m.vin[nIn].scriptSig, spk, &m.vin[nIn].scriptWitness, script_verify_flags::from_int(std::stoull(fl, nullptr, 16)), checker, &err);
            std::cout << (ok ? 1 : 0) << ' ' << (int)err << '\n'; }
        else std::cout << "E cmd\n";
        } catch (const std::exception& e){ std::cout << "E " << e.what() << '\n'; }
        std::cout << std::flush;
    }
}
