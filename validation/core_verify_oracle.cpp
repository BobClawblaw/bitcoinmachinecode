// validation/core_verify_oracle.cpp -- Bitcoin Core as the reference AND the
// signer for tests/fuzz_verify_diff.c (2026-09-02), AND the ground-truth
// VerifyScript oracle for validation/spend_corpus_diff.py and
// validation/synth_corpus_diff.py (original protocol, restored 2026-09-03 --
// see the note below the command list). One command per stdin line:
//   key <i>                                   -> <pub33> <xonly32>
//   leafhash <script>                         -> <hash32>
//   branch <a32> <b32>                        -> <hash32>
//   tweak <i> <root32|->                      -> <xonly32> <parity>
//   signecdsa <i> <sigv 0|1> <hashtype> <amount> <tx> <nIn> <scriptcode>  -> <sig+ht>
//   signschnorr <i> <sigv 2|3> <hashtype> <tx> <nIn> <spent> <root32|-> <leaf32|-> <codesep> <annex|->  -> <sig>
//   verify <flags-hex> <tx> <nIn> <spent>     -> <ok> <err>
// <spent> = for every input: 8-byte LE amount, compact-size, scriptPubKey; all hex.
// Keys are deterministic: privkey_i = SHA256("bmc-fuzz-key-<i>").
//
//   VERIFY <flags_hex> <inputidx> <tx_hex> <scriptSig_hex> <scriptPubKey_hex>
//                                             -> OK <0|1> <errcode> <errstring>
//   TAPVERIFY <inputidx> <tx_hex_WITH_witness> <n_prev> <amount_i> <spk_i_hex>...
//                                             -> OK <0|1> <errcode> <errstring>
//   QUIT
//
// RESTORED 2026-09-03. This file predates fuzz_verify_diff.c: it originally
// spoke ONLY the uppercase VERIFY/TAPVERIFY/QUIT protocol above, and caught
// real consensus false-accepts under that name (see git log on this file --
// incident #18, incident #21, a BIP66 false accept above height 363,725, two
// BIP341 sighash false accepts). The 2026-09-02 commit that added the
// lowercase commands for fuzz_verify_diff.c REPLACED this file wholesale
// instead of extending it, silently deleting VERIFY/TAPVERIFY. Nothing
// caught it for over a day: validation/spend_corpus_diff.py and
// validation/synth_corpus_diff.py both kept running, every case timed out
// waiting for an answer this binary no longer gave (20s per case, reported
// as an "engine failure", not a crash), and the reports' headline verdict --
// "ZERO DIVERGENCES" -- was technically true and completely meaningless,
// because nothing had actually been compared. Restoring these two commands
// is the fix; a caller that wants to notice a repeat of this failure mode
// should treat a high engine-failure count as a reason to distrust "zero
// divergences", not as a footnote beneath it.
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
        else if (cmd == "VERIFY"){
            /* VERIFY <flags_hex> <inputidx> <tx_hex> <scriptSig_hex> <scriptPubKey_hex>
             * -- the LEGACY differential: spend_corpus_diff.py / synth_corpus_diff.py.
             * Amount 0 at the checker: a legacy scriptPubKey never reaches the
             * BIP143 sighash that would need the real one (SigVersion::BASE
             * ignores it), which is exactly why this verb takes no amount --
             * restoring it with a fabricated nonzero amount would be the
             * subtler mistake, not a fix. */
            unsigned flags = 0, idx = 0; std::string txs, scs, scp;
            in >> std::hex >> flags >> std::dec >> idx >> txs >> scs >> scp;
            CMutableTransaction m;
            try { m = txof(txs); }
            catch (const std::exception&){
                /* A mutated tx can be malformed past the point of deserializing
                 * at all -- a REAL rejection, not "the oracle broke", and the
                 * caller's own mutation-agreement check needs a graceful
                 * verdict here to compare against, not a skipped case. */
                std::cout << "OK 0 " << (int)SCRIPT_ERR_UNKNOWN_ERROR << " tx-decode-fail\n";
                continue;
            }
            B sig = unhex(scs), spkb = unhex(scp);
            CScript scriptSig(sig.begin(), sig.end()), scriptPubKey(spkb.begin(), spkb.end());
            ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
            MutableTransactionSignatureChecker checker(&m, idx, 0, MissingDataBehavior::FAIL);
            bool ok = VerifyScript(scriptSig, scriptPubKey, nullptr, script_verify_flags::from_int(flags), checker, &err);
            std::cout << "OK " << (ok ? 1 : 0) << ' ' << (int)err << ' ' << ScriptErrorString(err) << '\n';
        }
        else if (cmd == "TAPVERIFY"){
            /* TAPVERIFY <inputidx> <tx_hex_WITH_witness> <n_prev> <amount_i> <spk_i_hex>...
             * -- the WITNESS differential (v0 and v1 alike): the same two
             * harnesses, routed here instead of VERIFY because BIP143/BIP341
             * need every spent output's amount and scriptPubKey, which VERIFY
             * has no room to carry. Flags are the fixed modern set (P2SH,
             * WITNESS, TAPROOT, DERSIG, NULLDUMMY, CLTV, CSV) rather than a
             * caller-supplied mask, matching how the two harnesses already
             * treat witness spends as post-activation. */
            unsigned idx = 0, nprev = 0; std::string txs;
            in >> idx >> txs >> nprev;
            CMutableTransaction m;
            try { m = txof(txs); }
            catch (const std::exception&){
                std::cout << "OK 0 " << (int)SCRIPT_ERR_UNKNOWN_ERROR << " tx-decode-fail\n";
                continue;
            }
            std::vector<CTxOut> spent;
            bool bad = false;
            for (unsigned i = 0; i < nprev; i++){
                long long amt = 0; std::string spkh;
                if (!(in >> amt >> spkh)){ bad = true; break; }
                B s = unhex(spkh);
                spent.emplace_back((CAmount)amt, CScript(s.begin(), s.end()));
            }
            if (bad || spent.size() != nprev || idx >= spent.size() || idx >= m.vin.size()){
                std::cout << "OK 0 " << (int)SCRIPT_ERR_UNKNOWN_ERROR << " bad-prevouts\n";
                continue;
            }
            const script_verify_flags tapflags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
                SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY |
                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
            CTransaction tx(m);
            PrecomputedTransactionData td; td.Init(tx, std::vector<CTxOut>(spent), true);
            TransactionSignatureChecker checker(&tx, idx, spent[idx].nValue, td, MissingDataBehavior::FAIL);
            ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
            bool ok = VerifyScript(CScript(m.vin[idx].scriptSig), spent[idx].scriptPubKey,
                                   &m.vin[idx].scriptWitness, tapflags, checker, &err);
            std::cout << "OK " << (ok ? 1 : 0) << ' ' << (int)err << ' ' << ScriptErrorString(err) << '\n';
        }
        else if (cmd == "QUIT") break;
        else std::cout << "E cmd\n";
        } catch (const std::exception& e){ std::cout << "E " << e.what() << '\n'; }
        std::cout << std::flush;
    }
}
