// core_verify_oracle.cpp -- drive Bitcoin Core's VerifyScript directly.
//
// Reads (scriptSig, scriptPubKey, tx, inputIndex, flags) triples from stdin and
// returns Core's exact accept/reject verdict + ScriptError code for each. This
// is the ground-truth oracle that the ASM P2SH VerifyScript (bitcoin_verify.asm)
// is differentially compared against, byte-for-byte / error-for-error.
//
// Line protocol (space separated):
//   VERIFY <flags_hex> <inputidx> <tx_hex> <scriptSig_hex> <scriptPubKey_hex>
//   QUIT
// Output:
//   OK <0|1> <error_code> <error_string>
//
// flags_hex is the raw uint32 SCRIPT_VERIFY_* bitmask (e.g. 200207cf = Core's
// consensus flags for modern heights). The caller computes it from the block
// height the same way Core does (incl. BIP16 gating at height >= 173805).
//
// Build (from /storage/bitcoin-core-source/build):
//   g++ -std=c++20 -I../src ... core_verify_oracle.cpp
//   libs: libbitcoin_consensus.a libbitcoin_common.a libbitcoin_crypto.a
//         libbitcoin_util.a libbitcoin_clientversion.a secp256k1/lib/libsecp256k1.a
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <optional>

#include <primitives/transaction.h>
#include <core_io.h>
#include <hash.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/verify_flags.h>
#include <uint256.h>
#include <util/strencodings.h>

static std::vector<unsigned char> hex2bytes(const char* h){
    std::vector<unsigned char> v;
    size_t n=strlen(h);
    for(size_t i=0;i+1<n;i+=2){
        unsigned int x; if(sscanf(h+i,"%2x",&x)!=1) break;
        v.push_back((unsigned char)x);
    }
    return v;
}

int main(){
    std::string line;
    while(std::getline(std::cin,line)){
        if(line.empty()) continue;
        std::istringstream iss(line);
        std::string cmd; iss>>cmd;
        if(cmd=="QUIT") break;
        if(cmd=="SIGENC"){
            /* SIGENC <flags_hex> <sig_hex>
             *   -> Core's CheckSignatureEncoding (script/interpreter.cpp) verdict
             *      for one raw signature-with-hashtype push, under the given
             *      script_verify_flags. With flags == SCRIPT_VERIFY_DERSIG alone
             *      this is exactly IsValidSignatureEncoding, which is `static` in
             *      interpreter.cpp and so cannot be called directly; with flags 0
             *      it is the pre-BIP66 "anything goes" answer. Added 2026-08-22
             *      for the DERSIG incident: the reference list of which malformed
             *      DER encodings Core accepts/rejects has to come from Core
             *      itself, never from a reading of Core. */
            unsigned flags=0; std::string sh;
            iss>>std::hex>>flags>>std::dec>>sh;
            if (sh=="-") sh="";
            std::vector<unsigned char> sig = hex2bytes(sh.c_str());
            ScriptError serror = SCRIPT_ERR_OK;
            bool ok = CheckSignatureEncoding(sig, script_verify_flags::from_int(flags), &serror);
            printf("OK %d %d %s\n", ok?1:0, (int)serror, ScriptErrorString(serror).c_str());
            fflush(stdout);
        } else if(cmd=="VERIFY"){
            unsigned flags=0, idx=0;
            std::string txs, scs, scp;
            iss>>std::hex>>flags>>std::dec>>idx>>txs>>scs>>scp;
            if (scs=="-") scs="";
            if (scp=="-") scp="";
            // parse tx
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, txs, false)) {
                printf("OK 0 %d %s\n", (int)SCRIPT_ERR_UNKNOWN_ERROR, "tx-decode-fail");
                fflush(stdout);
                continue;
            }
            std::vector<unsigned char> sig = hex2bytes(scs.c_str());
            std::vector<unsigned char> spk = hex2bytes(scp.c_str());
            CScript scriptSig(sig.begin(), sig.end());
            CScript scriptPubKey(spk.begin(), spk.end());
            ScriptError serror = SCRIPT_ERR_UNKNOWN_ERROR;
            MutableTransactionSignatureChecker checker(&mtx, idx, 0, MissingDataBehavior::FAIL);
            bool ok = VerifyScript(scriptSig, scriptPubKey, nullptr, script_verify_flags::from_int(flags),
                                   checker, &serror);
            printf("OK %d %d %s\n", ok?1:0, (int)serror,
                   ScriptErrorString(serror).c_str());
            fflush(stdout);
        } else if(cmd=="TAPVERIFY"){
            /* TAPVERIFY <inputidx> <tx_hex_WITH_witness> <n_prev> <amount_i> <spk_i_hex> ...
             *   -> Core's verdict for a segwit/taproot input, using the real
             *      consensus flag set at a taproot-active height
             *      (GetBlockScriptFlags: P2SH|WITNESS|TAPROOT plus the
             *      always-on DERSIG/NULLDUMMY/CLTV/CSV) and a
             *      PrecomputedTransactionData built from every spent output --
             *      which BIP341's aggregate sighash requires and the plain
             *      VERIFY command above cannot supply. Added 2026-08-22 to
             *      differentially check the BIP342 initial-stack limit vectors
             *      (validation/gen_tapscript_stack_vectors.py) against Core
             *      instead of against a reading of Core. */
            unsigned idx=0, nprev=0; std::string txs;
            iss>>idx>>txs>>nprev;
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, txs)) {
                printf("OK 0 %d %s\n", (int)SCRIPT_ERR_UNKNOWN_ERROR, "tx-decode-fail");
                fflush(stdout); continue;
            }
            std::vector<CTxOut> spent;
            bool bad=false;
            for (unsigned i=0;i<nprev;i++){
                long long amt=0; std::string spkh;
                if(!(iss>>amt>>spkh)){ bad=true; break; }
                std::vector<unsigned char> s = hex2bytes(spkh.c_str());
                spent.emplace_back(CAmount(amt), CScript(s.begin(), s.end()));
            }
            if (bad || spent.size()!=nprev || idx>=spent.size() || idx>=mtx.vin.size()){
                printf("OK 0 %d %s\n", (int)SCRIPT_ERR_UNKNOWN_ERROR, "bad-prevouts");
                fflush(stdout); continue;
            }
            const script_verify_flags tapflags =
                SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
                SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY |
                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
            CTransaction tx(mtx);
            PrecomputedTransactionData txdata;
            txdata.Init(tx, std::vector<CTxOut>(spent));
            TransactionSignatureChecker checker(&tx, idx, spent[idx].nValue, txdata,
                                                MissingDataBehavior::FAIL);
            ScriptError serror = SCRIPT_ERR_UNKNOWN_ERROR;
            bool ok = VerifyScript(CScript(mtx.vin[idx].scriptSig), spent[idx].scriptPubKey,
                                   &mtx.vin[idx].scriptWitness, tapflags, checker, &serror);
            printf("OK %d %d %s\n", ok?1:0, (int)serror, ScriptErrorString(serror).c_str());
            fflush(stdout);
        } else if(cmd=="SIGHASH"){
            /* SIGHASH <inputidx> <tx_hex> <scriptCode_hex>  -> Core's legacy
               SignatureHash(SIGHASH_ALL). */
            unsigned idx=0; std::string txs, sc;
            iss>>idx>>txs>>sc;
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, txs, false)){ printf("OK 0\n"); fflush(stdout); continue; }
            std::vector<unsigned char> scb = hex2bytes(sc.c_str());
            CScript scriptCode(scb.begin(), scb.end());
            uint256 h = SignatureHash(scriptCode, mtx, idx, SIGHASH_ALL, 0, SigVersion::BASE);
            std::string o = HexStr(h);
            printf("OK %s\n", o.c_str());
            fflush(stdout);
        } else if(cmd=="BIP143"){
            /* BIP143 <inputidx> <nHashType_dec> <amount_sats> <tx_hex> <scriptCode_hex>
             *   -> Core's SignatureHash(..., SigVersion::WITNESS_V0), i.e. the
             *      real BIP143 sighash, hex-printed in the same byte order the
             *      SIGHASH command above uses. Added 2026-08-22 so the
             *      large-scriptPubKey CTxOut vectors (incident #20) get a
             *      Core-authoritative answer rather than being checked against
             *      our own implementation or a re-reading of the BIP.
             *      scriptCode is the BARE script (no compactsize prefix) --
             *      Core's serializer adds the prefix itself, exactly as
             *      segwit_v0_sighash() does. */
            unsigned idx=0; long long ht=0; long long amount=0;
            std::string txs, sc;
            iss>>idx>>ht>>amount>>txs>>sc;
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, txs)){ printf("ERR tx-decode-fail\n"); fflush(stdout); continue; }
            if (idx >= mtx.vin.size()){ printf("ERR bad-input-index\n"); fflush(stdout); continue; }
            if (sc=="-") sc="";
            std::vector<unsigned char> scb = hex2bytes(sc.c_str());
            CScript scriptCode(scb.begin(), scb.end());
            uint256 h = SignatureHash(scriptCode, mtx, idx, (int32_t)ht, CAmount(amount),
                                      SigVersion::WITNESS_V0);
            printf("OK %s\n", HexStr(h).c_str());
            fflush(stdout);
        } else if(cmd=="BIP341"){
            /* BIP341 <inputidx> <hash_type_dec> <sigversion:0=taproot,1=tapscript>
             *        <codesep_pos_dec> <annex_hex|-> <tapleaf_hex|->
             *        <tx_hex_WITH_witness> <n_prev> <amount_0> <spk_0_hex> ...
             *   -> Core's SignatureHashSchnorr(), i.e. the real BIP341/BIP342
             *      taproot sighash, hex-printed in the same byte order the
             *      SIGHASH and BIP143 commands above use.
             *
             *      Added 2026-08-22.  The BIP143 command can only answer for
             *      witness-v0; taproot's sighash commits to EVERY spent output
             *      (amounts and scriptPubKeys of all prevouts, not just the one
             *      being spent) plus an execution-context blob -- the annex
             *      hash, and for tapscript the tapleaf hash / key version /
             *      last-executed OP_CODESEPARATOR position -- none of which
             *      SignatureHash() takes.  So the taproot sighash in the ASM
             *      implementation had no Core-authoritative check at all; it was
             *      only ever compared against our own reading of BIP341.  This
             *      command closes that gap the same way TAPVERIFY closed it for
             *      whole-input validation: build a real PrecomputedTransactionData
             *      from all spent outputs, fill a ScriptExecutionData by hand
             *      (which the interpreter would normally fill during witness
             *      execution), and ask Core for the digest.
             *
             *      Filling execdata by hand is deliberate: it lets the caller
             *      probe sighash space that a real transaction cannot reach --
             *      arbitrary codeseparator positions, an annex on a key-path
             *      spend, tapleaf hashes not committed to by any control block --
             *      without having to forge a spendable script for each case.
             *      The annex is supplied here as its raw bytes and hashed
             *      exactly as ExecuteWitnessScript does, (HashWriter{} << annex)
             *      .GetSHA256(), i.e. SHA256 over compactsize(len)||annex, so
             *      the caller passes what it would put on the witness stack and
             *      not a pre-hashed value.  Note the transaction's own witness
             *      is NOT consulted: BIP341 commits to the annex only through
             *      execdata, so a witness-stripped tx serialization gives the
             *      identical digest.
             *
             *      hash_type is a uint8_t (0 = SIGHASH_DEFAULT).  Core rejects
             *      any value outside {0x00..0x03, 0x81..0x83} and SIGHASH_SINGLE
             *      past the end of vout by returning false -> ERR
             *      schnorr-sighash-failed. */
            unsigned idx=0, nprev=0; long long ht=0; int sv=0;
            long long csp=0; std::string annexs, leafs, txs;
            if(!(iss>>idx>>ht>>sv>>csp>>annexs>>leafs>>txs>>nprev)){
                printf("ERR bad-args\n"); fflush(stdout); continue;
            }
            if (ht < 0 || ht > 255){ printf("ERR bad-hash-type\n"); fflush(stdout); continue; }
            if (sv != 0 && sv != 1){ printf("ERR bad-sigversion\n"); fflush(stdout); continue; }
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, txs)){ printf("ERR tx-decode-fail\n"); fflush(stdout); continue; }
            std::vector<CTxOut> spent;
            bool bad=false;
            for (unsigned i=0;i<nprev;i++){
                long long amt=0; std::string spkh;
                if(!(iss>>amt>>spkh)){ bad=true; break; }
                if (spkh=="-") spkh="";
                std::vector<unsigned char> s = hex2bytes(spkh.c_str());
                spent.emplace_back(CAmount(amt), CScript(s.begin(), s.end()));
            }
            if (bad || spent.size()!=nprev || spent.size()!=mtx.vin.size()){
                printf("ERR bad-prevouts\n"); fflush(stdout); continue;
            }
            if (idx >= mtx.vin.size()){ printf("ERR bad-input-index\n"); fflush(stdout); continue; }

            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            if (annexs=="-"){
                execdata.m_annex_present = false;
            } else {
                std::vector<unsigned char> annex = hex2bytes(annexs.c_str());
                // Exactly as EvalScript/VerifyWitnessProgram does it.
                execdata.m_annex_hash = (HashWriter{} << annex).GetSHA256();
                execdata.m_annex_present = true;
            }
            SigVersion sigversion = (sv==0) ? SigVersion::TAPROOT : SigVersion::TAPSCRIPT;
            if (sigversion == SigVersion::TAPSCRIPT){
                if (leafs=="-"){ printf("ERR missing-tapleaf\n"); fflush(stdout); continue; }
                std::vector<unsigned char> lh = hex2bytes(leafs.c_str());
                if (lh.size()!=32){ printf("ERR bad-tapleaf\n"); fflush(stdout); continue; }
                execdata.m_tapleaf_hash_init = true;
                execdata.m_tapleaf_hash = uint256(lh);
                execdata.m_codeseparator_pos_init = true;
                execdata.m_codeseparator_pos = (uint32_t)(unsigned long long)csp;
            }
            CTransaction tx(mtx);
            PrecomputedTransactionData txdata;
            // force=true: Init() otherwise only precomputes the BIP341 midstates
            // if it SEES a witness-bearing input with a v1 scriptPubKey, and this
            // command deliberately accepts a witness-stripped serialization (the
            // taproot sighash does not commit to the witness).  Without force,
            // m_bip341_taproot_ready stays false and SignatureHashSchnorr()
            // returns false via HandleMissingData().
            txdata.Init(tx, std::vector<CTxOut>(spent), /*force=*/true);
            uint256 h;
            if (!SignatureHashSchnorr(h, execdata, tx, idx, (uint8_t)ht, sigversion,
                                      txdata, MissingDataBehavior::FAIL)){
                printf("ERR schnorr-sighash-failed\n"); fflush(stdout); continue;
            }
            printf("OK %s\n", HexStr(h).c_str());
            fflush(stdout);
        }
    }
    return 0;
}
