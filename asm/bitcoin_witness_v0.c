#include "bmc_thread.h"
/* bitcoin_witness_v0.c -- BIP141 witness program classification and version-0
 * execution (P2WPKH, P2WSH, and their P2SH-wrapped "nested segwit" forms).
 *
 * Split out of bitcoin_scriptverify.c (2026-08-22) so that file -- the
 * general script interpreter driver, linked by many script-only unit tests --
 * does not pull in the segwit sighash (bitcoin_segwit.c) and hash160
 * (bitcoin_addr.o) at link time. This file is linked only where real witness
 * verification runs: the block verifier (daemon/tx_verify.c) and the mempool
 * validator (bitcoin_txval_modern.c).
 *
 * It drives the SAME shared interpreter (script_eval, SIGVERSION_WITNESS_V0)
 * through sv_run_v, reusing bitcoin_scriptverify.c's stack helpers and
 * sv_ctx (exported non-static there). Core reference: script/interpreter.cpp
 * VerifyWitnessProgram + ExecuteWitnessScript and VerifyScript's P2SH branch.
 */
#include <stdint.h>
#include <string.h>
#include "script_error_codes.h"

#define ELEM_SIZE     528
#define ELEM_DATA_OFF 4
#define MAX_STACK     1000
#define SIGV_WITNESS_V0 1
#define MAX_SCRIPT_ELEMENT_SIZE 520

/* --- shared with bitcoin_scriptverify.c (now non-static there) --- */
typedef struct { uint8_t* e; size_t sp; } sv_stack;
struct sv_ctx {
    const uint8_t* tx; unsigned long txlen; unsigned long nIn;
    uint8_t* work; unsigned long workcap;
    uint32_t tx_locktime; uint32_t in_sequence; uint32_t tx_version;
    uint64_t amount;
};
extern uint8_t* sv_rec(sv_stack*, size_t);
extern int  sv_true(sv_stack*, size_t);
extern int  sv_is_p2sh(const uint8_t*, size_t);
extern int  sv_get_locktime_context(const uint8_t* tx, unsigned long txlen, unsigned long nIn,
                                    uint32_t* ver, uint32_t* lt, uint32_t* seq);
extern int  sv_run_v(const uint8_t* script, size_t slen, sv_stack* st,
                     uint64_t flags, struct sv_ctx* ctx, int* err, int sigversion,
                     uint64_t (*cs)(void*, const uint8_t*, size_t, const uint8_t*, size_t, const void*));

/* --- crypto/sighash primitives --- */
extern long segwit_v0_sighash(uint8_t out32[32], const uint8_t* tx, int64_t txlen,
                              int64_t n_in, uint32_t nHashType, uint64_t amount,
                              const uint8_t* scriptCode, uint64_t scriptcode_len,
                              uint8_t* pre, long cap);
extern void sha256_full(uint8_t* out, const void* msg, int64_t len);
extern void hash160(uint8_t o[20], const void* in, long long len);
extern int  der_parse_sig(const uint8_t* sig, unsigned long siglen, uint64_t r[4], uint64_t s[4], uint32_t* ht);
extern int  pubkey_parse(const uint8_t* pub, unsigned long publen, uint64_t qx[4], uint64_t qy[4]);
extern int  ecdsa_verify(const uint64_t z[4], const uint64_t r[4], const uint64_t s[4], const uint64_t Qx[4], const uint64_t Qy[4]);
extern void be_to_limbs(uint64_t out[4], const uint8_t* be, unsigned long n);

/* --------------------------------------------- witness v0 checksig hook */
/* Core: interpreter.cpp GenericTransactionSignatureChecker::CheckECDSASignature
 * under SigVersion::WITNESS_V0 -> SignatureHash(scriptCode, tx, nIn,
 * nHashType, amount, WITNESS_V0) = BIP143. Differences from sv_checksig:
 * NO FindAndDelete (Core applies it only for SigVersion::BASE), and the
 * scriptCode is the interpreter's post-OP_CODESEPARATOR slice of the
 * witnessScript verbatim (BIP143: "removing everything up to and including
 * the last executed OP_CODESEPARATOR"; the separators themselves are NOT
 * removed -- that is the BASE serializer's job). The hashtype is the
 * signature's last byte, used as-is (same reasoning as sv_checksig's
 * 2026-08-19 note); segwit_v0_sighash implements NONE/SINGLE/ANYONECANPAY. */
static uint64_t sv_checksig_witness_v0(void* cptr, const uint8_t* sig, size_t siglen,
                                       const uint8_t* pub, size_t publen, const void* slice){
    struct sv_ctx* c = (struct sv_ctx*)cptr;
    const struct { const uint8_t* p; size_t n; }* sc = slice;
    if (!siglen) return 0;
    uint8_t ht = sig[siglen-1];
    uint64_t r[4], s[4]; uint32_t dht;
    if (!der_parse_sig(sig, (unsigned long)siglen, r, s, &dht)) return 0;
    static __thread uint8_t* pre; BMC_TLS_BUF(pre, 1<<16);
    uint8_t z[32];
    if (segwit_v0_sighash(z, c->tx, (int64_t)c->txlen, (int64_t)c->nIn, (uint32_t)ht,
                          c->amount, sc->p, (uint64_t)sc->n, pre, (long)(1<<16)) <= 0) return 0;
    uint64_t zl[4]; be_to_limbs(zl, z, 32);
    uint64_t qx[4], qy[4];
    if (!pubkey_parse(pub, (unsigned long)publen, qx, qy)) return 0;
    return (uint64_t)ecdsa_verify(zl, r, s, qx, qy);
}

/* ======================================================================
 * BIP141 witness program classification and version-0 execution
 * (2026-08-22). Core: script/interpreter.cpp VerifyWitnessProgram +
 * ExecuteWitnessScript, and the P2SH-wrapped branch of VerifyScript.
 * ====================================================================== */

/* CScript::IsWitnessProgram: 4..42 bytes, OP_0 or OP_1..OP_16, then one
 * push of exactly the remaining 2..40 bytes. */
int sv_witness_program(const uint8_t* s, uint32_t n, uint32_t* version,
                       const uint8_t** prog, uint32_t* proglen){
    if (n < 4 || n > 42) return 0;
    if (!(s[0] == 0x00 || (s[0] >= 0x51 && s[0] <= 0x60))) return 0;
    if (s[1] != n - 2) return 0;
    *version = s[0] == 0x00 ? 0 : (uint32_t)(s[0] - 0x50);
    *prog = s + 2; *proglen = n - 2;
    return 1;
}

/* Walk a push-only scriptSig and return its LAST push (the P2SH
 * redeemScript). Returns 0 if not push-only / malformed / empty. */
static int sv_last_push(const uint8_t* ss, uint32_t ssl, const uint8_t** data, uint32_t* len,
                        uint32_t* npush){
    uint32_t p = 0, n = 0; const uint8_t* d = 0; uint32_t dl = 0;
    while (p < ssl){
        uint8_t op = ss[p];
        if (op <= 0x4b){ if (p + 1 + op > ssl) return 0; d = ss + p + 1; dl = op; p += 1 + op; }
        else if (op == 0x4c){ if (p + 2 > ssl) return 0; dl = ss[p+1]; if (p + 2 + dl > ssl) return 0; d = ss + p + 2; p += 2 + dl; }
        else if (op == 0x4d){ if (p + 3 > ssl) return 0; dl = ss[p+1] | ((uint32_t)ss[p+2] << 8); if (p + 3 + dl > ssl) return 0; d = ss + p + 3; p += 3 + dl; }
        else if (op == 0x4e){ if (p + 5 > ssl) return 0; dl = ss[p+1] | ((uint32_t)ss[p+2] << 8) | ((uint32_t)ss[p+3] << 16) | ((uint32_t)ss[p+4] << 24); if ((uint64_t)p + 5 + dl > ssl) return 0; d = ss + p + 5; p += 5 + dl; }
        else if (op == 0x00 || op == 0x4f || (op >= 0x51 && op <= 0x60)){ d = ss + p; dl = 0; p += 1; } /* small-int pushes: not a script */
        else return 0;
        n++;
    }
    if (!n) return 0;
    *data = d; *len = dl; *npush = n;
    return 1;
}

/* sv_classify_segwit: decide whether an input spends a witness program.
 *   returns  1  native program (spk itself)        -> *version/*prog/*proglen set
 *            2  P2SH-wrapped program (BIP141 "P2SH-P2WPKH/P2SH-P2WSH"):
 *               spk is P2SH, scriptSig is exactly one push whose payload is
 *               a witness program and hash160(payload) == the P2SH hash
 *           -1  P2SH whose last push IS a witness program but the scriptSig
 *               is not exactly that single push (Core:
 *               SCRIPT_ERR_WITNESS_MALLEATED_P2SH) or whose hash does not
 *               match (Core: the P2SH EQUAL fails) -- reject
 *            0  not a witness spend: ordinary legacy evaluation applies.
 * Only meaningful when SCRIPT_VERIFY_WITNESS is active; the caller gates. */
int sv_classify_segwit(const uint8_t* spk, uint32_t spl,
                       const uint8_t* ss, uint32_t ssl,
                       uint32_t* version, const uint8_t** prog, uint32_t* proglen,
                       int* wrapped){
    *wrapped = 0;
    if (sv_witness_program(spk, spl, version, prog, proglen)) return 1;
    if (!sv_is_p2sh(spk, spl)) return 0;
    const uint8_t* rd; uint32_t rl, np;
    if (!sv_last_push(ss, ssl, &rd, &rl, &np)) return 0;
    if (!sv_witness_program(rd, rl, version, prog, proglen)) return 0;
    /* Core: scriptSig must be exactly `CScript() << redeemScript`, i.e. one
     * minimal direct push (redeem is 4..42 bytes, so opcode == length). */
    if (np != 1 || ssl != 1u + rl || ss[0] != rl) return -1;
    uint8_t h[20]; hash160(h, rd, (long long)rl);
    if (memcmp(h, spk + 2, 20) != 0) return -1;
    *wrapped = 1;
    return 2;
}

/* sv_verify_witness_v0: Core's VerifyWitnessProgram (version 0 arm) +
 * ExecuteWitnessScript, driving the shared interpreter with
 * SIGVERSION_WITNESS_V0 and the BIP143 checksig hook above.
 *   20-byte program (P2WPKH): witness must be exactly 2 items; the script is
 *     the implied P2PKH script OP_DUP OP_HASH160 <prog> OP_EQUALVERIFY
 *     OP_CHECKSIG.
 *   32-byte program (P2WSH): witness non-empty; last item is the
 *     witnessScript, SHA256 of it must equal the program; the rest is the
 *     initial stack.
 *   Any other length: WITNESS_PROGRAM_WRONG_LENGTH.
 * ExecuteWitnessScript: every initial stack element <= 520 bytes
 * (PUSH_SIZE); EvalScript; then exactly one element left (CLEANSTACK --
 * "scripts inside witness implicitly require cleanstack behaviour") and it
 * must CastToBool true (EVAL_FALSE). Returns a SCRIPT_ERR_* code. */
int sv_verify_witness_v0(const uint8_t* prog, uint32_t proglen,
                         const uint8_t* const* wit, const uint32_t* witlen, uint32_t nwit,
                         uint64_t amount, uint64_t flags, unsigned long nIn,
                         const uint8_t* tx, unsigned long txlen,
                         uint8_t* work, unsigned long workcap){
    static __thread uint8_t* main_e; BMC_TLS_BUF(main_e, MAX_STACK*ELEM_SIZE);
    static __thread uint8_t p2wpkh_script[25];
    const uint8_t* script; uint32_t slen; uint32_t nstack;
    if (proglen == 32){
        if (nwit == 0) return SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY;
        script = wit[nwit-1]; slen = witlen[nwit-1];
        uint8_t h[32]; sha256_full(h, script, (int64_t)slen);
        if (memcmp(h, prog, 32) != 0) return SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH;
        nstack = nwit - 1;
    } else if (proglen == 20){
        if (nwit != 2) return SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH;
        p2wpkh_script[0]=0x76; p2wpkh_script[1]=0xa9; p2wpkh_script[2]=0x14;
        memcpy(p2wpkh_script+3, prog, 20); p2wpkh_script[23]=0x88; p2wpkh_script[24]=0xac;
        script = p2wpkh_script; slen = 25;
        nstack = 2;
    } else return SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH;

    if (nstack > MAX_STACK) return SCRIPT_ERR_STACK_SIZE;
    sv_stack st = { main_e, 0 };
    for (uint32_t i = 0; i < nstack; i++){
        if (witlen[i] > MAX_SCRIPT_ELEMENT_SIZE) return SCRIPT_ERR_PUSH_SIZE;
        uint8_t* rec = sv_rec(&st, i);
        *(uint32_t*)rec = witlen[i];
        memcpy(rec + ELEM_DATA_OFF, wit[i], witlen[i]);
        st.sp++;
    }
    struct sv_ctx ctx = { tx, txlen, nIn, work, workcap, 0, 0, 0, amount };
    sv_get_locktime_context(tx, txlen, nIn, &ctx.tx_version, &ctx.tx_locktime, &ctx.in_sequence);
    int err = SCRIPT_ERR_OK;
    if (!sv_run_v(script, slen, &st, flags, &ctx, &err, SIGV_WITNESS_V0, sv_checksig_witness_v0))
        return err;
    if (st.sp != 1) return SCRIPT_ERR_CLEANSTACK;
    if (!sv_true(&st, 0)) return SCRIPT_ERR_EVAL_FALSE;
    return SCRIPT_ERR_OK;
}

