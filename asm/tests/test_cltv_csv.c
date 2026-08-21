/* test_cltv_csv.c -- OP_CHECKLOCKTIMEVERIFY (BIP65) and OP_CHECKSEQUENCEVERIFY
 * (BIP68/BIP112) were unconditional stubs: `.cltv_nn`/`.csv_nn` always
 * returned SCRIPT_ERR_UNSATISFIED_LOCKTIME regardless of the actual
 * relationship between the script's requested lock and the spending
 * transaction's real nLockTime/nSequence/nVersion -- the comment literally
 * said "no tx context in pure interpreter -> unsatisfied". Every single
 * CLTV- or CSV-locked spend on the whole chain, from BIP65's real
 * activation onward, was being rejected outright.
 *
 * Real mainnet regression: height 388431, right at BIP65 activation -- the
 * first CLTV-locked P2SH spend the replay ever reached. Root-caused via a
 * read-only query of the live archive's own UTXO record for the spent
 * outpoint (no production data touched or mutated) confirming the real
 * prevout script, then running sv_verify_script directly against the real
 * transaction bytes.
 *
 * Fix: sv_verify_script now parses tx.nVersion, tx.nLockTime, and the
 * current input's nSequence out of the raw tx bytes it already receives
 * (sv_get_locktime_context, bitcoin_scriptverify.c) and threads them into
 * script_state; bitcoin_interp.asm's op_cltv/op_csv implement Core's real
 * CheckLockTime/CheckSequence algorithms (script/interpreter.cpp) against
 * that context instead of unconditionally failing.
 *
 * This is genuinely new logic (not a narrow off-by-one like tonight's other
 * fixes), so this test covers the type-matching, boundary, and
 * bypass-prevention cases explicitly, not just the one real transaction.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern int sv_verify_script(const unsigned char* ss, unsigned long ssl,
                            const unsigned char* spk, unsigned long spl,
                            uint64_t flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);

#define SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY (1ULL<<9)
#define SCRIPT_VERIFY_CHECKSEQUENCEVERIFY (1ULL<<10)
#define SCRIPT_ERR_OK 0
#define SCRIPT_ERR_UNSATISFIED_LOCKTIME 22

static int fails = 0;

static int hv(char c){ return c<='9'?c-'0':c-'a'+10; }
static int uh(const char* s, unsigned char* o){ int n=0; while(s[0]&&s[1]){o[n++]=(hv(s[0])<<4)|hv(s[1]); s+=2;} return n; }

static void check(const char* label, int got, int want){
    if (got == want) printf("ok  : %s -> %d\n", label, got);
    else { printf("FAIL: %s -> got %d (SCRIPT_ERR code), want %d\n", label, got, want); fails++; }
}

/* Minimal CScriptNum push encoding (little-endian, sign-magnitude, minimal
 * bytes, with a sign-padding byte only if needed). Values used here are
 * always non-negative. */
static int push_scriptnum(unsigned char* out, int64_t v){
    if (v == 0) { out[0] = 0x00; return 1; }
    unsigned char buf[9]; int n = 0;
    uint64_t av = (uint64_t)v;
    while (av) { buf[n++] = (unsigned char)(av & 0xff); av >>= 8; }
    if (buf[n-1] & 0x80) buf[n++] = 0x00;
    out[0] = (unsigned char)n;
    memcpy(out+1, buf, n);
    return 1 + n;
}

/* Build a minimal 1-in-1-out legacy tx with a controllable version,
 * nLockTime, and input-0 nSequence. scriptSig is empty (push-only trivially
 * satisfied), output is OP_TRUE. */
static unsigned long build_tx(unsigned char* out, uint32_t version, uint32_t locktime, uint32_t sequence){
    unsigned char* p = out;
    memcpy(p, &version, 4); p += 4;
    *p++ = 0x01; /* n_in = 1 */
    memset(p, 0, 32); p += 32; /* prevout txid */
    memset(p, 0, 4); p += 4;   /* prevout index */
    *p++ = 0x00;               /* scriptSig len = 0 */
    memcpy(p, &sequence, 4); p += 4;
    *p++ = 0x01;                /* n_out = 1 */
    uint64_t value = 0; memcpy(p, &value, 8); p += 8;
    *p++ = 0x01; *p++ = 0x51;   /* scriptPubKey = OP_1, len 1 */
    memcpy(p, &locktime, 4); p += 4;
    return (unsigned long)(p - out);
}

static int run_cltv(int64_t script_locktime, uint32_t tx_locktime, uint32_t sequence, uint32_t version){
    unsigned char tx[128];
    unsigned long txlen = build_tx(tx, version, tx_locktime, sequence);
    unsigned char spk[16];
    int n = push_scriptnum(spk, script_locktime);
    spk[n++] = 0xb1; /* OP_CHECKLOCKTIMEVERIFY */
    spk[n++] = 0x75; /* OP_DROP */
    spk[n++] = 0x51; /* OP_1 */
    static unsigned char work[1<<20];
    return sv_verify_script((const unsigned char*)"", 0, spk, (unsigned long)n,
                            SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, 0, tx, txlen, work, sizeof work);
}

static int run_csv(int64_t script_seq, uint32_t sequence, uint32_t version){
    unsigned char tx[128];
    unsigned long txlen = build_tx(tx, version, 0, sequence);
    unsigned char spk[16];
    int n = push_scriptnum(spk, script_seq);
    spk[n++] = 0xb2; /* OP_CHECKSEQUENCEVERIFY */
    spk[n++] = 0x75; /* OP_DROP */
    spk[n++] = 0x51; /* OP_1 */
    static unsigned char work[1<<20];
    return sv_verify_script((const unsigned char*)"", 0, spk, (unsigned long)n,
                            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, 0, tx, txlen, work, sizeof work);
}

int main(void){
    static unsigned char work[1<<20];

    /* ---- real mainnet regression: height 388431 ---- */
    {
        unsigned char tx[512], ssig[256], spk[64];
        unsigned long txlen = (unsigned long)uh(
            "010000000168317ec8ecaee38c03a21939dde22622b37c0fb6d135fa3c3f9d2da71374ab3d0100000073483045022100b2e827"
            "d892be74e00a7d499244e6fc2ec392ba2c6dc7c72bbd99f31865d346450220612182f6bb99b7aec87e82945243b86f327411c3"
            "d1f3a6a2abf6bd1317c584af0129034ded05b17521038cd6db60cb937555dcd30d6f927a3e4ee0f631e8eaf1c61c76c40804ff"
            "a3edd4ac000000000194bb00000000000017a914f1f4fb78c04fe29032192919b3d90c6a5ccaddab874ded0500", tx);
        unsigned long ssl = (unsigned long)uh(
            "483045022100b2e827d892be74e00a7d499244e6fc2ec392ba2c6dc7c72bbd99f31865d346450220612182f6bb99b7aec87e8"
            "2945243b86f327411c3d1f3a6a2abf6bd1317c584af0129034ded05b17521038cd6db60cb937555dcd30d6f927a3e4ee0f631e"
            "8eaf1c61c76c40804ffa3edd4ac", ssig);
        unsigned long spl = (unsigned long)uh("a914f1f4fb78c04fe29032192919b3d90c6a5ccaddab87", spk);
        int r = sv_verify_script(ssig, ssl, spk, spl, 1ULL | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, 0,
                                 tx, txlen, work, sizeof work);
        check("real mainnet h=388431: P2SH CLTV spend", r, SCRIPT_ERR_OK);
    }

    /* ---- CLTV synthetic: height-type (both < LOCKTIME_THRESHOLD) ---- */
    check("CLTV: scriptTime == tx.nLockTime, non-final -> accept",
          run_cltv(388429, 388429, 0, 1), SCRIPT_ERR_OK);
    check("CLTV: scriptTime < tx.nLockTime -> accept",
          run_cltv(388429, 388430, 0, 1), SCRIPT_ERR_OK);
    check("CLTV: scriptTime > tx.nLockTime -> unsatisfied",
          run_cltv(388430, 388429, 0, 1), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    check("CLTV: satisfied locktime but SEQUENCE_FINAL input -> unsatisfied",
          run_cltv(388429, 388429, 0xffffffff, 1), SCRIPT_ERR_UNSATISFIED_LOCKTIME);

    /* ---- CLTV synthetic: type mismatch across LOCKTIME_THRESHOLD ---- */
    check("CLTV: script=height tx=time -> type mismatch, unsatisfied",
          run_cltv(388429, 500000001, 0, 1), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    check("CLTV: script=time tx=height -> type mismatch, unsatisfied",
          run_cltv(500000001, 388429, 0, 1), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    check("CLTV: both time-type, satisfied -> accept",
          run_cltv(500000001, 500000002, 0, 1), SCRIPT_ERR_OK);

    /* ---- CSV synthetic: height-type (both < TYPE_FLAG) ---- */
    check("CSV: scriptSeq == input.nSequence -> accept",
          run_csv(10, 10, 2), SCRIPT_ERR_OK);
    check("CSV: scriptSeq < input.nSequence -> accept",
          run_csv(5, 10, 2), SCRIPT_ERR_OK);
    check("CSV: scriptSeq > input.nSequence -> unsatisfied",
          run_csv(10, 5, 2), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    check("CSV: tx.nVersion < 2 -> unsatisfied even if value matches",
          run_csv(10, 10, 1), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    check("CSV: input's own disable flag set -> unsatisfied",
          run_csv(10, 10u | 0x80000000u, 2), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    check("CSV: script's own disable flag set -> NOP, always accepts",
          run_csv((int64_t)0x80000000, 0, 1), SCRIPT_ERR_OK);

    /* ---- CSV synthetic: type mismatch across TYPE_FLAG (bit 22) ---- */
    check("CSV: script=height-type input=time-type -> type mismatch, unsatisfied",
          run_csv(10, 0x00400000u | 10u, 2), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    check("CSV: script=time-type input=height-type -> type mismatch, unsatisfied",
          run_csv((int64_t)(0x00400000u | 10u), 10, 2), SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    check("CSV: both time-type, satisfied -> accept",
          run_csv((int64_t)(0x00400000u | 10u), 0x00400000u | 20u, 2), SCRIPT_ERR_OK);

    printf("cltv_csv: 17 check(s), %d failure(s)\n", fails);
    return fails?1:0;
}
