/* tests/test_scr9_policy_flags.c -- SCR-9: the MEMPOOL path must verify under
 * Core's standard (policy) script flags, not the consensus set a block gets.
 *
 * Before this, daemon/tx_verify.c's tx_verify_mempool passed
 * script_flags_for_block(tip+1) straight through, so the node accepted -- and
 * RELAYED -- transactions Core rejects as non-standard.
 *
 * The differential is driven WITHOUT signatures, so it cannot be masked by
 * the wallet signer's own low-S normalisation. CLEANSTACK is the lever:
 *
 *   prevout scriptPubKey : OP_1                (0x51)
 *   scriptSig            : OP_1 OP_1           (0x51 0x51)
 *
 * Under CONSENSUS flags EvalScript leaves [1,1,1], the top is true, and the
 * spend is valid -- this is genuinely consensus-legal, which is the whole
 * point. Under CLEANSTACK exactly one element may remain, so policy rejects
 * it. Core's STANDARD_SCRIPT_VERIFY_FLAGS contains CLEANSTACK; ours now does
 * too, and -acceptnonstdtxn drops back to the consensus set exactly as Core's
 * require_standard=false does.
 *
 * The OPPOSITE HALF matters as much: an ordinary spend that leaves one item
 * must still pass under BOTH flag sets, or "fixed" would just mean "rejects
 * everything".
 */
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;

extern int  tx_verify_mempool(const u8* tx, u64 txlen, long next_height,
                              int (*rf)(void*, const u8[36], u32, u64*, u64*, u64*,
                                        const u8**, unsigned long*),
                              void* rctx, const char** reason);
extern void txv_set_mempool_standard(int on);
extern int  txv_get_mempool_standard(void);
extern int  tx_dispatch_init(void);

static int fails = 0, checks = 0;
static void ck(const char* label, int cond){
    checks++;
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}

/* ---- the prevout this resolver hands back ---- */
static const u8 SPK_ANYONE[1] = { 0x51 };          /* OP_1 */
static int resolve_op1(void* ctx, const u8 outpoint[36], u32 index,
                       u64* value, u64* height, u64* is_coinbase,
                       const u8** spk, unsigned long* spklen){
    (void)ctx; (void)outpoint; (void)index;
    *value = 100000; *height = 1; *is_coinbase = 0;
    *spk = SPK_ANYONE; *spklen = sizeof SPK_ANYONE;
    return 1;
}

/* ---- a one-in one-out transaction with a caller-chosen scriptSig ---- */
static u64 build_tx(u8* out, const u8* ssig, u32 ssiglen){
    u8* p = out;
    *p++ = 1; *p++ = 0; *p++ = 0; *p++ = 0;              /* version 1      */
    *p++ = 1;                                            /* 1 input        */
    memset(p, 0x11, 32); p += 32;                        /* prevout hash   */
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;              /* prevout index 0*/
    *p++ = (u8)ssiglen;                                  /* scriptSig len  */
    memcpy(p, ssig, ssiglen); p += ssiglen;
    *p++ = 0xff; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff;  /* sequence       */
    *p++ = 1;                                            /* 1 output       */
    u64 val = 90000;
    for (int i = 0; i < 8; i++) *p++ = (u8)((val >> (8*i)) & 0xff);
    *p++ = 1; *p++ = 0x51;                               /* scriptPubKey OP_1 */
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;              /* locktime       */
    return (u64)(p - out);
}

static int verify(const u8* ssig, u32 ssiglen, const char** reason){
    u8 tx[256];
    u64 len = build_tx(tx, ssig, ssiglen);
    return tx_verify_mempool(tx, len, 900000, resolve_op1, NULL, reason);
}

int main(void){
    tx_dispatch_init();

    static const u8 DIRTY[2] = { 0x51, 0x51 };   /* OP_1 OP_1 -> 3 items left */
    static const u8 CLEAN[1] = { 0x51 };         /* OP_1      -> 2 items ...  */
    /* NOTE: scriptPubKey OP_1 pushes one more item, so a scriptSig of N
     * pushes leaves N+1. The single-item stack Core's CLEANSTACK wants comes
     * from an EMPTY scriptSig here. */
    const char* reason = NULL;

    printf("== default: the mempool path is STANDARD ==\n");
    ck("txv_get_mempool_standard() defaults to 1", txv_get_mempool_standard() == 1);

    printf("\n== a consensus-valid but non-standard spend ==\n");
    txv_set_mempool_standard(1);
    reason = NULL;
    int std_verdict = verify(DIRTY, sizeof DIRTY, &reason);
    ck("SCR-9: a dirty stack is REJECTED under standard flags", std_verdict == 0);
    if (std_verdict == 0 && reason) printf("      (reason: %s)\n", reason);

    txv_set_mempool_standard(0);
    reason = NULL;
    int cons_verdict = verify(DIRTY, sizeof DIRTY, &reason);
    ck("...and ACCEPTED under consensus flags, so it really is consensus-legal",
       cons_verdict == 1);
    if (cons_verdict == 0 && reason) printf("      (unexpected reason: %s)\n", reason);

    ck("the two flag sets DISAGREE on this transaction (the whole finding)",
       std_verdict != cons_verdict);

    printf("\n== -acceptnonstdtxn restores the consensus behaviour ==\n");
    txv_set_mempool_standard(0);
    ck("the setter reports 0 after -acceptnonstdtxn", txv_get_mempool_standard() == 0);
    txv_set_mempool_standard(1);
    ck("...and 1 again without it", txv_get_mempool_standard() == 1);

    printf("\n== THE OPPOSITE HALF: an ordinary spend still passes ==\n");
    /* empty scriptSig: the scriptPubKey's own OP_1 is the single item left */
    txv_set_mempool_standard(1);
    reason = NULL;
    int ok_std = verify(CLEAN, 0, &reason);
    ck("a clean single-item stack is accepted under STANDARD flags", ok_std == 1);
    if (!ok_std && reason) printf("      (reason: %s)\n", reason);
    txv_set_mempool_standard(0);
    reason = NULL;
    ck("...and under consensus flags too", verify(CLEAN, 0, &reason) == 1);

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
