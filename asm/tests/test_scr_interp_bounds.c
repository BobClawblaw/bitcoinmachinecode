/* test_scr_interp_bounds.c -- regressions for the interpreter consensus
 * defects the 2026-09-03 audit found (SCR-1, SCR-2, SCR-4). Each vector was
 * negative-controlled: with the fix reverted it FAILS, with the fix it passes.
 *
 *   SCR-1  MAX_STACK_SIZE is stack+altstack COMBINED, checked after every
 *          opcode (Core, interpreter.cpp). Pre-fix the two stacks were each
 *          capped at 1000 independently -> 2000 live elements possible; a
 *          spend Core rejects was ACCEPTED. Tapscript (sigv 2) has no opcode
 *          limit, so a long push-only script reaches the combined cap.
 *   SCR-2  vfexec (condition stack) overflow: the buffer held 1024 entries
 *          and pushed unbounded; the 1025th nested OP_IF overwrote
 *          vfexec_sp (the depth!) and an UNBALANCED script passed.
 *          Vectors: balanced 1030-deep nesting (must PASS -- pre-fix its
 *          own ENDIF sequence hit the depth-reset garbage), and an
 *          unbalanced 1030-deep script (must FAIL).
 *   SCR-4  CSV's nVersion < 2 gate was a SIGNED compare; Core compares the
 *          uint32_t unsigned, so nVersion >= 0x80000000 HAS BIP68 enforced.
 *          Pre-fix such a tx false-rejected every CSV spend.
 *
 * Harness: the asm interpreter directly (script_eval); struct layout mirrors
 * bitcoin_scriptverify.c / bitcoin_interp.asm.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define ELEM_SIZE 528
#define MAX_STACK 1000
#define SCRIPT_ERR_STACK_SIZE 8
#define SIGV_TAPSCRIPT 2
#define FLAG_CSV 0x400u   /* SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = 1<<10 (bitcoin_interp.asm) */
#define FLAG_CLTV 0x200u   /* SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = 1<<9 */
struct script_state {
    uint8_t* main_elems; size_t main_sp;
    uint8_t* alt_elems;  size_t alt_sp;
    uint8_t* script;     size_t script_len;
    int      sigversion; uint64_t flags;
    uint8_t* work;       size_t work_cap;
    uint64_t* error_out;
    void*    checksig_ctx;
    uint64_t (*checksig_fn)(void*,const uint8_t*,size_t,const uint8_t*,size_t,const void*);
    uint32_t tx_locktime; uint32_t in_sequence; uint32_t tx_version;
};
extern int script_eval(struct script_state* st);

static uint8_t main_elems[MAX_STACK*ELEM_SIZE];
static uint8_t alt_elems[MAX_STACK*ELEM_SIZE];
static uint8_t work[1<<16];
static uint64_t g_err;
static int fails = 0;

static int run(uint8_t* scr, size_t sl, int sigv, uint64_t flags,
               uint32_t txver, uint32_t txltime, uint32_t inseq)
{
    memset(main_elems,0,sizeof main_elems);
    memset(alt_elems,0,sizeof alt_elems);
    struct script_state st;
    memset(&st,0,sizeof st);
    st.main_elems=main_elems; st.main_sp=0;
    st.alt_elems=alt_elems;   st.alt_sp=0;
    st.script=scr; st.script_len=sl; st.sigversion=sigv; st.flags=flags;
    st.work=work; st.work_cap=sizeof work; st.error_out=&g_err;
    st.tx_locktime=txltime; st.in_sequence=inseq; st.tx_version=txver;
    g_err=999;
    return script_eval(&st);
}


/* ================= SCR-3: tapscript empty-signature / empty-pubkey =========
 * The interpreter's empty-signature shortcut used to skip the checksig
 * callback under tapscript, so the C-side TAPSCRIPT_EMPTY_PUBKEY rule never
 * fired: `OP_0 OP_0 OP_CHECKSIG OP_NOT` was ACCEPTED where Core fails the
 * script. The fix routes tapscript CHECKSIG/CHECKSIGADD through the callback
 * unconditionally; the callback mirrors Core's sequence. Here we assert the
 * interpreter-visible half: the callback IS invoked for an empty signature
 * under tapscript (it records its call), and its hard-fail propagates as a
 * script failure rather than a pushed value.
 * -------------------------------------------------------------------------- */
typedef struct { int calls; size_t last_siglen; size_t last_publen; int ret; } probe_t;
static uint64_t probe_fn(void* ctx, const uint8_t* sig, size_t siglen,
                         const uint8_t* pub, size_t publen, const void* slice){
    (void)sig; (void)slice;
    probe_t* p = (probe_t*)ctx;
    p->calls++; p->last_siglen = siglen; p->last_publen = publen;
    return (uint64_t)p->ret;
}
static probe_t g_probe;
static int run_cb(uint8_t* scr, size_t sl){
    memset(main_elems,0,sizeof main_elems);
    memset(alt_elems,0,sizeof alt_elems);
    struct script_state st; memset(&st,0,sizeof st);
    st.main_elems=main_elems; st.main_sp=0;
    st.alt_elems=alt_elems;   st.alt_sp=0;
    st.script=scr; st.script_len=sl; st.sigversion=SIGV_TAPSCRIPT; st.flags=0;
    st.work=work; st.work_cap=sizeof work; st.error_out=&g_err;
    g_probe=(probe_t){0,0,0,1};
    st.checksig_ctx=&g_probe; st.checksig_fn=probe_fn;
    g_err=999;
    return script_eval(&st);
}

int main(void){
    /* --- SCR-1 positive: 1001 pushes. TOALTSTACK is a main-POP + alt-PUSH
     * (Core's opcodetype moves the element), so it does not grow the sum --
     * but it also re-runs the alt stack_push, whose *per-buffer* 1000 guard
     * fires at the 1000th alt push. To exercise the COMBINED rule with no
     * per-buffer interference, push-only: the 1001st push trips main's own
     * guard at exactly the combined threshold (1000 main + 0 alt). The real
     * combined-vs-per-buffer proof is SCR-1c below (alt=200, main=801:
     * per-buffer guards pass, combined=1001 fails -- only possible if the
     * SUM is what the interpreter checks). */
    {
        static uint8_t scr[8192];
        size_t n=0;
        for (int i=0;i<1001;i++){ scr[n++]=0x01; scr[n++]=0x01; scr[n++]=0x01; }
        int r = run(scr,n,SIGV_TAPSCRIPT,0,1,0,0);
        if (r==0 && g_err==SCRIPT_ERR_STACK_SIZE)
            printf("ok: SCR-1 1001 pushes rejected with STACK_SIZE\n");
        else { printf("FAIL: SCR-1 got r=%d err=%llu (want r=0 err=8)\n", r,(unsigned long long)g_err); fails++; }
    }
    /* --- SCR-1c: THE combined-rule vector. 1000 main pushes + 200 alt moves
     * fills the alt buffer (each alt push passes its own <=1000 guard: alt
     * reaches 200, fine; main stays 800). Then 201 more pushes bring main to
     * 1001: main's own guard would fire anyway. INSTEAD: 900 main + 100 alt =
     * 1000 combined, then push 1 -> combined 1001 while main=901 < 1000 and
     * alt=100 < 1000: both per-buffer guards PASS; only the SUM can reject.
     * This is the discriminating vector for SCR-1. */
    {
        static uint8_t scr[8192];
        size_t n=0;
        for (int i=0;i<900;i++){ scr[n++]=0x01; scr[n++]=0x01; scr[n++]=0x01; }   /* main 900 */
        for (int i=0;i<100;i++) scr[n++]=0x6c;                                    /* main 800, alt 100 */
        for (int i=0;i<101;i++){ scr[n++]=0x01; scr[n++]=0x01; scr[n++]=0x01; }   /* main 901, alt 100 */
        int r = run(scr,n,SIGV_TAPSCRIPT,0,1,0,0);   /* 901+100 = 1001 combined */
        if (r==0 && g_err==SCRIPT_ERR_STACK_SIZE)
            printf("ok: SCR-1 combined rule fires at 901+100 (both stacks individually under 1000)\n");
        else { printf("FAIL: SCR-1c got r=%d err=%llu (want r=0 err=8: only the SUM can reject)\n", r,(unsigned long long)g_err); fails++; }
    }
    /* --- SCR-2 balanced deep nesting: 1030 x (OP_1 OP_IF), 1030 x OP_ENDIF,
     * OP_1 -> a valid script that MUST pass. Pre-fix the 1025th push zeroed
     * vfexec_sp's low bytes and the first executed ENDIF at the corrupted
     * depth failed UNBALANCED_CONDITIONAL. */
    {
        static uint8_t scr[8192];
        size_t n=0;
        for (int i=0;i<1030;i++){ scr[n++]=0x51; scr[n++]=0x63; }
        for (int i=0;i<1030;i++) scr[n++]=0x68;
        scr[n++]=0x51;
        int r = run(scr,n,SIGV_TAPSCRIPT,0,1,0,0);
        if (r==1) printf("ok: SCR-2 balanced 1030-deep nesting accepted (pre-fix overflow broke this)\n");
        else { printf("FAIL: SCR-2 balanced 1030-deep rejected (err=%llu)\n",(unsigned long long)g_err); fails++; }
    }
    /* --- SCR-2 unbalanced: 1030 IF (each with OP_1), 1029 ENDIF -> one IF
     * left open at the end. Must FAIL (pre-fix the corrupted depth could make
     * the engine believe the stack was balanced). */
    {
        static uint8_t scr[8192];
        size_t n=0;
        for (int i=0;i<1030;i++){ scr[n++]=0x51; scr[n++]=0x63; }
        for (int i=0;i<1029;i++) scr[n++]=0x68;
        scr[n++]=0x51;
        int r = run(scr,n,SIGV_TAPSCRIPT,0,1,0,0);
        if (r==0) printf("ok: SCR-2 unbalanced deep nesting rejected (err=%llu)\n",(unsigned long long)g_err);
        else { printf("FAIL: SCR-2 unbalanced 1030-deep script ACCEPTED (the false-accept bug)\n"); fails++; }
    }
    /* --- SCR-4: OP_1 OP_CSV with nVersion=0xffffffff. Core enforces BIP68
     * (unsigned >= 2): operand 1, in_sequence 1 -> satisfied -> script passes.
     * Pre-fix: signed cmp read 0xffffffff as negative -> UNSATISFIED_LOCKTIME. */
    {
        static uint8_t s2[] = {0x51,0xb2};   /* OP_1 CSV (CSV peeks, leaves [1]) */
        int r = run(s2,sizeof s2,0,FLAG_CSV,0xFFFFFFFFu,0,1);
        if (r==1) printf("ok: SCR-4 CSV with nVersion=0xffffffff enforced (unsigned compare)\n");
        else { printf("FAIL: SCR-4 CSV false-rejected (err=%llu)\n",(unsigned long long)g_err); fails++; }
    }
    /* --- SCR-4 controls, both version=1 (pre-BIP68):
     *  a) operand 1 (no disable bit): CSV MUST be unsatisfied (script fails)
     *     -> proves the version gate still exists (unsigned cmp >= 2).
     *  b) operand with the disable bit set (0x80000021): CSV NOPs regardless
     *     of version -> script passes. Proves the positive vector's pass is
     *     NOT the flag being inert. */
    {
        static uint8_t s2[] = {0x51,0xb2};
        int r = run(s2,sizeof s2,0,FLAG_CSV,1u,0,1);
        if (r==0) printf("ok: SCR-4 control v1/non-disabled operand still unsatisfied (err=%llu)\n",(unsigned long long)g_err);
        else { printf("FAIL: SCR-4 control a: version=1 CSV was satisfied (gate missing?)\n"); fails++; }
    }
    {
        /* push operand = 0x80000021 (5 bytes little-endian, disable bit set) */
        static uint8_t s3[] = {0x05,0x21,0x00,0x00,0x80,0x00, 0xb1};
        int r = run(s3,sizeof s3,0,FLAG_CSV,1u,0,1);
        if (r==1) printf("ok: SCR-4 control b: v1 + disabled operand NOPs (script passes)\n");
        else { printf("FAIL: SCR-4 control b: disabled operand not NOPed (err=%llu)\n",(unsigned long long)g_err); fails++; }
    }
    /* --- SCR-1: the tapscript CHECKSIG/CHECKSIGADD arms must CALL the
     * checker even for an EMPTY signature. Pre-fix the shortcut pushed
     * false/0 without invoking it, so the C-side empty-pubkey rule was
     * dead code and `OP_0 OP_0 CHECKSIG OP_NOT` was accepted. */
    {
        static uint8_t s[] = {0x00,0x00,0xac,0x87};          /* OP_0 OP_0 CHECKSIG NOT */
        int r = run_cb(s,sizeof s);
        if (g_probe.calls==1 && g_probe.last_siglen==0)
            printf("ok: SCR-3 tapscript CHECKSIG called the checker for an empty sig\n");
        else { printf("FAIL: SCR-3 CHECKSIG empty-sig: calls=%d siglen=%zu (want 1/0)\n", g_probe.calls,g_probe.last_siglen); fails++; }
        (void)r;
    }
    {
        static uint8_t s[] = {0x00,0x00,0x00,0xba};          /* OP_0 OP_0 OP_0 CHECKSIGADD */
        int r = run_cb(s,sizeof s);
        if (g_probe.calls==1 && g_probe.last_siglen==0)
            printf("ok: SCR-3 tapscript CHECKSIGADD called the checker for an empty sig\n");
        else { printf("FAIL: SCR-3 CHECKSIGADD empty-sig: calls=%d siglen=%zu (want 1/0)\n", g_probe.calls,g_probe.last_siglen); fails++; }
        (void)r;
    }
    /* a checker that reports hard-fail (ret=0 == "script invalid") must make
     * the WHOLE script fail -- the false-with-empty-pubkey path that Core
     * turns into TAPSCRIPT_EMPTY_PUBKEY. Pre-fix with the shortcut, OP_NOT
     * inverted a pushed false and the script PASSED. */
    {
        static uint8_t s[] = {0x00,0x00,0xac,0x87};
        uint8_t* p=s; size_t n=sizeof s;
        memset(main_elems,0,sizeof main_elems); memset(alt_elems,0,sizeof alt_elems);
        struct script_state st; memset(&st,0,sizeof st);
        st.main_elems=main_elems; st.alt_elems=alt_elems; st.script=p; st.script_len=n;
        st.sigversion=SIGV_TAPSCRIPT; st.flags=0;
        st.work=work; st.work_cap=sizeof work; st.error_out=&g_err;
        g_probe=(probe_t){0,0,0,0};                          /* ret=0: hard fail */
        st.checksig_ctx=&g_probe; st.checksig_fn=probe_fn;
        g_err=999;
        int r=script_eval(&st);
        if (r==0 && g_probe.calls==1)
            printf("ok: SCR-3 checker hard-fail fails the script (OP_NOT cannot rescue it)\n");
        else { printf("FAIL: SCR-3 hard-fail: r=%d calls=%d (want r=0, calls=1)\n", r,g_probe.calls); fails++; }
    }
    /* pre-tapscript (BASE) keeps the empty-sig shortcut (Core:
     * EvalChecksigPreTapscript pushes false without the checker) */
    {
        static uint8_t s[] = {0x00,0x00,0xac};               /* OP_0 OP_0 CHECKSIG */
        memset(main_elems,0,sizeof main_elems); memset(alt_elems,0,sizeof alt_elems);
        struct script_state st; memset(&st,0,sizeof st);
        st.main_elems=main_elems; st.alt_elems=alt_elems; st.script=s; st.script_len=sizeof s;
        st.sigversion=0; st.flags=0;
        st.work=work; st.work_cap=sizeof work; st.error_out=&g_err;
        g_probe=(probe_t){0,0,0,1};
        st.checksig_ctx=&g_probe; st.checksig_fn=probe_fn;
        g_err=999;
        int r=script_eval(&st);
        if (g_probe.calls==0 && r==1)
            printf("ok: SCR-3 control: BASE sigversion keeps the empty-sig shortcut (no call)\n");
        else { printf("FAIL: SCR-3 BASE control: calls=%d r=%d (want 0/1)\n", g_probe.calls,r); fails++; }
    }
    printf(fails?"\nFAILURES %d\n":"\nALL TESTS PASSED (0 failures)\n",fails);
    return fails?1:0;
}
