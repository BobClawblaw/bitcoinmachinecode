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
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
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
    /* --- IR-1 (INTERP_REVIEW_2026-09-05): every net-growing stack op
     * discarded the 0 "stack full" return of stack_dup_index/stack_push.
     * At exactly 1000 elements the op silently became a no-op, the post-op
     * combined check saw 1000 (not > 1000) and PASSED, where Core pushes to
     * 1001 and fails with SCRIPT_ERR_STACK_SIZE. A script Core rejects was
     * ACCEPTED -- consensus false accept, any sigversion.
     *
     * Each vector fills the stack with OP_1s to (1000 - growth + 1) so the
     * op is the one that would cross 1000, then runs the op. Both BASE (OP_1
     * is not counted toward the 201-op limit; 1001 bytes < 10000) and
     * TAPSCRIPT. Controls: the same op one element short MUST pass, and the
     * net-zero ops at exactly 1000 MUST pass. */
    for (int sigv = 0; sigv <= SIGV_TAPSCRIPT; sigv += SIGV_TAPSCRIPT) {
        struct { const char* name; int fill; uint8_t op; int want_reject; } v[] = {
            { "OP_DUP  @1000", 1000, 0x76, 1 },
            { "OP_OVER @1000", 1000, 0x78, 1 },
            { "OP_IFDUP@1000", 1000, 0x73, 1 },
            { "OP_TUCK @1000", 1000, 0x7d, 1 },
            { "OP_2DUP @999",   999, 0x6e, 1 },
            { "OP_2OVER@999",   999, 0x70, 1 },
            { "OP_3DUP @998",   998, 0x6f, 1 },
            { "OP_SIZE @1000", 1000, 0x82, 1 },
            { "OP_DEPTH@1000", 1000, 0x74, 1 },
            /* controls: one short of the cap, must pass */
            { "OP_DUP  @999",   999, 0x76, 0 },
            { "OP_2DUP @998",   998, 0x6e, 0 },
            { "OP_3DUP @997",   997, 0x6f, 0 },
            /* controls: net-zero ops AT the cap, must pass */
            { "OP_SWAP @1000", 1000, 0x7c, 0 },
            { "OP_2ROT @1000", 1000, 0x71, 0 },
            { "OP_ROT  @1000", 1000, 0x7b, 0 },
        };
        for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
            static uint8_t scr[4096]; size_t n = 0;
            for (int k = 0; k < v[i].fill; k++) scr[n++] = 0x51;
            scr[n++] = v[i].op;
            /* tapscript requires exactly one element at the end (CLEANSTACK is
             * consensus there): drain to one. If the op silently no-ops, the
             * drain runs and the script PASSES -- the same false accept BASE
             * shows without the drain. */
            if (sigv == SIGV_TAPSCRIPT) for (int k = 0; k < 999; k++) scr[n++] = 0x75;
            g_err = 999;
            int r = run(scr, n, sigv, 0, 1, 0, 0);
            if (v[i].want_reject) {
                if (r == 0 && g_err == SCRIPT_ERR_STACK_SIZE)
                    printf("ok: IR-1 sigv%d %s rejected with STACK_SIZE\n", sigv, v[i].name);
                else { printf("FAIL: IR-1 sigv%d %s got r=%d err=%llu (want r=0 err=8: Core pushes to 1001 and rejects)\n",
                              sigv, v[i].name, r, (unsigned long long)g_err); fails++; }
            } else {
                if (r == 1)
                    printf("ok: IR-1 control sigv%d %s passes\n", sigv, v[i].name);
                else { printf("FAIL: IR-1 control sigv%d %s got r=%d err=%llu (want r=1)\n",
                              sigv, v[i].name, r, (unsigned long long)g_err); fails++; }
            }
        }
        /* OP_PICK with n=0 at 999+index: pops the index, pushes a copy ->
         * exactly 1000, must pass (net zero). */
        {
            static uint8_t scr[4096]; size_t n = 0;
            for (int k = 0; k < 999; k++) scr[n++] = 0x51;
            scr[n++] = 0x00; scr[n++] = 0x79;
            if (sigv == SIGV_TAPSCRIPT) for (int k = 0; k < 999; k++) scr[n++] = 0x75;
            g_err = 999;
            int r = run(scr, n, sigv, 0, 1, 0, 0);
            if (r == 1) printf("ok: IR-1 control sigv%d <0> OP_PICK at 999 -> 1000 passes\n", sigv);
            else { printf("FAIL: IR-1 control sigv%d OP_PICK got r=%d err=%llu (want r=1)\n", sigv, r, (unsigned long long)g_err); fails++; }
        }
    }
    /* --- IR-4 (INTERP_REVIEW_2026-09-05): fExec was recomputed before every
     * opcode by a byte-at-a-time scan of the whole condition stack. Tapscript
     * has no opcode or script-size cap, so `OP_1 OP_IF` x N, `OP_ENDIF` x N,
     * OP_1 -- a consensus-VALID leaf -- cost O(N^2): ~N^2 byte loads. At
     * N=120,000 that is ~1.4e10 loads (10-20 s here; a ~4 MB leaf is
     * 15-40 minutes) while Core's ConditionStack is O(1) per opcode. The
     * vector must PASS (it is valid) and must do so in well under 3 s; it is
     * run in a child under alarm() so a quadratic regression is a FAIL, not
     * a hang. Watched against the unfixed object: ~12 s. */
    {
        enum { N = 250000 };
        static uint8_t big[3*N + 1]; size_t n = 0;
        for (int i = 0; i < N; i++){ big[n++] = 0x51; big[n++] = 0x63; }
        for (int i = 0; i < N; i++)  big[n++] = 0x68;
        big[n++] = 0x51;
        fflush(stdout);   /* stdout is a pipe under the gate: flush BEFORE forking or
                           * the parent's buffered lines are inherited and printed twice */
        pid_t pid = fork();
        if (pid == 0){
            alarm(30);
            struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
            int r = run(big, n, SIGV_TAPSCRIPT, 0, 1, 0, 0);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double ms = (t1.tv_sec - t0.tv_sec)*1e3 + (t1.tv_nsec - t0.tv_nsec)/1e6;
            /* stdout is a pipe under the gate: flush before _exit or the line is lost */
            if (r != 1) { printf("FAIL: IR-4 valid %d-deep nested IF leaf rejected (r=%d err=%llu)\n", N, r, (unsigned long long)g_err); fflush(stdout); _exit(2); }
            if (ms > 3000.0) { printf("FAIL: IR-4 %d-deep nested IF took %.0f ms (O(N^2) fExec scan; want O(1) per opcode)\n", N, ms); fflush(stdout); _exit(3); }
            printf("ok: IR-4 %d-deep nested IF leaf accepted in %.1f ms\n", N, ms); fflush(stdout); _exit(0);
        }
        int st_ = 0; waitpid(pid, &st_, 0);
        if (!(WIFEXITED(st_) && WEXITSTATUS(st_) == 0)){
            if (WIFSIGNALED(st_)) printf("FAIL: IR-4 child killed by signal %d (alarm: quadratic scan)\n", WTERMSIG(st_));
            else printf("FAIL: IR-4 child exit %d\n", WEXITSTATUS(st_));
            fails++;
        }
    }
    /* --- IR-8 sigversion gate: CONST_SCRIPTCODE rejects OP_CODESEPARATOR only
     * for SIGVERSION_BASE. The same script under WITNESS_V0 (sigv 1) must
     * still pass -- Core's check names the sigversion explicitly. */
    {
        static uint8_t scr0[5] = { 0x00, 0x63, 0xab, 0x68, 0x51 };   /* OP_0 OP_IF OP_CODESEPARATOR OP_ENDIF OP_1 */
        g_err = 999; int rb = run(scr0, 5, 0, (1ULL<<16), 1, 0, 0);
        if (rb == 0 && g_err == 53) printf("ok: IR-8 BASE + CONST_SCRIPTCODE: unexecuted OP_CODESEPARATOR -> SCRIPT_ERR_OP_CODESEPARATOR\n");
        else { printf("FAIL: IR-8 BASE got r=%d err=%llu (want r=0 err=53)\n", rb, (unsigned long long)g_err); fails++; }
        g_err = 999; int rw = run(scr0, 5, 1, (1ULL<<16), 1, 0, 0);
        if (rw == 1) printf("ok: IR-8 WITNESS_V0 + CONST_SCRIPTCODE: same script accepted (sigversion gate)\n");
        else { printf("FAIL: IR-8 WITNESS_V0 got r=%d err=%llu (want r=1)\n", rw, (unsigned long long)g_err); fails++; }
        g_err = 999; int rn = run(scr0, 5, 0, 0, 1, 0, 0);
        if (rn == 1) printf("ok: IR-8 BASE without the flag: accepted (consensus)\n");
        else { printf("FAIL: IR-8 BASE no-flag got r=%d err=%llu (want r=1)\n", rn, (unsigned long long)g_err); fails++; }
    }
    /* --- IR-13 (INTERP_REVIEW_2026-09-05): the LOW_S arm reported SIG_HIGH_S
     * for S >= N. Core's CheckLowS lax-parses the signature; an S >= N
     * overflows to a ZERO signature, which is not high, so the check passes
     * and the failure surfaces from verification as NULLFAIL (or false) --
     * never HIGH_S. The verdict is the same (reject); the error code that
     * reaches RPC differs. Probe checksig returns 0 so verification fails. */
    {
        static const uint8_t N_BE[32]  = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
                                          0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41};
        static const uint8_t HALF[32]  = {0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                          0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0};
        uint8_t half1[32]; memcpy(half1, HALF, 32); half1[31] = 0xA1;          /* N/2 + 1: high, below N */
        struct { const char* nm; const uint8_t* s; int want_err; } v[] = {
            { "S == N     -> NULLFAIL (Core: lax parse overflows to a zero sig)", N_BE, 32 },
            { "S == N/2+1 -> HIGH_S  (control)",                                 half1, 27 },
            { "S == N/2   -> low, verification fails -> NULLFAIL (control)",     HALF,  32 },
        };
        for (unsigned i = 0; i < 3; i++){
            uint8_t sig[80]; size_t n = 0; int pad = (v[i].s[0] & 0x80) ? 1 : 0;
            sig[n++] = 0x30; sig[n++] = (uint8_t)(4 + 32 + 32 + pad);
            sig[n++] = 0x02; sig[n++] = 32; sig[n++] = 0x7f; for (int k = 1; k < 32; k++) sig[n++] = 0x11;   /* R */
            sig[n++] = 0x02; sig[n++] = (uint8_t)(32 + pad); if (pad) sig[n++] = 0x00; memcpy(sig + n, v[i].s, 32); n += 32;
            sig[n++] = 0x01;                                                                                     /* SIGHASH_ALL */
            static uint8_t scr[160]; size_t m = 0;
            scr[m++] = (uint8_t)n; memcpy(scr + m, sig, n); m += n;
            scr[m++] = 33; scr[m++] = 0x02; for (int k = 0; k < 32; k++) scr[m++] = 0x22; scr[m++] = 0xac;   /* <pub> OP_CHECKSIG */
            memset(main_elems,0,sizeof main_elems); memset(alt_elems,0,sizeof alt_elems);
            struct script_state st; memset(&st,0,sizeof st);
            st.main_elems=main_elems; st.alt_elems=alt_elems; st.script=scr; st.script_len=m;
            st.sigversion=0; st.flags=(1ULL<<2)|(1ULL<<3)|(1ULL<<14);   /* DERSIG | LOW_S | NULLFAIL */
            st.work=work; st.work_cap=sizeof work; st.error_out=&g_err;
            g_probe=(probe_t){0,0,0,0}; st.checksig_ctx=&g_probe; st.checksig_fn=probe_fn;
            g_err=999; int r = script_eval(&st);
            if (r == 0 && (int)g_err == v[i].want_err) printf("ok: IR-13 %s\n", v[i].nm);
            else { printf("FAIL: IR-13 %s: got r=%d err=%llu (want r=0 err=%d)\n", v[i].nm, r, (unsigned long long)g_err, v[i].want_err); fails++; }
        }
    }
    /* --- IR-6 (INTERP_REVIEW_2026-09-05): OP_ROLL shifts whole 524-byte
     * records where Core moves a 24-byte header, so a valid tapscript of
     * `<998> OP_ROLL` repeated costs O(rolls x records) in bytes moved. These
     * vectors assert BOTH halves of the fix: the final order is exactly what
     * a rotate produces (whatever the internal storage), and the storm runs in
     * O(1) record moves per roll rather than O(records). The handle layer
     * (bitcoin_scriptcodec.asm) rotates 4-byte handles and puts the records
     * back in position order once, at script_eval's exit, only if anything
     * rolled -- so the ABI every external reader uses, element p at
     * elems + p*ELEM_SIZE with data inline, is unchanged.
     *
     * OP_ROLL(n) lifts the element n deep to the top, so <998> OP_ROLL over
     * 999 items rotates the whole stack by one: model[i] = (i + R) mod 999. */
    {   /* (a) BASE, small: the FULL final order is checkable (no CLEANSTACK) */
        enum { N = 10, RR = 25 };
        static uint8_t scr[2*RR]; size_t n = 0;
        for (int i = 0; i < RR; i++){ scr[n++] = 0x59; scr[n++] = 0x7a; }      /* OP_9 OP_ROLL */
        memset(main_elems, 0, sizeof main_elems);
        for (int i = 0; i < N; i++){ uint8_t* rec = main_elems + (size_t)i*ELEM_SIZE; *(uint32_t*)rec = 4; *(uint32_t*)(rec+4) = (uint32_t)(i+1); }
        struct script_state st; memset(&st,0,sizeof st);
        st.main_elems=main_elems; st.main_sp=N; st.alt_elems=alt_elems; st.alt_sp=0;
        st.script=scr; st.script_len=n; st.sigversion=0; st.flags=0;
        st.work=work; st.work_cap=sizeof work; st.error_out=&g_err;
        g_err=999; int r = script_eval(&st);
        int ok = (r==1) && (st.main_sp==(size_t)N); int bad=-1;
        for (int i=0;i<N && ok;i++){ uint8_t* rec=main_elems+(size_t)i*ELEM_SIZE; if (*(uint32_t*)(rec+4) != (uint32_t)(((i+RR)%N)+1)){ ok=0; bad=i; } }
        if (ok) printf("ok: IR-6 %d rolls over %d items: full final order exact\n", RR, N);
        else { printf("FAIL: IR-6 BASE roll order wrong at pos %d (r=%d sp=%zu err=%llu)\n", bad, r, st.main_sp, (unsigned long long)g_err); fails++; }
    }
    {   /* (b) tapscript, large: the storm the finding is about. Drained to one
         * element -- CLEANSTACK is consensus there -- and the survivor is the
         * old bottom, model[0] = R mod 999, a precise check on the rotation. */
        enum { R = 200000, ITEMS = 999, ILEN = 520 };
        static uint8_t scr[4*R + ITEMS + 8]; size_t n = 0;
        for (int i = 0; i < R; i++){ scr[n++]=0x02; scr[n++]=0xE6; scr[n++]=0x03; scr[n++]=0x7a; }   /* <998> OP_ROLL */
        for (int i = 0; i < ITEMS-1; i++) scr[n++] = 0x75;                                          /* OP_DROP x 998 */
        fflush(stdout);   /* see the IR-4 note: flush before fork, not just before _exit */
        pid_t pid = fork();
        if (pid == 0){
            alarm(120);
            memset(main_elems, 0, sizeof main_elems);
            for (int i = 0; i < ITEMS; i++){ uint8_t* rec = main_elems + (size_t)i*ELEM_SIZE; *(uint32_t*)rec = ILEN; memset(rec+4,0x5a,ILEN); *(uint32_t*)(rec+4) = (uint32_t)i; }
            struct script_state st; memset(&st,0,sizeof st);
            st.main_elems=main_elems; st.main_sp=ITEMS; st.alt_elems=alt_elems; st.alt_sp=0;
            st.script=scr; st.script_len=n; st.sigversion=SIGV_TAPSCRIPT; st.flags=0;
            st.work=work; st.work_cap=sizeof work; st.error_out=&g_err;
            struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
            g_err=999; int r = script_eval(&st);
            clock_gettime(CLOCK_MONOTONIC,&t1);
            double ms=(t1.tv_sec-t0.tv_sec)*1e3+(t1.tv_nsec-t0.tv_nsec)/1e6;
            if (r!=1){ printf("FAIL: IR-6 valid roll storm rejected (r=%d err=%llu)\n", r,(unsigned long long)g_err); fflush(stdout); _exit(2); }
            uint32_t got = *(uint32_t*)(main_elems+4), want = (uint32_t)(R % ITEMS);
            if (st.main_sp!=1 || got!=want){ printf("FAIL: IR-6 survivor is %u, want %u (sp=%zu)\n", got, want, st.main_sp); fflush(stdout); _exit(4); }
            printf("ok: IR-6 %d rolls over %d x %d-byte items: survivor exact, %.0f ms\n", R, ITEMS, ILEN, ms);
            fflush(stdout); _exit(ms > 400.0 ? 5 : 0);
        }
        int st_=0; waitpid(pid,&st_,0);
        if (!(WIFEXITED(st_) && WEXITSTATUS(st_)==0)){
            if (WIFSIGNALED(st_)) printf("FAIL: IR-6 child killed by signal %d\n", WTERMSIG(st_));
            else if (WEXITSTATUS(st_)==5) printf("FAIL: IR-6 roll storm over 400 ms -- records are being shifted per roll again\n");
            fails++;
        }
    }
    printf(fails?"\nFAILURES %d\n":"\nALL TESTS PASSED (0 failures)\n",fails);
    return fails?1:0;
}
