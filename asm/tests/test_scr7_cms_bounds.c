/* tests/test_scr7_cms_bounds.c -- SCR-7 (audit 2026-09-03): OP_CHECKMULTISIG
 * must fail with SCRIPT_ERR_INVALID_STACK_OPERATION before it reads an
 * operand that is not there.
 *
 * WHY A GUARD PAGE. stack_elem_ptr(&sp, elems, sp-k) is documented "No bounds
 * check" (bitcoin_scriptcodec.asm) and multiplies its index straight into a
 * pointer; with sp < k it returns a record BELOW main_elems. The stack buffers
 * are 528,000-byte BMC_TLS_BUF allocations, so what lives at
 * main_elems - 528 depends on allocation order (in sv_verify_script it is
 * copy_e; in the witness/tapscript paths, whatever the allocator put there).
 * A zeroed static array -- like tests/test_interp.c's main_elems -- makes the
 * out-of-range read LOOK harmless (len=0 -> decodes to 0 -> the later depth
 * check errors 18 anyway), which is exactly why that suite could not see this.
 * Here the usable page starts flush against a PROT_NONE page: the very first
 * below-buffer record access faults, and reaching the fault is the assertion.
 *
 * The assertion set:
 *   1. OP_16 OP_CHECKMULTISIG on an EMPTY stack -- Core check 1 (size < 1).
 *   2. stack [1] + OP_CHECKMULTISIG -- Core check 2 (size < nKeys+2): the n
 *      operand reads fine, m is below the bottom.
 *   3. stack [1, 1] + OP_CHECKMULTISIG -- Core check 2 again (need 3).
 *   4. The degenerate-but-legal operands must NOT fault: a full 0-of-0
 *      dummy/m/n run (4 elements) must complete without touching the guard.
 * All four must return r=0 (script invalid) or r=1 with no fault; NONE may
 * fault. The error code is also pinned to 18 for 1-3, matching Core
 * (interpreter.cpp set_error(SCRIPT_ERR_INVALID_STACK_OPERATION)).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define ELEM_SIZE 528
#define ELEM_DATA_OFF 4
#define MAX_STACK 1000

struct sc_slice { const uint8_t* p; size_t n; };
struct script_state {
    uint8_t* main_elems;      /* +0  */
    size_t   main_sp;         /* +8  */
    uint8_t* alt_elems;       /* +16 */
    size_t   alt_sp;          /* +24 */
    uint8_t* script;          /* +32 */
    size_t   script_len;      /* +40 */
    int      sigversion;      /* +48 */
    uint64_t flags;           /* +56 */
    uint8_t* work;            /* +64 */
    size_t   work_cap;        /* +72 */
    uint64_t* error_out;      /* +80 */
    void*    checksig_ctx;    /* +88 */
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t,
                            const uint8_t*, size_t,
                            const struct sc_slice*); /* +96 */
};

extern int script_eval(struct script_state* st);

static uint8_t alt_elems[MAX_STACK*ELEM_SIZE];
static uint64_t g_err;
static int failures=0;

/* the guarded main-elements buffer: usable records START flush against a
 * PROT_NONE page, so any record index < 0 faults immediately. */
static uint8_t* g_stack_lo;      /* first usable record (page start) */
static size_t   g_stack_cap;     /* records available above it */

static void guard_init(void){
    long pg = sysconf(_SC_PAGESIZE);
    size_t need = (size_t)MAX_STACK * ELEM_SIZE;
    size_t pages = (need + (size_t)pg - 1) / (size_t)pg;
    g_stack_cap = pages * (size_t)pg / ELEM_SIZE;
    /* [guard][data pages] */
    size_t total = (pages + 1) * (size_t)pg;
    uint8_t* m = (uint8_t*)mmap(0, total, PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED){ perror("mmap"); exit(1); }
    if (mprotect(m, (size_t)pg, PROT_NONE)){ perror("mprotect"); exit(1); }
    g_stack_lo = m + pg;
}

static void ck(const char* l,int cond){
    if(cond) printf("ok  : %s\n",l);
    else { printf("FAIL: %s\n",l); failures++; }
}

static int run(const char* script_hex, const uint8_t init[][8], const int* li, int ninit){
    memset(g_stack_lo, 0, (size_t)MAX_STACK*ELEM_SIZE);
    memset(alt_elems, 0, sizeof alt_elems);
    uint8_t script[64]; size_t slen=0;
    for (const char* p=script_hex; p[0]&&p[1]; p+=2){ unsigned v; sscanf(p,"%2x",&v); script[slen++]=(uint8_t)v; }
    for (int i=0;i<ninit;i++){
        uint8_t* rec = g_stack_lo + (size_t)i*ELEM_SIZE;
        ((uint32_t*)rec)[0] = (uint32_t)li[i];
        memcpy(rec+ELEM_DATA_OFF, init[i], (size_t)li[i]);
    }
    struct script_state st;
    st.main_elems=g_stack_lo; st.main_sp=(size_t)ninit;
    st.alt_elems=alt_elems;   st.alt_sp=0;
    st.script=script; st.script_len=slen;
    st.sigversion=0; st.flags=0;
    st.work=NULL; st.work_cap=0;
    st.error_out=&g_err; g_err=0;
    st.checksig_ctx=NULL; st.checksig_fn=NULL;
    return script_eval(&st);
}

int main(void){
    guard_init();

    /* 1. empty stack */
    {
        int r = run("60ae", NULL, NULL, 0);           /* OP_16 OP_CHECKMULTISIG */
        ck("empty stack + OP_16 OP_CHECKMULTISIG: no fault, returns invalid", r==0);
        ck("  -> SCRIPT_ERR_INVALID_STACK_OPERATION (18)", g_err==18);
    }
    /* 2. stack [1]: n reads, m below the bottom */
    {
        const uint8_t in[1][8] = {{0x01,0,0,0,0,0,0,0}};
        int li[1]={1};
        int r = run("ae", in, li, 1);
        ck("stack[1] + CHECKMULTISIG: no fault", r==0);
        ck("  -> INVALID_STACK_OPERATION (18)", g_err==18);
    }
    /* 3. stack [1,1]: need nKeys+2 = 3 */
    {
        const uint8_t in[2][8] = {{0x01,0},{0x01,0}};
        int li[2]={1,1};
        int r = run("ae", in, li, 2);
        ck("stack[1,1] + CHECKMULTISIG: no fault", r==0);
        ck("  -> INVALID_STACK_OPERATION (18)", g_err==18);
    }
    /* 4. a full-shape 0-of-0: [dummy][m=0][n=0] = 3 elements + the dummy = 4.
     * Layout bottom..top: dummy, m, pubkeys..., n. For 0-of-0: dummy, m=OP_0,
     * n=OP_0 -> 3 elements, need = 0+0+2 = 2, need+1 = 3 = exactly sp. This
     * must NOT fault and must be a valid (if false) execution: pushes 0. */
    {
        const uint8_t in[3][8] = {{0},{0},{0}};       /* dummy '', m '', n '' */
        int li[3]={0,0,0};
        int r = run("ae", in, li, 3);
        ck("full 0-of-0 shape: no fault (legal degenerate multisig)", r==1 || r==0);
    }

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
