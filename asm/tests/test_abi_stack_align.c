/* test_abi_stack_align.c -- SysV AMD64 16-byte stack alignment, at runtime.
 *
 * Incident #18 (b18114b) and incident #20 (this branch) are the same bug twice:
 * an assembly function reserves a frame whose size leaves RSP at 8 mod 16, so
 * every nested `call` violates the ABI. Assembly callees never notice (nothing
 * in this tree uses a 16-byte-aligned stack operand), so it stays invisible
 * until a C function lands on that path -- then glibc's vsnprintf executes
 *
 *     movaps %xmm0,-0xc0(%rbp)
 *
 * on a misaligned frame: #GP, delivered as SIGSEGV with si_addr == NULL.
 *
 * The static side of the guard is scripts/abi_stack_audit.py (`make abi-check`),
 * which proves the property for every call site in every .asm source. This is
 * the runtime half: it exercises the one place where assembly calls back OUT to
 * C through a function pointer -- script_eval's checksig_fn -- and asserts the
 * ABI both directly (measured RSP parity) and destructively (a printf-family
 * call in the callback, which is exactly what killed the serve child in #18).
 *
 * Before the bitcoin_interp.asm fix, case 1 reported 8 and case 2 SIGSEGV'd.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* abi_caller_rsp() -> the RSP its caller held at the `call` instruction.
 * Written in assembly because any C prologue would move RSP first. */
__asm__(".text\n"
        ".globl abi_caller_rsp\n"
        ".type abi_caller_rsp,@function\n"
        "abi_caller_rsp:\n"
        "    lea 8(%rsp),%rax\n"
        "    ret\n"
        ".size abi_caller_rsp,.-abi_caller_rsp\n");
extern unsigned long abi_caller_rsp(void);

#define ELEM_SIZE     528
#define ELEM_DATA_OFF 4
#define MAX_STACK     1000

/* struct script_state -- matches bitcoin_interp.asm */
struct script_state {
    uint8_t*  main_elems;   /* +0  */
    size_t    main_sp;      /* +8  */
    uint8_t*  alt_elems;    /* +16 */
    size_t    alt_sp;       /* +24 */
    uint8_t*  script;       /* +32 */
    size_t    script_len;   /* +40 */
    int       sigversion;   /* +48 */
    uint64_t  flags;        /* +56 */
    uint8_t*  work;         /* +64 */
    size_t    work_cap;     /* +72 */
    uint64_t* error_out;    /* +80 */
    void*     checksig_ctx; /* +88 */
    void*     checksig_fn;  /* +96 */
};
extern int script_eval(struct script_state* st);

static uint8_t g_main[MAX_STACK * ELEM_SIZE];
static uint8_t g_alt[MAX_STACK * ELEM_SIZE];
static uint64_t g_err;
static long g_seen_parity = -1;
static char g_log[128];
static int g_fails;

static uint64_t cb_measure(void* c, const uint8_t* s, size_t sn,
                           const uint8_t* p, size_t pn, const void* sc)
{
    g_seen_parity = (long)(abi_caller_rsp() & 15UL);
    (void)c; (void)s; (void)sn; (void)p; (void)pn; (void)sc;
    return 1;
}

/* The #18 mechanism itself: a printf-family call from the C callback. */
static uint64_t cb_snprintf(void* c, const uint8_t* s, size_t sn,
                            const uint8_t* p, size_t pn, const void* sc)
{
    snprintf(g_log, sizeof g_log, "sig=%zu pub=%zu ctx=%p sc=%p", sn, pn, c, sc);
    (void)s; (void)p;
    return 1;
}

/* stack: <1-byte sig> <33-byte pubkey>; script: a single OP_CHECKSIG (0xac). */
static int run_checksig(void* fn)
{
    static uint8_t script[1] = { 0xac };
    struct script_state st;

    memset(g_main, 0, sizeof g_main);
    memset(g_alt, 0, sizeof g_alt);
    ((uint32_t*)(g_main + 0 * ELEM_SIZE))[0] = 1;
    g_main[0 * ELEM_SIZE + ELEM_DATA_OFF] = 0x01;
    ((uint32_t*)(g_main + 1 * ELEM_SIZE))[0] = 33;
    g_main[1 * ELEM_SIZE + ELEM_DATA_OFF] = 0x02;

    memset(&st, 0, sizeof st);
    st.main_elems = g_main; st.main_sp = 2;
    st.alt_elems  = g_alt;  st.alt_sp  = 0;
    st.script = script; st.script_len = sizeof script;
    st.sigversion = 0; st.flags = 0;
    st.error_out = &g_err; g_err = 0;
    st.checksig_ctx = NULL; st.checksig_fn = fn;
    return script_eval(&st);
}

static void check(const char* name, int ok, const char* detail)
{
    printf("%-46s %s%s%s\n", name, ok ? "PASS" : "FAIL",
           detail && *detail ? "  " : "", detail ? detail : "");
    if (!ok) g_fails++;
}

int main(void)
{
    char buf[96];

    /* 0. The probe itself: C calls assembly, so this must be 0 by definition.
     *    If this fails the compiler, not the assembly, is at fault. */
    snprintf(buf, sizeof buf, "rsp%%16=%lu", abi_caller_rsp() & 15UL);
    check("probe sanity: C -> asm call is 16-aligned",
          (abi_caller_rsp() & 15UL) == 0, buf);

    /* 1. script_eval -> interp_checksig -> checksig_fn.  The ABI requires
     *    RSP == 0 mod 16 at the `call qword [r12+96]`. */
    (void)run_checksig((void*)cb_measure);
    snprintf(buf, sizeof buf, "rsp%%16=%ld (was 8 before the fix)",
             g_seen_parity);
    check("script_eval -> C checksig_fn is 16-aligned",
          g_seen_parity == 0, buf);

    /* 2. The destructive form: a printf in the callback. On a misaligned frame
     *    glibc's vsnprintf faults on `movaps %xmm0,-0xc0(%rbp)` and this
     *    process dies with SIGSEGV / si_addr == NULL instead of printing. */
    g_log[0] = 0;
    (void)run_checksig((void*)cb_snprintf);
    check("printf-family call from that callback survives",
          strncmp(g_log, "sig=1 pub=33", 12) == 0, g_log);

    printf("\n%s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASSED", g_fails);
    return g_fails ? 1 : 0;
}
