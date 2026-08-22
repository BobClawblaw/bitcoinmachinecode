/* test_tapscript_interp.c -- drive the asm script interpreter (bitcoin_interp.asm)
 * over Bitcoin Core's BIP342 / ExecuteWitnessScript interpreter-level semantics:
 *   - OP_SUCCESSx pre-scan short-circuits success (and DISCOURAGE_OP_SUCCESS rejects)
 *   - empty-stack / non-cleanstack treatment: tapscript must end with exactly one
 *     truthy element, else CLEANSTACK / EVAL_FALSE
 *   - OP_CHECKSIGVERIFY is VALID under tapscript (BIP342 re-specifies it for
 *     schnorr; only CHECKMULTISIG(VERIFY) are disabled) -- fixed for incident #16
 *   - OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY -> TAPSCRIPT_CHECKMULTISIG
 *   - OP_CHECKSIGADD is valid ONLY under tapscript (BAD_OPCODE in BASE)
 * Each check compares the interpreter verdict + error code against Core's
 * expected label from src/script/interpreter.cpp ExecuteWitnessScript.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ELEM_SIZE 528
#define ELEM_DATA_OFF 4
#define MAX_STACK 1000

/* struct script_state matches bitcoin_interp.asm offsets */
struct script_state {
    uint8_t* main_elems;      /* +0  */
    size_t   main_sp;         /* +8  */
    uint8_t* alt_elems;       /* +16 */
    size_t   alt_sp;          /* +24 */
    uint8_t* script;          /* +32 */
    size_t   script_len;      /* +40 */
    int      sigversion;      /* +48 (int! 4 bytes) */
    uint64_t flags;           /* +56 */
    uint8_t* work;            /* +64 */
    size_t   work_cap;        /* +72 */
    uint64_t* error_out;      /* +80 */
    void*    checksig_ctx;    /* +88 */
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t,
                            const uint8_t*, size_t,
                            const struct { const uint8_t* p; size_t n; }*); /* +96 */
};

extern int script_eval(struct script_state* st);
extern int is_opsuccess_c(int opcode);

static uint8_t main_elems[MAX_STACK*ELEM_SIZE];
static uint8_t alt_elems[MAX_STACK*ELEM_SIZE];
static uint64_t g_err;
static int g_fails = 0;

static int hex2b(const char* h, uint8_t* out){
    int n=0;
    for(const char*p=h;p[0]&&p[1];){
        while(*p==' '||*p=='\t') p++;
        if(!p[1]) break;
        unsigned v; sscanf(p,"%2x",&v); out[n++]=(uint8_t)v; p+=2;
    }
    return n;
}

/* Run a bare script for tapscript (sigversion=2) over an optional init stack. */
static int run_script(const char* script_hex,
                      const char* const* init, const int* linit, int ninit,
                      int sigversion, uint64_t flags)
{
    memset(main_elems,0,sizeof(main_elems));
    memset(alt_elems,0,sizeof(alt_elems));
    for(int i=0;i<ninit;i++){
        int n=linit[i]; uint8_t buf[520];
        hex2b(init[i], buf);
        uint8_t* rec = main_elems + i*ELEM_SIZE;
        ((uint32_t*)rec)[0]=(uint32_t)n;
        memcpy(rec+ELEM_DATA_OFF, buf, n);
    }
    static uint8_t script[20000];
    size_t slen = hex2b(script_hex, script);
    struct script_state st;
    st.main_elems=main_elems; st.main_sp=(size_t)ninit;
    st.alt_elems=alt_elems; st.alt_sp=0;
    st.script=script; st.script_len=slen;
    st.sigversion=sigversion; st.flags=flags;
    st.work=NULL; st.work_cap=0;
    st.error_out=&g_err; g_err=0;
    st.checksig_ctx=NULL; st.checksig_fn=NULL;
    /* ensure the struct is fully initialized so no padding is ever read */
    memset(&st, 0, sizeof(st));
    st.main_elems=main_elems; st.main_sp=(size_t)ninit;
    st.alt_elems=alt_elems; st.alt_sp=0;
    st.script=script; st.script_len=slen;
    st.sigversion=sigversion; st.flags=flags;
    st.work=NULL; st.work_cap=0;
    st.error_out=&g_err; g_err=0;
    st.checksig_ctx=NULL; st.checksig_fn=NULL;
    return script_eval(&st);
}

/* Error codes come from the GENERATED header, never a local copy.
 * This file used to carry its own enum of the interpreter's old private
 * numbering. When bitcoin_interp.asm was corrected to emit Bitcoin Core's
 * own ScriptError values, all twelve of this test's expectations were
 * suddenly wrong -- the test was stale, not the interpreter. Sharing one
 * generated source removes that failure mode entirely.
 * Regenerate with validation/gen_script_error_defines.py. */
#include "script_error_codes.h"
#define FLAG_DISCOURAGE_OP_SUCCESS (1ull<<18)
#define FLAG_MINIMALIF (1ull<<13)
#define SIGV_BASE 0
#define SIGV_WITNESS_V0 1
#define SIGV_TAPSCRIPT 2

/* Check: eval `script` at sigversion/flags -> expect (ok==exp_ok && err==exp_err). */
static void check_run(const char* name, const char* script,
                      int sigv, uint64_t flags, int exp_ok, uint64_t exp_err)
{
    uint64_t err_save = g_err;
    int r = run_script(script, NULL, NULL, 0, sigv, flags);
    if (r==exp_ok && g_err==exp_err) {
        printf("  ok  %-34s r=%d err=%llu\n", name, r, (unsigned long long)g_err);
    } else {
        printf("  FAIL %-28s r=%d err=%llu (want r=%d err=%llu)\n", name, r,
               (unsigned long long)g_err, exp_ok, (unsigned long long)exp_err);
        g_fails++;
    }
    g_err = err_save;
}

int main(void)
{
    printf("is_opsuccess spot checks (Core IsOpSuccess):\n");
    /* OP_RESERVED(0x50=80), OP_VER(0x62=98), OP_CAT(0x7e=126) */
    if (!is_opsuccess_c(80) || !is_opsuccess_c(98) || !is_opsuccess_c(126) ||
        !is_opsuccess_c(128) || !is_opsuccess_c(0x86) || !is_opsuccess_c(0x8a) ||
        !is_opsuccess_c(0x8e) || !is_opsuccess_c(0x99) || !is_opsuccess_c(0xbb) ||
        !is_opsuccess_c(0xfe)) { printf("  FAIL is_opsuccess positives\n"); g_fails++; }
    /* valid tapscript opcodes are NOT success: OP_1(0x51), OP_ADD(0x93), OP_CHECKSIGADD(0xba) */
    if (is_opsuccess_c(0x51) || is_opsuccess_c(0x93) || is_opsuccess_c(0xba) ||
        is_opsuccess_c(0xac) || is_opsuccess_c(0xb1)) { printf("  FAIL is_opsuccess negatives\n"); g_fails++; }

    printf("tapscript OP_SUCCESSx semantics (BIP342 ExecuteWitnessScript):\n");
    check_run("bare OP_SUCCESSx (0xbb)",    "bb", SIGV_TAPSCRIPT, 0, 1, SCRIPT_ERR_OK);
    check_run("OP_1 OP_SUCCESSx",           "51bb", SIGV_TAPSCRIPT, 0, 1, SCRIPT_ERR_OK);
    check_run("OP_SUCCESSx w/ discourage",  "51bb", SIGV_TAPSCRIPT, FLAG_DISCOURAGE_OP_SUCCESS, 0, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
    check_run("push then OP_SUCCESSx",      "02aabb", SIGV_TAPSCRIPT, 0, 1, SCRIPT_ERR_OK);
    check_run("SUCCESS in dead branch",     "00 63 bb 68", SIGV_TAPSCRIPT, 0, 1, SCRIPT_ERR_OK);

    printf("tapscript cleanstack / empty-stack treatment:\n");
    check_run("empty script + empty stack", "", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_CLEANSTACK);
    check_run("OP_0 single (false top)",    "00", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_EVAL_FALSE);
    check_run("OP_1 single (valid)",        "51", SIGV_TAPSCRIPT, 0, 1, SCRIPT_ERR_OK);
    check_run("two items -> non-clean",     "5151", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_CLEANSTACK);
    check_run("push+2drop leaves empty",    "51516d", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_CLEANSTACK);
    check_run("empty via IF empty true",    "516368", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_CLEANSTACK);
    check_run("IF(true){1} -> [1] valid",   "51635168", SIGV_TAPSCRIPT, 0, 1, SCRIPT_ERR_OK);

    printf("tapscript gating (opcode set):\n");
    /* incident #16: CHECKSIGVERIFY is VALID under tapscript, not BAD_OPCODE.
     * OP_0 (empty sig) <32-byte pubkey> OP_CHECKSIGVERIFY: empty sig makes
     * success=false, Core skips the schnorr check, so this is a clean
     * SCRIPT_ERR_CHECKSIGVERIFY failure -- identical to Core's EvalScript. */
    check_run("CHECKSIGVERIFY valid; empty-sig fails", "00200000000000000000000000000000000000000000000000000000000000000000ad", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_CHECKSIGVERIFY);
    check_run("CHECKMULTISIG forbidden",    "5151ae", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);
    check_run("CHECKMULTISIGVERIFY forb.",  "5151af", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);
    check_run("CHECKSIGADD valid (undeflow->stackerr)", "ba", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_INVALID_STACK_OPERATION);
    check_run("CHECKSIGADD BAD in BASE",    "ba", SIGV_BASE, 0, 0, SCRIPT_ERR_BAD_OPCODE);
    check_run("undefined 0xbb BAD in BASE", "bb", SIGV_BASE, 0, 0, SCRIPT_ERR_BAD_OPCODE);

    printf("tapscript MINIMALIF (consensus rule, unconditional per Core):\n");
    /* tapscript requires the IF/NOTIF condition to be empty or exactly [0x01];
       non-minimal conditions fail with TAPSCRIPT_MINIMALIF regardless of flags. */
    check_run("MINIMALIF non-minimal cond",  "020100635168", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);
    check_run("MINIMALIF 1-byte non-1 cond", "0151635168", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);
    check_run("MINIMALIF OP_0 cond ok",      "00635168", SIGV_TAPSCRIPT, 0, 0, SCRIPT_ERR_CLEANSTACK);
    check_run("MINIMALIF OP_1 cond ok",      "51635168", SIGV_TAPSCRIPT, 0, 1, SCRIPT_ERR_OK);

    printf("\n%s\n", g_fails ? "TAPSCRIPT_INTERP FAILED" : "TAPSCRIPT_INTERP PASSED");
    return g_fails ? 1 : 0;
}
