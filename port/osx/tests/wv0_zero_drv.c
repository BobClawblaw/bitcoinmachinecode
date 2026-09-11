/* wv0_zero_drv.c -- faithful differential driver for the WV0 zero-length
 * initial-stack-element divergence (bmc_osx; testnet4 h=124,032 + h=124,845).
 *
 * The daemon's p2wsh path (sv_verify_witness_v0) hands script_eval witness
 * items [0..n-2] as the initial stack. tx#167 of block 124,845 spends four
 * p2wsh outputs with witness {empty,empty,empty,71B-DER-sig,121B-script} --
 * THREE zero-length elements at the bottom of the initial stack. The x86
 * interpreter verifies those inputs (the block is consensus-valid); the osx
 * twin returns EVAL_FALSE at the final EQUAL, and the harness has crashed in
 * hnd_end's cycle walk with the same elements (element-record corruption).
 *
 * This driver replays the REAL script + REAL 71B signature with a stubbed
 * checksig (verdict via WCS_CS env, default 1 = valid, matching reality) and
 * a battery of micro-cases that poke zero-length elements through the stack
 * machinery (DUP/SWAP/DROP/VERIFY, hashes of empty, IF/ELSE, CHECKSIG with
 * empty sig or empty pubkey, and the real script's own opcode prefixes).
 *
 * Daemon-faithful state reuse: like the daemon worker, the element arena is
 * a long-lived buffer that is NEVER re-zeroed between runs (only pre-filled
 * with a fixed pattern once), so stale bytes beyond each element's length
 * are identical run-to-run on both arches. The REAL case runs 200x in a row
 * on one thread to give the hnd/TLS state the same workout the daemon gives
 * it. Output is deterministic; DIFF osx vs x86 output line-by-line -- the
 * diff IS the oracle (do not reason from single-arch output).
 *
 * Build (osx, from asm/):
 *   cc -O2 -arch arm64 -I. -Idaemon -Itests -I../port/osx/compat \
 *     -D_DARWIN_C_SOURCE -o /tmp/wv0x_osx ../port/osx/tests/wv0_zero_drv.c \
 *     ../port/osx/bitcoin_interp.S ../port/osx/bitcoin_scriptcodec.S \
 *     ../port/osx/sha256.S ../port/osx/bitcoin_hash.S sighash_twin.c \
 *     sha1_twin.c ripemd160_twin.c ../port/osx/tls_bitcoin_interp.c \
 *     ../port/osx/tls_bitcoin_scriptcodec.c
 * Build (x86, on .242 from asm/):
 *   cc -O2 -o /tmp/wv0x_x86 wv0_zero_drv.c bitcoin_interp.o \
 *     bitcoin_scriptcodec.o bitcoin_sighash.o sha256.o sha1.o ripemd160.o
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ELEM_SIZE 528
#define ELEM_DATA_OFF 4
#define MAX_STACK 1000
#define SIGV_WITNESS_V0 1

struct sc_slice { const uint8_t* p; size_t n; };
struct script_state {            /* offsets must match bitcoin_interp.asm */
    uint8_t* main_elems;         /* +0  */
    size_t   main_sp;            /* +8  */
    uint8_t* alt_elems;          /* +16 */
    size_t   alt_sp;             /* +24 */
    uint8_t* script;             /* +32 */
    size_t   script_len;         /* +40 */
    int      sigversion;         /* +48 (int; 4 bytes pad) */
    uint64_t flags;              /* +56 */
    uint8_t* work;               /* +64 */
    size_t   work_cap;           /* +72 */
    uint64_t* error_out;         /* +80 */
    void*    checksig_ctx;       /* +88 */
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t,
                            const uint8_t*, size_t,
                            const struct sc_slice*); /* +96 */
};

extern int script_eval(struct script_state* st);

/* crash reporter: si_addr + faulting PC + backtrace offsets */
#include <signal.h>
#include <sys/ucontext.h>
#include <execinfo.h>
#include <unistd.h>
static void crash_handler(int sig, siginfo_t* si, void* uc){
    ucontext_t* c = (ucontext_t*)uc;
    unsigned long pc = c->uc_mcontext->__ss.__pc;
    fprintf(stderr, "\n*** SIGNAL %d si_addr=%p pc=0x%lx\n", sig, si->si_addr, pc);
    void* bt[32];
    int n = backtrace(bt, 32);
    backtrace_symbols_fd(bt, n, 2);
    _exit(99);
}

static uint8_t  main_elems[MAX_STACK*ELEM_SIZE];
static uint8_t  alt_elems[MAX_STACK*ELEM_SIZE];
static uint8_t  script_buf[20000];
static uint8_t  work_buf[1<<20];          /* daemon uses a 1 MiB work arena */
static uint64_t g_err;
static unsigned long g_cs_calls;

#ifdef BMC_OPTRACE
/* per-opcode trace hook wired into bitcoin_interp.S (-DBMC_OPTRACE).
 * The asm's `bl __dbg_op` is the Mach-O symbol for C `_dbg_op`. */
void _dbg_op(unsigned op){
    if (getenv("WCS_TRACE")) fprintf(stderr, "  op %u\n", op);
    if (getenv("WCS_TRACE2")){
        fprintf(stderr, "  op %u recs:", op);
        for (int i = 0; i < 6; i++){
            const uint8_t* rec = main_elems + (size_t)i*ELEM_SIZE;
            uint32_t n; memcpy(&n, rec, 4);
            fprintf(stderr, " [%u:", n);
            for (uint32_t k = 0; k < n && k < 6; k++) fprintf(stderr, "%02x", rec[ELEM_DATA_OFF+k]);
            fprintf(stderr, "]");
        }
        fprintf(stderr, "\n");
    }
}
#endif

/* stub checksig -- the real sigs ARE valid, so default verdict 1 */
static uint64_t stub_checksig(void* ctx, const uint8_t* sig, size_t siglen,
                              const uint8_t* pub, size_t publen,
                              const struct sc_slice* sl){
    (void)ctx; (void)sl;
    g_cs_calls++;
    if (getenv("WCS_VERBOSE"))
        fprintf(stderr, "    [cs#%lu] siglen=%zu sig[0..3]=%02x,%02x,%02x,%02x "
                "publen=%zu pub[0]=%02x sc.n=%zu\n",
                g_cs_calls, siglen, siglen?sig[0]:0, siglen>1?sig[1]:0,
                siglen>2?sig[2]:0, siglen>3?sig[3]:0, publen, publen?pub[0]:0,
                sl?sl->n:0);
    return (uint64_t)(getenv("WCS_CS") ? atoi(getenv("WCS_CS")) : 1);
}

static void dump_stack(const char* tag, int r, struct script_state* st){
    printf("  %s r=%d err=%llu sp=%zu cs=%lu\n", tag, r,
           (unsigned long long)g_err, st->main_sp, g_cs_calls);
    /* records: len u32 at +0, data at +4; direct positions (no rolls in any
     * case here, so hnd_tab is identity) */
    for (size_t i = 0; i < st->main_sp && i < 8; i++){
        const uint8_t* rec = st->main_elems + i*ELEM_SIZE;
        uint32_t n; memcpy(&n, rec, 4);
        if (n > 520) n = 520;
        printf("    e[%zu] len=%u:", i, n);
        for (uint32_t k = 0; k < n && k < 48; k++) printf(" %02x", rec[ELEM_DATA_OFF+k]);
        printf("\n");
    }
}

static int hex1(const char* h, uint8_t* out){
    int n = 0;
    for (const char* p = h; p[0] && p[1]; p += 2){
        unsigned v;
        if (sscanf(p, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
    }
    return n;
}

/* run one case: init stack items (hex, "" = zero-length), script hex */
static void run_case(const char* name, const char* const* items,
                     const int* lens, int ninit, const char* script_hex){
    struct script_state st;
    memset(&st, 0, sizeof st);
    size_t sp = 0;
    static uint8_t tmp[520];
    for (int i = 0; i < ninit; i++){
        int n = lens[i];
        hex1(items[i], tmp);
        uint8_t* rec = main_elems + sp*ELEM_SIZE;
        memcpy(rec, &n, 4);
        memcpy(rec + ELEM_DATA_OFF, tmp, (size_t)n);
        sp++;
    }
    size_t slen = hex1(script_hex, script_buf);
    st.main_elems = main_elems; st.main_sp = sp;
    st.alt_elems  = alt_elems;  st.alt_sp = 0;
    st.script = script_buf;     st.script_len = slen;
    st.sigversion = SIGV_WITNESS_V0; st.flags = 0;
    st.work = work_buf; st.work_cap = sizeof work_buf;
    st.error_out = &g_err; g_err = 0;
    st.checksig_ctx = NULL; st.checksig_fn = stub_checksig;
    int r = script_eval(&st);
    dump_stack(name, r, &st);
}

/* ---------------- the real block-124,845 tx#167 vin#0 data ---------------- */
#define PK1 "0221fe6f04ce9f0995c35153e3dec5be19d4256af10921c9021a744da597f34bd0"
#define PK2 "03246f3cc25809c208c9ea70b5879e670544b8beb2ae6e661d2995066ab8226559"
#define PK3 "0315b9eac6b19b395060446ffa4f38b89e846bb0192ee9cace5170b99a9139dfe9"
#define SIG71 "30440220280579930a3383d7cf91febf8b2561bd3213c20137a823550c4bbb462b2d22e902207d1d17cec2a6e7175b25fef4c0aa61e083bb5898326b34691c746526e4c41c0101"
#define SCRIPT121 \
  "21" PK1 "ac7c" \
  "21" PK2 "ac937c" \
  "21" PK3 "ac937c" \
  "630067011eb29268935287"

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = crash_handler; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, NULL); sigaction(SIGSEGV, &sa, NULL);
    /* daemon-faithful: arena pre-filled once, never re-zeroed */
    memset(main_elems, 0xAA, sizeof main_elems);
    memset(alt_elems, 0xAA, sizeof alt_elems);

    /* ---- the REAL failing input ---- */
    const char* real_items[4] = { "", "", "", SIG71 };
    const int   real_lens[4]  = { 0, 0, 0, 71 };
    for (int it = 0; it < 200; it++){
        struct script_state st;
        memset(&st, 0, sizeof st);
        for (int i = 0; i < 4; i++){
            uint8_t tmp[520];
            int n = real_lens[i];
            hex1(real_items[i], tmp);
            uint8_t* rec = main_elems + i*ELEM_SIZE;
            memcpy(rec, &n, 4);
            memcpy(rec + ELEM_DATA_OFF, tmp, (size_t)n);
        }
        size_t slen = hex1(SCRIPT121, script_buf);
        st.main_elems = main_elems; st.main_sp = 4;
        st.alt_elems  = alt_elems;  st.alt_sp = 0;
        st.script = script_buf;     st.script_len = slen;
        st.sigversion = SIGV_WITNESS_V0; st.flags = 0;
        st.work = work_buf; st.work_cap = sizeof work_buf;
        st.error_out = &g_err; g_err = 0;
        st.checksig_ctx = NULL; st.checksig_fn = stub_checksig;
        int r = script_eval(&st);
        if (it == 0 || it == 199)
            printf("REAL it=%d r=%d err=%llu sp=%zu cs=%lu\n", it, r,
                   (unsigned long long)g_err, st.main_sp, g_cs_calls);
    }

    /* ---- micro cases (same arena, same thread, state carried over) ---- */
    { const char* it[] = { "" };            int ln[] = { 0 };
      run_case("dup_empty", it, ln, 1, "76"); }
    { const char* it[] = { "", "" };        int ln[] = { 0, 0 };
      run_case("dup_add", it, ln, 2, "7693"); }
    { const char* it[] = { "", SIG71 };     int ln[] = { 0, 71 };
      run_case("swap_empty_sig", it, ln, 2, "7c"); }
    { const char* it[] = { "", "", SIG71 }; int ln[] = { 0, 0, 71 };
      run_case("drop3", it, ln, 3, "6a6a6a"); }
    { const char* it[] = { "" };            int ln[] = { 0 };
      run_case("verify_empty", it, ln, 1, "75"); }
    { const char* it[] = { "" };            int ln[] = { 0 };
      run_case("sha256_empty", it, ln, 1, "a8"); }
    { const char* it[] = { "" };            int ln[] = { 0 };
      run_case("sha1_empty", it, ln, 1, "a7"); }
    { const char* it[] = { "" };            int ln[] = { 0 };
      run_case("hash160_empty", it, ln, 1, "a9"); }
    { const char* it[] = { "" };            int ln[] = { 0 };
      run_case("if_endif_empty", it, ln, 1, "6368"); }
    { const char* it[] = { "" };            int ln[] = { 0 };
      run_case("if_else_endif_empty", it, ln, 1, "636768"); }
    { const char* it[] = { "", PK1 };       int ln[] = { 0, 33 };
      run_case("cs_empty_sig", it, ln, 2, "ac"); }
    { const char* it[] = { SIG71, "" };     int ln[] = { 71, 0 };
      run_case("cs_empty_pub", it, ln, 2, "ac"); }
    { const char* it[] = { "", "", "", SIG71 }; int ln[] = { 0, 0, 0, 71 };
      run_case("real_prefix1", it, ln, 4, "21" PK1 "ac7c"); }
    { const char* it[] = { "", "", "", SIG71 }; int ln[] = { 0, 0, 0, 71 };
      run_case("real_prefix2", it, ln, 4, "21" PK1 "ac7c" "21" PK2 "ac937c"); }
    { const char* it[] = { "", "", "", SIG71 }; int ln[] = { 0, 0, 0, 71 };
      run_case("real_prefix3", it, ln, 4,
               "21" PK1 "ac7c" "21" PK2 "ac937c" "21" PK3 "ac937c"); }
    { const char* it[] = { "", "", "", SIG71 }; int ln[] = { 0, 0, 0, 71 };
      run_case("real_full", it, ln, 4, SCRIPT121); }

    /* second REAL pass after the micro cases polluted the arena */
    { struct script_state st; memset(&st, 0, sizeof st);
      const char* its[4] = { "", "", "", SIG71 };
      const int lns[4] = { 0, 0, 0, 71 };
      for (int i = 0; i < 4; i++){
          uint8_t tmp[520]; int n = lns[i]; hex1(its[i], tmp);
          uint8_t* rec = main_elems + i*ELEM_SIZE;
          memcpy(rec, &n, 4); memcpy(rec + ELEM_DATA_OFF, tmp, (size_t)n);
      }
      size_t slen = hex1(SCRIPT121, script_buf);
      st.main_elems = main_elems; st.main_sp = 4;
      st.alt_elems = alt_elems; st.alt_sp = 0;
      st.script = script_buf; st.script_len = slen;
      st.sigversion = SIGV_WITNESS_V0; st.flags = 0;
      st.work = work_buf; st.work_cap = sizeof work_buf;
      st.error_out = &g_err; g_err = 0;
      st.checksig_ctx = NULL; st.checksig_fn = stub_checksig;
      int r = script_eval(&st);
      printf("REAL_after r=%d err=%llu sp=%zu cs=%lu\n", r,
             (unsigned long long)g_err, st.main_sp, g_cs_calls); }

    printf("DONE cs_calls=%lu\n", g_cs_calls);
    return 0;
}
