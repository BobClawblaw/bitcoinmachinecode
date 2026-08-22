/* test_taproot_bounds_fuzz.c -- the BIP341/BIP342 sighash path must never read
 * past the end of the transaction buffer, for ANY byte string a peer can send.
 *
 * This is the sibling of tests/test_segwit_bounds_fuzz.c (fc4bd67), which does
 * the same job for bitcoin_segwit.c's BIP143 path, and it exists for the same
 * reason: bitcoin_taproot_sighash.c carried the SAME defect one file over.
 *
 *   - its read_cs() took no `end` at all.  A compactsize's width is chosen by
 *     its own first byte, which is wire data, so ANY walk that landed on the
 *     last byte of the transaction read up to 8 bytes past it.  tx_parse()
 *     read the input count BEFORE checking that it fit: a 10-byte buffer whose
 *     byte 4 is 0xff made it read tx[5..12] -- three bytes past the end --
 *     with `txlen < 10` the only guard, and that guard does not help;
 *   - every bound test was the pointer-overflow form `q + sl > end`, with the
 *     unsigned wire length cast through int64_t first, so any sl >= 2^63 went
 *     negative and the comparison passed unconditionally;
 *   - tx_seq() and ser_txout() had no bounds at all, and agg_hashes() iterated
 *     to c->num_inputs while tx_seq() indexed the TRANSACTION's t->nin.
 *
 * Method (copied from test_segwit_bounds_fuzz.c): the transaction is copied so
 * that its LAST byte is the last byte of a mapped page, with a PROT_NONE guard
 * page immediately after.  Any read of even one byte past the end is then a
 * SIGSEGV rather than a silent success, with no sanitizer needed -- which
 * matters because this path links the hand-written asm and the suite's ASAN
 * builds cannot instrument that.  Unlike the segwit test, this one INSTALLS a
 * SIGSEGV handler and siglongjmps out, so a fault is REPORTED (case, faulting
 * address, bytes past the end) instead of merely killing the process.
 *
 * Inputs: real mainnet transactions -- the P2TR script-path spends of
 * tests/tapscript_scale_vec.h and the real segwit/taproot-era transactions of
 * tests/segwit_txout_vec.h -- witness-STRIPPED via strip_witness(), because
 * that is the serialization the daemon hands taproot_verify_input().  Each is
 * truncated at every length, and single bytes are poisoned to 0x00/0xfd/0xfe/
 * 0xff, which is what turns a benign compactsize into a hostile one, across
 * seven hash types, several input indices, both ext_flags, and with an annex.
 *
 * The only assertion is that the process survives and every call returns
 * either a refusal or a hash -- correctness of the hashes themselves is
 * test_taproot_sighash's job, against Core's wallet-test-vectors.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>

#include "tapscript_scale_vec.h"
#include "segwit_txout_vec.h"

/* ---- bitcoin_taproot_sighash.c API (mirrors tests/test_taproot_sighash.c) -- */
typedef struct {
    const uint8_t* tx;   int64_t txlen;
    int64_t  n_in;
    uint8_t  hash_type;
    const uint8_t* prevouts;   /* 36 * num_inputs, contiguous */
    const uint8_t* amounts;    /* 8  * num_inputs, contiguous */
    const uint8_t* spks;       /* per input: compactsize + scriptPubKey */
    int64_t  num_inputs;
    int      ext_flag;         /* 0 keypath, 1 scriptpath */
    const uint8_t* tapleaf;    /* 32 bytes or NULL */
    uint32_t codesep_pos;
    const uint8_t* annex;
    uint64_t annexlen;
} tapctx_t;
extern long taproot_sighash(uint8_t* out32, const tapctx_t* c, uint8_t* pre, long cap);

/* bitcoin_segwit.c: produces the non-witness serialization taproot hashes. */
extern long strip_witness(const uint8_t* tx, int64_t txlen, uint8_t* out, long cap);

/* ---------------------------------------------------------------- reporting */
static int fails = 0, checks = 0;
static void ck(const char* what, int ok){
    checks++;
    if (!ok){ fails++; printf("  FAIL %s\n", what); }
    else      printf("  ok  %s\n", what);
}

/* ------------------------------------------- guard page (from the segwit fuzz)
 * A region whose last usable byte abuts a PROT_NONE guard page. */
static uint8_t* g_base; static size_t g_pages; static uint8_t* g_guard;
static uint8_t* guard_put(const uint8_t* src, size_t n){
    uint8_t* p = g_base + g_pages * (size_t)sysconf(_SC_PAGESIZE) - n;
    memcpy(p, src, n);
    return p;
}

/* --------------------------------------------------- fault capture machinery */
static sigjmp_buf g_jb;
static volatile sig_atomic_t g_in_call = 0;
static volatile void* g_fault_addr;
static volatile int  g_fault_sig;

static void on_fault(int s, siginfo_t* si, void* uc){
    (void)uc;
    if (!g_in_call) _exit(128 + s);      /* fault outside the call: give up */
    g_fault_addr = si->si_addr;
    g_fault_sig  = s;
    siglongjmp(g_jb, 1);
}

/* The case currently being driven, so a fault can name its own input. */
typedef struct {
    const char* fixture; size_t fx;
    size_t full_len, len;                /* full stripped length, truncation  */
    long   poison_pos; int poison_val;    /* -1 = none                         */
    unsigned ht; int64_t n_in, num_inputs; int ext, annex;
} case_t;
static case_t g_case;
static const uint8_t* g_case_tx;

static unsigned long long ncall = 0, nhash = 0, nrefuse = 0, nfault = 0;
static unsigned long long nfault_trunc = 0;   /* faults with NO byte poisoned */
static int nfault_printed = 0;
static size_t min_fault_len = (size_t)-1;
static case_t min_fault_case;
static unsigned char min_fault_buf[64]; static size_t min_fault_n;
static size_t min_trunc_len = (size_t)-1;
static case_t min_trunc_case;
static unsigned char min_trunc_buf[128]; static size_t min_trunc_n;

static void report_fault(void){
    nfault++;
    if (g_case.poison_pos < 0) nfault_trunc++;
    long past = (long)((const uint8_t*)g_fault_addr - (g_case_tx + g_case.len)) + 1;
    if (nfault_printed < 8){
        nfault_printed++;
        printf("  *** SIGNAL %d reading %p -- %ld byte(s) PAST the end of the "
               "transaction\n", g_fault_sig, (void*)g_fault_addr, past);
        printf("      fixture=%s[%zu] full=%zu txlen=%zu poison=",
               g_case.fixture, g_case.fx, g_case.full_len, g_case.len);
        if (g_case.poison_pos < 0) printf("none");
        else printf("tx[%ld]=0x%02x", g_case.poison_pos, g_case.poison_val);
        printf(" ht=0x%02x n_in=%lld num_inputs=%lld ext=%d annex=%d\n",
               g_case.ht, (long long)g_case.n_in, (long long)g_case.num_inputs,
               g_case.ext, g_case.annex);
        size_t n = g_case.len < 64 ? g_case.len : 64;
        printf("      tx = ");
        for (size_t i=0;i<n;i++) printf("%02x", g_case_tx[i]);
        printf("%s\n", g_case.len > 64 ? "..." : "");
    }
    if (g_case.len < min_fault_len){
        min_fault_len = g_case.len; min_fault_case = g_case;
        min_fault_n = g_case.len < sizeof min_fault_buf ? g_case.len : sizeof min_fault_buf;
        memcpy(min_fault_buf, g_case_tx, min_fault_n);
    }
    if (g_case.poison_pos < 0 && g_case.len < min_trunc_len){
        min_trunc_len = g_case.len; min_trunc_case = g_case;
        min_trunc_n = g_case.len < sizeof min_trunc_buf ? g_case.len : sizeof min_trunc_buf;
        memcpy(min_trunc_buf, g_case_tx, min_trunc_n);
    }
}

/* One guarded call.  Returns the sighash length, 0 on refusal, -1 on fault. */
static uint8_t* g_pre; static long g_precap;
static long drive(const tapctx_t* c){
    uint8_t out32[32];
    ncall++;
    g_case_tx = c->tx;
    if (sigsetjmp(g_jb, 1) == 0){
        g_in_call = 1;
        long r = taproot_sighash(out32, c, g_pre, g_precap);
        g_in_call = 0;
        if (r > 0) nhash++; else nrefuse++;
        return r;
    }
    g_in_call = 0;
    report_fault();
    return -1;
}

/* -------------------- our own trivially-correct bounded input-count reader ---
 * The hardened taproot_sighash requires c->num_inputs to equal the
 * transaction's own input count, so the test must derive it independently.
 * This reader is deliberately dull: bounded, minimality-checking, no pointer
 * arithmetic that can overflow. */
#define MAXIN 4096
static int64_t walk_nin(const uint8_t* tx, size_t len){
    if (len < 5) return -1;
    size_t i = 4;
    uint8_t f = tx[i++];
    uint64_t v;
    if (f < 0xfd) v = f;
    else {
        size_t extra = (f == 0xfd) ? 2 : (f == 0xfe ? 4 : 8);
        if (len - i < extra) return -1;
        v = 0; for (size_t k = 0; k < extra; k++) v |= (uint64_t)tx[i+k] << (8*k);
        uint64_t min = (f == 0xfd) ? 0xfdULL : (f == 0xfe ? 0x10000ULL : 0x100000000ULL);
        if (v < min) return -1;                 /* non-canonical, as Core */
    }
    if (v == 0 || v > (uint64_t)MAXIN) return -1;
    return (int64_t)v;
}

/* --------------------------------------------------------------- fixed data */
static uint8_t* g_prevouts; static uint8_t* g_amounts; static uint8_t* g_spks;
static uint8_t  g_tapleaf[32];
static uint8_t  g_annex[97];
static const uint8_t HT[7] = { 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 };

static void build_arrays(void){
    /* Generous: MAXIN entries, so the caller-supplied arrays are never the
     * thing that overflows.  The object under test is the TRANSACTION. */
    g_prevouts = (uint8_t*)malloc(36 * MAXIN);
    g_amounts  = (uint8_t*)malloc(8  * MAXIN);
    g_spks     = (uint8_t*)malloc(35 * MAXIN);   /* 1-byte cs + 34-byte P2TR */
    for (int i = 0; i < 36 * MAXIN; i++) g_prevouts[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 8  * MAXIN; i++) g_amounts[i]  = (uint8_t)(i * 13 + 3);
    for (int i = 0; i < MAXIN; i++){
        uint8_t* e = g_spks + 35 * i;
        e[0] = 34; e[1] = 0x51; e[2] = 0x20;
        for (int k = 0; k < 32; k++) e[3+k] = (uint8_t)(i * 31 + k);
    }
    for (int i = 0; i < 32; i++) g_tapleaf[i] = (uint8_t)(i * 5 + 9);
    g_annex[0] = 0x50; for (int i = 1; i < 97; i++) g_annex[i] = (uint8_t)(i * 3);
}

static void ctx_init(tapctx_t* c, const uint8_t* tx, size_t len, int64_t nin){
    memset(c, 0, sizeof *c);
    c->tx = tx; c->txlen = (int64_t)len;
    c->prevouts = g_prevouts; c->amounts = g_amounts; c->spks = g_spks;
    c->num_inputs = nin;
    c->codesep_pos = 0xffffffffu;
}

/* Run one buffer through a slice of the case space. `depth` selects how much:
 *   0 = one hash type, one index, keypath   (the truncation/poison sweeps)
 *   1 = all hash types x 3 indices x both ext_flags x annex-on-one
 */
static void hammer(const uint8_t* tx, size_t len, int64_t nin, int depth){
    tapctx_t c;
    g_case.len = len; g_case.num_inputs = nin;
    if (depth == 0){
        ctx_init(&c, tx, len, nin);
        c.n_in = 0; c.hash_type = 0x01; c.ext_flag = 0;
        g_case.ht = 0x01; g_case.n_in = 0; g_case.ext = 0; g_case.annex = 0;
        drive(&c);
        return;
    }
    for (int h = 0; h < 7; h++){
        for (int64_t n_in = 0; n_in < 3; n_in++){
            for (int ext = 0; ext < 2; ext++){
                ctx_init(&c, tx, len, nin);
                c.n_in = n_in; c.hash_type = HT[h]; c.ext_flag = ext;
                if (ext){ c.tapleaf = g_tapleaf; }
                g_case.ht = HT[h]; g_case.n_in = n_in; g_case.ext = ext;
                g_case.annex = 0;
                drive(&c);
                if (h == 1 && n_in == 0){            /* one annex case per buffer */
                    c.annex = g_annex; c.annexlen = sizeof g_annex;
                    g_case.annex = 1;
                    drive(&c);
                }
            }
        }
    }
}

/* --------------------------------------------------------------------- main */
static size_t hex2bin(const char* h, uint8_t* out, size_t cap){
    size_t n = strlen(h) / 2;
    if (n > cap) return 0;
    for (size_t i = 0; i < n; i++){
        unsigned v; sscanf(h + 2*i, "%2x", &v); out[i] = (uint8_t)v;
    }
    return n;
}

int main(void){
    long pg = sysconf(_SC_PAGESIZE);
    g_pages = 256;                                  /* 1 MB of usable space */
    size_t total = (g_pages + 1) * (size_t)pg;
    g_base = (uint8_t*)mmap(0, total, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (g_base == MAP_FAILED){ perror("mmap"); return 1; }
    g_guard = g_base + g_pages * (size_t)pg;
    if (mprotect(g_guard, (size_t)pg, PROT_NONE)){ perror("mprotect"); return 1; }
    size_t usable = g_pages * (size_t)pg;

    /* SIGSEGV on its own stack, so a fault inside the asm can be reported. */
    static char altbuf[SIGSTKSZ * 4];
    stack_t ss; ss.ss_sp = altbuf; ss.ss_size = sizeof altbuf; ss.ss_flags = 0;
    sigaltstack(&ss, NULL);
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);

    g_precap = 1 << 16;
    g_pre = (uint8_t*)malloc((size_t)g_precap);
    build_arrays();

    long scap = 1 << 22;
    uint8_t* raw  = (uint8_t*)malloc((size_t)scap);
    uint8_t* strp = (uint8_t*)malloc((size_t)scap);

    printf("== BIP341 sighash reads nothing past the transaction (guard page) ==\n");

    /* Gather the corpus: real mainnet transactions, witness-stripped, because
     * that is what daemon/tx_verify.c hands taproot_verify_input(). */
    #define MAXTX 64
    static uint8_t* corpus[MAXTX]; static size_t corpus_len[MAXTX];
    static const char* corpus_src[MAXTX]; static size_t corpus_idx[MAXTX];
    size_t ncorpus = 0;

    for (unsigned i = 0; i < TS_N && ncorpus < MAXTX; i++){
        size_t n = hex2bin(TS_FIXTURES[i].tx_hex, raw, (size_t)scap);
        if (!n) continue;
        long s = strip_witness(raw, (int64_t)n, strp, scap);
        if (s <= 0 || (size_t)s > usable) continue;
        corpus[ncorpus] = (uint8_t*)malloc((size_t)s);
        memcpy(corpus[ncorpus], strp, (size_t)s);
        corpus_len[ncorpus] = (size_t)s;
        corpus_src[ncorpus] = "tapscript_scale_vec";
        corpus_idx[ncorpus] = i;
        ncorpus++;
    }
    size_t nswto = sizeof(SWTO_TXS)/sizeof(SWTO_TXS[0]);
    for (size_t i = 0; i < nswto && ncorpus < MAXTX; i++){
        size_t hexlen = strlen(SWTO_TXS[i]);
        if (hexlen/2 > (size_t)scap) continue;
        size_t n = hex2bin(SWTO_TXS[i], raw, (size_t)scap);
        if (!n) continue;
        long s = strip_witness(raw, (int64_t)n, strp, scap);
        if (s <= 0 || (size_t)s > usable) continue;
        corpus[ncorpus] = (uint8_t*)malloc((size_t)s);
        memcpy(corpus[ncorpus], strp, (size_t)s);
        corpus_len[ncorpus] = (size_t)s;
        corpus_src[ncorpus] = "segwit_txout_vec";
        corpus_idx[ncorpus] = i;
        ncorpus++;
    }
    printf("  corpus: %zu real mainnet transactions, witness-stripped\n", ncorpus);

    static const uint8_t POISON[4] = { 0x00, 0xfd, 0xfe, 0xff };

    /* ---- targeted probe: the specific shape the old tx_parse could not
     * survive -- a transaction just long enough to pass `txlen < 10`, whose
     * input-count compactsize is the 9-byte 0xff form, sitting against the
     * guard page.  Derived from a real transaction's own leading bytes. */
    printf("  probe: 10/11/12-byte transactions with tx[4]=0xff\n");
    g_case.fixture = "probe(tx[4]=0xff)"; g_case.fx = 0;
    for (size_t k = 0; k < ncorpus && k < 4; k++){
        for (size_t L = 10; L <= 12; L++){
            if (corpus_len[k] < L) continue;
            uint8_t tmp[16];
            memcpy(tmp, corpus[k], L);
            tmp[4] = 0xff;
            g_case.full_len = L; g_case.poison_pos = 4; g_case.poison_val = 0xff;
            const uint8_t* tx = guard_put(tmp, L);
            hammer(tx, L, 1, 1);
        }
    }

    /* ---- the sweeps ---- */
    for (size_t k = 0; k < ncorpus; k++){
        uint8_t* full = corpus[k];
        size_t len = corpus_len[k];
        g_case.fixture = corpus_src[k]; g_case.fx = corpus_idx[k];
        g_case.full_len = len;
        size_t step = 1 + len / 1200;        /* keeps the big ones bounded */

        /* (a) every truncation, full case space */
        for (size_t L = 0; L <= len; L += step){
            g_case.poison_pos = -1; g_case.poison_val = 0;
            const uint8_t* tx = guard_put(full, L);
            int64_t nin = walk_nin(full, L);
            hammer(tx, L, nin > 0 ? nin : 1, 1);
            if (nin > 0) hammer(tx, L, MAXIN, 0);   /* mismatched count: refuse */
        }
        if ((len % step) != 0){
            g_case.poison_pos = -1;
            const uint8_t* tx = guard_put(full, len);
            int64_t nin = walk_nin(full, len);
            hammer(tx, len, nin > 0 ? nin : 1, 1);
        }

        /* (b) single-byte poison at full length: benign compactsize -> hostile */
        for (size_t pos = 0; pos < len; pos += step){
            for (int b = 0; b < 4; b++){
                uint8_t save = full[pos]; full[pos] = POISON[b];
                g_case.poison_pos = (long)pos; g_case.poison_val = POISON[b];
                const uint8_t* tx = guard_put(full, len);
                int64_t nin = walk_nin(full, len);
                hammer(tx, len, nin > 0 ? nin : 1, 1);
                full[pos] = save;
            }
        }

        /* (c) truncation x poison, concentrated where it matters: the input
         * count itself and the last 12 bytes of the truncated buffer, which
         * is exactly where a walk lands on the last byte and reads past it. */
        for (size_t L = 5; L <= len; L += step){
            for (int t = 0; t < 13; t++){
                size_t pos = (t == 0) ? 4 : (L >= (size_t)(13 - t) ? L - (13 - t) : (size_t)-1);
                if (pos == (size_t)-1 || pos >= L) continue;
                for (int b = 0; b < 4; b++){
                    uint8_t save = full[pos]; full[pos] = POISON[b];
                    g_case.poison_pos = (long)pos; g_case.poison_val = POISON[b];
                    const uint8_t* tx = guard_put(full, L);
                    int64_t nin = walk_nin(full, L);
                    hammer(tx, L, nin > 0 ? nin : 1, 0);
                    full[pos] = save;
                }
            }
        }
    }

    printf("  %llu calls over %zu real mainnet transactions "
           "(%llu hashed, %llu refused, %llu FAULTED)\n",
           ncall, ncorpus, nhash, nrefuse, nfault);
    if (nfault){
        printf("  %llu of those faults were PURE TRUNCATIONS of a real mainnet "
               "transaction (no byte altered)\n", nfault_trunc);
        printf("  smallest faulting transaction: txlen=%zu poison=tx[%ld]=0x%02x  hex=",
               min_fault_len, min_fault_case.poison_pos, min_fault_case.poison_val);
        for (size_t i = 0; i < min_fault_n; i++) printf("%02x", min_fault_buf[i]);
        printf("\n");
    }
    if (nfault_trunc){
        printf("  smallest faulting PURE TRUNCATION: %s[%zu] full=%zu txlen=%zu  hex=",
               min_trunc_case.fixture, min_trunc_case.fx,
               min_trunc_case.full_len, min_trunc_len);
        for (size_t i = 0; i < min_trunc_n; i++) printf("%02x", min_trunc_buf[i]);
        printf("%s\n", min_trunc_len > min_trunc_n ? "..." : "");
    }
    ck("no read past the end of the transaction (guard page never faulted)",
       nfault == 0);
    ck("every call returned a hash or a clean refusal", ncall == nhash + nrefuse + nfault);
    ck("truncation and corruption both produce refusals", nrefuse > 0);
    ck("valid transactions still hash", nhash > 0);

    printf("\n%s (%llu calls, %llu faults; %d checks, %d failures)\n",
           fails ? "FAILURES" : "ALL PASS", ncall, nfault, checks, fails);
    return fails ? 1 : 0;
}
