/* sn_diff.c -- differential test: the REAL assembled interpreter
 * (bitcoin_interp.o + bitcoin_scriptcodec.o, script_eval) against the C port
 * of Core v31.1 in core_scriptnum.h, opcode by opcode.
 *
 * Each case: an initial stack of 0..3 numeric operands (byte strings of
 * length 0..6, edge-biased), a one-opcode script (the 19 numeric opcodes,
 * OP_WITHIN, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY), a flag subset of
 * {MINIMALDATA, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY}, and a tx context
 * (nLockTime, this input's nSequence, nVersion). Compared: success, the
 * ScriptError on failure, and the whole final stack byte for byte.
 *
 * Phases: (1) EXHAUSTIVE: every binary opcode over every pair of operands of
 * length <= 1 (257 x 257), every unary opcode over every operand of length
 * <= 2, both MINIMALDATA settings; (2) RANDOM: N cases; (3) the primitives
 * scriptnum_decode / scriptnum_serialize / cast_to_bool called directly on N
 * random inputs each.
 *
 * usage: sn_diff N SEED     exit 0 iff no divergence. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "core_scriptnum.h"

#define ELEM_SIZE 528
#define ELEM_DATA_OFF 4
#define MAX_STACK 1000
struct sc_slice { const uint8_t* p; size_t n; };
struct script_state {                 /* bitcoin_interp.asm / bitcoin_scriptverify.c */
    uint8_t* main_elems; size_t main_sp;
    uint8_t* alt_elems;  size_t alt_sp;
    uint8_t* script;     size_t script_len;
    int      sigversion; uint64_t flags;
    uint8_t* work;       size_t work_cap;
    uint64_t* error_out;
    void*    checksig_ctx;
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t, const uint8_t*, size_t, const struct sc_slice*);
    uint32_t tx_locktime, in_sequence, tx_version;
};
extern int script_eval(struct script_state* st);
extern int64_t scriptnum_decode(uint64_t len, const uint8_t* data, uint64_t maxsize);
extern uint8_t* scriptnum_serialize(int64_t v);     /* rax = ptr; rdx = len (read below) */
extern long cast_to_bool(uint64_t len, const uint8_t* data);
extern uint64_t* snum_overflow_addr(void);

static uint8_t main_elems[MAX_STACK * ELEM_SIZE], alt_elems[MAX_STACK * ELEM_SIZE];
static uint64_t g_err;

static uint64_t rs;
static uint64_t rnd(void){ rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

static const uint8_t OPS[] = {0x8b,0x8c,0x8f,0x90,0x91,0x92,0x93,0x94,0x9a,0x9b,0x9c,0x9d,
                              0x9e,0x9f,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xb1,0xb2};
static long n_cases, n_fail;

/* run one case on both sides; report the first few divergences */
static void run_case(uint8_t op, const c_stack* init, uint64_t flags,
                     uint32_t lt, uint32_t sq, uint32_t ver){
    c_stack cs = *init;
    int cerr = core_exec1(&cs, op, flags, lt, sq, ver);
    for (size_t i = 0; i < init->sp; i++){
        uint8_t* rec = main_elems + i * ELEM_SIZE;
        uint32_t n = (uint32_t)init->e[i].n;
        memcpy(rec, &n, 4);
        memcpy(rec + ELEM_DATA_OFF, init->e[i].d, n);
    }
    uint8_t script[1] = { op };
    struct script_state st;
    memset(&st, 0, sizeof st);
    st.main_elems = main_elems; st.main_sp = init->sp;
    st.alt_elems = alt_elems;   st.alt_sp = 0;
    st.script = script; st.script_len = 1;
    st.sigversion = 0; st.flags = flags;
    st.error_out = &g_err; g_err = 0;
    st.tx_locktime = lt; st.in_sequence = sq; st.tx_version = ver;
    int ok = script_eval(&st);
    n_cases++;
    int same = (ok == (cerr == C_ERR_OK));
    if (same && !ok) same = ((int)g_err == cerr);
    if (same && ok){
        same = (st.main_sp == cs.sp);
        for (size_t i = 0; same && i < cs.sp; i++){
            uint8_t* rec = main_elems + i * ELEM_SIZE;
            uint32_t n; memcpy(&n, rec, 4);
            same = (n == cs.e[i].n) && !memcmp(rec + ELEM_DATA_OFF, cs.e[i].d, n);
        }
    }
    if (!same){
        if (n_fail < 10){
            printf("DIVERGE op=%02x flags=%llx lt=%u sq=%08x ver=%u stack=[", op,
                   (unsigned long long)flags, lt, sq, ver);
            for (size_t i = 0; i < init->sp; i++){
                printf(i ? " " : "");
                for (size_t k = 0; k < init->e[i].n; k++) printf("%02x", init->e[i].d[k]);
                if (!init->e[i].n) printf("<>");
            }
            printf("] bmc ok=%d err=%llu sp=%zu  core err=%d sp=%zu\n", ok,
                   (unsigned long long)g_err, st.main_sp, cerr, cs.sp);
        }
        n_fail++;
    }
}

static const uint8_t EDGE[] = {0x00,0x80,0x7f,0xff,0x01,0x81,0xfe,0x40};
static void rnd_elem(c_elem* e){
    size_t n = rnd() % 7;
    if (rnd() % 8 == 0) n = 5;
    e->n = n;
    for (size_t i = 0; i < n; i++)
        e->d[i] = (rnd() & 1) ? EDGE[rnd() % sizeof EDGE] : (uint8_t)rnd();
}
static uint32_t rnd_u32_edge(void){
    static const uint32_t E[] = {0,1,2,499999999u,500000000u,500000001u,0x7fffffffu,0x80000000u,
                                 0xfffffffeu,0xffffffffu,0x0040ffffu,0x00400000u,0x0000ffffu,0x003fffffu};
    return (rnd() & 1) ? E[rnd() % (sizeof E / sizeof E[0])] : (uint32_t)rnd();
}

int main(int argc, char** argv){
    long N = argc > 1 ? atol(argv[1]) : 1000000;
    rs = argc > 2 ? strtoull(argv[2], 0, 0) : 0x9e3779b97f4a7c15ULL;
    if (!rs) rs = 1;
    /* ---- (1) exhaustive short operands ---- */
    c_stack s;
    for (int fm = 0; fm < 2; fm++){
        uint64_t fl = fm ? C_FLAG_MINIMALDATA : 0;
        for (int a = -1; a < 256; a++) for (int b = -1; b < 256; b++){
            s.sp = 2;
            s.e[0].n = a < 0 ? 0 : 1; s.e[0].d[0] = (uint8_t)a;
            s.e[1].n = b < 0 ? 0 : 1; s.e[1].d[0] = (uint8_t)b;
            for (uint8_t op = 0x93; op <= 0xa4; op++){
                if (op >= 0x95 && op <= 0x99) continue;      /* MUL/DIV/MOD/LSHIFT/RSHIFT: disabled */
                run_case(op, &s, fl, 0, 0, 0);
            }
        }
        for (int a = -1; a < 65536; a++){
            s.sp = 1;
            if (a < 256){ s.e[0].n = a < 0 ? 0 : 1; s.e[0].d[0] = (uint8_t)a; }
            else { s.e[0].n = 2; s.e[0].d[0] = (uint8_t)a; s.e[0].d[1] = (uint8_t)(a >> 8); }
            static const uint8_t U[] = {0x8b,0x8c,0x8f,0x90,0x91,0x92};
            for (size_t k = 0; k < sizeof U; k++) run_case(U[k], &s, fl, 0, 0, 0);
        }
    }
    long ex_cases = n_cases;
    printf("exhaustive: %ld cases, %ld divergences\n", ex_cases, n_fail);
    /* ---- (2) random ---- */
    for (long i = 0; i < N; i++){
        uint8_t op = OPS[rnd() % sizeof OPS];
        s.sp = rnd() % 4;
        for (size_t k = 0; k < s.sp; k++) rnd_elem(&s.e[k]);
        uint64_t fl = 0;
        if (rnd() & 1) fl |= C_FLAG_MINIMALDATA;
        if (rnd() % 4) fl |= C_FLAG_CLTV;
        if (rnd() % 4) fl |= C_FLAG_CSV;
        /* CLTV/CSV operands: often a 5-byte or a lock-shaped value */
        if ((op == 0xb1 || op == 0xb2) && s.sp && (rnd() & 1)){
            uint8_t b[10]; int64_t v = (int64_t)(rnd() % 0x10000000000ULL) - (int64_t)(rnd() % 4 == 0 ? 0x8000000000LL : 0);
            if (rnd() & 1) v = (int64_t)rnd_u32_edge();
            size_t n = core_snum_serialize(v, b);
            memcpy(s.e[s.sp - 1].d, b, n); s.e[s.sp - 1].n = n;
        }
        run_case(op, &s, fl, rnd_u32_edge(), rnd_u32_edge(), rnd_u32_edge());
    }
    printf("random: %ld cases, %ld divergences (total)\n", n_cases - ex_cases, n_fail);
    /* ---- (3) primitives ---- */
    long pf = 0;
    uint64_t* ov = snum_overflow_addr();
    for (long i = 0; i < N; i++){
        c_elem e; rnd_elem(&e); if (rnd() % 16 == 0){ e.n = 7 + rnd() % 3; for (size_t k = 0; k < e.n; k++) e.d[k] = (uint8_t)rnd(); }
        int minimal = rnd() & 1; uint64_t msz = (rnd() & 1) ? 4 : 5;
        if (e.n > 8) msz = rnd() % 9;
        int64_t cv; int cok = core_snum_decode(e.d, e.n, minimal, msz, &cv);
        int64_t bv = scriptnum_decode(e.n, e.d, msz | (minimal ? 0x100 : 0));
        int bok = (*ov == 0);
        if (bok != cok || (cok && bv != cv)){ if (pf < 5) printf("DIVERGE decode n=%zu\n", e.n); pf++; }
        int64_t v = (int64_t)rnd();
        switch (rnd() % 4){ case 0: v >>= (rnd() % 64); break; case 1: v = (int64_t)(rnd() % 0x100000000ULL) - 0x80000000LL; break; default: break; }
        if (rnd() % 64 == 0) v = INT64_MIN;
        uint8_t cb[10]; size_t cn = core_snum_serialize(v, cb);
        uint64_t blen;
        uint8_t* bp;
        __asm__ volatile ("call scriptnum_serialize" : "=a"(bp), "=d"(blen) : "D"(v)
                          : "rcx","rsi","r8","r9","r10","r11","memory","cc");
        if (blen != cn || memcmp(bp, cb, cn)){ if (pf < 5) printf("DIVERGE serialize v=%lld\n", (long long)v); pf++; }
        if ((cast_to_bool(e.n, e.d) != 0) != core_cast_to_bool(e.d, e.n)){ if (pf < 5) printf("DIVERGE cast n=%zu\n", e.n); pf++; }
    }
    printf("primitives: %ld x 3 calls, %ld divergences\n", N, pf);
    return (n_fail || pf) ? 1 : 0;
}
