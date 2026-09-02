/* tests/test_interp_core_vectors.c -- vectors captured from Bitcoin Core's
 * EvalScript through validation/core_script_oracle on 2026-09-02, the day the
 * randomized differential (tests/fuzz_script_diff) found these divergences.
 * Each line: flags, sigversion, tx version/locktime/sequence, script, initial
 * stack, and Core's verdict + error. The fuzzer needs Core's build; this test
 * needs nothing, so it is the gate's memory of what was found. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define ELEM_SIZE 528
#define MAX_STACK 1000
struct sc_slice { const uint8_t* p; size_t n; };
struct script_state {
    uint8_t* main_elems; size_t main_sp; uint8_t* alt_elems; size_t alt_sp;
    uint8_t* script; size_t script_len; int sigversion; uint64_t flags;
    uint8_t* work; size_t work_cap; uint64_t* error_out; void* checksig_ctx;
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t, const uint8_t*, size_t, const struct sc_slice*);
    uint32_t tx_locktime, in_sequence, tx_version, pad_;
};
extern int script_eval(struct script_state* st);
static uint8_t main_elems[MAX_STACK*ELEM_SIZE], alt_elems[MAX_STACK*ELEM_SIZE];
static uint64_t no_sig(void* c,const uint8_t*s,size_t sn,const uint8_t*p,size_t pn,const struct sc_slice* sc){ (void)c;(void)s;(void)sn;(void)p;(void)pn;(void)sc; return 0; }
static int fails = 0;
static int hexin(const char* h, uint8_t* out){ if (!strcmp(h, "-")) return 0; int n = 0; for (const char* p = h; p[0] && p[1]; p += 2){ unsigned v; sscanf(p, "%2x", &v); out[n++] = (uint8_t)v; } return n; }
struct vec { const char* what; uint64_t flags; int sigv; uint32_t txv, lock, seq; const char* script; const char* init; int core_ok; int core_err; };
static const struct vec V[] = {
  /* --- SCRIPTNUM: minimal encoding under MINIMALDATA, 4-byte caps (Core error 4) --- */
  {"MINIMALDATA: non-minimal 0x0100 then 1 ADD",              0x40,  0, 2, 0, 0,   "0201005193", "-", 0, 4},
  {"MINIMALDATA: padded 0x00ff is minimal (needs the pad)",   0x40,  0, 2, 0, 0,   "02ff005193", "-", 1, 0},
  {"no MINIMALDATA: non-minimal 0x0100 is fine",              0x00,  0, 2, 0, 0,   "0201005193", "-", 1, 0},
  {"MINIMALDATA+CLTV: non-minimal CLTV operand",             0x240, 0, 2, 100, 0, "03ff7f00b1", "-", 0, 4},
  {"CHECKMULTISIG: 5-byte key count",                          0x00,  0, 2, 0, 0,   "4c03800000050000008000ae", "-", 0, 4},
  {"WITHIN: 5-byte operands",                                  0x00,  0, 2, 0, 0,   "05010000808005ffffffff7f51a5", "-", 0, 4},
  {"5-byte operand then 1 ADD",                                0x00,  0, 2, 0, 0,   "0501000000015193", "-", 0, 4},
  /* --- MINIMALIF reports MINIMALIF, not MINIMALDATA (31) --- */
  {"MINIMALIF, witness v0, IF on a 2-byte value",             0x2000, 1, 0, 0, 0,  "6368", "0102", 0, 31},
  {"MINIMALIF, legacy: not enforced",                          0x2000, 0, 0, 0, 0,  "6368", "0102", 1, 0},
  /* --- push minimality: 0x81 must be OP_1NEGATE (25) --- */
  {"MINIMALDATA: direct push of 0x81",                         0x40,  0, 2, 0, 0,   "0181", "-", 0, 25},
  {"MINIMALDATA: direct push of 0x00 is legal",                0x40,  0, 2, 0, 0,   "0100", "-", 1, 0},
  /* --- STRICTENC pubkey encoding (29), checked before the empty-sig shortcut --- */
  {"STRICTENC: empty sig, empty key, CHECKSIG",                0x02,  0, 2, 0, 0,   "0000ac", "-", 0, 29},
  {"STRICTENC: empty sig, empty key, CHECKSIGVERIFY",          0x02,  0, 2, 0, 0,   "0000ad", "-", 0, 29},
  {"no STRICTENC: empty sig, empty key -> false, no error",    0x00,  0, 2, 0, 0,   "0000ac", "-", 1, 0},
  {"STRICTENC: junk sig, good 33-byte key -> SIG_DER (24)",    0x02,  0, 2, 0, 0,   "5121020000000000000000000000000000000000000000000000000000000000000000ac", "-", 0, 24},
  /* --- CHECKSEQUENCEVERIFY disable flag is bit 31 only (22) --- */
  {"CSV: operand 2^32+10, v2, seq 0 -> UNSATISFIED",           0x400, 0, 2, 0, 0,   "050a00000001b2", "-", 0, 22},
  {"CSV: operand bit 31 set -> disabled -> passes",            0x400, 0, 2, 0, 0,   "050000008000b2", "-", 1, 0},
};
int main(void){
    for (size_t i = 0; i < sizeof V / sizeof V[0]; i++){
        const struct vec* v = &V[i]; static uint8_t script[512]; int slen = hexin(v->script, script);
        memset(main_elems, 0, ELEM_SIZE * 4); memset(alt_elems, 0, ELEM_SIZE * 4);
        int ninit = 0; if (strcmp(v->init, "-")){ ((uint32_t*)main_elems)[0] = (uint32_t)hexin(v->init, main_elems + 4); ninit = 1; }
        struct script_state st; memset(&st, 0, sizeof st); uint64_t err = 0;
        st.main_elems = main_elems; st.main_sp = (size_t)ninit; st.alt_elems = alt_elems; st.script = script; st.script_len = (size_t)slen;
        st.sigversion = v->sigv; st.flags = v->flags; st.error_out = &err; st.checksig_fn = no_sig; st.tx_version = v->txv; st.tx_locktime = v->lock; st.in_sequence = v->seq;
        int ok = script_eval(&st) ? 1 : 0; int e = ok ? 0 : (int)err;
        int good = (ok == v->core_ok) && (e == v->core_err);
        printf("  %s %s (ours %d/%d, Core %d/%d)\n", good ? "ok  " : "FAIL", v->what, ok, e, v->core_ok, v->core_err); if (!good) fails++;
    }
    printf("%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL PASS", fails); return fails ? 1 : 0;
}
