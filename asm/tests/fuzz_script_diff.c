/* tests/fuzz_script_diff.c -- randomized differential fuzzing of the asm
 * script interpreter against Bitcoin Core's EvalScript (audit 2026-09-02
 * §6.9). Core answers through validation/core_script_oracle (a line oracle
 * built from Core's own libraries by validation/build_core_oracle.sh), so
 * this is a MANUAL tool, not a gate test: it needs the scratch Core tree.
 *
 *   fuzz_script_diff [count] [seed] [oracle]
 *
 * Every case: random flags (from the set both sides implement), random
 * tx context (version / locktime / this input's nSequence), a random initial
 * stack, a random script biased toward the opcodes with the richest
 * semantics (numeric edge values, 5-byte scriptnums, non-minimal encodings,
 * CLTV/CSV, hashes, control flow, disabled opcodes, sig ops with junk).
 * Compared: the verdict, Core's error code, and the whole final stack when
 * both sides completed. A mismatch prints the oracle line (a reproducer). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
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
static uint64_t fake_checksig(void* c,const uint8_t*s,size_t sn,const uint8_t*p,size_t pn,const struct sc_slice* sc){ (void)c;(void)s;(void)sn;(void)p;(void)pn;(void)sc; return 0; }
/* ---- rng (xorshift64*) ---- */
static uint64_t rs;
static uint64_t rnd(void){ rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; return rs * 2685821657736338717ULL; }
static unsigned r(unsigned n){ return (unsigned)(rnd() % n); }
/* ---- generator ---- */
static const uint8_t OPS[] = {
 0x00,0x4f,0x51,0x52,0x53,0x60,0x61,0x63,0x64,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,
 0x82,0x87,0x88,0x8b,0x8c,0x8f,0x90,0x91,0x92,0x93,0x94,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,
 0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,0xb4,0xb9,
 /* disabled / reserved: both sides must fail identically */ 0x7e,0x7f,0x80,0x81,0x83,0x84,0x85,0x86,0x8d,0x8e,0x95,0x96,0x97,0x98,0x99,0x50,0x62,0x65,0x66,0x89,0x8a,0xba,0xff };
static const int64_t EDGE[] = { 0,1,-1,16,17,127,128,255,256,-128,-129,32767,32768,65535,65536,2147483647LL,2147483648LL,-2147483648LL,-2147483649LL,4294967295LL,4294967296LL,4294967306LL,549755813887LL,-549755813888LL,0x0040ffff,0x00400000,0x00400001,500000000,499999999,1231006505 };
static int push_num(uint8_t* out, int64_t v, int minimal){
    /* CScriptNum encoding; when !minimal, sometimes append a redundant 0x00 (or 0x80 for negative zero) */
    uint8_t b[9]; int n = 0; int neg = v < 0; uint64_t a = (uint64_t)(neg ? -v : v);
    while (a){ b[n++] = (uint8_t)(a & 0xff); a >>= 8; }
    if (n && (b[n-1] & 0x80)) b[n++] = neg ? 0x80 : 0x00; else if (n && neg) b[n-1] |= 0x80;
    if (!minimal && n < 5 && r(2)){ if (n && (b[n-1] & 0x80)){ b[n-1] &= 0x7f; b[n++] = neg ? 0x80 : 0x00; } else b[n++] = neg ? 0x80 : 0x00; }
    if (n == 0 && !minimal && r(3) == 0){ b[0] = 0x80; n = 1; }           /* negative zero */
    int o = 0;
    if (n == 0) out[o++] = 0x00;
    else if (n == 1 && b[0] >= 1 && b[0] <= 16 && minimal) out[o++] = (uint8_t)(0x50 + b[0]);
    else if (n == 1 && b[0] == 0x81 && minimal) out[o++] = 0x4f;
    else { if (!minimal && r(4) == 0){ out[o++] = 0x4c; out[o++] = (uint8_t)n; } else out[o++] = (uint8_t)n; memcpy(out + o, b, (size_t)n); o += n; }
    return o;
}
static int gen_script(uint8_t* s, int cap){
    int n = r(24) + 1, o = 0;
    for (int i = 0; i < n && o < cap - 80; i++){
        unsigned k = r(100);
        if (k < 30){ o += push_num(s + o, EDGE[r(sizeof EDGE / sizeof EDGE[0])], r(3) != 0); }
        else if (k < 40){ int64_t v = (int64_t)(rnd() % 2000) - 1000; o += push_num(s + o, v, r(4) != 0); }
        else if (k < 48){ int len = (int)r(r(8) ? 40 : 600); if (len > cap - o - 4) len = cap - o - 4; if (len < 0) len = 0;
            if (len <= 75 && r(3)) s[o++] = (uint8_t)len; else if (len <= 255){ s[o++] = 0x4c; s[o++] = (uint8_t)len; } else { s[o++] = 0x4d; s[o++] = (uint8_t)len; s[o++] = (uint8_t)(len >> 8); }
            for (int j = 0; j < len; j++) s[o++] = (uint8_t)rnd(); }
        else if (k < 52){ /* a 33/65-byte junk "pubkey" or a DER-ish junk "sig" for the sig ops */
            int len = r(2) ? 33 : (r(2) ? 65 : 71); s[o++] = (uint8_t)len; if (len == 71){ s[o++] = 0x30; s[o++] = 0x44; for (int j = 2; j < 71; j++) s[o++] = (uint8_t)rnd(); s[o-1] = 0x01; } else { s[o++] = r(2) ? 0x02 : 0x04; for (int j = 1; j < len; j++) s[o++] = (uint8_t)rnd(); } }
        else s[o++] = OPS[r(sizeof OPS)];
    }
    return o;
}
/* ---- oracle ---- */
static FILE *oin, *oout;
static void spawn_oracle(const char* path){
    int a[2], b[2]; if (pipe(a) || pipe(b)){ perror("pipe"); exit(2); }
    pid_t pid = fork(); if (pid < 0){ perror("fork"); exit(2); }
    if (pid == 0){ dup2(a[0], 0); dup2(b[1], 1); close(a[1]); close(b[0]); execl(path, path, (char*)0); perror(path); _exit(3); }
    close(a[0]); close(b[1]); oin = fdopen(a[1], "w"); oout = fdopen(b[0], "r");
}
static void hexout(FILE* f, const uint8_t* p, size_t n){ if (!n){ fputc('-', f); return; } for (size_t i = 0; i < n; i++) fprintf(f, "%02x", p[i]); }
static char linebuf[1 << 16], ourbuf[1 << 16];
static int hexin(const char* h, uint8_t* out){ if (!strcmp(h, "-")) return 0; int n = 0; for (const char* p = h; p[0] && p[1]; p += 2){ unsigned v; sscanf(p, "%2x", &v); out[n++] = (uint8_t)v; } return n; }
/* --case "<oracle line>": run exactly one case on both sides and print both answers (the reproducer path) */
static int one_case(const char* line, const char* oracle){
    spawn_oracle(oracle);
    char buf[1 << 15]; snprintf(buf, sizeof buf, "%s", line);
    char* tok[64]; int nt = 0; for (char* t = strtok(buf, " \n"); t && nt < 64; t = strtok(0, " \n")) tok[nt++] = t;
    if (nt < 6){ fprintf(stderr, "need: flags sigv txv lock seq script [stack...]\n"); return 2; }
    uint64_t flags = strtoull(tok[0], 0, 16); int sigv = atoi(tok[1]); uint32_t txv = (uint32_t)strtoul(tok[2], 0, 10), lock = (uint32_t)strtoul(tok[3], 0, 10), seq = (uint32_t)strtoul(tok[4], 0, 10);
    static uint8_t script[4096]; int slen = hexin(tok[5], script);
    memset(main_elems, 0, sizeof main_elems); memset(alt_elems, 0, ELEM_SIZE * 8);
    int ninit = nt - 6; for (int i = 0; i < ninit; i++){ uint8_t* rec = main_elems + i * ELEM_SIZE; ((uint32_t*)rec)[0] = (uint32_t)hexin(tok[6 + i], rec + 4); }
    struct script_state st; memset(&st, 0, sizeof st); uint64_t err = 0;
    st.main_elems = main_elems; st.main_sp = (size_t)ninit; st.alt_elems = alt_elems; st.script = script; st.script_len = (size_t)slen;
    st.sigversion = sigv; st.flags = flags; st.error_out = &err; st.checksig_fn = fake_checksig; st.tx_version = txv; st.tx_locktime = lock; st.in_sequence = seq;
    int ours = script_eval(&st);
    printf("ours: %d %d %d", ours ? 1 : 0, (int)err, (int)st.main_sp);
    for (size_t i = 0; i < st.main_sp; i++){ uint8_t* rec = main_elems + i * ELEM_SIZE; putchar(' '); hexout(stdout, rec + 4, ((uint32_t*)rec)[0]); }
    printf("\n"); fprintf(oin, "%s\n", line); fflush(oin);
    if (fgets(linebuf, sizeof linebuf, oout)) printf("core: %s", linebuf);
    return 0;
}
int main(int argc, char** argv){
    if (argc >= 3 && !strcmp(argv[1], "--case")) return one_case(argv[2], argc > 3 ? argv[3] : "../validation/core_script_oracle");
    long count = argc > 1 ? atol(argv[1]) : 20000; rs = argc > 2 ? strtoull(argv[2], 0, 0) : 0x9e3779b97f4a7c15ULL; if (!rs) rs = 1;
    const char* oracle = argc > 3 ? argv[3] : "../validation/core_script_oracle";
    spawn_oracle(oracle);
    const uint64_t FLAGSET[] = { 1u<<1, 1u<<2, 1u<<3, 1u<<4, 1u<<6, 1u<<9, 1u<<10, 1u<<13 };   /* STRICTENC DERSIG LOW_S NULLDUMMY MINIMALDATA CLTV CSV MINIMALIF */
    long mism = 0, ok_both = 0, fail_both = 0, shown = 0;
    static long hist[2][64][2][64]; int shown_max = argc > 4 ? atoi(argv[4]) : 25;
    static uint8_t script[2048], init[4][600]; int initlen[4];
    for (long c = 0; c < count; c++){
        uint64_t flags = 0; for (unsigned i = 0; i < 8; i++) if (r(2)) flags |= FLAGSET[i];
        if (r(4) == 0) flags = 0;
        uint32_t txv = r(3) == 0 ? 1 : 2, lock = r(2) ? (uint32_t)EDGE[r(30)] : (uint32_t)rnd(), seq = r(2) ? (uint32_t)EDGE[r(30)] : (uint32_t)rnd();
        int ninit = (int)r(4);
        for (int i = 0; i < ninit; i++){ int L = (int)r(r(4) ? 6 : 520); initlen[i] = L; for (int j = 0; j < L; j++) init[i][j] = (uint8_t)rnd(); if (r(3) == 0 && L >= 1) { int64_t v = EDGE[r(30)]; int n = 0; uint64_t a = (uint64_t)(v < 0 ? -v : v); while (a && n < 8){ init[i][n++] = (uint8_t)a; a >>= 8; } if (n && (init[i][n-1] & 0x80)) init[i][n++] = v < 0 ? 0x80 : 0; else if (n && v < 0) init[i][n-1] |= 0x80; initlen[i] = n; } }
        int slen = gen_script(script, sizeof script);
        int sigv = r(3) == 0 ? 1 : 0;
        /* ---- ours ---- */
        memset(main_elems, 0, (size_t)(ninit + 1) * ELEM_SIZE); memset(alt_elems, 0, ELEM_SIZE * 4);
        for (int i = 0; i < ninit; i++){ uint8_t* rec = main_elems + i * ELEM_SIZE; ((uint32_t*)rec)[0] = (uint32_t)initlen[i]; memcpy(rec + 4, init[i], (size_t)initlen[i]); }
        struct script_state st; memset(&st, 0, sizeof st); uint64_t err = 0;
        st.main_elems = main_elems; st.main_sp = (size_t)ninit; st.alt_elems = alt_elems; st.script = script; st.script_len = (size_t)slen;
        st.sigversion = sigv; st.flags = flags; st.error_out = &err; st.checksig_fn = fake_checksig; st.tx_version = txv; st.tx_locktime = lock; st.in_sequence = seq;
        int ours = script_eval(&st);
        /* ---- Core ---- */
        fprintf(oin, "%llx %d %u %u %u ", (unsigned long long)flags, sigv, txv, lock, seq); hexout(oin, script, (size_t)slen);
        for (int i = 0; i < ninit; i++){ fputc(' ', oin); hexout(oin, init[i], (size_t)initlen[i]); }
        fputc('\n', oin); fflush(oin);
        if (!fgets(linebuf, sizeof linebuf, oout)){ fprintf(stderr, "oracle died at case %ld\n", c); return 2; }
        int cok = 0, cerr = 0, cn = 0; char* p = linebuf; cok = (int)strtol(p, &p, 10); cerr = (int)strtol(p, &p, 10); cn = (int)strtol(p, &p, 10);
        /* our final stack as the oracle would print it */
        int o = 0; o += snprintf(ourbuf + o, sizeof ourbuf - (size_t)o, "%d %d %d", ours ? 1 : 0, (int)err, (int)st.main_sp);
        for (size_t i = 0; i < st.main_sp && o < (int)sizeof ourbuf - 1200; i++){ uint8_t* rec = main_elems + i * ELEM_SIZE; uint32_t L = ((uint32_t*)rec)[0]; ourbuf[o++] = ' '; if (!L) ourbuf[o++] = '-'; for (uint32_t j = 0; j < L; j++) o += snprintf(ourbuf + o, 4, "%02x", rec[4 + j]); }
        ourbuf[o] = 0;
        int same;
        if (ours && cok) same = (strcmp(ourbuf + 4, linebuf + 4) == 0 || (cn == (int)st.main_sp && strcmp(strchr(ourbuf, ' ') ? ourbuf : "", "") && !strncmp(ourbuf, linebuf, strlen(ourbuf)) )) , same = (strcmp(ourbuf, linebuf) == 0 || (strlen(linebuf) && linebuf[strlen(linebuf)-1] == '\n' && !strncmp(ourbuf, linebuf, strlen(linebuf) - 1) && strlen(ourbuf) == strlen(linebuf) - 1));
        else same = (!ours && !cok && (int)err == cerr);
        if (same){ if (ours) ok_both++; else fail_both++; }
        else {
            mism++;
            { int oe = ours ? 0 : (int)err, ce = cok ? 0 : cerr; if (oe < 64 && ce < 64) hist[ours ? 1 : 0][oe][cok ? 1 : 0][ce]++; }
            if (shown < shown_max){ shown++; printf("MISMATCH #%ld case %ld\n  in:   %llx %d %u %u %u ", mism, c, (unsigned long long)flags, sigv, txv, lock, seq); hexout(stdout, script, (size_t)slen); for (int i = 0; i < ninit; i++){ putchar(' '); hexout(stdout, init[i], (size_t)initlen[i]); } printf("\n  ours: %s\n  core: %s", ourbuf, linebuf); }
        }
    }
    printf("cases=%ld  both-ok=%ld  both-fail-same-error=%ld  MISMATCHES=%ld\n", count, ok_both, fail_both, mism);
    if (mism){ printf("mismatch classes (ours ok/err -> core ok/err : count):\n");
        for (int a = 0; a < 2; a++) for (int b = 0; b < 64; b++) for (int c = 0; c < 2; c++) for (int d = 0; d < 64; d++) if (hist[a][b][c][d]) printf("  ours %d/%-2d -> core %d/%-2d : %ld\n", a, b, c, d, hist[a][b][c][d]); }
    return mism ? 1 : 0;
}
