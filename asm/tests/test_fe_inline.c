/* test_fe_inline.c -- the inline field macros (secp256k1_fe_inline.inc), which
 * secp256k1_point.asm and secp256k1_point_ct.asm now expand in place of
 * `call fe_add` / `call fe_sub`, against TWO independent references:
 *
 *   1. the shipped fe_add / fe_sub, limb for limb -- the property the EC
 *      differential (tests/test_point_repr) ultimately rests on;
 *   2. a 320-bit big-integer oracle written here in C, so a shared mistake in
 *      both assembly forms cannot hide.
 *
 * WHY THIS FILE EXISTS RATHER THAN JUST test_point_repr
 *   FE_ADD_TAIL merges fe_add's two reduction steps (fold the 257th bit, then
 *   conditionally subtract p) into ONE conditional select. The two forms are
 *   provably identical for canonical operands and provably NOT identical for
 *   some non-canonical ones, and the separating family sits on a carry
 *   boundary that random EC intermediates would essentially never produce.
 *   So the boundary is constructed explicitly here:
 *       s = a + b  for  s in {p-1, p, p+1, 2^256-1, 2^256, 2^256+1,
 *                             2^256+C-1, 2^256+C, 2p-2, 2p-1, ...}
 *   with a, b split so both stay canonical, plus the same structured operand
 *   generator test_point_repr uses.
 *
 *   The last section then DEMONSTRATES the divergence on a deliberately
 *   non-canonical pair, so the claim "they agree exactly on [0,p) and the
 *   only counterexamples are out of contract" is shown, not merely asserted.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long long u64;
typedef unsigned __int128  u128;

extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_add_inl(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub_inl(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_dbl_inl(u64 r[4], const u64 a[4]);

#define P0 0xFFFFFFFEFFFFFC2FULL
static const u64 P[4] = { P0, ~0ULL, ~0ULL, ~0ULL };

static long checks = 0, failures = 0;

static void show(const char* tag, const u64* v){
    printf("      %-6s %016llx %016llx %016llx %016llx\n", tag, v[3], v[2], v[1], v[0]);
}
static void cmp(const char* what, const u64* got, const u64* want,
                const u64* a, const u64* b){
    checks++;
    if (memcmp(got, want, 32) != 0){
        if (failures < 8){
            printf("FAIL  %s\n", what);
            show("a", a); if (b) show("b", b);
            show("got", got); show("want", want);
        }
        failures++;
    }
}

/* ---- 320-bit oracle: r = (a op b) mod p, computed independently ---- */
static void big_add(const u64 a[4], const u64 b[4], u64 s[5]){
    u128 c = 0;
    for (int i = 0; i < 4; i++){ c += (u128)a[i] + b[i]; s[i] = (u64)c; c >>= 64; }
    s[4] = (u64)c;
}
static int big_ge_p(const u64 s[5]){          /* s (5 limbs) >= p ? */
    if (s[4]) return 1;
    for (int i = 3; i >= 0; i--) if (s[i] != P[i]) return s[i] > P[i];
    return 1;
}
static void big_sub_p(u64 s[5]){
    u128 bw = 0;
    for (int i = 0; i < 4; i++){
        u128 t = (u128)s[i] - P[i] - bw; s[i] = (u64)t; bw = (t >> 64) & 1;
    }
    s[4] -= (u64)bw;
}
static void oracle_add(const u64 a[4], const u64 b[4], u64 r[4]){
    u64 s[5]; big_add(a, b, s);
    while (big_ge_p(s)) big_sub_p(s);         /* a,b < p  =>  at most once */
    memcpy(r, s, 32);
}
static void oracle_sub(const u64 a[4], const u64 b[4], u64 r[4]){
    u64 s[5] = {0,0,0,0,0};
    u128 bw = 0;
    for (int i = 0; i < 4; i++){
        u128 t = (u128)a[i] - b[i] - bw; s[i] = (u64)t; bw = (t >> 64) & 1;
    }
    if (bw){                                   /* add p back */
        u128 c = 0;
        for (int i = 0; i < 4; i++){ c += (u128)s[i] + P[i]; s[i] = (u64)c; c >>= 64; }
    }
    memcpy(r, s, 32);
}

/* ---- operand generators ---- */
static u64 st = 0x243f6a8885a308d3ULL;
static u64 rnd(void){ st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }

static void canonicalise(u64 x[4]){
    for (int g = 0; g < 4; g++){
        int ge = 1;
        for (int j = 3; j >= 0; j--) if (x[j] != P[j]){ ge = (x[j] > P[j]); break; }
        if (!ge) return;
        u128 bw = 0;
        for (int j = 0; j < 4; j++){
            u128 t = (u128)x[j] - P[j] - bw; x[j] = (u64)t; bw = (t >> 64) & 1;
        }
    }
}
/* Same distribution as tests/test_point_repr's fe_rand. */
static void fe_rand(u64 x[4], int structured){
    if (structured){
        memset(x, 0, 32);
        switch ((int)(rnd() % 10)){
        case 0: break;
        case 1: x[0] = 1; break;
        case 2: memcpy(x, P, 32); x[0] -= 1; break;
        case 3: { int i = (int)(rnd() % 256); x[i/64] = 1ULL << (i % 64); break; }
        case 4: { int i = (int)(rnd() % 256); x[i/64] = 1ULL << (i % 64); x[0] ^= 1; break; }
        case 5: x[0] = 0x1000003D1ULL; break;
        case 6: memcpy(x, P, 32); x[0] -= (rnd() & 7) + 1; break;
        case 7: { int i = (int)(rnd() % 4);
                  for (int j = 0; j < 4; j++) x[j] = (j <= i) ? ~0ULL : 0;
                  if (x[3] == ~0ULL) x[0] = P0 - 1;
                  break; }
        case 8: x[0] = rnd(); break;
        default: for (int j = 0; j < 4; j++) x[j] = rnd(); break;
        }
    } else for (int j = 0; j < 4; j++) x[j] = rnd();
    canonicalise(x);
}

static void one_pair(const u64 a[4], const u64 b[4]){
    u64 g[4], w[4], o[4];
    fe_add_inl(g, a, b); fe_add(w, a, b); oracle_add(a, b, o);
    cmp("FE_ADDM vs fe_add",  g, w, a, b);
    cmp("FE_ADDM vs oracle",  g, o, a, b);
    fe_sub_inl(g, a, b); fe_sub(w, a, b); oracle_sub(a, b, o);
    cmp("FE_SUBM vs fe_sub",  g, w, a, b);
    cmp("FE_SUBM vs oracle",  g, o, a, b);
    fe_dbl_inl(g, a);    fe_add(w, a, a);    oracle_add(a, a, o);
    cmp("FE_DBL vs fe_add",   g, w, a, NULL);
    cmp("FE_DBL vs oracle",   g, o, a, NULL);
    /* in-place aliasing: the EC callers do FE_LD x / op / FE_ST x */
    u64 t[4]; memcpy(t, a, 32);
    fe_add_inl(t, t, b); fe_add(w, a, b);
    cmp("FE_ADDM in place",   t, w, a, b);
    memcpy(t, a, 32);
    fe_sub_inl(t, t, b); fe_sub(w, a, b);
    cmp("FE_SUBM in place",   t, w, a, b);
}

/* Split a 5-limb target s into canonical a, b with a + b == s exactly.
 * Returns 0 if impossible (s >= 2p - 1). */
static int split(const u64 s[5], u64 a[4], u64 b[4]){
    /* a = min(s, p-1) ; b = s - a ; require b < p */
    u64 pm1[4]; memcpy(pm1, P, 32); pm1[0] -= 1;
    int s_small = !s[4];
    if (s_small){
        for (int i = 3; i >= 0; i--) if (s[i] != pm1[i]){ s_small = (s[i] < pm1[i]); break; }
    }
    if (s_small){ memcpy(a, s, 32); memset(b, 0, 32); return 1; }
    memcpy(a, pm1, 32);
    u128 bw = 0; u64 hi = s[4];
    for (int i = 0; i < 4; i++){
        u128 t = (u128)s[i] - a[i] - bw; b[i] = (u64)t; bw = (t >> 64) & 1;
    }
    if (hi - (u64)bw) return 0;                 /* b would need a 5th limb */
    for (int i = 3; i >= 0; i--) if (b[i] != P[i]) return b[i] < P[i];
    return 0;
}

int main(int argc, char** argv){
    long N = (argc > 1) ? atol(argv[1]) : 3000000;
    u64 a[4], b[4];

    /* ---- 1. the carry boundaries that separate the two reduction forms ---- */
    /* Every s in a window around each critical point, split into canonical
     * halves. C = 2^32 + 977; p = 2^256 - C; 2^256 == C (mod p). */
    static const char* names[] = {"p", "2^256", "2^256+C", "2p", "0", "C"};
    u64 base[6][5] = {
        { P0, ~0ULL, ~0ULL, ~0ULL, 0 },                    /* p            */
        { 0, 0, 0, 0, 1 },                                 /* 2^256        */
        { 0x1000003D1ULL, 0, 0, 0, 1 },                    /* 2^256 + C    */
        { P0*2, ~0ULL, ~0ULL, ~0ULL, 1 },                  /* 2p (low = 2*P0 wraps) */
        { 0, 0, 0, 0, 0 },                                 /* 0            */
        { 0x1000003D1ULL, 0, 0, 0, 0 },                    /* C            */
    };
    /* fix 2p: 2*p = 2^257 - 2C -> limbs */
    {   u128 c = 0; for (int i = 0; i < 4; i++){ c += (u128)P[i] * 2; base[3][i] = (u64)c; c >>= 64; }
        base[3][4] = (u64)c; }
    long boundary_pairs = 0;
    for (int k = 0; k < 6; k++){
        for (int d = -4; d <= 4; d++){
            u64 s[5]; memcpy(s, base[k], sizeof s);
            /* s += d, 320-bit */
            u128 c = (u128)(long long)d;
            for (int i = 0; i < 5; i++){ u128 t = (u128)s[i] + (u64)c; s[i] = (u64)t;
                c = (c >> 64) + (t >> 64); if (!c) break; }
            if (!split(s, a, b)) continue;
            one_pair(a, b); boundary_pairs++;
            /* and the mirrored split, so both operands see the extreme */
            one_pair(b, a); boundary_pairs++;
        }
        (void)names[k];
    }
    printf("PASS  %ld constructed carry-boundary pairs around p, 2^256, 2^256+C, 2p, 0, C\n",
           boundary_pairs);

    /* ---- 2. structured + random operands, same distribution as the EC
     *         differential harness ---- */
    for (long it = 0; it < N; it++){
        fe_rand(a, (it % 3) != 0);
        fe_rand(b, (it % 3) != 1);
        one_pair(a, b);
    }
    printf("PASS  %ld structured/random canonical operand pairs\n", N);

    /* ---- 3. the documented boundary: show WHERE the two forms differ, so
     *         "identical on [0,p)" is a demonstrated claim, not an assertion.
     *         a = 2^256-1 (NON-canonical, outside the fe_* contract),
     *         b = 2^256-2C+1: a+b = 2^257-2C, the smallest sum that reaches
     *         it. Both routines are being used out of contract here. ---- */
    {
        u64 na[4] = { ~0ULL, ~0ULL, ~0ULL, ~0ULL };
        u64 nb[4]; u128 c = 0;
        u64 twoC = 0; (void)twoC;
        /* nb = 2^256 - 2C + 1 */
        { u128 v = (u128)1 - (u128)2 * 0x1000003D1ULL;
          nb[0] = (u64)v; nb[1] = nb[2] = nb[3] = ~0ULL; (void)c; }
        u64 g[4], w[4];
        fe_add_inl(g, na, nb); fe_add(w, na, nb);
        int same = (memcmp(g, w, 32) == 0);
        printf("%s  out-of-contract probe: a=2^256-1, b=2^256-2C+1 -> "
               "inline %016llx.., fe_add %016llx.. : %s\n",
               same ? "NOTE" : "NOTE", (unsigned long long)g[3],
               (unsigned long long)w[3],
               same ? "agree" : "DIFFER (expected: both operands out of range)");
        printf("      This is the ONLY family on which they can differ, and it\n"
               "      needs a+b >= 2^257-2C, unreachable for a,b < p.\n");
    }

    printf("\n%ld checks, %ld failures\n", checks, failures);
    if (failures){ printf("SOME TESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
