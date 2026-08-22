/* test_glv_wnaf.c -- PERF_SCOPE.md 4.3 (c): glv_wnaf (w=5, 129 slots).
 *
 * For >= 1e6 random magnitudes m < 2^128 (the split's contract), presented
 * either as m itself or as n - m (the "bit 255 set" negative form), check:
 *   - every digit is 0 or odd with |d| <= 15,
 *   - a non-zero digit is followed by at least w-1 = 4 zeros,
 *   - sum(d_i * 2^i), accumulated in 256-bit two's complement, equals
 *     +m (positive form) or 2^256 - m (negative form),
 *   - the returned length is the last non-zero index + 1,
 *   - magnitudes >= 2^129 are rejected with -1, never misencoded.
 * Fixed edges: 0, 1, 15, 16, 17, 2^127, 2^128 - 1 (all ones: the skip rule
 * turns it into -1 at slot 0 and +1 at slot 128 -- the carry-into-slot-128
 * case a 128-slot buffer would lose), 2^128, 2^128 + 15; and must-reject:
 * 2^129 - 1 (its top window carries past slot 128), 2^129, 2^192. A value
 * the 129-slot NAF cannot hold must come back as -1, never as a wrong
 * encoding; the split guarantees the halves are < 2^128 so -1 is a
 * fallback signal, not a normal path.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
typedef unsigned __int128 u128;
extern int glv_wnaf(signed char out[129], const u64 s[4]);

static const u64 N[4] = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
static long failures = 0;
#define CK(c, ...) do{ if(!(c)){ failures++; if(failures<=20){ printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } }while(0)
static u64 rng_s = 0x9e3779b97f4a7c15ULL;
static u64 rnd(void){ u64 x=rng_s; x^=x<<13; x^=x>>7; x^=x<<17; rng_s=x; return x; }

static void add_shifted(u64 acc[4], u64 mag, int sh, int neg){   /* acc += (+-mag) << sh, mod 2^256 */
    u64 v[4] = {0,0,0,0};
    int li = sh >> 6, lo = sh & 63;
    u128 w = (u128)mag << lo;
    if (li < 4) v[li] = (u64)w;
    if (li + 1 < 4) v[li+1] = (u64)(w >> 64);
    if (neg) { u128 br=0; for(int i=0;i<4;i++){ u128 t=(u128)0 - v[i] - br; v[i]=(u64)t; br=(t>>64)&1; } }
    u128 c=0; for(int i=0;i<4;i++){ u128 t=(u128)acc[i]+v[i]+c; acc[i]=(u64)t; c=t>>64; }
}

static void check_one(const u64 m[4], int negative, const char* lbl){
    u64 s[4]; memcpy(s, m, 32);
    if (negative) { u128 br=0; for(int i=0;i<4;i++){ u128 t=(u128)N[i]-m[i]-br; s[i]=(u64)t; br=(t>>64)&1; } }
    signed char d[129];
    int bits = glv_wnaf(d, s);
    CK(bits >= 0 && bits <= 129, "%s: bits=%d", lbl, bits);
    if (bits < 0) return;
    u64 acc[4] = {0,0,0,0}; int last = -1;
    for (int i = 0; i < 129; i++) {
        int v = d[i];
        if (v == 0) continue;
        CK((v & 1) && v >= -15 && v <= 15, "%s: digit %d at %d", lbl, v, i);
        for (int j = 1; j <= 4 && i + j < 129; j++) CK(d[i+j] == 0, "%s: non-zero within 4 of %d", lbl, i);
        add_shifted(acc, (u64)(v < 0 ? -v : v), i, v < 0);
        last = i;
    }
    CK(bits == last + 1, "%s: bits=%d last=%d", lbl, bits, last);
    u64 want[4]; memcpy(want, m, 32);
    if (negative) { u128 br=0; for(int i=0;i<4;i++){ u128 t=(u128)0-m[i]-br; want[i]=(u64)t; br=(t>>64)&1; } }
    CK(memcmp(acc, want, 32) == 0, "%s: reconstruction mismatch", lbl);
}

int main(int argc, char** argv){
    long n = (argc > 1) ? atol(argv[1]) : 1000000L;
    static const u64 E[][4] = {
        {0,0,0,0},{1,0,0,0},{15,0,0,0},{16,0,0,0},{17,0,0,0},{0,0x8000000000000000ULL,0,0},
        {~0ULL,~0ULL,0,0},{0,0,1,0},{15,0,1,0},
    };
    for (unsigned i = 0; i < sizeof E / sizeof E[0]; i++) { char l[32]; snprintf(l,sizeof l,"edge%u+",i); check_one(E[i],0,l); snprintf(l,sizeof l,"edge%u-",i); check_one(E[i],1,l); }
    { u64 big[4] = {~0ULL,~0ULL,1,0}; signed char d[129]; CK(glv_wnaf(d, big) == -1, "2^129-1 must be rejected (carry past slot 128)"); }
    { u64 big[4] = {0,0,2,0}; signed char d[129]; CK(glv_wnaf(d, big) == -1, "2^129 must be rejected"); }
    { u64 big[4] = {0,0,0,1}; signed char d[129]; CK(glv_wnaf(d, big) == -1, "2^192 must be rejected"); }
    long cnt = 0;
    for (long t = 0; t < n; t++) {
        u64 m[4] = {rnd(), rnd(), 0, 0};
        if ((t & 7) == 1) m[1] &= 0xFFFFFFFFULL;          /* short magnitudes too */
        check_one(m, (int)(t & 1), "random");
        cnt++;
    }
    printf("glv_wnaf: %ld random magnitudes (+- forms) + %zu edges\n", cnt, 2*(sizeof E/sizeof E[0]));
    if (failures) { printf("TESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n"); return 0;
}
