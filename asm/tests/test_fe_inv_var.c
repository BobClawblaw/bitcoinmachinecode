/* test_fe_inv_var.c -- fe_inv_var (safegcd mod p, safegcd_var.inc) against
 * fe_inv (the constant-time addition chain, unchanged), byte for byte; plus
 * the one behaviour the shared macro added to sc_inv_var (an input >= n is
 * reduced first) against sc_inv.
 *
 * fe_inv_var:
 *   - edges: 1, 2, p-1, p-2, 2^255, single bits, all-ones limbs below p
 *   - 1e6 random canonical elements (argv[2] scales)
 *   - non-canonical inputs a in [p, 2^256): must equal fe_inv(a - p)
 *   - a == 0 and a == p (both 0 mod p): return 0 and leave r untouched
 *   - r aliasing a
 *   - a * inv(a) == 1 for every canonical input
 * sc_inv_var:
 *   - a in [n, 2^256): must equal sc_inv(a - n); a == n returns 0.
 *
 * argv[1] = seed, argv[2] = random count (default 1000000). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;

extern int  fe_inv_var(u64 r[4], const u64 a[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern int  sc_inv_var(u64 r[4], const u64 a[4]);
extern void sc_inv(u64 r[4], const u64 a[4]);

static const u64 P[4] = {0xFFFFFFFEFFFFFC2FULL, ~0ULL, ~0ULL, ~0ULL};
static const u64 N[4] = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
static const u64 ONE[4] = {1,0,0,0};

static long failures, checks;
#define CK(c, ...) do{ checks++; if(!(c)){ if(failures++ < 10){ printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } }while(0)

static u64 rs;
static u64 rnd(void){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }
static int lt(const u64 a[4], const u64 m[4]){ for(int i=3;i>=0;i--){ if(a[i]<m[i]) return 1; if(a[i]>m[i]) return 0; } return 0; }
static void sub4(u64 r[4], const u64 a[4], const u64 b[4]){
    unsigned __int128 br=0;
    for(int i=0;i<4;i++){ unsigned __int128 t=(unsigned __int128)a[i]-b[i]-br; r[i]=(u64)t; br=(t>>64)&1; }
}
static int iszero(const u64 a[4]){ return !(a[0]|a[1]|a[2]|a[3]); }

static void check_fe(const u64 a[4], const char* what){
    u64 v[4], f[4], prod[4];
    memset(v, 0x5A, 32);
    int ok = fe_inv_var(v, a);
    fe_inv(f, a);
    CK(ok == 1, "%s: fe_inv_var returned %d for a=%016llx..%016llx", what, ok, a[3], a[0]);
    CK(!memcmp(v, f, 32), "%s: fe_inv_var != fe_inv for a=%016llx..%016llx: %016llx.. vs %016llx..", what, a[3], a[0], v[3], f[3]);
    fe_mul(prod, a, v);
    CK(!memcmp(prod, ONE, 32), "%s: a * fe_inv_var(a) != 1 for a=%016llx..%016llx", what, a[3], a[0]);
}

int main(int argc, char** argv){
    rs = argc > 1 ? strtoull(argv[1], 0, 0) : 0x5AFE6CD0DDBA11ULL;
    long n = argc > 2 ? atol(argv[2]) : 1000000;
    printf("seed=0x%016llx n=%ld\n", rs, n);
    u64 a[4], r[4];

    u64 edges[][4] = {
        {1,0,0,0}, {2,0,0,0}, {3,0,0,0}, {7,0,0,0},
        {P[0]-1, P[1], P[2], P[3]}, {P[0]-2, P[1], P[2], P[3]},
        {0,0,0,1ULL<<63}, {~0ULL,0,0,0}, {~0ULL,~0ULL,~0ULL,0x7FFFFFFFFFFFFFFFULL},
        {0xFFFFFFFEFFFFFC2EULL, ~0ULL, ~0ULL, ~0ULL}, {0x1000003D1ULL,0,0,0},
    };
    for (unsigned i = 0; i < sizeof edges/sizeof edges[0]; i++) check_fe(edges[i], "edge");
    for (int b = 0; b < 256; b++){ memset(a,0,32); a[b>>6] = 1ULL<<(b&63); if (lt(a,P)) check_fe(a, "bit"); }

    for (long i = 0; i < n; i++){
        do { for (int k=0;k<4;k++) a[k]=rnd(); } while (!lt(a,P) || iszero(a));
        check_fe(a, "random");
    }

    /* non-canonical: a in [p, 2^256) */
    long nc = 0;
    for (u64 d = 1; d < 0x1000003D1ULL; d = d*3 + 1){           /* a = p + d, spread up to 2^256-1 */
        u64 pd[4]; memcpy(pd, P, 32);
        unsigned __int128 c = (unsigned __int128)pd[0] + d; pd[0]=(u64)c; c>>=64;
        for (int k=1;k<4 && c;k++){ c += pd[k]; pd[k]=(u64)c; c>>=64; }
        if (c) break;                                            /* past 2^256 */
        u64 red[4], v[4], f[4]; sub4(red, pd, P);
        int ok = fe_inv_var(v, pd); fe_inv(f, red);
        CK(ok == 1 && !memcmp(v, f, 32), "noncanonical fe: a = p + %llu", d);
        nc++;
    }
    { u64 top[4] = {~0ULL,~0ULL,~0ULL,~0ULL}, red[4], v[4], f[4]; sub4(red, top, P);
      int ok = fe_inv_var(v, top); fe_inv(f, red);
      CK(ok == 1 && !memcmp(v, f, 32), "noncanonical fe: a = 2^256-1"); nc++; }

    /* zero mod p: 0 and p itself */
    const u64 Z[4] = {0,0,0,0};
    memset(r, 0x77, 32); CK(fe_inv_var(r, Z) == 0, "fe_inv_var(0) must return 0");
    CK(r[0]==0x7777777777777777ULL && r[3]==0x7777777777777777ULL, "fe_inv_var(0) must not write r");
    memset(r, 0x77, 32); CK(fe_inv_var(r, P) == 0, "fe_inv_var(p) must return 0");
    CK(r[0]==0x7777777777777777ULL, "fe_inv_var(p) must not write r");

    /* aliasing */
    do { for (int k=0;k<4;k++) a[k]=rnd(); } while (!lt(a,P) || iszero(a));
    { u64 f[4], x[4]; fe_inv(f, a); memcpy(x, a, 32); fe_inv_var(x, x); CK(!memcmp(x, f, 32), "alias: fe_inv_var(a, a)"); }

    /* sc_inv_var: the entry reduction the shared macro added */
    long ns = 0;
    for (long i = 0; i < 20000; i++){
        u64 an[4], red[4], v[4], f[4];
        do { for (int k=0;k<4;k++) an[k]=rnd(); an[3] = ~0ULL; an[2] |= 0xFFFFFFFFFFFFFFFEULL; } while (lt(an, N));
        sub4(red, an, N);
        if (iszero(red)) continue;
        int ok = sc_inv_var(v, an); sc_inv(f, red);
        CK(ok == 1 && !memcmp(v, f, 32), "noncanonical sc: a=%016llx..%016llx", an[3], an[0]);
        ns++;
    }
    memset(r, 0x77, 32); CK(sc_inv_var(r, N) == 0 && r[0]==0x7777777777777777ULL, "sc_inv_var(n) must return 0, r untouched");

    printf("fe_inv_var vs fe_inv: %ld random + edges/bits; %ld non-canonical; sc_inv_var non-canonical: %ld\n", n, nc, ns);
    if (failures){ printf("\nTESTS FAILED (%ld failures of %ld checks)\n", failures, checks); return 1; }
    printf("\nALL TESTS PASSED (%ld checks, 0 failures)\n", checks);
    return 0;
}
