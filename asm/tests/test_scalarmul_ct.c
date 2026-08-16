/* test_scalarmul_ct.c -- acceptance tests for point_scalar_mul_ct (FINDING 1).
 *
 *   1. Known-answer tests: 1G, 2G, 3G, kbig, nG==infinity.
 *   2. Cross-check: point_scalar_mul_ct(k,P) == point_scalar_mul(k,P) in
 *      affine, over random scalars AND random (non-G) base points.
 *   3. Timing invariance: the variable-time routine's runtime tracks the
 *      scalar's bit-length / digit pattern; the CT routine's must not.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
typedef unsigned long long u64;

extern void point_scalar_mul   (u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);

static int failures = 0;

static int is_inf(const u64 j[12]){ return !(j[8]|j[9]|j[10]|j[11]); }

static void toaff(u64 ox[4], u64 oy[4], const u64 j[12]){
    u64 zi[4], z2[4], z3[4];
    fe_inv(zi, &j[8]); fe_sqr(z2, zi); fe_mul(z3, z2, zi);
    fe_mul(ox, &j[0], z2); fe_mul(oy, &j[4], z3);
}

static void ck(const char *l, const u64 g[4], const u64 e[4]){
    if (memcmp(g, e, 32) == 0) printf("PASS %s\n", l);
    else { printf("FAIL %s\n  got %016llx %016llx %016llx %016llx\n"
                  "  exp %016llx %016llx %016llx %016llx\n",
                  l, g[0],g[1],g[2],g[3], e[0],e[1],e[2],e[3]); failures++; }
}

static const u64 Gaff[8] = {
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};

/* xorshift64* so the test is reproducible without libc rand differences */
static u64 st = 0x9E3779B97F4A7C15ULL;
static u64 rnd(void){ st ^= st>>12; st ^= st<<25; st ^= st>>27; return st*0x2545F4914F6CDD1DULL; }

static double now_s(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec*1e-9;
}

int main(void){
    u64 r[12], ax[4], ay[4];

    /* ---------- 1. known-answer tests ---------- */
    u64 k1[4]={1,0,0,0};
    point_scalar_mul_ct(r, Gaff, k1); toaff(ax,ay,r);
    ck("1G.x", ax, (u64[]){Gaff[0],Gaff[1],Gaff[2],Gaff[3]});
    ck("1G.y", ay, (u64[]){Gaff[4],Gaff[5],Gaff[6],Gaff[7]});

    u64 k2[4]={2,0,0,0};
    point_scalar_mul_ct(r, Gaff, k2); toaff(ax,ay,r);
    ck("2G.x", ax, (u64[]){0xABAC09B95C709EE5ULL,0x5C778E4B8CEF3CA7ULL,0x3045406E95C07CD8ULL,0xC6047F9441ED7D6DULL});
    ck("2G.y", ay, (u64[]){0x236431A950CFE52AULL,0xF7F632653266D0E1ULL,0xA3C58419466CEAEEULL,0x1AE168FEA63DC339ULL});

    u64 k3[4]={3,0,0,0};
    point_scalar_mul_ct(r, Gaff, k3); toaff(ax,ay,r);
    ck("3G.x", ax, (u64[]){0x8601F113BCE036F9ULL,0xB531C845836F99B0ULL,0x49344F85F89D5229ULL,0xF9308A019258C310ULL});
    ck("3G.y", ay, (u64[]){0x6CB9FD7584B8E672ULL,0x6500A99934C2231BULL,0x0FE337E62A37F356ULL,0x388F7B0F632DE814ULL});

    u64 kbig[4]={0x1234567890ABCDEFULL,0x1234567890ABCDEFULL,0,0};
    point_scalar_mul_ct(r, Gaff, kbig); toaff(ax,ay,r);
    ck("kbig.x", ax, (u64[]){0xDF502B61290BBF5EULL,0x094C533603687850ULL,0x911BF9E8C067BCF6ULL,0x9377C312145A5AFBULL});
    ck("kbig.y", ay, (u64[]){0xCAF6144B679779FBULL,0xDC7BB61E3AB527CEULL,0x2DCCCB176E7C8F9BULL,0x742BA607D6AE1FC8ULL});

    u64 n[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
    point_scalar_mul_ct(r, Gaff, n);
    if (is_inf(r) && r[0]==1 && r[4]==1) printf("PASS nG==canonical infinity (1,1,0)\n");
    else { printf("FAIL nG infinity: X0=%llx Y0=%llx Z=%llx\n", r[0], r[4], r[8]); failures++; }

    u64 k0[4]={0,0,0,0};
    point_scalar_mul_ct(r, Gaff, k0);
    if (is_inf(r)) printf("PASS 0G==infinity\n");
    else { printf("FAIL 0G != infinity\n"); failures++; }

    /* ---------- 2. cross-check vs the variable-time routine ---------- */
    /* random scalars against G */
    int mism = 0;
    for (int i = 0; i < 2000; i++){
        u64 k[4] = { rnd(), rnd(), rnd(), rnd() };
        u64 rv[12], rc[12], vx[4], vy[4], cx[4], cy[4];
        point_scalar_mul   (rv, Gaff, k);
        point_scalar_mul_ct(rc, Gaff, k);
        if (is_inf(rv) != is_inf(rc)) { mism++; continue; }
        if (is_inf(rv)) continue;
        toaff(vx,vy,rv); toaff(cx,cy,rc);
        if (memcmp(vx,cx,32) || memcmp(vy,cy,32)) {
            if (mism < 3) printf("  MISMATCH k=%016llx%016llx%016llx%016llx\n", k[3],k[2],k[1],k[0]);
            mism++;
        }
    }
    if (mism) { printf("FAIL cross-check vs point_scalar_mul: %d/2000 mismatches\n", mism); failures++; }
    else printf("PASS cross-check vs point_scalar_mul (2000 random scalars, base=G)\n");

    /* random NON-G base points: P = m*G for random m, then compare k*P */
    mism = 0;
    for (int i = 0; i < 300; i++){
        u64 m[4] = { rnd(), rnd(), rnd(), rnd() };
        u64 pj[12], paff[8];
        point_scalar_mul(pj, Gaff, m);
        if (is_inf(pj)) continue;
        toaff(&paff[0], &paff[4], pj);
        u64 k[4] = { rnd(), rnd(), rnd(), rnd() };
        u64 rv[12], rc[12], vx[4], vy[4], cx[4], cy[4];
        point_scalar_mul   (rv, paff, k);
        point_scalar_mul_ct(rc, paff, k);
        if (is_inf(rv) != is_inf(rc)) { mism++; continue; }
        if (is_inf(rv)) continue;
        toaff(vx,vy,rv); toaff(cx,cy,rc);
        if (memcmp(vx,cx,32) || memcmp(vy,cy,32)) mism++;
    }
    if (mism) { printf("FAIL cross-check on random base points: %d mismatches\n", mism); failures++; }
    else printf("PASS cross-check on 300 random (non-G) base points\n");

    /* small scalars where the variable-time path takes its short routes */
    mism = 0;
    for (u64 s = 1; s <= 512; s++){
        u64 k[4] = { s, 0, 0, 0 };
        u64 rv[12], rc[12], vx[4], vy[4], cx[4], cy[4];
        point_scalar_mul   (rv, Gaff, k);
        point_scalar_mul_ct(rc, Gaff, k);
        toaff(vx,vy,rv); toaff(cx,cy,rc);
        if (memcmp(vx,cx,32) || memcmp(vy,cy,32)) mism++;
    }
    if (mism) { printf("FAIL small-scalar cross-check: %d/512\n", mism); failures++; }
    else printf("PASS small-scalar cross-check (k=1..512)\n");

    /* ---------- 3. timing invariance ---------- */
    /* Two scalar classes chosen to be maximally different for the
     * variable-time routine: tiny (short bsr bound, few nonzero digits)
     * vs full-width dense. */
    u64 tiny[4] = {0xFF, 0, 0, 0};
    u64 dense[4]= {0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0x7FFFFFFFFFFFFFFFULL};
    const int reps = 300;
    double t_v_tiny, t_v_dense, t_c_tiny, t_c_dense, s;

    s = now_s(); for(int i=0;i<reps;i++) point_scalar_mul(r, Gaff, tiny);  t_v_tiny  = now_s()-s;
    s = now_s(); for(int i=0;i<reps;i++) point_scalar_mul(r, Gaff, dense); t_v_dense = now_s()-s;
    s = now_s(); for(int i=0;i<reps;i++) point_scalar_mul_ct(r, Gaff, tiny);  t_c_tiny  = now_s()-s;
    s = now_s(); for(int i=0;i<reps;i++) point_scalar_mul_ct(r, Gaff, dense); t_c_dense = now_s()-s;

    double v_ratio = t_v_dense / t_v_tiny;
    double c_ratio = t_c_dense / t_c_tiny;
    printf("\n  variable-time : tiny %.2f ms  dense %.2f ms  ratio %.2fx\n",
           t_v_tiny*1e3/reps, t_v_dense*1e3/reps, v_ratio);
    printf("  constant-time : tiny %.2f ms  dense %.2f ms  ratio %.3fx\n",
           t_c_tiny*1e3/reps, t_c_dense*1e3/reps, c_ratio);
    if (c_ratio > 1.05 || c_ratio < 0.95) {
        printf("FAIL CT timing ratio %.3f outside [0.95,1.05]\n", c_ratio);
        failures++;
    } else {
        printf("PASS CT timing ratio %.3f within 5%% (variable-time leaks %.1fx)\n",
               c_ratio, v_ratio);
    }

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
