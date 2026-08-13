#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_double(u64 r[12], const u64 p[12]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);

static int failures = 0;
static void toaff(u64 outx[4], u64 outy[4], const u64 jac[12]) {
    u64 zi[4], zi2[4], zi3[4];
    fe_inv(zi, &jac[8]);
    fe_sqr(zi2, zi);
    fe_mul(zi3, zi2, zi);
    fe_mul(outx, &jac[0], zi2);
    fe_mul(outy, &jac[4], zi3);
}
static void cmp(const char*lbl,const u64 got[4],const u64 exp[4]) {
    if (memcmp(got,exp,32)==0) printf("PASS %s\n",lbl);
    else { printf("FAIL %s\n  got %016llx %016llx %016llx %016llx\n  exp %016llx %016llx %016llx %016llx\n",
        lbl,got[0],got[1],got[2],got[3],exp[0],exp[1],exp[2],exp[3]); failures++; }
}
static const u64 G[12] = {
    /*X*/ 0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
    /*Y*/ 0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL,
    /*Z*/ 1, 0, 0, 0 };
int main(void){
    u64 d[12], ax[4], ay[4];
    point_double(d, G);
    toaff(ax, ay, d);
    printf("point_double(G) -> d[0]=%016llx Z=%016llx\n", d[0], d[8]);
    /* expected 2G affine */
    u64 ex[4] = {0xabac09b95c709ee5ULL,0x5c778e4b8cef3ca7ULL,0x3045406e95c07cd8ULL,0xc6047f9441ed7d6dULL};
    u64 ey[4] = {0x236431a950cfe52aULL,0xf7f632653266d0e1ULL,0xa3c58419466ceaeeULL,0x1ae168fea63dc339ULL};
    cmp("point_double(G).x == 2G.x", ax, ex);
    cmp("point_double(G).y == 2G.y", ay, ey);
    return failures?1:0;
}
