#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void sc_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_sqr(u64 r[4], const u64 a[4]);
extern void sc_inv(u64 r[4], const u64 a[4]);
static int failures = 0;
static void ck3(const char*lbl, const u64 r[4], const u64 e[4]){
    if (memcmp(r, e, 32) == 0) printf("PASS %s\n", lbl);
    else { printf("FAIL %s\n  got %016llx %016llx %016llx %016llx\n  exp %016llx %016llx %016llx %016llx\n",
        lbl, r[0],r[1],r[2],r[3], e[0],e[1],e[2],e[3]); failures++; }
}
#define A {0xbfd25e8cd0364140ULL,0xbaaedce6af48a03bULL,0xfffffffffffffffeULL,0xffffffffffffffffULL} /* n-1 */
#define B {0x0000000000000001ULL,0x0000000000000000ULL,0x0000000000000000ULL,0x0000000000000000ULL}
int main(void){
    u64 r[4];
    /* add(n-1,1)=0 */
    u64 n1[4]=A, one[4]=B, zero[4]={0,0,0,0};
    sc_add(r, n1, one); ck3("sc_add(n-1,1)=0", r, zero);
    /* add(n-1,n-1)=n-2 */
    u64 nm2[4]={0xbfd25e8cd036413fULL,0xbaaedce6af48a03bULL,0xfffffffffffffffeULL,0xffffffffffffffffULL};
    sc_add(r, n1, n1); ck3("sc_add(n-1,n-1)=n-2", r, nm2);
    /* sub(0,1)=n-1 */
    sc_sub(r, zero, one); ck3("sc_sub(0,1)=n-1", r, n1);
    /* mul(n-1,n-1)=1 */
    sc_mul(r, n1, n1); ck3("sc_mul(n-1,n-1)=1", r, one);
    /* mul(1,1)=1 */
    sc_mul(r, one, one); ck3("sc_mul(1,1)=1", r, one);
    /* mul(0x1234567890abcdef1234567890abcdef, 0x1111...) */
    u64 ba[4]={0x1234567890abcdefULL,0x1234567890abcdefULL,0,0};
    u64 bb[4]={0x1111111111111111ULL,0x1111111111111111ULL,0,0};
    u64 eb[4]={0xfec94f918ff48bdfULL,0xfec94f918ff48bdeULL,0x0136b06e700b7420ULL,0x0136b06e700b7421ULL};
    sc_mul(r, ba, bb); ck3("sc_mul(big)", r, eb);
    /* sqr(2)=4 */
    u64 two[4]={2,0,0,0}, four[4]={4,0,0,0};
    sc_sqr(r, two); ck3("sc_sqr(2)=4", r, four);
    /* inv(2) */
    u64 e2[4]={0xdfe92f46681b20a1ULL,0x5d576e7357a4501dULL,0xffffffffffffffffULL,0x7fffffffffffffffULL};
    sc_inv(r, two); ck3("sc_inv(2)", r, e2);
    /* inv(3) ; 3*inv(3)==1 */
    u64 three[4]={3,0,0,0}, prod[4], one2[4]={1,0,0,0};
    sc_inv(r, three); sc_mul(prod, r, three); ck3("3*inv(3)==1", prod, one2);
    /* a random pair: rand0 add */
    u64 ra[4]={0xc84a76077d1977f9ULL,0x11c48a08fcfc606bULL,0xfe4f40d33e9c06e9ULL,0x8d8629252bb3d5edULL};
    u64 rb[4]={0x647d62c6874903eeULL,0xea57e44c2cdb8479ULL,0x83b8f56e52d15286ULL,0x48f0c558d15342feULL};
    u64 rsum[4]={0x2cc7d8ce04627be7ULL,0xfc1c6e5529d7e4e5ULL,0x82083641916d596fULL,0xd676ee7dfd0718ecULL};
    sc_add(r, ra, rb); ck3("sc_add rand0", r, rsum);
    u64 rsub[4]={0x63cd1340f5d0740bULL,0x276ca5bcd020dbf2ULL,0x7a964b64ebcab462ULL,0x449563cc5a6092efULL};
    sc_sub(r, ra, rb); ck3("sc_sub rand0", r, rsub);
    u64 rmul[4]={0x1f6227bb0cae6abcULL,0x0eb395f4d1dc2748ULL,0x5a6d887478098fffULL,0x34bfa264913495c0ULL};
    sc_mul(r, ra, rb); ck3("sc_mul rand0", r, rmul);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
