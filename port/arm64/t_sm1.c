#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
static void dump(const char*tag,const u64 r[12]){
    printf("%s :",tag);
    for(int i=0;i<12;i++) printf(" %016llx",r[i]);
    printf("\n");
}
int main(void){
    const u64 G[8]={0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
                    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};
    u64 R[12]={0x1111111111111111ULL,2,3,4,5,6,7,8,0x3039,0x3039,0x3039,0x3039};
    u64 k[4]={1,0,0,0};
    point_scalar_mul(R,G,k);
    dump("k=1 R",R);
    return 0;
}
