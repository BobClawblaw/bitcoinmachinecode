#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
static void pp(const char*tag,const u64 r[12]){
    u64 zi[4],zi2[4],zi3[4],x[4],y[4];
    fe_inv(zi,&r[8]);fe_sqr(zi2,zi);fe_mul(zi3,zi2,zi);
    fe_mul(x,&r[0],zi2);fe_mul(y,&r[4],zi3);
    printf("%s X%016llx %016llx %016llx %016llx  Y%016llx %016llx %016llx %016llx  Z%016llx %016llx %016llx %016llx\n",
      tag,x[3],x[2],x[1],x[0],y[3],y[2],y[1],y[0],r[11],r[10],r[9],r[8]);
}
int main(void){
    const u64 G[8]={0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
                    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};
    u64 R[12], k[4]={1,0,0,0};
    R[8]=R[9]=R[10]=R[11]=12345;
    point_scalar_mul(R,G,k);
    printf("k=1 Z-in=%016llx\n",R[8]);
    pp("k=1",R);
    k[0]=2; point_scalar_mul(R,G,k); pp("k=2",R);
    k[0]=5; point_scalar_mul(R,G,k); pp("k=5",R);
    k[0]=0; point_scalar_mul(R,G,k);
    printf("k=0 Z=%016llx %016llx %016llx %016llx (should be 0 afford)\n",R[8],R[9],R[10],R[11]);
    return 0;
}
