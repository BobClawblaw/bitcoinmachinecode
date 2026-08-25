#include <stdio.h>
typedef unsigned long long u64;
extern void fe_pow(u64 out[4], const u64 base[4], const u64 exp[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern const unsigned long long EXP_QR[4];
static void pp(const char*t,const u64 v[4]){printf("%s %016llx %016llx %016llx %016llx\n",t,v[0],v[1],v[2],v[3]);}
int main(void){
    u64 x[4]={0x59F2815B16F81798,0x029BFCDB2DCE28D9,0x55A06295CE870B07,0x79BE667EF9DCBBAC};
    u64 t[4],y[4],y2[4],x2[4],x3[4],seven[4]={7,0,0,0};
    fe_sqr(x2,x);fe_mul(x3,x2,x);fe_add(t,x3,seven);
    pp(" EXP_QR",EXP_QR);
    fe_pow(y,t,EXP_QR);
    pp(" y",y);
    fe_sqr(y2,y);
    pp(" y2",y2);
    pp(" t ",t);
    return 0;
}
