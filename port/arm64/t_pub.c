#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void fe_pow(u64 out[4], const u64 base[4], const u64 exp[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern int pubkey_parse(const unsigned char* pub, u64 publen, u64 qx[4], u64 qy[4]);
static void pp(const char*t,const u64 v[4]){printf("%s %016llx %016llx %016llx %016llx\n",t,v[0],v[1],v[2],v[3]);}
int main(void){
    /* Gx bytes BE */
    unsigned char pub[33]={0x02,0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98};
    u64 x[4]={0x59F2815B16F81798,0x029BFCDB2DCE28D9,0x55A06295CE870B07,0x79BE667EF9DCBBAC};
    u64 t[4],y[4],y2[4],x2[4],x3[4],seven[4]={7,0,0,0};
    fe_sqr(x2,x);fe_mul(x3,x2,x);fe_add(t,x3,seven);
    extern void fe_pow(u64*,const u64*,const u64*);
    /* need EXP_QR address - recompute via parse; instead call parse and dump */
    u64 qx[4],qy[4];
    int ok=pubkey_parse(pub,33,qx,qy);
    printf("parse ret=%d\n",ok);
    pp(" t",t);pp("qx",qx);pp("qy",qy);
    return 0;
}
