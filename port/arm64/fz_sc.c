/* fz_sc.c -- differential-fuzz helper for secp256k1_scalar.S.
 * Usage: fz_sc <a_hex64> <b_hex64> ; prints A,S,M,Q,I as 4 LE limbs each. */
#include <stdio.h>
#include <stdlib.h>
typedef unsigned long u64;
extern void sc_add(u64 r[4],const u64 a[4],const u64 b[4]);
extern void sc_sub(u64 r[4],const u64 a[4],const u64 b[4]);
extern void sc_mul(u64 r[4],const u64 a[4],const u64 b[4]);
extern void sc_sqr(u64 r[4],const u64 a[4]);
extern void sc_inv(u64 r[4],const u64 a[4]);
static int hv(int c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; return -1; }
static u64 rdlimb(const char*h,int off){ u64 v=0; for(int k=0;k<8;k++){ unsigned b=((unsigned)hv(h[off+2*k])<<4)|(unsigned)hv(h[off+2*k+1]); v|=(u64)b<<(8*k);} return v; }
static void hex32(u64*out,const char*h){ for(int i=0;i<4;i++) out[i]=rdlimb(h,i*16); }
static void pr(char t,const u64*r){ printf("%c %016lx %016lx %016lx %016lx\n",t,r[0],r[1],r[2],r[3]); }
int main(int a,char**v){ u64 x[4],y[4],r[4]; if(a<3)return 2; hex32(x,v[1]); hex32(y,v[2]);
  sc_add(r,x,y); pr('A',r); sc_sub(r,x,y); pr('S',r); sc_mul(r,x,y); pr('M',r); sc_sqr(r,x); pr('Q',r); sc_inv(r,x); pr('I',r); return 0; }
