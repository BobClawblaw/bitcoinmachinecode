/* fz_fe.c -- differential-fuzz helper for secp256k1_fe.S.
 * Usage: fz_fe <a_hex64> <b_hex64>
 * Prints A(add)/S(sub)/M(mul)/Q(sqr)/I(inv) each as 4 LE limbs, per line:
 *   letter + 4 u64 in hex.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long u64;
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);

static int hv(int c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
/* parse a 16-hex-char LE limb at offset `off` (byte j = chars 2j..2j+1) */
static u64 rdlimb(const char*h,int off){ u64 v=0; for(int k=0;k<8;k++){ unsigned b=((unsigned)hv(h[off+2*k])<<4)|(unsigned)hv(h[off+2*k+1]); v |= (u64)b<<(8*k);} return v; }
static void hex32(u64*out,const char*h){ for(int i=0;i<4;i++) out[i]=rdlimb(h,i*16); }
static void pr(char tag,const u64*r){ printf("%c %016lx %016lx %016lx %016lx\n",tag,r[0],r[1],r[2],r[3]); }

int main(int argc,char**argv){
    if(argc<3){ printf("usage\n"); return 2; }
    u64 a[4], b[4], r[4];
    hex32(a,argv[1]); hex32(b,argv[2]);
    fe_add(r,a,b); pr('A',r);
    fe_sub(r,a,b); pr('S',r);
    fe_mul(r,a,b); pr('M',r);
    fe_sqr(r,a);   pr('Q',r);
    fe_inv(r,a);   pr('I',r);
    return 0;
}
