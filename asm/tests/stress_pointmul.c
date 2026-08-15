/* stress_pointmul.c — batch driver: reads hex scalars (one per line) and
 * prints "x y" affine coords of k*G, or "inf" for infinity.
 * Links asm point_mult + fe. (Static link; no shared-lib PIC needed.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
static void toaff(u64 ox[4], u64 oy[4], const u64 j[12]){
    u64 zi[4], z2[4], z3[4];
    fe_inv(zi, &j[8]); fe_sqr(z2, zi); fe_mul(z3, z2, zi);
    fe_mul(ox, &j[0], z2); fe_mul(oy, &j[4], z3);
}
static const u64 Gaff[8]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};
int main(int argc, char**argv){
    char line[128]; u64 r[12], ax[4], ay[4], k[4];
    while (fgets(line, sizeof line, stdin)){
        /* parse line as exactly 64 hex digits, BIG-endian (MSB first),
           into little-endian limbs k[0]=LSB..k[3]=MSB */
        size_t n = strlen(line);
        while (n>0 && (line[n-1]=='\n'||line[n-1]=='\r')) line[--n]=0;
        if (n==0) continue;
        int hex[64]; memset(hex,0,sizeof hex);
        int nl = n; if (nl>64) nl=64;
        for (int i=0;i<nl;i++){ char c=line[nl-1-i]; /* rightmost = least significant */
            hex[i]= (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:0; }
        for (int limb=0; limb<4; limb++){
            u64 v=0;
            for (int j=0;j<16;j++){ v |= ((u64)hex[limb*16+j]) << (4*j); }
            k[limb]=v;
        }
        point_scalar_mul(r, Gaff, k);
        toaff(ax, ay, r);
        int inf = (r[8]==0 && r[9]==0 && r[10]==0 && r[11]==0);
        if (inf) printf("inf\n");
        else printf("%016llx%016llx%016llx%016llx %016llx%016llx%016llx%016llx\n",
            ax[3],ax[2],ax[1],ax[0], ay[3],ay[2],ay[1],ay[0]);
    }
    return 0;
}
