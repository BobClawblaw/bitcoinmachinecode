
/* dpt.c -- cross-arch differential driver for the point layer.
 * stdin records: op(1B) then operands (32-byte field elements / 64B affine /
 * 96B jacobian / 32B scalar as needed):
 *   0: p[96]                     -> double(p)
 *   1: p[96] q[96]               -> add(p,q)
 *   2: p[96] xy[64]              -> add_mixed(p,xy)
 *   3: p[96] xy[64]              -> add_mixed_zr(p,xy) -> r[96]+zr[32]
 *   4: xy[64] k[32]              -> scalar_mul(xy,k)
 *   5: k[32]                     -> scalar_mul_fixed(k)
 *   6: xy[64] k[32]              -> scalar_mul_glv(xy,k)
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
typedef unsigned long long u64;
extern void point_double(u64 r[12], const u64 p[12]);
extern void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
extern void point_add_mixed_zr(u64 r[12], const u64 p[12], const u64 xy[8], u64 zr[4]);
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_fixed(u64 r[12], const u64 k[4]);
extern void point_scalar_mul_glv(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void pointh_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void pointh_double(u64 r[12], const u64 p[12]);
extern void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
static u64 p[12], q[12], xy[8], k[4], r[12], zr[4];
static int rd(void* v, size_t n){ return fread(v,1,n,stdin)==n; }
int main(void){
    for(;;){
        int op = getchar();
        if (op==EOF) break;
        if (op==0){ if(!rd(p,96))break; point_double(r,p); fwrite(r,8,12,stdout); }
        else if (op==1){ if(!rd(p,96)||!rd(q,96))break; point_add(r,p,q); fwrite(r,8,12,stdout); }
        else if (op==2){ if(!rd(p,96)||!rd(xy,64))break; point_add_mixed(r,p,xy); fwrite(r,8,12,stdout); }
        else if (op==3){ if(!rd(p,96)||!rd(xy,64))break; point_add_mixed_zr(r,p,xy,zr); fwrite(r,8,12,stdout); fwrite(zr,8,4,stdout); }
        else if (op==4){ if(!rd(xy,64)||!rd(k,32))break; point_scalar_mul(r,xy,k); fwrite(r,8,12,stdout); }
        else if (op==5){ if(!rd(k,32))break; point_scalar_mul_fixed(r,k); fwrite(r,8,12,stdout); }
        else if (op==6){ if(!rd(xy,64)||!rd(k,32))break; point_scalar_mul_glv(r,xy,k); fwrite(r,8,12,stdout); }
        else if (op==7){ if(!rd(p,96)||!rd(q,96))break; pointh_add(r,p,q); fwrite(r,8,12,stdout); }
        else if (op==8){ if(!rd(p,96))break; pointh_double(r,p); fwrite(r,8,12,stdout); }
        else if (op==9){ if(!rd(xy,64)||!rd(k,32))break; point_scalar_mul_ct(r,xy,k); fwrite(r,8,12,stdout); }
    }
    return 0;
}
