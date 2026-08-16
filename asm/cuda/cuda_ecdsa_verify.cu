/*
 * cuda_ecdsa_verify.cu -- PLAN.md option D: secp256k1 ECDSA BATCH verify.
 *
 * Full ECDSA verification math in CUDA for parallel offline signature audit.
 * Semantics bit-for-bit identical to the trusted asm ecdsa_verify: (r,s) valid
 * on hash z by pubkey Q iff
 *     w = s^-1 mod n;  R = (z*w)G + (r*w)Q;  R.x mod n == r.
 *
 * All numbers 4 x uint64, little-endian ascending limbs.  Field/scalar modular
 * multiply mirrors the PROJECT'S VALIDATED secp256k1_scalar_c.c algorithm
 * (10-limb schoolbook + bounded-fold reduction + 3 conditional subtracts), so
 * mod-n mul is the exact code proven over 4k+ vectors.  Mod-p / mod-n differ
 * only in DELTA/P vs DELTA/N constants.  Inversion = Fermat a^(n-2) mod n
 * (reused sc_inv_c).  Point ops in Jacobian coordinates over mod-p.
 *
 * Correctness axes (all asserted by main):
 *   (1) CPU mirror (same device funcs run on host) vs ./test_ecdsa asm oracle;
 *   (2) CUDA kernel batch MUST agree bit-for-bit with the CPU mirror;
 *   (3) modmul cross-checked vs python ints on the host.
 *
 * Build: nvcc -O2 -arch=sm_90 -o cuda_ecdsa_verify cuda_ecdsa_verify.cu
 *        (arch resolved per-device in the Makefile `ecdsaverify` target)
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>

typedef uint64_t u64;
typedef uint8_t  u8;
typedef unsigned __int128 u128;

/* curve constants (4-limb LE) — mirror of secp256k1_scalar_c.c */
__constant__ u64 d_DELTA[4];   /* 2^256 - n */
__constant__ u64 d_N[4];
__constant__ u64 d_DELTAP[4];  /* 2^256 - p = 2^32+977 */
__constant__ u64 d_P[4];
__constant__ u64 d_Gx[4];
__constant__ u64 d_Gy[4];
static u64 H_N[4], H_P[4], H_Gx[4], H_Gy[4];

/* =========================================================================
 * modular multiply (bounded fold) — EXACT mirror of validated sc_mul
 *   m = modulus, D = 2^256 - m (each 4 limbs; only entry i of D used as-is)
 * ========================================================================= */
__device__ __forceinline__ void mmul(u64 out[4], const u64 a[4], const u64 b[4],
                                     const u64 D[4], const u64 M[4]){
    u64 cur[10] = {0};
    int i,j,k;
    for (i=0;i<4;i++) for (j=0;j<4;j++){
        k=i+j; u128 p=(u128)a[i]*b[j]; u64 lo=(u64)p, hi=(u64)(p>>64);
        u128 s=(u128)cur[k]+lo; cur[k]=(u64)s; u64 c=(u64)(s>>64); k++;
        s=(u128)cur[k]+hi+c; cur[k]=(u64)s; c=(u64)(s>>64); k++;
        while(c){ s=(u128)cur[k]+c; cur[k]=(u64)s; c=(u64)(s>>64); k++; }
    }
    u64 tmp[10];
    for (i=0;i<8;i++){
        u64 hi[5]; memcpy(hi,&cur[4],sizeof hi);
        memcpy(tmp,cur,sizeof tmp); memset(tmp,0,sizeof tmp);
        for (int hi_i=0; hi_i<5; hi_i++) for (int dj=0; dj<4; dj++){
            k=hi_i+dj; u128 p=(u128)hi[hi_i]*D[dj]; u64 lo=(u64)p,h=(u64)(p>>64);
            u128 s=(u128)tmp[k]+lo; tmp[k]=(u64)s; u64 c=(u64)(s>>64); k++;
            s=(u128)tmp[k]+h+c; tmp[k]=(u64)s; c=(u64)(s>>64); k++;
            while(c){ s=(u128)tmp[k]+c; tmp[k]=(u64)s; c=(u64)(s>>64); k++; }
        }
        u64 c=0;
        for(k=0;k<4;k++){ u128 s=(u128)tmp[k]+cur[k]+c; tmp[k]=(u64)s; c=(u64)(s>>64); }
        for(k=4;k<10;k++){ u128 s=(u128)tmp[k]+c; tmp[k]=(u64)s; c=(u64)(s>>64); }
        memcpy(cur,tmp,sizeof cur);
    }
    for (int kk=0;kk<3;kk++){
        u64 r[4]; u64 borrow=0;
        for(k=0;k<4;k++){ u128 s=(u128)cur[k]-M[k]-borrow; r[k]=(u64)s; borrow=(u64)((s>>64)&1); }
        u64 do_sub=borrow^1;
        for(k=0;k<4;k++) cur[k]=do_sub?r[k]:cur[k];
    }
    for(k=0;k<4;k++) out[k]=cur[k];
}
__device__ __forceinline__ void mulmod_n(u64 o[4],const u64 a[4],const u64 b[4]){ mmul(o,a,b,d_DELTA,d_N); }
__device__ __forceinline__ void mulmod_p(u64 o[4],const u64 a[4],const u64 b[4]){ mmul(o,a,b,d_DELTAP,d_P); }

/* host-side aliases of the SAME math, compiled for CPU (used as the mirror) */
__host__ static void h_mmul(u64 out[4],const u64 a[4],const u64 b[4],const u64 D[4],const u64 M[4]);
__host__ static inline void h_mulmod_p(u64 o[4],const u64 a[4],const u64 b[4]){ h_mmul(o,a,b,H_Gx?H_DELTAP():H_P); }

/* We need host DELTA constants too. Simpler: reuse a factored host mmul. */
__host__ static void h_mmul_out(u64 out[4],const u64 a[4],const u64 b[4],const u64 D[4],const u64 M[4]);
