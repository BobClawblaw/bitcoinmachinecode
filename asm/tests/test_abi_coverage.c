/* test_abi_coverage.c -- run the callee-saved SENTINEL PROBE over the
 * consensus crypto layer, not just the fourteen functions it grew up with.
 *
 * WHY THIS EXISTS
 *
 *   The project has three ABI instruments and they do not cover the same
 *   ground:
 *
 *     make abi-check          static, ~1,078 call sites. Audits STACK
 *                             ALIGNMENT: does RSP == 0 mod 16 at every call
 *                             that leaves assembly. Says nothing about
 *                             register preservation -- it passed cleanly on
 *                             the 21 functions of LOG.md incident #27.
 *     make callee-saved-check static, ~374 functions. Audits whether what was
 *                             pushed is popped at every `ret`. Cannot see a
 *                             register a function never saved but did use,
 *                             and cannot see an 8-bit write that wanted 64
 *                             (incident #28).
 *     tests/bench_abi_audit   RUNTIME sentinel probe -- fills rbx/rbp/r12-r15
 *                             with known values, calls the function, checks
 *                             them afterwards. This is the instrument that
 *                             actually catches a clobber. It probes
 *                             FOURTEEN functions.
 *
 *   Fourteen, because it was written for BENCHMARKS.md tier 1 and covers what
 *   that benchmark calls: the hash primitives, tx_parse, script_eval,
 *   cons_verify. Not probed, until this file: every secp256k1 primitive,
 *   every taproot helper, the constant-time ladder, bech32 and chainwork --
 *   i.e. most of the code a block's signatures actually run through.
 *
 *   That gap is not hypothetical. On 2026-08-23 a real `-O2` failure was
 *   reproduced in `taproot_verify_input` <- `tx_verify_block_connect` with
 *   both static auditors green (LOG.md, "the -O0 pin is still load-bearing").
 *   Whatever its mechanism turns out to be, "the guards pass" was not enough
 *   to conclude the ABI is clean, and the runtime probe is the guard with
 *   teeth.
 *
 * WHAT IT ASSERTS
 *
 *   For every function below: rbx, rbp, r12, r13, r14 and r15 hold, on
 *   return, exactly what the caller put in them. Inputs are real curve points
 *   and real byte buffers so the functions do genuine work rather than
 *   early-returning past their own epilogues -- a probe of a function that
 *   bailed at its first bounds check proves nothing.
 *
 *   Return VALUES are deliberately ignored. ecdsa_verify returning 0 on a
 *   made-up signature is correct behaviour and irrelevant here; what is
 *   being measured is the register file, and only that.
 *
 * Usage: ./test_abi_coverage
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint64_t u64;
typedef uint8_t  u8;

extern long bench_abi_probe(void* fn, const unsigned long args[6],
                            unsigned long got[6]);

/* Addresses only -- bench_abi_probe builds the real argument registers. */
extern void fe_add(void); extern void fe_sub(void); extern void fe_mul(void);
extern void fe_sqr(void); extern void fe_inv(void);
extern void sc_add(void); extern void sc_sub(void); extern void sc_mul(void);
extern void sc_sqr(void); extern void sc_inv(void); extern void sc_inv_var(void);
extern void sc_split_lambda(void);
extern void point_double(void); extern void point_add(void);
extern void point_add_mixed(void); extern void point_scalar_mul(void);
extern void point_scalar_mul_fixed(void); extern void point_scalar_mul_glv(void);
extern void point_scalar_mul_ct(void); extern void pointh_add(void);
extern void pointh_double(void);
extern void ecdsa_verify(void); extern void ecdsa_x_eq_mod_n(void);
extern void schnorr_verify(void); extern void schnorr_x_eq_r(void);
extern void tagged_hash256(void); extern void tap_branch_hash(void);
extern void tap_leaf_hash(void); extern void tap_merkle_root(void);
extern void taproot_tweak_pubkey(void);
extern void block_work(void); extern void chainwork_add(void);
extern void chainwork_cmp(void); extern void u256_div(void);

static const char* RN[6] = { "rbx", "rbp", "r12", "r13", "r14", "r15" };
static int g_clean = 0, g_bad = 0;

static void probe6(const char* name, void* fn,
                   u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5)
{
    unsigned long args[6] = { a0, a1, a2, a3, a4, a5 };
    unsigned long got[6];
    long bad = bench_abi_probe(fn, args, got);
    if (!bad){ g_clean++; return; }
    printf("  FAIL %-22s CLOBBERS", name);
    for (int i = 0; i < 6; i++)
        if (got[i] != (0x1111111111111111UL * (unsigned long)(i+1)))
            printf(" %s", RN[i]);
    printf("   ABI VIOLATION\n");
    g_bad++;
}
#define P4(n,f,a,b,c,d) probe6(n,(void*)f,(u64)(a),(u64)(b),(u64)(c),(u64)(d),0,0)
#define P5(n,f,a,b,c,d,e) probe6(n,(void*)f,(u64)(a),(u64)(b),(u64)(c),(u64)(d),(u64)(e),0)

/* secp256k1 G, affine, little-endian limbs (same constants as
 * secp256k1_taproot.asm's G_AFF_TR). Real curve points, so the point
 * routines do full-length work instead of hitting an infinity shortcut. */
static u64 Gaff[8] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
};

int main(void)
{
    static u64 r12a[12], r12b[12], r12c[12];
    static u64 f0[4], f1[4], f2[4];
    static u64 k[4] = { 0x0123456789abcdefULL, 0xfedcba9876543210ULL,
                        0x1111222233334444ULL, 0x0000000000000007ULL };
    static u8  b32a[32], b32b[32], b32c[32], sig64[64], script[300], leaves[64];
    static u8  hdr[80], work[32], work2[32];

    for (int i = 0; i < 4; i++){ f0[i] = 0x1111111100000000ULL + i;
                                 f1[i] = 0x2222222200000000ULL + i; }
    for (int i = 0; i < 32;  i++){ b32a[i]=(u8)(i*7+1); b32b[i]=(u8)(i*11+3); b32c[i]=(u8)(i*13+5); }
    for (int i = 0; i < 64;  i++){ sig64[i]=(u8)(i*3+9); leaves[i]=(u8)(i*5+2); }
    for (int i = 0; i < 300; i++) script[i]=(u8)(i*167+13);
    for (int i = 0; i < 80;  i++) hdr[i]=(u8)(i*3+1);
    hdr[75]=0x1d; hdr[74]=0x00; hdr[73]=0xff; hdr[72]=0xff;   /* a sane nBits */
    /* Jacobian G (Z=1) so the point routines get a real curve point. */
    memcpy(r12a, Gaff, 64); r12a[8]=1; r12a[9]=r12a[10]=r12a[11]=0;
    memcpy(r12b, r12a, 96);

    printf("callee-saved sentinel probe over the consensus crypto layer\n");
    printf("  (rbx, rbp, r12-r15 must survive every call)\n\n");

    /* ---- field ---- */
    P4("fe_add",  fe_add,  f2, f0, f1, 0);
    P4("fe_sub",  fe_sub,  f2, f0, f1, 0);
    P4("fe_mul",  fe_mul,  f2, f0, f1, 0);
    P4("fe_sqr",  fe_sqr,  f2, f0, 0,  0);
    P4("fe_inv",  fe_inv,  f2, f0, 0,  0);

    /* ---- scalar ---- */
    P4("sc_add",  sc_add,  f2, f0, f1, 0);
    P4("sc_sub",  sc_sub,  f2, f0, f1, 0);
    P4("sc_mul",  sc_mul,  f2, f0, f1, 0);
    P4("sc_sqr",  sc_sqr,  f2, f0, 0,  0);
    P4("sc_inv",  sc_inv,  f2, f0, 0,  0);
    P4("sc_inv_var", sc_inv_var, f2, f0, 0, 0);
    P4("sc_split_lambda", sc_split_lambda, f2, f1, k, 0);

    /* ---- points ---- */
    P4("point_double", point_double, r12c, r12a, 0, 0);
    P4("point_add",    point_add,    r12c, r12a, r12b, 0);
    P4("point_add_mixed", point_add_mixed, r12c, r12a, Gaff, 0);
    P4("point_scalar_mul", point_scalar_mul, r12c, Gaff, k, 0);
    P4("point_scalar_mul_fixed", point_scalar_mul_fixed, r12c, Gaff, k, 0);
    P4("point_scalar_mul_glv",   point_scalar_mul_glv,   r12c, Gaff, k, 0);
    P4("point_scalar_mul_ct",    point_scalar_mul_ct,    r12c, Gaff, k, 0);
    P4("pointh_add",    pointh_add,    r12c, r12a, r12b, 0);
    P4("pointh_double", pointh_double, r12c, r12a, 0, 0);

    /* ---- signatures ---- */
    P5("ecdsa_verify", ecdsa_verify, f0, f1, f2, Gaff, Gaff+4);
    P4("ecdsa_x_eq_mod_n", ecdsa_x_eq_mod_n, f0, f1, f2, 0);
    P4("schnorr_verify", schnorr_verify, sig64, b32a, b32b, 32);
    P4("schnorr_x_eq_r", schnorr_x_eq_r, f0, f1, f2, 0);

    /* ---- taproot ---- */
    P5("tagged_hash256", tagged_hash256, b32a, "TapLeaf", 7, script, 300);
    P4("tap_branch_hash", tap_branch_hash, b32a, b32b, b32c, 0);
    P4("tap_leaf_hash",   tap_leaf_hash,   b32a, 0xc0, script, 300);
    P5("tap_merkle_root", tap_merkle_root, b32a, leaves, 1, b32c, 33);
    P4("taproot_tweak_pubkey", taproot_tweak_pubkey, b32a, b32b, 0, 0);

    /* ---- chainwork ---- */
    P4("block_work",    block_work,    work, hdr, 0, 0);
    P4("chainwork_add", chainwork_add, work2, work, work, 0);
    P4("chainwork_cmp", chainwork_cmp, work, work2, 0, 0);
    P4("u256_div",      u256_div,      work2, work, work, 0);

    printf("\n%d clean, %d violating\n", g_clean, g_bad);
    if (g_bad){
        printf("\nA clobbered callee-saved register is invisible at -O0 (gcc reloads\n"
               "from memory around every call) and corrupts the caller at -O2.\n");
        printf("\nTESTS FAILED (%d failures)\n", g_bad);
        return 1;
    }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
