/* test_num3072_inv.c -- num3072_inv_var (daemon/num3072_inv.c, the safegcd
 * inverse mod p = 2^3072 - 1103717) against the Fermat inverse it replaced
 * (x^(p-2), 6,142 modular multiplies, kept here as the oracle), byte for byte,
 * plus the identity x * x^{-1} == 1 through the accumulator's own multiply.
 *
 * Inputs: the edge values (1, 2, p-1, p-2, 2^3071, single bits, all-ones
 * limbs, p+1 and 2^3072-1 in the accumulator's overflow form), then N random
 * values below p, then N elements as MuHash inserts produce them (SHA-256 +
 * ChaCha20 expansion: the exact shape of a real denominator). Zero and p
 * (0 mod p) must return 0 and leave the output untouched.
 *
 * The constants are checked against Python's arithmetic at the top of the
 * file's history (MODULUS_INVERSE = p^{-1} mod 2^62 = 0x70a1421da087d93).
 *
 * argv[1] = random count per family (default 400; the oracle costs ~1.8 ms
 * per inverse), argv[2] = seed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../daemon/muhash_p2.inc.h"

extern int  num3072_inv_var(unsigned char out[384], const unsigned char in[384]);
extern void num3072_mul(void* a, const void* b);
extern void num3072_set_one(void* a);
extern void num3072_full_reduce(void* a);
extern long num3072_is_overflow(const void* a);
/* the accumulator's canonical form: full_reduce subtracts p unconditionally, so
 * it is only for a value at or above p (the asm's contract, and Core's) */
static void canon(void* a){ if (num3072_is_overflow(a)) num3072_full_reduce(a); }
extern void muhash_init(void* acc);
extern void muhash_insert(void* acc, const void* data, unsigned long len);

typedef unsigned char u8; typedef uint64_t u64;
static long failures, checks;
#define CK(c, ...) do{ checks++; if(!(c)){ if(failures++ < 12){ printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } }while(0)

static void fermat_inv(u8 out[384], const u8 in[384]){
    num3072_set_one(out);
    for (int byte = 383; byte >= 0; byte--) for (int bit = 7; bit >= 0; bit--){
        num3072_mul(out, out);
        if ((MUHASH_P_MINUS_2[byte] >> bit) & 1) num3072_mul(out, in);
    }
}
static u64 rs; static u64 rnd(void){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }
static void set_p(u64 x[48]){ memset(x, 0xff, 384); x[0] = (u64)-1 - 1103717 + 1; }   /* p = 2^3072 - 1103717 */
static int ge_p(const u64 x[48]){ u64 p[48]; set_p(p); for (int i = 47; i >= 0; i--){ if (x[i] > p[i]) return 1; if (x[i] < p[i]) return 0; } return 1; }

static void check(const u8 in[384], const char* what){
    static u8 sg[384], fm[384], prod[384], one[384];
    memset(sg, 0xA5, 384);
    int ok = num3072_inv_var(sg, in);
    fermat_inv(fm, in);
    canon(fm);
    CK(ok == 1, "%s: num3072_inv_var returned %d", what, ok);
    CK(!memcmp(sg, fm, 384), "%s: safegcd != Fermat (limb0 %016llx vs %016llx)", what, *(unsigned long long*)sg, *(unsigned long long*)fm);
    memcpy(prod, in, 384); num3072_mul(prod, sg); canon(prod);
    num3072_set_one(one);
    CK(!memcmp(prod, one, 384), "%s: x * inv(x) != 1", what);
}

int main(int argc, char** argv){
    long n = argc > 1 ? atol(argv[1]) : 400;
    rs = argc > 2 ? strtoull(argv[2], 0, 0) : 0x3072DEADBEEF0001ULL;
    printf("test_num3072_inv: n=%ld seed=0x%016llx\n", n, (unsigned long long)rs);

    static u64 x[48]; static u8 out[384];
    /* edges */
    memset(x, 0, 384); x[0] = 1; check((u8*)x, "1");
    x[0] = 2; check((u8*)x, "2");
    set_p(x); x[0] -= 1; check((u8*)x, "p-1");
    set_p(x); x[0] -= 2; check((u8*)x, "p-2");
    memset(x, 0, 384); x[47] = 1ULL << 63; check((u8*)x, "2^3071");
    for (int b = 0; b < 3072; b += 97){ memset(x, 0, 384); x[b >> 6] = 1ULL << (b & 63); char nm[32]; snprintf(nm, sizeof nm, "bit %d", b); check((u8*)x, nm); }
    memset(x, 0xff, 384); x[47] = 0x7fffffffffffffffULL; check((u8*)x, "2^3071-1 all ones");
    /* the overflow form: values in [p, 2^3072) that the accumulator may carry */
    set_p(x); x[0] += 1; check((u8*)x, "p+1 (overflow form of 1)");
    memset(x, 0xff, 384); check((u8*)x, "2^3072-1 (overflow form of 1103716)");
    /* zero and p: no inverse, output untouched */
    memset(out, 0x77, 384); memset(x, 0, 384);
    CK(num3072_inv_var(out, (u8*)x) == 0, "0 must return 0");
    CK(out[0] == 0x77 && out[383] == 0x77, "0 must not write out");
    set_p(x); memset(out, 0x77, 384);
    CK(num3072_inv_var(out, (u8*)x) == 0, "p (0 mod p) must return 0");
    CK(out[0] == 0x77, "p must not write out");

    /* random below p */
    for (long i = 0; i < n; i++){
        do { for (int k = 0; k < 48; k++) x[k] = rnd(); } while (ge_p(x));
        check((u8*)x, "random");
    }
    /* elements as the accumulator makes them */
    static u64 acc[48]; u8 key[32];
    for (long i = 0; i < n; i++){
        for (int k = 0; k < 32; k++) key[k] = (u8)(rnd() & 0xff);
        muhash_init(acc); muhash_insert(acc, key, 32);
        check((u8*)acc, "element");
    }
    /* a running product of many elements, as a real denominator is */
    muhash_init(acc);
    for (int i = 0; i < 1000; i++){ for (int k = 0; k < 32; k++) key[k] = (u8)(rnd() & 0xff); muhash_insert(acc, key, 32); if (i % 250 == 249) check((u8*)acc, "product of elements"); }

    printf("%ld checks\n", checks);
    if (failures){ printf("\nTESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
