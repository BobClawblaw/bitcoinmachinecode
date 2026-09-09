/*
 * sc_mul_512_c.c -- portable 256x256 -> 512-bit schoolbook multiply.
 * macOS/AArch64 stopgap for sc_mul_512 while the asm variant is being
 * debugged; matches asm/secp256k1_scalar.asm's sc_mul_512 bit-exactly
 * (same row-carry structure as the validated ref_mul_512 oracle).
 */
#include <stdint.h>
#include <string.h>
typedef uint64_t u64;
typedef unsigned __int128 u128;

void sc_mul_512_c(u64 r[8], const u64 a[4], const u64 b[4])
{
    u64 acc[9];
    memset(acc, 0, sizeof acc);
    for (int i = 0; i < 4; i++) {
        u64 carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 t = (u128)a[i] * b[j] + acc[i + j] + carry;
            acc[i + j] = (u64)t;
            carry = (u64)(t >> 64);
        }
        acc[i + 4] += carry;
    }
    memcpy(r, acc, 64);
}
