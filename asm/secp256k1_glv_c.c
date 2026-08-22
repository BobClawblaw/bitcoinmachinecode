/*
 * secp256k1_glv_c.c -- C helpers for the GLV scalar multiply (PERF_SCOPE 4.3).
 *
 * Precedent for C next to the asm crypto: secp256k1_scalar_c.c (batch
 * inversion glue) and utxo_lsm_mm.c. Nothing here touches a secret: the
 * only caller is the variable-time verification path.
 *
 *   glv_wnaf(out[129], s)       -- libsecp256k1's secp256k1_ecmult_wnaf
 *                                  (ecmult_impl.h) for len = 129, w = 5.
 *   bmc_ecdsa_glv_enabled()     -- runtime kill switch, BMC_ECDSA_GLV=0
 *                                  forces point_scalar_mul (same pattern as
 *                                  BMC_LSM_MMAP in utxo_lsm_mm.c).
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef uint64_t u64;
typedef unsigned __int128 u128;

#define GLV_WNAF_LEN 129
#define GLV_WINDOW_A 5

static const u64 N_LIMBS[4] = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};

/* bits [off, off+cnt) of the 256-bit s, cnt <= 8, may straddle a limb. */
static unsigned get_bits(const u64 s[4], int off, int cnt){
    int li = off >> 6, lo = off & 63;
    u128 w = (u128)s[li];
    if (li + 1 < 4) w |= (u128)s[li+1] << 64;
    return (unsigned)((w >> lo) & ((1u << cnt) - 1));
}

/*
 * Width-w NAF of a scalar, Core's algorithm verbatim (ecmult_impl.h,
 * secp256k1_ecmult_wnaf, called with len=129, w=WINDOW_A=5 for the two
 * GLV halves). Sign rule first: bit 255 set => the value is "negative",
 * use n - s as the magnitude and negate every digit. That is valid because
 * n > 2^255, so any r >= 2^255 cannot be the "< 2^128" representative the
 * split promised and its negation must be.
 *
 * Output: out[i] in {0, +-1, +-3, ..., +-15}, at least w-1 zeros after every
 * non-zero digit, sum(out[i] * 2^i) == +-magnitude. Returns the number of
 * digit positions in use (last non-zero index + 1; 0 for s == 0).
 * Returns -1 if the magnitude has a bit at or above position 129 -- the
 * split guarantees it does not; a caller seeing -1 must fall back.
 */
int glv_wnaf(signed char out[GLV_WNAF_LEN], const u64 s_in[4]){
    u64 s[4];
    int sign = 1, last_set_bit = -1, bit = 0, carry = 0;
    memcpy(s, s_in, 32);
    memset(out, 0, GLV_WNAF_LEN);
    if (s[3] >> 63) {                           /* negative: s = n - s */
        u128 br = 0;
        for (int i = 0; i < 4; i++) { u128 t = (u128)N_LIMBS[i] - s[i] - br; s[i] = (u64)t; br = (t >> 64) & 1; }
        sign = -1;
    }
    if (s[3] != 0 || (s[2] >> 1) != 0) return -1;   /* >= 2^129: not a valid half */

    while (bit < GLV_WNAF_LEN) {
        int now, word;
        if (get_bits(s, bit, 1) == (unsigned)carry) { bit++; continue; }
        now = GLV_WINDOW_A;
        if (now > GLV_WNAF_LEN - bit) now = GLV_WNAF_LEN - bit;
        word = (int)get_bits(s, bit, now) + carry;
        carry = (word >> (GLV_WINDOW_A - 1)) & 1;
        word -= carry << GLV_WINDOW_A;
        out[bit] = (signed char)(sign * word);
        last_set_bit = bit;
        bit += now;
    }
    if (carry) return -1;                       /* cannot happen for magnitudes < 2^129 */
    return last_set_bit + 1;
}

/* Kill switch. BMC_ECDSA_GLV=0 routes ecdsa_verify's u2*Q through the
 * original point_scalar_mul; anything else (or unset) uses the GLV path.
 * Read once. */
static int g_glv_enabled = -1;
int bmc_ecdsa_glv_enabled(void){
    if (g_glv_enabled < 0) {
        const char *e = getenv("BMC_ECDSA_GLV");
        g_glv_enabled = (e && e[0] == '0') ? 0 : 1;
    }
    return g_glv_enabled;
}
/* For tests: flip at runtime (also used by the differential harness). */
void bmc_ecdsa_glv_set_enabled(int on){ g_glv_enabled = on ? 1 : 0; }
