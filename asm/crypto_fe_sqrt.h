/* crypto_fe_sqrt.h -- square root and the square predicate in the secp256k1
 * field, needed by ElligatorSwift (BIP324). Field elements are 4 little-endian
 * u64 limbs in [0, p), the same representation secp256k1_fe.asm uses. */
#ifndef BMC_CRYPTO_FE_SQRT_H
#define BMC_CRYPTO_FE_SQRT_H
/* 1 and r = sqrt(a) when a is a residue; 0 and r untouched otherwise.
 * Which of the two roots you get is whatever a^((p+1)/4) yields, matching
 * libsecp256k1 -- negate explicitly if you need a particular parity. */
int fe_sqrt(unsigned long long r[4], const unsigned long long a[4]);
int fe_is_square(const unsigned long long a[4]);
/* the same predicate by the Jacobi symbol (safegcd, ~0.5 us instead of a
 * 2 us exponentiation); VARIABLE TIME, for public inputs only */
int fe_is_square_var(const unsigned long long a[4]);
int fe_is_zero(const unsigned long long a[4]);
int fe_equal(const unsigned long long a[4], const unsigned long long b[4]);
#endif
