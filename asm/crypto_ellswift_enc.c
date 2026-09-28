/* crypto_ellswift_enc.c -- turning a public key x-coordinate into the 64-byte
 * string BIP324 puts on the wire.
 *
 * Encoding is one-to-many: for a given x there are many (u, t) pairs that
 * decode to it, and the reverse map solves for t only when the branch admits
 * a solution. So the procedure is rejection sampling -- pick u and a branch,
 * try, and on failure pick again.
 *
 * WHY u AND THE BRANCH ARE BOTH DRAWN FROM THE HASH, EVERY ATTEMPT. The entire
 * point of ElligatorSwift here is that the 64 bytes on the wire are
 * indistinguishable from random to an observer. A retry that nudged a byte
 * of u would give successive candidates that differ in a few bits, and the
 * u that finally succeeds would not be uniform over the u that could have.
 * Less obviously, the BRANCH must be random too. The eight branches of the
 * reverse map partition the solutions t for a given (x, u); an encoder that
 * always tries them in a fixed order returns the first family's t whenever
 * that family has one, so its output over-represents those t and is not
 * uniform over the valid encodings. Until 2026-09-28 this file did exactly
 * that (c = 0..7 in order, and the four branches of a family repeat the same
 * feasibility test, so it also burnt 12 branch attempts per key). libsecp256k1
 * draws a 3-bit branch from a hash-filled pool and a fresh u from a hash on
 * every attempt (secp256k1_ellswift_xelligatorswift_var); this is that scheme.
 *
 * COST. A (u, branch) pair succeeds with probability about 1/4, so about four
 * attempts on average: a SHA-256 for each u, one for every 64 branch draws,
 * and one branch of the reverse map (0.75 us when it fails early, ~6 us when
 * it succeeds: two square roots). Mean ~8 us; it was 20 us with the fixed
 * order and 70 us before the square test became a Jacobi symbol.
 *
 * The attempt bound is a safety net: 1024 attempts at 3/4 failure each is
 * 10^-128, so it is never reached; the loop still cannot spin forever on an
 * input the mathematics has no encoding for (there is none, but the bound
 * makes that a return value rather than an assumption).
 */
#include <string.h>
#include "crypto_ellswift.h"

extern void sha256_full(unsigned char* out, const void* msg, long long len);

int ellswift_encode_x(unsigned char ellswift64[64],
                      const unsigned long long x[4],
                      const unsigned char* rnd, unsigned long rndlen){
    unsigned char seed[32];

    /* Compress whatever the caller gave us into a fixed-size seed. A NULL
     * rnd is deterministic on purpose -- tests want repeatability -- and the
     * header of crypto_ellswift_ecdh.c says plainly that the wire must not
     * use it. */
    if (rnd && rndlen) sha256_full(seed, rnd, (long long)rndlen);
    else memset(seed, 0, sizeof seed);

    /* the hash input: seed || counter || x || domain byte (0 = u, 1 = branches) */
    unsigned char buf[32 + 4 + 32 + 1];
    memcpy(buf, seed, 32);
    for (int i = 0; i < 4; i++)                       /* mixing x in keeps two keys from
                                                       * sharing a candidate sequence when
                                                       * a caller reuses a seed */
        for (int j = 0; j < 8; j++)
            buf[36 + i * 8 + j] = (unsigned char)(x[3 - i] >> (56 - 8 * j));

    unsigned char pool[32]; int pool_left = 0;         /* 64 three-bit branch draws per hash */
    unsigned cnt = 0;
    int found = 0;
    for (unsigned attempt = 0; attempt < 1024 && !found; attempt++){
        unsigned char ub[32];
        unsigned long long u[4], t[4];
        if (pool_left == 0){
            buf[32] = (unsigned char)(cnt >> 24); buf[33] = (unsigned char)(cnt >> 16);
            buf[34] = (unsigned char)(cnt >> 8);  buf[35] = (unsigned char)cnt; cnt++;
            buf[68] = 1;
            sha256_full(pool, buf, (long long)sizeof buf);
            pool_left = 64;
        }
        --pool_left;
        int c = (pool[pool_left >> 1] >> ((pool_left & 1) << 2)) & 7;   /* the nibble's low 3 bits */

        buf[32] = (unsigned char)(cnt >> 24); buf[33] = (unsigned char)(cnt >> 16);
        buf[34] = (unsigned char)(cnt >> 8);  buf[35] = (unsigned char)cnt; cnt++;
        buf[68] = 0;
        sha256_full(ub, buf, (long long)sizeof buf);
        ellswift_be32_to_fe(u, ub);                     /* reduced mod p, as BIP324 reads it */

        if (ellswift_xswiftec_inv(t, x, u, c)){
            ellswift_fe_to_be32(ellswift64, u);
            ellswift_fe_to_be32(ellswift64 + 32, t);
            found = 1;
        }
        memset(ub, 0, sizeof ub);
    }
    memset(seed, 0, sizeof seed);
    memset(buf, 0, sizeof buf);
    memset(pool, 0, sizeof pool);
    return found;
}
