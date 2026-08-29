/* crypto_ellswift_enc.c -- turning a public key x-coordinate into the 64-byte
 * string BIP324 puts on the wire.
 *
 * Encoding is one-to-many: for a given x there are many (u, t) pairs that
 * decode to it, and the reverse map solves for t only when the branch admits
 * a solution. So the procedure is rejection sampling -- pick u, try each of
 * the eight branches, and on total failure pick another u.
 *
 * WHY THE RETRY u IS HASHED RATHER THAN NUDGED. The obvious shortcut is to
 * take one random 32-byte block and bump a byte between attempts. That works
 * in the sense that it terminates, but successive candidates then differ in
 * only a few bits, and the u that finally succeeds is not uniform over the u
 * that could have. The entire point of ElligatorSwift here is that the 64
 * bytes on the wire are indistinguishable from random to an observer; a
 * biased u is exactly the kind of thing that stops being true. Hashing the
 * seed with an attempt counter gives an independent uniform candidate every
 * time, which is also what libsecp256k1 does.
 *
 * The 64-attempt bound is a safety net, not an expectation: each u succeeds
 * on some branch with probability close to 1, so the loop essentially always
 * ends on the first pass.
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
     * header says plainly that the wire must not use it. */
    if (rnd && rndlen) sha256_full(seed, rnd, (long long)rndlen);
    else memset(seed, 0, sizeof seed);

    for (unsigned attempt = 0; attempt < 64; attempt++){
        unsigned char buf[32 + 4 + 32], ub[32];
        unsigned long long u[4], t[4];

        memcpy(buf, seed, 32);
        buf[32] = (unsigned char)(attempt >> 24); buf[33] = (unsigned char)(attempt >> 16);
        buf[34] = (unsigned char)(attempt >> 8);  buf[35] = (unsigned char)attempt;
        /* mixing x in keeps two different keys from sharing a candidate
         * sequence when a caller reuses a seed */
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 8; j++)
                buf[36 + i * 8 + j] = (unsigned char)(x[3 - i] >> (56 - 8 * j));
        sha256_full(ub, buf, (long long)sizeof buf);
        memset(buf, 0, sizeof buf);

        ellswift_be32_to_fe(u, ub);
        for (int c = 0; c < 8; c++){
            if (ellswift_xswiftec_inv(t, x, u, c)){
                ellswift_fe_to_be32(ellswift64, u);
                ellswift_fe_to_be32(ellswift64 + 32, t);
                memset(seed, 0, sizeof seed);
                return 1;
            }
        }
    }
    memset(seed, 0, sizeof seed);
    return 0;
}
