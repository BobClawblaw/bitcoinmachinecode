/* crypto_ellswift.h -- ElligatorSwift for secp256k1 (BIP324).
 * Encodes a public key as 64 bytes indistinguishable from random, so a v2
 * connection has no recognisable header. See crypto_ellswift.c for the map. */
#ifndef BMC_CRYPTO_ELLSWIFT_H
#define BMC_CRYPTO_ELLSWIFT_H
/* the SwiftEC forward map: (u,t) -> a curve x-coordinate. Always succeeds. */
void ellswift_xswiftec(unsigned long long x[4],
                       const unsigned long long u[4], const unsigned long long t[4]);
/* 64 bytes big-endian (u || t) -> 32-byte big-endian x. Never fails: every
 * 64-byte string is a valid encoding, which is the point. */
void ellswift_decode(unsigned char x_out[32], const unsigned char ellswift64[64]);
/* big-endian <-> field element, reducing mod p (BIP324 reads the wire bytes
 * mod p so that no 64-byte string is invalid) */
void ellswift_be32_to_fe(unsigned long long r[4], const unsigned char b[32]);
void ellswift_fe_to_be32(unsigned char b[32], const unsigned long long a[4]);
/* the reverse map: t such that xswiftec(u,t) == x, for branch c in 0..7.
 * 1 on success; most (x,u,c) combinations have no solution, which is how
 * encoding works -- pick u at random and retry. */
int ellswift_xswiftec_inv(unsigned long long t[4], const unsigned long long x[4],
                          const unsigned long long u[4], int c);
/* find any 64-byte encoding that decodes to x. 1 on success. */
int ellswift_encode_x(unsigned char ellswift64[64], const unsigned long long x[4],
                      const unsigned char* rnd, unsigned long rndlen);

/* BIP324 ECDH. `initiating` is OUR role and decides the hash order, which is
 * always initiator-then-responder; get it wrong and both peers derive
 * different secrets. 1 on success. */
int ellswift_ecdh(unsigned char out32[32], const unsigned char their_ellswift64[64],
                  const unsigned char our_ellswift64[64],
                  const unsigned char our_seckey32[32], int initiating);

/* Our 64-byte handshake encoding of seckey*G. `rnd` selects among the many
 * valid encodings; NULL is deterministic and is for tests only -- on the wire
 * this must be random or the encoding stops being indistinguishable. */
int ellswift_create(unsigned char ellswift64[64], const unsigned char seckey32[32],
                    const unsigned char* rnd, unsigned long rndlen);

#endif
