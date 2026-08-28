/* bitcoin_sha3.c -- SHA3-256 (FIPS 202, Keccak-f[1600], rate 1088).
 *
 * WHY: a Tor v3 onion address is base32(pubkey[32] || checksum[2] || 0x03)
 * where checksum = SHA3-256(".onion checksum" || pubkey || 0x03)[0..1]. Core
 * verifies that checksum when it parses an address and computes it when it
 * prints one; without SHA3 this node could neither validate an onion address
 * a peer gossips nor print its own. Nothing else in the tree needed SHA3
 * until 2026-08-28 (Bitcoin itself uses SHA-256 / RIPEMD-160 only).
 *
 * Straight from the spec: 24 rounds of theta/rho/pi/chi/iota over a 5x5
 * lane state, absorbing 136-byte blocks with the 0x06 domain byte and the
 * 0x80 final-bit pad. Checked against the NIST vectors for "" and "abc" and
 * against Core's own example onion address (tests/test_sha3.c). */
#include <string.h>
#include <stdint.h>

typedef uint64_t u64;
static const u64 RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL };
static const int ROT[25] = { 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
                             41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };
static const int PI[25]  = { 0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22,
                             23, 8, 18, 3, 13, 14, 24, 9, 19, 4 };
static inline u64 rol(u64 x, int n){ return n ? (x << n) | (x >> (64 - n)) : x; }

static void keccak_f(u64 s[25]){
    for (int r = 0; r < 24; r++){
        u64 c[5], d[5], b[25];
        for (int x = 0; x < 5; x++) c[x] = s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20];
        for (int x = 0; x < 5; x++) d[x] = c[(x+4)%5] ^ rol(c[(x+1)%5], 1);
        for (int i = 0; i < 25; i++) s[i] ^= d[i % 5];
        /* rho + pi: lane (x,y) -> rotated, moved to (y, 2x+3y) */
        for (int i = 0; i < 25; i++) b[PI[i]] = rol(s[i], ROT[i]);
        /* chi */
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                s[y+x] = b[y+x] ^ ((~b[y+(x+1)%5]) & b[y+(x+2)%5]);
        s[0] ^= RC[r];
    }
}

/* sha3_256(out[32], data, len) -- one shot */
void sha3_256(unsigned char out[32], const void* data, unsigned long len){
    u64 s[25]; memset(s, 0, sizeof s);
    const unsigned char* p = data;
    const unsigned long rate = 136;
    unsigned char blk[136];
    while (len >= rate){
        for (unsigned i = 0; i < rate/8; i++){ u64 w = 0; for (int k = 0; k < 8; k++) w |= (u64)p[i*8+k] << (8*k); s[i] ^= w; }
        keccak_f(s); p += rate; len -= rate;
    }
    memset(blk, 0, sizeof blk); memcpy(blk, p, len);
    blk[len] ^= 0x06;                  /* SHA3 domain separation */
    blk[rate-1] ^= 0x80;               /* final pad bit */
    for (unsigned i = 0; i < rate/8; i++){ u64 w = 0; for (int k = 0; k < 8; k++) w |= (u64)blk[i*8+k] << (8*k); s[i] ^= w; }
    keccak_f(s);
    for (int i = 0; i < 4; i++) for (int k = 0; k < 8; k++) out[i*8+k] = (unsigned char)(s[i] >> (8*k));
}
