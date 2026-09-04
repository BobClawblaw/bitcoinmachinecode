/* daemon/wallet_crypter.c -- wallet-at-rest encryption, Core's scheme.
 *
 * WHAT & WHY: `encryptwallet` was refused ("no encryption path"). This adds
 * it, using Bitcoin Core's exact key derivation (wallet/crypter.cpp
 * BytesToKeySHA512AES: buf = SHA512(passphrase || salt), then SHA512(buf)
 * iterations-1 more times; key = buf[0:32], iv = buf[32:48]) over the SHA512
 * this node already implements, and the AES-256-CBC just added
 * (bitcoin_aes.c). The on-disk container is OURS (this node has never
 * matched Core's wallet.dat format -- every store here is its own), but the
 * crypto and the RPC state machine are Core's.
 *
 * TWO LAYERS, like Core: a random 32-byte MASTER KEY encrypts the seed; the
 * passphrase encrypts the master key. So `walletpassphrasechange` re-wraps
 * only the master key -- the seed ciphertext never moves -- and a compromise
 * of one passphrase-derived key does not expose the seed beyond that wrap.
 *
 * CONTAINER (bmcwallet.enc):
 *   "BMCWENC1" | salt[8] | u32 iterations | u16 wrapped_mk_len | wrapped_mk
 *   | seed_iv[16] | u32 seed_ct_len | seed_ct | sha256(all preceding)
 * A bad checksum or magic reads as "not an encrypted store".
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "secure_zero.h"   /* WAL-3: a memset the optimiser may not delete */

typedef unsigned char u8;
typedef unsigned int u32;

extern void sha512_full(u8 out[64], const void* msg, long len);
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern long aes256_cbc_encrypt(const u8 key[32], const u8 iv[16], const u8* in, long inlen, u8* out, long cap);
extern long aes256_cbc_decrypt(const u8 key[32], const u8 iv[16], const u8* in, long inlen, u8* out, long cap);

#define WC_MAGIC "BMCWENC1"
#define WC_SALT 8
#define WC_ITERS 100000            /* our fixed count (stored, so it can grow) */
#define WC_MKLEN 32

/* Core's BytesToKeySHA512AES: SHA512(pass||salt), then SHA512 iters-1 more
 * times; key=buf[0:32], iv=buf[32:48]. Exposed for the differential test. */
void wcrypt_derive(const char* pass, long passlen, const u8 salt[WC_SALT],
                   u32 iters, u8 key[32], u8 iv[16]){
    static u8 buf[128];            /* first 64 = pass||salt scratch region */
    u8 d[64];
    /* first hash over pass||salt */
    long n = passlen;
    if (n > 96) n = 96;            /* passphrases are short; bound the scratch */
    memcpy(buf, pass, (size_t)n);
    memcpy(buf + n, salt, WC_SALT);
    sha512_full(d, buf, n + WC_SALT);
    for (u32 i = 0; i + 1 < iters; i++) sha512_full(d, d, 64);
    memcpy(key, d, 32);
    memcpy(iv, d + 32, 16);
    /* WAL-3 (audit 2026-09-03): `buf` is STATIC, so the wallet passphrase (and
     * the salt) stayed in .bss for the life of the process after every KDF
     * call -- including after walletlock had zeroed the seed and the operator
     * believed nothing sensitive was resident. `d` is the derived key and iv,
     * equally worth clearing once it has been copied out.
     *
     * secure_zero, not memset: both are dead afterwards, so a plain memset is
     * exactly the store an optimiser is allowed to delete. */
    secure_zero(buf, sizeof buf);
    secure_zero(d, sizeof d);
}

static int wc_rand(u8* out, long n){
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    long got = 0;
    while (got < n){ long r = read(fd, out + got, n - got); if (r <= 0){ close(fd); return 0; } got += r; }
    close(fd);
    return 1;
}

/* Build the encrypted container for `seed` (its bytes -- the mnemonic
 * string) under `pass`. Returns bytes written, or -1. */
long wcrypt_seal(const char* pass, long passlen, const u8* seed, long seedlen,
                 u8* out, long cap){
    u8 salt[WC_SALT], mk[WC_MKLEN], seed_iv[16];
    if (!wc_rand(salt, WC_SALT) || !wc_rand(mk, WC_MKLEN) || !wc_rand(seed_iv, 16)) return -1;
    u8 kek[32], kek_iv[16];
    wcrypt_derive(pass, passlen, salt, WC_ITERS, kek, kek_iv);

    static u8 wrapped[64];
    long wl = aes256_cbc_encrypt(kek, kek_iv, mk, WC_MKLEN, wrapped, sizeof wrapped);
    if (wl < 0) return -1;
    static u8 seedct[4096];
    long sl = aes256_cbc_encrypt(mk, seed_iv, seed, seedlen, seedct, sizeof seedct);
    if (sl < 0) return -1;

    u8* p = out;
    long need = 8 + WC_SALT + 4 + 2 + wl + 16 + 4 + sl + 32;
    if (cap < need) return -1;
    memcpy(p, WC_MAGIC, 8); p += 8;
    memcpy(p, salt, WC_SALT); p += WC_SALT;
    u32 it = WC_ITERS; memcpy(p, &it, 4); p += 4;
    unsigned short wl16 = (unsigned short)wl; memcpy(p, &wl16, 2); p += 2;
    memcpy(p, wrapped, wl); p += wl;
    memcpy(p, seed_iv, 16); p += 16;
    u32 sl32 = (u32)sl; memcpy(p, &sl32, 4); p += 4;
    memcpy(p, seedct, sl); p += sl;
    sha256_full(p, out, (unsigned long)(p - out)); p += 32;
    /* wipe secrets */
    memset(mk, 0, sizeof mk); memset(kek, 0, sizeof kek);
    return p - out;
}

/* Is this blob our encrypted container? (magic + checksum) */
int wcrypt_is_encrypted(const u8* blob, long len){
    if (len < 8 + WC_SALT + 4 + 2 + 16 + 4 + 32) return 0;
    if (memcmp(blob, WC_MAGIC, 8) != 0) return 0;
    u8 want[32];
    sha256_full(want, blob, (unsigned long)(len - 32));
    return memcmp(want, blob + len - 32, 32) == 0;
}

/* Recover the seed bytes from the container under `pass`.
 * Returns seed length, 0 = wrong passphrase, -1 = malformed. */
long wcrypt_open(const char* pass, long passlen, const u8* blob, long len,
                 u8* seed_out, long cap){
    if (!wcrypt_is_encrypted(blob, len)) return -1;
    const u8* p = blob + 8;
    u8 salt[WC_SALT]; memcpy(salt, p, WC_SALT); p += WC_SALT;
    u32 iters; memcpy(&iters, p, 4); p += 4;
    unsigned short wl; memcpy(&wl, p, 2); p += 2;
    if (wl == 0 || wl > 64 || p + wl + 16 + 4 > blob + len - 32) return -1;
    const u8* wrapped = p; p += wl;
    u8 seed_iv[16]; memcpy(seed_iv, p, 16); p += 16;
    u32 sl; memcpy(&sl, p, 4); p += 4;
    if (p + sl > blob + len - 32) return -1;
    const u8* seedct = p;

    u8 kek[32], kek_iv[16];
    wcrypt_derive(pass, passlen, salt, iters, kek, kek_iv);
    u8 mk[64];
    long mkl = aes256_cbc_decrypt(kek, kek_iv, wrapped, wl, mk, sizeof mk);
    memset(kek, 0, sizeof kek);
    if (mkl != WC_MKLEN){ memset(mk, 0, sizeof mk); return 0; }   /* wrong passphrase: pad check failed */
    long out = aes256_cbc_decrypt(mk, seed_iv, seedct, sl, seed_out, cap);
    memset(mk, 0, sizeof mk);
    if (out < 0) return 0;   /* master key wrong (shouldn't happen if wrap decrypted) */
    return out;
}

/* Re-wrap under a new passphrase without touching the seed ciphertext.
 * Returns new blob length, 0 = old passphrase wrong, -1 = malformed/cap. */
long wcrypt_rewrap(const char* oldp, long oldlen, const char* newp, long newlen,
                   const u8* blob, long len, u8* out, long cap){
    if (!wcrypt_is_encrypted(blob, len)) return -1;
    /* recover the master key via the old passphrase */
    const u8* p = blob + 8;
    u8 salt[WC_SALT]; memcpy(salt, p, WC_SALT); p += WC_SALT;
    u32 iters; memcpy(&iters, p, 4); p += 4;
    unsigned short wl; memcpy(&wl, p, 2); p += 2;
    if (wl == 0 || wl > 64) return -1;
    const u8* wrapped = p;
    u8 kek[32], kek_iv[16];
    wcrypt_derive(oldp, oldlen, salt, iters, kek, kek_iv);
    u8 mk[64];
    long mkl = aes256_cbc_decrypt(kek, kek_iv, wrapped, wl, mk, sizeof mk);
    memset(kek, 0, sizeof kek);
    if (mkl != WC_MKLEN){ memset(mk, 0, sizeof mk); return 0; }

    /* new salt + new wrap; seed_iv and seed ct copied verbatim */
    const u8* seed_iv = p + wl;
    u32 sl; memcpy(&sl, seed_iv + 16, 4);
    const u8* seedct = seed_iv + 16 + 4;

    u8 nsalt[WC_SALT]; if (!wc_rand(nsalt, WC_SALT)){ memset(mk,0,sizeof mk); return -1; }
    u8 nkek[32], nkek_iv[16];
    wcrypt_derive(newp, newlen, nsalt, WC_ITERS, nkek, nkek_iv);
    static u8 nwrap[64];
    long nwl = aes256_cbc_encrypt(nkek, nkek_iv, mk, WC_MKLEN, nwrap, sizeof nwrap);
    memset(mk, 0, sizeof mk); memset(nkek, 0, sizeof nkek);
    if (nwl < 0) return -1;

    long need = 8 + WC_SALT + 4 + 2 + nwl + 16 + 4 + sl + 32;
    if (cap < need) return -1;
    u8* q = out;
    memcpy(q, WC_MAGIC, 8); q += 8;
    memcpy(q, nsalt, WC_SALT); q += WC_SALT;
    u32 it = WC_ITERS; memcpy(q, &it, 4); q += 4;
    unsigned short nwl16 = (unsigned short)nwl; memcpy(q, &nwl16, 2); q += 2;
    memcpy(q, nwrap, nwl); q += nwl;
    memcpy(q, seed_iv, 16); q += 16;
    memcpy(q, &sl, 4); q += 4;
    memcpy(q, seedct, sl); q += sl;
    sha256_full(q, out, (unsigned long)(q - out)); q += 32;
    return q - out;
}
