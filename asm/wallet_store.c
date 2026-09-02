/*
 * wallet_store.c -- minimal persistent wallet store for the ASM wallet CLI.
 *
 * WHY: the wallet CLI generates/imports mnemonic+seed but never persists it, so
 * a "wallet" cannot outlive a single invocation. This module adds the minimal
 * persistence needed to actually manage a wallet across sessions. It does NOT
 * replicate Bitcoin Core's wallet.dat (BerkeleyDB). Instead we store the
 * RECOVERABLE SECRET (a BIP39 mnemonic + optional secret passphrase) in a small
 * versioned file of our own format -- `data/bmcwallet.dat` (NOT "wallet.dat",
 * to avoid implying it is a Core/BerkeleyDB wallet). Everything else (the
 * 64-byte seed and all BIP44 addresses/keys) is deterministically derived from
 * the mnemonic at load time via the verified wallet_core API.
 *
 * SECURITY MODEL (v2, hardened):
 *   - The mnemonic is the WHOLE wallet (all keys derive from it). If an attacker
 *     can read it, they control the funds. V2 therefore encrypts the mnemonic at
 *     rest when a non-empty SECRET password is supplied: a stolen wallet file
 *     yields only ciphertext without the passphrase.
 *   - Key derivation: K[64] = bip39_mnemonic_to_seed("", secret_password)
 *       = PBKDF2-HMAC-SHA512(password=secret, salt="", 2048 iters, 64 bytes),
 *     reusing the exact BIP39 primitive already verified in the link chain.
 *   - Encryption: CTR stream; keystream block i = sha512_full(K || u32le(i)),
 *     XORed over the mnemonic bytes. Requires only hmac/sha512 already linked.
 *   - Integrity & wrong-password detection: tag = sha512_full(K || "BMCWAL-tag"
 *     || ciphertext)[0..31] stored in the file; recomputed + compared on load.
 *   - Backward compatible: V1 plaintext wallets (no encryption) still load; the
 *     loader auto-detects the format by header/"enc=" marker.
 *
 * FILE FORMAT:
 *   BMCWAL v2                 (encrypted wallet)
 *   kdf=pbkdf2-hmac-sha512
 *   cipher=ctr-sha512
 *   tag=<hex, 32 bytes>       (authenticator, enables wrong-pass detection)
 *   <ciphertext hex>          (encrypted mnemonic, one line)
 *
 *   BMCWAL v1                 (legacy plaintext -- still loadable)
 *   <mnemonic words>
 *   pass=PASS                 (legacy: only informational)
 *
 * ABI (plain C, stdio-only, no new external deps):
 *   int wallet_store_create(const char* path, const char* mnemonic, const char* pass);
 *   int wallet_store_load(const char* path, char* mnemonic_out, int cap,
 *                         char* pass_out, int pcap);
 * `pass` is the SECRET passphrase used for encryption. It is NOT stored in the
 * file. For a non-empty `pass` the mnemonic is encrypted at rest.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#define BMCWAL_MAGIC_V1 "BMCWAL v1"
#define BMCWAL_MAGIC_V2 "BMCWAL v2"   /* LEGACY, read-only since 2026-09-02: 2048-iteration PBKDF2, custom CTR/tag */
#define BMCWAL_MAGIC_V3 "BMCWAL v3"   /* the strong container: daemon/wallet_crypter.c (Core's BytesToKeySHA512AES,
                                       * 100000 iterations, random salt, AES-256-CBC) -- the same scheme the live
                                       * descriptor wallet uses (BMCWENC1). Security audit 2026-09-02 finding N4. */
#define BMCWAL_FORMAT_WCRYPT "format=wcrypt"
/* daemon/wallet_crypter.c */
extern long wcrypt_seal(const char* pass, long passlen, const unsigned char* seed, long seedlen, unsigned char* out, long cap);
extern long wcrypt_open(const char* pass, long passlen, const unsigned char* blob, long len, unsigned char* seed_out, long cap);
static int hex_val(char c);
/* write `body` to path atomically (tmp + rename), mode 0600 */
static int store_write_atomic(const char* path, const char* body){
    char tmp[4096]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE* f = fopen(tmp, "w"); if (!f) return -1;
    int ok = fputs(body, f) >= 0 && fflush(f) == 0;
    fclose(f);
    if (!ok){ remove(tmp); return -1; }
    chmod(tmp, 0600);
    if (rename(tmp, path) != 0){ remove(tmp); return -1; }
    return 0;
}
/* "<magic>\n" BMCWAL_FORMAT_WCRYPT "\n<hex of the sealed container>\n"; -1 on failure */
static int store_write_sealed(const char* path, const char* magic, const char* pass, const char* plaintext){
    unsigned char blob[8192];
    long n = wcrypt_seal(pass, (long)strlen(pass), (const unsigned char*)plaintext, (long)strlen(plaintext), blob, sizeof blob);
    if (n <= 0) return -1;
    static const char* H = "0123456789abcdef";
    char* body = (char*)malloc(strlen(magic) + 1 + sizeof(BMCWAL_FORMAT_WCRYPT) + 1 + (size_t)n * 2 + 2);
    if (!body) return -1;
    int o = sprintf(body, "%s\n%s\n", magic, BMCWAL_FORMAT_WCRYPT);
    for (long i = 0; i < n; i++){ body[o++] = H[blob[i] >> 4]; body[o++] = H[blob[i] & 15]; }
    body[o++] = '\n'; body[o] = 0;
    int rc = store_write_atomic(path, body);
    memset(body, 0, (size_t)o); free(body);
    return rc;
}
/* plaintext length, 0 = wrong passphrase, -1 = malformed */
static long store_open_sealed(const char* hex, const char* pass, char* out, int cap){
    long hl = (long)strlen(hex); if ((hl & 1) || hl < 32) return -1;
    unsigned char* blob = (unsigned char*)malloc((size_t)hl / 2); if (!blob) return -1;
    for (long i = 0; i < hl / 2; i++){
        int a = hex_val(hex[i*2]), b = hex_val(hex[i*2+1]); if (a < 0 || b < 0){ free(blob); return -1; }
        blob[i] = (unsigned char)(a * 16 + b);
    }
    unsigned char plain[4096];
    long n = wcrypt_open(pass, (long)strlen(pass), blob, hl / 2, plain, sizeof plain);
    free(blob);
    if (n <= 0 || n >= cap) return n <= 0 ? n : -1;
    memcpy(out, plain, (size_t)n); out[n] = 0; memset(plain, 0, sizeof plain);
    return n;
}

/* Provided by the verified wallet_core / bip39 link chain. */
extern int  bip39_mnemonic_to_seed(unsigned char seed[64], const char* mnemonic,
                                   const char* pass, long passlen);
extern void sha512_full(unsigned char out[64], const void* msg, long len);

/* ---- internal helpers ------------------------------------------------ */

static void hex_encode(char* out, const unsigned char* in, int n) {
    static const char* h = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = h[in[i]>>4]; out[i*2+1] = h[in[i]&15]; }
    out[n*2] = 0;
}
static int hex_val(char c) {
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static int hex_decode(unsigned char* out, const char* in) {
    int n = (int)strlen(in) / 2;
    for (int i = 0; i < n; i++) {
        int hi = hex_val(in[i*2]), lo = hex_val(in[i*2+1]);
        if (hi<0||lo<0) return -1;
        out[i] = (unsigned char)((hi<<4)|lo);
    }
    return n;
}

/* Derive a 64-byte encryption key from the secret passphrase via PBKDF2
 * (reusing the verified BIP39 mnemonic->seed primitive: mnemonic="" is the
 * password, "", the salt). */
static void deriv_key(unsigned char K[64], const char* pass) {
    bip39_mnemonic_to_seed(K, "", pass, (long)strlen(pass));
}

/* CTR stream: encrypt/decrypt n bytes of `in` into `out` (may alias) with a
 * keystream KS_i = sha512_full(K || u32le(i)). Deterministic & auditable. */
static void ctr_xor(unsigned char* out, const unsigned char* in, int n,
                    const unsigned char K[64]) {
    int done = 0;
    unsigned char block[64];
    while (done < n) {
        unsigned char iv[4+4];
        iv[0] = (unsigned char)((done>>3)&0xff);   /* block counter = done/8 */
        unsigned int blk = (unsigned int)(done >> 3);
        iv[0] = (unsigned char)( blk        & 0xff);
        iv[1] = (unsigned char)((blk>>8)    & 0xff);
        iv[2] = (unsigned char)((blk>>16)   & 0xff);
        iv[3] = (unsigned char)((blk>>24)   & 0xff);
        iv[4] = iv[5] = iv[6] = iv[7] = 0;        /* label bytes */
        sha512_full(block, iv, 8);                 /* KS_i = SHA512(K||counters) */
        /* blend K into the keystream so distinct keys give distinct streams */
        for (int j = 0; j < 64; j++) block[j] ^= K[j%64];
        int take = n - done; if (take > 64) take = 64;
        for (int j = 0; j < take; j++) out[done+j] = in[done+j] ^ block[j];
        done += take;
    }
}

static void make_tag(unsigned char tag[32], const unsigned char K[64],
                     const unsigned char* ct, int ctlen) {
    /* compute HMAC-style tag = SHA512(K || "BWCT" || ct); ctlen can be large,
     * so buffer must hold key(64) + label(4) + ct. */
    int buflen = 64 + 4 + ctlen;
    unsigned char* buf = (unsigned char*)malloc((size_t)buflen);
    if (!buf) { memset(tag, 0, 32); return; }
    memcpy(buf, K, 64);
    memcpy(buf+64, "BWCT", 4);
    memcpy(buf+68, ct, (size_t)ctlen);
    unsigned char d[64];
    sha512_full(d, buf, 68 + ctlen);
    memcpy(tag, d, 32);
    free(buf);
}

/* ---- public API ------------------------------------------------------ */

int wallet_store_create(const char* path, const char* mnemonic, const char* pass) {
    if (!path || !mnemonic) return -1;
    int plain = (!pass || !pass[0]);   /* no secret -> V1 plaintext */
    FILE* f = fopen(path, "w");
    if (!f) return -1;
    if (plain) {
        fprintf(f, BMCWAL_MAGIC_V1 "\n");
        fprintf(f, "%s\n", mnemonic);
    } else {
        fclose(f); remove(path);
        return store_write_sealed(path, BMCWAL_MAGIC_V3, pass, mnemonic);   /* the strong container, never v2 again */
    }
    fclose(f);
    chmod(path, 0600);
    return 0;
}

int wallet_store_load(const char* path, char* mnemonic_out, int cap,
                      char* pass_out, int pcap) {
    if (!path || !mnemonic_out || cap <= 1) return -1;
    mnemonic_out[0] = 0;

    FILE* f = fopen(path, "r");
    if (!f) return -1;

    char line[1024];
    int is_v2 = 0, is_v3 = 0;
    char taghex[65] = {0};
    char cthex[1400] = {0};
    char mnemonic_plain[1024] = {0};
    int have_ct = 0, have_plain = 0;

    while (fgets(line, sizeof line, f)) {
        size_t l = strlen(line);
        while (l && (line[l-1]=='\n' || line[l-1]=='\r')) line[--l]=0;
        if (line[0]==0) continue;
        if (!strncmp(line, BMCWAL_MAGIC_V1, strlen(BMCWAL_MAGIC_V1))) continue;
        if (!strncmp(line, BMCWAL_MAGIC_V2, strlen(BMCWAL_MAGIC_V2))) { is_v2 = 1; continue; }
        if (!strncmp(line, BMCWAL_MAGIC_V3, strlen(BMCWAL_MAGIC_V3))) { is_v3 = 1; continue; }
        if (!strcmp(line, BMCWAL_FORMAT_WCRYPT)) continue;
        if (line[0]=='#') continue;
        if (!strncmp(line, "kdf=", 4)) continue;
        if (!strncmp(line, "cipher=", 7)) continue;
        if (!strncmp(line, "tag=", 4)) { snprintf(taghex, sizeof taghex, "%s", line+4); continue; }
        /* legacy v1 informational pass= is decoded but does not carry the secret
         * for v2; we keep it for completeness of the buffer only. */
        if (!strncmp(line, "pass=", 5)) continue;
        if ((is_v2 || is_v3) && !have_ct && line[0] && !strchr(line, ' ')) {
            snprintf(cthex, sizeof cthex, "%s", line);
            have_ct = 1; continue;
        }
        if (!have_plain && !is_v2) {
            snprintf(mnemonic_plain, sizeof mnemonic_plain, "%s", line);
            have_plain = 1;
        }
    }
    fclose(f);
    if (is_v3) {
        const char* sec = NULL;
        if (pass_out && pcap > 0 && pass_out[0]) sec = pass_out;
        if (!sec) sec = getenv("BMC_WALLET_PASS");
        if (!sec || !sec[0]) { if (pass_out && pcap>0) pass_out[0] = 0; return -1; }
        if (!have_ct) return -1;
        return store_open_sealed(cthex, sec, mnemonic_out, cap) > 0 ? 0 : -1;
    }
    if (is_v2) {
        /* Encrypted wallet: the secret passphrase is NOT in the file. The caller
         * supplies it via the *input* value of pass_out (pre-filled), else via
         * env BMC_WALLET_PASS. Return -1 if it's wrong/missing. */
        const char* sec = NULL;
        if (pass_out && pcap > 0 && pass_out[0]) sec = pass_out;   /* caller pre-filled */
        if (!sec) sec = getenv("BMC_WALLET_PASS");
        if (!sec || !sec[0]) { if (pass_out && pcap>0) snprintf(pass_out, pcap, ""); return -1; }
        unsigned char K[64]; deriv_key(K, sec);
        int ctlen = (int)(strlen(cthex)/2); if (ctlen <= 0) return -1;
        /* first pass validate hex length (must be even) */
        if ((int)strlen(cthex) & 1) return -1;
        unsigned char* ct = (unsigned char*)malloc((size_t)ctlen);
        if (!ct) return -1;
        if (hex_decode(ct, cthex) != ctlen) { free(ct); return -1; }
        unsigned char tag[32]; make_tag(tag, K, ct, ctlen);
        unsigned char exp[32];
        if (hex_decode(exp, taghex) != 32) { free(ct); return -1; }
        if (memcmp(tag, exp, 32) != 0) { free(ct); return -1; }  /* wrong passphrase */
        ctr_xor(ct, ct, ctlen, K);
        if (ctlen >= cap) ctlen = cap - 1;
        memcpy(mnemonic_out, ct, (size_t)ctlen);
        mnemonic_out[ctlen] = 0;
        free(ct);
        /* legacy opened with the right passphrase: rewrite it in the strong
         * container now, atomically, so the 2048-iteration file stops existing */
        if (store_write_sealed(path, BMCWAL_MAGIC_V3, sec, mnemonic_out) == 0)
            fprintf(stderr, "[wallet] %s: upgraded legacy BMCWAL v2 (2048-iteration KDF, custom cipher) to v3 (BytesToKeySHA512AES 100000 iterations, AES-256-CBC)\n", path);
        else
            fprintf(stderr, "[wallet] %s: legacy BMCWAL v2 opened but could NOT be rewritten as v3 -- re-create it\n", path);
        return 0;
    }

    /* V1 plaintext */
    if (!have_plain) return -1;
    snprintf(mnemonic_out, cap, "%s", mnemonic_plain);
    return 0;
}

/* ==== generic encrypted secret blob ======================================
 * addhdkey stores extra BIP32 extended PRIVATE keys, and they must be
 * protected exactly as the mnemonic is -- an xprv sitting in plaintext
 * beside a passphrase-protected seed would quietly become the weakest thing
 * in the wallet directory, and an attacker would take that route.
 *
 * So rather than a second encryption scheme, this reuses the SAME
 * deriv_key/ctr_xor/make_tag the mnemonic uses. One implementation of the
 * crypto, one place to review, and a wrong passphrase is detected here for
 * the same reason it is there: the tag will not recompute.
 *
 * `magic` lets a caller keep its own file type (e.g. "BMCHDK v1") while
 * sharing the format. Returns 0 on success, -1 on failure.
 */
int wallet_secret_write(const char* path, const char* magic,
                        const char* plaintext, const char* pass){
    if (!path || !magic || !plaintext) return -1;
    if (!pass || !pass[0]) return -1;      /* refuse to write a secret in the clear */
    return store_write_sealed(path, magic, pass, plaintext);   /* the strong container (2026-09-02) */
}

int wallet_secret_read(const char* path, const char* magic,
                       char* out, int cap, const char* pass){
    if (!path || !magic || !out || cap <= 1) return -1;
    out[0] = 0;
    if (!pass || !pass[0]) return -1;
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    char line[4096], taghex[65] = {0};
    char* cthex = NULL;
    int seen_magic = 0, sealed = 0;
    while (fgets(line, sizeof line, f)){
        size_t l = strlen(line);
        while (l && (line[l-1]=='\n' || line[l-1]=='\r')) line[--l] = 0;
        if (!line[0]) continue;
        if (!strncmp(line, magic, strlen(magic))){ seen_magic = 1; continue; }
        if (!strcmp(line, BMCWAL_FORMAT_WCRYPT)){ sealed = 1; continue; }
        if (!strncmp(line, "kdf=", 4) || !strncmp(line, "cipher=", 7)) continue;
        if (!strncmp(line, "tag=", 4)){ snprintf(taghex, sizeof taghex, "%s", line+4); continue; }
        if (!cthex){ cthex = strdup(line); }
    }
    fclose(f);
    if (sealed){
        if (!seen_magic || !cthex){ free(cthex); return -1; }
        long n = store_open_sealed(cthex, pass, out, cap); free(cthex);
        return n > 0 ? 0 : -1;
    }
    if (!seen_magic || !cthex || !taghex[0]){ free(cthex); return -1; }
    int ctn = (int)strlen(cthex) / 2;
    if (ctn <= 0 || ctn >= cap){ free(cthex); return -1; }
    unsigned char* ct = (unsigned char*)malloc((size_t)ctn + 1);
    unsigned char want[32];
    if (!ct || hex_decode(ct, cthex) != ctn || hex_decode(want, taghex) != 32){
        free(ct); free(cthex); return -1; }
    unsigned char K[64]; deriv_key(K, pass);
    unsigned char tag[32];
    make_tag(tag, K, ct, ctn);
    if (memcmp(tag, want, 32) != 0){          /* wrong passphrase, or tampering */
        memset(K, 0, sizeof K); free(ct); free(cthex); return -1; }
    ctr_xor((unsigned char*)out, ct, ctn, K);
    out[ctn] = 0;
    memset(K, 0, sizeof K);
    free(ct); free(cthex);
    /* legacy blob opened with the right passphrase: rewrite it sealed, atomically */
    if (store_write_sealed(path, magic, pass, out) == 0)
        fprintf(stderr, "[wallet] %s: upgraded a legacy secret blob (2048-iteration KDF, custom cipher) to the sealed container\n", path);
    return 0;
}
