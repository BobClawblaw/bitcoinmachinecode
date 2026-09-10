/* ============================================================================
 * script_twin.c -- P2PKH spend validation + DER sig parsing for the
 * macOS/AArch64 port.  Functional twin of asm/bitcoin_script.asm.
 *
 *   int  der_parse_sig(const u8* sig, u64 slen, u64 r[4], u64 s[4],
 *                      u32 *hashtype);
 *   void be_to_limbs(u64 out[4], const u8* bytes, u64 len);
 *   int  verify_p2pkh(const u8* tx, u64 txlen, u64 input_index,
 *                     const u8* prevout_script, u64 prevout_len,
 *                     u8* work, u64 cap);
 *
 * der_parse_sig is TOLERANT on purpose (pre-BIP66 mainnet history): any
 * number of redundant leading 0x00 bytes in an INTEGER value, long-form
 * lengths exactly like Core's ecdsa_signature_parse_der_lax -- long-form
 * SEQUENCE length SKIPPED without checking its value, long-form INTEGER
 * length leading-zero-length-bytes skipped then rejected at >= 4 significant
 * length bytes then accumulated big-endian.  r/s must fit 32 bytes after
 * stripping; hashtype = trailing 0x01 byte, else 0.  (The BIP66 strict rule
 * is der_sig_strict in bitcoin_scriptcodec -- a separate predicate.)
 *
 * verify_p2pkh: sighash_all over prevout_script, walk raw tx to input_index
 * with every cursor advance bounded (IR-10: empty scriptSig / oversized /
 * non-direct pushes are refused, never misparsed -- only 1..75 direct
 * pushes), hashtype popped first (IR-2: parser sees siglen-1, the caller
 * reads sig[siglen-1] and requires SIGHASH_ALL), z = be_to_limbs(sighash),
 * pubkey_parse, ecdsa_verify.  Returns 1 only on a verifying signature.
 *
 * C twin per the escape hatch: dense cursor arithmetic + the Core-quirk DER
 * shape; every bound and strip rule of the x86 transcribed as-is.
 * Calls: sighash_all (sighash_twin), pubkey_parse (pubkey_schnorr_twin),
 * ecdsa_verify (ecdsa_twin).
 * ==========================================================================*/
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;

extern int  sighash_all(unsigned char out32[32], const unsigned char* tx,
                        unsigned long long txlen, unsigned long long input_index,
                        const unsigned char* script, unsigned long long script_len,
                        unsigned char* preimg, unsigned long long cap);
extern int  pubkey_parse(const unsigned char* pub, unsigned long plen,
                         u64 qx[4], u64 qy[4]);
extern int  ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
                         const u64 qx[4], const u64 qy[4]);

/* be_to_limbs: 1..32 big-endian bytes -> 4 LE limbs, zero-padded left. */
void be_to_limbs(u64 out[4], const unsigned char* bytes, unsigned long long len){
    unsigned char tmp[32] = {0};
    memcpy(tmp + (32 - len), bytes, len);          /* right-justify */
    for (int j = 0; j < 4; j++){
        const unsigned char* p = tmp + (3 - j) * 8;
        u64 v = 0;
        for (int k = 0; k < 8; k++) v = (v << 8) | p[k];
        out[j] = v;                                 /* bswap of the BE group */
    }
}

/* DER_LONG_LEN equivalent: decode a long-form INTEGER length.  n = the
 * header byte's low 7 bits (the COUNT of length bytes); *cur already points
 * at the length bytes.  Core, in order: skip leading ZERO length bytes;
 * reject at >= 4 significant length bytes; accumulate the rest big-endian.
 * Returns 0 on malformed.  Always advances *cur past the length bytes. */
static unsigned long long der_long_len(const unsigned char** cur,
                                       const unsigned char* end,
                                       unsigned long long n){
    const unsigned char* p = *cur;
    if ((unsigned long long)(end - p) < n) return 0;   /* lenbyte > remaining */
    while (n && p[0] == 0){ p++; n--; }                /* skip zero length bytes */
    if (n >= 4) return 0;                              /* Core: >= 4 -> reject */
    unsigned long long v = 0;
    for (unsigned long long i = 0; i < n; i++) v = (v << 8) | p[i];
    *cur = p + n;
    return v;
}

int der_parse_sig(const unsigned char* sig, unsigned long long slen,
                  u64 r[4], u64 s[4], u32 *hashtype){
    if (slen < 8) return 0;
    if (sig[0] != 0x30) return 0;
    const unsigned char* end = sig + slen;
    /* ---- sequence length: long form SKIPPED without checking the value
     *      (Core does pos += lenbyte and never reads it) ---- */
    const unsigned char* p = sig + 1;
    unsigned char lb = *p++;
    if (lb & 0x80){
        unsigned long long nb = lb & 0x7f;
        if ((unsigned long long)(end - p) < nb) return 0;
        p += nb;
    }
    /* ---- r: 0x02 then short- or long-form length ---- */
    if (p >= end || *p != 0x02) return 0;
    p++;
    if (p >= end) return 0;
    unsigned long long rlen;
    lb = *p++;
    if (lb & 0x80){
        rlen = der_long_len(&p, end, lb & 0x7f);
        if (rlen == 0) return 0;
    } else {
        rlen = lb;
    }
    if (rlen == 0) return 0;
    const unsigned char* rbase = p;
    if ((unsigned long long)(end - p) < rlen) return 0;
    /* strip ANY number of redundant leading 0x00 bytes down to <= 32
     * significant bytes (2026-08-19 fix; height-124275 spends carry
     * double-leading-zero 34-byte r/s) */
    while (rlen > 32){
        if (*rbase != 0x00) return 0;
        rbase++; rlen--;
    }
    be_to_limbs(r, rbase, rlen);
    /* ---- s: marker at stripped_r_base + stripped_r_len (base+len is
     *      invariant across the strip loop, same as the x86 comment) ---- */
    const unsigned char* q = rbase + rlen;
    if (q >= end || *q != 0x02) return 0;
    q++;
    if (q >= end) return 0;
    unsigned long long slen2;
    lb = *q++;
    if (lb & 0x80){
        slen2 = der_long_len(&q, end, lb & 0x7f);
        if (slen2 == 0) return 0;
    } else {
        slen2 = lb;
    }
    if (slen2 == 0) return 0;
    const unsigned char* sbase = q;
    const unsigned char* send = sbase + slen2;      /* ORIGINAL end-of-s: the
                                                       hashtype lookup uses it */
    if (send > end) return 0;
    while (slen2 > 32){
        if (*sbase != 0x00) return 0;
        sbase++; slen2--;
    }
    be_to_limbs(s, sbase, slen2);
    /* ---- hashtype: optional 0x01 right after s; 0 if absent or != 1 ---- */
    u32 ht = 0;
    if (send < end && send[0] == 0x01) ht = 1;
    *hashtype = ht;
    return 1;
}

/* parse_varint used by verify_p2pkh's walk: 0 on over-run; the cursor always
 * advances past what was consumed (prefix consumed even on the width fail,
 * exactly like the asm). */
static unsigned long long rd_cs(const unsigned char** cur,
                                const unsigned char* end){
    const unsigned char* p = *cur;
    if (p >= end) return 0;
    unsigned b = *p++;
    if (b < 0xfd){ *cur = p; return b; }
    unsigned long long w = (b == 0xfe) ? 4 : (b == 0xff) ? 8 : 2;
    if ((unsigned long long)(end - p) < w){ *cur = p; return 0; }
    unsigned long long v = 0;
    for (unsigned long long i = 0; i < w; i++) v |= (unsigned long long)p[i] << (8*i);
    *cur = p + w;
    return v;
}

int verify_p2pkh(const unsigned char* tx, unsigned long long txlen,
                 unsigned long long input_index,
                 const unsigned char* prevout_script, unsigned long long prevout_len,
                 unsigned char* work, unsigned long long cap){
    unsigned char out32[32];
    u64 r[4], s[4], qx[4], qy[4], z[4];
    u32 htype = 0;

    if (!sighash_all(out32, tx, txlen, input_index,
                     prevout_script, prevout_len, work, cap)) return 0;

    /* walk raw tx to input_index; every advance bounded by tx end */
    const unsigned char* end = tx + txlen;
    const unsigned char* p = tx + 4;
    unsigned long long n_in = rd_cs(&p, end);
    if (n_in == 0) return 0;
    if (input_index >= n_in) return 0;
    for (unsigned long long i = 0; i < input_index; i++){
        if (end - p < 36) return 0;
        p += 36;
        unsigned long long sl = rd_cs(&p, end);
        if ((unsigned long long)(end - p) < sl) return 0;
        p += sl;
        if (end - p < 4) return 0;
        p += 4;
    }
    /* target input */
    if (end - p < 36) return 0;
    p += 36;
    unsigned long long ssl = rd_cs(&p, end);
    if ((unsigned long long)(end - p) < ssl) return 0;
    const unsigned char* ss = p;
    const unsigned char* ssend = p + ssl;

    /* push0 (sig) and push1 (pubkey): direct pushes only (1..75) */
    if (p >= ssend) return 0;
    unsigned l0 = *p;
    if (l0 == 0 || l0 > 75) return 0;
    if ((unsigned long long)(ssend - p) < l0 + 1ull) return 0;
    const unsigned char* sig = p + 1;
    unsigned long long siglen = l0;
    p += 1 + l0;
    if (p >= ssend) return 0;
    unsigned l1 = *p;
    if (l1 == 0 || l1 > 75) return 0;
    if ((unsigned long long)(ssend - p) < l1 + 1ull) return 0;
    const unsigned char* pub = p + 1;
    unsigned long long publen = l1;

    /* IR-2: hashtype popped first -- parser sees siglen-1, the caller reads
     * the last byte itself and requires SIGHASH_ALL (as Core does) */
    if (siglen == 0) return 0;
    if (!der_parse_sig(sig, siglen - 1, r, s, &htype)) return 0;
    htype = sig[siglen - 1];
    if (htype != 1) return 0;

    be_to_limbs(z, out32, 32);
    if (!pubkey_parse(pub, publen, qx, qy)) return 0;
    if (!ecdsa_verify(z, r, s, qx, qy)) return 0;
    return 1;
}
