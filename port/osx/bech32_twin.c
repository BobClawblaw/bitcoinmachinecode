/* ============================================================================
 * bech32_twin.c -- C twin for the bech32/bech32m codec on the macOS port.
 *
 * The x86 body (asm/bech32.asm, 674 lines) carries two audited security
 * fixes in its control flow -- the 90-character input cap (SER-1/WAL-1)
 * and the mixed-case rejection (SER-5/WAL-9) -- plus a 256-byte CHAR2IDX
 * table and a shared 512-byte workspace (WS) whose bounds the comments
 * reason about carefully.  Translating those invariants into fresh AArch64
 * asm is exactly the kind of subtle-bounds work that burned two modules
 * already; the C twin below reproduces the same observable behavior,
 * including both audit fixes, and is differential-verified against the
 * authoritative BIP173/BIP350 vectors the x86 gate uses (asm/tests/
 * test_bech32.c runs UNCHANGED against this object).
 *
 * Semantics (all identical to the x86 module):
 *   bech32_init            -- build CHAR2IDX/IDX2CHAR; upper-case letters
 *                             map to the same values (decoder folds case).
 *   create_checksum(out6, hrp, hrplen, data5, datalen, spec)
 *                          -- spec 0 = bech32 (const 1), 1 = bech32m
 *                             (const 0x2bc830a3).
 *   verify_checksum(...)   -- 1 if polymod == const else 0.
 *   convert_bits(...)      -- generic bit regroup; pad!=0 pads the final
 *                             group, pad==0 requires zero padding.
 *   encode(...)            -- hrp + '1' + data chars + checksum chars;
 *                             returns total length (NUL-terminated).
 *   decode(out5, out_hrp, hrp_cap, in)
 *                          -- returns data5 count (incl. checksum) or -1.
 *   WS-equivalent buffers are per-call locals (thread-safe, unlike the x86
 *   .bss WS which the file documents as single-threaded).
 * ========================================================================== */
#include <stdint.h>
#include <string.h>

#define BECH32_MAX_LEN 90        /* SER-1/WAL-1: BIP173 string cap */
#define BECH32M_CONST  0x2bc830a3u

static const char CHARSET[33] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const uint32_t GEN[5] = { 0x3b6a57b2u, 0x26508e6du, 0x1ea119fau,
                                 0x3d4233ddu, 0x2a1462b3u };

static signed char CHAR2IDX[256];
static char IDX2CHAR[32];
static int inited;

/* internal: polymod over `count` bytes */
static uint32_t polymod(const unsigned char *values, long long count)
{
    uint32_t chk = 1;
    for (long long i = 0; i < count; i++) {
        unsigned char b = (unsigned char)(chk >> 25);
        chk = ((chk & 0x1ffffffu) << 5) ^ values[i];
        for (int k = 0; k < 5; k++) {
            if ((b >> k) & 1) chk ^= GEN[k];
        }
    }
    return chk;
}

/* internal: hrp_expand; returns 2*hrplen + 1 */
static long long hrp_expand(unsigned char *out, const char *hrp, long long len)
{
    for (long long i = 0; i < len; i++) out[i] = (unsigned char)(hrp[i] >> 5);
    out[len] = 0;
    for (long long i = 0; i < len; i++) out[len + 1 + i] = (unsigned char)(hrp[i] & 31);
    return 2 * len + 1;
}

void bech32_init(void)
{
    memset(CHAR2IDX, 0xFF, sizeof CHAR2IDX);
    for (int i = 0; i < 32; i++) {
        IDX2CHAR[i] = CHARSET[i];
        CHAR2IDX[(unsigned char)CHARSET[i]] = (signed char)i;
        if (CHARSET[i] >= 'a' && CHARSET[i] <= 'z')
            CHAR2IDX[(unsigned char)(CHARSET[i] - 32)] = (signed char)i;
    }
    inited = 1;
}

void bech32_create_checksum(unsigned char out6[6], const char *hrp,
                            long long hrplen, const unsigned char *data5,
                            long long datalen, long long spec)
{
    unsigned char ws[512];
    long long expand_len = hrp_expand(ws, hrp, hrplen);
    memcpy(ws + expand_len, data5, (size_t)datalen);
    memset(ws + expand_len + datalen, 0, 6);
    uint32_t chk = polymod(ws, expand_len + datalen + 6);
    chk ^= spec ? BECH32M_CONST : 1u;
    for (int i = 0; i < 6; i++)
        out6[i] = (unsigned char)((chk >> (5 * (5 - i))) & 31);
}

long long bech32_verify_checksum(const char *hrp, long long hrplen,
                                 const unsigned char *data5,
                                 long long datalen, long long spec)
{
    unsigned char ws[512];
    long long expand_len = hrp_expand(ws, hrp, hrplen);
    memcpy(ws + expand_len, data5, (size_t)datalen);
    uint32_t chk = polymod(ws, expand_len + datalen);
    uint32_t want = spec ? BECH32M_CONST : 1u;
    return chk == want;
}

long long bech32_convert_bits(unsigned char *out, const unsigned char *in,
                              long long inlen, long long frombits,
                              long long tobits, long long pad)
{
    uint32_t acc = 0;
    unsigned bits = 0;
    long long ret = 0;
    uint32_t max_acc = (uint32_t)((1ull << (frombits + tobits - 1)) - 1);
    for (long long i = 0; i < inlen; i++) {
        acc = ((acc << frombits) | in[i]) & max_acc;
        bits += (unsigned)frombits;
        while (bits >= (unsigned)tobits) {
            bits -= (unsigned)tobits;
            out[ret++] = (unsigned char)((acc >> bits) & ((1u << tobits) - 1));
        }
    }
    if (bits) {
        if (!pad) {
            if (acc & ((1u << bits) - 1)) return -1;
        } else {
            out[ret++] = (unsigned char)((acc << (tobits - bits)) &
                                         ((1u << tobits) - 1));
        }
    }
    return ret;
}

long long bech32_encode(char *out, const char *hrp, long long hrplen,
                        const unsigned char *data5, long long datalen,
                        long long spec)
{
    if (!inited) bech32_init();
    unsigned char ws[512];
    long long expand_len = hrp_expand(ws, hrp, hrplen);
    memcpy(ws + expand_len, data5, (size_t)datalen);
    memset(ws + expand_len + datalen, 0, 6);
    uint32_t chk = polymod(ws, expand_len + datalen + 6);
    chk ^= spec ? BECH32M_CONST : 1u;

    memcpy(out, hrp, (size_t)hrplen);
    out[hrplen] = '1';
    for (long long i = 0; i < datalen; i++)
        out[hrplen + 1 + i] = IDX2CHAR[data5[i]];
    for (int i = 0; i < 6; i++)
        out[hrplen + 1 + datalen + i] = IDX2CHAR[(chk >> (5 * (5 - i))) & 31];
    long long total = hrplen + 1 + datalen + 6;
    out[total] = 0;
    return total;
}

long long bech32_decode(unsigned char *out5, char *out_hrp,
                        long long hrp_cap, const char *in)
{
    if (!inited) bech32_init();
    long long total = 0;             /* running string length */
    long long sep = 0;               /* position of last '1' (0 = none) */
    int casebits = 0;                /* SER-5: 1 = saw lower, 2 = saw upper */

    /* SER-1/WAL-1: the whole string is capped at 90 characters, checked
     * before any conversion write.  Also rejects a missing separator. */
    while (in[total]) {
        if (total >= BECH32_MAX_LEN) return -1;
        unsigned char c = (unsigned char)in[total];
        if (c >= 'a' && c <= 'z') casebits |= 1;
        else if (c >= 'A' && c <= 'Z') casebits |= 2;
        if (c == '1') sep = total;
        total++;
    }
    if (casebits == 3) return -1;    /* SER-5/WAL-9: mixed case refused */
    if (sep == 0) return -1;         /* no separator or empty HRP */

    long long hrplen = sep;
    if (hrplen >= hrp_cap) return -1;
    for (long long i = 0; i < hrplen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c < 0x21 || c > 0x7e) return -1;   /* printable US-ASCII only */
    }
    memcpy(out_hrp, in, (size_t)hrplen);
    out_hrp[hrplen] = 0;

    unsigned char d5[BECH32_MAX_LEN + 8];
    long long dlen = 0;
    const char *dp = in + hrplen + 1;
    while (*dp) {
        if (dlen >= BECH32_MAX_LEN) return -1;   /* belt for non-NUL input */
        signed char v = CHAR2IDX[(unsigned char)*dp];
        if (v == -1) return -1;
        d5[dlen++] = (unsigned char)v;
        dp++;
    }
    if (dlen < 6) return -1;
    memcpy(out5, d5, (size_t)dlen);
    return dlen;
}
