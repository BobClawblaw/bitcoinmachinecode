/* test_bech32.c -- verify the asm bech32 (BIP173) / bech32m (BIP350) codec
 * against the authoritative BIP173 and BIP350 test vectors, plus real
 * mainnet segwit addresses. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

extern void bech32_init(void);
extern void bech32_create_checksum(unsigned char out6[6], const char* hrp,
                                   long long hrplen, const unsigned char* data5,
                                   long long datalen, long long spec);
extern long long bech32_verify_checksum(const char* hrp, long long hrplen,
                                        const unsigned char* data5,
                                        long long datalen, long long spec);
extern long long bech32_convert_bits(unsigned char* out, const unsigned char* in,
                                     long long inlen, long long frombits,
                                     long long tobits, long long pad);
extern long long bech32_encode(char* out, const char* hrp, long long hrplen,
                               const unsigned char* data5, long long datalen,
                               long long spec);
extern long long bech32_decode(unsigned char* out5, char* out_hrp,
                               long long hrp_cap, const char* in);

static int failures = 0;
static unsigned char d5buf[256];
static char hrpbuf[96];

/* lowercase a local copy of hrp */
static void lower(char* dst, const char* src) {
    int i = 0;
    while (src[i]) { dst[i] = (char)tolower((unsigned char)src[i]); i++; }
    dst[i] = 0;
}

/* decode a vector, then verify its checksum for the given spec. Returns 1 if
 * the string is valid for that spec (decode ok + verify 1), else 0. */
static int valid_for_spec(const char* s, long long spec) {
    long long n = bech32_decode(d5buf, hrpbuf, 95, s);
    if (n < 0) return 0;
    char lo[96];
    lower(lo, hrpbuf);
    long long hrplen = (long long)strlen(lo);
    return bech32_verify_checksum(lo, hrplen, d5buf, n, spec) == 1;
}

static void ck_valid(const char* name, const char* s, long long spec, int expect_valid) {
    int got = valid_for_spec(s, spec);
    int ok = (got == expect_valid);
    if (!ok) { printf("%s FAIL (got %d)\n", name, got); failures++; }
    else     { printf("%s PASS\n", name); }
}

static void ck_encrel(const char* name, const char* hrp, long long hrplen,
                      const unsigned char* data5, long long datalen, long long spec,
                      const char* exp) {
    static char buf[256];
    long long len = bech32_encode(buf, hrp, hrplen, data5, datalen, spec);
    if (strcmp(buf, exp) != 0 || len != (long long)strlen(exp)) {
        printf("%s FAIL\n  got %s\n  exp %s\n", name, buf, exp);
        failures++;
    } else {
        printf("%s PASS\n", name);
    }
}

int main(void) {
    bech32_init();

    /* === BIP173 valid bech32 vectors (must decode + verify as spec 0) === */
    {
        static const char* v[] = {
            "A12UEL5L",
            "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl"
        };
        int i;
        for (i = 0; i < 7; i++) {
            char nm[48]; snprintf(nm, sizeof nm, "b173 valid[%d]", i);
            ck_valid(nm, v[i], 0, 1);
        }
        /* the same strings must NOT verify as bech32m */
        for (i = 0; i < 7; i++) {
            char nm[48]; snprintf(nm, sizeof nm, "b173 not bech32m[%d]", i);
            ck_valid(nm, v[i], 1, 0);
        }
    }

    /* === BIP350 valid bech32m vectors (verify as spec 1) === */
    {
        static const char* v[] = {
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa"
        };
        int i;
        for (i = 0; i < 7; i++) {
            char nm[48]; snprintf(nm, sizeof nm, "b350 valid[%d]", i);
            ck_valid(nm, v[i], 1, 1);
        }
        /* the same strings must NOT verify as bech32 */
        for (i = 0; i < 7; i++) {
            char nm[48]; snprintf(nm, sizeof nm, "b350 not bech32[%d]", i);
            ck_valid(nm, v[i], 0, 0);
        }
    }

    /* === BIP173 invalid vectors (must not verify as bech32) === */
    {
        static const char* v[] = {
            " 1nwldj5",                          /* HRP char out of range */
            "\x7f" "1axkwrx",                    /* HRP char out of range */
            "\x80" "1eym55h",                    /* HRP char out of range */
            "an84characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", /* length */
            "pzry9x0s0muk",                      /* no separator */
            "1pzry9x0s0muk",                     /* empty HRP */
            "x1b4n0q5v",                         /* invalid data char */
            "li1dgmt3",                          /* too-short checksum */
            "de1lg7wt" "\xff",                   /* invalid char in checksum */
            "A1G7SGD8",                          /* checksum w/ uppercase HRP */
            "10a06t8",                           /* empty HRP */
            "1qzzfhee"                           /* empty HRP */
        };
        int i;
        for (i = 0; i < 12; i++) {
            char nm[48]; snprintf(nm, sizeof nm, "b173 invalid[%d]", i);
            ck_valid(nm, v[i], 0, 0);
        }
    }

    /* === Real mainnet segwit address encodings === */
    {
        /* BIP173 P2WPKH: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
         *   witness program (version 0 + h160(G)):
         *     00 751e76e8199196d454941c45d1b3a323f1433bd6 */
        static const unsigned char data1[33] = {
            0, 14,20,15,7,13,26,0,25,18,6,11,13,8,21,4,20,3,17,2,29,3,12,29,3,4,15,24,20,6,14,30,22
        };
        ck_encrel("enc(bc1qw508...)", "bc", 2, data1, 33, 0,
                  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

        /* BIP173 P2WSH: bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
         *   version 0 + 1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262 */
        static const unsigned char data2[53] = {
            0, 3,1,17,17,8,15,0,20,24,20,11,6,16,1,5,29,3,4,16,3,6,21,22,26,2,13,22,9,16,21,19,24,25,21,6,18,15,8,13,24,24,24,25,9,12,1,4,16,6,9,17,0
        };
        ck_encrel("enc(bc1qrp33...)", "bc", 2, data2, 53, 0,
                  "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");

        /* BIP350 P2TR (bech32m): bc1p + 32 zero bytes (version 1) -> known string */
        static const unsigned char data3[53] = {
            1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        };
        ck_encrel("enc(bc1p-zero-zlen)", "bc", 2, data3, 53, 1,
                  "bc1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpqqenm");
    }

    /* === convert_bits 8->5 for a real witness program === */
    {
        /* h160(G) 20 bytes -> 32 five-bit values (pad) */
        static const unsigned char wp[20] = {
            0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,
            0x1c,0x45,0xd1,0xb3,0xa3,0x23,0xf1,0x43,0x3b,0xd6
        };
        static unsigned char out5[64];
        long long n = bech32_convert_bits(out5, wp, 20, 8, 5, 1);
        int ok = 0;
        if (n == 32) {
            static const unsigned char expc[32] = {
                14,20,15,7,13,26,0,25,18,6,11,13,8,21,4,20,
                3,17,2,29,3,12,29,3,4,15,24,20,6,14,30,22
            };
            ok = memcmp(out5, expc, 32) == 0;
        }
        printf(ok ? "PASS convbits(8->5 h160G)\n" : "FAIL convbits(8->5 h160G) (n=%lld)\n", n);
        if (!ok) failures++;
    }

    /* === audit 2026-09-03 SER-1/WAL-1: over-length inputs must be rejected
     * WITHOUT writing past the decode scratch. bech32_decode had no length cap
     * at all: a ~300-char address on any address-taking RPC overflowed the
     * module's .bss workspace with attacker-chosen bytes. The BIP173 cap is
     * 90 chars total; the 90-char vectors above are valid, so the boundary is
     * "reject at 91+". The d5buf the harness passes is only 256 bytes, so
     * before the fix these inputs corrupted .bss past WS -- a PASS here means
     * the decode failed cleanly, exactly as Core's bech32::Decode rejects. */
    {
        char long91[96], long300[384], longhrp[256];
        /* 91 chars, otherwise well-formed (hrp "a", valid charset) */
        memset(long91, 'q', 91); long91[1] = '1'; long91[91] = 0;
        /* 300-char junk of valid charset chars after a real hrp */
        strcpy(long300, "bc1");
        memset(long300+3, 'q', 297); long300[300] = 0;
        /* a 95-char hrp with 6 data chars: hrp_len alone exceeds hrp_cap-1
         * (95) and the total blows BIP173's 90 -- must be rejected. (A
         * well-formed 80+6 string is NOT invalid: the BIP173 cap is 90.) */
        memset(longhrp, 'a', 95); longhrp[95] = '1'; strcpy(longhrp+96, "qqqqqq"); longhrp[102] = 0;
        struct { const char* what; const char* s; } lv[] = {
            {"91-char string rejected",        long91},
            {"300-char string rejected",       long300},
            {"95-char hrp rejected (hrp_cap)", longhrp},
        };
        for (int i = 0; i < 3; i++) {
            char nm[64]; snprintf(nm, sizeof nm, "overlength %s", lv[i].what);
            long long n = bech32_decode(d5buf, hrpbuf, 95, lv[i].s);
            int ok = (n < 0);
            printf(ok ? "PASS %s\n" : "FAIL %s (n=%lld)\n", nm, n);
            if (!ok) failures++;
        }
    }

    printf(failures ? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures ? 1 : 0;
}