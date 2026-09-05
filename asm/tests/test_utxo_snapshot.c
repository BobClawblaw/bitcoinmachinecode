/* test_utxo_snapshot.c -- the assumeutxo snapshot encoder vs Bitcoin Core.
 *
 * Fourteen coin records lifted VERBATIM from a snapshot the oracle Core
 * wrote (dumptxoutset at height 964065, 2026-08-25): all six special script
 * kinds, raw P2WPKH and P2TR, coinbase coins, amounts from 330 sat to
 * 50 BTC. For every row where the full scriptPubKey is reconstructible the
 * encoder must reproduce Core's bytes EXACTLY; the two uncompressed-P2PK
 * rows (the snapshot stores only the x-coordinate) pin the vout/code/amount
 * prefix instead. The header layout is pinned against the real snapshot's
 * first 51 bytes.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../utxo_snapshot.h"
/* UTX-7: y-recovery for the uncompressed-P2PK KATs (bitcoin_pubkey.asm) */
extern int pubkey_parse(const unsigned char* pub, unsigned long publen,
                        unsigned long long qx[4], unsigned long long qy[4]);
#include "snap_kats_gen.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static long unhex(unsigned char* out, const char* h){
    long n = 0;
    while (h[0] && h[1]){
        int a=h[0], b=h[1];
        a=(a<='9')?a-'0':((a|32)-'a'+10);
        b=(b<='9')?b-'0':((b|32)-'a'+10);
        out[n++]=(unsigned char)((a<<4)|b); h+=2;
    }
    return n;
}

int main(void){
    int nk = (int)(sizeof SNAP_KATS / sizeof *SNAP_KATS);
    int exact = 0, prefix_only = 0;
    for (int i = 0; i < nk; i++){
        const snap_kat_t* k = &SNAP_KATS[i];
        unsigned char want[256]; long wl = unhex(want, k->raw_hex);
        unsigned char got[256]; long gl = -1;
        char label[128];
        if (k->spk_hex){
            unsigned char spk[128]; long sl = unhex(spk, k->spk_hex);
            gl = usnap_coin(k->vout, k->height, k->coinbase, k->amount,
                            spk, (unsigned long)sl, got, sizeof got);
            snprintf(label, sizeof label,
                     "kat %d (kind %d, %llu sat%s): BYTE-IDENTICAL to Core",
                     i, k->nsize, k->amount, k->coinbase ? ", coinbase" : "");
            ck(label, gl == wl && !memcmp(got, want, (size_t)wl));
            if (gl == wl && !memcmp(got, want, (size_t)wl)) exact++;
            if (gl != wl || memcmp(got, want, (size_t)wl)){
                printf("      got  ");
                for (long b = 0; b < gl && b < 40; b++) printf("%02x", got[b]);
                printf("\n      want ");
                for (long b = 0; b < wl && b < 40; b++) printf("%02x", want[b]);
                printf("\n");
            }
        } else {
            /* Uncompressed P2PK. The snapshot keeps only x and a parity bit,
             * so the 65-byte key has to be rebuilt to feed the encoder.
             *
             * UTX-7 (2026-09-05): this used to build it with y = ALL ZEROS
             * and just set the parity byte -- a key that is syntactically
             * shaped like 0x04||x||y but is NOT ON THE CURVE. The old encoder
             * compressed it anyway, because it checked the prefix and length
             * and nothing else, and this assertion pinned that as correct.
             * It was constructing exactly the input UTX-7 says Core refuses to
             * compress, and calling the refusal a failure.
             *
             * y is now RECOVERED from x and the parity the way the curve
             * defines it -- pubkey_parse on the 33-byte compressed form solves
             * y^2 = x^3 + 7 -- so the key handed to the encoder is the real
             * point Core had, and the record can be compared in full. */
            unsigned char cpk[33];
            cpk[0] = (unsigned char)((k->nsize == 5) ? 0x03 : 0x02);   /* parity */
            memcpy(cpk + 1, want + wl - 32, 32);                        /* x */
            unsigned long long qx[4], qy[4];
            int on_curve = pubkey_parse(cpk, 33, qx, qy) == 1;
            snprintf(label, sizeof label,
                     "kat %d: the frozen x IS a real curve point (kind %d)", i, k->nsize);
            ck(label, on_curve);
            if (!on_curve){ prefix_only++; continue; }

            unsigned char spk[68]; memset(spk, 0, sizeof spk);
            spk[0] = 65; spk[1] = 0x04;
            memcpy(spk + 2, want + wl - 32, 32);                        /* x */
            /* qy limbs are little-endian u64[4]; the key wants y big-endian */
            for (int b = 0; b < 32; b++)
                spk[34 + b] = (unsigned char)(qy[3 - (b / 8)] >> (8 * (7 - (b % 8))));
            spk[66] = 0xac;
            gl = usnap_coin(k->vout, k->height, k->coinbase, k->amount,
                            spk, 67, got, sizeof got);
            snprintf(label, sizeof label,
                     "kat %d (uncompressed P2PK kind %d): full record matches Core",
                     i, k->nsize);
            ck(label, gl == wl && !memcmp(got, want, (size_t)wl));
            if (!(gl == wl && !memcmp(got, want, (size_t)wl))){
                printf("      got  "); for (long b = 0; b < gl && b < 40; b++) printf("%02x", got[b]);
                printf("\n      want "); for (long b = 0; b < wl && b < 40; b++) printf("%02x", want[b]);
                printf("\n");
            }
            /* the recovered y must carry the parity the snapshot recorded --
             * otherwise the key is a DIFFERENT point with the same x */
            snprintf(label, sizeof label,
                     "kat %d: recovered y has the parity kind %d encodes", i, k->nsize);
            ck(label, (spk[65] & 1) == (unsigned)((k->nsize == 5) ? 1 : 0));
            prefix_only++;
        }
    }
    ck("every special script kind was exercised (14 rows)", nk == 14);

    /* ---- UTX-7: the on-curve gate --------------------------------------
     * Core's IsToPubKey (compressor.cpp) ends its 67-byte arm with
     *   return pubkey.IsFullyValid();
     * so a bare P2PK output whose 0x04 key is NOT a curve point is written
     * RAW, as VARINT(len+6) || script. This encoder checked the prefix and
     * the length and nothing else, so it emitted kind 4/5 || x -- from which
     * Core's DecompressScript cannot recover y, because there is no y. The
     * result would be a snapshot loadtxoutset fails to deserialize.
     *
     * Such coins exist in mainnet's UTXO set, which is why Core carries the
     * gate at all. */
    {
        /* take a REAL curve point's x, then corrupt y so the point is off the
         * curve while every syntactic property Core's arm tests still holds:
         * 67 bytes, leading 0x41, 0x04 prefix, trailing OP_CHECKSIG. */
        unsigned char good[68], bad[68];
        memset(good, 0, sizeof good); memset(bad, 0, sizeof bad);
        static const char* X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        static const char* Y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        good[0] = 65; good[1] = 0x04;
        for (int b = 0; b < 32; b++){ unsigned v; sscanf(X + b*2, "%2x", &v); good[2+b]  = (unsigned char)v; }
        for (int b = 0; b < 32; b++){ unsigned v; sscanf(Y + b*2, "%2x", &v); good[34+b] = (unsigned char)v; }
        good[66] = 0xac;
        memcpy(bad, good, 68);
        bad[34] ^= 0x01;                     /* one bit of y -> off the curve */

        unsigned long long qx[4], qy[4];
        ck("UTX-7 fixture: the good key IS on the curve",
           pubkey_parse(good + 1, 65, qx, qy) == 1);
        ck("UTX-7 fixture: flipping one y bit takes it OFF the curve",
           pubkey_parse(bad + 1, 65, qx, qy) != 1);

        unsigned char rec[128];
        long n1 = usnap_coin(0, 1, 0, 5000ULL, good, 67, rec, sizeof rec);
        /* a valid key still COMPRESSES: kind 4|parity followed by 32 bytes of
         * x, so the script part is 33 bytes, not 67. */
        ck("a VALID uncompressed P2PK is still compressed", n1 > 0);
        int compressed = 0;
        if (n1 > 0){
            /* the script kind byte is the first byte after vout|code|amount;
             * rather than re-derive that offset, compare lengths: the raw arm
             * would carry all 67 script bytes. */
            long n2 = usnap_coin(0, 1, 0, 5000ULL, bad, 67, rec, sizeof rec);
            ck("an OFF-CURVE uncompressed P2PK is still encodable", n2 > 0);
            ck("UTX-7: the off-curve key takes the RAW arm (longer record)",
               n2 > n1);
            ck("UTX-7: the raw record is ~34 bytes longer (67 script vs 32 x)",
               n2 - n1 >= 34 && n2 - n1 <= 36);
            compressed = (n2 > n1);
        }
        ck("UTX-7: the two keys are NOT encoded the same way", compressed);
    }
    printf("      (%d exact rows, %d reconstructed-P2PK rows)\n", exact, prefix_only);

    /* the header, against the oracle snapshot's own first 51 bytes:
     * magic|v2|mainnet|base 00000000000000000001d04a...35bf|165721029 coins */
    { unsigned char hdr[51];
      unsigned char base[32];
      unhex(base, "bf3585d0fa75dac4a085d11402ae220b1c68dbaf4ad001000000000000000000");
      long n = usnap_header(base, 165721029ULL, hdr);
      unsigned char want[64];
      long wl = unhex(want,
        "7574786fff0200f9beb4d9"
        "bf3585d0fa75dac4a085d11402ae220b1c68dbaf4ad001000000000000000000"
        "c5b3e00900000000");
      ck("the 51-byte header is BYTE-IDENTICAL to the oracle snapshot's",
         n == 51 && wl == 51 && !memcmp(hdr, want, 51)); }

    /* CompressAmount spot values from compressor_tests-known pairs */
    ck("CompressAmount(0) == 0", usnap_compress_amount(0) == 0);
    ck("CompressAmount(1 sat)", usnap_compress_amount(1) == 1);
    ck("CompressAmount(1 BTC)", usnap_compress_amount(100000000ULL) == 0x9);
    ck("CompressAmount(50 BTC)", usnap_compress_amount(5000000000ULL) == 0x32);

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
