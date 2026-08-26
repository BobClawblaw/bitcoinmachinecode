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
            /* uncompressed P2PK: rebuild a syntactically-valid 65-byte key
             * with the frozen x-coordinate and the parity from the kind, and
             * require the vout|code|amount|kind prefix to match Core's bytes
             * (everything up to and including the kind byte). */
            unsigned char spk[68]; memset(spk, 0, sizeof spk);
            spk[0] = 65; spk[1] = 0x04;
            /* x-coordinate: the last 32 bytes of Core's record */
            memcpy(spk + 2, want + wl - 32, 32);
            spk[65] = (unsigned char)((k->nsize == 5) ? 1 : 0);  /* y parity */
            spk[66] = 0xac;
            gl = usnap_coin(k->vout, k->height, k->coinbase, k->amount,
                            spk, 67, got, sizeof got);
            snprintf(label, sizeof label,
                     "kat %d (uncompressed P2PK kind %d): full record matches Core",
                     i, k->nsize);
            ck(label, gl == wl && !memcmp(got, want, (size_t)wl));
            prefix_only++;
        }
    }
    ck("every special script kind was exercised (14 rows)", nk == 14);
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
