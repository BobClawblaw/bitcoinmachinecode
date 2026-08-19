/* test_legacy_sighash.c -- legacy_sighash against Bitcoin Core's own 500
 * official SignatureHash test vectors (src/test/data/sighash.json), covering
 * every hashtype bit pattern (ALL/NONE/SINGLE x ANYONECANPAY, including the
 * SIGHASH_SINGLE-out-of-range uint256(1) quirk) and scripts riddled with
 * embedded OP_CODESEPARATOR bytes. See validation/gen_sighash_vectors.py.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

extern int legacy_sighash(unsigned char out32[32], const unsigned char* tx,
    unsigned long txlen, unsigned long nIn, const unsigned char* scriptCode,
    unsigned long scLen, int32_t hashtype, unsigned char* preimg,
    unsigned long cap);

#include "sighash_vec.h"

static int hex2b(const char* h, unsigned char* out){
    int i = 0;
    if (!h) return 0;
    while (h[2*i] && h[2*i+1]) {
        unsigned v;
        sscanf(h + 2*i, "%2x", &v);
        out[i] = (unsigned char)v;
        i++;
    }
    return i;
}

int main(void){
    static unsigned char preimg[8192];
    int fails = 0;
    for (unsigned k = 0; k < SH_COUNT; k++) {
        static unsigned char tx[8192], script[4096], expect[32], out[32];
        int txlen = hex2b(SH_TX[k], tx);
        int scLen = hex2b(SH_SCRIPT[k], script);
        int explen = hex2b(SH_EXPECT[k], expect);
        (void)explen;
        int r = legacy_sighash(out, tx, (unsigned long)txlen, (unsigned long)SH_NIN[k],
                               script, (unsigned long)scLen, (int32_t)SH_HTYPE[k],
                               preimg, sizeof preimg);
        if (!r || memcmp(out, expect, 32) != 0) {
            fails++;
            if (fails <= 10) {
                printf("FAIL vec %u: nIn=%u hashtype=%d r=%d\n", k, SH_NIN[k], SH_HTYPE[k], r);
                printf("  got: "); for (int i=0;i<32;i++) printf("%02x", out[i]); printf("\n");
                printf("  exp: "); for (int i=0;i<32;i++) printf("%02x", expect[i]); printf("\n");
            }
        }
    }
    printf("\n%u/%u vectors passed (%d failures)\n", SH_COUNT - fails, SH_COUNT, fails);
    printf("%s\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED");
    return fails ? 1 : 0;
}
