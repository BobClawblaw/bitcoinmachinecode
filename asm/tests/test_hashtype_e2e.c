/* test_hashtype_e2e.c -- proves Stage B's non-ALL legacy hashtypes work
 * end-to-end through the real asm interpreter (sv_verify_script), not just
 * that legacy_sighash matches a fixture. Each hashtype gets a genuine spend
 * (must ACCEPT), a tamper of a field it's supposed to IGNORE (must still
 * ACCEPT -- proves the field is really unbound), and a tamper of a field it
 * DOES bind (must REJECT -- proves this isn't just accepting everything).
 * See validation/gen_hashtype_vectors.py.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern int sv_verify_script(const unsigned char* ss, unsigned long ssl,
                            const unsigned char* spk, unsigned long spl,
                            unsigned long long flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);

#include "hashtype_vec.h"

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
    static unsigned char work[1<<20];
    int fails = 0;
    for (unsigned k = 0; k < HT_COUNT; k++) {
        static unsigned char tx[8192], ss[600], spk[128];
        int txlen = hex2b(HT_TX[k], tx);
        int ssl   = hex2b(HT_SS[k], ss);
        int spl   = hex2b(HT_SPK[k], spk);
        int r = sv_verify_script(ss, (unsigned long)ssl, spk, (unsigned long)spl,
                                 HT_FLAGS[k], HT_NIN[k], tx, (unsigned long)txlen,
                                 work, sizeof work);
        int accepted = (r == 0);
        int want = HT_EXPECT[k] ? 1 : 0;
        if (accepted != want) {
            printf("FAIL %-45s got=%s (err=%d) want=%s\n", HT_NAME[k],
                   accepted ? "ACCEPT" : "REJECT", r, want ? "ACCEPT" : "REJECT");
            fails++;
        } else {
            printf("ok   %-45s %s\n", HT_NAME[k], accepted ? "ACCEPT" : "REJECT");
        }
    }
    printf("\n%s (%u/%u, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED",
           HT_COUNT - fails, HT_COUNT, fails);
    return fails ? 1 : 0;
}
