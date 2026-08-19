/* test_script_flags.c -- script_flags_for_block (Stage C) against vectors
 * re-derived independently from Core's chainparams.cpp. Covers the h-1/h
 * boundary of each buried deployment (DERSIG/CLTV/CSV/NULLDUMMY-via-segwit),
 * both extremes (nothing active / everything active), and both
 * script_flag_exceptions hashes (BIP16, Taproot) -- including confirming a
 * near-miss hash does NOT trigger the override, and that an exception block
 * past all four height thresholds still gets those bits ORed in on top of
 * the override (matching Core's GetBlockScriptFlags exactly, which applies
 * the height-gated bits unconditionally AFTER the exception check).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern uint64_t script_flags_for_block(uint64_t height, const uint8_t hash32[32]);

#include "flags_vec.h"

static int hex2b(const char* h, unsigned char* out){
    int i = 0;
    while (h[2*i] && h[2*i+1]) {
        unsigned v;
        sscanf(h + 2*i, "%2x", &v);
        out[i] = (unsigned char)v;
        i++;
    }
    return i;
}

int main(void){
    int fails = 0;
    for (unsigned k = 0; k < FV_COUNT; k++) {
        unsigned char display[32], raw[32];
        int n = hex2b(FV_HASH[k], display);
        if (n != 32) { printf("FAIL %s: bad hash hex length %d\n", FV_NAME[k], n); fails++; continue; }
        for (int i = 0; i < 32; i++) raw[i] = display[31 - i];  /* display -> raw, same
                                                                     transform as block_hash's
                                                                     own convention */
        uint64_t got = script_flags_for_block(FV_HEIGHT[k], raw);
        if (got != FV_EXPECT[k]) {
            printf("FAIL %-42s h=%llu got=0x%llx want=0x%llx\n", FV_NAME[k],
                   (unsigned long long)FV_HEIGHT[k], (unsigned long long)got,
                   (unsigned long long)FV_EXPECT[k]);
            fails++;
        } else {
            printf("ok   %-42s h=%llu flags=0x%llx\n", FV_NAME[k],
                   (unsigned long long)FV_HEIGHT[k], (unsigned long long)got);
        }
    }
    printf("\n%s (%u/%u, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED",
           FV_COUNT - fails, FV_COUNT, fails);
    return fails ? 1 : 0;
}
