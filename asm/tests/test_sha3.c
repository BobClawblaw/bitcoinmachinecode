/* tests/test_sha3.c -- SHA3-256 against NIST's vectors and Core's onion checksum. */
#include <stdio.h>
#include <string.h>
extern void sha3_256(unsigned char out[32], const void* data, unsigned long len);
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static int hexeq(const unsigned char* b, const char* hx, int n){
    for (int i = 0; i < n; i++){ unsigned v; sscanf(hx + 2*i, "%2x", &v); if (b[i] != (unsigned char)v) return 0; } return 1; }
int main(void){
    unsigned char h[32];
    sha3_256(h, "", 0);
    ck("SHA3-256(\"\") == NIST a7ffc6f8...", hexeq(h, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", 32));
    sha3_256(h, "abc", 3);
    ck("SHA3-256(\"abc\") == NIST 3a985da7...", hexeq(h, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", 32));
    /* a 200-byte message crosses the 136-byte rate: NIST SHA3-256 of 200 x 0xa3 */
    { unsigned char m[200]; memset(m, 0xa3, 200); sha3_256(h, m, 200);
      ck("SHA3-256(200 x a3) == NIST 79f38adec5...", hexeq(h, "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787", 32)); }
    /* Core's example onion (p2p_addrv2_relay.py): pubkey || checksum || 3.
     * checksum = SHA3-256(".onion checksum" || pubkey || 0x03)[0..1] == 21 47 */
    { static const unsigned char pk[32] = {0x79,0xbc,0xc6,0x25,0x18,0x4b,0x05,0x19,0x49,0x75,0xc2,0x8b,0x66,0xb6,0x6b,0x04,
                                           0x69,0xf7,0xf6,0x55,0x6f,0xb1,0xac,0x31,0x89,0xa7,0x9b,0x40,0xdd,0xa3,0x2f,0x1f};
      unsigned char m[15+32+1]; memcpy(m, ".onion checksum", 15); memcpy(m+15, pk, 32); m[47] = 3;
      sha3_256(h, m, 48);
      ck("onion v3 checksum of Core's example address == 21 47", h[0] == 0x21 && h[1] == 0x47); }
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
