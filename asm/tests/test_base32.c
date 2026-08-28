/* tests/test_base32.c -- RFC 4648 vectors + Core's example onion / i2p names. */
#include <stdio.h>
#include <string.h>
#include "../base32.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
int main(void){
    struct { const char* in; const char* out; } V[] = {
        {"", ""}, {"f", "my"}, {"fo", "mzxq"}, {"foo", "mzxw6"}, {"foob", "mzxw6yq"}, {"fooba", "mzxw6ytb"}, {"foobar", "mzxw6ytboi"} };
    for (unsigned i = 0; i < sizeof V / sizeof *V; i++){
        char o[32]; long n = base32_encode(o, (const unsigned char*)V[i].in, (long)strlen(V[i].in));
        char l[80]; snprintf(l, sizeof l, "RFC4648 encode(\"%s\") == \"%s\"", V[i].in, V[i].out);
        ck(l, n == (long)strlen(V[i].out) && !strcmp(o, V[i].out));
        unsigned char d[32]; long m = base32_decode(d, V[i].out, (long)strlen(V[i].out));
        snprintf(l, sizeof l, "RFC4648 decode(\"%s\") round-trips", V[i].out);
        ck(l, m == (long)strlen(V[i].in) && !memcmp(d, V[i].in, (size_t)m));
    }
    /* Core's example onion: 56 chars -> 35 bytes = pubkey(32) checksum(2) 0x03 */
    { const char* on = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd";
      static const unsigned char raw[35] = {0x79,0xbc,0xc6,0x25,0x18,0x4b,0x05,0x19,0x49,0x75,0xc2,0x8b,0x66,0xb6,0x6b,0x04,
        0x69,0xf7,0xf6,0x55,0x6f,0xb1,0xac,0x31,0x89,0xa7,0x9b,0x40,0xdd,0xa3,0x2f,0x1f,0x21,0x47,0x03};
      unsigned char d[40]; long m = base32_decode(d, on, 56);
      ck("Core's onion decodes to its 35 raw bytes", m == 35 && !memcmp(d, raw, 35));
      char o[64]; base32_encode(o, raw, 35);
      ck("and those bytes encode back to the same 56 chars", !strcmp(o, on)); }
    /* Core's example i2p: 52 chars -> 32 bytes */
    { const char* i2 = "c4gfnttsuwqomiygupdqqqyy5y5emnk5c73hrfvatri67prd7vyq";
      static const unsigned char raw[32] = {0x17,0x0c,0x56,0xce,0x72,0xa5,0xa0,0xe6,0x23,0x06,0xa3,0xc7,0x08,0x43,0x18,0xee,
        0x3a,0x46,0x35,0x5d,0x17,0xf6,0x78,0x96,0xa0,0x9c,0x51,0xef,0xbe,0x23,0xfd,0x71};
      unsigned char d[40]; long m = base32_decode(d, i2, 52);
      ck("Core's b32.i2p decodes to its 32 raw bytes", m == 32 && !memcmp(d, raw, 32));
      char o[64]; base32_encode(o, raw, 32);
      ck("and encodes back to the same 52 chars", !strcmp(o, i2)); }
    ck("a bad character is rejected", base32_decode((unsigned char[8]){0}, "mzx1", 4) == -1);
    ck("non-zero padding bits are rejected (\"my\" ok, \"mz\"/\"mx\" not, as Core)", base32_decode((unsigned char[8]){0}, "my", 2) == 1 && base32_decode((unsigned char[8]){0}, "mz", 2) == -1 && base32_decode((unsigned char[8]){0}, "mx", 2) == -1);
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
