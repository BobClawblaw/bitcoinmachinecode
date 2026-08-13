/* test_p2p.c -- 100% AI-generated harness for the assembly bitcoin_p2p.asm
 * P2P message payload builders. Expected bytes come from
 * validation/p2p_oracle.py (the authoritative reference).
 */
#include <stdio.h>
#include <string.h>

extern long p2p_getheaders(void* out, const void* locator, long count, const void* stop);
extern long p2p_getdata_block(void* out, const void* hash);
extern long p2p_ping(void* out, unsigned long long nonce);
extern long p2p_headers_count(const void* payload, long plen);

static int failures = 0;
static void cki(const char* lbl, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", lbl, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", lbl, got, exp); failures++; }
}
static void cbyte(const char* lbl, const unsigned char* got, const unsigned char* exp, int n){
    if (memcmp(got, exp, n)==0) printf("PASS %s\n", lbl);
    else { printf("FAIL %s\n  got ", lbl); for(int i=0;i<n;i++)printf("%02x",got[i]);
           printf("\n  exp "); for(int i=0;i<n;i++)printf("%02x",exp[i]); printf("\n"); failures++; }
}

int main(void){
    const unsigned char hash[32] = {0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a};
    const unsigned char zero[32] = {0};

    unsigned char out[200];

    /* ---- getheaders (count=1) : from oracle ---- */
    const unsigned char gh_exp[69] = {
        0x80,0x11,0x01,0x00,  0x01,
        0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
        0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    long gh = p2p_getheaders(out, hash, 1, zero);
    cki("getheaders len", gh, 69);
    cbyte("getheaders bytes", out, gh_exp, 69);

    /* ---- getdata (one block) : from oracle. Wire-correct inventory:
     * [count varint=1][type int32 LE=2][hash32] = 37 bytes, hash at +5.
     * The inventory `type` is a 4-byte little-endian int32 (NOT a 1-byte
     * varint). This was re-confirmed LIVE against a real node: the 37-byte form
     * is served; the 34-byte/short form is not. ---- */
    const unsigned char gd_exp[37] = {
        0x01, 0x02, 0x00, 0x00, 0x00,
        0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
        0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a
    };
    long gd = p2p_getdata_block(out, hash);
    cki("getdata len", gd, 37);
    cbyte("getdata bytes", out, gd_exp, 37);

    /* ---- ping ---- */
    memset(out, 0xAA, 8);
    long pg = p2p_ping(out, 0x1122334455667788ULL);
    cki("ping len", pg, 8);
    const unsigned char pg_exp[8] = {0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
    cbyte("ping bytes", out, pg_exp, 8);

    /* ---- headers_count ---- */
    /* empty headers payload: varint 0 */
    unsigned char hdr0[1] = {0x00};
    cki("headers_count 0", p2p_headers_count(hdr0, 1), 0);
    /* two headers: varint 2 + 2*81 bytes = 163 */
    unsigned char hdr2[163];
    memset(hdr2, 0, sizeof(hdr2)); hdr2[0]=2;
    cki("headers_count 2", p2p_headers_count(hdr2, 163), 2);
    /* truncated: varint 2 but only 100 bytes -> -1 */
    cki("headers_count truncated", p2p_headers_count(hdr2, 100), -1);
    /* empty payload -> -1 */
    cki("headers_count empty", p2p_headers_count(hdr2, 0), -1);
    /* 2-byte varint: 0xfd + u16=3 -> 3*81+3 = 246 bytes */
    unsigned char hdr3[246];
    memset(hdr3,0,sizeof(hdr3)); hdr3[0]=0xfd; hdr3[1]=3; hdr3[2]=0;
    cki("headers_count fd-varint 3", p2p_headers_count(hdr3, 246), 3);

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
