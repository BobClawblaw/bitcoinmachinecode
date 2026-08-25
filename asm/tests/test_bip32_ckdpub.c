/* test_bip32_ckdpub.c -- CKDpub kernel verified against Bitcoin Core's own
 * deriveaddresses output (BIP32 test-vector-1 master xpub, seed 000102..0f).
 * Ground truth captured from: bitcoin-cli deriveaddresses "<script>(xpub/..)#ck".
 * Derives child pubkeys with bip32_ckdpub_derive, builds the scriptPubKey, and
 * asserts the address equals Core's byte-for-byte. */
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;
extern int  bip32_ckdpub_derive(const char* xpub, const unsigned* path, int n, u8 out[33]);
extern int  bip32_xpub_parse(const char* xpub, u8 pub33[33], u8 cc32[32]);
extern void hash160(u8 out[20], const void* in, long long len);
extern int  wallet_script_to_address(char* out, long cap, const u8* script, long slen);

static const char* XPUB =
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

static int fails = 0, checks = 0;
static void ck_str(const char* what, const char* got, const char* want){
    checks++;
    if (!got || strcmp(got, want)){ printf("FAIL %s: got '%s' want '%s'\n", what, got?got:"(null)", want); fails++; }
    else printf("ok  : %s = %s\n", what, got);
}

/* address of a derived child pubkey, by output type. type: 0=pkh 1=wpkh 2=sh(wpkh) */
static void addr_of(char* out, long cap, unsigned c0, unsigned c1, int type){
    u8 pub[33]; unsigned path[2] = {c0, c1};
    out[0] = 0;
    if (!bip32_ckdpub_derive(XPUB, path, 2, pub)){ strcpy(out, "(derive-fail)"); return; }
    u8 h[20]; hash160(h, pub, 33);
    if (type == 0){ u8 s[25] = {0x76,0xa9,0x14}; memcpy(s+3,h,20); s[23]=0x88; s[24]=0xac; wallet_script_to_address(out, cap, s, 25); }
    else if (type == 1){ u8 s[22] = {0x00,0x14}; memcpy(s+2,h,20); wallet_script_to_address(out, cap, s, 22); }
    else { u8 rd[22] = {0x00,0x14}; memcpy(rd+2,h,20); u8 rh[20]; hash160(rh, rd, 22);
           u8 s[23] = {0xa9,0x14}; memcpy(s+2,rh,20); s[22]=0x87; wallet_script_to_address(out, cap, s, 23); }
}

int main(void){
    char a[128];
    /* parse must accept the vector-1 xpub */
    { u8 pub[33], cc[32]; ck_str("xpub parses", bip32_xpub_parse(XPUB, pub, cc) ? "ok" : "no", "ok"); }
    /* reject a corrupted xpub */
    { u8 pub[33], cc[32]; char bad[128]; strcpy(bad, XPUB); bad[10] ^= 1;
      checks++; if (bip32_xpub_parse(bad, pub, cc)){ printf("FAIL corrupt xpub accepted\n"); fails++; } else printf("ok  : corrupt xpub rejected\n"); }

    /* wpkh(xpub/0/i) [0..2] */
    addr_of(a,sizeof a,0,0,1); ck_str("wpkh /0/0", a, "bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz");
    addr_of(a,sizeof a,0,1,1); ck_str("wpkh /0/1", a, "bc1qrfxr69jqnhwufxgkqgcdep9prq4j4vuw2wyg0v");
    addr_of(a,sizeof a,0,2,1); ck_str("wpkh /0/2", a, "bc1qhvd6suvqzjcu9pxjhrwhtrlj85ny3n2mqql5w4");
    /* pkh(xpub/0/i) [0..2] */
    addr_of(a,sizeof a,0,0,0); ck_str("pkh /0/0", a, "12CL4K2eVqj7hQTix7dM7CVHCkpP17Pry3");
    addr_of(a,sizeof a,0,1,0); ck_str("pkh /0/1", a, "13Q3u97PKtyERBpXg31MLoJbQsECgJiMMw");
    addr_of(a,sizeof a,0,2,0); ck_str("pkh /0/2", a, "1J4LVanjHMu3JkXbVrahNuQCTGCRRgfWWx");
    /* sh(wpkh(xpub/0/i)) [0..2] */
    addr_of(a,sizeof a,0,0,2); ck_str("sh(wpkh) /0/0", a, "3AfyxhpBVVLmBR4ZYX2onGzRqjv5QZ7FqD");
    addr_of(a,sizeof a,0,1,2); ck_str("sh(wpkh) /0/1", a, "36Zf8sjtnkh7K7ujAeq2K5HeibEQva7gfR");
    addr_of(a,sizeof a,0,2,2); ck_str("sh(wpkh) /0/2", a, "3EZQk4F8GURH5sqVMLTFisD17yNeKa7Dfs");
    /* fixed non-ranged path wpkh(xpub/44/5) */
    addr_of(a,sizeof a,44,5,1); ck_str("wpkh /44/5 fixed", a, "bc1q0k2xl6ppmegpnxl7qvday08x0fyhv2k22vdea9");

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
