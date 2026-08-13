#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void sha256d(unsigned char out[32], const void *msg, long len);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void diff_target(unsigned char target[32], unsigned int bits);
extern int  pow_check(const unsigned char hdr[80]);
extern void merkle_root(unsigned char out[32], unsigned char hashes[], unsigned long n);
static int failures = 0;
static void rev32(unsigned char* o, const unsigned char* x){
    for (int i=0;i<32;i++) o[i]=x[31-i];
}
static void ckh(const char* lbl, const unsigned char* got, const unsigned char* exp){
    if (!memcmp(got,exp,32)) printf("PASS %s\n", lbl);
    else { printf("FAIL %s\n  got %s\n  exp %s\n", lbl, (char*)got, (char*)exp); failures++; }
}
static void cki(const char* lbl, int got, int exp){
    if (got==exp) printf("PASS %s\n", lbl);
    else { printf("FAIL %s got=%d exp=%d\n", lbl, got, exp); failures++; }
}
static void prb(const char* n, const unsigned char* b, int len){
    printf("%s = ", n); for(int i=0;i<len;i++) printf("%02x", b[i]); printf("\n");
}
int main(void){
    /* genesis block header, 80 bytes */
    unsigned char hdr[80] = {
        0x01,0x00,0x00,0x00,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
        0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a,
        0x29,0xab,0x5f,0x49,
        0xff,0xff,0x00,0x1d,
        0x1d,0xac,0x2b,0x7c
    };
    unsigned char h[32], hc[32];
    block_hash(h, hdr);
    rev32(hc, h);
    unsigned char exp_block[32];
    /* 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f */
    unsigned char eb[32]={0x00,0x00,0x00,0x00,0x00,0x19,0xd6,0x68,0x9c,0x08,0x5a,0xe1,0x65,0x83,0x1e,0x93,0x4f,0xf7,0x63,0xae,0x46,0xa2,0xa6,0xc1,0x72,0xb3,0xf1,0xb6,0x0a,0x8c,0xe2,0x6f};
    memcpy(exp_block, eb, 32);
    ckh("genesis block hash (display)", hc, exp_block);

    /* sha256d of a short message should equal double hash */
    unsigned char d[32];
    sha256d(d, "abc", 3);
    /* double sha256 of 'abc' = 4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358 */
    unsigned char exp_d[32]={0x4f,0x8b,0x42,0xc2,0x2d,0xd3,0x72,0x9b,0x51,0x9b,0xa6,0xf6,0x8d,0x2d,0xa7,0xcc,0x5b,0x2d,0x60,0x6d,0x05,0xda,0xed,0x5a,0xd5,0x12,0x8c,0xc0,0x3e,0x6c,0x63,0x58};
    ckh("sha256d(\"abc\")", d, exp_d);

    /* diff_target(0x1d00ffff) -> 00 00 00 00 ff ff 00 00 ... */
    unsigned char tgt[32];
    diff_target(tgt, 0x1d00ffffu);
    unsigned char et[32]={0x00,0x00,0x00,0x00,0xff,0xff};
    for (int i=6;i<32;i++) et[i]=0;
    ckh("diff_target(1d00ffff)", tgt, et);

    /* pow_check: genesis valid (1), tampered nonce invalid (0) */
    cki("pow_check(genesis)", pow_check(hdr), 1);
    unsigned char bad[80];
    memcpy(bad, hdr, 80);
    bad[76]=0; bad[77]=0; bad[78]=0; bad[79]=0;
    cki("pow_check(tampered-nonce)", pow_check(bad), 0);

    /* --- merkle root --- */
    /* leaf0 = genesis coinbase txid digest (internal order) */
    unsigned char leaf0[32]={0x3b,0xa3,0xde,0xda,0x7b,0xb2,0x12,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a};
    unsigned char leaf1[32]; for(int i=0;i<32;i++) leaf1[i]=(unsigned char)i;
    unsigned char leaf2[32]; for(int i=0;i<32;i++) leaf2[i]=(unsigned char)(32+i);
    unsigned char leaf3[32]; for(int i=0;i<32;i++) leaf3[i]=(unsigned char)(64+i);
    unsigned char buf[4*32], root[32];
    for(int i=0;i<32;i++) buf[i]=leaf0[i];
    merkle_root(root, buf, 1);
    ckh("merkle(1)=coinbase-txid", root, leaf0);
    /* expected merkle digests (internal byte order) computed by own Python oracle */
    unsigned char e2[32]={0x5c,0xcd,0x15,0xde,0x17,0x5a,0x45,0xb0,0x84,0x92,0x61,0x61,0x15,0x5c,0x16,0xfa,0x95,0xe2,0x7e,0x25,0xe7,0xb4,0x39,0x21,0x79,0x4e,0xda,0x28,0x9c,0xa7,0xaf,0xc0};
    for(int i=0;i<32;i++) buf[i]=leaf0[i]; for(int i=0;i<32;i++) buf[32+i]=leaf1[i];
    merkle_root(root, buf, 2);
    ckh("merkle(2)", root, e2);
    unsigned char e3[32]={0x40,0xd1,0xd5,0x7c,0xa9,0xbf,0xcb,0xb0,0xb1,0xa6,0x5f,0xe0,0x8f,0x13,0xed,0xaf,0xe1,0x6e,0x22,0xad,0x72,0x77,0x02,0x63,0x74,0x25,0x21,0xfc,0x3d,0x83,0x92,0xc2};
    for(int i=0;i<32;i++) buf[i]=leaf0[i]; for(int i=0;i<32;i++) buf[32+i]=leaf1[i]; for(int i=0;i<32;i++) buf[64+i]=leaf2[i];
    merkle_root(root, buf, 3);
    ckh("merkle(3)", root, e3);
    unsigned char e4[32]={0xd6,0xe7,0x25,0x3f,0x36,0x7d,0x9a,0x2d,0x01,0x1b,0x8e,0x6f,0x21,0xc5,0x7c,0x02,0xf1,0x91,0xef,0x2b,0x40,0xd6,0x58,0xed,0x4e,0xbb,0x93,0xbd,0xe3,0x74,0xfc,0x38};
    for(int i=0;i<32;i++) buf[i]=leaf0[i]; for(int i=0;i<32;i++) buf[32+i]=leaf1[i]; for(int i=0;i<32;i++) buf[64+i]=leaf2[i]; for(int i=0;i<32;i++) buf[96+i]=leaf3[i];
    merkle_root(root, buf, 4);
    ckh("merkle(4)", root, e4);

    return failures?1:0;
}
