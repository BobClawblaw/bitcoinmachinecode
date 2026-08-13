#include <stdio.h>
typedef unsigned long long u64;
extern int ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
                        const u64 Qx[4], const u64 Qy[4]);
static int failures = 0;
static void ck(const char* lbl, int got, int exp){
    if (got == exp) printf("PASS %s\n", lbl);
    else { printf("FAIL %s got=%d exp=%d\n", lbl, got, exp); failures++; }
}
static void ckpt(const char* lbl, const u64 z[4], const u64 r[4], const u64 s[4],
                 const u64 Qx[4], const u64 Qy[4], int exp){
    int g = ecdsa_verify(z, r, s, Qx, Qy);
    ck(lbl, g, exp);
}
int main(void){
    u64 z[4] = {0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL};
    u64 r[4] = {0x2af4a71489e9f1dbULL,0xc0cb2fd43c3b6e75ULL,0x5fbff28aa15cced7ULL,0x592cb214ca60184fULL};
    u64 s[4] = {0xc4a2c025aa14e92aULL,0x010761c8cf1d4450ULL,0x812cf05ef8411d64ULL,0x23d627acd53ebcd7ULL};
    u64 Qx[4]= {0xfd723873aa170695ULL,0xe7bcc89470d63e1aULL,0x8947c271ac274529ULL,0x9651c463c001f731ULL};
    u64 Qy[4]= {0x21837fb0e654eaf7ULL,0x3b16ba7a5a9b154dULL,0x73d6d17fe8b63c99ULL,0x4e362e7fe8ff06daULL};

    ckpt("valid sig -> accept", z, r, s, Qx, Qy, 1);

    u64 r2[4] = {r[0]^1, r[1], r[2], r[3]};
    ckpt("tampered r -> reject", z, r2, s, Qx, Qy, 0);

    u64 z2[4] = {z[0]^1, z[1], z[2], z[3]};
    ckpt("tampered msg -> reject", z2, r, s, Qx, Qy, 0);

    u64 Qx2[4] = {Qx[0]^1, Qx[1], Qx[2], Qx[3]};
    ckpt("wrong pubkey -> reject", z, r, s, Qx2, Qy, 0);

    u64 zero[4] = {0,0,0,0};
    ckpt("r=0 -> reject", z, zero, s, Qx, Qy, 0);
    ckpt("s=0 -> reject", z, r, zero, Qx, Qy, 0);

    u64 n_1[4] = {0xbfd25e8cd0364140ULL,0xbaaedce6af48a03bULL,0xfffffffffffffffeULL,0xffffffffffffffffULL};
    ckpt("r=n-1 -> reject", z, n_1, s, Qx, Qy, 0);

    u64 zB[4]= {0x0000000000000123ULL,0,0,0};
    u64 rB[4]= {0xa3153339064fe63eULL,0xa65c4156d690fb12ULL,0xd91eea399c0858aeULL,0x3527053278c9f1ffULL};
    u64 sB[4]= {0xb58e7e068ce2863aULL,0x8a9e493d602e86c7ULL,0x9a4c396fc74cbeb6ULL,0x5f4061d3e796efdbULL};
    ckpt("2nd valid sig -> accept", zB, rB, sB, Qx, Qy, 1);

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
