/* tests/test_sha1.c -- SHA-1 (sha1.asm): the FIPS 180-4 / RFC 3174 vectors
 * through both bodies (the scalar one and, where the CPU has the SHA
 * extensions, sha1_block_shani), and the two bodies against each other on
 * random blocks and random-length messages. The scalar body is the one that
 * reproduced OP_SHA1 on mainnet (block 251,683); the SHA-NI body is held to
 * it byte for byte. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char u8; typedef unsigned u32;
extern void sha1_full(u8 out[20], const void* msg, long long len);
extern void sha1_block(u32 st[5], const u8 blk[64]);
extern void sha1_block_scalar(u32 st[5], const u8 blk[64]);
extern void sha1_block_shani(u32 st[5], const u8 blk[64]);
extern void sha1_force_path(int p);            /* 0 re-probe, 1 SHA-NI, 2 scalar */
extern int  sha1_cpu_has_sha(void);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void tohex(char* o, const u8* b, int n){ static const char* H = "0123456789abcdef"; for (int i = 0; i < n; i++){ o[2*i] = H[b[i] >> 4]; o[2*i+1] = H[b[i] & 15]; } o[2*n] = 0; }

static const struct { const char* msg; long long repeat; const char* want; } VEC[] = {
    { "",    1, "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    { "abc", 1, "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1, "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1, "a49b2446a02c645bf419f995b67091253a04a259" },
    { "a", 1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },
    { "0123456701234567012345670123456701234567012345670123456701234567", 10, "dea356a2cddd90c7a7ecedc5ebb563934f460452" },
};

static void run_vectors(const char* body){
    for (unsigned i = 0; i < sizeof VEC / sizeof VEC[0]; i++){
        long long l = (long long)strlen(VEC[i].msg), n = l * VEC[i].repeat;
        u8* m = malloc((size_t)n + 1);
        for (long long r = 0; r < VEC[i].repeat; r++) memcpy(m + r * l, VEC[i].msg, (size_t)l);
        u8 d[20]; char h[48]; sha1_full(d, m, n); tohex(h, d, 20); free(m);
        char lbl[120]; snprintf(lbl, sizeof lbl, "%s vector %u (%lld bytes)", body, i, n);
        ck(lbl, !strcmp(h, VEC[i].want));
    }
}

static unsigned long long rs = 0x5A1D0BEEF00DULL;
static unsigned long long rnd(void){ rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

int main(void){
    int shani = sha1_cpu_has_sha();
    printf("== FIPS vectors, scalar body ==\n");
    sha1_force_path(2); run_vectors("scalar");
    if (shani){
        printf("== FIPS vectors, SHA-NI body ==\n");
        sha1_force_path(1); run_vectors("sha-ni");
        printf("== the two bodies against each other ==\n");
        long bad = 0;
        for (int i = 0; i < 100000; i++){
            u32 a[5], b[5]; u8 blk[64];
            for (int k = 0; k < 5; k++) a[k] = b[k] = (u32)rnd();
            for (int k = 0; k < 64; k++) blk[k] = (u8)rnd();
            sha1_block_scalar(a, blk); sha1_block_shani(b, blk);
            if (memcmp(a, b, 20)) bad++;
        }
        ck("100,000 random blocks and states: identical", bad == 0);
        bad = 0;
        static u8 msg[5000];
        for (int i = 0; i < 2000; i++){
            long long n = (long long)(rnd() % 5000);
            for (long long k = 0; k < n; k++) msg[k] = (u8)rnd();
            u8 d1[20], d2[20];
            sha1_force_path(2); sha1_full(d1, msg, n);
            sha1_force_path(1); sha1_full(d2, msg, n);
            if (memcmp(d1, d2, 20)) bad++;
        }
        ck("2,000 random messages (0..4999 bytes) through sha1_full: identical", bad == 0);
    } else {
        ck("(no SHA extensions on this CPU: the SHA-NI body is not exercised here)", 1);
    }
    sha1_force_path(0);
    if (fails){ printf("\nFAILURES: %d\n", fails); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
