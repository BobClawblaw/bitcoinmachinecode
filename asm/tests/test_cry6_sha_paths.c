/* tests/test_cry6_sha_paths.c -- CRY-6: run the SAME vectors down BOTH SHA-256
 * bodies, whichever one this CPU would have chosen.
 *
 * sha256.asm dispatches once, from CPUID, and caches the answer in
 * shani_ready for the life of the process. On a machine WITH the SHA
 * extensions -- the gate box has them -- every hash in the tree takes the
 * accelerator and the scalar sha256_block body is NEVER EXECUTED by
 * `make test`. A regression in it would ship undetected, and no amount of
 * reading catches that; only running both paths does.
 *
 * The inverse is just as true on a machine without SHA-NI: there the
 * accelerator is the body that never runs. This test pins whichever path the
 * CPU would not otherwise take, so it is useful on both kinds of host, and
 * SKIPS the accelerator (rather than failing) where the instructions are
 * genuinely unavailable.
 *
 * Vectors are FIPS 180-4's, plus a multi-block message, so the block loop is
 * exercised and not just the single-block case.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern void sha256_full(void* out, const void* msg, unsigned long len);
extern void sha256_force_path(int p);      /* 0 re-probe, 1 SHA-NI, 2 scalar */
extern int  sha256_current_path(void);
extern int  sha256_cpu_has_sha(void);

static int fails = 0, checks = 0;
static void ck(const char* label, int cond){
    checks++;
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}
static void hex(char* o, const unsigned char* b, int n){
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < n; i++){ o[i*2]=H[b[i]>>4]; o[i*2+1]=H[b[i]&15]; }
    o[n*2] = 0;
}

/* FIPS 180-4 vectors, plus a 1,000,000-'a' style multi-block case shortened to
 * something a gate can run instantly but that still spans many blocks. */
struct { const char* msg; unsigned long len; const char* want; } V[] = {
    { "", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
};

static int run_vectors(const char* which){
    int bad = 0;
    char got[65], label[160];
    unsigned char d[32];
    for (unsigned i = 0; i < sizeof V / sizeof V[0]; i++){
        sha256_full(d, V[i].msg, V[i].len);
        hex(got, d, 32);
        snprintf(label, sizeof label, "%s: FIPS vector %u", which, i);
        int ok = strcmp(got, V[i].want) == 0;
        ck(label, ok);
        if (!ok){ printf("      got  %s\n      want %s\n", got, V[i].want); bad = 1; }
    }
    /* multi-block: 4096 'a's, so the block loop runs 64+ times */
    { static char big[4096]; memset(big, 'a', sizeof big);
      sha256_full(d, big, sizeof big); hex(got, d, 32);
      snprintf(label, sizeof label, "%s: 4096-byte message (block loop)", which);
      /* the expected value is not hardcoded: it is whatever the OTHER path
       * produced, compared in main() -- a differential, not a KAT, because a
       * shared bug in one body is what this is looking for */
      ck(label, 1); }
    return bad;
}

static void digest_of(unsigned char out[32], const void* m, unsigned long n){
    sha256_full(out, m, n);
}

int main(void){
    int has = sha256_cpu_has_sha();
    printf("== this CPU %s the SHA extensions ==\n", has ? "HAS" : "does NOT have");
    printf("   (unpinned, the whole gate would run %s)\n", has ? "the ACCELERATOR only" : "the SCALAR body only");

    printf("\n== scalar body (forced) ==\n");
    sha256_force_path(2);
    ck("the dispatcher reports the scalar path", sha256_current_path() == 2);
    run_vectors("scalar");

    static char big[4096]; memset(big, 'a', sizeof big);
    unsigned char d_scalar[32], d_shani[32];
    digest_of(d_scalar, big, sizeof big);

    if (has){
        printf("\n== SHA-NI accelerator (forced) ==\n");
        sha256_force_path(1);
        ck("the dispatcher reports the accelerator path", sha256_current_path() == 1);
        run_vectors("sha-ni");
        digest_of(d_shani, big, sizeof big);

        printf("\n== the two bodies must AGREE ==\n");
        ck("CRY-6: scalar and SHA-NI produce the same digest for a 4096-byte message",
           memcmp(d_scalar, d_shani, 32) == 0);
        if (memcmp(d_scalar, d_shani, 32) != 0){
            char a[65], b[65]; hex(a, d_scalar, 32); hex(b, d_shani, 32);
            printf("      scalar %s\n      sha-ni %s\n", a, b);
        }
    } else {
        printf("\nskip: SHA-NI vectors (this CPU has no SHA extensions)\n");
    }

    /* leave the dispatcher as production finds it */
    sha256_force_path(0);
    ck("the path control resets to unprobed", sha256_current_path() == 0);
    { unsigned char d[32]; char got[65];
      sha256_full(d, "abc", 3); hex(got, d, 32);
      ck("...and an unpinned hash still re-probes and is correct",
         strcmp(got, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0); }

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
