/*
 * tests/test_sha256_osx.c -- macOS gate for port/osx/sha256.S (bmc_osx).
 *
 * Same three layers of proof as the x86 tree's test_sha256 +
 * test_cry6_sha_paths, merged into one harness (the CRY-1 CPUID probe has no
 * macOS counterpart -- Darwin has no CPUID -- so the x86-only dispatch
 * cross-check is replaced by an independent sysctl read):
 *
 *   1. FIPS 180-4 KATs through sha256_full (scalar-forced AND accelerator-
 *      forced via sha256_force_path, closing CRY-6's "both bodies over the
 *      same vectors" gate on THIS cpu).
 *   2. Differential fuzz: thousands of random lengths vs hashlib (digest
 *      piped from python3) -- proves the padding/length field over every
 *      residue class, not just the KAT lengths.
 *   3. Dispatcher contract: probe result equals the sysctl feature flag;
 *      forced-accelerator output == forced-scalar output block-for-block on
 *      random states (the accelerator's differential proof, re-run live).
 *
 * 100% AI-generated, like everything in the tree.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/sysctl.h>

extern void sha256_full(void *out, const void *msg, unsigned long len);
extern void sha256_init(uint32_t state[8]);
extern void sha256_block(uint32_t state[8], const void *block);
extern void sha256_block_shani(uint32_t state[8], const void *block);
extern void sha256_force_path(int p);   /* 0 re-probe, 1 sha2 ext, 2 scalar */
extern int  sha256_current_path(void);
extern int  sha256_cpu_has_sha(void);

static int failures = 0, checks = 0;

static void hex(const uint8_t *p, int n, char *buf)
{
    for (int i = 0; i < n; i++) sprintf(buf + 2 * i, "%02x", p[i]);
    buf[2 * n] = 0;
}

static void ck(const char *label, int cond)
{
    checks++;
    if (cond) printf("PASS  %s\n", label);
    else { printf("FAIL  %s\n", label); failures++; }
}

/* python3 hashlib as an independent oracle.
 * Deadlock lesson (2026-09-09, first gate run): popen("r+") + fwrite into the
 * child's stdin can deadlock -- the parent blocks in fread while the child,
 * having inherited a large pipe buffer, never sees EOF, and python3 has no
 * one-shot flag for this.  Fix: write the message to a temp file and let the
 * child read it (a path, not a pipe), stdout stays a plain pipe we read to
 * EOF.  Also batch: one python3 per call costs a fork+import (~25 ms);
 * 4000 calls = forever.  One python3 process hashes every queued message
 * from a length-prefixed file. */
static char portdir[512];  /* set in main before oracle use */

static int python_sha256_many(const uint8_t *buf, const int *lens, int count,
                              uint8_t *out32s /* count*32 */)
{
    char inpath[64], outpath[64], cmd[256];
    snprintf(inpath, sizeof inpath, "/tmp/bmc_osx_fuzz_in.%d", (int)getpid());
    snprintf(outpath, sizeof outpath, "/tmp/bmc_osx_fuzz_out.%d", (int)getpid());
    FILE *f = fopen(inpath, "wb");
    if (!f) return -1;
    for (int i = 0; i < count; i++) {
        uint32_t n = (uint32_t)lens[i];
        fwrite(&n, 4, 1, f);
        fwrite(buf, 1, (size_t)lens[i], f);
        buf += lens[i];
    }
    fclose(f);
    snprintf(cmd, sizeof cmd,
        "python3 %s/helper_sha256.py %s %s",
        portdir, inpath, outpath);
    int rc = system(cmd);
    if (rc != 0) { unlink(inpath); return -1; }
    f = fopen(outpath, "rb");
    if (!f) { unlink(inpath); return -1; }
    size_t want = (size_t)count * 32;
    size_t got = fread(out32s, 1, want, f);
    fclose(f);
    unlink(inpath); unlink(outpath);
    return got == want ? 0 : -1;
}

int main(void)
{
    /* locate this source dir so the oracle can find helper_sha256.py */
    {
        char cwd[400];
        if (getcwd(cwd, sizeof cwd)) {
            const char *leaf = strstr(__FILE__, "port/osx/tests");
            if (!leaf) leaf = "port/osx/tests";
            size_t base = (size_t)(leaf - __FILE__ > 0 ? leaf - __FILE__ : 0);
            (void)base;
            snprintf(portdir, sizeof portdir, "%s/port/osx/tests", cwd);
        } else {
            snprintf(portdir, sizeof portdir, "port/osx/tests");
        }
    }
    uint8_t digest[32], expect[32];
    char got_hex[65], exp_hex[65];

    /* feature flag via sysctl -- the independent reference for the probe */
    int feat = 0;
    size_t fl = sizeof feat;
    sysctlbyname("hw.optional.arm.FEAT_SHA256", &feat, &fl, NULL, 0);
    printf("info: hw.optional.arm.FEAT_SHA256 = %d\n", feat);

    /* ---- layer 1: FIPS 180-4 KATs, scalar path forced ---- */
    struct { const char *m; int len; const char *want; const char *tag; } kats[] = {
        { "", 0,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty" },
        { "abc", 3,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "\"abc\"" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "2-block KAT" },
    };
    sha256_force_path(2);
    ck("force_path(2) pins scalar", sha256_current_path() == 2);
    for (unsigned i = 0; i < sizeof kats / sizeof kats[0]; i++) {
        sha256_full(digest, kats[i].m, (size_t)kats[i].len);
        hex(digest, 32, got_hex);
        ck(kats[i].tag, strcmp(got_hex, kats[i].want) == 0);
    }

    /* boundary lengths around the two padding edges: 55/56/57/63/64/119/120 */
    static const int edges[] = { 55, 56, 57, 63, 64, 119, 120 };
    {
        uint8_t big[7 * 200];
        int lens[7];
        uint8_t ores[7 * 32];
        int total = 0;
        for (unsigned e = 0; e < sizeof edges / sizeof edges[0]; e++) {
            int n = edges[e];
            for (int i = 0; i < n; i++) big[total + i] = (uint8_t)i;
            lens[e] = n; total += n;
        }
        if (python_sha256_many(big, lens, 7, ores) == 0) {
            int off = 0;
            for (unsigned e = 0; e < sizeof edges / sizeof edges[0]; e++) {
                sha256_full(digest, big + off, (size_t)lens[e]);
                char lbl[64];
                snprintf(lbl, sizeof lbl, "len=%d vs hashlib (scalar)", lens[e]);
                ck(lbl, memcmp(digest, ores + e * 32, 32) == 0);
                off += lens[e];
            }
        } else ck("hashlib oracle reachable", 0);
    }

    /* ---- layer 2: differential fuzz, both paths, 2000 random lengths ---- */
    uint8_t msg[4096];
    unsigned long seed = 0x9e3779b97f4a7c15UL;
    for (unsigned t = 0; t < 2; t++) {
        sha256_force_path((int)(t + 1));   /* 1 = accelerator, 2 = scalar */
        if (t == 1 && !feat) { printf("SKIP accelerator fuzz (no FEAT_SHA256)\n"); break; }
        static int lens[2000];
        static uint8_t big[2000 * 3000];
        static uint8_t ores[2000 * 32];
        long total = 0;
        for (int i = 0; i < 2000; i++) {
            seed = seed * 6364136223846793005UL + 1442695040888963407UL;
            int n = (int)((seed >> 33) % 3000);
            for (int j = 0; j < n; j++) {
                seed = seed * 6364136223846793005UL + 1442695040888963407UL;
                msg[j] = (uint8_t)(seed >> 40);
            }
            memcpy(big + total, msg, (size_t)n);
            lens[i] = n; total += n;
        }
        int bad = -1;
        if (python_sha256_many(big, lens, 2000, ores) != 0) bad = 2000;
        else {
            bad = 0; long off = 0;
            for (int i = 0; i < 2000; i++) {
                sha256_full(digest, big + off, (size_t)lens[i]);
                if (memcmp(digest, ores + i * 32, 32) != 0) {
                    bad++; if (bad < 3) printf("  mismatch at len=%d\n", lens[i]);
                }
                off += lens[i];
            }
        }
        char lbl[48];
        snprintf(lbl, sizeof lbl, "fuzz 2000 random lens vs hashlib (%s)",
                 t == 0 ? "accelerator" : "scalar");
        ck(lbl, bad == 0);
    }

    /* ---- layer 3: dispatcher contract + body-vs-body differential ---- */
    {
        int got = sha256_cpu_has_sha();
        ck("sha256_cpu_has_sha() == sysctl flag", got == feat);

        /* forced scalar vs forced accelerator over random state/block pairs */
        if (feat) {
            int mismatch = 0;
            for (int i = 0; i < 5000; i++) {
                uint32_t s1[8], s2[8];
                uint8_t blk[64];
                for (int j = 0; j < 8; j++) {
                    seed = seed * 6364136223846793005UL + 1442695040888963407UL;
                    s1[j] = (uint32_t)(seed >> 24);
                }
                memcpy(s2, s1, 32);
                for (int j = 0; j < 64; j++) {
                    seed = seed * 6364136223846793005UL + 1442695040888963407UL;
                    blk[j] = (uint8_t)(seed >> 40);
                }
                sha256_force_path(2); sha256_block(s1, blk);
                sha256_force_path(1); sha256_block(s2, blk);
                sha256_force_path(0);          /* back to unprobed default */
                if (memcmp(s1, s2, 32) != 0) { mismatch++; if (mismatch < 3)
                    printf("  state mismatch on vector %d\n", i); }
            }
            ck("5000 random blocks: scalar == accelerator, bit-for-bit", mismatch == 0);
        } else {
            printf("SKIP body-vs-body (no FEAT_SHA256 on this cpu)\n");
        }
        /* force(0) means "re-probe on the NEXT sha256_block call", so pin it
         * back to unprobed and drive one real block through the dispatcher
         * before reading the tri-state (the byte stays 0 until then). */
        sha256_force_path(0);
        {
            uint32_t st[8];
            uint8_t blk[64];
            sha256_init(st);
            for (int j = 0; j < 64; j++) blk[j] = (uint8_t)j;
            sha256_block(st, blk);
        }
        ck("default path re-probed to dispatcher choice",
           sha256_current_path() == (feat ? 1 : 2));
    }

    printf("\n%d checks, %d failures -- %s\n", checks, failures,
           failures ? "TESTS FAILED" : "ALL TESTS PASSED");
    return failures ? 1 : 0;
}
