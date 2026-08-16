/*
 * cuda_autodetect_test.c -- verifies the auto-detect dispatcher routes and
 * produces correct output in EVERY mode. Because the probe result is cached on
 * first call, each distinct mode runs in a FRESH process (we re-exec ourselves
 * with a mode argument) so the per-mode probe state is clean.
 *
 *   mode default : GPU + big batch                 -> CUDA
 *   mode disable : BMC_CUDA=0 (forced)             -> CPU   (despite GPU)
 *   mode small   : batch 100 < threshold 512       -> CPU   (despite GPU)
 *   mode noglpu  : BMC_CUDA_LIB=/nonexistent/lib   -> CPU   (simulated no GPU)
 *
 * In every mode the batch output MUST equal the proven assembly sha256d oracle.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

extern int bmc_sha256d_batch(uint8_t *out, const uint8_t *msgs,
                             const uint64_t *idx, uint64_t count);
extern int bmc_cuda_was_used(void);
extern int bmc_cuda_detected(void);
extern void sha256d(void *out, const void *msg, unsigned long len);

static int build_batch(uint8_t **blob_out, uint64_t **idx_out, int count,
                       uint8_t *expect)
{
    uint8_t *blob = malloc((size_t)80 * count);
    uint64_t *idx = malloc((size_t)count * 2 * sizeof(uint64_t));
    if (!blob || !idx) return -1;
    srand((unsigned)count * 1000);
    for (int i = 0; i < count; i++) {
        for (int k = 0; k < 80; k++) blob[i*80+k] = (uint8_t)(rand() & 0xff);
        idx[2*i+0] = (uint64_t)i*80;
        idx[2*i+1] = 80;
        sha256d(expect + i*32, blob + i*80, 80);
    }
    *blob_out = blob; *idx_out = idx;
    return 0;
}

/* ---- worker: run a single batch in THIS process and report ---- */
static int worker(const char *mode)
{
    setenv("LD_LIBRARY_PATH", ".", 1);
    if (strcmp(mode, "disable") == 0) setenv("BMC_CUDA", "0", 1);
    else if (strcmp(mode, "noglpu") == 0) setenv("BMC_CUDA_LIB", "/nonexistent/libbmc_cuda.so", 1);
    else setenv("BMC_CUDA", "1", 1);   /* default/normal */

    int count = (strcmp(mode, "small") == 0) ? 100 : 2000;
    uint8_t *blob, *expect = malloc((size_t)count*32), *out = malloc((size_t)count*32);
    uint64_t *idx;
    if (build_batch(&blob, &idx, count, expect) < 0) return 2;

    int det = bmc_cuda_detected();
    int rc  = bmc_sha256d_batch(out, blob, idx, count);
    int used = bmc_cuda_was_used();

    int correct = 1;
    for (int i = 0; i < count; i++)
        if (memcmp(out + i*32, expect + i*32, 32) != 0) { correct = 0; break; }

    printf("MODE=%s detected=%d path=%s rc=%d digests=%s\n",
           mode, det, used ? "CUDA" : "CPU", rc, correct ? "OK" : "MISMATCH");
    return (!correct || rc != 0) ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2) return worker(argv[1]);   /* fresh-process mode */

    /* ---- driver: spawn a fresh process per mode and check routing ---- */
    const char *modes[] = {"default", "disable", "small", "noglpu"};
    const int expect_path[] = {1, 0, 0, 0};   /* CUDA=1, CPU=0 */
    int failures = 0;
    int n = (int)(sizeof(modes)/sizeof(modes[0]));

    printf("Auto-detect dispatcher test (fresh process per mode)\n");
    for (int i = 0; i < n; i++) {
        int pipefd[2];
        if (pipe(pipefd) != 0) { failures++; continue; }
        pid_t pid = fork();
        if (pid == 0) {
            dup2(pipefd[1], 1); close(pipefd[1]);
            char *args[] = {(char*)argv[0], (char*)modes[i], NULL};
            execv(argv[0], args);
            _exit(127);
        }
        close(pipefd[1]);
        char buf[512]; int r = (int)read(pipefd[0], buf, sizeof(buf)-1);
        buf[r<0?0:r] = 0;
        waitpid(pid, NULL, 0);
        close(pipefd[0]);

        printf("  sub: %s", buf);
        int used_cuda = strstr(buf, "path=CUDA") != NULL;
        int correct   = strstr(buf, "digests=OK")    != NULL;
        int routed_ok = (used_cuda == expect_path[i]);
        if (!routed_ok) { printf("      ROUTING MISMATCH (expected %s)\n", expect_path[i]?"CUDA":"CPU"); failures++; }
        if (!correct)   { printf("      DIGEST MISMATCH\n"); failures++; }
    }

    printf("\n%s (%d failures)\n", failures ? "AUTODETECT TEST FAILED" : "AUTODETECT ROUTING + DIGESTS OK", failures);
    return failures ? 1 : 0;
}
