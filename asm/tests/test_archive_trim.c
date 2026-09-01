/* tests/test_archive_trim.c -- boot self-heal of the derived files
 * (incident 2026-09-01): trailing empty index.dat records past the tip are
 * trimmed, and headers.dat / chainwork.dat longer than the index are cut to
 * it; a consistent archive is left untouched. Plus a structural pin that the
 * catch-up's worker-wait loop honours the shutdown flag. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
extern long archive_trim_derived_tails(void);
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static long fsize(const char* p){ struct stat st; return stat(p, &st) == 0 ? (long)st.st_size : -1; }
static void put(const char* p, long n, int nonzero_upto){ FILE* f = fopen(p, "wb"); unsigned char z[112]; for (long i = 0; i < n; i++){ memset(z, i < nonzero_upto ? 0x5a : 0, sizeof z); fwrite(z, 1, (size_t)(!strcmp(p,"index.dat")?48:!strcmp(p,"headers.dat")?112:16), f); } fclose(f); }
int main(void){
    char cwd0[512]; if (!getcwd(cwd0, sizeof cwd0)) cwd0[0] = 0;
    char td[] = "/tmp/bmc_trim_XXXXXX"; if (!mkdtemp(td)){ perror("mkdtemp"); return 1; }
    if (chdir(td) != 0){ perror("chdir"); return 1; }
    printf("== a consistent archive is untouched ==\n");
    put("index.dat", 3, 3); put("headers.dat", 3, 3); put("chainwork.dat", 3, 3);
    ck("nothing to trim -> 0", archive_trim_derived_tails() == 0);
    ck("sizes unchanged", fsize("index.dat") == 144 && fsize("headers.dat") == 336 && fsize("chainwork.dat") == 48);
    printf("== the incident's shape: empty index tail, over-long headers and chainwork ==\n");
    put("index.dat", 7, 3); put("headers.dat", 9, 9); put("chainwork.dat", 10, 10);
    ck("three files trimmed", archive_trim_derived_tails() == 3);
    ck("index.dat back to the last stored record (3 records)", fsize("index.dat") == 144);
    ck("headers.dat cut to the index (3 records)", fsize("headers.dat") == 336);
    ck("chainwork.dat cut to the index (3 records)", fsize("chainwork.dat") == 48);
    ck("a second pass finds nothing", archive_trim_derived_tails() == 0);
    printf("== headers longer than the index with a clean index ==\n");
    put("index.dat", 5, 5); put("headers.dat", 8, 8); put("chainwork.dat", 5, 5);
    ck("only headers.dat trimmed", archive_trim_derived_tails() == 1 && fsize("headers.dat") == 5*112 && fsize("index.dat") == 5*48);
    printf("== an archive with no stored block at all is left alone ==\n");
    put("index.dat", 4, 0);
    ck("all-zero index is not judged", archive_trim_derived_tails() == 0 && fsize("index.dat") == 4*48);
    if (cwd0[0]) (void)!chdir(cwd0);
    printf("== the catch-up's worker-wait loop honours SIGTERM (structural) ==\n");
    { FILE* f = fopen("daemon/main.c", "r"); ck("daemon/main.c readable", f != NULL);
      if (f){ fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET); char* src = malloc((size_t)n + 1); size_t got = fread(src, 1, (size_t)n, f); src[got] = 0; fclose(f);
        const char* w = strstr(src, "while(alive>0){"); const char* sc = w ? strstr(w, "dlc_scan_progress(") : NULL; const char* sd = w ? strstr(w, "if(g_shutdown_requested)") : NULL;
        ck("the shutdown check sits inside the wait loop, before the progress report", w && sc && sd && sd < sc);
        free(src); } }
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
