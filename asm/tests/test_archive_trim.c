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
    printf("== the incident's real shape: junk records with real-looking hashes above the chainwork-backed tip ==\n");
    { extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
      /* an archive of 5 linked blocks (heights 0..4) in blk00000.dat, then 3 junk
       * records: blocks whose chain starts elsewhere (prev = some other hash),
       * linked among themselves, appended at the file's end as heights 5..7;
       * chainwork covers 0..4 (the applied ones), headers.dat has correct 0..4
       * and junk 5..7, plus a WRONG record at 3 (the mirror lagged and was
       * filled from a peer that answered from elsewhere). */
      unsigned char hdr[8][80], hh[8][32]; unsigned char prev[32]; memset(prev, 0, 32);
      for (int i = 0; i < 5; i++){ memset(hdr[i], 0, 80); hdr[i][0] = 1; memcpy(hdr[i] + 4, prev, 32); hdr[i][36] = (unsigned char)(0x10 + i); block_hash(hh[i], hdr[i]); memcpy(prev, hh[i], 32); }
      memset(prev, 0xee, 32);
      for (int i = 5; i < 8; i++){ memset(hdr[i], 0, 80); hdr[i][0] = 1; memcpy(hdr[i] + 4, prev, 32); hdr[i][36] = (unsigned char)(0x50 + i); block_hash(hh[i], hdr[i]); memcpy(prev, hh[i], 32); }
      FILE* bf = fopen("blk00000.dat", "wb"); FILE* fi = fopen("index.dat", "wb"); FILE* fh = fopen("headers.dat", "wb"); FILE* fc = fopen("chainwork.dat", "wb");
      unsigned long long pos = 0;
      for (int i = 0; i < 8; i++){
          unsigned char fr[8] = {80,0,0,0, 0xf9,0xbe,0xb4,0xd9}; fwrite(fr, 1, 8, bf); fwrite(hdr[i], 1, 80, bf);
          unsigned char rec[48]; memset(rec, 0, 48); memcpy(rec, hh[i], 32); unsigned int fno = 0, size = 80; memcpy(rec + 32, &fno, 4); memcpy(rec + 36, &pos, 8); memcpy(rec + 44, &size, 4); fwrite(rec, 1, 48, fi);
          unsigned char hr[112]; memcpy(hr, hdr[i], 80); memcpy(hr + 80, hh[i], 32); if (i == 3) hr[80] ^= 1; fwrite(hr, 1, 112, fh);
          if (i < 5){ unsigned char cwr[16]; memset(cwr, 0, 16); cwr[0] = (unsigned char)i; fwrite(cwr, 1, 16, fc); }
          pos += 88;
      }
      fclose(bf); fclose(fi); fclose(fh); fclose(fc);
      long r = archive_trim_derived_tails();
      ck("two files trimmed (index beyond the chain, headers at the divergence)", r == 2);
      ck("index.dat cut to height 4: record 5 does not continue record 4", fsize("index.dat") == 5*48);
      ck("headers.dat cut at position 3, where it disagreed with the index", fsize("headers.dat") == 3*112);
      ck("chainwork.dat untouched (5 records)", fsize("chainwork.dat") == 5*16);
      ck("a second pass finds nothing", archive_trim_derived_tails() == 0);
      /* legit blocks appended above chainwork (crash before apply) are KEPT */
      fi = fopen("index.dat", "ab"); unsigned char rec[48]; memset(rec, 0, 48);
      { unsigned char h5[80]; memset(h5, 0, 80); h5[0] = 1; memcpy(h5 + 4, hh[4], 32); h5[36] = 0x77; unsigned char x5[32]; block_hash(x5, h5);
        bf = fopen("blk00000.dat", "r+b"); fseek(bf, 0, SEEK_END); unsigned long long p5 = (unsigned long long)ftell(bf); unsigned char fr[8] = {80,0,0,0, 0xf9,0xbe,0xb4,0xd9}; fwrite(fr, 1, 8, bf); fwrite(h5, 1, 80, bf); fclose(bf);
        memcpy(rec, x5, 32); unsigned int fno = 0, size = 80; memcpy(rec + 32, &fno, 4); memcpy(rec + 36, &p5, 8); memcpy(rec + 44, &size, 4); fwrite(rec, 1, 48, fi); }
      fclose(fi);
      ck("a linked block above chainwork (crash before apply) is kept", archive_trim_derived_tails() == 0 && fsize("index.dat") == 6*48); }
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
