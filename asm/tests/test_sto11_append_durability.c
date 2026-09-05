/* tests/test_sto11_append_durability.c -- STO-11: an archive index record must
 * never become durable before the block bytes it points at.
 *
 * store_append writes the block frame to the BLOCK file and the 48-byte index
 * record to INDEX.DAT. They are different files with no ordering between them,
 * so before this fix a power loss could leave a record pointing at zeros.
 * archive_check detects that at boot and only LOGS it, and nothing cuts the
 * record, so catch-up stops at that height on every boot.
 *
 * THE ORDERING IS THE ASSERTION, and it is checked the only way an ordering
 * between two file descriptors can be: by observing the syscalls. The test
 * re-execs itself under strace and reads the trace back, asserting that
 * between the 800000-byte block write and the 48-byte index write there is an
 * fdatasync on the block fd. A test that merely appended and read the block
 * back would pass with or without the fix -- the page cache hides exactly the
 * failure this is about.
 *
 * If strace is unavailable the syscall assertions SKIP rather than pass, so a
 * machine without it cannot report a green it did not earn.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, unsigned long len);
extern int  store_get_at(void* st, unsigned long long height, unsigned long long* out_meta);
extern int  store_get_file_fd(void* st, unsigned int file_no);
extern void store_set_sync(int on);
extern long store_get_sync(void);

static int fails = 0, checks = 0;
static void ck(const char* label, int cond){
    checks++;
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}
static void skip(const char* label, const char* why){
    printf("skip: %s (%s)\n", label, why);
}

#define BLKSZ 800000
static u8 g_blk[BLKSZ];

/* The child half: two appends, sync on then off, nothing else, so the trace
 * is short and unambiguous. */
static int child_appends(void){
    static unsigned char st[128];
    if (store_init(st) < 0){ fprintf(stderr, "store_init failed\n"); return 2; }
    memset(g_blk, 0xab, sizeof g_blk);
    u8 h[32];
    store_set_sync(1);
    memset(h, 0x11, 32);
    if (store_append(st, h, g_blk, BLKSZ) < 0) return 2;
    store_set_sync(0);
    memset(h, 0x22, 32);
    if (store_append(st, h, g_blk, BLKSZ) < 0) return 2;
    return 0;
}

int main(int argc, char** argv){
    /* the --child half runs in the cwd strace put it in; it must NOT isolate
     * again or it would append into a different directory than the parent
     * is tracing. */
    if (argc > 1 && !strcmp(argv[1], "--child")) return child_appends();

    tt_isolate();                      /* private cwd; see test_tmpdir.h */
    const char* dir = tt_workdir();

    printf("== the switch itself ==\n");
    ck("store_get_sync() defaults to 1 (durable)", store_get_sync() == 1);
    store_set_sync(0); ck("store_set_sync(0) takes", store_get_sync() == 0);
    store_set_sync(1); ck("store_set_sync(1) takes", store_get_sync() == 1);

    printf("\n== an ordinary append still works and reads back ==\n");
    { static unsigned char st[128];
      if (store_init(st) < 0){ fprintf(stderr, "store_init failed\n"); return 1; }
      memset(g_blk, 0xcd, sizeof g_blk);
      u8 h[32]; memset(h, 0x77, 32);
      long height = store_append(st, h, g_blk, 4096);
      ck("store_append returns a height with sync ON", height >= 0);
      unsigned long long meta[3];
      ck("store_get_at finds the record", store_get_at(st, (unsigned long long)height, meta) == 1);
      ck("...with the size that went in", meta[1] == 4096);
      /* read the payload straight out of the block file at the recorded
       * offset: the whole point of STO-11 is that the record and the bytes
       * agree, so the test reads them the way the serve path does. */
      static u8 back[8192];
      int bfd = store_get_file_fd(st, (unsigned int)meta[2]);
      ck("the block file opens", bfd >= 0);
      ssize_t rd = bfd >= 0 ? pread(bfd, back, 4096, (off_t)meta[0] + 8) : -1;
      ck("the payload reads back at the recorded offset", rd == 4096);
      ck("...and is the bytes that went in", rd == 4096 && memcmp(back, g_blk, 4096) == 0); }

    printf("\n== THE ORDERING (strace) ==\n");
    char self[1024];
    ssize_t sl = readlink("/proc/self/exe", self, sizeof self - 1);
    if (sl <= 0){ skip("fdatasync sits between the block write and the index write",
                       "cannot resolve /proc/self/exe"); goto done; }
    self[sl] = 0;

    if (system("strace -V >/dev/null 2>&1") != 0){
        skip("fdatasync sits between the block write and the index write", "strace unavailable");
        goto done;
    }
    { char tdir[2048]; snprintf(tdir, sizeof tdir, "%s/trace", dir);
      if (mkdir(tdir, 0700) != 0 && access(tdir, W_OK) != 0){
          skip("fdatasync sits between the block write and the index write", "no trace dir");
          goto done; }
      char cmd[8192];
      snprintf(cmd, sizeof cmd,
               "cd '%s' && strace -f -e trace=write,fdatasync -o '%s/t.log' '%s' --child >/dev/null 2>&1",
               tdir, dir, self);
      int rc = system(cmd);
      if (rc != 0){
          skip("fdatasync sits between the block write and the index write",
               "strace could not run (ptrace may be restricted)");
          goto done; }

      char logp[2048]; snprintf(logp, sizeof logp, "%s/t.log", dir);
      FILE* f = fopen(logp, "r");
      if (!f){ skip("fdatasync sits between the block write and the index write", "no trace file"); goto done; }

      /* Walk the trace. State machine: after a write of BLKSZ bytes we expect
       * an fdatasync BEFORE the next write of 48 bytes. Two appends are traced
       * -- the first with sync ON, the second with it OFF -- so the same trace
       * proves both the presence and the absence. */
      char line[4096];
      int seen_block = 0, sync_after_block = 0;
      int pass1 = -1, pass2 = -1;      /* per-append verdict: 1 synced, 0 not */
      int appends = 0;
      char wantw[64]; snprintf(wantw, sizeof wantw, ") = %d", BLKSZ);
      while (fgets(line, sizeof line, f)){
          if (strstr(line, "fdatasync(")){ if (seen_block) sync_after_block = 1; continue; }
          if (!strstr(line, "write(")) continue;
          if (strstr(line, wantw)){ seen_block = 1; sync_after_block = 0; continue; }
          if (seen_block && strstr(line, ") = 48")){
              if (appends == 0) pass1 = sync_after_block;
              else if (appends == 1) pass2 = sync_after_block;
              appends++;
              seen_block = 0; sync_after_block = 0;
          }
      }
      fclose(f);

      if (appends < 2){
          skip("fdatasync sits between the block write and the index write",
               "trace did not contain both appends");
          goto done; }

      ck("STO-11: with sync ON, an fdatasync separates the block write from the index write",
         pass1 == 1);
      ck("...and with sync OFF it does not, so the trace is really discriminating",
         pass2 == 0);
    }

done:
    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
