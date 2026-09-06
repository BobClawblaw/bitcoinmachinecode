/* tests/test_scr10_sigops_bounds.c -- SCR-10: tx_legacy_sigops must not read
 * past the transaction it was given.
 *
 * The function walked the transaction with NO bounds checks at all: r13 (len)
 * was loaded once and never compared, and every varint read and every advance
 * indexed the cursor unconditionally. It was unreachable only because both
 * callers happen to parse the transaction fully first -- the "a distant
 * function already checked this" pattern this tree's own comments warn about.
 *
 * PROVING AN OUT-OF-BOUNDS READ NEEDS A GUARD PAGE. A test that merely passes
 * a truncated transaction proves nothing: the bytes after it are ordinary heap
 * and reading them is invisible. Each transaction here is instead placed so
 * that its last byte is the last byte of a mapping, with a PROT_NONE page
 * immediately after. A read one byte past the end is then a SIGSEGV, not a
 * silent success -- the same technique that turned WAL-14 from "PLAUSIBLE"
 * into a demonstrated fault.
 *
 * The harness runs each case in a FORKED CHILD so a fault is reported as a
 * failed case rather than killing the run, and sets an alarm so a hang is a
 * failure rather than a stall.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

typedef unsigned char u8;
extern long tx_legacy_sigops(const u8* tx, unsigned long len);

static int fails = 0, checks = 0;
static void ck(const char* label, int cond){
    checks++;
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}

/* Place `len` bytes so the LAST one abuts a PROT_NONE guard page. */
static u8* guarded(const u8* src, size_t len, void** map_out, size_t* map_len){
    long pg = sysconf(_SC_PAGESIZE);
    size_t data_pages = (len + (size_t)pg - 1) / (size_t)pg;
    size_t total = (data_pages + 1) * (size_t)pg;
    u8* m = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return NULL;
    if (mprotect(m + data_pages * (size_t)pg, (size_t)pg, PROT_NONE) != 0){
        munmap(m, total); return NULL;
    }
    u8* p = m + data_pages * (size_t)pg - len;    /* end-aligned */
    memcpy(p, src, len);
    *map_out = m; *map_len = total;
    return p;
}

/* Run tx_legacy_sigops over a guarded copy in a child. Returns:
 *   >= 0 / -1  the value the function returned
 *   -99        the child faulted (SIGSEGV/SIGBUS) -- an out-of-bounds read
 *   -98        the child hung past the alarm
 */
static long run_guarded(const u8* tx, size_t len){
    int fd[2];
    if (pipe(fd) != 0) return -97;
    pid_t pid = fork();
    if (pid < 0){ close(fd[0]); close(fd[1]); return -97; }
    if (pid == 0){
        close(fd[0]);
        alarm(10);                       /* a hang must be a failure, not a stall */
        void* m = NULL; size_t ml = 0;
        u8* p = guarded(tx, len, &m, &ml);
        if (!p) _exit(97);
        long r = tx_legacy_sigops(p, (unsigned long)len);
        ssize_t w = write(fd[1], &r, sizeof r); (void)w;
        _exit(0);
    }
    close(fd[1]);
    long r = 0;
    ssize_t got = read(fd[0], &r, sizeof r);
    close(fd[0]);
    int st = 0; waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)){
        int sig = WTERMSIG(st);
        if (sig == SIGALRM) return -98;
        return -99;
    }
    if (got != (ssize_t)sizeof r) return -97;
    return r;
}

/* A minimal well-formed legacy transaction: version, 1 input (null prevout,
 * empty scriptSig, seq), 1 output (value, empty spk), locktime. */
static size_t build_ok(u8* o){
    size_t n = 0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0;      /* version */
    o[n++]=1;                                  /* 1 input */
    memset(o+n, 0, 32); n += 32;               /* prevout hash */
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;      /* prevout index */
    o[n++]=0;                                  /* scriptSig len 0 */
    o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;  /* sequence */
    o[n++]=1;                                  /* 1 output */
    memset(o+n, 0, 8); n += 8;                 /* value */
    o[n++]=0;                                  /* scriptPubKey len 0 */
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;      /* locktime */
    return n;
}

int main(void){
    u8 full[256];
    size_t fl = build_ok(full);

    printf("== the harness itself ==\n");
    { long r = run_guarded(full, fl);
      ck("a well-formed transaction returns a count, not a fault", r >= 0);
      if (r < 0) printf("      got %ld (-99 fault, -98 hang, -97 harness)\n", r); }

    printf("\n== SCR-10: every truncation must be refused, not read past ==\n");
    /* Every prefix of a valid transaction is malformed. With the guard page
     * behind it, an unbounded walk faults; a bounded one returns -1. */
    { int faulted = 0, wrong = 0, refused = 0;
      for (size_t cut = 1; cut < fl; cut++){
          long r = run_guarded(full, cut);
          if (r == -99) { faulted++; if (faulted == 1) printf("      first fault at length %zu\n", cut); }
          else if (r == -98) { wrong++; printf("      HANG at length %zu\n", cut); }
          else if (r == -1) refused++;
          else if (r >= 0) {
              /* a prefix that happens to parse as a complete smaller tx is
               * possible in principle; none exists for this fixture, and a
               * count here would mean the walk stayed in bounds anyway */
              refused++;
          }
      }
      printf("      %zu truncations: %d refused/counted in bounds, %d FAULTED, %d hung\n",
             fl - 1, refused, faulted, wrong);
      ck("SCR-10: no truncation reads past the end of the transaction", faulted == 0);
      ck("SCR-10: no truncation hangs", wrong == 0); }

    printf("\n== a varint claiming more than the buffer holds ==\n");
    /* n_in = 0xff <8-byte huge>: the loop would walk forever / far past the
     * end. Bounded, it must refuse. */
    { u8 t[64]; size_t n = 0;
      t[n++]=1;t[n++]=0;t[n++]=0;t[n++]=0;
      t[n++]=0xff;                                   /* 8-byte varint follows */
      for (int i = 0; i < 8; i++) t[n++] = 0xff;     /* n_in = 2^64-1 */
      long r = run_guarded(t, n);
      ck("a 2^64-1 input count is refused, not walked", r == -1);
      if (r != -1) printf("      got %ld\n", r); }

    { /* a scriptSig length larger than the whole transaction */
      u8 t[128]; size_t n = 0;
      t[n++]=1;t[n++]=0;t[n++]=0;t[n++]=0;
      t[n++]=1;                                  /* 1 input */
      memset(t+n, 0, 32); n += 32;
      t[n++]=0;t[n++]=0;t[n++]=0;t[n++]=0;
      t[n++]=0xfe; t[n++]=0xff; t[n++]=0xff; t[n++]=0xff; t[n++]=0x7f;  /* slen ~2^31 */
      long r = run_guarded(t, n);
      ck("an oversized scriptSig length is refused, not followed", r == -1);
      if (r != -1) printf("      got %ld\n", r); }

    { /* a varint header at the very last byte: the length bytes are off the end */
      u8 t[64]; size_t n = 0;
      t[n++]=1;t[n++]=0;t[n++]=0;t[n++]=0;
      t[n++]=0xfd;                               /* claims 2 more bytes; none follow */
      long r = run_guarded(t, n);
      ck("a varint header with no length bytes after it is refused", r == -1);
      if (r != -1) printf("      got %ld\n", r); }

    printf("\n== THE OPPOSITE HALF: real transactions still counted ==\n");
    { long r = run_guarded(full, fl);
      ck("the well-formed transaction still returns a non-negative count", r >= 0); }
    { /* one with an actual CHECKSIG in the output script, so the count is not 0 */
      u8 t[256]; size_t n = build_ok(t);
      /* rebuild with a 1-byte scriptPubKey containing OP_CHECKSIG (0xac) */
      size_t m = 0; u8 t2[256];
      t2[m++]=1;t2[m++]=0;t2[m++]=0;t2[m++]=0;
      t2[m++]=1; memset(t2+m,0,32); m+=32; t2[m++]=0;t2[m++]=0;t2[m++]=0;t2[m++]=0;
      t2[m++]=0; t2[m++]=0xff;t2[m++]=0xff;t2[m++]=0xff;t2[m++]=0xff;
      t2[m++]=1; memset(t2+m,0,8); m+=8;
      t2[m++]=1; t2[m++]=0xac;                    /* scriptPubKey = OP_CHECKSIG */
      t2[m++]=0;t2[m++]=0;t2[m++]=0;t2[m++]=0;
      (void)n; (void)t;
      long r = run_guarded(t2, m);
      ck("a transaction with one OP_CHECKSIG counts exactly 1 sigop", r == 1);
      if (r != 1) printf("      got %ld\n", r); }

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
