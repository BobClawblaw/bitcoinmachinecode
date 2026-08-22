/* test_tmpdir.h -- per-test private working directory.
 *
 * WHY THIS EXISTS
 * ---------------
 * The node's storage layer opens its files by BARE RELATIVE NAME: index.dat,
 * blk%05u.dat, prune.dat, utxo.dat, utxo.idx, utxo_manifest.dat,
 * utxo_run_%06u.dat, headers.dat, chainwork.dat, peers.dat, wallet.dat
 * (see bitcoin_store.asm:1798, bitcoin_utxo_store.asm:102, bitcoin_utxo_lsm.asm:237,
 * bitcoin_headers.asm:223, bitcoin_chainwork.asm:771, bitcoin_addrmgr.asm:343).
 * That is a deliberate design property -- the daemon is pointed at a datadir and
 * runs there -- but it means a test that links the storage layer and does NOT
 * move out of asm/ writes its archive into the SOURCE TREE, where it persists
 * and is shared with every other test.
 *
 * Three failure modes follow, all of which this header removes:
 *   1. concurrency  -- nothing else may touch asm/ while the suite runs;
 *   2. order        -- a test can read state an earlier test left behind
 *                      (a false PASS is as available as a false FAIL);
 *   3. carryover    -- `make test` in a used tree differs from a fresh clone.
 *
 * USAGE
 * -----
 *   #include "test_tmpdir.h"
 *   int main(int argc, char** argv){
 *       tt_isolate();                       // FIRST statement in main()
 *       ...
 *       FILE* f = fopen(tt_src("tests/fixtures/blk_600000.bin"), "rb");
 *       execv(tt_src("daemon/bitcoind"), av);
 *       spawn_child_with_datadir(tt_workdir());
 *   }
 *
 * tt_isolate() mkdtemp()s a private directory and chdir()s into it, so every
 * bare relative name the storage layer opens lands there. Paths that must still
 * resolve against the source tree (fixtures, the daemon binary, shim
 * executables) go through tt_src(), which rebases them onto the directory the
 * test was launched from. tt_workdir() hands the absolute path to a forked child
 * or a spawned daemon that takes its datadir as an argument.
 *
 * CLEANUP is registered on atexit() AND on the fatal signals, so the bounds
 * tests -- which provoke SIGSEGV/SIGABRT on purpose -- do not leave litter. The
 * signal path re-raises with the default disposition afterwards, so the exit
 * status a parent observes is unchanged.
 *
 * CLEANUP IS PID-GUARDED. A forked child inherits both the atexit list and the
 * handlers; without the guard a child that exit()s or crashes would delete the
 * PARENT's working directory out from under it. tt_cleanup() is a no-op in any
 * process that is not the one that created the directory.
 *
 * The removal walk uses getdents64/unlinkat directly rather than nftw() or
 * system("rm -rf") -- no allocation, no fork, safe to run from a SIGSEGV
 * handler, and structurally incapable of escaping the directory it was handed
 * (it recurses through an O_NOFOLLOW|O_DIRECTORY descriptor, never a path).
 *
 * ENVIRONMENT
 * -----------
 *   BMC_TEST_TMPDIR  root to create the private directory under.
 *                    Default: $TMPDIR, else /tmp. These tests write real block
 *                    data, so point this at a filesystem with room if /tmp is
 *                    a small tmpfs.
 *   BMC_TEST_KEEP    if set and non-empty, the directory is left in place and
 *                    its path printed, for post-mortem inspection.
 */
#ifndef BMC_TEST_TMPDIR_H
#define BMC_TEST_TMPDIR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

#ifndef O_DIRECTORY
#define O_DIRECTORY 0200000
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0400000
#endif
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif
#ifndef DT_DIR
#define DT_DIR 4
#endif
#ifndef DT_UNKNOWN
#define DT_UNKNOWN 0
#endif

/* TT_DIRMAX bounds the two directory strings; TT_PATHMAX bounds a directory
 * plus a relative path glued onto it. Keeping the first strictly smaller is what
 * makes the concatenations below provably non-truncating. */
#define TT_DIRMAX  1024
#define TT_PATHMAX 4096

struct tt_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

static char  tt_srcdir_buf[TT_DIRMAX];
static char  tt_workdir_buf[TT_DIRMAX];
static pid_t tt_owner_pid;
static int   tt_active;

/* Depth-first removal of everything under `dirfd` (the directory itself is left
 * for the caller to rmdir). Async-signal-safe: no malloc, no stdio, no fork.
 * Bounded recursion; these trees are one or two levels deep. */
__attribute__((unused)) static void tt_rmrf_at(int dirfd, int depth)
{
    char buf[8192];
    int  pass;
    if (depth > 8) return;
    /* Deleting while iterating a directory stream is defined-but-fiddly; do
     * repeated full passes instead and stop when a pass removes nothing. */
    for (pass = 0; pass < 64; pass++) {
        long removed = 0;
        if (lseek(dirfd, 0, SEEK_SET) < 0) return;
        for (;;) {
            long n = syscall(SYS_getdents64, dirfd, buf, (unsigned)sizeof buf);
            long off;
            if (n <= 0) break;
            for (off = 0; off < n; ) {
                struct tt_dirent64* de = (struct tt_dirent64*)(buf + off);
                const char* nm = de->d_name;
                off += de->d_reclen;
                if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0)))
                    continue;
                if (de->d_type == DT_DIR) {
                    int sub = openat(dirfd, nm, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
                    if (sub >= 0) { tt_rmrf_at(sub, depth + 1); close(sub); }
                    if (unlinkat(dirfd, nm, AT_REMOVEDIR) == 0) removed++;
                } else if (de->d_type == DT_UNKNOWN) {
                    /* filesystem did not fill d_type: try file, then directory */
                    if (unlinkat(dirfd, nm, 0) == 0) { removed++; }
                    else {
                        int sub = openat(dirfd, nm, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
                        if (sub >= 0) { tt_rmrf_at(sub, depth + 1); close(sub); }
                        if (unlinkat(dirfd, nm, AT_REMOVEDIR) == 0) removed++;
                    }
                } else {
                    if (unlinkat(dirfd, nm, 0) == 0) removed++;
                }
            }
        }
        if (removed == 0) return;
    }
}

__attribute__((unused)) static void tt_cleanup(void)
{
    int fd;
    if (!tt_active) return;
    /* A forked child inherits this handler; the directory is not its to remove. */
    if (getpid() != tt_owner_pid) return;
    tt_active = 0;

    if (getenv("BMC_TEST_KEEP") && *getenv("BMC_TEST_KEEP")) {
        /* write(2) rather than printf: this also runs from a signal handler */
        const char* m = "[test_tmpdir] BMC_TEST_KEEP set, keeping ";
        ssize_t ign;
        ign = write(2, m, strlen(m));
        ign = write(2, tt_workdir_buf, strlen(tt_workdir_buf));
        ign = write(2, "\n", 1);
        (void)ign;
        return;
    }

    /* step out first, so the rmdir cannot fail on a busy cwd */
    if (chdir(tt_srcdir_buf) != 0) { if (chdir("/") != 0) { /* nothing left to try */ } }

    fd = open(tt_workdir_buf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd >= 0) { tt_rmrf_at(fd, 0); close(fd); }
    rmdir(tt_workdir_buf);
}

__attribute__((unused)) static void tt_sigcleanup(int sig)
{
    struct sigaction sa;
    tt_cleanup();
    /* Re-raise with the default disposition so the wait status a parent sees
     * (and any core-dump policy) is exactly what it would have been. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigaction(sig, &sa, 0);
    raise(sig);
}

/* Absolute path of the directory the test was launched from (asm/). */
__attribute__((unused)) static const char* tt_srcdir(void)
{
    return tt_active ? tt_srcdir_buf : ".";
}

/* Absolute path of this test's private working directory. Hand this to a forked
 * child or a spawned daemon that takes a datadir argument. */
__attribute__((unused)) static const char* tt_workdir(void)
{
    return tt_active ? tt_workdir_buf : ".";
}

/* Move into a fresh, uniquely numbered subdirectory of the private working
 * directory, for a test that runs several independent phases in one process and
 * needs each to start from an empty datadir. The whole tree still goes away in
 * one piece at exit. Returns the subdirectory name (relative to tt_workdir()). */
__attribute__((unused)) static const char* tt_subdir(const char* tag)
{
    static char name[128];
    static int  seq;
    snprintf(name, sizeof name, "%s.%d", (tag && *tag) ? tag : "phase", seq++);
    if (chdir(tt_workdir()) != 0 || mkdir(name, 0700) != 0 || chdir(name) != 0) {
        fprintf(stderr, "test_tmpdir: tt_subdir(%s): %s\n", name, strerror(errno));
        exit(2);
    }
    return name;
}

/* Rebase a source-tree-relative path (a fixture, the daemon binary, a shim) onto
 * the launch directory, so it still resolves after the chdir. Four rotating
 * buffers, so a handful of tt_src() calls in one expression are all still live. */
__attribute__((unused)) static const char* tt_src(const char* rel)
{
    static char ring[4][TT_PATHMAX];
    static int  slot;
    char* out;
    if (!tt_active) return rel;
    if (rel && rel[0] == '/') return rel;
    out = ring[slot];
    slot = (slot + 1) & 3;
    snprintf(out, TT_PATHMAX, "%s/%s", tt_srcdir_buf, rel ? rel : "");
    return out;
}

/* Create a private working directory named after `tag` and chdir into it.
 * Call as the first statement of main(). Idempotent. */
__attribute__((unused)) static void tt_isolate_named(const char* tag)
{
    const char* root;
    char safe[64];
    size_t i;
    int n;

    if (tt_active) return;

    if (!getcwd(tt_srcdir_buf, sizeof tt_srcdir_buf)) {
        fprintf(stderr, "test_tmpdir: getcwd: %s\n", strerror(errno));
        exit(2);
    }

    root = getenv("BMC_TEST_TMPDIR");
    if (!root || !*root) root = getenv("TMPDIR");
    if (!root || !*root) root = "/tmp";
    if (root[0] != '/') {
        fprintf(stderr, "test_tmpdir: temp root must be absolute, got \"%s\"\n", root);
        exit(2);
    }

    if (!tag || !*tag) tag = "test";
    for (i = 0; i + 1 < sizeof safe && tag[i]; i++) {
        char c = tag[i];
        safe[i] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '_' || c == '-') ? c : '_';
    }
    safe[i] = 0;

    /* mkdtemp() edits the template in place, so build it straight into the
     * buffer that will hold the result. */
    n = snprintf(tt_workdir_buf, sizeof tt_workdir_buf, "%s/bmc.%s.XXXXXX", root, safe);
    if (n < 0 || n >= (int)sizeof tt_workdir_buf) {
        fprintf(stderr, "test_tmpdir: temp root too long: %s\n", root);
        exit(2);
    }
    if (!mkdtemp(tt_workdir_buf)) {
        fprintf(stderr, "test_tmpdir: mkdtemp(%s): %s\n"
                        "             (set BMC_TEST_TMPDIR to a writable directory)\n",
                tt_workdir_buf, strerror(errno));
        exit(2);
    }

    tt_owner_pid = getpid();
    tt_active    = 1;

    if (chdir(tt_workdir_buf) != 0) {
        fprintf(stderr, "test_tmpdir: chdir(%s): %s\n", tt_workdir_buf, strerror(errno));
        tt_cleanup();
        exit(2);
    }

    atexit(tt_cleanup);
    {
        /* Fatal signals the suite actually produces (the bounds tests provoke
         * SIGSEGV and SIGABRT deliberately) plus the ones a harness sends. */
        static const int sigs[] = { SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE,
                                    SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGPIPE };
        struct sigaction sa, old;
        size_t k;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = tt_sigcleanup;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_NODEFER;   /* the re-raise must reach the default handler */
        for (k = 0; k < sizeof sigs / sizeof sigs[0]; k++) {
            /* Do not stomp a disposition the test set on purpose (several
             * ignore SIGPIPE, and the crash-recovery tests install their own). */
            if (sigaction(sigs[k], 0, &old) == 0 &&
                old.sa_handler == SIG_DFL)
                sigaction(sigs[k], &sa, 0);
        }
    }
}

/* Derive the tag from the program name. */
#define tt_isolate() tt_isolate_named(tt_progname())

__attribute__((unused)) static const char* tt_progname(void)
{
#ifdef TT_NAME
    return TT_NAME;
#else
    extern char* program_invocation_short_name;
    return program_invocation_short_name;
#endif
}

#endif /* BMC_TEST_TMPDIR_H */
