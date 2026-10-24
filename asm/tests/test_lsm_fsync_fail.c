/* tests/test_lsm_fsync_fail.c -- ST2-1 (audit 2026-10-23): a failed fsync in
 * the LSM's flush or compaction must fail that flush or compaction.
 *
 * THE BUG. bitcoin_utxo_lsm.asm calls mac_fsync2 six times -- the flush's run
 * file, manifest tmp and directory, and the compaction's merged run, manifest
 * tmp (or .child) and directory -- and went straight on to close() without
 * looking at the result. A writeback error (EIO, ENOSPC) reported by fsync
 * therefore still renamed the manifest over the old one, truncated the WAL
 * (the flush), or adopted the merge and unlinked its inputs (the compaction):
 * the only durable copy of the data could be the one the kernel just said it
 * failed to write.
 *
 * THE INJECTION. The asm issues fsync as a raw syscall, so an LD_PRELOAD shim
 * never sees it. A seccomp filter turns syscall 74 (fsync) into SIGSYS; the
 * handler counts the calls made while the test has armed it, answers the k-th
 * with -EIO and every other one with a real fdatasync(fd) (syscall 75, not
 * filtered). Each scenario runs in its own forked child and directory.
 *
 * WHAT IS ASSERTED, for k = 1, 2, 3 (each fsync site of the operation):
 *   flush:      returns -1; the WAL is not truncated (log_len and the file's
 *               size unchanged); for k = 1, 2 no manifest has been published.
 *   compaction: returns -1; both input runs are still on disk; for k = 1, 2
 *               the on-disk manifest still lists the two input runs.
 * And the controls: with no failure armed the flush and the compaction each
 * issue exactly three fsyncs (so k names the site the comment says it does)
 * and succeed. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "test_tmpdir.h"

typedef unsigned long long u64;
typedef unsigned char u8;

struct lsm_state { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; };

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8* txid, unsigned index, u64 value,
                         unsigned long height, unsigned long cb, const u8* script, unsigned slen);
extern long utxo_lsm_flush(void* lst, void* u);
extern long utxo_lsm_compact(void* lst);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("ok  : %s\n", l); else { printf("FAIL: %s\n", l); fails++; } }

/* ---- the fsync trap ---- */
static volatile int g_armed, g_fail_at, g_seen;
static void on_sigsys(int sig, siginfo_t* si, void* ctx){
    (void)sig;
    ucontext_t* uc = (ucontext_t*)ctx;
    long fd = uc->uc_mcontext.gregs[REG_RDI];
    long r;
    if (si->si_syscall != SYS_fsync){ uc->uc_mcontext.gregs[REG_RAX] = -ENOSYS; return; }
    if (g_armed && ++g_seen == g_fail_at) r = -EIO;
    else { r = syscall(SYS_fdatasync, fd); if (r < 0) r = -errno; }
    uc->uc_mcontext.gregs[REG_RAX] = r;
}
static int install_trap(void){
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sigsys; sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSYS, &sa, 0)) return -1;
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fsync, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = { (unsigned short)(sizeof f / sizeof f[0]), f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p);
}
static void arm(int k){ g_seen = 0; g_fail_at = k; g_armed = 1; }
static int  disarm(void){ g_armed = 0; return g_seen; }

/* ---- a small store ---- */
enum { SLOTS = 65536, TOMBS = 4096 };
static struct lsm_state lst;
static void* g_u;
static void open_store(void){
    void* blob = malloc(16u << 20);
    g_u = malloc(utxo_struct_size(SLOTS));
    if (!blob || !g_u){ printf("FAIL: malloc\n"); _exit(1); }
    utxo_init(g_u, SLOTS, blob, 16u << 20);
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = 100000000ULL; lst.fill_threshold = SLOTS;
    lst.tomb_buf = malloc(TOMBS * 36); lst.tomb_cap = TOMBS;
    lst.manifest_buf = malloc(512 * 16); lst.manifest_cap = 512;
    lst.scratch_cap = (u64)(SLOTS + TOMBS) * 128 + 8 * 1024 * 1024 + 65536;
    lst.scratch_buf = malloc(lst.scratch_cap);
    if (!lst.tomb_buf || !lst.manifest_buf || !lst.scratch_buf){ printf("FAIL: malloc\n"); _exit(1); }
    if (utxo_lsm_init(&lst) != 1){ printf("FAIL: lsm_init\n"); _exit(1); }
}
static void put_batch(int seed){
    u8 script[40]; for (int j = 0; j < 40; j++) script[j] = (u8)(0x80 + j);
    for (unsigned i = 0; i < 300; i++){
        u8 t[32]; for (int j = 0; j < 32; j++) t[j] = (u8)(seed + j);
        t[0] = (u8)i; t[1] = (u8)(i >> 8);
        if (utxo_lsm_put(&lst, g_u, t, i & 3, 1000ULL + i, 100 + i, 0, script, 20 + (i % 20)) < 0){
            printf("FAIL: put\n"); _exit(1);
        }
    }
}
static int file_exists(const char* p){ struct stat st; return stat(p, &st) == 0; }
static long file_size(const char* p){ struct stat st; return stat(p, &st) == 0 ? (long)st.st_size : -1; }
/* manifest_n as the on-disk utxo_manifest.dat states it, -1 if absent */
static long disk_manifest_n(void){
    int fd = open("utxo_manifest.dat", O_RDONLY);
    if (fd < 0) return -1;
    u8 h[12]; long n = -1;
    if (read(fd, h, 12) == 12){ u64 v; memcpy(&v, h + 4, 8); n = (long)v; }
    close(fd);
    return n;
}
static void run_name(char* buf, u64 run_no){ snprintf(buf, 32, "utxo_run_%06llu.dat", run_no); }

/* k = 0: the control (no failure; reports the fsync count) */
static int flush_case(int k){
    char d[32]; snprintf(d, sizeof d, "flush%d", k);
    if (mkdir(d, 0755) || chdir(d)) return 1;
    open_store(); put_batch(0x40);
    u64 log_before = lst.log_len;
    ck("the WAL holds the batch before the flush", log_before > 0);
    arm(k);
    long r = utxo_lsm_flush(&lst, g_u);
    int seen = disarm();
    if (k == 0){
        ck("control: the flush succeeds", r == 1);
        ck("control: the flush issues exactly three fsyncs (run, manifest, dir)", seen == 3);
        if (seen != 3) printf("      saw %d\n", seen);
        ck("control: the manifest is published with one run", disk_manifest_n() == 1);
        return fails;
    }
    printf("  flush, fsync %d of 3 fails:\n", k);
    ck("  the flush reports failure", r == -1);
    if (r != -1) printf("      got %ld\n", r);
    ck("  log_len is not cleared", lst.log_len == log_before);
    ck("  the WAL file holds the whole batch (drained, not truncated)", file_size("utxo.dat") == (long)log_before);
    if (k < 3){
        ck("  no manifest was published", disk_manifest_n() == -1);
        if (disk_manifest_n() != -1) printf("      on-disk manifest_n %ld\n", disk_manifest_n());
    }
    return fails;
}

static int compact_case(int k){
    char d[32]; snprintf(d, sizeof d, "compact%d", k);
    if (mkdir(d, 0755) || chdir(d)) return 1;
    open_store();
    put_batch(0x40);
    if (utxo_lsm_flush(&lst, g_u) != 1){ printf("FAIL: flush 1\n"); return 1; }
    put_batch(0x60);
    if (utxo_lsm_flush(&lst, g_u) != 1){ printf("FAIL: flush 2\n"); return 1; }
    ck("two runs before the compaction", lst.manifest_n == 2 && disk_manifest_n() == 2);
    char r1[32], r2[32];
    const u64* e = (const u64*)lst.manifest_buf;
    run_name(r1, e[1]); run_name(r2, e[3]);
    ck("both input runs are on disk", file_exists(r1) && file_exists(r2));
    arm(k);
    long r = utxo_lsm_compact(&lst);
    int seen = disarm();
    if (k == 0){
        ck("control: the compaction succeeds", r == 1);
        ck("control: the compaction issues exactly three fsyncs (run, manifest, dir)", seen == 3);
        if (seen != 3) printf("      saw %d\n", seen);
        ck("control: the inputs are unlinked", !file_exists(r1) && !file_exists(r2));
        ck("control: the manifest names one run", disk_manifest_n() == 1);
        return fails;
    }
    printf("  compaction, fsync %d of 3 fails:\n", k);
    ck("  the compaction reports failure", r == -1);
    if (r != -1) printf("      got %ld\n", r);
    ck("  both input runs are still on disk", file_exists(r1) && file_exists(r2));
    if (k < 3){
        ck("  the on-disk manifest still names both inputs", disk_manifest_n() == 2);
        if (disk_manifest_n() != 2) printf("      on-disk manifest_n %ld\n", disk_manifest_n());
    }
    return fails;
}

static int in_child(int (*fn)(int), int k){
    fflush(stdout);
    pid_t p = fork();
    if (p < 0) return 1;
    if (p == 0){ int f = fn(k); fflush(stdout); _exit(f ? 1 : 0); }
    int st = 0;
    if (waitpid(p, &st, 0) != p) return 1;
    if (!WIFEXITED(st)){ printf("FAIL: scenario %d died (signal %d)\n", k, WIFSIGNALED(st) ? WTERMSIG(st) : 0); return 1; }
    return WEXITSTATUS(st) != 0;
}

int main(void){
    tt_isolate();
    if (install_trap()){ printf("FAIL: seccomp filter: %s\n", strerror(errno)); return 1; }
    int bad = 0;
    for (int k = 0; k <= 3; k++) bad += in_child(flush_case, k);
    for (int k = 0; k <= 3; k++) bad += in_child(compact_case, k);
    if (bad){ printf("\nTESTS FAILED (%d scenario(s))\n", bad); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
