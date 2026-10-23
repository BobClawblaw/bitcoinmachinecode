/* tests/durable_image.h -- a power-loss image of the working directory,
 * recorded from the fsync/fdatasync calls the real code makes. Ported from
 * the formal/storage crash driver (2026-10-23) for tests/test_sto_crash.c.
 *
 * A seccomp filter traps fsync(2) and fdatasync(2) (the asm issues them as raw
 * `syscall` instructions, so an LD_PRELOAD shim would miss them). The SIGSYS
 * handler records what that call makes durable and answers 0:
 *   - a regular file: its content at that moment is copied to the snapshot
 *     directory, keyed by inode + birth time (an inode number can be reused);
 *   - the namespace (name -> inode of every regular file in the directory) is
 *     recorded on ANY sync: ext4 data=ordered commits the whole journal on
 *     every fsync, so every create, rename and unlink so far is durable, and
 *     a truncation committed with it shortens the snapshot.
 * di_build_image() then writes the directory a power loss at that moment can
 * leave: every name of the last committed namespace with the content its
 * inode had at its last sync (empty if it was never synced). Names matching a
 * `cached` prefix are taken from the live directory instead, as if the kernel
 * had written those files back on its own -- also a state a power loss can
 * leave, used to isolate one hole from another (and by the controls, which
 * keep the one write a scenario's power loss loses).
 *
 * This is the "every unsynced write is lost" corner of the crash-state space,
 * reachable under ext4 data=ordered while the unsynced data is still delalloc
 * (~30 s). It does not model torn appends or out-of-order page writeback.
 *
 * Differences from the formal driver: the recorder's state lives in a
 * MAP_SHARED mapping, so one install in a scenario's runner records every
 * process it forks (the processes of a trace, and utxo_live's own flush
 * writer); and di_freeze_after(name, k) stops recording after the k-th sync
 * of `name`, so the image is a power loss at exactly that point even though
 * the process goes on.
 *
 * Async-signal safety: the handler uses raw syscalls and fixed buffers only
 * (no stdio, no malloc); a spinlock serialises handlers of different
 * processes. */
#ifndef DURABLE_IMAGE_H
#define DURABLE_IMAGE_H
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define DI_MAXN 512
#define DI_LOGN 256
struct di_ent { char name[64]; unsigned long long ino; long long bt; };
struct di_state {
    int lock;
    int armed, frozen, nsync, nns, nlog, freeze_left;
    char freeze_name[64];
    char snap[400];
    struct di_ent ns[DI_MAXN];          /* the committed namespace */
    char log[DI_LOGN][48];              /* sync order, for the report */
};
static struct di_state* di;

static size_t di_strlen(const char* s){ size_t n = 0; while (s[n]) n++; return n; }
static char* di_cat(char* d, const char* s){ while (*s) *d++ = *s++; *d = 0; return d; }
static char* di_u64(char* d, unsigned long long v){
    char t[24]; int n = 0; do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n) *d++ = t[--n];
    *d = 0; return d;
}
static int di_statx(int dfd, const char* path, int flags, struct statx* sx){
    return (int)syscall(SYS_statx, dfd, path, flags, STATX_INO | STATX_BTIME | STATX_SIZE | STATX_TYPE, sx);
}
static void di_key(char* out, unsigned long long ino, long long bt){
    char* p = di_cat(out, di->snap); p = di_cat(p, "/i"); p = di_u64(p, ino); p = di_cat(p, "_"); di_u64(p, (unsigned long long)bt);
}
static void di_copy_fd(int src, const char* dst){
    static char buf[1 << 16];
    int o = (int)syscall(SYS_openat, AT_FDCWD, dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (o < 0) return;
    off_t off = 0;
    for (;;){ ssize_t r = (ssize_t)syscall(SYS_pread64, src, buf, sizeof buf, off); if (r <= 0) break;
              syscall(SYS_write, o, buf, r); off += r; }
    syscall(SYS_close, o);
}
/* the namespace of "." now becomes durable */
static void di_commit_ns(void){
    static char dbuf[1 << 15];
    int d = (int)syscall(SYS_openat, AT_FDCWD, ".", O_RDONLY | O_DIRECTORY);
    if (d < 0) return;
    di->nns = 0;
    for (;;){
        long n = syscall(SYS_getdents64, d, dbuf, sizeof dbuf);
        if (n <= 0) break;
        for (long off = 0; off < n; ){
            struct { unsigned long long ino; long long off; unsigned short reclen; unsigned char type; char name[]; }* e = (void*)(dbuf + off);
            off += e->reclen;
            if (e->type != DT_REG || di_strlen(e->name) >= 64 || di->nns >= DI_MAXN) continue;
            struct statx sx; if (di_statx(d, e->name, AT_SYMLINK_NOFOLLOW, &sx) != 0) continue;
            struct di_ent* x = &di->ns[di->nns++];
            di_cat(x->name, e->name); x->ino = sx.stx_ino; x->bt = (long long)sx.stx_btime.tv_sec * 1000000000LL + sx.stx_btime.tv_nsec;
            /* a truncation is metadata: committed with the namespace */
            char k[480]; di_key(k, x->ino, x->bt);
            struct statx ss;
            if (di_statx(AT_FDCWD, k, 0, &ss) == 0 && ss.stx_size > sx.stx_size)
                syscall(SYS_truncate, k, (long)sx.stx_size);
        }
    }
    syscall(SYS_close, d);
}
static void di_note(const char* what){
    if (di->nlog >= DI_LOGN) return;
    size_t n = di_strlen(what); if (n > 47) n = 47;
    memcpy(di->log[di->nlog], what, n); di->log[di->nlog][n] = 0; di->nlog++;
}
static void di_on_sigsys(int sig, siginfo_t* si, void* ctx){
    (void)sig; (void)si;
    ucontext_t* uc = (ucontext_t*)ctx;
    int fd = (int)uc->uc_mcontext.gregs[REG_RDI];
    while (__atomic_exchange_n(&di->lock, 1, __ATOMIC_ACQUIRE)) {}
    if (di->armed && !di->frozen){
        struct statx sx;
        if (di_statx(fd, "", AT_EMPTY_PATH, &sx) == 0){
            char lp[64], tgt[256]; char* p = di_cat(lp, "/proc/self/fd/"); di_u64(p, (unsigned long long)fd);
            long n = syscall(SYS_readlinkat, AT_FDCWD, lp, tgt, sizeof tgt - 1); if (n < 0) n = 0; tgt[n] = 0;
            const char* base = tgt; for (const char* q = tgt; *q; q++) if (*q == '/') base = q + 1;
            di->nsync++;
            if (S_ISDIR(sx.stx_mode)){ di_note("<dir>"); di_commit_ns(); }
            else if (S_ISREG(sx.stx_mode)){
                di_note(base);
                int r = (int)syscall(SYS_openat, AT_FDCWD, lp, O_RDONLY);
                if (r >= 0){ char k[480]; di_key(k, sx.stx_ino, (long long)sx.stx_btime.tv_sec * 1000000000LL + sx.stx_btime.tv_nsec);
                             di_copy_fd(r, k); syscall(SYS_close, r); }
                di_commit_ns();
                if (di->freeze_left > 0){
                    const char* a = base; const char* b = di->freeze_name;
                    while (*a && *a == *b){ a++; b++; }
                    if (*a == 0 && *b == 0 && --di->freeze_left == 0){ di->frozen = 1; di_note("<power lost here>"); }
                }
            }
        }
    }
    __atomic_store_n(&di->lock, 0, __ATOMIC_RELEASE);
    uc->uc_mcontext.gregs[REG_RAX] = 0;
}
/* install in the scenario's runner (before it forks the trace's processes) */
static int di_install(const char* snapdir){
    di = mmap(0, sizeof *di, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (di == MAP_FAILED) return -1;
    memset(di, 0, sizeof *di);
    di_cat(di->snap, snapdir);
    mkdir(snapdir, 0755);
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = di_on_sigsys; sa.sa_flags = SA_SIGINFO | SA_RESTART;
    if (sigaction(SIGSYS, &sa, 0)) return -1;
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fsync, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fdatasync, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog pr = { (unsigned short)(sizeof f / sizeof f[0]), f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &pr)) return -1;
    return 0;
}
/* start recording in the live directory (the caller's cwd): what exists now counts as durable */
static void di_arm(void){ di_commit_ns(); di->armed = 1; }
static void di_freeze_now(void){ di->frozen = 1; di_note("<power lost here>"); }
static void di_freeze_after(const char* name, int k){
    size_t n = strlen(name); if (n > 63) n = 63;
    memcpy(di->freeze_name, name, n); di->freeze_name[n] = 0; di->freeze_left = k;
}
static int di_cached(const char* name, const char* const* cached){
    for (int i = 0; cached && cached[i]; i++) if (!strncmp(name, cached[i], strlen(cached[i]))) return 1;
    return 0;
}
static int di_copy_path(const char* src, const char* dst){
    int s = open(src, O_RDONLY); if (s < 0) return -1;
    di_copy_fd(s, dst); close(s); return 0;
}
/* the power-loss image of "." into dst (created); call with cwd = the live directory */
static int di_build_image(const char* dst, const char* const* cached){
    if (mkdir(dst, 0755) != 0 && errno != EEXIST) return -1;
    char p[1200];
    for (int i = 0; i < di->nns; i++){
        if (di_cached(di->ns[i].name, cached)) continue;
        char k[480]; di_key(k, di->ns[i].ino, di->ns[i].bt);
        if (strlen(dst) + 66 > sizeof p) continue;
        if (snprintf(p, sizeof p, "%s/%s", dst, di->ns[i].name) >= (int)sizeof p) continue;
        if (di_copy_path(k, p) != 0){ int o = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (o >= 0) close(o); }
    }
    DIR* d = opendir("."); struct dirent* e;
    while (d && (e = readdir(d))){
        if (e->d_type != DT_REG || !di_cached(e->d_name, cached)) continue;
        if (strlen(dst) + strlen(e->d_name) + 2 > sizeof p) continue;
        if (snprintf(p, sizeof p, "%s/%s", dst, e->d_name) >= (int)sizeof p) continue;
        di_copy_path(e->d_name, p);
    }
    if (d) closedir(d);
    return 0;
}
static void di_print_log(void){
    printf("  syncs in order:");
    for (int i = 0; i < di->nlog; ){
        int j = i; while (j < di->nlog && !strcmp(di->log[j], di->log[i])) j++;
        if (j - i > 1) printf(" %s(x%d)", di->log[i], j - i); else printf(" %s", di->log[i]);
        i = j;
    }
    printf("\n");
}
#endif
