/* formal/storage/crash/durable_image.h -- a power-loss image of the working
 * directory, recorded from the syscalls the real code makes.
 *
 * A seccomp filter traps fsync(2) and fdatasync(2) (the asm issues them as raw
 * `syscall` instructions, so an LD_PRELOAD shim would miss them). The SIGSYS
 * handler records what that call makes durable and answers 0:
 *   - a regular file: its content at that moment is copied to the snapshot
 *     directory, keyed by inode + birth time (an inode number can be reused);
 *   - the namespace (name -> inode of every regular file in the directory) is
 *     recorded on a directory fsync (DI_POSIX), or on ANY sync (DI_EXT4: ext4
 *     commits the whole journal on every fsync, so every create, rename and
 *     unlink so far is durable; a truncation committed with it shortens the
 *     snapshot).
 * di_build_image() then writes the directory a power loss at that moment can
 * leave: every name of the last committed namespace with the content its inode
 * had at its last sync (empty if it was never synced). Names matching a
 * `cached` prefix are taken from the live directory instead, i.e. as if the
 * kernel had written those files back on its own -- also a state a power loss
 * can leave, used to isolate one hole from another.
 *
 * This is the "every unsynced write is lost" corner of the crash-state space:
 * reachable under the weak model always, and under ext4 data=ordered whenever
 * the unsynced data was still delalloc (not yet written back, ~30 s). It does
 * not model torn appends or out-of-order page writeback.
 *
 * Optional fault: di_fail_dir_fsync = k makes the k-th directory fsync return
 * -EIO without committing anything.
 *
 * Async-signal safety: the handler uses raw syscalls and fixed static buffers
 * only (no stdio, no malloc). */
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
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define DI_EXT4  0
#define DI_POSIX 1
#define DI_MAXN  512

struct di_ent { char name[64]; unsigned long long ino; long long bt; };
static struct di_ent di_ns[DI_MAXN]; static int di_nns;     /* the committed namespace */
static char di_snap[400];                                   /* snapshot dir (absolute) */
static int  di_mode = DI_EXT4;
static volatile int di_armed = 0;
static int  di_dirsyncs = 0, di_fail_dir_fsync = 0, di_nsync = 0;
#define DI_LOGN 256
static char di_log[DI_LOGN][48]; static int di_nlog;        /* sync order, for the report */

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
    char* p = di_cat(out, di_snap); p = di_cat(p, "/i"); p = di_u64(p, ino); p = di_cat(p, "_"); di_u64(p, (unsigned long long)bt);
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
/* the namespace now becomes durable */
static void di_commit_ns(void){
    static char dbuf[1 << 15];
    int d = (int)syscall(SYS_openat, AT_FDCWD, ".", O_RDONLY | O_DIRECTORY);
    if (d < 0) return;
    di_nns = 0;
    for (;;){
        long n = syscall(SYS_getdents64, d, dbuf, sizeof dbuf);
        if (n <= 0) break;
        for (long off = 0; off < n; ){
            struct { unsigned long long ino; long long off; unsigned short reclen; unsigned char type; char name[]; }* e = (void*)(dbuf + off);
            off += e->reclen;
            if (e->type != DT_REG || di_strlen(e->name) >= 64 || di_nns >= DI_MAXN) continue;
            struct statx sx; if (di_statx(d, e->name, AT_SYMLINK_NOFOLLOW, &sx) != 0) continue;
            struct di_ent* x = &di_ns[di_nns++];
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
    if (di_nlog >= DI_LOGN) return;
    size_t n = di_strlen(what); if (n > 47) n = 47;
    memcpy(di_log[di_nlog], what, n); di_log[di_nlog][n] = 0; di_nlog++;
}
static void di_on_sigsys(int sig, siginfo_t* si, void* ctx){
    (void)sig; (void)si;
    ucontext_t* uc = (ucontext_t*)ctx;
    int fd = (int)uc->uc_mcontext.gregs[REG_RDI];
    long rv = 0;
    if (di_armed){
        struct statx sx;
        if (di_statx(fd, "", AT_EMPTY_PATH, &sx) == 0){
            char lp[64], tgt[256]; char* p = di_cat(lp, "/proc/self/fd/"); di_u64(p, (unsigned long long)fd);
            long n = syscall(SYS_readlinkat, AT_FDCWD, lp, tgt, sizeof tgt - 1); if (n < 0) n = 0; tgt[n] = 0;
            const char* base = tgt; for (const char* q = tgt; *q; q++) if (*q == '/') base = q + 1;
            di_nsync++;
            if (S_ISDIR(sx.stx_mode)){
                di_dirsyncs++;
                if (di_fail_dir_fsync && di_dirsyncs == di_fail_dir_fsync){ di_note("<dir> -EIO"); rv = -EIO; }
                else { di_note("<dir>"); di_commit_ns(); }
            } else if (S_ISREG(sx.stx_mode)){
                di_note(base);
                int r = (int)syscall(SYS_openat, AT_FDCWD, lp, O_RDONLY);
                if (r >= 0){ char k[480]; di_key(k, sx.stx_ino, (long long)sx.stx_btime.tv_sec * 1000000000LL + sx.stx_btime.tv_nsec);
                             di_copy_fd(r, k); syscall(SYS_close, r); }
                if (di_mode == DI_EXT4) di_commit_ns();
            }
        }
    }
    uc->uc_mcontext.gregs[REG_RAX] = rv;
}
/* install in the process whose syscalls are recorded (before it starts threads) */
static int di_install(const char* snapdir, int mode){
    di_cat(di_snap, snapdir); di_mode = mode;
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
    di_commit_ns();            /* what exists at arm time counts as durable */
    di_armed = 1;
    return 0;
}
static int di_cached(const char* name, const char* const* cached){
    for (int i = 0; cached && cached[i]; i++) if (!strncmp(name, cached[i], strlen(cached[i]))) return 1;
    return 0;
}
static int di_copy_path(const char* src, const char* dst){
    int s = open(src, O_RDONLY); if (s < 0) return -1;
    di_copy_fd(s, dst); close(s); return 0;
}
/* the power-loss image of "." into dst (created) */
static int di_build_image(const char* dst, const char* const* cached){
    if (mkdir(dst, 0755) != 0 && errno != EEXIST) return -1;
    char p[1200];
    for (int i = 0; i < di_nns; i++){
        if (di_cached(di_ns[i].name, cached)) continue;
        char k[480]; di_key(k, di_ns[i].ino, di_ns[i].bt);
        if (strlen(dst) + 66 > sizeof p) continue;
        memcpy(p, dst, strlen(dst)); p[strlen(dst)] = '/'; strcpy(p + strlen(dst) + 1, di_ns[i].name);
        if (di_copy_path(k, p) != 0){ int o = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (o >= 0) close(o); }
    }
    DIR* d = opendir("."); struct dirent* e;
    while (d && (e = readdir(d))){
        if (e->d_type != DT_REG || !di_cached(e->d_name, cached)) continue;
        if (strlen(dst) + strlen(e->d_name) + 2 > sizeof p) continue;
        memcpy(p, dst, strlen(dst)); p[strlen(dst)] = '/'; strcpy(p + strlen(dst) + 1, e->d_name);
        di_copy_path(e->d_name, p);
    }
    if (d) closedir(d);
    return 0;
}
static void di_print_log(const char* tag){
    printf("  [%s] syncs in order:", tag);
    for (int i = 0; i < di_nlog; ){
        int j = i; while (j < di_nlog && !strcmp(di_log[j], di_log[i])) j++;
        if (j - i > 1) printf(" %s(x%d)", di_log[i], j - i); else printf(" %s", di_log[i]);
        i = j;
    }
    printf("\n");
}
static int di_synced(const char* name){ for (int i = 0; i < di_nlog; i++) if (!strcmp(di_log[i], name)) return 1; return 0; }
#endif
