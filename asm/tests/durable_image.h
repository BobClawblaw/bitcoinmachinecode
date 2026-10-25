/* tests/durable_image.h -- a power-loss image of the working directory,
 * recorded from the fsync/fdatasync calls the real code makes. Ported from
 * the formal/storage crash driver (2026-10-23) for tests/test_sto_crash.c.
 *
 * A seccomp filter traps fsync(2) and fdatasync(2) (the asm issues them as raw
 * `syscall` instructions, so an LD_PRELOAD shim would miss them), and open(2)
 * (see "Weak mode"). The SIGSYS handler records what a sync makes durable and
 * answers 0 (or an armed EIO):
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
 * di_kill_after(name, k) (STO-1, 2026-10-24) SIGKILLs the process right after
 * the k-th sync of `name` returns: a crash at a named step of a trace.
 *
 * Weak mode (di_set_weak; STO-D/STO-W, 2026-10-23): POSIX only, the formal
 * model's FS = "weak". A regular file's sync makes its own content (its
 * truncations included) durable and nothing else; the namespace becomes
 * durable only at a directory fsync. A power loss keeps ANY subset of the name
 * ops since the last directory fsync: di_build_image_weak(dst, cached, kept)
 * takes every name from the last committed namespace, except the names
 * matching a `kept` prefix, which take their state at the moment of the loss
 * (present with the inode they had then, or absent) -- the name ops the disk
 * happened to keep. Two directory-fsync points can be armed by the name of a
 * file synced before them, so a trace can place them without knowing how many
 * syncs come first: di_fail_dir_after(name, k) answers EIO to the first
 * directory fsync after the k-th sync of `name` (and commits nothing), and
 * di_lose_dir_after(name, k) loses the power at it. di_fail_open_dot_after
 * makes the first raw open(".") after that point fail with EMFILE (the asm
 * opens with the `open` syscall, which the filter traps; glibc's openat is not
 * trapped, and the handler forwards every other open as an openat).
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
/* a point armed by name: after `left` more syncs of `name`, `fire` is set */
struct di_trig { char name[64]; int left, fire; };
struct di_state {
    int lock;
    int armed, frozen, nsync, nns, nlog, freeze_left;
    char freeze_name[64];
    char snap[400];
    int weak, nloss, have_loss;
    struct di_trig dir_fail, dir_lose, open_fail, kill;
    struct di_ent ns[DI_MAXN];          /* the committed namespace */
    struct di_ent loss[DI_MAXN];        /* weak: the live namespace when the power was lost */
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
/* read the namespace of "." into ents[0..*cnt); with `trunc`, a truncation is
 * committed with it (ext4: metadata, in the same journal commit) */
static void di_read_ns(struct di_ent* ents, int* cnt, int trunc){
    static char dbuf[1 << 15];
    int d = (int)syscall(SYS_openat, AT_FDCWD, ".", O_RDONLY | O_DIRECTORY);
    if (d < 0) return;
    *cnt = 0;
    for (;;){
        long n = syscall(SYS_getdents64, d, dbuf, sizeof dbuf);
        if (n <= 0) break;
        for (long off = 0; off < n; ){
            struct { unsigned long long ino; long long off; unsigned short reclen; unsigned char type; char name[]; }* e = (void*)(dbuf + off);
            off += e->reclen;
            if (e->type != DT_REG || di_strlen(e->name) >= 64 || *cnt >= DI_MAXN) continue;
            struct statx sx; if (di_statx(d, e->name, AT_SYMLINK_NOFOLLOW, &sx) != 0) continue;
            struct di_ent* x = &ents[(*cnt)++];
            di_cat(x->name, e->name); x->ino = sx.stx_ino; x->bt = (long long)sx.stx_btime.tv_sec * 1000000000LL + sx.stx_btime.tv_nsec;
            if (!trunc) continue;
            /* a truncation is metadata: committed with the namespace */
            char k[480]; di_key(k, x->ino, x->bt);
            struct statx ss;
            if (di_statx(AT_FDCWD, k, 0, &ss) == 0 && ss.stx_size > sx.stx_size)
                syscall(SYS_truncate, k, (long)sx.stx_size);
        }
    }
    syscall(SYS_close, d);
}
/* the namespace of "." now becomes durable (weak: a file's truncation is its
 * own, made durable by its own sync, which copies its content as it is) */
static void di_commit_ns(void){ di_read_ns(di->ns, &di->nns, !di->weak); }
static void di_note(const char* what){
    if (di->nlog >= DI_LOGN) return;
    size_t n = di_strlen(what); if (n > 47) n = 47;
    memcpy(di->log[di->nlog], what, n); di->log[di->nlog][n] = 0; di->nlog++;
}
static int di_eq(const char* a, const char* b){ while (*a && *a == *b){ a++; b++; } return *a == 0 && *b == 0; }
static void di_trig_count(struct di_trig* t, const char* base){
    if (t->left > 0 && di_eq(base, t->name) && --t->left == 0) t->fire = 1;
}
/* the power is lost now: nothing later is recorded; weak keeps the live
 * namespace of this moment for the names a scenario's image keeps */
static void di_lose(void){
    di->frozen = 1; di_note("<power lost here>");
    di_read_ns(di->loss, &di->nloss, 0); di->have_loss = 1;
}
static void di_on_sigsys(int sig, siginfo_t* si, void* ctx){
    (void)sig;
    ucontext_t* uc = (ucontext_t*)ctx;
    int fd = (int)uc->uc_mcontext.gregs[REG_RDI];
    long ret = 0;
    int saved_errno = errno;            /* the interrupted code's */
    if (si->si_syscall == SYS_open){
        /* the asm's raw open: forwarded as an openat, unless it is the armed
         * open(".") that fails */
        const char* path = (const char*)uc->uc_mcontext.gregs[REG_RDI];
        long flags = (long)uc->uc_mcontext.gregs[REG_RSI], mode = (long)uc->uc_mcontext.gregs[REG_RDX];
        int fail = 0;
        while (__atomic_exchange_n(&di->lock, 1, __ATOMIC_ACQUIRE)) {}
        if (di->open_fail.fire && path[0] == '.' && path[1] == 0){ di->open_fail.fire = 0; fail = 1; di_note("<open(.) EMFILE>"); }
        __atomic_store_n(&di->lock, 0, __ATOMIC_RELEASE);
        uc->uc_mcontext.gregs[REG_RAX] = fail ? -EMFILE : syscall(SYS_openat, AT_FDCWD, path, flags, mode);
        if (!fail && (long)uc->uc_mcontext.gregs[REG_RAX] == -1) uc->uc_mcontext.gregs[REG_RAX] = -errno;
        errno = saved_errno;
        return;
    }
    while (__atomic_exchange_n(&di->lock, 1, __ATOMIC_ACQUIRE)) {}
    if (di->armed && !di->frozen){
        struct statx sx;
        if (di_statx(fd, "", AT_EMPTY_PATH, &sx) == 0){
            char lp[64], tgt[256]; char* p = di_cat(lp, "/proc/self/fd/"); di_u64(p, (unsigned long long)fd);
            long n = syscall(SYS_readlinkat, AT_FDCWD, lp, tgt, sizeof tgt - 1); if (n < 0) n = 0; tgt[n] = 0;
            const char* base = tgt; for (const char* q = tgt; *q; q++) if (*q == '/') base = q + 1;
            di->nsync++;
            if (S_ISDIR(sx.stx_mode)){
                if (di->dir_lose.fire){ di->dir_lose.fire = 0; di_lose(); }
                else if (di->dir_fail.fire){ di->dir_fail.fire = 0; di_note("<dir EIO>"); ret = -EIO; }
                else { di_note("<dir>"); di_commit_ns(); }
            } else if (S_ISREG(sx.stx_mode)){
                di_note(base);
                int r = (int)syscall(SYS_openat, AT_FDCWD, lp, O_RDONLY);
                if (r >= 0){ char k[480]; di_key(k, sx.stx_ino, (long long)sx.stx_btime.tv_sec * 1000000000LL + sx.stx_btime.tv_nsec);
                             di_copy_fd(r, k); syscall(SYS_close, r); }
                if (!di->weak) di_commit_ns();
                di_trig_count(&di->dir_fail, base); di_trig_count(&di->dir_lose, base); di_trig_count(&di->open_fail, base);
                if (di->freeze_left > 0 && di_eq(base, di->freeze_name) && --di->freeze_left == 0) di_lose();
                di_trig_count(&di->kill, base);
            }
        }
    }
    int die = di->kill.fire; if (die){ di->kill.fire = 0; di_note("<SIGKILL here>"); }
    __atomic_store_n(&di->lock, 0, __ATOMIC_RELEASE);
    if (die) syscall(SYS_kill, (long)syscall(SYS_getpid), SIGKILL);   /* the sync returned; the process dies */
    uc->uc_mcontext.gregs[REG_RAX] = ret;
    errno = saved_errno;
}
/* install in the scenario's runner (before it forks the trace's processes) */
static __attribute__((unused)) int di_install(const char* snapdir){
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
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fsync, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fdatasync, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog pr = { (unsigned short)(sizeof f / sizeof f[0]), f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &pr)) return -1;
    return 0;
}
/* start recording in the live directory (the caller's cwd): what exists now counts as durable */
static __attribute__((unused)) void di_arm(void){ di_commit_ns(); di->armed = 1; }
static __attribute__((unused)) void di_freeze_now(void){ di_lose(); }
static __attribute__((unused)) void di_freeze_after(const char* name, int k){
    size_t n = strlen(name); if (n > 63) n = 63;
    memcpy(di->freeze_name, name, n); di->freeze_name[n] = 0; di->freeze_left = k;
}
static __attribute__((unused)) void di_set_weak(void){ di->weak = 1; }
static void di_trig_set(struct di_trig* t, const char* name, int k){
    size_t n = strlen(name); if (n > 63) n = 63;
    memcpy(t->name, name, n); t->name[n] = 0; t->fire = 0; t->left = k;
}
static __attribute__((unused)) void di_fail_dir_after(const char* name, int k){ di_trig_set(&di->dir_fail, name, k); }
static __attribute__((unused)) void di_lose_dir_after(const char* name, int k){ di_trig_set(&di->dir_lose, name, k); }
static __attribute__((unused)) void di_fail_open_dot_after(const char* name, int k){ di_trig_set(&di->open_fail, name, k); }
/* SIGKILL the process right after the k-th sync of `name` returns (armed only) */
static __attribute__((unused)) void di_kill_after(const char* name, int k){ di_trig_set(&di->kill, name, k); }
static int di_cached(const char* name, const char* const* cached){
    for (int i = 0; cached && cached[i]; i++) if (!strncmp(name, cached[i], strlen(cached[i]))) return 1;
    return 0;
}
static int di_copy_path(const char* src, const char* dst){
    int s = open(src, O_RDONLY); if (s < 0) return -1;
    di_copy_fd(s, dst); close(s); return 0;
}
static void di_image_ent(const char* dst, const struct di_ent* x){
    char p[1200], k[480]; di_key(k, x->ino, x->bt);
    if (strlen(dst) + 66 > sizeof p) return;
    if (snprintf(p, sizeof p, "%s/%s", dst, x->name) >= (int)sizeof p) return;
    if (di_copy_path(k, p) != 0){ int o = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (o >= 0) close(o); }
}
/* the power-loss image of "." into dst (created); call with cwd = the live
 * directory. kept (weak mode; 0 = none): names whose state at the loss the
 * disk kept, though no directory fsync committed it. A trace that ends
 * without a loss point loses the power at its end. */
static __attribute__((unused)) int di_build_image_weak(const char* dst, const char* const* cached, const char* const* kept){
    if (mkdir(dst, 0755) != 0 && errno != EEXIST) return -1;
    char p[1200];
    if (kept && !di->have_loss){ di_read_ns(di->loss, &di->nloss, 0); di->have_loss = 1; }
    for (int i = 0; i < di->nns; i++){
        if (di_cached(di->ns[i].name, cached) || di_cached(di->ns[i].name, kept)) continue;
        di_image_ent(dst, &di->ns[i]);
    }
    for (int i = 0; kept && i < di->nloss; i++)
        if (!di_cached(di->loss[i].name, cached) && di_cached(di->loss[i].name, kept)) di_image_ent(dst, &di->loss[i]);
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
static __attribute__((unused)) int di_build_image(const char* dst, const char* const* cached){ return di_build_image_weak(dst, cached, 0); }
static __attribute__((unused)) void di_print_log(void){
    printf("  syncs in order:");
    for (int i = 0; i < di->nlog; ){
        int j = i; while (j < di->nlog && !strcmp(di->log[j], di->log[i])) j++;
        if (j - i > 1) printf(" %s(x%d)", di->log[i], j - i); else printf(" %s", di->log[i]);
        i = j;
    }
    printf("\n");
}
#endif
