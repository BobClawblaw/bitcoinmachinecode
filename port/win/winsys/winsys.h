/* winsys.h -- Linux x86_64 syscall emulation on Win32 (bmc_win).
 *
 * winsys is the only Win64-ABI code in a bmc_win binary. Everything above it
 * (musl, rt, the bmc C and assembly) is SysV/LP64 and talks to it through
 * __bmc_win_syscall (Linux numbers, Linux argument/struct layouts, -errno
 * results) and a few ms_abi helpers declared below. No C runtime is linked:
 * this code uses Win32 only, and its compiler-emitted mem* calls are renamed
 * to the __ws_ copies at build time (build.py WINSYS_RENAMES). */
#ifndef BMC_WINSYS_H
#define BMC_WINSYS_H

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include "ws_ws2.h"

#define SV __attribute__((sysv_abi))
#define WSAPI __attribute__((ms_abi))

typedef int64_t i64;
typedef uint64_t u64;

/* ---- Linux errno values (x86_64) ---- */
enum {
	L_EPERM = 1, L_ENOENT = 2, L_ESRCH = 3, L_EINTR = 4, L_EIO = 5, L_ENXIO = 6, L_E2BIG = 7,
	L_ENOEXEC = 8, L_EBADF = 9, L_ECHILD = 10, L_EAGAIN = 11, L_ENOMEM = 12, L_EACCES = 13,
	L_EFAULT = 14, L_EBUSY = 16, L_EEXIST = 17, L_EXDEV = 18, L_ENODEV = 19, L_ENOTDIR = 20,
	L_EISDIR = 21, L_EINVAL = 22, L_ENFILE = 23, L_EMFILE = 24, L_ENOTTY = 25, L_EFBIG = 27,
	L_ENOSPC = 28, L_ESPIPE = 29, L_EROFS = 30, L_EMLINK = 31, L_EPIPE = 32, L_ERANGE = 34,
	L_EDEADLK = 35, L_ENAMETOOLONG = 36, L_ENOLCK = 37, L_ENOSYS = 38, L_ENOTEMPTY = 39,
	L_ELOOP = 40, L_ENOTSOCK = 88, L_EDESTADDRREQ = 89, L_EMSGSIZE = 90, L_EPROTOTYPE = 91,
	L_ENOPROTOOPT = 92, L_EPROTONOSUPPORT = 93, L_EOPNOTSUPP = 95, L_EAFNOSUPPORT = 97,
	L_EADDRINUSE = 98, L_EADDRNOTAVAIL = 99, L_ENETDOWN = 100, L_ENETUNREACH = 101,
	L_ECONNABORTED = 103, L_ECONNRESET = 104, L_ENOBUFS = 105, L_EISCONN = 106,
	L_ENOTCONN = 107, L_ETIMEDOUT = 110, L_ECONNREFUSED = 111, L_EHOSTDOWN = 112,
	L_EHOSTUNREACH = 113, L_EALREADY = 114, L_EINPROGRESS = 115, L_ECANCELED = 125,
};

/* ---- ws_util.c ---- */
void *__ws_memcpy(void *d, const void *s, size_t n);
void *__ws_memset(void *d, int c, size_t n);
void *__ws_memmove(void *d, const void *s, size_t n);
int __ws_memcmp(const void *a, const void *b, size_t n);
size_t ws_strlen(const char *s);
size_t ws_wcslen(const wchar_t *s);
void *ws_alloc(size_t n);          /* process heap, zeroed */
void ws_free(void *p);
/* UTF-8 <-> UTF-16; results from ws_alloc */
wchar_t *ws_utf8_to_w(const char *s);
char *ws_w_to_utf8(const wchar_t *w);
i64 ws_err(DWORD e);              /* GetLastError() value -> -Linux errno */
i64 ws_wsaerr(int e);             /* WSAGetLastError() value -> -Linux errno */
void ws_write_stderr(const char *s);
void ws_fatal(const char *msg) __attribute__((noreturn));
void ws_fmt_u64(char *buf, u64 v);

/* ---- ws_path.c ---- */
/* Linux path (UTF-8, relative to dirfd) -> Windows path (UTF-16, ws_alloc'd).
 * Returns NULL and sets *err on failure. */
wchar_t *ws_path(int dirfd, const char *path, i64 *err);

/* ---- ws_fd.c ---- */
enum { FT_FREE = 0, FT_FILE, FT_DIR, FT_CONSOLE, FT_PIPE, FT_NULL, FT_RANDOM, FT_SOCKET,
       FT_MEM, FT_MEMDIR };  /* /proc files and directories built at open (ws_procfs.c) */
typedef struct ws_desc {
	volatile LONG refs;
	int type;
	int flags;            /* Linux O_* status flags (O_APPEND, O_NONBLOCK, access mode) */
	HANDLE h;
	SOCKET s;
	i64 off;              /* file offset (we always do positioned I/O) */
	SRWLOCK lock;
	wchar_t *wpath;       /* for directories / fstat fallbacks / openat */
	HANDLE find;          /* directory enumeration */
	int find_state;       /* 0 = not started, 1 = entry pending, 2 = done */
	WIN32_FIND_DATAW fd;
	i64 dir_pos;
	int flock_held;        /* flock: 0 none, 1 shared, 2 exclusive */
	DWORD rcvtimeo, sndtimeo;  /* sockets: SO_RCVTIMEO / SO_SNDTIMEO in ms, 0 = none */
	struct sockaddr_storage peer;  /* sockets: the address connected to / accepted from */
	int peerlen;
	volatile LONG connected;   /* sockets: the connection is known to be up */
	char *mem;                 /* FT_MEM: the content; FT_MEMDIR: NUL-separated names */
	u64 pair_key;              /* sockets from socketpair: the pair (SCM_RIGHTS escrow key) */
	int pair_side;             /* ...and which end this is (0/1) */
	volatile u64 last_rx_ms, last_tx_ms, since_ms;   /* sockets: TCP_INFO's last_data_* */
	u64 memlen;
} ws_desc;
void ws_fd_init(void);
ws_desc *ws_fd_get(int fd);       /* +1 ref, NULL if not open */
void ws_desc_put(ws_desc *d);
int ws_fd_install(ws_desc *d, int cloexec, int min_fd); /* consumes the ref; -EMFILE */
ws_desc *ws_desc_new(int type);
i64 ws_sys_file(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled);

/* ---- ws_mem.c ---- */
i64 ws_sys_mem(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled);

/* ---- ws_net.c ---- */
i64 ws_sys_net(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled);
void ws_net_init(void);
i64 ws_sock_read(ws_desc *d, void *buf, size_t n);
i64 ws_sock_write(ws_desc *d, const void *buf, size_t n);
i64 ws_sock_nread(ws_desc *d);

/* ---- ws_thread.c ---- */
i64 ws_sys_thread(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled);

/* ---- ws_time.c ---- */
i64 ws_sys_time(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled);

/* ---- ws_sig.c ---- */
enum { WS_WAIT_TIMEOUT = -1, WS_WAIT_INTR = -2, WS_WAIT_FAILED = -3 };
/* wait on hs[0..n) and this thread's signal event: index, or WS_WAIT_* */
int ws_wait(const HANDLE *hs, int n, DWORD ms);
void ws_sig_init(void);
void ws_sig_thread_start(int is_main);
void ws_sig_thread_end(void);
int ws_sig_pending_here(void);
i64 ws_sig_deliver(i64 r, int *restart);
void ws_sig_futex_begin(volatile void *addr);
int ws_sig_futex_end(void);
void ws_sig_sync_io(int on);
int ws_sig_raise_process(int sig, int code);
i64 ws_sig_kill_self(int sig);
u64 ws_sig_current_mask(void);
void ws_sig_thread_inherit_mask(u64 m);
i64 ws_sys_sig(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled);

/* ---- ws_procfs.c ---- */
ws_desc *ws_procfs_open(const char *path, i64 *err);
i64 ws_procfs_readlink(const char *path, char *buf, size_t cap);
char *ws_path_to_posix(const wchar_t *w);
void ws_sbuf_hex(void *b, u64 v, int width);
void ws_sbuf_str(void *b, const char *s);
void ws_sbuf_dec(void *b, u64 v);

/* ---- ws_fork.c ---- */
extern int ws_is_root;             /* 0 in a forked (cloned) process */
void ws_fork_init(void);
void ws_broker_start(void);
void ws_broker_child(void);
/* the private heap (ws_util.c) */
HANDLE ws_heap(void);
void ws_heap_lock(void);
void ws_heap_unlock(void);
void ws_heap_reset_child(void);
void *ws_heap_alloc(size_t n, int zero);
void *ws_heap_realloc(void *p, size_t n);
void ws_heap_free(void *p);
size_t ws_heap_size(void *p);
/* SCM_RIGHTS escrow (ws_broker.c): what a passed descriptor carries */
typedef struct {
	int type, flags;
	DWORD rcvtimeo, sndtimeo;
	int peerlen, connected;
	struct sockaddr_storage peer;
	u64 pair_key;
	int pair_side;
	wchar_t path[300];
} ws_fd_meta;
int ws_escrow_put(u64 key, int side, HANDLE h, const ws_fd_meta *meta);
int ws_escrow_take(u64 key, int side, HANDLE *hs, ws_fd_meta *metas, int max);
HANDLE ws_create_thread(LPTHREAD_START_ROUTINE fn, void *arg, size_t stack, DWORD *tid);
void ws_threads_settle(void);
void ws_futex_shared_init(void);
void ws_robust_release_current_thread(void);
void ws_futex_wake_any(volatile int *addr, int n);
void ws_robust_release_all(void);
int ws_sig_take_pending(void);
i64 ws_sys_exec(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled);
i64 ws_sys_fork(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled);
i64 ws_kill_other(int pid, int sig);
void ws_exit_process(UINT code) __attribute__((noreturn));
int ws_sig_disposition(int sig);
void ws_exit_signaled(int sig) __attribute__((noreturn));

/* ---- entry points used by the SysV side (ms_abi there) ---- */
WSAPI i64 __bmc_win_syscall(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6);
WSAPI void *__bmc_win_heap_alloc(size_t n, int zero);
WSAPI void *__bmc_win_heap_realloc(void *p, size_t n);
WSAPI void __bmc_win_heap_free(void *p);
WSAPI size_t __bmc_win_heap_size(void *p);
typedef SV void *(*ws_thread_fn)(void *);
WSAPI i64 __bmc_win_thread_create(ws_thread_fn fn, void *arg, size_t stack, void **handle_out, int *tid_out);
WSAPI i64 __bmc_win_thread_join(void *handle);
WSAPI void __bmc_win_thread_close(void *handle);
WSAPI void __bmc_win_run_ctors(void);

extern char **ws_envp;

#endif
