/* ws_entry.c -- process entry, PE TLS directory, constructors and the syscall
 * dispatcher (bmc_win). */
#include "winsys.h"
#include <shellapi.h>

/* ---- PE TLS directory (what the MSVC CRT's tlssup.obj would provide) ----
 * The loader copies [_tls_start, _tls_end) into each new thread's block.
 * Variables land in ".tls$" (compiler) and ".tls$BMC" (assembly), which the
 * linker sorts between ".tls" and ".tls$ZZZ". The EXE's index is always 0;
 * the assembly's TLS_ADDR relies on that and ws_check_tls() asserts it. */
ULONG _tls_index = 0;
__attribute__((section(".tls"))) char _tls_start = 0;
__attribute__((section(".tls$ZZZ"))) char _tls_end = 0;
__attribute__((section(".CRT$XLA"))) PIMAGE_TLS_CALLBACK __xl_a = 0;
__attribute__((section(".CRT$XLZ"))) PIMAGE_TLS_CALLBACK __xl_z = 0;
const IMAGE_TLS_DIRECTORY64 _tls_used = {
	(ULONGLONG)&_tls_start, (ULONGLONG)&_tls_end, (ULONGLONG)&_tls_index,
	(ULONGLONG)(&__xl_a + 1), 0, { 0 }
};

/* ---- constructors: clang puts the SysV side's llvm.global_ctors here ---- */
typedef SV void (*ws_ctor)(void);
__attribute__((section(".CRT$XCA"))) ws_ctor __xc_a = 0;
__attribute__((section(".CRT$XCZ"))) ws_ctor __xc_z = 0;

WSAPI void __bmc_win_run_ctors(void)
{
	for (ws_ctor *p = &__xc_a + 1; p < &__xc_z; p++)
		if (*p)
			(*p)();
}

char **ws_envp;

/* argv from the UTF-16 command line, as UTF-8 */
static char **build_argv(int *argc_out)
{
	int argc = 0;
	wchar_t **wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
	char **argv = ws_alloc(sizeof(char *) * (size_t)(argc + 1));
	for (int i = 0; i < argc; i++)
		argv[i] = ws_w_to_utf8(wargv[i]);
	argv[argc] = NULL;
	LocalFree(wargv);
	*argc_out = argc;
	return argv;
}

static char **build_envp(void)
{
	wchar_t *blk = GetEnvironmentStringsW();
	size_t n = 0;
	for (wchar_t *p = blk; *p; p += ws_wcslen(p) + 1)
		n++;
	char **envp = ws_alloc(sizeof(char *) * (n + 1));
	size_t i = 0;
	for (wchar_t *p = blk; *p; p += ws_wcslen(p) + 1) {
		if (*p == L'=')           /* the hidden "=C:=C:\..." drive entries */
			continue;
		envp[i++] = ws_w_to_utf8(p);
	}
	envp[i] = NULL;
	FreeEnvironmentStringsW(blk);
	return envp;
}

static void ws_check_tls(void)
{
	if (_tls_index != 0)
		ws_fatal("PE TLS index is not 0 (assembly TLS_ADDR assumes it)");
}

typedef SV int (*ws_start_fn)(int, char **, char **);
SV int __bmc_start(int argc, char **argv, char **envp);

/* PE entry point (/entry:__bmc_win_entry) */
WSAPI void __bmc_win_entry(void)
{
	ws_check_tls();
	extern uintptr_t __security_cookie;
	extern i64 ws_getrandom(void *buf, size_t n);
	uintptr_t ck;
	if (ws_getrandom(&ck, sizeof ck) == sizeof ck && ck)
		__security_cookie = ck & 0x0000FFFFFFFFFFFFULL;
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	SetConsoleOutputCP(CP_UTF8);
	ws_sig_init();
	ws_fork_init();
	ws_fd_init();
	ws_net_init();
	int argc;
	char **argv = build_argv(&argc);
	ws_envp = build_envp();
	ws_start_fn start = __bmc_start;
	ws_exit_process((UINT)start(argc, argv, ws_envp));
}

/* ---- the syscall dispatcher ---- */
static volatile LONG warned[512];

static i64 dispatch(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6)
{
	int handled = 0;
	i64 r;
	r = ws_sys_file(n, a1, a2, a3, a4, a5, a6, &handled);
	if (handled)
		return r;
	r = ws_sys_mem(n, a1, a2, a3, a4, a5, a6, &handled);
	if (handled)
		return r;
	r = ws_sys_exec(n, a1, a2, a3, a4, a5, a6, &handled);
	if (handled)
		return r;
	r = ws_sys_fork(n, a1, a2, a3, a4, a5, a6, &handled);
	if (handled)
		return r;
	r = ws_sys_time(n, a1, a2, a3, a4, a5, a6, &handled);
	if (handled)
		return r;
	r = ws_sys_sig(n, a1, a2, a3, a4, a5, a6, &handled);
	if (handled)
		return r;
	r = ws_sys_thread(n, a1, a2, a3, a4, a5, a6, &handled);
	if (handled)
		return r;
	r = ws_sys_net(n, a1, a2, a3, a4, a5, a6, &handled);
	if (handled)
		return r;
	if (n >= 0 && n < 512 && !InterlockedExchange(&warned[n], 1) &&
	    GetEnvironmentVariableA("BMC_WIN_TRACE_ENOSYS", NULL, 0)) {
		char buf[32];
		ws_fmt_u64(buf, (u64)n);
		ws_write_stderr("bmc_win: unemulated syscall ");
		ws_write_stderr(buf);
		ws_write_stderr("\n");
	}
	return -L_ENOSYS;
}

/* Signals pending for this thread are handled on the way out of a syscall;
 * an interrupted call whose handlers all have SA_RESTART runs again. */
WSAPI i64 __bmc_win_syscall(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6)
{
	for (;;) {
		i64 r = dispatch(n, a1, a2, a3, a4, a5, a6);
		if (!ws_sig_pending_here())
			return r;
		int restart;
		r = ws_sig_deliver(r, &restart);
		if (!restart)
			return r;
	}
}
