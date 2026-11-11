/* ws_entry.c -- process entry, PE TLS directory, constructors and the syscall
 * dispatcher (bmc_win). */
#include "winsys.h"

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
/* The command line split as CommandLineToArgvW does (the MSVC rules: the
 * program name ends at the first space or its closing quote; then 2n
 * backslashes + quote -> n backslashes and a quote toggle, 2n+1 -> n and a
 * literal quote, "" inside quotes -> a literal quote). Done here because
 * CommandLineToArgvW lives in shell32, which loads user32 and imm32, whose
 * thread-attach code faults in a forked (cloned) process. */
static char **build_argv(int *argc_out)
{
	const wchar_t *cl = GetCommandLineW();
	size_t len = ws_wcslen(cl);
	wchar_t *buf = ws_alloc((len + 2) * sizeof(wchar_t));
	char **argv = ws_alloc(sizeof(char *) * (len / 2 + 2));
	int argc = 0;
	const wchar_t *p = cl;
	/* argv[0] */
	wchar_t *o = buf;
	if (*p == L'"') {
		p++;
		while (*p && *p != L'"')
			*o++ = *p++;
		if (*p == L'"')
			p++;
	} else {
		while (*p && *p != L' ' && *p != L'\t')
			*o++ = *p++;
	}
	*o = 0;
	argv[argc++] = ws_w_to_utf8(buf);
	for (;;) {
		while (*p == L' ' || *p == L'\t')
			p++;
		if (!*p)
			break;
		o = buf;
		int inq = 0;
		while (*p && (inq || (*p != L' ' && *p != L'\t'))) {
			size_t bs = 0;
			while (*p == L'\\') {
				bs++;
				p++;
			}
			if (*p == L'"') {
				for (size_t i = 0; i < bs / 2; i++)
					*o++ = L'\\';
				if (bs & 1) {
					*o++ = L'"';
					p++;
				} else if (inq && p[1] == L'"') {
					*o++ = L'"';
					p += 2;
				} else {
					inq = !inq;
					p++;
				}
			} else {
				for (size_t i = 0; i < bs; i++)
					*o++ = L'\\';
				if (*p && (inq || (*p != L' ' && *p != L'\t')))
					*o++ = *p++;
			}
		}
		*o = 0;
		argv[argc++] = ws_w_to_utf8(buf);
	}
	argv[argc] = NULL;
	ws_free(buf);
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

/* BMC_WIN_STRACE=1: every syscall to stderr as "[pid] nr(a1, a2, a3) = r",
 * with path arguments of the common file calls shown as strings */
static int strace_on = -1;

static void hex64(char *o, u64 v)
{
	char t[17];
	int i = 0;
	do {
		t[i++] = "0123456789abcdef"[v & 15];
		v >>= 4;
	} while (v);
	*o++ = '0';
	*o++ = 'x';
	while (i)
		*o++ = t[--i];
	*o = 0;
}

static void strace_line(i64 n, i64 a1, i64 a2, i64 a3, i64 r)
{
	char line[512], num[24];
	size_t k = 0;
#define PUT(s) do { const char *s_ = (s); while (*s_ && k < sizeof line - 2) line[k++] = *s_++; } while (0)
	PUT("[");
	ws_fmt_u64(num, GetCurrentProcessId());
	PUT(num);
	PUT("] ");
	ws_fmt_u64(num, (u64)n);
	PUT(num);
	PUT("(");
	int path1 = n == 2 || n == 4 || n == 6 || n == 21 || n == 83 || n == 84 || n == 87 || n == 82 || n == 80;
	int path2 = n == 257 || n == 262 || n == 263 || n == 258 || n == 269;
	i64 args[3] = { a1, a2, a3 };
	for (int i = 0; i < 3; i++) {
		if (i)
			PUT(", ");
		if ((path1 && i == 0) || (path2 && i == 1)) {
			PUT("\"");
			const char *s = (const char *)args[i];
			for (int j = 0; s && s[j] && j < 160; j++) {
				char c[2] = { s[j], 0 };
				PUT(c);
			}
			PUT("\"");
		} else if (args[i] < 0 && args[i] > -4096) {
			PUT("-");
			ws_fmt_u64(num, (u64)-args[i]);
			PUT(num);
		} else if ((u64)args[i] > 0xffff) {
			hex64(num, (u64)args[i]);
			PUT(num);
		} else {
			ws_fmt_u64(num, (u64)args[i]);
			PUT(num);
		}
	}
	PUT(") = ");
	if (r < 0 && r > -4096) {
		PUT("-");
		ws_fmt_u64(num, (u64)-r);
	} else if ((u64)r > 0xffff) {
		hex64(num, (u64)r);
	} else {
		ws_fmt_u64(num, (u64)r);
	}
	PUT(num);
	PUT("\n");
#undef PUT
	line[k] = 0;
	/* BMC_WIN_STRACE_LOG=<file>: append there instead of to stderr (whose
	 * fd 2 may be the very pipe under study) */
	static HANDLE logh;
	if (!logh) {
		wchar_t p[MAX_PATH];
		DWORD l = GetEnvironmentVariableW(L"BMC_WIN_STRACE_LOG", p, MAX_PATH);
		logh = l && l < MAX_PATH ? CreateFileW(p, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
						      OPEN_ALWAYS, 0, NULL) : INVALID_HANDLE_VALUE;
	}
	if (logh != INVALID_HANDLE_VALUE) {
		DWORD w;
		WriteFile(logh, line, (DWORD)k, &w, NULL);
	} else {
		ws_write_stderr(line);
	}
}

/* Signals pending for this thread are handled on the way out of a syscall;
 * an interrupted call whose handlers all have SA_RESTART runs again. */
WSAPI i64 __bmc_win_syscall(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6)
{
	if (strace_on < 0) {
		char v[4] = "";
		strace_on = GetEnvironmentVariableA("BMC_WIN_STRACE", v, sizeof v) ? (v[0] == '2' ? 2 : 1) : 0;
	}
	ws_prof_count(n);
	for (;;) {
		if (strace_on == 2)                 /* BMC_WIN_STRACE=2: calls as they start, too */
			strace_line(n, a1, a2, a3, -4095);
		i64 r = dispatch(n, a1, a2, a3, a4, a5, a6);
		if (strace_on)                  /* the trace itself writes with WriteFile, not a syscall */
			strace_line(n, a1, a2, a3, r);
		if (!ws_sig_pending_here())
			return r;
		int restart;
		r = ws_sig_deliver(r, &restart);
		if (!restart)
			return r;
	}
}
