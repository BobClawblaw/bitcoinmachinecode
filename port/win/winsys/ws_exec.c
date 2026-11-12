/* ws_exec.c -- execve on Windows (bmc_win).
 *
 * Windows cannot replace a process image, so execve starts the program as a
 * new process and the calling process stands in for it: it closes its
 * O_CLOEXEC fds (what the new image would not have inherited), forwards
 * terminating signals sent to it, and exits with the program's exit code,
 * so the parent's wait4 sees the status it would on Linux. posix_spawn,
 * system and popen are built on fork + execve (rt/spawn.c).
 *
 * The program gets fds 0, 1 and 2 as its standard handles. "/bin/sh -c
 * CMD" runs CMD through %ComSpec% ("cmd /d /s /c"), as Bitcoin Core does on
 * Windows for its -*notify commands. A path without ".exe" is tried with it.
 * A forked (cloned) process cannot call CreateProcess itself; the root
 * process creates the program for it (ws_broker.c, OP_SPAWN). */
#include "winsys.h"

#define L_AT_FDCWD (-100)

/* ---- command line (the quoting CommandLineToArgvW undoes) ---- */
typedef struct { wchar_t *p; size_t n, cap; } wbuf;

static int wput(wbuf *b, wchar_t c)
{
	if (b->n + 2 > b->cap) {
		size_t cap = b->cap ? b->cap * 2 : 256;
		wchar_t *np = ws_alloc(cap * sizeof(wchar_t));
		if (!np)
			return -1;
		if (b->p)
			__ws_memcpy(np, b->p, b->n * sizeof(wchar_t));
		ws_free(b->p);
		b->p = np;
		b->cap = cap;
	}
	b->p[b->n++] = c;
	b->p[b->n] = 0;
	return 0;
}

static void wputs(wbuf *b, const wchar_t *s)
{
	while (*s)
		wput(b, *s++);
}

static void quote_arg(wbuf *b, const wchar_t *a)
{
	int plain = *a != 0;
	for (const wchar_t *p = a; *p; p++)
		if (*p == L' ' || *p == L'\t' || *p == L'"' || *p == L'\n' || *p == L'\v')
			plain = 0;
	if (plain) {
		wputs(b, a);
		return;
	}
	wput(b, L'"');
	for (const wchar_t *p = a;; p++) {
		size_t bs = 0;
		while (*p == L'\\') {
			bs++;
			p++;
		}
		if (!*p) {
			for (size_t i = 0; i < bs * 2; i++)
				wput(b, L'\\');
			break;
		}
		if (*p == L'"') {
			for (size_t i = 0; i < bs * 2 + 1; i++)
				wput(b, L'\\');
		} else {
			for (size_t i = 0; i < bs; i++)
				wput(b, L'\\');
		}
		wput(b, *p);
	}
	wput(b, L'"');
}

static int is_shell(const char *path)
{
	size_t l = ws_strlen(path);
	return (l >= 2 && path[l - 2] == 's' && path[l - 1] == 'h' && (l == 2 || path[l - 3] == '/')) ||
	       !__ws_memcmp(path, "/bin/sh", 8) || !__ws_memcmp(path, "/bin/bash", 10);
}

/* the program to run and its command line; NULL + *err on failure */
/* BMC_WIN_SH=<a POSIX sh.exe> (Git for Windows' bin\sh.exe, say): /bin/sh
 * and #! scripts run under it, with their arguments as given. Unset, a
 * "sh -c" command goes to cmd.exe (an operator's -*notify line on Windows) */
static wchar_t *posix_sh(void)
{
	wchar_t p[MAX_PATH];
	DWORD l = GetEnvironmentVariableW(L"BMC_WIN_SH", p, MAX_PATH);
	if (!l || l >= MAX_PATH)
		return NULL;
	wchar_t *r = ws_alloc((l + 1) * sizeof(wchar_t));
	if (r)
		__ws_memcpy(r, p, (l + 1) * sizeof(wchar_t));
	return r;
}

static void args_tail(wbuf *cmd, char *const argv[], int from)
{
	for (int i = from; argv[i]; i++) {
		wchar_t *aw = ws_utf8_to_w(argv[i]);
		if (!aw)
			continue;
		wput(cmd, L' ');
		quote_arg(cmd, aw);
		ws_free(aw);
	}
}

static int has_shebang(const wchar_t *w)
{
	HANDLE h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			       OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return 0;
	char b[2] = { 0, 0 };
	DWORD got = 0;
	ReadFile(h, b, 2, &got, NULL);
	CloseHandle(h);
	return got == 2 && b[0] == '#' && b[1] == '!';
}

static wchar_t *resolve(const char *path, char *const argv[], wbuf *cmd, i64 *err)
{
	if (is_shell(path)) {
		wchar_t *sh = posix_sh();
		if (sh) {
			wputs(cmd, L"sh");
			args_tail(cmd, argv, 1);
			return sh;
		}
	}
	if (is_shell(path) && argv[0] && argv[1] && argv[1][0] == '-' && argv[1][1] == 'c' && !argv[1][2] && argv[2]) {
		wchar_t comspec[MAX_PATH];
		if (!GetEnvironmentVariableW(L"ComSpec", comspec, MAX_PATH))
			__ws_memcpy(comspec, L"C:\\Windows\\System32\\cmd.exe", 28 * sizeof(wchar_t));
		wchar_t *c = ws_utf8_to_w(argv[2]);
		if (!c) {
			*err = -L_ENOMEM;
			return NULL;
		}
		wputs(cmd, L"cmd /d /s /c \"");
		wputs(cmd, c);
		wput(cmd, L'"');
		ws_free(c);
		size_t l = ws_wcslen(comspec);
		wchar_t *app = ws_alloc((l + 1) * sizeof(wchar_t));
		__ws_memcpy(app, comspec, (l + 1) * sizeof(wchar_t));
		return app;
	}
	wchar_t *w = ws_path(L_AT_FDCWD, path, err);
	if (!w)
		return NULL;
	DWORD a = GetFileAttributesW(w);
	if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY)) {
		size_t l = ws_wcslen(w);
		wchar_t *x = ws_alloc((l + 5) * sizeof(wchar_t));
		__ws_memcpy(x, w, l * sizeof(wchar_t));
		__ws_memcpy(x + l, L".exe", 5 * sizeof(wchar_t));
		ws_free(w);
		w = x;
		a = GetFileAttributesW(w);
		if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY)) {
			/* BMC_WIN_BINDIR: the port's binaries live in its out/bin, not
			 * beside the sources the tests name (daemon/bmc_cli); a missing
			 * program is looked up there by its base name */
			wchar_t dir[MAX_PATH];
			DWORD dl = GetEnvironmentVariableW(L"BMC_WIN_BINDIR", dir, MAX_PATH);
			const wchar_t *base = x + l;
			while (base > x && base[-1] != L'\\' && base[-1] != L'/')
				base--;
			size_t bl = ws_wcslen(base);
			if (dl && dl < MAX_PATH && dl + bl + 2 < MAX_PATH) {
				wchar_t *y = ws_alloc((dl + bl + 2) * sizeof(wchar_t));
				__ws_memcpy(y, dir, dl * sizeof(wchar_t));
				y[dl] = L'\\';
				__ws_memcpy(y + dl + 1, base, (bl + 1) * sizeof(wchar_t));
				DWORD b = GetFileAttributesW(y);
				if (b != INVALID_FILE_ATTRIBUTES && !(b & FILE_ATTRIBUTE_DIRECTORY)) {
					ws_free(w);
					w = y;
					a = b;
				} else {
					ws_free(y);
				}
			}
		}
		if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY)) {
			ws_free(w);
			*err = a == INVALID_FILE_ATTRIBUTES ? -L_ENOENT : -L_EACCES;
			return NULL;
		}
	}
	if (has_shebang(w)) {                  /* a script: the POSIX shell runs it, or nothing can */
		wchar_t *sh = posix_sh();
		if (!sh) {
			ws_free(w);
			*err = -L_ENOEXEC;
			return NULL;
		}
		wchar_t *pw = ws_utf8_to_w(path);
		wputs(cmd, L"sh ");
		quote_arg(cmd, pw ? pw : w);
		ws_free(pw);
		args_tail(cmd, argv, 1);
		ws_free(w);
		return sh;
	}
	for (int i = 0; argv[i]; i++) {
		wchar_t *aw = ws_utf8_to_w(argv[i]);
		if (!aw)
			continue;
		if (i)
			wput(cmd, L' ');
		quote_arg(cmd, aw);
		ws_free(aw);
	}
	if (!cmd->n)
		quote_arg(cmd, w);
	return w;
}

static wchar_t *env_block(char *const envp[], size_t *chars)
{
	wbuf b = { 0 };
	for (int i = 0; envp && envp[i]; i++) {
		wchar_t *w = ws_utf8_to_w(envp[i]);
		if (!w)
			continue;
		wputs(&b, w);
		wput(&b, 0);
		ws_free(w);
	}
	char *sc = ws_seccomp_env();                   /* seccomp filters survive execve */
	if (sc) {
		wchar_t *w = ws_utf8_to_w(sc);
		if (w) {
			wputs(&b, w);
			wput(&b, 0);
			ws_free(w);
		}
		ws_free(sc);
	}
	wput(&b, 0);
	if (b.n == 1)
		wput(&b, 0);
	*chars = b.n;
	return b.p;
}

/* create the process; std handles valid in *this* process. Returns the
 * process handle (pid in *pid) or NULL with *err. */
HANDLE ws_spawn_local(const wchar_t *app, wchar_t *cmdline, const wchar_t *env, const wchar_t *cwd,
		      HANDLE std[3], DWORD *pid, i64 *err)
{
	HANDLE inh[3] = { NULL, NULL, NULL }, list[3];
	int nl = 0;
	for (int i = 0; i < 3; i++) {
		if (std[i] && std[i] != INVALID_HANDLE_VALUE)
			DuplicateHandle(GetCurrentProcess(), std[i], GetCurrentProcess(), &inh[i], 0, TRUE,
					DUPLICATE_SAME_ACCESS);
		if (inh[i])
			list[nl++] = inh[i];
	}
	SIZE_T asz = 0;
	InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
	LPPROC_THREAD_ATTRIBUTE_LIST al = ws_alloc(asz);
	InitializeProcThreadAttributeList(al, 1, 0, &asz);
	if (nl)
		UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, sizeof(HANDLE) * (size_t)nl,
					  NULL, NULL);
	STARTUPINFOEXW si;
	__ws_memset(&si, 0, sizeof si);
	si.StartupInfo.cb = sizeof si;
	si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
	si.StartupInfo.hStdInput = inh[0];
	si.StartupInfo.hStdOutput = inh[1];
	si.StartupInfo.hStdError = inh[2];
	si.lpAttributeList = al;
	PROCESS_INFORMATION pi;
	BOOL ok = CreateProcessW(app, cmdline, NULL, NULL, nl ? TRUE : FALSE,
				 EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT, (LPVOID)env, cwd,
				 &si.StartupInfo, &pi);
	DWORD e = ok ? 0 : GetLastError();
	DeleteProcThreadAttributeList(al);
	ws_free(al);
	for (int i = 0; i < 3; i++)
		if (inh[i])
			CloseHandle(inh[i]);
	if (!ok) {
		*err = e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND ? -L_ENOENT
		       : e == ERROR_BAD_EXE_FORMAT ? -L_ENOEXEC : ws_err(e);
		return NULL;
	}
	CloseHandle(pi.hThread);
	*pid = pi.dwProcessId;
	return pi.hProcess;
}

static HANDLE fd_handle(int fd, HANDLE *tmp)
{
	ws_desc *d = ws_fd_get(fd);
	HANDLE h = NULL;
	if (!d)
		return NULL;
	if (d->type == FT_SOCKET)
		h = (HANDLE)d->s;
	else if (d->type == FT_NULL || d->type == FT_RANDOM)
		h = *tmp = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
				       OPEN_EXISTING, 0, NULL);
	else
		h = fd > 0 && d->hout ? d->hout : d->h;   /* /dev/tty as stdout/stderr: its CONOUT$ */
	ws_desc_put(d);
	return h;
}

void ws_fd_close_on_exec(void);
HANDLE ws_broker_spawn(const wchar_t *app, const wchar_t *cmdline, const wchar_t *env, size_t env_chars,
		       const wchar_t *cwd, HANDLE std[3], DWORD *pid, i64 *err);

static i64 sys_execve(const char *path, char *const argv[], char *const envp[])
{
	i64 err = 0;
	wbuf cmd = { 0 };
	wchar_t *app = resolve(path, argv, &cmd, &err);
	if (!app) {
		ws_free(cmd.p);
		return err;
	}
	size_t env_chars = 0;
	wchar_t *env = env_block(envp, &env_chars);
	DWORD cn = GetCurrentDirectoryW(0, NULL);
	wchar_t *cwd = ws_alloc((cn + 1) * sizeof(wchar_t));
	GetCurrentDirectoryW(cn + 1, cwd);
	HANDLE tmp[3] = { NULL, NULL, NULL }, std[3];
	for (int i = 0; i < 3; i++)
		std[i] = fd_handle(i, &tmp[i]);
	DWORD pid = 0;
	HANDLE proc = ws_is_root ? ws_spawn_local(app, cmd.p, env, cwd, std, &pid, &err)
				 : ws_broker_spawn(app, cmd.p, env, env_chars, cwd, std, &pid, &err);
	for (int i = 0; i < 3; i++)
		if (tmp[i])
			CloseHandle(tmp[i]);
	ws_free(app);
	ws_free(cmd.p);
	ws_free(env);
	ws_free(cwd);
	if (!proc)
		return err;
	/* the point of no return: we are now the program's stand-in */
	ws_fd_close_on_exec();
	for (;;) {
		int w = ws_wait(&proc, 1, INFINITE);
		if (w == 0)
			break;
		if (w == WS_WAIT_INTR) {
			/* we stand in for the program: what is sent to us is meant for
			 * it -- delivered as a signal (it handles SIGTERM its own way),
			 * or, for a program without winsys, as termination */
			int sig;
			while ((sig = ws_sig_take_pending()) > 0)
				ws_kill_other((int)GetProcessId(proc), sig);
		}
	}
	DWORD code = 0;
	GetExitCodeProcess(proc, &code);
	ws_exit_process(code);
}

i64 ws_sys_exec(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	(void)a4;
	(void)a5;
	(void)a6;
	*handled = 1;
	switch (n) {
	case 59: return sys_execve((const char *)a1, (char *const *)a2, (char *const *)a3);
	default:
		*handled = 0;
		return 0;
	}
}
