/* ws_procfs.c -- the parts of Linux /proc bmc reads (bmc_win).
 *
 * Opening a /proc path builds the file's text at open time into a memory
 * descriptor (FT_MEM; FT_MEMDIR for the directories), in the Linux format:
 *   /proc/meminfo                  GlobalMemoryStatusEx
 *   /proc/self|<pid>/stat          state, flags, times, threads, vsize, rss
 *   /proc/self|<pid>/statm, io, comm, wchan, syscall
 *   /proc/self/maps, smaps, smaps_rollup   the mmap region table (ws_mem.c)
 *   /proc/<pid>/task/, task/<tid>/stat     the process's threads
 *   /proc/self/fd/                 our fd table; readlink of fd/N, exe
 * Another process's fd table is not visible (ENOENT), as for an unprivileged
 * reader of a foreign process on Linux. */
#include "winsys.h"
#include <psapi.h>
#include <tlhelp32.h>

typedef struct { char *p; u64 n, cap; } sbuf;

static void sput(sbuf *b, const char *s)
{
	u64 l = ws_strlen(s);
	if (b->n + l + 1 > b->cap) {
		u64 cap = b->cap ? b->cap * 2 : 4096;
		while (cap < b->n + l + 1)
			cap *= 2;
		char *np = ws_alloc((size_t)cap);
		if (!np)
			return;
		if (b->p)
			__ws_memcpy(np, b->p, (size_t)b->n);
		ws_free(b->p);
		b->p = np;
		b->cap = cap;
	}
	__ws_memcpy(b->p + b->n, s, (size_t)l + 1);
	b->n += l;
}

static void sputu(sbuf *b, u64 v)
{
	char t[24];
	ws_fmt_u64(t, v);
	sput(b, t);
}

static void sputi(sbuf *b, i64 v)
{
	if (v < 0) {
		sput(b, "-");
		v = -v;
	}
	sputu(b, (u64)v);
}

static void sputx(sbuf *b, u64 v, int width)
{
	char t[20];
	int i = 0;
	do {
		t[i++] = "0123456789abcdef"[v & 15];
		v >>= 4;
	} while (v);
	while (i < width)
		t[i++] = '0';
	char o[20];
	for (int k = 0; k < i; k++)
		o[k] = t[i - 1 - k];
	o[i] = 0;
	sput(b, o);
}

void ws_sbuf_hex(void *b, u64 v, int width) { sputx(b, v, width); }
void ws_sbuf_str(void *b, const char *s) { sput(b, s); }
void ws_sbuf_dec(void *b, u64 v) { sputu(b, v); }

/* "C:\x\y" -> "/c/x/y" (ws_alloc'd) */
char *ws_path_to_posix(const wchar_t *w)
{
	char *u = ws_w_to_utf8(w);
	if (!u)
		return NULL;
	if (u[0] == '\\' && u[1] == '\\' && u[2] == '?' && u[3] == '\\')
		__ws_memmove(u, u + 4, ws_strlen(u + 4) + 1);
	size_t l = ws_strlen(u);
	for (size_t i = 0; i < l; i++)
		if (u[i] == '\\')
			u[i] = '/';
	if (l >= 2 && u[1] == ':') {
		u[1] = (char)(u[0] | 0x20);
		u[0] = '/';
	}
	return u;
}

/* ---- per-process facts ---- */
static i64 boot_100ns(void)
{
	FILETIME now;
	GetSystemTimeAsFileTime(&now);
	return (i64)(((u64)now.dwHighDateTime << 32) | now.dwLowDateTime) - (i64)GetTickCount64() * 10000;
}

static u64 ft(FILETIME f) { return ((u64)f.dwHighDateTime << 32) | f.dwLowDateTime; }

static int proc_name(HANDLE h, char *out, size_t cap)
{
	wchar_t w[MAX_PATH];
	DWORD n = MAX_PATH;
	if (!QueryFullProcessImageNameW(h, 0, w, &n))
		return 0;
	wchar_t *base = w;
	for (wchar_t *p = w; *p; p++)
		if (*p == L'\\')
			base = p + 1;
	size_t l = ws_wcslen(base);
	if (l > 4 && base[l - 4] == L'.')
		base[l - 4] = 0;            /* "bmcbitcoind.exe" -> "bmcbitcoind" (Linux comm) */
	char *u = ws_w_to_utf8(base);
	if (!u)
		return 0;
	size_t k = 0;
	for (; u[k] && k < 15 && k + 1 < cap; k++)   /* comm is 15 chars */
		out[k] = u[k];
	out[k] = 0;
	ws_free(u);
	return 1;
}

static DWORD thread_count(DWORD pid)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return 1;
	THREADENTRY32 te;
	te.dwSize = sizeof te;
	DWORD n = 0;
	for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te))
		if (te.th32OwnerProcessID == pid)
			n++;
	CloseHandle(snap);
	return n ? n : 1;
}

extern DWORD ws_parent_pid_of_self(void);

/* /proc/<pid>/stat (52 fields; the ones bmc reads are real) */
int ws_pid_reaped(DWORD pid);

static int gen_stat(sbuf *b, DWORD pid, DWORD tid)
{
	if (ws_pid_reaped(pid))
		return -L_ENOENT;
	HANDLE h = pid == GetCurrentProcessId() ? GetCurrentProcess()
		 : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!h)
		return -L_ENOENT;
	char name[32] = "?";
	proc_name(h, name, sizeof name);
	DWORD code = STILL_ACTIVE;
	GetExitCodeProcess(h, &code);
	FILETIME c, e, k, u;
	u64 start = 0, utime = 0, stime = 0;
	if (GetProcessTimes(h, &c, &e, &k, &u)) {
		i64 since_boot = (i64)ft(c) - boot_100ns();
		start = since_boot > 0 ? (u64)since_boot / 100000 : 0;     /* clock ticks: 100 Hz */
		utime = ft(u) / 100000;
		stime = ft(k) / 100000;
	}
	PROCESS_MEMORY_COUNTERS pm;
	__ws_memset(&pm, 0, sizeof pm);
	pm.cb = sizeof pm;
	K32GetProcessMemoryInfo(h, &pm, sizeof pm);
	sputu(b, tid ? tid : pid);
	sput(b, " (");
	sput(b, name);
	sput(b, code == STILL_ACTIVE ? ") R " : ") Z ");
	sputu(b, pid == GetCurrentProcessId() ? ws_parent_pid_of_self() : 1);
	sput(b, " ");
	sputu(b, pid);                        /* pgrp */
	sput(b, " ");
	sputu(b, pid);                        /* session */
	sput(b, " 0 -1 0 ");                  /* tty_nr tpgid flags */
	sputu(b, pm.PageFaultCount);          /* minflt */
	sput(b, " 0 0 0 ");
	sputu(b, utime);
	sput(b, " ");
	sputu(b, stime);
	sput(b, " 0 0 20 0 ");
	sputu(b, thread_count(pid));
	sput(b, " 0 ");
	sputu(b, start);
	sput(b, " ");
	sputu(b, pm.PagefileUsage + pm.WorkingSetSize);  /* vsize (approx) */
	sput(b, " ");
	sputu(b, pm.WorkingSetSize / 4096);   /* rss pages */
	for (int i = 25; i <= 52; i++)
		sput(b, " 0");
	sput(b, "\n");
	if (h != GetCurrentProcess())
		CloseHandle(h);
	return 0;
}

static int gen_statm(sbuf *b, DWORD pid)
{
	HANDLE h = pid == GetCurrentProcessId() ? GetCurrentProcess()
		 : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!h)
		return -L_ENOENT;
	PROCESS_MEMORY_COUNTERS pm;
	__ws_memset(&pm, 0, sizeof pm);
	pm.cb = sizeof pm;
	K32GetProcessMemoryInfo(h, &pm, sizeof pm);
	u64 size = (pm.PagefileUsage + pm.WorkingSetSize) / 4096, res = pm.WorkingSetSize / 4096;
	sputu(b, size);
	sput(b, " ");
	sputu(b, res);
	sput(b, " 0 0 0 ");
	sputu(b, pm.PagefileUsage / 4096);
	sput(b, " 0\n");
	if (h != GetCurrentProcess())
		CloseHandle(h);
	return 0;
}

static int gen_io(sbuf *b, DWORD pid)
{
	HANDLE h = pid == GetCurrentProcessId() ? GetCurrentProcess()
		 : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!h)
		return -L_ENOENT;
	IO_COUNTERS io;
	__ws_memset(&io, 0, sizeof io);
	GetProcessIoCounters(h, &io);
	sput(b, "rchar: ");
	sputu(b, io.ReadTransferCount);
	sput(b, "\nwchar: ");
	sputu(b, io.WriteTransferCount);
	sput(b, "\nsyscr: ");
	sputu(b, io.ReadOperationCount);
	sput(b, "\nsyscw: ");
	sputu(b, io.WriteOperationCount);
	sput(b, "\nread_bytes: ");
	sputu(b, io.ReadTransferCount);
	sput(b, "\nwrite_bytes: ");
	sputu(b, io.WriteTransferCount);
	sput(b, "\ncancelled_write_bytes: 0\n");
	if (h != GetCurrentProcess())
		CloseHandle(h);
	return 0;
}

static int gen_meminfo(sbuf *b)
{
	MEMORYSTATUSEX m;
	m.dwLength = sizeof m;
	GlobalMemoryStatusEx(&m);
	const char *k[] = { "MemTotal:", "MemFree:", "MemAvailable:", "Buffers:", "Cached:",
			    "SwapTotal:", "SwapFree:", "CommitLimit:", "Committed_AS:" };
	u64 v[] = { m.ullTotalPhys, m.ullAvailPhys, m.ullAvailPhys, 0, 0,
		    m.ullTotalPageFile > m.ullTotalPhys ? m.ullTotalPageFile - m.ullTotalPhys : 0,
		    m.ullAvailPageFile > m.ullAvailPhys ? m.ullAvailPageFile - m.ullAvailPhys : 0,
		    m.ullTotalPageFile, m.ullTotalPageFile - m.ullAvailPageFile };
	for (int i = 0; i < 9; i++) {
		sput(b, k[i]);
		u64 kb = v[i] / 1024;
		char t[24];
		ws_fmt_u64(t, kb);
		for (int pad = (int)(16 - ws_strlen(k[i]) - ws_strlen(t)); pad > 0; pad--)
			sput(b, " ");
		sput(b, t);
		sput(b, " kB\n");
	}
	return 0;
}

/* Another process's threads come from a system-wide snapshot shared for
 * 250 ms: a walk over /proc/<pid>/task of every process (the daemon's
 * datadir-lock scan does one per pass) would otherwise take one snapshot per
 * process, ~50 ms each -- 15 s a pass with 300 processes. Our own threads
 * are always listed fresh. */
typedef struct { DWORD pid, tid; } pt_pair;
static pt_pair *pt_cache;
static size_t pt_n;
static u64 pt_at;
static SRWLOCK pt_lock = SRWLOCK_INIT;

static void pt_refresh(void)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return;
	size_t cap = pt_n > 1024 ? pt_n * 2 : 4096, n = 0;
	pt_pair *v = ws_alloc(sizeof *v * cap);
	THREADENTRY32 te;
	te.dwSize = sizeof te;
	for (BOOL ok = Thread32First(snap, &te); ok && v; ok = Thread32Next(snap, &te)) {
		if (n == cap) {
			pt_pair *w = ws_alloc(sizeof *w * cap * 2);
			if (!w)
				break;
			__ws_memcpy(w, v, sizeof *v * n);
			ws_free(v);
			v = w;
			cap *= 2;
		}
		v[n].pid = te.th32OwnerProcessID;
		v[n].tid = te.th32ThreadID;
		n++;
	}
	CloseHandle(snap);
	if (v) {
		ws_free(pt_cache);
		pt_cache = v;
		pt_n = n;
		pt_at = GetTickCount64();
	}
}

static int gen_task_dir(sbuf *b, DWORD pid)
{
	int any = 0;
	AcquireSRWLockExclusive(&pt_lock);
	if (pid == GetCurrentProcessId() || !pt_cache || GetTickCount64() - pt_at > 250)
		pt_refresh();
	for (size_t i = 0; i < pt_n; i++)
		if (pt_cache[i].pid == pid) {
			sputu(b, pt_cache[i].tid);
			sput(b, "x");
			b->p[b->n - 1] = 0;        /* NUL-separated names */
			any = 1;
		}
	ReleaseSRWLockExclusive(&pt_lock);
	return any ? 0 : -L_ENOENT;
}

/* our fd numbers as a directory */
int ws_fd_list(void (*emit)(void *ctx, int fd), void *ctx);

static void emit_fd(void *ctx, int fd)
{
	sbuf *b = ctx;
	sputu(b, (u64)fd);
	sput(b, "x");
	b->p[b->n - 1] = 0;
}

char *ws_mem_maps_text(u64 *len, int smaps);

static int is_num(const char *s, const char *e)
{
	if (s == e)
		return 0;
	for (; s < e; s++)
		if (*s < '0' || *s > '9')
			return 0;
	return 1;
}

static u64 to_u(const char *s, const char *e)
{
	u64 v = 0;
	for (; s < e; s++)
		v = v * 10 + (u64)(*s - '0');
	return v;
}

/* path after "/proc/": the pid ("self" -> ours) and the rest */
static int split_pid(const char *p, DWORD *pid, const char **rest)
{
	const char *s = p;
	while (*s && *s != '/')
		s++;
	if (s - p == 4 && !__ws_memcmp(p, "self", 4))
		*pid = GetCurrentProcessId();
	else if (is_num(p, s))
		*pid = (DWORD)to_u(p, s);
	else
		return 0;
	*rest = *s ? s + 1 : s;
	return 1;
}

static int streq(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

/* /proc itself: every process's pid */
static int gen_pid_dir(sbuf *b)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return -L_ENOENT;
	PROCESSENTRY32W pe;
	pe.dwSize = sizeof pe;
	for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
		if (pe.th32ProcessID) {
			sputu(b, pe.th32ProcessID);
			sput(b, "x");
			b->p[b->n - 1] = 0;
		}
	CloseHandle(snap);
	return 0;
}

ws_desc *ws_procfs_open(const char *path, i64 *err)
{
	const char *p = path[5] ? path + 6 : path + 5;   /* after "/proc/" */
	sbuf b = { 0 };
	int dir = 0, r = -L_ENOENT;
	DWORD pid;
	const char *rest;
	if (!*p) {
		sput(&b, "");
		b.n = 0;
		r = gen_pid_dir(&b);
		dir = 1;
	} else if (streq(p, "meminfo")) {
		r = gen_meminfo(&b);
	} else if (split_pid(p, &pid, &rest) && !ws_pid_reaped(pid)) {
		int self = pid == GetCurrentProcessId();
		if (!*rest) {
			HANDLE h = self ? GetCurrentProcess() : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			r = h ? 0 : -L_ENOENT;
			if (h && !self)
				CloseHandle(h);
			sput(&b, "");
			dir = 1;
		} else if (streq(rest, "stat")) {
			r = gen_stat(&b, pid, 0);
		} else if (streq(rest, "statm")) {
			r = gen_statm(&b, pid);
		} else if (streq(rest, "io")) {
			r = gen_io(&b, pid);
		} else if (streq(rest, "comm")) {
			HANDLE h = self ? GetCurrentProcess() : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			char name[32];
			if (h && proc_name(h, name, sizeof name)) {
				sput(&b, name);
				sput(&b, "\n");
				r = 0;
			}
			if (h && !self)
				CloseHandle(h);
		} else if (streq(rest, "wchan") || streq(rest, "syscall")) {
			sput(&b, "0\n");
			r = 0;
		} else if (self && (streq(rest, "maps") || streq(rest, "smaps") || streq(rest, "smaps_rollup"))) {
			u64 n = 0;
			char *t = ws_mem_maps_text(&n, streq(rest, "smaps") ? 1 : streq(rest, "smaps_rollup") ? 2 : 0);
			if (t) {
				b.p = t;
				b.n = n;
				r = 0;
			}
		} else if (streq(rest, "task") || streq(rest, "task/")) {
			sput(&b, "");
			b.n = 0;
			r = gen_task_dir(&b, pid);
			dir = 1;
		} else if (!__ws_memcmp(rest, "task/", 5)) {
			const char *t = rest + 5, *e = t;
			while (*e && *e != '/')
				e++;
			if (is_num(t, e) && streq(e, "/stat"))
				r = gen_stat(&b, pid, (DWORD)to_u(t, e));
		} else if (self && (streq(rest, "fd") || streq(rest, "fd/"))) {
			sput(&b, "");
			b.n = 0;
			ws_fd_list(emit_fd, &b);
			r = 0;
			dir = 1;
		} else if (streq(rest, "fd") || streq(rest, "fd/")) {
			/* another process: the descriptions it shares with us */
			HANDLE h = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
			if (h) {
				sput(&b, "");
				b.n = 0;
				ws_fd_list_shared(h, emit_fd, &b);
				CloseHandle(h);
				r = 0;
				dir = 1;
			} else {
				r = -L_EACCES;
			}
		}
	}
	if (r) {
		ws_free(b.p);
		*err = r;
		return NULL;
	}
	ws_desc *d = ws_desc_new(dir ? FT_MEMDIR : FT_MEM);
	if (!d) {
		ws_free(b.p);
		*err = -L_ENOMEM;
		return NULL;
	}
	if (!b.p)
		b.p = ws_alloc(1);
	d->mem = b.p;
	d->memlen = b.n;
	size_t pl = ws_strlen(path);
	while (pl > 1 && path[pl - 1] == '/')
		pl--;
	d->ppath = ws_alloc(pl + 1);
	if (d->ppath) {
		__ws_memcpy(d->ppath, path, pl);
		d->ppath[pl] = 0;
	}
	return d;
}

/* does process pid hold our fd's description (as its /proc/<pid>/fd lists)? */
static void note_fd(void *ctx, int fd)
{
	int *want = ctx;
	if (fd == want[0])
		want[1] = 1;
}
static int other_holds(DWORD pid, int fd)
{
	HANDLE h = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
	if (!h)
		return 0;
	int want[2] = { fd, 0 };
	ws_fd_list_shared(h, note_fd, want);
	CloseHandle(h);
	return want[1];
}

/* the fd an /proc/<pid>/fd/N path of another process stands for (it is our
 * fd N's description), or -1 */
int ws_procfs_other_fd(const char *path)
{
	DWORD pid;
	const char *rest;
	if (!split_pid(path + 6, &pid, &rest) || pid == GetCurrentProcessId())
		return -1;
	if (__ws_memcmp(rest, "fd/", 3) || !is_num(rest + 3, rest + ws_strlen(rest)))
		return -1;
	int fd = (int)to_u(rest + 3, rest + ws_strlen(rest));
	return other_holds(pid, fd) ? fd : -1;
}

/* readlink of /proc/self/exe and /proc/self/fd/N */
i64 ws_procfs_readlink(const char *path, char *buf, size_t cap)
{
	const char *p = path + 6;
	DWORD pid;
	const char *rest;
	char *u = NULL;
	if (!split_pid(p, &pid, &rest))
		return -L_ENOENT;
	if (pid != GetCurrentProcessId()) {
		if (__ws_memcmp(rest, "fd/", 3) || !is_num(rest + 3, rest + ws_strlen(rest)))
			return -L_ENOENT;
		int fd = (int)to_u(rest + 3, rest + ws_strlen(rest));
		if (!other_holds(pid, fd))
			return -L_ENOENT;
		char self_path[40] = "/proc/self/fd/";
		sbuf t = { 0 };
		sputu(&t, (u64)fd);
		sput(&t, "x");
		size_t tl = t.n - 1;
		if (tl > 20)
			tl = 20;
		__ws_memcpy(self_path + 14, t.p, tl);
		self_path[14 + tl] = 0;
		ws_free(t.p);
		return ws_procfs_readlink(self_path, buf, cap);
	}
	if (streq(rest, "exe")) {
		wchar_t w[MAX_PATH];
		if (GetModuleFileNameW(NULL, w, MAX_PATH))
			u = ws_path_to_posix(w);
	} else if (!__ws_memcmp(rest, "fd/", 3) && is_num(rest + 3, rest + ws_strlen(rest))) {
		int fd = (int)to_u(rest + 3, rest + ws_strlen(rest));
		ws_desc *d = ws_fd_get(fd);
		if (!d)
			return -L_ENOENT;
		if (d->wpath)
			u = ws_path_to_posix(d->wpath);
		else if (d->type == FT_SOCKET || d->type == FT_UXDGRAM)
			u = ws_w_to_utf8(L"socket:[0]");
		else if (d->type == FT_PIPE)
			u = ws_w_to_utf8(L"pipe:[0]");
		else
			u = ws_w_to_utf8(d->type == FT_NULL ? L"/dev/null" : L"/dev/pts/0");
		ws_desc_put(d);
	}
	if (!u)
		return -L_ENOENT;
	size_t l = ws_strlen(u);
	if (l > cap)
		l = cap;
	__ws_memcpy(buf, u, l);
	ws_free(u);
	return (i64)l;
}
