/* ws_proc.c -- clocks, sleeping, process identity, limits and signals
 * (bmc_win). */
#include "winsys.h"
#include <psapi.h>

struct l_timespec { i64 sec, nsec; };
struct l_timeval { i64 sec, usec; };

/* ---- clocks ---- */
static i64 qpc_freq;

static void now_realtime(struct l_timespec *ts)
{
	FILETIME ft;
	GetSystemTimePreciseAsFileTime(&ft);
	i64 t = (i64)(((u64)ft.dwHighDateTime << 32) | ft.dwLowDateTime) - 116444736000000000LL;
	ts->sec = t / 10000000;
	ts->nsec = (t % 10000000) * 100;
}

static void now_monotonic(struct l_timespec *ts)
{
	LARGE_INTEGER c;
	if (!qpc_freq) {
		LARGE_INTEGER f;
		QueryPerformanceFrequency(&f);
		qpc_freq = f.QuadPart;
	}
	QueryPerformanceCounter(&c);
	ts->sec = c.QuadPart / qpc_freq;
	ts->nsec = (c.QuadPart % qpc_freq) * 1000000000LL / qpc_freq;
}

static void ft_dur(FILETIME a, FILETIME b, struct l_timespec *ts)
{
	u64 t = (((u64)a.dwHighDateTime << 32) | a.dwLowDateTime) + (((u64)b.dwHighDateTime << 32) | b.dwLowDateTime);
	ts->sec = (i64)(t / 10000000);
	ts->nsec = (i64)(t % 10000000) * 100;
}

static i64 sys_clock_gettime(int clk, struct l_timespec *ts)
{
	FILETIME c, e, k, u;
	switch (clk) {
	case 0: case 5: case 8: case 11:      /* REALTIME, _COARSE, _ALARM, TAI */
		now_realtime(ts);
		return 0;
	case 1: case 4: case 6: case 7: case 9: /* MONOTONIC, _RAW, _COARSE, BOOTTIME(_ALARM) */
		now_monotonic(ts);
		return 0;
	case 2:
		if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u))
			return ws_err(GetLastError());
		ft_dur(k, u, ts);
		return 0;
	case 3:
		if (!GetThreadTimes(GetCurrentThread(), &c, &e, &k, &u))
			return ws_err(GetLastError());
		ft_dur(k, u, ts);
		return 0;
	default:
		return -L_EINVAL;
	}
}

static __thread HANDLE sleep_timer;

/* sleep for ns nanoseconds with a high-resolution waitable timer */
static void sleep_ns(i64 ns)
{
	if (ns <= 0) {
		SwitchToThread();
		return;
	}
	if (!sleep_timer)
		sleep_timer = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
						     TIMER_ALL_ACCESS);
	if (sleep_timer) {
		LARGE_INTEGER due;
		due.QuadPart = -(ns / 100 ? ns / 100 : 1);
		if (SetWaitableTimer(sleep_timer, &due, 0, NULL, NULL, FALSE)) {
			WaitForSingleObject(sleep_timer, INFINITE);
			return;
		}
	}
	Sleep((DWORD)((ns + 999999) / 1000000));
}

static i64 sys_nanosleep(const struct l_timespec *req, struct l_timespec *rem)
{
	if (req->nsec < 0 || req->nsec >= 1000000000 || req->sec < 0)
		return -L_EINVAL;
	sleep_ns(req->sec * 1000000000LL + req->nsec);
	if (rem) {
		rem->sec = 0;
		rem->nsec = 0;
	}
	return 0;
}

static i64 sys_clock_nanosleep(int clk, int flags, const struct l_timespec *req, struct l_timespec *rem)
{
	if (!(flags & 1))                     /* relative */
		return sys_nanosleep(req, rem);
	struct l_timespec now;
	i64 r = sys_clock_gettime(clk, &now);
	if (r)
		return r;
	i64 ns = (req->sec - now.sec) * 1000000000LL + (req->nsec - now.nsec);
	sleep_ns(ns);
	return 0;
}

/* ---- identity ---- */
struct l_utsname { char f[6][65]; };

static void put(char *d, const char *s)
{
	size_t i = 0;
	for (; s[i] && i < 64; i++)
		d[i] = s[i];
	d[i] = 0;
}

static i64 sys_uname(struct l_utsname *u)
{
	__ws_memset(u, 0, sizeof *u);
	put(u->f[0], "Windows_NT");
	char host[65];
	DWORD n = sizeof host;
	if (!GetComputerNameA(host, &n))
		put(host, "localhost");
	put(u->f[1], host);
	put(u->f[2], "10.0");
	put(u->f[3], "bmc_win");
	put(u->f[4], "x86_64");
	return 0;
}

struct l_sysinfo {
	i64 uptime;
	u64 loads[3];
	u64 totalram, freeram, sharedram, bufferram, totalswap, freeswap;
	unsigned short procs, pad;
	u64 totalhigh, freehigh;
	uint32_t mem_unit;
	char f[0];
};

static i64 sys_sysinfo(struct l_sysinfo *s)
{
	__ws_memset(s, 0, sizeof *s);
	MEMORYSTATUSEX m;
	m.dwLength = sizeof m;
	GlobalMemoryStatusEx(&m);
	s->uptime = (i64)(GetTickCount64() / 1000);
	s->totalram = m.ullTotalPhys;
	s->freeram = m.ullAvailPhys;
	s->totalswap = m.ullTotalPageFile - m.ullTotalPhys;
	s->freeswap = m.ullAvailPageFile > m.ullAvailPhys ? m.ullAvailPageFile - m.ullAvailPhys : 0;
	s->procs = 1;
	s->mem_unit = 1;
	return 0;
}

struct l_rlimit { u64 cur, max; };

static i64 sys_prlimit(int pid, int res, const struct l_rlimit *nw, struct l_rlimit *old)
{
	(void)pid;
	(void)nw;
	if (old) {
		switch (res) {
		case 7:  /* RLIMIT_NOFILE */
			old->cur = old->max = 1 << 20;
			break;
		case 3:  /* RLIMIT_STACK */
			old->cur = old->max = 16 << 20;
			break;
		default:
			old->cur = old->max = ~0ULL;
		}
	}
	return 0;
}

struct l_rusage {
	struct l_timeval utime, stime;
	i64 maxrss, ixrss, idrss, isrss, minflt, majflt, nswap, inblock, oublock, msgsnd, msgrcv,
	    nsignals, nvcsw, nivcsw;
};

static i64 sys_getrusage(int who, struct l_rusage *ru)
{
	FILETIME c, e, k, u;
	__ws_memset(ru, 0, sizeof *ru);
	BOOL ok = who == 1 ? GetThreadTimes(GetCurrentThread(), &c, &e, &k, &u)
			   : GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);
	if (!ok)
		return ws_err(GetLastError());
	u64 ut = ((u64)u.dwHighDateTime << 32) | u.dwLowDateTime;
	u64 kt = ((u64)k.dwHighDateTime << 32) | k.dwLowDateTime;
	ru->utime.sec = (i64)(ut / 10000000);
	ru->utime.usec = (i64)(ut % 10000000) / 10;
	ru->stime.sec = (i64)(kt / 10000000);
	ru->stime.usec = (i64)(kt % 10000000) / 10;
	PROCESS_MEMORY_COUNTERS pm;
	pm.cb = sizeof pm;
	if (K32GetProcessMemoryInfo(GetCurrentProcess(), &pm, sizeof pm))
		ru->maxrss = (i64)(pm.PeakWorkingSetSize / 1024);
	return 0;
}

static i64 sys_sched_getaffinity(int pid, size_t len, unsigned char *mask)
{
	(void)pid;
	DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
	size_t need = ((n + 63) / 64) * 8;
	if (len < need)
		return -L_EINVAL;
	__ws_memset(mask, 0, len);
	for (DWORD i = 0; i < n; i++)
		mask[i / 8] |= (unsigned char)(1u << (i % 8));
	return (i64)need;
}

/* ---- signals ----
 * Handlers are recorded per signal. Console Ctrl+C / Ctrl+Break / close run
 * the SIGINT / SIGTERM handler (on the console's handler thread); kill() of
 * our own pid runs the handler synchronously; a default action terminates
 * with 128+sig, as a shell would report it. */
struct l_sigaction { void *handler; u64 flags; void *restorer; u64 mask; };
typedef SV void (*sig_fn)(int);
typedef SV void (*sig_info_fn)(int, void *, void *);
static struct l_sigaction actions[65];
static SRWLOCK sig_lock = SRWLOCK_INIT;

static void deliver(int sig)
{
	struct l_sigaction a;
	AcquireSRWLockShared(&sig_lock);
	a = actions[sig];
	ReleaseSRWLockShared(&sig_lock);
	if (a.handler == (void *)1)            /* SIG_IGN */
		return;
	if (a.handler == NULL) {               /* SIG_DFL */
		if (sig == 17 || sig == 23 || sig == 28)  /* SIGCHLD, SIGURG, SIGWINCH */
			return;
		ExitProcess(128 + (UINT)sig);
	}
	if (a.flags & 4) {                     /* SA_SIGINFO */
		unsigned char info[128];
		__ws_memset(info, 0, sizeof info);
		*(int *)info = sig;
		((sig_info_fn)a.handler)(sig, info, NULL);
	} else {
		((sig_fn)a.handler)(sig);
	}
	if (a.flags & 0x80000000u) {           /* SA_RESETHAND */
		AcquireSRWLockExclusive(&sig_lock);
		actions[sig].handler = NULL;
		ReleaseSRWLockExclusive(&sig_lock);
	}
}

static BOOL WINAPI ctrl_handler(DWORD t)
{
	int sig = t == CTRL_C_EVENT ? 2 : t == CTRL_BREAK_EVENT ? 15 : t == CTRL_CLOSE_EVENT ? 1 : 15;
	struct l_sigaction a;
	AcquireSRWLockShared(&sig_lock);
	a = actions[sig];
	ReleaseSRWLockShared(&sig_lock);
	if (a.handler == NULL)
		return FALSE;                      /* default: let Windows end us */
	deliver(sig);
	if (t == CTRL_CLOSE_EVENT || t == CTRL_LOGOFF_EVENT || t == CTRL_SHUTDOWN_EVENT)
		Sleep(5000);                       /* give the handler's shutdown a moment */
	return TRUE;
}

static i64 sys_rt_sigaction(int sig, const struct l_sigaction *act, struct l_sigaction *old)
{
	static volatile LONG installed;
	if (sig < 1 || sig > 64 || sig == 9 || sig == 19)
		return act ? -L_EINVAL : 0;
	AcquireSRWLockExclusive(&sig_lock);
	if (old)
		*old = actions[sig];
	if (act)
		actions[sig] = *act;
	ReleaseSRWLockExclusive(&sig_lock);
	if (act && (sig == 2 || sig == 15 || sig == 1) && !InterlockedExchange(&installed, 1))
		SetConsoleCtrlHandler(ctrl_handler, TRUE);
	return 0;
}

static i64 sys_kill(int pid, int sig)
{
	if (pid == 0 || pid == -1 || pid == (int)GetCurrentProcessId()) {
		if (sig == 0)
			return 0;
		if (sig < 1 || sig > 64)
			return -L_EINVAL;
		deliver(sig);
		return 0;
	}
	if (pid < 0)
		return -L_ESRCH;
	HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
	if (!h)
		return -L_ESRCH;
	i64 r = 0;
	if (sig != 0) {
		DWORD code;
		if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE)
			r = -L_ESRCH;
		else if (!TerminateProcess(h, 128 + (UINT)sig))
			r = ws_err(GetLastError());
	}
	CloseHandle(h);
	return r;
}

i64 ws_sys_time(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	*handled = 1;
	(void)a5;
	(void)a6;
	struct l_timespec ts;
	switch (n) {
	case 228: return sys_clock_gettime((int)a1, (struct l_timespec *)a2);
	case 229:                              /* clock_getres */
		if (a2) {
			((struct l_timespec *)a2)->sec = 0;
			((struct l_timespec *)a2)->nsec = a1 == 0 || a1 == 5 ? 100 : 1;
		}
		return 0;
	case 96:                               /* gettimeofday */
		if (a1) {
			now_realtime(&ts);
			((struct l_timeval *)a1)->sec = ts.sec;
			((struct l_timeval *)a1)->usec = ts.nsec / 1000;
		}
		if (a2)
			__ws_memset((void *)a2, 0, 8);
		return 0;
	case 201:                              /* time */
		now_realtime(&ts);
		if (a1)
			*(i64 *)a1 = ts.sec;
		return (i64)ts.sec;
	case 35: return sys_nanosleep((const struct l_timespec *)a1, (struct l_timespec *)a2);
	case 230: return sys_clock_nanosleep((int)a1, (int)a2, (const struct l_timespec *)a3,
					     (struct l_timespec *)a4);
	case 63: return sys_uname((struct l_utsname *)a1);
	case 99: return sys_sysinfo((struct l_sysinfo *)a1);
	case 39: return (i64)GetCurrentProcessId();
	case 110: return 1;                    /* getppid: re-parented to "init" */
	case 102: case 104: case 107: case 108: return 1000;  /* uid/gid/euid/egid */
	case 118: case 120:                    /* getresuid / getresgid */
		*(int *)a1 = *(int *)a2 = *(int *)a3 = 1000;
		return 0;
	case 105: case 106: case 113: case 114: case 117: case 119: return 0;  /* set*id */
	case 111: return (i64)GetCurrentProcessId();   /* getpgrp */
	case 112: return (i64)GetCurrentProcessId();   /* setsid */
	case 121: case 124: return (i64)GetCurrentProcessId();  /* getpgid / getsid */
	case 109: return 0;                    /* setpgid */
	case 97: return sys_prlimit(0, (int)a1, NULL, (struct l_rlimit *)a2);
	case 160: return 0;                    /* setrlimit */
	case 302: return sys_prlimit((int)a1, (int)a2, (const struct l_rlimit *)a3, (struct l_rlimit *)a4);
	case 98: return sys_getrusage((int)a1, (struct l_rusage *)a2);
	case 204: return sys_sched_getaffinity((int)a1, (size_t)a2, (unsigned char *)a3);
	case 203: return 0;                    /* sched_setaffinity */
	case 13: return sys_rt_sigaction((int)a1, (const struct l_sigaction *)a2, (struct l_sigaction *)a3);
	case 14:                               /* rt_sigprocmask: no async signals to block */
		if (a3)
			__ws_memset((void *)a3, 0, (size_t)(a4 > 0 && a4 <= 128 ? a4 : 8));
		return 0;
	case 127: return -L_EINTR;             /* rt_sigpending */
	case 131: return 0;                    /* sigaltstack */
	case 62: return sys_kill((int)a1, (int)a2);
	case 200: return a1 == (i64)GetCurrentThreadId() ? (deliver((int)a2), 0) : -L_ESRCH;  /* tkill */
	case 234: return sys_kill((int)a1, (int)a3);   /* tgkill */
	case 37: return 0;                     /* alarm: unsupported, no-op */
	case 157:                              /* prctl */
		if (a1 == 16) {                    /* PR_GET_NAME */
			__ws_memcpy((void *)a2, "bmc", 4);
			return 0;
		}
		return 0;
	case 140: case 141: return 0;          /* getpriority / setpriority */
	case 251: case 252: return 0;          /* ioprio_set / ioprio_get */
	default:
		*handled = 0;
		return 0;
	}
}
