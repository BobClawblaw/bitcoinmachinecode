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
/* 0, or -1 when a signal interrupted the sleep */
static int sleep_ns(i64 ns)
{
	if (ns <= 0) {
		SwitchToThread();
		return 0;
	}
	if (!sleep_timer)
		sleep_timer = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
						     TIMER_ALL_ACCESS);
	if (sleep_timer) {
		LARGE_INTEGER due;
		due.QuadPart = -(ns / 100 ? ns / 100 : 1);
		if (SetWaitableTimer(sleep_timer, &due, 0, NULL, NULL, FALSE))
			return ws_wait(&sleep_timer, 1, INFINITE) == WS_WAIT_INTR ? -1 : 0;
	}
	return ws_wait(NULL, 0, (DWORD)((ns + 999999) / 1000000)) == WS_WAIT_INTR ? -1 : 0;
}

static i64 sys_nanosleep(const struct l_timespec *req, struct l_timespec *rem)
{
	if (req->nsec < 0 || req->nsec >= 1000000000 || req->sec < 0)
		return -L_EINVAL;
	if (sleep_ns(req->sec * 1000000000LL + req->nsec))
		return -L_EINTR;          /* rem: the remaining time is not tracked */
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
	return sleep_ns(ns) ? -L_EINTR : 0;
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

static i64 sys_kill(int pid, int sig)
{
	if (pid == 0 || pid == -1 || pid == (int)GetCurrentProcessId())
		return ws_sig_kill_self(sig);
	if (pid < 0)
		return -L_ESRCH;
	HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
	if (!h)
		return -L_ESRCH;
	i64 r = 0;
	DWORD code;
	if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE)
		r = -L_ESRCH;
	else if (sig != 0 && !TerminateProcess(h, 128 + (UINT)sig))
		r = ws_err(GetLastError());
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
	case 62: return sys_kill((int)a1, (int)a2);
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
