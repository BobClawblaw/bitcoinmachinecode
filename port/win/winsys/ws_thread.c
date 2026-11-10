/* ws_thread.c -- threads, futex and exit (bmc_win).
 *
 * futex(2) maps onto WaitOnAddress/WakeByAddress*: the same "sleep if the
 * word still holds this value" contract, spurious wakeups allowed on both.
 * They are process-private; a process-shared futex in a shared mapping is
 * not supported (see port/WIN_STRATEGY.md). */
#include "winsys.h"

struct l_timespec { i64 sec, nsec; };

typedef struct { ws_thread_fn fn; void *arg; } tramp;

static DWORD WINAPI thread_main(LPVOID p)
{
	tramp t = *(tramp *)p;
	ws_free(p);
	return (DWORD)(uintptr_t)t.fn(t.arg);
}

WSAPI i64 __bmc_win_thread_create(ws_thread_fn fn, void *arg, size_t stack, void **handle_out, int *tid_out)
{
	tramp *t = ws_alloc(sizeof *t);
	if (!t)
		return -L_ENOMEM;
	t->fn = fn;
	t->arg = arg;
	if (stack < (1 << 20))
		stack = 1 << 20;
	/* committed in full (no STACK_SIZE_PARAM_IS_A_RESERVATION): the SysV
	 * assembly moves rsp by large frames without probing guard pages */
	DWORD tid;
	HANDLE h = CreateThread(NULL, stack, thread_main, t, 0, &tid);
	if (!h) {
		ws_free(t);
		return ws_err(GetLastError());
	}
	*handle_out = h;
	*tid_out = (int)tid;
	return 0;
}

WSAPI i64 __bmc_win_thread_join(void *handle)
{
	if (WaitForSingleObject(handle, INFINITE) != WAIT_OBJECT_0)
		return ws_err(GetLastError());
	return 0;
}

WSAPI void __bmc_win_thread_close(void *handle)
{
	CloseHandle(handle);
}

static DWORD ts_ms(const struct l_timespec *ts)
{
	if (!ts)
		return INFINITE;
	if (ts->sec < 0)
		return 0;
	u64 ms = (u64)ts->sec * 1000 + (u64)(ts->nsec + 999999) / 1000000;
	return ms >= INFINITE ? INFINITE - 1 : (DWORD)ms;
}

static i64 now_ns(int realtime)
{
	if (realtime) {
		FILETIME ft;
		GetSystemTimePreciseAsFileTime(&ft);
		return ((i64)(((u64)ft.dwHighDateTime << 32) | ft.dwLowDateTime) - 116444736000000000LL) * 100;
	}
	static i64 freq;
	LARGE_INTEGER c;
	if (!freq) {
		LARGE_INTEGER f;
		QueryPerformanceFrequency(&f);
		freq = f.QuadPart;
	}
	QueryPerformanceCounter(&c);
	return (c.QuadPart / freq) * 1000000000LL + (c.QuadPart % freq) * 1000000000LL / freq;
}

static i64 futex_wait(volatile int *addr, int val, DWORD ms)
{
	if (*addr != val)
		return -L_EAGAIN;
	if (!WaitOnAddress(addr, &val, sizeof val, ms))
		return GetLastError() == ERROR_TIMEOUT ? -L_ETIMEDOUT : ws_err(GetLastError());
	return 0;
}

static i64 sys_futex(volatile int *addr, int op, int val, const struct l_timespec *to, volatile int *addr2, int val3)
{
	int cmd = op & 127;
	int realtime = (op & 256) != 0;
	switch (cmd) {
	case 0:                               /* FUTEX_WAIT: relative timeout */
		return futex_wait(addr, val, ts_ms(to));
	case 9: {                             /* FUTEX_WAIT_BITSET: absolute timeout */
		DWORD ms = INFINITE;
		if (to) {
			i64 left = (to->sec * 1000000000LL + to->nsec) - now_ns(realtime);
			if (left <= 0)
				return *addr != val ? -L_EAGAIN : -L_ETIMEDOUT;
			ms = (DWORD)((left + 999999) / 1000000);
		}
		return futex_wait(addr, val, ms);
	}
	case 1: case 10:                      /* FUTEX_WAKE(_BITSET) */
		if (val <= 0)
			return 0;
		if (val == 1)
			WakeByAddressSingle((PVOID)addr);
		else
			WakeByAddressAll((PVOID)addr);
		return val == 1 ? 1 : 0;
	case 3: case 4:                       /* FUTEX_(CMP_)REQUEUE: wake everyone instead */
		if (cmd == 4 && *addr != val3)
			return -L_EAGAIN;
		WakeByAddressAll((PVOID)addr);
		WakeByAddressAll((PVOID)addr2);
		return 0;
	default:
		return -L_ENOSYS;
	}
}

i64 ws_sys_thread(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	*handled = 1;
	switch (n) {
	case 202: return sys_futex((volatile int *)a1, (int)a2, (int)a3, (const struct l_timespec *)a4,
				   (volatile int *)a5, (int)a6);
	case 24: SwitchToThread(); return 0;  /* sched_yield */
	case 186: return (i64)GetCurrentThreadId();       /* gettid */
	case 218: return (i64)GetCurrentThreadId();       /* set_tid_address */
	case 273: case 274: case 334: return 0;            /* robust lists, rseq */
	case 324: return 0;                                /* membarrier */
	case 60: ExitThread((DWORD)a1);                    /* exit (this thread) */
	case 231: ExitProcess((UINT)a1);                   /* exit_group */
	default:
		*handled = 0;
		return 0;
	}
}
