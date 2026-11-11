/* ws_thread.c -- threads, futex and exit (bmc_win).
 *
 * futex(2) maps onto WaitOnAddress/WakeByAddress*: the same "sleep if the
 * word still holds this value" contract, spurious wakeups allowed on both.
 * They are process-private; a process-shared futex in a shared mapping is
 * not supported (see port/WIN_STRATEGY.md). */
#include "winsys.h"

struct l_timespec { i64 sec, nsec; };

typedef struct { ws_thread_fn fn; void *arg; u64 mask; } tramp;

static DWORD WINAPI thread_main(LPVOID p)
{
	tramp t = *(tramp *)p;
	ws_free(p);
	ws_sig_thread_start(0);
	ws_sig_thread_inherit_mask(t.mask);
	DWORD r = (DWORD)(uintptr_t)t.fn(t.arg);
	ws_robust_release_current_thread();
	ws_sig_thread_end();
	return r;
}

WSAPI i64 __bmc_win_thread_create(ws_thread_fn fn, void *arg, size_t stack, void **handle_out, int *tid_out)
{
	tramp *t = ws_alloc(sizeof *t);
	if (!t)
		return -L_ENOMEM;
	t->fn = fn;
	t->arg = arg;
	t->mask = ws_sig_current_mask();
	if (stack < (1 << 20))
		stack = 1 << 20;
	/* committed in full (no STACK_SIZE_PARAM_IS_A_RESERVATION): the SysV
	 * assembly moves rsp by large frames without probing guard pages */
	DWORD tid;
	HANDLE h = ws_create_thread(thread_main, t, stack, &tid);
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
	ws_sig_futex_begin(addr);
	if (ws_sig_pending_here()) {
		ws_sig_futex_end();
		return -L_EINTR;
	}
	BOOL ok = WaitOnAddress(addr, &val, sizeof val, ms);
	DWORD e = ok ? 0 : GetLastError();
	if (ws_sig_futex_end())
		return -L_EINTR;
	if (!ok)
		return e == ERROR_TIMEOUT ? -L_ETIMEDOUT : ws_err(e);
	return 0;
}

/* ---- process-shared futexes (no FUTEX_PRIVATE_FLAG) ----
 * WaitOnAddress only sees waiters in its own process. A futex word in a
 * MAP_SHARED page is at the same address in every process of the fork tree,
 * so the root sets up a table of buckets -- a waiter count in a shared
 * section and a semaphore each, both inherited -- hashed by address. A wake
 * releases every waiter of the bucket; each re-checks its word, as futex
 * callers must anyway. */
#define FX_BUCKETS 256
typedef struct { volatile LONG waiters; volatile LONG pad[15]; } fx_bucket;   /* a cache line each */
static fx_bucket *fx;
static HANDLE fx_sem[FX_BUCKETS];

void ws_futex_shared_init(void)
{
	SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
	HANDLE sec = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(fx_bucket) * FX_BUCKETS, NULL);
	fx = sec ? MapViewOfFile(sec, FILE_MAP_WRITE, 0, 0, 0) : NULL;
	if (!fx)
		ws_fatal("cannot create the shared futex table");
	for (int i = 0; i < FX_BUCKETS; i++)
		if (!(fx_sem[i] = CreateSemaphoreW(&sa, 0, 0x7fffffff, NULL)))
			ws_fatal("cannot create the shared futex semaphores");
}

static unsigned fx_hash(volatile void *addr)
{
	u64 a = (u64)(uintptr_t)addr >> 2;
	a ^= a >> 17;
	a *= 0x9E3779B97F4A7C15ULL;
	return (unsigned)(a >> 56) % FX_BUCKETS;
}

static i64 futex_wait_shared(volatile int *addr, int val, DWORD ms)
{
	fx_bucket *b = &fx[fx_hash(addr)];
	HANDLE sem = fx_sem[b - fx];
	InterlockedIncrement(&b->waiters);
	if (*addr != val) {                     /* after the count: a waker now sees us */
		InterlockedDecrement(&b->waiters);
		return -L_EAGAIN;
	}
	int w = ws_wait(&sem, 1, ms);
	InterlockedDecrement(&b->waiters);
	if (w == 0)
		return 0;
	return w == WS_WAIT_INTR ? -L_EINTR : w == WS_WAIT_TIMEOUT ? -L_ETIMEDOUT : -L_EINVAL;
}

static i64 futex_wake_shared(volatile int *addr, int n)
{
	fx_bucket *b = &fx[fx_hash(addr)];
	LONG w = b->waiters;
	if (w > 0)
		ReleaseSemaphore(fx_sem[b - fx], w, NULL);
	return w < n ? w : n;
}

void ws_futex_wake_any(volatile int *addr, int n)
{
	WakeByAddressAll((PVOID)addr);
	futex_wake_shared(addr, n);
}

/* ---- robust mutex lists (set_robust_list): what the kernel does when a
 * thread dies holding a robust mutex, done on every death path winsys
 * controls -- thread exit, exit_group, a fatal signal, SIGKILL through the
 * signal box, an unhandled exception. The list format is the Linux ABI:
 * head { next, futex_offset, list_op_pending }; a held lock's word carries
 * the owner's tid; the dead owner's locks become FUTEX_OWNER_DIED. */
struct l_robust_head { void *next; i64 off; void *pending; };
typedef struct { DWORD tid; struct l_robust_head *head; } robust_reg;
static robust_reg robust[1024];
static SRWLOCK robust_lock = SRWLOCK_INIT;

#define FUTEX_WAITERS_ 0x80000000u
#define FUTEX_OWNER_DIED_ 0x40000000u
#define FUTEX_TID_MASK_ 0x3fffffffu

static void robust_set(struct l_robust_head *h)
{
	DWORD tid = GetCurrentThreadId();
	AcquireSRWLockExclusive(&robust_lock);
	int free_at = -1;
	for (int i = 0; i < 1024; i++) {
		if (robust[i].tid == tid) {
			robust[i].head = h;
			ReleaseSRWLockExclusive(&robust_lock);
			return;
		}
		if (!robust[i].tid && free_at < 0)
			free_at = i;
	}
	if (free_at >= 0) {
		robust[free_at].tid = tid;
		robust[free_at].head = h;
	}
	ReleaseSRWLockExclusive(&robust_lock);
}

static struct l_robust_head *robust_get(void)
{
	DWORD tid = GetCurrentThreadId();
	struct l_robust_head *h = NULL;
	AcquireSRWLockShared(&robust_lock);
	for (int i = 0; i < 1024; i++)
		if (robust[i].tid == tid)
			h = robust[i].head;
	ReleaseSRWLockShared(&robust_lock);
	return h;
}

static void robust_mark(volatile int *word, DWORD tid)
{
	for (;;) {
		unsigned v = (unsigned)*word;
		if ((v & FUTEX_TID_MASK_) != (tid & FUTEX_TID_MASK_))
			return;
		unsigned nv = (v & FUTEX_WAITERS_) | FUTEX_OWNER_DIED_;
		if ((unsigned)InterlockedCompareExchange((volatile LONG *)word, (LONG)nv, (LONG)v) == v) {
			ws_futex_wake_any(word, 1);
			return;
		}
	}
}

static void robust_walk(DWORD tid, struct l_robust_head *h)
{
	int guard = 0;
	for (void **e = h->next; e && e != (void **)h && guard < 4096; e = *e, guard++)
		robust_mark((volatile int *)((char *)e + h->off), tid);
	if (h->pending)
		robust_mark((volatile int *)((char *)h->pending + h->off), tid);
}

/* this thread is ending: its robust locks become OWNER_DIED */
void ws_robust_release_current_thread(void)
{
	DWORD tid = GetCurrentThreadId();
	AcquireSRWLockExclusive(&robust_lock);
	for (int i = 0; i < 1024; i++)
		if (robust[i].tid == tid) {
			if (robust[i].head)
				robust_walk(tid, robust[i].head);
			robust[i].tid = 0;
			robust[i].head = NULL;
		}
	ReleaseSRWLockExclusive(&robust_lock);
}

/* the process is ending: every thread's robust locks become OWNER_DIED */
void ws_robust_release_all(void)
{
	AcquireSRWLockExclusive(&robust_lock);
	for (int i = 0; i < 1024; i++)
		if (robust[i].tid && robust[i].head)
			robust_walk(robust[i].tid, robust[i].head);
	ReleaseSRWLockExclusive(&robust_lock);
}

static i64 sys_futex(volatile int *addr, int op, int val, const struct l_timespec *to, volatile int *addr2, int val3)
{
	int cmd = op & 127;
	int realtime = (op & 256) != 0;
	int shared = !(op & 128) && fx;
	if (shared) {
		switch (cmd) {
		case 0:
			return futex_wait_shared(addr, val, ts_ms(to));
		case 9: {
			DWORD ms = INFINITE;
			if (to) {
				i64 left = (to->sec * 1000000000LL + to->nsec) - now_ns(realtime);
				if (left <= 0)
					return *addr != val ? -L_EAGAIN : -L_ETIMEDOUT;
				ms = (DWORD)((left + 999999) / 1000000);
			}
			return futex_wait_shared(addr, val, ms);
		}
		case 1: case 10:
			/* a shared word may also have private-path waiters in this process */
			WakeByAddressAll((PVOID)addr);
			return futex_wake_shared(addr, val);
		case 3: case 4:
			if (cmd == 4 && *addr != val3)
				return -L_EAGAIN;
			futex_wake_shared(addr, 0x7fffffff);
			futex_wake_shared(addr2, 0x7fffffff);
			return 0;
		default:
			return -L_ENOSYS;
		}
	}
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
	case 273:                                          /* set_robust_list */
		robust_set((struct l_robust_head *)a1);
		return 0;
	case 274:                                          /* get_robust_list (self) */
		if (a2)
			*(void **)a2 = robust_get();
		if (a3)
			*(u64 *)a3 = sizeof(struct l_robust_head);
		return 0;
	case 334: return 0;                                /* rseq */
	case 324: return 0;                                /* membarrier */
	case 60:                                           /* exit (this thread) */
		ws_robust_release_current_thread();
		ws_sig_thread_end();
		ExitThread((DWORD)a1);
	case 231: ws_exit_process((UINT)a1);              /* exit_group */
	default:
		*handled = 0;
		return 0;
	}
}

/* ---- every winsys thread starts through here ----
 * A thread is "starting" from CreateThread until its own code runs, i.e.
 * until the loader has finished its DLL thread-attach. RtlCloneUserProcess
 * waits for such threads, and they may need locks the forking thread holds
 * (the heap), so fork waits until none is starting (ws_threads_settle). */
static volatile LONG starting;

typedef struct { LPTHREAD_START_ROUTINE fn; void *arg; } starter;

static DWORD WINAPI start_main(LPVOID p)
{
	starter s = *(starter *)p;
	ws_free(p);
	ws_fpu_linux();
	InterlockedDecrement(&starting);
	return s.fn(s.arg);
}

HANDLE ws_create_thread(LPTHREAD_START_ROUTINE fn, void *arg, size_t stack, DWORD *tid)
{
	starter *s = ws_alloc(sizeof *s);
	if (!s)
		return NULL;
	s->fn = fn;
	s->arg = arg;
	InterlockedIncrement(&starting);
	HANDLE h = CreateThread(NULL, stack, start_main, s, 0, tid);
	if (!h) {
		InterlockedDecrement(&starting);
		ws_free(s);
	}
	return h;
}

void ws_threads_settle(void)
{
	while (starting)
		SwitchToThread();
}
