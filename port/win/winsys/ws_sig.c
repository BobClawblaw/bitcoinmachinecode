/* ws_sig.c -- POSIX signals on Win32 (bmc_win).
 *
 * Each thread that runs SysV code is registered here with a manual-reset
 * event and Linux-style pending/blocked masks. A signal is made pending on
 * one thread (process-directed ones prefer the main thread, then any thread
 * that does not block it) and that thread's event is set. Every blocking
 * wait in winsys goes through ws_wait(), which also waits on the event, so a
 * blocked read/poll/sleep/futex returns -EINTR. Handlers run on the target
 * thread at the exit of the syscall it is in (__bmc_win_syscall calls
 * ws_sig_deliver), i.e. with no winsys lock held -- a handler that
 * siglongjmps out unwinds cleanly. A thread that never makes a syscall sees
 * its signal at its next one.
 *
 * Sources: kill/tkill/tgkill on ourselves, alarm/setitimer(ITIMER_REAL), the
 * console (Ctrl+C -> SIGINT, Ctrl+Break/close -> SIGTERM/SIGHUP), and
 * hardware exceptions (vectored handler -> SIGSEGV/SIGBUS/SIGILL/SIGFPE/
 * SIGTRAP, with siginfo si_addr and the register state in the ucontext). */
#include "winsys.h"

struct l_sigaction { void *handler; u64 flags; void *restorer; u64 mask; };
typedef SV void (*sig_fn)(int);
typedef SV void (*sig_info_fn)(int, void *, void *);

#define L_SA_SIGINFO 0x4ULL
#define L_SA_RESTART 0x10000000ULL
#define L_SA_NODEFER 0x40000000ULL
#define L_SA_RESETHAND 0x80000000ULL
#define BIT(s) (1ULL << ((s) - 1))
#define UNBLOCKABLE (BIT(9) | BIT(19))          /* SIGKILL, SIGSTOP */

typedef struct ws_ts {
	struct ws_ts *next;
	DWORD tid;
	HANDLE th;
	HANDLE ev;
	volatile LONG64 pending;
	volatile LONG64 blocked;
	volatile void *futex;              /* address the thread waits on, if any */
	volatile LONG sync_io;             /* inside a synchronous pipe/console read */
	int is_main;
} ws_ts;

static ws_ts *threads;
static SRWLOCK tlock = SRWLOCK_INIT;
static __thread ws_ts *self;
static struct l_sigaction actions[65];
static SRWLOCK alock = SRWLOCK_INIT;
static volatile LONG any_handler;          /* a handler was ever installed */
static int ws_info_code[65];               /* si_code for the next delivery per signal */

/* ---------------------------------------------------------------- threads */
void ws_sig_thread_start(int is_main)
{
	ws_ts *t = ws_alloc(sizeof *t);
	if (!t)
		ws_fatal("out of memory (thread state)");
	t->tid = GetCurrentThreadId();
	DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &t->th, 0, FALSE,
			DUPLICATE_SAME_ACCESS);
	t->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
	t->is_main = is_main;
	if (!is_main && self)               /* a new thread inherits its creator's mask */
		t->blocked = self->blocked;
	AcquireSRWLockExclusive(&tlock);
	t->next = threads;
	threads = t;
	ReleaseSRWLockExclusive(&tlock);
	self = t;
}

void ws_sig_thread_inherit_mask(u64 m)
{
	if (self)
		self->blocked = (LONG64)(m & ~UNBLOCKABLE);
}

u64 ws_sig_current_mask(void)
{
	return self ? (u64)self->blocked : 0;
}

void ws_sig_thread_end(void)
{
	ws_ts *t = self;
	if (!t)
		return;
	AcquireSRWLockExclusive(&tlock);
	for (ws_ts **pp = &threads; *pp; pp = &(*pp)->next)
		if (*pp == t) {
			*pp = t->next;
			break;
		}
	ReleaseSRWLockExclusive(&tlock);
	self = NULL;
	CloseHandle(t->ev);
	CloseHandle(t->th);
	ws_free(t);
}

/* ---------------------------------------------------------------- waiting */
static int deliverable(ws_ts *t)
{
	return t && ((u64)t->pending & ~(u64)t->blocked) != 0;
}

int ws_sig_pending_here(void)
{
	return deliverable(self);
}

int ws_wait(const HANDLE *hs, int n, DWORD ms)
{
	HANDLE all[MAXIMUM_WAIT_OBJECTS];
	if (n > MAXIMUM_WAIT_OBJECTS - 1)
		n = MAXIMUM_WAIT_OBJECTS - 1;
	for (int i = 0; i < n; i++)
		all[i] = hs[i];
	int k = n;
	if (self) {
		if (deliverable(self))
			return WS_WAIT_INTR;
		all[k++] = self->ev;
	}
	if (k == 0) {
		Sleep(ms);
		return WS_WAIT_TIMEOUT;
	}
	for (;;) {
		DWORD r = WaitForMultipleObjects((DWORD)k, all, FALSE, ms);
		if (r == WAIT_TIMEOUT)
			return WS_WAIT_TIMEOUT;
		if (r >= WAIT_OBJECT_0 && r < WAIT_OBJECT_0 + (DWORD)n)
			return (int)(r - WAIT_OBJECT_0);
		if (self && r == WAIT_OBJECT_0 + (DWORD)n) {
			if (deliverable(self))
				return WS_WAIT_INTR;
			ResetEvent(self->ev);       /* only blocked signals: keep waiting */
			if (deliverable(self))
				return WS_WAIT_INTR;
			continue;
		}
		return WS_WAIT_FAILED;
	}
}

/* futex waits record their address so a signal can wake them */
void ws_sig_futex_begin(volatile void *addr)
{
	if (self)
		self->futex = addr;
}

int ws_sig_futex_end(void)
{
	if (!self)
		return 0;
	self->futex = NULL;
	return deliverable(self);
}

void ws_sig_sync_io(int on)
{
	if (self)
		InterlockedExchange(&self->sync_io, on);
}

/* ---------------------------------------------------------------- raising */
static void kick(ws_ts *t)
{
	SetEvent(t->ev);
	volatile void *f = t->futex;
	if (f)
		WakeByAddressAll((PVOID)f);
	if (t->sync_io)
		CancelSynchronousIo(t->th);
}

static void raise_on(ws_ts *t, int sig, int code)
{
	ws_info_code[sig] = code;
	InterlockedOr64(&t->pending, (LONG64)BIT(sig));
	kick(t);
}

static int ignored(int sig)
{
	void *h = actions[sig].handler;
	if (h == (void *)1)
		return 1;
	return h == NULL && (sig == 17 || sig == 23 || sig == 28 || sig == 18 || (sig >= 20 && sig <= 22));
}

/* process-directed: the main thread unless it blocks sig, else any thread
 * that does not, else (all block it) leave it pending on the main thread */
int ws_sig_raise_process(int sig, int code)
{
	if (sig < 1 || sig > 64)
		return -L_EINVAL;
	AcquireSRWLockShared(&alock);
	int ign = ignored(sig);
	ReleaseSRWLockShared(&alock);
	if (ign)
		return 0;
	AcquireSRWLockShared(&tlock);
	ws_ts *main = NULL, *pick = NULL;
	for (ws_ts *t = threads; t; t = t->next) {
		if (t->is_main)
			main = t;
		if (!pick && !((u64)t->blocked & BIT(sig)))
			pick = t;
	}
	if (main && !((u64)main->blocked & BIT(sig)))
		pick = main;
	if (!pick)
		pick = main ? main : threads;
	if (pick)
		raise_on(pick, sig, code);
	ReleaseSRWLockShared(&tlock);
	return 0;
}

static i64 raise_thread(DWORD tid, int sig)
{
	if (sig == 0)
		return 0;
	if (sig < 1 || sig > 64)
		return -L_EINVAL;
	i64 r = -L_ESRCH;
	AcquireSRWLockShared(&tlock);
	for (ws_ts *t = threads; t; t = t->next)
		if (t->tid == tid) {
			AcquireSRWLockShared(&alock);
			int ign = ignored(sig);
			ReleaseSRWLockShared(&alock);
			if (!ign)
				raise_on(t, sig, -6 /* SI_TKILL */);
			r = 0;
			break;
		}
	ReleaseSRWLockShared(&tlock);
	return r;
}

/* ---------------------------------------------------------------- delivery */
void ws_exit_signaled(int sig)
{
	/* the root reports 128+sig as a shell would; a forked process uses the
	 * marker wait4 decodes as "killed by sig" */
	ws_exit_process(ws_is_root ? 128 + (UINT)sig : 0x4B4D5300u | (UINT)sig);
}

static void default_action(int sig)
{
	if (sig == 17 || sig == 23 || sig == 28 || sig == 18 || (sig >= 19 && sig <= 22))
		return;                            /* ignore / stop / continue */
	ws_exit_signaled(sig);
}

/* Linux x86_64 siginfo_t (128 bytes) / ucontext_t (gregs at +40) */
typedef struct { int signo, err, code, pad; union { struct { int pid, uid; } kill; void *addr; } u;
		 char rest[104]; } l_siginfo;
typedef struct { u64 flags; void *link; void *ss_sp; int ss_flags, pad; u64 ss_size; i64 gregs[23];
		 void *fpregs; u64 reserved[8]; u64 sigmask; char fpstate[512]; } l_ucontext;

static void run_handler(int sig, struct l_sigaction *a, l_siginfo *si, l_ucontext *uc)
{
	ws_ts *t = self;
	LONG64 old = t ? t->blocked : 0;
	if (t) {
		u64 add = a->mask | ((a->flags & L_SA_NODEFER) ? 0 : BIT(sig));
		t->blocked = (LONG64)(((u64)old | add) & ~UNBLOCKABLE);
	}
	if (a->flags & L_SA_SIGINFO)
		((sig_info_fn)a->handler)(sig, si, uc);
	else
		((sig_fn)a->handler)(sig);
	if (t)
		t->blocked = old;
}

i64 ws_sig_deliver(i64 r, int *restart)
{
	ws_ts *t = self;
	*restart = 0;
	int interrupted = r == -L_EINTR;
	int all_restart = 1, ran = 0;
	while (deliverable(t)) {
		u64 d = (u64)t->pending & ~(u64)t->blocked;
		int sig = 1;
		while (!(d & 1)) {
			d >>= 1;
			sig++;
		}
		InterlockedAnd64(&t->pending, ~(LONG64)BIT(sig));
		if (!t->pending)
			ResetEvent(t->ev);
		AcquireSRWLockExclusive(&alock);
		struct l_sigaction a = actions[sig];
		if ((a.flags & L_SA_RESETHAND) && a.handler != (void *)1)
			actions[sig].handler = NULL;
		ReleaseSRWLockExclusive(&alock);
		if (a.handler == (void *)1)
			continue;
		if (a.handler == NULL) {
			default_action(sig);
			continue;
		}
		l_siginfo si;
		l_ucontext uc;
		__ws_memset(&si, 0, sizeof si);
		__ws_memset(&uc, 0, sizeof uc);
		si.signo = sig;
		si.code = ws_info_code[sig];
		si.u.kill.pid = (int)GetCurrentProcessId();
		si.u.kill.uid = 1000;
		uc.sigmask = (u64)t->blocked;
		ran = 1;
		if (!(a.flags & L_SA_RESTART))
			all_restart = 0;
		run_handler(sig, &a, &si, &uc);
	}
	if (interrupted && ran && all_restart)
		*restart = 1;
	return r;
}

/* A seccomp filter answered SECCOMP_RET_TRAP: SIGSYS now, on this thread,
 * with the call's number and arguments; the handler's RAX is the result.
 * Blocked, ignored or defaulted, it kills the process (Linux forces it). */
i64 ws_sig_seccomp_trap(i64 nr, const i64 *a, unsigned data)
{
	AcquireSRWLockShared(&alock);
	struct l_sigaction act = actions[31];
	ReleaseSRWLockShared(&alock);
	ws_ts *t = self;
	if (act.handler == NULL || act.handler == (void *)1 || (t && ((u64)t->blocked & BIT(31))))
		ws_exit_signaled(31);
	l_siginfo si;
	l_ucontext uc;
	__ws_memset(&si, 0, sizeof si);
	__ws_memset(&uc, 0, sizeof uc);
	si.signo = 31;
	si.err = (int)data;
	si.code = 1;                                   /* SYS_SECCOMP */
	char *raw = (char *)&si;
	int sc = (int)nr;
	uint32_t arch = 0xC000003EU;
	__ws_memcpy(raw + 24, &sc, 4);                 /* si_syscall (si_call_addr at +16 stays 0) */
	__ws_memcpy(raw + 28, &arch, 4);               /* si_arch */
	uc.gregs[8] = a[0];                            /* RDI */
	uc.gregs[9] = a[1];                            /* RSI */
	uc.gregs[12] = a[2];                           /* RDX */
	uc.gregs[2] = a[3];                            /* R10 */
	uc.gregs[0] = a[4];                            /* R8 */
	uc.gregs[1] = a[5];                            /* R9 */
	uc.gregs[13] = -38;                            /* RAX: -ENOSYS unless the handler answers */
	uc.sigmask = t ? (u64)t->blocked : 0;
	run_handler(31, &act, &si, &uc);
	return uc.gregs[13];
}

/* ---------------------------------------------------------------- faults */
void ws_crash_report(PEXCEPTION_POINTERS ep, const char *what);

static LONG CALLBACK veh(PEXCEPTION_POINTERS ep)
{
	DWORD code = ep->ExceptionRecord->ExceptionCode;
	if (code == EXCEPTION_ACCESS_VIOLATION && GetEnvironmentVariableA("BMC_WIN_CRASHLOG", NULL, 0))
		ws_crash_report(ep, "bmc_win first-chance AV:");
	int sig;
	switch (code) {
	case EXCEPTION_ACCESS_VIOLATION: case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: sig = 11; break;
	case EXCEPTION_IN_PAGE_ERROR: case EXCEPTION_DATATYPE_MISALIGNMENT: sig = 7; break;
	case EXCEPTION_ILLEGAL_INSTRUCTION: case EXCEPTION_PRIV_INSTRUCTION: sig = 4; break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO: case EXCEPTION_INT_OVERFLOW:
	case EXCEPTION_FLT_DIVIDE_BY_ZERO: case EXCEPTION_FLT_INVALID_OPERATION: sig = 8; break;
	case EXCEPTION_BREAKPOINT: case EXCEPTION_SINGLE_STEP: sig = 5; break;
	default: return EXCEPTION_CONTINUE_SEARCH;   /* stack overflow, C++ ..., debugger events */
	}
	/* a fault while its signal is blocked -- inside its own handler, say --
	 * kills the process with the default action (the kernel's force_sig):
	 * running the handler again would fault again, forever */
	if (self && ((u64)self->blocked & BIT(sig)))
		ws_exit_signaled(sig);
	AcquireSRWLockExclusive(&alock);
	struct l_sigaction a = actions[sig];
	if ((a.flags & L_SA_RESETHAND) && a.handler != NULL && a.handler != (void *)1)
		actions[sig].handler = NULL;           /* SA_RESETHAND: the next one is fatal */
	ReleaseSRWLockExclusive(&alock);
	if (a.handler == NULL || a.handler == (void *)1 || !self)
		return EXCEPTION_CONTINUE_SEARCH;
	l_siginfo si;
	l_ucontext uc;
	__ws_memset(&si, 0, sizeof si);
	__ws_memset(&uc, 0, sizeof uc);
	si.signo = sig;
	si.code = 1;
	PCONTEXT c = ep->ContextRecord;
	si.u.addr = code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR
		    ? (void *)ep->ExceptionRecord->ExceptionInformation[1] : (void *)c->Rip;
	i64 *g = uc.gregs;
	g[0] = (i64)c->R8; g[1] = (i64)c->R9; g[2] = (i64)c->R10; g[3] = (i64)c->R11;
	g[4] = (i64)c->R12; g[5] = (i64)c->R13; g[6] = (i64)c->R14; g[7] = (i64)c->R15;
	g[8] = (i64)c->Rdi; g[9] = (i64)c->Rsi; g[10] = (i64)c->Rbp; g[11] = (i64)c->Rbx;
	g[12] = (i64)c->Rdx; g[13] = (i64)c->Rax; g[14] = (i64)c->Rcx; g[15] = (i64)c->Rsp;
	g[16] = (i64)c->Rip; g[17] = (i64)c->EFlags; g[22] = (i64)si.u.addr;
	uc.sigmask = (u64)self->blocked;
	run_handler(sig, &a, &si, &uc);
	/* the handler returned: resume where it says (a handler that only
	 * logs and re-raises never gets here) */
	c->R8 = (DWORD64)g[0]; c->R9 = (DWORD64)g[1]; c->R10 = (DWORD64)g[2]; c->R11 = (DWORD64)g[3];
	c->R12 = (DWORD64)g[4]; c->R13 = (DWORD64)g[5]; c->R14 = (DWORD64)g[6]; c->R15 = (DWORD64)g[7];
	c->Rdi = (DWORD64)g[8]; c->Rsi = (DWORD64)g[9]; c->Rbp = (DWORD64)g[10]; c->Rbx = (DWORD64)g[11];
	c->Rdx = (DWORD64)g[12]; c->Rax = (DWORD64)g[13]; c->Rcx = (DWORD64)g[14]; c->Rsp = (DWORD64)g[15];
	c->Rip = (DWORD64)g[16];
	return EXCEPTION_CONTINUE_EXECUTION;
}

/* ---------------------------------------------------------------- console */
static BOOL WINAPI ctrl_handler(DWORD type)
{
	int sig = type == CTRL_C_EVENT ? 2 : type == CTRL_CLOSE_EVENT ? 1 : 15;
	AcquireSRWLockShared(&alock);
	void *h = actions[sig].handler;
	ReleaseSRWLockShared(&alock);
	if (h == NULL)
		return FALSE;                      /* default action: let Windows end the process */
	ws_sig_raise_process(sig, 0x80 /* SI_KERNEL */);
	if (type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT)
		Sleep(10000);                      /* Windows ends us when this returns */
	return TRUE;
}

/* ---------------------------------------------------------------- timers */
struct l_timeval { i64 sec, usec; };
struct l_itimerval { struct l_timeval interval, value; };

static HANDLE itimer;
static i64 it_due_ms, it_interval_ms;        /* GetTickCount64 deadline, period */
static SRWLOCK itlock = SRWLOCK_INIT;

static DWORD WINAPI itimer_main(LPVOID p)
{
	(void)p;
	for (;;) {
		WaitForSingleObject(itimer, INFINITE);
		AcquireSRWLockExclusive(&itlock);
		int fire = it_due_ms && (i64)GetTickCount64() >= it_due_ms - 1;
		if (fire) {
			if (it_interval_ms) {
				it_due_ms += it_interval_ms;
				LARGE_INTEGER due;
				due.QuadPart = -(it_interval_ms * 10000);
				SetWaitableTimer(itimer, &due, 0, NULL, NULL, FALSE);
			} else {
				it_due_ms = 0;
			}
		}
		ReleaseSRWLockExclusive(&itlock);
		if (fire)
			ws_sig_raise_process(14, 0x80);  /* SIGALRM */
	}
	return 0;
}

static i64 set_itimer(i64 value_ms, i64 interval_ms, i64 *old_value_ms, i64 *old_interval_ms)
{
	AcquireSRWLockExclusive(&itlock);
	if (!itimer) {
		itimer = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
		if (!itimer)
			itimer = CreateWaitableTimerW(NULL, FALSE, NULL);
		HANDLE th = ws_create_thread(itimer_main, NULL, 64 * 1024, NULL);
		if (th)
			CloseHandle(th);
	}
	i64 now = (i64)GetTickCount64();
	if (old_value_ms)
		*old_value_ms = it_due_ms ? (it_due_ms > now ? it_due_ms - now : 1) : 0;
	if (old_interval_ms)
		*old_interval_ms = it_interval_ms;
	it_interval_ms = interval_ms;
	if (value_ms > 0) {
		it_due_ms = now + value_ms;
		LARGE_INTEGER due;
		due.QuadPart = -(value_ms * 10000);
		SetWaitableTimer(itimer, &due, 0, NULL, NULL, FALSE);
	} else {
		it_due_ms = 0;
		CancelWaitableTimer(itimer);
	}
	ReleaseSRWLockExclusive(&itlock);
	return 0;
}

static i64 tv_ms(const struct l_timeval *tv)
{
	i64 ms = tv->sec * 1000 + (tv->usec + 999) / 1000;
	return ms;
}

static void ms_tv(i64 ms, struct l_timeval *tv)
{
	tv->sec = ms / 1000;
	tv->usec = (ms % 1000) * 1000;
}

/* ---------------------------------------------------------------- syscalls */
static i64 sys_rt_sigaction(int sig, const struct l_sigaction *act, struct l_sigaction *old)
{
	if (sig < 1 || sig > 64)
		return -L_EINVAL;
	if (act && (sig == 9 || sig == 19))
		return -L_EINVAL;
	AcquireSRWLockExclusive(&alock);
	if (old)
		*old = actions[sig];
	if (act) {
		actions[sig] = *act;
		actions[sig].mask &= ~UNBLOCKABLE;
		if (act->handler != NULL && act->handler != (void *)1)
			InterlockedExchange(&any_handler, 1);
	}
	ReleaseSRWLockExclusive(&alock);
	return 0;
}

static i64 sys_rt_sigprocmask(int how, const u64 *set, u64 *old)
{
	ws_ts *t = self;
	u64 cur = t ? (u64)t->blocked : 0;
	if (old)
		*old = cur;
	if (!set || !t)
		return 0;
	u64 nw;
	switch (how) {
	case 0: nw = cur | *set; break;          /* SIG_BLOCK */
	case 1: nw = cur & ~*set; break;         /* SIG_UNBLOCK */
	case 2: nw = *set; break;                /* SIG_SETMASK */
	default: return -L_EINVAL;
	}
	t->blocked = (LONG64)(nw & ~UNBLOCKABLE);
	if (deliverable(t))
		SetEvent(t->ev);
	return 0;
}

static i64 sys_rt_sigsuspend(const u64 *mask)
{
	ws_ts *t = self;
	if (!t)
		return -L_EINTR;
	LONG64 old = t->blocked;
	t->blocked = (LONG64)(*mask & ~UNBLOCKABLE);
	while (ws_wait(NULL, 0, INFINITE) != WS_WAIT_INTR)
		;
	/* deliver under the temporary mask, then restore it */
	int restart;
	ws_sig_deliver(-L_EINTR, &restart);
	t->blocked = old;
	return -L_EINTR;
}

struct l_ts { i64 sec, nsec; };

static i64 sys_rt_sigtimedwait(const u64 *set, l_siginfo *info, const struct l_ts *to)
{
	ws_ts *t = self;
	if (!t)
		return -L_EAGAIN;
	DWORD ms = to ? (DWORD)(to->sec * 1000 + (to->nsec + 999999) / 1000000) : INFINITE;
	i64 deadline = (i64)GetTickCount64() + ms;
	for (;;) {
		u64 hit = (u64)t->pending & *set;
		if (hit) {
			int sig = 1;
			while (!(hit & 1)) {
				hit >>= 1;
				sig++;
			}
			InterlockedAnd64(&t->pending, ~(LONG64)BIT(sig));
			if (info) {
				__ws_memset(info, 0, sizeof *info);
				info->signo = sig;
				info->code = ws_info_code[sig];
			}
			return sig;
		}
		i64 left = to ? deadline - (i64)GetTickCount64() : INFINITE;
		if (to && left <= 0)
			return -L_EAGAIN;
		/* the wanted signals are blocked, so ws_wait would not see them:
		 * wait on the event directly */
		HANDLE ev = t->ev;
		if (WaitForSingleObject(ev, to ? (DWORD)left : INFINITE) == WAIT_OBJECT_0 && !(t->pending & ~0LL))
			ResetEvent(ev);
		if (deliverable(t))
			return -L_EINTR;
	}
}

i64 ws_sys_sig(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	*handled = 1;
	(void)a5;
	(void)a6;
	i64 ov, oi;
	switch (n) {
	case 13: return sys_rt_sigaction((int)a1, (const struct l_sigaction *)a2, (struct l_sigaction *)a3);
	case 14: return sys_rt_sigprocmask((int)a1, (const u64 *)a2, (u64 *)a3);
	case 127:                              /* rt_sigpending */
		*(u64 *)a1 = self ? (u64)self->pending & (u64)self->blocked : 0;
		return 0;
	case 130: return sys_rt_sigsuspend((const u64 *)a1);
	case 128: return sys_rt_sigtimedwait((const u64 *)a1, (l_siginfo *)a2, (const struct l_ts *)a3);
	case 34:                               /* pause */
		while (ws_wait(NULL, 0, INFINITE) != WS_WAIT_INTR)
			;
		return -L_EINTR;
	case 131: return 0;                    /* sigaltstack: handlers run on the thread stack */
	case 200: return raise_thread((DWORD)a1, (int)a2);                      /* tkill */
	case 234:                                                                /* tgkill */
		if (a1 != (i64)GetCurrentProcessId())
			return -L_ESRCH;
		return raise_thread((DWORD)a2, (int)a3);
	case 37: {                                                               /* alarm */
		set_itimer(a1 * 1000, 0, &ov, &oi);
		return (ov + 999) / 1000;
	}
	case 38: {                                                               /* setitimer */
		if (a1 != 0)
			return -L_EINVAL;              /* only ITIMER_REAL */
		const struct l_itimerval *nv = (const struct l_itimerval *)a2;
		struct l_itimerval *old = (struct l_itimerval *)a3;
		set_itimer(nv ? tv_ms(&nv->value) : 0, nv ? tv_ms(&nv->interval) : 0, &ov, &oi);
		if (old) {
			ms_tv(ov, &old->value);
			ms_tv(oi, &old->interval);
		}
		return 0;
	}
	case 36: {                                                               /* getitimer */
		if (a1 != 0)
			return -L_EINVAL;
		struct l_itimerval *cur = (struct l_itimerval *)a2;
		AcquireSRWLockShared(&itlock);
		i64 now = (i64)GetTickCount64();
		ms_tv(it_due_ms ? (it_due_ms > now ? it_due_ms - now : 1) : 0, &cur->value);
		ms_tv(it_interval_ms, &cur->interval);
		ReleaseSRWLockShared(&itlock);
		return 0;
	}
	default:
		*handled = 0;
		return 0;
	}
}

i64 ws_sig_kill_self(int sig)
{
	if (sig == 0)
		return 0;
	if (sig < 1 || sig > 64)
		return -L_EINVAL;
	if (sig == 9)
		ws_exit_signaled(9);
	return ws_sig_raise_process(sig, 0 /* SI_USER */);
}

/* a crash nobody handles: robust locks the process holds become OWNER_DIED
 * before it goes, as the kernel would make them */
static void put_hex(const char *label, u64 v)
{
	char b[48];
	int i = 0, k = 0;
	char t[17];
	do {
		t[k++] = "0123456789abcdef"[v & 15];
		v >>= 4;
	} while (v);
	b[i++] = ' ';
	while (*label)
		b[i++] = *label++;
	b[i++] = '=';
	while (k)
		b[i++] = t[--k];
	b[i] = 0;
	ws_write_stderr(b);
}

/* BMC_WIN_CRASHLOG=1: where a process died (symbolize rip with the linker
 * map); works in a forked process too, where no debugger can attach */
void ws_crash_report(PEXCEPTION_POINTERS ep, const char *what)
{
	{
		PCONTEXT c = ep->ContextRecord;
		ws_write_stderr(what);
		put_hex("pid", GetCurrentProcessId());
		put_hex("tid", GetCurrentThreadId());
		put_hex("code", ep->ExceptionRecord->ExceptionCode);
		put_hex("rip", c->Rip);
		put_hex("addr", ep->ExceptionRecord->NumberParameters > 1 ? ep->ExceptionRecord->ExceptionInformation[1] : 0);
		put_hex("rsp", c->Rsp);
		put_hex("rax", c->Rax);
		put_hex("rcx", c->Rcx);
		put_hex("rdx", c->Rdx);
		put_hex("rdi", c->Rdi);
		put_hex("rsi", c->Rsi);
		HMODULE mod = NULL;
		wchar_t mname[MAX_PATH];
		if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				       (LPCWSTR)c->Rip, &mod) && GetModuleFileNameW(mod, mname, MAX_PATH)) {
			char *u = ws_w_to_utf8(mname);
			ws_write_stderr(" module=");
			ws_write_stderr(u ? u : "?");
			put_hex("base", (u64)mod);
			ws_free(u);
		}
		ws_write_stderr("\nstack:");
		u64 *sp = (u64 *)c->Rsp;
		for (int i = 0; i < 64; i++)
			if (sp[i] >= 0x10000000 && sp[i] < 0x20000000)
				put_hex("", sp[i]);
		ws_write_stderr("\n");
	}
}

static LONG WINAPI last_chance(PEXCEPTION_POINTERS ep)
{
	if (GetEnvironmentVariableA("BMC_WIN_CRASHLOG", NULL, 0))
		ws_crash_report(ep, "bmc_win crash:");
	ws_robust_release_all();
	return EXCEPTION_CONTINUE_SEARCH;
}

void ws_sig_init(void)
{
	ws_sig_thread_start(1);
	AddVectoredExceptionHandler(1, veh);
	SetUnhandledExceptionFilter(last_chance);
	SetConsoleCtrlHandler(ctrl_handler, TRUE);
}

/* ---- fork (ws_fork.c) ----
 * The child has only the forking thread: its registry is rebuilt around it
 * with a fresh event, pending signals are cleared, dispositions and the
 * mask are kept, and timers are not inherited (POSIX). */
void ws_sig_fork_prepare(void)
{
	AcquireSRWLockExclusive(&alock);
	AcquireSRWLockExclusive(&itlock);
	AcquireSRWLockExclusive(&tlock);
}

void ws_sig_fork_done(int child)
{
	if (child) {
		ws_ts *t = self;
		threads = t;
		if (t) {
			t->next = NULL;
			t->is_main = 1;
			t->pending = 0;
			t->futex = NULL;
			t->sync_io = 0;
			t->tid = GetCurrentThreadId();
			t->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
			DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &t->th, 0, FALSE,
					DUPLICATE_SAME_ACCESS);
		}
		itimer = NULL;
		it_due_ms = 0;
		it_interval_ms = 0;
	}
	/* the child re-initializes rather than releases: a parent thread waiting
	 * on it at the fork left a ghost in its waiter list, and a release could
	 * hand it to that ghost */
	if (child) {
		InitializeSRWLock(&tlock);
		InitializeSRWLock(&itlock);
		InitializeSRWLock(&alock);
		return;
	}
	ReleaseSRWLockExclusive(&tlock);
	ReleaseSRWLockExclusive(&itlock);
	ReleaseSRWLockExclusive(&alock);
}

int ws_sig_disposition(int sig)
{
	/* 0 default, 1 ignore, 2 handler */
	AcquireSRWLockShared(&alock);
	void *h = actions[sig].handler;
	ReleaseSRWLockShared(&alock);
	return h == NULL ? 0 : h == (void *)1 ? 1 : 2;
}

/* take one deliverable pending signal without running its handler (execve's
 * stand-in forwards it to the program instead); 0 when none */
int ws_sig_take_pending(void)
{
	ws_ts *t = self;
	if (!deliverable(t))
		return 0;
	u64 d = (u64)t->pending & ~(u64)t->blocked;
	int sig = 1;
	while (!(d & 1)) {
		d >>= 1;
		sig++;
	}
	InterlockedAnd64(&t->pending, ~(LONG64)BIT(sig));
	if (!t->pending)
		ResetEvent(t->ev);
	return sig;
}
