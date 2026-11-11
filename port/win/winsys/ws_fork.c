/* ws_fork.c -- fork, wait4, cross-process kill, SIGCHLD and PDEATHSIG
 * (bmc_win).
 *
 * fork() is RtlCloneUserProcess: the child is a copy-on-write image of the
 * whole address space (views of sections -- MAP_SHARED -- stay shared), the
 * inheritable handles keep their values, and only the calling thread runs in
 * it. Two limits of a cloned process shape the rest of winsys: it is not
 * registered with CSRSS, so it must not call ExitProcess or CreateProcess
 * (it leaves with TerminateProcess; spawning goes through the root), and
 * Winsock's user-mode state is unusable in it (socket data and readiness
 * never use Winsock -- ws_net.c -- and socket control is done by the root
 * process on a duplicated handle -- ws_broker.c).
 *
 * Signals between processes: each process owns a "box" (a shared page
 * holding a pending mask, plus an event). A parent creates its child's box
 * before cloning, so it can signal the child; every process inherits its
 * ancestors' boxes, so a child can signal its parent. A listener thread per
 * process turns box bits into process-directed signals, raises SIGCHLD when
 * a child exits, and the PR_SET_PDEATHSIG signal when the parent does.
 *
 * Exit status: a process ended by a signal's default action exits with
 * 0x4B4D5300|sig (root: 128+sig, as a shell expects); wait4 decodes it, and
 * a Windows exception exit code as the matching signal. */
#include "winsys.h"

int ws_is_root = 1;

typedef struct {
	ULONG Length;
	HANDLE Process;
	HANDLE Thread;
	struct { HANDLE UniqueProcess, UniqueThread; } ClientId;
	unsigned char ImageInformation[64];
} rtl_upi;
typedef LONG (NTAPI *clone_fn)(ULONG, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, HANDLE, rtl_upi *);
#define RTL_CLONE_INHERIT_HANDLES 0x2
#define STATUS_PROCESS_CLONED 0x00000129

#define SIG_EXIT_MARK 0x4B4D5300u

typedef struct { volatile LONG64 mask; volatile LONG pid; } sigbox;
typedef struct { HANDLE sec, ev; sigbox *box; } boxref;

typedef struct ws_child {
	struct ws_child *next;
	DWORD pid;
	HANDLE proc;
	boxref box;
	int notified;           /* SIGCHLD raised for its exit */
} ws_child;

static ws_child *children;
static SRWLOCK clock_ = SRWLOCK_INIT;
static boxref self_box, parent_box;
static DWORD parent_pid;
static HANDLE parent_proc;          /* inheritable handle on the parent (children only) */
static volatile LONG pdeathsig;
static HANDLE wake_ev;              /* the listener re-reads the child list */
static clone_fn clone_proc;

static int box_new(boxref *b)
{
	SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
	b->sec = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 4096, NULL);
	b->ev = CreateEventW(&sa, FALSE, FALSE, NULL);
	b->box = b->sec ? MapViewOfFile(b->sec, FILE_MAP_WRITE, 0, 0, 4096) : NULL;
	return b->sec && b->ev && b->box ? 0 : -1;
}

static void box_free(boxref *b)
{
	if (b->box)
		UnmapViewOfFile(b->box);
	if (b->sec)
		CloseHandle(b->sec);
	if (b->ev)
		CloseHandle(b->ev);
	__ws_memset(b, 0, sizeof *b);
}

static void box_post(boxref *b, int sig)
{
	InterlockedOr64(&b->box->mask, (LONG64)(1ULL << (sig - 1)));
	SetEvent(b->ev);
}

/* ---------------------------------------------------------------- listener */
static DWORD WINAPI listener(LPVOID p)
{
	(void)p;
	HANDLE hs[MAXIMUM_WAIT_OBJECTS];
	ws_child *who[MAXIMUM_WAIT_OBJECTS];
	for (;;) {
		int n = 0;
		hs[n++] = self_box.ev;
		hs[n++] = wake_ev;
		int parent_at = -1;
		if (parent_proc && pdeathsig) {
			parent_at = n;
			hs[n++] = parent_proc;
		}
		int first_child = n;
		AcquireSRWLockShared(&clock_);
		for (ws_child *c = children; c && n < MAXIMUM_WAIT_OBJECTS; c = c->next)
			if (!c->notified) {
				who[n] = c;
				hs[n++] = c->proc;
			}
		ReleaseSRWLockShared(&clock_);
		DWORD r = WaitForMultipleObjects((DWORD)n, hs, FALSE, INFINITE);
		if (r == WAIT_OBJECT_0) {
			u64 m = (u64)InterlockedExchange64(&self_box.box->mask, 0);
			for (int sig = 1; m; sig++, m >>= 1)
				if (m & 1) {
					if (sig == 9)
						ws_exit_signaled(9);
					ws_sig_raise_process(sig, 0 /* SI_USER */);
				}
		} else if (parent_at >= 0 && r == WAIT_OBJECT_0 + (DWORD)parent_at) {
			int sig = (int)InterlockedExchange(&pdeathsig, 0);
			if (sig)
				ws_sig_raise_process(sig, 0x80);
		} else if (r >= WAIT_OBJECT_0 + (DWORD)first_child && r < WAIT_OBJECT_0 + (DWORD)n) {
			ws_child *c = who[r - WAIT_OBJECT_0];
			AcquireSRWLockExclusive(&clock_);
			c->notified = 1;
			ReleaseSRWLockExclusive(&clock_);
			if (ws_sig_disposition(17) == 2)
				ws_sig_raise_process(17, 1 /* CLD_EXITED */);
		} else if (r == WAIT_FAILED) {
			Sleep(10);
		}
	}
	return 0;
}

static void start_listener(void)
{
	HANDLE th = ws_create_thread(listener, NULL, 64 * 1024, NULL);
	if (th)
		CloseHandle(th);
}

void ws_fork_init(void)
{
	HMODULE nt = GetModuleHandleW(L"ntdll.dll");
	clone_proc = (clone_fn)(void *)GetProcAddress(nt, "RtlCloneUserProcess");

	if (box_new(&self_box))
		ws_fatal("cannot create the signal box");
	self_box.box->pid = (LONG)GetCurrentProcessId();
	wake_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
	start_listener();
}

/* ---------------------------------------------------------------- fork */
void ws_fd_fork_prepare(void);
void ws_fd_fork_done(int child);
void ws_mem_fork_prepare(void);
void ws_mem_fork_done(int child);
void ws_sig_fork_prepare(void);
void ws_sig_fork_done(int child);
void ws_net_fork_child(void);
void ws_proc_fork_child(void);

static i64 sys_fork(void)
{
	if (!clone_proc)
		return -L_ENOSYS;
	ws_broker_start();             /* the root serves Winsock to its descendants */
	ws_child *c = ws_alloc(sizeof *c);
	if (!c)
		return -L_ENOMEM;
	if (box_new(&c->box)) {
		box_free(&c->box);
		ws_free(c);
		return -L_EAGAIN;
	}
	HANDLE me = NULL;
	SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
	(void)sa;
	DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &me,
			SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, TRUE, 0);
	DWORD mypid = GetCurrentProcessId();

	/* nothing another thread holds may be copied in a locked state */
	ws_sig_fork_prepare();
	ws_fd_fork_prepare();
	ws_mem_fork_prepare();
	AcquireSRWLockExclusive(&clock_);
	/* No thread may be mid-start (in its DLL thread-attach, under the
	 * loader lock): RtlCloneUserProcess waits for those, and they may want
	 * the heap lock taken below. winsys starts all its threads through
	 * ws_create_thread, so waiting for that count is enough. The loader
	 * lock itself must not be held here, for the same reason. */
	ws_threads_settle();
	HeapLock(GetProcessHeap());

	rtl_upi info;
	__ws_memset(&info, 0, sizeof info);
	info.Length = sizeof info;
	LONG st = clone_proc(RTL_CLONE_INHERIT_HANDLES, NULL, NULL, NULL, &info);

	if (st == STATUS_PROCESS_CLONED) {
		/* ---- the child ---- */
		HeapUnlock(GetProcessHeap());
		ws_is_root = 0;
		ws_child *k = children;
		children = NULL;
		ReleaseSRWLockExclusive(&clock_);
		while (k) {                    /* the parent's children are not ours */
			ws_child *nx = k->next;
			ws_free(k);
			k = nx;
		}
		ws_mem_fork_done(1);
		ws_fd_fork_done(1);
		ws_sig_fork_done(1);
		ws_net_fork_child();
		ws_broker_child();
		ws_proc_fork_child();
		parent_box = self_box;         /* our parent's box, inherited */
		self_box = c->box;             /* the box our parent made for us */
		ws_free(c);
		self_box.box->pid = (LONG)GetCurrentProcessId();
		parent_pid = mypid;
		parent_proc = me;
		pdeathsig = 0;
		wake_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
		start_listener();
		return 0;
	}

	HeapUnlock(GetProcessHeap());
	if (st < 0) {
		ReleaseSRWLockExclusive(&clock_);
		ws_mem_fork_done(0);
		ws_fd_fork_done(0);
		ws_sig_fork_done(0);
		if (me)
			CloseHandle(me);
		box_free(&c->box);
		ws_free(c);
		return -L_EAGAIN;
	}
	/* ---- the parent ---- */
	c->pid = (DWORD)(uintptr_t)info.ClientId.UniqueProcess;
	c->proc = info.Process;
	c->next = children;
	children = c;
	ReleaseSRWLockExclusive(&clock_);
	ws_mem_fork_done(0);
	ws_fd_fork_done(0);
	ws_sig_fork_done(0);
	if (info.Thread)
		CloseHandle(info.Thread);
	if (me)
		CloseHandle(me);
	SetEvent(wake_ev);
	return (i64)c->pid;
}

/* ---------------------------------------------------------------- wait4 */
static int status_of(DWORD code)
{
	if ((code & 0xFFFFFF00u) == SIG_EXIT_MARK)
		return (int)(code & 0x7f);                   /* WIFSIGNALED */
	switch (code) {
	case 0xC0000005: case 0xC00000FD: case 0xC0000409: return 11;   /* SIGSEGV */
	case 0xC000001D: case 0xC0000096: return 4;                       /* SIGILL */
	case 0xC0000094: case 0xC0000095: case 0xC000008E: return 8;      /* SIGFPE */
	case 0x80000003: return 5;                                        /* SIGTRAP */
	case 0xC0000006: return 7;                                        /* SIGBUS */
	case 0x40010004: case 0xC000013A: return 2;                       /* console kill */
	}
	return (int)((code & 0xff) << 8);                  /* WIFEXITED */
}

struct l_rusage { i64 f[18]; };

static i64 sys_wait4(int pid, int *status, int options, struct l_rusage *ru)
{
	int nohang = options & 1;
	for (;;) {
		HANDLE hs[MAXIMUM_WAIT_OBJECTS - 1];
		ws_child *who[MAXIMUM_WAIT_OBJECTS - 1];
		int n = 0;
		AcquireSRWLockShared(&clock_);
		for (ws_child *c = children; c && n < MAXIMUM_WAIT_OBJECTS - 1; c = c->next)
			if (pid == -1 || pid == 0 || pid < -1 || (DWORD)pid == c->pid) {
				who[n] = c;
				hs[n++] = c->proc;
			}
		ReleaseSRWLockShared(&clock_);
		if (!n)
			return -L_ECHILD;
		int w = ws_wait(hs, n, nohang ? 0 : INFINITE);
		if (w == WS_WAIT_TIMEOUT)
			return 0;
		if (w == WS_WAIT_INTR)
			return -L_EINTR;
		if (w < 0)
			return -L_ECHILD;
		ws_child *c = who[w];
		DWORD code = 0;
		GetExitCodeProcess(c->proc, &code);
		if (status)
			*status = status_of(code);
		if (ru)
			__ws_memset(ru, 0, sizeof *ru);
		DWORD cpid = c->pid;
		AcquireSRWLockExclusive(&clock_);
		for (ws_child **pp = &children; *pp; pp = &(*pp)->next)
			if (*pp == c) {
				*pp = c->next;
				break;
			}
		ReleaseSRWLockExclusive(&clock_);
		CloseHandle(c->proc);
		box_free(&c->box);
		ws_free(c);
		SetEvent(wake_ev);
		return (i64)cpid;
	}
}

/* ---------------------------------------------------------------- kill */
i64 ws_kill_other(int pid, int sig)
{
	if (sig < 0 || sig > 64)
		return -L_EINVAL;
	boxref *b = NULL;
	HANDLE ph = NULL;
	AcquireSRWLockShared(&clock_);
	for (ws_child *c = children; c; c = c->next)
		if (c->pid == (DWORD)pid) {
			b = &c->box;
			ph = c->proc;
			break;
		}
	ReleaseSRWLockShared(&clock_);
	if (!b && parent_box.box && (DWORD)pid == parent_pid)
		b = &parent_box;
	if (b) {
		if (ph) {
			DWORD code;
			if (GetExitCodeProcess(ph, &code) && code != STILL_ACTIVE)
				return sig ? 0 : 0;      /* a zombie: signals are discarded */
		}
		if (sig == 9 && ph)
			return TerminateProcess(ph, SIG_EXIT_MARK | 9) ? 0 : ws_err(GetLastError());
		if (sig)
			box_post(b, sig);
		return 0;
	}
	/* not related to us: only termination can be delivered */
	HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
	if (!h)
		return -L_ESRCH;
	i64 r = 0;
	DWORD code;
	if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE)
		r = -L_ESRCH;
	else if (sig != 0 && !TerminateProcess(h, SIG_EXIT_MARK | (UINT)sig))
		r = ws_err(GetLastError());
	CloseHandle(h);
	return r;
}

void ws_exit_process(UINT code)
{
	if (ws_is_root)
		ExitProcess(code);
	TerminateProcess(GetCurrentProcess(), code);   /* a clone must not call into CSRSS */
	for (;;)
		Sleep(INFINITE);
}

i64 ws_sys_fork(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	*handled = 1;
	(void)a5;
	(void)a6;
	switch (n) {
	case 57: case 58: return sys_fork();                   /* fork, vfork */
	case 56:                                               /* clone: fork-like only */
		if (a1 & 0x100)                                    /* CLONE_VM */
			return -L_ENOSYS;
		return sys_fork();
	case 61: return sys_wait4((int)a1, (int *)a2, (int)a3, (struct l_rusage *)a4);
	case 110: return ws_is_root ? 1 : (i64)parent_pid;     /* getppid */
	case 157:                                              /* prctl */
		if (a1 == 1) {                                     /* PR_SET_PDEATHSIG */
			InterlockedExchange(&pdeathsig, (LONG)a2);
			SetEvent(wake_ev);
			return 0;
		}
		if (a1 == 2) {                                     /* PR_GET_PDEATHSIG */
			*(int *)a2 = (int)pdeathsig;
			return 0;
		}
		*handled = 0;
		return 0;
	default:
		*handled = 0;
		return 0;
	}
}
