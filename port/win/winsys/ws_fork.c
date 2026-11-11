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

/* pids this process has reaped: gone, as on Linux, even while Windows keeps
 * the process object alive for some other holder (/proc reports them absent) */
static volatile LONG reaped_pid[256];
static volatile LONG reaped_at;

int ws_pid_reaped(DWORD pid)
{
	for (int i = 0; i < 256; i++)
		if ((DWORD)reaped_pid[i] == pid)
			return 1;
	return 0;
}
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

/* ---- the public box: signals from processes that are not our parent or
 * child (a test signalling a daemon's worker; an exec stand-in passing a
 * signal on to the program it started). A section and an event named after
 * the pid in the session's BaseNamedObjects, created and opened through the
 * native API by absolute name: kernel32's cached named-object directory
 * handle is not inheritable, so in a forked process it is stale (the
 * CreatePipe trap). */
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } nt_ustr;
typedef struct { ULONG Length; HANDLE RootDirectory; nt_ustr *ObjectName; ULONG Attributes;
		 PVOID SecurityDescriptor, SecurityQualityOfService; } nt_oattr;
typedef LONG (NTAPI *nt_create_section_fn)(HANDLE *, ACCESS_MASK, nt_oattr *, LARGE_INTEGER *, ULONG, ULONG, HANDLE);
typedef LONG (NTAPI *nt_open_fn)(HANDLE *, ACCESS_MASK, nt_oattr *);
typedef LONG (NTAPI *nt_create_event_fn)(HANDLE *, ACCESS_MASK, nt_oattr *, int, BOOLEAN);
static boxref pub_box;

static void pub_name(wchar_t *out, const wchar_t *kind, DWORD pid)
{
	DWORD sess = 0;
	ProcessIdToSessionId(GetCurrentProcessId(), &sess);
	const wchar_t *parts[4] = { L"\\Sessions\\", NULL, L"\\BaseNamedObjects\\bmc-", kind };
	char num[24];
	wchar_t *o = out;
	for (int i = 0; i < 4; i++) {
		if (i == 1) {
			ws_fmt_u64(num, sess);
			for (char *q = num; *q; q++)
				*o++ = (wchar_t)*q;
			continue;
		}
		for (const wchar_t *q = parts[i]; *q; q++)
			*o++ = *q;
	}
	*o++ = L'-';
	ws_fmt_u64(num, pid);
	for (char *q = num; *q; q++)
		*o++ = (wchar_t)*q;
	*o = 0;
}

static void pub_oa(nt_oattr *oa, nt_ustr *us, wchar_t *name)
{
	us->Length = (USHORT)(ws_wcslen(name) * sizeof(wchar_t));
	us->MaximumLength = (USHORT)(us->Length + sizeof(wchar_t));
	us->Buffer = name;
	__ws_memset(oa, 0, sizeof *oa);
	oa->Length = sizeof *oa;
	oa->ObjectName = us;
	oa->Attributes = 0x40;                       /* OBJ_CASE_INSENSITIVE */
}

static void pub_box_create(void)
{
	HMODULE nt = GetModuleHandleW(L"ntdll.dll");
	nt_create_section_fn cs = (nt_create_section_fn)(void *)GetProcAddress(nt, "NtCreateSection");
	nt_create_event_fn ce = (nt_create_event_fn)(void *)GetProcAddress(nt, "NtCreateEvent");
	__ws_memset(&pub_box, 0, sizeof pub_box);
	if (!cs || !ce)
		return;
	wchar_t name[160];
	nt_ustr us;
	nt_oattr oa;
	DWORD pid = GetCurrentProcessId();
	pub_name(name, L"sig", pid);
	pub_oa(&oa, &us, name);
	LARGE_INTEGER sz;
	sz.QuadPart = 4096;
	HANDLE sec = NULL, ev = NULL;
	if (cs(&sec, SECTION_ALL_ACCESS, &oa, &sz, PAGE_READWRITE, SEC_COMMIT, NULL) < 0)
		return;
	pub_name(name, L"sigev", pid);
	pub_oa(&oa, &us, name);
	if (ce(&ev, EVENT_ALL_ACCESS, &oa, 1 /* SynchronizationEvent */, FALSE) < 0) {
		CloseHandle(sec);
		return;
	}
	sigbox *b = MapViewOfFile(sec, FILE_MAP_WRITE, 0, 0, 4096);
	if (!b) {
		CloseHandle(sec);
		CloseHandle(ev);
		return;
	}
	b->pid = (LONG)pid;
	pub_box.sec = sec;
	pub_box.ev = ev;
	pub_box.box = b;
}

/* post sig to process pid's public box: 1 = delivered, 0 = it has none */
static int pub_post(DWORD pid, int sig)
{
	HMODULE nt = GetModuleHandleW(L"ntdll.dll");
	nt_open_fn os = (nt_open_fn)(void *)GetProcAddress(nt, "NtOpenSection");
	nt_open_fn oe = (nt_open_fn)(void *)GetProcAddress(nt, "NtOpenEvent");
	if (!os || !oe)
		return 0;
	wchar_t name[160];
	nt_ustr us;
	nt_oattr oa;
	boxref b;
	__ws_memset(&b, 0, sizeof b);
	pub_name(name, L"sig", pid);
	pub_oa(&oa, &us, name);
	if (os(&b.sec, SECTION_MAP_WRITE | SECTION_MAP_READ, &oa) < 0)
		return 0;
	pub_name(name, L"sigev", pid);
	pub_oa(&oa, &us, name);
	int ok = 0;
	if (oe(&b.ev, EVENT_MODIFY_STATE, &oa) >= 0) {
		b.box = MapViewOfFile(b.sec, FILE_MAP_WRITE, 0, 0, 4096);
		if (b.box && (DWORD)b.box->pid == pid) {
			if (sig)
				box_post(&b, sig);
			ok = 1;
		}
	}
	box_free(&b);
	return ok;
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
		int pub_at = -1;
		if (pub_box.ev) {
			pub_at = n;
			hs[n++] = pub_box.ev;
		}
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
		if (r == WAIT_OBJECT_0 || (pub_at >= 0 && r == WAIT_OBJECT_0 + (DWORD)pub_at)) {
			u64 m = (u64)InterlockedExchange64(&self_box.box->mask, 0);
			if (pub_box.box)
				m |= (u64)InterlockedExchange64(&pub_box.box->mask, 0);
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
	ws_futex_shared_init();
	self_box.box->pid = (LONG)GetCurrentProcessId();
	pub_box_create();
	wake_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
	start_listener();
	ws_prof_start(0);
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
	ws_heap_lock();
	HeapLock(GetProcessHeap());

	rtl_upi info;
	__ws_memset(&info, 0, sizeof info);
	info.Length = sizeof info;
	LONG st = clone_proc(RTL_CLONE_INHERIT_HANDLES, NULL, NULL, NULL, &info);

	if (st == STATUS_PROCESS_CLONED) {
		/* ---- the child ---- */
		HeapUnlock(GetProcessHeap());
		ws_heap_reset_child();
		ws_is_root = 0;
		ws_child *k = children;
		children = NULL;
		ReleaseSRWLockExclusive(&clock_);
		while (k) {                    /* the parent's children are not ours */
			ws_child *nx = k->next;
			ws_free(k);
			k = nx;
		}
		/* the PEB's current-directory handle is not inheritable, so it is
		 * stale here; ws_path resolves relative paths from the PEB's path
		 * string instead (touching the handle in a clone can hang) */
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
		pub_box_create();              /* the parent's handles are not ours (not inheritable) */
		wake_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
		start_listener();
		ws_prof_start(1);
		return 0;
	}

	HeapUnlock(GetProcessHeap());
	ws_heap_unlock();
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
	/* this child's handles were inheritable for its own clone only: a later
	 * fork must not hand them on (an inherited process handle would keep an
	 * exited child alive after it is reaped) */
	SetHandleInformation(c->proc, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(c->box.sec, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(c->box.ev, HANDLE_FLAG_INHERIT, 0);
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
	/* a Cygwin/MSYS program (Git's sh) dead by a signal exits with
	 * signal << 8, e.g. 0xB00 for SIGSEGV; a normal exit is the status
	 * itself. (A native exit code of exactly that shape reads as a signal;
	 * Linux would have truncated it to 0 anyway.) */
	if (code >= 0x100 && code <= 0x4000 && !(code & 0xff))
		return (int)(code >> 8);                     /* WIFSIGNALED */
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
		if (code > 255 && (code & 0xFFFFFF00u) != SIG_EXIT_MARK && GetEnvironmentVariableA("BMC_WIN_CRASHLOG", NULL, 0)) {
			char num[24], hx[24];
			int k = 0;
			u64 v = code;
			do {
				hx[k++] = "0123456789abcdef"[v & 15];
				v >>= 4;
			} while (v);
			for (int i = 0; i < k; i++)
				num[i] = hx[k - 1 - i];
			num[k] = 0;
			ws_write_stderr("bmc_win: child exited with Windows status 0x");
			ws_write_stderr(num);
			ws_write_stderr("\n");
		}
		if (status)
			*status = status_of(code);
		if (ru)
			__ws_memset(ru, 0, sizeof *ru);
		DWORD cpid = c->pid;
		reaped_pid[(InterlockedIncrement(&reaped_at) - 1) & 255] = (LONG)cpid;
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
/* SIGSTOP / SIGCONT: the whole process suspended or resumed, as the kernel
 * stops every thread of a stopped process. 1 = done, 0 = no such process. */
typedef LONG (NTAPI *nt_proc_fn)(HANDLE);
static int suspend_resume(DWORD pid, int resume)
{
	static nt_proc_fn fs, fr;
	if (!fs) {
		HMODULE nt = GetModuleHandleW(L"ntdll.dll");
		fs = (nt_proc_fn)(void *)GetProcAddress(nt, "NtSuspendProcess");
		fr = (nt_proc_fn)(void *)GetProcAddress(nt, "NtResumeProcess");
	}
	HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!h)
		return 0;
	DWORD code;
	int alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
	if (alive && (resume ? fr : fs))
		(resume ? fr : fs)(h);
	CloseHandle(h);
	return alive;
}

i64 ws_kill_other(int pid, int sig)
{
	if (sig < 0 || sig > 64)
		return -L_EINVAL;
	if (sig == 19)                                     /* SIGSTOP: cannot be caught */
		return suspend_resume((DWORD)pid, 0) ? 0 : -L_ESRCH;
	if (sig == 18 && !suspend_resume((DWORD)pid, 1))   /* SIGCONT: resume, then deliver */
		return -L_ESRCH;
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
		if (sig)
			box_post(b, sig);           /* SIGKILL too: the target cleans up, then ends */
		if (sig == 9 && ph && WaitForSingleObject(ph, 2000) == WAIT_TIMEOUT)
			TerminateProcess(ph, SIG_EXIT_MARK | 9);   /* it did not: as the kernel would */
		return 0;
	}
	/* not related to us: only termination can be delivered -- or a stop. A
	 * signal whose default action is to do nothing (SIGCONT once resumed,
	 * SIGCHLD, SIGURG, SIGWINCH) must not end the process. */
	if (sig != 9 && pub_post((DWORD)pid, sig))        /* another winsys process: a real signal */
		return 0;
	if (sig == 9 && pub_post((DWORD)pid, 9)) {         /* SIGKILL: it cleans up, then ends -- or is ended */
		HANDLE kh = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, (DWORD)pid);
		if (kh) {
			if (WaitForSingleObject(kh, 2000) == WAIT_TIMEOUT)
				TerminateProcess(kh, SIG_EXIT_MARK | 9);
			CloseHandle(kh);
		}
		return 0;
	}
	if (sig >= 20 && sig <= 22)                        /* SIGTSTP / SIGTTIN / SIGTTOU */
		return suspend_resume((DWORD)pid, 0) ? 0 : -L_ESRCH;
	int harmless = sig == 18 || sig == 17 || sig == 23 || sig == 28;
	HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
	if (!h)
		return -L_ESRCH;
	i64 r = 0;
	DWORD code;
	if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE)
		r = -L_ESRCH;
	else if (sig != 0 && !harmless && !TerminateProcess(h, SIG_EXIT_MARK | (UINT)sig))
		r = ws_err(GetLastError());
	CloseHandle(h);
	return r;
}

static void exit_note(const char *what)
{
	/* BMC_WIN_EXITDEBUG=<file>: appended there (a worker's stderr is a
	 * pipe whose reader may be gone by now) */
	wchar_t path[MAX_PATH];
	if (!GetEnvironmentVariableW(L"BMC_WIN_EXITDEBUG", path, MAX_PATH))
		return;
	char line[160], a[24];
	size_t n = 0;
	const char *parts[6] = { "exit ", NULL, " ", what, " at ", NULL };
	for (int i = 0; i < 6; i++) {
		const char *s = parts[i];
		if (i == 1 || i == 5) {
			ws_fmt_u64(a, i == 1 ? GetCurrentProcessId() : GetTickCount64() % 10000000);
			s = a;
		}
		while (*s && n < sizeof line - 2)
			line[n++] = *s++;
	}
	line[n++] = '\n';
	HANDLE f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
	if (f != INVALID_HANDLE_VALUE) {
		DWORD w;
		WriteFile(f, line, (DWORD)n, &w, NULL);
		CloseHandle(f);
	}
}

void ws_exit_process(UINT code)
{
	exit_note("start");
	ws_robust_release_all();
	exit_note("robust released");
	if (ws_is_root)
		ExitProcess(code);
	ws_fd_exit_sockets();                          /* graceful where we hold the last handle */
	exit_note("sockets closed; terminating");
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

DWORD ws_parent_pid_of_self(void)
{
	return ws_is_root ? 1 : parent_pid;
}
