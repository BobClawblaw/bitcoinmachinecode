/* ws_prof.c -- a sampling profiler for bmc_win processes (debug aid).
 *
 * BMC_WIN_PROF=<path>: every process (forked ones included) runs a thread
 * that, about every 2 ms, suspends each other thread of the process, reads
 * its instruction pointer and resumes it, counting RIPs in a table; the
 * syscall dispatcher counts calls by number. Every 5 s the totals are
 * written to <path>#<pid> ("r <rip hex> <count>" and "s <nr> <count>"
 * lines); tools/prof_report.py symbolizes them with the linker map.
 *
 * Attaching a debugger is not an option here: lldb's detach kills a cloned
 * process (STATUS_DEBUGGER_INACTIVE). Nothing below touches the heap -- a
 * suspended thread may hold its lock -- and the thread list is refreshed
 * only while every thread is running.
 */
#include "winsys.h"
#include <tlhelp32.h>

#define SLOTS (1u << 16)
#define NSYS 512

static struct { u64 rip; uint32_t n; } table[SLOTS];
static volatile LONG sys_counts[NSYS];
static u64 samples, dropped;
static int prof_on = -1;
static wchar_t out_path[MAX_PATH + 32];
static DWORD self_tid;

void ws_prof_count(i64 nr)
{
	if (prof_on > 0 && (u64)nr < NSYS)
		InterlockedIncrement(&sys_counts[nr]);
}

static void record(u64 rip)
{
	uint32_t h = (uint32_t)((rip * 0x9E3779B97F4A7C15ull) >> 48) & (SLOTS - 1);
	for (uint32_t i = 0; i < 64; i++, h = (h + 1) & (SLOTS - 1)) {
		if (table[h].rip == rip) {
			table[h].n++;
			return;
		}
		if (!table[h].rip) {
			table[h].rip = rip;
			table[h].n = 1;
			return;
		}
	}
	dropped++;
}

static char *put_hex(char *p, u64 v)
{
	char t[16];
	int n = 0;
	do {
		t[n++] = "0123456789abcdef"[v & 15];
		v >>= 4;
	} while (v);
	while (n)
		*p++ = t[--n];
	return p;
}

static char *put_dec(char *p, u64 v)
{
	char t[24];
	int n = 0;
	do {
		t[n++] = (char)('0' + v % 10);
		v /= 10;
	} while (v);
	while (n)
		*p++ = t[--n];
	return p;
}

static void dump(void)
{
	HANDLE f = CreateFileW(out_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return;
	static char buf[1 << 16];
	char *p = buf;
	DWORD w;
#define FLUSH_IF(k) do { if (p - buf > (long long)sizeof buf - (k)) { WriteFile(f, buf, (DWORD)(p - buf), &w, NULL); p = buf; } } while (0)
	p = put_dec(buf, samples);
	*p++ = ' ';
	p = put_dec(p, dropped);
	*p++ = '\n';
	for (uint32_t i = 0; i < SLOTS; i++) {
		if (!table[i].rip)
			continue;
		FLUSH_IF(64);
		*p++ = 'r';
		*p++ = ' ';
		p = put_hex(p, table[i].rip);
		*p++ = ' ';
		p = put_dec(p, table[i].n);
		*p++ = '\n';
	}
	for (uint32_t i = 0; i < NSYS; i++) {
		if (!sys_counts[i])
			continue;
		FLUSH_IF(64);
		*p++ = 's';
		*p++ = ' ';
		p = put_dec(p, i);
		*p++ = ' ';
		p = put_dec(p, (u64)sys_counts[i]);
		*p++ = '\n';
	}
	WriteFile(f, buf, (DWORD)(p - buf), &w, NULL);
	CloseHandle(f);
#undef FLUSH_IF
}

#define MAXT 128
static DWORD WINAPI prof_main(void *arg)
{
	(void)arg;
	DWORD pid = GetCurrentProcessId();
	HANDLE th[MAXT];
	int nth = 0;
	u64 last_list = 0, last_dump = GetTickCount64();
	for (;;) {
		u64 now = GetTickCount64();
		if (now - last_list > 1000 || !nth) {
			for (int i = 0; i < nth; i++)
				CloseHandle(th[i]);
			nth = 0;
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (snap != INVALID_HANDLE_VALUE) {
				THREADENTRY32 te;
				te.dwSize = sizeof te;
				for (BOOL ok = Thread32First(snap, &te); ok && nth < MAXT; ok = Thread32Next(snap, &te)) {
					if (te.th32OwnerProcessID != pid || te.th32ThreadID == self_tid)
						continue;
					HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
							      FALSE, te.th32ThreadID);
					if (h)
						th[nth++] = h;
				}
				CloseHandle(snap);
			}
			last_list = now;
		}
		for (int i = 0; i < nth; i++) {
			if (SuspendThread(th[i]) == (DWORD)-1)
				continue;
			CONTEXT c;
			c.ContextFlags = CONTEXT_CONTROL;
			if (GetThreadContext(th[i], &c)) {
				record(c.Rip);
				samples++;
			}
			ResumeThread(th[i]);
		}
		if (now - last_dump >= 5000) {
			dump();
			last_dump = now;
		}
		Sleep(2);
	}
	return 0;
}

/* at startup and in every forked child (whose table is the parent's copy) */
void ws_prof_start(int child)
{
	if (prof_on < 0) {
		wchar_t p[MAX_PATH];
		DWORD l = GetEnvironmentVariableW(L"BMC_WIN_PROF", p, MAX_PATH);
		prof_on = l && l < MAX_PATH ? 1 : 0;
		if (prof_on)
			__ws_memcpy(out_path, p, (l + 1) * sizeof(wchar_t));
	}
	if (prof_on <= 0)
		return;
	if (child) {
		__ws_memset(table, 0, sizeof table);
		for (int i = 0; i < NSYS; i++)
			sys_counts[i] = 0;
		samples = dropped = 0;
	}
	/* <path>.<pid> */
	size_t l = ws_wcslen(out_path);
	for (size_t i = l; i > 0; i--)
		if (out_path[i - 1] == L'#') {    /* a previous ".#<pid>" suffix */
			l = i - 1;
			break;
		}
	char num[24];
	ws_fmt_u64(num, GetCurrentProcessId());
	out_path[l++] = L'#';
	for (char *q = num; *q; q++)
		out_path[l++] = (wchar_t)*q;
	out_path[l] = 0;
	HANDLE t = CreateThread(NULL, 64 << 10, prof_main, NULL, 0, &self_tid);
	if (t) {
		SetThreadPriority(t, THREAD_PRIORITY_HIGHEST);
		CloseHandle(t);
	}
}
