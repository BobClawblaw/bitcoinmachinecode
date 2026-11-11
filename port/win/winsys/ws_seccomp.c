/* ws_seccomp.c -- seccomp(2) filter mode: classic BPF programs run over a
 * struct seccomp_data before every syscall.
 *
 * The tests use it to watch or fail chosen calls (a SIGSYS handler that
 * records fsync/fdatasync, unlink answered with EPERM), so this covers what a
 * filter can say: ALLOW, ERRNO, TRAP (SIGSYS, delivered synchronously with the
 * arguments in the ucontext; the handler's RAX is the call's result), KILL.
 * TRACE / USER_NOTIF / LOG act as ALLOW (no tracer exists to take them).
 *
 * Like Linux, filters are inherited by fork (they live in our memory, which a
 * clone copies) and across execve: the new process gets them through the
 * environment variable BMC_WIN_SECCOMP, which it reads and removes at start.
 * They cannot be removed. */
#include "winsys.h"

struct l_sock_filter { unsigned short code; unsigned char jt, jf; uint32_t k; };
struct l_sock_fprog { unsigned short len; struct l_sock_filter *filter; };

#define MAX_FILTERS 16
#define MAX_INSNS 4096
static struct { int n; struct l_sock_filter *f; } filters[MAX_FILTERS];
static volatile LONG nfilters;
static SRWLOCK flock_ = SRWLOCK_INIT;

int ws_seccomp_active;

static i64 add_filter(const struct l_sock_filter *f, int n)
{
	if (n <= 0 || n > MAX_INSNS)
		return -L_EINVAL;
	struct l_sock_filter *c = ws_alloc(sizeof *c * (size_t)n);
	if (!c)
		return -L_ENOMEM;
	__ws_memcpy(c, f, sizeof *c * (size_t)n);
	AcquireSRWLockExclusive(&flock_);
	i64 r = 0;
	if (nfilters >= MAX_FILTERS) {
		r = -L_ENOMEM;
		ws_free(c);
	} else {
		filters[nfilters].n = n;
		filters[nfilters].f = c;
		nfilters++;
		ws_seccomp_active = 1;
	}
	ReleaseSRWLockExclusive(&flock_);
	return r;
}

/* prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog) and
 * seccomp(SECCOMP_SET_MODE_FILTER, flags, prog) */
i64 ws_seccomp_install(const void *prog)
{
	const struct l_sock_fprog *p = prog;
	if (!p || !p->filter)
		return -L_EFAULT;
	return add_filter(p->filter, p->len);
}

/* seccomp_data: nr, arch, instruction_pointer, args[6] */
struct l_seccomp_data { int nr; uint32_t arch; u64 ip; u64 args[6]; };

static uint32_t run_bpf(const struct l_sock_filter *f, int n, const struct l_seccomp_data *d)
{
	uint32_t A = 0, X = 0, M[16];
	__ws_memset(M, 0, sizeof M);
	const unsigned char *data = (const unsigned char *)d;
	for (int pc = 0; pc < n; pc++) {
		const struct l_sock_filter *i = &f[pc];
		uint32_t k = i->k;
		switch (i->code) {
		case 0x20:                                     /* LD W ABS */
			if (k + 4 > sizeof *d || (k & 3))
				return 0;                          /* KILL */
			__ws_memcpy(&A, data + k, 4);
			break;
		case 0x00: A = k; break;                       /* LD IMM */
		case 0x01: X = k; break;                       /* LDX IMM */
		case 0x60: A = M[k & 15]; break;               /* LD MEM */
		case 0x61: X = M[k & 15]; break;               /* LDX MEM */
		case 0x02: M[k & 15] = A; break;               /* ST */
		case 0x03: M[k & 15] = X; break;               /* STX */
		case 0x80: A = sizeof *d; break;               /* LD W LEN */
		case 0x81: X = sizeof *d; break;               /* LDX W LEN */
		case 0x04: A += k; break;                      /* ALU ADD K */
		case 0x0c: A += X; break;
		case 0x14: A -= k; break;                      /* SUB */
		case 0x1c: A -= X; break;
		case 0x24: A *= k; break;                      /* MUL */
		case 0x2c: A *= X; break;
		case 0x34: if (!k) return 0; A /= k; break;   /* DIV */
		case 0x3c: if (!X) return 0; A /= X; break;
		case 0x94: if (!k) return 0; A %= k; break;   /* MOD */
		case 0x9c: if (!X) return 0; A %= X; break;
		case 0x44: A |= k; break;                      /* OR */
		case 0x4c: A |= X; break;
		case 0x54: A &= k; break;                      /* AND */
		case 0x5c: A &= X; break;
		case 0xa4: A ^= k; break;                      /* XOR */
		case 0xac: A ^= X; break;
		case 0x64: A <<= (k & 31); break;              /* LSH */
		case 0x6c: A <<= (X & 31); break;
		case 0x74: A >>= (k & 31); break;              /* RSH */
		case 0x7c: A >>= (X & 31); break;
		case 0x84: A = (uint32_t)-(int32_t)A; break;   /* NEG */
		case 0x05: pc += (int)k; break;                /* JA */
		case 0x15: pc += A == k ? i->jt : i->jf; break;        /* JEQ K */
		case 0x1d: pc += A == X ? i->jt : i->jf; break;
		case 0x25: pc += A > k ? i->jt : i->jf; break;         /* JGT */
		case 0x2d: pc += A > X ? i->jt : i->jf; break;
		case 0x35: pc += A >= k ? i->jt : i->jf; break;        /* JGE */
		case 0x3d: pc += A >= X ? i->jt : i->jf; break;
		case 0x45: pc += (A & k) ? i->jt : i->jf; break;       /* JSET */
		case 0x4d: pc += (A & X) ? i->jt : i->jf; break;
		case 0x06: return k;                           /* RET K */
		case 0x16: return A;                           /* RET A */
		case 0x07: X = A; break;                       /* TAX */
		case 0x87: A = X; break;                       /* TXA */
		default: return 0;                             /* invalid: KILL */
		}
	}
	return 0;
}

#define RET_KILL_PROCESS 0x80000000U
#define RET_KILL_THREAD 0x00000000U
#define RET_TRAP 0x00030000U
#define RET_ERRNO 0x00050000U
#define RET_ALLOW 0x7fff0000U

/* Run every filter over the call; the most restrictive action wins.
 * Returns 1 when the call is answered (*result set), 0 to run it. */
int ws_seccomp_check(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, i64 *result)
{
	struct l_seccomp_data d;
	d.nr = (int)n;
	d.arch = 0xC000003EU;                              /* AUDIT_ARCH_X86_64 */
	d.ip = 0;
	d.args[0] = (u64)a1; d.args[1] = (u64)a2; d.args[2] = (u64)a3;
	d.args[3] = (u64)a4; d.args[4] = (u64)a5; d.args[5] = (u64)a6;
	uint32_t best = RET_ALLOW;
	int cnt = (int)nfilters;
	for (int i = 0; i < cnt; i++) {
		uint32_t r = run_bpf(filters[i].f, filters[i].n, &d);
		if ((int32_t)(r & 0xffff0000U) < (int32_t)(best & 0xffff0000U))
			best = r;
	}
	switch (best & 0xffff0000U) {
	case RET_KILL_PROCESS:
	case RET_KILL_THREAD:
		ws_exit_signaled(31);                      /* SIGSYS */
	case RET_TRAP: {
		i64 args[6] = { a1, a2, a3, a4, a5, a6 };
		*result = ws_sig_seccomp_trap(n, args, best & 0xffff);
		return 1;
	}
	case RET_ERRNO: {
		uint32_t e = best & 0xffff;
		*result = -(i64)(e > 4095 ? 4095 : e);
		return 1;
	}
	default:
		return 0;
	}
}

/* ---- execve handoff: "BMC_WIN_SECCOMP=<n>:<hex insns>,<n>:<hex>..." */
static const char hexd[] = "0123456789abcdef";

char *ws_seccomp_env(void)
{
	int cnt = (int)nfilters;
	if (!cnt)
		return NULL;
	size_t len = 16;
	for (int i = 0; i < cnt; i++)
		len += 8 + (size_t)filters[i].n * 16;
	char *s = ws_alloc(len), *p = s;
	if (!s)
		return NULL;
	__ws_memcpy(p, "BMC_WIN_SECCOMP=", 16);
	p += 16;
	for (int i = 0; i < cnt; i++) {
		if (i)
			*p++ = ',';
		const unsigned char *b = (const unsigned char *)filters[i].f;
		for (size_t j = 0; j < (size_t)filters[i].n * 8; j++) {
			*p++ = hexd[b[j] >> 4];
			*p++ = hexd[b[j] & 15];
		}
	}
	*p = 0;
	return s;
}

static int hexv(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

void ws_seccomp_init_from_env(void)
{
	DWORD need = GetEnvironmentVariableA("BMC_WIN_SECCOMP", NULL, 0);
	if (!need)
		return;
	char *v = ws_alloc(need + 1);
	if (!v)
		return;
	GetEnvironmentVariableA("BMC_WIN_SECCOMP", v, need + 1);
	SetEnvironmentVariableW(L"BMC_WIN_SECCOMP", NULL);
	char *p = v;
	while (*p) {
		char *e = p;
		while (*e && *e != ',')
			e++;
		size_t hex = (size_t)(e - p);
		int n = (int)(hex / 16);
		struct l_sock_filter *f = n > 0 && n <= MAX_INSNS && hex % 16 == 0 ? ws_alloc(sizeof *f * (size_t)n) : NULL;
		if (f) {
			unsigned char *b = (unsigned char *)f;
			int ok = 1;
			for (size_t j = 0; j < hex / 2; j++) {
				int hi = hexv(p[2 * j]), lo = hexv(p[2 * j + 1]);
				if (hi < 0 || lo < 0)
					ok = 0;
				b[j] = (unsigned char)(hi << 4 | lo);
			}
			if (ok)
				add_filter(f, n);
			ws_free(f);
		}
		p = *e ? e + 1 : e;
	}
	ws_free(v);
}
