/* ws_broker.c -- Winsock for forked processes, done by the root (bmc_win).
 *
 * A cloned process cannot use Winsock (its user-mode state does not survive
 * the clone), but the kernel socket objects do: data and readiness never go
 * through Winsock (ws_net.c). For the rest, a forked process swaps the ws2
 * table (ws_ws2.h) for the stubs below; each sends one request over a named
 * pipe to the root process, which duplicates the caller's socket handle into
 * itself, makes the real Winsock call on it (Winsock imports a duplicated
 * socket's context from AFD, as it does for inherited sockets), closes its
 * copy and replies. Sockets the root creates for a caller (socket, accept)
 * are moved into the caller's handle table.
 *
 * The pipe is \\.\pipe\bmc-broker-<root pid>-<nonce>, created by the root
 * with the default (same-user) security; each request is one connection
 * served on its own thread, so a slow call (getaddrinfo) blocks no one. */
#define BMC_WS2_IMPL            /* table fields by name: no ws2 renaming macros */
#include "winsys.h"
#include <stddef.h>

enum { OP_SOCKET = 1, OP_CONNECT, OP_BIND, OP_LISTEN, OP_ACCEPT, OP_PEERNAME, OP_SOCKNAME, OP_SEND, OP_RECV,
       OP_SENDTO, OP_RECVFROM, OP_SHUTDOWN, OP_SETSOCKOPT, OP_GETSOCKOPT, OP_IOCTL, OP_GETADDRINFO, OP_SPAWN };

#define BR_DATA 65536
typedef struct {
	uint32_t op, pid;
	u64 h;
	i64 a[6];
	uint32_t n1, n2;            /* lengths of the two blobs in data */
	unsigned char data[BR_DATA];
} br_req;

typedef struct {
	i64 ret;
	int32_t err;                /* WSA error when ret signals failure */
	uint32_t pad;
	u64 h;                      /* a handle now in the caller's table */
	i64 v[4];
	uint32_t n1, n2;
	unsigned char data[BR_DATA];
} br_rep;

static wchar_t pipe_name[96];
static struct ws2_table real;       /* the root's own Winsock, for serving */

/* ---------------------------------------------------------------- server */
static HANDLE dup_in(HANDLE proc, u64 h)
{
	HANDLE out = NULL;
	if (!DuplicateHandle(proc, (HANDLE)h, GetCurrentProcess(), &out, 0, FALSE, DUPLICATE_SAME_ACCESS))
		return NULL;
	return out;
}

static u64 move_out(HANDLE proc, SOCKET s)
{
	HANDLE out = NULL;
	BOOL ok = DuplicateHandle(GetCurrentProcess(), (HANDLE)s, proc, &out, 0, TRUE, DUPLICATE_SAME_ACCESS);
	real.closesocket(s);
	return ok ? (u64)out : 0;
}

static void serve_spawn(br_req *q, br_rep *p, HANDLE proc);

static void serve(br_req *q, br_rep *p)
{
	__ws_memset(p, 0, sizeof *p - BR_DATA);
	HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, q->pid);
	if (!proc) {
		p->ret = -1;
		p->err = WSAEACCES;
		return;
	}
	if (q->op == OP_SPAWN) {
		serve_spawn(q, p, proc);
		CloseHandle(proc);
		return;
	}
	SOCKET s = INVALID_SOCKET;
	if (q->op != OP_SOCKET && q->op != OP_GETADDRINFO) {
		HANDLE h = dup_in(proc, q->h);
		if (!h) {
			p->ret = -1;
			p->err = WSAENOTSOCK;
			CloseHandle(proc);
			return;
		}
		s = (SOCKET)h;
	}
	struct sockaddr_storage sa;
	int sl = sizeof sa, r = 0;
	unsigned char *b1 = q->data, *b2 = q->data + q->n1;
	switch (q->op) {
	case OP_SOCKET: {
		SOCKET n = real.WSASocketW((int)q->a[0], (int)q->a[1], (int)q->a[2], NULL, 0, (DWORD)q->a[3]);
		if (n == INVALID_SOCKET) {
			r = -1;
		} else {
			p->h = move_out(proc, n);
			if (!p->h) {
				r = -1;
				p->err = WSAEMFILE;
			}
		}
		break;
	}
	case OP_CONNECT: {
		u_long nb = (u_long)q->a[0];
		if (nb)
			real.ioctlsocket(s, FIONBIO, &nb);
		r = real.connect(s, (struct sockaddr *)b1, (int)q->n1);
		int e = r ? real.WSAGetLastError() : 0;
		u_long off = 0;
		if (nb)
			real.ioctlsocket(s, FIONBIO, &off);
		if (r)
			p->err = e;
		break;
	}
	case OP_BIND: r = real.bind(s, (struct sockaddr *)b1, (int)q->n1); break;
	case OP_LISTEN: r = real.listen(s, (int)q->a[0]); break;
	case OP_ACCEPT: {
		SOCKET n = real.accept(s, (struct sockaddr *)&sa, &sl);
		if (n == INVALID_SOCKET) {
			r = -1;
		} else {
			u_long off = 0;
			real.ioctlsocket(n, FIONBIO, &off);
			__ws_memcpy(p->data, &sa, (size_t)sl);
			p->n1 = (uint32_t)sl;
			p->h = move_out(proc, n);
		}
		break;
	}
	case OP_PEERNAME: case OP_SOCKNAME:
		r = q->op == OP_PEERNAME ? real.getpeername(s, (struct sockaddr *)&sa, &sl)
					 : real.getsockname(s, (struct sockaddr *)&sa, &sl);
		if (!r) {
			__ws_memcpy(p->data, &sa, (size_t)sl);
			p->n1 = (uint32_t)sl;
		}
		break;
	case OP_SEND:
		r = real.send(s, (const char *)b1, (int)q->n1, (int)q->a[0]);
		break;
	case OP_RECV:
		r = real.recv(s, (char *)p->data, (int)(q->a[1] < BR_DATA ? q->a[1] : BR_DATA), (int)q->a[0]);
		if (r > 0)
			p->n1 = (uint32_t)r;
		break;
	case OP_SENDTO:
		r = real.sendto(s, (const char *)b1, (int)q->n1, (int)q->a[0], q->n2 ? (struct sockaddr *)b2 : NULL,
				(int)q->n2);
		break;
	case OP_RECVFROM: {
		int cap = (int)(q->a[1] < BR_DATA - 256 ? q->a[1] : BR_DATA - 256);
		r = real.recvfrom(s, (char *)p->data, cap, (int)q->a[0], (struct sockaddr *)&sa, &sl);
		if (r >= 0) {
			p->n1 = (uint32_t)r;
			__ws_memcpy(p->data + r, &sa, (size_t)sl);
			p->n2 = (uint32_t)sl;
		}
		break;
	}
	case OP_SHUTDOWN: r = real.shutdown(s, (int)q->a[0]); break;
	case OP_SETSOCKOPT:
		r = real.setsockopt(s, (int)q->a[0], (int)q->a[1], (const char *)b1, (int)q->n1);
		break;
	case OP_GETSOCKOPT: {
		int len = (int)(q->a[2] < 256 ? q->a[2] : 256);
		r = real.getsockopt(s, (int)q->a[0], (int)q->a[1], (char *)p->data, &len);
		if (!r)
			p->n1 = (uint32_t)len;
		break;
	}
	case OP_IOCTL: {
		u_long v = (u_long)q->a[1];
		r = real.ioctlsocket(s, (long)q->a[0], &v);
		p->v[0] = (i64)v;
		break;
	}
	case OP_GETADDRINFO: {
		typedef struct { int family, socktype, protocol, addrlen; unsigned char addr[28]; } rec;
		ADDRINFOA hints, *res = NULL;
		__ws_memset(&hints, 0, sizeof hints);
		hints.ai_family = (int)q->a[0];
		hints.ai_socktype = (int)q->a[1];
		hints.ai_protocol = (int)q->a[2];
		hints.ai_flags = (int)q->a[3];
		const char *node = q->a[4] ? (const char *)b1 : NULL;
		const char *svc = q->a[5] ? (const char *)b2 : NULL;
		int g = real.getaddrinfo(node, svc, &hints, &res);
		if (g) {
			r = -1;
			p->err = g;
			break;
		}
		rec *out = (rec *)p->data;
		int k = 0, cap = BR_DATA / (int)sizeof(rec);
		for (ADDRINFOA *x = res; x && k < cap; x = x->ai_next) {
			if (x->ai_addrlen > sizeof out[k].addr)
				continue;
			out[k].family = x->ai_family;
			out[k].socktype = x->ai_socktype;
			out[k].protocol = x->ai_protocol;
			out[k].addrlen = (int)x->ai_addrlen;
			__ws_memcpy(out[k].addr, x->ai_addr, x->ai_addrlen);
			k++;
		}
		real.freeaddrinfo(res);
		p->n1 = (uint32_t)(k * (int)sizeof(rec));
		r = k;
		break;
	}
	default:
		r = -1;
		p->err = WSAEOPNOTSUPP;
	}
	if (r < 0 && !p->err)
		p->err = real.WSAGetLastError();
	p->ret = r;
	if (s != INVALID_SOCKET)
		real.closesocket(s);
	CloseHandle(proc);
}

static DWORD WINAPI conn_main(LPVOID arg)
{
	HANDLE pipe = arg;
	br_req *q = ws_alloc(sizeof *q);
	br_rep *p = ws_alloc(sizeof *p);
	DWORD got = 0, put;
	if (q && p && ReadFile(pipe, q, sizeof *q, &got, NULL) && got >= offsetof(br_req, data) &&
	    q->n1 <= BR_DATA && q->n2 <= BR_DATA - q->n1) {
		serve(q, p);
		WriteFile(pipe, p, (DWORD)(offsetof(br_rep, data) + p->n1 + p->n2), &put, NULL);
		FlushFileBuffers(pipe);
	}
	ws_free(q);
	ws_free(p);
	DisconnectNamedPipe(pipe);
	CloseHandle(pipe);
	return 0;
}

static DWORD WINAPI server_main(LPVOID arg)
{
	(void)arg;
	for (;;) {
		HANDLE pipe = CreateNamedPipeW(pipe_name, PIPE_ACCESS_DUPLEX,
					       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
					       PIPE_UNLIMITED_INSTANCES, sizeof(br_rep), sizeof(br_req), 0, NULL);
		if (pipe == INVALID_HANDLE_VALUE) {
			Sleep(50);
			continue;
		}
		if (!ConnectNamedPipe(pipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
			CloseHandle(pipe);
			continue;
		}
		HANDLE th = ws_create_thread(conn_main, pipe, 256 * 1024, NULL);
		if (th)
			CloseHandle(th);
		else
			conn_main(pipe);
	}
	return 0;
}

/* lazily, on the first fork: a process that never forks never listens */
void ws_broker_start(void)
{
	static volatile LONG started;
	if (!ws_is_root || InterlockedExchange(&started, 1))
		return;
	real = ws2;
	u64 nonce = 0;
	extern i64 ws_getrandom(void *buf, size_t n);
	ws_getrandom(&nonce, sizeof nonce);
	char name[96] = "\\\\.\\pipe\\bmc-broker-", num[24];
	size_t l = ws_strlen(name);
	ws_fmt_u64(num, GetCurrentProcessId());
	for (size_t i = 0; num[i]; i++)
		name[l++] = num[i];
	name[l++] = '-';
	ws_fmt_u64(num, nonce & 0xffffffffffffULL);
	for (size_t i = 0; num[i]; i++)
		name[l++] = num[i];
	name[l] = 0;
	for (size_t i = 0; i <= l; i++)
		pipe_name[i] = (wchar_t)name[i];
	HANDLE th = ws_create_thread(server_main, NULL, 256 * 1024, NULL);
	if (th)
		CloseHandle(th);
}

/* ---------------------------------------------------------------- client */
static __thread int last_err;

static int call(br_req *q, br_rep *p)
{
	q->pid = GetCurrentProcessId();
	HANDLE pipe = INVALID_HANDLE_VALUE;
	for (int tries = 0; tries < 200; tries++) {
		pipe = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (pipe != INVALID_HANDLE_VALUE)
			break;
		if (GetLastError() != ERROR_PIPE_BUSY && GetLastError() != ERROR_FILE_NOT_FOUND)
			break;
		WaitNamedPipeW(pipe_name, 50);
	}
	if (pipe == INVALID_HANDLE_VALUE) {
		last_err = WSAENETDOWN;
		return -1;
	}
	DWORD mode = PIPE_READMODE_MESSAGE, n;
	SetNamedPipeHandleState(pipe, &mode, NULL, NULL);
	BOOL ok = WriteFile(pipe, q, (DWORD)(offsetof(br_req, data) + q->n1 + q->n2), &n, NULL) &&
		  ReadFile(pipe, p, sizeof *p, &n, NULL) && n >= offsetof(br_rep, data);
	CloseHandle(pipe);
	if (!ok) {
		last_err = WSAENETDOWN;
		return -1;
	}
	if (p->ret < 0)
		last_err = p->err;
	return 0;
}

static br_req *req(uint32_t op, u64 h)
{
	br_req *q = ws_alloc(sizeof *q);
	if (q) {
		q->op = op;
		q->h = h;
	}
	return q;
}

static void put1(br_req *q, const void *b, size_t n)
{
	if (n > BR_DATA)
		n = BR_DATA;
	__ws_memcpy(q->data, b, n);
	q->n1 = (uint32_t)n;
}

static void put2(br_req *q, const void *b, size_t n)
{
	if (n > BR_DATA - q->n1)
		n = BR_DATA - q->n1;
	__ws_memcpy(q->data + q->n1, b, n);
	q->n2 = (uint32_t)n;
}

/* run a request; returns ret (or -1 when the broker is unreachable) */
#define RUN(q, p, failval) \
	br_rep *p = ws_alloc(sizeof *p); \
	if (!q || !p || call(q, p)) { ws_free(q); ws_free(p); if (!q || !p) last_err = WSAENOBUFS; return failval; }

static int WSAAPI r_WSAStartup(WORD v, LPWSADATA d) { (void)v; (void)d; return 0; }

static SOCKET WSAAPI r_WSASocketW(int af, int type, int proto, LPWSAPROTOCOL_INFOW pi, GROUP g, DWORD fl)
{
	(void)pi;
	(void)g;
	br_req *q = req(OP_SOCKET, 0);
	if (q) {
		q->a[0] = af;
		q->a[1] = type;
		q->a[2] = proto;
		q->a[3] = fl;
	}
	RUN(q, p, INVALID_SOCKET)
	SOCKET s = p->ret < 0 ? INVALID_SOCKET : (SOCKET)p->h;
	ws_free(q);
	ws_free(p);
	return s;
}

static SOCKET WSAAPI r_socket(int af, int type, int proto)
{
	return r_WSASocketW(af, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED);
}

static int simple(uint32_t op, SOCKET s, const void *b, int n, i64 a0, i64 a1)
{
	br_req *q = req(op, (u64)s);
	if (q) {
		if (b)
			put1(q, b, (size_t)n);
		q->a[0] = a0;
		q->a[1] = a1;
	}
	RUN(q, p, -1)
	int r = (int)p->ret;
	ws_free(q);
	ws_free(p);
	return r;
}

/* ws_net.c brackets connect with FIONBIO on/off; the broker does the whole
 * non-blocking connect in one call, so these toggles are remembered here */
static __thread int pending_nb;

static int WSAAPI r_connect(SOCKET s, const struct sockaddr *a, int n)
{
	return simple(OP_CONNECT, s, a, n, pending_nb, 0);
}

static int WSAAPI r_bind(SOCKET s, const struct sockaddr *a, int n) { return simple(OP_BIND, s, a, n, 0, 0); }
static int WSAAPI r_listen(SOCKET s, int bl) { return simple(OP_LISTEN, s, NULL, 0, bl, 0); }
static int WSAAPI r_shutdown(SOCKET s, int how) { return simple(OP_SHUTDOWN, s, NULL, 0, how, 0); }
static int WSAAPI r_send(SOCKET s, const char *b, int n, int f) { return simple(OP_SEND, s, b, n, f, 0); }

static int WSAAPI r_setsockopt(SOCKET s, int lvl, int opt, const char *v, int n)
{
	return simple(OP_SETSOCKOPT, s, v, n, lvl, opt);
}

static SOCKET WSAAPI r_accept(SOCKET s, struct sockaddr *a, int *al)
{
	br_req *q = req(OP_ACCEPT, (u64)s);
	RUN(q, p, INVALID_SOCKET)
	SOCKET n = INVALID_SOCKET;
	if (p->ret >= 0) {
		n = (SOCKET)p->h;
		if (a && al) {
			int c = (int)p->n1 < *al ? (int)p->n1 : *al;
			__ws_memcpy(a, p->data, (size_t)c);
			*al = (int)p->n1;
		}
	}
	ws_free(q);
	ws_free(p);
	return n;
}

static int name_op(uint32_t op, SOCKET s, struct sockaddr *a, int *al)
{
	br_req *q = req(op, (u64)s);
	RUN(q, p, -1)
	int r = (int)p->ret;
	if (r == 0 && a && al) {
		int c = (int)p->n1 < *al ? (int)p->n1 : *al;
		__ws_memcpy(a, p->data, (size_t)c);
		*al = (int)p->n1;
	}
	ws_free(q);
	ws_free(p);
	return r;
}

static int WSAAPI r_getpeername(SOCKET s, struct sockaddr *a, int *al) { return name_op(OP_PEERNAME, s, a, al); }
static int WSAAPI r_getsockname(SOCKET s, struct sockaddr *a, int *al) { return name_op(OP_SOCKNAME, s, a, al); }

static int WSAAPI r_recv(SOCKET s, char *b, int n, int f)
{
	br_req *q = req(OP_RECV, (u64)s);
	if (q) {
		q->a[0] = f;
		q->a[1] = n;
	}
	RUN(q, p, -1)
	int r = (int)p->ret;
	if (r > 0)
		__ws_memcpy(b, p->data, p->n1);
	ws_free(q);
	ws_free(p);
	return r;
}

static int WSAAPI r_sendto(SOCKET s, const char *b, int n, int f, const struct sockaddr *to, int tl)
{
	br_req *q = req(OP_SENDTO, (u64)s);
	if (q) {
		put1(q, b, (size_t)n);
		if (to)
			put2(q, to, (size_t)tl);
		q->a[0] = f;
	}
	RUN(q, p, -1)
	int r = (int)p->ret;
	ws_free(q);
	ws_free(p);
	return r;
}

static int WSAAPI r_recvfrom(SOCKET s, char *b, int n, int f, struct sockaddr *from, int *fl)
{
	br_req *q = req(OP_RECVFROM, (u64)s);
	if (q) {
		q->a[0] = f;
		q->a[1] = n;
	}
	RUN(q, p, -1)
	int r = (int)p->ret;
	if (r >= 0) {
		__ws_memcpy(b, p->data, p->n1);
		if (from && fl) {
			int c = (int)p->n2 < *fl ? (int)p->n2 : *fl;
			__ws_memcpy(from, p->data + p->n1, (size_t)c);
			*fl = (int)p->n2;
		}
	}
	ws_free(q);
	ws_free(p);
	return r;
}

static int WSAAPI r_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD nb, LPDWORD sent, DWORD f, const struct sockaddr *to,
			      int tl, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
	(void)ov;
	(void)cr;
	size_t total = 0;
	for (DWORD i = 0; i < nb; i++)
		total += bufs[i].len;
	char *flat = ws_alloc(total ? total : 1);
	if (!flat) {
		last_err = WSAENOBUFS;
		return SOCKET_ERROR;
	}
	size_t at = 0;
	for (DWORD i = 0; i < nb; i++) {
		__ws_memcpy(flat + at, bufs[i].buf, bufs[i].len);
		at += bufs[i].len;
	}
	int r = to ? r_sendto(s, flat, (int)total, (int)f, to, tl) : r_send(s, flat, (int)total, (int)f);
	ws_free(flat);
	if (r < 0)
		return SOCKET_ERROR;
	*sent = (DWORD)r;
	return 0;
}

static int WSAAPI r_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD nb, LPDWORD got, LPDWORD fl, struct sockaddr *from,
				LPINT froml, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
	(void)ov;
	(void)cr;
	size_t total = 0;
	for (DWORD i = 0; i < nb; i++)
		total += bufs[i].len;
	char *flat = ws_alloc(total ? total : 1);
	if (!flat) {
		last_err = WSAENOBUFS;
		return SOCKET_ERROR;
	}
	int r = from ? r_recvfrom(s, flat, (int)total, (int)*fl, from, froml) : r_recv(s, flat, (int)total, (int)*fl);
	if (r < 0) {
		ws_free(flat);
		return SOCKET_ERROR;
	}
	size_t at = 0;
	for (DWORD i = 0; i < nb && at < (size_t)r; i++) {
		size_t c = (size_t)r - at < bufs[i].len ? (size_t)r - at : bufs[i].len;
		__ws_memcpy(bufs[i].buf, flat + at, c);
		at += c;
	}
	ws_free(flat);
	*got = (DWORD)r;
	*fl = 0;
	return 0;
}

static int WSAAPI r_getsockopt(SOCKET s, int lvl, int opt, char *v, int *n)
{
	br_req *q = req(OP_GETSOCKOPT, (u64)s);
	if (q) {
		q->a[0] = lvl;
		q->a[1] = opt;
		q->a[2] = *n;
	}
	RUN(q, p, -1)
	int r = (int)p->ret;
	if (r == 0) {
		int c = (int)p->n1 < *n ? (int)p->n1 : *n;
		__ws_memcpy(v, p->data, (size_t)c);
		*n = (int)p->n1;
	}
	ws_free(q);
	ws_free(p);
	return r;
}

static int WSAAPI r_ioctlsocket(SOCKET s, long cmd, u_long *arg)
{
	if (cmd == (long)FIONBIO) {        /* only around connect (ws_net.c) */
		pending_nb = *arg ? 1 : 0;
		return 0;
	}
	br_req *q = req(OP_IOCTL, (u64)s);
	if (q) {
		q->a[0] = cmd;
		q->a[1] = (i64)*arg;
	}
	RUN(q, p, -1)
	int r = (int)p->ret;
	*arg = (u_long)p->v[0];
	ws_free(q);
	ws_free(p);
	return r;
}

static int WSAAPI r_closesocket(SOCKET s)
{
	return CloseHandle((HANDLE)s) ? 0 : SOCKET_ERROR;
}

static int WSAAPI r_WSAPoll(LPWSAPOLLFD f, ULONG n, INT t)
{
	(void)f;
	(void)n;
	(void)t;
	last_err = WSAEOPNOTSUPP;
	return SOCKET_ERROR;
}

static int WSAAPI r_WSAGetLastError(void) { return last_err; }

static u_long WSAAPI r_htonl(u_long v)
{
	return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | (v >> 24);
}

static INT WSAAPI r_getaddrinfo(PCSTR node, PCSTR svc, const ADDRINFOA *hints, PADDRINFOA *res)
{
	typedef struct { int family, socktype, protocol, addrlen; unsigned char addr[28]; } rec;
	br_req *q = req(OP_GETADDRINFO, 0);
	if (q) {
		q->a[0] = hints ? hints->ai_family : 0;
		q->a[1] = hints ? hints->ai_socktype : 0;
		q->a[2] = hints ? hints->ai_protocol : 0;
		q->a[3] = hints ? hints->ai_flags : 0;
		q->a[4] = node != NULL;
		q->a[5] = svc != NULL;
		if (node)
			put1(q, node, ws_strlen(node) + 1);
		if (svc)
			put2(q, svc, ws_strlen(svc) + 1);
	}
	RUN(q, p, WSANO_RECOVERY)
	int r = (int)p->ret;
	INT out = 0;
	if (r < 0) {
		out = p->err;
	} else {
		int k = r;
		const rec *in = (const rec *)p->data;
		/* one block: k ADDRINFOA nodes then k sockaddr slots */
		ADDRINFOA *ai = ws_alloc((size_t)k * (sizeof(ADDRINFOA) + 28) + 1);
		unsigned char *addrs = (unsigned char *)(ai + k);
		for (int i = 0; i < k; i++) {
			ai[i].ai_family = in[i].family;
			ai[i].ai_socktype = in[i].socktype;
			ai[i].ai_protocol = in[i].protocol;
			ai[i].ai_addrlen = (size_t)in[i].addrlen;
			__ws_memcpy(addrs + 28 * i, in[i].addr, (size_t)in[i].addrlen);
			ai[i].ai_addr = (struct sockaddr *)(addrs + 28 * i);
			ai[i].ai_next = i + 1 < k ? &ai[i + 1] : NULL;
		}
		*res = k ? ai : NULL;
		if (!k)
			ws_free(ai);
	}
	ws_free(q);
	ws_free(p);
	return out;
}

static VOID WSAAPI r_freeaddrinfo(PADDRINFOA ai)
{
	ws_free(ai);
}

/* a forked process: every Winsock call goes to the root */
void ws_broker_child(void)
{
	ws2.WSAStartup = r_WSAStartup;
	ws2.WSASocketW = r_WSASocketW;
	ws2.socket = r_socket;
	ws2.connect = r_connect;
	ws2.bind = r_bind;
	ws2.listen = r_listen;
	ws2.accept = r_accept;
	ws2.getpeername = r_getpeername;
	ws2.getsockname = r_getsockname;
	ws2.send = r_send;
	ws2.recv = r_recv;
	ws2.sendto = r_sendto;
	ws2.recvfrom = r_recvfrom;
	ws2.WSASendTo = r_WSASendTo;
	ws2.WSARecvFrom = r_WSARecvFrom;
	ws2.shutdown = r_shutdown;
	ws2.setsockopt = r_setsockopt;
	ws2.getsockopt = r_getsockopt;
	ws2.ioctlsocket = r_ioctlsocket;
	ws2.closesocket = r_closesocket;
	ws2.WSAPoll = r_WSAPoll;
	ws2.WSAGetLastError = r_WSAGetLastError;
	ws2.htonl = r_htonl;
	ws2.getaddrinfo = r_getaddrinfo;
	ws2.freeaddrinfo = r_freeaddrinfo;
}

/* ---------------------------------------------------------------- spawn */
HANDLE ws_spawn_local(const wchar_t *app, wchar_t *cmdline, const wchar_t *env, const wchar_t *cwd,
		      HANDLE std[3], DWORD *pid, i64 *err);

/* root side of OP_SPAWN: blob = app, cmdline, cwd (NUL-terminated wide
 * strings, lengths in a[3..5]) then the environment block */
static void serve_spawn(br_req *q, br_rep *p, HANDLE proc)
{
	const wchar_t *app = (const wchar_t *)q->data;
	wchar_t *cmd = (wchar_t *)q->data + q->a[3];
	const wchar_t *cwd = (const wchar_t *)q->data + q->a[3] + q->a[4];
	const wchar_t *env = cwd + q->a[5];
	HANDLE std[3] = { NULL, NULL, NULL };
	for (int i = 0; i < 3; i++)
		if (q->a[i])
			std[i] = dup_in(proc, (u64)q->a[i]);
	DWORD pid = 0;
	i64 err = 0;
	HANDLE ph = ws_spawn_local(app, cmd, env, cwd, std, &pid, &err);
	for (int i = 0; i < 3; i++)
		if (std[i])
			CloseHandle(std[i]);
	if (!ph) {
		p->ret = -1;
		p->v[1] = err;
		return;
	}
	HANDLE out = NULL;
	DuplicateHandle(GetCurrentProcess(), ph, proc, &out, 0, FALSE, DUPLICATE_SAME_ACCESS);
	CloseHandle(ph);
	p->h = (u64)out;
	p->v[0] = pid;
	p->ret = 0;
}

HANDLE ws_broker_spawn(const wchar_t *app, const wchar_t *cmdline, const wchar_t *env, size_t env_chars,
		       const wchar_t *cwd, HANDLE std[3], DWORD *pid, i64 *err)
{
	size_t la = ws_wcslen(app) + 1, lc = ws_wcslen(cmdline) + 1, lw = ws_wcslen(cwd) + 1;
	size_t bytes = (la + lc + lw + env_chars) * sizeof(wchar_t);
	if (bytes > BR_DATA) {
		*err = -L_E2BIG;
		return NULL;
	}
	br_req *q = req(OP_SPAWN, 0);
	br_rep *p = ws_alloc(sizeof *p);
	if (!q || !p) {
		ws_free(q);
		ws_free(p);
		*err = -L_ENOMEM;
		return NULL;
	}
	wchar_t *d = (wchar_t *)q->data;
	__ws_memcpy(d, app, la * sizeof(wchar_t));
	__ws_memcpy(d + la, cmdline, lc * sizeof(wchar_t));
	__ws_memcpy(d + la + lc, cwd, lw * sizeof(wchar_t));
	__ws_memcpy(d + la + lc + lw, env, env_chars * sizeof(wchar_t));
	q->n1 = (uint32_t)bytes;
	for (int i = 0; i < 3; i++)
		q->a[i] = (i64)(u64)std[i];
	q->a[3] = (i64)la;
	q->a[4] = (i64)lc;
	q->a[5] = (i64)lw;
	HANDLE ph = NULL;
	if (call(q, p)) {
		*err = -L_EAGAIN;
	} else if (p->ret < 0) {
		*err = p->v[1] ? p->v[1] : -L_EAGAIN;
	} else {
		ph = (HANDLE)p->h;
		*pid = (DWORD)p->v[0];
	}
	ws_free(q);
	ws_free(p);
	return ph;
}
