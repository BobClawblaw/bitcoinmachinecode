/* ws_net.c -- Linux socket syscalls, poll and select on Windows (bmc_win).
 *
 * Sockets live in the fd table (FT_SOCKET). Winsock is used only to create
 * and configure them; at the Winsock level every socket stays blocking.
 * Readiness is the AFD poll ioctl (IOCTL_AFD_POLL, the interface libuv and
 * wepoll build on), waited on through ws_wait so a signal interrupts it, and
 * data moves with overlapped ReadFile/WriteFile on the socket handle. So
 * O_NONBLOCK, MSG_DONTWAIT and SO_RCVTIMEO/SO_SNDTIMEO are emulated here, and
 * the data path works in a forked (cloned) process too, where Winsock's
 * user-mode state is not usable.
 *
 * Translated at this boundary: address families (AF_INET6 10 <-> 23),
 * SOL_SOCKET/TCP/IPv6 option numbers and value shapes, Linux message flags,
 * errors (-> Linux errno; a non-blocking connect reports EINPROGRESS) and
 * poll bits. socketpair is a connected loopback TCP pair. */
#include "winsys.h"
#include <mstcpip.h>
#include <winternl.h>

#define L_AF_UNIX 1
#define L_AF_INET 2
#define L_AF_INET6 10
#define L_SOCK_NONBLOCK 04000
#define L_SOCK_CLOEXEC 02000000
#define L_O_NONBLOCK 04000
#define L_MSG_OOB 1
#define L_MSG_PEEK 2
#define L_MSG_DONTWAIT 0x40
#define L_MSG_WAITALL 0x100

/* ---------------------------------------------------------------- AFD poll */
#define IOCTL_AFD_POLL 0x00012024
#define AFD_POLL_RECEIVE 0x0001
#define AFD_POLL_RECEIVE_EXPEDITED 0x0002
#define AFD_POLL_SEND 0x0004
#define AFD_POLL_DISCONNECT 0x0008
#define AFD_POLL_ABORT 0x0010
#define AFD_POLL_LOCAL_CLOSE 0x0020
#define AFD_POLL_ACCEPT 0x0080
#define AFD_POLL_CONNECT_FAIL 0x0100
#define AFD_POLL_ERRORS (AFD_POLL_ABORT | AFD_POLL_LOCAL_CLOSE | AFD_POLL_CONNECT_FAIL)

typedef struct { HANDLE Handle; ULONG Events; LONG Status; } afd_handle_info;
typedef struct { LARGE_INTEGER Timeout; ULONG NumberOfHandles; ULONG Exclusive; afd_handle_info Handles[1]; } afd_poll_info;

static __thread HANDLE io_ev;

static HANDLE thread_event(void)
{
	if (!io_ev)
		io_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
	ResetEvent(io_ev);
	return io_ev;
}

/* A failed socket handle operation's Win32 error as -errno */
static i64 net_err(DWORD e)
{
	switch (e) {
	case ERROR_NETNAME_DELETED: return -L_ECONNRESET;
	case ERROR_CONNECTION_ABORTED: return -L_ECONNABORTED;
	case ERROR_GRACEFUL_DISCONNECT: case ERROR_HANDLE_EOF: return 0;
	case ERROR_PORT_UNREACHABLE: return -L_ECONNREFUSED;
	case ERROR_OPERATION_ABORTED: return -L_EINTR;
	}
	if (e >= 10000)
		return ws_wsaerr((int)e);
	if (GetEnvironmentVariableA("BMC_WIN_NETDEBUG", NULL, 0)) {
		char n1[24];
		ws_fmt_u64(n1, e);
		ws_write_stderr("bmc_win: socket I/O failed: err ");
		ws_write_stderr(n1);
		ws_write_stderr("\n");
	}
	return ws_err(e);
}

/* Wait for an overlapped operation on h, interruptibly. Returns the byte
 * count, -EINTR / -EAGAIN (timeout) after cancelling it, or -errno. */
static i64 io_finish(HANDLE h, OVERLAPPED *ov, BOOL started, DWORD ms)
{
	DWORD n = 0;
	if (!started) {
		DWORD e = GetLastError();
		if (e != ERROR_IO_PENDING)
			return net_err(e);
		int w = ws_wait(&ov->hEvent, 1, ms);
		if (w != 0) {
			DWORD we = GetLastError();
			CancelIoEx(h, ov);
			if (GetOverlappedResult(h, ov, &n, TRUE))
				return (i64)n;          /* it completed after all */
			if (w == WS_WAIT_FAILED) {
				if (GetEnvironmentVariableA("BMC_WIN_NETDEBUG", NULL, 0)) {
					char n1[24];
					ws_fmt_u64(n1, we);
					ws_write_stderr("bmc_win: overlapped wait failed: err ");
					ws_write_stderr(n1);
					ws_write_stderr("\n");
				}
				return ws_err(we);
			}
			return w == WS_WAIT_INTR ? -L_EINTR : -L_EAGAIN;
		}
	}
	if (!GetOverlappedResult(h, ov, &n, TRUE)) {
		return net_err(GetLastError());
	}
	return (i64)n;
}

/* One AFD poll over n handles; info is filled with the result events.
 * ms: 0 = check, INFINITE = forever. Returns handles reported, or -errno. */
static i64 afd_poll(afd_poll_info *info, int n, DWORD ms)
{
	info->Timeout.QuadPart = ms == INFINITE ? 0x7fffffffffffffffLL : -(LONGLONG)ms * 10000;
	info->NumberOfHandles = (ULONG)n;
	info->Exclusive = 0;
	DWORD size = (DWORD)(sizeof(afd_poll_info) + sizeof(afd_handle_info) * (size_t)(n - 1));
	OVERLAPPED ov;
	__ws_memset(&ov, 0, sizeof ov);
	ov.hEvent = thread_event();
	HANDLE h = info->Handles[0].Handle;
	BOOL ok = DeviceIoControl(h, IOCTL_AFD_POLL, info, size, info, size, NULL, &ov);
	DWORD e0 = ok ? 0 : GetLastError();
	i64 r = io_finish(h, &ov, ok, INFINITE);   /* AFD itself applies the timeout */
	if (r < 0) {
		if (GetEnvironmentVariableA("BMC_WIN_NETDEBUG", NULL, 0)) {
			char n1[24], n2[24], n3[24];
			ws_fmt_u64(n1, e0);
			ws_fmt_u64(n2, (u64)-r);
			ws_fmt_u64(n3, (u64)(uintptr_t)h);
			ws_write_stderr("bmc_win: AFD poll failed: ioctl err ");
			ws_write_stderr(n1);
			ws_write_stderr(" -> errno ");
			ws_write_stderr(n2);
			ws_write_stderr(" handle ");
			ws_write_stderr(n3);
			ws_write_stderr("\n");
		}
		return r;
	}
	return (i64)info->NumberOfHandles;
}

/* wait until one of `events` is reported for d (or an error event) */
static i64 sock_wait(ws_desc *d, ULONG events, DWORD ms)
{
	u64 deadline = ms == INFINITE ? 0 : GetTickCount64() + ms;
	for (;;) {
		afd_poll_info pi;
		__ws_memset(&pi, 0, sizeof pi);
		pi.Handles[0].Handle = (HANDLE)d->s;
		pi.Handles[0].Events = events | AFD_POLL_ERRORS;
		DWORD left = ms;
		if (deadline) {
			u64 now = GetTickCount64();
			left = now >= deadline ? 0 : (DWORD)(deadline - now);
		}
		i64 r = afd_poll(&pi, 1, left);
		if (r < 0)
			return r;
		if (r > 0 && (pi.Handles[0].Events & (events | AFD_POLL_ERRORS)))
			return (i64)pi.Handles[0].Events;
		/* nothing, or only events nobody asked for (AFD can wake a poll
		 * early, e.g. on a connect's completion): poll again until the
		 * deadline */
		if (left == 0 || (deadline && GetTickCount64() >= deadline)) {
			if (GetEnvironmentVariableA("BMC_WIN_NETDEBUG", NULL, 0) && ms) {
				char n1[24], n2[24], n3[24], n4[24];
				ws_fmt_u64(n1, (u64)r);
				ws_fmt_u64(n2, pi.Handles[0].Events);
				ws_fmt_u64(n3, events);
				ws_fmt_u64(n4, ms);
				ws_write_stderr("bmc_win: sock_wait EAGAIN: r ");
				ws_write_stderr(n1);
				ws_write_stderr(" got ");
				ws_write_stderr(n2);
				ws_write_stderr(" want ");
				ws_write_stderr(n3);
				ws_write_stderr(" ms ");
				ws_write_stderr(n4);
				ws_write_stderr("\n");
			}
			return -L_EAGAIN;
		}
	}
}

/* readiness gate before an operation: O_NONBLOCK / MSG_DONTWAIT check once,
 * otherwise wait (SO_RCVTIMEO / SO_SNDTIMEO bound the wait) */
static i64 gate(ws_desc *d, ULONG events, int dontwait, DWORD timeo)
{
	int nb = dontwait || (d->flags & L_O_NONBLOCK);
	i64 r = sock_wait(d, events, nb ? 0 : (timeo ? timeo : INFINITE));
	return r < 0 ? r : 0;
}

void ws_net_init(void)
{
	ws_ws2_init();
	WSADATA w;
	WSAStartup(MAKEWORD(2, 2), &w);
}

static int wfam(int f) { return f == L_AF_INET6 ? AF_INET6 : f; }
static int lfam(int f) { return f == AF_INET6 ? L_AF_INET6 : f; }

/* Linux sockaddr -> Windows sockaddr (copy; family translated) */
static int addr_in(const void *la, int len, struct sockaddr_storage *out)
{
	if (len < 2 || len > (int)sizeof *out)
		return -1;
	__ws_memcpy(out, la, (size_t)len);
	out->ss_family = (ADDRESS_FAMILY)wfam(*(const unsigned short *)la);
	return len;
}

static void addr_out(const struct sockaddr_storage *wa, int wlen, void *la, int *llen)
{
	if (!la || !llen)
		return;
	struct sockaddr_storage t;
	__ws_memcpy(&t, wa, (size_t)wlen);
	*(unsigned short *)&t = (unsigned short)lfam(wa->ss_family);
	int n = wlen < *llen ? wlen : *llen;
	__ws_memcpy(la, &t, (size_t)n);
	*llen = wlen;
}

static ws_desc *sock_get(int fd, i64 *err)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d) {
		*err = -L_EBADF;
		return NULL;
	}
	if (d->type != FT_SOCKET) {
		ws_desc_put(d);
		*err = -L_ENOTSOCK;
		return NULL;
	}
	return d;
}

static i64 lasterr(void) { return ws_wsaerr(WSAGetLastError()); }

static i64 install_socket(SOCKET s, int nonblock, int cloexec)
{
	ws_desc *d = ws_desc_new(FT_SOCKET);
	if (!d) {
		closesocket(s);
		return -L_ENOMEM;
	}
	d->s = s;
	d->flags = 2 | (nonblock ? L_O_NONBLOCK : 0);   /* O_RDWR */
	return ws_fd_install(d, cloexec, 0);
}

static i64 sys_socket(int fam, int type, int proto)
{
	int nb = (type & L_SOCK_NONBLOCK) != 0, ce = (type & L_SOCK_CLOEXEC) != 0;
	type &= 0xf;
	SOCKET s = WSASocketW(wfam(fam), type, proto, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	if (s == INVALID_SOCKET)
		return lasterr();
	if (wfam(fam) == AF_INET6) {
		/* Linux default: dual-stack unless IPV6_V6ONLY is set */
		DWORD off = 0;
		setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof off);
	}
	return install_socket(s, nb, ce);
}

/* A connect Winsock did not see complete (it finished while we waited on
 * AFD, or in the root on a handle it has since closed) leaves the socket's
 * stored context at "connecting"; this is the documented refresh (as after
 * ConnectEx). */
#define SO_UPDATE_CONNECT_CONTEXT_ 0x7010
static void refresh_connected(SOCKET s)
{
	setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT_, NULL, 0);
}

static i64 sys_connect(int fd, const void *addr, int len)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	struct sockaddr_storage a;
	i64 r = 0;
	int wl = addr_in(addr, len, &a);
	if (wl < 0) {
		ws_desc_put(d);
		return -L_EINVAL;
	}
	d->peer = a;
	d->peerlen = wl;
	d->connected = 0;
	d->since_ms = GetTickCount64();
	u_long on = 1, off = 0;
	ioctlsocket(d->s, FIONBIO, &on);
	int c = connect(d->s, (struct sockaddr *)&a, wl);
	int e = c == SOCKET_ERROR ? WSAGetLastError() : 0;
	if (e && e != WSAEWOULDBLOCK && GetEnvironmentVariableA("BMC_WIN_NETDEBUG", NULL, 0)) {
		char n1[24], n2[24], n3[24];
		ws_fmt_u64(n1, (u64)e);
		ws_fmt_u64(n2, (u64)wl);
		ws_fmt_u64(n3, (u64)a.ss_family);
		ws_write_stderr("bmc_win: connect failed: WSA ");
		ws_write_stderr(n1);
		ws_write_stderr(" len ");
		ws_write_stderr(n2);
		ws_write_stderr(" family ");
		ws_write_stderr(n3);
		const unsigned char *ab = (const unsigned char *)&a;
		ws_fmt_u64(n1, (u64)((ab[2] << 8) | ab[3]));
		ws_write_stderr(" port ");
		ws_write_stderr(n1);
		ws_fmt_u64(n1, ((u64)ab[4] << 24) | ((u64)ab[5] << 16) | ((u64)ab[6] << 8) | ab[7]);
		ws_write_stderr(" addr32 ");
		ws_write_stderr(n1);
		ws_write_stderr("\n");
	}
	ioctlsocket(d->s, FIONBIO, &off);
	if (c == 0) {
		r = 0;
		d->connected = 1;
	} else if (e != WSAEWOULDBLOCK) {
		r = ws_wsaerr(e);
		d->peerlen = 0;
	} else if (d->flags & L_O_NONBLOCK) {
		r = -L_EINPROGRESS;
	} else {
		i64 w = sock_wait(d, AFD_POLL_SEND, d->sndtimeo ? d->sndtimeo : INFINITE);
		if (w == -L_EAGAIN) {
			r = -L_ETIMEDOUT;
		} else if (w < 0) {
			r = w;                        /* -EINTR: the connect goes on, as on Linux */
		} else if (w & (AFD_POLL_CONNECT_FAIL | AFD_POLL_ABORT)) {
			int so = 0, sl = sizeof so;
			getsockopt(d->s, SOL_SOCKET, SO_ERROR, (char *)&so, &sl);
			r = so ? ws_wsaerr(so) : -L_ECONNREFUSED;
		} else {
			refresh_connected(d->s);
			ioctlsocket(d->s, FIONBIO, &off);   /* once more: the first came mid-connect */
			d->connected = 1;
		}
	}
	ws_desc_put(d);
	return r;
}

static i64 sys_bind(int fd, const void *addr, int len)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	struct sockaddr_storage a;
	int wl = addr_in(addr, len, &a);
	i64 r = wl < 0 ? -L_EINVAL : bind(d->s, (struct sockaddr *)&a, wl) == SOCKET_ERROR ? lasterr() : 0;
	ws_desc_put(d);
	return r;
}

static i64 sys_listen(int fd, int backlog)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	i64 r = listen(d->s, backlog) == SOCKET_ERROR ? lasterr() : 0;
	ws_desc_put(d);
	return r;
}

static i64 sys_accept(int fd, void *addr, int *alen, int flags)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	i64 g = gate(d, AFD_POLL_ACCEPT, 0, d->rcvtimeo);
	if (g < 0) {
		ws_desc_put(d);
		return g;
	}
	struct sockaddr_storage a;
	int wl = sizeof a;
	SOCKET s = accept(d->s, (struct sockaddr *)&a, &wl);
	ws_desc_put(d);
	if (s == INVALID_SOCKET)
		return lasterr();
	u_long off = 0;
	ioctlsocket(s, FIONBIO, &off);
	addr_out(&a, wl, addr, alen);
	i64 nfd = install_socket(s, (flags & L_SOCK_NONBLOCK) != 0, (flags & L_SOCK_CLOEXEC) != 0);
	if (nfd >= 0) {
		ws_desc *nd = ws_fd_get((int)nfd);
		if (nd) {
			nd->peer = a;
			nd->peerlen = wl;
			nd->connected = 1;
			ws_desc_put(nd);
		}
	}
	return nfd;
}

/* local/remote address straight from AFD (no Winsock: works in a forked
 * process, and is never stale): the socket-name and remote-address
 * ioctls return a SOCKADDR at the start of their output */
#define IOCTL_AFD_GET_SOCK_NAME_ 0x0001202F
#define IOCTL_AFD_GET_REMOTE_ADDRESS_ 0x0001203F
static int afd_name(SOCKET s, int peer, struct sockaddr_storage *out, int *len)
{
	unsigned char buf[256];
	OVERLAPPED ov;
	__ws_memset(&ov, 0, sizeof ov);
	ov.hEvent = thread_event();
	DWORD code = peer ? IOCTL_AFD_GET_REMOTE_ADDRESS_ : IOCTL_AFD_GET_SOCK_NAME_;
	BOOL ok = DeviceIoControl((HANDLE)s, code, NULL, 0, buf, sizeof buf, NULL, &ov);
	i64 n = io_finish((HANDLE)s, &ov, ok, INFINITE);
	if (n < 2)
		return -1;
	int fam = *(unsigned short *)buf;
	int l = fam == AF_INET ? (int)sizeof(struct sockaddr_in) : fam == AF_INET6 ? (int)sizeof(struct sockaddr_in6) : 0;
	if (!l || n < l)
		return -1;
	if (peer && fam == AF_INET && !*(u_long *)(buf + 4) && !*(u_short *)(buf + 2))
		return -1;                   /* not connected */
	__ws_memcpy(out, buf, (size_t)l);
	*len = l;
	return 0;
}

static i64 sys_name(int fd, void *addr, int *alen, int peer)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	struct sockaddr_storage a;
	int wl = sizeof a;
	if (peer && d->peerlen) {
		/* the address connect() was given / accept() returned, once the
		 * connection is seen up (Linux: ENOTCONN before that) */
		if (!d->connected) {
			i64 ev = sock_wait(d, AFD_POLL_SEND | AFD_POLL_RECEIVE, 0);
			if (ev > 0 && !(ev & (AFD_POLL_CONNECT_FAIL | AFD_POLL_ABORT)))
				InterlockedExchange(&d->connected, 1);
		}
		i64 r = d->connected ? 0 : -L_ENOTCONN;
		if (!r) {
			a = d->peer;
			wl = d->peerlen;
		}
		ws_desc_put(d);
		if (!r)
			addr_out(&a, wl, addr, alen);
		return r;
	}
	if (!peer && afd_name(d->s, 0, &a, &wl) == 0) {
		ws_desc_put(d);
		addr_out(&a, wl, addr, alen);
		return 0;
	}
	int r = peer ? getpeername(d->s, (struct sockaddr *)&a, &wl) : getsockname(d->s, (struct sockaddr *)&a, &wl);
	if (r == SOCKET_ERROR && peer && WSAGetLastError() == WSAENOTCONN) {
		refresh_connected(d->s);
		wl = sizeof a;
		r = getpeername(d->s, (struct sockaddr *)&a, &wl);
	}
	ws_desc_put(d);
	if (r == SOCKET_ERROR)
		return lasterr();
	addr_out(&a, wl, addr, alen);
	return 0;
}

/* ---- data ---- */
static i64 handle_io(ws_desc *d, void *buf, size_t n, int write)
{
	if (n > 0x7ffff000)
		n = 0x7ffff000;
	OVERLAPPED ov;
	__ws_memset(&ov, 0, sizeof ov);
	ov.hEvent = thread_event();
	BOOL ok = write ? WriteFile((HANDLE)d->s, buf, (DWORD)n, NULL, &ov)
			: ReadFile((HANDLE)d->s, buf, (DWORD)n, NULL, &ov);
	return io_finish((HANDLE)d->s, &ov, ok, INFINITE);
}

/* gate, then the handle I/O. The socket's mode at the Winsock level is not
 * ours to trust (a connect left it non-blocking, or another process holds
 * the endpoint): a blocking descriptor whose I/O comes back EAGAIN waits for
 * readiness again, within its SO_RCVTIMEO/SO_SNDTIMEO */
static i64 sock_io(ws_desc *d, void *buf, size_t n, int write)
{
	ULONG ev = write ? AFD_POLL_SEND : AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT;
	DWORD timeo = write ? d->sndtimeo : d->rcvtimeo;
	u64 deadline = timeo ? GetTickCount64() + timeo : 0;
	for (;;) {
		DWORD left = timeo;
		if (deadline) {
			u64 now = GetTickCount64();
			if (now >= deadline)
				return -L_EAGAIN;
			left = (DWORD)(deadline - now);
		}
		i64 g = gate(d, ev, 0, left);
		if (g < 0)
			return g;
		if (n == 0)
			return 0;
		i64 r = handle_io(d, buf, n, write);
		if (r > 0) {
			if (write)
				d->last_tx_ms = GetTickCount64();
			else
				d->last_rx_ms = GetTickCount64();
		}
		if (r == -L_ECONNRESET || r == -L_ECONNABORTED) {
			if (InterlockedExchange(&d->reset_seen, 1))
				return write ? -L_EPIPE : 0;
		}
		if (r != -L_EAGAIN || (d->flags & L_O_NONBLOCK))
			return r;
	}
}

i64 ws_sock_read(ws_desc *d, void *buf, size_t n)
{
	return sock_io(d, buf, n, 0);
}

i64 ws_sock_write(ws_desc *d, const void *buf, size_t n)
{
	i64 r = sock_io(d, (void *)buf, n, 1);
	return r == -L_ECONNRESET || r == -L_ECONNABORTED ? -L_EPIPE : r;
}

i64 ws_sock_nread(ws_desc *d)
{
	u_long n = 0;
	return ioctlsocket(d->s, FIONREAD, &n) ? lasterr() : (i64)n;
}

static int wflags(int f)
{
	return (f & L_MSG_OOB ? MSG_OOB : 0) | (f & L_MSG_PEEK ? MSG_PEEK : 0) | (f & L_MSG_WAITALL ? MSG_WAITALL : 0);
}

static i64 sys_sendto(int fd, const void *buf, size_t n, int flags, const void *addr, int alen)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	i64 res;
	if (!addr && !(flags & (L_MSG_OOB))) {
		res = (flags & L_MSG_DONTWAIT) ? gate(d, AFD_POLL_SEND, 1, 0) : 0;
		if (res == 0)
			res = ws_sock_write(d, buf, n);
		ws_desc_put(d);
		return res;
	}
	struct sockaddr_storage a;
	int wl = 0;
	if (addr && (wl = addr_in(addr, alen, &a)) < 0) {
		ws_desc_put(d);
		return -L_EINVAL;
	}
	res = gate(d, AFD_POLL_SEND, (flags & L_MSG_DONTWAIT) != 0, d->sndtimeo);
	if (res == 0) {
		int len = n > 0x7fffffff ? 0x7fffffff : (int)n;
		int r = addr ? sendto(d->s, buf, len, wflags(flags), (struct sockaddr *)&a, wl)
			     : send(d->s, buf, len, wflags(flags));
		res = r == SOCKET_ERROR ? lasterr() : r;
	}
	ws_desc_put(d);
	return res;
}

static i64 sys_recvfrom(int fd, void *buf, size_t n, int flags, void *addr, int *alen)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	i64 res = gate(d, AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT, (flags & L_MSG_DONTWAIT) != 0, d->rcvtimeo);
	if (res == 0) {
		if (!addr && !(flags & (L_MSG_PEEK | L_MSG_OOB | L_MSG_WAITALL))) {
			res = n ? handle_io(d, buf, n, 0) : 0;
		} else {
			struct sockaddr_storage a;
			int wl = sizeof a;
			int len = n > 0x7fffffff ? 0x7fffffff : (int)n;
			int r = addr ? recvfrom(d->s, buf, len, wflags(flags), (struct sockaddr *)&a, &wl)
				     : recv(d->s, buf, len, wflags(flags));
			if (r == SOCKET_ERROR) {
				int e = WSAGetLastError();
				res = (e == WSAEMSGSIZE) ? len : ws_wsaerr(e);
			} else {
				res = r;
				if (addr)
					addr_out(&a, wl, addr, alen);
			}
		}
	}
	ws_desc_put(d);
	return res;
}

struct l_iovec { void *base; u64 len; };
struct l_msghdr {
	void *name;
	int namelen, pad0;
	struct l_iovec *iov;
	u64 iovlen;
	void *control;
	u64 controllen;
	int flags, pad1;
};

struct l_cmsghdr { u64 len; int level, type; };
#define L_SOL_SOCKET 1
#define L_SCM_RIGHTS 1
#define L_MSG_CTRUNC 0x8
#define L_MSG_CMSG_CLOEXEC 0x40000000
#define CMSG_ALIGN8(x) (((x) + 7) & ~(u64)7)

static void meta_of(ws_desc *d, ws_fd_meta *m)
{
	__ws_memset(m, 0, sizeof *m);
	m->type = d->type;
	m->flags = d->flags;
	m->rcvtimeo = d->rcvtimeo;
	m->sndtimeo = d->sndtimeo;
	m->peerlen = d->peerlen;
	m->connected = d->connected;
	m->peer = d->peer;
	m->pair_key = d->pair_key;
	m->pair_side = d->pair_side;
	if (d->wpath) {
		size_t l = ws_wcslen(d->wpath);
		if (l < 299)
			__ws_memcpy(m->path, d->wpath, (l + 1) * sizeof(wchar_t));
	}
}

/* deposit the SCM_RIGHTS descriptors of a sendmsg; -errno on failure */
static i64 send_rights(ws_desc *d, struct l_msghdr *m)
{
	if (!m->control || m->controllen < sizeof(struct l_cmsghdr))
		return 0;
	unsigned char *c = m->control, *end = c + m->controllen;
	while (c + sizeof(struct l_cmsghdr) <= end) {
		struct l_cmsghdr *h = (struct l_cmsghdr *)c;
		if (h->len < sizeof *h || c + h->len > end)
			return -L_EINVAL;
		if (h->level == L_SOL_SOCKET && h->type == L_SCM_RIGHTS) {
			if (!d->pair_key)
				return -L_EOPNOTSUPP;           /* only our socketpairs carry descriptors */
			int nfd = (int)((h->len - sizeof *h) / sizeof(int));
			const int *fds = (const int *)(c + sizeof *h);
			for (int i = 0; i < nfd; i++) {
				ws_desc *x = ws_fd_get(fds[i]);
				if (!x)
					return -L_EBADF;
				ws_fd_meta meta;
				meta_of(x, &meta);
				HANDLE hh = x->type == FT_SOCKET ? (HANDLE)x->s : x->h;
				int r = ws_escrow_put(d->pair_key, 1 - d->pair_side, hh, &meta);
				ws_desc_put(x);
				if (r < 0)
					return -L_ENOBUFS;
			}
		}
		c += CMSG_ALIGN8(h->len);
	}
	return 0;
}

/* collect descriptors waiting for this end into m->control */
static void recv_rights(ws_desc *d, struct l_msghdr *m, int flags)
{
	u64 cap = m->control ? m->controllen : 0;
	m->controllen = 0;
	if (!d->pair_key || cap < sizeof(struct l_cmsghdr) + sizeof(int))
		return;
	int max = (int)((cap - sizeof(struct l_cmsghdr)) / sizeof(int));
	HANDLE hs[16];
	ws_fd_meta *metas = ws_alloc(sizeof(ws_fd_meta) * 16);
	if (!metas)
		return;
	int n = ws_escrow_take(d->pair_key, d->pair_side, hs, metas, max > 16 ? 16 : max);
	if (n <= 0) {
		ws_free(metas);
		return;
	}
	struct l_cmsghdr *h = (struct l_cmsghdr *)m->control;
	int *fds = (int *)((unsigned char *)m->control + sizeof *h);
	int got = 0;
	for (int i = 0; i < n; i++) {
		ws_desc *x = ws_desc_new(metas[i].type);
		if (!x) {
			CloseHandle(hs[i]);
			continue;
		}
		if (metas[i].type == FT_SOCKET)
			x->s = (SOCKET)hs[i];
		else
			x->h = hs[i];
		x->flags = metas[i].flags;
		x->rcvtimeo = metas[i].rcvtimeo;
		x->sndtimeo = metas[i].sndtimeo;
		x->peerlen = metas[i].peerlen;
		x->connected = metas[i].connected;
		x->peer = metas[i].peer;
		x->pair_key = metas[i].pair_key;
		x->pair_side = metas[i].pair_side;
		if (metas[i].path[0]) {
			size_t l = ws_wcslen(metas[i].path);
			x->wpath = ws_alloc((l + 1) * sizeof(wchar_t));
			if (x->wpath)
				__ws_memcpy(x->wpath, metas[i].path, (l + 1) * sizeof(wchar_t));
		}
		int fd = ws_fd_install(x, (flags & L_MSG_CMSG_CLOEXEC) != 0, 0);
		if (fd >= 0)
			fds[got++] = fd;
	}
	ws_free(metas);
	if (!got)
		return;
	h->len = sizeof *h + sizeof(int) * (u64)got;
	h->level = L_SOL_SOCKET;
	h->type = L_SCM_RIGHTS;
	m->controllen = CMSG_ALIGN8(h->len);
}

/* sendmsg/recvmsg without an address: the handle path (no Winsock, so a
 * forked process does it itself), the iovec flattened */
static i64 msg_plain(ws_desc *d, struct l_msghdr *m, int flags, int out)
{
	u64 total = 0;
	for (u64 i = 0; i < m->iovlen; i++)
		total += m->iov[i].len;
	if (total > 0x7ffff000)
		total = 0x7ffff000;
	char *flat = ws_alloc(total ? (size_t)total : 1);
	if (!flat)
		return -L_ENOMEM;
	i64 r;
	int was_nb = d->flags & L_O_NONBLOCK;
	if (flags & L_MSG_DONTWAIT)
		d->flags |= L_O_NONBLOCK;
	if (out) {
		u64 at = 0;
		for (u64 i = 0; i < m->iovlen && at < total; i++) {
			u64 c = m->iov[i].len < total - at ? m->iov[i].len : total - at;
			__ws_memcpy(flat + at, m->iov[i].base, (size_t)c);
			at += c;
		}
		r = send_rights(d, m);
		if (r == 0)
			r = ws_sock_write(d, flat, (size_t)total);
	} else {
		r = ws_sock_read(d, flat, (size_t)total);
		if (r > 0) {
			u64 at = 0;
			for (u64 i = 0; i < m->iovlen && at < (u64)r; i++) {
				u64 c = m->iov[i].len < (u64)r - at ? m->iov[i].len : (u64)r - at;
				__ws_memcpy(m->iov[i].base, flat + at, (size_t)c);
				at += c;
			}
		}
		m->flags = 0;
		if (r >= 0)
			recv_rights(d, m, flags);
		else
			m->controllen = 0;
	}
	if (!was_nb)
		d->flags &= ~L_O_NONBLOCK;
	ws_free(flat);
	return r;
}

static i64 sys_msg(int fd, struct l_msghdr *m, int flags, int out)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	if (m->iovlen > 64) {
		ws_desc_put(d);
		return -L_EMSGSIZE;
	}
	if (!m->name && !(flags & (L_MSG_PEEK | L_MSG_OOB | L_MSG_WAITALL))) {
		i64 r = msg_plain(d, m, flags, out);
		ws_desc_put(d);
		return r;
	}
	i64 res = gate(d, out ? AFD_POLL_SEND : AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT,
		       (flags & L_MSG_DONTWAIT) != 0, out ? d->sndtimeo : d->rcvtimeo);
	if (res) {
		ws_desc_put(d);
		return res;
	}
	WSABUF b[64];
	for (u64 i = 0; i < m->iovlen; i++) {
		b[i].buf = m->iov[i].base;
		b[i].len = (ULONG)m->iov[i].len;
	}
	struct sockaddr_storage a;
	int wl = 0;
	if (out && m->name && (wl = addr_in(m->name, m->namelen, &a)) < 0) {
		ws_desc_put(d);
		return -L_EINVAL;
	}
	DWORD got = 0, wf = (DWORD)wflags(flags);
	int r;
	if (out) {
		r = WSASendTo(d->s, b, (DWORD)m->iovlen, &got, wf, m->name ? (struct sockaddr *)&a : NULL, wl,
			      NULL, NULL);
	} else {
		wl = sizeof a;
		r = WSARecvFrom(d->s, b, (DWORD)m->iovlen, &got, &wf, m->name ? (struct sockaddr *)&a : NULL,
				m->name ? &wl : NULL, NULL, NULL);
		if (r != SOCKET_ERROR && m->name)
			addr_out(&a, wl, m->name, &m->namelen);
		m->controllen = 0;
		m->flags = 0;
	}
	res = r == SOCKET_ERROR ? lasterr() : (i64)got;
	ws_desc_put(d);
	return res;
}

static i64 sys_shutdown(int fd, int how)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	i64 r = shutdown(d->s, how) == SOCKET_ERROR ? lasterr() : 0;
	ws_desc_put(d);
	return r;
}

/* ---- options ---- */
struct l_timeval { i64 sec, usec; };

static DWORD tv_ms(const struct l_timeval *tv)
{
	i64 ms = tv->sec * 1000 + tv->usec / 1000;
	if (!ms && tv->usec)
		ms = 1;
	return ms > 0x7ffffffe ? 0x7ffffffe : (DWORD)ms;
}

static i64 sys_setsockopt(int fd, int level, int opt, const void *val, int len)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	int wlevel = level, wopt = -1, ival = len >= 4 ? *(const int *)val : 0;
	const char *wval = (const char *)&ival;
	int wlen = sizeof ival;
	struct linger lg;
	i64 r = 0;
	if (level == 1) {                      /* SOL_SOCKET */
		wlevel = SOL_SOCKET;
		switch (opt) {
		case 2: case 15: goto done;        /* SO_REUSEADDR/PORT: Windows rebinding is already permissive */
		case 9: wopt = SO_KEEPALIVE; break;
		case 7: wopt = SO_SNDBUF; break;
		case 8: wopt = SO_RCVBUF; break;
		case 6: wopt = SO_BROADCAST; break;
		case 20:                           /* SO_RCVTIMEO: emulated (the waits are ours) */
			if (len < (int)sizeof(struct l_timeval)) {
				r = -L_EINVAL;
				goto done;
			}
			d->rcvtimeo = tv_ms(val);
			goto done;
		case 21:                           /* SO_SNDTIMEO */
			if (len < (int)sizeof(struct l_timeval)) {
				r = -L_EINVAL;
				goto done;
			}
			d->sndtimeo = tv_ms(val);
			goto done;
		case 13: {                         /* SO_LINGER {int onoff; int linger} */
			const int *l = val;
			lg.l_onoff = (u_short)(l[0] != 0);
			lg.l_linger = (u_short)l[1];
			wopt = SO_LINGER;
			wval = (const char *)&lg;
			wlen = sizeof lg;
			break;
		}
		default: goto done;                /* SO_PRIORITY, SO_MARK, ...: no Windows meaning */
		}
	} else if (level == 6) {               /* IPPROTO_TCP */
		switch (opt) {
		case 1: wopt = TCP_NODELAY; break;
		case 4: wopt = TCP_KEEPIDLE; break;
		case 5: wopt = TCP_KEEPINTVL; break;
		case 6: wopt = TCP_KEEPCNT; break;
		default: goto done;                /* QUICKACK, USER_TIMEOUT, ... */
		}
	} else if (level == 41) {              /* IPPROTO_IPV6 */
		if (opt == 26)
			wopt = IPV6_V6ONLY;
		else
			goto done;
	} else {
		goto done;
	}
	if (setsockopt(d->s, wlevel, wopt, wval, wlen) == SOCKET_ERROR)
		r = lasterr();
done:
	ws_desc_put(d);
	return r;
}

static i64 sys_getsockopt(int fd, int level, int opt, void *val, int *len)
{
	i64 err;
	ws_desc *d = sock_get(fd, &err);
	if (!d)
		return err;
	i64 r = 0;
	int iv = 0, wl = sizeof iv;
	if (level == 1 && opt == 4) {          /* SO_ERROR */
		if (getsockopt(d->s, SOL_SOCKET, SO_ERROR, (char *)&iv, &wl) == SOCKET_ERROR)
			r = lasterr();
		else
			iv = iv ? (int)-ws_wsaerr(iv) : 0;
	} else if (level == 1 && opt == 3) {   /* SO_TYPE */
		if (getsockopt(d->s, SOL_SOCKET, SO_TYPE, (char *)&iv, &wl) == SOCKET_ERROR)
			r = lasterr();
	} else if (level == 1 && (opt == 7 || opt == 8)) {
		if (getsockopt(d->s, SOL_SOCKET, opt == 7 ? SO_SNDBUF : SO_RCVBUF, (char *)&iv, &wl) == SOCKET_ERROR)
			r = lasterr();
	} else if (level == 1 && (opt == 20 || opt == 21)) {
		DWORD ms = opt == 20 ? d->rcvtimeo : d->sndtimeo;
		if (*len >= (int)sizeof(struct l_timeval)) {
			struct l_timeval *tv = val;
			tv->sec = ms / 1000;
			tv->usec = (ms % 1000) * 1000;
			*len = sizeof *tv;
		} else {
			r = -L_EINVAL;
		}
		ws_desc_put(d);
		return r;
	} else if (level == 6 && opt == 11) {        /* TCP_INFO: Linux struct tcp_info */
		unsigned char ti[232];
		__ws_memset(ti, 0, sizeof ti);
		i64 ev = sock_wait(d, AFD_POLL_DISCONNECT | AFD_POLL_ABORT, 0);
		unsigned char state = 7;                 /* TCP_CLOSE */
		if (d->connected || (d->peerlen && ev >= 0 && !(ev & (AFD_POLL_ABORT | AFD_POLL_CONNECT_FAIL))))
			state = 1;                           /* TCP_ESTABLISHED */
		else if (d->peerlen)
			state = 2;                           /* TCP_SYN_SENT */
		if (ev > 0 && (ev & AFD_POLL_DISCONNECT))
			state = 8;                           /* TCP_CLOSE_WAIT: the peer sent FIN */
		if (ev > 0 && (ev & AFD_POLL_ABORT))
			state = 7;
		ti[0] = state;
		u64 now = GetTickCount64(), base = d->since_ms ? d->since_ms : now;
		uint32_t since_tx = (uint32_t)(now - (d->last_tx_ms ? d->last_tx_ms : base));
		uint32_t since_rx = (uint32_t)(now - (d->last_rx_ms ? d->last_rx_ms : base));
		__ws_memcpy(ti + 44, &since_tx, 4);     /* tcpi_last_data_sent */
		__ws_memcpy(ti + 52, &since_rx, 4);     /* tcpi_last_data_recv */
		__ws_memcpy(ti + 56, &since_rx, 4);     /* tcpi_last_ack_recv */
		uint32_t mss = 1460;
		__ws_memcpy(ti + 16, &mss, 4);          /* tcpi_snd_mss */
		__ws_memcpy(ti + 20, &mss, 4);          /* tcpi_rcv_mss */
		int l = *len < (int)sizeof ti ? *len : (int)sizeof ti;
		__ws_memcpy(val, ti, (size_t)l);
		*len = l;
		ws_desc_put(d);
		return 0;
	} else if (level == 6 && opt == 1) {
		if (getsockopt(d->s, IPPROTO_TCP, TCP_NODELAY, (char *)&iv, &wl) == SOCKET_ERROR)
			r = lasterr();
		iv = iv != 0;
	} else if (level == 1 && opt == 9) {
		if (getsockopt(d->s, SOL_SOCKET, SO_KEEPALIVE, (char *)&iv, &wl) == SOCKET_ERROR)
			r = lasterr();
		iv = iv != 0;
	} else {
		iv = 0;
	}
	if (!r && *len >= 4) {
		*(int *)val = iv;
		*len = 4;
	}
	ws_desc_put(d);
	return r;
}

/* ---- socketpair: a connected loopback TCP pair ---- */
static i64 sys_socketpair(int fam, int type, int proto, int *sv)
{
	(void)proto;
	if (fam != L_AF_UNIX && fam != L_AF_INET)
		return -L_EAFNOSUPPORT;
	if ((type & 0xf) != SOCK_STREAM)
		return -L_EOPNOTSUPP;
	int nb = (type & L_SOCK_NONBLOCK) != 0, ce = (type & L_SOCK_CLOEXEC) != 0;
	SOCKET l = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	SOCKET a = INVALID_SOCKET, c = INVALID_SOCKET;
	struct sockaddr_in sa;
	int sl = sizeof sa;
	__ws_memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	i64 r = 0;
	if (l == INVALID_SOCKET || bind(l, (struct sockaddr *)&sa, sizeof sa) || listen(l, 1) ||
	    getsockname(l, (struct sockaddr *)&sa, &sl)) {
		r = lasterr();
		goto out;
	}
	c = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	if (c == INVALID_SOCKET || connect(c, (struct sockaddr *)&sa, sizeof sa)) {
		r = lasterr();
		goto out;
	}
	a = accept(l, NULL, NULL);
	if (a == INVALID_SOCKET) {
		r = lasterr();
		goto out;
	}
	BOOL one = TRUE;
	setsockopt(a, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
	setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
	i64 f0 = install_socket(c, nb, ce);
	c = INVALID_SOCKET;
	if (f0 < 0) {
		r = f0;
		goto out;
	}
	i64 f1 = install_socket(a, nb, ce);
	a = INVALID_SOCKET;
	if (f1 < 0) {
		__bmc_win_syscall(3, f0, 0, 0, 0, 0, 0);
		r = f1;
		goto out;
	}
	sv[0] = (int)f0;
	sv[1] = (int)f1;
	{
		extern i64 ws_getrandom(void *buf, size_t n);
		u64 key = 0;
		ws_getrandom(&key, sizeof key);
		for (int side = 0; side < 2; side++) {
			ws_desc *pd = ws_fd_get(sv[side]);
			if (pd) {
				pd->pair_key = key | 1;
				pd->pair_side = side;
				ws_desc_put(pd);
			}
		}
	}
out:
	if (l != INVALID_SOCKET)
		closesocket(l);
	if (a != INVALID_SOCKET)
		closesocket(a);
	if (c != INVALID_SOCKET)
		closesocket(c);
	return r;
}

/* ---- poll ---- */
#define L_POLLIN 0x1
#define L_POLLPRI 0x2
#define L_POLLOUT 0x4
#define L_POLLERR 0x8
#define L_POLLHUP 0x10
#define L_POLLNVAL 0x20
#define L_POLLRDNORM 0x40
#define L_POLLWRNORM 0x100
#define L_POLLRDHUP 0x2000

struct l_pollfd { int fd; short events, revents; };

/* readiness of a non-socket fd right now */
static short other_ready(ws_desc *d, short ev)
{
	short r = 0;
	switch (d->type) {
	case FT_PIPE: {
		DWORD avail = 0;
		if (!(d->flags & 3)) {             /* read end */
			if (!PeekNamedPipe(d->h, NULL, 0, NULL, &avail, NULL))
				r |= L_POLLHUP | (ev & (L_POLLIN | L_POLLRDNORM));
			else if (avail)
				r |= ev & (L_POLLIN | L_POLLRDNORM);
		} else {
			r |= ev & (L_POLLOUT | L_POLLWRNORM);
		}
		break;
	}
	case FT_EVENTFD:
		r = ws_eventfd_ready(d, ev);
		break;
	case FT_CONSOLE:
		if ((ev & (L_POLLIN | L_POLLRDNORM)) && WaitForSingleObject(d->h, 0) == WAIT_OBJECT_0)
			r |= ev & (L_POLLIN | L_POLLRDNORM);
		r |= ev & (L_POLLOUT | L_POLLWRNORM);
		break;
	default:                               /* files, /dev/null, directories: always ready */
		r |= ev & (L_POLLIN | L_POLLRDNORM | L_POLLOUT | L_POLLWRNORM);
	}
	return r;
}

static ULONG afd_events(short ev)
{
	ULONG a = AFD_POLL_ERRORS;
	if (ev & (L_POLLIN | L_POLLRDNORM))
		a |= AFD_POLL_RECEIVE | AFD_POLL_ACCEPT | AFD_POLL_DISCONNECT;
	if (ev & L_POLLRDHUP)
		a |= AFD_POLL_DISCONNECT;
	if (ev & L_POLLPRI)
		a |= AFD_POLL_RECEIVE_EXPEDITED;
	if (ev & (L_POLLOUT | L_POLLWRNORM))
		a |= AFD_POLL_SEND;
	return a;
}

static short poll_events(ULONG a, short ev)
{
	short r = 0;
	if (a & (AFD_POLL_RECEIVE | AFD_POLL_ACCEPT))
		r |= ev & (L_POLLIN | L_POLLRDNORM);
	if (a & AFD_POLL_RECEIVE_EXPEDITED)
		r |= ev & L_POLLPRI;
	if (a & AFD_POLL_SEND)
		r |= ev & (L_POLLOUT | L_POLLWRNORM);
	if (a & AFD_POLL_DISCONNECT)
		r |= (ev & (L_POLLIN | L_POLLRDNORM | L_POLLRDHUP));
	if (a & AFD_POLL_ABORT)
		r |= L_POLLHUP | L_POLLERR;
	if (a & AFD_POLL_CONNECT_FAIL)
		r |= L_POLLERR | (ev & (L_POLLOUT | L_POLLWRNORM));
	if (a & AFD_POLL_LOCAL_CLOSE)
		r |= L_POLLNVAL;
	return r;
}

static i64 sys_poll(struct l_pollfd *fds, u64 n, int timeout)
{
	if (n > 65536)
		return -L_EINVAL;
	ws_desc **ds = n ? ws_alloc(sizeof(ws_desc *) * n) : NULL;
	int *map = n ? ws_alloc(sizeof(int) * n) : NULL;
	afd_poll_info *pi = ws_alloc(sizeof(afd_poll_info) + sizeof(afd_handle_info) * (n ? n : 1));
	if ((n && (!ds || !map)) || !pi) {
		ws_free(ds);
		ws_free(map);
		ws_free(pi);
		return -L_ENOMEM;
	}
	int ns = 0, others = 0;
	for (u64 i = 0; i < n; i++) {
		fds[i].revents = 0;
		if (fds[i].fd < 0)
			continue;
		ds[i] = ws_fd_get(fds[i].fd);
		if (!ds[i])
			fds[i].revents = L_POLLNVAL;
		else if (ds[i]->type == FT_SOCKET)
			map[ns++] = (int)i;
		else
			others = 1;
	}
	i64 deadline = timeout < 0 ? -1 : (i64)GetTickCount64() + timeout;
	i64 ready;
	for (;;) {
		ready = 0;
		for (u64 i = 0; i < n; i++) {
			if (fds[i].revents == L_POLLNVAL) {
				ready++;
			} else if (ds[i] && ds[i]->type != FT_SOCKET) {
				fds[i].revents = other_ready(ds[i], fds[i].events);
				if (fds[i].revents)
					ready++;
			}
		}
		DWORD slice;
		if (ready) {
			slice = 0;
		} else if (timeout < 0) {
			slice = others ? 10 : INFINITE;
		} else {
			i64 left = deadline - (i64)GetTickCount64();
			if (left < 0)
				left = 0;
			slice = others && left > 10 ? 10 : (DWORD)left;
		}
		if (ns) {
			for (int k = 0; k < ns; k++) {
				pi->Handles[k].Handle = (HANDLE)ds[map[k]]->s;
				pi->Handles[k].Events = afd_events(fds[map[k]].events);
				pi->Handles[k].Status = 0;
			}
			i64 r = afd_poll(pi, ns, slice);
			if (r < 0) {
				ready = r;
				break;
			}
			/* the result lists only the signalled handles */
			for (ULONG k = 0; k < pi->NumberOfHandles; k++) {
				for (int j = 0; j < ns; j++) {
					if ((HANDLE)ds[map[j]]->s != pi->Handles[k].Handle)
						continue;
					short re = poll_events(pi->Handles[k].Events, fds[map[j]].events);
					if (re && !fds[map[j]].revents)
						ready++;
					fds[map[j]].revents |= re;
				}
			}
		} else if (slice) {
			if (ws_wait(NULL, 0, slice) == WS_WAIT_INTR) {
				ready = -L_EINTR;
				break;
			}
		}
		if (ready)
			break;
		if (timeout >= 0 && (i64)GetTickCount64() >= deadline)
			break;
	}
	for (u64 i = 0; i < n; i++)
		if (ds[i])
			ws_desc_put(ds[i]);
	ws_free(ds);
	ws_free(map);
	ws_free(pi);
	return ready;
}

struct l_timespec { i64 sec, nsec; };

static int ts_timeout(const struct l_timespec *ts)
{
	if (!ts)
		return -1;
	i64 ms = ts->sec * 1000 + (ts->nsec + 999999) / 1000000;
	return ms > 0x7fffffff ? 0x7fffffff : (int)ms;
}

/* select / pselect6 over poll: Linux fd_set is a 1024-bit little-endian map */
static i64 sys_select(int nfds, u64 *rd, u64 *wr, u64 *ex, int timeout)
{
	if (nfds < 0 || nfds > 1024)
		return -L_EINVAL;
	struct l_pollfd *p = ws_alloc(sizeof *p * (size_t)(nfds ? nfds : 1));
	if (!p)
		return -L_ENOMEM;
	int n = 0;
	for (int fd = 0; fd < nfds; fd++) {
		u64 bit = 1ULL << (fd & 63);
		short ev = 0;
		if (rd && (rd[fd >> 6] & bit))
			ev |= L_POLLIN;
		if (wr && (wr[fd >> 6] & bit))
			ev |= L_POLLOUT;
		if (ex && (ex[fd >> 6] & bit))
			ev |= L_POLLPRI;
		if (ev) {
			p[n].fd = fd;
			p[n].events = ev;
			n++;
		}
	}
	i64 r = sys_poll(p, (u64)n, timeout);
	if (r >= 0) {
		int words = (nfds + 63) / 64;
		for (int k = 0; k < words; k++) {
			if (rd)
				rd[k] = 0;
			if (wr)
				wr[k] = 0;
			if (ex)
				ex[k] = 0;
		}
		r = 0;
		for (int k = 0; k < n; k++) {
			u64 bit = 1ULL << (p[k].fd & 63);
			short re = p[k].revents;
			if (re & L_POLLNVAL) {
				ws_free(p);
				return -L_EBADF;
			}
			if (rd && (p[k].events & L_POLLIN) && (re & (L_POLLIN | L_POLLHUP | L_POLLERR))) {
				rd[p[k].fd >> 6] |= bit;
				r++;
			}
			if (wr && (p[k].events & L_POLLOUT) && (re & (L_POLLOUT | L_POLLERR))) {
				wr[p[k].fd >> 6] |= bit;
				r++;
			}
			if (ex && (p[k].events & L_POLLPRI) && (re & L_POLLPRI)) {
				ex[p[k].fd >> 6] |= bit;
				r++;
			}
		}
	}
	ws_free(p);
	return r;
}

i64 ws_sys_net(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	*handled = 1;
	struct l_timeval *tv;
	switch (n) {
	case 41: return sys_socket((int)a1, (int)a2, (int)a3);
	case 42: return sys_connect((int)a1, (const void *)a2, (int)a3);
	case 43: return sys_accept((int)a1, (void *)a2, (int *)a3, 0);
	case 288: return sys_accept((int)a1, (void *)a2, (int *)a3, (int)a4);
	case 44: return sys_sendto((int)a1, (const void *)a2, (size_t)a3, (int)a4, (const void *)a5, (int)a6);
	case 45: return sys_recvfrom((int)a1, (void *)a2, (size_t)a3, (int)a4, (void *)a5, (int *)a6);
	case 46: return sys_msg((int)a1, (struct l_msghdr *)a2, (int)a3, 1);
	case 47: return sys_msg((int)a1, (struct l_msghdr *)a2, (int)a3, 0);
	case 48: return sys_shutdown((int)a1, (int)a2);
	case 49: return sys_bind((int)a1, (const void *)a2, (int)a3);
	case 50: return sys_listen((int)a1, (int)a2);
	case 51: return sys_name((int)a1, (void *)a2, (int *)a3, 0);
	case 52: return sys_name((int)a1, (void *)a2, (int *)a3, 1);
	case 53: return sys_socketpair((int)a1, (int)a2, (int)a3, (int *)a4);
	case 54: return sys_setsockopt((int)a1, (int)a2, (int)a3, (const void *)a4, (int)a5);
	case 55: return sys_getsockopt((int)a1, (int)a2, (int)a3, (void *)a4, (int *)a5);
	case 7: return sys_poll((struct l_pollfd *)a1, (u64)a2, (int)a3);
	case 271: return sys_poll((struct l_pollfd *)a1, (u64)a2, ts_timeout((const struct l_timespec *)a3));
	case 23:
		tv = (struct l_timeval *)a5;
		return sys_select((int)a1, (u64 *)a2, (u64 *)a3, (u64 *)a4,
				  tv ? (int)(tv->sec * 1000 + (tv->usec + 999) / 1000) : -1);
	case 270:
		return sys_select((int)a1, (u64 *)a2, (u64 *)a3, (u64 *)a4, ts_timeout((const struct l_timespec *)a5));
	default:
		*handled = 0;
		return 0;
	}
}

/* fork child: the thread's overlapped event was not inherited */
void ws_net_fork_child(void)
{
	io_ev = NULL;
}

/* ---------------------------------------------------------------- last close
 * A forked process cannot closesocket, and the last handle of an AFD
 * endpoint closed without it is an ABORTIVE close: a reset, which throws
 * away whatever the peer has not read yet (a dial helper's result, written
 * just before it exits, was lost: "helper exited without a result"). Linux
 * delivers the data and then EOF. So when ours is the endpoint's only
 * handle left, the send side is shut down gracefully first (AFD partial
 * disconnect, as shutdown(SD_SEND) does), then the handle closed. */
#define IOCTL_AFD_PARTIAL_DISCONNECT 0x0001202B
typedef struct {
	ULONG flags;                /* 1 = send */
	ULONG reserved;
	LARGE_INTEGER timeout;
} afd_disconnect_info;
typedef struct {
	ULONG attributes, access, handles, pointers, paged, nonpaged, reserved[3], name_len, type_len, sd_len;
	LARGE_INTEGER created;
} obj_basic_info;
typedef LONG(NTAPI *ntqueryobject_fn)(HANDLE, int, void *, ULONG, ULONG *);

static ULONG handle_count(HANDLE h)
{
	static ntqueryobject_fn q;
	if (!q)
		q = (ntqueryobject_fn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
	obj_basic_info bi;
	__ws_memset(&bi, 0, sizeof bi);
	if (!q || q(h, 0 /* ObjectBasicInformation */, &bi, sizeof bi, NULL) < 0)
		return 0;
	return bi.handles;
}

void ws_sock_close_last(SOCKET s)
{
	HANDLE h = (HANDLE)s;
	if (handle_count(h) == 1) {
		afd_disconnect_info di;
		__ws_memset(&di, 0, sizeof di);
		di.flags = 1;
		di.timeout.QuadPart = -1;
		OVERLAPPED ov;
		__ws_memset(&ov, 0, sizeof ov);
		ov.hEvent = thread_event();
		BOOL ok = DeviceIoControl(h, IOCTL_AFD_PARTIAL_DISCONNECT, &di, sizeof di, NULL, 0, NULL, &ov);
		io_finish(h, &ov, ok, 2000);
	}
	CloseHandle(h);
}
