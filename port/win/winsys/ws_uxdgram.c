/* ws_uxdgram.c -- AF_UNIX SOCK_DGRAM sockets, on mailslots.
 *
 * Windows' AF_UNIX is stream-only. A datagram socket is emulated here as a
 * mailslot, a message-preserving one-way queue between any processes:
 * - bind() creates the mailslot. Its name is a hash of the socket's address:
 *   the absolute path, case-folded (NTFS is case-insensitive), or the bytes
 *   of an abstract name. A path socket also creates its file, empty, as
 *   Linux makes the socket's inode: bind fails with EADDRINUSE while it
 *   exists, and it outlives the socket until unlinked.
 * - sendto() (and write/send on a connected socket) opens the destination's
 *   mailslot and writes one message. No mailslot: ECONNREFUSED, or ENOENT
 *   when a path socket's file is missing, as on Linux.
 * - recv() reads one message, honouring O_NONBLOCK, MSG_DONTWAIT,
 *   SO_RCVTIMEO (EAGAIN) and signals (EINTR). A message longer than the
 *   buffer is truncated and the rest dropped, as on Linux.
 * The descriptor is FT_UXDGRAM, with the mailslot in d->h (so close and fork
 * need nothing special), the bound address in d->mem and the connected one
 * in d->peer. A sender's address is not carried: recvfrom reports an
 * unnamed AF_UNIX peer, as Linux does for an unbound sender.
 */
#include "winsys.h"

#define L_AF_UNIX 1
#define L_SOCK_DGRAM 2
#define L_SOCK_NONBLOCK 04000
#define L_SOCK_CLOEXEC 02000000
#define L_O_NONBLOCK 04000
#define L_MSG_PEEK 2
#define L_MSG_TRUNC 0x20
#define L_MSG_DONTWAIT 0x40
#define L_POLLIN 0x1
#define L_POLLOUT 0x4
#define L_POLLRDNORM 0x40
#define L_POLLWRNORM 0x100
#define UX_PATH_MAX 108

static u64 fnv(const void *p, size_t n, u64 h)
{
	const unsigned char *b = p;
	for (size_t i = 0; i < n; i++)
		h = (h ^ b[i]) * 0x100000001b3ULL;
	return h;
}

/* The mailslot name for a Linux sockaddr_un. For a path socket, *wpath is
 * its Windows path (the caller frees it). */
static i64 slot_name(const void *addr, int len, wchar_t name[64], wchar_t **wpath)
{
	*wpath = NULL;
	if (!addr || len < 3 || len > 2 + UX_PATH_MAX || *(const unsigned short *)addr != L_AF_UNIX)
		return -L_EINVAL;
	const char *p = (const char *)addr + 2;
	int n = len - 2;
	u64 h = 0xcbf29ce484222325ULL;
	wchar_t kind;
	if (p[0] == 0) {                       /* abstract: the bytes after the NUL, all of them */
		kind = L'a';
		h = fnv(p + 1, (size_t)(n - 1), h);
	} else {
		char path[UX_PATH_MAX + 1];
		int k = 0;
		while (k < n && p[k]) {
			path[k] = p[k];
			k++;
		}
		path[k] = 0;
		i64 err = 0;
		wchar_t *w = ws_path(-100, path, &err);   /* AT_FDCWD */
		if (!w)
			return err ? err : -L_ENOENT;
		kind = L'u';
		for (wchar_t *c = w; *c; c++) {
			wchar_t f = (*c >= L'A' && *c <= L'Z') ? (wchar_t)(*c + 32) : *c;
			h = fnv(&f, sizeof f, h);
		}
		*wpath = w;
	}
	static const wchar_t pre[] = L"\\\\.\\mailslot\\bmc_uxd\\";
	int i = 0;
	for (; pre[i]; i++)
		name[i] = pre[i];
	name[i++] = kind;
	name[i++] = L'_';
	for (int s = 60; s >= 0; s -= 4)
		name[i++] = L"0123456789abcdef"[(h >> s) & 15];
	name[i] = 0;
	return 0;
}

static int bound(ws_desc *d) { return d->h && d->h != INVALID_HANDLE_VALUE; }

static i64 uxd_socket(int type)
{
	ws_desc *d = ws_desc_new(FT_UXDGRAM);
	if (!d)
		return -L_ENOMEM;
	d->flags = 2 | ((type & L_SOCK_NONBLOCK) ? L_O_NONBLOCK : 0);   /* O_RDWR */
	return ws_fd_install(d, (type & L_SOCK_CLOEXEC) != 0, 0);
}

static i64 uxd_bind(ws_desc *d, const void *addr, int len)
{
	if (bound(d))
		return -L_EINVAL;
	wchar_t name[64], *wp;
	i64 r = slot_name(addr, len, name, &wp);
	if (r)
		return r;
	if (wp) {
		HANDLE f = CreateFileW(wp, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
				       CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if (f == INVALID_HANDLE_VALUE) {
			DWORD e = GetLastError();
			ws_free(wp);
			return (e == ERROR_FILE_EXISTS || e == ERROR_ALREADY_EXISTS) ? -L_EADDRINUSE : ws_err(e);
		}
		CloseHandle(f);
	}
	HANDLE m = CreateMailslotW(name, 0, 0, NULL);
	if (m == INVALID_HANDLE_VALUE) {
		DWORD e = GetLastError();
		if (wp)
			DeleteFileW(wp);
		ws_free(wp);
		return e == ERROR_ALREADY_EXISTS ? -L_EADDRINUSE : ws_err(e);
	}
	ws_free(wp);
	d->h = m;
	d->mem = ws_alloc((size_t)len);
	if (d->mem) {
		__ws_memcpy(d->mem, addr, (size_t)len);
		d->memlen = (u64)len;
	}
	return 0;
}

static i64 uxd_connect(ws_desc *d, const void *addr, int len)
{
	if (len < 2 || !addr)
		return -L_EINVAL;
	if (*(const unsigned short *)addr == 0) {   /* AF_UNSPEC: dissolve the association */
		d->peerlen = 0;
		return 0;
	}
	wchar_t name[64], *wp;
	i64 r = slot_name(addr, len, name, &wp);
	ws_free(wp);
	if (r)
		return r;
	if (len > (int)sizeof d->peer)
		return -L_EINVAL;
	__ws_memcpy(&d->peer, addr, (size_t)len);
	d->peerlen = len;
	return 0;
}

static i64 uxd_sendto(ws_desc *d, const void *buf, size_t n, const void *addr, int alen)
{
	if (!addr || !alen) {
		if (!d->peerlen)
			return -L_ENOTCONN;
		addr = &d->peer;
		alen = d->peerlen;
	} else if (d->peerlen) {
		return -L_EISCONN;
	}
	if (n > 0xffff)
		return -L_EMSGSIZE;
	wchar_t name[64], *wp;
	i64 r = slot_name(addr, alen, name, &wp);
	if (r)
		return r;
	HANDLE h = CreateFileW(name, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		r = (wp && GetFileAttributesW(wp) == INVALID_FILE_ATTRIBUTES) ? -L_ENOENT : -L_ECONNREFUSED;
		ws_free(wp);
		return r;
	}
	ws_free(wp);
	DWORD w = 0;
	BOOL ok = WriteFile(h, buf, (DWORD)n, &w, NULL);
	DWORD e = GetLastError();
	CloseHandle(h);
	return ok ? (i64)w : ws_err(e);
}

static i64 uxd_recv(ws_desc *d, void *buf, size_t n, int flags, void *addr, int *alen)
{
	if (flags & L_MSG_PEEK)
		return -L_EOPNOTSUPP;
	int nb = (flags & L_MSG_DONTWAIT) || (d->flags & L_O_NONBLOCK);
	u64 t0 = GetTickCount64();
	for (;;) {
		DWORD next = MAILSLOT_NO_MESSAGE;
		if (bound(d) && !GetMailslotInfo(d->h, NULL, &next, NULL, NULL))
			return ws_err(GetLastError());
		if (next != MAILSLOT_NO_MESSAGE) {
			char *tmp = buf, *big = NULL;
			if (next > n) {
				big = ws_alloc(next ? next : 1);
				if (!big)
					return -L_ENOMEM;
				tmp = big;
			}
			DWORD got = 0;
			if (!ReadFile(d->h, tmp, next, &got, NULL)) {
				DWORD e = GetLastError();
				ws_free(big);
				if (e == ERROR_SEM_TIMEOUT)   /* another reader took it: wait for the next */
					continue;
				return ws_err(e);
			}
			if (big) {
				__ws_memcpy(buf, big, n);
				ws_free(big);
			}
			if (addr && alen) {
				if (*alen >= 2)
					*(unsigned short *)addr = L_AF_UNIX;
				*alen = 2;
			}
			return (flags & L_MSG_TRUNC) ? (i64)got : (i64)(got < n ? got : n);
		}
		if (nb)
			return -L_EAGAIN;
		if (ws_sig_pending_here())
			return -L_EINTR;
		if (d->rcvtimeo && GetTickCount64() - t0 >= d->rcvtimeo)
			return -L_EAGAIN;
		Sleep(1);
	}
}

/* read()/write() on the descriptor */
i64 ws_uxd_rw(ws_desc *d, void *buf, size_t n, int write)
{
	return write ? uxd_sendto(d, buf, n, NULL, 0) : uxd_recv(d, buf, n, 0, NULL, NULL);
}

/* poll(): readable with a message waiting; always writable */
short ws_uxd_ready(ws_desc *d, short ev)
{
	short r = ev & (L_POLLOUT | L_POLLWRNORM);
	DWORD next = MAILSLOT_NO_MESSAGE;
	if (bound(d) && GetMailslotInfo(d->h, NULL, &next, NULL, NULL) && next != MAILSLOT_NO_MESSAGE)
		r |= ev & (L_POLLIN | L_POLLRDNORM);
	return r;
}

struct l_iovec_u { void *base; u64 len; };
struct l_msghdr_u {
	void *name;
	int namelen, pad0;
	struct l_iovec_u *iov;
	u64 iovlen;
	void *control;
	u64 controllen;
	int flags;
};

static i64 uxd_msg(ws_desc *d, struct l_msghdr_u *m, int flags, int out)
{
	u64 total = 0;
	for (u64 i = 0; i < m->iovlen; i++)
		total += m->iov[i].len;
	if (total > 0xffff)
		total = 0xffff;
	char *b = ws_alloc(total ? total : 1);
	if (!b)
		return -L_ENOMEM;
	i64 r;
	if (out) {
		u64 o = 0;
		for (u64 i = 0; i < m->iovlen && o < total; i++) {
			u64 k = m->iov[i].len < total - o ? m->iov[i].len : total - o;
			__ws_memcpy(b + o, m->iov[i].base, k);
			o += k;
		}
		r = uxd_sendto(d, b, total, m->name, m->namelen);
	} else {
		r = uxd_recv(d, b, total, flags, m->name, m->name ? &m->namelen : NULL);
		u64 o = 0;
		for (u64 i = 0; r > 0 && i < m->iovlen && o < (u64)r; i++) {
			u64 k = m->iov[i].len < (u64)r - o ? m->iov[i].len : (u64)r - o;
			__ws_memcpy(m->iov[i].base, b + o, k);
			o += k;
		}
		m->controllen = 0;
		m->flags = 0;
	}
	ws_free(b);
	return r;
}

static i64 name_out(const void *a, int al, void *addr, int *alen)
{
	static const unsigned short unnamed = L_AF_UNIX;
	if (!a || !al) {
		a = &unnamed;
		al = 2;
	}
	int k = al < *alen ? al : *alen;
	if (k > 0)
		__ws_memcpy(addr, a, (size_t)k);
	*alen = al;
	return 0;
}

/* The network syscalls, for an AF_UNIX datagram socket. *handled is set
 * when the call was one (socket() of that kind, or a call on such an fd). */
i64 ws_uxd_sys(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	*handled = 0;
	if (n == 41) {
		if (a1 != L_AF_UNIX || (a2 & 0xf) != L_SOCK_DGRAM)
			return 0;
		*handled = 1;
		return uxd_socket((int)a2);
	}
	switch (n) {
	case 42: case 43: case 44: case 45: case 46: case 47: case 48: case 49: case 50:
	case 51: case 52: case 54: case 55: case 288:
		break;
	default:
		return 0;
	}
	ws_desc *d = ws_fd_get((int)a1);
	if (!d)
		return 0;
	if (d->type != FT_UXDGRAM) {
		ws_desc_put(d);
		return 0;
	}
	*handled = 1;
	i64 r;
	switch (n) {
	case 42: r = uxd_connect(d, (const void *)a2, (int)a3); break;
	case 43: case 288: case 50: r = -L_EOPNOTSUPP; break;   /* accept, listen */
	case 44: r = uxd_sendto(d, (const void *)a2, (size_t)a3, (const void *)a5, (int)a6); break;
	case 45: r = uxd_recv(d, (void *)a2, (size_t)a3, (int)a4, (void *)a5, (int *)a6); break;
	case 46: r = uxd_msg(d, (struct l_msghdr_u *)a2, (int)a3, 1); break;
	case 47: r = uxd_msg(d, (struct l_msghdr_u *)a2, (int)a3, 0); break;
	case 48: r = (a2 < 0 || a2 > 2) ? -L_EINVAL : 0; break;  /* shutdown: nothing to flush */
	case 49: r = uxd_bind(d, (const void *)a2, (int)a3); break;
	case 51: r = name_out(d->mem, (int)d->memlen, (void *)a2, (int *)a3); break;
	case 52: r = d->peerlen ? name_out(&d->peer, d->peerlen, (void *)a2, (int *)a3) : -L_ENOTCONN; break;
	case 54:                                   /* setsockopt */
		if (a2 == 1 && (a3 == 20 || a3 == 21)) {   /* SO_RCVTIMEO / SO_SNDTIMEO */
			const i64 *tv = (const void *)a4;
			if ((int)a5 < 16) {
				r = -L_EINVAL;
				break;
			}
			i64 ms = tv[0] * 1000 + tv[1] / 1000;
			if (!ms && tv[1])
				ms = 1;
			DWORD v = ms > 0x7ffffffe ? 0x7ffffffe : ms < 0 ? 0 : (DWORD)ms;
			if (a3 == 20)
				d->rcvtimeo = v;
			else
				d->sndtimeo = v;
		}
		r = 0;                                 /* the rest have no effect here */
		break;
	case 55: {                                 /* getsockopt: SO_TYPE, SO_ERROR, SO_DOMAIN */
		int *len = (int *)a5, iv;
		if (a2 == 1 && a3 == 3)
			iv = L_SOCK_DGRAM;
		else if (a2 == 1 && a3 == 4)
			iv = 0;
		else if (a2 == 1 && a3 == 39)
			iv = L_AF_UNIX;
		else {
			r = -L_ENOPROTOOPT;
			break;
		}
		if (*len < 4) {
			r = -L_EINVAL;
			break;
		}
		*(int *)a4 = iv;
		*len = 4;
		r = 0;
		break;
	}
	default: r = -L_ENOSYS; break;
	}
	ws_desc_put(d);
	return r;
}
