/* ws_util.c -- freestanding helpers for winsys (no C runtime is linked). */
#include "winsys.h"

void *__ws_memcpy(void *d, const void *s, size_t n)
{
	unsigned char *dp = d;
	const unsigned char *sp = s;
	while (n--)
		*dp++ = *sp++;
	return d;
}

void *__ws_memset(void *d, int c, size_t n)
{
	unsigned char *dp = d;
	while (n--)
		*dp++ = (unsigned char)c;
	return d;
}

void *__ws_memmove(void *d, const void *s, size_t n)
{
	unsigned char *dp = d;
	const unsigned char *sp = s;
	if (dp < sp) {
		while (n--)
			*dp++ = *sp++;
	} else {
		while (n--)
			dp[n] = sp[n];
	}
	return d;
}

int __ws_memcmp(const void *a, const void *b, size_t n)
{
	const unsigned char *x = a, *y = b;
	for (; n; n--, x++, y++)
		if (*x != *y)
			return *x - *y;
	return 0;
}

size_t ws_strlen(const char *s)
{
	size_t n = 0;
	while (s[n])
		n++;
	return n;
}

size_t ws_wcslen(const wchar_t *s)
{
	size_t n = 0;
	while (s[n])
		n++;
	return n;
}

void *ws_alloc(size_t n)
{
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n ? n : 1);
}

void ws_free(void *p)
{
	if (p)
		HeapFree(GetProcessHeap(), 0, p);
}

wchar_t *ws_utf8_to_w(const char *s)
{
	int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
	if (n <= 0)
		return NULL;
	wchar_t *w = ws_alloc((size_t)n * sizeof(wchar_t));
	if (w)
		MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
	return w;
}

char *ws_w_to_utf8(const wchar_t *w)
{
	int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
	if (n <= 0)
		return NULL;
	char *s = ws_alloc((size_t)n);
	if (s)
		WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
	return s;
}

i64 ws_err(DWORD e)
{
	switch (e) {
	case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: case ERROR_INVALID_DRIVE:
	case ERROR_BAD_NETPATH: case ERROR_BAD_PATHNAME: case ERROR_DIRECTORY:
		return -L_ENOENT;
	case ERROR_ACCESS_DENIED: case ERROR_SHARING_VIOLATION: case ERROR_LOCK_VIOLATION:
	case ERROR_PRIVILEGE_NOT_HELD: case ERROR_CANNOT_MAKE:
		return -L_EACCES;
	case ERROR_DELETE_PENDING:
		return -L_ENOENT;
	case ERROR_FILE_EXISTS: case ERROR_ALREADY_EXISTS:
		return -L_EEXIST;
	case ERROR_INVALID_HANDLE:
		return -L_EBADF;
	case ERROR_NOT_ENOUGH_MEMORY: case ERROR_OUTOFMEMORY: case ERROR_COMMITMENT_LIMIT:
		return -L_ENOMEM;
	case ERROR_DISK_FULL: case ERROR_HANDLE_DISK_FULL:
		return -L_ENOSPC;
	case ERROR_DIR_NOT_EMPTY:
		return -L_ENOTEMPTY;
	case ERROR_BROKEN_PIPE: case ERROR_NO_DATA: case ERROR_PIPE_NOT_CONNECTED:
		return -L_EPIPE;
	case ERROR_FILENAME_EXCED_RANGE:
		return -L_ENAMETOOLONG;
	case ERROR_NEGATIVE_SEEK: case ERROR_INVALID_PARAMETER: case ERROR_INVALID_NAME:
		return -L_EINVAL;
	case ERROR_NOT_SAME_DEVICE:
		return -L_EXDEV;
	case ERROR_WRITE_PROTECT:
		return -L_EROFS;
	case ERROR_TOO_MANY_OPEN_FILES:
		return -L_EMFILE;
	case ERROR_NOT_SUPPORTED: case ERROR_CALL_NOT_IMPLEMENTED:
		return -L_EOPNOTSUPP;
	case ERROR_IO_PENDING:
		return -L_EAGAIN;
	case ERROR_OPERATION_ABORTED:
		return -L_EINTR;
	default:
		return -L_EIO;
	}
}

i64 ws_wsaerr(int e)
{
	switch (e) {
	case WSAEWOULDBLOCK: return -L_EAGAIN;
	case WSAEINPROGRESS: return -L_EINPROGRESS;
	case WSAEALREADY: return -L_EALREADY;
	case WSAENOTSOCK: return -L_ENOTSOCK;
	case WSAEDESTADDRREQ: return -L_EDESTADDRREQ;
	case WSAEMSGSIZE: return -L_EMSGSIZE;
	case WSAEPROTOTYPE: return -L_EPROTOTYPE;
	case WSAENOPROTOOPT: return -L_ENOPROTOOPT;
	case WSAEPROTONOSUPPORT: return -L_EPROTONOSUPPORT;
	case WSAEOPNOTSUPP: return -L_EOPNOTSUPP;
	case WSAEAFNOSUPPORT: case WSAEPFNOSUPPORT: return -L_EAFNOSUPPORT;
	case WSAEADDRINUSE: return -L_EADDRINUSE;
	case WSAEADDRNOTAVAIL: return -L_EADDRNOTAVAIL;
	case WSAENETDOWN: return -L_ENETDOWN;
	case WSAENETUNREACH: return -L_ENETUNREACH;
	case WSAENETRESET: case WSAECONNRESET: return -L_ECONNRESET;
	case WSAECONNABORTED: return -L_ECONNABORTED;
	case WSAENOBUFS: return -L_ENOBUFS;
	case WSAEISCONN: return -L_EISCONN;
	case WSAENOTCONN: return -L_ENOTCONN;
	case WSAESHUTDOWN: return -L_EPIPE;
	case WSAETIMEDOUT: return -L_ETIMEDOUT;
	case WSAECONNREFUSED: return -L_ECONNREFUSED;
	case WSAEHOSTDOWN: return -L_EHOSTDOWN;
	case WSAEHOSTUNREACH: return -L_EHOSTUNREACH;
	case WSAEINTR: return -L_EINTR;
	case WSAEBADF: return -L_EBADF;
	case WSAEACCES: return -L_EACCES;
	case WSAEFAULT: return -L_EFAULT;
	case WSAEINVAL: return -L_EINVAL;
	case WSAEMFILE: return -L_EMFILE;
	default: return -L_EIO;
	}
}

/* to fd 2 when it is open (a forked process's PEB stderr handle is not
 * inherited), else the standard handle */
void ws_write_stderr(const char *s)
{
	DWORD w;
	HANDLE h = NULL;
	ws_desc *d = ws_fd_get(2);
	if (d) {
		if (d->type == FT_CONSOLE || d->type == FT_PIPE || d->type == FT_FILE)
			h = d->h;
		ws_desc_put(d);
	}
	if (!h)
		h = GetStdHandle(STD_ERROR_HANDLE);
	WriteFile(h, s, (DWORD)ws_strlen(s), &w, NULL);
}

void ws_fatal(const char *msg)
{
	ws_write_stderr("bmc_win fatal: ");
	ws_write_stderr(msg);
	ws_write_stderr("\n");
	ExitProcess(127);
}

void ws_fmt_u64(char *buf, u64 v)
{
	char t[24];
	int i = 0;
	do {
		t[i++] = (char)('0' + v % 10);
		v /= 10;
	} while (v);
	while (i)
		*buf++ = t[--i];
	*buf = 0;
}

/* clang emits a reference to _fltused for floating point on MSVC targets */
int _fltused = 0;

/* ---- stack protector (sspstrong frames on a Windows triple use the MSVC
 * names). The cookie is seeded at entry (ws_entry.c). ---- */
uintptr_t __security_cookie = 0x2B992DDFA232ULL;

void __security_check_cookie(uintptr_t c)
{
	if (c != __security_cookie)
		ws_fatal("stack smashing detected (security cookie)");
}
