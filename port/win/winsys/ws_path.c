/* ws_path.c -- Linux path -> Windows path (bmc_win).
 *
 *   /dev/null          -> NUL
 *   /tmp, /tmp/...     -> %TEMP% (GetTempPathW) + rest
 *   /c/x               -> C:\x  (the form getcwd returns; MSYS spelling)
 *   /x/y               -> \x\y on the current drive
 *   C:/x, rel/x        -> unchanged apart from '/' -> '\'
 *   rel with a dirfd   -> <the dirfd's path>\rel
 *
 * Symbolic links are WSL's (reparse tag IO_REPARSE_TAG_LX_SYMLINK, the
 * target stored verbatim): an unprivileged user may create them, unlike
 * NTFS symlinks (those need Developer Mode or admin), and WSL and Cygwin
 * read them as symlinks. Windows itself refuses to open one
 * (ERROR_CANT_ACCESS_FILE), so nothing reads through one by accident.
 * ws_path follows a link at the LAST component (to 40 hops, then ELOOP);
 * ws_path_nf does not. A link in the middle of a path is not followed.
 */
#include "winsys.h"

#define L_AT_FDCWD (-100)

static wchar_t *wcat3(const wchar_t *a, const wchar_t *sep, const wchar_t *b)
{
	size_t la = ws_wcslen(a), ls = ws_wcslen(sep), lb = ws_wcslen(b);
	wchar_t *r = ws_alloc((la + ls + lb + 1) * sizeof(wchar_t));
	if (!r)
		return NULL;
	__ws_memcpy(r, a, la * sizeof(wchar_t));
	__ws_memcpy(r + la, sep, ls * sizeof(wchar_t));
	__ws_memcpy(r + la + ls, b, lb * sizeof(wchar_t));
	r[la + ls + lb] = 0;
	return r;
}

static int starts(const char *s, const char *p)
{
	while (*p)
		if (*s++ != *p++)
			return 0;
	return 1;
}

wchar_t *ws_path_nf(int dirfd, const char *path, i64 *err)
{
	*err = 0;
	if (!path) {
		*err = -L_EFAULT;
		return NULL;
	}
	if (!*path) {
		*err = -L_ENOENT;
		return NULL;
	}
	if (ws_strlen(path) >= 32000) {
		*err = -L_ENAMETOOLONG;
		return NULL;
	}
	wchar_t *w;
	wchar_t shp[MAX_PATH];
	DWORD shl;
	if (starts(path, "/dev/null") && (path[9] == 0)) {
		w = ws_utf8_to_w("NUL");
	} else if ((starts(path, "/bin/") || starts(path, "/usr/bin/")) &&
		   (shl = GetEnvironmentVariableW(L"BMC_WIN_SH", shp, MAX_PATH)) && shl < MAX_PATH) {
		/* with a POSIX tool set configured (BMC_WIN_SH = <root>\bin\sh.exe,
		 * Git for Windows' layout), /bin and /usr/bin are <root>\usr\bin */
		int up = 0;
		for (DWORD i = shl; i-- > 0 && up < 2;)
			if (shp[i] == L'\\' || shp[i] == L'/') {
				shp[i] = 0;
				up++;
			}
		wchar_t *rest = ws_utf8_to_w(path + (path[1] == 'b' ? 5 : 9));
		w = rest && up == 2 ? wcat3(shp, L"\\usr\\bin\\", rest) : NULL;
		ws_free(rest);
		if (w)
			for (wchar_t *q = w; *q; q++)
				if (*q == L'/')
					*q = L'\\';
	} else if (starts(path, "/tmp") && (path[4] == 0 || path[4] == '/')) {
		wchar_t tmp[MAX_PATH + 1];
		DWORD n = GetTempPathW(MAX_PATH + 1, tmp);
		if (n && (tmp[n - 1] == L'\\' || tmp[n - 1] == L'/'))
			tmp[n - 1] = 0;
		wchar_t *rest = ws_utf8_to_w(path + 4);
		w = rest ? wcat3(tmp, L"", rest) : NULL;
		ws_free(rest);
	} else if (path[0] == '/' && ((path[1] >= 'a' && path[1] <= 'z') || (path[1] >= 'A' && path[1] <= 'Z')) &&
		   (path[2] == '/' || path[2] == 0)) {
		/* "/c/x" -> "C:\x": the drive form getcwd hands out (MSYS spelling) */
		char drive[4] = { (char)(path[1] & ~0x20), ':', '\\', 0 };
		wchar_t *d = ws_utf8_to_w(drive);
		wchar_t *rest = ws_utf8_to_w(path[2] ? path + 3 : "");
		w = (d && rest) ? wcat3(d, L"", rest) : NULL;
		ws_free(d);
		ws_free(rest);
	} else if (path[0] == '/' || (path[0] && path[1] == ':')) {
		w = ws_utf8_to_w(path);
	} else if (dirfd == L_AT_FDCWD) {
		/* relative to the cwd: made absolute here from the path the PEB
		 * holds, so nothing depends on the cwd *handle* (not inherited by
		 * a forked process) */
		wchar_t *rel = ws_utf8_to_w(path);
		w = NULL;
		if (rel) {
			for (wchar_t *q = rel; *q; q++)
				if (*q == L'/')
					*q = L'\\';
			DWORD n = GetFullPathNameW(rel, 0, NULL, NULL);
			if (n) {
				w = ws_alloc((size_t)(n + 1) * sizeof(wchar_t));
				if (w && !GetFullPathNameW(rel, n + 1, w, NULL)) {
					ws_free(w);
					w = NULL;
				}
			}
			ws_free(rel);
		}
	} else {
		ws_desc *d = ws_fd_get(dirfd);
		if (!d) {
			*err = -L_EBADF;
			return NULL;
		}
		if (d->type != FT_DIR || !d->wpath) {
			ws_desc_put(d);
			*err = -L_ENOTDIR;
			return NULL;
		}
		wchar_t *rest = ws_utf8_to_w(path);
		w = rest ? wcat3(d->wpath, L"\\", rest) : NULL;
		ws_free(rest);
		ws_desc_put(d);
	}
	if (!w) {
		*err = -L_ENOMEM;
		return NULL;
	}
	for (wchar_t *p = w; *p; p++)
		if (*p == L'/')
			*p = L'\\';
	return w;
}

/* ---- WSL symlinks ---- */
#define LX_TAG 0xA000001Du
#define FSCTL_SET_RP 0x000900A4u
#define FSCTL_GET_RP 0x000900A8u

/* the target of the link h is (opened with FILE_FLAG_OPEN_REPARSE_POINT):
 * its full length, at most cap bytes of it copied to buf; -EINVAL when h is
 * not a WSL symlink */
i64 ws_lx_readlink_h(HANDLE h, char *buf, size_t cap)
{
	FILE_ATTRIBUTE_TAG_INFO ti;
	if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ti, sizeof ti) ||
	    !(ti.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || ti.ReparseTag != LX_TAG)
		return -L_EINVAL;
	static const DWORD cap_rp = 16 * 1024;
	unsigned char *rp = ws_alloc(cap_rp);
	if (!rp)
		return -L_ENOMEM;
	DWORD n = 0;
	i64 r;
	if (!DeviceIoControl(h, FSCTL_GET_RP, NULL, 0, rp, cap_rp, &n, NULL)) {
		r = ws_err(GetLastError());
	} else {
		DWORD tag;
		unsigned short dl;
		__ws_memcpy(&tag, rp, 4);
		__ws_memcpy(&dl, rp + 4, 2);
		if (tag != LX_TAG || dl < 4 || (DWORD)dl + 8 > n) {
			r = -L_EINVAL;
		} else {
			size_t tl = (size_t)dl - 4;          /* after the 4-byte version */
			if (buf)
				__ws_memcpy(buf, rp + 12, tl < cap ? tl : cap);
			r = (i64)tl;
		}
	}
	ws_free(rp);
	return r;
}

i64 ws_lx_readlink(const wchar_t *w, char *buf, size_t cap)
{
	HANDLE h = CreateFileW(w, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			       NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return ws_err(GetLastError());
	i64 r = ws_lx_readlink_h(h, buf, cap);
	CloseHandle(h);
	return r;
}

/* a WSL symlink at w (which must not exist) holding target */
i64 ws_lx_symlink(const char *target, const wchar_t *w)
{
	size_t tl = ws_strlen(target);
	if (!tl)
		return -L_ENOENT;
	if (tl > 4000)
		return -L_ENAMETOOLONG;
	HANDLE h = CreateFileW(w, GENERIC_WRITE | DELETE, 0, NULL, CREATE_NEW,
			       FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		DWORD e = GetLastError();
		return e == ERROR_FILE_EXISTS || e == ERROR_ALREADY_EXISTS ? -L_EEXIST : ws_err(e);
	}
	size_t len = 12 + tl;
	unsigned char *rp = ws_alloc(len);
	if (!rp) {
		CloseHandle(h);
		return -L_ENOMEM;
	}
	DWORD tag = LX_TAG, ver = 2;
	unsigned short dl = (unsigned short)(4 + tl), z = 0;
	__ws_memcpy(rp, &tag, 4);
	__ws_memcpy(rp + 4, &dl, 2);
	__ws_memcpy(rp + 6, &z, 2);
	__ws_memcpy(rp + 8, &ver, 4);
	__ws_memcpy(rp + 12, target, tl);
	DWORD n = 0;
	i64 r = 0;
	if (!DeviceIoControl(h, FSCTL_SET_RP, rp, (DWORD)len, NULL, 0, &n, NULL)) {
		r = ws_err(GetLastError());
		FILE_DISPOSITION_INFO di = { TRUE };
		SetFileInformationByHandle(h, FileDispositionInfo, &di, sizeof di);
	}
	ws_free(rp);
	CloseHandle(h);
	return r;
}

/* the path with a symlink at its last component followed */
wchar_t *ws_path(int dirfd, const char *path, i64 *err)
{
	wchar_t *w = ws_path_nf(dirfd, path, err);
	for (int hops = 0; w; hops++) {
		DWORD a = GetFileAttributesW(w);
		if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_REPARSE_POINT))
			return w;
		char t[4097];
		i64 n = ws_lx_readlink(w, t, sizeof t - 1);
		if (n < 0)
			return w;                          /* a junction or the like: Windows' to follow */
		if (n > (i64)sizeof t - 1 || hops == 40) {
			ws_free(w);
			*err = n > (i64)sizeof t - 1 ? -L_ENAMETOOLONG : -L_ELOOP;
			return NULL;
		}
		t[n] = 0;
		wchar_t *nw;
		if (t[0] == '/' || (t[0] && t[1] == ':')) {
			nw = ws_path_nf(L_AT_FDCWD, t, err);
		} else {                                   /* relative to the link's directory */
			size_t l = ws_wcslen(w);
			while (l && w[l - 1] != L'\\')
				l--;
			if (l)
				w[l - 1] = 0;
			wchar_t *rest = ws_utf8_to_w(t);
			nw = rest ? wcat3(w, L"\\", rest) : NULL;
			ws_free(rest);
			if (!nw)
				*err = -L_ENOMEM;
			for (wchar_t *q = nw; q && *q; q++)
				if (*q == L'/')
					*q = L'\\';
		}
		ws_free(w);
		w = nw;
	}
	return NULL;
}
