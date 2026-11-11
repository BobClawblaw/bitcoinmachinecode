/* ws_path.c -- Linux path -> Windows path (bmc_win).
 *
 *   /dev/null          -> NUL
 *   /tmp, /tmp/...     -> %TEMP% (GetTempPathW) + rest
 *   /c/x               -> C:\x  (the form getcwd returns; MSYS spelling)
 *   /x/y               -> \x\y on the current drive
 *   C:/x, rel/x        -> unchanged apart from '/' -> '\'
 *   rel with a dirfd   -> <the dirfd's path>\rel
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

wchar_t *ws_path(int dirfd, const char *path, i64 *err)
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
	if (starts(path, "/dev/null") && (path[9] == 0)) {
		w = ws_utf8_to_w("NUL");
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
