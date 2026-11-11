/* ws_fd.c -- the Linux fd table and file syscalls on Win32 (bmc_win).
 *
 * fds index ws_desc "open file descriptions" (shared by dup, refcounted).
 * Files are opened FILE_SHARE_READ|WRITE|DELETE and unlink/rename use the
 * POSIX-semantics dispositions, so an open file can be unlinked or renamed
 * over the way the storage layer expects. File I/O is always positioned
 * (the description keeps the offset), so read/pread/write/pwrite mix the way
 * they do on Linux. flock/fcntl locks are advisory as on Linux: they lock a
 * shadow byte range far beyond any real data (Windows locks are mandatory
 * and would otherwise block other processes' reads of the locked bytes). */
#include "winsys.h"
#include <winioctl.h>

#define L_O_ACCMODE 3
#define L_O_WRONLY 1
#define L_O_RDWR 2
#define L_O_CREAT 0100
#define L_O_EXCL 0200
#define L_O_TRUNC 01000
#define L_O_APPEND 02000
#define L_O_NONBLOCK 04000
#define L_O_DIRECTORY 0200000
#define L_O_NOFOLLOW 0400000
#define L_O_CLOEXEC 02000000
#define L_O_PATH 010000000
#define L_O_TMPFILE_DIR 020000000
#define L_AT_FDCWD (-100)
#define L_AT_REMOVEDIR 0x200
#define L_AT_SYMLINK_NOFOLLOW 0x100
#define L_AT_EMPTY_PATH 0x1000

#define MAX_FD (1 << 20)

static int is_proc(const char *path)
{
	return path && !__ws_memcmp(path, "/proc/", 6);
}

typedef struct { ws_desc *d; int cloexec; } ws_slot;
static ws_slot *fdt;
static int fdt_cap;
static SRWLOCK fdt_lock = SRWLOCK_INIT;

ws_desc *ws_desc_new(int type)
{
	ws_desc *d = ws_alloc(sizeof *d);
	if (!d)
		return NULL;
	d->refs = 1;
	d->type = type;
	d->h = INVALID_HANDLE_VALUE;
	d->s = INVALID_SOCKET;
	InitializeSRWLock(&d->lock);
	return d;
}

void ws_desc_put(ws_desc *d)
{
	if (!d || InterlockedDecrement(&d->refs) != 0)
		return;
	if (d->type == FT_SOCKET && d->s != INVALID_SOCKET) {
		if (ws_is_root)
			closesocket(d->s);
		else
			CloseHandle((HANDLE)d->s);   /* no Winsock in a forked process */
	}
	if (d->h != INVALID_HANDLE_VALUE && d->h != NULL)
		CloseHandle(d->h);
	if (d->find && d->find != INVALID_HANDLE_VALUE)
		FindClose(d->find);
	ws_free(d->wpath);
	ws_free(d->mem);
	ws_free(d);
}

static int grow(int need)
{
	if (need < fdt_cap)
		return 0;
	if (need >= MAX_FD)
		return -L_EMFILE;
	int cap = fdt_cap ? fdt_cap : 256;
	while (cap <= need)
		cap *= 2;
	ws_slot *n = ws_alloc(sizeof(ws_slot) * (size_t)cap);
	if (!n)
		return -L_ENOMEM;
	if (fdt)
		__ws_memcpy(n, fdt, sizeof(ws_slot) * (size_t)fdt_cap);
	ws_free(fdt);
	fdt = n;
	fdt_cap = cap;
	return 0;
}

ws_desc *ws_fd_get(int fd)
{
	ws_desc *d = NULL;
	AcquireSRWLockShared(&fdt_lock);
	if (fd >= 0 && fd < fdt_cap && fdt[fd].d) {
		d = fdt[fd].d;
		InterlockedIncrement(&d->refs);
	}
	ReleaseSRWLockShared(&fdt_lock);
	return d;
}

volatile int ws_nofile_cur = MAX_FD;    /* RLIMIT_NOFILE's soft limit (ws_proc.c) */

int ws_fd_install(ws_desc *d, int cloexec, int min_fd)
{
	AcquireSRWLockExclusive(&fdt_lock);
	int fd = min_fd < 0 ? 0 : min_fd;
	for (;; fd++) {
		int r = fd >= ws_nofile_cur ? -L_EMFILE : grow(fd);
		if (r) {
			ReleaseSRWLockExclusive(&fdt_lock);
			ws_desc_put(d);
			return r;
		}
		if (!fdt[fd].d)
			break;
	}
	fdt[fd].d = d;
	fdt[fd].cloexec = cloexec;
	ReleaseSRWLockExclusive(&fdt_lock);
	return fd;
}

static int install_at(ws_desc *d, int fd, int cloexec)
{
	ws_desc *old = NULL;
	AcquireSRWLockExclusive(&fdt_lock);
	int r = fd >= ws_nofile_cur ? -L_EBADF : grow(fd);
	if (r) {
		ReleaseSRWLockExclusive(&fdt_lock);
		ws_desc_put(d);
		return r;
	}
	old = fdt[fd].d;
	fdt[fd].d = d;
	fdt[fd].cloexec = cloexec;
	ReleaseSRWLockExclusive(&fdt_lock);
	ws_desc_put(old);
	return fd;
}

static i64 fd_close(int fd)
{
	ws_desc *d = NULL;
	AcquireSRWLockExclusive(&fdt_lock);
	if (fd >= 0 && fd < fdt_cap) {
		d = fdt[fd].d;
		fdt[fd].d = NULL;
	}
	ReleaseSRWLockExclusive(&fdt_lock);
	if (!d)
		return -L_EBADF;
	ws_desc_put(d);
	return 0;
}

static ws_desc *std_desc(DWORD which)
{
	HANDLE h = GetStdHandle(which);
	if (h == NULL || h == INVALID_HANDLE_VALUE)
		return NULL;
	HANDLE dup;
	if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup, 0, FALSE,
			     DUPLICATE_SAME_ACCESS))
		return NULL;
	DWORD t = GetFileType(dup);
	DWORD mode;
	int type = FT_PIPE;   /* streams: never positioned */
	if (t == FILE_TYPE_CHAR)
		type = GetConsoleMode(dup, &mode) ? FT_CONSOLE : FT_PIPE;
	ws_desc *d = ws_desc_new(type);
	if (!d) {
		CloseHandle(dup);
		return NULL;
	}
	d->h = dup;
	d->flags = which == STD_INPUT_HANDLE ? 0 : L_O_WRONLY;
	return d;
}

void ws_fd_init(void)
{
	grow(3);
	DWORD std[3] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };
	for (int i = 0; i < 3; i++) {
		ws_desc *d = std_desc(std[i]);
		if (!d) {
			d = ws_desc_new(FT_NULL);
			if (!d)
				continue;
		}
		install_at(d, i, 0);
	}
}

/* ---- time conversion ---- */
static void ft_to_ts(FILETIME ft, i64 *sec, i64 *nsec)
{
	u64 t = ((u64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	if (t == 0) {
		*sec = 0;
		*nsec = 0;
		return;
	}
	i64 v = (i64)t - 116444736000000000LL;   /* 1601 -> 1970, 100 ns units */
	*sec = v / 10000000;
	*nsec = (v % 10000000) * 100;
	if (*nsec < 0) {
		*nsec += 1000000000;
		*sec -= 1;
	}
}

/* ---- Unix permission bits: an NTFS extended attribute "BMCMODE" (4 bytes,
 * the low 12 bits of st_mode), set at creation (mode & ~umask) and by
 * chmod; a file without it reads 0644 (directories 0755). WSL1 kept Linux
 * metadata in EAs the same way. On a filesystem without EAs the bits are
 * simply not kept. ---- */
typedef struct { ULONG next; UCHAR flags; UCHAR namelen; USHORT valuelen; char name[8]; uint32_t value; } mode_ea;
typedef struct { ULONG next; UCHAR namelen; char name[8]; } mode_ea_get;
typedef struct { union { LONG status; PVOID p; } u; ULONG_PTR info; } ws_iosb;
typedef LONG (NTAPI *nt_set_ea_fn)(HANDLE, ws_iosb *, PVOID, ULONG);
typedef LONG (NTAPI *nt_query_ea_fn)(HANDLE, ws_iosb *, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN);
static nt_set_ea_fn nt_set_ea;
static nt_query_ea_fn nt_query_ea;
static volatile LONG umask_bits = 022;

static void ea_init(void)
{
	if (nt_set_ea)
		return;
	HMODULE nt = GetModuleHandleW(L"ntdll.dll");
	nt_query_ea = (nt_query_ea_fn)(void *)GetProcAddress(nt, "NtQueryEaFile");
	nt_set_ea = (nt_set_ea_fn)(void *)GetProcAddress(nt, "NtSetEaFile");
}

static int mode_set_handle(HANDLE h, unsigned mode)
{
	ea_init();
	if (!nt_set_ea)
		return -1;
	mode_ea e;
	__ws_memset(&e, 0, sizeof e);
	e.namelen = 7;
	e.valuelen = 4;
	__ws_memcpy(e.name, "BMCMODE", 8);
	e.value = mode & 07777;
	ws_iosb io;
	return nt_set_ea(h, &io, &e, sizeof e) >= 0 ? 0 : -1;
}

/* -1 when the file carries no mode */
static int mode_get_handle(HANDLE h)
{
	ea_init();
	if (!nt_query_ea)
		return -1;
	mode_ea_get q;
	__ws_memset(&q, 0, sizeof q);
	q.namelen = 7;
	__ws_memcpy(q.name, "BMCMODE", 8);
	mode_ea out;
	__ws_memset(&out, 0, sizeof out);
	ws_iosb io;
	LONG st = nt_query_ea(h, &io, &out, sizeof out, TRUE, &q, sizeof q, NULL, TRUE);
	if (st < 0 || out.valuelen != 4)
		return -1;
	return (int)(out.value & 07777);
}

static int mode_set_path(const wchar_t *w, unsigned mode)
{
	HANDLE h = CreateFileW(w, FILE_WRITE_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			       NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return -1;
	int r = mode_set_handle(h, mode);
	CloseHandle(h);
	return r;
}

/* Linux x86_64 struct stat (kernel layout, what musl's kstat expects) */
struct l_stat {
	u64 st_dev, st_ino, st_nlink;
	uint32_t st_mode, st_uid, st_gid, pad0;
	u64 st_rdev;
	i64 st_size, st_blksize, st_blocks;
	i64 st_atime_sec, st_atime_nsec, st_mtime_sec, st_mtime_nsec, st_ctime_sec, st_ctime_nsec;
	i64 unused[3];
};

static i64 stat_handle(HANDLE h, int type, struct l_stat *st)
{
	__ws_memset(st, 0, sizeof *st);
	st->st_blksize = 4096;
	st->st_nlink = 1;
	if (type == FT_CONSOLE || type == FT_NULL || type == FT_RANDOM) {
		st->st_mode = 0020000 | 0666;
		st->st_rdev = type == FT_NULL ? 0x103 : 0x500;
		return 0;
	}
	if (type == FT_PIPE) {
		st->st_mode = 0010000 | 0600;
		return 0;
	}
	if (type == FT_MEM) {
		st->st_mode = 0100000 | 0444;
		return 0;
	}
	if (type == FT_MEMDIR) {
		st->st_mode = 0040000 | 0555;
		return 0;
	}
	if (type == FT_SOCKET) {
		st->st_mode = 0140000 | 0777;
		return 0;
	}
	BY_HANDLE_FILE_INFORMATION bi;
	if (!GetFileInformationByHandle(h, &bi)) {
		DWORD e = GetLastError();
		if (GetFileType(h) == FILE_TYPE_PIPE) {
			st->st_mode = 0010000 | 0600;
			return 0;
		}
		return ws_err(e);
	}
	st->st_dev = bi.dwVolumeSerialNumber;
	st->st_ino = ((u64)bi.nFileIndexHigh << 32) | bi.nFileIndexLow;
	st->st_nlink = bi.nNumberOfLinks;
	int perm = mode_get_handle(h);
	if (bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		st->st_mode = 0040000 | (perm >= 0 ? (unsigned)perm : 0755);
	else
		st->st_mode = 0100000 | (perm >= 0 ? (unsigned)perm
					  : (bi.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 0444 : 0644);
	st->st_size = (i64)(((u64)bi.nFileSizeHigh << 32) | bi.nFileSizeLow);
	FILE_STANDARD_INFO si;
	if (GetFileInformationByHandleEx(h, FileStandardInfo, &si, sizeof si))
		st->st_blocks = si.AllocationSize.QuadPart / 512;
	else
		st->st_blocks = (st->st_size + 511) / 512;
	ft_to_ts(bi.ftLastAccessTime, &st->st_atime_sec, &st->st_atime_nsec);
	ft_to_ts(bi.ftLastWriteTime, &st->st_mtime_sec, &st->st_mtime_nsec);
	FILE_BASIC_INFO b;
	if (GetFileInformationByHandleEx(h, FileBasicInfo, &b, sizeof b)) {
		FILETIME c = { (DWORD)b.ChangeTime.QuadPart, (DWORD)(b.ChangeTime.QuadPart >> 32) };
		ft_to_ts(c, &st->st_ctime_sec, &st->st_ctime_nsec);
	} else {
		st->st_ctime_sec = st->st_mtime_sec;
		st->st_ctime_nsec = st->st_mtime_nsec;
	}
	return 0;
}

static HANDLE open_meta(const wchar_t *w, int nofollow, DWORD access)
{
	return CreateFileW(w, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			   OPEN_EXISTING,
			   FILE_FLAG_BACKUP_SEMANTICS | (nofollow ? FILE_FLAG_OPEN_REPARSE_POINT : 0), NULL);
}

static int is_nul(const wchar_t *w)
{
	return (w[0] == L'N' || w[0] == L'n') && (w[1] == L'U' || w[1] == L'u') &&
	       (w[2] == L'L' || w[2] == L'l') && w[3] == 0;
}

/* a program named without ".exe" (daemon/bmc_cli, <exe dir>/bmc_build_...):
 * stat and access find "<path>.exe" when "<path>" itself does not exist, as
 * Cygwin does, so the checks before an exec agree with the exec */
static void exe_alt(wchar_t **w)
{
	if (GetFileAttributesW(*w) != INVALID_FILE_ATTRIBUTES)
		return;
	size_t l = ws_wcslen(*w);
	wchar_t *x = ws_alloc((l + 5) * sizeof(wchar_t));
	if (!x)
		return;
	__ws_memcpy(x, *w, l * sizeof(wchar_t));
	__ws_memcpy(x + l, L".exe", 5 * sizeof(wchar_t));
	DWORD a = GetFileAttributesW(x);
	if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
		ws_free(*w);
		*w = x;
		return;
	}
	/* ...and in BMC_WIN_BINDIR by base name, as exec looks (ws_exec.c) */
	wchar_t dir[MAX_PATH];
	DWORD dl = GetEnvironmentVariableW(L"BMC_WIN_BINDIR", dir, MAX_PATH);
	const wchar_t *base = x + l;
	while (base > x && base[-1] != L'\\' && base[-1] != L'/')
		base--;
	size_t bl = ws_wcslen(base);
	if (dl && dl < MAX_PATH) {
		wchar_t *y = ws_alloc((dl + bl + 2) * sizeof(wchar_t));
		if (y) {
			__ws_memcpy(y, dir, dl * sizeof(wchar_t));
			y[dl] = L'\\';
			__ws_memcpy(y + dl + 1, base, (bl + 1) * sizeof(wchar_t));
			a = GetFileAttributesW(y);
			if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
				ws_free(x);
				ws_free(*w);
				*w = y;
				return;
			}
			ws_free(y);
		}
	}
	ws_free(x);
	SetLastError(ERROR_FILE_NOT_FOUND);
}

static i64 sys_stat_path(int dirfd, const char *path, struct l_stat *st, int flags)
{
	if ((flags & L_AT_EMPTY_PATH) && path && !*path) {
		ws_desc *d = ws_fd_get(dirfd);
		if (!d)
			return -L_EBADF;
		i64 r = stat_handle(d->h, d->type, st);
		if (!r && d->type == FT_MEM)
			st->st_size = (i64)d->memlen;
		ws_desc_put(d);
		return r;
	}
	if (is_proc(path)) {
		i64 e2;
		ws_desc *d = ws_procfs_open(path, &e2);
		if (!d)
			return e2;
		i64 r = stat_handle(NULL, d->type, st);
		if (d->type == FT_MEM)
			st->st_size = (i64)d->memlen;
		ws_desc_put(d);
		return r;
	}
	i64 err;
	wchar_t *w = ws_path(dirfd, path, &err);
	if (!w)
		return err;
	if (is_nul(w)) {
		ws_free(w);
		return stat_handle(NULL, FT_NULL, st);
	}
	exe_alt(&w);
	HANDLE h = open_meta(w, (flags & L_AT_SYMLINK_NOFOLLOW) != 0, FILE_READ_ATTRIBUTES | FILE_READ_EA);
	ws_free(w);
	if (h == INVALID_HANDLE_VALUE)
		return ws_err(GetLastError());
	i64 r = stat_handle(h, FT_FILE, st);
	CloseHandle(h);
	return r;
}

static i64 delete_path(const wchar_t *w, int want_dir);

static i64 sys_open(int dirfd, const char *path, int flags, int mode)
{
	i64 err;
	int cloexec = (flags & L_O_CLOEXEC) != 0;
	if (is_proc(path)) {
		if ((flags & L_O_ACCMODE) != 0)
			return -L_EACCES;
		ws_desc *d = ws_procfs_open(path, &err);
		if (!d)
			return err;
		d->flags = flags & L_O_ACCMODE;
		return ws_fd_install(d, cloexec, 0);
	}
	if (path && (!__ws_memcmp(path, "/dev/urandom", 13) || !__ws_memcmp(path, "/dev/random", 12))) {
		ws_desc *d = ws_desc_new(FT_RANDOM);
		return d ? ws_fd_install(d, cloexec, 0) : -L_ENOMEM;
	}
	wchar_t *w = ws_path(dirfd, path, &err);
	if (!w)
		return err;
	if (is_nul(w)) {
		ws_free(w);
		ws_desc *d = ws_desc_new(FT_NULL);
		if (!d)
			return -L_ENOMEM;
		d->flags = flags;
		return ws_fd_install(d, cloexec, 0);
	}
	DWORD acc = 0;
	switch (flags & L_O_ACCMODE) {
	case 0: acc = GENERIC_READ; break;
	case L_O_WRONLY: acc = GENERIC_WRITE; break;
	default: acc = GENERIC_READ | GENERIC_WRITE; break;
	}
	if (flags & L_O_PATH)
		acc = FILE_READ_ATTRIBUTES;
	acc |= FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
	DWORD disp;
	if ((flags & L_O_CREAT) && (flags & L_O_EXCL))
		disp = CREATE_NEW;
	else if ((flags & L_O_CREAT) && (flags & L_O_TRUNC))
		disp = CREATE_ALWAYS;
	else if (flags & L_O_CREAT)
		disp = OPEN_ALWAYS;
	else if (flags & L_O_TRUNC)
		disp = TRUNCATE_EXISTING;
	else
		disp = OPEN_EXISTING;
	DWORD attrs = GetFileAttributesW(w);
	int isdir = attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
	if ((flags & L_O_DIRECTORY) && attrs != INVALID_FILE_ATTRIBUTES && !isdir) {
		ws_free(w);
		return -L_ENOTDIR;
	}
	if ((flags & L_O_DIRECTORY) && attrs == INVALID_FILE_ATTRIBUTES) {
		i64 e = ws_err(GetLastError());
		ws_free(w);
		return e;
	}
	if (isdir && (flags & L_O_ACCMODE) != 0) {
		ws_free(w);
		return -L_EISDIR;
	}
	if (isdir) {
		acc = FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_LIST_DIRECTORY | SYNCHRONIZE;
		disp = OPEN_EXISTING;
	}
	if (acc & GENERIC_WRITE) {
		/* a read-only attribute must not stop the owner (Linux: mode bits
		 * of a file we created ourselves) -- bmc never relies on it */
		if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY) && !isdir)
			SetFileAttributesW(w, attrs & ~FILE_ATTRIBUTE_READONLY);
	}
	HANDLE h = CreateFileW(w, acc, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, disp,
			       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_USER_MAPPED_FILE && (flags & L_O_TRUNC) && !isdir) {
		/* O_TRUNC on a file something still maps (a reader's cached view of
		 * the run this name held): Windows cannot cut it. Unlink it with
		 * POSIX semantics instead -- the views keep the old contents, the
		 * name is free -- and create the file afresh. A reader that checks
		 * what it mapped (the LSM's generation) sees the old file whole
		 * rather than Linux's truncated one. */
		if (delete_path(w, 0) == 0) {
			h = CreateFileW(w, acc, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW,
					FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);
			if (h != INVALID_HANDLE_VALUE) {
				disp = CREATE_NEW;
				if (!(flags & L_O_CREAT))
					mode = 0644;
				flags |= L_O_CREAT;
			}
		} else {
			SetLastError(ERROR_USER_MAPPED_FILE);
		}
	}
	if (h == INVALID_HANDLE_VALUE) {
		DWORD e = GetLastError();
		ws_free(w);
		if (e == ERROR_FILE_EXISTS)
			return -L_EEXIST;
		return ws_err(e);
	}
	if ((flags & L_O_CREAT) && !isdir &&
	    (disp == CREATE_NEW || (disp != OPEN_EXISTING && GetLastError() != ERROR_ALREADY_EXISTS))) {
		/* we created it: its permission bits are mode & ~umask */
		HANDLE wh = ReOpenFile(h, FILE_WRITE_EA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
		if (wh != INVALID_HANDLE_VALUE) {
			mode_set_handle(wh, (unsigned)mode & ~(unsigned)umask_bits & 07777);
			CloseHandle(wh);
		}
	}
	ws_desc *d = ws_desc_new(isdir ? FT_DIR : FT_FILE);
	if (!d) {
		CloseHandle(h);
		ws_free(w);
		return -L_ENOMEM;
	}
	d->h = h;
	d->flags = flags & ~(L_O_CREAT | L_O_EXCL | L_O_TRUNC | L_O_CLOEXEC);
	d->wpath = w;
	return ws_fd_install(d, cloexec, 0);
}

static i64 file_size(HANDLE h, i64 *sz)
{
	LARGE_INTEGER li;
	if (!GetFileSizeEx(h, &li))
		return ws_err(GetLastError());
	*sz = li.QuadPart;
	return 0;
}

static i64 rw_file(ws_desc *d, void *buf, size_t n, i64 pos, int write, int positioned)
{
	if (n > 0x7ffff000)
		n = 0x7ffff000;
	OVERLAPPED ov;
	__ws_memset(&ov, 0, sizeof ov);
	int lock = !positioned;
	if (lock)
		AcquireSRWLockExclusive(&d->lock);
	i64 at = positioned ? pos : d->off;
	int append = write && (d->flags & L_O_APPEND);
	if (append) {
		ov.Offset = 0xFFFFFFFF;
		ov.OffsetHigh = 0xFFFFFFFF;
	} else {
		ov.Offset = (DWORD)at;
		ov.OffsetHigh = (DWORD)((u64)at >> 32);
	}
	DWORD got = 0;
	BOOL ok = write ? WriteFile(d->h, buf, (DWORD)n, &got, &ov) : ReadFile(d->h, buf, (DWORD)n, &got, &ov);
	i64 r;
	if (!ok) {
		DWORD e = GetLastError();
		r = (e == ERROR_HANDLE_EOF) ? 0 : ws_err(e);
	} else {
		r = (i64)got;
	}
	if (lock) {
		if (r >= 0) {
			if (append) {
				i64 sz;
				if (!file_size(d->h, &sz))
					d->off = sz;
			} else {
				d->off = at + r;
			}
		}
		ReleaseSRWLockExclusive(&d->lock);
	}
	return r;
}

static i64 rw_stream(ws_desc *d, void *buf, size_t n, int write)
{
	if (n > 0x7ffff000)
		n = 0x7ffff000;
	DWORD got = 0;
	if (!write)
		ws_sig_sync_io(1);           /* a signal cancels the read: -EINTR */
	BOOL ok = write ? WriteFile(d->h, buf, (DWORD)n, &got, NULL) : ReadFile(d->h, buf, (DWORD)n, &got, NULL);
	if (!write)
		ws_sig_sync_io(0);
	if (!ok) {
		DWORD e = GetLastError();
		if (!write && (e == ERROR_BROKEN_PIPE || e == ERROR_HANDLE_EOF))
			return 0;
		if (e == ERROR_OPERATION_ABORTED)
			return -L_EINTR;
		return ws_err(e);
	}
	return (i64)got;
}

static i64 fill_random(void *buf, size_t n);

static i64 do_rw(int fd, void *buf, size_t n, i64 pos, int write, int positioned)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	i64 r;
	if (!write && (d->flags & L_O_ACCMODE) == L_O_WRONLY && d->type == FT_FILE)
		r = -L_EBADF;
	else if (write && (d->flags & L_O_ACCMODE) == 0 && d->type == FT_FILE)
		r = -L_EBADF;
	else switch (d->type) {
	case FT_FILE:
		r = rw_file(d, buf, n, pos, write, positioned);
		break;
	case FT_DIR:
		r = -L_EISDIR;
		break;
	case FT_NULL:
		r = write ? (i64)n : 0;
		break;
	case FT_MEM:
		if (write) {
			r = -L_EBADF;
		} else {
			AcquireSRWLockExclusive(&d->lock);
			i64 at = positioned ? pos : d->off;
			u64 avail = (u64)at < d->memlen ? d->memlen - (u64)at : 0;
			if (n > avail)
				n = (size_t)avail;
			__ws_memcpy(buf, d->mem + at, n);
			if (!positioned)
				d->off = at + (i64)n;
			ReleaseSRWLockExclusive(&d->lock);
			r = (i64)n;
		}
		break;
	case FT_MEMDIR:
		r = -L_EISDIR;
		break;
	case FT_RANDOM:
		r = write ? (i64)n : fill_random(buf, n);
		break;
	case FT_SOCKET:
		r = positioned ? -L_ESPIPE : write ? ws_sock_write(d, buf, n) : ws_sock_read(d, buf, n);
		break;
	default:
		r = positioned ? -L_ESPIPE : rw_stream(d, buf, n, write);
		break;
	}
	ws_desc_put(d);
	return r;
}

struct l_iovec { void *base; u64 len; };

static i64 do_rwv(int fd, const struct l_iovec *iov, int cnt, i64 pos, int write, int positioned)
{
	i64 total = 0;
	if (cnt < 0 || cnt > 1024)
		return -L_EINVAL;
	/* a gathered write goes out as ONE write, as writev does: a pipe reader
	 * (or an O_APPEND writer next door) must not see it split per iovec --
	 * musl's printf("%s\n") is a two-iovec writev */
	if (write && cnt > 1) {
		u64 sum = 0;
		for (int i = 0; i < cnt; i++)
			sum += iov[i].len;
		if (sum <= (1u << 20)) {
			char stackbuf[4096];
			char *g = sum <= sizeof stackbuf ? stackbuf : ws_alloc((size_t)sum);
			if (g) {
				u64 at = 0;
				for (int i = 0; i < cnt; i++) {
					__ws_memcpy(g + at, iov[i].base, (size_t)iov[i].len);
					at += iov[i].len;
				}
				i64 r = do_rw(fd, g, (size_t)sum, pos, write, positioned);
				if (g != stackbuf)
					ws_free(g);
				return r;
			}
		}
	}
	for (int i = 0; i < cnt; i++) {
		if (!iov[i].len)
			continue;
		i64 r = do_rw(fd, iov[i].base, iov[i].len, pos + total, write, positioned);
		if (r < 0)
			return total ? total : r;
		total += r;
		if ((u64)r < iov[i].len)
			break;
	}
	return total;
}

typedef BOOLEAN (WINAPI *rtlgenrandom_fn)(PVOID, ULONG);
static i64 fill_random(void *buf, size_t n)
{
	static rtlgenrandom_fn fn;
	if (!fn) {
		HMODULE m = LoadLibraryW(L"advapi32.dll");
		fn = m ? (rtlgenrandom_fn)(void *)GetProcAddress(m, "SystemFunction036") : NULL;
		if (!fn)
			return -L_EIO;
	}
	size_t done = 0;
	while (done < n) {
		ULONG chunk = (n - done) > 0x10000000 ? 0x10000000 : (ULONG)(n - done);
		if (!fn((char *)buf + done, chunk))
			return -L_EIO;
		done += chunk;
	}
	return (i64)n;
}

i64 ws_getrandom(void *buf, size_t n) { return fill_random(buf, n); }

static i64 sys_lseek(int fd, i64 off, int whence)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	i64 r;
	if (d->type != FT_FILE && d->type != FT_DIR && d->type != FT_NULL && d->type != FT_MEM &&
	    d->type != FT_MEMDIR) {
		ws_desc_put(d);
		return -L_ESPIPE;
	}
	AcquireSRWLockExclusive(&d->lock);
	i64 base = 0, sz;
	if (whence == 0) {
		base = 0;
	} else if (whence == 1) {
		base = d->off;
	} else if (whence == 2) {
		r = d->type == FT_FILE ? file_size(d->h, &sz) : (sz = d->type == FT_MEM ? (i64)d->memlen : 0, 0);
		if (r) {
			ReleaseSRWLockExclusive(&d->lock);
			ws_desc_put(d);
			return r;
		}
		base = sz;
	} else if (whence == 3 || whence == 4) {  /* SEEK_DATA / SEEK_HOLE: no sparse map */
		r = d->type == FT_FILE ? file_size(d->h, &sz) : (sz = 0, 0);
		if (!r && off >= sz)
			r = -L_ENXIO;
		if (r) {
			ReleaseSRWLockExclusive(&d->lock);
			ws_desc_put(d);
			return r;
		}
		base = 0;
		if (whence == 4)
			off = sz;
	} else {
		ReleaseSRWLockExclusive(&d->lock);
		ws_desc_put(d);
		return -L_EINVAL;
	}
	if (base + off < 0) {
		r = -L_EINVAL;
	} else {
		d->off = base + off;
		r = (i64)d->off;
	}
	if ((d->type == FT_DIR || d->type == FT_MEMDIR) && d->off == 0) {
		if (d->find && d->find != INVALID_HANDLE_VALUE)
			FindClose(d->find);
		d->find = NULL;
		d->find_state = 0;
		d->dir_pos = 0;
	}
	ReleaseSRWLockExclusive(&d->lock);
	ws_desc_put(d);
	return r;
}

static i64 set_eof(HANDLE h, i64 len)
{
	FILE_END_OF_FILE_INFO e;
	e.EndOfFile.QuadPart = len;
	if (!SetFileInformationByHandle(h, FileEndOfFileInfo, &e, sizeof e))
		return ws_err(GetLastError());
	return 0;
}

/* (f)truncate. Windows refuses to cut a file below a live mapping of it
 * (ERROR_USER_MAPPED_FILE: this process's or another's); Linux allows it.
 * Then the cut range is zeroed instead and the call succeeds: the file keeps
 * its physical size, but everything past the new end reads as zeros, as it
 * would after Linux's shrink and a later regrow -- the use here is always
 * "truncate, then map that size" */
static i64 truncate_handle(HANDLE h, i64 len)
{
	FILE_END_OF_FILE_INFO e;
	e.EndOfFile.QuadPart = len;
	if (SetFileInformationByHandle(h, FileEndOfFileInfo, &e, sizeof e))
		return 0;
	DWORD err = GetLastError();
	i64 sz;
	if (err != ERROR_USER_MAPPED_FILE || file_size(h, &sz) || sz <= len)
		return ws_err(err);
	FILE_ZERO_DATA_INFORMATION z;
	z.FileOffset.QuadPart = len;
	z.BeyondFinalZero.QuadPart = sz;
	DWORD got;
	if (!DeviceIoControl(h, FSCTL_SET_ZERO_DATA, &z, sizeof z, NULL, 0, &got, NULL))
		return ws_err(GetLastError());
	return 0;
}

static i64 sys_ftruncate(int fd, i64 len)
{
	if (len < 0)
		return -L_EINVAL;
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	i64 r = d->type == FT_FILE ? truncate_handle(d->h, len) : -L_EINVAL;
	ws_desc_put(d);
	return r;
}

static i64 sys_truncate(const char *path, i64 len)
{
	i64 err;
	wchar_t *w = ws_path(L_AT_FDCWD, path, &err);
	if (!w)
		return err;
	HANDLE h = CreateFileW(w, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			       OPEN_EXISTING, 0, NULL);
	ws_free(w);
	if (h == INVALID_HANDLE_VALUE)
		return ws_err(GetLastError());
	i64 r = truncate_handle(h, len);
	CloseHandle(h);
	return r;
}

static i64 sys_fallocate(int fd, int mode, i64 off, i64 len)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	i64 r = 0;
	if (d->type != FT_FILE) {
		r = -L_ENODEV;
	} else if (mode == 3 || mode == 0x10 || mode == 0x11) {
		/* FALLOC_FL_PUNCH_HOLE|KEEP_SIZE (3), FALLOC_FL_ZERO_RANGE (0x10,
		 * |KEEP_SIZE 0x11): the range reads as zeros; on a sparse NTFS file
		 * SET_ZERO_DATA also gives its clusters back, which is what a hole
		 * punch is for */
		DWORD got;
		FILE_SET_SPARSE_BUFFER sp = { TRUE };
		if (mode == 3)
			DeviceIoControl(d->h, FSCTL_SET_SPARSE, &sp, sizeof sp, NULL, 0, &got, NULL);
		i64 sz;
		r = file_size(d->h, &sz);
		i64 end = off + len;
		if (!r && (mode & 1) && end > sz)
			end = sz;                     /* KEEP_SIZE: nothing past EOF */
		if (!r && end > off) {
			FILE_ZERO_DATA_INFORMATION z;
			z.FileOffset.QuadPart = off;
			z.BeyondFinalZero.QuadPart = end;
			if (!DeviceIoControl(d->h, FSCTL_SET_ZERO_DATA, &z, sizeof z, NULL, 0, &got, NULL))
				r = ws_err(GetLastError());
		}
		if (!r && !(mode & 1) && off + len > sz)
			r = set_eof(d->h, off + len);
	} else if (mode & ~1) {
		r = -L_EOPNOTSUPP;
	} else {
		i64 sz;
		r = file_size(d->h, &sz);
		if (!r) {
			FILE_ALLOCATION_INFO a;
			a.AllocationSize.QuadPart = off + len;
			if (off + len > sz)
				SetFileInformationByHandle(d->h, FileAllocationInfo, &a, sizeof a);
			if (!(mode & 1) && off + len > sz)
				r = set_eof(d->h, off + len);
		}
	}
	ws_desc_put(d);
	return r;
}

static i64 sys_fsync(int fd)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	i64 r = 0;
	if (d->type == FT_FILE && !FlushFileBuffers(d->h)) {
		DWORD e = GetLastError();
		if (e != ERROR_ACCESS_DENIED)   /* read-only handle: nothing to flush */
			r = ws_err(e);
	}
	ws_desc_put(d);
	return r;
}

/* ---- advisory locks: a shadow range at the top of the 63-bit offset space ---- */
#define LOCK_BASE 0x4000000000000000ULL

static i64 lock_range(HANDLE h, u64 start, u64 len, int excl, int wait)
{
	OVERLAPPED ov;
	__ws_memset(&ov, 0, sizeof ov);
	u64 at = LOCK_BASE + start;
	ov.Offset = (DWORD)at;
	ov.OffsetHigh = (DWORD)(at >> 32);
	DWORD fl = (excl ? LOCKFILE_EXCLUSIVE_LOCK : 0) | (wait ? 0 : LOCKFILE_FAIL_IMMEDIATELY);
	if (!LockFileEx(h, fl, 0, (DWORD)len, (DWORD)(len >> 32), &ov)) {
		DWORD e = GetLastError();
		if (e == ERROR_LOCK_VIOLATION || e == ERROR_IO_PENDING)
			return -L_EAGAIN;
		return ws_err(e);
	}
	return 0;
}

static i64 unlock_range(HANDLE h, u64 start, u64 len)
{
	OVERLAPPED ov;
	__ws_memset(&ov, 0, sizeof ov);
	u64 at = LOCK_BASE + start;
	ov.Offset = (DWORD)at;
	ov.OffsetHigh = (DWORD)(at >> 32);
	if (!UnlockFileEx(h, 0, (DWORD)len, (DWORD)(len >> 32), &ov))
		return ws_err(GetLastError());
	return 0;
}

/* flock state lives in the description: 0 none, 1 shared, 2 exclusive */
#define FLOCK_SPAN 1ULL
#define FLOCK_AT 0x3fffffffffff0000ULL

static i64 sys_flock(int fd, int op)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	if (d->type != FT_FILE && d->type != FT_DIR) {
		ws_desc_put(d);
		return -L_EINVAL;
	}
	int nb = (op & 4) != 0;
	op &= ~4;
	i64 r = 0;
	AcquireSRWLockExclusive(&d->lock);
	int held = d->flock_held;
	if (op == 8) {                       /* LOCK_UN */
		if (held)
			unlock_range(d->h, FLOCK_AT, FLOCK_SPAN);
		held = 0;
	} else if (op == 1 || op == 2) {
		int want = op;
		if (held != want) {
			if (held)
				unlock_range(d->h, FLOCK_AT, FLOCK_SPAN);
			held = 0;
			r = lock_range(d->h, FLOCK_AT, FLOCK_SPAN, want == 2, !nb);
			if (r == 0)
				held = want;
			else if (r == -L_EAGAIN)
				r = -L_EAGAIN;   /* EWOULDBLOCK */
		}
	} else {
		r = -L_EINVAL;
	}
	d->flock_held = held;
	ReleaseSRWLockExclusive(&d->lock);
	ws_desc_put(d);
	return r;
}

struct l_flock { short l_type, l_whence; i64 l_start, l_len; int l_pid; };

static i64 fcntl_lock(ws_desc *d, int cmd, struct l_flock *fl)
{
	if (d->type != FT_FILE)
		return -L_EBADF;
	i64 base = 0;
	if (fl->l_whence == 1)
		base = d->off;
	else if (fl->l_whence == 2 && file_size(d->h, &base))
		return -L_EINVAL;
	i64 start = base + fl->l_start;
	i64 len = fl->l_len;
	if (len < 0) {
		start += len;
		len = -len;
	}
	if (start < 0)
		return -L_EINVAL;
	if (len == 0)
		len = 0x3000000000000000LL - start;   /* "to EOF and beyond" */
	if (cmd == 5 || cmd == 36) {           /* F_GETLK: probe */
		i64 r = lock_range(d->h, (u64)start, (u64)len, fl->l_type == 1, 0);
		if (r == 0) {
			unlock_range(d->h, (u64)start, (u64)len);
			fl->l_type = 2;               /* F_UNLCK */
		} else {
			fl->l_pid = -1;
		}
		return 0;
	}
	if (fl->l_type == 2)
		return unlock_range(d->h, (u64)start, (u64)len) == 0 ? 0 : 0;
	return lock_range(d->h, (u64)start, (u64)len, fl->l_type == 1, cmd == 7 || cmd == 38);
}

static i64 sys_fcntl(int fd, int cmd, i64 arg)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	i64 r = 0;
	switch (cmd) {
	case 0:      /* F_DUPFD */
	case 1030:   /* F_DUPFD_CLOEXEC */
		InterlockedIncrement(&d->refs);
		r = ws_fd_install(d, cmd == 1030, (int)arg);
		break;
	case 1:      /* F_GETFD */
		AcquireSRWLockShared(&fdt_lock);
		r = fdt[fd].cloexec ? 1 : 0;
		ReleaseSRWLockShared(&fdt_lock);
		break;
	case 2:      /* F_SETFD */
		AcquireSRWLockExclusive(&fdt_lock);
		if (fdt[fd].d == d)
			fdt[fd].cloexec = (arg & 1) != 0;
		ReleaseSRWLockExclusive(&fdt_lock);
		break;
	case 3:      /* F_GETFL */
		r = d->flags & (L_O_ACCMODE | L_O_APPEND | L_O_NONBLOCK);
		break;
	case 4:      /* F_SETFL */
		/* sockets stay blocking at the Winsock level; ws_net.c emulates
		 * O_NONBLOCK from this flag */
		d->flags = (d->flags & ~(L_O_APPEND | L_O_NONBLOCK)) | ((int)arg & (L_O_APPEND | L_O_NONBLOCK));
		break;
	case 5: case 6: case 7: case 36: case 37: case 38:
		r = fcntl_lock(d, cmd, (struct l_flock *)arg);
		break;
	case 1031: case 1032:  /* F_SETPIPE_SZ / F_GETPIPE_SZ */
		r = 65536;
		break;
	default:
		r = -L_EINVAL;
	}
	ws_desc_put(d);
	return r;
}

static i64 sys_dup(int fd, int newfd, int flags, int mode)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	if (mode == 0)
		return ws_fd_install(d, 0, 0);
	if (newfd < 0) {
		ws_desc_put(d);
		return -L_EBADF;
	}
	if (newfd == fd) {
		ws_desc_put(d);
		return mode == 3 ? -L_EINVAL : fd;
	}
	return install_at(d, newfd, (flags & L_O_CLOEXEC) != 0);
}

/* ---- ioctl ---- */
static i64 sys_ioctl(int fd, u64 req, i64 arg)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	i64 r = -L_ENOTTY;
	if (req == 0x5413 && d->type == FT_CONSOLE) {         /* TIOCGWINSZ */
		CONSOLE_SCREEN_BUFFER_INFO ci;
		unsigned short *ws = (unsigned short *)arg;
		__ws_memset(ws, 0, 8);
		if (GetConsoleScreenBufferInfo(d->h, &ci)) {
			ws[0] = (unsigned short)(ci.srWindow.Bottom - ci.srWindow.Top + 1);
			ws[1] = (unsigned short)(ci.srWindow.Right - ci.srWindow.Left + 1);
		} else {
			ws[0] = 25;
			ws[1] = 80;
		}
		r = 0;
	} else if (req == 0x5401 && d->type == FT_CONSOLE) {  /* TCGETS */
		__ws_memset((void *)arg, 0, 60);
		r = 0;
	} else if (req == 0x5421 && d->type == FT_SOCKET) {   /* FIONBIO: emulated flag */
		d->flags = *(int *)arg ? (d->flags | L_O_NONBLOCK) : (d->flags & ~L_O_NONBLOCK);
		r = 0;
	} else if (req == 0x541B) {                            /* FIONREAD */
		if (d->type == FT_SOCKET) {
			r = ws_sock_nread(d);
			if (r >= 0) {
				*(int *)arg = (int)r;
				r = 0;
			}
		} else if (d->type == FT_PIPE) {
			DWORD avail = 0;
			r = PeekNamedPipe(d->h, NULL, 0, NULL, &avail, NULL) ? 0 : ws_err(GetLastError());
			*(int *)arg = (int)avail;
		}
	} else if (req == 0x5421) {                            /* FIONBIO on a non-socket */
		r = 0;
	}
	ws_desc_put(d);
	return r;
}

/* ---- directory and namespace operations ---- */
struct l_dirent64 { u64 d_ino; i64 d_off; unsigned short d_reclen; unsigned char d_type; char d_name[]; };

static i64 sys_getdents64(int fd, void *buf, size_t cnt)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	if (d->type == FT_MEMDIR) {
		AcquireSRWLockExclusive(&d->lock);
		char *out = buf;
		size_t used = 0;
		i64 idx = 0;
		for (u64 at = 0; at < d->memlen; idx++) {
			const char *name = d->mem + at;
			size_t nl = ws_strlen(name);
			at += nl + 1;
			if (idx < d->dir_pos)
				continue;
			size_t rec = (sizeof(struct l_dirent64) + nl + 1 + 7) & ~(size_t)7;
			if (used + rec > cnt)
				break;
			struct l_dirent64 *e = (struct l_dirent64 *)(out + used);
			e->d_ino = (u64)(idx + 1);
			e->d_off = idx + 1;
			e->d_reclen = (unsigned short)rec;
			e->d_type = 4;
			__ws_memcpy(e->d_name, name, nl + 1);
			used += rec;
			d->dir_pos = idx + 1;
		}
		ReleaseSRWLockExclusive(&d->lock);
		ws_desc_put(d);
		return (i64)used;
	}
	if (d->type != FT_DIR) {
		ws_desc_put(d);
		return -L_ENOTDIR;
	}
	AcquireSRWLockExclusive(&d->lock);
	i64 r = 0;
	if (d->find_state == 0) {
		size_t l = ws_wcslen(d->wpath);
		wchar_t *pat = ws_alloc((l + 3) * sizeof(wchar_t));
		__ws_memcpy(pat, d->wpath, l * sizeof(wchar_t));
		pat[l] = L'\\';
		pat[l + 1] = L'*';
		d->find = FindFirstFileW(pat, &d->fd);
		ws_free(pat);
		if (d->find == INVALID_HANDLE_VALUE) {
			d->find = NULL;
			d->find_state = 2;
		} else {
			d->find_state = 1;
		}
	}
	char *out = buf;
	size_t used = 0;
	while (d->find_state == 1) {
		char *name = ws_w_to_utf8(d->fd.cFileName);
		size_t nl = name ? ws_strlen(name) : 0;
		size_t rec = (sizeof(struct l_dirent64) + nl + 1 + 7) & ~(size_t)7;
		if (used + rec > cnt) {
			ws_free(name);
			if (!used)
				r = -L_EINVAL;
			break;
		}
		struct l_dirent64 *e = (struct l_dirent64 *)(out + used);
		e->d_ino = (u64)(d->dir_pos + 1);
		e->d_off = d->dir_pos + 1;
		e->d_reclen = (unsigned short)rec;
		e->d_type = (d->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 4 : 8;
		__ws_memcpy(e->d_name, name ? name : "", nl + 1);
		ws_free(name);
		used += rec;
		d->dir_pos++;
		if (!FindNextFileW(d->find, &d->fd))
			d->find_state = 2;
	}
	if (r == 0)
		r = (i64)used;
	ReleaseSRWLockExclusive(&d->lock);
	ws_desc_put(d);
	return r;
}

static i64 sys_mkdir(int dirfd, const char *path, int mode)
{
	i64 err;
	wchar_t *w = ws_path(dirfd, path, &err);
	if (!w)
		return err;
	BOOL ok = CreateDirectoryW(w, NULL);
	DWORD e = GetLastError();
	if (ok)
		mode_set_path(w, (unsigned)mode & ~(unsigned)umask_bits & 07777);
	ws_free(w);
	return ok ? 0 : ws_err(e);
}

typedef struct { DWORD Flags; } ws_disp_ex;

static i64 delete_path(const wchar_t *w, int want_dir)
{
	DWORD attrs = GetFileAttributesW(w);
	if (attrs == INVALID_FILE_ATTRIBUTES)
		return ws_err(GetLastError());
	int isdir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
	if (want_dir && !isdir)
		return -L_ENOTDIR;
	if (!want_dir && isdir)
		return -L_EISDIR;
	if (attrs & FILE_ATTRIBUTE_READONLY)
		SetFileAttributesW(w, attrs & ~FILE_ATTRIBUTE_READONLY);
	HANDLE h = CreateFileW(w, DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			       NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return ws_err(GetLastError());
	/* FILE_DISPOSITION_DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE */
	ws_disp_ex dx = { 0x1 | 0x2 | 0x10 };
	BOOL ok = SetFileInformationByHandle(h, (FILE_INFO_BY_HANDLE_CLASS)21 /* FileDispositionInfoEx */,
					     &dx, sizeof dx);
	DWORD e = ok ? 0 : GetLastError();
	if (!ok && e != ERROR_DIR_NOT_EMPTY) {
		FILE_DISPOSITION_INFO di = { TRUE };
		ok = SetFileInformationByHandle(h, FileDispositionInfo, &di, sizeof di);
		e = ok ? 0 : GetLastError();
	}
	CloseHandle(h);
	return ok ? 0 : ws_err(e);
}

static i64 sys_unlinkat(int dirfd, const char *path, int flags)
{
	i64 err;
	wchar_t *w = ws_path(dirfd, path, &err);
	if (!w)
		return err;
	i64 r = delete_path(w, (flags & L_AT_REMOVEDIR) != 0);
	ws_free(w);
	return r;
}

static wchar_t *full_path(const wchar_t *w)
{
	DWORD n = GetFullPathNameW(w, 0, NULL, NULL);
	if (!n)
		return NULL;
	wchar_t *f = ws_alloc((size_t)(n + 1) * sizeof(wchar_t));
	if (f && !GetFullPathNameW(w, n + 1, f, NULL)) {
		ws_free(f);
		return NULL;
	}
	return f;
}

static i64 sys_renameat(int ofd, const char *op, int nfd, const char *np, unsigned flags)
{
	i64 err;
	if (flags & ~1u)              /* only RENAME_NOREPLACE */
		return -L_EINVAL;
	wchar_t *wo = ws_path(ofd, op, &err);
	if (!wo)
		return err;
	wchar_t *wn = ws_path(nfd, np, &err);
	if (!wn) {
		ws_free(wo);
		return err;
	}
	wchar_t *fn = full_path(wn);
	i64 r = 0;
	HANDLE h = CreateFileW(wo, DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			       NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (h == INVALID_HANDLE_VALUE || !fn) {
		r = h == INVALID_HANDLE_VALUE ? ws_err(GetLastError()) : -L_ENOMEM;
	} else {
		size_t fl = ws_wcslen(fn);
		size_t sz = sizeof(FILE_RENAME_INFO) + (fl + 1) * sizeof(wchar_t);
		FILE_RENAME_INFO *ri = ws_alloc(sz);
		/* FILE_RENAME_FLAG_REPLACE_IF_EXISTS | POSIX_SEMANTICS */
		*(DWORD *)ri = (flags & 1) ? 0x2 : (0x1 | 0x2);
		ri->RootDirectory = NULL;
		ri->FileNameLength = (DWORD)(fl * sizeof(wchar_t));
		__ws_memcpy(ri->FileName, fn, (fl + 1) * sizeof(wchar_t));
		BOOL ok = SetFileInformationByHandle(h, (FILE_INFO_BY_HANDLE_CLASS)22 /* FileRenameInfoEx */,
						     ri, (DWORD)sz);
		DWORD e = ok ? 0 : GetLastError();
		ws_free(ri);
		CloseHandle(h);
		if (!ok && (e == ERROR_INVALID_PARAMETER || e == ERROR_NOT_SUPPORTED)) {
			ok = MoveFileExW(wo, wn, (flags & 1) ? 0 : MOVEFILE_REPLACE_EXISTING);
			e = ok ? 0 : GetLastError();
		}
		if (!ok)
			r = (e == ERROR_ALREADY_EXISTS || e == ERROR_FILE_EXISTS) ? -L_EEXIST : ws_err(e);
	}
	ws_free(fn);
	ws_free(wo);
	ws_free(wn);
	return r;
}

static i64 sys_faccessat(int dirfd, const char *path, int mode)
{
	i64 err;
	wchar_t *w = ws_path(dirfd, path, &err);
	if (!w)
		return err;
	if (!is_nul(w))
		exe_alt(&w);
	DWORD a = GetFileAttributesW(w);
	DWORD e = GetLastError();
	int nul = is_nul(w);
	ws_free(w);
	if (nul)
		return 0;
	if (a == INVALID_FILE_ATTRIBUTES)
		return ws_err(e);
	if ((mode & 2) && (a & FILE_ATTRIBUTE_READONLY) && !(a & FILE_ATTRIBUTE_DIRECTORY))
		return -L_EACCES;
	return 0;
}

static i64 sys_getcwd(char *buf, size_t size)
{
	DWORD n = GetCurrentDirectoryW(0, NULL);
	wchar_t *w = ws_alloc((size_t)(n + 1) * sizeof(wchar_t));
	if (!w)
		return -L_ENOMEM;
	GetCurrentDirectoryW(n + 1, w);
	char *u = ws_w_to_utf8(w);
	ws_free(w);
	if (!u)
		return -L_ENOMEM;
	size_t l = ws_strlen(u);
	for (size_t i = 0; i < l; i++)
		if (u[i] == '\\')
			u[i] = '/';
	if (l >= 2 && u[1] == ':') {
		/* "C:/x" -> "/c/x": an absolute POSIX path (musl's getcwd insists
		 * on a leading '/'); ws_path maps it back */
		u[1] = (char)(u[0] | 0x20);
		u[0] = '/';
		if (l == 3) {           /* "C:/" -> "/c" */
			u[2] = 0;
			l = 2;
		}
	}
	i64 r;
	if (l + 1 > size) {
		r = -L_ERANGE;
	} else {
		__ws_memcpy(buf, u, l + 1);
		r = (i64)(l + 1);
	}
	ws_free(u);
	return r;
}

static i64 sys_chdir(const char *path)
{
	i64 err;
	wchar_t *w = ws_path(L_AT_FDCWD, path, &err);
	if (!w)
		return err;
	BOOL ok = SetCurrentDirectoryW(w);
	DWORD e = GetLastError();
	ws_free(w);
	return ok ? 0 : ws_err(e);
}

/* an anonymous pipe as a uniquely named one: CreatePipe opens through a
 * named-pipe directory handle kernelbase caches at startup, which a forked
 * (cloned) process does not have -- pipe() there failed */
static BOOL make_pipe(HANDLE *r, HANDLE *w)
{
	static volatile LONG seq;
	wchar_t name[96], *q = name;
	const wchar_t *pre = L"\\\\.\\pipe\\bmc-anon-";
	while (*pre)
		*q++ = *pre++;
	u64 parts[3] = { GetCurrentProcessId(), (u64)InterlockedIncrement(&seq), GetTickCount64() };
	for (int i = 0; i < 3; i++) {
		for (int sh = 60; sh >= 0; sh -= 4)
			*q++ = L"0123456789abcdef"[(parts[i] >> sh) & 15];
		*q++ = i < 2 ? L'-' : 0;
	}
	*r = CreateNamedPipeW(name, PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
			      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
			      1, 65536, 65536, 0, NULL);
	if (*r == INVALID_HANDLE_VALUE)
		return FALSE;
	*w = CreateFileW(name, GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (*w == INVALID_HANDLE_VALUE) {
		DWORD e = GetLastError();
		CloseHandle(*r);
		SetLastError(e);
		return FALSE;
	}
	return TRUE;
}

static i64 sys_pipe(int *fds, int flags)
{
	HANDLE r, w;
	if (!make_pipe(&r, &w))
		return ws_err(GetLastError());
	ws_desc *dr = ws_desc_new(FT_PIPE), *dw = ws_desc_new(FT_PIPE);
	if (!dr || !dw) {
		CloseHandle(r);
		CloseHandle(w);
		ws_free(dr);
		ws_free(dw);
		return -L_ENOMEM;
	}
	dr->h = r;
	dw->h = w;
	dw->flags = L_O_WRONLY;
	int ce = (flags & L_O_CLOEXEC) != 0;
	int a = ws_fd_install(dr, ce, 0);
	if (a < 0) {
		ws_desc_put(dw);
		return a;
	}
	int b = ws_fd_install(dw, ce, 0);
	if (b < 0) {
		fd_close(a);
		return b;
	}
	fds[0] = a;
	fds[1] = b;
	return 0;
}

static i64 sys_chmod(int dirfd, const char *path, unsigned mode)
{
	i64 err;
	wchar_t *w = ws_path(dirfd, path, &err);
	if (!w)
		return err;
	DWORD a = GetFileAttributesW(w);
	i64 r = a == INVALID_FILE_ATTRIBUTES ? ws_err(GetLastError()) : 0;
	if (!r)
		mode_set_path(w, mode);
	ws_free(w);
	return r;
}

static i64 sys_fchmod(int fd, unsigned mode)
{
	ws_desc *d = ws_fd_get(fd);
	if (!d)
		return -L_EBADF;
	if (d->type == FT_FILE || d->type == FT_DIR) {
		HANDLE wh = ReOpenFile(d->h, FILE_WRITE_EA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				       d->type == FT_DIR ? FILE_FLAG_BACKUP_SEMANTICS : 0);
		if (wh != INVALID_HANDLE_VALUE) {
			mode_set_handle(wh, mode);
			CloseHandle(wh);
		} else if (d->wpath) {
			mode_set_path(d->wpath, mode);
		}
	}
	ws_desc_put(d);
	return 0;
}

i64 ws_sys_file(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	*handled = 1;
	(void)a6;
	switch (n) {
	case 0: return do_rw((int)a1, (void *)a2, (size_t)a3, 0, 0, 0);
	case 1: return do_rw((int)a1, (void *)a2, (size_t)a3, 0, 1, 0);
	case 2: return sys_open(L_AT_FDCWD, (const char *)a1, (int)a2, (int)a3);
	case 3: return fd_close((int)a1);
	case 4: return sys_stat_path(L_AT_FDCWD, (const char *)a1, (struct l_stat *)a2, 0);
	case 5: return sys_stat_path((int)a1, "", (struct l_stat *)a2, L_AT_EMPTY_PATH);
	case 6: return sys_stat_path(L_AT_FDCWD, (const char *)a1, (struct l_stat *)a2, L_AT_SYMLINK_NOFOLLOW);
	case 8: return sys_lseek((int)a1, (i64)a2, (int)a3);
	case 16: return sys_ioctl((int)a1, (u64)a2, a3);
	case 17: return a4 < 0 ? -L_EINVAL : do_rw((int)a1, (void *)a2, (size_t)a3, (i64)a4, 0, 1);
	case 18: return a4 < 0 ? -L_EINVAL : do_rw((int)a1, (void *)a2, (size_t)a3, (i64)a4, 1, 1);
	case 19: return do_rwv((int)a1, (const struct l_iovec *)a2, (int)a3, 0, 0, 0);
	case 20: return do_rwv((int)a1, (const struct l_iovec *)a2, (int)a3, 0, 1, 0);
	case 295: return do_rwv((int)a1, (const struct l_iovec *)a2, (int)a3, (i64)a4, 0, 1);  /* preadv */
	case 296: return do_rwv((int)a1, (const struct l_iovec *)a2, (int)a3, (i64)a4, 1, 1);  /* pwritev */
	case 21: return sys_faccessat(L_AT_FDCWD, (const char *)a1, (int)a2);
	case 269: case 439: return sys_faccessat((int)a1, (const char *)a2, (int)a3);
	case 22: return sys_pipe((int *)a1, 0);
	case 293: return sys_pipe((int *)a1, (int)a2);
	case 32: return sys_dup((int)a1, 0, 0, 0);
	case 33: return sys_dup((int)a1, (int)a2, 0, 2);
	case 292: return sys_dup((int)a1, (int)a2, (int)a3, 3);
	case 72: return sys_fcntl((int)a1, (int)a2, a3);
	case 73: return sys_flock((int)a1, (int)a2);
	case 74: case 75: return sys_fsync((int)a1);
	case 277: return sys_fsync((int)a1);   /* sync_file_range: durability, not precision */
	case 162: return 0;                    /* sync */
	case 76: return sys_truncate((const char *)a1, (i64)a2);
	case 77: return sys_ftruncate((int)a1, (i64)a2);
	case 285: return sys_fallocate((int)a1, (int)a2, (i64)a3, (i64)a4);
	case 221: case 187: return 0;          /* fadvise64, readahead: hints */
	case 79: return sys_getcwd((char *)a1, (size_t)a2);
	case 80: return sys_chdir((const char *)a1);
	case 82: return sys_renameat(L_AT_FDCWD, (const char *)a1, L_AT_FDCWD, (const char *)a2, 0);
	case 264: return sys_renameat((int)a1, (const char *)a2, (int)a3, (const char *)a4, 0);
	case 316: return sys_renameat((int)a1, (const char *)a2, (int)a3, (const char *)a4, (unsigned)a5);
	case 83: return sys_mkdir(L_AT_FDCWD, (const char *)a1, (int)a2);
	case 258: return sys_mkdir((int)a1, (const char *)a2, (int)a3);
	case 84: return sys_unlinkat(L_AT_FDCWD, (const char *)a1, L_AT_REMOVEDIR);
	case 87: return sys_unlinkat(L_AT_FDCWD, (const char *)a1, 0);
	case 263: return sys_unlinkat((int)a1, (const char *)a2, (int)a3);
	case 257: return sys_open((int)a1, (const char *)a2, (int)a3, (int)a4);
	case 262: return sys_stat_path((int)a1, (const char *)a2, (struct l_stat *)a3, (int)a4);
	case 217: return sys_getdents64((int)a1, (void *)a2, (size_t)a3);
	case 89:                               /* readlink: /proc links; no others are made */
		return is_proc((const char *)a1) ? ws_procfs_readlink((const char *)a1, (char *)a2, (size_t)a3) : -L_EINVAL;
	case 267:
		return is_proc((const char *)a2) ? ws_procfs_readlink((const char *)a2, (char *)a3, (size_t)a4) : -L_EINVAL;
	case 86: case 265: case 88: case 266: return -L_EPERM;  /* link / symlink */
	case 90: return sys_chmod(L_AT_FDCWD, (const char *)a1, (unsigned)a2);
	case 268: return sys_chmod((int)a1, (const char *)a2, (unsigned)a3);   /* fchmodat */
	case 91: return sys_fchmod((int)a1, (unsigned)a2);
	case 92: case 93: case 94: case 260: return 0;   /* chown family: one user */
	case 95: return (i64)InterlockedExchange(&umask_bits, (LONG)(a1 & 0777));   /* umask */
	case 332: return -L_ENOSYS;            /* statx: musl falls back to fstatat */
	case 318: return fill_random((void *)a1, (size_t)a2);   /* getrandom */
	default:
		*handled = 0;
		return 0;
	}
	(void)a5;
}

/* ---- fork (ws_fork.c): the table is locked across the clone and every
 * handle in it made inheritable, so the child sees the same fds ---- */
static void inherit(HANDLE h)
{
	if (h && h != INVALID_HANDLE_VALUE)
		SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
}

void ws_fd_fork_prepare(void)
{
	AcquireSRWLockExclusive(&fdt_lock);
	for (int i = 0; i < fdt_cap; i++) {
		ws_desc *d = fdt[i].d;
		if (!d)
			continue;
		inherit(d->h);
		if (d->type == FT_SOCKET)
			inherit((HANDLE)d->s);
		if (d->find && d->find != INVALID_HANDLE_VALUE) {
			/* a FindFirstFile enumeration is not a kernel handle: the child
			 * restarts the listing from its position on next getdents */
			d->find_state = d->find_state == 1 ? 0 : d->find_state;
		}
	}
}

void ws_fd_fork_done(int child)
{
	if (child) {
		/* enumeration handles are process-local; rewind them in the child */
		for (int i = 0; i < fdt_cap; i++) {
			ws_desc *d = fdt[i].d;
			if (d && d->find && d->find != INVALID_HANDLE_VALUE) {
				d->find = NULL;
				d->find_state = 0;
				d->dir_pos = 0;
			}
		}
	}
	ReleaseSRWLockExclusive(&fdt_lock);
}

/* execve: the fds the new image would not have inherited */
void ws_fd_close_on_exec(void)
{
	for (int fd = 0;; fd++) {
		ws_desc *d = NULL;
		AcquireSRWLockExclusive(&fdt_lock);
		if (fd >= fdt_cap) {
			ReleaseSRWLockExclusive(&fdt_lock);
			break;
		}
		if (fdt[fd].d && fdt[fd].cloexec) {
			d = fdt[fd].d;
			fdt[fd].d = NULL;
		}
		ReleaseSRWLockExclusive(&fdt_lock);
		ws_desc_put(d);
	}
}

/* /proc/self/fd: the open fd numbers */
int ws_fd_list(void (*emit)(void *ctx, int fd), void *ctx)
{
	int n = 0;
	AcquireSRWLockShared(&fdt_lock);
	for (int i = 0; i < fdt_cap; i++)
		if (fdt[i].d) {
			emit(ctx, i);
			n++;
		}
	ReleaseSRWLockShared(&fdt_lock);
	return n;
}
