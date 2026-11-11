/* ws_mem.c -- heap entry points and mmap/munmap/mremap/mprotect/madvise/msync
 * on Win32 (bmc_win).
 *
 * Regions are tracked so munmap can tell VirtualAlloc memory from file views.
 *   anonymous private  -> VirtualAlloc (partial munmap decommits)
 *   anonymous shared   -> pagefile-backed section + view (shareable later)
 *   file shared/private-> section on the file + view (FILE_MAP_COPY for private)
 * Windows maps views at 64 KiB granularity: an offset that is only page
 * aligned is mapped from the granule below and the pointer adjusted. A view
 * is only released once every byte of it has been munmapped. */
#include "winsys.h"
#include <psapi.h>

#define L_PROT_READ 1
#define L_PROT_WRITE 2
#define L_PROT_EXEC 4
#define L_MAP_SHARED 0x01
#define L_MAP_PRIVATE 0x02
#define L_MAP_SHARED_VALIDATE 0x03
#define L_MAP_FIXED 0x10
#define L_MAP_ANONYMOUS 0x20
#define L_MAP_FIXED_NOREPLACE 0x100000
#define PAGE 4096ULL

WSAPI void *__bmc_win_heap_alloc(size_t n, int zero)
{
	return HeapAlloc(GetProcessHeap(), zero ? HEAP_ZERO_MEMORY : 0, n ? n : 1);
}

WSAPI void *__bmc_win_heap_realloc(void *p, size_t n)
{
	return HeapReAlloc(GetProcessHeap(), 0, p, n ? n : 1);
}

WSAPI void __bmc_win_heap_free(void *p)
{
	if (p)
		HeapFree(GetProcessHeap(), 0, p);
}

WSAPI size_t __bmc_win_heap_size(void *p)
{
	return HeapSize(GetProcessHeap(), 0, p);
}

enum { R_VA = 1, R_VIEW = 2 };
typedef struct region {
	struct region *next;
	int kind;
	char *user;          /* address returned to the caller */
	char *base;          /* VirtualAlloc base / MapViewOfFile result */
	u64 len;             /* user length, page rounded */
	u64 unmapped;        /* bytes munmapped so far (views) */
	HANDLE section;      /* views: the section handle */
	HANDLE file;         /* file views: duplicated file handle, for msync */
	int shared, prot;
	i64 off;             /* file views: file offset of user */
	char *path;          /* file views: the file, POSIX form (for /proc/self/maps) */
	char name[64];       /* anonymous: the PR_SET_VMA_ANON_NAME name */
} region;

static region *regions;
static SRWLOCK reg_lock = SRWLOCK_INIT;

static region *find_region(char *p)
{
	for (region *r = regions; r; r = r->next)
		if (p >= r->user && p < r->user + r->len)
			return r;
	return NULL;
}

static DWORD page_prot(int prot, int copy)
{
	int w = (prot & L_PROT_WRITE) != 0, x = (prot & L_PROT_EXEC) != 0;
	if (!(prot & (L_PROT_READ | L_PROT_WRITE | L_PROT_EXEC)))
		return PAGE_NOACCESS;
	if (x)
		return w ? (copy ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE_READWRITE) : PAGE_EXECUTE_READ;
	return w ? (copy ? PAGE_WRITECOPY : PAGE_READWRITE) : PAGE_READONLY;
}

static void link_region(region *r)
{
	AcquireSRWLockExclusive(&reg_lock);
	r->next = regions;
	regions = r;
	ReleaseSRWLockExclusive(&reg_lock);
}

static void free_region(region *r)
{
	if (r->kind == R_VA) {
		VirtualFree(r->base, 0, MEM_RELEASE);
	} else {
		UnmapViewOfFile(r->base);
		CloseHandle(r->section);
		if (r->file)
			CloseHandle(r->file);
	}
	ws_free(r->path);
	ws_free(r);
}

/* ---- placeholders (Windows 10 1803+): what lets MAP_FIXED place a file
 * view inside memory we already handed out. Private anonymous regions are
 * reserved as a placeholder and committed into it, so they can later be
 * turned back into a placeholder, split at page granularity, and refilled. */
typedef PVOID (WINAPI *va2_fn)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
typedef PVOID (WINAPI *mv3_fn)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
static va2_fn va2;
static mv3_fn mv3;

static void ph_init(void)
{
	static volatile LONG done;
	if (InterlockedExchange(&done, 1))
		return;
	HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
	if (kb) {
		va2 = (va2_fn)(void *)GetProcAddress(kb, "VirtualAlloc2");
		mv3 = (mv3_fn)(void *)GetProcAddress(kb, "MapViewOfFile3");
	}
}

static char *va_commit(char *at, u64 len, int prot)
{
	if (!va2)
		return VirtualAlloc(at, len, MEM_RESERVE | MEM_COMMIT, page_prot(prot, 0));
	if (!at) {
		at = va2(NULL, NULL, len, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, NULL, 0);
		if (!at)
			return NULL;
	}
	char *p = va2(NULL, at, len, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, page_prot(prot, 0), NULL, 0);
	if (!p)
		VirtualFree(at, 0, MEM_RELEASE);
	return p;
}

/* MAP_FIXED of a file view at [addr, addr+len) inside a private anonymous
 * region: the region becomes [head][view][tail]. The head and tail read as
 * zero afterwards -- bmc maps over a region it has just created (utxo_live:
 * the table's header page is the file's first page), never over live data. */
static i64 map_fixed_view(char *addr, u64 len, int prot, HANDLE section, HANDLE file, i64 off, char *path)
{
	if (!va2 || !mv3 || (off & 0xffff))
		return -L_EINVAL;
	AcquireSRWLockExclusive(&reg_lock);
	region **pp = &regions, *r = NULL;
	for (; *pp; pp = &(*pp)->next)
		if (addr >= (*pp)->user && addr + len <= (*pp)->user + (*pp)->len && (*pp)->kind == R_VA) {
			r = *pp;
			break;
		}
	if (!r) {
		ReleaseSRWLockExclusive(&reg_lock);
		ws_free(path);
		return -L_EINVAL;
	}
	char *s = r->base, *e = r->base + r->len, *b = addr + len;
	if (!VirtualFree(s, (SIZE_T)r->len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) ||
	    (addr > s && !VirtualFree(s, (SIZE_T)(addr - s), MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) ||
	    (b < e && !VirtualFree(addr, (SIZE_T)len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER))) {
		ReleaseSRWLockExclusive(&reg_lock);
		return ws_err(GetLastError());
	}
	DWORD vp = (prot & L_PROT_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
	char *v = mv3(section, GetCurrentProcess(), addr, (ULONG64)off, (SIZE_T)len, MEM_REPLACE_PLACEHOLDER, vp, NULL, 0);
	char *h = addr > s ? va_commit(s, (u64)(addr - s), r->prot) : s;
	char *t = b < e ? va_commit(b, (u64)(e - b), r->prot) : b;
	if (!v || !h || !t) {
		ReleaseSRWLockExclusive(&reg_lock);
		return -L_ENOMEM;
	}
	*pp = r->next;                         /* replace r by its pieces */
	region *pieces[3] = { NULL, NULL, NULL };
	if (addr > s) {
		pieces[0] = ws_alloc(sizeof(region));
		*pieces[0] = *r;
		pieces[0]->base = pieces[0]->user = s;
		pieces[0]->len = (u64)(addr - s);
	}
	pieces[1] = ws_alloc(sizeof(region));
	pieces[1]->kind = R_VIEW;
	pieces[1]->base = pieces[1]->user = v;
	pieces[1]->len = len;
	pieces[1]->section = section;
	pieces[1]->file = file;
	pieces[1]->shared = 1;
	pieces[1]->prot = prot;
	pieces[1]->path = path;
	pieces[1]->off = off;
	if (b < e) {
		pieces[2] = ws_alloc(sizeof(region));
		*pieces[2] = *r;
		pieces[2]->base = pieces[2]->user = b;
		pieces[2]->len = (u64)(e - b);
	}
	for (int i = 0; i < 3; i++)
		if (pieces[i]) {
			pieces[i]->next = regions;
			regions = pieces[i];
		}
	ws_free(r);
	ReleaseSRWLockExclusive(&reg_lock);
	return (i64)addr;
}

static i64 sys_mmap(char *addr, u64 len, int prot, int flags, int fd, i64 off)
{
	if (!len || (off & (PAGE - 1)) || off < 0)
		return -L_EINVAL;
	ph_init();
	int fixed = (flags & (L_MAP_FIXED | L_MAP_FIXED_NOREPLACE)) != 0;
	if (fixed && ((u64)addr & (PAGE - 1)))
		return -L_EINVAL;
	len = (len + PAGE - 1) & ~(PAGE - 1);
	int shared = (flags & 3) == L_MAP_SHARED || (flags & 3) == L_MAP_SHARED_VALIDATE;
	if (fixed && ((flags & L_MAP_ANONYMOUS) || !shared))
		return -L_EINVAL;                  /* only the shared file view bmc places */
	region *r = ws_alloc(sizeof *r);
	if (!r)
		return -L_ENOMEM;
	r->len = len;
	r->shared = shared;
	r->prot = prot;
	if ((flags & L_MAP_ANONYMOUS) && !shared) {
		r->kind = R_VA;
		r->base = va_commit(NULL, len, prot);
		if (!r->base) {
			ws_free(r);
			return -L_ENOMEM;
		}
		r->user = r->base;
		link_region(r);
		return (i64)r->user;
	}
	if (fixed) {
		ws_desc *d = ws_fd_get(fd);
		if (!d || d->type != FT_FILE) {
			if (d)
				ws_desc_put(d);
			ws_free(r);
			return -L_EBADF;
		}
		if ((prot & L_PROT_WRITE) && !(d->flags & 3)) {
			ws_desc_put(d);
			ws_free(r);
			return -L_EACCES;
		}
		HANDLE sec = CreateFileMappingW(d->h, NULL, (prot & L_PROT_WRITE) ? PAGE_READWRITE : PAGE_READONLY, 0, 0,
						NULL);
		HANDLE file = NULL;
		DuplicateHandle(GetCurrentProcess(), d->h, GetCurrentProcess(), &file, 0, FALSE, DUPLICATE_SAME_ACCESS);
		char *path = d->wpath ? ws_path_to_posix(d->wpath) : NULL;
		ws_desc_put(d);
		ws_free(r);
		if (!sec) {
			if (file)
				CloseHandle(file);
			return ws_err(GetLastError());
		}
		i64 res = map_fixed_view(addr, len, prot, sec, file, off, path);
		if (res < 0) {
			CloseHandle(sec);
			if (file)
				CloseHandle(file);
		}
		return res;
	}
	r->kind = R_VIEW;
	DWORD acc;
	if (flags & L_MAP_ANONYMOUS) {
		r->section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, page_prot(prot | L_PROT_READ, 0),
						(DWORD)(len >> 32), (DWORD)len, NULL);
		if (!r->section) {
			ws_free(r);
			return -L_ENOMEM;
		}
		acc = (prot & L_PROT_WRITE) ? FILE_MAP_WRITE : FILE_MAP_READ;
		r->base = MapViewOfFile(r->section, acc, 0, 0, len);
		if (!r->base) {
			i64 e = ws_err(GetLastError());
			CloseHandle(r->section);
			ws_free(r);
			return e;
		}
		r->user = r->base;
		link_region(r);
		return (i64)r->user;
	}
	ws_desc *d = ws_fd_get(fd);
	if (!d) {
		ws_free(r);
		return -L_EBADF;
	}
	if (d->type != FT_FILE) {
		ws_desc_put(d);
		ws_free(r);
		return -L_ENODEV;
	}
	LARGE_INTEGER sz;
	if (!GetFileSizeEx(d->h, &sz)) {
		i64 e = ws_err(GetLastError());
		ws_desc_put(d);
		ws_free(r);
		return e;
	}
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	u64 gran = si.dwAllocationGranularity;
	u64 aoff = (u64)off & ~(gran - 1);
	u64 delta = (u64)off - aoff;
	u64 want = (u64)off + len;          /* end of the requested range */
	u64 fsz = (u64)sz.QuadPart;
	/* Linux maps past EOF (access faults); Windows would extend the file.
	 * Map at most to EOF; a mapping that starts at/after EOF is refused. */
	u64 end = want < fsz ? want : fsz;
	if (end <= (u64)off) {
		ws_desc_put(d);
		ws_free(r);
		return -L_ENXIO;
	}
	int copy = !shared && (prot & L_PROT_WRITE);
	DWORD sprot = copy ? PAGE_WRITECOPY : ((prot & L_PROT_WRITE) && (d->flags & 3) ? PAGE_READWRITE : PAGE_READONLY);
	if ((prot & L_PROT_WRITE) && shared && !(d->flags & 3)) {
		ws_desc_put(d);
		ws_free(r);
		return -L_EACCES;
	}
	r->section = CreateFileMappingW(d->h, NULL, sprot, 0, 0, NULL);
	if (!r->section) {
		i64 e = ws_err(GetLastError());
		ws_desc_put(d);
		ws_free(r);
		return e;
	}
	acc = copy ? FILE_MAP_COPY : ((prot & L_PROT_WRITE) ? FILE_MAP_WRITE : FILE_MAP_READ);
	r->base = MapViewOfFile(r->section, acc, (DWORD)(aoff >> 32), (DWORD)aoff, (SIZE_T)(end - aoff));
	if (!r->base) {
		i64 e = ws_err(GetLastError());
		CloseHandle(r->section);
		ws_desc_put(d);
		ws_free(r);
		return e;
	}
	DuplicateHandle(GetCurrentProcess(), d->h, GetCurrentProcess(), &r->file, 0, FALSE, DUPLICATE_SAME_ACCESS);
	r->path = d->wpath ? ws_path_to_posix(d->wpath) : NULL;
	r->off = off;
	ws_desc_put(d);
	r->user = r->base + delta;
	link_region(r);
	return (i64)r->user;
}

static i64 sys_munmap(char *addr, u64 len)
{
	if (((u64)addr & (PAGE - 1)) || !len)
		return -L_EINVAL;
	len = (len + PAGE - 1) & ~(PAGE - 1);
	AcquireSRWLockExclusive(&reg_lock);
	char *end = addr + len;
	region **pp = &regions;
	while (*pp) {
		region *r = *pp;
		char *rs = r->user, *re = r->user + r->len;
		if (re <= addr || rs >= end) {
			pp = &r->next;
			continue;
		}
		char *s = addr > rs ? addr : rs, *e = end < re ? end : re;
		if (s == rs && e == re) {
			*pp = r->next;
			free_region(r);
			continue;
		}
		if (r->kind == R_VA) {
			VirtualFree(s, (SIZE_T)(e - s), MEM_DECOMMIT);
		} else {
			r->unmapped += (u64)(e - s);
			if (r->unmapped >= r->len) {
				*pp = r->next;
				free_region(r);
				continue;
			}
		}
		pp = &r->next;
	}
	ReleaseSRWLockExclusive(&reg_lock);
	return 0;
}

static i64 sys_mremap(char *old, u64 oldlen, u64 newlen, int flags)
{
	if (!newlen)
		return -L_EINVAL;
	oldlen = (oldlen + PAGE - 1) & ~(PAGE - 1);
	newlen = (newlen + PAGE - 1) & ~(PAGE - 1);
	AcquireSRWLockShared(&reg_lock);
	region *r = find_region(old);
	int ok = r && r->user == old && r->kind == R_VA;
	int prot = r ? r->prot : 0;
	ReleaseSRWLockShared(&reg_lock);
	if (!ok)
		return -L_EINVAL;
	if (newlen <= oldlen) {
		if (newlen < oldlen)
			VirtualFree(old + newlen, (SIZE_T)(oldlen - newlen), MEM_DECOMMIT);
		return (i64)old;
	}
	if (!(flags & 1))                    /* MREMAP_MAYMOVE */
		return -L_ENOMEM;
	i64 n = sys_mmap(NULL, newlen, prot, L_MAP_PRIVATE | L_MAP_ANONYMOUS, -1, 0);
	if (n < 0 && n > -4096)
		return n;
	__ws_memcpy((void *)n, old, oldlen);
	sys_munmap(old, oldlen);
	return n;
}

static i64 sys_mprotect(char *addr, u64 len, int prot)
{
	DWORD oldp;
	AcquireSRWLockShared(&reg_lock);
	region *r = find_region(addr);
	int copy = r && r->kind == R_VIEW && !r->shared && r->file;
	ReleaseSRWLockShared(&reg_lock);
	if (!VirtualProtect(addr, (SIZE_T)len, page_prot(prot, copy), &oldp))
		return ws_err(GetLastError());
	return 0;
}

static i64 sys_madvise(char *addr, u64 len, int advice)
{
	if (advice != 4)                     /* only MADV_DONTNEED changes contents */
		return 0;
	AcquireSRWLockShared(&reg_lock);
	region *r = find_region(addr);
	int va = r && r->kind == R_VA;
	int prot = r ? r->prot : 0;
	ReleaseSRWLockShared(&reg_lock);
	if (va) {
		/* private anonymous pages read back as zero afterwards */
		len = (len + PAGE - 1) & ~(PAGE - 1);
		VirtualFree(addr, (SIZE_T)len, MEM_DECOMMIT);
		VirtualAlloc(addr, (SIZE_T)len, MEM_COMMIT, page_prot(prot, 0));
	}
	return 0;
}

static i64 sys_msync(char *addr, u64 len, int flags)
{
	if (!FlushViewOfFile(addr, (SIZE_T)len))
		return ws_err(GetLastError());
	if (flags & 4) {                     /* MS_SYNC */
		AcquireSRWLockShared(&reg_lock);
		region *r = find_region(addr);
		HANDLE f = r ? r->file : NULL;
		if (f)
			FlushFileBuffers(f);
		ReleaseSRWLockShared(&reg_lock);
	}
	return 0;
}

static i64 name_regions(char *a, u64 len, const char *name);

i64 ws_sys_mem(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	*handled = 1;
	switch (n) {
	case 9: return sys_mmap((char *)a1, (u64)a2, (int)a3, (int)a4, (int)a5, (i64)a6);
	case 11: return sys_munmap((char *)a1, (u64)a2);
	case 25: return sys_mremap((char *)a1, (u64)a2, (u64)a3, (int)a4);
	case 10: return sys_mprotect((char *)a1, (u64)a2, (int)a3);
	case 28: return sys_madvise((char *)a1, (u64)a2, (int)a3);
	case 26: return sys_msync((char *)a1, (u64)a2, (int)a3);
	case 12: return 0;                   /* brk: no program break; malloc is the heap */
	case 157:                            /* prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, a, len, name) */
		if (a1 != 0x53564d41 || a2 != 0) {
			*handled = 0;
			return 0;
		}
		return name_regions((char *)a3, (u64)a4, (const char *)a5);
	case 149: case 150: case 151: case 152: case 325: return 0;   /* mlock family */
	default:
		*handled = 0;
		return 0;
	}
}

/* ---- fork (ws_fork.c): views of sections are shared with the child
 * (MAP_SHARED stays shared), private memory is copied on write; the region
 * list's own handles must be inheritable to stay valid there ---- */
void ws_mem_fork_prepare(void)
{
	AcquireSRWLockExclusive(&reg_lock);
	for (region *r = regions; r; r = r->next) {
		if (r->section)
			SetHandleInformation(r->section, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
		if (r->file)
			SetHandleInformation(r->file, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	}
}

void ws_mem_fork_done(int child)
{
	(void)child;
	ReleaseSRWLockExclusive(&reg_lock);
}

WSAPI void __bmc_win_heap_stats(size_t *committed, size_t *allocated)
{
	HEAP_SUMMARY hs;
	__ws_memset(&hs, 0, sizeof hs);
	hs.cb = sizeof hs;
	if (HeapSummary(GetProcessHeap(), 0, &hs)) {
		*committed = hs.cbCommitted;
		*allocated = hs.cbAllocated;
	} else {
		*committed = *allocated = 0;
	}
}

/* PR_SET_VMA_ANON_NAME: name the anonymous regions in [a, a+len) */
static i64 name_regions(char *a, u64 len, const char *name)
{
	AcquireSRWLockExclusive(&reg_lock);
	int hit = 0;
	for (region *r = regions; r; r = r->next) {
		if (r->user + r->len <= a || r->user >= a + len || r->path)
			continue;
		size_t i = 0;
		for (; name && name[i] && i < sizeof r->name - 1; i++)
			r->name[i] = name[i];
		r->name[i] = 0;
		hit = 1;
	}
	ReleaseSRWLockExclusive(&reg_lock);
	return hit ? 0 : -L_EINVAL;
}

/* /proc/self/maps (smaps: 1 adds Size/Rss per region; smaps_rollup: 2) */
char *ws_mem_maps_text(u64 *len, int smaps)
{
	struct { char *p; u64 n, cap; } b = { 0 };
	AcquireSRWLockShared(&reg_lock);
	u64 total = 0, n = 0;
	for (region *r = regions; r; r = r->next)
		n++;
	region **v = ws_alloc(sizeof(region *) * (size_t)(n ? n : 1));
	n = 0;
	for (region *r = regions; r; r = r->next)
		v[n++] = r;
	for (u64 i = 1; i < n; i++)             /* by address, as the kernel lists them */
		for (u64 j = i; j > 0 && v[j - 1]->user > v[j]->user; j--) {
			region *t = v[j];
			v[j] = v[j - 1];
			v[j - 1] = t;
		}
	for (u64 i = 0; i < n && smaps != 2; i++) {
		region *r = v[i];
		ws_sbuf_hex(&b, (u64)r->user, 8);
		ws_sbuf_str(&b, "-");
		ws_sbuf_hex(&b, (u64)(r->user + r->len), 8);
		ws_sbuf_str(&b, (r->prot & L_PROT_READ) ? " r" : " -");
		ws_sbuf_str(&b, (r->prot & L_PROT_WRITE) ? "w" : "-");
		ws_sbuf_str(&b, (r->prot & L_PROT_EXEC) ? "x" : "-");
		ws_sbuf_str(&b, r->shared ? "s " : "p ");
		ws_sbuf_hex(&b, (u64)r->off, 8);
		ws_sbuf_str(&b, " 00:00 0");
		const char *col = r->path ? r->path : NULL;
		char nm[80];
		if (!col && r->name[0]) {
			size_t k = 0;
			const char *pre = "[anon:";
			for (; *pre; pre++)
				nm[k++] = *pre;
			for (const char *q = r->name; *q && k < sizeof nm - 2; q++)
				nm[k++] = *q;
			nm[k++] = ']';
			nm[k] = 0;
			col = nm;
		}
		if (col) {
			ws_sbuf_str(&b, "                          ");
			ws_sbuf_str(&b, col);
		}
		ws_sbuf_str(&b, "\n");
		if (smaps == 1) {
			ws_sbuf_str(&b, "Size:           ");
			ws_sbuf_dec(&b, r->len / 1024);
			ws_sbuf_str(&b, " kB\nRss:            ");
			ws_sbuf_dec(&b, r->len / 1024);
			ws_sbuf_str(&b, " kB\n");
		}
		total += r->len;
	}
	ReleaseSRWLockShared(&reg_lock);
	ws_free(v);
	if (smaps == 2) {
		PROCESS_MEMORY_COUNTERS pm;
		__ws_memset(&pm, 0, sizeof pm);
		pm.cb = sizeof pm;
		K32GetProcessMemoryInfo(GetCurrentProcess(), &pm, sizeof pm);
		ws_sbuf_str(&b, "00000000-ffffffff ---p 00000000 00:00 0                          [rollup]\nRss:            ");
		ws_sbuf_dec(&b, pm.WorkingSetSize / 1024);
		ws_sbuf_str(&b, " kB\nPss:            ");
		ws_sbuf_dec(&b, pm.WorkingSetSize / 1024);
		ws_sbuf_str(&b, " kB\nAnonymous:      ");
		ws_sbuf_dec(&b, pm.PagefileUsage / 1024);
		ws_sbuf_str(&b, " kB\n");
	}
	(void)total;
	if (!b.p)
		ws_sbuf_str(&b, "");
	*len = b.n;
	return b.p;
}
