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
	ws_free(r);
}

static i64 sys_mmap(char *addr, u64 len, int prot, int flags, int fd, i64 off)
{
	if (!len || (off & (PAGE - 1)) || off < 0)
		return -L_EINVAL;
	if (flags & (L_MAP_FIXED | L_MAP_FIXED_NOREPLACE)) {
		/* bmc does not place mappings; refuse rather than corrupt */
		(void)addr;
		return -L_EINVAL;
	}
	len = (len + PAGE - 1) & ~(PAGE - 1);
	int shared = (flags & 3) == L_MAP_SHARED || (flags & 3) == L_MAP_SHARED_VALIDATE;
	region *r = ws_alloc(sizeof *r);
	if (!r)
		return -L_ENOMEM;
	r->len = len;
	r->shared = shared;
	r->prot = prot;
	if ((flags & L_MAP_ANONYMOUS) && !shared) {
		r->kind = R_VA;
		r->base = VirtualAlloc(NULL, len, MEM_RESERVE | MEM_COMMIT, page_prot(prot, 0));
		if (!r->base) {
			ws_free(r);
			return -L_ENOMEM;
		}
		r->user = r->base;
		link_region(r);
		return (i64)r->user;
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
	case 149: case 150: case 151: case 152: case 325: return 0;   /* mlock family */
	default:
		*handled = 0;
		return 0;
	}
}
