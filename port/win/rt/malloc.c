/* malloc.c -- the malloc family over the Win32 process heap (bmc_win).
 *
 * Every block carries a 16-byte header {raw pointer, requested size} right
 * below the user pointer, so over-aligned blocks (aligned_alloc et al.) and
 * plain ones free/realloc/size the same way. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <malloc.h>

__attribute__((ms_abi)) void *__bmc_win_heap_alloc(size_t, int);
__attribute__((ms_abi)) void *__bmc_win_heap_realloc(void *, size_t);
__attribute__((ms_abi)) void __bmc_win_heap_free(void *);

typedef struct { void *raw; size_t size; } hdr;
#define H(p) ((hdr *)(p) - 1)

static void *alloc_aligned(size_t n, size_t align, int zero)
{
	if (align < 16)
		align = 16;
	if (align & (align - 1)) {
		errno = EINVAL;
		return NULL;
	}
	if (n > SIZE_MAX - align - sizeof(hdr)) {
		errno = ENOMEM;
		return NULL;
	}
	char *raw = __bmc_win_heap_alloc(n + align + sizeof(hdr) - 16 + 16, zero);
	if (!raw) {
		errno = ENOMEM;
		return NULL;
	}
	uintptr_t u = ((uintptr_t)raw + sizeof(hdr) + align - 1) & ~(uintptr_t)(align - 1);
	H(u)->raw = raw;
	H(u)->size = n;
	return (void *)u;
}

void *malloc(size_t n) { return alloc_aligned(n, 16, 0); }

void *calloc(size_t m, size_t n)
{
	if (n && m > SIZE_MAX / n) {
		errno = ENOMEM;
		return NULL;
	}
	return alloc_aligned(m * n, 16, 1);
}

void free(void *p)
{
	if (p)
		__bmc_win_heap_free(H(p)->raw);
}

void *realloc(void *p, size_t n)
{
	if (!p)
		return malloc(n);
	hdr h = *H(p);
	if ((char *)p - (char *)h.raw == sizeof(hdr) && n <= SIZE_MAX - 64) {
		char *raw = __bmc_win_heap_realloc(h.raw, n + sizeof(hdr) + 16);
		if (!raw) {
			errno = ENOMEM;
			return NULL;
		}
		void *u = raw + sizeof(hdr);
		H(u)->raw = raw;
		H(u)->size = n;
		return u;
	}
	void *q = malloc(n);
	if (!q)
		return NULL;
	memcpy(q, p, h.size < n ? h.size : n);
	free(p);
	return q;
}

void *reallocarray(void *p, size_t m, size_t n)
{
	if (n && m > SIZE_MAX / n) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(p, m * n);
}

void *aligned_alloc(size_t align, size_t n) { return alloc_aligned(n, align, 0); }
void *memalign(size_t align, size_t n) { return alloc_aligned(n, align, 0); }
void *valloc(size_t n) { return alloc_aligned(n, 4096, 0); }
void *pvalloc(size_t n) { return alloc_aligned((n + 4095) & ~(size_t)4095, 4096, 0); }

int posix_memalign(void **res, size_t align, size_t n)
{
	if (align < sizeof(void *) || (align & (align - 1)))
		return EINVAL;
	void *p = alloc_aligned(n, align, 0);
	if (!p)
		return ENOMEM;
	*res = p;
	return 0;
}

size_t malloc_usable_size(void *p) { return p ? H(p)->size : 0; }

/* musl-internal spellings */
void *__libc_malloc(size_t n) { return malloc(n); }
void *__libc_malloc_impl(size_t n) { return malloc(n); }
void *__libc_calloc(size_t m, size_t n) { return calloc(m, n); }
void *__libc_realloc(void *p, size_t n) { return realloc(p, n); }
void __libc_free(void *p) { free(p); }
int __malloc_replaced;
int __aligned_alloc_replaced;
void __malloc_atfork(int who) { (void)who; }
void __malloc_donate(char *a, char *b) { (void)a; (void)b; }

/* glibc's mallinfo2: the process heap's committed and in-use bytes */
struct bmc_mallinfo2 { size_t arena, ordblks, smblks, hblks, hblkhd, usmblks, fsmblks, uordblks, fordblks, keepcost; };
__attribute__((ms_abi)) void __bmc_win_heap_stats(size_t *committed, size_t *allocated);

struct bmc_mallinfo2 mallinfo2(void)
{
	struct bmc_mallinfo2 m = { 0 };
	size_t c = 0, a = 0;
	__bmc_win_heap_stats(&c, &a);
	m.arena = c;
	m.uordblks = a;
	m.fordblks = c > a ? c - a : 0;
	return m;
}
