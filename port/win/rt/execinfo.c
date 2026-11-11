/* execinfo.c -- backtrace() for bmc_win (see include/execinfo.h). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern const char __ImageBase[];   /* the PE image (lld defines it) */

/* the executable's code range, from its PE headers */
static void text_range(uintptr_t *lo, uintptr_t *hi)
{
	const unsigned char *b = (const unsigned char *)__ImageBase;
	uint32_t pe = *(const uint32_t *)(b + 0x3c);
	const unsigned char *opt = b + pe + 24;
	uint32_t code_size = *(const uint32_t *)(opt + 4);
	uint32_t code_base = *(const uint32_t *)(opt + 20);
	*lo = (uintptr_t)b + code_base;
	*hi = *lo + code_size;
}

__attribute__((noinline)) int backtrace(void **buffer, int size)
{
	uintptr_t lo, hi;
	text_range(&lo, &hi);
	volatile uintptr_t marker = 0;
	uintptr_t *sp = (uintptr_t *)&marker;
	int n = 0;
	/* the frame's own return address first, then stack words in the code range */
	if (n < size)
		buffer[n++] = __builtin_return_address(0);
	for (int i = 0; i < 8192 && n < size; i++) {
		uintptr_t v = sp[i];
		if (v > lo && v < hi && v != (uintptr_t)buffer[n - 1])
			buffer[n++] = (void *)v;
	}
	return n;
}

static void fmt(char *out, size_t cap, void *a)
{
	snprintf(out, cap, "exe+0x%lx [%p]", (unsigned long)((uintptr_t)a - (uintptr_t)__ImageBase), a);
}

char **backtrace_symbols(void *const *buffer, int size)
{
	char **v = malloc((size_t)size * (sizeof(char *) + 48));
	if (!v)
		return NULL;
	char *s = (char *)(v + size);
	for (int i = 0; i < size; i++) {
		v[i] = s + 48 * i;
		fmt(v[i], 48, buffer[i]);
	}
	return v;
}

void backtrace_symbols_fd(void *const *buffer, int size, int fd)
{
	for (int i = 0; i < size; i++) {
		char line[64];
		fmt(line, sizeof line - 1, buffer[i]);
		size_t l = strlen(line);
		line[l] = '\n';
		(void)!write(fd, line, l + 1);
	}
}
