/* formal/parsers/harness/nd.h -- nondeterminism helpers shared by the CBMC
 * harnesses. Each harness #includes the product source under test (SRC, a
 * path given with -DSRC=...) so its static functions are visible; the
 * mutation runs pass a scratch copy of that source instead. */
#ifndef FP_ND_H
#define FP_ND_H
#include <stddef.h>
#include <stdint.h>
unsigned char      nondet_uchar(void);
unsigned short     nondet_ushort(void);
unsigned int       nondet_uint(void);
int                nondet_int(void);
long               nondet_long(void);
unsigned long      nondet_ulong(void);
unsigned long long nondet_ull(void);
size_t             nondet_size(void);
#define ASSUME(c) __CPROVER_assume(c)
#define CHECK(c, msg) __CPROVER_assert((c), msg)
/* reachability goals for the vacuity run (cbmc --cover cover): each must be
 * reported SATISFIED, which shows the assumptions admit that path */
#ifdef FP_COVER
#define COVER(c, msg) __CPROVER_cover(c)
#else
#define COVER(c, msg) ((void)0)
#endif
/* a malloc'd buffer of nondeterministic content, exactly `n` bytes long,
 * so any read past it is a --pointer-check / --bounds-check failure */
static inline unsigned char* nd_buf(size_t n){
    unsigned char* p = (unsigned char*)malloc(n ? n : 1);
    ASSUME(p != 0);
    return p;
}
/* `len` bytes of nondeterministic content that END exactly where a
 * constant-size (cap) object ends: a read past buf[len) leaves the object and
 * is caught, while the object's size stays concrete for the solver (a
 * symbolic-size malloc costs far more memory). Reads BEFORE the start are not
 * caught by this layout; no parser here ever reads before its input. The
 * caller frees nd_tail_base(p, len, cap). */
static inline unsigned char* nd_tail(size_t len, size_t cap){
    unsigned char* b = (unsigned char*)malloc(cap ? cap : 1); ASSUME(b != 0 && len <= cap);
    return b + (cap - len);
}
static inline void* nd_tail_base(unsigned char* p, size_t len, size_t cap){ return p - (cap - len); }
/* Core's ReadCompactSize canonical rule, used by postconditions */
static inline int fp_cs_canonical(const unsigned char* p, size_t len){
    if (len < 1) return 0;
    if (p[0] < 0xfd) return 1;
    if (p[0] == 0xfd){ if (len < 3) return 0; return ((unsigned)p[1] | ((unsigned)p[2] << 8)) >= 0xfd; }
    if (p[0] == 0xfe){ if (len < 5) return 0; unsigned long long v = 0; for (int i = 0; i < 4; i++) v |= (unsigned long long)p[1+i] << (8*i); return v > 0xffff; }
    if (len < 9) return 0;
    unsigned long long v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long long)p[1+i] << (8*i);
    return v > 0xffffffffULL;
}
/* libc functions CBMC 6.11 has no model for, written the way the C
 * standard specifies them (trusted) */
#include <string.h>
void* memchr(const void* s, int c, size_t n){
    const unsigned char* p = (const unsigned char*)s;
    for (size_t i = 0; i < n; i++) if (p[i] == (unsigned char)c) return (void*)(p + i);
    return 0;
}
int strncasecmp(const char* a, const char* b, size_t n){
    for (size_t i = 0; i < n; i++){
        int x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return x - y;
        if (!x) return 0;
    }
    return 0;
}
/* FP_STUB_PRINTF: CBMC's printf-family models are far over the memory cap in
 * these harnesses; where formatted text is only logged or echoed, the
 * harness stubs them: the output buffer gets a NUL (its first byte), the
 * return value is 0. Text content is then not under test. */
#ifdef FP_STUB_PRINTF
#include <stdio.h>
#include <stdarg.h>
int snprintf(char* s, size_t n, const char* f, ...){ (void)f; if (n) s[0] = 0; return 0; }
int vsnprintf(char* s, size_t n, const char* f, va_list ap){ (void)f; (void)ap; if (n) s[0] = 0; return 0; }
int fprintf(FILE* fp, const char* f, ...){ (void)fp; (void)f; return 0; }
int printf(const char* f, ...){ (void)f; return 0; }
#endif
#endif
