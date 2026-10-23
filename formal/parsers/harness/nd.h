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
#endif
