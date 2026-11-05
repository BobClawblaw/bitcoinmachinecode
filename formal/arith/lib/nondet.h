/* Shared declarations for the CBMC harnesses: CBMC treats a body-less
 * function returning a value as a fresh nondeterministic input. */
#ifndef ARITH_NONDET_H
#define ARITH_NONDET_H
unsigned char      nondet_u8(void);
unsigned int       nondet_u32(void);
unsigned long      nondet_u64(void);
long               nondet_long(void);
long long          nondet_ll(void);
int                nondet_int(void);
#define ASSUME(c) __CPROVER_assume(c)
#define CHECK(c, msg) __CPROVER_assert((c), msg)
#endif
