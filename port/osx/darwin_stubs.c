/* darwin_stubs.c -- Linux-only libc surface the daemon references, provided
 * at link time for the macOS port (bmc_osx).  Behaviour notes in
 * port/osx/compat/sys/prctl.h. */
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

/* malloc_info: glibc XML malloc-stat dump used by the "mallocinfo" RPC
 * debug mode.  macOS has no equivalent; return failure so the RPC reports
 * "malloc_info failed" -- the explicit-refusal convention. */
int malloc_info(int options, FILE* stream)
{ (void)options; (void)stream; return -1; }

int pthread_mutexattr_setrobust(pthread_mutexattr_t* attr, int robust)
{ (void)attr; (void)robust; return ENOTSUP; }   /* MEM-20: best-effort path */

int pthread_mutex_consistent(pthread_mutex_t* m)
{ (void)m; return 0; }                          /* unreachable: nothing is
                                                   ever made EOWNERDEAD */
