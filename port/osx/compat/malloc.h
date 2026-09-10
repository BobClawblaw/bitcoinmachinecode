/* malloc.h -- Darwin stand-in for the osx port.  rpc_commands.c includes
 * <malloc.h> (a glibc-ism); everything it needs is <stdlib.h>, and the one
 * getrandom call in the file maps to arc4random_buf. */
#ifndef BMC_DARWIN_MALLOC_H
#define BMC_DARWIN_MALLOC_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

/* glibc declares this in <malloc.h>; the implementation is the failure stub
 * in port/osx/darwin_stubs.c (no macOS equivalent -- the RPC refuses). */
int malloc_info(int options, FILE* stream);

/* Linux getrandom(2) -> arc4random_buf (CSPRNG, no fd, no EINTR) */
static inline long bmc_getrandom_shim(void* buf, size_t n, unsigned flags)
{ (void)flags; arc4random_buf(buf, n); return (long)n; }
#define getrandom(buf, n, fl) bmc_getrandom_shim((buf), (n), (fl))

#endif
