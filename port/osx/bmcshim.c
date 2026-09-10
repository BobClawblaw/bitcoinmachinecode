/* bmcshim.c -- C shims for syscalls with no Darwin twin (strategy doc:
 * "_bmcshim_* only where no Darwin twin exists, each shim noted"). */
#include <stdlib.h>
#include <stdint.h>

/* Linux getrandom(2) (bitcoin_serve's cmpct nonce): arc4random_buf fills
 * without a syscall and never fails. */
void bmcshim_getrandom(void* buf, unsigned long long n)   /* Mach-O: _bmcshim_getrandom */
{ arc4random_buf(buf, n); }
