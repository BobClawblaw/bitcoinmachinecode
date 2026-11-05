/* rd_cs (asm/daemon/signet_block.c): signet block-solution parser. */
#include <stdint.h>
#include <string.h>
typedef unsigned char u8; typedef unsigned long u64;
#include "../gen/cs_signet_block.inc"
static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used){
    const u8* p = b; u64 x = 0; int ok = rd_cs(&p, end, &x);
    *v = x; *used = (unsigned)(p - b); return ok;
}
#include "cs_check.h"
