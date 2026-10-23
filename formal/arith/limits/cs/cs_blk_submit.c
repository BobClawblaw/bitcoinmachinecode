/* bsub_varint (asm/daemon/blk_submit.c): submitblock pre-parse. */
#include <stdint.h>
#include <string.h>
typedef unsigned char u8; typedef unsigned long long u64;
#include "../gen/cs_blk_submit.inc"
static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used){
    u64 x = 0; u64 w = bsub_varint(b, end, &x);
    *v = x; *used = (unsigned)w; return w != 0;
}
#include "cs_check.h"
