/* txv_rd_cs (asm/daemon/tx_verify.c): the block-connect and mempool
 * (tx_verify_mempool) transaction parser. */
#include <stdint.h>
#include <string.h>
typedef unsigned char u8; typedef unsigned long u64; typedef unsigned int u32;
#include "../gen/cs_tx_verify.inc"
static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used){
    const u8* p = b; int ok = 1; u64 x = txv_rd_cs(&p, end, &ok);
    *v = x; *used = (unsigned)(p - b); return ok;
}
#include "cs_check.h"
