/* rd_varint (asm/bitcoin_mempool_policy.c): mempool parse_tx. */
#include <stdint.h>
#include <string.h>
typedef unsigned char u8;
#include "../gen/cs_mempool_policy.inc"
static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used){
    const unsigned char* p = b; int ok = 0; uint64_t x = rd_varint(&p, end, &ok);
    *v = x; *used = (unsigned)(p - b); return ok;
}
#include "cs_check.h"
