/* txacc_varint (asm/daemon/tx_accept.c): mempool admission helpers. */
#include <stdint.h>
#include <string.h>
typedef unsigned char u8; typedef unsigned long u64;
#include "../gen/cs_tx_accept.inc"
static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used){
    const u8* p = b; u64 c = 0; u64 x = txacc_varint(&p, end, &c);
    *v = x; *used = (unsigned)c; return c != 0;
}
#include "cs_check.h"
