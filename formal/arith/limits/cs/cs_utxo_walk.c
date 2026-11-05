/* utxo_walk_read_varint (asm/daemon/utxo_walk.h): the block apply path's
 * reader (apply_block_inner's tx count, val_read_tx -> stripped size). */
#include <stdint.h>
#include <string.h>
typedef unsigned char u8; typedef unsigned long u64; typedef unsigned int u32;
#include "../gen/cs_utxo_walk.inc"
static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used){
    u64 c = 0; u64 r = utxo_walk_read_varint(b, end, &c);
    *v = r; *used = (unsigned)c; return c != 0;
}
#include "cs_check.h"
