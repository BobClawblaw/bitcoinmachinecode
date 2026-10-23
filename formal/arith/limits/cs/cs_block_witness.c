/* rd_varint (asm/daemon/block_witness.c): bw_walk_tx, the witness walk of
 * every block transaction (CON-4). */
#include <stdint.h>
#include <string.h>
typedef uint8_t u8; typedef uint64_t u64;
#include "../gen/cs_block_witness.inc"
static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used){
    u64 x = 0, u = 0; int ok = rd_varint(b, end, &x, &u);
    *v = x; *used = (unsigned)u; return ok;
}
#include "cs_check.h"
