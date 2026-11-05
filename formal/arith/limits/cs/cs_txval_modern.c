/* rd_cs (asm/bitcoin_txval_modern.c): mempool modern-output validator. */
#include <stdint.h>
#include <string.h>
typedef unsigned char u8;
#include "../gen/cs_txval_modern.inc"
static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used){
    const uint8_t* p = b; int ok = 1; uint64_t x = rd_cs(&p, end, &ok);
    *v = x; *used = (unsigned)(p - b); return ok;
}
#include "cs_check.h"
