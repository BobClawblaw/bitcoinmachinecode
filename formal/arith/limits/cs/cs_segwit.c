/* read_cs (asm/bitcoin_segwit.c): BIP143/segwit tx walker. */
#include <stdint.h>
#include <string.h>
typedef unsigned char u8;
#include "../gen/cs_segwit.inc"
static int bmc_rd(const u8* b, const u8* end, uint64_t* v, unsigned* used){
    const uint8_t* p = b; int ok = 1; uint64_t x = read_cs(&p, end, &ok);
    *v = x; *used = (unsigned)(p - b); return ok;
}
#include "cs_check.h"
