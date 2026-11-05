/* Port of Bitcoin Core v31.1 serialize.h ReadCompactSize(is, range_check),
 * line for line. A stream holding `avail` bytes at p; a read past the end is
 * Core's std::ios_base::failure (end of data), like the non-canonical and
 * size-too-large throws. Returns 1 and sets *v, *used, or 0 for "throws".
 *
 *   serialize.h:330  uint8_t chSize = ser_readdata8(is);
 *   serialize.h:333  if (chSize < 253) nSizeRet = chSize;
 *   serialize.h:337  else if (chSize == 253) { nSizeRet = ser_readdata16(is);
 *                        if (nSizeRet < 253) throw non-canonical }
 *   serialize.h:343  else if (chSize == 254) { nSizeRet = ser_readdata32(is);
 *                        if (nSizeRet < 0x10000u) throw non-canonical }
 *   serialize.h:349  else { nSizeRet = ser_readdata64(is);
 *                        if (nSizeRet < 0x100000000ULL) throw non-canonical }
 *   serialize.h:356  if (range_check && nSizeRet > MAX_SIZE) throw size too large
 * MAX_SIZE = 0x02000000 (serialize.h:32). Every transaction and block field
 * (vector sizes, script lengths, witness stacks) uses range_check = true. */
#ifndef CORE_CS_H
#define CORE_CS_H
#include <stdint.h>
#define CORE_MAX_SIZE 0x02000000ULL
static int core_read_compact_size(const unsigned char* p, unsigned avail, int range_check,
                                  uint64_t* v, unsigned* used){
    if (avail < 1) return 0;
    uint8_t ch = p[0];
    uint64_t n;
    unsigned u;
    if (ch < 253) { n = ch; u = 1; }
    else if (ch == 253) {
        if (avail < 3) return 0;
        n = (uint64_t)p[1] | ((uint64_t)p[2] << 8); u = 3;
        if (n < 253) return 0;
    } else if (ch == 254) {
        if (avail < 5) return 0;
        n = 0; for (int i = 0; i < 4; i++) n |= (uint64_t)p[1+i] << (8*i); u = 5;
        if (n < 0x10000u) return 0;
    } else {
        if (avail < 9) return 0;
        n = 0; for (int i = 0; i < 8; i++) n |= (uint64_t)p[1+i] << (8*i); u = 9;
        if (n < 0x100000000ULL) return 0;
    }
    if (range_check && n > CORE_MAX_SIZE) return 0;
    *v = n; *used = u;
    return 1;
}
#endif
