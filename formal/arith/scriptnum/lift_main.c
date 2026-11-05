/* Link anchor for the angr lift: a real executable around the assembled
 * bitcoin_scriptcodec.o, so its TLS relocations are resolved by the linker. */
#include <stdint.h>
extern int64_t scriptnum_decode(uint64_t len, const uint8_t* data, uint64_t maxsize);
int main(void){ uint8_t d[1] = {1}; return (int)scriptnum_decode(1, d, 4); }
