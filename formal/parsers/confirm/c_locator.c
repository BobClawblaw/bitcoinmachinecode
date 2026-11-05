/* confirm X-LOC-canon on the compiled serve_invbounds.c: a getheaders whose
 * locator count is the non-canonical `fd 01 00` (1). Core's ReadCompactSize
 * throws "non-canonical ReadCompactSize()" and the message is dropped. */
#include <stdio.h>
#include <string.h>
int serve_locator_from(const unsigned char* pl, unsigned long plen, void* htidx, long* out_from, long* out_stop, unsigned char* out_stop_hash);
int idx_get(void* idx, const unsigned char hash[32], long* h){ (void)idx; if (hash[0] == 0xAB){ *h = 100; return 1; } return 0; }
long idxscan_tip(void){ return 0; }
int main(void){
    unsigned char pl[4 + 3 + 32 + 32]; memset(pl, 0, sizeof pl);
    pl[0] = 0x80; pl[1] = 0x11; pl[2] = 0x01;           /* nVersion 70016 */
    pl[4] = 0xfd; pl[5] = 0x01; pl[6] = 0x00;           /* count 1, 3-byte form */
    pl[7] = 0xAB;                                        /* a known locator hash */
    long from = -9, stop = -9; char idx; unsigned char sh[32];
    int r = serve_locator_from(pl, sizeof pl, &idx, &from, &stop, sh);
    printf("serve_locator_from(non-canonical count fd0100) = %d, from=%ld stop=%ld\n", r, from, stop);
    printf("%s\n", r == 1 ? "CONFIRMED: accepted (Core: non-canonical ReadCompactSize, message dropped)" : "not reproduced");
    return r == 1 ? 0 : 1;
}
