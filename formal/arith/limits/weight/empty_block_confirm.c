/* empty_block_confirm.c -- runs the REAL assembled cons_verify
 * (bitcoin_cons.o + bitcoin_hash.o + bitcoin_tx.o + sha256.o) on
 *   (A) a block with a valid-PoW header and a zero transaction count
 *       (82 bytes: header, CompactSize 0, one pad byte so the length floor
 *       is not what refuses it);
 *   (B) the same header shape with one coinbase and the correct merkle root
 *       (positive control: the harness can produce an accepted block).
 * Expected: A -> 0 (refused: Core's CheckBlock bad-blk-length on vtx.empty()),
 *           B -> 1. Exit 0 iff both hold. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern int  pow_check(const unsigned char hdr[80]);
extern void sha256d(unsigned char out[32], const void* msg, long len);
static unsigned char scratch[64 * 32];

static void grind(unsigned char* h){
    for (uint32_t n = 0;; n++){ memcpy(h + 76, &n, 4); if (pow_check(h)) return; }
}
static void header(unsigned char* h, const unsigned char root[32]){
    memset(h, 0, 80);
    h[0] = 1;                                   /* nVersion 1 */
    memcpy(h + 36, root, 32);
    uint32_t t = 1231006505u, bits = 0x207fffffu;
    memcpy(h + 68, &t, 4); memcpy(h + 72, &bits, 4);
    grind(h);
}
int main(void){
    int fails = 0;
    unsigned char a[82]; unsigned char zero[32] = {0};
    header(a, zero); a[80] = 0x00; a[81] = 0x00;
    int ra = cons_verify(a, sizeof a, scratch, 64);
    printf("A empty block (ntx=0): cons_verify=%d (expect 0)\n", ra);
    if (ra != 0) fails++;
    unsigned char tx[64]; int n = 0;
    tx[n++]=1; tx[n++]=0; tx[n++]=0; tx[n++]=0;     /* version */
    tx[n++]=1;                                       /* 1 input */
    memset(tx+n, 0, 32); n += 32;                    /* null prevout */
    tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff;
    tx[n++]=2; tx[n++]=0x51; tx[n++]=0x00;           /* scriptSig */
    tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff; tx[n++]=0xff;
    tx[n++]=1;                                       /* 1 output */
    memset(tx+n, 0, 8); n += 8;
    tx[n++]=1; tx[n++]=0x51;                         /* OP_TRUE */
    tx[n++]=0; tx[n++]=0; tx[n++]=0; tx[n++]=0;      /* locktime */
    unsigned char root[32]; sha256d(root, tx, n);
    unsigned char b[80 + 1 + 64];
    header(b, root); b[80] = 1; memcpy(b + 81, tx, n);
    int rb = cons_verify(b, 81 + n, scratch, 64);
    printf("B one coinbase:        cons_verify=%d (expect 1)\n", rb);
    if (rb != 1) fails++;
    return fails ? 1 : 0;
}
