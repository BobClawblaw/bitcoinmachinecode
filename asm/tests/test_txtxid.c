#include <stdio.h>
#include <string.h>
extern int tx_txid(unsigned char out[32], const unsigned char* tx, unsigned long txlen, unsigned char* buf, unsigned long buflen);
int main(){
    /* same synthetic tx as probe_tx.py (64 bytes) */
    unsigned char tx[64];
    tx[0]=1;tx[1]=0;tx[2]=0;tx[3]=0;           /* version 1 */
    tx[4]=1;                                   /* 1 input */
    memset(tx+5,0,36);                         /* prevout null + index 4 */
    tx[41]=3; tx[42]=1;tx[43]=2;tx[44]=3;      /* scriptSig len 3 + 3 bytes */
    tx[45]=0xff;tx[46]=0xff;tx[47]=0xff;tx[48]=0xff; /* sequence */
    tx[49]=1;                                  /* 1 output */
    tx[50]=0xe8;tx[51]=0x03;tx[52]=0;tx[53]=0;tx[54]=0;tx[55]=0;tx[56]=0;tx[57]=0; /* value 1000 */
    tx[58]=1; tx[59]=0x51;                     /* script len 1 + PUSH1 */
    tx[60]=0;tx[61]=0;tx[62]=0;tx[63]=0;       /* locktime */
    unsigned char out[32], buf[512];
    int r = tx_txid(out, tx, 64, buf, sizeof buf);
    printf("tx_txid valid=%d\n", r);
    for(int i=0;i<8;i++) printf("%02x", out[i]);
    printf("...\n");
    /* a valid 1-in/1-out legacy tx MUST parse */
    if(r!=1){ printf("FAIL: tx_txid rejected a valid tx\n"); return 1; }
    /* txid must equal sha256d(raw) for a legacy tx (no witness) */
    unsigned char want[32];
    { /* sha256d of the 64 bytes */
        /* use sha256 twice through the asm one-shot? we'll compute via sha256d */
        extern void sha256d(unsigned char out[32], const unsigned char* in, unsigned long len);
        sha256d(want, tx, 64);
    }
    if(memcmp(out, want, 32)!=0){ printf("FAIL: txid != sha256d(raw)\n"); return 1; }
    printf("tx_txid matches sha256d(raw) for legacy tx\n");
    return 0;
}
