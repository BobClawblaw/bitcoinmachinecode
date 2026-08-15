/* repro_sighash_oob.c -- demonstrate the legacy sighash_all source-bounds gap.
 * Craft a tx whose scriptSig length varint overruns the tx buffer. A correct
 * builder must reject it (return 0). A buggy one reads OOB and returns 1.
 */
#include <stdio.h>
#include <string.h>

extern int sighash_all(unsigned char out32[32], const unsigned char* tx,
                       unsigned long txlen, unsigned long input_index,
                       const unsigned char* script, unsigned long script_len,
                       unsigned char* preimg, unsigned long cap);

static unsigned char* put_varint(unsigned char* p, unsigned long n){
    if(n<0xfd){ *p++=(unsigned char)n; }
    else if(n<=0xffff){ *p++=0xfd; p[0]=n&0xff; p[1]=(n>>8)&0xff; p+=2; }
    else if(n<=0xffffffffUL){ *p++=0xfe; p[0]=n&0xff;p[1]=(n>>8)&0xff;p[2]=(n>>16)&0xff;p[3]=(n>>24)&0xff; p+=4; }
    else { *p++=0xff; for(int i=0;i<8;i++){ p[i]=(n>>(8*i))&0xff; } p+=8; }
    return p;
}

int main(void){
    static unsigned char tx[256];
    static unsigned char preimg[4096], out[32];
    unsigned char* p = tx;

    /* version */
    *p++=2;*p++=0;*p++=0;*p++=0;
    /* n_in = 1 */
    p=put_varint(p,1);
    /* prevout(32) + index(4) */
    for(int i=0;i<32;i++) *p++=0x22;
    *p++=0;*p++=0;*p++=0;*p++=0;
    /* scriptSig: length varint = 200 (overruns the 256-byte tx buffer hard) */
    p=put_varint(p,200);
    /* only 4 bytes of script actually present before tx ends */
    for(int i=0;i<4;i++) *p++=0x01;
    /* tx buffer ends here -> scriptSig len 200 reads past tx[] */
    unsigned long txlen = (unsigned long)(p - tx);

    /* script (signing) = 1-op dummy */
    unsigned char script[1] = {0x51};

    int r = sighash_all(out, tx, txlen, 0, script, 1, preimg, sizeof preimg);
    if (r == 0) { printf("PASS: OOB scriptSig overrun rejected (r=0)\n"); return 0; }
    printf("FAIL: OOB scriptSig overrun accepted (r=%d) -- OOB source read!\n", r);
    return 1;
}
