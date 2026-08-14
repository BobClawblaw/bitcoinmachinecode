/* test_sighash.c -- verify asm sighash_all (legacy SIGHASH_ALL) against
 * independent Python-computed oracles. Two cases:
 *   case1: 1-in/1-out, target input 0, supplied 25-byte P2PKH script.
 *   case2: 2-in/1-out, target input 1; input 0 has a non-empty raw scriptSig
 *          the builder must correctly step over. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern int sighash_all(unsigned char out32[32], const unsigned char* tx,
                       unsigned long txlen, unsigned long input_index,
                       const unsigned char* script, unsigned long script_len,
                       unsigned char* preimg, unsigned long cap);

static int fails=0;
static void ck(const char* l, const unsigned char got[32], const char* hexexp){
    unsigned char ex[32];
    for(int i=0;i<32;i++){ unsigned int v; sscanf(hexexp+2*i,"%2x",&v); ex[i]=(unsigned char)v; }
    if(memcmp(got,ex,32)==0) printf("ok  : %s\n",l);
    else { printf("FAIL: %s\n",l); fails++; }
}

static unsigned char* put_varint(unsigned char* p, unsigned long n){
    if(n<0xfd){ *p++=(unsigned char)n; }
    else if(n<=0xffff){ *p++=0xfd; p[0]=n&0xff; p[1]=(n>>8)&0xff; p+=2; }
    else if(n<=0xffffffffUL){ *p++=0xfe; p[0]=n&0xff;p[1]=(n>>8)&0xff;p[2]=(n>>16)&0xff;p[3]=(n>>24)&0xff; p+=4; }
    else { *p++=0xff; for(int i=0;i<8;i++){ p[i]=(n>>(8*i))&0xff; } p+=8; }
    return p;
}

int main(void){
    static unsigned char preimg[4096], out[32];
    unsigned char* p;

    /* ---------------- case 1 ---------------- */
    {
        unsigned char tx[512]; p=tx;
        *p++=2;*p++=0;*p++=0;*p++=0;
        p=put_varint(p,1);
        for(int i=0;i<32;i++) *p++=0x11;
        *p++=1;*p++=0;*p++=0;*p++=0;
        p=put_varint(p,0);
        *p++=0xfe;*p++=0xff;*p++=0xff;*p++=0xff;
        p=put_varint(p,1);
        unsigned long long v=50000; for(int i=0;i<8;i++) *p++=(v>>(8*i))&0xff;
        p=put_varint(p,25);
        *p++=0x76;*p++=0xa9;*p++=0x14; for(int i=0;i<20;i++) *p++=0x33; *p++=0x88;*p++=0xac;
        *p++=0;*p++=0;*p++=0;*p++=0;
        unsigned long txlen=(unsigned long)(p-tx);
        unsigned char script[25]; unsigned char* q=script;
        *q++=0x76;*q++=0xa9;*q++=0x14; for(int i=0;i<20;i++) *q++=0x44; *q++=0x88;*q++=0xac;
        int r = sighash_all(out, tx, txlen, 0, script, 25, preimg, sizeof preimg);
        ck(r?"case1 r=1":"case1 r=0", out, "6cb449d7e6a1e3b260acd0fd6714e2035ed86c9ea86b0ee88ef2376faa96ef6a");
    }

    /* ---------------- case 2 ---------------- */
    {
        unsigned char tx2[512]; p=tx2;
        *p++=1;*p++=0;*p++=0;*p++=0;
        p=put_varint(p,2);
        for(int i=0;i<32;i++) *p++=0xab;
        *p++=0;*p++=0;*p++=0;*p++=0;
        p=put_varint(p,3); *p++=0x01;*p++=0x02;*p++=0x03;
        *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;
        for(int i=0;i<32;i++) *p++=0xcd;
        *p++=7;*p++=0;*p++=0;*p++=0;
        p=put_varint(p,0);
        *p++=0xfe;*p++=0xff;*p++=0xff;*p++=0xff;
        p=put_varint(p,1);
        unsigned long long v=999; for(int i=0;i<8;i++) *p++=(v>>(8*i))&0xff;
        p=put_varint(p,5); *p++=0x51;*p++=0x52;*p++=0x53;*p++=0x54;*p++=0x55;
        *p++=9;*p++=0;*p++=0;*p++=0;
        unsigned long txlen2=(unsigned long)(p-tx2);
        unsigned char s2[5]={0x51,0x52,0x53,0x54,0x55};
        int r2 = sighash_all(out, tx2, txlen2, 1, s2, 5, preimg, sizeof preimg);
        ck(r2?"case2 r=1":"case2 r=0", out, "ac793e7284b03ae7d489a3b7ae45983c6bf8afebab6cf6d7535aa99a8873eefe");
    }

    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
