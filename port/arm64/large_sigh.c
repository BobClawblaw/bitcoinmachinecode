/* Large-tx repro for the ported legacy_sighash bug.
 *
 * The ported bitcoin_sighash.S legacy_sighash returns rc=0 (zero digest, never
 * writes out32) for txs with N inputs x non-empty scriptSigs once the tx grows
 * past ~28KB (threshold: synthetic 70-byte scriptSig fails for N>=255, passes
 * for N<=250; content-independent). Real trigger: mainnet block 29663's
 * 320-input consolidation -> every valid signature fails EVAL_FALSE.
 *
 * Diagnosis (gdb): the input-walk TX cursor misaligns on the early inputs
 * (parse_varint reads a scriptSig CONTENT byte, e.g. 0xAB=171, instead of the
 * script-len field because txcur starts 101 bytes too far forward) -> cumulative
 * overshoot until a `b.hi .ls_fail` (txcur > txend) fires and the digest is
 * never emitted. The cursor self-realigns late (inputs ~121+ parse len 70
 * correctly), but by then the accumulated overshoot already tripped the guard.
 * Crypto core is CORRECT: the ecdsa library validates the real block-29663
 * signature against the true SIGHASH_ALL digest.
 *
 * Build+run (port/arm64):
 *   gcc -no-pie -O2 -o /tmp/large_sigh large_sigh.c bitcoin_sighash.o bitcoin_hash.o sha256.o
 *   /tmp/large_sigh <N> <scriptSigLen>
 *   returns 1 + a nonzero hash  -> works
 *   returns 0 + all-zeros       -> BUG (N>=255 x 70B)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
extern int legacy_sighash(unsigned char out[32], const unsigned char* tx, unsigned long long txlen,
                          unsigned long long nIn, const unsigned char* sc, unsigned long long scl,
                          unsigned int ht, unsigned char* preimg, unsigned long long cap);
static void putvarint(unsigned char**pp, unsigned long long n){
    unsigned char*p=*pp;
    if(n<0xfd){ *p++=(unsigned char)n; }
    else if(n<=0xffff){ *p++=0xfd; *p++=n&0xff; *p++=(n>>8)&0xff; }
    else { *p++=0xfe; for(int i=0;i<4;i++){ *p++=(n>>(8*i))&0xff; } }
    *pp=p;
}
int main(int argc,char**argv){
    long N = argc>1? atol(argv[1]):320;
    long ss= argc>2? atol(argv[2]):70;
    static unsigned char tx[1<<20]; unsigned char* p=tx;
    *p++=0x01;*p++=0;*p++=0;*p++=0;                 /* version 1 */
    putvarint(&p,(unsigned long long)N);            /* n_in */
    for(long i=0;i<N;i++){
        memset(p,0x11,32); p+=32;                    /* prevout hash */
        *p++=1;*p++=0;*p++=0;*p++=0;                /* prevout index */
        putvarint(&p,(unsigned long long)ss);        /* scriptSig len */
        memset(p,0xAB,(size_t)ss); p+=ss;           /* scriptSig */
        *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;    /* sequence */
    }
    putvarint(&p,1);                                 /* n_out */
    unsigned char v[8]={0,0,0,0,0xf2,0x05,0x2a,0x01}; memcpy(p,v,8); p+=8; /* 50btc */
    *p++=0x19; memcpy(p,"\x76\xa9\x14" "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
                           "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11" "\x88\xac",25); p+=25;
    *p++=0;*p++=0;*p++=0;*p++=0;                    /* locktime */
    long txlen = (long)(p-tx);
    /* scriptPubKey: PUSHDATA65 uncompressed pubkey + OP_CHECKSIG */
    static unsigned char sc[67]; sc[0]=0x41; sc[1]=0x04;
    for(int i=0;i<64;i++) sc[2+i]=(unsigned char)(0x33+i);
    sc[66]=0xac;
    static unsigned char out[32], pre[1<<20];
    memset(out,0,32);
    int r=legacy_sighash(out, tx, txlen, 0, sc, 67, 1, pre, sizeof pre);
    int nonzero=0; for(int i=0;i<32;i++) if(out[i]) nonzero=1;
    printf("N=%ld ss=%ld txbytes=%ld rc=%d digest_nonzero=%d\n", N, ss, txlen, r, nonzero);
    for(int i=0;i<32;i++) printf("%02x",out[i]); printf("\n");
    return (r==1 && nonzero)?0:1;
}
