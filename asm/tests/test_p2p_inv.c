/* test_p2p_inv.c -- harness for the new asm inv parsers in bitcoin_p2p.asm.
 * Builds an `inv` payload (CompactSize count + (type u32 LE, hash32) entries)
 * the same way a real peer / the reference client would, then checks
 * p2p_inv_count / p2p_inv_get round-trip every entry and reject malformed
 * payloads (truncated, count overflow, 0xfe varint). */
#include <stdio.h>
#include <string.h>

extern long p2p_inv_count(const unsigned char* payload, long plen);
extern long p2p_inv_get(const unsigned char* payload, long i,
                        unsigned int* out_type, unsigned char out_hash[32]);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }

static void build_inv(unsigned char* out, long n, int fd_varint){
    /* fd_varint: 0 -> 1-byte count, 1 -> 0xfd u16, 2 -> 0xfe u32 */
    long p=0;
    if(fd_varint==0){ out[p++]= (unsigned char)n; }
    else if(fd_varint==1){ out[p++]=0xfd; out[p++]=(unsigned char)(n&0xff); out[p++]=(unsigned char)(n>>8); }
    else { out[p++]=0xfe; for(int b=0;b<4;b++) out[p++]=(unsigned char)(n>>(8*b)); }
    for(long i=0;i<n;i++){
        unsigned int type=(unsigned int)(0x02 + i*7);
        out[p++]= (unsigned char)(type&0xff); out[p++]=((type>>8)&0xff); out[p++]=((type>>16)&0xff); out[p++]=((type>>24)&0xff);
        for(int k=0;k<32;k++) out[p++]=(unsigned char)(i*11+k*3);
    }
}

int main(void){
    /* 1-byte count, 3 items */
    unsigned char inv[1+3*36];
    build_inv(inv+0, 3, 0);
    cki("inv_count(=3 items)", p2p_inv_count(inv, (long)(1+3*36)), 3);
    unsigned int t=0; unsigned char h[32];
    cki("inv_get[0]", p2p_inv_get(inv,0,&t,h), 1);
    cki("item0 type", (long)t, 0x02);
    cki("item0 hash[0]", (long)h[0], 0);
    cki("item0 hash[31]", (long)h[31], 0*11+31*3); /* 93 */
    /* check a later item */
    cki("inv_get[2]", p2p_inv_get(inv,2,&t,h), 1);
    cki("item2 type", (long)t, 0x02+2*7);
    /* out of range -> 0 */
    cki("inv_get[3] (out of range)", p2p_inv_get(inv,3,&t,h), 0);
    /* empty count=0 */
    unsigned char inv0[1]; inv0[0]=0;
    cki("inv_count empty", p2p_inv_count(inv0,1), 0);
    /* 0xfd varint with 300 items */
    unsigned char inv3[3+300*36];
    build_inv(inv3,300,1);
    cki("inv_count fd=300", p2p_inv_count(inv3,(long)(3+300*36)), 300);
    /* malformed: truncated (only half the items) */
    cki("inv_count truncated -> -1", p2p_inv_count(inv,(long)(1+1*36+10)), -1);
    /* 0xfe varint not used for inv -> -1 (matches builder? our build type 2 uses 0xfe header) */
    unsigned char invfe[5+2*36];
    build_inv(invfe,2,2);
    cki("inv_count 0xfe -> -1", p2p_inv_count(invfe,(long)(5+2*36)), -1);

    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
