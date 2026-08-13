/* test_bip32_master.c -- verify asm BIP32 master-key derivation against the
 * official BIP32 test vector 1. */
#include <stdio.h>
#include <string.h>
extern int bip32_master(unsigned char k[32], unsigned char c[32],
                        const unsigned char* seed, long seedlen);
static int failures=0;
static void hx(unsigned char*d,int n){for(int i=0;i<n;i++)printf("%02x",d[i]);}
static void ck(const char* name,const unsigned char* seed,long sl,const char* ek,const char* ec){
    unsigned char k[32],c[32];
    int r=bip32_master(k,c,seed,sl);
    unsigned char kg[32],cg[32];
    for(int i=0;i<32;i++)sscanf(ek+i*2,"%2x",(unsigned*)&kg[i]);
    for(int i=0;i<32;i++)sscanf(ec+i*2,"%2x",(unsigned*)&cg[i]);
    int ok = r==1 && memcmp(k,kg,32)==0 && memcmp(c,cg,32)==0;
    printf("%s %s\n", ok?"PASS":"FAIL", name);
    if(!ok){ printf("  k got "); hx(k,32); printf("\n  k exp "); hx(kg,32); printf("\n  c got "); hx(c,32); printf("\n  c exp "); hx(cg,32); printf("\n"); failures++; }
}
int main(void){
    /* BIP32 test vector 1, seed 000102...0f */
    unsigned char s1[16]; for(int i=0;i<16;i++) s1[i]=i;
    ck("vector1 master", s1,16,
       "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
       "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
