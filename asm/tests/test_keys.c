/* test_keys.c -- verify asm scalar_to_pubkey against known secp256k1 pubkeys. */
#include <stdio.h>
#include <string.h>
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char k[32]);
extern int  scalar_small_nonzero(const unsigned char k[32]);
static int failures=0;
static void hx(unsigned char*d,int n){for(int i=0;i<n;i++)printf("%02x",d[i]);}
static void ck(const char*name,const char* khex,const char* pubhex){
    unsigned char k[32],pub[33],exp[33];
    for(int i=0;i<32;i++){unsigned v; sscanf(khex+i*2,"%2x",&v); k[i]=(unsigned char)v;}
    for(int i=0;i<33;i++){unsigned v; sscanf(pubhex+i*2,"%2x",&v); exp[i]=(unsigned char)v;}
    scalar_to_pubkey(pub,k);
    int ok=memcmp(pub,exp,33)==0;
    printf("%s %s\n", ok?"PASS":"FAIL", name);
    if(!ok){printf("  got ");hx(pub,33);printf("\n  exp ");hx(exp,33);printf("\n");failures++;}
}
int main(void){
    ck("G (k=1)","0000000000000000000000000000000000000000000000000000000000000001",
       "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    ck("bip32 master","e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
       "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
    /* scalar_small_nonzero checks */
    unsigned char z[32]={0};
    unsigned char one[32]={0}; one[31]=1;
    unsigned char nm[32]; memset(nm,0xff,32); /* n-? > n -> invalid (>= n since n starts 0xff..fe) */
    /* n-1 valid */
    unsigned char nm1[32]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
                           0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
                           0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40};
    printf("%s scalar nonzero: k=0 -> %d (exp 0)\n", scalar_small_nonzero(z)==0?"PASS":"FAIL", scalar_small_nonzero(z)); if(scalar_small_nonzero(z)!=0)failures++;
    printf("%s scalar nonzero: k=1 -> %d (exp 1)\n", scalar_small_nonzero(one)==1?"PASS":"FAIL", scalar_small_nonzero(one)); if(scalar_small_nonzero(one)!=1)failures++;
    printf("%s scalar nonzero: k=n-1 -> %d (exp 1)\n", scalar_small_nonzero(nm1)==1?"PASS":"FAIL", scalar_small_nonzero(nm1)); if(scalar_small_nonzero(nm1)!=1)failures++;
    printf("%s scalar nonzero: k>=n (0xff..) -> %d (exp 0)\n", scalar_small_nonzero(nm)==0?"PASS":"FAIL", scalar_small_nonzero(nm)); if(scalar_small_nonzero(nm)!=0)failures++;
    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
