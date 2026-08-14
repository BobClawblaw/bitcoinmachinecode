/* test_bip32_chain.c -- verify asm BIP32 master + CKDpriv against the official
 * BIP32 test vector 1, walking the full chain m -> m/0' -> ... -> m/0'/1/2'/2/1000000000.
 * Each step checks both child key k and child chain code c byte-exact. */
#include <stdio.h>
#include <string.h>
extern int bip32_master(unsigned char k[32], unsigned char c[32], const unsigned char* seed, long seedlen);
extern int bip32_ckd_priv(unsigned char k[32], unsigned char c[32],
                          const unsigned char* kpar, const unsigned char* cpar, unsigned index);
static int failures=0;
static void hx(unsigned char*d,int n){for(int i=0;i<n;i++)printf("%02x",d[i]);}
static void ck(const char* name,const unsigned char*k,const unsigned char*c,const char* ek,const char* ec){
    unsigned char ekb[32],ecb[32]; int ok=1;
    for(int i=0;i<32;i++){unsigned v;sscanf(ek+i*2,"%2x",&v);ekb[i]=(unsigned char)v;}
    for(int i=0;i<32;i++){unsigned v;sscanf(ec+i*2,"%2x",&v);ecb[i]=(unsigned char)v;}
    if(memcmp(k,ekb,32)!=0||memcmp(c,ecb,32)!=0)ok=0;
    printf("%s %s\n",ok?"PASS":"FAIL",name);
    if(!ok){printf("  k got ");hx(k,32);printf("\n  k exp ");hx(ekb,32);printf("\n  c got ");hx(c,32);printf("\n  c exp ");hx(ecb,32);printf("\n");failures++;}
}
int main(void){
    unsigned char seed[16]; for(int i=0;i<16;i++)seed[i]=(unsigned char)i;
    unsigned char k[32],c[32];
    if(bip32_master(k,c,seed,16)!=1){ printf("FAIL master return\n"); return 1; }
    ck("m (master)", k,c,
       "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
       "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    /* m/0'  (hardened) */
    unsigned char k2[32],c2[32];
    if(bip32_ckd_priv(k2,c2,k,c,0x80000000)!=1){ printf("FAIL m/0' return\n"); return 1; }
    ck("m/0' (hardened)", k2,c2,
       "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
       "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
    /* m/0'/1  (normal) */
    if(bip32_ckd_priv(k,c,k2,c2,1)!=1){ printf("FAIL m/0'/1 return\n"); return 1; }
    ck("m/0'/1 (normal)", k,c,
       "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
       "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19");
    /* m/0'/1/2'  (hardened) */
    if(bip32_ckd_priv(k2,c2,k,c,0x80000002)!=1){ printf("FAIL m/0'/1/2' return\n"); return 1; }
    ck("m/0'/1/2' (hardened)", k2,c2,
       "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
       "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f");
    /* m/0'/1/2'/2  (normal) */
    if(bip32_ckd_priv(k,c,k2,c2,2)!=1){ printf("FAIL m/0'/1/2'/2 return\n"); return 1; }
    ck("m/0'/1/2'/2 (normal)", k,c,
       "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
       "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd");
    /* m/0'/1/2'/2/1000000000  (normal) */
    if(bip32_ckd_priv(k2,c2,k,c,1000000000u)!=1){ printf("FAIL m/0'/1/2'/2/1e9 return\n"); return 1; }
    ck("m/0'/1/2'/2/1000000000", k2,c2,
       "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
       "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e");

    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
