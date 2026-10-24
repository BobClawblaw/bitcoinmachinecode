/* test_bip32_master.c -- verify asm BIP32 master-key derivation against the
 * official BIP32 test vector 1. */
#include <stdio.h>
#include <string.h>
extern int bip32_master(unsigned char k[32], unsigned char c[32],
                        const unsigned char* seed, long seedlen);
/* -Wl,--wrap=hmac_sha512: the test can hand bip32_master a chosen digest */
static int g_forced = 0; static unsigned char g_digest[64];
extern void __real_hmac_sha512(unsigned char out[64], const unsigned char* key, long keylen, const unsigned char* msg, long msglen);
void __wrap_hmac_sha512(unsigned char out[64], const unsigned char* key, long keylen, const unsigned char* msg, long msglen){
    if (g_forced){ memcpy(out, g_digest, 64); return; }
    __real_hmac_sha512(out, key, keylen, msg, msglen);
}
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
    /* BIP32: "In case parse256(IL) is 0 or parse256(IL) >= n, the master key
     * is invalid." Only the zero case was refused; IL >= n has probability
     * ~2^-128, so the digest is forced through the HMAC wrap. */
    { static const unsigned char N[32] = {
          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
          0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41 };
      unsigned char k[32], c[32]; int r;
      g_forced = 1; memset(g_digest, 0x11, 64);
      memcpy(g_digest, N, 32);
      r = bip32_master(k, c, s1, 16);
      printf("%s IL == n is an invalid master key\n", r == 0 ? "PASS" : "FAIL"); if (r != 0) failures++;
      memset(g_digest, 0xff, 32);
      r = bip32_master(k, c, s1, 16);
      printf("%s IL == 2^256-1 is an invalid master key\n", r == 0 ? "PASS" : "FAIL"); if (r != 0) failures++;
      memset(g_digest, 0, 32);
      r = bip32_master(k, c, s1, 16);
      printf("%s IL == 0 is an invalid master key\n", r == 0 ? "PASS" : "FAIL"); if (r != 0) failures++;
      memcpy(g_digest, N, 32); g_digest[31] = 0x40;          /* n - 1 */
      r = bip32_master(k, c, s1, 16);
      printf("%s control: IL == n-1 is valid\n", r == 1 ? "PASS" : "FAIL"); if (r != 1) failures++;
      g_forced = 0;
      /* the range check itself, which bip32_ckd_priv and the xprv import
       * (rpc_wallet_ops.c) use too: k == n fell through its byte compare as
       * "less than" */
      extern int scalar_small_nonzero(const unsigned char k[32]);
      unsigned char t[32]; memcpy(t, N, 32);
      r = scalar_small_nonzero(t);
      printf("%s scalar_small_nonzero(n) == 0\n", r == 0 ? "PASS" : "FAIL"); if (r != 0) failures++;
      t[31] = 0x40; r = scalar_small_nonzero(t);
      printf("%s scalar_small_nonzero(n-1) == 1\n", r == 1 ? "PASS" : "FAIL"); if (r != 1) failures++;
      t[31] = 0x42; r = scalar_small_nonzero(t);
      printf("%s scalar_small_nonzero(n+1) == 0\n", r == 0 ? "PASS" : "FAIL"); if (r != 0) failures++; }
    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
