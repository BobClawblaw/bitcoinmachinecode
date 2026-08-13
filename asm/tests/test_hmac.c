/* test_hmac.c -- verify asm HMAC-SHA512 against RFC 4231 test vectors. */
#include <stdio.h>
#include <string.h>
extern void hmac_sha512(unsigned char out[64], const unsigned char* key, long keylen,
                        const unsigned char* msg, long msglen);
static int failures=0;
static void hex(unsigned char*d,int n,char*o){for(int i=0;i<n;i++)sprintf(o+i*2,"%02x",d[i]);}
static void ck(const char* name,const unsigned char* key,long kl,const unsigned char* msg,long ml,const char* expect){
    unsigned char out[64]; char got[129];
    hmac_sha512(out,key,kl,msg,ml);
    hex(out,64,got);
    if(strcmp(got,expect)==0){printf("PASS %s\n",name);}
    else{printf("FAIL %s\ngot %s\nexp %s\n",name,got,expect);failures++;}
}
int main(void){
    /* RFC 4231 test case 1: key=0x0b*20, msg="Hi There" */
    unsigned char k1[20]; memset(k1,0x0b,20);
    ck("tc1", k1,20,(const unsigned char*)"Hi There",8,
       "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    /* RFC 4231 test case 2: key="Jefe", msg="what do ya want for nothing?" */
    ck("tc2",(const unsigned char*)"Jefe",4,(const unsigned char*)"what do ya want for nothing?",28,
       "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
    /* RFC 4231 test case 3: key=0xaa*20, msg=0xdd*50 */
    unsigned char k3[20]; memset(k3,0xaa,20);
    unsigned char m3[50]; memset(m3,0xdd,50);
    ck("tc3", k3,20,m3,50,
       "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
