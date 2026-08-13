/* test_sha512.c -- verify the asm SHA-512 against published FIPS 180-4 vectors. */
#include <stdio.h>
#include <string.h>
extern void sha512_full(unsigned char out[64], const void* msg, long len);
static int failures=0;
static void hex(unsigned char* d,int n,char* o){for(int i=0;i<n;i++)sprintf(o+i*2,"%02x",d[i]);}
static void ck(const char* name,const char* msg,long len,const char* expect){
    unsigned char out[64]; char got[129];
    sha512_full(out,msg,len);
    hex(out,64,got);
    if(strcmp(got,expect)==0){printf("PASS %s\n",name);}
    else{printf("FAIL %s\ngot  %s\nexp  %s\n",name,got,expect);failures++;}
}
int main(void){
    ck("empty","",0,"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    ck("abc","abc",3,"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    ck("two-block","abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",112,
       "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    /* 1,000,000 x 'a' */
    {
        static char buf[1000000+200]; memset(buf,'a',1000000);
        ck("1M-a",buf,1000000,"e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    }
    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
