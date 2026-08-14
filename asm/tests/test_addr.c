/* test_addr.c -- verify asm hash160 + base58check P2PKH address generation
 * against known reference addresses (pycryptodome / standard Bitcoin values).
 * All buffers are static to avoid -O0 stack-frame layout interactions. */
#include <stdio.h>
#include <string.h>
extern void hash160(unsigned char out[20], const void* in, long long len);
extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);
static int failures=0;

static void ck_hash160(const char* name, const void* in, long long len, const char* exp, int fail){
    unsigned char d[20]; int ok=1;
    hash160(d,in,len);
    for(int i=0;i<20;i++){unsigned v;sscanf(exp+i*2,"%2x",&v);if(d[i]!=(unsigned char)v)ok=0;}
    printf("%s %s\n",ok?"PASS":"FAIL",name);
    if(!ok && fail){failures++;}
}
static void ck_addr(const char* name, const unsigned char* payload, long long paylen, const char* exp, int fail){
    static char buf[64];
    base58check_encode(buf,payload,paylen);
    if(strcmp(buf,exp)!=0){ printf("%s FAIL\n  got %s\n  exp %s\n",name,buf,exp); if(fail)failures++; }
    else printf("%s PASS\n",name);
}
static unsigned char GK[33];
static unsigned char WIKI[33];
static unsigned char GBP[21], WIKIP[21];
int main(void){
    /* HASH160 = RIPEMD160(SHA256(x)) */
    ck_hash160("h160(hello world)","hello world",11,"d7d5ee7824ff93f94c3055af9382c86c68b5ca92",1); /* informational */
    /* G compressed pubkey */
    static const unsigned char g[33]={0x02,0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98};
    memcpy(GK,g,33);
    ck_hash160("h160(G)",GK,33,"751e76e8199196d454941c45d1b3a323f1433bd6",1);
    /* base58check all-zero payload -> canonical address */
    { static unsigned char zeb[21]={0}; ck_addr("b58(zero21)",zeb,21,"1111111111111111111114oLvT2",1); }
    /* P2PKH of G pubkey */
    hash160(GBP+1,GK,33); GBP[0]=0x00;
    ck_addr("addr(G)",GBP,21,"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",1);
    /* P2PKH of the Bitcoin-wiki pubkey -> 1PMycacn... */
    static const unsigned char w[33]={0x02,0x02,0xa4,0x06,0x62,0x42,0x11,0xf2,0xab,0xbd,0xc6,0x8d,0xa3,0xdf,0x92,0x9f,0x93,0x8c,0x33,0x99,0xdd,0x79,0xfa,0xc1,0xb5,0x1b,0x0e,0x4a,0xd1,0xd2,0x6a,0x47,0xaa};
    memcpy(WIKI,w,33);
    hash160(WIKIP+1,WIKI,33); WIKIP[0]=0x00;
    ck_addr("addr(wiki)",WIKIP,21,"1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK",1);
    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
