/* test_ripemd160.c -- verify asm RIPEMD-160 against the standard test vectors
 * and length-boundary cases, digests cross-checked against hashlib ripemd160. */
#include <stdio.h>
#include <string.h>
extern void ripemd160(unsigned char out[20], const void* in, long long len);
static int failures=0;
static void r(const char*name,const void*in_v,long long len,const char*exp){
    const unsigned char* in=(const unsigned char*)in_v;   /* vectors are C strings or byte buffers; the hash sees bytes */
    unsigned char d[20]; int ok=1;
    ripemd160(d,in,len);
    for(int i=0;i<20;i++){unsigned v;sscanf(exp+i*2,"%2x",&v);if(d[i]!=(unsigned char)v)ok=0;}
    printf("%s %s\n",ok?"PASS":"FAIL",name);
    if(!ok){printf("  got ");for(int i=0;i<20;i++)printf("%02x",d[i]);printf("\n  exp %s\n",exp);failures++;}
}
int main(void){
    r("empty","\0",0,"9c1185a5c5e9fc54612808977ee8f548b2258d31");
    r("abc","abc",3,"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    r("msg digest","message digest",14,"5d0689ef49d2fae572b881b123a85ffa21595f36");
    r("alphabet","abcdefghijklmnopqrstuvwxyz",26,"f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    r("a-z0-9","abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",56,
      "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
    { static unsigned char mbuf[1000000]; memset(mbuf,'a',1000000); r("million a",mbuf,1000000,"52783243c1697bdbe16d37f97f68f08325dc1528"); }
    /* length boundaries that force single- vs double-block padding */
    { static unsigned char buf[200]; memset(buf,'A',55); r("len55",buf,55,"c4cf09138ab0b859b70c321375557430649190b4"); }
    { static unsigned char buf[200]; memset(buf,'B',56); r("len56",buf,56,"5a31503106a9a0571330197f80c5d56b690500d7"); }
    { static unsigned char buf[200]; memset(buf,'C',63); r("len63",buf,63,"ed631a90f3c39b4bc83181ffde29a6e224437ec6"); }
    { static unsigned char buf[200]; memset(buf,'D',64); r("len64",buf,64,"03ff44b6d2f0665591ce33840f39f58440f6eae1"); }
    { static unsigned char buf[200]; memset(buf,'E',65); r("len65",buf,65,"3be8da5222fd9faebf31485575f6bd773813a027"); }
    { static unsigned char buf[200]; memset(buf,'F',120); r("len120",buf,120,"cd5ef8c9ca5f12c41726536ee5b0cd3c90853d69"); }
    /* fuzz: deterministic byte patterns at assorted lengths incl. multi-block */
    { static unsigned char e[70000]; 
      for(int i=0;i<70000;i++)e[i]=(unsigned char)((i*7)%256);
      struct{int ln;const char*h;} cv[]={
        {1,"c81b94933420221a7ac004a90242d8b1d3e5070d"},
        {2,"9dbf3424d03b33b5b6064964c5ab34f016615903"},
        {30,"b7511cde9ac3f2ea414e5fb80028a33e17c6e3aa"},
        {54,"47d35037b6d6309f01fc60a3b8dda9690b00f5a8"},
        {57,"be2aa9d6611aafbfd9f2253fc0d198b52f38ec3b"},
        {100,"0c7c9ce7e88b4a892d4bede247103b4ff459858a"},
        {200,"5f46013eeca0be822ec2c04dfac8ec3a343722b9"},
        {1000,"63d8857fbd68bc894a8f3ff6da0bb868ecf7d9a2"},
        {4096,"5b8e0607147a4e6f304be82f987bc80f96204e0d"},
        {65536,"fd37823586c40ed9a4362c21d3ec5f9eb9fe9f1f"}};
      char n[32];
      for(unsigned k=0;k<sizeof(cv)/sizeof(cv[0]);k++){
        sprintf(n,"vol%d",cv[k].ln); r(n,e,cv[k].ln,cv[k].h);
      }
    }
    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
