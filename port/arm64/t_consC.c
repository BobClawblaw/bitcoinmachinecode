#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern int pow_check(const unsigned char* hdr);
extern u64 tx_parse(u64 info[8], const unsigned char* tx, u64 len);
extern int tx_txid(unsigned char* o,const unsigned char* tx,u64 len,unsigned char* buf,u64 buflen);
extern void merkle_root(unsigned char* out,unsigned char* hashes,u64 n);
static int hv(char c){return (c<='9')?c-'0':(c|32)-'a'+10;}
static int hexiz(unsigned char* o,const char*h){int n=strlen(h)/2;for(int i=0;i<n;i++)o[i]=(hv(h[2*i])<<4)|hv(h[2*i+1]);return n;}
static u64 readvarint(const unsigned char*p, int*size){
    unsigned char b=p[0];
    if(b<0xfd){*size=1;return b;}
    if(b==0xfd){*size=3;return (u64)p[1]|(u64)p[2]<<8;}
    if(b==0xfe){*size=5;u64 v=*(unsigned int*)(p+1);return v;}
    *size=9;u64 v=*(u64*)(p+1);return v;
}
int main(void){
    const char* THE_CB="01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
    unsigned char hdr[80];
    unsigned char root_rev[32]={0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a};
    unsigned int v=1,t=1231006505u,bits=0x1d00ffffu,nonce=2083236893u;
    memcpy(hdr,&v,4);memset(hdr+4,0,32);memcpy(hdr+36,root_rev,32);memcpy(hdr+68,&t,4);memcpy(hdr+72,&bits,4);memcpy(hdr+76,&nonce,4);
    unsigned char tx[204];int tlen=hexiz(tx,THE_CB);
    unsigned char block[3000];memcpy(block,hdr,80);block[80]=0x01;memcpy(block+81,tx,tlen);
    u64 len=81+tlen;
    if(!pow_check(block)){printf("fail pow\n");return 1;}
    int cs;u64 expc=readvarint(block+80,&cs);
    u64 idx=80+cs;
    static unsigned char scratch[1024];u64 n=0;
    while(idx<len){
        u64 info[8]; memset(info,0,64);
        u64 r=tx_parse(info,block+idx,len-idx);
        if(!r){printf("fail tx_parse at %lld\n",(long long)idx);return 1;}
        u64 txl=info[0];
        if(idx+txl>len){printf("fail bounds\n");return 1;}
        if(n==0 && (unsigned)(info[1]>>32)!=1){printf("fail coinbase n_in=%u\n",(unsigned)(info[1]>>32));return 1;}
        static unsigned char tid[32],rb[0x100000];
        if(!tx_txid(tid,block+idx,txl,rb,0x100000)){printf("fail txtxid\n");return 1;}
        memcpy(scratch+n*32,tid,32);
        n++;idx+=txl;
    }
    if(idx!=len){printf("fail idx!=len\n");return 1;}
    if(n!=expc){printf("fail n!=expc %llu %llu\n",n,expc);return 1;}
    static unsigned char mr[32];
    merkle_root(mr,scratch,n);
    if(memcmp(mr,block+36,32)!=0){printf("fail merkle cmp\n  mr=%02x%02x..\n  hd=%02x%02x..\n",mr[0],mr[1],block[36],block[37]);return 1;}
    printf("C cons_verify(genesis)=VALID (1)\n");
    return 0;
}
