#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern int cons_verify(const unsigned char* block, u64 len, unsigned char* scratch, u64 cap);
extern unsigned long long cons_fail, cons_idx, cons_tl, cons_len;
static int hv(char c){return (c<='9')?c-'0':(c|32)-'a'+10;}
static int hexiz(unsigned char* o,const char*h){int n=strlen(h)/2;for(int i=0;i<n;i++)o[i]=(hv(h[2*i])<<4)|hv(h[2*i+1]);return n;}
int main(void){
    const char* THE_CB="01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
    unsigned char hdr[80];
    unsigned char root_rev[32]={0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a};
    unsigned int v=1,t=1231006505u,bits=0x1d00ffffu,nonce=2083236893u;
    memcpy(hdr,&v,4);memset(hdr+4,0,32);memcpy(hdr+36,root_rev,32);memcpy(hdr+68,&t,4);memcpy(hdr+72,&bits,4);memcpy(hdr+76,&nonce,4);
    unsigned char tx[204];int tlen=hexiz(tx,THE_CB);
    unsigned char block[3000];memcpy(block,hdr,80);block[80]=0x01;memcpy(block+81,tx,tlen);
    static unsigned char scratch[1024];
    int r=cons_verify(block,81+tlen,scratch,16);
    printf("ret=%d fail=%llu idx=0x%llx txlen=0x%llx len=0x%llx\n",r,cons_fail,cons_idx,cons_tl,cons_len);
    return 0;
}
