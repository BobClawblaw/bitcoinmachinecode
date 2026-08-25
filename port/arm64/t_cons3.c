#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern int pow_check(const unsigned char* hdr);
extern u64 tx_parse(u64 info[8], const unsigned char* tx, u64 len);
extern int tx_txid(unsigned char* o,const unsigned char* tx,u64 len,unsigned char* buf,u64 buflen);
extern void merkle_root(unsigned char* out,unsigned char* hashes,u64 n);
extern int cons_verify(const unsigned char* block, u64 len, unsigned char* scratch, u64 cap);
static int hv(char c){return (c<='9')?c-'0':(c|32)-'a'+10;}
static int hexiz(unsigned char* o, const char* h){int n=strlen(h)/2;for(int i=0;i<n;i++)o[i]=(hv(h[2*i])<<4)|hv(h[2*i+1]);return n;}
int main(void){
    const char* THE_CB="01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
    unsigned char tx[204]; int tlen=hexiz(tx,THE_CB);
    u64 info[8];memset(info,0,64);
    u64 r=tx_parse(info,tx,tlen);
    printf("tx_parse=%llu n_in=%u (want 1)\n",r,(unsigned)(info[1]>>32));
    static unsigned char tid[32],buf[0x100000];
    int ok=tx_txid(tid,tx,tlen,buf,0x100000);
    printf("tx_txid=%d txid=",ok);for(int i=0;i<32;i++)printf("%02x",tid[i]);printf("\n");
    printf("hdr root =3b a3 ed fd 7a 7b 12 b2 7a c7 2c 3e 67 76 8f 61 7f c8 1b c3 88 8a 51 32 3a 9f b8 aa 4b 1e 5e 4a\n");
    static unsigned char mk[32]; static unsigned char hashes[32]; memcpy(hashes,tid,32);
    merkle_root(mk,hashes,1);
    printf("merkle(1)=");for(int i=0;i<32;i++)printf("%02x",mk[i]);printf("\n");
    /* full block */
    unsigned char hdr[80];
    unsigned char root_rev[32]={0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a};
    unsigned int v=1,tm=1231006505u,bits=0x1d00ffffu,nonce=2083236893u;
    memcpy(hdr,&v,4);memset(hdr+4,0,32);memcpy(hdr+36,root_rev,32);memcpy(hdr+68,&tm,4);memcpy(hdr+72,&bits,4);memcpy(hdr+76,&nonce,4);
    printf("pow_check=%d\n",pow_check(hdr));
    unsigned char block[3000];memcpy(block,hdr,80);block[80]=0x01;memcpy(block+81,tx,tlen);
    static unsigned char scratch[1024];
    printf("cons_verify(genesis)=%d\n",cons_verify(block,81+tlen,scratch,16));
    /* dump the txids cons_verify wrote into scratch */
    printf("scratch[0..31]: ");
    static unsigned char scratch2[1024];
    cons_verify(block,81+tlen,scratch2,16);
    for(int i=0;i<32;i++)printf("%02x",scratch2[i]);printf("\n");
    return 0;
}
