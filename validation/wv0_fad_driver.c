
#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
extern int  sv_verify_witness_v0(const u8* prog, u32 proglen,
                                 const u8* const* wit, const u32* witlen, u32 nwit,
                                 u64 amount, u64 flags, unsigned long nIn,
                                 const u8* tx, unsigned long txlen,
                                 u8* work, unsigned long workcap);
extern long sv_verify_witness_v0_asm(const u8* prog, u32 proglen,
                                     const u8* const* wit, const u32* witlen, u32 nwit,
                                     u64 amount, u64 flags, u64 nIn,
                                     const u8* tx, u64 txlen,
                                     u8* work, u64 workcap);
extern void sha256_full(u8 out[32], const void* in, int64_t len);
long mempool_resolve_confirmed_utxo_stub(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk,
                                    unsigned long* spklen){ (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen; return 0; }
static u8 workc[1<<20], worka[1<<20];
static u8 txbuf[512];
static void put32(u8**p, unsigned v){ memcpy(*p,&v,4); *p+=4; }
static void put64(u8**p, unsigned long long v){ memcpy(*p,&v,8); *p+=8; }
static void push(u8**p, const u8* d, u32 n){ if(n<76){*(*p)++=(u8)n;} else if(n<256){ *(*p)++=76; *(*p)++=(u8)n; } else { *(*p)++=77; *(*p)++=(u8)(n&0xff); *(*p)++=(u8)(n>>8); *(*p)++=0; } memcpy(*p,d,n); *p+=n; }

static u8 sig[89], pub[33], wscript[128]; static u32 wsl;
static void build_case(void){
    static const u8 sigbase[71] = {
        0x30,0x44,0x02,0x20,0x21,0x10,0xc6,0x92,0xb5,0xa3,0x61,0x2c,0xef,0xd8,0x38,0x55,
        0x61,0xd4,0xd9,0xcb,0x4e,0x4f,0x64,0xda,0x67,0x03,0x6d,0x71,0x00,0xcd,0xcc,0xbd,
        0x3e,0x18,0x42,0xb0,0x02,0x20,0x73,0x15,0x49,0x03,0xf5,0xca,0x82,0x30,0xbe,0xa0,
        0xf9,0x3a,0xd9,0x6e,0xa9,0xd5,0x2d,0x68,0x21,0x1f,0x51,0x53,0x8c,0x83,0x0b,0xcf,
        0x7f,0x14,0x50,0x78,0x1f,0x36,0x03};
    memcpy(sig,sigbase,71); memset(sig+71,5,17); sig[88]=0x5a;
    pub[0]=2; memset(pub+1,0x39,32);
    u8*wp=wscript;
    push(&wp,sig,89); *wp++=0x75; push(&wp,pub,33); *wp++=0xac;
    wsl=(u32)(wp-wscript);
}
static u64 build_tx(u8* t){
    u8 wsh[32]; sha256_full(wsh,wscript,wsl);
    u8 spk[34]; spk[0]=0; spk[1]=32; memcpy(spk+2,wsh,32);
    u8* o=t;
    put32(&o,2); *o++=0; *o++=1;
    memset(o,0,32); o+=32; put32(&o,0);
    *o++=0; put32(&o,0xffffffff);
    put64(&o,1000); push(&o,spk,34);
    *o++=3; push(&o,sig,89); push(&o,pub,33); push(&o,wscript,wsl);
    put32(&o,0);
    return (u64)(o-t);
}
int main(void){
    build_case();
    u64 txlen = build_tx(txbuf);
    const u8* wit[3]={sig,pub,wscript}; u32 witlen[3]={89,33,wsl};
    u8 wsh[32]; sha256_full(wsh,wscript,wsl);
    u64 flags = (1ULL<<0)|(1ULL<<1)|(1ULL<<2)|(1ULL<<3)|(1ULL<<13)|(1ULL<<14); /* P2SH|STRICTENC|DERSIG|LOW_S|WITNESS|CSC */
    int c = sv_verify_witness_v0(wsh,32,wit,witlen,3,1000,flags,0,txbuf,txlen,workc,sizeof workc);
    long a = sv_verify_witness_v0_asm(wsh,32,wit,witlen,3,1000,flags,0,txbuf,txlen,worka,sizeof worka);
    printf("C   engine: rc=%d   (24=SIG_DER expected; 54=SIG_FINDANDDELETE = the old bug)\n", c);
    printf("ASM engine: rc=%ld\n", a);
    printf("%s\n", c==a? "AGREE":"DIVERGE");
    return 0;
}
