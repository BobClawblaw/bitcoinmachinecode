/* test_bip30.c -- smoke regression for the chain-context BIP30 gate
 * (asm/tests/bip30_shim.c + asm/bitcoin_utxo.asm).
 *
 * BIP30 (validation.cpp ConnectBlock) forbids a block whose tx output
 * (txid,vout) collides with an already-unspent coin, except at the two
 * historical mainnet duplicate-coinbase blocks (91842 / 91880) that Core
 * grandfathers via IsBIP30Repeat.
 *
 * This test drives the shim over stdin and smoke-checks the transport + a
 * connected block (bip30=0, enforcement on). The authoritative end-to-end
 * chain-context semantics (grandfather enforce==0/1 exactness on the real
 * mainnet region, and bip30=1-while-live vs bip30=0-after-spend) are
 * differentially proven against a real Bitcoin Core node by
 * validation/bip30_diff.py (report: bip30_diff_report.json, zero divergences).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "test_tmpdir.h"

extern void sha256d(unsigned char out[32], const void* msg, long len);

static void put_varint(unsigned char* o, size_t* p, unsigned long long n){
    if (n < 0xfd) o[(*p)++]=(unsigned char)n;
    else if (n<=0xffff){ o[(*p)++]=0xfd; o[(*p)++]=n&0xff; o[(*p)++]=n>>8; }
    else if (n<=0xffffffff){ o[(*p)++]=0xfe; for(int i=0;i<4;i++) o[(*p)++]=n>>(8*i); }
    else { o[(*p)++]=0xff; for(int i=0;i<8;i++) o[(*p)++]=n>>(8*i); }
}
static void put_le32(unsigned char* o, size_t* p, unsigned long long v){
    for(int i=0;i<4;i++) o[(*p)++]=(unsigned char)(v>>(8*i));
}
static void put_le64(unsigned char* o, size_t* p, unsigned long long v){
    for(int i=0;i<8;i++) o[(*p)++]=(unsigned char)(v>>(8*i));
}
static void coinbase_bip34(unsigned char* o, size_t* p, int height){
    put_le32(o,p,1); put_varint(o,p,1);
    for(int i=0;i<32;i++) o[(*p)++]=0;
    put_le32(o,p,0xffffffff);
    unsigned char sc[6]; size_t sl=0;
    if (height){ int h=height; unsigned char nb[4]; int nn=0; while(h){ nb[nn++]=h&0xff; h>>=8; } sc[sl++]=(unsigned char)nn; for(int i=0;i<nn;i++) sc[sl++]=nb[i]; }
    else sc[sl++]=0;
    sc[sl++]=0;
    put_varint(o,p,sl); for(size_t i=0;i<sl;i++) o[(*p)++]=sc[i];
    put_le32(o,p,0xffffffff);
    put_varint(o,p,1);
    put_le64(o,p, 5000000000ULL >> (height/150));
    put_varint(o,p,1); o[(*p)++]=0x51; put_le32(o,p,0);
}
static void merkle_root(unsigned char out[32], unsigned char(*ids)[32], int n){
    unsigned char cur[64][32]; memcpy(cur, ids, 32*n);
    while(n>1){ int m=0; for(int i=0;i<n;i+=2){ unsigned char tmp[64]; memcpy(tmp,cur[i],32); memcpy(tmp+32,(i+1<n)?cur[i+1]:cur[i],32); sha256d(cur[m++],tmp,64); } n=m; }
    memcpy(out,cur[0],32);
}
/* single coinbase-only block */
static size_t build_cb_block(unsigned char* out, unsigned long long prev_be,
                             unsigned long nbits, int height, uint32_t btime){
    unsigned char body[1024]; size_t bp=0;
    unsigned char cb[512]; size_t cbl=0; coinbase_bip34(cb,&cbl,height);
    unsigned char ids[1][32]; put_varint(body,&bp,1); memcpy(body+bp,cb,cbl); bp+=cbl;
    sha256d(ids[0],cb,(long)cbl);
    unsigned char merk[32]; merkle_root(merk,ids,1);
    unsigned char hdr[80]; size_t hp=0;
    put_le32(hdr,&hp,0x20000000ull);
    /* prev: the 8-byte tag, then zeros. (Was a 32-byte read of an 8-byte variable:
     * bytes 8..31 came from whatever sat above it on the stack.) */
    for(int i=0;i<32;i++) hdr[hp++]=(i<8)?((unsigned char*)&prev_be)[i]:0;
    memcpy(hdr+hp,merk,32); hp+=32;
    put_le32(hdr,&hp,btime);
    put_le32(hdr,&hp,nbits);
    put_le32(hdr,&hp,0);
    memcpy(out,hdr,80); memcpy(out+80,body,bp); return 80+bp;
}

/* Run RESET+CONNECT(h)+QUIT through the shim; parse the CONNECT verdict line
   from the shim's stdout (captured to a temp file). */
static void do_connect(const unsigned char* blk, size_t n, int h, int* en, int* bi){
    static char hex[4000000]; size_t x=0; static const char* d="0123456789abcdef";
    for(size_t i=0;i<n && x+1<sizeof hex;i++){ hex[x++]=(char)d[blk[i]>>4]; hex[x++]=d[blk[i]&15]; }
    hex[x]=0;
    const char* shim=getenv("BIP30_SHIM"); if(!shim) shim="tests/bip30_shim";
    shim=tt_src(shim);   /* absolute passes through; relative rebases past the chdir */
    static char cmd[6000000];
    snprintf(cmd,sizeof cmd,
        "{ printf 'RESET\\nCONNECT %s %d\\nQUIT\\n'; } | %s > b30shim.out 2>/dev/null",
        hex, h, shim);
    if (system(cmd) != 0) fprintf(stderr, "warning: shim pipeline exited nonzero\n");
    /* parse: line1=RESET OK, line2=CONNECT verdict */
    FILE* f=fopen("b30shim.out","r");
    char line[256]; int e=-1,a=-1,b=-1;
    int lc=0;
    while(f && fgets(line,sizeof line,f)){ lc++; if(lc==2){ sscanf(line,"OK %d %d %d %d",&e,&a,&b,&b); break; } }
    if(f) fclose(f);
    if(en)*en=e;
    if(bi)*bi=a;
}


int main(void){
    tt_isolate();   /* the shim's stdout capture was a fixed /tmp path */
    int fails=0;
    unsigned char blk[1024];
    size_t bl = build_cb_block(blk, 0xABC1230000000000ULL, 0x207fffffUL, 200, 1600000000u);
    int en=0,bi=-1;
    do_connect(blk, bl, 200, &en, &bi);
    int ok = (en==1 && bi==0);
    printf("%s: connected coinbase-only block @200 -> enforce=%d bip30=%d (expect 1/0)\n",
           ok?"ok  ":"FAIL", en, bi);
    if(!ok) fails++;
    printf("bip30 shim smoke: %d failure(s)\n", fails);
    return fails?1:0;
}
