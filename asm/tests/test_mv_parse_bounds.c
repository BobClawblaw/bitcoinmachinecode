/* incident #37: the mempool-path parser (bitcoin_txval_modern.c mv_parse)
 * had an unbounded compactsize reader and pointer-overflow bounds on the
 * no-PoW inbound-tx path. This pins the bounded/split-bound fix via the
 * mv_test_parse hook, which exposes the PARSE verdict (a resolve failure
 * otherwise masks a parse that accepted a truncated length). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef unsigned char u8;
extern int mv_test_parse(const u8* tx, long txlen, uint32_t* wl0);
long mempool_resolve_confirmed_utxo(void* u, const u8* t, unsigned long i,
    unsigned long long* v, const u8** sp, unsigned long* sl){
    (void)u;(void)t;(void)i;(void)v;(void)sp;(void)sl; return 0; }

static int fails=0;
static long build(u8* o, const u8* witil, int witn){
    long n=0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0; o[n++]=0x00; o[n++]=0x01; o[n++]=1;
    for(int i=0;i<36;i++) o[n++]=(u8)i;
    o[n++]=0x00; o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    o[n++]=1; for(int i=0;i<8;i++) o[n++]=0; o[n++]=0x00;
    o[n++]=1; memcpy(o+n,witil,witn); n+=witn;
    for(int i=0;i<8;i++) o[n++]=(u8)0xAB;
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
    return n;
}
static void expect(const char* nm, const u8* witil, int witn, int want_ok){
    static u8 tx[512]; long n=build(tx,witil,witn); uint32_t wl0=0xdead;
    int r=mv_test_parse(tx,n,&wl0);
    int good = (r==want_ok) && (r==0 || wl0<=(uint32_t)n);  /* if accepted, witlen must be sane */
    printf("%s  %-26s parse=%d witlen0=%u\n", good?"PASS":"FAIL", nm, r, wl0);
    if(!good) fails++;
}
int main(void){
    { u8 e[1]={0x01}; expect("witlen=1 (well-formed)", e,1, 1); }
    { u8 e[9]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}; expect("witlen=2^64-1", e,9, 0); }
    { u8 e[9]={0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff}; expect("witlen=0xFFFFFFFF<<32", e,9, 0); }
    { u8 e[5]={0xfe,0xff,0xff,0xff,0x7f}; expect("witlen=0x7FFFFFFF", e,5, 0); }
    /* truncated varint at buffer end -> must reject, not read past end */
    { u8 e[1]={0xff}; expect("truncated 0xff varint", e,1, 0); }
    printf("\n%s (%d failure(s))\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
