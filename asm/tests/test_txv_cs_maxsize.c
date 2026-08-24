/* Demonstrate: txv_parse accepts scriptSig-length compactsizes that Core
 * rejects (Core throws for any compactsize > MAX_SIZE=0x02000000), and for
 * values within 4 of 2^64 the bound `(end-p) < sl+4` WRAPS so it accepts a
 * tx whose scriptSiglen becomes 0xFFFFFFFF and whose parse cursor advances
 * only ~3 bytes. Read-only; uses the existing txv_test_parse hook. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef unsigned char u8; typedef unsigned long u64;
extern int txv_test_parse(const u8* tx, u64 txlen, u64* out_nin, const char** reason);

long mempool_resolve_confirmed_utxo(void* u, const u8* t, unsigned long i,
    unsigned long long* v, const u8** sp, unsigned long* sl){
    (void)u;(void)t;(void)i;(void)v;(void)sp;(void)sl; return 0; }
static int fails=0;
static void expect_reject(const char* nm, const u8* tx, u64 len){
    u64 nin=0; const char* r="(accepted)";
    int rc = txv_test_parse(tx, len, &nin, &r);
    if (rc==0) printf("PASS  %-28s rejected: %s\n", nm, r);
    else { printf("FAIL  %-28s ACCEPTED (Core rejects; nin=%lu)\n", nm, nin); fails++; }
}

/* 1-input non-segwit tx skeleton with a chosen scriptSig-length encoding.
 * layout: ver(4) nin=01 outpoint(36) <sslen-enc> <trailer...> */
static u64 build(u8* o, const u8* sslen_enc, int enclen){
    u64 n=0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0;      /* version; byte4 next != 0 => non-segwit */
    o[n++]=1;                                  /* nin = 1 */
    for(int i=0;i<36;i++) o[n++]=(u8)(i+1);    /* outpoint */
    memcpy(o+n, sslen_enc, enclen); n+=enclen; /* scriptSig length compactsize */
    for(int i=0;i<64;i++) o[n++]=0;            /* trailer: gives >=3 bytes so the
                                                  wrapped bound cannot reject on size */
    return n;
}

int main(void){
    static u8 tx[256];
    /* (a) scriptSig len = 2^64-1 via 0xff + eight 0xFF bytes */
    { u8 enc[9]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
      expect_reject("sslen=2^64-1 (0xff form)", tx, build(tx, enc, 9)); }
    /* (b) scriptSig len = MAX_SIZE+1 = 0x02000001 via 0xfe form */
    { u8 enc[5]={0xfe,0x01,0x00,0x00,0x02};
      expect_reject("sslen=MAX_SIZE+1", tx, build(tx, enc, 5)); }
    /* (c) scriptSig len = 0xFFFFFFFF via 0xfe form (== the truncated value) */
    { u8 enc[5]={0xfe,0xff,0xff,0xff,0xff};
      expect_reject("sslen=0xFFFFFFFF", tx, build(tx, enc, 5)); }
    /* control: a well-formed empty-scriptSig input must still PARSE fine
       (sanity that the harness/skeleton isn't rejecting everything) */
    { u8 enc[1]={0x00}; u64 n=build(tx, enc, 1);
      u64 nin=0; const char* r=""; int rc=txv_test_parse(tx,n,&nin,&r);
      printf("%s  control (empty scriptSig): rc=%d nin=%lu\n", rc?"note":"note", rc, nin); }

    printf("\n%s (%d divergence(s) from Core's MAX_SIZE rule)\n",
           fails?"BUG DEMONSTRATED":"no divergence", fails);
    return 0;
}
