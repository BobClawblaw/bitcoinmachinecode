/* Incident #13 regression: block 481827 (999 KB, a 331-input P2SH-P2WPKH tx
 * and two 500-input legacy txs) drove the verify-pool threads off their
 * stacks -- ~12 MB of static TLS lived inside the default 2 MB pthread
 * mapping, so every worker started with almost no real stack and the deep
 * witness-v0 -> script_eval -> BIP143 chain wrote past the guard page.
 *
 * This runs the block through the FULL production apply path
 * (utxo_live_test_apply_block -> apply_block_inner -> witness commitment ->
 * tx_verify_block_connect_all on the real pool) against a UTXO view seeded
 * from tests/fixtures/blk_481827.prevouts. With the fix it applies cleanly.
 * With BMC_THREAD_STACK_MB=0 (library-default attrs) it reproduces the
 * overflow -- run by the Makefile as a separate, expected-to-die process.
 *
 * Fixtures are gitignored (fetched by validation/fetch_block_prevouts.py);
 * the test SKIPs (exit 0) when they are absent so CI without an oracle is
 * green. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "test_tmpdir.h"
typedef unsigned char u8;
extern long store_init(void* st);
extern int  utxo_live_init(const char* dir);
extern void utxo_live_close(void);
extern int  utxo_live_test_apply_block(const u8* blk, unsigned long len, long height);
extern int  utxo_live_test_seed(const u8 txid[32], unsigned index, unsigned long long value, const u8* spk, unsigned spklen);
extern void utxo_live_set_undo_enabled(int on);

/* utxo_live.c pulls this in but the apply path never calls it here. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk, unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr,"unexpected mempool_resolve_confirmed_utxo\n"); abort();
}
static u8 store_buf[4096];
static int hx(const char* h, u8* out, int cap){ int n=0; for(; h[0]&&h[1]&&n<cap; h+=2,n++){ unsigned v; sscanf(h,"%2x",&v); out[n]=(u8)v; } return n; }
int main(void){
    tt_isolate();
    const char* FX_BIN=tt_src("tests/fixtures/blk_481827.bin");
    const char* FX_PRE=tt_src("tests/fixtures/blk_481827.prevouts");
    FILE* fb=fopen(FX_BIN,"rb"); FILE* fp=fopen(FX_PRE,"r");
    if(!fb||!fp){ printf("SKIP: fixtures absent (run validation/fetch_block_prevouts.py 481827)\n"); return 0; }
    static u8 blk[1<<21]; long blen=fread(blk,1,sizeof blk,fb); fclose(fb);
    memset(store_buf,0,sizeof store_buf);
    if(store_init(store_buf)!=1){ printf("FAIL store_init\n"); return 1; }
    if(utxo_live_init(".")!=1){ printf("FAIL utxo_live_init\n"); return 1; }
    utxo_live_set_undo_enabled(0);
    char line[8192]; long seeded=0;
    while(fgets(line,sizeof line,fp)){
        char txh[80],spkh[6000]; unsigned idx; unsigned long long val;
        if(sscanf(line,"%79s %u %llu %5999s",txh,&idx,&val,spkh)!=4) continue;
        u8 txid[32],txwire[32],spk[3000]; hx(txh,txid,32); for(int k=0;k<32;k++) txwire[k]=txid[31-k]; int sl=hx(spkh,spk,sizeof spk);
        long r=utxo_live_test_seed(txwire,idx,val,spk,(unsigned)sl);
        if(r<0){ printf("FAIL seed prevout %ld (r=%ld)\n",seeded,r); return 1; } seeded++;
    }
    fclose(fp);
    printf("seeded %ld prevouts; applying block 481827 (%ld bytes) on the real verify pool...\n",seeded,blen);
    fflush(stdout);
    int ok=utxo_live_test_apply_block(blk,(unsigned long)blen,481827);
    utxo_live_close();
    if(ok!=1){ printf("FAIL apply_block 481827 returned %d\n",ok); return 1; }
    printf("PASS block 481827 verified+applied, no stack overflow\n");
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
