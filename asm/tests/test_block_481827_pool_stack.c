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
 * The load-bearing part of the fix is SW_MIDSTATE_CAP (bitcoin_segwit.c):
 * with it put back to 4096 this test FAILS (checked 2026-09-24: tx 1076
 * rejected "p2wpkh signature invalid" -- the bounds check now refuses where
 * the old buffer overflowed). The thread-stack half no longer reproduces:
 * after 8aaf68cb moved the 1 MiB TLS scratch to the heap, the block passes
 * at BMC_THREAD_STACK_MB=0, 2 and 1, so no expected-to-die control is run
 * (an earlier version of this comment said the Makefile ran one; it never
 * did).
 *
 * Fixtures (validation/fetch_block_prevouts.py 481827) are COMMITTED
 * (2026-09-24): until then they were gitignored and this test SKIPped in
 * every gate, which hid that it had been broken since VAL-4 (ae7c369c,
 * 2026-09-04) -- 481827 is past CSV, so the finality rule reads the
 * median-time-past window, and this harness had no headers: every run
 * rejected the block "bad-txns-nonfinal (median-time-past window
 * unreadable)". A missing fixture is now a FAIL, not a SKIP.
 *
 * The window is the 11 real headers before the block (blk_481827.headers),
 * served through the store the rule reads: utxo_live.c is part of this TU so
 * its static g_bip30_store can point at our store, and store_get_at /
 * store_rd_fd are wrapped (-Wl,--wrap in the Makefile rule) to answer for
 * those 11 heights from a small framed file. Production code is untouched. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "test_tmpdir.h"
#include "../daemon/utxo_live.c"
extern long store_init(void* st);

/* ---- the median-time-past window: 11 real headers from a framed file ---- */
#define NHDR 11
static long g_hh[NHDR]; static int g_nh; static int g_hfd = -1;
extern int __real_store_get_at(void* st, u64 height, u64 out_meta[3]);
extern int __real_store_rd_fd(void* st, unsigned file_no);
#define HDR_FILE_NO 0xFFFFu
int __wrap_store_get_at(void* st, u64 height, u64 out_meta[3]){
    for (int i = 0; i < g_nh; i++)
        if (g_hh[i] == (long)height){ out_meta[0] = (u64)i * 88; out_meta[1] = 80; out_meta[2] = HDR_FILE_NO; return 1; }
    return __real_store_get_at(st, height, out_meta);
}
int __wrap_store_rd_fd(void* st, unsigned file_no){ return file_no == HDR_FILE_NO ? g_hfd : __real_store_rd_fd(st, file_no); }
/* one 88-byte frame per header: [8 bytes len/magic][80-byte header], as the
 * store frames a block (powr_hdr_from_store reads at meta[0] + 8) */
static int load_headers(const char* path){
    FILE* f = fopen(path, "r"); if (!f) return 0;
    char tmp[] = "hdr.XXXXXX"; g_hfd = mkstemp(tmp); unlink(tmp);
    char hexs[200]; long h; u8 frame[88];
    while (g_nh < NHDR && fscanf(f, "%ld %199s", &h, hexs) == 2){
        memset(frame, 0, 8);
        for (int k = 0; k < 80; k++){ unsigned v; sscanf(hexs + 2*k, "%2x", &v); frame[8+k] = (u8)v; }
        if (write(g_hfd, frame, sizeof frame) != (ssize_t)sizeof frame){ fclose(f); return 0; }
        g_hh[g_nh++] = h;
    }
    fclose(f);
    return g_nh == NHDR;
}

/* utxo_live.c pulls this in but the apply path never calls it here. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk, unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr,"unexpected mempool_resolve_confirmed_utxo\n"); abort();
}
static u8 store_buf[4096];
static int hx8(const char* h, u8* out, int cap){ int n=0; for(; h[0]&&h[1]&&n<cap; h+=2,n++){ unsigned v; sscanf(h,"%2x",&v); out[n]=(u8)v; } return n; }
int main(void){
    tt_isolate();
    const char* FX_BIN=tt_src("tests/fixtures/blk_481827.bin");
    const char* FX_PRE=tt_src("tests/fixtures/blk_481827.prevouts");
    FILE* fb=fopen(FX_BIN,"rb"); FILE* fp=fopen(FX_PRE,"r");
    if(!fb||!fp){ printf("FAIL: fixtures absent (committed; regenerate with validation/fetch_block_prevouts.py 481827)\n"); return 1; }
    static u8 blk[1<<21]; long blen=fread(blk,1,sizeof blk,fb); fclose(fb);
    memset(store_buf,0,sizeof store_buf);
    if(store_init(store_buf)!=1){ printf("FAIL store_init\n"); return 1; }
    if(utxo_live_init(".")!=1){ printf("FAIL utxo_live_init\n"); return 1; }
    utxo_live_set_undo_enabled(0);
    if(!load_headers(tt_src("tests/fixtures/blk_481827.headers"))){ printf("FAIL: blk_481827.headers absent or short (%d of %d)\n", g_nh, NHDR); return 1; }
    g_bip30_store = store_buf;           /* the store the finality rule reads the window through */
    char line[8192]; long seeded=0;
    while(fgets(line,sizeof line,fp)){
        char txh[80],spkh[6000]; unsigned idx; unsigned long long val;
        if(sscanf(line,"%79s %u %llu %5999s",txh,&idx,&val,spkh)!=4) continue;
        u8 txid[32],txwire[32],spk[3000]; hx8(txh,txid,32); for(int k=0;k<32;k++) txwire[k]=txid[31-k]; int sl=hx8(spkh,spk,sizeof spk);
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
