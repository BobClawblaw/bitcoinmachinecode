/* tn4_replay.c -- replay the testnet4 blocks bmc_osx rejected on 2026-09-11
 * (124,864 / 125,673 / 126,361) through the real apply path and the real
 * txvb worker pool, each after the five blocks before it, all in one
 * process so the pool carries earlier rounds' slots. Prints each block's
 * verdict; exit 0 only if all 18 apply. Fixtures: argv[1] (blk_<h>.bin,
 * batch_<target>.prevouts). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "test_tmpdir.h"
/* utxo_live.c as part of this TU: g_bip30_store (the handle the
 * median-time-past check reads headers through) is static there */
#include "../daemon/utxo_live.c"
extern long store_init(void* st);
extern int  chainparams_select(const char* name);
/* headers the MTP window needs, served from a small framed file: store_get_at
 * and store_rd_fd are wrapped (-Wl,--wrap), everything else is the real store */
#define NHDR 64
static long g_hh[NHDR]; static int g_nh; static int g_hfd = -1;
extern int __real_store_get_at(void* st, u64 height, u64 out_meta[3]);
extern int __real_store_rd_fd(void* st, unsigned file_no);
int __wrap_store_get_at(void* st, u64 height, u64 out_meta[3]){
    for (int i = 0; i < g_nh; i++) if (g_hh[i] == (long)height){ out_meta[0] = (u64)i * 88; out_meta[1] = 80; out_meta[2] = 9999; return 1; }
    return __real_store_get_at(st, height, out_meta);
}
int __wrap_store_rd_fd(void* st, unsigned file_no){ return file_no == 9999 ? g_hfd : __real_store_rd_fd(st, file_no); }
static void load_headers(const char* dir){
    char p[600]; snprintf(p, sizeof p, "%s/headers.txt", dir); FILE* f = fopen(p, "r");
    char tmp[] = "/tmp/tn4hdr.XXXXXX"; g_hfd = mkstemp(tmp); unlink(tmp);
    char hexs[200]; long h; u8 frame[88];
    while (f && g_nh < NHDR && fscanf(f, "%ld %199s", &h, hexs) == 2){
        memset(frame, 0, 8); for (int k = 0; k < 80; k++){ unsigned v; sscanf(hexs + 2*k, "%2x", &v); frame[8+k] = (u8)v; }
        if (write(g_hfd, frame, 88) != 88) abort();
        g_hh[g_nh++] = h;
    }
    if (f) fclose(f);
}
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk, unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen; abort();
}
static u8 store_buf[4096];
static int hx2(const char* h, u8* out, int cap){ int n=0; for(; h[0]&&h[1]&&n<cap; h+=2,n++){ unsigned v; sscanf(h,"%2x",&v); out[n]=(u8)v; } return n; }
int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: tn4_replay <fixture dir>\n"); return 2; }
    char fx[512]; snprintf(fx, sizeof fx, "%s", argv[1]);
    if (chainparams_select("testnet4") != 1){ printf("FAIL select testnet4\n"); return 1; }
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    if (store_init(store_buf)!=1){ printf("FAIL store_init\n"); return 1; }
    if (utxo_live_init(".")!=1){ printf("FAIL utxo_live_init\n"); return 1; }
    utxo_live_set_undo_enabled(0);
    load_headers(fx); g_bip30_store = store_buf;
    printf("served %d real testnet4 headers for the median-time-past windows\n", g_nh);
    static const long targets[3] = {124864, 125673, 126361};
    int bad = 0;
    for (int t = 0; t < 3; t++){
        char p[600]; snprintf(p, sizeof p, "%s/batch_%ld.prevouts", fx, targets[t]);
        FILE* fp = fopen(p, "r"); if (!fp){ printf("FAIL open %s\n", p); return 1; }
        char line[20000]; long seeded = 0;
        while (fgets(line, sizeof line, fp)){
            char txh[80], spkh[19000]; unsigned idx; unsigned long long val;
            if (sscanf(line, "%79s %u %llu %18999s", txh, &idx, &val, spkh) != 4) continue;
            u8 txid[32], txwire[32], spk[9500]; hx2(txh, txid, 32); for (int k=0;k<32;k++) txwire[k] = txid[31-k];
            int sl = hx2(spkh, spk, sizeof spk);
            if (utxo_live_test_seed(txwire, idx, val, spk, (unsigned)sl) < 0){ printf("FAIL seed %s:%u\n", txh, idx); return 1; }
            seeded++;
        }
        fclose(fp);
        for (long h = targets[t] - 5; h <= targets[t]; h++){
            snprintf(p, sizeof p, "%s/blk_%ld.bin", fx, h);
            FILE* fb = fopen(p, "rb"); if (!fb){ printf("FAIL open %s\n", p); return 1; }
            static u8 blk[1<<22]; long blen = (long)fread(blk, 1, sizeof blk, fb); fclose(fb);
            int ok = utxo_live_test_apply_block(blk, (unsigned long)blen, h);
            printf("h=%ld %s (%ld bytes)%s\n", h, ok == 1 ? "applied" : "REJECTED", blen, h == targets[t] ? "  <- osx-rejected block" : "");
            fflush(stdout);
            if (ok != 1) bad++;
        }
        printf("  (batch %ld: %ld prevouts seeded)\n", targets[t], seeded);
    }
    utxo_live_close();
    printf("%s (%d rejected)\n", bad ? "REPLAY FAILED" : "ALL 18 APPLIED", bad);
    return bad ? 1 : 0;
}
