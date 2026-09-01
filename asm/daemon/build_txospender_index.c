/* daemon/build_txospender_index.c -- offline base build of the txo-spender
 * index (Core's -txospenderindex): every non-coinbase input in the archive
 * becomes one record (spent outpoint -> spending tx location), sorted by
 * (txid prefix, vout) with a sparse index. Same two-pass external sort and
 * header-written-last discipline as build_tx_index.c; see txosp_format.h
 * for the layout. The daemon's tail (txosp_tail.c) covers heights after
 * to_height, and gettxspendingprevout consults both.
 *
 * Usage: build_txospender_index <datadir> [from_height] [to_height]
 * Size: ~28 bytes per spent output (~35 GB for mainnet's ~1.25e9 spends);
 * run it while the node is idle -- it reads the whole archive once. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
extern int  store_init(void* st);
extern int  store_reload(void* st);
extern int  store_rd_init(void* st);
extern long store_read_at(void* st, unsigned long h, void* out, long cap);
#include "txosp_format.h"
#define NBUCKETS 256
#define BLOCKBUF (4u << 20)
static int rec_cmp(const void* a, const void* b){
    const tsp_rec* x = a; const tsp_rec* y = b;
    int c = tsp_key_cmp(x->prefix, x->vout, y->prefix, y->vout); if (c) return c;
    if (x->height != y->height) return x->height < y->height ? -1 : 1;
    if (x->offset != y->offset) return x->offset < y->offset ? -1 : 1;
    return 0;
}
typedef struct { FILE* bucket[NBUCKETS]; u32 height; u64 n; } pass1_ctx;
static void emit(void* ctxv, const u8* prev, u32 vout, u32 off, u32 len){
    pass1_ctx* c = ctxv; tsp_rec r;
    memcpy(r.prefix, prev, 12); r.vout = vout; r.height = c->height; r.offset = off; r.len = len;
    if (fwrite(&r, 1, sizeof r, c->bucket[r.prefix[0]]) == sizeof r) c->n++;
}
int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: build_txospender_index <datadir> [from] [to]\n"); return 2; }
    const char* dir = argv[1];
    long from_h = argc > 2 ? atol(argv[2]) : 0;
    long to_h   = argc > 3 ? atol(argv[3]) : -1;
    if (chdir(dir)){ perror("chdir"); return 1; }
    static u8 store_buf[4096];
    if (store_init(store_buf) != 1){ fprintf(stderr, "store_init failed\n"); return 1; }
    store_reload(store_buf); store_rd_init(store_buf);
    long tip = *(int*)(store_buf + 24);
    if (tip < 0){ fprintf(stderr, "empty store\n"); return 1; }
    if (to_h < 0 || to_h > tip) to_h = tip;
    if (from_h < 0) from_h = 0;
    if (to_h < from_h){ fprintf(stderr, "empty height range\n"); return 1; }
    fprintf(stderr, "[txospender] dir=%s tip=%ld range=[%ld,%ld]\n", dir, tip, from_h, to_h);
    pass1_ctx c; memset(&c, 0, sizeof c);
    u8* blockbuf = malloc(BLOCKBUF); if (!blockbuf){ fprintf(stderr, "oom\n"); return 1; }
    char nm[64];
    for (int i = 0; i < NBUCKETS; i++){ snprintf(nm, sizeof nm, "txosp_b%03d.tmp", i); c.bucket[i] = fopen(nm, "wb"); if (!c.bucket[i]){ fprintf(stderr, "cannot open %s\n", nm); return 1; } }
    time_t t0 = time(NULL);
    for (long h = from_h; h <= to_h; h++){
        long blen = store_read_at(store_buf, (unsigned long)h, blockbuf, BLOCKBUF);
        if (blen < 81){
            fprintf(stderr, "[txospender] FATAL: block %ld unreadable (%ld); index abandoned\n", h, blen);
            for (int i = 0; i < NBUCKETS; i++){ fclose(c.bucket[i]); snprintf(nm, sizeof nm, "txosp_b%03d.tmp", i); unlink(nm); }
            return 1;
        }
        c.height = (u32)h;
        if (!tsp_walk_block(blockbuf, blen, emit, &c)){ fprintf(stderr, "[txospender] FATAL: block %ld is malformed; index abandoned\n", h); for (int i = 0; i < NBUCKETS; i++) fclose(c.bucket[i]); return 1; }
        if ((h - from_h) % 20000 == 0) fprintf(stderr, "[txospender] pass1 %ld/%ld (%llu spends, %llds)\n", h, to_h, (unsigned long long)c.n, (long long)(time(NULL) - t0));
    }
    for (int i = 0; i < NBUCKETS; i++) fclose(c.bucket[i]);
    fprintf(stderr, "[txospender] pass1 done: %llu spends in %llds\n", (unsigned long long)c.n, (long long)(time(NULL) - t0));
    FILE* out = fopen(TSP_BASE_FILE ".tmp", "wb"); if (!out){ fprintf(stderr, "cannot open %s.tmp\n", TSP_BASE_FILE); return 1; }
    { u8 hdr[TSP_HDR]; memset(hdr, 0, sizeof hdr); if (fwrite(hdr, 1, TSP_HDR, out) != TSP_HDR){ fprintf(stderr, "short write\n"); return 1; } }
    u64 written = 0, nsparse = 0;
    u8* sparse = malloc((size_t)(c.n / TSP_STRIDE + 2) * TSP_SPARSE); if (!sparse){ fprintf(stderr, "oom (sparse)\n"); return 1; }
    for (int i = 0; i < NBUCKETS; i++){
        snprintf(nm, sizeof nm, "txosp_b%03d.tmp", i);
        struct stat sb; if (stat(nm, &sb) != 0 || sb.st_size == 0){ unlink(nm); continue; }
        u64 cnt = (u64)sb.st_size / sizeof(tsp_rec);
        tsp_rec* arr = malloc((size_t)sb.st_size); if (!arr){ fprintf(stderr, "oom (bucket %d)\n", i); return 1; }
        FILE* bf = fopen(nm, "rb"); if (!bf || fread(arr, 1, (size_t)sb.st_size, bf) != (size_t)sb.st_size){ fprintf(stderr, "cannot read %s\n", nm); return 1; }
        fclose(bf);
        qsort(arr, cnt, sizeof(tsp_rec), rec_cmp);
        for (u64 k = 0; k < cnt; k++){
            if (written % TSP_STRIDE == 0){
                u8* e = sparse + nsparse * TSP_SPARSE; memcpy(e, arr[k].prefix, 12);
                for (int b = 0; b < 4; b++) e[12+b] = (u8)(arr[k].vout >> (8*b));
                u64 off = TSP_HDR + written * TSP_REC; for (int b = 0; b < 8; b++) e[16+b] = (u8)(off >> (8*b));
                nsparse++;
            }
            u8 rec[TSP_REC]; tsp_pack(rec, &arr[k]);
            if (fwrite(rec, 1, TSP_REC, out) != TSP_REC){ fprintf(stderr, "short write\n"); return 1; }
            written++;
        }
        free(arr); unlink(nm);
    }
    u64 sparse_off = TSP_HDR + written * TSP_REC;
    if (fwrite(sparse, 1, (size_t)(nsparse * TSP_SPARSE), out) != nsparse * TSP_SPARSE){ fprintf(stderr, "short write (sparse)\n"); return 1; }
    free(sparse);
    if (fflush(out) || fsync(fileno(out))){ fprintf(stderr, "fsync failed\n"); return 1; }
    { u8 hdr[TSP_HDR]; memset(hdr, 0, sizeof hdr); memcpy(hdr, TSP_MAGIC, 8);
      for (int b = 0; b < 8; b++) hdr[8+b]  = (u8)(written >> (8*b));
      for (int b = 0; b < 8; b++) hdr[16+b] = (u8)(sparse_off >> (8*b));
      for (int b = 0; b < 8; b++) hdr[24+b] = (u8)(nsparse >> (8*b));
      for (int b = 0; b < 4; b++) hdr[32+b] = (u8)((u32)from_h >> (8*b));
      for (int b = 0; b < 4; b++) hdr[36+b] = (u8)((u32)to_h >> (8*b));
      if (fseek(out, 0, SEEK_SET) || fwrite(hdr, 1, TSP_HDR, out) != TSP_HDR){ fprintf(stderr, "short write (header)\n"); return 1; } }
    if (fflush(out) || fsync(fileno(out)) || fclose(out)){ fprintf(stderr, "close failed\n"); return 1; }
    if (rename(TSP_BASE_FILE ".tmp", TSP_BASE_FILE)){ perror("rename"); return 1; }
    fprintf(stderr, "[txospender] DONE: %llu records, %llu sparse, %.2f GB, %llds\n", (unsigned long long)written, (unsigned long long)nsparse, (double)(sparse_off + nsparse * TSP_SPARSE) / 1e9, (long long)(time(NULL) - t0));
    return 0;
}
