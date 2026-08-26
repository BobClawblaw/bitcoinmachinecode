/* daemon/build_tx_index.c -- txid -> (height, offset, length) index.
 *
 * WHY: `getrawtransaction <txid>` with no blockhash is one of the most-used
 * RPCs there is, and without an index this node had to refuse it -- which is
 * the single most likely thing to break an application swapping this in for
 * Core. It also bounds getblockfilter to the ~200-block undo window, because
 * the spent-prevout scripts a filter needs can otherwise only come from undo
 * data.
 *
 * SIZE, AND WHY THE KEY IS TRUNCATED. Mainnet is ~1.43 billion transactions.
 * A full 32-byte key plus a 12-byte location is 44 bytes per transaction --
 * about 63 GB, plus as much again for the external sort. This index stores
 * only the FIRST 8 BYTES of the txid (20 bytes per record, ~29 GB) and
 * resolves the difference by VERIFICATION: a lookup reads every record
 * sharing the prefix, reads that transaction out of the archive, recomputes
 * its txid, and returns the one that actually matches.
 *
 * That is not a probabilistic shortcut -- it is exact. A prefix collision
 * costs one extra archive read and is then rejected on the full hash, so the
 * answer is always the transaction whose txid was asked for, or none. With
 * ~1.4e9 entries in a 2^64 space a handful of collisions is expected, which
 * is precisely why the reader scans neighbours rather than assuming the
 * first prefix match is the answer.
 *
 * LAYOUT (little-endian throughout):
 *   header, 48 bytes:
 *     "BMCTXIDX" | u64 n_records | u64 sparse_off | u64 sparse_n
 *     | u32 from_height | u32 to_height | u64 reserved
 *   records: n_records x 20 bytes, SORTED by prefix:
 *     u8 prefix[8] | u32 height | u32 offset | u32 len
 *   sparse index: every SPARSE_STRIDE'th record, 16 bytes each:
 *     u8 prefix[8] | u64 byte offset of that record
 *
 * The header is written LAST, after every record is durable, so a crash
 * mid-build leaves a file whose header still describes nothing rather than a
 * partial index that looks whole -- the same discipline wallet_scan.c uses.
 *
 * Two-pass external sort, as build_addr_index.c does and for the same reason:
 * the record set is far too large to hold in memory. Pass 1 walks the archive
 * once and buckets each record by prefix[0] into one of 256 temp files (a
 * hash prefix distributes evenly, so the buckets come out level). Pass 2
 * sorts each bucket on its own -- comfortably RAM-sized -- and appends it,
 * sampling the sparse index as it goes. Because bucket k holds exactly the
 * records whose first byte is k, concatenating buckets in order yields a
 * globally sorted file.
 *
 * Usage: build_tx_index <datadir> [from_height] [to_height]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

extern int  store_init(void* st);
extern int  store_reload(void* st);
extern int  store_rd_init(void* st);
extern long store_read_at(void* st, unsigned long h, void* out, long cap);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);

/* record layout + the per-block transaction walk live in txi_format.h,
 * shared with the daemon's incremental tail writer (tx_index_tail.c) so the
 * two writers cannot drift on what a record means */
#include "txi_format.h"

#define SPARSE_STRIDE 256
#define NBUCKETS    256
#define BLOCKBUF    (4u << 20)

static int rec_cmp(const void* a, const void* b){
    const txi_rec* x = a; const txi_rec* y = b;
    int c = memcmp(x->prefix, y->prefix, 8);
    if (c) return c;
    /* deterministic order within a prefix group, so a rebuild is byte-stable */
    if (x->height != y->height) return x->height < y->height ? -1 : 1;
    if (x->offset != y->offset) return x->offset < y->offset ? -1 : 1;
    return 0;
}

typedef struct { FILE* bucket[NBUCKETS]; u32 height; u64 n; u8* scratch; } pass1_ctx;

static void emit(void* ctxv, const u8* tx, u32 off, u32 len){
    pass1_ctx* c = ctxv;
    u8 txid[32];
    if (tx_txid(txid, tx, len, c->scratch, BLOCKBUF) != 1) return;
    txi_rec r;
    memcpy(r.prefix, txid, 8);          /* txid is WIRE order; so is the key */
    r.height = c->height; r.offset = off; r.len = len;
    if (fwrite(&r, 1, sizeof r, c->bucket[r.prefix[0]]) == sizeof r) c->n++;
}

int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: build_tx_index <datadir> [from] [to]\n"); return 2; }
    const char* dir = argv[1];
    long from_h = argc > 2 ? atol(argv[2]) : 0;
    long to_h   = argc > 3 ? atol(argv[3]) : -1;
    if (chdir(dir)){ perror("chdir"); return 1; }

    static u8 store_buf[4096];
    if (store_init(store_buf) != 1){ fprintf(stderr, "store_init failed\n"); return 1; }
    store_reload(store_buf);
    store_rd_init(store_buf);
    long tip = *(int*)(store_buf + 24);
    if (tip < 0){ fprintf(stderr, "empty store\n"); return 1; }
    if (to_h < 0 || to_h > tip) to_h = tip;
    if (from_h < 0) from_h = 0;
    if (to_h < from_h){ fprintf(stderr, "empty height range\n"); return 1; }

    fprintf(stderr, "[txindex] dir=%s tip=%ld range=[%ld,%ld]\n", dir, tip, from_h, to_h);

    pass1_ctx c; memset(&c, 0, sizeof c);
    c.scratch = malloc(BLOCKBUF);
    u8* blockbuf = malloc(BLOCKBUF);
    if (!c.scratch || !blockbuf){ fprintf(stderr, "oom\n"); return 1; }
    char nm[64];
    for (int i = 0; i < NBUCKETS; i++){
        snprintf(nm, sizeof nm, "txidx_b%03d.tmp", i);
        c.bucket[i] = fopen(nm, "wb");
        if (!c.bucket[i]){ fprintf(stderr, "cannot open %s\n", nm); return 1; }
    }

    time_t t0 = time(NULL);
    for (long h = from_h; h <= to_h; h++){
        long blen = store_read_at(store_buf, (unsigned long)h, blockbuf, BLOCKBUF);
        if (blen < 81){
            /* A height we cannot read is not "no transactions there" -- it is
             * unknown, and an index missing it would answer "no such tx" for
             * every transaction in that block. Abandon rather than mislead. */
            fprintf(stderr, "[txindex] FATAL: block %ld unreadable (%ld); index abandoned\n", h, blen);
            for (int i = 0; i < NBUCKETS; i++) fclose(c.bucket[i]);
            for (int i = 0; i < NBUCKETS; i++){ snprintf(nm, sizeof nm, "txidx_b%03d.tmp", i); unlink(nm); }
            return 1;
        }
        c.height = (u32)h;
        if (!txi_walk_block(blockbuf, blen, emit, &c)){
            fprintf(stderr, "[txindex] FATAL: block %ld is malformed; index abandoned\n", h);
            for (int i = 0; i < NBUCKETS; i++) fclose(c.bucket[i]);
            return 1;
        }
        if ((h - from_h) % 20000 == 0)
            fprintf(stderr, "[txindex] pass1 %ld/%ld (%llu txs, %llds)\n",
                    h, to_h, (unsigned long long)c.n, (long long)(time(NULL) - t0));
    }
    for (int i = 0; i < NBUCKETS; i++) fclose(c.bucket[i]);
    fprintf(stderr, "[txindex] pass1 done: %llu transactions in %llds\n",
            (unsigned long long)c.n, (long long)(time(NULL) - t0));

    /* pass 2: sort each bucket, append, sample the sparse index */
    FILE* out = fopen("txindex.dat.tmp", "wb");
    if (!out){ fprintf(stderr, "cannot open txindex.dat.tmp\n"); return 1; }
    { u8 hdr[TXI_HDR]; memset(hdr, 0, sizeof hdr);
      if (fwrite(hdr, 1, TXI_HDR, out) != TXI_HDR){ fprintf(stderr, "short write\n"); return 1; } }

    u64 written = 0;
    u8* sparse = malloc((c.n / SPARSE_STRIDE + 2) * TXI_SPARSE);
    u64 nsparse = 0;
    if (!sparse){ fprintf(stderr, "oom (sparse)\n"); return 1; }

    for (int i = 0; i < NBUCKETS; i++){
        snprintf(nm, sizeof nm, "txidx_b%03d.tmp", i);
        struct stat sb;
        if (stat(nm, &sb) != 0 || sb.st_size == 0){ unlink(nm); continue; }
        u64 cnt = (u64)sb.st_size / sizeof(txi_rec);
        txi_rec* arr = malloc((size_t)sb.st_size);
        if (!arr){ fprintf(stderr, "oom (bucket %d, %lld bytes)\n", i, (long long)sb.st_size); return 1; }
        FILE* bf = fopen(nm, "rb");
        if (!bf || fread(arr, 1, (size_t)sb.st_size, bf) != (size_t)sb.st_size){
            fprintf(stderr, "cannot read %s\n", nm); return 1; }
        fclose(bf);
        qsort(arr, cnt, sizeof(txi_rec), rec_cmp);
        for (u64 k = 0; k < cnt; k++){
            if (written % SPARSE_STRIDE == 0){
                u8* e = sparse + nsparse * TXI_SPARSE;
                memcpy(e, arr[k].prefix, 8);
                u64 off = TXI_HDR + written * TXI_REC;
                for (int b = 0; b < 8; b++) e[8+b] = (u8)(off >> (8*b));
                nsparse++;
            }
            u8 rec[TXI_REC];
            memcpy(rec, arr[k].prefix, 8);
            for (int b = 0; b < 4; b++) rec[8+b]  = (u8)(arr[k].height >> (8*b));
            for (int b = 0; b < 4; b++) rec[12+b] = (u8)(arr[k].offset >> (8*b));
            for (int b = 0; b < 4; b++) rec[16+b] = (u8)(arr[k].len    >> (8*b));
            if (fwrite(rec, 1, TXI_REC, out) != TXI_REC){ fprintf(stderr, "short write\n"); return 1; }
            written++;
        }
        free(arr);
        unlink(nm);
    }
    u64 sparse_off = TXI_HDR + written * TXI_REC;
    if (fwrite(sparse, 1, (size_t)(nsparse * TXI_SPARSE), out) != nsparse * TXI_SPARSE){
        fprintf(stderr, "short write (sparse)\n"); return 1; }
    free(sparse);

    /* header LAST, after everything above is durable */
    if (fflush(out) || fsync(fileno(out))){ fprintf(stderr, "fsync failed\n"); return 1; }
    { u8 hdr[TXI_HDR]; memset(hdr, 0, sizeof hdr);
      memcpy(hdr, TXI_MAGIC, 8);
      for (int b = 0; b < 8; b++) hdr[8+b]  = (u8)(written >> (8*b));
      for (int b = 0; b < 8; b++) hdr[16+b] = (u8)(sparse_off >> (8*b));
      for (int b = 0; b < 8; b++) hdr[24+b] = (u8)(nsparse >> (8*b));
      for (int b = 0; b < 4; b++) hdr[32+b] = (u8)((u32)from_h >> (8*b));
      for (int b = 0; b < 4; b++) hdr[36+b] = (u8)((u32)to_h >> (8*b));
      if (fseek(out, 0, SEEK_SET) || fwrite(hdr, 1, TXI_HDR, out) != TXI_HDR){
          fprintf(stderr, "short write (header)\n"); return 1; } }
    if (fflush(out) || fsync(fileno(out)) || fclose(out)){ fprintf(stderr, "close failed\n"); return 1; }
    if (rename("txindex.dat.tmp", "txindex.dat")){ perror("rename"); return 1; }

    fprintf(stderr, "[txindex] DONE: %llu records, %llu sparse, %.2f GB, %llds\n",
            (unsigned long long)written, (unsigned long long)nsparse,
            (double)(sparse_off + nsparse * TXI_SPARSE) / 1e9,
            (long long)(time(NULL) - t0));
    return 0;
}
