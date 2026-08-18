/* daemon/build_addr_index.c -- Stage 3: build a scriptPubKey(hash)->UTXO
 * reverse index from a (Stage 2-)compacted LSM UTXO run file.
 *
 * The LSM store (asm/bitcoin_utxo_lsm.asm) is keyed by outpoint (txid,vout),
 * not owning script -- there's no way to answer "what does address X own"
 * without scanning every record. This tool does that scan ONCE, classifies
 * each record's scriptPubKey (P2PKH/P2WPKH/P2SH/P2WSH/P2TR; anything else
 * -- OP_RETURN, non-standard -- has no address and is skipped, same as
 * real Core's own listunspent), and emits a sorted sidecar file keyed by
 * (type_tag, hash) -> (txid, vout, value), with the same sparse-index-over-
 * sorted-records shape bitcoin_utxo_lsm.asm's own run files use.
 *
 * Two-pass EXTERNAL sort (the input can be many hundreds of millions of
 * records -- too large to qsort in one shot without risking heavy paging):
 *   pass 1: scan the run file once (mmap, sequential), classify+hash each
 *           PUSH record, bucket it into one of 256 temp files by hash[0]
 *           (uniformly distributed since these are hash outputs -- buckets
 *           come out roughly even).
 *   pass 2: for each bucket in turn (comfortably RAM-sized on its own),
 *           qsort it by (type_tag,hash) and append to the final output,
 *           sampling the sparse index as it goes.
 *
 * This is a periodically-*rebuilt* index, not incrementally live-maintained
 * -- deliberately, to avoid touching the live daemon's already-proven UTXO-
 * application code at all. Re-run on a cadence (cron/timer) against the
 * store's current compacted run to keep staleness bounded.
 *
 * Usage: build_addr_index <run_file> <out_file>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>

typedef uint8_t u8; typedef uint64_t u64; typedef uint32_t u32; typedef uint16_t u16;

#define MAGIC_RUN2 0x32555255u   /* "URU2" */
#define MAGIC_ADDR 0x58444155u   /* "UADX" */
#define SPARSE_STRIDE 256
#define NBUCKETS 256

/* record types (mirrors rpc_commands.c's WAL_ADDR_* enum) */
enum { T_INVALID=0, T_P2PKH=1, T_P2WPKH=2, T_P2SH=3, T_P2WSH=4, T_P2TR=5 };

#pragma pack(push,1)
typedef struct { u8 type_tag; u8 hash[32]; u8 txid[32]; u32 vout; u64 value; } addr_rec;   /* 77 bytes */
typedef struct { u8 type_tag; u8 hash[32]; u64 file_off; } sparse_ent;                      /* 41 bytes */
#pragma pack(pop)

static int classify(const u8* s, u32 slen, u8* hash_out /*32 bytes*/) {
    if (slen == 25 && s[0]==0x76 && s[1]==0xa9 && s[2]==0x14 && s[23]==0x88 && s[24]==0xac) {
        memset(hash_out, 0, 32); memcpy(hash_out, s+3, 20); return T_P2PKH;
    }
    if (slen == 22 && s[0]==0x00 && s[1]==0x14) {
        memset(hash_out, 0, 32); memcpy(hash_out, s+2, 20); return T_P2WPKH;
    }
    if (slen == 23 && s[0]==0xa9 && s[1]==0x14 && s[22]==0x87) {
        memset(hash_out, 0, 32); memcpy(hash_out, s+2, 20); return T_P2SH;
    }
    if (slen == 34 && s[0]==0x00 && s[1]==0x20) {
        memcpy(hash_out, s+2, 32); return T_P2WSH;
    }
    if (slen == 34 && s[0]==0x51 && s[1]==0x20) {
        memcpy(hash_out, s+2, 32); return T_P2TR;
    }
    return T_INVALID;
}

static double now_s(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+ts.tv_nsec*1e-9; }

static FILE* bucket_f[NBUCKETS];
static char bucket_path[NBUCKETS][64];

static int cmp_rec(const void* a, const void* b) {
    const addr_rec* ra = a; const addr_rec* rb = b;
    if (ra->type_tag != rb->type_tag) return (int)ra->type_tag - (int)rb->type_tag;
    return memcmp(ra->hash, rb->hash, 32);
}

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <run_file> <out_file>\n", argv[0]); return 2; }
    const char* run_path = argv[1];
    const char* out_path = argv[2];

    int fd = open(run_path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open(%s): %s\n", run_path, strerror(errno)); return 1; }
    struct stat st; if (fstat(fd, &st) != 0) { perror("fstat"); return 1; }
    u64 fsize = (u64)st.st_size;
    u8* base = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 1; }
    close(fd);

    u32 magic; memcpy(&magic, base, 4);
    if (magic != MAGIC_RUN2) { fprintf(stderr, "not a MAGIC_RUN2 run file (magic=%08x) -- run Stage 2 compaction first\n", magic); return 1; }
    u64 gen, nrec, bloom_bits, sparse_off, sparse_n;
    memcpy(&gen, base+4, 8); memcpy(&nrec, base+12, 8); memcpy(&bloom_bits, base+20, 8);
    memcpy(&sparse_off, base+28, 8); memcpy(&sparse_n, base+36, 8);
    u64 bloom_bytes = bloom_bits/8;
    u64 records_start = 44 + bloom_bytes;
    u64 records_end = sparse_off;
    fprintf(stderr, "[addridx] run=%s size=%lu gen=%lu nrec=%lu records=[%lu,%lu)\n",
            run_path, fsize, gen, nrec, records_start, records_end);

    char tmpdir[256]; snprintf(tmpdir, sizeof tmpdir, "%s.buckets", out_path);
    if (mkdir(tmpdir, 0755) != 0 && errno != EEXIST) { perror("mkdir"); return 1; }
    for (int i = 0; i < NBUCKETS; i++) {
        snprintf(bucket_path[i], sizeof bucket_path[i], "%s/b%03d.tmp", tmpdir, i);
        bucket_f[i] = fopen(bucket_path[i], "wb");
        if (!bucket_f[i]) { fprintf(stderr, "fopen(%s): %s\n", bucket_path[i], strerror(errno)); return 1; }
    }

    /* ---- pass 1: scan + classify + bucket ---- */
    double t0 = now_s();
    u64 off = records_start;
    u64 n_push = 0, n_del = 0, n_skipped = 0, n_indexed = 0;
    u64 bucket_counts[NBUCKETS]; memset(bucket_counts, 0, sizeof bucket_counts);
    while (off < records_end) {
        const u8* txid = base + off;
        u32 vout; memcpy(&vout, base+off+32, 4);
        u8 type = base[off+36];
        if (type == 1) {
            n_push++;
            u64 value; memcpy(&value, base+off+37, 8);
            u16 slen; memcpy(&slen, base+off+45, 2);
            const u8* script = base + off + 47;
            u8 hash[32];
            int t = classify(script, slen, hash);
            if (t != T_INVALID) {
                addr_rec r;
                r.type_tag = (u8)t;
                memcpy(r.hash, hash, 32);
                memcpy(r.txid, txid, 32);
                r.vout = vout;
                r.value = value;
                int b = hash[0];
                if (fwrite(&r, sizeof r, 1, bucket_f[b]) != 1) { fprintf(stderr, "bucket write failed\n"); return 1; }
                bucket_counts[b]++;
                n_indexed++;
            } else {
                n_skipped++;
            }
            off += 47 + slen;
        } else if (type == 2) {
            n_del++;
            off += 37;
        } else {
            fprintf(stderr, "[addridx] FATAL: unknown record type %u at off=%lu\n", type, off);
            return 1;
        }
        if ((n_push + n_del) % 50000000 == 0 && (n_push + n_del) > 0) {
            fprintf(stderr, "[addridx] pass1: %lu push %lu del %lu indexed %lu skipped (%.0fs)\n",
                    n_push, n_del, n_indexed, n_skipped, now_s()-t0);
        }
    }
    for (int i = 0; i < NBUCKETS; i++) fclose(bucket_f[i]);
    fprintf(stderr, "[addridx] pass1 done: %lu push %lu del %lu indexed %lu skipped (%.1fs)\n",
            n_push, n_del, n_indexed, n_skipped, now_s()-t0);
    munmap(base, fsize);

    /* ---- pass 2: sort each bucket, append to final output, sample sparse index ---- */
    int outfd = open(out_path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (outfd < 0) { perror("open out"); return 1; }
    /* placeholder header */
    u8 hdr[28]; memset(hdr, 0, sizeof hdr);
    memcpy(hdr, &(u32){MAGIC_ADDR}, 4);
    if (write(outfd, hdr, 28) != 28) { perror("write hdr"); return 1; }

    u64 max_bucket = 0; for (int i=0;i<NBUCKETS;i++) if (bucket_counts[i] > max_bucket) max_bucket = bucket_counts[i];
    addr_rec* buf = malloc((size_t)max_bucket * sizeof(addr_rec));
    if (max_bucket && !buf) { fprintf(stderr, "malloc(%lu recs) failed\n", max_bucket); return 1; }

    sparse_ent* sparse = malloc((size_t)(n_indexed/SPARSE_STRIDE + NBUCKETS + 2) * sizeof(sparse_ent));
    if (!sparse) { fprintf(stderr, "sparse malloc failed\n"); return 1; }
    u64 sparse_count = 0;
    u64 global_idx = 0;
    u64 cur_off = 28;

    double t1 = now_s();
    for (int i = 0; i < NBUCKETS; i++) {
        u64 c = bucket_counts[i];
        if (c == 0) { unlink(bucket_path[i]); continue; }
        FILE* bf = fopen(bucket_path[i], "rb");
        if (!bf) { fprintf(stderr, "reopen bucket %d failed: %s\n", i, strerror(errno)); return 1; }
        if (fread(buf, sizeof(addr_rec), (size_t)c, bf) != (size_t)c) { fprintf(stderr, "bucket %d short read\n", i); return 1; }
        fclose(bf);
        unlink(bucket_path[i]);
        qsort(buf, (size_t)c, sizeof(addr_rec), cmp_rec);
        for (u64 j = 0; j < c; j++) {
            if ((global_idx & (SPARSE_STRIDE-1)) == 0) {
                sparse[sparse_count].type_tag = buf[j].type_tag;
                memcpy(sparse[sparse_count].hash, buf[j].hash, 32);
                sparse[sparse_count].file_off = cur_off;
                sparse_count++;
            }
            ssize_t w = write(outfd, &buf[j], sizeof(addr_rec));
            if (w != (ssize_t)sizeof(addr_rec)) { fprintf(stderr, "final write failed\n"); return 1; }
            cur_off += sizeof(addr_rec);
            global_idx++;
        }
        if ((i % 32) == 0) fprintf(stderr, "[addridx] pass2: bucket %d/%d done (%lu recs, %.0fs)\n", i, NBUCKETS, c, now_s()-t1);
    }
    free(buf);

    u64 sparse_off_final = cur_off;
    if (sparse_count) {
        size_t sbytes = (size_t)sparse_count * sizeof(sparse_ent);
        ssize_t w = write(outfd, sparse, (ssize_t)sbytes);
        if (w != (ssize_t)sbytes) { fprintf(stderr, "sparse write failed\n"); return 1; }
    }
    free(sparse);

    memcpy(hdr, &(u32){MAGIC_ADDR}, 4);
    memcpy(hdr+4, &global_idx, 8);
    memcpy(hdr+12, &sparse_off_final, 8);
    memcpy(hdr+20, &sparse_count, 8);
    if (lseek(outfd, 0, SEEK_SET) != 0) { perror("lseek"); return 1; }
    if (write(outfd, hdr, 28) != 28) { perror("write hdr2"); return 1; }
    close(outfd);
    rmdir(tmpdir);

    fprintf(stderr, "[addridx] DONE: %lu records indexed, sparse_n=%lu, sparse_off=%lu, total=%.1fs\n",
            global_idx, sparse_count, sparse_off_final, now_s()-t0);
    return 0;
}
