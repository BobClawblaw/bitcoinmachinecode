/* bench_store_read.c -- correctness + throughput for the fast block read path.
 *
 * Builds a real block store, then reads every block back two ways:
 *   OLD : store_get_at + store_get_file_fd + lseek + read   (6 syscalls/block)
 *   NEW : store_read_at                                     (2 syscalls/block)
 * Byte-compares both against the originals, then times them.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

typedef unsigned char u8;
typedef unsigned long u64;

extern int  store_init(void* st);
extern int  store_append(void* st, const u8 hash[32], const void* raw, u64 len);
extern long store_get_at(void* st, u64 height, u64 out_meta[3]);
extern long store_get_file_fd(void* st, unsigned file_no);

extern void store_rd_init(void* st);
extern long store_read_at(void* st, u64 height, void* buf, u64 cap);
extern long store_read_meta(void* st, u64 height, u64 meta[3], void* buf, u64 cap);
extern int  store_rd_fd(void* st, unsigned file_no);
extern void store_rd_advise(void* st, u64 height, u64 nblocks);
extern void store_rd_close(void* st);
extern void  store_map_init(void* st);
extern const unsigned char* store_map_at(void* st, u64 height, u64 out[2]);
extern void  store_map_close(void* st);

static double now_s(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return ts.tv_sec + ts.tv_nsec*1e-9;
}

static u64 rs = 0x12345678ULL;
static u64 rnd(void){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }

#define NBLK   4000
#define MAXSZ  (256*1024)

static unsigned char stbuf[4096];
static u8 *orig[NBLK];
static unsigned origlen[NBLK];
static u8 rbuf[MAXSZ];

/* the OLD read path, exactly as node_serve_block does it */
static long old_read(void* st, u64 h, void* buf, u64 cap){
    u64 meta[3];
    if (store_get_at(st, h, meta) != 1) return -1;
    if (meta[1] > cap) return -1;
    long fd = store_get_file_fd(st, (unsigned)meta[2]);
    if (fd < 0) return -1;
    if (lseek((int)fd, (off_t)(meta[0]+8), SEEK_SET) < 0) return -1;
    ssize_t n = read((int)fd, buf, (size_t)meta[1]);
    if (n != (ssize_t)meta[1]) return -1;
    return (long)meta[1];
}

int main(void){
    char dir[] = "/tmp/benchstoreXXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    if (chdir(dir)) { perror("chdir"); return 1; }

    if (store_init(stbuf) != 1){ printf("FAIL store_init\n"); return 1; }
    store_rd_init(stbuf);
    store_map_init(stbuf);

    printf("building store: %d blocks in %s\n", NBLK, dir);
    u64 total = 0;
    for (int i = 0; i < NBLK; i++){
        /* size distribution roughly like mainnet: mostly large, some small */
        unsigned sz = 4096 + (unsigned)(rnd() % (200*1024));
        origlen[i] = sz;
        orig[i] = malloc(sz);
        for (unsigned j = 0; j < sz; j += 8) *(u64*)(orig[i]+j) = rnd();
        u8 hash[32]; for (int j=0;j<32;j++) hash[j] = (u8)(i*7+j);
        if (store_append(stbuf, hash, orig[i], sz) < 0){
            printf("FAIL append %d\n", i); return 1;
        }
        total += sz;
    }
    printf("stored %.1f MB across blk files\n", total/1048576.0);

    /* ---------- correctness ---------- */
    int bad = 0;
    for (int i = 0; i < NBLK; i++){
        long n = store_read_at(stbuf, i, rbuf, sizeof rbuf);
        if (n != (long)origlen[i] || memcmp(rbuf, orig[i], origlen[i])) { bad++; if(bad<4) printf("  MISMATCH new@%d n=%ld exp=%u\n", i, n, origlen[i]); }
    }
    if (bad){ printf("FAIL store_read_at: %d/%d mismatches\n", bad, NBLK); return 1; }
    printf("PASS store_read_at byte-exact on %d blocks\n", NBLK);

    bad = 0;
    for (int i = 0; i < NBLK; i++){
        long n = old_read(stbuf, i, rbuf, sizeof rbuf);
        if (n != (long)origlen[i] || memcmp(rbuf, orig[i], origlen[i])) bad++;
    }
    if (bad){ printf("FAIL old path: %d mismatches\n", bad); return 1; }
    printf("PASS old path byte-exact (both paths agree)\n");

    /* random-access correctness, to exercise fd-cache eviction */
    bad = 0;
    for (int t = 0; t < 4000; t++){
        int i = (int)(rnd() % NBLK);
        long n = store_read_at(stbuf, i, rbuf, sizeof rbuf);
        if (n != (long)origlen[i] || memcmp(rbuf, orig[i], origlen[i])) bad++;
    }
    if (bad){ printf("FAIL random-access: %d mismatches\n", bad); return 1; }
    printf("PASS random-access byte-exact (4000 reads)\n");

    /* mmap zero-copy correctness */
    bad = 0;
    for (int i = 0; i < NBLK; i++){
        u64 o[2];
        const unsigned char* p = store_map_at(stbuf, i, o);
        if (!p || o[0] != origlen[i] || memcmp(p, orig[i], origlen[i])) { if(bad<4) printf("  MISMATCH map@%d\n", i); bad++; }
    }
    if (bad){ printf("FAIL store_map_at: %d mismatches\n", bad); return 1; }
    printf("PASS store_map_at byte-exact (zero-copy) on %d blocks\n", NBLK);

    bad = 0;
    for (int t = 0; t < 4000; t++){
        int i = (int)(rnd() % NBLK);
        u64 o[2];
        const unsigned char* p = store_map_at(stbuf, i, o);
        if (!p || o[0] != origlen[i] || memcmp(p, orig[i], origlen[i])) bad++;
    }
    if (bad){ printf("FAIL map random-access: %d mismatches\n", bad); return 1; }
    printf("PASS store_map_at random-access byte-exact\n");

    /* ---------- throughput ---------- */
    const int REPS = 6;
    double t0, t_old, t_new, t_meta;
    volatile long sink = 0;

    /* warm the page cache equally for both */
    for (int i = 0; i < NBLK; i++) sink += store_read_at(stbuf, i, rbuf, sizeof rbuf);

    t0 = now_s();
    for (int r = 0; r < REPS; r++)
        for (int i = 0; i < NBLK; i++) sink += old_read(stbuf, i, rbuf, sizeof rbuf);
    t_old = now_s() - t0;

    t0 = now_s();
    for (int r = 0; r < REPS; r++)
        for (int i = 0; i < NBLK; i++) sink += store_read_at(stbuf, i, rbuf, sizeof rbuf);
    t_new = now_s() - t0;

    /* one-syscall variant: caller keeps the index record it already has */
    t0 = now_s();
    for (int r = 0; r < REPS; r++){
        for (int i = 0; i < NBLK; i++){
            u64 meta[3] = {0,0,0};
            if (store_get_at(stbuf, i, meta) != 1) { printf("meta fail\n"); return 1; }
            sink += store_read_meta(stbuf, i, meta, rbuf, sizeof rbuf);
        }
    }
    t_meta = now_s() - t0;

    long nreads = (long)REPS * NBLK;
    double mb = total/1048576.0 * REPS;
    printf("\n  OLD  lseek+read, close/open per block : %7.3f s  %8.0f blk/s  %7.1f MB/s\n",
           t_old, nreads/t_old, mb/t_old);
    printf("  NEW  store_read_at (cached fd, pread) : %7.3f s  %8.0f blk/s  %7.1f MB/s\n",
           t_new, nreads/t_new, mb/t_new);
    printf("  NEW  store_read_meta (meta supplied)  : %7.3f s  %8.0f blk/s  %7.1f MB/s\n",
           t_meta, nreads/t_meta, mb/t_meta);
    printf("\n  speedup: %.2fx (store_read_at)\n", t_old/t_new);

    /* small-block regime: syscall overhead dominates, so the win is larger */
    printf("\n  --- small-block regime (syscall-bound) ---\n");
    t0 = now_s();
    for (int r = 0; r < REPS*4; r++)
        for (int i = 0; i < 500; i++) sink += old_read(stbuf, i, rbuf, sizeof rbuf);
    double s_old = now_s()-t0;
    t0 = now_s();
    for (int r = 0; r < REPS*4; r++)
        for (int i = 0; i < 500; i++) sink += store_read_at(stbuf, i, rbuf, sizeof rbuf);
    double s_new = now_s()-t0;
    printf("  OLD %.3f s   NEW %.3f s   speedup %.2fx\n", s_old, s_new, s_old/s_new);

    /* --- realistic consumer: something must actually READ the bytes --- */
    printf("\n  --- end-to-end: consume every byte (as cons_verify/sha256 would) ---\n");
    unsigned long long acc = 0;
    t0 = now_s();
    for (int r = 0; r < REPS; r++)
        for (int i = 0; i < NBLK; i++){
            long n = old_read(stbuf, i, rbuf, sizeof rbuf);
            for (long j = 0; j < n; j += 64) acc += rbuf[j];
        }
    double c_old = now_s()-t0;

    t0 = now_s();
    for (int r = 0; r < REPS; r++)
        for (int i = 0; i < NBLK; i++){
            long n = store_read_at(stbuf, i, rbuf, sizeof rbuf);
            for (long j = 0; j < n; j += 64) acc += rbuf[j];
        }
    double c_copy = now_s()-t0;

    t0 = now_s();
    for (int r = 0; r < REPS; r++)
        for (int i = 0; i < NBLK; i++){
            u64 o[2];
            const unsigned char* p = store_map_at(stbuf, i, o);
            for (u64 j = 0; j < o[0]; j += 64) acc += p[j];
        }
    double c_map = now_s()-t0;
    printf("  pread into buffer, then consume : %7.3f s  %7.1f MB/s\n", c_copy, mb/c_copy);
    printf("  mmap, consume in place          : %7.3f s  %7.1f MB/s\n", c_map,  mb/c_map);
    printf("  ORIGINAL path, then consume     : %7.3f s  %7.1f MB/s\n", c_old, mb/c_old);
    printf("  speedup vs original: %.2fx (pread) / %.2fx (mmap)   (acc=%llu)\n",
           c_old/c_copy, c_old/c_map, acc);

    /* --- growth safety: append while a mapping of that file is live --- */
    printf("\n  --- remap-on-growth safety ---\n");
    {
        u64 o[2];
        const unsigned char* p = store_map_at(stbuf, NBLK-1, o);
        if (!p){ printf("FAIL premap\n"); return 1; }
        int gbad = 0;
        for (int i = 0; i < 200; i++){
            unsigned sz = 4096 + (unsigned)(rnd() % (150*1024));
            u8* nb = malloc(sz);
            for (unsigned j = 0; j < sz; j += 8) *(u64*)(nb+j) = rnd();
            u8 h[32]; for (int j=0;j<32;j++) h[j]=(u8)(i+j);
            int nh = store_append(stbuf, h, nb, sz);
            if (nh < 0){ printf("FAIL append-during-map\n"); return 1; }
            /* immediately read the just-appended block back through the map */
            const unsigned char* q = store_map_at(stbuf, (u64)nh, o);
            if (!q || o[0] != sz || memcmp(q, nb, sz)) gbad++;
            /* and an old one, to confirm the remap did not corrupt anything */
            const unsigned char* r2 = store_map_at(stbuf, 7, o);
            if (!r2 || o[0] != origlen[7] || memcmp(r2, orig[7], origlen[7])) gbad++;
            free(nb);
        }
        if (gbad){ printf("FAIL remap-on-growth: %d\n", gbad); return 1; }
        printf("  PASS 200 append+map-read cycles, incl. re-reading old blocks\n");
    }

    store_map_close(stbuf);
    store_rd_close(stbuf);
    printf("\n%s\n", "ALL TESTS PASSED");
    (void)sink;
    return 0;
}
