/* bench_hashidx.c -- correctness + before/after throughput for the boot-time
 * hash->height index build (build_hash_index in daemon/main.c).
 *
 *   OLD (baseline) : verbatim copy of build_hash_index's C loop (fopen +
 *                     sequential fread + C byte-reverse + idx_put per record).
 *   NEW            : asm/bitcoin_idx.asm:idx_build_from_file -- buffered
 *                     pread64 (192KB window) doing the same scan/reverse/put
 *                     entirely in one asm call.
 *
 * Runs read-only against a SNAPSHOT of index.dat (copied first) so it's safe
 * to point at the live production archive without racing the daemon's
 * writer or making the two passes see different data.
 *
 * Usage: bench_hashidx [data_dir]   (defaults to ".")
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

typedef unsigned char u8;

#define HT_SLOTS (1<<21)

extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern int  idx_get(void* idx, const unsigned char hash[32], long* height);
extern long idx_count(void* idx);
extern long idx_build_from_file(void* idx, const char* path);

/* ---- baseline: verbatim port of build_hash_index's C loop ---- */
static void build_hash_index_c(void* ht_idx){
    FILE* f=fopen("index.dat","rb"); if(!f) return;
    fseek(f,0,SEEK_END); long n=ftell(f)/48; fseek(f,0,SEEK_SET);
    unsigned char rec[48];
    for(long h=0;h<n;h++){
        if(fread(rec,1,48,f)!=48) break;
        if(rec[0]==0&&rec[1]==0&&rec[2]==0&&rec[3]==0) continue;
        unsigned char le[32]; for(int k=0;k<32;k++) le[k]=rec[31-k];
        idx_put(ht_idx, le, h);
    }
    fclose(f);
}

static double now_s(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return ts.tv_sec + ts.tv_nsec*1e-9;
}

static void snapshot_index(const char* src_dir, char* out_dir, size_t out_cap){
    char tmpl[] = "/tmp/bench_hashidx_snapXXXXXX";
    if (!mkdtemp(tmpl)) { perror("mkdtemp"); exit(1); }
    char srcpath[4096], dstpath[4096], cmd[8320];
    snprintf(srcpath, sizeof srcpath, "%s/index.dat", src_dir);
    snprintf(dstpath, sizeof dstpath, "%s/index.dat", tmpl);
    snprintf(cmd, sizeof cmd, "cp '%.4000s' '%.4000s'", srcpath, dstpath);
    if (system(cmd) != 0) { fprintf(stderr, "snapshot copy failed\n"); exit(1); }
    snprintf(out_dir, out_cap, "%s", tmpl);
}

int main(int argc, char** argv){
    const char* src = argc > 1 ? argv[1] : ".";
    char snap_dir[4096];
    snapshot_index(src, snap_dir, sizeof snap_dir);
    printf("snapshot: %s/index.dat (frozen copy, immune to concurrent writers)\n\n", snap_dir);
    if (chdir(snap_dir)) { perror("chdir"); return 1; }

    void* idx_c = malloc(24 + (size_t)HT_SLOTS*48 + 64);
    void* idx_a = malloc(24 + (size_t)HT_SLOTS*48 + 64);
    if (!idx_c || !idx_a) { fprintf(stderr, "alloc failed\n"); return 1; }
    idx_init(idx_c, HT_SLOTS);
    idx_init(idx_a, HT_SLOTS);

    build_hash_index_c(idx_c);
    long rc = idx_build_from_file(idx_a, "index.dat");
    if (rc != 0) { printf("FAIL idx_build_from_file rc=%ld\n", rc); return 1; }

    long n_c = idx_count(idx_c), n_a = idx_count(idx_a);
    printf("idx_count: C=%ld  asm=%ld  %s\n", n_c, n_a, n_c==n_a ? "MATCH" : "MISMATCH");
    if (n_c != n_a) { printf("FAIL count mismatch\n"); return 1; }

    /* correctness: sample every ~4001st record (odd stride so it doesn't
     * alias any power-of-two structure), confirm both tables idx_get the
     * IDENTICAL result for the exact same (byte-reversed) hash. NOTE: this
     * does NOT assert idx_get returns exactly height h -- the real archive
     * has some genuine hash duplicates across heights (idx_put's documented
     * "0 dup" case keeps the FIRST height a hash was stored under), so the
     * only thing that must hold is that both tables agree with each other,
     * proving the asm conversion is behaviorally identical to the C
     * original, not that idx_put's own dup policy matches this sample. */
    FILE* f = fopen("index.dat","rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long n = ftell(f)/48; fseek(f,0,SEEK_SET);
    unsigned char rec[48];
    long checked=0, bad=0, dup_seen=0;
    for (long h=0; h<n; h++){
        if (fread(rec,1,48,f)!=48) break;
        if (!(rec[0]||rec[1]||rec[2]||rec[3])) continue;
        if (h % 4001 != 0) continue;
        unsigned char le[32]; for(int k=0;k<32;k++) le[k]=rec[31-k];
        long hc=-1, ha=-1;
        int fc = idx_get(idx_c, le, &hc);
        int fa = idx_get(idx_a, le, &ha);
        checked++;
        if (hc!=h || ha!=h) dup_seen++; /* hash duplicated at an earlier height -- expected */
        if (!fc || !fa || fc!=fa || hc!=ha) {
            bad++;
            if (bad<=4) printf("  MISMATCH h=%ld found_c=%d hc=%ld found_a=%d ha=%ld\n", h, fc, hc, fa, ha);
        }
    }
    fclose(f);
    if (bad) { printf("FAIL %ld/%ld sampled lookups disagree between C and asm\n", bad, checked); return 1; }
    printf("PASS %ld sampled idx_get lookups agree between C and asm tables (%ld were duplicate-hash heights)\n\n", checked, dup_seen);

    /* ---------- throughput ---------- */
    void* idx_t1 = malloc(24 + (size_t)HT_SLOTS*48 + 64);
    void* idx_t2 = malloc(24 + (size_t)HT_SLOTS*48 + 64);
    if (!idx_t1 || !idx_t2) { fprintf(stderr, "alloc failed\n"); return 1; }
    const int REPS_C = 1;   /* C baseline is ~180s/rep on the real archive -- I/O-bound and stable, 1 rep is plenty */
    const int REPS_A = 5;
    double t0;

    t0 = now_s();
    for (int r=0;r<REPS_C;r++){ idx_init(idx_t1, HT_SLOTS); build_hash_index_c(idx_t1); }
    double t_c = now_s()-t0;

    t0 = now_s();
    for (int r=0;r<REPS_A;r++){ idx_init(idx_t2, HT_SLOTS); idx_build_from_file(idx_t2, "index.dat"); }
    double t_a = now_s()-t0;

    printf("index.dat: %ld records, %ld indexed\n\n", n, n_c);
    printf("%-28s %10s %10s %10s\n", "build_hash_index", "C (old)", "asm (new)", "speedup");
    printf("%-28s %9.4fs %9.4fs %9.2fx   (C %d rep, asm %d reps, full archive build each)\n",
           "build_hash_index", t_c/REPS_C, t_a/REPS_A, (t_c/REPS_C)/(t_a/REPS_A), REPS_C, REPS_A);
    return 0;
}
