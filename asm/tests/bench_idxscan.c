/* bench_idxscan.c -- correctness + before/after throughput for the
 * index.dat positional-record scans that dl_catchup runs every status tick
 * and every worker chunk-claim.
 *
 *   OLD (baseline) : dlc_* -- verbatim copies of the static C functions in
 *                     daemon/main.c (fopen/fseek/fread, one syscall pair per
 *                     record via stdio buffering).
 *   NEW            : idxscan_* -- asm/bitcoin_idxscan.asm, raw
 *                     open/pread64/close syscalls, same semantics.
 *
 * Runs read-only against whatever index.dat is in the given directory (the
 * real production archive if pointed at it) -- safe to run alongside the
 * live daemon since nothing here writes.
 *
 * Usage: bench_idxscan [data_dir]   (defaults to ".")
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

typedef unsigned char u8;

/* ---- baseline: verbatim port of the static functions in daemon/main.c ---- */
static int dlc_chunk_all_present(long lo, long hi){
    FILE* f=fopen("index.dat","rb"); if(!f) return 0;
    unsigned char rec[48]; int all=1;
    for(long k=lo;k<=hi;k++){
        if(fseek(f,k*48,SEEK_SET)!=0 || fread(rec,1,48,f)!=48 || !(rec[0]||rec[1]||rec[2]||rec[3])){ all=0; break; }
    }
    fclose(f);
    return all;
}

static long dlc_index_tip(void){
    FILE* f=fopen("index.dat","rb"); if(!f) return -1;
    fseek(f,0,SEEK_END); long n=ftell(f)/48;
    unsigned char rec[48]; long tip=-1;
    for(long h=n-1; h>=0; h--){
        if(fseek(f,h*48,SEEK_SET)!=0 || fread(rec,1,48,f)!=48) continue;
        if(rec[0]||rec[1]||rec[2]||rec[3]){ tip=h; break; }
    }
    fclose(f); return tip;
}

static long dlc_first_hole(long tip){
    if(tip<0) return -1;
    FILE* f=fopen("index.dat","rb"); if(!f) return -1;
    unsigned char rec[48];
    for(long h=0; h<=tip; h++){
        if(fread(rec,1,48,f)!=48){ fclose(f); return h; }
        if(!(rec[0]||rec[1]||rec[2]||rec[3])){ fclose(f); return h; }
    }
    fclose(f); return -1;
}

static void dlc_scan_progress(long* out_tip, long* out_present){
    FILE* f=fopen("index.dat","rb");
    long tip=-1, present=0;
    if(f){
        fseek(f,0,SEEK_END); long n=ftell(f)/48; fseek(f,0,SEEK_SET);
        unsigned char rec[48];
        for(long h=0; h<n; h++){
            if(fread(rec,1,48,f)!=48) break;
            if(rec[0]||rec[1]||rec[2]||rec[3]){ present++; tip=h; }
        }
        fclose(f);
    }
    *out_tip=tip; *out_present=present;
}

/* ---- new: asm/bitcoin_idxscan.asm ---- */
extern long idxscan_tip(void);
extern long idxscan_first_hole(long tip);
extern long idxscan_all_present(long lo, long hi);
extern void idxscan_progress(long* out_tip, long* out_present);

static double now_s(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return ts.tv_sec + ts.tv_nsec*1e-9;
}

/* Snapshot index.dat into a scratch dir so a concurrently-writing daemon
 * (this is meant to run safely against the live production archive) can't
 * make the C and asm passes see different data between the two calls --
 * that showed up as a spurious 1-record mismatch before this fix. */
static void snapshot_index(const char* src_dir, char* out_dir, size_t out_cap){
    char tmpl[] = "/tmp/bench_idxscan_snapXXXXXX";
    if (!mkdtemp(tmpl)) { perror("mkdtemp"); exit(1); }
    char srcpath[4096], dstpath[4096];
    snprintf(srcpath, sizeof srcpath, "%s/index.dat", src_dir);
    snprintf(dstpath, sizeof dstpath, "%s/index.dat", tmpl);
    /* sized from the two paths it can actually receive: 2 x 4095 + the fixed
     * text, so the cp line can never be cut (-Werror=format-truncation) */
    char cmd[sizeof srcpath + sizeof dstpath + 16];
    snprintf(cmd, sizeof cmd, "cp '%s' '%s'", srcpath, dstpath);
    if (system(cmd) != 0) { fprintf(stderr, "snapshot copy failed\n"); exit(1); }
    snprintf(out_dir, out_cap, "%s", tmpl);
}

int main(int argc, char** argv){
    const char* src = argc > 1 ? argv[1] : ".";
    char snap_dir[4096];
    snapshot_index(src, snap_dir, sizeof snap_dir);
    printf("snapshot: %s/index.dat (frozen copy, immune to concurrent writers)\n\n", snap_dir);
    if (chdir(snap_dir)) { perror("chdir"); return 1; }

    /* ---------- correctness: asm must agree with the C baseline ---------- */
    long c_tip = dlc_index_tip();
    long a_tip = idxscan_tip();
    printf("idxscan_tip:          C=%ld  asm=%ld  %s\n", c_tip, a_tip, c_tip==a_tip ? "MATCH" : "MISMATCH");
    if (c_tip != a_tip) { printf("FAIL tip mismatch\n"); return 1; }

    long c_hole = dlc_first_hole(c_tip);
    long a_hole = idxscan_first_hole(a_tip);
    printf("idxscan_first_hole:   C=%ld  asm=%ld  %s\n", c_hole, a_hole, c_hole==a_hole ? "MATCH" : "MISMATCH");
    if (c_hole != a_hole) { printf("FAIL first_hole mismatch\n"); return 1; }

    long c_ptip, c_present, a_ptip, a_present;
    dlc_scan_progress(&c_ptip, &c_present);
    idxscan_progress(&a_ptip, &a_present);
    printf("idxscan_progress:     C=(tip=%ld,present=%ld)  asm=(tip=%ld,present=%ld)  %s\n",
           c_ptip, c_present, a_ptip, a_present,
           (c_ptip==a_ptip && c_present==a_present) ? "MATCH" : "MISMATCH");
    if (c_ptip != a_ptip || c_present != a_present) { printf("FAIL progress mismatch\n"); return 1; }

    if (c_tip >= 0) {
        /* a few representative chunks: known-present near tip, and a
         * deliberately out-of-range chunk past the tip (all_present must be
         * false for both -- short/EOF read). */
        long chunks[][2] = {
            { c_tip>200 ? c_tip-200 : 0, c_tip>1 ? c_tip-1 : 0 },
            { 0, c_tip>40 ? 40 : c_tip },
            { c_tip+1000, c_tip+1040 },
        };
        for (int i = 0; i < 3; i++) {
            long lo = chunks[i][0], hi = chunks[i][1];
            int c_ap = dlc_chunk_all_present(lo, hi);
            int a_ap = idxscan_all_present(lo, hi) != 0;
            printf("idxscan_all_present[%ld,%ld]: C=%d  asm=%d  %s\n",
                   lo, hi, c_ap, a_ap, c_ap==a_ap ? "MATCH" : "MISMATCH");
            if (c_ap != a_ap) { printf("FAIL all_present mismatch\n"); return 1; }
        }
    }
    printf("\nPASS: asm/C outputs agree on live data\n\n");

    /* ---------- throughput ---------- */
    if (c_tip < 0) { printf("(empty index.dat -- skipping timing)\n"); return 0; }

    const int REPS = 20;
    double t0;
    volatile long sink = 0;

    t0 = now_s();
    for (int r = 0; r < REPS; r++) sink += dlc_index_tip();
    double t_tip_c = now_s() - t0;

    t0 = now_s();
    for (int r = 0; r < REPS; r++) sink += idxscan_tip();
    double t_tip_a = now_s() - t0;

    t0 = now_s();
    for (int r = 0; r < REPS; r++) sink += dlc_first_hole(c_tip);
    double t_hole_c = now_s() - t0;

    t0 = now_s();
    for (int r = 0; r < REPS; r++) sink += idxscan_first_hole(c_tip);
    double t_hole_a = now_s() - t0;

    t0 = now_s();
    for (int r = 0; r < REPS; r++) { long t,p; dlc_scan_progress(&t,&p); sink += t+p; }
    double t_prog_c = now_s() - t0;

    t0 = now_s();
    for (int r = 0; r < REPS; r++) { long t,p; idxscan_progress(&t,&p); sink += t+p; }
    double t_prog_a = now_s() - t0;

    long lo = c_tip>2000 ? c_tip-2000 : 0, hi = c_tip>1 ? c_tip-1 : 0;
    const int REPS_AP = 200;
    t0 = now_s();
    for (int r = 0; r < REPS_AP; r++) sink += dlc_chunk_all_present(lo,hi);
    double t_ap_c = now_s() - t0;

    t0 = now_s();
    for (int r = 0; r < REPS_AP; r++) sink += idxscan_all_present(lo,hi);
    double t_ap_a = now_s() - t0;

    long n_records = c_tip + 1;
    printf("index.dat: %ld records (~%ld heights present, tip=%ld)\n\n", n_records, c_present, c_tip);
    printf("%-28s %10s %10s %10s\n", "function", "C (old)", "asm (new)", "speedup");
    printf("%-28s %9.4fs %9.4fs %9.2fx   (%d reps, full backward scan each)\n",
           "index_tip/idxscan_tip", t_tip_c, t_tip_a, t_tip_c/t_tip_a, REPS);
    printf("%-28s %9.4fs %9.4fs %9.2fx   (%d reps, full forward scan each)\n",
           "first_hole/idxscan_first_hole", t_hole_c, t_hole_a, t_hole_c/t_hole_a, REPS);
    printf("%-28s %9.4fs %9.4fs %9.2fx   (%d reps, full forward scan each)\n",
           "scan_progress/idxscan_progress", t_prog_c, t_prog_a, t_prog_c/t_prog_a, REPS);
    printf("%-28s %9.4fs %9.4fs %9.2fx   (%d reps, %ld-record chunk)\n",
           "chunk_all_present", t_ap_c, t_ap_a, t_ap_c/t_ap_a, REPS_AP, hi-lo+1);
    printf("\n(sink=%ld)\n", sink);
    return 0;
}
