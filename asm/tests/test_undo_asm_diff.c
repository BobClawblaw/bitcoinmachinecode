/* test_undo_asm_diff.c -- bitcoin_undo.asm vs daemon/undo_log.c, function by
 * function, byte by byte.
 *
 * WHY THIS EXISTS
 *   Phase 1 of the C->asm conversion (2026-08-24) ports undo_log.c to
 *   bitcoin_undo.asm. Every prior asm port has re-opened the same bug
 *   classes (#27 callee-saved clobbers, #28 8-bit SETcc leftovers, #31
 *   locals landing on the save area), and the pattern that caught them was
 *   differential: keep the C alive as the oracle and compare on the same
 *   inputs. This harness links BOTH implementations -- the C compiled with
 *   objcopy-prefixed symbols (ref_*) -- and drives them through identical op
 *   streams in separate directories, comparing:
 *     - the FILES they write (byte-for-byte, the on-disk format IS the
 *       contract: the daemon must be able to read undo files the C wrote
 *       and vice versa across a deploy boundary);
 *     - every return value;
 *     - undo_load's filled undo_rec_t arrays (cross-loaded: asm reads the
 *       C's files, C reads the asm's);
 *     - undo_replay's callback stream (order-sensitive checksum), the
 *       strict/tolerant split on torn files, and the cb-abort contract;
 *     - discard/prune/prune_from return values and surviving file sets.
 *
 * Usage: ./test_undo_asm_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

typedef unsigned char u8; typedef unsigned int u32;
typedef unsigned short u16; typedef unsigned long long u64;

#define UNDO_MAX_SCRIPT 10000
typedef struct { u8 txid[32]; u32 index; u64 value; u32 height;
                 u8 is_coinbase; u16 slen; u8 script[UNDO_MAX_SCRIPT]; } undo_rec_t;
typedef int (*undo_replay_cb)(void* ctx, const u8 txid[32], u32 index,
                              u64 value, u32 height, u8 is_coinbase,
                              const u8* script, u16 slen);

/* the asm twin */
extern long undo_append_record(long h, const u8 txid[32], u32 index, u64 value,
                               u32 utxo_height, u8 is_coinbase, const u8* script, u16 slen);
extern long undo_load(long h, undo_rec_t* out, long max_recs);
extern long undo_replay(long h, undo_replay_cb cb, void* ctx);
extern long undo_replay_tolerant(long h, undo_replay_cb cb, void* ctx, int* torn);
extern long undo_discard(long h);
extern long undo_prune_from(long from, long tip, long window, long max_scan);
extern long undo_prune(long tip, long window);

/* the C oracle, objcopy --redefine-sym'd to ref_* */
extern long ref_undo_append_record(long h, const u8 txid[32], u32 index, u64 value,
                                   u32 utxo_height, u8 is_coinbase, const u8* script, u16 slen);
extern long ref_undo_load(long h, undo_rec_t* out, long max_recs);
extern long ref_undo_replay(long h, undo_replay_cb cb, void* ctx);
extern long ref_undo_replay_tolerant(long h, undo_replay_cb cb, void* ctx, int* torn);
extern long ref_undo_discard(long h);
extern long ref_undo_prune_from(long from, long tip, long window, long max_scan);
extern long ref_undo_prune(long tip, long window);

static int fails = 0;
static void ck(const char* what, long got, long want){
    if (got == want) printf("PASS %-64s (got %ld)\n", what, got);
    else { printf("FAIL %-64s got=%ld exp=%ld\n", what, got, want); fails++; }
}

/* deterministic content */
static u64 rs;
static u64 rnd(void){ rs ^= rs<<13; rs ^= rs>>7; rs ^= rs<<17; return rs; }
static void mk_txid(u8 t[32], u64 tag){ for (int i=0;i<32;i++) t[i]=(u8)(tag*31+i*7+1); }

/* replay callback: order-sensitive FNV over every field */
typedef struct { u64 sum; long calls; long abort_at; } cbctx_t;
static int cb_sum(void* ctxv, const u8 txid[32], u32 index, u64 value,
                  u32 height, u8 is_coinbase, const u8* script, u16 slen){
    cbctx_t* c = (cbctx_t*)ctxv;
    if (c->abort_at >= 0 && c->calls == c->abort_at) return 0;
    u64 s = c->sum;
    for (int i=0;i<32;i++) s = (s ^ txid[i]) * 1099511628211ULL;
    s = (s ^ index) * 1099511628211ULL;
    s = (s ^ value) * 1099511628211ULL;
    s = (s ^ height) * 1099511628211ULL;
    s = (s ^ is_coinbase) * 1099511628211ULL;
    s = (s ^ slen) * 1099511628211ULL;
    for (int i=0;i<slen;i++) s = (s ^ script[i]) * 1099511628211ULL;
    c->sum = s; c->calls++;
    return 1;
}

/* byte-compare one height's file between dirs a/ and b/ */
static int file_eq(long h){
    char pa[96], pb[96];
    snprintf(pa, sizeof pa, "a/undo_%ld.dat", h);
    snprintf(pb, sizeof pb, "b/undo_%ld.dat", h);
    int fa = open(pa, O_RDONLY), fb = open(pb, O_RDONLY);
    if (fa < 0 && fb < 0) return 1;                 /* both absent: equal */
    if (fa < 0 || fb < 0){ if (fa>=0) close(fa); if (fb>=0) close(fb); return 0; }
    static u8 ba[1<<16], bb[1<<16];
    int eq = 1;
    for (;;){
        long ra = read(fa, ba, sizeof ba), rb = read(fb, bb, sizeof bb);
        if (ra != rb || (ra > 0 && memcmp(ba, bb, ra) != 0)){ eq = 0; break; }
        if (ra <= 0) break;
    }
    close(fa); close(fb);
    return eq;
}

static int file_exists(const char* dir, long h){
    char p[96]; snprintf(p, sizeof p, "%s/undo_%ld.dat", dir, h);
    return access(p, F_OK) == 0;
}

/* truncate a file to n bytes (to construct torn tails) in BOTH dirs */
static void truncate_both(long h, long nbytes){
    char p[96];
    snprintf(p, sizeof p, "a/undo_%ld.dat", h); if (truncate(p, nbytes)){ perror("truncate a"); exit(1); }
    snprintf(p, sizeof p, "b/undo_%ld.dat", h); if (truncate(p, nbytes)){ perror("truncate b"); exit(1); }
}

int main(void){
    tt_isolate();
    if (mkdir("a", 0755) || mkdir("b", 0755)){ perror("mkdir"); return 1; }

    static const long HEIGHTS[] = {0, 1, 42, 91842, 99999, 963764};
    static const int  NH = 6;
    static u8 script[UNDO_MAX_SCRIPT];
    for (int i=0;i<UNDO_MAX_SCRIPT;i++) script[i] = (u8)(i*13+5);

    /* ---- 1. append: same op stream to a/ (asm) and b/ (C oracle) ---- */
    rs = 0xdecaf15decaf15ULL;
    for (int hi = 0; hi < NH; hi++){
        long h = HEIGHTS[hi];
        /* deterministic count: the abort-at-1 and torn-tail sections below
         * need height 42 to hold >= 2 records with known layout (k0 slen=0,
         * k1 slen=UNDO_MAX_SCRIPT). A random count of 1 made the abort test
         * vacuous AND turned the 202-byte "truncate" into an EXTENSION whose
         * zero padding parses as valid zero-length records -- both sides
         * agreed (3 == 3), only the test's absolute expectations were wrong. */
        int nrec = 4;
        for (int k = 0; k < nrec; k++){
            u8 txid[32]; mk_txid(txid, h*100 + k);
            u64 r = rnd();
            /* slen sweep hits 0, tiny, and the exact UNDO_MAX_SCRIPT edge */
            u16 slen = (k==0) ? 0 : (k==1) ? UNDO_MAX_SCRIPT : (u16)(r % 200);
            u32 idx = (u32)(r % 5);
            u64 val = r | 1;
            u32 uh  = (u32)(h ? h-1 : 0);
            u8  cbf = (u8)(r & 1);
            long ra, rb;
            if (chdir("a")) return 1;
            ra = undo_append_record(h, txid, idx, val, uh, cbf, script, slen);
            if (chdir("../b")) return 1;
            rb = ref_undo_append_record(h, txid, idx, val, uh, cbf, script, slen);
            if (chdir("..")) return 1;
            if (ra != rb){ printf("FAIL append rc h=%ld k=%d asm=%ld ref=%ld\n", h, k, ra, rb); fails++; }
            if (ra != 1){ printf("FAIL append did not succeed (h=%ld k=%d rc=%ld)\n", h, k, ra); fails++; }
        }
    }
    { int alleq = 1;
      for (int hi = 0; hi < NH; hi++) if (!file_eq(HEIGHTS[hi])) alleq = 0;
      ck("append: every undo_<h>.dat byte-identical asm vs C", alleq, 1); }

    /* ---- 2. load: cross-read (asm loads C's files, C loads asm's) ---- */
    {
        static undo_rec_t ra[16], rb[16];
        int all = 1;
        for (int hi = 0; hi < NH; hi++){
            long h = HEIGHTS[hi];
            memset(ra, 0, sizeof ra); memset(rb, 0, sizeof rb);
            long na, nb;
            if (chdir("b")) return 1;
            na = undo_load(h, ra, 16);          /* asm reads the C's files */
            if (chdir("../a")) return 1;
            nb = ref_undo_load(h, rb, 16);      /* C reads the asm's files */
            if (chdir("..")) return 1;
            if (na != nb || na < 0) all = 0;
            else if (memcmp(ra, rb, (size_t)na * sizeof(undo_rec_t)) != 0) all = 0;
        }
        ck("load: cross-read record arrays identical (memset'd, full stride)", all, 1);
    }
    {   /* max_recs cap honored the same way */
        static undo_rec_t ra[2], rb[2];
        memset(ra, 0, sizeof ra); memset(rb, 0, sizeof rb);
        long na, nb;
        if (chdir("a")) return 1;
        na = undo_load(42, ra, 2);
        if (chdir("../b")) return 1;
        nb = ref_undo_load(42, rb, 2);
        if (chdir("..")) return 1;
        ck("load: max_recs cap identical", na, nb);
    }
    ck("load: absent height reads as 0 (asm)", ({ long v = -99; if (!chdir("a")){ v = undo_load(777777, 0, 0); if (chdir("..")) v = -98; } v; }), 0);

    /* ---- 3. replay: stream checksum + cb-abort + NULL cb ---- */
    {
        int all = 1;
        for (int hi = 0; hi < NH; hi++){
            long h = HEIGHTS[hi];
            cbctx_t ca = { 14695981039346656037ULL, 0, -1 };
            cbctx_t cc = { 14695981039346656037ULL, 0, -1 };
            long na, nb;
            if (chdir("a")) return 1;
            na = undo_replay(h, cb_sum, &ca);
            if (chdir("../b")) return 1;
            nb = ref_undo_replay(h, cb_sum, &cc);
            if (chdir("..")) return 1;
            if (na != nb || ca.sum != cc.sum || ca.calls != cc.calls) all = 0;
        }
        ck("replay: counts and order-sensitive stream checksums identical", all, 1);
    }
    {
        cbctx_t ca = { 1, 0, 1 }, cc = { 1, 0, 1 };   /* abort at record 1 */
        long na, nb;
        if (chdir("a")) return 1;
        na = undo_replay(42, cb_sum, &ca);
        if (chdir("../b")) return 1;
        nb = ref_undo_replay(42, cb_sum, &cc);
        if (chdir("..")) return 1;
        ck("replay: cb abort -> -1 on both", na, nb);
        ck("replay: cb abort is -1 (not a short count)", na, -1);
    }
    {
        long na, nb;
        if (chdir("a")) return 1;
        na = undo_replay(42, 0, 0);
        if (chdir("../b")) return 1;
        nb = ref_undo_replay(42, 0, 0);
        if (chdir("..")) return 1;
        ck("replay: NULL cb just counts, identically", na, nb);
    }

    /* ---- 4. torn tails: strict vs tolerant, short header and short script ---- */
    {
        /* height 1's file: truncate to 30 bytes (mid-header) */
        truncate_both(1, 30);
        long na, nb; int ta = 7, tb = 7;
        if (chdir("a")) return 1;
        na = undo_replay(1, 0, 0);
        if (chdir("../b")) return 1;
        nb = ref_undo_replay(1, 0, 0);
        if (chdir("..")) return 1;
        ck("torn header: strict replay -1 on both", na, nb);
        ck("torn header: strict is -1", na, -1);
        if (chdir("a")) return 1;
        na = undo_replay_tolerant(1, 0, 0, &ta);
        if (chdir("../b")) return 1;
        nb = ref_undo_replay_tolerant(1, 0, 0, &tb);
        if (chdir("..")) return 1;
        ck("torn header: tolerant count identical", na, nb);
        ck("torn header: torn flag set on both", (long)ta*10+tb, 11);
    }
    {
        /* height 42: cut mid-script -- first record is slen=0 (51 bytes),
         * second is slen=UNDO_MAX_SCRIPT; cut into its script region */
        truncate_both(42, 51 + 51 + 100);
        long na, nb; int ta = 7, tb = 7;
        if (chdir("a")) return 1;
        na = undo_replay(42, 0, 0);
        if (chdir("../b")) return 1;
        nb = ref_undo_replay(42, 0, 0);
        if (chdir("..")) return 1;
        ck("torn script: strict replay -1 on both", na, nb);
        if (chdir("a")) return 1;
        na = undo_replay_tolerant(42, 0, 0, &ta);
        if (chdir("../b")) return 1;
        nb = ref_undo_replay_tolerant(42, 0, 0, &tb);
        if (chdir("..")) return 1;
        ck("torn script: tolerant counts identical", na, nb);
        ck("torn script: tolerant stops after the intact record", na, 1);
        ck("torn script: torn flag set on both", (long)ta*10+tb, 11);
    }
    {
        /* oversized slen is corruption in BOTH modes: forge one */
        int fd;
        u8 bad[51]; memset(bad, 0, sizeof bad); bad[49] = 0xff; bad[50] = 0xff; /* slen=0xffff */
        if (chdir("a")) return 1;
        fd = open("undo_500.dat", O_WRONLY|O_CREAT|O_TRUNC, 0644); if (write(fd, bad, 51) != 51){ perror("write undo_500"); exit(1); } close(fd);
        if (chdir("../b")) return 1;
        fd = open("undo_500.dat", O_WRONLY|O_CREAT|O_TRUNC, 0644); if (write(fd, bad, 51) != 51){ perror("write undo_500"); exit(1); } close(fd);
        if (chdir("..")) return 1;
        long na, nb; int ta = 7, tb = 7;
        if (chdir("a")) return 1;
        na = undo_replay_tolerant(500, 0, 0, &ta);
        if (chdir("../b")) return 1;
        nb = ref_undo_replay_tolerant(500, 0, 0, &tb);
        if (chdir("..")) return 1;
        ck("oversized slen: -1 even in tolerant mode, on both", na, nb);
        ck("oversized slen: is -1", na, -1);
    }

    /* ---- 5. discard / prune / prune_from ---- */
    {
        long da, db;
        if (chdir("a")) return 1;
        da = undo_discard(500);
        if (chdir("../b")) return 1;
        db = ref_undo_discard(500);
        if (chdir("..")) return 1;
        ck("discard: removed -> 1 on both", da*10+db, 11);
        if (chdir("a")) return 1;
        da = undo_discard(500);
        if (chdir("../b")) return 1;
        db = ref_undo_discard(500);
        if (chdir("..")) return 1;
        ck("discard: second time -> 0 on both", da*10+db, 0);
    }
    {
        /* prune_from: sweep [0..91842) in bounded steps; both sides must
         * report the same cursors and end with the same surviving files */
        long ca = 0, cc = 0, guard = 0;
        for (;;){
            long na, nb;
            if (chdir("a")) return 1;
            na = undo_prune_from(ca, 963764, 963764-91842+1, 40000);
            if (chdir("../b")) return 1;
            nb = ref_undo_prune_from(cc, 963764, 963764-91842+1, 40000);
            if (chdir("..")) return 1;
            if (na != nb){ printf("FAIL prune_from cursor asm=%ld ref=%ld\n", na, nb); fails++; break; }
            if (na == ca) break;
            ca = na; cc = nb;
            if (++guard > 10){ printf("FAIL prune_from did not converge\n"); fails++; break; }
        }
        ck("prune_from: converged cursor at keep_from", ca, 91842);
        int surv = file_exists("a",91842) && file_exists("b",91842)
                && !file_exists("a",42)   && !file_exists("b",42)
                && !file_exists("a",0)    && !file_exists("b",0)
                && file_exists("a",99999) && file_exists("b",99999);
        ck("prune_from: identical survivors (91842+ kept, below gone)", surv, 1);
        /* bad-args early returns */
        ck("prune_from: bad args return from_height (asm)", undo_prune_from(5, -1, 10, 10), 5);
        ck("prune_from: bad args return from_height (C)",   ref_undo_prune_from(5, -1, 10, 10), 5);
    }
    {
        long pa, pb;
        if (chdir("a")) return 1;
        pa = undo_prune(963764, 100);
        if (chdir("../b")) return 1;
        pb = ref_undo_prune(963764, 100);
        if (chdir("..")) return 1;
        ck("prune: removed counts identical", pa, pb);
        int gone = !file_exists("a",91842) && !file_exists("b",91842)
                && !file_exists("a",99999) && !file_exists("b",99999)
                && file_exists("a",963764) && file_exists("b",963764);
        ck("prune: window enforced identically (only tip-window survivors)", gone, 1);
        ck("prune: bad window -> 0 (asm)", undo_prune(10, 0), 0);
    }

    /* ---- 6. negative height formats identically (oracle uses %ld) ---- */
    {
        u8 txid[32]; mk_txid(txid, 9);
        long ra, rb;
        if (chdir("a")) return 1;
        ra = undo_append_record(-7, txid, 0, 1, 0, 0, script, 4);
        if (chdir("../b")) return 1;
        rb = ref_undo_append_record(-7, txid, 0, 1, 0, 0, script, 4);
        if (chdir("..")) return 1;
        ck("negative height: append rc identical", ra, rb);
        ck("negative height: undo_-7.dat byte-identical", file_eq(-7), 1);
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
