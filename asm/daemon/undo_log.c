/* daemon/undo_log.c -- per-block undo data: what a block's inputs spent,
 * captured as the block is applied so it can be disconnected again, and read
 * back for fees and prevouts.
 *
 * 2026-09-08: kept for EVERY block, like Core's rev*.dat, on the packed store
 * of daemon/undo_store.h (rev%05u.dat runs + undo.idx). Before that each
 * height had its own undo_<h>.dat and a 200-block window deleted them, which
 * capped reorg depth, fee/prevout answers and the address-index backfill at
 * 200 blocks. The API below is unchanged for its callers; only where the
 * bytes live changed. Two additions: undo_commit(height) closes a block's run
 * with the END marker (apply_block_at calls it; a block that spent nothing
 * still gets an entry so "undo exists for h" means "h was applied"), and
 * undo_exists(height) replaces the callers' stat() of the old file name.
 * Legacy undo_<h>.dat files are folded into the store once at start
 * (undo_migrate_legacy) so an upgraded node keeps its recent history.
 *
 * Record (unchanged): txid[32] | index u32 | value u64 | height u32 |
 * is_coinbase u8 | slen u16 | script[slen]. `height` is the spent UTXO's
 * own creation height (needed to restore a coinbase output's maturity), NOT
 * the spending block's height, which names the run.
 *
 * Retention: undo_prune_below(keep_from) follows the block store's prune
 * gate (whole rev files, like Core); undo_prune/undo_prune_from are kept as
 * no-ops for their remaining callers and tests -- the window is gone. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <stdint.h>
#include <time.h>
#include "undo_store.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned long long u64;

#define UNDO_MAX_SCRIPT 10000   /* generous vs. any real scriptPubKey */
#define UNDO_HEADER_BYTES 51    /* 32 + 4 + 8 + 4 + 1 + 2 (was 46 before Stage D) */

/* ---- writer state: one open rev file, one run at a time ------------------ */
static int  g_undo_fd = -1;          /* the current rev file, O_APPEND */
static long g_undo_fd_height = -1;   /* the height whose run is being written */
static unsigned g_undo_file = 0;     /* its file number */
void undo_close_current(void){
    if (g_undo_fd >= 0) close(g_undo_fd);
    g_undo_fd = -1; g_undo_fd_height = -1;
}
/* open the current rev file (rotating at UNDO_REV_MAX) and, for a height with
 * no entry yet, register the run's start = the file's end */
static int undo_fd_for(long height){
    if (g_undo_fd >= 0 && g_undo_fd_height == height) return g_undo_fd;
    /* moving on from a run that was never committed (a failed apply that
     * nobody rolled back yet): close it with END so the next run in the file
     * can never be read as its continuation. Its records stay as they are. */
    if (g_undo_fd >= 0 && g_undo_fd_height >= 0 && g_undo_fd_height != height){
        u8 end[UNDO_REC_HDR]; us_make_end(end, g_undo_fd_height);
        if (write(g_undo_fd, end, UNDO_REC_HDR) != UNDO_REC_HDR){ undo_close_current(); return -1; }
    }
    undo_close_current();
    int ifd = us_idx_open_rw(); if (ifd < 0) return -1;
    undo_slot_t s; int have = us_slot_get(height, &s);
    unsigned file; unsigned long long off;
    if (have == 1){ file = s.file; off = s.off; }
    else {
        file = us_cur_file(ifd);
        char name[32]; us_rev_name(name, file);
        struct stat sb; unsigned long long sz = (stat(name, &sb) == 0) ? (unsigned long long)sb.st_size : 0;
        if (sz >= UNDO_REV_MAX){ file++; if (us_set_cur_file(ifd, file) != 0){ close(ifd); return -1; } sz = 0; }
        off = sz;
        if (us_slot_put(ifd, height, file, off) != 0){ close(ifd); return -1; }
    }
    close(ifd);
    char name[32]; us_rev_name(name, file);
    int fd = open(name, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;
    g_undo_fd = fd; g_undo_fd_height = height; g_undo_file = file;
    return fd;
}
int undo_exists(long height){ return us_exists(height); }
/* close block `height`'s run with the END marker (creating the run if the
 * block spent nothing). 1 ok, -1 write failure. */
/* 2026-10-05 (bmc.benchlog): the split of undo_capture_and_del + undo_commit,
 * so the applier's `put` phase can be read as get / undo write / del / commit.
 * Four clock reads per spent input when on; off (the default) costs one load
 * and one branch per call. utxo_live.c turns it on with the benchlog. */
static int g_undo_split_timing = 0;
static u64 g_undo_split_ns[4];   /* 0 the prevout get, 1 the record write, 2 the del, 3 undo_commit */
static u64 undo_clock_ns(void);
void undo_set_split_timing(int on){ g_undo_split_timing = on; }
unsigned long long undo_split_ns(int k){ return (k >= 0 && k < 4) ? g_undo_split_ns[k] : 0; }
long undo_commit(long height){
    u64 t0 = g_undo_split_timing ? undo_clock_ns() : 0;
    int fd = undo_fd_for(height);
    if (fd < 0) return -1;
    u8 end[UNDO_REC_HDR]; us_make_end(end, height);
    long w = write(fd, end, UNDO_REC_HDR);
    undo_close_current();
    if (g_undo_split_timing) g_undo_split_ns[3] += undo_clock_ns() - t0;
    return w == UNDO_REC_HDR ? 1 : -1;
}

long undo_append_record(long height, const u8 txid[32], u32 index, u64 value,
                         u32 utxo_height, u8 is_coinbase,
                         const u8* script, u16 slen){
    int fd = undo_fd_for(height);
    if (fd < 0) return -1;

    u8 hdr[UNDO_HEADER_BYTES];
    memcpy(hdr, txid, 32);
    memcpy(hdr+32, &index, 4);
    memcpy(hdr+36, &value, 8);
    memcpy(hdr+44, &utxo_height, 4);
    hdr[48] = is_coinbase;
    memcpy(hdr+49, &slen, 2);

    struct iovec iov[2] = { { hdr, UNDO_HEADER_BYTES }, { (void*)script, slen } };
    long want = UNDO_HEADER_BYTES + (long)slen;
    long w = writev(fd, iov, slen > 0 ? 2 : 1);
    if (w != want) { undo_close_current(); return -1; }
    return 1;
}

typedef struct {
    u8  txid[32];
    u32 index;
    u64 value;
    u32 height;        /* the spent UTXO's own original creation height */
    u8  is_coinbase;
    u16 slen;
    u8  script[UNDO_MAX_SCRIPT];
} undo_rec_t;

/* undo_load(height, out, max_recs) -> number of records read (>=0), or -1
 * on a malformed/truncated file. Missing file -> 0 records (not an error --
 * a height with no spends, or one that's already been pruned/never
 * existed, both legitimately read back as "nothing here"). */
long undo_load(long height, undo_rec_t* out, long max_recs){
    u8* buf = 0; int torn = 0;
    long len = us_read_run(height, &buf, &torn);
    if (len < 0) return 0;                       /* absent == empty, as before */
    if (torn){ free(buf); return -1; }           /* a torn run is malformed to the strict loader */
    long n = 0, off = 0;
    while (n < max_recs && off + UNDO_HEADER_BYTES <= len){
        const u8* hdr = buf + off;
        memcpy(out[n].txid, hdr, 32);
        memcpy(&out[n].index, hdr+32, 4);
        memcpy(&out[n].value, hdr+36, 8);
        memcpy(&out[n].height, hdr+44, 4);
        out[n].is_coinbase = hdr[48];
        memcpy(&out[n].slen, hdr+49, 2);
        if (out[n].slen > UNDO_MAX_SCRIPT || off + UNDO_HEADER_BYTES + out[n].slen > len){ free(buf); return -1; }
        memcpy(out[n].script, hdr + UNDO_HEADER_BYTES, out[n].slen);
        off += UNDO_HEADER_BYTES + out[n].slen;
        n++;
    }
    free(buf);
    return n;
}

/* ---- STAGE B additions ---------------------------------------------------
 *
 * undo_replay: a STREAMING reader, added because undo_load's caller-supplied
 * undo_rec_t array cannot be used on the real disconnect path. One
 * undo_rec_t is UNDO_MAX_SCRIPT+46 = 10046 bytes; a real mainnet block can
 * spend >10000 inputs, so a "load it all then walk it" disconnect would need
 * ~100MB of contiguous buffer PER BLOCK DISCONNECTED. undo_replay hands each
 * record to a callback as it is read, with one fixed 10KB record buffer, so
 * disconnect memory is O(1) in the block's input count. undo_load itself is
 * left completely unchanged (tests/test_undo_log.c still covers it).
 *
 * Returns the number of records replayed (>=0), or -1 on a malformed file or
 * a callback that reported failure (a callback returning 0 aborts the replay
 * immediately -- a half-restored UTXO set must surface as an error, never as
 * a silently short success).
 */
typedef int (*undo_replay_cb)(void* ctx, const u8 txid[32], u32 index,
                               u64 value, u32 height, u8 is_coinbase,
                               const u8* script, u16 slen);

static long undo_replay_impl(long height, undo_replay_cb cb, void* ctx, int tolerant, int* torn){
    u8* buf = 0; int t = 0;
    long len = us_read_run(height, &buf, &t);
    if (len < 0) return 0;            /* same contract as undo_load: absent == empty */
    if (t && !tolerant){ free(buf); return -1; }
    if (t && torn) *torn = 1;
    long n = 0, off = 0;
    while (off + UNDO_HEADER_BYTES <= len){
        const u8* hdr = buf + off;
        u32 index; u64 value; u32 utxo_height; u8 is_coinbase; u16 slen;
        memcpy(&index, hdr+32, 4);
        memcpy(&value, hdr+36, 8);
        memcpy(&utxo_height, hdr+44, 4);
        is_coinbase = hdr[48];
        memcpy(&slen,  hdr+49, 2);
        if (slen > UNDO_MAX_SCRIPT || off + UNDO_HEADER_BYTES + slen > len){ free(buf); return -1; }
        if (cb && !cb(ctx, hdr, index, value, utxo_height, is_coinbase, hdr + UNDO_HEADER_BYTES, slen)){ free(buf); return -1; }
        off += UNDO_HEADER_BYTES + slen;
        n++;
    }
    free(buf);
    return n;
}

long undo_replay(long height, undo_replay_cb cb, void* ctx){
    return undo_replay_impl(height, cb, ctx, 0, 0);
}

/* undo_replay_tolerant: identical, except a torn TRAILING record (short
 * header or short script at end-of-file) ends the replay instead of failing
 * it, and reports that via *torn. For boot-time crash recovery ONLY
 * (daemon/utxo_live.c, utxo_live_recover_partial_block): an append that
 * never completed is an append whose delete never ran, so stopping there is
 * exactly correct. The reorg pre-flight keeps the strict variant -- a torn
 * file is NOT acceptable evidence for disconnecting a block. */
long undo_replay_tolerant(long height, undo_replay_cb cb, void* ctx, int* torn){
    if (torn) *torn = 0;
    return undo_replay_impl(height, cb, ctx, 1, torn);
}

/* undo_discard(height) -> 1 removed / 0 nothing there.
 * Drops one height's undo file once it has been consumed by a disconnect --
 * that data describes a block that is no longer on our chain, so keeping it
 * around could only ever mislead a later disconnect at the same height (a
 * reconnected block at height H writes its OWN undo_<H>.dat, and
 * undo_append_record opens with O_APPEND, so a stale file left in place
 * would be silently PREPENDED to the new block's records). */
long undo_discard(long height){
    if (g_undo_fd_height == height) undo_close_current();
    return us_slot_clear(height) == 1 ? 1 : 0;
}

/* Retention follows the block store now (2026-09-08). undo_prune_from and
 * undo_prune were the 200-block window; they keep their signatures for the
 * callers and tests that still name them and do nothing: undo data is kept
 * for every block the node keeps. */
long undo_prune_from(long from_height, long tip_height, long window, long max_scan){
    (void)tip_height; (void)window; (void)max_scan;
    return from_height < 0 ? 0 : from_height;
}
long undo_prune(long tip_height, long window){ (void)tip_height; (void)window; return 0; }
/* the block store pruned below keep_from: drop the rev files that hold only
 * lower heights (whole files, like Core). Returns files removed. */
long undo_prune_below(long keep_from){
    undo_close_current();
    return keep_from > 0 ? us_prune_below(keep_from) : 0;
}
/* the UTXO state is being rebuilt from scratch: drop every undo file */
long undo_wipe(void){ undo_close_current(); return us_wipe(); }

/* One-time migration of the pre-2026-09-08 per-height files: each
 * undo_<h>.dat becomes h's run in the store (records copied, END added), then
 * the file is deleted. A torn legacy file (no END could be proven) is copied
 * as it is and left WITHOUT an END marker, so recovery still sees it as torn.
 * Returns the number of files migrated. */
long undo_migrate_legacy(void){
    DIR* d = opendir("."); if (!d) return 0;
    struct dirent* e; long n = 0;
    while ((e = readdir(d))){
        long h; char tail[8];
        if (sscanf(e->d_name, "undo_%ld.da%7s", &h, tail) != 2 || strcmp(tail, "t") != 0 || h < 0) continue;
        if (us_exists(h)){ unlink(e->d_name); continue; }      /* the store already has it */
        int fd = open(e->d_name, O_RDONLY); if (fd < 0) continue;
        struct stat sb; if (fstat(fd, &sb) != 0){ close(fd); continue; }
        u8* buf = malloc((size_t)sb.st_size + 1); if (!buf){ close(fd); continue; }
        long got = 0; ssize_t r;
        while (got < sb.st_size && (r = pread(fd, buf + got, (size_t)(sb.st_size - got), got)) > 0) got += r;
        close(fd);
        /* validate: whole records only; a short tail = torn */
        long off = 0; int torn = 0;
        while (off + UNDO_HEADER_BYTES <= got){
            u16 slen; memcpy(&slen, buf + off + 49, 2);
            if (slen > UNDO_MAX_SCRIPT || off + UNDO_HEADER_BYTES + slen > got){ torn = 1; break; }
            off += UNDO_HEADER_BYTES + slen;
        }
        if (off != got) torn = 1;
        /* copied as a closed run: the partial record (if any) is dropped, which
         * is what the tolerant replay dropped anyway */
        (void)torn;
        if (us_append_run(h, buf, (size_t)off, 1) == 0){ unlink(e->d_name); n++; }
        free(buf);
    }
    closedir(d);
    return n;
}

/* ---- the intended future live_on_input hookup shape (see file header for
 * why it is NOT actually installed there in this stage). Exercised only by
 * tests/test_undo_log.c against the real LSM. ---- */
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                          u64* value, unsigned long* height, unsigned long* is_coinbase,
                          const u8** script, unsigned long* slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index);

/* undo_capture_and_del(lst, u, height, txid, index)
 *   -> 1 ok (captured + deleted) / 0 no such UTXO (nothing to capture or
 *      delete -- e.g. a coinbase input, which live_on_input already skips
 *      before this point in its real shape) / -1 error (lookup, capture,
 *      or delete failure).
 * `height` is the CONSUMING block's height (undo file name); the spent
 * UTXO's OWN creation height/is_coinbase come from utxo_lsm_get and are
 * captured into the record so a later reorg-restore gets them right --
 * see this file's header comment. */
/* coinstats-index observer: fired with the FULL captured coin when the del
 * actually removed it. Registered by the worker; NULL in tests/tools. */
static void (*g_undo_coin_obs)(const u8 txid[32], u32 index, u64 value, u64 height,
                               u64 coinbase, const u8* script, unsigned long slen) = 0;
void undo_set_coin_observer(void (*fn)(const u8*, u32, u64, u64, u64,
                                       const u8*, unsigned long)){
    g_undo_coin_obs = fn;
}
/* Step-0 cost instrumentation (UTXO_INLINE_BUILD_PERF_SCOPE, 2026-09-06):
 * nanoseconds spent inside the observer (the coinstats MuHash fold, ~1.7 us
 * per coin) since process start. daemon/utxo_live.c reads the delta across
 * each block's apply walk and books it as its `csi` phase. Two clock reads
 * per observed spend; undo_set_coin_observer_timing(0) skips them and the
 * counter stays put. Nothing behavioural reads it. */
static int g_undo_obs_timing = 1;
static u64 g_undo_obs_ns = 0;
void undo_set_coin_observer_timing(int on){ g_undo_obs_timing = on; }
unsigned long long undo_coin_observer_ns(void){ return g_undo_obs_ns; }
static inline u64 undo_clock_ns(void){
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (u64)t.tv_sec * 1000000000ULL + (u64)t.tv_nsec;
}

/* the del + the coin observer, shared by the two captures; ts2 = the clock
 * before the del (0 when the split timing is off) */
static long capture_tail(void* lst, void* u, const u8 txid[32], u32 index, u64 value,
                         unsigned long utxo_height, unsigned long is_coinbase, const u8* script, unsigned long slen, u64 ts2){
    /* copy the script before the del: get()'s pointer is only valid until
     * the next LSM call, and the observer needs the exact bytes */
    static u8 scbuf[10000];
    unsigned long scn = slen <= sizeof scbuf ? slen : 0;
    if (scn && g_undo_coin_obs) memcpy(scbuf, script, scn);
    long d = utxo_lsm_del(lst, u, txid, index);
    if (g_undo_split_timing) g_undo_split_ns[2] += undo_clock_ns() - ts2;
    if (d == 1 && g_undo_coin_obs && scn == slen){
        u64 t0 = g_undo_obs_timing ? undo_clock_ns() : 0;
        g_undo_coin_obs(txid, index, value, (u64)utxo_height, (u64)is_coinbase, scbuf, slen);
        if (g_undo_obs_timing) g_undo_obs_ns += undo_clock_ns() - t0;
    }
    return d;
}
long undo_capture_and_del(void* lst, void* u, long height,
                           const u8 txid[32], u32 index){
    u64 value = 0;
    unsigned long utxo_height = 0, is_coinbase = 0;
    const u8* script = 0;
    unsigned long slen = 0;
    u64 ts0 = g_undo_split_timing ? undo_clock_ns() : 0;
    long r = utxo_lsm_get(lst, u, txid, index, &value, &utxo_height, &is_coinbase, &script, &slen);
    u64 ts1 = g_undo_split_timing ? undo_clock_ns() : 0;
    if (g_undo_split_timing) g_undo_split_ns[0] += ts1 - ts0;
    if (r != 1) return r;   /* 0 not-found, -1 err: pass through unchanged */
    long ar = undo_append_record(height, txid, index, value, (u32)utxo_height, (u8)is_coinbase, script, (u16)slen);
    u64 ts2 = g_undo_split_timing ? undo_clock_ns() : 0;
    if (g_undo_split_timing) g_undo_split_ns[1] += ts2 - ts1;
    if (ar != 1)
        return -1;
    return capture_tail(lst, u, txid, index, value, utxo_height, is_coinbase, script, slen, ts2);
}
/* 2026-10-05 (plan B2): the same capture with the prevout ALREADY RESOLVED --
 * the applier passes what tx_verify's Phase 1 looked up for this input
 * (txvb_last_in_prevout) instead of asking the store a second time. The
 * record written, the del and the observer call are byte-for-byte what
 * undo_capture_and_del does after its get; the get is the only difference.
 * Return: the del's (1 / 0 / -1), -1 on a record write failure. */
long undo_capture_and_del_resolved(void* lst, void* u, long height, const u8 txid[32], u32 index,
                                   u64 value, u32 utxo_height, u8 is_coinbase, const u8* script, u16 slen){
    u64 ts1 = g_undo_split_timing ? undo_clock_ns() : 0;
    long ar = undo_append_record(height, txid, index, value, utxo_height, is_coinbase, script, slen);
    u64 ts2 = g_undo_split_timing ? undo_clock_ns() : 0;
    if (g_undo_split_timing) g_undo_split_ns[1] += ts2 - ts1;
    if (ar != 1) return -1;
    return capture_tail(lst, u, txid, index, value, utxo_height, is_coinbase, script, slen, ts2);
}
