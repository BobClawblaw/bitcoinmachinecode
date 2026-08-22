/* daemon/undo_log.c -- Stage A reorg/fork-choice primitive #5 (per-block
 * undo-data structure). 100% AI-generated, plain C.
 *
 * STAGE B UPDATE -- THIS IS NOW LIVE. Stage A deliberately left this module
 * unwired (its original note explained that adding the capture step to
 * daemon/utxo_live.c's live_on_input meant editing a real-time call site the
 * production daemon executes, which that stage's brief forbade). Stage B is
 * the stage that does it: undo_capture_and_del is now called from
 * live_on_input for every non-coinbase input of every block the live daemon
 * applies, which is what makes a later DISCONNECT of those blocks possible
 * at all. Stage B also adds undo_replay (streaming reader -- the disconnect
 * path cannot afford undo_load's 10KB-per-record array), undo_discard, and
 * undo_prune_from (bounded/resumable retention sweep). undo_append_record,
 * undo_load, undo_prune and undo_capture_and_del are unchanged.
 *
 * PERFORMANCE NOTE for the now-live capture path: every spent input costs one
 * extra utxo_lsm_get (to read the value+script before deleting) plus one
 * open/write/close on undo_<height>.dat. The LSM's own header comment notes
 * that utxo_lsm_get does a linear scan per candidate disk run and was written
 * on the assumption of never being on a hot path -- it now is. See this
 * stage's report; this is called out as something to measure under real
 * mainnet block sizes before it is trusted at scale.
 *
 * Record format (one per spent input), written in order to a per-height
 * file `undo_<height>.dat` (append-only; simplest possible layout given a
 * bounded ~100-200 block retention window -- no separate index file is
 * needed since consumers just read a whole small file sequentially):
 *   txid[32] | index(u32 LE) | value(u64 LE) | height(u32 LE) |
 *   is_coinbase(u8) | script_len(u16 LE) | script[script_len]
 * (51-byte fixed header + variable-length script, back to back, no framing
 * beyond that -- a reader just consumes records until EOF, mirroring how
 * bitcoin_store.asm's blk%05u.dat framing is "read until you know you're
 * done" rather than length-prefixed as a whole file).
 *
 * height/is_coinbase added 2026-08-19 (Stage D of PLAN_SCRIPT_VERIFY.md).
 * CAREFUL: this record's `height` field is the spent UTXO's OWN original
 * creation height (captured from utxo_lsm_get right before the spend) --
 * NOT the height of the block doing the spending, which is a completely
 * different value already used elsewhere (the undo FILE's own name,
 * `undo_<consuming_block_height>.dat`). Losing this distinction would mean
 * a reorg-restored coinbase output silently gets the WRONG creation height
 * (or none at all), defeating the 100-block maturity check for exactly the
 * blocks that most need reorg correctness.
 *
 * Retention: undo_prune(tip_height, window) removes undo_<h>.dat files for
 * every h below (tip_height-window+1), mirroring bitcoin_store.asm's own
 * store_prune in spirit (a cheap forward-only deletion sweep) though far
 * simpler here since there's no byte-range compaction to do -- undo data is
 * already one whole file per height, so "prune" is just unlink().
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned long long u64;

#define UNDO_MAX_SCRIPT 10000   /* generous vs. any real scriptPubKey */
#define UNDO_HEADER_BYTES 51    /* 32 + 4 + 8 + 4 + 1 + 2 (was 46 before Stage D) */

static void undo_path(char out[64], long height){
    snprintf(out, 64, "undo_%ld.dat", height);
}

/* undo_append_record(height, txid, index, value, utxo_height, is_coinbase,
 *                    script, slen) -> 1 ok / -1 err
 * `height` here is the CONSUMING block's height (the undo file this record
 * is appended to); `utxo_height` is the spent UTXO's OWN original creation
 * height, captured separately -- see this file's header comment. */
long undo_append_record(long height, const u8 txid[32], u32 index, u64 value,
                         u32 utxo_height, u8 is_coinbase,
                         const u8* script, u16 slen){
    char path[64]; undo_path(path, height);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;

    u8 hdr[UNDO_HEADER_BYTES];
    memcpy(hdr, txid, 32);
    memcpy(hdr+32, &index, 4);
    memcpy(hdr+36, &value, 8);
    memcpy(hdr+44, &utxo_height, 4);
    hdr[48] = is_coinbase;
    memcpy(hdr+49, &slen, 2);

    long ok = 1;
    if (write(fd, hdr, UNDO_HEADER_BYTES) != UNDO_HEADER_BYTES) ok = -1;
    if (ok == 1 && slen > 0) {
        long w = write(fd, script, slen);
        if (w != (long)slen) ok = -1;
    }
    close(fd);
    return ok;
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
    char path[64]; undo_path(path, height);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    long n = 0;
    while (n < max_recs) {
        u8 hdr[UNDO_HEADER_BYTES];
        long r = read(fd, hdr, UNDO_HEADER_BYTES);
        if (r == 0) break;                 /* clean EOF between records */
        if (r != UNDO_HEADER_BYTES) { close(fd); return -1; }

        memcpy(out[n].txid, hdr, 32);
        memcpy(&out[n].index, hdr+32, 4);
        memcpy(&out[n].value, hdr+36, 8);
        memcpy(&out[n].height, hdr+44, 4);
        out[n].is_coinbase = hdr[48];
        memcpy(&out[n].slen, hdr+49, 2);
        if (out[n].slen > UNDO_MAX_SCRIPT) { close(fd); return -1; }
        if (out[n].slen > 0) {
            long sr = read(fd, out[n].script, out[n].slen);
            if (sr != (long)out[n].slen) { close(fd); return -1; }
        }
        n++;
    }
    close(fd);
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
    char path[64]; undo_path(path, height);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;            /* same contract as undo_load: absent == empty */

    static u8 script[UNDO_MAX_SCRIPT];
    long n = 0;
    for (;;) {
        u8 hdr[UNDO_HEADER_BYTES];
        long r = read(fd, hdr, UNDO_HEADER_BYTES);
        if (r == 0) break;
        if (r != UNDO_HEADER_BYTES) {
            /* Short header at the tail: undo_append_record died between
             * open and its first write completing (or a power loss tore
             * it). The matching delete never ran, so in tolerant mode this
             * is end-of-file, not corruption. */
            if (tolerant && r > 0) { if (torn) *torn = 1; break; }
            close(fd); return -1;
        }
        u32 index; u64 value; u32 utxo_height; u8 is_coinbase; u16 slen;
        memcpy(&index, hdr+32, 4);
        memcpy(&value, hdr+36, 8);
        memcpy(&utxo_height, hdr+44, 4);
        is_coinbase = hdr[48];
        memcpy(&slen,  hdr+49, 2);
        if (slen > UNDO_MAX_SCRIPT) { close(fd); return -1; }
        if (slen > 0) {
            long sr = read(fd, script, slen);
            if (sr != (long)slen) {
                /* Header landed, script didn't: the kill hit between
                 * undo_append_record's two write()s. Same reasoning --
                 * the delete that follows the append never happened. */
                if (tolerant && sr >= 0) { if (torn) *torn = 1; break; }
                close(fd); return -1;
            }
        }
        if (cb && !cb(ctx, hdr, index, value, utxo_height, is_coinbase, script, slen)) { close(fd); return -1; }
        n++;
    }
    close(fd);
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
    char path[64]; undo_path(path, height);
    return unlink(path) == 0 ? 1 : 0;
}

/* undo_prune_from(from_height, tip_height, window, max_scan)
 *   -> the height the sweep reached (a resumable cursor), or -1 on bad args.
 *
 * Bounded, resumable variant of undo_prune below. undo_prune restarts its
 * unlink sweep at h=0 on EVERY call: wired into a per-block flow on a store
 * whose tip is ~974k, that is ~974,000 failing unlink() syscalls per block
 * applied, forever. This variant starts at a caller-held cursor and examines
 * at most `max_scan` heights per call, returning the new cursor -- so the
 * steady-state per-block cost is O(1) and a cold start (cursor 0 on a deep
 * store) is amortised over several calls instead of stalling one.
 * undo_prune is left byte-for-byte unchanged (tests/test_undo_log.c covers
 * its exact existing semantics).
 */
long undo_prune_from(long from_height, long tip_height, long window, long max_scan){
    if (tip_height < 0 || window <= 0 || max_scan <= 0) return from_height;
    if (from_height < 0) from_height = 0;
    long keep_from = tip_height - window + 1;
    if (keep_from < 0) keep_from = 0;
    long end = from_height + max_scan;
    if (end > keep_from) end = keep_from;
    for (long h = from_height; h < end; h++){
        char path[64]; undo_path(path, h);
        unlink(path);
    }
    return end > from_height ? end : from_height;
}

/* undo_prune(tip_height, window) -> number of undo_<h>.dat files removed.
 * Retains heights [max(0,tip_height-window+1) .. tip_height]; everything
 * older is deleted. A no-op (0 removed) for an invalid tip/window. Meant to
 * be called once per (future, wired-in) block application -- see this
 * file's header for why that wiring isn't done in this stage; a caller
 * that jumps `tip_height` forward by a lot in one call will still correctly
 * remove everything now outside the window (just at O(jump) cost, fine for
 * an occasional catch-up but not a hot per-block path if jumps are large). */
long undo_prune(long tip_height, long window){
    if (tip_height < 0 || window <= 0) return 0;
    long keep_from = tip_height - window + 1;
    if (keep_from < 0) keep_from = 0;
    long removed = 0;
    for (long h = 0; h < keep_from; h++){
        char path[64]; undo_path(path, h);
        if (unlink(path) == 0) removed++;
    }
    return removed;
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
long undo_capture_and_del(void* lst, void* u, long height,
                           const u8 txid[32], u32 index){
    u64 value = 0;
    unsigned long utxo_height = 0, is_coinbase = 0;
    const u8* script = 0;
    unsigned long slen = 0;
    long r = utxo_lsm_get(lst, u, txid, index, &value, &utxo_height, &is_coinbase, &script, &slen);
    if (r != 1) return r;   /* 0 not-found, -1 err: pass through unchanged */
    if (undo_append_record(height, txid, index, value, (u32)utxo_height, (u8)is_coinbase, script, (u16)slen) != 1)
        return -1;
    return utxo_lsm_del(lst, u, txid, index);
}
