/* daemon/undo_log.c -- Stage A reorg/fork-choice primitive #5 (per-block
 * undo-data structure). 100% AI-generated, plain C.
 *
 * STANDALONE / ADDITIVE, DELIBERATELY NOT WIRED IN: the Stage A brief asks
 * for a capture step to be added inside daemon/utxo_live.c's live_on_input,
 * BEFORE its real utxo_lsm_del call, on the theory that it's "just" an
 * additive capture step. It is not, in the sense that matters here:
 * live_on_input is called for every real input of every real block the
 * live daemon actually applies (via apply_block <- utxo_live_catchup,
 * which daemon/main.c calls repeatedly during real sync against a live
 * UTXO set) -- editing it means editing a real-time call site the
 * production daemon executes today, which the very same Stage A brief
 * separately and repeatedly says not to do ("do NOT modify ... any other
 * real-time call site that the production daemon actually executes today
 * -- every primitive you add should be new, dead code from the live
 * daemon's perspective"). Given that direct conflict, this file keeps
 * daemon/utxo_live.c completely untouched (zero diff) and instead
 * implements the exact capture shape live_on_input would use once this
 * primitive is wired in a later, separately reviewed stage --
 * undo_capture_and_del below -- as a new, standalone function exercised
 * only by tests/test_undo_log.c against the real LSM (utxo_lsm_get/_del).
 * This choice, and why, is called out again in the top-level report for
 * this stage.
 *
 * Record format (one per spent input), written in order to a per-height
 * file `undo_<height>.dat` (append-only; simplest possible layout given a
 * bounded ~100-200 block retention window -- no separate index file is
 * needed since consumers just read a whole small file sequentially):
 *   txid[32] | index(u32 LE) | value(u64 LE) | script_len(u16 LE) | script[script_len]
 * (46-byte fixed header + variable-length script, back to back, no framing
 * beyond that -- a reader just consumes records until EOF, mirroring how
 * bitcoin_store.asm's blk%05u.dat framing is "read until you know you're
 * done" rather than length-prefixed as a whole file).
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
#define UNDO_HEADER_BYTES 46    /* 32 + 4 + 8 + 2 */

static void undo_path(char out[64], long height){
    snprintf(out, 64, "undo_%ld.dat", height);
}

/* undo_append_record(height, txid, index, value, script, slen) -> 1 ok / -1 err */
long undo_append_record(long height, const u8 txid[32], u32 index, u64 value,
                         const u8* script, u16 slen){
    char path[64]; undo_path(path, height);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;

    u8 hdr[UNDO_HEADER_BYTES];
    memcpy(hdr, txid, 32);
    memcpy(hdr+32, &index, 4);
    memcpy(hdr+36, &value, 8);
    memcpy(hdr+44, &slen, 2);

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
        memcpy(&out[n].slen, hdr+44, 2);
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
                          u64* value, const u8** script, unsigned long* slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index);

/* undo_capture_and_del(lst, u, height, txid, index)
 *   -> 1 ok (captured + deleted) / 0 no such UTXO (nothing to capture or
 *      delete -- e.g. a coinbase input, which live_on_input already skips
 *      before this point in its real shape) / -1 error (lookup, capture,
 *      or delete failure). */
long undo_capture_and_del(void* lst, void* u, long height,
                           const u8 txid[32], u32 index){
    u64 value = 0;
    const u8* script = 0;
    unsigned long slen = 0;
    long r = utxo_lsm_get(lst, u, txid, index, &value, &script, &slen);
    if (r != 1) return r;   /* 0 not-found, -1 err: pass through unchanged */
    if (undo_append_record(height, txid, index, value, script, (u16)slen) != 1)
        return -1;
    return utxo_lsm_del(lst, u, txid, index);
}
