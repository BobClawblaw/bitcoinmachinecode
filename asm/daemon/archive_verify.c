/* daemon/archive_verify.c -- boot-time archive integrity check and self-repair.
 *
 * WHY THIS EXISTS. The block store is append-only and, until now, blindly
 * trusted whatever was already on disk. A network drop mid-sync can make the
 * locator collapse to all-zero (see anchor_locator's comment in main.c): the
 * peer then starts serving from GENESIS and store_append happily writes those
 * early blocks onto the tail, at heights where they do not belong. Nothing
 * downstream noticed -- so the daemon would keep syncing on a corrupt chain
 * and, worse, build a UTXO set from it and report success.
 *
 * Observed on the real archive 2026-08-18: 1,003,675 index entries but only
 * 944,039 unique block hashes -- 59,636 duplicate entries, ~18,792 real blocks
 * missing, and 40,844 bogus entries appended PAST the real chain tip. Height
 * 479,658 held the block that belongs at height 43. The tip read 1,003,674,
 * a height that does not exist on mainnet, so every locator/catch-up/chainwork
 * decision was operating in a fabricated height space.
 *
 * DETECTION. A duplicate block hash at two heights is never valid on a real
 * chain -- not even for BIP30's duplicate-coinbase pairs (91722/91880 and
 * 91812/91842), whose *blocks* have distinct hashes. So "hash already seen"
 * is an unambiguous corruption signal, with no legitimate false positive. We
 * reuse idx_init/idx_put (bitcoin_idx.asm) for an O(1)-amortized single pass,
 * the same primitive check_chain.c uses for exactly this check.
 *
 * REPAIR. The store is append-only: there is no splice. The only sound repair
 * is to truncate to the last known-good height and let normal sync re-download
 * from there -- which is precisely what store_truncate_to (Stage A) does. That
 * can discard a lot of good blocks above the first bad one, which is expensive
 * but CORRECT; continuing to serve and validate against a corrupt chain is not
 * a tradeoff worth taking. We log exactly what is being discarded first.
 */
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include "log_ts.h"

#include "archive_verify.h"

extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern int  store_truncate_to(void* st, long target_height);
extern int  store_truncate_index_only(void* st, long target_height);
extern long store_reload(void* st);

static unsigned long next_pow2(unsigned long v){
    unsigned long p = 1; while (p < v) p <<= 1; return p;
}

/* archive_scan(): first height whose block hash was already seen at a lower
 * height, or -1 if the index holds no duplicates. Also reports totals.
 * Reads index.dat positionally (48-byte records, hash in the first 32 bytes)
 * rather than trusting any cached in-memory state. */
long archive_scan(long* out_entries, long* out_unique, long* out_dups){
    if (out_entries) *out_entries = 0;
    if (out_unique)  *out_unique  = 0;
    if (out_dups)    *out_dups    = 0;

    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return -1;                     /* no index yet -- nothing to verify */
    off_t sz = lseek(fd, 0, SEEK_END);
    long n = (long)(sz / 48);
    if (n <= 0) { close(fd); return -1; }

    unsigned long slots = next_pow2((unsigned long)n * 4 + 1024);  /* ~25% load */
    unsigned char* ht = malloc(24 + (size_t)slots * 48 + 64);
    if (!ht) { close(fd); fprintf(stderr, "[archive] verify: alloc failed -- SKIPPING integrity check\n"); return -1; }
    idx_init(ht, slots);

    long first_dup = -1, dups = 0, stored = 0;
    unsigned char rec[48];
    for (long h = 0; h < n; h++){
        if (pread(fd, rec, 48, (off_t)h * 48) != 48) break;
        /* an all-zero hash prefix marks a hole, not a block -- skip, matching
         * check_chain.c's own convention */
        if (!rec[0] && !rec[1] && !rec[2] && !rec[3]) continue;
        stored++;
        if (idx_put(ht, rec, h) == 0){
            dups++;
            if (first_dup < 0) first_dup = h;
        }
    }
    free(ht);
    close(fd);

    if (out_entries) *out_entries = n;
    if (out_unique)  *out_unique  = stored - dups;
    if (out_dups)    *out_dups    = dups;
    return first_dup;
}

/* archive_scan_duplicates(): like archive_scan, but records EVERY duplicate
 * height (not just the first) into out_heights, up to max_out entries, in
 * ascending height order. Returns the TOTAL number of duplicate heights
 * found -- this can exceed max_out; the caller must treat that as "not all
 * of them fit" and size max_out generously (see ARCHIVE_REPAIR_MAX_DUPS).
 * Returns 0 for a clean archive, -1 on error (missing index / alloc failure,
 * same convention as archive_scan's own -1-on-error path via first_dup). */
long archive_scan_duplicates(long* out_heights, long max_out){
    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return -1;
    off_t sz = lseek(fd, 0, SEEK_END);
    long n = (long)(sz / 48);
    if (n <= 0) { close(fd); return -1; }

    unsigned long slots = next_pow2((unsigned long)n * 4 + 1024);
    unsigned char* ht = malloc(24 + (size_t)slots * 48 + 64);
    if (!ht) { close(fd); fprintf(stderr, "[archive] dup-scan: alloc failed -- SKIPPING\n"); return -1; }
    idx_init(ht, slots);

    long dups = 0;
    unsigned char rec[48];
    for (long h = 0; h < n; h++){
        if (pread(fd, rec, 48, (off_t)h * 48) != 48) break;
        if (!rec[0] && !rec[1] && !rec[2] && !rec[3]) continue;
        if (idx_put(ht, rec, h) == 0){
            if (out_heights && dups < max_out) out_heights[dups] = h;
            dups++;
        }
    }
    free(ht);
    close(fd);
    return dups;
}

/* archive_repair_duplicates(): find every duplicate-hash height and mark it
 * as a HOLE (zero its index.dat record -- the exact same representation an
 * ordinary never-fetched height already has, see archive_first_hole/
 * dlc_span in main.c) so the normal, already-proven catch-up/hole-fill path
 * re-downloads the REAL block for that height from a live peer.
 *
 * Deliberately does NOT truncate anything, unlike archive_verify_and_repair.
 * That matters because truncation additionally requires the archive to be
 * laid out in monotonic (file_no, data_pos) order below the cut -- a
 * precondition this archive can genuinely fail even in a range that has no
 * duplicate-hash corruption at all (see archive_layout_monotonic's own
 * header comment: enforcing it here has already prevented a truncate from
 * destroying a well-formed-content-but-non-monotonic archive once). Zeroing
 * specific existing records carries no such precondition -- it never
 * deletes or reorders anything, so it is safe to run unconditionally,
 * regardless of layout, and touches only the exact heights found bad.
 *
 * Returns the number of heights repaired (marked as holes) on success (0 for
 * a clean archive), or -1 on error (nothing changed). */
#define ARCHIVE_REPAIR_MAX_DUPS 65536
long archive_repair_duplicates(void){
    static long heights[ARCHIVE_REPAIR_MAX_DUPS];
    long found = archive_scan_duplicates(heights, ARCHIVE_REPAIR_MAX_DUPS);
    if (found <= 0) return found;   /* 0 clean, -1 error -- both pass through as-is */

    long to_fix = found;
    if (to_fix > ARCHIVE_REPAIR_MAX_DUPS){
        fprintf(stderr, "[archive] dup-repair: %ld duplicate heights found, only the first %d were "
                        "recorded this pass -- repairing those now; the next boot's scan will catch "
                        "the rest once these are refilled\n", found, ARCHIVE_REPAIR_MAX_DUPS);
        to_fix = ARCHIVE_REPAIR_MAX_DUPS;
    }

    int fd = open("index.dat", O_RDWR);
    if (fd < 0){
        fprintf(stderr, "[archive] dup-repair: could not open index.dat for writing: %s\n", strerror(errno));
        return -1;
    }

    static const unsigned char zero48[48] = {0};
    long fixed = 0;
    for (long i = 0; i < to_fix; i++){
        long h = heights[i];
        if (pwrite(fd, zero48, 48, (off_t)h * 48) != 48){
            fprintf(stderr, "[archive] dup-repair: pwrite failed at height %ld: %s\n", h, strerror(errno));
            continue;
        }
        fixed++;
    }
    /* Durable before anything downstream (the boot catch-up's own hole scan,
     * which runs right after this) trusts the file -- an unflushed zero that
     * a crash right here lost would silently un-repair the height with
     * nothing in the log to explain why it's still corrupt next boot. */
    fsync(fd);
    close(fd);

    if (fixed > 0)
        fprintf(stderr, "[archive] dup-repair: found %ld duplicate-hash height(s) (heights %ld..%ld), "
                        "marked %ld as hole(s) for normal catch-up to re-fill\n",
                found, heights[0], heights[to_fix-1], fixed);
    return fixed;
}

/* archive_drop_utxo_state(): delete every persisted UTXO artefact so the set
 * is rebuilt from a genuinely clean slate.
 *
 * Removing utxo_applied_height.dat alone is NOT enough, and getting this
 * wrong silently reintroduces the corruption we just repaired: utxo_live_init
 * decides "prior state exists" from utxo.dat / utxo_manifest.dat, so it would
 * utxo_lsm_reload() the old (wrong) set and then replay from height 0 ON TOP
 * of it. The run files must go too -- there were 366 of them left behind by
 * the interrupted rebuild that exposed this.
 *
 * Returns the number of files removed. */
long archive_drop_utxo_state(void){
    static const char* fixed[] = {
        "utxo_applied_height.dat", "utxo.dat", "utxo.idx", "utxo_manifest.dat",
        "utxo_manifest.dat.new", "utxo_lsm_table.map", "utxo_lsm_blob.map", 0
    };
    long removed = 0;
    for (int i = 0; fixed[i]; i++)
        if (unlink(fixed[i]) == 0) removed++;

    /* utxo_run_*.dat -- variable set, so enumerate rather than guess */
    DIR* d = opendir(".");
    if (d){
        struct dirent* e;
        while ((e = readdir(d))){
            if (strncmp(e->d_name, "utxo_run_", 9) == 0 && unlink(e->d_name) == 0) removed++;
        }
        closedir(d);
    }
    /* per-block undo data describes heights that may no longer exist */
    d = opendir(".");
    if (d){
        struct dirent* e;
        while ((e = readdir(d))){
            if (strncmp(e->d_name, "undo_", 5) == 0 && unlink(e->d_name) == 0) removed++;
        }
        closedir(d);
    }
    return removed;
}

/* archive_layout_monotonic(): -1 if block data is laid out in increasing
 * (file_no, data_pos) order across heights 0..upto, else the FIRST height
 * that goes backwards.
 *
 * THIS GUARD EXISTS BECAUSE ITS ABSENCE DESTROYED A ~50GB ARCHIVE.
 *
 * store_truncate_to assumes the archive is well formed: that block data was
 * appended in increasing height order, so "truncate to H" means cut H's file
 * at H's offset and delete every higher-numbered blk file. On a CORRUPT
 * archive that invariant does not hold -- and a corrupt archive is precisely
 * when repair gets called. Here, height 479,658 held the block belonging at
 * height 43, so its recorded location was blk00000.dat at offset ~9,597.
 * Truncating "to" that location cut the first block file down to 9,597 bytes
 * and unlinked all ~4,855 files above it. The entire chain archive was gone.
 *
 * So: never hand a destructive, well-formedness-assuming primitive an archive
 * we have just proven malformed. Verify the layout first; if it goes
 * backwards anywhere, truncation is NOT a safe repair and must be refused.
 *
 * Index record (48B): [0..31] hash, [32..35] file_no u32,
 *                     [36..43] data_pos u64, [44..47] data_size u32. */
long archive_layout_monotonic(long upto){
    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return -1;
    unsigned char rec[48];
    unsigned long long prev_file = 0, prev_pos = 0;
    int seen = 0;
    long bad = -1;
    for (long h = 0; h <= upto; h++){
        if (pread(fd, rec, 48, (off_t)h * 48) != 48) break;
        if (!rec[0] && !rec[1] && !rec[2] && !rec[3]) continue;   /* hole */
        unsigned int fno; unsigned long long pos;
        memcpy(&fno, rec + 32, 4);
        memcpy(&pos, rec + 36, 8);
        if (seen && (fno < prev_file || (fno == prev_file && pos < prev_pos))){
            bad = h;
            break;
        }
        prev_file = fno; prev_pos = pos; seen = 1;
    }
    close(fd);
    return bad;
}

/* archive_truncate_safe(): truncate the archive to target_height using the
 * best available method, instead of unconditionally requiring physical
 * monotonic layout the way a bare store_truncate_to call does.
 *
 * When the archive genuinely IS laid out in height order up to (and
 * including) the boundary record at target_height+1, uses the physical,
 * space-reclaiming store_truncate_to (unlinks/ftruncates blk files). When
 * it is NOT -- exactly the situation that used to make every truncating
 * caller (reorg's disconnect path, this file's own corruption repair)
 * either refuse outright or risk destroying the archive -- falls back to
 * store_truncate_index_only, which is unconditionally safe (never reads or
 * trusts a (file_no,data_pos) boundary) at the cost of not reclaiming the
 * disconnected heights' disk space. See store_truncate_index_only's own
 * header comment (bitcoin_store.asm) for why that tradeoff is sound.
 *
 * out_used_index_only, if non-NULL, is set to 1 when the fallback path ran
 * and 0 when the physical path ran, so callers can log which happened.
 * Returns whatever the primitive actually invoked returns (1 ok / -1 err) --
 * a -1 here is a genuine failure of that primitive (bad fd, I/O error,
 * corrupt index), never "layout was non-monotonic", since that case is
 * routed to the always-safe primitive instead of failing. */
int archive_truncate_safe(void* st, long target_height, int* out_used_index_only){
    long badh = archive_layout_monotonic(target_height + 1);
    int use_index_only = (badh >= 0);
    if (out_used_index_only) *out_used_index_only = use_index_only;
    if (use_index_only)
        return store_truncate_index_only(st, target_height);
    return store_truncate_to(st, target_height);
}

/* ---------------------------------------------------------------------------
 * BOOT VERIFICATION (Core -checkblocks / -checklevel)
 *
 * Core's levels are defined against its own storage model (undo data,
 * disconnect/reconnect). Ours is an append-only archive plus an LSM UTXO set,
 * so the levels are mapped to the strongest checks this layout supports, in
 * the same order of increasing cost:
 *
 *   0  nothing
 *   1  index records well-formed (present, non-zero size, sane geometry)
 *   2  + block data laid out monotonically across the checked range
 *   3  + on-disk frame is intact AND the body hashes to the index hash
 *   4  + cons_verify on the body (PoW, tx parsing, coinbase, merkle root)
 *
 * Level 3 covers the frame plus the HEADER: block_hash digests 80 bytes, so a
 * body whose transaction data has been corrupted still hashes correctly and
 * passes. Only level 4 recomputes the merkle root and therefore notices. Both
 * properties are pinned by tests/test_archive_check.c, because the difference
 * decides which level is worth running.
 *
 * ON-DISK FRAMING. index.dat's data_pos is the offset of the 8-byte FRAME
 * ([u32 len LE][u32 magic 0xd9b4bef9]), not of the block itself -- the block
 * payload starts at data_pos + 8 and runs for data_size bytes. See the format
 * block at the top of bitcoin_store.asm. The first version of this function
 * read data_size bytes from data_pos, so it hashed 8 bytes of frame plus a
 * truncated header and reported EVERY block in a healthy archive as corrupt.
 * Its unit test passed only because the fixture was written with the same
 * wrong assumption; the live run against a real archive is what caught it.
 * The frame is now validated explicitly, which makes that class of mistake
 * fail loudly at the first block instead of silently mis-reading every one.
 *
 * Level 3 is the first level that reads actual block DATA. Levels 1 and 2 only
 * read index.dat, so they cannot detect a truncated or overwritten blk file --
 * which is exactly the failure mode that destroyed this archive once. That is
 * why the default is 3, matching Core's own default.
 *
 * NOTE ON LEVEL 4: cons_verify does NOT verify scripts or signatures (see its
 * header in bitcoin_cons.asm). No level here can, because nothing in this
 * codebase script-verifies a block. Level 4 is therefore PoW + merkle
 * integrity, not full consensus validation, and must not be read as such.
 *
 * Returns the number of problems found (0 == clean), or -1 if the check could
 * not run at all. Read-only: this NEVER modifies or deletes anything.
 * ------------------------------------------------------------------------ */
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);

/* On-disk frame that precedes every block body: [u32 len LE][u32 magic].
 * Mirrors the format block at the top of bitcoin_store.asm -- if that layout
 * ever changes, this must change with it. */
#define ARCHIVE_FRAME_LEN 8
/* NOT A CHAIN DISCRIMINATOR, despite looking like one (2026-08-29).
 * The store writes this SAME constant into every frame on every chain --
 * store state +36 is fixed at the mainnet value and chainparams_select only
 * sets net_magic, the WIRE message-start. Verified by reading the bytes of a
 * regtest archive: its frames carry 0xd9b4bef9, not regtest's 0xdab5bffa.
 *
 * So this check catches a truncated, overwritten or spliced archive, which is
 * what it is for -- it cannot tell you the archive belongs to another chain.
 * That job is chain_archive_matches() in daemon/main.c, which compares block
 * 0 against the chain's genesis hash. Making the frame magic per-chain would
 * change the on-disk format and invalidate every existing non-mainnet
 * archive, for a property the genesis check already provides. */
#define ARCHIVE_MAGIC     0xd9b4bef9u

/* STO-11 (audit 2026-09-03): archive_check_collect() is archive_check() with
 * an out-list. Every height whose BODY cannot be trusted -- missing block
 * file, unreadable or wrong-magic frame, frame length disagreeing with the
 * index, short read, or a body whose hash is not the one the record claims --
 * is appended to `bad`, so a caller can repair exactly those heights.
 *
 * Deliberately NOT collected: a cons_verify (PoW/merkle) failure at level 4.
 * That is a statement about the CHAIN, not about whether the bytes on disk are
 * the block the record names, and refetching the same height from a peer
 * cannot fix it. Holes (all-zero records) are already the repaired state.
 *
 * archive_check() is now a thin wrapper, so the single scan and every log line
 * stay exactly as they were. */
long archive_check_collect(long nblocks, int level, long* bad, long bad_cap, long* bad_n);

long archive_check(long nblocks, int level){
    return archive_check_collect(nblocks, level, NULL, 0, NULL);
}

long archive_check_collect(long nblocks, int level, long* bad, long bad_cap, long* bad_n){
    if (bad_n) *bad_n = 0;
    if (level <= 0) return 0;

    int ifd = open("index.dat", O_RDONLY);
    if (ifd < 0){ fprintf(stderr,"[check] no index.dat -- nothing to verify\n"); return -1; }
    off_t isz = lseek(ifd, 0, SEEK_END);
    long n = (long)(isz / 48);
    if (n <= 0){ close(ifd); fprintf(stderr,"[check] index.dat empty -- nothing to verify\n"); return -1; }

    long tip   = n - 1;
    long first = (nblocks > 0 && nblocks < n) ? (n - nblocks) : 0;   /* 0 == all */

    long problems = 0, examined = 0, holes = 0;
    unsigned char rec[48];
    unsigned char* body = NULL;
    unsigned char  txids[64 * 32];
    long body_cap = 0;
    int  cur_file = -1, cur_fd = -1;

    for (long h = first; h <= tip; h++){
        if (pread(ifd, rec, 48, (off_t)h * 48) != 48){
            fprintf(stderr,"[check] height %ld: index record unreadable\n", h);
            problems++; continue;
        }
        if (!rec[0] && !rec[1] && !rec[2] && !rec[3]){ holes++; continue; }  /* not yet downloaded */

        unsigned int fno, dsz; unsigned long long pos;
        memcpy(&fno, rec + 32, 4);
        memcpy(&pos, rec + 36, 8);
        memcpy(&dsz, rec + 44, 4);
        examined++;

        /* level 1: geometry */
        if (dsz < 80 || dsz > (32u << 20)){
            fprintf(stderr,"[check] height %ld: implausible data_size %u\n", h, dsz);
            problems++; continue;
        }
        if (level < 3) continue;

        /* level 3+: read the body and confirm it is the block the index claims */
        if ((long)dsz > body_cap){
            unsigned char* nb = realloc(body, dsz);
            if (!nb){ fprintf(stderr,"[check] height %ld: alloc failed -- stopping\n", h); problems++; break; }
            body = nb; body_cap = dsz;
        }
        /* level 3+: the frame must be intact before the body means anything */
        if ((int)fno != cur_file){
            if (cur_fd >= 0) close(cur_fd);
            char nm[32]; snprintf(nm, sizeof nm, "blk%05u.dat", fno);
            cur_fd = open(nm, O_RDONLY);
            cur_file = (int)fno;
            if (cur_fd < 0){
                fprintf(stderr,"[check] height %ld: %s missing (pruned or lost)\n", h, nm);
                problems++; cur_file = -1;
                if (bad && bad_n && *bad_n < bad_cap) bad[(*bad_n)++] = h;
                continue;
            }
        }
        {
            unsigned char fr[ARCHIVE_FRAME_LEN];
            if (pread(cur_fd, fr, ARCHIVE_FRAME_LEN, (off_t)pos) != (ssize_t)ARCHIVE_FRAME_LEN){
                fprintf(stderr,"[check] height %ld: cannot read frame at blk%05u.dat+%llu\n",
                        h, fno, (unsigned long long)pos);
                problems++;
                if (bad && bad_n && *bad_n < bad_cap) bad[(*bad_n)++] = h;
                continue;
            }
            unsigned flen, fmagic;
            memcpy(&flen,   fr,     4);
            memcpy(&fmagic, fr + 4, 4);
            if (fmagic != ARCHIVE_MAGIC){
                fprintf(stderr,"[check] height %ld: bad frame magic 0x%08x at blk%05u.dat+%llu\n",
                        h, fmagic, fno, (unsigned long long)pos);
                problems++;
                if (bad && bad_n && *bad_n < bad_cap) bad[(*bad_n)++] = h;
                continue;
            }
            if (flen != dsz){
                fprintf(stderr,"[check] height %ld: frame length %u disagrees with index data_size %u\n",
                        h, flen, dsz);
                problems++;
                if (bad && bad_n && *bad_n < bad_cap) bad[(*bad_n)++] = h;
                continue;
            }
        }
        if (pread(cur_fd, body, dsz, (off_t)pos + ARCHIVE_FRAME_LEN) != (ssize_t)dsz){
            fprintf(stderr,"[check] height %ld: short read at blk%05u.dat+%llu (%u bytes)\n",
                    h, fno, (unsigned long long)(pos + ARCHIVE_FRAME_LEN), dsz);
            problems++;
                if (bad && bad_n && *bad_n < bad_cap) bad[(*bad_n)++] = h;
            continue;
        }
        unsigned char got[32];
        block_hash(got, body);
        if (memcmp(got, rec, 32) != 0){
            fprintf(stderr,"[check] height %ld: body hash does not match the index record\n", h);
            problems++;
                if (bad && bad_n && *bad_n < bad_cap) bad[(*bad_n)++] = h;
            continue;
        }
        if (level < 4) continue;

        /* level 4: PoW + merkle integrity of the body itself */
        if (cons_verify(body, (long)dsz, txids, 64) != 1){
            fprintf(stderr,"[check] height %ld: cons_verify failed (PoW/merkle)\n", h);
            problems++;
        }
    }

    if (cur_fd >= 0) close(cur_fd);
    free(body);
    close(ifd);

    /* level 2+: layout ordering over the checked range. Cheap (index only) and
     * it is the precondition store_truncate_to and store_prune both depend on,
     * so a violation matters well beyond this check. */
    if (level >= 2){
        long badh = archive_layout_monotonic(tip);
        if (badh >= 0){
            fprintf(stderr,"[check] block data is NOT laid out monotonically (first break at height %ld) -- "
                           "truncation and pruning will refuse to run\n", badh);
            problems++;
        }
    }

    fprintf(stderr,"[check] checklevel=%d over %ld block(s) [%ld..%ld]: %ld examined, %ld hole(s), %ld problem(s)\n",
            level, tip - first + 1, first, tip, examined, holes, problems);
    return problems;
}

/* archive_first_hole(): lowest height <= upto whose index record is empty, or
 * -1 if the range is fully populated. A "hole" is a height we have never
 * downloaded -- distinct from corruption, and the reason pruning must not run
 * during an incomplete sync. */
long archive_first_hole(long upto){
    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return -1;
    unsigned char rec[48];
    long found = -1;
    for (long h = 0; h <= upto; h++){
        if (pread(fd, rec, 48, (off_t)h * 48) != 48){ found = h; break; }
        if (!rec[0] && !rec[1] && !rec[2] && !rec[3]){ found = h; break; }
    }
    close(fd);
    return found;
}

/* archive_prune_height_for_budget(): the lowest height that can be RETAINED
 * while keeping total retained block data under `budget_bytes`.
 *
 * Core's -prune is a size budget, not a height, so the budget has to be turned
 * into the height gate store_prune actually takes. Walk back from the tip
 * accumulating real data_size values -- not an average block size, which would
 * be badly wrong at both ends of this chain (early blocks are ~200 bytes,
 * recent ones ~1.5 MB).
 *
 * Returns the prune height (>=0), or -1 if it could not be computed. A budget
 * larger than the whole archive yields 0, i.e. retain everything. */
long archive_prune_height_for_budget(long long budget_bytes){
    if (budget_bytes <= 0) return -1;
    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return -1;
    off_t isz = lseek(fd, 0, SEEK_END);
    long n = (long)(isz / 48);
    if (n <= 0){ close(fd); return -1; }

    unsigned char rec[48];
    long long acc = 0;
    long h = n - 1;
    for (; h >= 0; h--){
        if (pread(fd, rec, 48, (off_t)h * 48) != 48) continue;
        if (!rec[0] && !rec[1] && !rec[2] && !rec[3]) continue;
        unsigned int dsz; memcpy(&dsz, rec + 44, 4);
        if (acc + (long long)dsz > budget_bytes) break;
        acc += (long long)dsz;
    }
    close(fd);
    return (h < 0) ? 0 : h + 1;    /* h is the first height that did NOT fit */
}


/* STO-4: highest height index.dat has a slot for. One stat, no scan. */
static long archive_index_tip(void){
    struct stat st;
    if (stat("index.dat", &st) != 0) return -1;
    return (long)(st.st_size / 48) - 1;
}

/* archive_prune_decide(): should we delete anything, and if so below what
 * height? Pure decision, no side effects -- SEPARATE FROM THE DELETION on
 * purpose.
 *
 * store_prune physically unlinks block files. The last time a destructive
 * store primitive was driven straight from inline caller logic, that logic
 * was wrong and the archive was lost. Splitting the decision out means the
 * refusal cases can be tested exhaustively against small synthetic archives
 * instead of requiring a multi-hundred-megabyte one, and main.c is reduced to
 * acting on a verdict it cannot get subtly wrong.
 *
 * out_height receives the first height to RETAIN; out_detail receives the
 * offending height for the refusal verdicts (-1 otherwise). */
/* STO-12: Core's MIN_BLOCKS_TO_KEEP. 288 > UTXO_UNDO_WINDOW (200) >
 * REORG_MAX_DEPTH (100), so this one number subsumes both windows.
 *
 * INJECTABLE, and that is not test-only convenience. The prune verdicts are
 * exercised on a two- or three-block fixture precisely so all five outcomes
 * can be reached without a 550 MiB archive (see the note in
 * tests/test_archive_check.c). A hard 288 makes every one of those verdicts
 * NOTHING -- correct for a two-block archive, and useless for testing the
 * gate. Lowering the floor lets the suite exercise BOTH the floor itself and
 * the verdicts it sits in front of. Production never calls the setter. */
static long g_min_blocks_to_keep = 288;
void archive_set_min_blocks_to_keep(long n){ g_min_blocks_to_keep = n < 0 ? 0 : n; }
long archive_get_min_blocks_to_keep(void){ return g_min_blocks_to_keep; }

archive_prune_verdict_t archive_prune_decide(long long budget_bytes,
                                             long* out_height, long* out_detail){
    if (out_height) *out_height = 0;
    if (out_detail) *out_detail = -1;

    long ph = archive_prune_height_for_budget(budget_bytes);
    if (ph < 0)  return ARCHIVE_PRUNE_ERROR;
    if (ph == 0) return ARCHIVE_PRUNE_NOTHING;   /* budget covers the archive */

    /* ---- STO-12 (audit 2026-09-03): a minimum-retention floor ----
     * Pruning was purely budget-driven, so a small -prune could delete inside
     * the windows the node needs to stay correct: REORG_MAX_DEPTH (100) for a
     * reorg's disconnect, and UTXO_UNDO_WINDOW (200) for the undo files. Core
     * keeps MIN_BLOCKS_TO_KEEP = 288 for exactly this, which subsumes both.
     *
     * It fails CLOSED today -- read_stored_block returns -1/-3 and the reorg
     * pre-flight refuses -- so the cost is a node that cannot reorg rather
     * than one that corrupts itself. That is still a node that stops doing its
     * job, on a setting an operator chose freely.
     *
     * Applied HERE and not inside archive_prune_height_for_budget: that
     * function is a pure budget->height mapping and flooring it would change
     * its meaning for any other caller. The `ph <= 0` re-check matters -- on a
     * short archive the floor drives ph to zero or below, and falling through
     * with ph == 0 would call store_prune(0) and arm the prune gate for
     * nothing. Retaining MORE than the budget asked is Core's behaviour, and
     * it is said out loud rather than done silently. */
    {
        long tip = archive_index_tip();
        if (tip >= 0){
            long floor_h = tip - g_min_blocks_to_keep + 1;
            if (floor_h < 0) floor_h = 0;
            if (ph > floor_h){
                fprintf(stderr,
                    "[archive] prune budget wants height %ld but the last %d blocks are "
                    "retained regardless (reorg depth %d, undo window %d) -- pruning below %ld\n",
                    ph, (int)g_min_blocks_to_keep, 100, 200, floor_h);
                ph = floor_h;
            }
            if (ph <= 0) return ARCHIVE_PRUNE_NOTHING;
        }
    }

    if (out_height) *out_height = ph;

    /* STO-4 (audit 2026-09-03): the guards must cover the WHOLE index, not
     * just the heights below the prune boundary.
     *
     * store_prune unlinks every file below the boundary file F and then walks
     * h = ph, ph+1, ... re-packing records while rec.file_no == F, finally
     * ftruncate(F, new_off). That walk assumes every height stored in F
     * appears as ONE CONTIGUOUS RUN starting at ph -- an assumption about the
     * layout ABOVE ph. These two guards were called with `ph`, so they
     * validated only the part store_prune does not walk.
     *
     * What that costs, with a hole at H > ph (a sync-in-progress archive is
     * normally full of them -- the 09-01 incident log records "282 holes in
     * [0,968954]" as an ordinary state): at h = H the record reads all-zero,
     * file_no = 0 != F, the walk stops, and ftruncate(F, new_off) destroys
     * every block of F stored after H's slot WHILE ITS INDEX RECORD STILL
     * POINTS INTO F. Catch-up then reads a short block at the first destroyed
     * height and stops, and the hole-fill cannot re-fetch it because the
     * record is non-zero. If F happens to be blk00000.dat then F == 0
     * "matches" the zero record and an 8-byte frame from offset 0 is copied
     * over the compacted stream instead.
     *
     * A non-monotonic run above ph does the same thing: heights ph..ph+k in
     * F, ph+k+1 in F+1, ph+k+2 back in F (ordinary parallel-downloader
     * interleaving) stops the walk at ph+k+1 and truncates away ph+k+2.
     *
     * Scanning to the index tip rather than to ph costs one more sequential
     * pass over index.dat and turns both cases into a REFUSE verdict, which
     * main.c already routes to archive_prune_file_granular -- whole-file
     * deletion, which is what Core does and needs neither assumption. */
    long tip = archive_index_tip();
    if (tip < ph) tip = ph;          /* nothing above the boundary to check */

    long badh = archive_layout_monotonic(tip);
    if (badh >= 0){
        if (out_detail) *out_detail = badh;
        return ARCHIVE_PRUNE_REFUSE_LAYOUT;
    }
    long hole = archive_first_hole(tip);
    if (hole >= 0){
        if (out_detail) *out_detail = hole;
        return ARCHIVE_PRUNE_REFUSE_HOLE;
    }
    return ARCHIVE_PRUNE_OK;
}

/* archive_prune_file_granular(): fallback executor for the
 * ARCHIVE_PRUNE_REFUSE_LAYOUT verdict -- reclaims disk space below
 * target_height even when the archive is NOT laid out monotonically, by
 * operating at WHOLE-FILE granularity instead of assuming a single
 * (file_no, data_pos) boundary the way store_prune's in-place compaction
 * does (store_prune walks height h=target_height upward expecting every
 * record naming the boundary file to appear as one contiguous run before
 * the first record of a different file -- exactly the assumption a
 * non-monotonic archive breaks, which is why archive_prune_decide refuses
 * before ever calling it in that case).
 *
 * Mirrors Bitcoin Core's own real approach to this identical problem: Core's
 * blk*.dat files are not perfectly height-ordered either (parallel peer
 * download interleaves them there too), so Core prunes by tracking the
 * min/max height held in each file and deleting whole files once every
 * block they contain is safely below the target -- never a partial file,
 * never a byte-range guess.
 *
 * Algorithm:
 *   1. One sequential pass over index.dat (0..tip) computing, per file_no,
 *      the min and max height that file holds. Holes (all-zero records,
 *      the same sentinel archive_first_hole/archive_layout_monotonic
 *      already treat as empty) are skipped. This also records each
 *      height's file_no in an array so step 3 does not need a second read
 *      pass over the file.
 *   2. A file_no is prunable iff every height it holds is < target_height
 *      AND it is not the file holding the current tip. The tip-file
 *      exclusion is deliberate and unconditional, independent of what its
 *      computed max height happens to be: the tip's file_no is always the
 *      store's cur_file_no (store_append updates tip_height and
 *      cur_file_no together, so they can only diverge via truncation, and
 *      target_height <= tip always here) -- i.e. it is the file the live
 *      process may still be appending to. Deleting an open file out from
 *      under its own write fd would not crash the writer (the inode stays
 *      alive via the fd) but would silently desync it from disk: on the
 *      next boot, store_init/store_reload would find no file at that name
 *      and either fail to reopen it or create a fresh empty one, corrupting
 *      the append offset. Reading tip's file_no straight from index.dat's
 *      own record (rather than the state struct) keeps this function fully
 *      independent of bitcoin_store.asm's struct layout, matching this
 *      file's existing convention of never reaching into st's fields
 *      directly (see every other archive_* function in this file).
 *   3. Unlink each prunable file's blk%05u.dat (ENOENT tolerated -- may
 *      already be gone from a prior partial run).
 *   4. Mark every index.dat record whose file_no was just deleted by
 *      setting its data_size field to 0xFFFFFFFF (an impossible real
 *      value -- no Bitcoin block is anywhere near 4GB), leaving hash/
 *      file_no/data_pos untouched. Deliberately NOT the all-zero "hole"
 *      sentinel used elsewhere (archive_first_hole, archive_layout_
 *      monotonic, and critically idxscan_first_hole/dlc_span, whose
 *      hole-fill scan reads the archive's SCALAR prune_height field, not
 *      individual records -- see main.c's dlc_span comment on the exact
 *      redownload loop that guards against for the scalar-gate case).
 *      Reusing that sentinel here would make dlc_span's hole scan see a
 *      deliberately-pruned, permanently-gone record as an ordinary sync
 *      gap and have the downloader re-fetch it from peers every boot,
 *      defeating pruning entirely. The data_size marker is invisible to
 *      every hash- or (file_no,pos)-ordering-based scan and is checked
 *      only by store_get_at (bitcoin_store.asm), which is the one place
 *      that would otherwise try to open the now-deleted blk file.
 *
 * This does NOT guarantee heights [0, target_height) all become holes --
 * a file whose min height is below target_height but whose max height is
 * NOT is retained whole (files are the deletion unit; a still-needed height
 * a few bytes away from a prunable one is not sacrificed to reclaim it).
 * That is expected and correct, the same tradeoff Core makes.
 *
 * Returns the number of files deleted (>=0), or -1 on an I/O error (index.dat
 * unreadable). A return of 0 is a normal, successful "nothing was prunable
 * yet" outcome, not a failure. */
long archive_prune_file_granular(long target_height){
    if (target_height <= 0) return 0;

    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return -1;
    off_t isz = lseek(fd, 0, SEEK_END);
    if (isz < 48){ close(fd); return 0; }       /* nothing stored yet */
    long tip = (long)(isz / 48) - 1;
    if (target_height > tip + 1) target_height = tip + 1;

    unsigned int* rec_fileno = malloc((size_t)(tip + 1) * sizeof(unsigned int));
    if (!rec_fileno){ close(fd); return -1; }

    long fno_cap = 256;
    unsigned int* fmin = malloc((size_t)fno_cap * sizeof(unsigned int));
    unsigned int* fmax = malloc((size_t)fno_cap * sizeof(unsigned int));
    if (!fmin || !fmax){ free(rec_fileno); free(fmin); free(fmax); close(fd); return -1; }
    for (long i = 0; i < fno_cap; i++){ fmin[i] = 0xFFFFFFFFu; fmax[i] = 0; }

    unsigned char rec[48];
    unsigned int tip_fileno = 0xFFFFFFFFu;
    for (long h = 0; h <= tip; h++){
        if (pread(fd, rec, 48, (off_t)h * 48) != 48){
            rec_fileno[h] = 0xFFFFFFFFu;   /* short read: treat as hole */
            continue;
        }
        if (!rec[0] && !rec[1] && !rec[2] && !rec[3]){
            rec_fileno[h] = 0xFFFFFFFFu;   /* hole */
            continue;
        }
        unsigned int fno; memcpy(&fno, rec + 32, 4);
        rec_fileno[h] = fno;
        if (h == tip) tip_fileno = fno;

        if ((long)fno >= fno_cap){
            long newcap = fno_cap;
            while ((long)fno >= newcap) newcap *= 2;
            unsigned int* nmin = realloc(fmin, (size_t)newcap * sizeof(unsigned int));
            unsigned int* nmax = realloc(fmax, (size_t)newcap * sizeof(unsigned int));
            if (!nmin || !nmax){ free(rec_fileno); free(nmin?nmin:fmin); free(nmax?nmax:fmax); close(fd); return -1; }
            for (long i = fno_cap; i < newcap; i++){ nmin[i] = 0xFFFFFFFFu; nmax[i] = 0; }
            fmin = nmin; fmax = nmax; fno_cap = newcap;
        }
        if ((unsigned int)h < fmin[fno]) fmin[fno] = (unsigned int)h;
        if ((unsigned int)h > fmax[fno]) fmax[fno] = (unsigned int)h;
    }
    close(fd);

    if (tip_fileno == 0xFFFFFFFFu){   /* tip itself is a hole -- refuse to guess */
        free(rec_fileno); free(fmin); free(fmax);
        return 0;
    }

    /* ---- decide which files are wholly prunable ---- */
    char* prunable = calloc((size_t)fno_cap, 1);
    if (!prunable){ free(rec_fileno); free(fmin); free(fmax); return -1; }
    long deleted = 0;
    for (long f = 0; f < fno_cap; f++){
        if (fmin[f] == 0xFFFFFFFFu) continue;         /* file never referenced */
        if ((unsigned int)f == tip_fileno) continue;   /* never touch the open file */
        if (fmax[f] >= (unsigned int)target_height) continue;  /* still holds a live height */
        prunable[f] = 1;
    }
    free(fmin); free(fmax);

    /* ---- unlink the whole-file victims ---- */
    for (long f = 0; f < fno_cap; f++){
        if (!prunable[f]) continue;
        char name[24];
        snprintf(name, sizeof name, "blk%05u.dat", (unsigned int)f);
        if (unlink(name) == 0 || errno == ENOENT) deleted++;
        else prunable[f] = 0;   /* unlink failed for a real reason -- do not touch its index records */
    }

    /* ---- mark the index records that pointed into a deleted file: patch
     * only the 4-byte data_size field (offset 44) to the 0xFFFFFFFF pruned
     * sentinel, leaving hash/file_no/data_pos exactly as they were. ---- */
    if (deleted > 0){
        int wfd = open("index.dat", O_WRONLY);
        if (wfd >= 0){
            static const unsigned char pruned_size[4] = {0xFF, 0xFF, 0xFF, 0xFF};
            for (long h = 0; h <= tip; h++){
                unsigned int fno = rec_fileno[h];
                if (fno == 0xFFFFFFFFu) continue;
                if ((long)fno >= fno_cap || !prunable[fno]) continue;
                if (pwrite(wfd, pruned_size, 4, (off_t)h * 48 + 44) != 4){
                    /* the record still points into a file that is gone: say so
                     * loudly, per height, rather than leave a silent dangling entry */
                    fprintf(stderr, "[archive_verify] WARNING: could not mark index record h=%ld as pruned (%s) -- it still points into deleted blk%05u.dat\n",
                            h, strerror(errno), fno);
                }
            }
            close(wfd);
        }
    }

    free(rec_fileno); free(prunable);
    return deleted;
}

/* archive_verify_and_repair(): scan, and if corrupt, truncate back to the last
 * known-good height so normal sync re-downloads the rest.
 *   repair == 0 -> report only (log and return, change nothing)
 * Returns 1 clean, 0 corrupt-and-repaired, -1 corrupt-and-NOT-repaired. */
int archive_verify_and_repair(void* store_buf, int repair){
    long entries = 0, unique = 0, dups = 0;
    long first_bad = archive_scan(&entries, &unique, &dups);

    if (first_bad < 0){
        fprintf(stderr, "[archive] integrity OK: %ld entries, %ld unique, 0 duplicates\n", entries, unique);
        return 1;
    }

    fprintf(stderr, "[archive] *** CORRUPTION DETECTED ***\n");
    fprintf(stderr, "[archive]   index entries      : %ld\n", entries);
    fprintf(stderr, "[archive]   unique block hashes: %ld\n", unique);
    fprintf(stderr, "[archive]   duplicate entries  : %ld\n", dups);
    fprintf(stderr, "[archive]   first bad height   : %ld\n", first_bad);
    fprintf(stderr, "[archive]   cause is almost certainly a locator collapse mid-sync (a peer\n");
    fprintf(stderr, "[archive]   re-served from genesis and the append-only store wrote it onto the tail)\n");

    if (!repair){
        fprintf(stderr, "[archive] repair DISABLED -- refusing to trust this archive; UTXO tracking should stay off\n");
        return -1;
    }

    long keep = first_bad - 1;
    if (keep < 0) keep = 0;

    /* SAFETY -- see archive_layout_monotonic / store_truncate_index_only.
     * A non-monotonic archive below `keep` used to make this refuse outright
     * (destroyed ~600GB once when it didn't -- see this file's own header
     * comment). archive_truncate_safe now routes to the always-safe,
     * index-only fallback in that case instead of refusing: it discards the
     * disconnected heights' index records (so normal sync re-downloads them)
     * without trusting the corrupt archive's (file_no,data_pos) ordering,
     * at the cost of not reclaiming their disk space. */
    fprintf(stderr, "[archive] repairing: truncating to height %ld (discarding %ld entries above it).\n",
            keep, entries - 1 - keep);
    fprintf(stderr, "[archive] the store is append-only, so truncate-and-resync is the only sound repair;\n");
    fprintf(stderr, "[archive] normal sync will re-download from %ld.\n", keep + 1);

    int used_index_only = 0;
    if (archive_truncate_safe(store_buf, keep, &used_index_only) != 1){
        fprintf(stderr, "[archive] TRUNCATE FAILED -- archive still corrupt, UTXO tracking should stay off\n");
        return -1;
    }
    if (used_index_only){
        fprintf(stderr, "[archive] NOTE: block data below height %ld is not laid out in height order, so this\n", keep);
        fprintf(stderr, "[archive]   repair used the index-only fallback -- disconnected block bytes remain on\n");
        fprintf(stderr, "[archive]   disk, unreclaimed, rather than risk a destructive truncate on bad layout.\n");
    }
    store_reload(store_buf);
    fprintf(stderr, "[archive] repair complete: archive truncated to height %ld\n", keep);
    return 0;
}


/* archive_repair_bad_bodies() -- STO-11 (audit 2026-09-03).
 *
 * The defect: store_append wrote the block frame and the index record to two
 * different files with no ordering between them, so a power loss could leave
 * a durable record pointing at bytes that never reached disk. store_append
 * now fdatasync()s the block file first, which stops NEW damage -- but an
 * archive already carrying such a record still stalls catch-up at that height
 * on every boot: archive_check DETECTED it and only logged,
 * archive_trim_derived_tails only validates records above the chainwork
 * count, and reorg_chainwork_sync adds zero work for an all-zero header, so
 * nothing ever cut the record.
 *
 * The repair reuses archive_repair_duplicates' mechanism EXACTLY, and for the
 * same reason: zero the index record so the height becomes an ordinary hole
 * and the already-proven catch-up/hole-fill path re-downloads the real block.
 *
 * It does NOT truncate. That is the whole point. Truncation additionally
 * requires monotonic (file_no, data_pos) layout below the cut -- a
 * precondition this archive can genuinely fail on well-formed data, and this
 * file's header records that enforcing it once prevented a truncate from
 * destroying ~600GB. Zeroing specific existing records never deletes or
 * reorders anything, so it is safe regardless of layout and touches only the
 * heights actually found bad.
 *
 * Returns heights repaired (0 for a clean archive), or -1 on error. */
#define ARCHIVE_REPAIR_MAX_BAD 65536
long archive_repair_bad_bodies(long nblocks, int level){
    static long heights[ARCHIVE_REPAIR_MAX_BAD];
    long nbad = 0;
    /* level is clamped to 3: level 3 is what validates frame+body hash, which
     * is exactly the class this repairs. Level 4 adds cons_verify, whose
     * failures are deliberately NOT collected -- refetching cannot fix them. */
    long probs = archive_check_collect(nblocks, level < 3 ? 3 : level,
                                       heights, ARCHIVE_REPAIR_MAX_BAD, &nbad);
    if (probs < 0) return -1;
    if (nbad <= 0) return 0;

    int fd = open("index.dat", O_RDWR);
    if (fd < 0){
        fprintf(stderr, "[archive] body-repair: could not open index.dat for writing: %s\n",
                strerror(errno));
        return -1;
    }
    static const unsigned char zero48[48] = {0};
    long fixed = 0;
    for (long i = 0; i < nbad; i++){
        long h = heights[i];
        if (pwrite(fd, zero48, 48, (off_t)h * 48) != 48){
            fprintf(stderr, "[archive] body-repair: pwrite failed at height %ld: %s\n",
                    h, strerror(errno));
            continue;
        }
        fixed++;
    }
    /* Durable before the boot catch-up's own hole scan trusts the file --
     * same reasoning as the duplicate repair above. */
    fsync(fd);
    close(fd);
    fprintf(stderr, "[archive] body-repair: marked %ld height(s) as holes; normal catch-up will "
                    "re-download them\n", fixed);
    return fixed;
}

/* ---------------------------------------------------------------------------
 * BOOT SELF-HEAL OF THE DERIVED FILES (incident 2026-09-01)
 *
 * index.dat's length IS the tip (height = records - 1), so a run of all-zero
 * records at its very end is never a real state: the tip is by definition a
 * stored block. Such a tail is what a boot catch-up leaves behind when it
 * extended the index toward a header count it should never have believed
 * (966,657 hole records on 2026-09-01). headers.dat and chainwork.dat are
 * derived from the archive too and must not outrun it. Trims all three to
 * the last stored block and says so. Returns the number of files trimmed, or
 * -1 if a truncation failed. Read-only when the files are consistent. */
long archive_trim_derived_tails(void){
    struct stat st;
    if (stat("index.dat", &st) != 0) return 0;
    long n = (long)(st.st_size / 48);
    if (n <= 0) return 0;
    FILE* f = fopen("index.dat", "rb"); if (!f) return -1;
    long last = n - 1; unsigned char rec[48];
    while (last >= 0){
        if (fseek(f, last * 48, SEEK_SET) != 0 || fread(rec, 1, 48, f) != 48) break;
        int zero = 1; for (int i = 0; i < 48; i++) if (rec[i]){ zero = 0; break; }
        if (!zero) break;
        last--;
    }
    fclose(f);
    if (last < 0) return 0;                       /* nothing stored at all: not ours to judge */
    long trimmed = 0;
    if (last < n - 1){
        if (truncate("index.dat", (off_t)(last + 1) * 48) != 0) return -1;
        fprintf(stderr, "[boot] index.dat carried %ld empty record(s) past the tip (height %ld) -- trimmed\n", n - 1 - last, last);
        trimmed++; n = last + 1;
    }
    /* Records that do not CONTINUE THE CHAIN. chainwork.dat is written as
     * blocks are applied, so every height it covers was validated; anything
     * the index holds above that is only trustworthy if each block's header
     * links to the record below it (and hashes to its own record). The
     * incident's junk (real early blocks recorded at fake heights) fails at
     * the first such record: block 1's prev-hash is genesis, not 965029. */
    long cw = (stat("chainwork.dat", &st) == 0) ? (long)(st.st_size / 16) : 0;
    if (cw >= 1 && n > cw){
        f = fopen("index.dat", "rb"); if (!f) return -1;
        unsigned char prev_hash[32], r2[48];
        long h = cw - 1;
        if (fseek(f, h * 48, SEEK_SET) != 0 || fread(r2, 1, 48, f) != 48){ fclose(f); return -1; }
        memcpy(prev_hash, r2, 32);
        long good = h;                            /* highest height proven to continue the chain */
        while (good + 1 < n){
            if (fseek(f, (good + 1) * 48, SEEK_SET) != 0 || fread(r2, 1, 48, f) != 48) break;
            int zero = 1; for (int i = 0; i < 48; i++) if (r2[i]){ zero = 0; break; }
            if (zero) break;
            unsigned int fno; unsigned long long pos; unsigned int size;
            memcpy(&fno, r2 + 32, 4); memcpy(&pos, r2 + 36, 8); memcpy(&size, r2 + 44, 4);
            if (size < 80) break;
            char fn[64]; snprintf(fn, sizeof fn, "blk%05u.dat", fno);
            FILE* bf = fopen(fn, "rb"); if (!bf) break;
            unsigned char hdr[80]; int okr = (fseek(bf, (long)(pos + ARCHIVE_FRAME_LEN), SEEK_SET) == 0 && fread(hdr, 1, 80, bf) == 80);
            fclose(bf);
            if (!okr) break;
            unsigned char bh[32]; block_hash(bh, hdr);
            if (memcmp(bh, r2, 32) != 0 || memcmp(hdr + 4, prev_hash, 32) != 0) break;
            memcpy(prev_hash, bh, 32); good++;
        }
        fclose(f);
        if (good + 1 < n){
            if (truncate("index.dat", (off_t)(good + 1) * 48) != 0) return -1;
            fprintf(stderr, "[boot] index.dat carried %ld record(s) beyond the linked chain (height %ld does not continue height %ld) -- trimmed\n",
                    n - (good + 1), good + 1, good);
            trimmed++; n = good + 1;
        }
    }
    /* the header mirror must agree with the index height by height; cut it at
     * the first disagreement (the daemon re-derives the rest from the blocks) */
    if (stat("headers.dat", &st) == 0 && st.st_size >= 112){
        long hn = (long)(st.st_size / 112); long lim = hn < n ? hn : n;
        FILE* fi = fopen("index.dat", "rb"); FILE* fh = fopen("headers.dat", "rb");
        if (fi && fh){
            long bad = -1; unsigned char ir[48], hr[112];
            for (long h = 0; h < lim; h++){
                if (fread(ir, 1, 48, fi) != 48 || fread(hr, 1, 112, fh) != 112) break;
                int zero = 1; for (int i = 0; i < 32; i++) if (ir[i]){ zero = 0; break; }
                if (zero) continue;                /* a hole in the index says nothing about the mirror */
                if (memcmp(ir, hr + 80, 32) != 0){ bad = h; break; }
            }
            fclose(fi); fclose(fh);
            if (bad >= 0){
                if (truncate("headers.dat", (off_t)bad * 112) != 0) return -1;
                fprintf(stderr, "[boot] headers.dat diverged from the archive at position %ld -- trimmed (re-derived from the blocks at boot)\n", bad);
                trimmed++;
            }
        } else { if (fi) fclose(fi); if (fh) fclose(fh); }
    }
    if (stat("headers.dat", &st) == 0 && st.st_size > (off_t)n * 112){
        if (truncate("headers.dat", (off_t)n * 112) != 0) return -1;
        fprintf(stderr, "[boot] headers.dat ran %ld record(s) past the archive tip -- trimmed to %ld\n", (long)(st.st_size / 112) - n, n);
        trimmed++;
    }
    if (stat("chainwork.dat", &st) == 0 && st.st_size > (off_t)n * 16){
        if (truncate("chainwork.dat", (off_t)n * 16) != 0) return -1;
        fprintf(stderr, "[boot] chainwork.dat ran %ld record(s) past the archive tip -- trimmed to %ld\n", (long)(st.st_size / 16) - n, n);
        trimmed++;
    }
    return trimmed;
}
