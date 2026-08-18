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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern int  store_truncate_to(void* st, long target_height);
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
    fprintf(stderr, "[archive] repairing: truncating to height %ld (discarding %ld entries above it).\n",
            keep, entries - 1 - keep);
    fprintf(stderr, "[archive] the store is append-only, so truncate-and-resync is the only sound repair;\n");
    fprintf(stderr, "[archive] normal sync will re-download from %ld.\n", keep + 1);

    if (store_truncate_to(store_buf, keep) != 1){
        fprintf(stderr, "[archive] TRUNCATE FAILED -- archive still corrupt, UTXO tracking should stay off\n");
        return -1;
    }
    store_reload(store_buf);
    fprintf(stderr, "[archive] repair complete: archive truncated to height %ld\n", keep);
    return 0;
}
