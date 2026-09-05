/*
 * utxo_lsm_mm.c -- mmap-cached fast path for the UTXO LSM's on-disk run
 * lookup (PERF_SCOPE.md 4.1).
 *
 * WHY THIS EXISTS
 * ---------------
 * bitcoin_utxo_lsm.asm's mac_run_lookup, for EVERY key lookup and for EVERY
 * run in the manifest, used to:
 *     open(run file) -> read 44-byte header
 *                    -> read the ENTIRE bloom filter into TLS scratch
 *                    -> test exactly 3 bits of it
 *                    -> (maybe) lseek/read binary-search the sparse index
 *                    -> (maybe) lseek/read-scan records
 *                    -> close()
 * The bloom read is up to BLOOM_MAX_BYTES (4 MiB) copied out of the page
 * cache to answer 3 bit tests. A live profile of the full-chain replay put
 * the kernel file-read path at ~31% of ALL cycles, with _copy_to_iter alone
 * at 24% -- that copy.
 *
 * This file replaces that with a per-thread cache of read-only mmaps: a run
 * is opened and mapped once, then every later lookup against it is pure
 * memory access -- no syscall, no copy. Records and sparse entries are read
 * straight from the mapping too, so the whole lookup becomes syscall-free
 * after the first touch of a run.
 *
 * RELATIONSHIP TO THE ASM
 * -----------------------
 * The asm path is NOT deleted. mac_run_lookup calls lsm_run_lookup_mm first;
 * on LSM_MM_FALLBACK (-2) it runs its original code unchanged. Anything this
 * file cannot handle safely -- open/mmap failure, a truncated or malformed
 * file, an offset that would read out of bounds -- returns LSM_MM_FALLBACK
 * rather than guessing, and the audited asm answers instead. That keeps the
 * proven implementation as the correctness anchor (same stance the repo
 * takes for SHA-NI and CUDA: new tier, old path always reachable).
 *
 * THREAD SAFETY
 * -------------
 * utxo_lsm_get runs concurrently on the block-verification worker pool
 * (daemon/tx_verify.c's txvb_verify_all), which is why the asm's own bloom
 * staging buffer is __thread. The cache here is __thread for the same
 * reason: no locks, no shared mutable state, no races by construction. The
 * cost is one mapping per (thread, run) instead of one per run -- cheap,
 * because MAP_SHARED PROT_READ pages ARE the page cache: mapping the same
 * file from 16 threads maps the same physical pages, adding page-table
 * entries but no page-cache copies.
 *
 * STALENESS / run_no REUSE -- the correctness hazard
 * --------------------------------------------------
 * utxo_lsm_compact unlinks the run files it merged. A mapping outlives the
 * unlink (the inode is pinned while mapped), so the danger is not a crash
 * but a STALE ANSWER: serving a lookup from a run that is no longer in the
 * manifest, or worse from a file whose run_no has been handed to a new run.
 *
 * next_run_no (lst+144) is monotonic within a process, and utxo_lsm_reload
 * recomputes it as 1 + max(run_no) over the manifest -- so a live run_no is
 * never reassigned while it is live. That alone is nearly enough, but
 * "nearly" is not a standard this code should be held to, and a reload can
 * in principle move next_run_no. So every cache entry is tagged with the
 * run's GENERATION, and the caller passes the gen from the manifest entry it
 * is iterating. A hit requires BOTH run_no and gen to match; any mismatch
 * unmaps and re-opens. gen is assigned fresh from next_gen on every flush
 * and every compaction, so a reused run_no necessarily carries a different
 * gen and can never be served from the stale mapping. The mapped header's
 * own gen field is checked against the expected gen as well, so even a file
 * swapped underneath us is caught.
 *
 * BOUNDED FOOTPRINT
 * -----------------
 * Direct-mapped cache, LSM_MM_SLOTS (64) entries per thread, indexed by
 * run_no % 64; a colliding slot is unmapped and replaced. 64 comfortably
 * exceeds UTXO_LIVE_COMPACT_THRESHOLD (12, the steady-state run count) while
 * staying well under UTXO_LIVE_MANIFEST_CAP (256). Direct-mapped rather than
 * LRU on purpose: no bookkeeping, no ordering bugs, and with <= 12 live runs
 * collisions are essentially absent.
 *
 * Virtual-address cost is bounded by 64 mappings/thread; RESIDENT cost is
 * ~zero beyond page tables, since the pages are shared page-cache pages that
 * were being read anyway.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* Return codes -- must match what mac_run_lookup's caller expects.
 *   1 found / 0 absent-in-this-run / 2 tombstone-hit / -1 error
 *  -2 = fall back to the asm path (not an error, just "not handled here"). */
#define LSM_MM_FOUND     1
#define LSM_MM_ABSENT    0
#define LSM_MM_TOMB      2
#define LSM_MM_ERR      (-1)
#define LSM_MM_FALLBACK (-2)

#define MAGIC_RUN   0x4E555255u   /* "URUN" */
#define MAGIC_RUN2  0x32555255u   /* "URU2" */
#define MAGIC_RUN3  0x33555255u   /* "URU3" */

#define SPARSE_ENT_SIZE  44
#define KEY_SIZE         36
#define SCRIPT_MAX_BYTES 65536

#define LSM_MM_SLOTS 64

typedef struct {
    int   valid;
    u64   run_no;
    u64   gen;
    int   fd;
    const u8 *base;
    size_t len;
    /* parsed header */
    u64   nrec, bloom_bytes, bits_mask, header_size, sparse_off, sparse_n, rec_v2;
    u64   records_start;
} lsm_run_t;

/* Cache epoch. utxo_lsm_init / utxo_lsm_reload bump this; every thread
 * notices the change on its next lookup and drops its whole cache.
 *
 * This is what makes run_no reuse ACROSS LSM instances safe. Within one
 * instance next_run_no only climbs, so a live run_no is never reassigned --
 * but a fresh utxo_lsm_init in the same directory restarts run_no and gen at
 * 0 while writing entirely different files, so (run_no, gen) alone is NOT a
 * unique key over process lifetime. tests/test_utxo_lsm.c does exactly this
 * (several init cycles in one temp dir) and caught it: 4 stress mismatches,
 * including a lookup answered with another key's record, from mappings left
 * over from the previous instance.
 *
 * A plain non-atomic counter is enough here: the bump happens in init/reload,
 * which by this module's own single-writer architecture never runs
 * concurrently with get(). Readers only ever compare for inequality, so a
 * torn or stale read can at worst cost one extra cache drop, never a stale
 * hit. */
static volatile unsigned long g_epoch = 1;
static __thread unsigned long t_epoch;

static __thread lsm_run_t g_cache[LSM_MM_SLOTS];
static __thread u8        g_script[SCRIPT_MAX_BYTES];

static void slot_release(lsm_run_t *s);

/* Opt-out, for differential testing: BMC_LSM_MMAP=0 forces the asm path. */
static __thread int g_enabled = -1;
static int mm_enabled(void){
    if (g_enabled < 0) {
        const char *e = getenv("BMC_LSM_MMAP");
        g_enabled = (e && e[0] == '0') ? 0 : 1;
    }
    return g_enabled;
}

/* Runtime toggle so a single process can diff the fast path against the asm
 * path (tests/test_lsm_mmap_diff.c). Disabling also drops the cache, so a
 * later re-enable cannot serve anything mapped under different state. */
void lsm_mm_set_enabled(int on){
    if (!on)
        for (int i = 0; i < LSM_MM_SLOTS; i++)
            if (g_cache[i].valid) slot_release(&g_cache[i]);
    g_enabled = on ? 1 : 0;
}

/* Telemetry for the benchmark (per-thread; summed by the bench harness). */
static __thread u64 g_stat_map, g_stat_hit, g_stat_fallback;
void lsm_mm_stats(u64 *maps, u64 *hits, u64 *fallbacks){
    if (maps)      *maps      = g_stat_map;
    if (hits)      *hits      = g_stat_hit;
    if (fallbacks) *fallbacks = g_stat_fallback;
}
void lsm_mm_stats_reset(void){ g_stat_map = g_stat_hit = g_stat_fallback = 0; }

/* Called from utxo_lsm_init / utxo_lsm_reload (bitcoin_utxo_lsm.asm). */
void lsm_mm_invalidate_all(void){ g_epoch++; }

static void slot_release(lsm_run_t *s){
    if (s->base) { munmap((void*)s->base, s->len); s->base = NULL; }
    if (s->fd >= 0) { close(s->fd); s->fd = -1; }
    s->valid = 0;
}

static u32 rd32(const u8 *p){ u32 v; memcpy(&v, p, 4); return v; }
static u64 rd64(const u8 *p){ u64 v; memcpy(&v, p, 8); return v; }

/* Parse the run header out of the mapping. Mirrors mac_read_run_header
 * (bitcoin_utxo_lsm.asm:545) field for field, including the three magics and
 * the bloom_bits -> {bits_mask, bloom_bytes} derivation. Returns 0 ok. */
static int parse_header(lsm_run_t *s){
    if (s->len < 4) return -1;
    u32 magic = rd32(s->base);
    u64 need_body;
    if (magic == MAGIC_RUN)                                 { s->header_size = 28; need_body = 24; s->rec_v2 = 0; }
    else if (magic == MAGIC_RUN2 || magic == MAGIC_RUN3)    { s->header_size = 44; need_body = 40;
                                                              s->rec_v2 = (magic == MAGIC_RUN3) ? 1 : 0; }
    else return -1;
    if (s->len < 4 + need_body) return -1;

    const u8 *b = s->base + 4;
    s->gen         = rd64(b + 0);
    s->nrec        = rd64(b + 8);
    u64 bloom_bits = rd64(b + 16);
    s->bits_mask   = bloom_bits - 1;      /* same as the asm: dec then shr 3 */
    s->bloom_bytes = bloom_bits >> 3;
    if (s->header_size == 44) {
        s->sparse_off = rd64(b + 24);
        s->sparse_n   = rd64(b + 32);
    } else {
        s->sparse_off = 0;
        s->sparse_n   = 0;
    }
    s->records_start = s->header_size + s->bloom_bytes;

    /* Bounds: every region we will touch must lie inside the mapping.
     * A malformed/truncated run falls back rather than reading OOB. */
    if (s->records_start > s->len) return -1;
    if (s->sparse_n) {
        u64 end;
        if (__builtin_mul_overflow(s->sparse_n, (u64)SPARSE_ENT_SIZE, &end)) return -1;
        if (__builtin_add_overflow(end, s->sparse_off, &end)) return -1;
        if (end > s->len) return -1;
    }
    return 0;
}

/* Acquire a mapping for (run_no, gen), reusing the cache when possible. */
static lsm_run_t *slot_get(u64 run_no, u64 gen){
    if (t_epoch != g_epoch) {                 /* new LSM instance -- drop all */
        for (int i = 0; i < LSM_MM_SLOTS; i++)
            if (g_cache[i].valid) slot_release(&g_cache[i]);
        t_epoch = g_epoch;
    }
    lsm_run_t *s = &g_cache[run_no % LSM_MM_SLOTS];

    if (s->valid && s->run_no == run_no && s->gen == gen) { g_stat_hit++; return s; }
    if (s->valid) slot_release(s);          /* collision, or stale gen */

    memset(s, 0, sizeof *s);
    s->fd = -1;

    char path[32];
    snprintf(path, sizeof path, "utxo_run_%06u.dat", (unsigned)run_no);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return NULL; }

    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { close(fd); return NULL; }

    s->fd   = fd;
    s->base = (const u8*)m;
    s->len  = (size_t)st.st_size;

    if (parse_header(s) != 0) { slot_release(s); return NULL; }

    /* The file's own generation must be the one the manifest promised.
     * Guards against a run_no whose file was replaced underneath us. */
    if (s->gen != gen) { slot_release(s); return NULL; }

    s->run_no = run_no;
    s->valid  = 1;
    g_stat_map++;
    return s;
}

/* FNV-1a-style, byte-for-byte identical to mac_bloom_h
 * (bitcoin_utxo_lsm.asm:658): h = seed; for each of 36 key bytes,
 * h ^= byte; h *= 16777619, all in 32-bit wraparound. */
static u32 bloom_h(const u8 *key, u32 seed){
    u32 h = seed;
    for (int i = 0; i < KEY_SIZE; i++) { h ^= key[i]; h *= 16777619u; }
    return h;
}

static int bloom_test(const u8 *bloom, u32 bits_mask, const u8 *key, u32 seed){
    u32 bit = bloom_h(key, seed) & bits_mask;
    return (bloom[bit >> 3] >> (bit & 7)) & 1;
}

/* mac_cmp_key semantics: the 36-byte key compared big-endian-wise, which is
 * exactly unsigned bytewise order. Returns <0, 0, >0. */
static int cmp_key(const u8 *a, const u8 *b){ return memcmp(a, b, KEY_SIZE); }

/*
 * lsm_run_lookup_mm -- the fast path.
 *
 * Signature deliberately mirrors mac_run_lookup's, with `gen` added so the
 * cache can be validated (see the staleness note at the top).
 */
long lsm_run_lookup_mm(void *lst, u64 run_no, u64 gen,
                       const u8 *txid, u32 index,
                       u64 *out_value, u64 *out_height, u64 *out_is_coinbase,
                       const u8 **out_script, u32 *out_slen)
{
    (void)lst;
    if (!mm_enabled()) { g_stat_fallback++; return LSM_MM_FALLBACK; }

    lsm_run_t *s = slot_get(run_no, gen);
    if (!s) { g_stat_fallback++; return LSM_MM_FALLBACK; }

    u8 key[KEY_SIZE];
    memcpy(key, txid, 32);
    memcpy(key + 32, &index, 4);

    /* ---- bloom: 3 seeds, all must hit ---- */
    const u8 *bloom = s->base + s->header_size;
    if (s->bloom_bytes) {
        if (!bloom_test(bloom, (u32)s->bits_mask, key, 0x811c9dc5u)) return LSM_MM_ABSENT;
        if (!bloom_test(bloom, (u32)s->bits_mask, key, 0xa1b2c3d4u)) return LSM_MM_ABSENT;
        if (!bloom_test(bloom, (u32)s->bits_mask, key, 0x5bd1e995u)) return LSM_MM_ABSENT;
    }

    /* ---- sparse index: largest sampled key <= target ---- */
    u64 pos = s->records_start;
    if (s->sparse_n) {
        u64 lo = 0, hi = s->sparse_n - 1;
        while (lo <= hi) {
            u64 mid = lo + (hi - lo) / 2;
            const u8 *e = s->base + s->sparse_off + mid * SPARSE_ENT_SIZE;
            int c = cmp_key(e, key);
            if (c > 0) { if (mid == 0) break; hi = mid - 1; }
            else       { pos = rd64(e + KEY_SIZE); lo = mid + 1; }
        }
        if (pos > s->len) return LSM_MM_FALLBACK;   /* corrupt sparse offset */
    }

    /* ---- linear scan forward from `pos` (records are sorted) ----
     *
     * UTX-9 (audit 2026-09-03): the bound was s->len, the whole MAPPING, not
     * the records region. For a target greater than every key in the run --
     * reached whenever the bloom passes, and a saturated 4 MiB filter on a
     * 30M-record bulk run passes almost always -- the scan ran off the end of
     * the records and into the SPARSE-INDEX TRAILER, parsing 44-byte index
     * entries as records and skipping by whatever their bytes happened to say
     * `slen` was. It stayed inside the mapping, so nothing was ever read out
     * of bounds; the cost was wasted I/O and a false hit needing a 36-byte
     * match at a garbage-aligned position. But "in bounds by luck of the
     * layout" is not an invariant worth keeping.
     *
     * The records end where the sparse index begins; a run written without a
     * sparse index has no trailer, so the mapping end is correct there. */
    const u64 rec_end = s->sparse_off ? s->sparse_off : s->len;
    for (;;) {
        if (pos + 37 > rec_end) return LSM_MM_ABSENT;
        const u8 *rec  = s->base + pos;
        int c    = cmp_key(rec, key);
        u8  kind = rec[36];

        if (c == 0) {
            if (kind == 2) return LSM_MM_TOMB;
            /* PUSH: value(8) slen(2) [height(4) is_coinbase(1) if rec_v2] */
            u64 vp = pos + 37;
            u64 vlen = s->rec_v2 ? 15 : 10;
            if (vp + vlen > rec_end) return LSM_MM_FALLBACK;   /* UTX-9 */
            const u8 *v = s->base + vp;
            u32 slen = (u32)(v[8] | (v[9] << 8));
            if (slen > SCRIPT_MAX_BYTES) return LSM_MM_FALLBACK;
            if (vp + vlen + slen > rec_end) return LSM_MM_FALLBACK;   /* UTX-9 */

            *out_value = rd64(v);
            if (s->rec_v2) {
                *out_height      = (u64)rd32(v + 10);
                *out_is_coinbase = (u64)v[14];
            } else {
                *out_height = 0;
                *out_is_coinbase = 0;
            }
            if (slen) memcpy(g_script, s->base + vp + vlen, slen);
            *out_script = g_script;
            *out_slen   = slen;
            return LSM_MM_FOUND;
        }
        if (c > 0) return LSM_MM_ABSENT;   /* sorted: we are past it */

        /* advance past this record */
        if (kind != 1) { pos += 37; continue; }      /* tombstone: header only */
        u64 vp = pos + 37;
        u64 vlen = s->rec_v2 ? 15 : 10;
        if (vp + vlen > rec_end) return LSM_MM_ABSENT;   /* UTX-9 */
        const u8 *v = s->base + vp;
        u32 slen = (u32)(v[8] | (v[9] << 8));
        pos = vp + vlen + slen;
    }
}
