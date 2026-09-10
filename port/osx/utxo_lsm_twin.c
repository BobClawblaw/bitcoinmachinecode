/* ============================================================================
 * utxo_lsm_twin.c -- LSM-tree-style persistent UTXO store, macOS/AArch64.
 * Functional twin of asm/bitcoin_utxo_lsm.asm (branch bmc_osx).
 *
 * Architecture (mirrors the x86 module):
 *   - memtable+WAL tier is utxo_store_* + the in-memory table (this twin
 *     delegates to utxo_store_twin.c / utxo_twin.c; the state struct's first
 *     40 bytes are utxo_store's own layout, so `lst` doubles as its `st`).
 *   - THIS module adds: flush (memtable live entries + this generation's
 *     tombstones -> sorted immutable run file, MAGIC_RUN3 44-byte header,
 *     3-seed bloom, 64-record sparse index), manifest (UMAN/UMN2, tmp+fsync+
 *     rename+dir-fsync), multi-run point lookup newest-generation-first
 *     bloom-gated sparse-accelerated, k-way merge recount/compact/walk.
 *
 * State struct offsets (lst; caller zeroes then sets the config fields):
 *   +0..39   utxo_store layout (log_fd idx_fd log_len ckpt_log_off ckpt_n)
 *   +40  op_count      +48 op_threshold      +56 fill_threshold
 *   +64  tomb_buf      +72 tomb_cap          +80 tomb_n
 *   +88  total_live    +96 next_gen          +104 manifest_buf
 *   +112 manifest_cap  +120 manifest_n       +128 scratch_buf
 *   +136 scratch_cap   +144 next_run_no      +152 tomb_hash_buf (LSM-owned)
 *   +160 tomb_hash_mask (LSM-owned)          total 168 bytes
 *
 * Descriptor (64B, flush scratch): key36 @0, index @32, type @36,
 * value @40, slen @48, height @50, is_coinbase @54, script_ptr @56.
 *
 * Run file: MAGIC_RUN3 header 44B [magic][gen][nrec][bloom_bits]
 * [sparse_off][sparse_n], bloom bytes, sorted records (key36+type1 [+value8
 * slen2 height4 cb1 [+script] for PUSH]), sparse index (key36+offset8,
 * SPARSE_STRIDE 64).
 *
 * Exports:
 *   utxo_lsm_init/init_ro/put/del/get/count/reload/reload_ro/walk/compact/
 *   compact_range/close/flush, sort_desc, set_sort_mode, set_defer_unlink,
 *   set_defer_publish, set_flush_hook, wal_drain (tail to utxo_store_close).
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef int64_t i64;
typedef unsigned char u8;

#define MAGIC_RUN        0x4E555255u   /* "URUN" */
#define MAGIC_RUN2       0x32555255u   /* "URU2" */
#define MAGIC_RUN3       0x33555255u   /* "URU3" */
#define MAGIC_MANIFEST   0x4E414D55u   /* "UMAN" */
#define MAGIC_MANIFEST2  0x324E4D55u   /* "UMN2" */
#define BLOOM_MAX_BYTES  (4u * 1024 * 1024)
#define SCRIPT_MAX_BYTES 65536
#define SPARSE_STRIDE    64
#define SPARSE_ENT_SIZE  44
#define COMPACT_MAX_RUNS 64
#define COMPACT_RDBUF    262144
#define SLOT_RD_FILL     (104 + SCRIPT_MAX_BYTES)
#define SLOT_RD_POS      (SLOT_RD_FILL + 8)
#define SLOT_RD_BUF      (SLOT_RD_FILL + 16)
#define COMPACT_SLOT_SIZE (SLOT_RD_BUF + COMPACT_RDBUF)
#define COMPACT_SLOTS_BYTES (COMPACT_MAX_RUNS * COMPACT_SLOT_SIZE)
#define COMPACT_SCRATCH_BYTES (COMPACT_SLOTS_BYTES + BLOOM_MAX_BYTES)
#define MAC_FLBUF        1048576
#define MAC_OWBUF        1048576
#define RS_INS_MAX       32
#define RS_MAX_DEPTH     72
#define RS_CNT_BYTES     (4096 * 8)
#define RS_PF            8
#define RS_GATHER_PF     16

static const char manifest_name[]      = "utxo_manifest.dat";
static const char manifest_tmp_name[]  = "utxo_manifest.tmp";
static const char manifest_child_name[] = "utxo_manifest.child";
static const char dot_name[]           = ".";
static const char wal_name[]           = "utxo.dat";

/* ---- upstream C fast path (vendored byte-for-byte as asm/utxo_lsm_mm.c) -- */
extern long lsm_run_lookup_mm(void *lst, u64 run_no, u64 gen, const u8 *txid,
                              u32 index, u64 *out_value, u64 *out_height,
                              u64 *out_is_coinbase, const u8 **out_script,
                              u32 *out_slen);
extern void lsm_mm_invalidate_all(void);

/* ---- memtable + WAL tier (utxo_store_twin.c / utxo_twin.c) --------------- */
extern long utxo_store_init(void *st);
extern long utxo_store_init_ro(void *st);
extern long utxo_store_put(void *st, void *u, const u8 txid[32], unsigned index,
                           u64 value, unsigned height, unsigned is_coinbase,
                           const void *script, unsigned slen);
extern long utxo_store_del(void *st, void *u, const u8 txid[32], unsigned index);
extern long utxo_store_get(void *st, void *u, const u8 txid[32], unsigned index,
                           u64 *value, unsigned long *height,
                           unsigned long *is_coinbase, const void **script,
                           unsigned long *slen);
extern long utxo_store_reload(void *st, void *u);
extern long utxo_store_wal_drain(void *st);
extern void utxo_store_close(void *st);
extern long utxo_get(void *u, const u8 txid[32], unsigned long index,
                     u64 *value, unsigned long *height,
                     unsigned long *is_coinbase, const void **script,
                     unsigned long *slen);
extern long utxo_del(void *u, const u8 txid[32], unsigned long index);
extern long utxo_walk_live(void *u,
                           long (*cb)(void *, const u8 *, unsigned long, u64,
                                      unsigned, unsigned, const void *,
                                      unsigned long),
                           void *ctx);

/* ---- process-global writer state (mirrors the x86 .bss) ------------------ */
static u64 mac_ow_fd, mac_ow_fill;
static u8 mac_ow_buf[MAC_OWBUF];
static u64 mac_fl_fill;
static u8 mac_fl_buf[MAC_FLBUF];
static u64 mac_compact_defer_unlink, mac_compact_defer_publish;
static void *mac_flush_hook;
static u64 mac_cr_lo, mac_cr_k;
static u64 mac_sort_mode = 1;                /* 1 = radix (default) */
static u64 mac_rs_a, mac_rs_final;
static u8 mac_rs_counts[RS_MAX_DEPTH * RS_CNT_BYTES];

/* flush-writer buffer */
static int write_exact(int fd, const void *buf, u64 len);
static long mac_fl_drain(int fd);

static long mac_fl_write(int fd, const u8 *src, u64 len)
{
    if (mac_fl_fill + len > MAC_FLBUF) {
        if (mac_fl_drain(fd)) return -1;
        if (len > MAC_FLBUF) {
            return write_exact(fd, src, len) ? -1 : 0;
        }
    }
    memcpy(mac_fl_buf + mac_fl_fill, src, len);
    mac_fl_fill += len;
    return 0;
}

static long mac_fl_drain(int fd)
{
    if (!mac_fl_fill) return 0;
    long r = write_exact(fd, mac_fl_buf, mac_fl_fill);
    mac_fl_fill = 0;
    return r ? -1 : 0;
}

static int write_exact(int fd, const void *buf, u64 len)
{
    const u8 *p = buf;
    while (len) {
        ssize_t w = write(fd, p, len);
        if (w <= 0) return -1;
        p += w;
        len -= (u64)w;
    }
    return 0;
}

static int read_exact(int fd, void *buf, u64 len)
{
    u8 *p = buf;
    while (len) {
        ssize_t r = read(fd, p, len);
        if (r <= 0) return -1;
        p += r;
        len -= (u64)r;
    }
    return 0;
}

static void lmemcpy(void *dst, const void *src, u64 n) { memcpy(dst, src, n); }

/* ---- fmt_runname(buf20, run_no): "utxo_run_%06u.dat" -------------------- */
static void fmt_runname(char *buf, u32 run_no)
{
    snprintf(buf, 21, "utxo_run_%06u.dat", run_no);
}

/* ---- mac_cmp_key: 36-byte unsigned bytewise; 0 lt / 1 eq / 2 gt ---------- */
static int mac_cmp_key(const u8 *p, const u8 *q)
{
    for (int i = 0; i < 36; i++) {
        if (p[i] < q[i]) return 0;
        if (p[i] > q[i]) return 2;
    }
    return 1;
}

/* ---- bloom hash: FNV-1a over the 36-byte key ---------------------------- */
static u32 mac_bloom_h(const u8 *key, u32 seed)
{
    u32 h = seed;
    for (int i = 0; i < 36; i++) {
        h ^= key[i];
        h *= 16777619u;
    }
    return h;
}

static void mac_bloom_setbit(const u8 *key, u32 seed, u8 *bloom, u32 bits_mask)
{
    u32 bit = mac_bloom_h(key, seed) & bits_mask;
    bloom[bit >> 3] |= (u8)(1u << (bit & 7));
}

static int mac_bloom_testbit(const u8 *key, u32 seed, const u8 *bloom, u32 bits_mask)
{
    u32 bit = mac_bloom_h(key, seed) & bits_mask;
    return (bloom[bit >> 3] >> (bit & 7)) & 1;
}

/* ---- tombstone-membership hash set (lst+152/160), LSM-owned mmap -------- */
static long mac_tomb_hash_reset(void *lst)
{
    u8 *L = (u8 *)lst;
    if (!*(u64 *)(L + 152)) {
        u64 cap = *(u64 *)(L + 72);
        if (cap < 1) cap = 1;
        cap <<= 1;
        cap--;                                   /* next_pow2 below */
        cap |= cap >> 1; cap |= cap >> 2; cap |= cap >> 4;
        cap |= cap >> 8; cap |= cap >> 16; cap |= cap >> 32;
        cap++;
        void *m = mmap(NULL, cap * 8, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) return -1;
        *(u64 *)(L + 152) = (u64)m;
        *(u64 *)(L + 160) = cap - 1;
    }
    u64 *slots = (u64 *)*(u64 *)(L + 152);
    u64 count = *(u64 *)(L + 160) + 1;
    memset(slots, 0xFF, count * 8);
    return 1;
}

/* ---- tombstone probe: returns &slot (empty -1 or matching index) -------- */
static u64 *mac_tomb_hash_probe(void *lst, const u8 key[36])
{
    u8 *L = (u8 *)lst;
    u32 h = 0x811c9dc5u;
    for (int i = 0; i < 8; i++) {
        h ^= key[i];
        h *= 16777619u;
    }
    u32 idx;
    memcpy(&idx, key + 32, 4);
    u64 off = (h ^ idx) & *(u64 *)(L + 160);
    u64 *slots = (u64 *)*(u64 *)(L + 152);
    u8 *tomb = (u8 *)*(u64 *)(L + 64);
    u64 mask = *(u64 *)(L + 160);
    for (;;) {
        u64 *slot = &slots[off];
        if (*slot == (u64)-1) return slot;
        if (mac_cmp_key(tomb + *slot * 36, key) == 1) return slot;
        off = (off + 1) & mask;
    }
}

/* ---- mac_read_run_header(fd, out64) -> 0 / -1 ---------------------------- */
/* out: +0 gen +8 nrec +16 bloom_bytes +24 bits_mask +32 header_size
        +40 sparse_off +48 sparse_n +56 rec_v2 */
static long mac_read_run_header(int fd, u64 *out)
{
    u8 tmp[40];
    u32 magic;
    if (read_exact(fd, &magic, 4)) return -1;
    u64 rec_v2;
    u64 need;
    if (magic == MAGIC_RUN3)      { rec_v2 = 1; need = 40; }
    else if (magic == MAGIC_RUN2) { rec_v2 = 0; need = 40; }
    else if (magic == MAGIC_RUN)  { rec_v2 = 0; need = 24; }
    else return -1;
    if (read_exact(fd, tmp, need)) return -1;
    u64 bloom_bits;
    memcpy(&out[0], tmp + 0, 8);                 /* gen */
    memcpy(&out[1], tmp + 8, 8);                 /* nrec */
    memcpy(&bloom_bits, tmp + 16, 8);
    out[2] = bloom_bits >> 3;                    /* bloom_bytes */
    out[3] = bloom_bits - 1;                     /* bits_mask */
    if (need == 40) {
        memcpy(&out[4], tmp + 24, 8);            /* sparse_off */
        memcpy(&out[5], tmp + 32, 8);            /* sparse_n */
        out[6] = 44;
    } else {
        out[4] = 0;
        out[5] = 0;
        out[6] = 28;
    }
    out[7] = rec_v2;
    return 0;
}

/* ---- sort: merge sort (stable) or MSD radix (default), 64B descriptors --- */
static int cmp_key_be(const u8 *p, const u8 *q)
{
    /* mac_cmp_key compares big-endian-wise = plain unsigned bytewise over
     * the raw key bytes; identical result either way. */
    return mac_cmp_key(p, q);
}

static void mac_sort_desc(u8 *a, u8 *b, u64 n);

static void mac_rs_rec_buckets(u8 *src, u8 *dst, u64 n, u32 bitoff, unsigned depth);
static u64 extract_digit(const u8 *e, u32 bitoff, unsigned width, u32 shift);

static void mac_rsort_rec(u8 *src, u8 *dst, u64 n, u32 bitoff, unsigned depth)
{
    if (bitoff >= 288) {                          /* all key bits consumed */
        if (src < (u8 *)mac_rs_final)
            memcpy(dst, src, n * 16);
        return;
    }
    if (n <= RS_INS_MAX || depth >= RS_MAX_DEPTH) {
        /* stable insertion sort on (hi, lo), tie-break key bytes 12..35 */
        for (u64 i = 1; i < n; i++) {
            u8 hold[16];
            memcpy(hold, src + i * 16, 16);
            u64 j = i;
            while (j) {
                u8 *prev = src + (j - 1) * 16;
                u64 hi_p, hi_h;
                memcpy(&hi_p, prev, 8);
                memcpy(&hi_h, hold, 8);
                int gt;
                if (hi_p > hi_h) gt = 1;
                else if (hi_p < hi_h) gt = 0;
                else {
                    u32 lo_p, lo_h;
                    memcpy(&lo_p, prev + 12, 4);
                    memcpy(&lo_h, hold + 12, 4);
                    if (lo_p > lo_h) gt = 1;
                    else if (lo_p < lo_h) gt = 0;
                    else {
                        /* 96-bit tie: key bytes 12..35 via the descriptors */
                        u32 pi, hi_i;
                        memcpy(&pi, prev + 8, 4);
                        memcpy(&hi_i, hold + 8, 4);
                        const u8 *dp = (const u8 *)mac_rs_a;
                        const u8 *a = dp + (u64)pi * 64 + 12;
                        const u8 *b = dp + (u64)hi_i * 64 + 12;
                        gt = 0;
                        for (int k = 0; k < 24; k++) {
                            if (b[k] > a[k]) { gt = 1; break; }
                            if (b[k] < a[k]) break;
                        }
                    }
                }
                if (!gt) break;
                memcpy(src + j * 16, src + (j - 1) * 16, 16);
                j--;
            }
            memcpy(src + j * 16, hold, 16);
        }
        if (src < (u8 *)mac_rs_final)
            memcpy(dst, src, n * 16);
        return;
    }
    unsigned width = n >= 65536 ? 12u : 8u;
    if (bitoff >= 96) {
        /* variant C: the digit is a KEY BYTE (bytes 12..35) read through the
         * descriptor array -- the compact entry only carries 96 bits. */
        u64 counts[256];
        memset(counts, 0, sizeof counts);
        u64 byteoff = bitoff >> 3;
        const u8 *A = (const u8 *)mac_rs_a;
        for (u64 i = 0; i < n; i++) {
            u32 eidx;
            memcpy(&eidx, src + i * 16 + 8, 4);
            counts[A[eidx * 64 + byteoff]]++;
        }
        u64 pos[256];
        u64 acc = 0;
        for (int d = 0; d < 256; d++) { pos[d] = acc; acc += counts[d]; }
        /* one shared digit -> next level, no scatter */
        int shared = 0;
        for (int d = 0; d < 256; d++)
            if (counts[d] == n) { shared = 1; break; }
        if (shared) { mac_rsort_rec(src, dst, n, bitoff + width, depth + 1); return; }
        for (u64 i = 0; i < n; i++) {
            u32 eidx;
            memcpy(&eidx, src + i * 16 + 8, 4);
            u8 digit = A[eidx * 64 + byteoff];
            memcpy(dst + pos[digit] * 16, src + i * 16, 16);
            pos[digit]++;                            /* pos[d] = bucket END */
        }
        u64 start = 0;
        for (int d = 0; d < 256; d++) {
            u64 end = pos[d];
            if (end > start) {
                if (dst == (u8 *)mac_rs_final)
                    mac_rsort_rec(dst + start * 16, src + start * 16, end - start,
                                  bitoff + width, depth + 1);
                else
                    mac_rsort_rec(dst + start * 16, src + start * 16, end - start,
                                  bitoff + width, depth + 1);
            }
            start = end;
        }
        return;
    }
    /* variants A/B on the compact entry */
    u64 nbuckets = 1ull << width;
    u64 *counts = malloc(nbuckets * 8);
    memset(counts, 0, nbuckets * 8);
    u32 shift;
    if (bitoff + width <= 64) shift = 64 - (bitoff + width);
    else                      shift = 128 - (bitoff + width);
    for (u64 i = 0; i < n; i++) {
        u64 digit = extract_digit(src + i * 16, bitoff, width, shift);
        counts[digit]++;
    }
    /* one shared digit -> next level, no scatter */
    int shared = 0;
    for (u64 d = 0; d < nbuckets; d++)
        if (counts[d] == n) { shared = 1; break; }
    if (shared) { free(counts); mac_rsort_rec(src, dst, n, bitoff + width, depth + 1); return; }
    u64 *pos = malloc(nbuckets * 8);
    u64 acc = 0;
    for (u64 d = 0; d < nbuckets; d++) { pos[d] = acc; acc += counts[d]; }
    for (u64 i = 0; i < n; i++) {
        u64 digit = extract_digit(src + i * 16, bitoff, width, shift);
        memcpy(dst + pos[digit] * 16, src + i * 16, 16);
        pos[digit]++;                                /* pos[d] = bucket END */
    }
    u64 start = 0;
    for (u64 d = 0; d < nbuckets; d++) {
        u64 end = pos[d];
        if (end > start) {
            /* recurse; ping-pong so the next level reads what we just wrote */
            if (dst == (u8 *)mac_rs_final)
                mac_rsort_rec(dst + start * 16, src + start * 16, end - start,
                              bitoff + width, depth + 1);
            else
                mac_rsort_rec(dst + start * 16, src + start * 16, end - start,
                              bitoff + width, depth + 1);
        }
        start = end;
    }
    free(pos);
    free(counts);
}

/* extract the digit for entry at e (16B compact: hi@0, idx@8, lo@12) */
static u64 extract_digit(const u8 *e, u32 bitoff, unsigned width, u32 shift)
{
        if (bitoff + width <= 64) {                  /* from hi alone */
        u64 hi;
        memcpy(&hi, e, 8);
        return (hi >> shift) & ((1u << width) - 1);
    }
    /* straddles hi and lo:idx (shift in [32,63]) */
    u64 hi, lo_idx;
    memcpy(&hi, e, 8);
    memcpy(&lo_idx, e + 8, 8);
    return ((hi << (64 - shift)) | (lo_idx >> shift)) &
           ((1u << width) - 1);
}

static void mac_rsort_desc(u8 *a, u8 *b, u64 n)
{
    if (n <= 1) return;
    mac_rs_a = (u64)a;
    u8 *compact_ping = b + n * 32;
    u8 *compact_pong = compact_ping + n * 16;
    mac_rs_final = (u64)compact_pong;
    for (u64 i = 0; i < n; i++) {
        u64 hi;
        memcpy(&hi, a + i * 64, 8);
        hi = __builtin_bswap64(hi);
        u32 lo;
        memcpy(&lo, a + i * 64 + 8, 4);
        lo = __builtin_bswap32(lo);
        memcpy(compact_ping + i * 16, &hi, 8);
        memcpy(compact_ping + i * 16 + 8, &i, 4);
        memcpy(compact_ping + i * 16 + 12, &lo, 4);
    }
    mac_rsort_rec(compact_ping, compact_pong, n, 0, 0);
    /* the sorted order must END in compact_pong; gather a[order] -> b -> a */
    for (u64 j = 0; j < n; j++) {
        u32 idx;
        memcpy(&idx, compact_pong + j * 16 + 8, 4);
        memcpy(b + j * 64, a + (u64)idx * 64, 64);
    }
    memcpy(a, b, n * 64);
}

static void mac_sort_desc(u8 *a, u8 *b, u64 n)
{
    if (n <= 1) return;
    u64 width = 1;
    int cur_src_is_a = 1;
    for (;;) {
        if (width >= n) break;
        u8 *src = cur_src_is_a ? a : b;
        u8 *dst = cur_src_is_a ? b : a;
        for (u64 lo = 0; lo < n; lo += 2 * width) {
            u64 mid = lo + width < n ? lo + width : n;
            u64 hi = lo + 2 * width < n ? lo + 2 * width : n;
            u64 p = lo, q = mid, out = lo;
            while (p < mid && q < hi) {
                if (mac_cmp_key(src + p * 64, src + q * 64) == 2)
                    memcpy(dst + out++ * 64, src + q++ * 64, 64);
                else
                    memcpy(dst + out++ * 64, src + p++ * 64, 64);
            }
            while (p < mid) memcpy(dst + out++ * 64, src + p++ * 64, 64);
            while (q < hi) memcpy(dst + out++ * 64, src + q++ * 64, 64);
        }
        width <<= 1;
        cur_src_is_a ^= 1;
    }
    if (!cur_src_is_a) memcpy(a, b, n * 64);
}

void utxo_lsm_sort_desc(u8 *a, u8 *b, u64 n)
{
    if (mac_sort_mode) mac_rsort_desc(a, b, n);
    else mac_sort_desc(a, b, n);
}

void utxo_lsm_set_sort_mode(u64 mode) { mac_sort_mode = mode; }
void utxo_lsm_set_defer_unlink(u64 v) { mac_compact_defer_unlink = v; }
void utxo_lsm_set_defer_publish(u64 v) { mac_compact_defer_publish = v; }
void utxo_lsm_set_flush_hook(void *hook) { mac_flush_hook = hook; }

/* ==========================================================================
 * public API
 * ======================================================================== */

static long mac_calc_desc_cap(void *lst)
{
    u8 *L = (u8 *)lst;
    u64 cap = *(u64 *)(L + 136);
    if (cap < BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES) return 0;
    return (long)((cap - BLOOM_MAX_BYTES - SCRIPT_MAX_BYTES) / 128);
}

static void mac_clear_memtable(void *u)
{
    u8 *U = (u8 *)u;
    *(u64 *)(U + 0) = 0;
    *(u64 *)(U + 32) = 0;
    u64 mask = *(u64 *)(U + 8);
    u8 *slot = U + 40;
    for (u64 s = 0; s <= mask; s++, slot += 48)
        *(u32 *)(slot + 40) = 0xFFFFFFFFu;
}

long utxo_lsm_init(void *lst)
{
    u8 *L = (u8 *)lst;
    lsm_mm_invalidate_all();                 /* fresh instance: stale caches */
    if (utxo_store_init(lst) != 1) return -1;
    *(u64 *)(L + 40) = 0;                    /* op_count */
    *(u64 *)(L + 80) = 0;                    /* tomb_n */
    *(u64 *)(L + 88) = 0;                    /* total_live */
    *(u64 *)(L + 96) = 0;                    /* next_gen */
    *(u64 *)(L + 120) = 0;                   /* manifest_n */
    *(u64 *)(L + 144) = 0;                   /* next_run_no */
    if (mac_tomb_hash_reset(lst) != 1) return -1;
    return 1;
}

/* --------------------------------------------------------------------------
 * mac_flush(lst, u): sort memtable live entries + not-currently-live
 * tombstones into a new MAGIC_RUN3 run; publish the manifest; truncate the
 * WAL; reset the memtable + tomb list for the next generation.
 * ------------------------------------------------------------------------ */
static long mac_flush(void *lst, void *u)
{
    u8 *L = (u8 *)lst;
    if (utxo_store_wal_drain(lst) == -1) return -1;

    long desc_cap = mac_calc_desc_cap(lst);
    if (desc_cap < 0) return -1;
    u64 off_desc_b = (u64)desc_cap * 64;
    u64 off_bloom = off_desc_b * 2;
    u64 n_desc = 0;
    u8 *scratch = (u8 *)*(u64 *)(L + 128);
    u8 *desc = scratch;

    /* ---- memtable live slots -> PUSH descriptors ---- */
    u8 *U = (u8 *)u;
    u64 mask = *(u64 *)(U + 8);
    u8 *blob = (u8 *)(uintptr_t)*(u64 *)(U + 16);
    for (u64 s = 0; s <= mask; s++) {
        u8 *slot = U + 40 + s * 48;
        u32 idx;
        memcpy(&idx, slot + 40, 4);
        if (idx == 0xFFFFFFFFu) continue;
        if (n_desc >= (u64)desc_cap) return -1;
        u8 *d = desc + n_desc * 64;
        memcpy(d, slot + 8, 32);                    /* txid */
        memcpy(d + 32, &idx, 4);                    /* index */
        d[36] = 1;                                  /* type = PUSH */
        u8 *rec = blob + *(u64 *)slot;
        memcpy(d + 40, rec, 8);                     /* value */
        u64 hc;
        memcpy(&hc, rec + 8, 8);
        u32 height = (u32)(hc & 0xFFFFFFFFu);
        memcpy(d + 50, &height, 4);
        d[54] = (u8)((hc >> 32) & 0xFF);            /* is_coinbase */
        u16 slen = (u16)*(u64 *)(rec + 16);
        memcpy(d + 48, &slen, 2);
        memcpy(d + 56, &(u64){ (u64)(uintptr_t)(rec + 24) }, 8);
        n_desc++;
    }

    /* ---- tombstones -> DEL descriptors where the key is NOT still live ---- */
    u64 tomb_n = *(u64 *)(L + 80);
    u8 *tomb = (u8 *)*(u64 *)(L + 64);
    for (u64 t = 0; t < tomb_n; t++) {
        u8 *key = tomb + t * 36;
        u32 index;
        memcpy(&index, key + 32, 4);
        u64 v;
        unsigned long h, cb;
        const void *sc;
        unsigned long sl;
        if (utxo_get(u, key, index, &v, &h, &cb, &sc, &sl) == 1)
            continue;                                /* still live: skip */
        if (n_desc >= (u64)desc_cap) return -1;
        u8 *d = desc + n_desc * 64;
        memcpy(d, key, 36);
        d[36] = 2;                                   /* type = DEL */
        n_desc++;
    }

    if (n_desc == 0) goto finish_reset;              /* nothing to write */
    if (*(u64 *)(L + 120) >= *(u64 *)(L + 112)) return -1;  /* manifest cap */

    utxo_lsm_sort_desc(desc, scratch + off_desc_b, n_desc);

    /* ---- bloom sizing: max(64, n_desc*10) rounded up to pow2, capped ---- */
    u64 bloom_bits = n_desc * 10;
    if (bloom_bits < 64) bloom_bits = 64;
    u64 bb = 1;
    while (bb < bloom_bits) bb <<= 1;
    if (bb > (u64)BLOOM_MAX_BYTES * 8) bb = (u64)BLOOM_MAX_BYTES * 8;
    u64 bloom_bytes = bb >> 3;
    u64 bits_mask = bb - 1;
    memset(scratch + off_bloom, 0, bloom_bytes);
    for (u64 i = 0; i < n_desc; i++) {
        u8 *key = desc + i * 64;
        mac_bloom_setbit(key, 0x811c9dc5u, scratch + off_bloom, (u32)bits_mask);
        mac_bloom_setbit(key, 0xa1b2c3d4u, scratch + off_bloom, (u32)bits_mask);
        mac_bloom_setbit(key, 0x5bd1e995u, scratch + off_bloom, (u32)bits_mask);
    }

    /* ---- write the run file ---- */
    char runname[24];
    u64 run_no = *(u64 *)(L + 144);
    fmt_runname(runname, (u32)run_no);
    int fd = open(runname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    mac_fl_fill = 0;

    u8 hdr[44];
    u32 m3 = MAGIC_RUN3;
    memcpy(hdr + 0, &m3, 4);
    u64 gen = *(u64 *)(L + 96);
    memcpy(hdr + 4, &gen, 8);
    memcpy(hdr + 12, &n_desc, 8);
    memcpy(hdr + 20, &bb, 8);
    u64 sparse_off = 0, sparse_n = 0;
    memcpy(hdr + 28, &sparse_off, 8);
    memcpy(hdr + 36, &sparse_n, 8);
    if (write_exact(fd, hdr, 44)) goto fail_close;
    if (write_exact(fd, scratch + off_bloom, bloom_bytes)) goto fail_close;

    /* sparse staging lives in the off_desc_b slack region */
    u8 *sparse = desc + (u64)desc_cap * 0 + off_desc_b - (u64)desc_cap * 64;
    sparse = scratch + off_desc_b;                   /* same region: pong slack */
    (void)sparse;
    u8 *sparse_buf = scratch + off_desc_b;
    for (u64 i = 0; i < n_desc; i++) {
        u8 *rec = desc + i * 64;
        if ((i & (SPARSE_STRIDE - 1)) == 0) {
            off_t cur = lseek(fd, 0, SEEK_CUR);
            if (cur < 0) goto fail_close;
            u64 foff = (u64)cur + mac_fl_fill;       /* logical offset */
            memcpy(sparse_buf + sparse_n * SPARSE_ENT_SIZE, rec, 36);
            memcpy(sparse_buf + sparse_n * SPARSE_ENT_SIZE + 36, &foff, 8);
            sparse_n++;
        }
        if (mac_fl_write(fd, rec, 37)) goto fail_close;          /* key+type */
        if (rec[36] == 1) {                                       /* PUSH */
            if (mac_fl_write(fd, rec + 40, 15)) goto fail_close;  /* v+s+h+cb */
            u16 slen;
            memcpy(&slen, rec + 48, 2);
            if (slen) {
                const void *sp;
                memcpy(&sp, rec + 56, 8);
                if (mac_fl_write(fd, sp, slen)) goto fail_close;
            }
        }
    }
    if (mac_fl_drain(fd)) goto fail_close;
    /* sparse index after the last record */
    off_t sp_off = lseek(fd, 0, SEEK_CUR);
    if (sp_off < 0) goto fail_close;
    if (sparse_n &&
        write_exact(fd, sparse_buf, sparse_n * SPARSE_ENT_SIZE)) goto fail_close;
    /* patch sparse_off/sparse_n into the header at offset 28 */
    if (lseek(fd, 28, SEEK_SET) < 0) goto fail_close;
    memcpy(hdr + 28, &sp_off, 8);
    memcpy(hdr + 36, &sparse_n, 8);
    if (write_exact(fd, hdr + 28, 16)) goto fail_close;
    fsync(fd);
    close(fd);

    /* ---- manifest append + publish ---- */
    if (*(u64 *)(L + 120) >= *(u64 *)(L + 112)) return -1;
    u8 *ment = (u8 *)*(u64 *)(L + 104) + *(u64 *)(L + 120) * 16;
    memcpy(ment, &gen, 8);
    memcpy(ment + 8, &run_no, 8);
    (*(u64 *)(L + 120))++;
    (*(u64 *)(L + 96))++;                            /* next_gen */
    (*(u64 *)(L + 144))++;                           /* next_run_no */

    int mfd = open(manifest_tmp_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (mfd < 0) return -1;
    u8 mh[20];
    u32 m2 = MAGIC_MANIFEST2;
    memcpy(mh + 0, &m2, 4);
    /* total_live at THIS point is the runs-only count: the memtable entries
     * were just folded into the run and the WAL is truncated below. */
    memcpy(mh + 4, L + 120, 8);
    memcpy(mh + 12, L + 88, 8);
    if (write_exact(mfd, mh, 20) ||
        write_exact(mfd, (void *)*(u64 *)(L + 104), *(u64 *)(L + 120) * 16)) {
        close(mfd);
        return -1;
    }
    fsync(mfd);
    close(mfd);
    if (rename(manifest_tmp_name, manifest_name) < 0) return -1;
    { int dfd = open(".", O_RDONLY);
      if (dfd >= 0) { fsync(dfd); close(dfd); } }

finish_reset:
    /* UTX-8: the WAL reset must succeed before any state is cleared */
    if (ftruncate((int)*(u64 *)(L + 0), 0) < 0) return -1;
    if (lseek((int)*(u64 *)(L + 0), 0, SEEK_SET) < 0) return -1;
    *(u64 *)(L + 16) = 0;
    mac_clear_memtable(u);
    *(u64 *)(L + 40) = 0;                            /* op_count */
    *(u64 *)(L + 80) = 0;                            /* tomb_n */
    if (mac_tomb_hash_reset(lst) != 1) return -1;
    return 1;

fail_close:
    close(fd);
    return -1;
}

long utxo_lsm_flush(void *lst, void *u)
{
    return mac_flush(lst, u);
}

long utxo_lsm_put(void *lst, void *u, const u8 txid[32], u32 index,
                  u64 value, u32 height, u32 is_coinbase,
                  const void *script, u32 slen)
{
    u8 *L = (u8 *)lst;
    long r = utxo_store_put(lst, u, txid, index, value, height, is_coinbase,
                            script, slen);
    if (r == 1) (*(u64 *)(L + 88))++;                /* total_live++ on new coin */
    (*(u64 *)(L + 40))++;                            /* op_count++ */
    if (*(u64 *)(L + 40) >= *(u64 *)(L + 48) ||
        *(u64 *)u >= *(u64 *)(L + 56)) {
        if (mac_flush(lst, u) == -1) return -1;
    }
    return r;
}

long utxo_lsm_del(void *lst, void *u, const u8 txid[32], u32 index)
{
    u8 *L = (u8 *)lst;
    if (utxo_store_del(lst, u, txid, index) == -1) return -1;
    /* tombstone appended unconditionally (hit or miss -- contract change) */
    if (*(u64 *)(L + 80) >= *(u64 *)(L + 72)) return -1;
    u8 *key = (u8 *)*(u64 *)(L + 64) + *(u64 *)(L + 80) * 36;
    memcpy(key, txid, 32);
    memcpy(key + 32, &index, 4);
    *mac_tomb_hash_probe(lst, key) = *(u64 *)(L + 80);
    (*(u64 *)(L + 80))++;
    (*(u64 *)(L + 40))++;
    (*(u64 *)(L + 88))--;                            /* total_live-- */
    if (*(u64 *)(L + 40) >= *(u64 *)(L + 48) ||
        *(u64 *)u >= *(u64 *)(L + 56)) {
        if (mac_flush(lst, u) == -1) return -1;
    }
    return 1;
}

long utxo_lsm_count(void *lst)
{
    return (long)*(u64 *)((u8 *)lst + 88);
}

void utxo_lsm_close(void *lst)
{
    utxo_store_close(lst);
}

/* ---- per-run lookup: 1 found / 0 absent / 2 tombstone / -1 err ---------- */
static long mac_run_lookup(void *lst, u32 run_no, u64 gen, const u8 txid[32],
                           u32 index, u64 *value, u32 *height, u32 *is_coinbase,
                           const u8 **script_out, u32 *slen_out)
{
    u64 mv = 0, mh = 0, mcb = 0;
    u32 msl = 0;
    const u8 *msc = NULL;
    long mm = lsm_run_lookup_mm(lst, run_no, gen, txid, index,
                                &mv, &mh, &mcb, &msc, &msl);
    if (mm != -2) {
        if (mm == 1) {
            *value = mv;
            *height = (u32)mh;
            *is_coinbase = (u32)mcb;
            *script_out = msc;
            *slen_out = msl;
        }
        return mm;
    }
    /* fallback path (mirrors the x86 asm): open + header + bloom + sparse
     * binary search + forward scan. */
    char runname[24];
    fmt_runname(runname, run_no);
    int fd = open(runname, O_RDONLY);
    if (fd < 0) return -1;
    u64 hdr[8];
    if (mac_read_run_header(fd, hdr)) { close(fd); return -1; }
    u64 bloom_bytes = hdr[2], bits_mask = (u32)hdr[3];
    u64 header_size = hdr[6], sparse_off = hdr[4], sparse_n = hdr[5];
    int rec_v2 = (int)hdr[7];
    u8 key[36];
    memcpy(key, txid, 32);
    memcpy(key + 32, &index, 4);

    static __thread u8 bloom[BLOOM_MAX_BYTES];
    if (bloom_bytes > BLOOM_MAX_BYTES) { close(fd); return -1; }
    if (read_exact(fd, bloom, bloom_bytes)) { close(fd); return -1; }
    if (!mac_bloom_testbit(key, 0x811c9dc5u, bloom, (u32)bits_mask) ||
        !mac_bloom_testbit(key, 0xa1b2c3d4u, bloom, (u32)bits_mask) ||
        !mac_bloom_testbit(key, 0x5bd1e995u, bloom, (u32)bits_mask)) {
        close(fd);
        return 0;                                    /* bloom says absent */
    }
    u64 records_start = header_size + bloom_bytes;
    u64 pos = records_start;
    if (sparse_n) {                                  /* binary search */
        u64 lo = 0, hi = sparse_n - 1;
        static __thread u8 ent[SPARSE_ENT_SIZE];
        while (lo <= hi) {
            u64 mid = lo + (hi - lo) / 2;
            if (pread(fd, ent, SPARSE_ENT_SIZE,
                      (off_t)(sparse_off + mid * SPARSE_ENT_SIZE))
                != SPARSE_ENT_SIZE) { close(fd); return -1; }
            if (mac_cmp_key(ent, key) == 2) {
                if (mid == 0) break;
                hi = mid - 1;
            } else {
                memcpy(&pos, ent + 36, 8);
                lo = mid + 1;
            }
        }
        if (lseek(fd, (off_t)pos, SEEK_SET) < 0) { close(fd); return -1; }
    }
    u8 rec[37];
    for (;;) {
        if (read_exact(fd, rec, 37)) { close(fd); return 0; }  /* EOF = absent */
        int c = mac_cmp_key(rec, key);
        if (c == 1) {
            if (rec[36] == 2) { close(fd); return 2; }         /* tombstone */
            u8 vp[15];
            u64 vlen = rec_v2 ? 15 : 10;
            if (read_exact(fd, vp, vlen)) { close(fd); return -1; }
            u32 slen = (u32)(vp[8] | (vp[9] << 8));
            static __thread u8 script[SCRIPT_MAX_BYTES];
            if (slen && read_exact(fd, script, slen)) { close(fd); return -1; }
            memcpy(value, vp, 8);
            if (rec_v2) {
                memcpy(height, vp + 10, 4);
                *is_coinbase = vp[14];
            } else {
                *height = 0;
                *is_coinbase = 0;
            }
            *script_out = script;
            *slen_out = slen;
            close(fd);
            return 1;
        }
        if (c == 2) { close(fd); return 0; }     /* sorted: past it */
        if (rec[36] != 1) continue;              /* tombstone: header only */
        u8 vp[15];
        u64 vlen = rec_v2 ? 15 : 10;
        if (read_exact(fd, vp, vlen)) { close(fd); return -1; }
        u32 slen = (u32)(vp[8] | (vp[9] << 8));
        if (slen && lseek(fd, (off_t)slen, SEEK_CUR) < 0) { close(fd); return -1; }
    }
}

/* ---- get: memtable, then this generation's tombstones, then runs --------- */
long utxo_lsm_get(void *lst, void *u, const u8 txid[32], u32 index,
                  u64 *value, unsigned long *height,
                  unsigned long *is_coinbase, const u8 **script,
                  unsigned long *slen)
{
    u8 *L = (u8 *)lst;
    u64 v;
    unsigned long h, cb;
    const void *sc;
    unsigned long sl;
    long r = utxo_get(u, txid, index, &v, &h, &cb, &sc, &sl);
    if (r == 1) {
        *value = v;
        *height = h;
        *is_coinbase = cb;
        *script = sc;
        *slen = sl;
        return 1;
    }
    /* this generation's unflushed tombstones shadow older runs */
    u8 key[36];
    memcpy(key, txid, 32);
    memcpy(key + 32, &index, 4);
    if (*mac_tomb_hash_probe(lst, key) != (u64)-1) return 0;

    for (u64 i = *(u64 *)(L + 120); i-- > 0; ) {     /* newest manifest index first */
        u64 *ment = (u64 *)*(u64 *)(L + 104) + i * 2;
        u64 gen = ment[0];
        u32 run_no = (u32)ment[1];
        u32 rh, rcb, rsl;
        const u8 *rsc;
        u64 rv;
        long rr = mac_run_lookup(lst, run_no, gen, txid, index, &rv, &rh,
                                 &rcb, &rsc, &rsl);
        if (rr == 1) {
            *value = rv;
            *height = rh;
            *is_coinbase = rcb;
            *script = rsc;                           /* into get-scratch: valid
                                                        until the next get() */
            *slen = rsl;
            return 1;
        }
        if (rr == 2) return 0;                       /* tombstoned in this run */
        if (rr == -1) return -1;
    }
    return 0;
}

/* ---- recount: k-way merge over all runs (newest index wins ties) -------- */
typedef struct {
    int fd;
    u64 gen, run_no, remaining;
    int active;
    u8 key[37];          /* key36 + type1 at [36]: the x86 slot layout */
    u8 type;
    u64 value;
    u16 slen;
    u32 height;
    u8 is_coinbase;
    int rec_v2;
    u8 script[SCRIPT_MAX_BYTES];
    /* read-ahead */
    u64 rd_fill, rd_pos;
    u8 rd_buf[COMPACT_RDBUF];
} lsm_slot_t;

static long mac_slot_read(lsm_slot_t *slot, void *dst, u64 len)
{
    u8 *p = dst;
    while (len) {
        u64 avail = slot->rd_fill - slot->rd_pos;
        if (!avail) {
            ssize_t r = read(slot->fd, slot->rd_buf, COMPACT_RDBUF);
            if (r <= 0) return -1;
            slot->rd_fill = (u64)r;
            slot->rd_pos = 0;
            continue;
        }
        u64 take = avail < len ? avail : len;
        memcpy(p, slot->rd_buf + slot->rd_pos, take);
        slot->rd_pos += take;
        p += take;
        len -= take;
    }
    return 0;
}

static long mac_compact_read_rec(lsm_slot_t *slot)
{
    if (mac_slot_read(slot, slot->key, 37)) return -1;
    slot->type = slot->key[36];
    if (slot->type == 1) {
        u64 vlen = slot->rec_v2 ? 15 : 10;
        u8 vp[15];
        if (mac_slot_read(slot, vp, vlen)) return -1;
        memcpy(&slot->value, vp, 8);
        memcpy(&slot->slen, vp + 8, 2);
        if (slot->rec_v2) {
            memcpy(&slot->height, vp + 10, 4);
            slot->is_coinbase = vp[14];
        } else {
            slot->height = 0;
            slot->is_coinbase = 0;
        }
        if (slot->slen && mac_slot_read(slot, slot->script, slot->slen))
            return -1;
    }
    slot->active = 1;
    slot->remaining--;
    return 1;
}

/* merge: visits the live run-resident set once each; cb NULL = count only */
static long mac_lsm_recount(void *lst, void *u,
                            void (*visit)(void *, const u8 *, u64, u64,
                                          const u8 *, u64),
                            void *ctx)
{
    u8 *L = (u8 *)lst;
    u64 live = *(u64 *)u;                            /* memtable first */
    u64 nruns = *(u64 *)(L + 120);
    if (!nruns) return (long)live;
    lsm_slot_t *slots = mmap(NULL, nruns * sizeof(lsm_slot_t),
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (slots == MAP_FAILED) return -1;
    for (u64 i = 0; i < nruns; i++) {
        lsm_slot_t *sl = &slots[i];
        memset(sl, 0, sizeof *sl);
        sl->fd = -1;
        u64 *ment = (u64 *)*(u64 *)(L + 104) + i * 2;
        sl->gen = ment[0];
        sl->run_no = ment[1];
        char runname[24];
        fmt_runname(runname, (u32)sl->run_no);
        sl->fd = open(runname, O_RDONLY);
        if (sl->fd < 0) goto cleanup;
        u64 hdr[8];
        if (mac_read_run_header(sl->fd, hdr)) goto cleanup;
        sl->remaining = hdr[1];
        sl->rec_v2 = (int)hdr[7];
        if (lseek(sl->fd, (off_t)hdr[2], SEEK_CUR) < 0) goto cleanup;
        if (sl->remaining && mac_compact_read_rec(sl) == -1) goto cleanup;
    }
    for (;;) {                                       /* streaming k-way merge */
        long best = -1;
        for (u64 i = 0; i < nruns; i++) {
            if (!slots[i].active) continue;
            if (best < 0) { best = (long)i; continue; }
            /* ascending scan: `this` always wins a tie (UTX-1: manifest
             * index, matching utxo_lsm_get's newest-index-first lookup) */
            if (mac_cmp_key(slots[i].key, slots[best].key) != 2)
                best = (long)i;
        }
        if (best < 0) break;
        lsm_slot_t *w = &slots[best];
        u8 key[36];
        memcpy(key, w->key, 36);
        if (w->type == 1) {
            /* PUSH: live unless newer memtable holds it or tombstoned here */
            u64 v;
            unsigned long h, cb;
            const void *sc;
            unsigned long sl;
            if (utxo_get(u, key, *(u32 *)(key + 32), &v, &h, &cb, &sc, &sl) != 1 &&
                *mac_tomb_hash_probe(lst, key) == (u64)-1) {
                live++;
                if (visit)
                    visit(ctx, key, w->value,
                          ((u64)w->height << 1) | w->is_coinbase, w->script,
                          w->slen);
            }
        }
        /* advance every active slot holding the winning key */
        for (u64 i = 0; i < nruns; i++) {
            if (!slots[i].active) continue;
            if (mac_cmp_key(slots[i].key, key) != 1) continue;
            if (!slots[i].remaining) { slots[i].active = 0; continue; }
            if (mac_compact_read_rec(&slots[i]) == -1) goto cleanup;
        }
    }
    for (u64 i = 0; i < nruns; i++)
        if (slots[i].fd >= 0) close(slots[i].fd);
    munmap(slots, nruns * sizeof(lsm_slot_t));
    return (long)live;
cleanup:
    for (u64 i = 0; i < nruns; i++)
        if (slots[i].fd >= 0) close(slots[i].fd);
    munmap(slots, nruns * sizeof(lsm_slot_t));
    return -1;
}

/* ---- walk: recount with the visitor + the memtable's own entries --------- */
/* The memtable walker's callback returns int (nonzero aborts the walk); the
 * LSM visitor is void. A direct cast would feed garbage into the abort check
 * and cut the walk short -- bridge through a trampoline returning 0. */
static struct { void (*cb)(void *, const u8 *, u64, u64, const u8 *, u64);
                void *ctx; } g_walk_bridge;

static long walk_bridge_cb(void *ctx, const u8 *key, unsigned long index,
                           u64 value, unsigned height, unsigned is_coinbase,
                           const void *script, unsigned long slen)
{
    (void)index;
    g_walk_bridge.cb(ctx, key, value, ((u64)height << 1) | is_coinbase,
                     script, slen);
    return 0;
}

long utxo_lsm_walk(void *lst, void *u,
                   void (*cb)(void *, const u8 *, u64, u64, const u8 *, u64),
                   void *ctx)
{
    long total = mac_lsm_recount(lst, u, cb, ctx);
    if (total == -1) return -1;
    g_walk_bridge.cb = cb;
    g_walk_bridge.ctx = ctx;
    long mem = utxo_walk_live(u, walk_bridge_cb, ctx);
    if (mem != (long)*(u64 *)u) return -1;           /* self-check */
    return total;
}

/* ---- reload: manifest -> WAL rebuild -> tombstone rescan -> live count -- */
static long mac_lsm_reload_impl(void *lst, void *u, int read_only)
{
    u8 *L = (u8 *)lst;
    lsm_mm_invalidate_all();
    if (read_only) {
        if (utxo_store_init_ro(lst) != 1) return -1;
    } else {
        if (utxo_store_init(lst) != 1) return -1;
    }
    u64 has_count = 0, persisted_base = 0;
    int mfd = open(manifest_name, O_RDONLY);
    if (mfd >= 0) {
        u8 mh[12];
        if (read_exact(mfd, mh, 12)) { close(mfd); return -1; }   /* UTX-6 */
        u32 magic;
        memcpy(&magic, mh, 4);
        if (magic == MAGIC_MANIFEST2) {
            if (read_exact(mfd, &persisted_base, 8)) { close(mfd); return -1; }
            has_count = 1;
        } else if (magic != MAGIC_MANIFEST) { close(mfd); return -1; }
        u64 mn;
        memcpy(&mn, mh + 4, 8);
        if (mn > *(u64 *)(L + 112)) { close(mfd); return -1; }
        *(u64 *)(L + 120) = mn;
        if (mn && read_exact(mfd, (void *)*(u64 *)(L + 104), mn * 16)) {
            close(mfd);
            return -1;
        }
        close(mfd);
        /* next_gen/next_run_no = 1 + max over the entries */
        u64 max_gen = 0, max_run = 0;
        for (u64 i = 0; i < mn; i++) {
            u64 *ment = (u64 *)*(u64 *)(L + 104) + i * 2;
            if (ment[0] > max_gen) max_gen = ment[0];
            if (ment[1] > max_run) max_run = ment[1];
        }
        if (mn) { max_gen++; max_run++; }
        *(u64 *)(L + 96) = max_gen;
        *(u64 *)(L + 144) = max_run;
    } else if (errno == ENOENT) {
        *(u64 *)(L + 120) = 0;
        *(u64 *)(L + 96) = 0;
        *(u64 *)(L + 144) = 0;
    } else {
        return -1;                                   /* UTX-6: not ENOENT = fail */
    }

    long replayed = utxo_store_reload(lst, u);
    if (replayed == -1) return -1;

    /* rebuild tombstones + op_count from the WAL's DEL records */
    *(u64 *)(L + 80) = 0;
    *(u64 *)(L + 40) = 0;
    if (mac_tomb_hash_reset(lst) != 1) return -1;
    int wfd = open(wal_name, O_RDONLY);
    if (wfd < 0) return -1;
    u64 pushes = 0, dels = 0;
    u8 rec[51];
    for (;;) {
        u64 off = (u64)lseek(wfd, 0, SEEK_CUR);
        if ((u64)off >= *(u64 *)(L + 16)) break;
        if (read_exact(wfd, rec, 8)) break;
        (*(u64 *)(L + 40))++;
        u8 op = rec[4];
        if (op == 1) {
            pushes++;
            if (read_exact(wfd, rec, 51)) break;
            u16 s16;
            memcpy(&s16, rec + 49, 2);
            if (s16 && lseek(wfd, s16, SEEK_CUR) < 0) break;
        } else if (op == 2) {
            dels++;
            if (read_exact(wfd, rec, 36)) break;
            if (*(u64 *)(L + 80) < *(u64 *)(L + 72)) {
                u8 *key = (u8 *)*(u64 *)(L + 64) + *(u64 *)(L + 80) * 36;
                memcpy(key, rec, 36);
                *mac_tomb_hash_probe(lst, key) = *(u64 *)(L + 80);
                (*(u64 *)(L + 80))++;
            }
        } else {
            break;
        }
    }
    close(wfd);

    /* accurate total_live: v2 manifest with an EMPTY WAL tail uses the
     * persisted runs-only base; ANY tail (or an old/absent manifest) takes
     * the exact recount (incident #45: base+tail double-counts a folded
     * tail). The recount already reflects the WAL tail. */
    if (has_count && !pushes && !dels) {
        *(u64 *)(L + 88) = persisted_base;
    } else {
        long cnt = mac_lsm_recount(lst, u, NULL, NULL);
        if (cnt == -1) return -1;
        *(u64 *)(L + 88) = (u64)cnt;
    }
    return replayed;
}

long utxo_lsm_reload(void *lst, void *u)  { return mac_lsm_reload_impl(lst, u, 0); }
long utxo_lsm_reload_ro(void *lst, void *u) { return mac_lsm_reload_impl(lst, u, 1); }

/* ---- compact: merge the oldest min(manifest_n, 64) runs into one --------- */
long utxo_lsm_compact_range(void *lst, u64 lo, u64 k);
long utxo_lsm_compact(void *lst) { return utxo_lsm_compact_range(lst, 0, 0); }

long utxo_lsm_compact_range(void *lst, u64 lo, u64 k)
{
    u8 *L = (u8 *)lst;
    u64 manifest_n = *(u64 *)(L + 120);
    if (manifest_n < 2) return 0;
    int keep_dels = 0;
    if (k) {
        if (k < 2 || k > COMPACT_MAX_RUNS) return 0;
        if (lo + k > manifest_n) return 0;
        if (lo != 0 && lo + k != manifest_n) return 0;
        if (lo != 0) keep_dels = 1;
    } else {
        k = manifest_n < COMPACT_MAX_RUNS ? manifest_n : COMPACT_MAX_RUNS;
    }
    u64 batch = k;

    lsm_slot_t *slots = mmap(NULL, batch * sizeof(lsm_slot_t),
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (slots == MAP_FAILED) return -1;
    u64 upper_bound = 0;
    for (u64 i = 0; i < batch; i++) {
        lsm_slot_t *sl = &slots[i];
        memset(sl, 0, sizeof *sl);
        sl->fd = -1;
        u64 *ment = (u64 *)*(u64 *)(L + 104) + (lo + i) * 2;
        sl->gen = ment[0];
        sl->run_no = ment[1];
        char runname[24];
        fmt_runname(runname, (u32)sl->run_no);
        sl->fd = open(runname, O_RDONLY);
        if (sl->fd < 0) goto cleanup;
        u64 hdr[8];
        if (mac_read_run_header(sl->fd, hdr)) goto cleanup;
        sl->remaining = hdr[1];
        sl->rec_v2 = (int)hdr[7];
        upper_bound += hdr[1];
        if (lseek(sl->fd, (off_t)hdr[2], SEEK_CUR) < 0) goto cleanup;
        if (sl->remaining && mac_compact_read_rec(sl) == -1) goto cleanup;
    }

    /* bloom sizing from the upper bound */
    u64 bloom_bits = upper_bound * 10;
    if (bloom_bits < 64) bloom_bits = 64;
    u64 bb = 1;
    while (bb < bloom_bits) bb <<= 1;
    if (bb > (u64)BLOOM_MAX_BYTES * 8) bb = (u64)BLOOM_MAX_BYTES * 8;
    u64 bloom_bytes = bb >> 3;
    u64 bits_mask = bb - 1;
    u8 *bloom = mmap(NULL, bloom_bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (bloom == MAP_FAILED) goto cleanup;
    memset(bloom, 0, bloom_bytes);

    /* sparse build buffer, own mmap */
    u64 sparse_scratch_bytes = (upper_bound / SPARSE_STRIDE + 2) * SPARSE_ENT_SIZE;
    u8 *sparse = mmap(NULL, sparse_scratch_bytes, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sparse == MAP_FAILED) { munmap(bloom, bloom_bytes); goto cleanup; }
    u64 sparse_n = 0;

    u64 out_gen = *(u64 *)(L + 96);
    u64 out_run_no = *(u64 *)(L + 144);
    char runname[24];
    fmt_runname(runname, (u32)out_run_no);
    int ofd = open(runname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ofd < 0) { munmap(sparse, sparse_scratch_bytes); munmap(bloom, bloom_bytes); goto cleanup; }

    u8 ohdr[44];
    u32 m3 = MAGIC_RUN3;
    memcpy(ohdr + 0, &m3, 4);
    memcpy(ohdr + 4, &out_gen, 8);
    u64 nrec_placeholder = 0;
    memcpy(ohdr + 12, &nrec_placeholder, 8);
    memcpy(ohdr + 20, &bb, 8);
    u64 sparse_off_placeholder = 0, sparse_n_placeholder = 0;
    memcpy(ohdr + 28, &sparse_off_placeholder, 8);
    memcpy(ohdr + 36, &sparse_n_placeholder, 8);
    if (write_exact(ofd, ohdr, 44)) goto fail_compact;
    if (write_exact(ofd, bloom, bloom_bytes)) goto fail_compact;
    mac_ow_fd = (u64)ofd;
    mac_ow_fill = 0;
    u64 true_nrec = 0;

    for (;;) {                                       /* streaming k-way merge */
        long best = -1;
        for (u64 i = 0; i < batch; i++) {
            if (!slots[i].active) continue;
            if (best < 0) { best = (long)i; continue; }
            if (mac_cmp_key(slots[i].key, slots[best].key) != 2)
                best = (long)i;                      /* ascending: this wins ties */
        }
        if (best < 0) break;
        lsm_slot_t *w = &slots[best];
        u8 key[36];
        memcpy(key, w->key, 36);
        int emit = (w->type == 1) || (keep_dels && w->type == 2);
        if (emit) {
            if ((true_nrec & (SPARSE_STRIDE - 1)) == 0) {
                /* buffered writer: lseek lags the buffer; use fd + fill */
                off_t cur = lseek(ofd, 0, SEEK_CUR);
                if (cur < 0) goto fail_compact;
                u64 foff = (u64)cur + mac_ow_fill;
                memcpy(sparse + sparse_n * SPARSE_ENT_SIZE, key, 36);
                memcpy(sparse + sparse_n * SPARSE_ENT_SIZE + 36, &foff, 8);
                sparse_n++;
            }
            u8 kt[37];
            memcpy(kt, key, 36);
            kt[36] = w->type;
            if (write_exact(ofd, kt, 37)) goto fail_compact;
            if (w->type == 1) {
                u8 vp[15];
                memcpy(vp, &w->value, 8);
                memcpy(vp + 8, &w->slen, 2);
                memcpy(vp + 10, &w->height, 4);
                vp[14] = w->is_coinbase;
                if (write_exact(ofd, vp, 15)) goto fail_compact;
                if (w->slen && write_exact(ofd, w->script, w->slen))
                    goto fail_compact;
                mac_bloom_setbit(key, 0x811c9dc5u, bloom, (u32)bits_mask);
                mac_bloom_setbit(key, 0xa1b2c3d4u, bloom, (u32)bits_mask);
                mac_bloom_setbit(key, 0x5bd1e995u, bloom, (u32)bits_mask);
            }
            true_nrec++;
        }
        for (u64 i = 0; i < batch; i++) {
            if (!slots[i].active) continue;
            if (mac_cmp_key(slots[i].key, key) != 1) continue;
            if (!slots[i].remaining) { slots[i].active = 0; continue; }
            if (mac_compact_read_rec(&slots[i]) == -1) goto fail_compact;
        }
    }

    /* patch bloom + nrec, append sparse, patch sparse_off/n */
    if (lseek(ofd, 44, SEEK_SET) < 0) goto fail_compact;
    if (write_exact(ofd, bloom, bloom_bytes)) goto fail_compact;
    if (lseek(ofd, 12, SEEK_SET) < 0) goto fail_compact;
    if (write_exact(ofd, &true_nrec, 8)) goto fail_compact;
    off_t sp_off = lseek(ofd, 0, SEEK_END);
    if (sp_off < 0) goto fail_compact;
    if (sparse_n && write_exact(ofd, sparse, sparse_n * SPARSE_ENT_SIZE))
        goto fail_compact;
    if (lseek(ofd, 28, SEEK_SET) < 0) goto fail_compact;
    memcpy(ohdr + 28, &sp_off, 8);
    memcpy(ohdr + 36, &sparse_n, 8);
    if (write_exact(ofd, ohdr + 28, 16)) goto fail_compact;
    fsync(ofd);
    close(ofd);

    /* manifest: merged entry at index lo, survivors shifted down after it */
    u8 *marr = (u8 *)*(u64 *)(L + 104);
    u64 *merged = (u64 *)(marr + lo * 16);
    merged[0] = out_gen;
    merged[1] = out_run_no;
    u64 src = lo + batch, dst = lo + 1;
    while (src < manifest_n) {
        u64 *s = (u64 *)(marr + src * 16);
        u64 *d = (u64 *)(marr + dst * 16);
        d[0] = s[0];
        d[1] = s[1];
        src++;
        dst++;
    }
    *(u64 *)(L + 120) = dst;
    (*(u64 *)(L + 96))++;
    (*(u64 *)(L + 144))++;

    /* live-count field: full merge -> true_nrec is authoritative; partial ->
     * carry the previously persisted base (or write v1 when none) */
    u64 has_count = 0, persisted_base = 0;
    int pfd = open(manifest_name, O_RDONLY);
    if (pfd >= 0) {
        u8 mh[12];
        if (!read_exact(pfd, mh, 12)) {
            u32 magic;
            memcpy(&magic, mh, 4);
            if (magic == MAGIC_MANIFEST2 &&
                !read_exact(pfd, &persisted_base, 8))
                has_count = 1;
        }
        close(pfd);
    }
    u64 persist_count = 0;
    int write_v2;
    if (batch == manifest_n) {
        persist_count = true_nrec;
        write_v2 = 1;
        if (has_count)
            *(u64 *)(L + 88) = *(u64 *)(L + 88) - persisted_base + true_nrec;
    } else if (has_count) {
        persist_count = persisted_base;
        write_v2 = 1;
    } else {
        write_v2 = 0;
    }

    const char *pub = mac_compact_defer_publish ? manifest_child_name
                                                : manifest_tmp_name;
    int mfd = open(pub, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (mfd < 0) goto cleanup;
    u8 mh[20];
    u32 magic = write_v2 ? MAGIC_MANIFEST2 : MAGIC_MANIFEST;
    memcpy(mh + 0, &magic, 4);
    memcpy(mh + 4, L + 120, 8);
    u64 mhdr_len = write_v2 ? 20 : 12;
    if (write_v2) memcpy(mh + 12, &persist_count, 8);
    if (write_exact(mfd, mh, mhdr_len) ||
        write_exact(mfd, marr, *(u64 *)(L + 120) * 16)) {
        close(mfd);
        goto cleanup;
    }
    fsync(mfd);
    close(mfd);
    if (!mac_compact_defer_publish && rename(manifest_tmp_name, manifest_name) < 0)
        goto cleanup;
    if (!mac_compact_defer_publish) {
        int dfd = open(".", O_RDONLY);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
    }

    for (u64 i = 0; i < batch; i++) {
        if (slots[i].fd >= 0) close(slots[i].fd);
        if (!mac_compact_defer_unlink) {
            char nm[24];
            fmt_runname(nm, (u32)slots[i].run_no);
            unlink(nm);
        }
    }
    munmap(slots, batch * sizeof(lsm_slot_t));
    munmap(bloom, bloom_bytes);
    munmap(sparse, sparse_scratch_bytes);
    return 1;

fail_compact:
    close(ofd);
cleanup:
    for (u64 i = 0; i < batch; i++)
        if (slots[i].fd >= 0) close(slots[i].fd);
    munmap(slots, batch * sizeof(lsm_slot_t));
    return -1;
}
