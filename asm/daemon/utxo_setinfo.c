/* daemon/utxo_setinfo.c -- `gettxoutsetinfo` over our LSM UTXO set.
 *
 * Computes, over a datadir it NEVER writes to:
 *   txouts        -- live outputs after Core's unspendable filter
 *   total_amount  -- their satoshi sum
 *   bogosize      -- Core's GetBogoSize sum over them
 *   muhash        -- MuHash3072 of the same filtered set (optional; the
 *                    expensive one)
 * plus the numbers Core has no counterpart for, reported rather than hidden:
 * the raw live count, and how many entries the filter removed and their value.
 *
 * Compare against Bitcoin Core with validation/diff_utxo_setinfo.py, which
 * asks a real node `gettxoutsetinfo muhash <height>` and diffs field by
 * field. Nothing here is baked.
 *
 * ---------------------------------------------------------------------------
 * READING A LIVE LSM, AND WHY THIS TOOL REFUSES
 * ---------------------------------------------------------------------------
 * The datadir this is pointed at is normally the live replay's, and the live
 * replay writes to it continuously: every applied block appends WAL records
 * to utxo.dat and rewrites utxo_applied_height.dat, and a flush or compaction
 * publishes a new manifest and UNLINKS run files. A naive reader that walked
 * the manifest and then opened the runs it names can therefore see a torn
 * state -- half of a compaction, a manifest that no longer describes the runs
 * on disk, or a WAL whose tail grew underneath it -- and produce a number
 * that is wrong and looks entirely plausible.
 *
 * There is no way to take a consistent snapshot of a datadir from outside the
 * process that owns it, and this tool is not allowed to stop that process. So
 * it does not try to be clever. It:
 *
 *   1. Fingerprints the whole UTXO state (every relevant file's inode, size
 *      and nanosecond mtime, plus the directory's own mtime and link count,
 *      which is what catches a run file appearing or being unlinked).
 *   2. Waits --settle-ms and fingerprints again. Any difference means a
 *      writer is active: it REFUSES, and says so.
 *   3. Does the whole read.
 *   4. Fingerprints a third time and requires it to still match. Anything
 *      that changed mid-read invalidates the result, and the result is
 *      discarded rather than printed.
 *
 * That is fail-closed in both directions: a busy datadir is never read, and a
 * datadir that becomes busy mid-read never yields an answer. --force exists
 * for a deliberately-inconsistent read, and marks its own output
 * `"quiesced": false` so the JSON can never be mistaken for a real one.
 *
 * Everything below the fingerprint is read-only by construction:
 * utxo_lsm_reload_ro opens utxo.dat O_RDONLY and never creates utxo.idx (the
 * ordinary reload path's O_RDWR|O_CREAT is the only write in the whole chain),
 * run files are opened O_RDONLY by the merge, and the memtable is rebuilt in
 * this process's own anonymous memory -- the datadir's utxo_lsm_table.map and
 * utxo_lsm_blob.map are never even opened, only stat'd for their sizes.
 *
 * ---------------------------------------------------------------------------
 * SELF-CHECKS (a tool that cannot be wrong beats a tool that is usually right)
 * ---------------------------------------------------------------------------
 *   - The walk's own raw live count is compared against utxo_lsm_count(),
 *     which reload derives INDEPENDENTLY (persisted runs-only base from the
 *     manifest, plus the WAL tail's PUSH/DEL net). Two derivations, one
 *     answer; a disagreement is reported with its delta and clears
 *     "consistent".
 *   - The memtable walk's count is required to equal u->n inside
 *     utxo_lsm_walk itself.
 *   - Entries reporting height 0 are counted. Height is part of what Core
 *     hashes, and a run file written before MAGIC_RUN3 (2026-08-19) carries
 *     no height at all and reports zero -- which would produce a silently
 *     wrong set hash. A nonzero count here clears "consistent" too.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int u32;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);
extern long utxo_lsm_reload_ro(void* lst, void* u);
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);
extern void utxo_stats_init(void* st, unsigned long want_muhash,
                            unsigned long exclude_genesis_coinbase);
extern void utxo_stats_add(void* st, const u8 key36[36], u64 value, u64 code,
                           const u8* script, u64 slen);
extern void utxo_stats_finalize(void* st);

/* Mirrors bitcoin_utxo_stats.asm's state struct, offset for offset. */
typedef struct {
    u64 txouts;
    u64 total_amount;
    u64 bogosize;
    u64 unspendable_txouts;
    u64 unspendable_amount;
    u64 raw_txouts;
    u64 zero_height;
    u64 want_muhash;
    u8  muhash[32];
    u8  acc[384];
    u64 excl_genesis;
    u64 genesis_excluded;
} utxo_stats_t;

/* Mirrors bitcoin_utxo_lsm.asm's `lst` (168 bytes; see its header comment). */
typedef struct {
    u64 log_fd, idx_fd, log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    u64 tomb_buf, tomb_cap, tomb_n;
    u64 total_live, next_gen;
    u64 manifest_buf, manifest_cap, manifest_n;
    u64 scratch_buf, scratch_cap, next_run_no;
    u64 tomb_hash_buf, tomb_hash_mask;
} lsm_state_t;

#define UTXO_APPLIED_HEIGHT_MAGIC 0x48504155u /* "UAPH" */

/* ---------------- coin height overrides (a DIAGNOSTIC, not a fix) --------
 *
 * --override-coin <displaytxid>:<n>=<height> re-hashes one named outpoint as
 * if it carried a different height. It exists to turn "our set hash differs
 * from Core's" into a falsifiable statement about WHICH entries differ and
 * HOW, which is the only useful form of that finding.
 *
 * The case it was written for: Core's BIP30 exception path calls
 * AddCoin(..., possible_overwrite=true), so a duplicate coinbase OVERWRITES
 * the earlier coin and Core's chainstate ends up holding the LATER height.
 * utxo_lsm_put returns "duplicate" and keeps the EARLIER one. Same txid, same
 * index, same value, same script -- so txouts, total_amount and bogosize are
 * all blind to it, and only the set hash can see it. Naming the two outpoints
 * and their Core heights, and getting Core's hash out exactly, PROVES that is
 * the whole difference. Getting something else out disproves it.
 *
 * This is deliberately not a way to make numbers agree: every override is
 * reported in the output, and an override that never matched a live entry is
 * reported too, so a hypothesis that quietly did nothing cannot pass as one
 * that was confirmed. */
#define MAX_OVERRIDES 8
typedef struct { u8 key[36]; u64 height; u64 hits; } coin_override;
static coin_override g_ov[MAX_OVERRIDES];
static int g_ov_n;
static utxo_stats_t* g_st;

/* Parse "<64 hex display txid>:<n>=<height>". The display form is the
 * reverse of the wire order our keys use, so it is reversed here -- the same
 * convention `getblock` prints and a human would paste in. */
static int add_override(const char* spec)
{
    char txid[65];
    unsigned long n, h;
    if (g_ov_n >= MAX_OVERRIDES) return 0;
    if (sscanf(spec, "%64[0-9a-fA-F]:%lu=%lu", txid, &n, &h) != 3) return 0;
    if (strlen(txid) != 64) return 0;
    coin_override* o = &g_ov[g_ov_n];
    memset(o, 0, sizeof *o);
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(txid + 2 * (31 - i), "%2x", &v) != 1) return 0;
        o->key[i] = (u8)v;
    }
    u32 idx = (u32)n;
    memcpy(o->key + 32, &idx, 4);
    o->height = h;
    g_ov_n++;
    return 1;
}

/* The visitor the walk actually calls when overrides are in play. Without
 * any, utxo_stats_add is handed to the walk directly and this never runs. */
static void override_cb(void* ctx, const u8 key36[36], u64 value, u64 code,
                        const u8* script, u64 slen)
{
    (void)ctx;
    for (int i = 0; i < g_ov_n; i++) {
        if (memcmp(key36, g_ov[i].key, 36) == 0) {
            g_ov[i].hits++;
            code = (g_ov[i].height << 1) | (code & 1);   /* keep the coinbase bit */
            break;
        }
    }
    utxo_stats_add(g_st, key36, value, code, script, slen);
}

/* ---------------- quiescence fingerprint ---------------- */

#define FP_MAX 4096
typedef struct { char name[64]; u64 ino, size, sec, nsec; } fp_ent;
typedef struct { int n; fp_ent e[FP_MAX]; } fingerprint;

static int fp_add(fingerprint* f, const char* name)
{
    struct stat sb;
    if (f->n >= FP_MAX) return 0;
    fp_ent* e = &f->e[f->n];
    memset(e, 0, sizeof *e);
    snprintf(e->name, sizeof e->name, "%s", name);
    if (stat(name, &sb) == 0) {
        e->ino = sb.st_ino;
        e->size = (u64)sb.st_size;
        e->sec = (u64)sb.st_mtim.tv_sec;
        e->nsec = (u64)sb.st_mtim.tv_nsec;
    } /* absent files fingerprint as all-zero, so appearing/vanishing shows */
    f->n++;
    return 1;
}

/* The directory entry itself catches run files being created or unlinked,
 * which no per-file stat of a name we already know about ever would. */
static int fingerprint_take(fingerprint* f)
{
    static const char* fixed[] = {
        ".", "utxo.dat", "utxo.idx", "utxo_manifest.dat",
        "utxo_applied_height.dat", "utxo_applied_height.dat.tmp",
        "utxo_manifest.dat.tmp",
    };
    f->n = 0;
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) fp_add(f, fixed[i]);

    DIR* d = opendir(".");
    if (!d) return 0;
    /* readdir order is not guaranteed stable, so collect then sort. */
    char names[FP_MAX][64];
    int nn = 0;
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "utxo_run_", 9) != 0) continue;
        if (nn >= FP_MAX) { closedir(d); return 0; }
        snprintf(names[nn++], 64, "%s", de->d_name);
    }
    closedir(d);
    for (int i = 1; i < nn; i++) {
        char t[64];
        snprintf(t, sizeof t, "%s", names[i]);
        int j = i - 1;
        while (j >= 0 && strcmp(names[j], t) > 0) { snprintf(names[j + 1], 64, "%s", names[j]); j--; }
        snprintf(names[j + 1], 64, "%s", t);
    }
    for (int i = 0; i < nn; i++) fp_add(f, names[i]);
    return 1;
}

static int fingerprint_diff(const fingerprint* a, const fingerprint* b, char* why, size_t whyn)
{
    if (a->n != b->n) {
        snprintf(why, whyn, "file count changed (%d -> %d)", a->n, b->n);
        return 1;
    }
    for (int i = 0; i < a->n; i++) {
        const fp_ent* x = &a->e[i];
        const fp_ent* y = &b->e[i];
        if (strcmp(x->name, y->name) != 0) {
            snprintf(why, whyn, "file list changed (%s -> %s)", x->name, y->name);
            return 1;
        }
        if (x->ino != y->ino || x->size != y->size || x->sec != y->sec || x->nsec != y->nsec) {
            snprintf(why, whyn, "%s changed (size %lu -> %lu, mtime %lu.%09lu -> %lu.%09lu)",
                     x->name, x->size, y->size, x->sec, x->nsec, y->sec, y->nsec);
            return 1;
        }
    }
    return 0;
}

static void sleep_ms(long ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* ---------------- helpers ---------------- */

static long read_applied_height(void)
{
    int fd = open("utxo_applied_height.dat", O_RDONLY);
    if (fd < 0) return -1;
    u8 buf[12];
    long n = read(fd, buf, sizeof buf);
    close(fd);
    if (n != (long)sizeof buf) return -1;
    u32 magic;
    memcpy(&magic, buf, 4);
    if (magic != UTXO_APPLIED_HEIGHT_MAGIC) return -1;
    long h;
    memcpy(&h, buf + 4, 8);
    return h;
}

static void* xmap(u64 size, const char* what)
{
    void* p = mmap(0, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "utxo_setinfo: mmap(%s, %lu) failed: %s\n", what, size, strerror(errno));
        exit(1);
    }
    return p;
}

static u64 file_size_or(const char* path, u64 dflt)
{
    struct stat sb;
    if (stat(path, &sb) != 0) return dflt;
    return (u64)sb.st_size;
}

/* REVERSED hex, because that is what Core prints.
 *
 * MuHash3072::Finalize() puts the raw SHA256 of the 384-byte accumulator into
 * a uint256, and `gettxoutsetinfo` renders it with uint256::GetHex(), which
 * emits the bytes back-to-front (the usual Bitcoin big-endian display
 * convention). Printing our raw byte order instead produced a value that was
 * the exact byte-reverse of Core's -- which reads as a total mismatch and
 * would have sent someone hunting a hashing bug that does not exist. The
 * digest itself is identical; only the rendering differs, and this is where
 * that is reconciled. */
static void hex32(const u8* p, char* out)
{
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        u8 b = p[31 - i];
        out[2 * i] = H[b >> 4];
        out[2 * i + 1] = H[b & 15];
    }
    out[64] = 0;
}

static void usage(const char* a0)
{
    fprintf(stderr,
        "usage: %s <datadir> [--muhash] [--settle-ms N] [--force]\n"
        "                    [--slots-log2 N] [--blob-mb M] [--text]\n"
        "\n"
        "  --muhash      also compute the MuHash3072 set hash (the expensive part;\n"
        "                without it only txouts/total_amount/bogosize are produced)\n"
        "  --height N    the applied height, for a datadir with no\n"
        "                utxo_applied_height.dat (build_utxo writes none)\n"
        "  --settle-ms   quiescence probe interval, default 1500\n"
        "  --force       read even a datadir that is being written; the output is\n"
        "                marked \"quiesced\": false and MUST NOT be compared\n"
        "  --slots-log2  memtable slots (default: derived from utxo_lsm_table.map)\n"
        "  --blob-mb     memtable blob MB (default: derived from utxo_lsm_blob.map)\n"
        "  --exclude-genesis-coinbase\n"
        "                skip the genesis coinbase, which Core's chainstate never\n"
        "                holds. daemon/utxo_live.c already excludes it at apply time;\n"
        "                daemon/build_utxo.c does not, so a batch-seeded set carries\n"
        "                one extra entry. Reported as \"genesis_excluded\".\n"
        "  --override-coin <64-hex-txid>:<n>=<height>\n"
        "                DIAGNOSTIC: re-hash one named outpoint as if it carried a\n"
        "                different height, to test a specific hypothesis about WHY\n"
        "                two sets differ. Always reported, including when it matched\n"
        "                nothing. Repeatable up to 8 times.\n"
        "  --text        human-readable output instead of JSON\n", a0);
    exit(2);
}

int main(int argc, char** argv)
{
    if (argc < 2) usage(argv[0]);
    const char* dir = argv[1];
    int want_muhash = 0, force = 0, text = 0, excl_genesis = 0;
    long settle_ms = 1500;
    int slots_log2 = 0;
    long blob_mb = 0;
    long height_override = -1;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--muhash")) want_muhash = 1;
        else if (!strcmp(argv[i], "--force")) force = 1;
        else if (!strcmp(argv[i], "--text")) text = 1;
        else if (!strcmp(argv[i], "--exclude-genesis-coinbase")) excl_genesis = 1;
        else if (!strcmp(argv[i], "--override-coin") && i + 1 < argc) {
            if (!add_override(argv[++i])) {
                fprintf(stderr, "utxo_setinfo: bad --override-coin %s "
                                "(want <64-hex-txid>:<n>=<height>)\n", argv[i]);
                return 2;
            }
        }
        else if (!strcmp(argv[i], "--settle-ms") && i + 1 < argc) settle_ms = atol(argv[++i]);
        else if (!strcmp(argv[i], "--height") && i + 1 < argc) height_override = atol(argv[++i]);
        else if (!strcmp(argv[i], "--slots-log2") && i + 1 < argc) slots_log2 = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--blob-mb") && i + 1 < argc) blob_mb = atol(argv[++i]);
        else usage(argv[0]);
    }

    if (chdir(dir) != 0) {
        fprintf(stderr, "utxo_setinfo: chdir(%s): %s\n", dir, strerror(errno));
        return 1;
    }

    /* ---- quiescence gate ---- */
    fingerprint fp0, fp1, fp2;
    char why[512] = "";
    int quiesced = 1;
    if (!fingerprint_take(&fp0)) { fprintf(stderr, "utxo_setinfo: fingerprint failed\n"); return 1; }
    sleep_ms(settle_ms);
    if (!fingerprint_take(&fp1)) { fprintf(stderr, "utxo_setinfo: fingerprint failed\n"); return 1; }
    if (fingerprint_diff(&fp0, &fp1, why, sizeof why)) {
        quiesced = 0;
        fprintf(stderr,
            "utxo_setinfo: REFUSING -- %s is being written (%s).\n"
            "  A UTXO set hash over a datadir that is changing underneath the read is\n"
            "  meaningless: the run files, the manifest that names them and the WAL tail\n"
            "  would come from different moments. Stop the writer, point this at a\n"
            "  quiesced copy, or pass --force and accept that the answer is not\n"
            "  comparable to anything.\n", dir, why);
        if (!force) return 3;
    }

    /* --height is for a datadir that carries no utxo_applied_height.dat --
     * daemon/build_utxo.c never writes one, since that file belongs to the
     * live daemon's catch-up loop. It is an assertion by the operator about a
     * datadir they built, not a guess by this tool, so it is only ever
     * ACCEPTED, never inferred: if the file exists and disagrees, the file
     * wins and the override is rejected, because the file is what the process
     * that wrote the set recorded. */
    long height = read_applied_height();
    if (height >= 0 && height_override >= 0 && height_override != height) {
        fprintf(stderr, "utxo_setinfo: --height %ld contradicts utxo_applied_height.dat "
                        "(%ld) -- refusing\n", height_override, height);
        return 1;
    }
    if (height < 0 && height_override >= 0) height = height_override;
    if (height < 0) {
        fprintf(stderr, "utxo_setinfo: no readable utxo_applied_height.dat -- refusing, "
                        "since a set hash with no height is not comparable to anything\n");
        if (!force) return 1;
    }

    /* ---- size the memtable from the datadir itself where possible ----
     * The daemon's own memtable geometry is recorded by the sizes of the
     * files it mmap'd it into. Deriving from those means this tool cannot be
     * accidentally sized SMALLER than the WAL tail it must replay, which
     * would silently drop entries. The files themselves are never opened. */
    unsigned long slots;
    if (slots_log2 > 0) {
        slots = 1UL << slots_log2;
    } else {
        u64 tsz = file_size_or("utxo_lsm_table.map", 0);
        /* utxo_struct_size(slots) == 40 + slots*48 + 8 */
        slots = tsz > 48 ? (unsigned long)((tsz - 48) / 48) : (1UL << 22);
        if (slots < (1UL << 20)) slots = 1UL << 20;
    }
    u64 blob_cap = blob_mb > 0 ? ((u64)blob_mb << 20)
                               : file_size_or("utxo_lsm_blob.map", 1UL << 30);
    if (blob_cap < (256UL << 20)) blob_cap = 256UL << 20;

    u64 tomb_cap = (u64)slots * 2;
    u64 manifest_cap = 4096;

    long ustruct = utxo_struct_size(slots);
    void* u = xmap((u64)ustruct, "memtable");
    void* blob = xmap(blob_cap, "memtable blob");
    utxo_init(u, slots, blob, blob_cap);

    lsm_state_t lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = (u64)slots * 2;
    lst.fill_threshold = (u64)slots * 3 / 4;
    lst.tomb_buf = (u64)(uintptr_t)xmap(tomb_cap * 36, "tombstone list");
    lst.tomb_cap = tomb_cap;
    lst.manifest_buf = (u64)(uintptr_t)xmap(manifest_cap * 16, "manifest");
    lst.manifest_cap = manifest_cap;
    /* scratch_buf is only ever touched by mac_flush and utxo_lsm_get's disk
     * path, neither of which this tool can reach: it never puts, never dels,
     * never flushes, and the walk reads runs through its own mmap'd slots. A
     * token allocation keeps the field non-NULL without reserving the ~6GB
     * the daemon's flush-sized arena would need. */
    lst.scratch_buf = (u64)(uintptr_t)xmap(1UL << 20, "scratch");
    lst.scratch_cap = 1UL << 20;

    long replayed = utxo_lsm_reload_ro(&lst, u);
    if (replayed < 0) {
        fprintf(stderr, "utxo_setinfo: utxo_lsm_reload_ro failed\n");
        return 1;
    }
    long lsm_count = utxo_lsm_count(&lst);

    utxo_stats_t st;
    memset(&st, 0, sizeof st);
    utxo_stats_init(&st, (unsigned long)want_muhash, (unsigned long)excl_genesis);

    g_st = &st;
    long walked = g_ov_n ? utxo_lsm_walk(&lst, u, (void*)override_cb, &st)
                         : utxo_lsm_walk(&lst, u, (void*)utxo_stats_add, &st);
    if (walked < 0) {
        fprintf(stderr, "utxo_setinfo: utxo_lsm_walk failed (memtable count did not "
                        "match u->n, or a run file could not be read)\n");
        return 1;
    }
    utxo_stats_finalize(&st);

    /* ---- the datadir must not have moved underneath the read ---- */
    if (!fingerprint_take(&fp2)) { fprintf(stderr, "utxo_setinfo: fingerprint failed\n"); return 1; }
    if (fingerprint_diff(&fp0, &fp2, why, sizeof why)) {
        quiesced = 0;
        fprintf(stderr,
            "utxo_setinfo: DISCARDING RESULT -- %s changed during the read (%s).\n"
            "  Everything computed above is a mixture of two different states.\n", dir, why);
        if (!force) return 3;
    }

    int consistent = 1;
    if ((long)st.raw_txouts != walked) {
        fprintf(stderr, "utxo_setinfo: INCONSISTENT -- walk emitted %lu entries but "
                        "reported %ld live\n", st.raw_txouts, walked);
        consistent = 0;
    }
    if (walked != lsm_count) {
        fprintf(stderr, "utxo_setinfo: INCONSISTENT -- walk counted %ld live entries, "
                        "utxo_lsm_count() independently says %ld (delta %ld)\n",
                walked, lsm_count, walked - lsm_count);
        consistent = 0;
    }
    if (st.zero_height > 1) {
        fprintf(stderr, "utxo_setinfo: INCONSISTENT -- %lu live entries report height 0. "
                        "A run file written before MAGIC_RUN3 carries no height, and height "
                        "is part of what Core hashes, so the set hash would be wrong.\n",
                st.zero_height);
        consistent = 0;
    }

    char mh[65];
    hex32(st.muhash, mh);

    for (int i = 0; i < g_ov_n; i++) {
        char t[65];
        hex32(g_ov[i].key, t);   /* the key's first 32 bytes ARE the txid */
        fprintf(stderr, "utxo_setinfo: override %s:%u -> height %lu matched %lu live "
                        "entr%s%s\n", t, *(u32*)(g_ov[i].key + 32),
                (unsigned long)g_ov[i].height, (unsigned long)g_ov[i].hits,
                g_ov[i].hits == 1 ? "y" : "ies",
                g_ov[i].hits ? "" : "  <-- MATCHED NOTHING: this hypothesis did not fire");
    }

    if (text) {
        printf("applied_height     %ld\n", height);
        printf("txouts             %lu\n", st.txouts);
        printf("total_amount(sat)  %lu\n", st.total_amount);
        printf("bogosize           %lu\n", st.bogosize);
        printf("muhash             %s\n", want_muhash ? mh : "(not computed)");
        printf("raw_txouts         %lu\n", st.raw_txouts);
        printf("unspendable_txouts %lu\n", st.unspendable_txouts);
        printf("unspendable_amount %lu\n", st.unspendable_amount);
        printf("genesis_excluded   %lu\n", st.genesis_excluded);
        printf("coin_overrides     %d\n", g_ov_n);
        printf("lsm_count          %ld\n", lsm_count);
        printf("quiesced           %s\n", quiesced ? "true" : "false");
        printf("consistent         %s\n", consistent ? "true" : "false");
    } else {
        printf("{\n");
        printf("  \"height\": %ld,\n", height);
        printf("  \"txouts\": %lu,\n", st.txouts);
        printf("  \"total_amount_sat\": %lu,\n", st.total_amount);
        printf("  \"bogosize\": %lu,\n", st.bogosize);
        printf("  \"muhash\": \"%s\",\n", want_muhash ? mh : "");
        printf("  \"raw_txouts\": %lu,\n", st.raw_txouts);
        printf("  \"unspendable_txouts\": %lu,\n", st.unspendable_txouts);
        printf("  \"unspendable_amount_sat\": %lu,\n", st.unspendable_amount);
        printf("  \"zero_height_entries\": %lu,\n", st.zero_height);
        printf("  \"genesis_excluded\": %lu,\n", st.genesis_excluded);
        printf("  \"coin_overrides\": %d,\n", g_ov_n);
        printf("  \"lsm_count\": %ld,\n", lsm_count);
        printf("  \"wal_records_replayed\": %ld,\n", replayed);
        printf("  \"manifest_runs\": %lu,\n", lst.manifest_n);
        printf("  \"quiesced\": %s,\n", quiesced ? "true" : "false");
        printf("  \"consistent\": %s\n", consistent ? "true" : "false");
        printf("}\n");
    }
    return (quiesced && consistent) ? 0 : 4;
}
