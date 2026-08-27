/* daemon/coinstats_index.c -- the incrementally-maintained coinstats index.
 *
 * WHY: `gettxoutsetinfo` was a full O(set) walk (~6 minutes with MuHash)
 * that additionally demanded a quiesced datadir -- correct, and proven
 * byte-identical to Core at the parity capstone, but unusable as a routine
 * instrument. Core's coinstatsindex folds each connected block's coin
 * events into a running MuHash and running totals; this module does the
 * same, riding the live apply path's own coin events. The result: the RPC
 * answers instantly at any time, and the node carries a CONTINUOUS
 * cryptographic parity instrument -- our running muhash can be compared to
 * the oracle's `gettxoutsetinfo muhash <height>` at any shared height.
 *
 * TWO ACCUMULATORS, ONE ELEMENT SERIALIZER. bitcoin_muhash.asm is insert-
 * only by design (the snapshot walk never removes; no inverse machinery).
 * Removal here is Core's own trick from the other direction: keep a second
 * accumulator for removed elements and divide AT FINALIZE TIME --
 * digest = H(num * den^-1), with the inverse computed by Fermat
 * (den^(p-2), square-and-multiply over num3072_mul, ~4600 modmuls, tens of
 * milliseconds, paid only per RPC call / parity check, never per block).
 *
 * Both sides are utxo_stats_t objects fed through the PROVEN
 * utxo_stats_add (Core's exact compressed-coin serialization -- the
 * capstone's byte-identical muhash went through that code), so this module
 * never re-serializes a coin: inserts fold into the num side's stats,
 * removals into the den side's, and the reported txouts/amount/bogosize
 * are simply num.counters - den.counters.
 *
 * EVENT DISCIPLINE (why re-applied blocks cannot double-count): events fire
 * only on REAL state transitions -- a put that returns "duplicate" or a del
 * of an absent key fires nothing, which is exactly how a crash-resumed
 * block re-applies. The remaining torn window (state advanced in memory,
 * crash before the per-block persist) is detected at boot: a stored height
 * that does not match the applied height INVALIDATES the index, and it
 * re-seeds from a full walk. Persistence rides the same per-block
 * durability point as utxo_applied_height.dat (csi_commit is called from
 * persist_applied_height), tmp+fsync+rename like everything else here.
 *
 * REORGS stay incremental: the rewind path restores spent coins with full
 * fields (insert events) and deletes created coins get-first (remove
 * events), so a disconnect is just more events. The one path that
 * invalidates outright is the pre-BIP34 duplicate-coinbase overwrite --
 * unreachable at live heights, and a full replay re-seeds anyway.
 *
 * FILE (coinstats.dat): "BMCCSI1\0" | i64 height | u8 blockhash[32]
 *   | num utxo_stats_t counters (txouts,amount,bogosize: 3x u64)
 *   | den counters (3x u64) | num acc[384] | den acc[384] | sha256 of all
 *   the above. A bad checksum or magic reads as ABSENT (re-seed), never as
 *   a partially-trusted state.
 */
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern void muhash_init(void* acc);
extern void muhash_finalize(unsigned char out[32], const void* acc);
extern void num3072_mul(void* a, const void* b);
extern void num3072_set_one(void* a);
extern void utxo_stats_init(void* st, unsigned long want_muhash, unsigned long excl_genesis);
extern void utxo_stats_add(void* st, const u8 key36[36], unsigned long value,
                           unsigned long code, const u8* script, unsigned long slen);
extern void sha256_full(unsigned char out[32], const void* data, unsigned long len);

#include "muhash_p2.inc.h"

/* utxo_stats_t layout (bitcoin_utxo_stats.asm): counters at 0/8/16, the
 * 384-byte accumulator at offset 96, struct comfortably inside 512 bytes.
 * Mirrored by offset exactly as every other cross-language struct here. */
#define ST_SIZE     512
#define ST_TXOUTS   0
#define ST_AMOUNT   8
#define ST_BOGO     16
#define ST_ACC      96

typedef struct {
    u8   num[ST_SIZE] __attribute__((aligned(16)));
    u8   den[ST_SIZE] __attribute__((aligned(16)));
    long height;              /* state corresponds to the set AT this height */
    u8   blockhash[32];
    int  valid;
} csi_t;

static csi_t g_csi;
#define CSI_FILE "coinstats.dat"
#define CSI_MAGIC "BMCCSI1"

static u64 st_get(const u8* st, int off){ u64 v; memcpy(&v, st+off, 8); return v; }

/* den^(p-2) mod p by square-and-multiply, using the asm's own modmul.
 * MSB-first over the little-endian exponent bytes. ~3072 squarings + ~3070
 * multiplies (the exponent is nearly all ones); tens of ms. */
static void num3072_inv(u8 out[384], const u8 in[384]){
    num3072_set_one(out);
    for (int byte = 383; byte >= 0; byte--){
        for (int bit = 7; bit >= 0; bit--){
            num3072_mul(out, out);
            if ((MUHASH_P_MINUS_2[byte] >> bit) & 1)
                num3072_mul(out, in);
        }
    }
}

void csi_invalidate(const char* why){
    if (g_csi.valid)
        fprintf(stderr, "[coinstats] index INVALIDATED (%s) -- will re-seed\n", why ? why : "?");
    g_csi.valid = 0;
    unlink(CSI_FILE);
}

int csi_valid(void){ return g_csi.valid; }
long csi_height(void){ return g_csi.valid ? g_csi.height : -1; }

/* one coin entered the live set */
void csi_on_add(const u8 txid[32], u32 index, u64 value, u64 height, u64 coinbase,
                const u8* script, unsigned long slen){
    if (!g_csi.valid) return;
    u8 key[36]; memcpy(key, txid, 32);
    for (int i = 0; i < 4; i++) key[32+i] = (u8)(index >> (8*i));
    utxo_stats_add(g_csi.num, key, value, (height << 1) | coinbase, script, slen);
}

/* one coin left the live set (spend, or a disconnected block's creation) */
void csi_on_remove(const u8 txid[32], u32 index, u64 value, u64 height, u64 coinbase,
                   const u8* script, unsigned long slen){
    if (!g_csi.valid) return;
    u8 key[36]; memcpy(key, txid, 32);
    for (int i = 0; i < 4; i++) key[32+i] = (u8)(index >> (8*i));
    utxo_stats_add(g_csi.den, key, value, (height << 1) | coinbase, script, slen);
}

/* ---- persistence --------------------------------------------------------- */
#define CSI_BODY (8 + 8 + 32 + 6*8 + 384 + 384)

static long csi_serialize(u8* buf){
    u8* p = buf;
    memcpy(p, CSI_MAGIC, 8); p += 8;
    memcpy(p, &g_csi.height, 8); p += 8;
    memcpy(p, g_csi.blockhash, 32); p += 32;
    u64 v;
    v = st_get(g_csi.num, ST_TXOUTS); memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.num, ST_AMOUNT); memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.num, ST_BOGO);   memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.den, ST_TXOUTS); memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.den, ST_AMOUNT); memcpy(p, &v, 8); p += 8;
    v = st_get(g_csi.den, ST_BOGO);   memcpy(p, &v, 8); p += 8;
    memcpy(p, g_csi.num + ST_ACC, 384); p += 384;
    memcpy(p, g_csi.den + ST_ACC, 384); p += 384;
    return p - buf;
}

/* Persist the state for `height`/`blockhash`. Called from the same per-block
 * durability point as utxo_applied_height.dat. Failure invalidates rather
 * than lying about coverage. */
void csi_commit(long height){
    if (!g_csi.valid) return;
    g_csi.height = height;
    memset(g_csi.blockhash, 0, 32);   /* the RPC resolves height->hash itself */
    static u8 buf[CSI_BODY + 32];
    long n = csi_serialize(buf);
    sha256_full(buf + n, buf, (unsigned long)n);
    int fd = open(CSI_FILE ".tmp", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0){ csi_invalidate("persist open failed"); return; }
    if (write(fd, buf, (size_t)(n + 32)) != n + 32 || fsync(fd) != 0){
        close(fd); csi_invalidate("persist write failed"); return;
    }
    close(fd);
    if (rename(CSI_FILE ".tmp", CSI_FILE) != 0) csi_invalidate("persist rename failed");
}

/* Load persisted state; returns the stored height, or -1 when absent/bad.
 * Counters land in the stats structs so the running arithmetic continues
 * exactly where it stopped. */
static long csi_load(void){
    int fd = open(CSI_FILE, O_RDONLY);
    if (fd < 0) return -1;
    static u8 buf[CSI_BODY + 32];
    long r = read(fd, buf, sizeof buf);
    close(fd);
    if (r != CSI_BODY + 32) return -1;
    u8 want[32];
    sha256_full(want, buf, CSI_BODY);
    if (memcmp(want, buf + CSI_BODY, 32) != 0) return -1;
    if (memcmp(buf, CSI_MAGIC, 8) != 0) return -1;
    const u8* p = buf + 8;
    long h; memcpy(&h, p, 8); p += 8;
    memcpy(g_csi.blockhash, p, 32); p += 32;
    utxo_stats_init(g_csi.num, 1 /* muhash */, 0 /* no genesis exclusion: live set */);
    utxo_stats_init(g_csi.den, 1, 0);
    memcpy(g_csi.num + ST_TXOUTS, p, 8); p += 8;
    memcpy(g_csi.num + ST_AMOUNT, p, 8); p += 8;
    memcpy(g_csi.num + ST_BOGO,   p, 8); p += 8;
    memcpy(g_csi.den + ST_TXOUTS, p, 8); p += 8;
    memcpy(g_csi.den + ST_AMOUNT, p, 8); p += 8;
    memcpy(g_csi.den + ST_BOGO,   p, 8); p += 8;
    memcpy(g_csi.num + ST_ACC, p, 384); p += 384;
    memcpy(g_csi.den + ST_ACC, p, 384); p += 384;
    g_csi.height = h;
    return h;
}

/* ---- seed ---------------------------------------------------------------- */
/* Seed by FULL WALK of the live set (the parity tool's own machinery: the
 * walk cb IS utxo_stats_add). Only correct on a quiesced set -- the caller
 * (worker boot, before catch-up starts) guarantees that. Minutes with
 * MuHash; paid only when no valid persisted state exists. */
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);

int csi_seed_from_walk(void* lst, void* u, long height){
    utxo_stats_init(g_csi.num, 1, 0);
    utxo_stats_init(g_csi.den, 1, 0);
    fprintf(stderr, "[coinstats] seeding from a full walk at height %ld (minutes; one-time)\n", height);
    long n = utxo_lsm_walk(lst, u, (void*)utxo_stats_add, g_csi.num);
    if (n < 0){ fprintf(stderr, "[coinstats] seed walk failed\n"); g_csi.valid = 0; return 0; }
    g_csi.valid = 1;
    csi_commit(height);
    fprintf(stderr, "[coinstats] seeded: %ld coins, txouts=%llu at height %ld\n",
            n, (unsigned long long)st_get(g_csi.num, ST_TXOUTS), height);
    return g_csi.valid;
}

/* Boot: adopt the persisted state iff it matches the applied height exactly;
 * anything else re-seeds (the caller decides when to pay the walk). Returns
 * 1 = adopted, 0 = needs seed. */
int csi_boot(long applied_height){
    long h = csi_load();
    if (h >= 0 && h == applied_height){
        g_csi.valid = 1;
        fprintf(stderr, "[coinstats] adopted persisted state at height %ld\n", h);
        return 1;
    }
    if (h >= 0)
        fprintf(stderr, "[coinstats] persisted height %ld != applied %ld -- re-seed needed\n",
                h, applied_height);
    g_csi.valid = 0;
    return 0;
}

/* ---- read side ----------------------------------------------------------- */
/* Fill the caller's outputs from the running state; digest = H(num/den).
 * Also usable OUT-OF-PROCESS: csi_read_file loads coinstats.dat into the
 * same struct and finalizes, which is how the parent's RPC answers without
 * sharing memory with the worker. Returns 1 ok / 0 no valid state. */
static int csi_finalize_into(unsigned char digest[32], u64* txouts, u64* amount, u64* bogo){
    static u8 inv[384] __attribute__((aligned(16)));
    static u8 tmp[384] __attribute__((aligned(16)));
    num3072_inv(inv, g_csi.den + ST_ACC);
    memcpy(tmp, g_csi.num + ST_ACC, 384);
    num3072_mul(tmp, inv);
    muhash_finalize(digest, tmp);
    *txouts = st_get(g_csi.num, ST_TXOUTS) - st_get(g_csi.den, ST_TXOUTS);
    *amount = st_get(g_csi.num, ST_AMOUNT) - st_get(g_csi.den, ST_AMOUNT);
    *bogo   = st_get(g_csi.num, ST_BOGO)   - st_get(g_csi.den, ST_BOGO);
    return 1;
}

int csi_read_live(long* height, unsigned char digest[32], u64* txouts, u64* amount, u64* bogo){
    if (!g_csi.valid) return 0;
    *height = g_csi.height;
    return csi_finalize_into(digest, txouts, amount, bogo);
}

/* light height probe: read + checksum, no finalize. -1 = no valid state. */
long csi_file_height(void){
    csi_t save = g_csi;
    long h = csi_load();
    g_csi = save;
    return h;
}

/* Forward declaration: csi_rpc_run below calls csi_read_file, which is
 * DEFINED further down this file. Without this the call was implicit, so
 * none of its six pointer arguments was type-checked. */
int csi_read_file(long* height, unsigned char blockhash[32], unsigned char digest[32],
                  u64* txouts, u64* amount, u64* bogo);

/* RPC adapter: the same out-contract as the walk reader
 * (rpc_chain.c rpc_usi_out_t: height, txouts, bogosize, total_amount,
 * muhash[32], muhash_valid). Returns 1 served / 0 no-valid-index. */
long csi_rpc_run(int want_muhash, void* outv, char* msg, unsigned long mcap){
    struct { long height; unsigned long long txouts, bogosize, total_amount;
             unsigned char muhash[32]; int muhash_valid; } *o = outv;
    (void)msg; (void)mcap;
    long h; unsigned char digest[32]; u64 tx, amt, bg;
    if (!csi_read_file(&h, NULL, digest, &tx, &amt, &bg)) return 0;
    o->height = h; o->txouts = tx; o->total_amount = amt; o->bogosize = bg;
    if (want_muhash){
        /* PRESENTATION byte order: the raw finalize output is the exact
         * byte-reverse of what Core prints (the same trap utxo_setinfo.c
         * documents and reverses) -- the first live parity check against
         * the oracle read as a "total mismatch" that was really identical.
         * Reverse here so the RPC's hex compares directly. */
        for (int i = 0; i < 32; i++) o->muhash[i] = digest[31 - i];
        o->muhash_valid = 1;
    }
    else o->muhash_valid = 0;
    return 1;
}

/* out-of-process read: load the file fresh each call (one writer, atomic
 * rename; a torn read fails the checksum and reports "no state"). */
int csi_read_file(long* height, unsigned char blockhash[32], unsigned char digest[32],
                  u64* txouts, u64* amount, u64* bogo){
    csi_t save = g_csi;               /* don't disturb an in-process live state */
    long h = csi_load();
    int ok = 0;
    if (h >= 0){
        *height = h;
        if (blockhash) memcpy(blockhash, g_csi.blockhash, 32);
        ok = csi_finalize_into(digest, txouts, amount, bogo);
    }
    g_csi = save;
    return ok;
}
