/* daemon/addr_index_tail.c -- the LIVE address index.
 *
 * WHY: build_addr_index.c snapshots the compacted UTXO set into a sorted
 * address->UTXO file, but it is an offline batch tool -- the daemon never
 * maintained it, so "what does address X own" could only be answered as of
 * the last manual rebuild (FEATURE_GAPS.md's "not a live, queryable index").
 * This module keeps a live, append-only address JOURNAL at the same choke
 * point where the txid/filter index tails already run, and serves the two
 * extension RPCs (rpc_chain.c getaddressbalance / getaddresstxids) from it.
 *
 * NOTE: Bitcoin Core has NO address index at all -- this whole feature is a
 * deliberate EXTENSION (in the spirit of the old addrindex patch set), off
 * by default and enabled with addrindex=1 in bitcoin.conf. It changes no
 * consensus or wire behaviour.
 *
 * FILE (datadir): addrindex.tail -- fixed 82-byte records, strictly
 * ascending by height (see addr_index_fmt.h for the record layout and the
 * shared script classifier). Fixed grid => a torn final record from a crash
 * truncates back onto the grid, exactly tx_index_tail.c's argument; records
 * are strictly height-ordered => a reorg truncates by height from the end.
 *
 * Per applied block, ONE buffered write(2) appends:
 *   ADD   per indexable output the block creates (the block's own bytes),
 *   DEL   per indexable prevout the block spends (that block's own UNDO
 *         records -- the only place a spent output's script still exists),
 *   TOUCH per (spending tx, spent address) so history queries can name the
 *         spend, not just the funding (the DEL's txid field must carry the
 *         SPENT outpoint so it can cancel its ADD -- the spender's txid
 *         travels as its own op instead).
 *
 * COVERAGE: from genesis, which means addrindex=1 must be set BEFORE the
 * node syncs (or within the undo retention window of the tip): enabling it
 * on an already-synced node cannot reconstruct historic spends -- the undo
 * data below tip-200 is pruned -- so boot REFUSES loudly rather than build
 * an index that silently lies about balances. This is the honest version of
 * old-Core's own "-txindex requires -reindex" rule.
 *
 * The genesis coinbase is NOT indexed, matching Core's chainstate (which
 * never contains it) and this node's own UTXO set, so getaddressbalance
 * agrees with scantxoutset ground truth from record one.
 *
 * READERS run in the RPC parent process while the writer appends in the
 * download worker: every query opens the file fresh and reads only whole
 * records (bfi_get_file's out-of-process argument). A linear scan per query
 * is the deliberate v1 trade-off: at regtest/testnet scale it is instant,
 * and the mainnet-scale answer remains the sorted offline snapshot builder.
 */
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "addr_index_fmt.h"
#include "txi_format.h"

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

extern long store_read_at(void* st, unsigned long h, void* out, long cap);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);

#define AXT_BLOCKBUF (8u << 20)
#define AXT_ADOPT_GAP 144        /* enable-late only within the undo window */
#define AXT_MAX_TX_RECS 65536    /* per-block record cap (records, not txs) */

static int  g_fd = -1;           /* addrindex.tail, O_APPEND; -1 = disabled */
static long g_covered = -1;      /* highest height whose records are durable */

/* undo access is REGISTERED, not linked (bfilter_index.c's pattern): the
 * writer runs only in the daemon worker; the RPC-side reader must not drag
 * undo_log into every rpc_chain consumer. */
typedef int (*axt_undo_cb)(void*, const u8*, u32, u64, u32, u8, const u8*, unsigned short);
static long (*g_undo_replay_fn)(long, axt_undo_cb, void*);
void axt_set_undo_replay(long (*fn)(long, axt_undo_cb, void*)){ g_undo_replay_fn = fn; }

int axt_active(void){ return g_fd >= 0; }
long axt_covered(void){ return g_covered; }

/* ---- record pack helpers ------------------------------------------------ */
static void axt_pack(u8* r, u8 op, u8 type_tag, const u8 hash[32],
                     const u8 txid[32], u32 vout, u64 value, u32 height){
    r[0] = op; r[1] = type_tag;
    memcpy(r + 2, hash, 32);
    memcpy(r + 34, txid, 32);
    for (int i = 0; i < 4; i++) r[66+i] = (u8)(vout   >> (8*i));
    for (int i = 0; i < 8; i++) r[70+i] = (u8)(value  >> (8*i));
    for (int i = 0; i < 4; i++) r[78+i] = (u8)(height >> (8*i));
}
static u32 axt_rec_height(const u8* r){
    u32 h = 0; for (int i = 0; i < 4; i++) h |= (u32)r[78+i] << (8*i);
    return h;
}

/* ---- per-block append --------------------------------------------------- */

/* the block's own inputs: prevout -> spending txid, so the undo phase can
 * attribute each spend. Small linear table -- a block has at most a few
 * thousand inputs. */
typedef struct { u8 prevout[36]; u8 spender[32]; } axt_spend_ent;

typedef struct {
    u8* recs; long n; long cap; u32 height; int ok;
    u8* scratch;
    axt_spend_ent* spends; long nspends; long spendcap;
} axt_blk_ctx;

/* walk callback: one transaction. Emits ADDs for its outputs and remembers
 * its inputs' prevouts for the undo phase. */
static void axt_tx_cb(void* ctxv, const u8* tx, u32 off, u32 len){
    (void)off;
    axt_blk_ctx* c = ctxv;
    if (!c->ok) return;
    u8 txid[32];
    if (tx_txid(txid, tx, len, c->scratch, AXT_BLOCKBUF) != 1){ c->ok = 0; return; }
    const u8* p = tx; const u8* end = tx + len;
    u64 cc;
    p += 4;                                     /* version */
    int segwit = (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01);
    if (segwit) p += 2;
    u64 nin = txi_rd_varint(p, end, &cc); if (!cc){ c->ok = 0; return; }
    p += cc;
    for (u64 i = 0; i < nin; i++){
        if (p + 36 > end){ c->ok = 0; return; }
        static const u8 zero36[36] = {0};       /* trailing 0xffffffff differs */
        int coinbase_in = (memcmp(p, zero36, 32) == 0 &&
                           p[32]==0xff && p[33]==0xff && p[34]==0xff && p[35]==0xff);
        if (!coinbase_in){
            if (c->nspends < c->spendcap){
                memcpy(c->spends[c->nspends].prevout, p, 36);
                memcpy(c->spends[c->nspends].spender, txid, 32);
                c->nspends++;
            } else { c->ok = 0; return; }       /* never index a partial block */
        }
        p += 36;
        u64 sl = txi_rd_varint(p, end, &cc); if (!cc){ c->ok = 0; return; }
        p += cc + sl + 4;
        if (p > end){ c->ok = 0; return; }
    }
    u64 nout = txi_rd_varint(p, end, &cc); if (!cc){ c->ok = 0; return; }
    p += cc;
    for (u64 i = 0; i < nout; i++){
        if (p + 8 > end){ c->ok = 0; return; }
        u64 value = 0; for (int b = 0; b < 8; b++) value |= (u64)p[b] << (8*b);
        p += 8;
        u64 sl = txi_rd_varint(p, end, &cc); if (!cc){ c->ok = 0; return; }
        p += cc;
        if (p + sl > end){ c->ok = 0; return; }
        u8 hash[32];
        int t = axf_classify(p, (u32)sl, hash);
        if (t != AXF_INVALID){
            if (c->n >= c->cap){ c->ok = 0; return; }
            axt_pack(c->recs + c->n * AXF_TAIL_REC, AXF_OP_ADD, (u8)t, hash,
                     txid, (u32)i, value, c->height);
            c->n++;
        }
        p += sl;
    }
    /* witness + locktime already validated by the walker */
}

/* undo callback: one spent prevout, script included. */
static int axt_undo_cb_fn(void* ctxv, const u8* txid, u32 index, u64 value,
                          u32 height, u8 coinbase, const u8* script, unsigned short slen){
    (void)height; (void)coinbase;
    axt_blk_ctx* c = ctxv;
    if (!c->ok) return 0;
    u8 hash[32];
    int t = axf_classify(script, slen, hash);
    if (t == AXF_INVALID) return 1;
    if (c->n + 2 > c->cap){ c->ok = 0; return 0; }
    axt_pack(c->recs + c->n * AXF_TAIL_REC, AXF_OP_DEL, (u8)t, hash,
             txid, index, value, c->height);
    c->n++;
    /* attribute the spend: find this prevout in the block's own input map */
    u8 want[36];
    memcpy(want, txid, 32);
    for (int i = 0; i < 4; i++) want[32+i] = (u8)(index >> (8*i));
    for (long i = 0; i < c->nspends; i++){
        if (memcmp(c->spends[i].prevout, want, 36) == 0){
            axt_pack(c->recs + c->n * AXF_TAIL_REC, AXF_OP_TOUCH, (u8)t, hash,
                     c->spends[i].spender, 0, 0, c->height);
            c->n++;
            break;
        }
    }
    return 1;
}

/* Append one block's records as ONE write. 1 ok / 0 failed. Height 0 is a
 * recorded no-op: the genesis coinbase is not in anyone's UTXO set. */
static int axt_append_block(long h, const u8* blk, long blen){
    static u8* recs; static u8* scratch; static axt_spend_ent* spends;
    if (!recs)    recs    = malloc((size_t)AXT_MAX_TX_RECS * AXF_TAIL_REC);
    if (!scratch) scratch = malloc(AXT_BLOCKBUF);
    if (!spends)  spends  = malloc((size_t)AXT_MAX_TX_RECS * sizeof *spends);
    if (!recs || !scratch || !spends) return 0;
    if (h == 0){ g_covered = 0; return 1; }
    if (blen < 81) return 0;
    axt_blk_ctx c = { recs, 0, AXT_MAX_TX_RECS, (u32)h, 1, scratch,
                      spends, 0, AXT_MAX_TX_RECS };
    if (!txi_walk_block(blk, blen, axt_tx_cb, &c) || !c.ok) return 0;
    if (!g_undo_replay_fn) return 0;
    long ur = g_undo_replay_fn(h, axt_undo_cb_fn, &c);
    if (ur < 0 || !c.ok) return 0;              /* undo pruned/torn: cannot index */
    long want = c.n * AXF_TAIL_REC;
    if (want && write(g_fd, c.recs, (size_t)want) != want) return 0;
    g_covered = h;
    return 1;
}

/* torn-tail scan: truncate to the 82-byte grid, return the last record's
 * height (records are strictly ascending) or -1 for an empty file. */
static long axt_scan_max(int fd){
    struct stat sb;
    if (fstat(fd, &sb) != 0) return -2;
    long nrec = (long)(sb.st_size / AXF_TAIL_REC);
    if ((long)sb.st_size != nrec * AXF_TAIL_REC && ftruncate(fd, nrec * AXF_TAIL_REC) != 0)
        return -2;
    if (nrec == 0) return -1;
    u8 r[AXF_TAIL_REC];
    if (pread(fd, r, AXF_TAIL_REC, (nrec - 1) * AXF_TAIL_REC) != AXF_TAIL_REC) return -2;
    return (long)axt_rec_height(r);
}

static long axt_backfill(void* store_buf, long tip){
    if (g_fd < 0) return 0;
    long done = 0;
    static u8* blockbuf;
    if (!blockbuf && !(blockbuf = malloc(AXT_BLOCKBUF))) return -1;
    while (g_covered < tip){
        long h = g_covered + 1;
        long blen = h == 0 ? 0 : store_read_at(store_buf, (unsigned long)h, blockbuf, AXT_BLOCKBUF);
        if (h != 0 && blen < 81){
            fprintf(stderr, "[addrindex] backfill: block %ld unreadable\n", h);
            return -1;
        }
        if (!axt_append_block(h, blockbuf, blen)){
            fprintf(stderr, "[addrindex] backfill stopped at height %ld (undo pruned?)\n", h);
            return -1;
        }
        done++;
    }
    return done;
}

/* Boot (download worker, after archive verify). Gated by the caller on
 * addrindex=1. Establishes coverage; a gap wider than the undo retention
 * window cannot be closed honestly, so it disables the index loudly. */
void axt_boot(void* store_buf){
    int fd = open(AXF_TAIL_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd < 0){ fprintf(stderr, "[addrindex] cannot open %s -- disabled\n", AXF_TAIL_FILE); return; }
    long max_h = axt_scan_max(fd);
    if (max_h == -2){
        fprintf(stderr, "[addrindex] cannot reconcile %s -- disabled\n", AXF_TAIL_FILE);
        close(fd); return;
    }
    long tip = *(int*)((u8*)store_buf + 24);
    long covered = max_h;                        /* -1 for a fresh file */
    if (tip - covered > AXT_ADOPT_GAP && !(covered == -1 && tip <= AXT_ADOPT_GAP)){
        fprintf(stderr, "[addrindex] index at %ld but tip is %ld -- the gap exceeds the "
                        "undo retention window, so historic spends cannot be recovered. "
                        "Disabled: set addrindex=1 BEFORE the node syncs (fresh datadir), "
                        "or use daemon/build_addr_index for an offline snapshot.\n",
                covered, tip);
        close(fd);
        return;
    }
    g_fd = fd;
    g_covered = covered;
    long n = axt_backfill(store_buf, tip);
    if (n < 0 && g_covered < tip){
        fprintf(stderr, "[addrindex] boot backfill failed -- disabled\n");
        close(g_fd); g_fd = -1;
        return;
    }
    fprintf(stderr, "[addrindex] LIVE: covered=%ld (backfilled %ld) -- extension index, "
                    "not a Core feature\n", g_covered, n < 0 ? 0 : n);
}

/* New-block choke point (same site as txit_on_block / bfi_on_block). */
void axt_on_block(void* store_buf, long h, const u8* blk, long blen){
    if (g_fd < 0 || h <= g_covered) return;
    if (h > g_covered + 1 && axt_backfill(store_buf, h - 1) < 0){
        fprintf(stderr, "[addrindex] gap close failed below %ld -- disabled\n", h);
        close(g_fd); g_fd = -1;
        return;
    }
    if (h == g_covered + 1 && !axt_append_block(h, blk, blen)){
        fprintf(stderr, "[addrindex] append failed at height %ld -- disabled\n", h);
        close(g_fd); g_fd = -1;
    }
}

/* Reorg: records are strictly height-ascending, so drop everything above the
 * new tip from the end of the file; the reconnected blocks re-append through
 * the choke point. (Unlike the txid tail, these records are NOT
 * self-verifying against the archive -- a stale ADD would corrupt balances,
 * so they must be physically removed.) */
void axt_on_truncate(void* store_buf){
    if (g_fd < 0) return;
    long tip = *(int*)((u8*)store_buf + 24);
    if (g_covered <= tip) return;
    struct stat sb;
    if (fstat(g_fd, &sb) != 0){ close(g_fd); g_fd = -1; return; }
    long nrec = (long)(sb.st_size / AXF_TAIL_REC);
    long keep = nrec;
    u8 r[AXF_TAIL_REC];
    while (keep > 0){
        if (pread(g_fd, r, AXF_TAIL_REC, (keep - 1) * AXF_TAIL_REC) != AXF_TAIL_REC){
            close(g_fd); g_fd = -1; return;
        }
        if ((long)axt_rec_height(r) <= tip) break;
        keep--;
    }
    if (ftruncate(g_fd, keep * AXF_TAIL_REC) != 0){ close(g_fd); g_fd = -1; return; }
    fprintf(stderr, "[addrindex] rolled back %ld -> %ld (store truncated)\n", g_covered, tip);
    g_covered = tip;
}

/* ---- the out-of-process reader (RPC parent) ----------------------------- */

/* Last covered height by a fresh probe, or -1 (absent/empty). */
long axt_probe_covered(void){
    int fd = open(AXF_TAIL_FILE, O_RDONLY);
    if (fd < 0) return -1;
    struct stat sb;
    long h = -1;
    if (fstat(fd, &sb) == 0){
        long nrec = (long)(sb.st_size / AXF_TAIL_REC);
        if (nrec > 0){
            u8 r[AXF_TAIL_REC];
            if (pread(fd, r, AXF_TAIL_REC, (nrec - 1) * AXF_TAIL_REC) == AXF_TAIL_REC)
                h = (long)axt_rec_height(r);
        } else h = -1;
    }
    close(fd);
    return h;
}

/* Scan the whole journal for ONE (type,hash) key. Fills:
 *   balance   sum of currently-unspent matching outputs' values
 *   received  sum of ALL matching outputs ever created (spent or not)
 *   nutxo     count of currently-unspent matching outputs
 *   txids     up to txid_cap 32-byte txids, deduplicated, file order:
 *             every tx that CREATED an output for the key (ADD) and every
 *             tx that SPENT one (TOUCH)
 * Returns number of txids filled, or -1 when the index file is absent. */
long axt_read_address(int type, const u8 hash[32],
                      u64* balance, u64* received, long* nutxo,
                      u8* txids, long txid_cap){
    int fd = open(AXF_TAIL_FILE, O_RDONLY);
    if (fd < 0) return -1;
    struct stat sb;
    if (fstat(fd, &sb) != 0){ close(fd); return -1; }
    long nrec = (long)(sb.st_size / AXF_TAIL_REC);
    *balance = 0; *received = 0; *nutxo = 0;
    long ntxid = 0;
    /* live UTXOs for this key: (txid,vout,value) triples */
    enum { UCAP = 4096 };
    static struct { u8 txid[32]; u32 vout; u64 value; } utxo[UCAP];
    long nu = 0;
    enum { CHUNK = 512 };
    u8* buf = malloc((size_t)CHUNK * AXF_TAIL_REC);
    if (!buf){ close(fd); return -1; }
    for (long i = 0; i < nrec; i += CHUNK){
        long n = nrec - i < CHUNK ? nrec - i : CHUNK;
        if (pread(fd, buf, (size_t)n * AXF_TAIL_REC, i * AXF_TAIL_REC) != n * AXF_TAIL_REC) break;
        for (long k = 0; k < n; k++){
            const u8* r = buf + k * AXF_TAIL_REC;
            if (r[1] != (u8)type || memcmp(r + 2, hash, 32) != 0) continue;
            u32 vout = 0; for (int b = 0; b < 4; b++) vout |= (u32)r[66+b] << (8*b);
            u64 val = 0;  for (int b = 0; b < 8; b++) val  |= (u64)r[70+b] << (8*b);
            if (r[0] == AXF_OP_ADD){
                if (nu < UCAP){
                    memcpy(utxo[nu].txid, r + 34, 32);
                    utxo[nu].vout = vout; utxo[nu].value = val;
                    nu++;
                }
                *received += val;
            } else if (r[0] == AXF_OP_DEL){
                for (long u = 0; u < nu; u++){
                    if (utxo[u].vout == vout && memcmp(utxo[u].txid, r + 34, 32) == 0){
                        utxo[u] = utxo[nu - 1]; nu--;
                        break;
                    }
                }
            }
            if (r[0] == AXF_OP_ADD || r[0] == AXF_OP_TOUCH){
                int dup = 0;
                for (long t = 0; t < ntxid; t++)
                    if (memcmp(txids + t * 32, r + 34, 32) == 0){ dup = 1; break; }
                if (!dup && ntxid < txid_cap){
                    memcpy(txids + ntxid * 32, r + 34, 32);
                    ntxid++;
                }
            }
        }
    }
    free(buf);
    close(fd);
    for (long u = 0; u < nu; u++) *balance += utxo[u].value;
    *nutxo = nu;
    return ntxid;
}
