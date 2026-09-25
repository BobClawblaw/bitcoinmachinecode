/* rpc_chain.c -- blockchain-query / node-status JSON-RPC methods over the
 * on-disk archive. See rpc_chain.h for why this is a separate, read-only
 * module (bitcoin_rpcd is a standalone process with no in-memory chain).
 *
 * Implemented (Core v31 shapes, src/rpc/blockchain.cpp + rawtransaction.cpp
 * + core_io.cpp):
 *   getblockcount, getbestblockhash, getblockhash, getblockheader, getblock,
 *   getblockchaininfo, getdifficulty, getrawtransaction (block-hash form),
 *   gettxoutproof / verifytxoutproof (BIP37 partial merkle tree; proofs are
 *   byte-identical to Core's), decodescript (util; identical to Core modulo
 *   the omitted descriptor), createmultisig (util; identical modulo the
 *   omitted descriptor), uptime, stop.
 *
 * How chain state reaches this process: bitcoin_store.asm's store_init +
 * store_reload on -datadir's index.dat (positional 48-byte records:
 * [0..32) hash, [32..36) file_no, [36..44) data_pos, [44..48) data_size),
 * bitcoin_store_fast.asm's pread-based read path for block bytes, a
 * bitcoin_idx.asm hash->height table that THIS module fills from the raw
 * record bytes (built at open, extended incrementally as the live daemon
 * appends), chainwork.dat
 * (positional 16-byte LE cumulative work; recomputed from headers when the
 * file is absent/short), headers.dat (112-byte records) for the "headers"
 * count. store_reload is called on every request so the answers track the
 * live daemon's appends without a restart.
 *
 * Byte order, verified against the production archive rather than trusted
 * from comments: index.dat stores the hash in WIRE (raw sha256d) order.
 * bitcoin_idx.asm's idx_build_from_file comment claims DISPLAY order and
 * byte-reverses every record before idx_put; that is inconsistent with what
 * the writers actually persist, so this module deliberately does not use it
 * -- it keys the table on the raw record bytes and reverses only the RPC
 * parameter (display order) at lookup time, which is self-consistent
 * whichever way the archive was written. RPC output reverses record bytes
 * into display order.
 *
 * Known, deliberate divergences from Core (each a fabrication we refuse to
 * make rather than a bug):
 *   - scriptPubKey "desc": Core emits an inferred output descriptor with
 *     checksum; we have no descriptor engine, so the key is OMITTED.
 *   - "address" for witness_unknown / anchor outputs is omitted (no bech32m
 *     encoder for unknown versions in wallet_script_to_address).
 *   - getblockchaininfo "verificationprogress" is blocks/headers, not Core's
 *     tx-count-weighted GuessVerificationProgress. "initialblockdownload" is
 *     "tip older than 24h" (Core also requires min chainwork).
 *   - getblock verbosity 3 now carries Core's per-input `prevout`
 *     {generated, height, value, scriptPubKey}, from the same undo_<h>.dat
 *     the v2 fees come from. (RPX-2 corrected the old claim here that v3
 *     behaved like v2 for want of undo data -- never true; the fees beside it
 *     always came from that file. Wired 2026-09-05.) When the undo file is
 *     pruned the fields are omitted, which is what Core does too.
 *   - uptime/stop apply to THIS RPC process (bitcoin_rpcd), which is not the
 *     block-relaying node; stop's reply names this project, not Core.
 */
#include "daemon/undo_store.h"
#include "rpc_chain.h"
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "bitcoin_pow_rules.h"
#include "mempool_cluster.h"   /* the one linearization/chunking implementation */
#include "rpc_node.h"     /* rpc_mempool_hooks: getblocktemplate reads the shared pool */
#include "script_flags_consts.h"
#include "block_filter.h"   /* BIP158 basic filters, Core-byte-validated */  /* buried-deployment heights, generated from
                                   * Core's chainparams -- the SAME parse the
                                   * script-flag path assembles against */
#include "mempool_entry.h"
#include "mempool_slot.h"    /* the structural mempool's slot layout */
#include "rpc_commands.h"
#include "version_gen.h"

#include <stdio.h>
#include "daemon/log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <pthread.h>



typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;

/* ---- asm primitives ---- */
extern int  store_init(void* st);
extern int  store_reload(void* st);
extern int  store_get_at(void* st, u64 height, u64 out_meta[3]);
extern void store_rd_init(void* st);
extern int  store_rd_fd(void* st, unsigned file_no);
extern long store_read_at(void* st, unsigned long height, void* buf, unsigned long cap);
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const u8 hash[32], long height);
extern int  idx_get(void* idx, const u8 hash[32], long* height);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* data, unsigned long len);
extern void block_work(u8 work[16], unsigned bits);
extern void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16]);
extern int  wallet_script_to_address(char* out, long cap, const u8* script, long slen);
extern int  wallet_validate_address(const char* str, int* type_, unsigned char* version,
                                    unsigned char h160[20], unsigned char prog32[32]);
extern void hash160(u8 out[20], const void* in, long long len);
extern void sha256_full(u8 out[32], const void* msg, long long len);

/* ---- module state ---- */
#define ST_SIZE 4096
static u8   g_st[ST_SIZE];
static int  g_open = 0;
static void* g_idx = NULL;
static unsigned long g_idx_slots = 0;
static long g_idx_tip = -1;          /* highest height folded into g_idx */
static int  g_cw_fd = -1;            /* chainwork.dat, read-only, or -1 */
static u8 (*g_cw_cache)[16] = NULL;  /* computed cumulative work fallback */
static long g_cw_cache_n = 0;        /* entries valid in g_cw_cache */
static long g_cw_cache_cap = 0;
static long g_prune_mib = 0;
static time_t g_start = 0;
static u8*  g_blockbuf = NULL;
#define BLOCKBUF_CAP (8u<<20)

/* ---- lanes: which store handle a thread reads through (2026-09-19) -------
 * Every handler here used to share g_st, the hash index, one block buffer and
 * a handful of static caches, so the RPC server ran them all under ONE write
 * lock. Any slow call -- getchaintxstats re-walking 960k blocks (46 s on
 * production), getindexinfo rescanning a 61 GB txospender tail (run 27),
 * waitfornewblock sleeping 30 s -- therefore stalled uptime and getblockcount
 * behind it. uptime took 44 s on run 27 during IBD.
 *
 * A LANE is a private store handle plus the mutex that owns it. A method that
 * runs in a lane reads the archive through that handle and touches nothing
 * the write-locked handlers share, so the server can run it without the
 * execution lock:
 *   - the fast lane (g_fast_mu, g_fst): getblockcount, getbestblockhash,
 *     getblockchaininfo, getdifficulty, getindexinfo -- bounded, a few preads;
 *   - the chain-tx lane (g_ctx_mu, g_ctx_st): getchaintxstats and the
 *     cumulative-count cache behind it;
 *   - a per-call handle: waitfornewblock / waitforblockheight / waitforblock,
 *     which may legitimately wait 30 s and must not hold anything shared.
 * The handle a thread reads through is t_st; NULL means g_st (the write-locked
 * handlers). read_idx_rec / read_block_prefix / refresh all go through CUR_ST.
 *
 * Shared by every lane, and so locked on its own: the hash->height table
 * (g_idx_mu -- folded by refresh, read by the by-hash lookups) and the
 * computed-chainwork fallback (g_cw_mu). g_blockbuf and read_block stay
 * write-lock-only; no lane method calls them.
 *
 * Lock order: exec lock -> a lane mutex -> g_idx_mu / g_cw_mu. No lane mutex
 * is ever held while taking the exec lock or another lane's mutex. */
static __thread u8* t_st = NULL;
#define CUR_ST (t_st ? t_st : g_st)
static pthread_mutex_t g_idx_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_cw_mu  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_fast_mu = PTHREAD_MUTEX_INITIALIZER;
static u8  g_fst[ST_SIZE];  static int g_fst_ok;
extern void store_rd_close(void* st);
/* Open a lane's private handle on the archive in the cwd (rpc_chain_open
 * chdir()ed there). Its own index.dat descriptor -- store_reload lseeks it,
 * so two handles must never share one -- and its own block-file fd cache. */
static int lane_handle_open(u8* st, int* ok){
    if (*ok) return 1;
    memset(st, 0, ST_SIZE);
    if (store_init(st) != 1) return 0;
    store_reload(st);
    store_rd_init(st);
    *ok = 1;
    return 1;
}
static void lanes_open(void);   /* after the chain-tx lane's state, below */
static void lane_handle_close(u8* st){
    store_rd_close(st);
    long fd = *(long*)(st + 8);   if (fd > 0) close((int)fd);     /* +8 idx_fd       */
    long bf = *(long*)st;          if (bf >= 0) close((int)bf);    /* +0 cur_blk_fd   */
}

static void default_stop(void){ kill(getpid(), SIGTERM); }
static void (*g_stop_fn)(void) = default_stop;
void rpc_chain_set_stop_handler(void (*fn)(void)){ g_stop_fn = fn ? fn : default_stop; }
void rpc_chain_set_prune_mib(long mib){ g_prune_mib = mib; }
/* -blockmaxweight/-blockreservedweight/-blockmintxfee/-blockversion/-printpriority
 * and -maxtipage: injected by main.c from the config (this file never includes
 * node_config.h). Defaults are Core's. */
static long g_gbt_maxweight = 4000000, g_gbt_reserved = 8000, g_gbt_minfee_satkvb = 1;
/* the last template's totals, for getmininginfo. Core omits both fields until
 * a template has been built, and so do we -- reporting 0 would assert an empty
 * block rather than "not asked yet". */
static long g_last_tmpl_tx = 0, g_last_tmpl_weight = 0; static int g_last_tmpl_seen = 0;
static long long g_tmpl_used_w = 0;   /* the selection loop's running weight, read back above */
/* getmininginfo is defined before the template builder; these are its two
   dependencies from further down the file. */
static u32 gbt_next_bits(long tip, long curtime);
static rpc_mempool_hooks g_gbt_mph;
static int  g_gbt_version = 0, g_gbt_printpriority = 0;
/* Core honours -blockversion ONLY where blocks are mined on demand:
 *   node/miner.cpp:148  if (chainparams.MineBlocksOnDemand()) {
 *                           pblock->nVersion = args.GetIntArg("-blockversion", ...); }
 *   kernel/chainparams.h:107  MineBlocksOnDemand() { return consensus.fPowNoRetargeting; }
 * so on mainnet, testnet and signet Core ignores the setting entirely. This
 * node applied it on every chain until 2026-09-06, which let a mainnet
 * operator change the version this node hands out in getblocktemplate where
 * Core would not. Set from g_chainp->pow_no_retargeting at boot. */
static int  g_gbt_mine_on_demand = 0;
void rpc_chain_set_mine_on_demand(int on){ g_gbt_mine_on_demand = on ? 1 : 0; }
/* the version getblocktemplate will report: -blockversion only where Core
 * would honour it, else 0 meaning "the node decides" (0x20000000). */
int rpc_chain_gbt_version_effective(void){
    return g_gbt_mine_on_demand ? g_gbt_version : 0;
}
static long g_maxtipage = 86400;
void rpc_chain_set_gbt_policy(long maxweight, long reserved, long minfee_satkvb, int version, int printpriority){
    if (maxweight < 4000) { maxweight = 4000; } if (maxweight > 4000000) { maxweight = 4000000; }
    if (reserved < 2000) { reserved = 2000; } if (reserved > maxweight) { reserved = maxweight; }
    g_gbt_maxweight = maxweight; g_gbt_reserved = reserved;
    g_gbt_minfee_satkvb = minfee_satkvb < 0 ? 0 : minfee_satkvb;
    g_gbt_version = version; g_gbt_printpriority = printpriority;
}
void rpc_chain_set_maxtipage(long seconds){ g_maxtipage = seconds < 0 ? 0 : seconds; }
/* 3.1 (UTXO_INLINE_CONNECT_SCOPE, 2026-09-06): the tip every chain RPC reports
 * is the CONNECTED tip. refresh() below is the one place the stored tip is
 * read for getblockcount, getbestblockhash, getblockchaininfo.blocks,
 * getchaintips, getblockhash's range, confirmations -- so the cap is applied
 * there, once. main.c registers a reader of the shared status block's
 * connected_tip; a value of NODE_TIP_UNTRACKED (-2, live tracking off) or no
 * reader at all means the stored tip, the pre-3.1 behaviour. "headers" in
 * getblockchaininfo keeps reading headers.dat, as Core's does. */
static long (*g_public_tip_fn)(void) = 0;
void rpc_chain_set_public_tip_fn(long (*fn)(void)){ g_public_tip_fn = fn; }
static long public_tip_cap(long stored){
    if (!g_public_tip_fn) return stored;
    long cap = g_public_tip_fn();
    if (cap == -2L /* NODE_TIP_UNTRACKED */) return stored;
    return cap < stored ? cap : stored;
}

#define ST_IDX_FD(st)     (*(long*)((u8*)(st)+8))
#define ST_TIP(st)        (*(int*)((u8*)(st)+24))
#define ST_PRUNE_H(st)    (*(int*)((u8*)(st)+48))

/* ---- small helpers ---- */
static const char HEXD[] = "0123456789abcdef";
static void hex_of(char* out, const u8* b, size_t n){
    for (size_t i = 0; i < n; i++){ out[i*2] = HEXD[b[i]>>4]; out[i*2+1] = HEXD[b[i]&15]; }
    out[n*2] = 0;
}
static void hex_rev(char* out, const u8* b, size_t n){ /* display order of a wire hash */
    for (size_t i = 0; i < n; i++){ u8 c = b[n-1-i]; out[i*2] = HEXD[c>>4]; out[i*2+1] = HEXD[c&15]; }
    out[n*2] = 0;
}
static int hexv(char c){
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int is_hex_str(const char* s){ for (; *s; s++) if (hexv(*s) < 0) return 0; return 1; }
static u32 rd32(const u8* p){ return (u32)p[0] | ((u32)p[1]<<8) | ((u32)p[2]<<16) | ((u32)p[3]<<24); }
static u64 rd64(const u8* p){ u64 v = 0; for (int i = 7; i >= 0; i--) v = (v<<8) | p[i]; return v; }
static u64 read_varint(const u8* p, const u8* end, u64* consumed){
    if (p >= end){ *consumed = 0; return 0; }
    u8 c = p[0];
    if (c < 0xfd){ *consumed = 1; return c; }
    if (c == 0xfd){ if (p+3 > end){ *consumed = 0; return 0; } *consumed = 3; return (u64)p[1] | ((u64)p[2]<<8); }
    if (c == 0xfe){ if (p+5 > end){ *consumed = 0; return 0; } *consumed = 5; return rd32(p+1); }
    if (p+9 > end){ *consumed = 0; return 0; }
    *consumed = 9; return rd64(p+1);
}

/* Core ParseHashV: "parameter N must be of length 64 (not M, for 'x')" /
 * "parameter N must be hexadecimal string (not 'x')". Writes the 32-byte
 * DISPLAY-order bytes to out. */
static __thread char g_hasherr[256];   /* per thread: lanes run concurrently */
static int parse_hash_param(const char* s, int pnum, u8 out[32], long* ec, const char** em){
    size_t n = strlen(s);
    if (n != 64){
        snprintf(g_hasherr, sizeof g_hasherr, "parameter %d must be of length 64 (not %zu, for '%s')", pnum, n, s);
        *ec = -8; *em = g_hasherr; return 0;
    }
    if (!is_hex_str(s)){
        snprintf(g_hasherr, sizeof g_hasherr, "parameter %d must be hexadecimal string (not '%s')", pnum, s);
        *ec = -8; *em = g_hasherr; return 0;
    }
    for (int i = 0; i < 32; i++) out[i] = (u8)((hexv(s[i*2])<<4) | hexv(s[i*2+1]));
    return 1;
}

/* ---- archive access ---- */
static int read_idx_rec(long h, u8 rec[48]){
    long fd = ST_IDX_FD(CUR_ST);
    if (fd < 0) return 0;
    if (pread(fd, rec, 48, (off_t)h * 48) != 48) return 0;
    return 1;
}
static int rec_present(const u8 rec[48]){ return rd32(rec) != 0; }

/* Load index.dat records [from, to] into the table, keyed by the RAW record
 * hash bytes (wire order). Returns 0 ok / 2 table full. */
/* fold counters for the [idx] trace: what the last idx_load_range saw */
static long g_lr_read, g_lr_present, g_lr_new, g_lr_dup, g_lr_short, g_lr_err;
/* Load index.dat records [from, to] into the table, keyed by the RAW record
 * hash bytes (wire order). Returns 0 ok / 2 table full.
 *
 * *folded_to is the highest height h such that EVERY record in [from, h] was
 * present (from-1 when the first is absent). It is the only thing the caller
 * may advance the fold point to. Records above the first hole are still
 * inserted when present (idx_put dedups a re-read), but they do not move the
 * fold point, so the hole is read again next time.
 *
 * Why (run 24/25 and the probe node, 2026-09-16): the downloader pre-extends
 * index.dat with ZERO records up to the header count, and the store's tip
 * follows the file's extent. The fold once ran over 1..967,314 when 13,880
 * records existed, inserted those, and marked the whole extent folded -- so no
 * fold ever ran again and every block stored afterwards was "Block not found"
 * by hash for the rest of IBD. A read error is not a fold either: it used to
 * return "ok" and advance past whatever it failed to read. */
static int idx_load_range(void* idx, long from, long to, long* folded_to){
    long fd = ST_IDX_FD(g_st);
    enum { CHUNK = 4096 };
    static u8 buf[CHUNK * 48];
    long contiguous = from - 1; int hole = 0;
    g_lr_read = g_lr_present = g_lr_new = g_lr_dup = g_lr_short = g_lr_err = 0;
    for (long h = from; h <= to; h += CHUNK){
        long n = to - h + 1; if (n > CHUNK) n = CHUNK;
        ssize_t got = pread(fd, buf, (size_t)n * 48, (off_t)h * 48);
        if (got < 0){ g_lr_err = errno; *folded_to = contiguous; return 0; }
        long have = got / 48;
        if (have < n){ g_lr_short++; }
        g_lr_read += have;
        for (long i = 0; i < have; i++){
            const u8* rec = buf + i * 48;
            if (!rec_present(rec)){ hole = 1; continue; }
            g_lr_present++;
            int r = idx_put(idx, rec, h + i);
            if (r == 2){ *folded_to = contiguous; return 2; }
            if (r == 1) g_lr_new++; else g_lr_dup++;
            if (!hole) contiguous = h + i;
        }
        if (have < n) hole = 1;                 /* short read: the rest is absent */
        /* Past the first hole nothing can move the fold point, and everything
         * above it is read again next time anyway -- so stop here. Without
         * this every refresh read the whole pre-extended extent (46 MB on
         * mainnet) from the fold point to end-of-file, on every RPC call. */
        if (hole) break;
    }
    *folded_to = contiguous;
    return 0;
}
static int idx_alloc(unsigned long slots){
    void* n = malloc(24 + (size_t)slots*48 + 64);
    if (!n) return 0;
    idx_init(n, slots);
    free(g_idx); g_idx = n; g_idx_slots = slots; g_idx_tip = -1;
    return 1;
}
/* Fold every present height in (g_idx_tip, tip] into the hash index,
 * rebuilding bigger if it fills. The fold point advances only over records
 * that were actually there (see idx_load_range). */
static void idx_sync(long tip){
    if (!g_idx) return;
    long from = g_idx_tip + 1, folded = g_idx_tip;
    int r = idx_load_range(g_idx, from, tip, &folded);
    /* [idx] trace. Measured on run 26 (2026-09-18): this subsystem wrote 10,017
     * of the log's 41,810 lines -- 24% of the whole node log -- and 7,922 of
     * them (79.1%) said present=0 new=0, i.e. nothing happened. err and short
     * were non-zero ZERO times in 30 hours, and folded_to had only 3,907
     * distinct values across those 10,017 lines, so most of them did not even
     * report progress. A fifth of the log was one subsystem saying it was idle.
     *
     * Two rules now, not one:
     *   trouble (err/short) and the present-but-not-inserted anomaly are NEVER
     *     throttled. They were before -- the old condition was
     *     `anomaly || now - last >= 5`, so a non-zero err landing inside the
     *     5 s window was dropped and never reported anywhere. That never bit
     *     because err stayed zero, which is luck rather than design.
     *   a pass that did something keeps the 5 s throttle; a pass that did
     *     nothing gets a 5-minute heartbeat instead, and the heartbeat carries
     *     how many quiet passes it stands for, so the silence is still counted
     *     rather than simply absent. */
    { static time_t last, last_quiet; static long quiet_n, quiet_read;
      time_t now = time(NULL);
      int anomaly = g_lr_present > 0 && g_lr_new + g_lr_dup == 0;
      int trouble = g_lr_err > 0 || g_lr_short > 0;
      int active  = g_lr_present > 0 || g_lr_new > 0 || g_lr_dup > 0;
      if (anomaly || trouble || (active && now - last >= 5) || (!active && now - last_quiet >= 300)){
          char quiet[80]; quiet[0] = 0;
          if (quiet_n) snprintf(quiet, sizeof quiet, "  (+%ld quiet pass(es), read=%ld)", quiet_n, quiet_read);
          last = now; if (!active) last_quiet = now;
          fprintf(stderr, "[idx] fold %ld..%ld: read=%ld present=%ld new=%ld dup=%ld short=%ld err=%ld r=%d folded_to=%ld slots=%lu%s%s\n",
                  from, tip, g_lr_read, g_lr_present, g_lr_new, g_lr_dup, g_lr_short, g_lr_err, r, folded, g_idx_slots,
                  anomaly ? "  <-- PRESENT BUT NOT INSERTED" : "", quiet);
          quiet_n = 0; quiet_read = 0;
      } else if (!active){ quiet_n++; quiet_read += g_lr_read; }
    }
    if (r == 2){
        if (!idx_alloc(g_idx_slots * 2)){ fprintf(stderr, "[idx] grow to %lu slots FAILED (malloc)\n", g_idx_slots * 2); return; }
        int r2 = idx_load_range(g_idx, 0, tip, &folded);
        fprintf(stderr, "[idx] table full; grew to %lu slots, reload 0..%ld: present=%ld new=%ld r=%d folded_to=%ld\n",
                g_idx_slots, tip, g_lr_present, g_lr_new, r2, folded);
        if (r2 != 0) return;
    }
    if (folded > g_idx_tip) g_idx_tip = folded;
}

/* A reorg rewrites index.dat records at heights the table has already folded
 * (reorg.c truncates the store and appends the new branch), and the fold only
 * ever moved forward -- so a block reorged IN below the old fold point was
 * never findable by hash. Before folding, confirm the record at the fold
 * point is still the block the table has there; walk the fold point down
 * until one is, and the fold re-reads everything above it. One pread and one
 * probe per refresh when nothing changed. Caller holds g_idx_mu. */
#define IDX_UNFOLD_MAX 10000   /* deeper than any reorg; past it, something else is wrong */
static void idx_unfold_reorged(void){
    long fd = ST_IDX_FD(g_st);
    if (!g_idx || fd < 0) return;
    long from = g_idx_tip, walked = 0;
    while (g_idx_tip >= 0 && walked < IDX_UNFOLD_MAX){
        u8 rec[48]; long hh = -1;
        if (pread(fd, rec, 48, (off_t)g_idx_tip * 48) == 48 && rec_present(rec) &&
            idx_get(g_idx, rec, &hh) == 1 && hh == g_idx_tip) break;
        g_idx_tip--; walked++;
    }
    if (walked){
        /* a 10,000-deep walk is not a reorg: refold from where it stopped
         * rather than walking on (and re-reading the archive) every call */
        fprintf(stderr, "[idx] records rewritten below the fold (reorg?): fold point %ld -> %ld%s\n",
                from, g_idx_tip, walked >= IDX_UNFOLD_MAX ? "  <-- WALK CAPPED" : "");
    }
}

/* Re-sync with the live daemon's appends. Returns current tip (-1 empty).
 * Reloads the CALLING lane's handle (CUR_ST); the fold into the shared hash
 * index reads g_st's index.dat descriptor with pread only, under g_idx_mu. */
static long refresh(void){
    store_reload(CUR_ST);
    long tip = ST_TIP(CUR_ST);
    pthread_mutex_lock(&g_idx_mu);
    idx_unfold_reorged();
    if (tip > g_idx_tip) idx_sync(tip);       /* the index follows the ARCHIVE: by-hash lookups see every stored block */
    pthread_mutex_unlock(&g_idx_mu);
    return public_tip_cap(tip);               /* the tip the RPCs report is the CONNECTED one (3.1) */
}

int rpc_chain_open(const char* dir){
    if (dir && chdir(dir) != 0) return 0;
    if (g_start == 0) g_start = time(NULL);
    memset(g_st, 0, sizeof g_st);
    struct stat sb;
    if (stat("index.dat", &sb) != 0) return 0;  /* store_init would create an empty one; don't */
    if (store_init(g_st) != 1) return 0;
    store_reload(g_st);
    store_rd_init(g_st);
    long tip = ST_TIP(g_st);
    unsigned long slots = 1u << 16;
    while (slots < (unsigned long)(tip + 1) * 4) slots <<= 1;
    if (!idx_alloc(slots)) return 0;
    fprintf(stderr, "[idx] chain view open: stored tip=%ld, by-hash table %lu slots\n", tip, slots);
    pthread_mutex_lock(&g_idx_mu);
    idx_sync(tip);
    pthread_mutex_unlock(&g_idx_mu);
    g_cw_fd = open("chainwork.dat", O_RDONLY);
    if (!g_blockbuf) g_blockbuf = malloc(BLOCKBUF_CAP);
    g_open = g_blockbuf != NULL;
    if (g_open) lanes_open();
    return g_open;
}

/* Records are keyed by their raw (wire-order) bytes; an RPC hash string is
 * display order, so reverse it to look up. */
/* The table as it stands: a hash it has ever folded, and the height it was
 * folded at. A block reorged OUT keeps its entry (the table never forgets). */
static int height_by_hash_raw(const u8 display[32], long* h){
    u8 wire[32]; for (int i = 0; i < 32; i++) wire[i] = display[31-i];
    pthread_mutex_lock(&g_idx_mu);
    int ok = g_idx && idx_get(g_idx, wire, h) == 1;   /* no index built: not-found, never crash */
    pthread_mutex_unlock(&g_idx_mu);
    return ok;
}
/* ... and only if the archive still holds that block at that height. Before
 * 2026-09-19 a reorged-out hash resolved to its old height, and getblock
 * served whatever block the new branch had put there. This archive keeps no
 * stale blocks, so "not found" is the honest answer. */
static int height_by_hash(const u8 display[32], long* h){
    if (!height_by_hash_raw(display, h)) return 0;
    u8 rec[48];
    if (!read_idx_rec(*h, rec)) return 0;
    for (int i = 0; i < 32; i++) if (rec[i] != display[31-i]) return 0;
    return 1;
}

/* First `n` bytes of block at `h` (header + tx-count prefix). 1 ok / -3 pruned
 * or hole / -1 error. */
static int read_block_prefix(long h, u8* out, size_t n){
    u64 meta[3];
    int r = store_get_at(CUR_ST, (u64)h, meta);
    if (r != 1) return r == -3 ? -3 : -1;
    if (meta[1] == 0) return -3;                       /* hole record */
    if (n > meta[1]) n = (size_t)meta[1];
    int fd = store_rd_fd(CUR_ST, (unsigned)meta[2]);
    if (fd < 0) return -1;
    if (pread(fd, out, n, (off_t)(meta[0] + 8)) != (ssize_t)n) return -1;
    return 1;
}
/* Whole block into g_blockbuf. Returns size, or -3 unavailable / -1 error. */
/* Which height g_blockbuf currently holds, -1 when its contents are unknown.
 * read_block is the only writer of g_blockbuf, so this is the whole truth,
 * and it lets a caller that parsed a block keep using its offsets without
 * copying the bytes out: it can ask whether the buffer still holds its
 * block and re-read only if something else has been through since. */
static long g_blockbuf_h = -1;
static long read_block(long h){
    long r = store_read_at(g_st, (unsigned long)h, g_blockbuf, BLOCKBUF_CAP);
    if (r == -3 || r == -2){ g_blockbuf_h = -1; return -3; }
    if (r < 0){ g_blockbuf_h = -1; return -1; }
    if (r < 81){ g_blockbuf_h = -1; return -3; } /* hole / short */
    g_blockbuf_h = h;
    return r;
}

/* ---- chainwork ---- */
static int chainwork_at(long h, u8 out[16]){
    if (g_cw_fd >= 0 && pread(g_cw_fd, out, 16, (off_t)h * 16) == 16) return 1;
    /* fallback: accumulate from headers, cached -- shared by every lane */
    pthread_mutex_lock(&g_cw_mu);
    if (h >= g_cw_cache_n){
        if (h >= g_cw_cache_cap){
            long cap = g_cw_cache_cap ? g_cw_cache_cap : 4096;
            while (cap <= h) cap *= 2;
            void* n = realloc(g_cw_cache, (size_t)cap * 16);
            if (!n){ pthread_mutex_unlock(&g_cw_mu); return 0; }
            g_cw_cache = n; g_cw_cache_cap = cap;
        }
        for (long i = g_cw_cache_n; i <= h; i++){
            u8 hdr[80];
            if (read_block_prefix(i, hdr, 80) != 1){ pthread_mutex_unlock(&g_cw_mu); return 0; }
            u8 w[16]; block_work(w, rd32(hdr + 72));
            if (i == 0) memcpy(g_cw_cache[0], w, 16);
            else chainwork_add(g_cw_cache[i], g_cw_cache[i-1], w);
            g_cw_cache_n = i + 1;
        }
    }
    memcpy(out, g_cw_cache[h], 16);
    pthread_mutex_unlock(&g_cw_mu);
    return 1;
}
static void chainwork_hex(const u8 w[16], char out[65]){
    memset(out, '0', 32);
    hex_rev(out + 32, w, 16);
}

/* ---- header math (Core GetDifficulty / DeriveTarget / GetMedianTimePast) ---- */
/* ---- chain parameters (runtime-selected; daemon/chainparams.c) ----------
 * Statics default to MAINNET so every existing consumer of rpc_chain.o
 * (standalone rpcd, tests) behaves exactly as before without linking
 * chainparams.c; the daemon calls rpc_chain_set_chainparams() after
 * chainparams_select(). Regtest: name "regtest", halving 150,
 * fPowNoRetargeting (GBT keeps the tip's nBits forever). */
/* getblocktemplate proposal mode: evaluation runs in the download worker
 * (the chain-state owner) via the same staging channel submitblock uses;
 * rpc_node.c owns that channel, so the daemon injects its helper here.
 * NULL (standalone rpcd, tests) => an honest "unavailable". Returns 1 valid,
 * 0 reason filled, -2 decode, -3 timeout, -1 unavailable. */
static long (*g_gbt_proposal)(const char* hex, char* reason, unsigned long rcap) = 0;
void rpc_chain_set_proposal(long (*fn)(const char*, char*, unsigned long)){ g_gbt_proposal = fn; }

static const char* g_chain_name = "main";
static long g_halving_interval  = 210000;
static int  g_pow_no_retarget   = 0;
static int  g_allow_min_diff    = 0;          /* testnet4: 20-min exception  */
static u32  g_pow_limit_bits    = 0x1d00ffff; /* compact powLimit            */
static int  g_enforce_bip94     = 0;          /* testnet4: retarget from the
                                                 FIRST block of the period   */
void rpc_chain_set_chainparams(const char* name, long halving_interval, int pow_no_retargeting,
                               int allow_min_difficulty, unsigned int pow_limit_bits,
                               int enforce_bip94){
    g_chain_name = name; g_halving_interval = halving_interval;
    g_pow_no_retarget = pow_no_retargeting;
    g_allow_min_diff = allow_min_difficulty;
    g_pow_limit_bits = pow_limit_bits;
    g_enforce_bip94 = enforce_bip94;
}

static double difficulty_of(u32 bits){
    int shift = (bits >> 24) & 0xff;
    double d = (double)0x0000ffff / (double)(bits & 0x00ffffff);
    while (shift < 29){ d *= 256.0; shift++; }
    while (shift > 29){ d /= 256.0; shift--; }
    return d;
}
static void target_bytes(u32 bits, u8 t[32]){ /* arith_uint256::SetCompact, big-endian */
    memset(t, 0, 32);
    int size = bits >> 24;
    u32 word = bits & 0x007fffff;
    if (size <= 3){
        word >>= 8 * (3 - size);
        t[31] = (u8)word; t[30] = (u8)(word>>8); t[29] = (u8)(word>>16);
    } else {
        int shift = size - 3; /* bytes */
        /* word occupies 3 bytes, placed so its LSB lands `shift` bytes from the end */
        for (int i = 0; i < 3; i++){
            int pos = 31 - shift - i;
            if (pos >= 0 && pos < 32) t[pos] = (u8)(word >> (8*i));
        }
    }
}
static void target_hex(u32 bits, char out[65]){
    u8 t[32]; target_bytes(bits, t); hex_of(out, t, 32);
}
static int cmp_u32(const void* a, const void* b){ u32 x = *(const u32*)a, y = *(const u32*)b; return x < y ? -1 : x > y; }
static long median_time_past(long h){
    u32 t[11]; int n = 0;
    for (long i = h; i >= 0 && n < 11; i--){
        u8 hdr[80];
        if (read_block_prefix(i, hdr, 80) != 1) break;
        t[n++] = rd32(hdr + 68);
    }
    if (n == 0) return 0;
    qsort(t, (size_t)n, sizeof t[0], cmp_u32);
    return (long)t[n/2];
}
/* UniValue::setFloat: ostringstream << setprecision(16) */
static rj_val* rj_double(double v){ return rj_numf("%.16g", v); }

/* ---- transaction walker (witness-aware) ---- */
#define TX_MAX_IN  65536
typedef struct {
    u32 version, locktime;
    int segwit;
    size_t len, stripped;           /* full serialized size; size without marker/flag/witness */
    u64 n_in, n_out;
    const u8* vin;                  /* start of input count varint */
    const u8* vout;                 /* start of output count varint */
    const u8* wit;                  /* start of witness section (segwit only) */
} txw_t;

/* Walks one tx at p; returns 1 and fills w, or 0 if malformed/truncated. */
static int tx_walk(const u8* p, const u8* end, txw_t* w){
    const u8* s = p;
    u64 c;
    if (p + 4 > end) return 0;
    w->version = rd32(p); p += 4;
    w->segwit = 0;
    if (p + 2 <= end && p[0] == 0x00 && p[1] != 0x00){ w->segwit = 1; p += 2; }
    w->vin = p;
    w->n_in = read_varint(p, end, &c); if (!c) return 0; p += c;
    if (w->n_in > TX_MAX_IN) return 0;
    for (u64 i = 0; i < w->n_in; i++){
        if (p + 36 > end) { return 0; } p += 36;
        u64 sl = read_varint(p, end, &c); if (!c) return 0; p += c;
        { u64 avail=(u64)(end - p); if (avail < sl || avail - sl < 4) return 0; } p += sl + 4;  /* split bound (incident #38) */
    }
    w->vout = p;
    w->n_out = read_varint(p, end, &c); if (!c) return 0; p += c;
    for (u64 i = 0; i < w->n_out; i++){
        if (p + 8 > end) { return 0; } p += 8;
        u64 sl = read_varint(p, end, &c); if (!c) return 0; p += c;
        if ((u64)(end - p) < sl) { return 0; } p += sl;
    }
    size_t witbytes = 0;
    w->wit = NULL;
    if (w->segwit){
        w->wit = p;
        for (u64 i = 0; i < w->n_in; i++){
            u64 ni = read_varint(p, end, &c); if (!c) return 0; p += c;
            for (u64 j = 0; j < ni; j++){
                u64 il = read_varint(p, end, &c); if (!c) return 0; p += c;
                if ((u64)(end - p) < il) { return 0; } p += il;
            }
        }
        witbytes = (size_t)(p - w->wit);
    }
    if (p + 4 > end) return 0;
    w->locktime = rd32(p); p += 4;
    w->len = (size_t)(p - s);
    w->stripped = w->segwit ? w->len - 2 - witbytes : w->len;
    return 1;
}

/* ---- script rendering (Core ScriptToAsmStr / Solver / GetTxnOutputType) ---- */
static const char* opname(u8 op){
    static const char* names[256] = {0};
    static int init = 0;
    if (!init){
        init = 1;
        for (int i = 0; i < 256; i++) names[i] = NULL;
        names[0x00]="0"; names[0x4c]="OP_PUSHDATA1"; names[0x4d]="OP_PUSHDATA2"; names[0x4e]="OP_PUSHDATA4";
        names[0x4f]="-1"; names[0x50]="OP_RESERVED";
        static const char* small[16] = {"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16"};
        for (int i = 0; i < 16; i++) names[0x51+i] = small[i];
        names[0x61]="OP_NOP"; names[0x62]="OP_VER"; names[0x63]="OP_IF"; names[0x64]="OP_NOTIF"; names[0x65]="OP_VERIF";
        names[0x66]="OP_VERNOTIF"; names[0x67]="OP_ELSE"; names[0x68]="OP_ENDIF"; names[0x69]="OP_VERIFY"; names[0x6a]="OP_RETURN";
        names[0x6b]="OP_TOALTSTACK"; names[0x6c]="OP_FROMALTSTACK"; names[0x6d]="OP_2DROP"; names[0x6e]="OP_2DUP"; names[0x6f]="OP_3DUP";
        names[0x70]="OP_2OVER"; names[0x71]="OP_2ROT"; names[0x72]="OP_2SWAP"; names[0x73]="OP_IFDUP"; names[0x74]="OP_DEPTH";
        names[0x75]="OP_DROP"; names[0x76]="OP_DUP"; names[0x77]="OP_NIP"; names[0x78]="OP_OVER"; names[0x79]="OP_PICK";
        names[0x7a]="OP_ROLL"; names[0x7b]="OP_ROT"; names[0x7c]="OP_SWAP"; names[0x7d]="OP_TUCK"; names[0x7e]="OP_CAT";
        names[0x7f]="OP_SUBSTR"; names[0x80]="OP_LEFT"; names[0x81]="OP_RIGHT"; names[0x82]="OP_SIZE"; names[0x83]="OP_INVERT";
        names[0x84]="OP_AND"; names[0x85]="OP_OR"; names[0x86]="OP_XOR"; names[0x87]="OP_EQUAL"; names[0x88]="OP_EQUALVERIFY";
        names[0x89]="OP_RESERVED1"; names[0x8a]="OP_RESERVED2"; names[0x8b]="OP_1ADD"; names[0x8c]="OP_1SUB"; names[0x8d]="OP_2MUL";
        names[0x8e]="OP_2DIV"; names[0x8f]="OP_NEGATE"; names[0x90]="OP_ABS"; names[0x91]="OP_NOT"; names[0x92]="OP_0NOTEQUAL";
        names[0x93]="OP_ADD"; names[0x94]="OP_SUB"; names[0x95]="OP_MUL"; names[0x96]="OP_DIV"; names[0x97]="OP_MOD";
        names[0x98]="OP_LSHIFT"; names[0x99]="OP_RSHIFT"; names[0x9a]="OP_BOOLAND"; names[0x9b]="OP_BOOLOR"; names[0x9c]="OP_NUMEQUAL";
        names[0x9d]="OP_NUMEQUALVERIFY"; names[0x9e]="OP_NUMNOTEQUAL"; names[0x9f]="OP_LESSTHAN"; names[0xa0]="OP_GREATERTHAN";
        names[0xa1]="OP_LESSTHANOREQUAL"; names[0xa2]="OP_GREATERTHANOREQUAL"; names[0xa3]="OP_MIN"; names[0xa4]="OP_MAX"; names[0xa5]="OP_WITHIN";
        names[0xa6]="OP_RIPEMD160"; names[0xa7]="OP_SHA1"; names[0xa8]="OP_SHA256"; names[0xa9]="OP_HASH160"; names[0xaa]="OP_HASH256";
        names[0xab]="OP_CODESEPARATOR"; names[0xac]="OP_CHECKSIG"; names[0xad]="OP_CHECKSIGVERIFY"; names[0xae]="OP_CHECKMULTISIG";
        names[0xaf]="OP_CHECKMULTISIGVERIFY"; names[0xb0]="OP_NOP1"; names[0xb1]="OP_CHECKLOCKTIMEVERIFY"; names[0xb2]="OP_CHECKSEQUENCEVERIFY";
        names[0xb3]="OP_NOP4"; names[0xb4]="OP_NOP5"; names[0xb5]="OP_NOP6"; names[0xb6]="OP_NOP7"; names[0xb7]="OP_NOP8";
        names[0xb8]="OP_NOP9"; names[0xb9]="OP_NOP10"; names[0xba]="OP_CHECKSIGADD"; names[0xff]="OP_INVALIDOPCODE";
    }
    return names[op] ? names[op] : "OP_UNKNOWN";
}
/* CScript::GetOp. Returns 1 ok (opcode, push data span), 0 error. */
static int script_getop(const u8** pc, const u8* end, u8* op, const u8** data, size_t* dlen){
    if (*pc >= end) return 0;
    u8 o = *(*pc)++;
    *op = o; *data = NULL; *dlen = 0;
    if (o <= 0x4e){
        size_t n;
        if (o < 0x4c) n = o;
        else if (o == 0x4c){ if (end - *pc < 1) return 0; n = **pc; *pc += 1; }
        else if (o == 0x4d){ if (end - *pc < 2) return 0; n = (*pc)[0] | ((*pc)[1]<<8); *pc += 2; }
        else { if (end - *pc < 4) return 0; n = rd32(*pc); *pc += 4; }
        if ((size_t)(end - *pc) < n) return 0;
        *data = *pc; *dlen = n; *pc += n;
    }
    return 1;
}
/* CScriptNum(vch, false).getint() for |vch| <= 4 */
static long scriptnum_int(const u8* d, size_t n){
    if (n == 0) return 0;
    long long v = 0;
    for (size_t i = 0; i < n; i++) v |= (long long)d[i] << (8*i);
    if (d[n-1] & 0x80) v = -(v & ~(0x80LL << (8*(n-1))));
    if (v > INT_MAX) return INT_MAX;
    if (v < INT_MIN) return INT_MIN;
    return (long)v;
}
/* IsValidSignatureEncoding (strict DER, Core interpreter.cpp) */
static int der_sig_ok(const u8* s, size_t n){
    if (n < 9 || n > 73) return 0;
    if (s[0] != 0x30 || s[1] != n - 3) return 0;
    size_t lr = s[3]; if (5 + lr >= n) return 0;
    size_t ls = s[5 + lr]; if (lr + ls + 7 != n) return 0;
    if (s[2] != 0x02 || lr == 0 || (s[4] & 0x80)) return 0;
    if (lr > 1 && s[4] == 0 && !(s[5] & 0x80)) return 0;
    if (s[lr+4] != 0x02 || ls == 0 || (s[lr+6] & 0x80)) return 0;
    if (ls > 1 && s[lr+6] == 0 && !(s[lr+7] & 0x80)) return 0;
    return 1;
}
static const char* sighash_name(u8 t){
    switch (t){
        case 0x01: return "ALL"; case 0x02: return "NONE"; case 0x03: return "SINGLE";
        case 0x81: return "ALL|ANYONECANPAY"; case 0x82: return "NONE|ANYONECANPAY"; case 0x83: return "SINGLE|ANYONECANPAY";
        default: return NULL;
    }
}
static int script_unspendable(const u8* s, size_t n){ return (n > 0 && s[0] == 0x6a) || n > 10000; }

static char* script_asm(const u8* s, size_t n, int sighash_decode){
    size_t cap = n * 3 + 64;
    char* out = malloc(cap); if (!out) return NULL;
    size_t len = 0; out[0] = 0;
    const u8* pc = s; const u8* end = s + n;
    int unspendable = script_unspendable(s, n);
    while (pc < end){
        if (len){ out[len++] = ' '; out[len] = 0; }
        u8 op; const u8* d; size_t dl;
        if (!script_getop(&pc, end, &op, &d, &dl)){ len += (size_t)snprintf(out+len, cap-len, "[error]"); return out; }
        if (op <= 0x4e){
            if (dl <= 4){ len += (size_t)snprintf(out+len, cap-len, "%ld", scriptnum_int(d, dl)); }
            else {
                size_t hl = dl; const char* tag = NULL;
                if (sighash_decode && !unspendable && der_sig_ok(d, dl) && (tag = sighash_name(d[dl-1])) != NULL) hl = dl - 1;
                if (len + hl*2 + 32 >= cap){ cap = len + hl*2 + 64; char* n2 = realloc(out, cap); if (!n2){ free(out); return NULL; } out = n2; }
                hex_of(out+len, d, hl); len += hl*2;
                if (tag){ len += (size_t)snprintf(out+len, cap-len, "[%s]", tag); }
            }
        } else {
            len += (size_t)snprintf(out+len, cap-len, "%s", opname(op));
        }
    }
    return out;
}
static int pubkey_size_ok(const u8* p, size_t n){
    return (n == 33 && (p[0] == 0x02 || p[0] == 0x03)) || (n == 65 && p[0] == 0x04);
}
static int small_int(u8 op, int* v){
    if (op == 0x00){ *v = 0; return 1; }
    if (op >= 0x51 && op <= 0x60){ *v = op - 0x50; return 1; }
    return 0;
}
static const char* script_type(const u8* s, size_t n){
    if (n == 25 && s[0]==0x76 && s[1]==0xa9 && s[2]==0x14 && s[23]==0x88 && s[24]==0xac) return "pubkeyhash";
    if (n == 23 && s[0]==0xa9 && s[1]==0x14 && s[22]==0x87) return "scripthash";
    if (n == 4 && s[0]==0x51 && s[1]==0x02 && s[2]==0x4e && s[3]==0x73) return "anchor";
    if (n >= 4 && n <= 42 && (s[0] == 0x00 || (s[0] >= 0x51 && s[0] <= 0x60)) && s[1] >= 2 && s[1] <= 40 && (size_t)s[1] + 2 == n){
        int ver = s[0] == 0 ? 0 : s[0] - 0x50;
        if (ver == 0 && s[1] == 20) return "witness_v0_keyhash";
        if (ver == 0 && s[1] == 32) return "witness_v0_scripthash";
        if (ver == 1 && s[1] == 32) return "witness_v1_taproot";
        if (ver != 0) return "witness_unknown";
    }
    if ((n == 35 && s[0]==33 && s[34]==0xac && pubkey_size_ok(s+1, 33)) || (n == 67 && s[0]==65 && s[66]==0xac && pubkey_size_ok(s+1, 65))) return "pubkey";
    if (n >= 1 && s[0] == 0x6a){
        const u8* pc = s + 1; u8 op; const u8* d; size_t dl; int ok = 1;
        while (pc < s + n){ if (!script_getop(&pc, s+n, &op, &d, &dl) || op > 0x60){ ok = 0; break; } }
        if (ok) return "nulldata";
    }
    if (n >= 3 && s[n-1] == 0xae){
        int k, m; const u8* pc = s; u8 op; const u8* d; size_t dl;
        if (small_int(s[0], &k) && small_int(s[n-2], &m)){
            pc = s + 1; int keys = 0, ok = 1;
            while (pc < s + n - 2){
                if (!script_getop(&pc, s+n-2, &op, &d, &dl) || op > 0x4e || !pubkey_size_ok(d, dl)){ ok = 0; break; }
                keys++;
            }
            if (ok && keys == m && k >= 1 && k <= m) return "multisig";
        }
    }
    return "nonstandard";
}
static char* desc_inner_of(const u8* s, size_t n);        /* InferDescriptor, defined below */
static char* desc_with_checksum(const char* inner);

/* ScriptToUniv(include_hex=true, include_address=true). want_desc adds the
 * inferred "desc" (after asm) as Core does for tx outputs; decodescript's
 * segwit passes 0 because it supplies its own provider-aware desc. */
static rj_val* script_pubkey_json_x(const u8* s, size_t n, int want_desc){
    rj_val* o = rj_obj();
    char* a = script_asm(s, n, 0);
    rj_obj_set(o, "asm", rj_str(a ? a : "")); free(a);
    if (want_desc){ char* di = desc_inner_of(s, n); char* dc = desc_with_checksum(di);
                    if (dc){ rj_obj_set(o, "desc", rj_str(dc)); free(dc); } free(di); }
    char* h = malloc(n*2 + 1); if (h){ hex_of(h, s, n); rj_obj_set(o, "hex", rj_str(h)); free(h); }
    const char* type = script_type(s, n);
    if (strcmp(type, "pubkey") != 0){
        char addr[128]; addr[0] = 0;
        if (wallet_script_to_address(addr, sizeof addr, s, (long)n) > 0 && addr[0]) rj_obj_set(o, "address", rj_str(addr));
    }
    rj_obj_set(o, "type", rj_str(type));
    return o;
}
/* exported for decodepsbt (witness_utxo.scriptPubKey), the tx-output shape with desc */
rj_val* rpc_chain_script_pubkey_json(const unsigned char* sc, unsigned long n){ return script_pubkey_json_x(sc, (size_t)n, 1); }
/* ScriptToAsmStr(script, attempt_sighash_decode) -- decodepsbt final_scriptSig */
char* rpc_chain_script_asm(const unsigned char* sc, unsigned long n, int sighash){ return script_asm(sc, (size_t)n, sighash); }
/* ScriptToUniv(include_hex=true, include_address=false): decodepsbt's redeem_script / witness_script */
rj_val* rpc_chain_script_json_noaddr(const unsigned char* sc, unsigned long n){
    rj_val* o = rj_obj();
    char* a = script_asm(sc, n, 0); rj_obj_set(o, "asm", rj_str(a ? a : "")); free(a);
    /* no "desc": Core's decodepsbt calls the ScriptToUniv overload without a provider for these */
    char* h = malloc(n*2 + 1); if (h){ hex_of(h, sc, n); rj_obj_set(o, "hex", rj_str(h)); free(h); }
    rj_obj_set(o, "type", rj_str(script_type(sc, n)));
    return o;
}

/* ---- TxToUniv (core_io.cpp), include_hex=true, no undo data ---- */
static rj_val* amount_json(u64 sats){ return rj_numf("%llu.%08llu", sats / 100000000ULL, sats % 100000000ULL); }

/* Read the per-input prevout VALUES from undo_<h>.dat, in block order (all
 * non-coinbase inputs, tx-by-tx). Lets getblock v2 report per-tx fees without
 * a UTXO lookup. Record layout (daemon/undo_log.c): txid[32] index(4)
 * value(8) height(4) is_coinbase(1) script_len(2) script[len] -- 51-byte
 * header + script. Returns count, or -1 if the file is absent/pruned (Core
 * always has undo; we keep only a window, so fees are recent-blocks-only). */
/* RPX-2 (audit 2026-09-03): Core's getrawtransaction verbosity 2 adds `fee`
 * and, per input, a `prevout` sub-object {generated, height, value,
 * scriptPubKey}. This node passed in_total = -1 for every verbosity, so
 * verbosity 2 was byte-identical to verbosity 1 and a caller asking for the
 * details silently got the shape without them.
 *
 * Everything needed is already on disk. The undo record (daemon/undo_log.c)
 * is txid[32] | index u32 | value u64 | height u32 | is_coinbase u8 |
 * script_len u16 | script -- value, height, coinbase AND the scriptPubKey,
 * which is exactly Core's prevout. undo_block_values already walks this file
 * for getblock v2's fees and throws everything but the value away. */
typedef struct {
    u64 value;
    u32 height;
    u8  is_coinbase;
    const u8* spk;
    u32 spklen;
} undo_prevout_t;

/* Loads one block's undo file whole and points the entries INTO it. The
 * caller frees *raw when done; entries are invalid after that. Returns the
 * entry count, or -1 (absent/pruned/garbage) with *raw NULL. */
static long undo_block_load(long h, undo_prevout_t* out, long cap, u8** raw){
    *raw = NULL;
    /* 2026-09-08: the block's run from the packed store (undo_store.h); a
     * torn run (no END marker) is unusable, as trailing garbage was. */
    u8* buf = 0; int torn = 0;
    long run_len = us_read_run(h, &buf, &torn);
    if (run_len < 0) return -1;
    if (torn){ free(buf); return -1; }
    struct { long st_size; } sb = { run_len };
    long n = 0, off = 0;
    while (off + 51 <= sb.st_size && n < cap){
        u32 slen = (u32)buf[off+49] | ((u32)buf[off+50] << 8);
        if (off + 51 + (long)slen > sb.st_size) break;      /* truncated tail */
        out[n].value       = rd64(buf + off + 36);
        out[n].height      = (u32)rd32(buf + off + 44);
        out[n].is_coinbase = buf[off + 48];
        out[n].spk         = buf + off + 51;
        out[n].spklen      = slen;
        n++;
        off += 51 + (long)slen;
    }
    if (off != sb.st_size){ free(buf); return -1; }         /* trailing garbage -> unusable */
    *raw = buf;
    return n;
}

static long undo_block_values(long h, u64* out, long cap){
    /* 2026-09-08: the block's run from the packed store (undo_store.h); a
     * torn run (no END marker) is unusable, as trailing garbage was. */
    u8* buf = 0; int torn = 0;
    long run_len = us_read_run(h, &buf, &torn);
    if (run_len < 0) return -1;
    if (torn){ free(buf); return -1; }
    struct { long st_size; } sb = { run_len };
    long off = 0;
    long n = 0;
    while (off + 51 <= sb.st_size && n < cap){
        out[n++] = rd64(buf + off + 36);            /* value at offset 36 */
        u32 slen = (u32)buf[off+49] | ((u32)buf[off+50] << 8);
        off += 51 + (long)slen;
    }
    free(buf);
    return (off == sb.st_size) ? n : -1;            /* trailing garbage -> unusable */
}

/* Like undo_block_values but also returns each spent prevout's script length
 * (for getblockstats' utxo_size_inc). Fills vals[] and slens[] in block order;
 * returns count or -1 (absent/pruned/garbage). */
static long undo_block_prevouts(long h, u64* vals, u32* slens, long cap){
    /* 2026-09-08: the block's run from the packed store (undo_store.h); a
     * torn run (no END marker) is unusable, as trailing garbage was. */
    u8* buf = 0; int torn = 0;
    long run_len = us_read_run(h, &buf, &torn);
    if (run_len < 0) return -1;
    if (torn){ free(buf); return -1; }
    struct { long st_size; } sb = { run_len };
    long off = 0;
    long n = 0;
    while (off + 51 <= sb.st_size && n < cap){
        u32 slen = (u32)buf[off+49] | ((u32)buf[off+50] << 8);
        vals[n] = rd64(buf + off + 36);
        slens[n] = slen;
        n++;
        off += 51 + (long)slen;
    }
    free(buf);
    return (off == sb.st_size) ? n : -1;
}

/* RPX-2: `prevouts` (may be NULL) is this transaction's spent outputs in
 * input order, from the block's undo file. When present each non-coinbase
 * input gains Core's `prevout` sub-object. NULL keeps the pre-RPX-2 shape,
 * which is what verbosity 1 and the mempool/decode paths still want. */
static rj_val* tx_to_json_pv(const u8* tx, const txw_t* w, long long in_total,
                             const undo_prevout_t* prevouts, long nprevouts){
    rj_val* o = rj_obj();
    u8 txid[32], wtxid[32]; char hx[65];
    u8* scratch = malloc(w->len ? w->len : 1);
    if (scratch){ tx_txid(txid, tx, w->len, scratch, w->len); free(scratch); } else memset(txid, 0, 32);
    if (w->segwit) sha256d(wtxid, tx, w->len); else memcpy(wtxid, txid, 32);
    hex_rev(hx, txid, 32);  rj_obj_set(o, "txid", rj_str(hx));
    hex_rev(hx, wtxid, 32); rj_obj_set(o, "hash", rj_str(hx));
    rj_obj_set(o, "version", rj_numf("%u", w->version));
    size_t weight = w->stripped * 3 + w->len;
    rj_obj_set(o, "size", rj_numf("%zu", w->len));
    rj_obj_set(o, "vsize", rj_numf("%zu", (weight + 3) / 4));
    rj_obj_set(o, "weight", rj_numf("%zu", weight));
    rj_obj_set(o, "locktime", rj_numf("%u", w->locktime));

    int coinbase = 0;
    const u8* p = w->vin; u64 c; read_varint(p, tx + w->len, &c); p += c;
    const u8* wp = w->wit;
    rj_val* vin = rj_arr();
    for (u64 i = 0; i < w->n_in; i++){
        rj_val* in = rj_obj();
        const u8* prev = p; u32 vout = rd32(p + 32); p += 36;
        u64 sl = read_varint(p, tx + w->len, &c); p += c;
        const u8* ss = p; p += sl;
        u32 seq = rd32(p); p += 4;
        static const u8 zero32[32] = {0};
        if (i == 0 && vout == 0xffffffffu && memcmp(prev, zero32, 32) == 0) coinbase = 1;
        if (coinbase){
            char* h = malloc(sl*2 + 1); if (h){ hex_of(h, ss, sl); rj_obj_set(in, "coinbase", rj_str(h)); free(h); }
        } else {
            hex_rev(hx, prev, 32); rj_obj_set(in, "txid", rj_str(hx));
            rj_obj_set(in, "vout", rj_numf("%u", vout));
            rj_val* sso = rj_obj();
            char* a = script_asm(ss, sl, 1); rj_obj_set(sso, "asm", rj_str(a ? a : "")); free(a);
            char* h = malloc(sl*2 + 1); if (h){ hex_of(h, ss, sl); rj_obj_set(sso, "hex", rj_str(h)); free(h); }
            rj_obj_set(in, "scriptSig", sso);
        }
        if (wp){
            u64 ni = read_varint(wp, tx + w->len, &c); wp += c;
            if (ni > 0){
                rj_val* arr = rj_arr();
                for (u64 j = 0; j < ni; j++){
                    u64 il = read_varint(wp, tx + w->len, &c); wp += c;
                    char* h = malloc(il*2 + 1); if (h){ hex_of(h, wp, il); rj_arr_push(arr, rj_str(h)); free(h); }
                    wp += il;
                }
                rj_obj_set(in, "txinwitness", arr);
            }
        }
        /* RPX-2: Core's TxToUniv with TxVerbosity::SHOW_DETAILS. Coinbase
         * inputs have no prevout to show -- they spend nothing. The prevout
         * comes BEFORE sequence (2026-09-08: the REST differential against
         * Core caught the two the other way round). */
        if (!coinbase && prevouts && (long)i < nprevouts){
            const undo_prevout_t* pv = &prevouts[i];
            rj_val* po = rj_obj();
            rj_obj_set(po, "generated", rj_bool(pv->is_coinbase != 0));
            rj_obj_set(po, "height", rj_numf("%u", pv->height));
            rj_obj_set(po, "value", amount_json(pv->value));
            rj_obj_set(po, "scriptPubKey", script_pubkey_json_x(pv->spk, pv->spklen, 1));
            rj_obj_set(in, "prevout", po);
        }
        rj_obj_set(in, "sequence", rj_numf("%u", seq));
        rj_arr_push(vin, in);
    }
    rj_obj_set(o, "vin", vin);

    p = w->vout; read_varint(p, tx + w->len, &c); p += c;
    rj_val* vout = rj_arr();
    u64 out_total = 0;
    for (u64 i = 0; i < w->n_out; i++){
        u64 val = rd64(p); p += 8; out_total += val;
        u64 sl = read_varint(p, tx + w->len, &c); p += c;
        rj_val* out = rj_obj();
        rj_obj_set(out, "value", amount_json(val));
        rj_obj_set(out, "n", rj_numf("%llu", i));
        rj_obj_set(out, "scriptPubKey", script_pubkey_json_x(p, sl, 1));
        p += sl;
        rj_arr_push(vout, out);
    }
    rj_obj_set(o, "vout", vout);
    /* fee = sum(prevout values) - sum(output values), when the caller supplied
     * the input total from the block's undo data (getblock v2). in_total < 0
     * means "not available" (coinbase, or undo file pruned/absent). */
    if (in_total >= 0 && (u64)in_total >= out_total)
        rj_obj_set(o, "fee", amount_json((u64)in_total - out_total));
    char* h = malloc(w->len*2 + 1); if (h){ hex_of(h, tx, w->len); rj_obj_set(o, "hex", rj_str(h)); free(h); }
    return o;
}
/* The pre-RPX-2 shape: no prevouts. Every existing caller keeps it. */
static rj_val* tx_to_json(const u8* tx, const txw_t* w, long long in_total){
    return tx_to_json_pv(tx, w, in_total, NULL, 0);
}

/* ---- blockheaderToJSON ---- */
static int header_json(long h, long tip, rj_val** out, long* ec, const char** em){
    u8 pre[89 + 9];
    int r = read_block_prefix(h, pre, sizeof pre);
    if (r != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u8 rec[48]; if (!read_idx_rec(h, rec)){ *ec = -1; *em = "Block not available"; return 0; }
    char hx[65];
    rj_val* o = rj_obj();
    hex_rev(hx, rec, 32); rj_obj_set(o, "hash", rj_str(hx));
    /* Core: a block that is stored but not in the active chain (here: above
     * the connected tip) reports confirmations -1, never 0 or negative. */
    rj_obj_set(o, "confirmations", rj_numf("%ld", h > tip ? -1L : tip - h + 1));
    rj_obj_set(o, "height", rj_numf("%ld", h));
    u32 ver = rd32(pre);
    rj_obj_set(o, "version", rj_numf("%d", (int)ver));
    rj_obj_set(o, "versionHex", rj_strf("%08x", ver));
    hex_rev(hx, pre + 36, 32); rj_obj_set(o, "merkleroot", rj_str(hx));
    rj_obj_set(o, "time", rj_numf("%u", rd32(pre + 68)));
    rj_obj_set(o, "mediantime", rj_numf("%ld", median_time_past(h)));
    rj_obj_set(o, "nonce", rj_numf("%u", rd32(pre + 76)));
    u32 bits = rd32(pre + 72);
    rj_obj_set(o, "bits", rj_strf("%08x", bits));
    target_hex(bits, hx); rj_obj_set(o, "target", rj_str(hx));
    rj_obj_set(o, "difficulty", rj_double(difficulty_of(bits)));
    u8 cw[16]; if (chainwork_at(h, cw)){ chainwork_hex(cw, hx); rj_obj_set(o, "chainwork", rj_str(hx)); }
    u64 c; u64 ntx = read_varint(pre + 80, pre + sizeof pre, &c);
    rj_obj_set(o, "nTx", rj_numf("%llu", ntx));
    if (h > 0){ hex_rev(hx, pre + 4, 32); rj_obj_set(o, "previousblockhash", rj_str(hx)); }
    if (h < tip){ u8 nrec[48]; if (read_idx_rec(h + 1, nrec) && rec_present(nrec)){ hex_rev(hx, nrec, 32); rj_obj_set(o, "nextblockhash", rj_str(hx)); } }
    *out = o;
    return 1;
}

/* ---- param helpers ---- */
static int param_present(const rj_val* params, size_t i){
    return params && params->typ == RJ_ARR && i < params->nitems && params->items[i]->typ != RJ_NULL;
}
/* Core ParseVerbosity(allow_bool) */
static int param_verbosity(const rj_val* params, size_t i, int dflt, long* ec, const char** em){
    if (!param_present(params, i)) return dflt;
    const rj_val* e = params->items[i];
    if (e->typ == RJ_BOOL) return e->str[0] == '1' ? 1 : 0;
    long long v;
    if (!rpc_param_i64(params, i, &v, ec, em)) return -999;
    return (int)v;
}
static int lookup_block_param(const rj_val* params, size_t i, int pnum, long* h, long* ec, const char** em){
    const char* s = rpc_param_str(params, i, ec, em); if (!s) return 0;
    u8 disp[32]; if (!parse_hash_param(s, pnum, disp, ec, em)) return 0;
    if (!height_by_hash(disp, h)){ *ec = -5; *em = "Block not found"; return 0; }
    return 1;
}

/* ---- commands ---- */
static int cmd_getblockcount(rj_val** res){ *res = rj_numf("%ld", refresh()); return 1; }
static int cmd_getdifficulty(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    u8 hdr[80]; if (read_block_prefix(tip, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u32 bits = rd32(hdr + 72);
    *res = rj_double(difficulty_of(bits));   /* Core: difficulty of the current tip */
    return 1;
}

/* getnetworkhashps (Core rpc/mining.cpp GetNetworkHashPS): estimated network
 * hashes/sec from the cumulative-work delta over a window of `nblocks` blocks
 * ending at `height` (defaults 120, tip). Computed from chainwork.dat + header
 * timestamps -- no UTXO dependency, so verifiable now. arith_uint256.getdouble()
 * replicated word-by-word (high 32-bit word first). */
static double gnh_getdouble(const u8 w[16]){
    double r=0; for (int i=3;i>=0;i--) r = r*4294967296.0 + (double)rd32(w+i*4); return r;
}
static int cmd_getnetworkhashps(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec=-28; *em="Loading block index..."; return 0; }
    long nblocks=120, height=-1;
    if (param_present(params,0)){ long long v; if(!rpc_param_i64(params,0,&v,ec,em)) return 0; nblocks=(long)v; }
    if (param_present(params,1)){ long long v; if(!rpc_param_i64(params,1,&v,ec,em)) return 0; height=(long)v; }
    if (nblocks < -1 || nblocks == 0){ *ec=-8; *em="Invalid nblocks. Must be a positive number or -1."; return 0; }
    if (height < -1 || height > tip){ *ec=-8; *em="Block does not exist at specified height"; return 0; }
    long pbh = (height>=0) ? height : tip;
    if (pbh == 0){ *res=rj_numf("%d",0); return 1; }
    if (nblocks == -1) nblocks = pbh % 2016 + 1;
    if (nblocks > pbh) nblocks = pbh;
    u8 hdr[80];
    if (read_block_prefix(pbh, hdr, 80) != 1){ *ec=-1; *em="Block not available"; return 0; }
    long mn=(long)rd32(hdr+68), mx=mn, pb0=pbh;
    for (long i=0;i<nblocks;i++){ pb0--;
        if (read_block_prefix(pb0, hdr, 80) != 1){ *ec=-1; *em="Block not available"; return 0; }
        long t=(long)rd32(hdr+68); if(t<mn)mn=t; if(t>mx)mx=t; }
    if (mn==mx){ *res=rj_numf("%d",0); return 1; }
    u8 cw1[16], cw0[16];
    if (!chainwork_at(pbh,cw1) || !chainwork_at(pb0,cw0)){ *ec=-1; *em="Chainwork not available"; return 0; }
    u8 wd[16]; int borrow=0;
    for (int i=0;i<16;i++){ int d=(int)cw1[i]-(int)cw0[i]-borrow; if(d<0){d+=256;borrow=1;}else borrow=0; wd[i]=(u8)d; }
    *res = rj_double(gnh_getdouble(wd) / (double)(mx-mn));
    return 1;
}

/* getmininginfo (Core rpc/mining.cpp).
 *
 * 2026-09-12: this used to stop at blocks/bits/difficulty/networkhashps/
 * pooledtx/chain/warnings, and the comment here called target, next and
 * blockmintxfee "bleeding-edge fields the project policy does not chase". That
 * was an ASSUMPTION, and it was wrong: Bitcoin Core v31.1 run on regtest
 * returns all three, plus currentblocktx and currentblockweight once a
 * template exists. The assumption survived because the parity register
 * compared method NAMES and nothing compared response shape -- the same gap
 * that left getrawmempool at four fields. See docs/PARITY_RPC_FIELDS.md.
 *
 * currentblocktx/currentblockweight are omitted until a template has actually
 * been built, exactly as Core omits them: reporting 0 would assert an empty
 * block rather than "nobody has asked for a template yet". */
static int cmd_getmininginfo(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec=-28; *em="Loading block index..."; return 0; }
    u8 hdr[80]; if (read_block_prefix(tip, hdr, 80) != 1){ *ec=-1; *em="Block not available"; return 0; }
    u32 bits = rd32(hdr+72);
    rj_val* o = rj_obj();
    rj_obj_set(o,"blocks", rj_numf("%ld", tip));
    { char b[9]; snprintf(b,sizeof b,"%08x",(unsigned)bits); rj_obj_set(o,"bits", rj_str(b)); }
    rj_obj_set(o,"difficulty", rj_double(difficulty_of(bits)));
    { rj_val* nh=NULL; long e2; const char* m2;
      if (cmd_getnetworkhashps(NULL,&nh,&e2,&m2)) rj_obj_set(o,"networkhashps", nh);
      else rj_obj_set(o,"networkhashps", rj_numf("%d",0)); }
    { char hx[65]; target_hex(bits, hx); rj_obj_set(o,"target", rj_str(hx)); }
    /* -blockmintxfee is carried in sat/kvB; Core prints it as a BTC amount */
    { long long s = g_gbt_minfee_satkvb;
      rj_obj_set(o,"blockmintxfee", rj_numf("%lld.%08lld", s/100000000LL, s%100000000LL)); }
    /* the block that would be mined NEXT: its retargeted bits, and what they mean */
    { u32 nb = gbt_next_bits(tip, (long)time(NULL));
      rj_val* nx = rj_obj();
      rj_obj_set(nx,"height", rj_numf("%ld", tip+1));
      { char b[9]; snprintf(b,sizeof b,"%08x",(unsigned)nb); rj_obj_set(nx,"bits", rj_str(b)); }
      rj_obj_set(nx,"difficulty", rj_double(difficulty_of(nb)));
      { char hx[65]; target_hex(nb, hx); rj_obj_set(nx,"target", rj_str(hx)); }
      rj_obj_set(o,"next", nx); }
    if (g_last_tmpl_seen){
        rj_obj_set(o,"currentblocktx", rj_numf("%ld", g_last_tmpl_tx));
        rj_obj_set(o,"currentblockweight", rj_numf("%ld", g_last_tmpl_weight));
    }
    /* pooledtx is the mempool's transaction count, not a constant. It was
     * hard-coded to 0, which the key-level differential could never catch --
     * a field present and always wrong is invisible to a shape diff. */
    { long pooled = 0;
      if (g_gbt_mph.mp && g_gbt_mph.count) pooled = (long)g_gbt_mph.count(g_gbt_mph.mp);
      rj_obj_set(o,"pooledtx", rj_numf("%ld", pooled)); }
    rj_obj_set(o,"chain", rj_str(g_chain_name));
    rj_obj_set(o,"warnings", rj_arr());     /* v31: empty array */
    *res = o;
    return 1;
}

/* ==== getblocktemplate (BIP22/23, Core rpc/mining.cpp) =====================
 * The deterministic frame -- previousblockhash, height, bits (incl the 2016-
 * block retarget), target, mintime (MTP+1), version/rules/limits -- comes
 * from our own chain state and is diffable against the oracle at the same
 * tip. The transaction list comes from the SHARED mempool via the same
 * injected hooks rpc_node uses (rpc_chain_set_mempool); with no pool
 * injected the template is simply empty -- valid, just feeless. NOT
 * implemented (documented): longpoll blocking (longpollid is emitted and
 * changes per tip/template, but a hanging longpoll request is not honored),
 * BIP23 proposal mode, and tx priority/ordering beyond parents-before-
 * children (Core package-feerate-orders; any parent-first order is a VALID
 * template, just not fee-optimal -- honesty note, not a correctness gap). */
static rpc_mempool_hooks g_gbt_mph;
static long (*g_gbt_sigop_cost)(const unsigned char*, unsigned long);
static u64 gbs_subsidy(long h);        /* defined with getblockstats below */
void rpc_chain_set_mempool(const void* hooks_rpc_mempool,
                           long (*sigop_cost)(const unsigned char*, unsigned long)){
    const rpc_mempool_hooks* h = (const rpc_mempool_hooks*)hooks_rpc_mempool;
    if (h) g_gbt_mph = *h; else memset(&g_gbt_mph, 0, sizeof g_gbt_mph);
    g_gbt_sigop_cost = sigop_cost;
}


/* Pure retarget arithmetic -- MOVED to bitcoin_pow_rules.c (one
 * implementation for GBT and validation; proven against every header of the
 * real mainnet and testnet4 chains, see validation/pow_replay.c). This
 * wrapper keeps the hermetic KAT surface (vectors frozen from an
 * arith_uint256-faithful reference) at its historical name/signature,
 * pinned to the mainnet powLimit the KATs were generated under. */
u32 rpc_chain_retarget(u32 old_bits, long ts){
    return pow_retarget_bits(old_bits, ts, 0x1d00ffff);
}
/* Core pow.cpp GetNextWorkRequired via the SHARED rule engine
 * (bitcoin_pow_rules.c) -- the same pow_expected_bits validation enforces,
 * so a template this node builds is by construction one its own validator
 * accepts. The adapter reads ancestor headers out of the archive. */
static int gbt_hdr_at(void* ctx, long h, u8 hdr[80]){
    (void)ctx; return read_block_prefix(h, hdr, 80) == 1 ? 1 : 0;
}
static u32 gbt_next_bits(long tip, long curtime){
    return pow_expected_bits(tip + 1, curtime, gbt_hdr_at, NULL,
                             g_pow_no_retarget, g_allow_min_diff,
                             g_enforce_bip94, g_pow_limit_bits);
}

/* Slot walk of the shared structural pool (bitcoin_mempool.asm's documented
 * layout; the same walk daemon/reorg.c and rpc_node.c use). */
typedef struct { const u8* txid; const u8* tx; unsigned long len; } gbt_ent;
static long gbt_slot(void* mp, unsigned long i, gbt_ent* e){
    u8* m = (u8*)mp;
    unsigned long long mask; memcpy(&mask, m+8, 8);
    if (i > mask) return -1;
    u8* sl = MPOOL_SLOT_AT(m, i);
    unsigned long long len; memcpy(&len, sl, 8);
    if (len == MPOOL_SLOT_EMPTY) return 0;
    u8* blob; memcpy(&blob, m+16, 8);
    unsigned long long off; memcpy(&off, sl+MPOOL_SLOT_OFF, 8);
    e->txid = sl+8; e->tx = blob+off; e->len = (unsigned long)len;
    return 1;
}

#define GBT_MAX_TX 4000
/* txid -> position in the emitted template order, so `depends` resolves in
 * O(1). It used to be a scan of every earlier emitted entry, for every
 * dependency of every transaction. Open-addressed, rebuilt per template;
 * 16384 slots against GBT_MAX_TX 4000 keeps the load factor under a quarter. */
#define GBT_POS_N (1u << 14)
static int g_gbt_pos[GBT_POS_N];
static unsigned gbt_pos_h(const u8* t){
    unsigned long long k; memcpy(&k, t, 8);
    return (unsigned)((k * 0x9E3779B97F4A7C15ULL) >> 50) & (GBT_POS_N - 1);
}
static int cmd_getblocktemplate(const rj_val* params, rj_val** res, long* ec, const char** em){
    /* template_request: rules MUST include "segwit" (Core-exact error) */
    int segwit_rule = 0;
    if (params && params->typ == RJ_ARR && params->nitems >= 1 && params->items[0]->typ == RJ_OBJ){
        const rj_val* req = params->items[0];
        const rj_val* rules = rj_obj_get((rj_val*)req, "rules");
        if (rules && rules->typ == RJ_ARR)
            for (unsigned long i = 0; i < rules->nitems; i++)
                if (rules->items[i]->typ == RJ_STR && !strcmp(rules->items[i]->str, "segwit")) segwit_rule = 1;
        const rj_val* mode = rj_obj_get((rj_val*)req, "mode");
        if (mode && mode->typ == RJ_STR && !strcmp(mode->str, "proposal")){
            /* BIP23 proposal: full validation of a caller-built block WITHOUT
             * PoW and WITHOUT connecting -- Core's TestBlockValidity via the
             * worker's dry-run path. null = valid, else the BIP22 reason. */
            const rj_val* data = rj_obj_get((rj_val*)req, "data");
            if (!data || data->typ != RJ_STR){
                *ec = -8; *em = "Missing data String key for proposal"; return 0; }
            if (!g_gbt_proposal){
                *ec = -1; *em = "Block proposal evaluation unavailable (no download worker)"; return 0; }
            static char reason[64];
            long pr = g_gbt_proposal(data->str, reason, sizeof reason);
            if (pr == 1){ *res = rj_null(); return 1; }
            if (pr == -2){ *ec = -22; *em = "Block decode failed"; return 0; }
            if (pr == -3){ *ec = -4; *em = "Block proposal timed out (node may be catching up)"; return 0; }
            if (pr == -1){ *ec = -1; *em = "Block proposal evaluation unavailable (no download worker)"; return 0; }
            *res = rj_str(reason[0] ? reason : "rejected");
            return 1;
        }
        if (mode && mode->typ == RJ_STR && strcmp(mode->str, "template")){
            *ec = -8; *em = "Invalid mode"; return 0; }
    }
    if (!segwit_rule){
        *ec = -8; *em = "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})";
        return 0; }

    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    u8 hdr[80];
    if (read_block_prefix(tip, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u8 tiphash[32]; sha256d(tiphash, hdr, 80);
    long height = tip + 1;
    long mintime = median_time_past(tip) + 1;
    long curtime = (long)time(NULL); if (curtime < mintime) curtime = mintime;
    u32 bits = gbt_next_bits(tip, curtime);
    if (!bits){ *ec = -1; *em = "Block not available"; return 0; }

    rj_val* o = rj_obj();
    { rj_val* caps = rj_arr(); rj_arr_push(caps, rj_str("proposal"));
      rj_obj_set(o, "capabilities", caps); }
    { int ev = rpc_chain_gbt_version_effective();
      rj_obj_set(o, "version", rj_numf("%d", ev ? ev : 536870912)); }  /* 0x20000000 unless -blockversion, and only where Core honours it */
    { rj_val* rls = rj_arr();
      rj_arr_push(rls, rj_str("csv")); rj_arr_push(rls, rj_str("!segwit"));
      rj_arr_push(rls, rj_str("taproot"));
      rj_obj_set(o, "rules", rls); }
    rj_obj_set(o, "vbavailable", rj_obj());
    rj_obj_set(o, "vbrequired", rj_numf("%d", 0));
    { char hx[65]; hex_rev(hx, tiphash, 32);
      rj_obj_set(o, "previousblockhash", rj_str(hx));
      static unsigned long long lp_ctr = 0;                  /* template id */
      char lp[80]; snprintf(lp, sizeof lp, "%s%llu", hx, ++lp_ctr);
      rj_obj_set(o, "longpollid", rj_str(lp)); }

    /* ---- transaction list: shared pool, parents before children ---- */
    unsigned long long fees_total = 0;
    rj_val* txs = rj_arr();
    if (g_gbt_mph.mp && g_gbt_mph.get){
        static gbt_ent ents[GBT_MAX_TX];
        static int order[GBT_MAX_TX];
        long n = 0;
        if (g_gbt_mph.lock) g_gbt_mph.lock();
        { u8* m = (u8*)g_gbt_mph.mp; unsigned long long mask; memcpy(&mask, m+8, 8);
          for (unsigned long i = 0; i <= mask && n < GBT_MAX_TX; i++){
              gbt_ent e; if (gbt_slot(g_gbt_mph.mp, i, &e) == 1) ents[n++] = e; } }
        /* ---- chunk selection (Core v31 cluster mempool: BlockAssembler over
         * the linearization) ----
         * Each cluster (connected component of the spend graph) is
         * linearized -- ancestor-set greedy, a later chunk that pays more
         * than the one before it merged into it -- into chunks of
         * non-increasing feerate. The block is filled with WHOLE chunks in
         * feerate order across clusters, parents-first inside a chunk. A
         * chunk that does not fit is skipped together with the rest of its
         * cluster (later chunks depend on it) and selection continues with
         * other clusters' chunks: Core's BlockBuilder::Skip. Ancestor-
         * package greedy (Core's addPackageTxs before v31) scored a package
         * by its ancestor set alone and skipped per package; the chunk view
         * is what lifts a cheap parent by the chunk it ends up in, and what
         * keeps a skipped cluster's descendants out. Weight and sigop budgets
         * are Core's (4M weight / 80k cost, minus the 4000-weight / 400-sigop
         * coinbase reservation). Tie-break among equal feerates: the cluster
         * seen first (slot order), then the smaller txid -- Core's exact tie
         * order is not part of the protocol. Clusters wider than
         * GBT_CLUSTER_MAX are linearized without the merge step (each
         * ancestor set is its own chunk), which is the pre-v31 order. */
        static mp_entry_info infs[GBT_MAX_TX];
        static unsigned char have_inf[GBT_MAX_TX];
        static unsigned long long tfee[GBT_MAX_TX], tsize[GBT_MAX_TX];
        static long tweight[GBT_MAX_TX], tsig[GBT_MAX_TX];
        /* One batched call for every candidate. This was pol_entry_info per
         * entry, and that scans the registry to locate the transaction, then
         * scans it AGAIN for spentby, then walks the descendant set with a
         * nested pass over every node -- none of which this template reads. */
        static unsigned char pkg_txids[GBT_MAX_TX][32];
        long pkg_got = -1;
        if (g_gbt_mph.polstate && g_gbt_mph.pol_pkg_many && n <= GBT_MAX_TX){
            for (long i = 0; i < n; i++) memcpy(pkg_txids[i], ents[i].txid, 32);
            pkg_got = g_gbt_mph.pol_pkg_many(g_gbt_mph.polstate,
                        (const unsigned char (*)[32])pkg_txids, (unsigned)n, infs, have_inf);
        }
        for (long i = 0; i < n; i++){
            if (pkg_got < 0){
                have_inf[i] = 0;
                if (g_gbt_mph.polstate && g_gbt_mph.pol_entry_info &&
                    g_gbt_mph.pol_entry_info(g_gbt_mph.polstate, ents[i].txid, &infs[i]))
                    have_inf[i] = 1;
            }
            tfee[i] = 0; tsize[i] = 1;
            if (have_inf[i]){
                tfee[i] = infs[i].fee; tsize[i] = infs[i].size ? infs[i].size : 1;
            }
            { const u8* tp = ents[i].tx; const u8* tend = tp + ents[i].len; txw_t w;
              tweight[i] = tx_walk(tp, tend, &w) ? (long)(w.stripped * 3 + w.len) : (long)(ents[i].len * 4); }
            tsig[i] = (have_inf[i] && infs[i].sigop_cost)
                        ? (long)infs[i].sigop_cost
                        : (g_gbt_sigop_cost ? g_gbt_sigop_cost(ents[i].tx, ents[i].len) : 0);
        }
        /* ancestor index lists (self excluded), resolved once; an entry
         * whose ancestor is not in the registry is left out (registry-stale) */
        static int anc_idx[GBT_MAX_TX][MPE_MAX_SET]; static int anc_n[GBT_MAX_TX];
        static unsigned char usable[GBT_MAX_TX];
        for (long i = 0; i < n; i++){
            anc_n[i] = 0; usable[i] = have_inf[i];
            if (!have_inf[i]) continue;
            for (int a = 0; a < infs[i].n_anc; a++){
                if (!memcmp(infs[i].anc[a], ents[i].txid, 32)) continue;
                long j = -1;
                for (long m = 0; m < n; m++) if (!memcmp(ents[m].txid, infs[i].anc[a], 32)){ j = m; break; }
                if (j < 0){ usable[i] = 0; break; }
                anc_idx[i][anc_n[i]++] = (int)j;
            }
        }
        /* clusters: union-find over ancestor links */
        static int uf[GBT_MAX_TX];
        for (long i = 0; i < n; i++) uf[i] = (int)i;
        #define UF_FIND(x) ({ int r_ = (x); while (uf[r_] != r_) r_ = uf[r_]; int q_ = (x); while (uf[q_] != r_){ int t_ = uf[q_]; uf[q_] = r_; q_ = t_; } r_; })
        for (long i = 0; i < n; i++){
            if (!usable[i]) continue;
            for (int a = 0; a < anc_n[i]; a++){ int ra = UF_FIND(anc_idx[i][a]), ri = UF_FIND((int)i); if (ra != ri) uf[ra] = ri; }
        }
        /* group members by cluster root (stable in slot order) */
        static int byroot[GBT_MAX_TX]; long nb = 0;
        static int root_of[GBT_MAX_TX];
        for (long i = 0; i < n; i++){ if (!usable[i]) continue; root_of[i] = UF_FIND((int)i); byroot[nb++] = (int)i; }
        /* insertion sort by root (n <= 4000; clusters are small in practice) */
        for (long i = 1; i < nb; i++){ int v = byroot[i]; long j = i - 1; while (j >= 0 && root_of[byroot[j]] > root_of[v]){ byroot[j+1] = byroot[j]; j--; } byroot[j+1] = v; }
        /* chunks: contiguous member runs in cmem; merging two adjacent chunks
         * of one cluster is a run extension */
        /* 2026-09-14: was 512. Accept refuses a cluster above 64 (Core's
         * DEFAULT_CLUSTER_LIMIT), so this was unreachable and disagreed with
         * the eviction and RPC bounds. One bound, Core's, everywhere. */
        #define GBT_CLUSTER_MAX 64
        typedef struct { int start, cnt; unsigned long long fee, size; long long w, s; int cluster, seq; } gbt_chunk;
        static gbt_chunk chunks[GBT_MAX_TX]; long nch = 0;
        static int cmem[GBT_MAX_TX]; long ncm = 0;
        static unsigned char done[GBT_MAX_TX];
        for (long i = 0; i < n; i++) done[i] = 0;
        long gi = 0; int cluster_no = 0;
        while (gi < nb){
            long gj = gi; while (gj < nb && root_of[byroot[gj]] == root_of[byroot[gi]]) gj++;
            long msz = gj - gi; const int* mem = &byroot[gi];
            long first_chunk = nch;

            /* UNIFIED 2026-09-14: the linearization and chunking are
             * mempool_cluster.c's, not a second copy of the same idea. This
             * file, bitcoin_mempool_policy.c and mempool_cluster.c each carried
             * their own; one of them is tested to the letter (74 tests, 3,000
             * randomised DAGs) and that is the one that should decide which
             * transactions a block holds.
             *
             * The feerate denominator is deliberately UNCHANGED: tsize (vsize)
             * is handed to the module as its weight, so today's ordering
             * arithmetic is preserved exactly. Core chunks by sigops-ADJUSTED
             * WEIGHT and this node should too, but that is a change to what the
             * numbers MEAN, and doing it in the same commit as a change to
             * WHICH CODE computes them would make the diff unreadable. Separate
             * commit, separate justification.
             *
             * A cluster above the bound cannot occur -- accept refuses one
             * (too-large-cluster, Core's DEFAULT_CLUSTER_LIMIT) -- but if the
             * registry ever handed us one, falling back to per-member chunks is
             * the honest answer: no ordering claim we cannot support. */
            if (msz > MPC_MAX_CLUSTER){
                for (long m = 0; m < msz; m++){
                    int t = mem[m]; if (done[t]) continue;
                    gbt_chunk* c = &chunks[nch++];
                    c->start = (int)ncm; c->cnt = 1; c->cluster = cluster_no;
                    c->seq = (int)(nch - 1 - first_chunk);
                    c->fee = tfee[t]; c->size = tsize[t]; c->w = tweight[t]; c->s = tsig[t];
                    done[t] = 1; cmem[ncm++] = t;
                }
            } else {
                mpc_cluster cl; memset(&cl, 0, sizeof cl); cl.n = (int)msz;
                for (long m = 0; m < msz; m++){
                    int t = mem[m];
                    cl.m[m].fee = tfee[t];
                    cl.m[m].weight = tsize[t];          /* see the note above */
                    cl.m[m].ancestors = (uint64_t)1 << m;
                    memcpy(cl.txid[m], ents[t].txid, 32);
                }
                /* ancestor bitsets, restricted to this cluster */
                for (long m = 0; m < msz; m++){
                    int t = mem[m];
                    for (int a = 0; a < anc_n[t]; a++){
                        int at = anc_idx[t][a];
                        for (long q = 0; q < msz; q++)
                            if (mem[q] == at){ cl.m[m].ancestors |= (uint64_t)1 << q; break; }
                    }
                }
                for (long m = 0; m < msz; m++)
                    for (long q = 0; q < msz; q++)
                        if (cl.m[q].ancestors & ((uint64_t)1 << m)) cl.m[m].descendants |= (uint64_t)1 << q;

                int lin[MPC_MAX_CLUSTER]; mpc_chunking mch;
                if (mpc_linearize_ancestor_score(&cl, lin) == 0 &&
                    (mpc_post_linearize(&cl, lin), 1) &&
                    mpc_chunk_linearization(&cl, lin, &mch) == 0){
                    for (int ci2 = 0; ci2 < mch.n; ci2++){
                        gbt_chunk* c = &chunks[nch++];
                        c->start = (int)ncm; c->cnt = 0; c->fee = 0; c->size = 0; c->w = 0; c->s = 0;
                        c->cluster = cluster_no; c->seq = (int)(nch - 1 - first_chunk);
                        /* members in LINEARIZATION order: a chunk is an ordered
                         * run, and depends[] downstream is built from it */
                        for (long k = 0; k < msz; k++){
                            int idx = lin[k];
                            if (!(mch.c[ci2].members & ((uint64_t)1 << idx))) continue;
                            int t = mem[idx];
                            done[t] = 1; cmem[ncm++] = t; c->cnt++;
                            c->fee += tfee[t]; c->size += tsize[t];
                            c->w += tweight[t]; c->s += tsig[t];
                        }
                    }
                } else {
                    /* the module refused: emit per-member rather than guess */
                    for (long m = 0; m < msz; m++){
                        int t = mem[m]; if (done[t]) continue;
                        gbt_chunk* c = &chunks[nch++];
                        c->start = (int)ncm; c->cnt = 1; c->cluster = cluster_no;
                        c->seq = (int)(nch - 1 - first_chunk);
                        c->fee = tfee[t]; c->size = tsize[t]; c->w = tweight[t]; c->s = tsig[t];
                        done[t] = 1; cmem[ncm++] = t;
                    }
                }
            }
            cluster_no++; gi = gj;
        }
        /* chunk order across clusters: feerate descending; ties by cluster (slot order) then sequence */
        static int corder[GBT_MAX_TX];
        for (long i = 0; i < nch; i++) corder[i] = (int)i;
        for (long i = 1; i < nch; i++){
            int v = corder[i]; long j = i - 1;
            while (j >= 0){
                const gbt_chunk* A = &chunks[corder[j]]; const gbt_chunk* B = &chunks[v];
                int a_before = ((unsigned __int128)A->fee * B->size > (unsigned __int128)B->fee * A->size) ||
                               ((unsigned __int128)A->fee * B->size == (unsigned __int128)B->fee * A->size &&
                                (A->cluster < B->cluster || (A->cluster == B->cluster && A->seq < B->seq)));
                if (a_before) break;
                corder[j+1] = corder[j]; j--;
            }
            corder[j+1] = v;
        }
        long emitted_n = 0;
        /* Core: MAX_BLOCK_WEIGHT - reserved (the coinbase and header the
         * miner adds); -blockmaxweight caps the template lower. Sigops keep
         * the same proportional reserve. */
        long long budget_w = g_gbt_maxweight - g_gbt_reserved, budget_s = 80000 - (80000LL * g_gbt_reserved) / 4000000;
        long long used_w = 0, used_s = 0;
        static unsigned char cluster_skipped[GBT_MAX_TX];
        for (int i = 0; i < cluster_no; i++) cluster_skipped[i] = 0;
        for (long ci = 0; ci < nch; ci++){
            const gbt_chunk* c = &chunks[corder[ci]];
            if (cluster_skipped[c->cluster]) continue;
            if (used_w + c->w > budget_w || used_s + c->s > budget_s){ cluster_skipped[c->cluster] = 1; continue; }
            /* -blockmintxfee: a chunk paying below it is left out (Core's
             * BlockAssembler stops at the first package under the floor) */
            if (c->size && (unsigned __int128)c->fee * 1000 < (unsigned __int128)g_gbt_minfee_satkvb * c->size){ cluster_skipped[c->cluster] = 1; continue; }
            if (g_gbt_printpriority)
                fprintf(stderr, "[gbt] chunk of %d tx: fee %llu sat, %llu vB, %.8f BTC/kvB\n", c->cnt,
                        (unsigned long long)c->fee, (unsigned long long)c->size,
                        c->size ? (double)c->fee / (double)c->size * 1000.0 / 1e8 : 0.0);
            for (int k = 0; k < c->cnt; k++){ order[emitted_n++] = cmem[c->start + k]; }
            used_w += c->w; used_s += c->s; g_tmpl_used_w = used_w;
        }
        #undef UF_FIND
        /* render in order; depends[] are 1-based indices into this array */
        memset(g_gbt_pos, 0, sizeof g_gbt_pos);
        for (long oj = 0; oj < emitted_n; oj++){
            unsigned h = gbt_pos_h(ents[order[oj]].txid);
            while (g_gbt_pos[h]) h = (h + 1) & (GBT_POS_N - 1);
            g_gbt_pos[h] = (int)(oj + 1);                 /* 0 means empty */
        }
        #define GBT_POS_FIND(TXID, OUT) do {                                       \
            (OUT) = -1; unsigned h_ = gbt_pos_h(TXID);                             \
            while (g_gbt_pos[h_]){                                                 \
                long p_ = g_gbt_pos[h_] - 1;                                       \
                if (!memcmp(ents[order[p_]].txid, (TXID), 32)){ (OUT) = p_; break; }\
                h_ = (h_ + 1) & (GBT_POS_N - 1);                                   \
            } } while (0)
        for (long oi = 0; oi < emitted_n; oi++){
            long i = order[oi];
            /* Everything this loop needs was already resolved, per entry, in
             * the pass above: tfee/tsig/tweight and infs[]. It used to ask the
             * registry again -- pol_entry for the fee, pol_entry_info for the
             * depends, pol_entry_info a THIRD time for the sigops -- and each
             * of those is a linear scan of the node array, so the render was
             * three more O(n^2) passes on top of the one that built the data.
             * Measured on run 26 at 10,311 transactions, getblocktemplate took
             * 1,664 ms against Bitcoin Core's 53 ms at 78,342. */
            if (!have_inf[i]) continue;    /* can't price it -> don't offer it */
            unsigned long long fee = tfee[i];
            rj_val* t = rj_obj();
            { char* dhex = malloc(ents[i].len*2 + 1);
              if (dhex){ hex_of(dhex, ents[i].tx, ents[i].len);
                         rj_obj_set(t, "data", rj_str(dhex)); free(dhex); } }
            { char hx[65]; hex_rev(hx, ents[i].txid, 32); rj_obj_set(t, "txid", rj_str(hx)); }
            { u8 wt[32]; char hx[65];
              int is_segwit = ents[i].len > 5 && ents[i].tx[4] == 0x00 && ents[i].tx[5] == 0x01;
              if (is_segwit) sha256d(wt, ents[i].tx, ents[i].len); else memcpy(wt, ents[i].txid, 32);
              hex_rev(hx, wt, 32); rj_obj_set(t, "hash", rj_str(hx)); }
            { rj_val* dep = rj_arr();
              const mp_entry_info* pi = &infs[i];          /* from the pass above */
              for (int k = 0; k < pi->n_depends; k++){
                  long pj; GBT_POS_FIND(pi->depends[k], pj);   /* O(1), was a scan of every earlier entry */
                  if (pj >= 0 && pj < oi) rj_arr_push(dep, rj_numf("%ld", pj + 1));
              }
              rj_obj_set(t, "depends", dep); }
            rj_obj_set(t, "fee", rj_numf("%llu", fee));
            fees_total += fee;
            /* exact BIP141 cost stamped at accept time (tx_accept.c);
             * legacy-x4 lower bound only if the stamp is absent */
            /* tsig[] and tweight[] were computed by the pass above with
             * exactly this logic (stamped BIP141 cost, else the legacy x4
             * bound; tx_walk weight, else len*4). */
            rj_obj_set(t, "sigops", rj_numf("%ld", tsig[i]));
            rj_obj_set(t, "weight", rj_numf("%ld", tweight[i]));
            rj_arr_push(txs, t);
        }
        #undef GBT_POS_FIND
        if (g_gbt_mph.unlock) g_gbt_mph.unlock();
    }
    rj_obj_set(o, "transactions", txs);
    /* Core's getmininginfo reports currentblocktx/currentblockweight from the
     * LAST BLOCK TEMPLATE assembled, and omits both until one exists. Record
     * them here, which is the only place a template is built. */
    g_last_tmpl_tx = (long)txs->nitems;
    g_last_tmpl_weight = (long)g_tmpl_used_w;
    g_last_tmpl_seen = 1;

    rj_obj_set(o, "coinbaseaux", rj_obj());
    rj_obj_set(o, "coinbasevalue", rj_numf("%llu", (unsigned long long)gbs_subsidy(height) + fees_total));
    { char hx[65]; target_hex(bits, hx); rj_obj_set(o, "target", rj_str(hx)); }
    rj_obj_set(o, "mintime", rj_numf("%ld", mintime));
    { rj_val* mut = rj_arr();
      rj_arr_push(mut, rj_str("time")); rj_arr_push(mut, rj_str("transactions"));
      rj_arr_push(mut, rj_str("prevblock"));
      rj_obj_set(o, "mutable", mut); }
    rj_obj_set(o, "noncerange", rj_str("00000000ffffffff"));
    rj_obj_set(o, "sigoplimit", rj_numf("%d", 80000));
    rj_obj_set(o, "sizelimit", rj_numf("%d", 4000000));
    rj_obj_set(o, "weightlimit", rj_numf("%d", 4000000));
    rj_obj_set(o, "curtime", rj_numf("%ld", curtime));
    { char bx[9]; snprintf(bx, sizeof bx, "%08x", bits); rj_obj_set(o, "bits", rj_str(bx)); }
    rj_obj_set(o, "height", rj_numf("%ld", height));

    /* default_witness_commitment: BIP141 -- wtxid merkle root with the
     * coinbase's wtxid as 32 zero bytes, committed with a zero nonce:
     * OP_RETURN 0x24 aa21a9ed sha256d(root || 0x00*32). Recomputed over the
     * template's own tx order. */
    { u8 (*leaves)[32] = malloc(32u * (unsigned)(txs->nitems + 1));
      if (leaves){
          memset(leaves[0], 0, 32);
          for (unsigned long i = 0; i < txs->nitems; i++){
              const char* hh = rj_obj_get(txs->items[i], "hash")->str;
              for (int b = 0; b < 32; b++){
                  unsigned hv; sscanf(hh + 2*b, "%2x", &hv);
                  leaves[i+1][31-b] = (u8)hv;              /* display -> wire */
              }
          }
          unsigned long cnt = txs->nitems + 1;
          while (cnt > 1){
              unsigned long w2 = 0;
              for (unsigned long i = 0; i < cnt; i += 2){
                  u8 pair[64];
                  memcpy(pair, leaves[i], 32);
                  memcpy(pair + 32, leaves[i + 1 < cnt ? i + 1 : i], 32);
                  sha256d(leaves[w2++], pair, 64);
              }
              cnt = w2;
          }
          u8 pair[64], commit[32];
          memcpy(pair, leaves[0], 32); memset(pair + 32, 0, 32);   /* nonce 0 */
          sha256d(commit, pair, 64);
          char spk[13 + 64 + 1];
          memcpy(spk, "6a24aa21a9ed", 12);
          hex_of(spk + 12, commit, 32);
          rj_obj_set(o, "default_witness_commitment", rj_str(spk));
          free(leaves);
      } }

    *res = o;
    return 1;
}

static int cmd_getbestblockhash(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    u8 rec[48];
    if (tip < 0 || !read_idx_rec(tip, rec)){ *ec = -1; *em = "Block not available"; return 0; }
    char hx[65]; hex_rev(hx, rec, 32); *res = rj_str(hx); return 1;
}
/* getchaintips: Core lists the active tip plus any known side-branch tips.
 * This node does not persist non-active tips (reorg candidates are dropped
 * once the best chain is chosen), so we report exactly the active tip -- which
 * is Core's output for a node with no stored forks (the common case). */
static int cmd_getchaintips(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    u8 rec[48];
    if (tip < 0 || !read_idx_rec(tip, rec)){ *ec = -1; *em = "Block not available"; return 0; }
    rj_val* arr = rj_arr();
    rj_val* o = rj_obj();
    rj_obj_set(o, "height", rj_numf("%ld", tip));
    char hx[65]; hex_rev(hx, rec, 32); rj_obj_set(o, "hash", rj_str(hx));
    rj_obj_set(o, "branchlen", rj_numf("%d", 0));
    rj_obj_set(o, "status", rj_str("active"));
    rj_arr_push(arr, o);
    *res = arr;
    return 1;
}
static int cmd_getblockhash(const rj_val* params, rj_val** res, long* ec, const char** em){
    long long h; if (!rpc_param_i64(params, 0, &h, ec, em)) return 0;
    long tip = refresh();
    if (h < 0 || h > tip){ *ec = -8; *em = "Block height out of range"; return 0; }
    u8 rec[48];
    if (!read_idx_rec((long)h, rec) || !rec_present(rec)){ *ec = -1; *em = "Block not available"; return 0; }
    char hx[65]; hex_rev(hx, rec, 32); *res = rj_str(hx); return 1;
}
static int cmd_getblockheader(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh(); long h;
    /* Core type-checks EVERY argument before running the body, and the LOWEST
     * position that fails its type wins -- measured against v31.1, 2026-09-15:
     *   getblockheader 5 5        -> Position 1 (blockhash)
     *   getblockheader <bad hash> 5 -> Position 2 (verbose), NOT the hash
     * A bad hash VALUE is a body error and loses to a type error anywhere. So
     * both type checks run first, in position order, and lookup_block_param --
     * which does the value work -- runs after. (Its own type refusal comes from
     * the shared rpc_param_str, which cannot name a position; the explicit
     * check below is what produces Core's message for this method.) */
    rj_typeerrs te; rj_typeerr_init(&te);
    if (param_present(params, 0) && params->items[0]->typ != RJ_STR)
        rj_typeerr_add(&te, 1, "blockhash", params->items[0], "string");
    if (param_present(params, 1) && params->items[1]->typ != RJ_BOOL)
        rj_typeerr_add(&te, 2, "verbose", params->items[1], "bool");
    if (rj_typeerr_fail(&te, ec, em)) return 0;
    int verbose = param_present(params, 1) ? params->items[1]->str[0] == '1' : 1;
    if (!lookup_block_param(params, 0, 1, &h, ec, em)) return 0;
    if (!verbose){
        u8 hdr[80];
        if (read_block_prefix(h, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
        char hx[161]; hex_of(hx, hdr, 80); *res = rj_str(hx); return 1;
    }
    return header_json(h, tip, res, ec, em);
}
static int cmd_getblock(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh(); long h;
    if (!lookup_block_param(params, 0, 1, &h, ec, em)) return 0;
    int verbosity = param_verbosity(params, 1, 1, ec, em);
    if (verbosity == -999) return 0;
    long len = read_block(h);
    if (len == -3){ *ec = -1; *em = "Block not available (pruned data)"; return 0; }
    if (len < 0){ *ec = -1; *em = "Block not found on disk"; return 0; }
    const u8* blk = g_blockbuf; const u8* end = blk + len;
    if (verbosity <= 0){
        char* hx = malloc((size_t)len*2 + 1); if (!hx){ *ec = -7; *em = "out of memory"; return 0; }
        hex_of(hx, blk, (size_t)len); *res = rj_str(hx); free(hx); return 1;
    }
    rj_val* o;
    if (!header_json(h, tip, &o, ec, em)) return 0;
    u64 c; u64 ntx = read_varint(blk + 80, end, &c);
    const u8* p = blk + 80 + c;
    size_t stripped = 80 + c;
    rj_val* txs = rj_arr();
    rj_val* cb = NULL;
    /* per-tx fees for verbosity 2: prevout values from the block's undo file
     * (in block order, non-coinbase inputs). undo_n < 0 -> undo pruned/absent
     * (fee omitted, honest -- we keep only a recent-heights window). */
    static u64 undo_vals[600000]; long undo_n = -1, undo_cur = 0;
    if (verbosity >= 2) undo_n = undo_block_values(h, undo_vals, (long)(sizeof undo_vals / sizeof undo_vals[0]));
    /* verbosity 3 additionally carries Core's per-input `prevout`
     * {generated, height, value, scriptPubKey}. Same undo file the fees above
     * come from -- undo_block_load reads the WHOLE record (value, height,
     * coinbase flag and the scriptPubKey) where undo_block_values keeps only
     * the value.
     *
     * This file's own header used to explain verbosity 3 behaving like 2 as
     * "no undo data => no prevout/fee". That was never the reason -- the fees
     * beside it have always come from undo_<h>.dat. RPX-2 corrected the
     * comment and wired getRAWtransaction's verbosity 2; this wires getblock's
     * verbosity 3, from the same loader. */
    static undo_prevout_t undo_pv[600000]; long undo_pn = -1;
    u8* undo_raw = NULL;
    if (verbosity >= 3)
        undo_pn = undo_block_load(h, undo_pv, (long)(sizeof undo_pv / sizeof undo_pv[0]), &undo_raw);
    for (u64 i = 0; i < ntx; i++){
        txw_t w;
        if (!tx_walk(p, end, &w)){ rj_free(txs); if (cb) rj_free(cb); rj_free(o); *ec = -1; *em = "Block decode failed"; return 0; }
        stripped += w.stripped;
        if (i == 0){
            cb = rj_obj();
            rj_obj_set(cb, "version", rj_numf("%u", w.version));
            rj_obj_set(cb, "locktime", rj_numf("%u", w.locktime));
            const u8* q = w.vin; u64 cc; read_varint(q, end, &cc); q += cc; q += 36;
            u64 sl = read_varint(q, end, &cc); q += cc;
            rj_obj_set(cb, "sequence", rj_numf("%u", rd32(q + sl)));
            char* hx = malloc(sl*2 + 1); if (hx){ hex_of(hx, q, sl); rj_obj_set(cb, "coinbase", rj_str(hx)); free(hx); }
            if (w.wit){
                const u8* wq = w.wit; u64 ni = read_varint(wq, end, &cc); wq += cc;
                if (ni >= 1){ u64 il = read_varint(wq, end, &cc); wq += cc; char* wh = malloc(il*2+1); if (wh){ hex_of(wh, wq, il); rj_obj_set(cb, "witness", rj_str(wh)); free(wh); } }
            }
        }
        if (verbosity == 1){
            u8 txid[32]; u8* scratch = malloc(w.len); char hx[65];
            if (scratch){ tx_txid(txid, p, w.len, scratch, w.len); free(scratch); } else memset(txid, 0, 32);
            hex_rev(hx, txid, 32); rj_arr_push(txs, rj_str(hx));
        } else {
            long long in_total = -1;
            if (i > 0 && undo_n >= 0 && undo_cur + (long)w.n_in <= undo_n){
                in_total = 0;
                for (u64 k = 0; k < w.n_in; k++) in_total += (long long)undo_vals[undo_cur + k];
            }
            /* the prevout slice for THIS transaction starts where the fee
             * accumulator is, since both walk the same undo file in the same
             * block order -- read it before undo_cur advances below. */
            const undo_prevout_t* pv = NULL; long pvn = 0;
            if (verbosity >= 3 && i > 0 && undo_pn >= 0 &&
                undo_cur + (long)w.n_in <= undo_pn){
                pv = undo_pv + undo_cur; pvn = (long)w.n_in;
            }
            if (i > 0 && undo_n >= 0) undo_cur += (long)w.n_in;   /* advance even if capped */
            rj_arr_push(txs, tx_to_json_pv(p, &w, in_total, pv, pvn));
        }
        p += w.len;
    }
    free(undo_raw);                      /* verbosity 3 prevout backing store */
    rj_obj_set(o, "strippedsize", rj_numf("%zu", stripped));
    rj_obj_set(o, "size", rj_numf("%ld", len));
    rj_obj_set(o, "weight", rj_numf("%zu", stripped * 3 + (size_t)len));
    /* coinbase_tx: Core v31.1 DOES emit this, and we used to build it and
     * throw it away.
     *
     * The 2026-09-03 audit removed it on the reasoning that "Core's
     * blockToJSON has no such member" and that an additive field is what a
     * strict field-set diff would flag. The reasoning was sound; the premise
     * was not checked. Bitcoin Core v31.1 run on regtest returns coinbase_tx
     * at verbosity 1, 2 and 3, with exactly these five members -- version,
     * locktime, sequence, coinbase, witness -- which is the object built
     * above, unchanged.
     *
     * It survived a year as a wrong assumption because the parity register
     * compared method NAMES and nothing compared response shape. The
     * differential that would have caught it in either direction is
     * validation/rpc_field_parity.py; see docs/PARITY_RPC_FIELDS.md. */
    if (cb) rj_obj_set(o, "coinbase_tx", cb);
    rj_obj_set(o, "tx", txs);
    *res = o;
    return 1;
}
static long headers_height(long tip){
    struct stat sb;
    if (stat("headers.dat", &sb) == 0 && sb.st_size >= 112){
        long n = (long)(sb.st_size / 112) - 1;
        if (n > tip) return n;
    }
    return tip;
}
/* Total bytes of blk*.dat.
 *
 * This read the whole directory and stat()ed every file, EVERY call: 5,763
 * stat syscalls on a 716 GB archive, inside getblockchaininfo, under the RPC
 * execution lock. It was most of that call's 5 ms, and with execution
 * serialised it was most of what 32 concurrent callers waited on.
 *
 * The archive is append-only: blk files are written in order and only the
 * NEWEST one grows -- once the writer rolls over to the next, the previous is
 * immutable. So the sum of everything but the newest is cached, and the steady
 * state costs two stats: the newest file, and a probe for the next one having
 * appeared.
 *
 * Two escapes back to the full scan, because "append-only" stops being true:
 * with pruning enabled files are DELETED, and a reindex can truncate. Pruning
 * takes the slow path always; everything else revalidates on a timer, so any
 * drift is bounded by SOD_REVALIDATE_S rather than lasting until restart. */
#define SOD_REVALIDATE_S 300
static long long sod_full_scan(void){
    long long total = 0;
    DIR* d = opendir("."); if (!d) return 0;
    struct dirent* e;
    while ((e = readdir(d))){
        if (strncmp(e->d_name, "blk", 3) == 0 && strstr(e->d_name, ".dat")){
            struct stat sb; if (stat(e->d_name, &sb) == 0) total += sb.st_size;
        }
    }
    closedir(d);
    return total;
}
static long long size_on_disk(void){
    static long long prefix = -1;      /* bytes in files [0, newest)          */
    static long  newest = -1;          /* index of the file still being written */
    static time_t last_full = 0;
    time_t now = time(NULL);
    int pruning = (g_prune_mib != 0 || ST_PRUNE_H(CUR_ST) > 0);

    if (pruning) return sod_full_scan();          /* files can vanish */
    if (prefix < 0 || now - last_full >= SOD_REVALIDATE_S){
        /* full scan, and re-derive which file is newest */
        long long total = sod_full_scan();
        long n = 0;
        for (;;){
            char nm[32]; struct stat sb;
            snprintf(nm, sizeof nm, "blk%05ld.dat", n);
            if (stat(nm, &sb) != 0) break;
            n++;
        }
        if (n == 0) return total;
        newest = n - 1;
        struct stat sb; char lastnm[32];
        snprintf(lastnm, sizeof lastnm, "blk%05ld.dat", newest);
        prefix = (stat(lastnm, &sb) == 0) ? total - sb.st_size : total;
        last_full = now;
        return total;
    }
    /* steady state: has the writer rolled over? then fold the old newest in */
    for (;;){
        char nm[32]; struct stat sb;
        snprintf(nm, sizeof nm, "blk%05ld.dat", newest + 1);
        if (stat(nm, &sb) != 0) break;
        char cur[32]; struct stat cs;
        snprintf(cur, sizeof cur, "blk%05ld.dat", newest);
        if (stat(cur, &cs) == 0) prefix += cs.st_size;
        newest++;
    }
    char nm[32]; struct stat sb;
    snprintf(nm, sizeof nm, "blk%05ld.dat", newest);
    if (stat(nm, &sb) != 0) return sod_full_scan();
    return prefix + sb.st_size;
}
static int cmd_getblockchaininfo(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    u8 hdr[80]; if (read_block_prefix(tip, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u8 rec[48]; read_idx_rec(tip, rec);
    char hx[65];
    rj_val* o = rj_obj();
    rj_obj_set(o, "chain", rj_str(g_chain_name));
    rj_obj_set(o, "blocks", rj_numf("%ld", tip));
    long hh = headers_height(tip);
    rj_obj_set(o, "headers", rj_numf("%ld", hh));
    hex_rev(hx, rec, 32); rj_obj_set(o, "bestblockhash", rj_str(hx));
    u32 bits = rd32(hdr + 72);
    rj_obj_set(o, "bits", rj_strf("%08x", bits));
    target_hex(bits, hx); rj_obj_set(o, "target", rj_str(hx));
    rj_obj_set(o, "difficulty", rj_double(difficulty_of(bits)));
    u32 t = rd32(hdr + 68);
    rj_obj_set(o, "time", rj_numf("%u", t));
    rj_obj_set(o, "mediantime", rj_numf("%ld", median_time_past(tip)));
    double prog = hh >= 0 ? (double)(tip + 1) / (double)(hh + 1) : 1.0;
    if (prog > 1.0) prog = 1.0;
    rj_obj_set(o, "verificationprogress", rj_double(prog));
    rj_obj_set(o, "initialblockdownload", rj_bool((time_t)t < time(NULL) - g_maxtipage));   /* -maxtipage */
    u8 cw[16]; if (chainwork_at(tip, cw)){ chainwork_hex(cw, hx); rj_obj_set(o, "chainwork", rj_str(hx)); }
    rj_obj_set(o, "size_on_disk", rj_numf("%lld", size_on_disk()));
    int pruned = g_prune_mib != 0 || ST_PRUNE_H(CUR_ST) > 0;
    rj_obj_set(o, "pruned", rj_bool(pruned));
    if (pruned){
        rj_obj_set(o, "pruneheight", rj_numf("%d", ST_PRUNE_H(CUR_ST)));
        int automatic = g_prune_mib > 1;
        rj_obj_set(o, "automatic_pruning", rj_bool(automatic));
        if (automatic) rj_obj_set(o, "prune_target_size", rj_numf("%lld", (long long)g_prune_mib * 1024 * 1024));
    }
    rj_obj_set(o, "warnings", rj_arr());
    *res = o;
    return 1;
}

/* ==== the txid index (daemon/build_tx_index.c) ===========================
 * mmap'd read-only; absent is simply "no index", never an error. Records are
 * 20 bytes sorted by an 8-byte txid PREFIX, with a sparse index every 256th
 * record -- see the builder for why the key is truncated and why that is
 * exact rather than probabilistic: a lookup reads every record sharing the
 * prefix, pulls that transaction out of the archive, recomputes its txid and
 * compares all 32 bytes. A prefix collision costs one extra read and is then
 * rejected; it can never return the wrong transaction. */
#define TXI_HDR    48
#define TXI_REC    20
#define TXI_SPARSE 16

#include "daemon/index_runs.h"
/* 2026-09-16: the txid index is a SET of sorted runs (index_runs.h): the
 * legacy txindex.dat base plus every txindex.r<from>-<to>.dat the daemon
 * builds behind the applied height, during the sync and after it. A lookup
 * asks each run, then the tail. Refreshed before every lookup (at most one
 * directory scan per second), so a run committed by the trailing builder is
 * picked up without a restart -- the property the old "latch on success"
 * open had for the single base. */
/* ---- which optional indexes the node is CONFIGURED to keep (2026-09-19) --
 * Core builds and consults an index only when its option is set: without
 * -txindex, getrawtransaction answers from the mempool (or a given block) and
 * says "Use -txindex"; without -txospenderindex, gettxspendingprevout is
 * mempool-only; without -blockfilterindex, getblockfilter refuses; and
 * getindexinfo lists only the indexes that are enabled. This reader used to
 * decide from the FILES alone, so a node whose operator never asked for an
 * index still served -- and advertised -- whatever an earlier configuration
 * (or an unconditional tail, run 27's txospender) had left in the datadir.
 *
 * The daemon passes its configuration here at start-up. -1 = never told: a
 * standalone reader (bmc_rpcd) and the unit tests, where the files decide as
 * before. */
static int g_ix_txindex = -1, g_ix_txospender = -1, g_ix_bfilter = -1, g_ix_coinstats = -1, g_ix_addrindex = -1;
void rpc_chain_set_index_config(int txindex, int txospenderindex, int blockfilterindex, int coinstatsindex, int addrindex){
    g_ix_txindex = txindex ? 1 : 0; g_ix_txospender = txospenderindex ? 1 : 0; g_ix_bfilter = blockfilterindex ? 1 : 0;
    g_ix_coinstats = coinstatsindex ? 1 : 0; g_ix_addrindex = addrindex ? 1 : 0;
}
static int ix_on(int v){ return v != 0; }        /* configured on, or not told */
static irunset_t g_txi_runs;
static int g_txi_runs_init;
static void txi_open(void){
    if (!g_txi_runs_init){ irs_init(&g_txi_runs, "txindex", "BMCTXIDX", TXI_REC, TXI_SPARSE); g_txi_runs_init = 1; }
    irs_refresh(&g_txi_runs);
}
static void txi_tail_refresh(void);
static const u8* g_txi_tail;
static int  txi_have(void){ if (!ix_on(g_ix_txindex)) return 0; txi_open(); if (g_txi_runs.n > 0) return 1; txi_tail_refresh(); return g_txi_tail != NULL; }
static long txi_runs_to(void){ txi_open(); long t = -1; for (int i = 0; i < g_txi_runs.n; i++) if (g_txi_runs.r[i].to > t) t = g_txi_runs.r[i].to; return t; }
static long txi_runs_from(void){ txi_open(); long f = -1; for (int i = 0; i < g_txi_runs.n; i++) if (f < 0 || g_txi_runs.r[i].from < f) f = g_txi_runs.r[i].from; return f; }

/* ---- the incremental tail (daemon/tx_index_tail.c) ----------------------
 * Unsorted records in the same 20-byte layout, appended by the download
 * worker for every block after the base index's to_height. Remapped when
 * the file grows, so lookups see newly accepted blocks without a restart.
 * The scan is linear, which is fine because the tail only ever holds the
 * span since the last offline rebuild. */
static u64 g_txi_tail_sz;          /* mapped size, bytes (whole records only) */
static long g_txi_tail_maxh = -1;  /* highest height among mapped records */

/* RPX-8 (audit 2026-09-03): the txid-index coverage range, in one place.
 *
 * getrawtransaction and gettxoutproof both tell a caller which heights the
 * index covers when a lookup misses, because "not found" from a PARTIAL index
 * is a different fact from "not found" on the whole chain. The two had
 * near-identical copies of the range computation and the wording, which is a
 * maintenance hazard exactly where accuracy matters: if the coverage rule ever
 * changed, one of them would keep saying the old thing.
 *
 * The MESSAGES stay separate -- Core's texts differ between the two methods
 * and each names what its own caller should do -- but the range they quote now
 * comes from one function. */
static long txi_coverage_to(void){
    long rt = txi_runs_to();
    return g_txi_tail_maxh > rt ? g_txi_tail_maxh : rt;
}


static void txi_tail_refresh(void){
    struct stat sb;
    if (stat("txindex.tail", &sb) != 0 || (u64)sb.st_size < TXI_REC) return;
    u64 sz = (u64)sb.st_size - (u64)sb.st_size % TXI_REC;  /* ignore a torn last record */
    if (g_txi_tail && sz == g_txi_tail_sz) return;
    u64 scanned = g_txi_tail ? g_txi_tail_sz : 0;
    if (g_txi_tail){ munmap((void*)g_txi_tail, (size_t)g_txi_tail_sz); g_txi_tail = NULL; g_txi_tail_sz = 0; }
    int fd = open("txindex.tail", O_RDONLY);
    if (fd < 0) return;
    void* m = mmap(NULL, (size_t)sz, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return;
    g_txi_tail = m; g_txi_tail_sz = sz;
    if (scanned > sz){ scanned = 0; g_txi_tail_maxh = -1; }  /* shrank: folded into a rebuilt base */
    for (u64 o = scanned; o + TXI_REC <= sz; o += TXI_REC){
        const u8* r = g_txi_tail + o;
        u32 hh = 0; for (int b = 0; b < 4; b++) hh |= (u32)r[8+b] << (8*b);
        if ((long)hh > g_txi_tail_maxh) g_txi_tail_maxh = (long)hh;
    }
}

/* VERIFY one candidate record: read the transaction out of the archive and
 * compare the FULL txid. This is what makes an 8-byte key exact -- and what
 * makes the unsorted tail crash-safe: a torn or stale record simply fails
 * here instead of ever being returned as a wrong answer. */
static int txi_verify_rec(const u8* r, const u8 txid_wire[32],
                          long* h_out, u32* off_out, u32* len_out){
    static u8 txbuf[4u << 20];
    static u8 scratch[4u << 20];
    u32 hh = 0, off = 0, ln = 0;
    for (int b = 0; b < 4; b++) hh  |= (u32)r[8+b]  << (8*b);
    for (int b = 0; b < 4; b++) off |= (u32)r[12+b] << (8*b);
    for (int b = 0; b < 4; b++) ln  |= (u32)r[16+b] << (8*b);
    long blen = read_block((long)hh);
    if (blen < 81 || (u64)off + ln > (u64)blen || ln > sizeof txbuf) return 0;
    memcpy(txbuf, g_blockbuf + off, ln);
    u8 got[32];
    if (tx_txid(got, txbuf, ln, scratch, sizeof scratch) != 1) return 0;
    if (memcmp(got, txid_wire, 32)) return 0;          /* prefix collision */
    *h_out = (long)hh; *off_out = off; *len_out = ln;
    return 1;
}

/* Look a WIRE-order txid up. Returns 1 and fills height/offset/len, or 0. */
static int txi_lookup(const u8 txid_wire[32], long* h_out, u32* off_out, u32* len_out){
    if (!ix_on(g_ix_txindex)) return 0;          /* txindex=0: no index, whatever the datadir holds */
    txi_open();
    for (int ri = 0; ri < g_txi_runs.n; ri++){
        const irun_t* run = &g_txi_runs.r[ri];
        if (!run->n) continue;
        const u8* recs = run->map + TXI_HDR;
        const u8* sp   = run->map + run->sparse_off;
        /* binary search the sparse index for the last sample <= our prefix */
        u64 lo = 0, hi = run->nsparse ? run->nsparse - 1 : 0, start = 0;
        while (run->nsparse && lo <= hi){
            u64 mid = lo + (hi - lo) / 2;
            int c = memcmp(sp + mid * TXI_SPARSE, txid_wire, 8);
            if (c <= 0){
                u64 off = 0;
                for (int i = 0; i < 8; i++) off |= (u64)sp[mid*TXI_SPARSE + 8 + i] << (8*i);
                start = (off - TXI_HDR) / TXI_REC;
                lo = mid + 1;
            } else {
                if (mid == 0) break;
                hi = mid - 1;
            }
        }
        for (u64 i = start; i < run->n; i++){
            const u8* r = recs + i * TXI_REC;
            int c = memcmp(r, txid_wire, 8);
            if (c < 0) continue;
            if (c > 0) break;                  /* past the prefix group */
            if (txi_verify_rec(r, txid_wire, h_out, off_out, len_out)) return 1;
        }
    }
    /* not in any run -- the tail covers the heights after them */
    txi_tail_refresh();
    for (u64 o = 0; g_txi_tail && o + TXI_REC <= g_txi_tail_sz; o += TXI_REC){
        const u8* r = g_txi_tail + o;
        if (memcmp(r, txid_wire, 8)) continue;
        if (txi_verify_rec(r, txid_wire, h_out, off_out, len_out)) return 1;
    }
    return 0;
}


/* ---- txo-spender index reader (Core's -txospenderindex; 2026-09-01) -------
 * Base file + unsorted tail, exactly the txid index's shape (see
 * daemon/txosp_format.h). Every candidate is VERIFIED against the archive:
 * the spending transaction is read at the recorded location and must carry
 * the FULL outpoint among its inputs. */
#include "daemon/txosp_format.h"
static irunset_t g_tsp_runs; static int g_tsp_runs_init;
static void tsp_open(void){
    if (!g_tsp_runs_init){ irs_init(&g_tsp_runs, "txospender", TSP_MAGIC, TSP_REC, TSP_SPARSE); g_tsp_runs_init = 1; }
    irs_refresh(&g_tsp_runs);
}
static void tsp_tail_refresh(void);
static const u8* g_tsp_tail;
static int  tsp_have(void){ if (!ix_on(g_ix_txospender)) return 0; tsp_open(); if (g_tsp_runs.n > 0) return 1; tsp_tail_refresh(); return g_tsp_tail != NULL; }
static u64 g_tsp_tail_sz;
/* 2026-09-19: remap only. This also scanned every record for the highest
 * height -- from byte 0, every time the file grew -- for getindexinfo alone.
 * Run 27's txospender tail reached 61.6 GB during IBD and grew every block,
 * so each getindexinfo read 61 GB under the RPC execution lock; uptime took
 * 44 s behind it. getindexinfo now reads the tail's last record instead
 * (gii_tail_last), and nothing else here wanted the maximum. */
static void tsp_tail_refresh(void){
    struct stat sb;
    if (stat(TSP_TAIL_FILE, &sb) != 0 || (u64)sb.st_size < TSP_REC){ if (g_tsp_tail){ munmap((void*)g_tsp_tail, (size_t)g_tsp_tail_sz); g_tsp_tail = NULL; g_tsp_tail_sz = 0; } return; }
    u64 sz = (u64)sb.st_size - (u64)sb.st_size % TSP_REC;
    if (g_tsp_tail && sz == g_tsp_tail_sz) return;
    if (g_tsp_tail){ munmap((void*)g_tsp_tail, (size_t)g_tsp_tail_sz); g_tsp_tail = NULL; g_tsp_tail_sz = 0; }
    int fd = open(TSP_TAIL_FILE, O_RDONLY); if (fd < 0) return;
    void* m = mmap(NULL, (size_t)sz, PROT_READ, MAP_SHARED, fd, 0); close(fd);
    if (m == MAP_FAILED) return;
    g_tsp_tail = m; g_tsp_tail_sz = sz;
}
/* verify: the tx at (height, off, len) spends (txid_wire, vout); on success
 * fills the spender's txid, height, and optionally copies the tx bytes */
static int tsp_verify_rec(const u8* r, const u8 txid_wire[32], u32 vout, u8 spender[32], long* h_out, u8* txout, long txcap, long* txlen_out){
    static u8 scratch[4u << 20];
    tsp_rec rec; tsp_unpack(&rec, r);
    if (rec.vout != vout) return 0;
    long blen = read_block((long)rec.height);
    if (blen < 81 || (u64)rec.offset + rec.len > (u64)blen || rec.len < 10) return 0;
    const u8* tx = g_blockbuf + rec.offset; const u8* end = tx + rec.len;
    const u8* q = tx + 4; if (q + 2 <= end && q[0] == 0 && q[1] == 1) q += 2;
    uint64_t cc = 0; u64 nin = tsp_rd_varint(q, end, &cc); if (!cc) return 0; q += cc;   /* uint64_t: tsp_rd_varint's out-param type */
    int hit = 0;
    for (u64 i = 0; i < nin && q + 36 <= end; i++){
        u32 vo = (u32)q[32] | ((u32)q[33] << 8) | ((u32)q[34] << 16) | ((u32)q[35] << 24);
        if (vo == vout && !memcmp(q, txid_wire, 32)){ hit = 1; break; }
        q += 36; u64 sl = tsp_rd_varint(q, end, &cc); if (!cc) return 0; q += cc + sl + 4;
    }
    if (!hit) return 0;
    if (tx_txid(spender, tx, rec.len, scratch, sizeof scratch) != 1) return 0;
    *h_out = (long)rec.height;
    if (txout && txlen_out){ if ((long)rec.len <= txcap){ memcpy(txout, tx, rec.len); *txlen_out = (long)rec.len; } else *txlen_out = -1; }
    return 1;
}
int rpc_chain_txospender_available(void){ return tsp_have(); }
/* 1 = spent by `spender` (wire txid) in block `height` whose hash is filled;
 * 0 = no confirmed spend known (unspent, or beyond the index's coverage). */
int rpc_chain_txospender_lookup(const unsigned char txid_wire[32], unsigned vout, unsigned char spender_wire[32],
                                long* height_out, unsigned char blockhash_wire[32], unsigned char* txout, long txcap, long* txlen_out){
    if (!ix_on(g_ix_txospender)) return 0;             /* txospenderindex=0 */
    (void)refresh();                                   /* the tail may name blocks newer than our cached tip */
    tsp_open();
    for (int ri = 0; ri < g_tsp_runs.n; ri++){
        const irun_t* run = &g_tsp_runs.r[ri];
        if (!run->n) continue;
        const u8* recs = run->map + TSP_HDR; const u8* sp = run->map + run->sparse_off;
        u64 lo = 0, hi = run->nsparse ? run->nsparse - 1 : 0, start = 0;
        while (run->nsparse && lo <= hi){
            u64 mid = lo + (hi - lo) / 2; const u8* e = sp + mid * TSP_SPARSE;
            u32 ev = (u32)e[12] | ((u32)e[13] << 8) | ((u32)e[14] << 16) | ((u32)e[15] << 24);
            int c = tsp_key_cmp(e, ev, txid_wire, vout);
            if (c <= 0){ u64 off = 0; for (int i = 0; i < 8; i++) off |= (u64)e[16+i] << (8*i); start = (off - TSP_HDR) / TSP_REC; lo = mid + 1; }
            else { if (mid == 0) break; hi = mid - 1; }
        }
        for (u64 i = start; i < run->n; i++){
            const u8* r = recs + i * TSP_REC;
            u32 rv = (u32)r[12] | ((u32)r[13] << 8) | ((u32)r[14] << 16) | ((u32)r[15] << 24);
            int c = tsp_key_cmp(r, rv, txid_wire, vout);
            if (c < 0) continue;
            if (c > 0) break;
            if (tsp_verify_rec(r, txid_wire, vout, spender_wire, height_out, txout, txcap, txlen_out)){
                u8 rec[48]; if (read_idx_rec(*height_out, rec)) memcpy(blockhash_wire, rec, 32); else memset(blockhash_wire, 0, 32);
                return 1; }
        }
    }
    tsp_tail_refresh();
    for (u64 o = 0; g_tsp_tail && o + TSP_REC <= g_tsp_tail_sz; o += TSP_REC){
        const u8* r = g_tsp_tail + o;
        if (memcmp(r, txid_wire, 12)) continue;
        if (tsp_verify_rec(r, txid_wire, vout, spender_wire, height_out, txout, txcap, txlen_out)){
            u8 rec[48]; if (read_idx_rec(*height_out, rec)) memcpy(blockhash_wire, rec, 32); else memset(blockhash_wire, 0, 32);
            return 1; }
    }
    return 0;
}

static const char GENESIS_CB_TXID[] = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
static int cmd_getrawtransaction(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh();
    const char* txs = rpc_param_str(params, 0, ec, em); if (!txs) return 0;
    u8 want_disp[32]; if (!parse_hash_param(txs, 1, want_disp, ec, em)) return 0;
    if (strcmp(txs, GENESIS_CB_TXID) == 0){ *ec = -5; *em = "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved"; return 0; }
    int verbosity = param_verbosity(params, 1, 0, ec, em);
    if (verbosity == -999) return 0;
    /* The transaction is located either from the caller's blockhash or from
     * the txid index; from there ONE render path serves both, so the two
     * cannot drift in what they emit. `known_off` is the index's byte offset
     * (-1 when we must scan the block for it). */
    long h = -1, known_off = -1;
    static char bs_buf[65];
    const char* bs = NULL;
    const int have_blockhash = param_present(params, 2);
    if (!have_blockhash){
        u8 want_wire[32];
        for (int i = 0; i < 32; i++) want_wire[i] = want_disp[31-i];

        /* ---- MEMPOOL FIRST, which is Core's order --------------------------
         * Core's GetTransaction consults the mempool before the txid index
         * whenever no blockhash was given, and its own help says so: "By
         * default, this call only returns a transaction if it is in the
         * mempool." This node consulted only the OFFLINE index, so an
         * unconfirmed transaction -- the common case the call is reached for
         * -- came back as -5 "No such transaction", with a message about
         * index coverage that was true and beside the point.
         *
         * rpc_node_mempool_rawtx copies the bytes out under the pool lock;
         * nothing here holds a live pointer into shared memory that an
         * eviction could move. */
        {
            static u8 mraw[RPC_TXSUBMIT_MAX];
            long mlen = rpc_node_mempool_rawtx(want_wire, mraw, sizeof mraw);
            if (mlen > 0){
                if (verbosity <= 0){
                    char* hx = malloc((size_t)mlen*2 + 1);
                    if (!hx){ *ec = -7; *em = "out of memory"; return 0; }
                    hex_of(hx, mraw, (size_t)mlen);
                    *res = rj_str(hx); free(hx); return 1;
                }
                txw_t w;
                if (!tx_walk(mraw, mraw + mlen, &w)){
                    *ec = -5; *em = "Mempool transaction could not be parsed"; return 0; }
                /* An unconfirmed transaction has NO block, so Core emits no
                 * blockhash, no confirmations and no time/blocktime -- and no
                 * in_active_chain either, which is documented as "only
                 * present with explicit blockhash argument". Filling any of
                 * them in would assert a confirmation that has not happened.
                 *
                 * No `vsize_adjusted` either. This comment used to call it a
                 * known omission, but that was the v31.99 development oracle
                 * talking: v31.1's getrawtransaction has no such field
                 * (checked in its rpc/ tree, 2026-09-18), so leaving it out
                 * is parity, not a gap. */
                *res = tx_to_json(mraw, &w, -1);
                return 1;
            }
        }

        long th; u32 toff, tlen;
        if (txi_lookup(want_wire, &th, &toff, &tlen)){
            h = th; known_off = (long)toff; (void)tlen;
            u8 rec[48];
            if (read_idx_rec(h, rec)){ hex_rev(bs_buf, rec, 32); bs = bs_buf; }
        } else {
            txi_open();
            static char nomsg[288];
            if (txi_have()){
                /* An index EXISTS and does not hold it. Say which heights it
                 * covers: "not found" from a PARTIAL index is a different
                 * fact from "not found" on the whole chain, and a caller who
                 * cannot tell them apart will draw the wrong conclusion. */
                long cov_to = txi_coverage_to();     /* RPX-8 */
                snprintf(nomsg, sizeof nomsg,
                         "No such mempool or blockchain transaction. The txid index "
                         "covers heights %ld..%ld; if the transaction is outside that "
                         "range, rebuild the index over it or pass the block hash. "
                         "Use gettransaction for wallet transactions.",
                         txi_runs_from(), cov_to);
                *ec = -5; *em = nomsg; return 0;
            }
            *ec = -5; *em = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.";
            return 0;
        }
    } else {
        bs = rpc_param_str(params, 2, ec, em); if (!bs) return 0;
        u8 bdisp[32]; if (!parse_hash_param(bs, 3, bdisp, ec, em)) return 0;
        if (!height_by_hash(bdisp, &h)){ *ec = -5; *em = "Block hash not found"; return 0; }
    }
    if (!bs){ *ec = -1; *em = "Block not available"; return 0; }
    long len = read_block(h);
    if (len < 0){ *ec = -1; *em = "Block not available"; return 0; }
    const u8* blk = g_blockbuf; const u8* end = blk + len;
    u8 want[32]; for (int i = 0; i < 32; i++) want[i] = want_disp[31-i];
    u64 c; u64 ntx = read_varint(blk + 80, end, &c);
    const u8* p = blk + 80 + c;
    u64 pre = 0;                      /* transactions before p in the block */
    if (known_off > 0 && known_off < len){
        /* the index already knows where it is: start there and stop after
         * one transaction. The txid is still recomputed and compared below,
         * so a stale or wrong index entry cannot return the wrong tx.
         * 2026-09-08: the transaction's INDEX in the block still has to be
         * real -- the undo slice below is located by it, and with i == 0 for
         * every indexed lookup the prevouts were skipped as if the tx were
         * the coinbase (production's Esplora facade showed fee 0 on every
         * /tx). One pass over the block up to the offset, as the block-hash
         * path does over the whole block. */
        const u8* q = blk + 80 + c;
        while (q < blk + known_off){ txw_t kw; if (!tx_walk(q, end, &kw)) break; pre++; q += kw.len; }
        p = blk + known_off;
        ntx = 1;
    }
    for (u64 i0 = 0; i0 < ntx; i0++){
        const u64 i = i0 + pre;       /* the transaction's index in the block */
        txw_t w;
        if (!tx_walk(p, end, &w)) break;
        u8 txid[32]; u8* scratch = malloc(w.len);
        if (!scratch){ *ec = -7; *em = "out of memory"; return 0; }
        tx_txid(txid, p, w.len, scratch, w.len); free(scratch);
        if (memcmp(txid, want, 32) == 0){
            if (verbosity <= 0){
                char* hx = malloc(w.len*2 + 1); if (!hx){ *ec = -7; *em = "out of memory"; return 0; }
                hex_of(hx, p, w.len); *res = rj_str(hx); free(hx); return 1;
            }
            rj_val* o = rj_obj();
            /* Core: "only present with explicit blockhash argument". It used
             * to be emitted unconditionally here, which the mempool path
             * above makes plainly wrong -- an unconfirmed transaction is in
             * no block at all. */
            if (have_blockhash) rj_obj_set(o, "in_active_chain", rj_bool(1));
            /* RPX-2: verbosity 2 adds `fee` and per-input `prevout`, from the
             * block's undo file -- the same source getblock v2 already uses
             * for its fees. Verbosity 1 stays exactly as it was: in_total -1
             * and no prevouts, which is Core's verbosity-1 shape.
             *
             * When the undo file is absent (pruned, or below the retention
             * window) the fields are simply omitted, which is also what Core
             * does when it cannot reach the undo data. */
            long long rt_in_total = -1;
            /* 2026-09-08: this was a 1,024-entry stack array, and undo_block_load
             * refuses a run it cannot hold whole ("trailing garbage"), so every
             * mainnet block with more than 1,024 inputs -- all of them -- lost
             * its fee and prevouts on this route while getblock verbosity 3,
             * with the 600,000-entry table below, kept them. Same table size;
             * the handlers run under the server's execution lock. */
            static undo_prevout_t rt_pv[600000];
            long rt_npv = 0;
            u8* rt_raw = NULL;
            if (verbosity >= 2){   /* the mempool path returned far above */
                long all = undo_block_load(h, rt_pv, (long)(sizeof rt_pv / sizeof rt_pv[0]), &rt_raw);
                if (all > 0){
                    /* the undo file covers the WHOLE block in input order, so
                     * this transaction's slice starts after every earlier
                     * non-coinbase input. Walk the block again to find it --
                     * the same walk that located the transaction, so the cost
                     * is one extra pass over a block already in memory. */
                    /* 2026-09-08: the walk started at the block HEADER, so
                     * tx_walk failed on the first step and `skip` stayed 0:
                     * every transaction past the first got the first
                     * transaction's prevouts (and fee) on both paths. Start
                     * at the first transaction. */
                    long skip = 0; const u8* q = blk + 80 + c;
                    for (u64 k = 0; k < i; k++){
                        txw_t kw;
                        if (!tx_walk(q, end, &kw)) break;
                        if (k > 0) skip += (long)kw.n_in;      /* tx 0 is the coinbase */
                        q += kw.len;
                    }
                    if (i > 0 && skip + (long)w.n_in <= all){
                        rt_npv = (long)w.n_in;
                        memmove(rt_pv, rt_pv + skip, (size_t)rt_npv * sizeof rt_pv[0]);
                        rt_in_total = 0;
                        for (long k = 0; k < rt_npv; k++) rt_in_total += (long long)rt_pv[k].value;
                    }
                }
            }
            rj_val* t = tx_to_json_pv(p, &w, rt_in_total,
                                      rt_npv ? rt_pv : NULL, rt_npv);
            free(rt_raw);
            /* splice TxToUniv's members into our object to keep Core's order */
            for (size_t k = 0; k < t->nmembers; k++){ rj_obj_set(o, t->members[k].key, t->members[k].val); t->members[k].val = NULL; }
            for (size_t k = 0; k < t->nmembers; k++) free(t->members[k].key);
            free(t->members); t->nmembers = 0; t->members = NULL; rj_free(t);
            rj_obj_set(o, "blockhash", rj_str(bs));
            rj_obj_set(o, "confirmations", rj_numf("%ld", h > tip ? -1L : tip - h + 1));   /* -1 above the connected tip (3.1) */
            u8 hdr[80]; read_block_prefix(h, hdr, 80);
            rj_obj_set(o, "time", rj_numf("%u", rd32(hdr + 68)));
            rj_obj_set(o, "blocktime", rj_numf("%u", rd32(hdr + 68)));
            *res = o; return 1;
        }
        p += w.len;
    }
    *ec = -5; *em = "No such transaction found in the provided block. Use gettransaction for wallet transactions.";
    return 0;
}
static int cmd_uptime(rj_val** res){
    if (g_start == 0) g_start = time(NULL);
    *res = rj_numf("%lld", (long long)(time(NULL) - g_start)); return 1;
}
static int cmd_stop(rj_val** res){
    *res = rj_str("Bitcoin Machine Code stopping");
    g_stop_fn();
    return 1;
}


/* ==== gettxoutproof / verifytxoutproof: BIP37 partial merkle tree ==========
 * Core: CMerkleBlock (blockencodings/merkleblock). A proof is the 80-byte
 * header || CPartialMerkleTree{ uint32 nTx, compactsize(nHashes), hashes,
 * compactsize(nBytes), flag bytes (LSB-first bits) }. Pure block data; no
 * txindex/mempool needed, so like getrawtransaction we REQUIRE the blockhash
 * param (Core's own behaviour with no txindex). */
static u32 pmt_width(u32 ntx, int height){ return (ntx + (1u<<height) - 1) >> height; }
static int pmt_height(u32 ntx){ int h=0; while (pmt_width(ntx,h) > 1) h++; return h; }

static void pmt_calc_hash(const u8 (*leaves)[32], u32 ntx, int height, u32 pos, u8 out[32]){
    if (height == 0){ memcpy(out, leaves[pos], 32); return; }
    u8 left[32], right[32];
    pmt_calc_hash(leaves, ntx, height-1, pos*2, left);
    if (pos*2u+1u < pmt_width(ntx, height-1)) pmt_calc_hash(leaves, ntx, height-1, pos*2+1, right);
    else memcpy(right, left, 32);
    u8 cat[64]; memcpy(cat, left, 32); memcpy(cat+32, right, 32);
    sha256d(out, cat, 64);
}

typedef struct { const u8 (*leaves)[32]; const u8* match; u32 ntx;
                 u8 (*hashes)[32]; u32 nhash; u8* bits; u32 nbits; } pmt_build_t;
static int pmt_match_sub(const u8* match, u32 ntx, int height, u32 pos){
    u64 lo = (u64)pos << height, hi = lo + ((u64)1<<height); if (hi>ntx) hi=ntx;
    for (u64 i=lo;i<hi;i++) { if (match[i]) return 1; } return 0;
}
static void pmt_build(pmt_build_t* b, int height, u32 pos){
    int parent = pmt_match_sub(b->match, b->ntx, height, pos);
    b->bits[b->nbits++] = (u8)parent;
    if (height==0 || !parent){
        pmt_calc_hash(b->leaves, b->ntx, height, pos, b->hashes[b->nhash++]);
    } else {
        pmt_build(b, height-1, pos*2);
        if (pos*2u+1u < pmt_width(b->ntx, height-1)) pmt_build(b, height-1, pos*2+1);
    }
}

typedef struct { const u8 (*hashes)[32]; u32 nhash, hpos; const u8* bits; u32 nbits, bpos;
                 u8 (*matched)[32]; u32 nmatched; int bad; } pmt_extract_t;
static void pmt_extract(pmt_extract_t* e, u32 ntx, int height, u32 pos, u8 out[32]){
    if (e->bpos >= e->nbits){ e->bad=1; memset(out,0,32); return; }
    int parent = e->bits[e->bpos++];
    if (height==0 || !parent){
        if (e->hpos >= e->nhash){ e->bad=1; memset(out,0,32); return; }
        memcpy(out, e->hashes[e->hpos++], 32);
        if (height==0 && parent) memcpy(e->matched[e->nmatched++], out, 32);
    } else {
        u8 left[32], right[32];
        pmt_extract(e, ntx, height-1, pos*2, left);
        if (pos*2u+1u < pmt_width(ntx, height-1)){
            pmt_extract(e, ntx, height-1, pos*2+1, right);
            if (!memcmp(left,right,32)) e->bad=1;   /* BIP37: no duplicate right */
        } else memcpy(right, left, 32);
        u8 cat[64]; memcpy(cat,left,32); memcpy(cat+32,right,32); sha256d(out,cat,64);
    }
}

/* small compactsize writer (values here are small) */
static int pmt_put_cs(u8* d, u64 v);   /* fwd */
static int pmt_put_cs_pad(u8* d, u64 v, int force_fd){
    if (force_fd && v <= 0xffff){ d[0]=0xfd; d[1]=(u8)v; d[2]=(u8)(v>>8); return 3; }
    if (v < 0xfd){ d[0]=(u8)v; return 1; }
    if (v <= 0xffff){ d[0]=0xfd; d[1]=(u8)v; d[2]=(u8)(v>>8); return 3; }
    d[0]=0xfe; d[1]=(u8)v; d[2]=(u8)(v>>8); d[3]=(u8)(v>>16); d[4]=(u8)(v>>24); return 5;
}
static int hex1(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }

/* --- test hooks (exercised by tests/test_txoutproof.c) --- */
int pmt_test_root(const u8 (*leaves)[32], u32 ntx, u8 out[32]){
    if (ntx == 0) return 0;
    pmt_calc_hash(leaves, ntx, pmt_height(ntx), 0, out);
    return 1;
}
/* build a proof for the single leaf `idx`, extract it back, and return the
 * extracted root + recovered txid: a full serialise-free build/extract cycle. */
int pmt_test_roundtrip(const u8 (*leaves)[32], u32 ntx, u32 idx, u8 out_root[32], u8 out_leaf[32]){
    if (idx >= ntx) return 0;
    u8* match = calloc(ntx, 1); if (!match) return 0; match[idx] = 1;
    u8 (*hashes)[32] = malloc(sizeof(*hashes)*(ntx+64));
    u8* bits = malloc((size_t)ntx*2 + 64);
    if (!hashes || !bits){ free(match); free(hashes); free(bits); return 0; }
    pmt_build_t b = { leaves, match, ntx, hashes, 0, bits, 0 };
    pmt_build(&b, pmt_height(ntx), 0);
    free(match);
    u8 (*matched)[32] = malloc(sizeof(*matched)*ntx);
    pmt_extract_t e = { (const u8(*)[32])hashes, b.nhash, 0, bits, b.nbits, 0, matched, 0, 0 };
    pmt_extract(&e, ntx, pmt_height(ntx), 0, out_root);
    int ok = !e.bad && e.hpos == b.nhash && e.nmatched == 1;
    if (ok) memcpy(out_leaf, matched[0], 32);
    free(hashes); free(bits); free(matched);
    return ok;
}

/* merkle root for the crafted proofs (display hex), set by the test from
 * its own block-100,000 vector so the serializer's header stamp matches the
 * tree the proof carries */
static char g_pmt_root_hex[65] = "0000000000000000000000000000000000000000000000000000000000000000";
void pmt_test_set_root(const char* hex64){
    if (hex64 && strlen(hex64) == 64) memcpy(g_pmt_root_hex, hex64, 64), g_pmt_root_hex[64] = 0;
}
/* When armed via pmt_test_set_root, the crafted header carries the REAL
 * block-100,000 root: then an honest proof passes the root check and even
 * reaches the (empty, guarded) archive step -- the strongest possible proof
 * that the tightened bounds did NOT reject a legitimate serialization. */
static void pmt_root_wire(u8 out[32]){
    for (int i = 0; i < 32; i++){
        char b[3] = { g_pmt_root_hex[i*2], g_pmt_root_hex[i*2+1], 0 };
        out[31-i] = (u8)strtol(b, 0, 16);
    }
}
/* RPX-1 regression hooks (audit 2026-09-03). pmt_test_verify calls
 * cmd_verifytxoutproof DIRECTLY, bypassing the dispatcher's g_open archive
 * gate: for parse-level decisions the command is a pure function of its hex
 * argument -- the archive only participates in the final "block must be in
 * our chain" step, which merely turns an otherwise-valid proof into an empty
 * result array and cannot mask a parse accept/reject. (An empty archive
 * cannot reach the parse path at all: with tip=-1 every proof dies at the
 * "block not found" gate before the hex is walked -- which is why an earlier
 * version of this hook, routed through rpc_chain_dispatch against an empty
 * store, silently PASSED against the buggy code. The negative control for
 * these vectors -- run with the fix reverted and watch them FAIL -- is
 * mandatory, not optional.) */
static int cmd_verifytxoutproof(const rj_val* params, rj_val** res, long* ec, const char** em);

const char* pmt_test_verify_msg(const char* proof_hex, long* ec_out);

long pmt_test_verify(const char* proof_hex){
    long ec = 0;
    pmt_test_verify_msg(proof_hex, &ec);
    return (ec < 0) ? ec : 0;
}

/* same call, but ALSO hands back the error string: vectors that only assert
 * "ec == -8" cannot tell a parse-bound rejection from a coincidental one,
 * and this test suite has been burned by exactly that class of false pass */
const char* pmt_test_verify_msg(const char* proof_hex, long* ec_out){
    rj_val* params = rj_arr();
    rj_arr_push(params, rj_str(proof_hex));
    rj_val* res = 0; long ec = 0; const char* em = 0;
    int ok = cmd_verifytxoutproof(params, &res, &ec, &em);
    (void)ok; (void)res;
    *ec_out = ec;
    return em ? em : "";
}

/* Shared serializer for the crafted proofs: the same CPartialMerkleTree the
 * real command builds, but with ATTACKER-CHOSEN ntx / nhash / nFlagsBytes
 * fields (0 = the honest value) and the payload zero-padded to the lie.
 * This is the only way to construct the RPX-1 attack input: a proof-shaped
 * serialization whose nTransactions field exceeds PMT_MAX_TX while its
 * nHashes drives the copy loop past the hashes[] allocation. */
static int pmt_serialize_lie2(const u8 (*leaves)[32], u32 ntx, u32 ntx_field,
                              u32 nhash_field, u32 nfb_field, u32 idx,
                              int pad_cs, char* out, size_t outcap){
    if (idx >= ntx) return 0;
    u8* match = calloc(ntx, 1); if (!match) return 0; match[idx] = 1;
    u8 (*hashes)[32] = malloc(sizeof(*hashes)*((size_t)ntx+64));
    u8* bits = malloc((size_t)ntx*2 + 64);
    if (!hashes || !bits){ free(match); free(hashes); free(bits); return 0; }
    pmt_build_t b = { leaves, match, ntx, hashes, 0, bits, 0 };
    pmt_build(&b, pmt_height(ntx), 0);
    free(match);
    u32 nhf = nhash_field ? nhash_field : b.nhash;
    u32 nbf = nfb_field   ? nfb_field   : (b.nbits+7)/8;
    if (nhf < b.nhash || nbf*8 < b.nbits){ free(hashes); free(bits); return 0; }
    size_t need = 80 + 4 + 9 + (size_t)nhf*32 + 9 + (size_t)nbf;
    u8* big = malloc(need + 16); if (!big){ free(hashes); free(bits); return 0; }
    memset(big, 0, need + 16);
    /* byte-exact unaligned writes (no aliasing/alignment assumptions) */
    size_t o = 0; u32 v;
    v = 1;           memcpy(big+o, &v, 4); o += 4;   /* version */
    o += 32;                                          /* hashPrevBlock */
    /* the tree's merkle root, stamped into the header: honest proofs then
     * pass the root==header check, while the ntx/nhash lies remain the only
     * variables under test. Computed straight from the caller's leaves --
     * NOT the test's TXID_DISP (the serializer has no access to it; an
     * earlier version stamped the vector root and the tree computed a
     * different one, which is why every crafted proof hit "Invalid proof").
     * The test may ALSO arm the real block-100,000 root via
     * pmt_test_set_root for byte-exact vectors. */
    u8 root[32];
    pmt_calc_hash(leaves, ntx, pmt_height(ntx), 0, root);
    if (g_pmt_root_hex[0] != '0') pmt_root_wire(root);
    memcpy(big+o, root, 32); o += 32;   /* header merkleRoot field */
    v = 1300000000u; memcpy(big+o, &v, 4); o += 4;   /* time */
    v = 0x1d00ffffu; memcpy(big+o, &v, 4); o += 4;   /* bits */
    v = 0;           memcpy(big+o, &v, 4); o += 4;   /* nonce */
    v = (ntx_field ? ntx_field : ntx); memcpy(big+o, &v, 4); o += 4;  /* the attacked field */
    o += (size_t)pmt_put_cs_pad(big+o, nhf, pad_cs);
    for (u32 i=0;i<b.nhash;i++){ memcpy(big+o, hashes[i], 32); o += 32; }
    o += (size_t)(nhf - b.nhash) * 32;               /* zero-pad to the lie */
    o += (size_t)pmt_put_cs_pad(big+o, nbf, pad_cs);
    memset(big+o, 0, nbf);
    for (u32 i=0;i<b.nbits;i++) if (bits[i]) big[o + i/8] |= (u8)(1u << (i%8));
    o += nbf;
    if (o*2 + 1 > outcap){ free(big); free(hashes); free(bits); return 0; }
    hex_of(out, big, o);
    free(big); free(hashes); free(bits);
    return 1;
}

/* honest-shaped proof with only the ntx field inflated (or 0 for honest) */
int pmt_test_build_hex(const u8 (*leaves)[32], u32 ntx, u32 ntx_field, u32 idx, char* out, size_t outcap){
    return pmt_serialize_lie2(leaves, ntx, ntx_field, 0, 0, idx, 0, out, outcap);
}
/* full attacker fields: ntx, nhash and nFlagsBytes all lie */
int pmt_test_build_hex_atk(const u8 (*leaves)[32], u32 ntx, u32 ntx_field,
                           u32 nhash_field, u32 nfb_field, u32 idx, char* out, size_t outcap){
    return pmt_serialize_lie2(leaves, ntx, ntx_field, nhash_field, nfb_field, idx, 0, out, outcap);
}
/* like _atk but the nhash/nfb compactsize fields use the 0xfd two-byte form
 * for a value < 0xfd: LEGAL to this parser (like Core's, minus Core's
 * non-canonical throw -- that divergence is SER-3, tracked separately), so
 * it lets the payload carry past 0xff=255 hash slots while a naive
 * single-byte-field builder could not. */
int pmt_test_build_hex_pad(const u8 (*leaves)[32], u32 ntx, u32 ntx_field,
                           u32 nhash_field, u32 nfb_field, u32 idx, char* out, size_t outcap){
    return pmt_serialize_lie2(leaves, ntx, ntx_field, nhash_field, nfb_field, idx, 1, out, outcap);
}

/* collect ordered wire-order txids of block h into leaves (caller-sized);
 * returns ntx, or -1 on decode error. */
static long pmt_block_txids(long h, u8 (*leaves)[32], u32 cap){
    long len = read_block(h);
    if (len < 80) return -1;
    const u8* blk = g_blockbuf; const u8* end = blk + len;
    u64 c; u64 ntx = read_varint(blk + 80, end, &c);
    if (!c || ntx == 0 || ntx > cap) return -1;
    const u8* p = blk + 80 + c;
    for (u64 i=0;i<ntx;i++){
        txw_t w;
        if (!tx_walk(p, end, &w)) return -1;
        u8* scratch = malloc(w.len); if (!scratch) return -1;
        tx_txid(leaves[i], p, w.len, scratch, w.len); free(scratch);
        p += w.len;
    }
    return (long)ntx;
}

#define PMT_MAX_TX 100000

/* RPX-1 canary: a guard page immediately after the hashes[] allocation, so
 * any copy past the buffer END faults instead of corrupting the heap. The
 * command's hashes[] is a lazily malloc'd static, so the only way to arm
 * the guard before the copy runs is to install an allocation hook the
 * command consults on its FIRST hashes[] allocation: g_rpx1_alloc replaces
 * malloc there. The canary mapping is [data 32*(PMT_MAX_TX+64) | PROT_NONE
 * page], so hashes[PMT_MAX_TX+64] -- the exact overflow entry -- hits the
 * guard page and SIGSEGVs. pmt_test_verify(CANARY) therefore behaves as:
 * fixed code: returns -8 before the copy, child never faults;
 * buggy code: the copy faults (caller sees a forked-child fault, reported
 * by pmt_test_verify_guarded). Production builds never set the hook. */
static void* (*g_rpx1_alloc)(size_t) = 0;
#define RPX1_HASH_ENTRIES (PMT_MAX_TX + 64)
static u8* g_rpx1_canary_base = 0;     /* mmap region (for munmap) */
static size_t g_rpx1_canary_sz = 0;
static int  g_rpx1_armed = 0;

static void* rpx1_canary_malloc(size_t n){
    size_t need = RPX1_HASH_ENTRIES * 32;
    if (n < need) return malloc(n);
    size_t pagesz = 4096;
    size_t sz = ((need + pagesz - 1) / pagesz) * pagesz + pagesz;
    u8* m = mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return malloc(n);
    mprotect(m + sz - pagesz, pagesz, PROT_NONE);
    g_rpx1_canary_base = m; g_rpx1_canary_sz = sz;
    return m;
}

void pmt_test_arm_hashes_guard(int on){
    if (on){ g_rpx1_alloc = rpx1_canary_malloc; g_rpx1_armed = 1; }
    else   { g_rpx1_alloc = 0; g_rpx1_armed = 0; }
}

/* run the command with the guard-page canary armed, in a forked child so a
 * real overflow fault is observable rather than fatal. Returns the child's
 * outcome: 0 = exited with ec (in *ec_out), -SIG = killed by signal
 * (SIGSEGV = the copy wrote past the allocation). */
const char* pmt_test_verify_msg(const char* proof_hex, long* ec_out);
long pmt_test_verify_guarded(const char* proof_hex, int* sig_out){
    /* arm IN THE CHILD so the canary buffer is this process's to fault on */
    int pipefd[2]; if (pipe(pipefd) != 0) return -1;
    pid_t pid = fork();
    if (pid == 0){
        close(pipefd[0]);
        g_rpx1_alloc = rpx1_canary_malloc;
        long ec = 0; pmt_test_verify_msg(proof_hex, &ec);
        long out = (ec < 0) ? ec : 0;
        ssize_t w = write(pipefd[1], &out, sizeof out); (void)w;
        _exit(0);
    }
    close(pipefd[1]);
    long out = 0;
    ssize_t r = read(pipefd[0], &out, sizeof out); (void)r;
    close(pipefd[0]);
    int st = 0; waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)){ if (sig_out) *sig_out = WTERMSIG(st); return -WTERMSIG(st); }
    if (sig_out) *sig_out = 0;
    return (r == (ssize_t)sizeof out) ? out : -1;
}

static int cmd_gettxoutproof(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 || params->items[0]->typ != RJ_ARR){
        *ec = -8; *em = "Invalid parameter, expected array of txids"; return 0; }
    const rj_val* txarr = params->items[0];
    if (txarr->nitems < 1){ *ec = -8; *em = "Parameter 'txids' cannot be empty"; return 0; }
    refresh(); long h;
    if (param_present(params, 1)){
        if (!lookup_block_param(params, 1, 1, &h, ec, em)) return 0;
    } else {
        /* No blockhash given. Core's own order: try the txid index (built
         * offline, daemon/bmc_build_tx_index, or maintained live by
         * daemon/tx_index_tail.c) on the FIRST requested txid -- exactly
         * one lookup, since a proof only makes sense when every txid in the
         * request lives in the SAME block, and the loop below already
         * confirms that for the rest.
         *
         * This used to be an unconditional "-5, a blockhash is required
         * with no txindex" -- true in 2026-08-21 when txindex did not
         * exist, false since 2026-08-26 when it landed (audit finding,
         * 2026-09-03: the stated REASON was wrong, not just the message). */
        if (txarr->items[0]->typ != RJ_STR || strlen(txarr->items[0]->str) != 64){
            *ec = -8; *em = "Invalid txid"; return 0; }
        u8 first_disp[32];
        for (int k = 0; k < 32; k++){
            int hi = hex1(txarr->items[0]->str[k*2]), lo = hex1(txarr->items[0]->str[k*2+1]);
            if (hi < 0 || lo < 0){ *ec = -8; *em = "Invalid txid"; return 0; }
            first_disp[k] = (u8)(hi<<4|lo);
        }
        u8 first_wire[32]; for (int i = 0; i < 32; i++) first_wire[i] = first_disp[31-i];
        long th; u32 toff, tlen;
        if (txi_lookup(first_wire, &th, &toff, &tlen)){
            (void)toff; (void)tlen; h = th;
        } else {
            txi_open();
            if (txi_have()){
                static char nomsg[288];
                long cov_to = txi_coverage_to();     /* RPX-8 */
                snprintf(nomsg, sizeof nomsg,
                         "Transaction not found in the txid index (covers heights %ld..%ld); "
                         "if the transaction is outside that range, rebuild the index over it "
                         "or pass the block hash.", txi_runs_from(), cov_to);
                *ec = -5; *em = nomsg; return 0;
            }
            /* txindex=0 is Core without -txindex: after its UTXO lookup
             * misses, Core's words are "Transaction not yet in block" */
            if (!ix_on(g_ix_txindex)){ *ec = -5; *em = "Transaction not yet in block"; return 0; }
            *ec = -5; *em = "No txid index built (daemon/bmc_build_tx_index) and no block hash given -- "
                            "pass the block hash, or build the index to locate a confirmed "
                            "transaction by txid alone."; return 0;
        }
    }

    static u8 (*leaves)[32]; if (!leaves){ leaves = malloc(sizeof(*leaves)*PMT_MAX_TX); if(!leaves){*ec=-7;*em="oom";return 0;} }
    long ntx = pmt_block_txids(h, leaves, PMT_MAX_TX);
    if (ntx < 0){ *ec = -1; *em = "Block decode failed"; return 0; }

    u8* match = calloc((size_t)ntx, 1); if (!match){ *ec=-7; *em="oom"; return 0; }
    for (size_t t=0; t<txarr->nitems; t++){
        const rj_val* e = txarr->items[t];
        if (e->typ != RJ_STR || strlen(e->str) != 64){ free(match); *ec=-8; *em="Invalid txid"; return 0; }
        u8 want[32];  /* display hex -> wire order */
        for (int k=0;k<32;k++){ int hi=hex1(e->str[k*2]), lo=hex1(e->str[k*2+1]); if(hi<0||lo<0){free(match);*ec=-8;*em="Invalid txid";return 0;} want[31-k]=(u8)(hi<<4|lo); }
        int found=0; for (long i=0;i<ntx;i++) if (!memcmp(leaves[i], want, 32)){ match[i]=1; found=1; break; }
        if (!found){ free(match); *ec=-5; *em="Transaction not found in specified block"; return 0; }
    }
    /* build the partial merkle tree */
    static u8 (*hashes)[32]; if(!hashes){ hashes=malloc(sizeof(*hashes)*(PMT_MAX_TX+64)); if(!hashes){free(match);*ec=-7;*em="oom";return 0;} }
    static u8* bits; if(!bits){ bits=malloc(PMT_MAX_TX*2+64); if(!bits){free(match);*ec=-7;*em="oom";return 0;} }
    pmt_build_t b = { (const u8(*)[32])leaves, match, (u32)ntx, hashes, 0, bits, 0 };
    pmt_build(&b, pmt_height((u32)ntx), 0);
    free(match);
    /* serialize: header(80) || u32 ntx LE || cs(nhash) || hashes || cs(nbytes) || flags */
    u8 hdr[80]; if (read_block_prefix(h, hdr, 80) != 1){ *ec=-1; *em="Block not available"; return 0; }
    u32 nflagbytes = (b.nbits + 7) / 8;
    size_t cap = 80 + 4 + 9 + (size_t)b.nhash*32 + 9 + nflagbytes;
    u8* buf = malloc(cap); if (!buf){ *ec=-7; *em="oom"; return 0; }
    size_t o = 0;
    memcpy(buf+o, hdr, 80); o += 80;
    buf[o++]=(u8)ntx; buf[o++]=(u8)(ntx>>8); buf[o++]=(u8)((u32)ntx>>16); buf[o++]=(u8)((u32)ntx>>24);
    o += pmt_put_cs(buf+o, b.nhash);
    for (u32 i=0;i<b.nhash;i++){ memcpy(buf+o, hashes[i], 32); o += 32; }
    o += pmt_put_cs(buf+o, nflagbytes);
    memset(buf+o, 0, nflagbytes);
    for (u32 i=0;i<b.nbits;i++) if (bits[i]) buf[o + i/8] |= (u8)(1u << (i%8));
    o += nflagbytes;
    char* hx = malloc(o*2 + 1); if (!hx){ free(buf); *ec=-7; *em="oom"; return 0; }
    hex_of(hx, buf, o); free(buf);
    *res = rj_str(hx); free(hx);
    return 1;
}

static int cmd_verifytxoutproof(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* proof = rpc_param_str(params, 0, ec, em); if (!proof) return 0;
    size_t hn = strlen(proof); if (hn < (80+5)*2 || (hn & 1)){ *ec=-8; *em="Invalid proof"; return 0; }
    size_t bn = hn/2; u8* buf = malloc(bn); if (!buf){ *ec=-7; *em="oom"; return 0; }
    for (size_t i=0;i<bn;i++){ int hi=hex1(proof[i*2]),lo=hex1(proof[i*2+1]); if(hi<0||lo<0){free(buf);*ec=-8;*em="Invalid proof hex";return 0;} buf[i]=(u8)(hi<<4|lo); }
    const u8* p = buf; const u8* end = buf + bn;
    if (p + 84 > end){ free(buf); *ec=-8; *em="Invalid proof"; return 0; }
    const u8* hdr = p; p += 80;
    u32 ntx = rd32(p); p += 4;
    /* RPX-1 fix (audit 2026-09-03): cap ntx BEFORE anything derived from it
     * is read or copied. nhash is bounded by ntx below, and the copy loop
     * writes into a PMT_MAX_TX+64 entry buffer, so an unbounded ntx let a
     * caller with ntx > PMT_MAX_TX drive the copy past the allocation
     * (nhash <= ntx+64 admitted PMT_MAX_TX+65 entries). Core rejects
     * nTransactions > MAX_SIZE at deserialisation and nHashes >
     * nTransactions at the CPartialMerkleTree level; our equivalents are
     * PMT_MAX_TX and nhash > ntx, both enforced before the reads
     * (merkleblock.cpp never sizes a buffer to the untrusted count). */
    if (ntx == 0 || ntx > PMT_MAX_TX){ free(buf); *ec=-8; *em="Invalid proof"; return 0; }
    u64 c; u64 nhash = read_varint(p, end, &c); if (!c || nhash > ntx){ free(buf); *ec=-8; *em="Invalid proof"; return 0; } p += c;
    if (p + nhash*32 > end){ free(buf); *ec=-8; *em="Invalid proof"; return 0; }
    static u8 (*hashes)[32];
    if(!hashes){ hashes = (g_rpx1_alloc ? (u8(*)[32])g_rpx1_alloc(sizeof(*hashes)*(PMT_MAX_TX+64))
                                        : malloc(sizeof(*hashes)*(PMT_MAX_TX+64))); }
    for (u64 i=0;i<nhash;i++){ memcpy(hashes[i], p, 32); p += 32; }
    u64 nfb = read_varint(p, end, &c); if (!c){ free(buf); *ec=-8; *em="Invalid proof"; return 0; } p += c;
    if (p + nfb > end || nfb*8 > PMT_MAX_TX*2+64){ free(buf); *ec=-8; *em="Invalid proof"; return 0; }
    static u8* bits; if(!bits){ bits=malloc(PMT_MAX_TX*2+64); }
    u32 nbits = (u32)(nfb*8);
    for (u32 i=0;i<nbits;i++) bits[i] = (p[i/8] >> (i%8)) & 1;
    static u8 (*matched)[32]; if(!matched){ matched=malloc(sizeof(*matched)*(PMT_MAX_TX)); }
    pmt_extract_t e = { (const u8(*)[32])hashes, (u32)nhash, 0, bits, nbits, 0, matched, 0, 0 };
    u8 root[32]; pmt_extract(&e, ntx, pmt_height(ntx), 0, root);
    /* BIP37 validity: every hash and every bit consumed, no error */
    int ok = !e.bad && e.hpos == nhash && ((e.bpos + 7)/8) == nfb;
    if (ok && memcmp(root, hdr + 36, 32) != 0) ok = 0;   /* root must match header */
    /* block must be in our chain */
    long h_out = -1;
    if (ok){ u8 bh[32], disp[32]; sha256d(bh, hdr, 80);   /* wire order */
        for (int i=0;i<32;i++) disp[i]=bh[31-i];           /* height_by_hash wants display order */
        if (!height_by_hash(disp, &h_out)) ok = 0; }
    rj_val* arr = rj_arr();
    if (ok){ for (u32 i=0;i<e.nmatched;i++){ char hx[65]; hex_rev(hx, matched[i], 32); rj_arr_push(arr, rj_str(hx)); } }
    free(buf);
    *res = arr;   /* empty array if the proof is invalid or not in chain, like Core */
    return 1;
}

/* ---- decodescript (util): classify a redeem/script hex like Core ----------
 * Faithful port of src/rpc/rawtransaction.cpp decodescript: ScriptToUniv
 * (no hex at top level) + the p2sh / segwit wrappers, gated exactly as Core
 * gates them (can_wrap / can_wrap_P2WSH). "desc" is the one documented
 * omission (no descriptor engine) -- everything else diffs against Core. */
static int ds_op_success(u8 op){            /* IsOpSuccess (tapscript) */
    return op==80 || op==98 || (op>=126&&op<=129) || (op>=131&&op<=134) ||
           (op>=137&&op<=138) || (op>=141&&op<=142) || (op>=149&&op<=153) ||
           (op>=187&&op<=254);
}
static int ds_valid_ops(const u8* s, size_t n){   /* CScript::HasValidOps */
    const u8* pc=s; const u8* end=s+n; u8 op; const u8* d; size_t dl;
    while (pc < end){
        if (!script_getop(&pc, end, &op, &d, &dl)) return 0;
        if (op > 0xb9 /*MAX_OPCODE=OP_NOP10*/) return 0;
        if (dl > 520 /*MAX_SCRIPT_ELEMENT_SIZE*/) return 0;
    }
    return 1;
}
static int ds_compressed_pk(const u8* d, size_t dl){ return dl==33 && (d[0]==0x02||d[0]==0x03); }
/* P2SH address of an arbitrary script; 1 on success. */
static int ds_p2sh_addr(const u8* s, size_t n, char* out, long cap){
    u8 h[20]; hash160(h, s, (long long)n);
    u8 spk[23]; spk[0]=0xa9; spk[1]=0x14; memcpy(spk+2,h,20); spk[22]=0x87;
    return wallet_script_to_address(out, cap, spk, 23) > 0 && out[0];
}

static int desc_checksum(const char* span, char out[9]);   /* defined below */
int rpc_chain_desc_checksum(const char* span, char out[9]){ return desc_checksum(span, out); }

/* InferDescriptor for a bare scriptPubKey with no keystore (Core
 * descriptor.cpp InferScript fallbacks): pk()/multi() when the key material is
 * in the script, rawtr() for a taproot output key, addr() for a hash-only
 * standard type, else raw(). Returns the inner descriptor string (no
 * checksum), malloc'd; caller frees. */
static char* desc_inner_of(const u8* s, size_t n){
    const char* type = script_type(s, n);
    char* d = NULL;
    if (!strcmp(type,"pubkey")){
        size_t pl = s[0]; d = malloc(4 + pl*2 + 2);
        if (d){ memcpy(d,"pk(",3); hex_of(d+3, s+1, pl); strcpy(d+3+pl*2, ")"); }
    } else if (!strcmp(type,"multisig")){
        int m = 0; small_int(s[0], &m);
        d = malloc(n*2 + 32);
        if (d){ int off = sprintf(d, "multi(%d", m);
            const u8* pc=s+1; const u8* end=s+n-2; u8 op; const u8* dp; size_t dl;
            while (pc<end){ if(!script_getop(&pc,end,&op,&dp,&dl)) break; d[off++]=','; hex_of(d+off,dp,dl); off += (int)dl*2; }
            d[off++]=')'; d[off]=0; }
    } else if (!strcmp(type,"witness_v1_taproot")){
        d = malloc(6 + 64 + 2);
        if (d){ memcpy(d,"rawtr(",6); hex_of(d+6, s+2, 32); strcpy(d+6+64, ")"); }
    } else if (!strcmp(type,"pubkeyhash")||!strcmp(type,"scripthash")||
               !strcmp(type,"witness_v0_keyhash")||!strcmp(type,"witness_v0_scripthash")){
        char addr[128]; addr[0]=0;
        if (wallet_script_to_address(addr, sizeof addr, s, (long)n) > 0 && addr[0]){
            d = malloc(strlen(addr)+8); if (d) sprintf(d, "addr(%s)", addr);
        }
    }
    if (!d){                                              /* raw() fallback */
        d = malloc(n*2 + 8);
        if (d){ memcpy(d,"raw(",4); hex_of(d+4, s, n); strcpy(d+4+n*2, ")"); }
    }
    return d;
}
/* wrap an inner descriptor string with Core's #checksum; malloc'd, caller frees. */
static char* desc_with_checksum(const char* inner){
    if (!inner) return NULL;
    char cks[9]; if (!desc_checksum(inner, cks)) return NULL;
    char* out = malloc(strlen(inner) + 10);
    if (out) sprintf(out, "%s#%s", inner, cks);
    return out;
}

static int cmd_decodescript(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* hex = rpc_param_str(params, 0, ec, em); if (!hex) return 0;
    size_t hn = strlen(hex);
    if (hn & 1){ *ec = -8; *em = "argument must be hexadecimal string (not '...')"; return 0; }
    size_t n = hn/2;
    u8* s = n ? malloc(n) : (u8*)"";
    if (n && !s){ *ec=-7; *em="oom"; return 0; }
    for (size_t i=0;i<n;i++){ int hi=hex1(hex[i*2]),lo=hex1(hex[i*2+1]); if(hi<0||lo<0){ if(n)free(s); *ec=-8; *em="argument must be hexadecimal string"; return 0; } s[i]=(u8)(hi<<4|lo); }

    /* --- ScriptToUniv, include_hex=false, include_address=true --- */
    rj_val* o = rj_obj();
    char* a = script_asm(s, n, 0); rj_obj_set(o,"asm", rj_str(a?a:"")); free(a);
    { char* di = desc_inner_of(s, n); char* dc = desc_with_checksum(di);
      if (dc){ rj_obj_set(o,"desc", rj_str(dc)); free(dc); } free(di); }
    const char* type = script_type(s, n);
    { char addr[128]; addr[0]=0;
      if (wallet_script_to_address(addr, sizeof addr, s, (long)n) > 0 && addr[0]) rj_obj_set(o,"address", rj_str(addr)); }
    rj_obj_set(o,"type", rj_str(type));

    /* --- can_wrap --- */
    int cand = !strcmp(type,"multisig")||!strcmp(type,"nonstandard")||!strcmp(type,"pubkey")||
               !strcmp(type,"pubkeyhash")||!strcmp(type,"witness_v0_keyhash")||!strcmp(type,"witness_v0_scripthash");
    int can_wrap = 0;
    if (cand){
        can_wrap = ds_valid_ops(s,n) && !script_unspendable(s,n);
        if (can_wrap){                                   /* no OP_CHECKSIGADD / OP_SUCCESSx */
            const u8* pc=s; const u8* end=s+n; u8 op; const u8* d; size_t dl;
            while (pc<end){ if(!script_getop(&pc,end,&op,&d,&dl)){ can_wrap=0; break; }
                            if (op==0xba || ds_op_success(op)){ can_wrap=0; break; } }
        }
    }
    if (can_wrap){
        char p2sh[128]; if (ds_p2sh_addr(s,n,p2sh,sizeof p2sh)) rj_obj_set(o,"p2sh", rj_str(p2sh));

        /* --- can_wrap_P2WSH --- */
        int wsh = 0;
        if (!strcmp(type,"nonstandard")||!strcmp(type,"pubkeyhash")) wsh = 1;
        else if (!strcmp(type,"pubkey")){ wsh = ds_compressed_pk(s+1, s[0]); }
        else if (!strcmp(type,"multisig")){
            wsh = 1; const u8* pc=s+1; const u8* end=s+n-2; u8 op; const u8* d; size_t dl;
            while (pc<end){ if(!script_getop(&pc,end,&op,&d,&dl)){ wsh=0; break; }
                            if (dl!=1 && !ds_compressed_pk(d,dl)){ wsh=0; break; } }
        }
        if (wsh){
            u8 wspk[34]; size_t wl;
            if (!strcmp(type,"pubkey")){ u8 h[20]; hash160(h, s+1, (long long)s[0]); wspk[0]=0x00; wspk[1]=0x14; memcpy(wspk+2,h,20); wl=22; }
            else if (!strcmp(type,"pubkeyhash")){ wspk[0]=0x00; wspk[1]=0x14; memcpy(wspk+2, s+3, 20); wl=22; }
            else { u8 h[32]; sha256_full(h, s, (long long)n); wspk[0]=0x00; wspk[1]=0x20; memcpy(wspk+2,h,32); wl=34; }
            rj_val* sr = script_pubkey_json_x(wspk, wl, 0);   /* segwit supplies its own desc below */
            /* segwit desc: P2WPKH -> addr() (no inner known); P2WSH -> wsh(inner
             * descriptor of the original script), matching Core's provider. */
            char* sdc;
            if (wl == 22){ char* di = desc_inner_of(wspk, wl); sdc = desc_with_checksum(di); free(di); }
            else { char* di = desc_inner_of(s, n);
                   if (di && !strncmp(di, "raw(", 4)){    /* inner not a proper descriptor -> addr() */
                       free(di); di = desc_inner_of(wspk, wl); sdc = desc_with_checksum(di); free(di);
                   } else {
                       char* w = di ? malloc(strlen(di)+6) : NULL;
                       if (w) sprintf(w, "wsh(%s)", di);
                       sdc = desc_with_checksum(w); free(w); free(di);
                   } }
            if (sdc){ rj_obj_set(sr,"desc", rj_str(sdc)); free(sdc); }
            char pss[128]; if (ds_p2sh_addr(wspk, wl, pss, sizeof pss)) rj_obj_set(sr,"p2sh-segwit", rj_str(pss));
            rj_obj_set(o,"segwit", sr);
        }
    }
    if (n) free(s);
    *res = o;
    return 1;
}

/* ---- createmultisig (util): build an m-of-n multisig address ---------------
 * Core's rpc/output_script.cpp createmultisig + rpc/util.cpp
 * AddAndGetMultisigDestination. Pure: validate the pubkeys (on-curve, via
 * pubkey_parse = CPubKey::IsFullyValid), assemble the redeemScript, and derive
 * the address for the requested output type. Uncompressed keys force legacy
 * (and, if a segwit type was asked for, add Core's warning). The "descriptor"
 * field is the one omission -- no descriptor engine (same as decodescript's
 * "desc"). */
extern int pubkey_parse(const u8* pub, unsigned long publen, u64 qx[4], u64 qy[4]);

/* CScript << int for a 0..20 count: OP_0 / OP_1..OP_16, else a 1-byte push. */
static size_t cms_push_count(u8* d, int v){
    if (v == 0){ d[0] = 0x00; return 1; }
    if (v >= 1 && v <= 16){ d[0] = (u8)(0x50 + v); return 1; }
    d[0] = 0x01; d[1] = (u8)v; return 2;             /* CScriptNum, v <= 20 */
}
static int cms_p2sh_addr(const u8* s, size_t n, char* out, long cap){
    u8 h[20]; hash160(h, s, (long long)n);
    u8 spk[23]; spk[0]=0xa9; spk[1]=0x14; memcpy(spk+2,h,20); spk[22]=0x87;
    return wallet_script_to_address(out, cap, spk, 23) > 0 && out[0];
}

/* Core's descriptor checksum (descriptor.cpp DescriptorChecksum): appends the
 * 8-char "#..." suffix to a descriptor string. Fills out[9]; 0 if `span` holds
 * a char outside the descriptor input charset. */
static u64 desc_polymod(u64 c, int val){
    u8 c0 = (u8)(c >> 35);
    c = ((c & 0x7ffffffffULL) << 5) ^ (u64)val;
    if (c0 & 1)  c ^= 0xf5dee51989ULL;
    if (c0 & 2)  c ^= 0xa9fdca3312ULL;
    if (c0 & 4)  c ^= 0x1bab10e32dULL;
    if (c0 & 8)  c ^= 0x3706b1677aULL;
    if (c0 & 16) c ^= 0x644d626ffdULL;
    return c;
}
static int desc_checksum(const char* span, char out[9]){
    static const char* IN =
        "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    static const char* CK = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    u64 c = 1; int cls = 0, clscount = 0;
    for (const char* p = span; *p; p++){
        const char* q = strchr(IN, *p); if (!q) return 0;
        int pos = (int)(q - IN);
        c = desc_polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        if (++clscount == 3){ c = desc_polymod(c, cls); cls = 0; clscount = 0; }
    }
    if (clscount > 0) c = desc_polymod(c, cls);
    for (int j = 0; j < 8; ++j) c = desc_polymod(c, 0);
    c ^= 1;
    for (int j = 0; j < 8; ++j) out[j] = CK[(c >> (5 * (7 - j))) & 31];
    out[8] = 0;
    return 1;
}

/* ---- descriptor engine: getdescriptorinfo + deriveaddresses ----------------
 * Core rpc/output_script.cpp over descriptor.c, this node's port of Core's
 * descriptor.cpp: pk/pkh/wpkh/combo, multi/sortedmulti, sh/wsh wrappers,
 * tr with script trees (multi_a/sortedmulti_a leaves), rawtr, addr, raw;
 * hex, x-only, WIF, xpub/xprv keys with origins, paths and ranges. Expansion
 * is byte-identical to Core on its own descriptor_tests.cpp vectors
 * (tests/test_descriptor_vectors). Miniscript and musig() are refused by
 * name. */
#include "descriptor.h"
extern int wscan_spk_h160(const unsigned char* spk, unsigned long len, const unsigned char** h);

/* parse for an RPC: Core's exact checksum messages; deriveaddresses REQUIRES
 * a checksum, getdescriptorinfo verifies one when present */
static int rpcdesc_parse(const char* in, int need_checksum, descr_t* d, long* ec, const char** em){
    static char perr[256];
    if (need_checksum && !strchr(in, '#')){ *ec=-5; *em="Missing checksum"; return 0; }
    char err[256];
    if (!descr_parse(in, d, err, sizeof err)){ snprintf(perr, sizeof perr, "%s", err); *ec=-5; *em=perr; return 0; }
    return 1;
}
/* the single address at range index idx (Core ExtractDestination: bare pk,
 * bare multisig and combo have none) */
static int rpcdesc_address_at(const descr_t* d, long idx, char* out, long cap, long* ec, const char** em){
    static char perr[256];
    descr_spk_t sp[4]; int n = descr_expand(d, idx, sp, 4);
    if (n < 0){ const char* e = descr_last_error(); snprintf(perr, sizeof perr, "%s", e[0] ? e : "Key derivation failed"); *ec=-5; *em=perr; return 0; }
    if (n != 1 || !descr_has_address(d)){ *ec=-5; *em="Descriptor does not have a corresponding address"; return 0; }
    out[0]=0;
    if (wallet_script_to_address(out, cap, sp[0].spk, sp[0].len) <= 0 || !out[0]){ *ec=-5; *em="Descriptor does not have a corresponding address"; return 0; }
    return 1;
}

static int cmd_getdescriptorinfo_impl(const rj_val* params, rj_val** res, long* ec, const char** em, descr_t* d){
    const char* in = rpc_param_str(params, 0, ec, em); if (!in) return 0;
    if (!rpcdesc_parse(in, 0, d, ec, em)) return 0;
    /* "descriptor": the public form with ITS checksum; "checksum": the
     * checksum of the descriptor as given (Core reports both) */
    static char pub[1500], full[1520];
    if (!descr_to_string(d, 0, pub, sizeof pub)){ *ec=-5; *em="Descriptor too long"; return 0; }
    char pcs[9]; descr_checksum(pub, pcs);
    snprintf(full, sizeof full, "%s#%s", pub, pcs);
    int t = d->nodes[d->root].type;
    rj_val* o = rj_obj();
    rj_obj_set(o,"descriptor", rj_str(full));
    rj_obj_set(o,"checksum", rj_str(d->checksum));
    rj_obj_set(o,"isrange", rj_bool(d->ranged));
    rj_obj_set(o,"issolvable", rj_bool(t != DN_RAW && t != DN_ADDR));   /* addr()/raw() carry no key */
    rj_obj_set(o,"hasprivatekeys", rj_bool(d->has_priv));
    if (descr_multipath_n(d) > 1){                                       /* BIP389: "descriptor" is the first expansion; all of them here */
        rj_val* arr = rj_arr();
        for (int sel = 0; sel < descr_multipath_n(d); sel++){
            descr_multipath_select(d, sel);
            if (!descr_to_string(d, 0, pub, sizeof pub)) continue;
            char c2[9]; descr_checksum(pub, c2); snprintf(full, sizeof full, "%s#%s", pub, c2);
            rj_arr_push(arr, rj_str(full));
        }
        descr_multipath_select(d, 0);
        rj_obj_set(o,"multipath_expansion", arr);
    }
    *res = o;
    return 1;
}
static int cmd_getdescriptorinfo(const rj_val* params, rj_val** res, long* ec, const char** em){
    descr_t* d = malloc(sizeof *d); if (!d){ *ec=-7; *em="oom"; return 0; }
    int r = cmd_getdescriptorinfo_impl(params, res, ec, em, d); free(d); return r;
}

static int cmd_deriveaddresses_impl(const rj_val* params, rj_val** res, long* ec, const char** em, descr_t* d){
    const char* in = rpc_param_str(params, 0, ec, em); if (!in) return 0;
    if (!rpcdesc_parse(in, 1, d, ec, em)) return 0;

    /* range argument (params[1]): int N -> [0,N]; [a,b] -> [a,b]; inclusive. */
    long begin=0, end=0; int have_range=0;
    if (params && params->typ==RJ_ARR && params->nitems>=2){
        const rj_val* r = params->items[1];
        if (r->typ==RJ_NUM){ have_range=1; begin=0; end=(long)strtoll(r->str,NULL,10); }
        else if (r->typ==RJ_ARR && r->nitems==2 && r->items[0]->typ==RJ_NUM && r->items[1]->typ==RJ_NUM){
            have_range=1; begin=(long)strtoll(r->items[0]->str,NULL,10); end=(long)strtoll(r->items[1]->str,NULL,10); }
        else if (r->typ!=RJ_NULL){ *ec=-8; *em="Invalid range"; return 0; }
    }
    if (d->ranged && !have_range){ *ec=-8; *em="Range must be specified for a ranged descriptor"; return 0; }
    if (!d->ranged && have_range){ *ec=-8; *em="Range should not be specified for an un-ranged descriptor"; return 0; }
    if (have_range){
        if (begin<0 || end<0){ *ec=-8; *em="Range should be greater or equal than 0"; return 0; }
        if (end<begin){ *ec=-8; *em="Range specified as [begin,end] must not have begin after end"; return 0; }
        if (end-begin > 100000){ *ec=-8; *em="Range is too large"; return 0; }
    }
    long lo = d->ranged?begin:0, hi = d->ranged?end:0;
    int nmp = descr_multipath_n(d);
    rj_val* outer = nmp > 1 ? rj_arr() : NULL;                           /* BIP389: one address list per expansion, in specifier order */
    for (int sel = 0; sel < nmp; sel++){
        if (nmp > 1) descr_multipath_select(d, sel);
        rj_val* arr = rj_arr();
        for (long i=lo; i<=hi; i++){
            char addr[128];
            if (!rpcdesc_address_at(d, i, addr, sizeof addr, ec, em)){ rj_free(arr); if (outer) rj_free(outer); return 0; }
            rj_arr_push(arr, rj_str(addr));
        }
        if (outer) rj_arr_push(outer, arr); else { *res = arr; return 1; }
    }
    *res = outer;
    return 1;
}
static int cmd_deriveaddresses(const rj_val* params, rj_val** res, long* ec, const char** em){
    descr_t* d = malloc(sizeof *d); if (!d){ *ec=-7; *em="oom"; return 0; }
    int r = cmd_deriveaddresses_impl(params, res, ec, em, d); free(d); return r;
}

/* ---- exported descriptor API (wallet management) ---------------------------
 * rpc_wallet_ops.c's importdescriptors / watch-only wallets use the SAME
 * engine, without a second one growing next to it. Three entry points:
 *
 *   rpc_desc_normalize  checksum-verify (or append) and classify;
 *   rpc_desc_expand     the 20 bytes to SCAN for over an index range -- the
 *                       key hash for pkh/wpkh, the script hash for sh(...),
 *                       the first 20 bytes of the 32-byte program for
 *                       wsh(...)/tr(...) (wallet_scan.c matches every one of
 *                       those forms by that 20-byte compare);
 *   rpc_desc_address_at the address at one index, byte-identical to what
 *                       deriveaddresses answers (same code path).
 *
 * Script types reported: 0 pkh, 1 wpkh, 2 sh(...), 3 wsh(...), 4 tr(...),
 * 5 addr/raw. Descriptors whose expansion has no single address (bare pk,
 * bare multisig, combo) are refused for wallet use with a reason -- a
 * watch-only wallet must only claim scripts it can recognize in the chain
 * scan; private-key descriptors are refused because this wallet holds no
 * imported keys. */
static int rpc_desc_normalize_impl(const char* in, char* out, long cap, int* is_range,
                       char* err, unsigned long errcap, descr_t* d){
    char e[256];
    if (!descr_parse(in, d, e, sizeof e)){ snprintf(err,errcap,"%s", e); return 0; }
    if (d->has_priv){ snprintf(err,errcap,"private-key descriptors are not supported for import"); return 0; }
    if (!descr_has_address(d)){
        snprintf(err,errcap,"only descriptors with one address per index (pkh, wpkh, sh, wsh, tr, addr) can be imported for watching"); return 0; }
    if (is_range) *is_range = d->ranged;
    if ((long)snprintf(out, (size_t)cap, "%s#%s", d->text, d->checksum) >= cap){
        snprintf(err,errcap,"Descriptor too long"); return 0; }
    return 1;
}
/* BIP389 for importdescriptors: the number of expansions of `in` (1 when it is
 * not multipath), writing each expansion's public form + checksum into out[]
 * (up to cap). 0 with err on a parse error. */
int rpc_desc_multipath_expand(const char* in, char (*out)[340], int cap, char* err, unsigned long errcap){
    descr_t* d = malloc(sizeof *d); if (!d){ snprintf(err,errcap,"oom"); return 0; }
    char e[256];
    if (!descr_parse(in, d, e, sizeof e)){ snprintf(err,errcap,"%s", e); free(d); return 0; }
    int n = descr_multipath_n(d); if (n > cap) n = cap;
    for (int sel = 0; sel < n; sel++){
        char pub[1500]; descr_multipath_select(d, sel);
        if (!descr_to_string(d, 0, pub, sizeof pub) || strlen(pub) + 10 > 340){ snprintf(err,errcap,"Descriptor too long"); free(d); return 0; }
        char c2[9]; descr_checksum(pub, c2); snprintf(out[sel], 340, "%s#%s", pub, c2);
    }
    free(d); return n;
}
int rpc_desc_normalize(const char* in, char* out, long cap, int* is_range,
                       char* err, unsigned long errcap){
    descr_t* d = malloc(sizeof *d); if (!d){ snprintf(err,errcap,"oom"); return 0; }
    int r = rpc_desc_normalize_impl(in, out, cap, is_range, err, errcap, d); free(d); return r;
}

static long rpc_desc_expand_impl(const char* in, long start, long count,
                     unsigned char (*h160s)[20], long cap, int* script_type,
                     char* err, unsigned long errcap, descr_t* d){
    char e[256];
    if (!descr_parse(in, d, e, sizeof e)){ snprintf(err,errcap,"%s", e); return -1; }
    if (!d->ranged){ start = 0; count = 1; }
    long n = 0;
    for (long i = start; i < start+count && n < cap; i++, n++){
        descr_spk_t sp[4]; int k = descr_expand(d, i, sp, 4);
        if (k != 1){ snprintf(err,errcap,"%s", k < 0 ? descr_last_error() : "Descriptor does not have a corresponding address"); return -1; }
        const unsigned char* h;
        if (!wscan_spk_h160(sp[0].spk, (unsigned long)sp[0].len, &h)){ snprintf(err,errcap,"Descriptor script cannot be scanned for"); return -1; }
        memcpy(h160s[n], h, 20);
        if (script_type && n == 0){
            int t = d->nodes[d->root].type;
            *script_type = t==DN_PKH ? 0 : t==DN_WPKH ? 1 : t==DN_SH ? 2 : t==DN_WSH ? 3 : (t==DN_TR||t==DN_RAWTR) ? 4 : 5;
        }
    }
    return n;
}
long rpc_desc_expand(const char* in, long start, long count,
                     unsigned char (*h160s)[20], long cap, int* script_type,
                     char* err, unsigned long errcap){
    descr_t* d = malloc(sizeof *d); if (!d){ snprintf(err,errcap,"oom"); return -1; }
    long r = rpc_desc_expand_impl(in, start, count, h160s, cap, script_type, err, errcap, d); free(d); return r;
}

static int rpc_desc_address_at_impl(const char* in, long idx, char* out, long cap,
                        char* err, unsigned long errcap, descr_t* d){
    char e[256];
    if (!descr_parse(in, d, e, sizeof e)){ snprintf(err,errcap,"%s", e); return 0; }
    long ec2; const char* em2;
    if (!rpcdesc_address_at(d, idx, out, cap, &ec2, &em2)){ snprintf(err,errcap,"%s", em2); return 0; }
    return 1;
}
int rpc_desc_address_at(const char* in, long idx, char* out, long cap,
                        char* err, unsigned long errcap){
    descr_t* d = malloc(sizeof *d); if (!d){ snprintf(err,errcap,"oom"); return 0; }
    int r = rpc_desc_address_at_impl(in, idx, out, cap, err, errcap, d); free(d); return r;
}

static int cmd_createmultisig(const rj_val* params, rj_val** res, long* ec, const char** em){
    long long req;
    if (!rpc_param_i64(params, 0, &req, ec, em)) return 0;
    if (!params || params->typ != RJ_ARR || params->nitems < 2 || params->items[1]->typ != RJ_ARR){
        *ec = -8; *em = "Invalid parameter, \"keys\" must be an array"; return 0; }
    const rj_val* keys = params->items[1];
    int n = (int)keys->nitems;

    /* 1. validate + collect every pubkey (Core: HexToPubKey before the count
     * checks, so a bad key is reported even when the count is also wrong). */
    static char keyerr[160];
    u8 (*pk)[65] = malloc((size_t)(n > 0 ? n : 1) * 65);
    int* pklen = malloc((size_t)(n > 0 ? n : 1) * sizeof(int));
    if (!pk || !pklen){ free(pk); free(pklen); *ec=-7; *em="oom"; return 0; }
    int uncompressed = 0;
    for (int i = 0; i < n; i++){
        const rj_val* e = keys->items[i];
        int bad = (e->typ != RJ_STR);
        size_t hl = bad ? 0 : strlen(e->str);
        int bytes = (int)(hl/2);
        if (bad || (hl & 1) || (bytes != 33 && bytes != 65)){
            snprintf(keyerr, sizeof keyerr, "Invalid public key: %s", bad ? "" : e->str);
            free(pk); free(pklen); *ec=-5; *em=keyerr; return 0; }
        for (int k = 0; k < bytes; k++){ int hi=hex1(e->str[k*2]),lo=hex1(e->str[k*2+1]);
            if (hi<0||lo<0){ snprintf(keyerr,sizeof keyerr,"Invalid public key: %s", e->str); free(pk);free(pklen);*ec=-5;*em=keyerr;return 0; }
            pk[i][k]=(u8)(hi<<4|lo); }
        u64 qx[4], qy[4];
        if (!pubkey_parse(pk[i], (unsigned long)bytes, qx, qy)){   /* on-curve / valid header */
            snprintf(keyerr, sizeof keyerr, "Invalid public key: %s", e->str);
            free(pk); free(pklen); *ec=-5; *em=keyerr; return 0; }
        pklen[i] = bytes;
        if (bytes == 65) uncompressed = 1;
    }

    /* 2. output type (default legacy) */
    const char* atype = "legacy";
    if (param_present(params, 2)){
        if (params->items[2]->typ != RJ_STR){ free(pk);free(pklen); *ec=-8; *em="Invalid address_type"; return 0; }
        atype = params->items[2]->str;
    }
    int otype;   /* 0 legacy, 1 p2sh-segwit, 2 bech32 */
    static char typeerr[96];
    if (!strcmp(atype,"legacy")) otype=0;
    else if (!strcmp(atype,"p2sh-segwit")) otype=1;
    else if (!strcmp(atype,"bech32")) otype=2;
    else if (!strcmp(atype,"bech32m")){ free(pk);free(pklen); *ec=-5; *em="createmultisig cannot create bech32m multisig addresses"; return 0; }
    else { snprintf(typeerr,sizeof typeerr,"Unknown address type '%s'", atype); free(pk);free(pklen); *ec=-5; *em=typeerr; return 0; }

    /* 3. count checks (AddAndGetMultisigDestination) */
    static char cnterr[160];
    if (req < 1){ free(pk);free(pklen); *ec=-8; *em="a multisignature address must require at least one key to redeem"; return 0; }
    if (n < req){ snprintf(cnterr,sizeof cnterr,"not enough keys supplied (got %d keys, but need at least %lld to redeem)", n, req); free(pk);free(pklen); *ec=-8; *em=cnterr; return 0; }
    if (n > 20){ snprintf(cnterr,sizeof cnterr,"Number of keys involved in the multisignature address creation > 20\nReduce the number"); free(pk);free(pklen); *ec=-8; *em=cnterr; return 0; }

    /* 4. redeemScript = OP_m <key>.. OP_n OP_CHECKMULTISIG */
    int requested_segwit = (otype != 0);
    if (uncompressed) otype = 0;                          /* force legacy */
    u8* redeem = malloc((size_t)n * 66 + 8); if (!redeem){ free(pk);free(pklen); *ec=-7;*em="oom"; return 0; }
    size_t rl = 0;
    rl += cms_push_count(redeem+rl, (int)req);
    for (int i=0;i<n;i++){ redeem[rl++]=(u8)pklen[i]; memcpy(redeem+rl,pk[i],pklen[i]); rl+=pklen[i]; }
    rl += cms_push_count(redeem+rl, n);
    redeem[rl++] = 0xae;
    /* descriptor inner (canonical lowercase keys): multi(m,k1,k2,...) */
    char* dinner = malloc((size_t)n * 132 + 32);
    size_t di = 0;
    if (dinner){
        di += (size_t)snprintf(dinner+di, 32, "multi(%d", (int)req);
        for (int i=0;i<n;i++){ dinner[di++]=','; hex_of(dinner+di, pk[i], (size_t)pklen[i]); di += (size_t)pklen[i]*2; }
        dinner[di++] = ')'; dinner[di] = 0;
    }
    free(pk); free(pklen);

    if (otype == 0 && rl > 520){
        static char szerr[96]; snprintf(szerr,sizeof szerr,"redeemScript exceeds size limit: %zu > 520", rl);
        free(redeem); free(dinner); *ec=-8; *em=szerr; return 0; }

    /* 5. address */
    char addr[128]; addr[0]=0;
    if (otype == 0){                                      /* legacy: P2SH(redeem) */
        cms_p2sh_addr(redeem, rl, addr, sizeof addr);
    } else if (otype == 2){                               /* bech32: P2WSH(redeem) */
        u8 h[32]; sha256_full(h, redeem, (long long)rl);
        u8 spk[34]; spk[0]=0x00; spk[1]=0x20; memcpy(spk+2,h,32);
        wallet_script_to_address(addr, sizeof addr, spk, 34);
    } else {                                              /* p2sh-segwit: P2SH(P2WSH(redeem)) */
        u8 h[32]; sha256_full(h, redeem, (long long)rl);
        u8 wspk[34]; wspk[0]=0x00; wspk[1]=0x20; memcpy(wspk+2,h,32);
        cms_p2sh_addr(wspk, 34, addr, sizeof addr);
    }

    rj_val* o = rj_obj();
    rj_obj_set(o, "address", rj_str(addr));
    { char* hx = malloc(rl*2+1); if (hx){ hex_of(hx, redeem, rl); rj_obj_set(o,"redeemScript", rj_str(hx)); free(hx); } }
    /* descriptor: sh(multi..) / wsh(multi..) / sh(wsh(multi..)) + checksum */
    if (dinner){
        char* dwrap = malloc(strlen(dinner) + 16);
        if (dwrap){
            if (otype == 0)      sprintf(dwrap, "sh(%s)", dinner);
            else if (otype == 2) sprintf(dwrap, "wsh(%s)", dinner);
            else                 sprintf(dwrap, "sh(wsh(%s))", dinner);
            char cks[9];
            if (desc_checksum(dwrap, cks)){
                char* desc = malloc(strlen(dwrap) + 10);
                if (desc){ sprintf(desc, "%s#%s", dwrap, cks); rj_obj_set(o,"descriptor", rj_str(desc)); free(desc); }
            }
            free(dwrap);
        }
    }
    if (requested_segwit && uncompressed){
        rj_val* w = rj_arr();
        rj_arr_push(w, rj_str("Unable to make chosen address type, please ensure no uncompressed public keys are present."));
        rj_obj_set(o, "warnings", w);
    }
    free(dinner);
    free(redeem);
    *res = o;
    return 1;
}

/* ---- getblockstats (Core rpc/blockchain.cpp) -------------------------------
 * Per-block statistics. Block-only fields (sizes/weights/counts/subsidy/times/
 * total_out/utxo_increase) are computed from block data and match Core exactly.
 * The fee/feerate fields and utxo_size_inc{,_actual} need the block's spent
 * prevout values+sizes (undo data). Without undo Core's GetUndoChecked throws
 * RPC_MISC_ERROR "Can't read undo data from disk" (the genesis block excepted:
 * it has no undo and answers), and so does this, since 2026-09-08: the eleven
 * keys used to be OMITTED, which mempool.space's block indexer read as
 * `stats.feerate_percentiles[2]` of undefined and died on the first block
 * below production's undo history. A caller that must have the block-only
 * fields for such a height has getblock (whose fee omission matches Core).
 * Constants match Core: PER_UTXO_OVERHEAD = sizeof(COutPoint) +
 * sizeof(uint32_t) + sizeof(bool) = 36+4+1 = 41 (rpc/blockchain.cpp). It was
 * 40 here -- the coinbase bool missing -- so utxo_size_inc{,_actual} ran
 * short by exactly (outputs - inputs) bytes on every block (caught against
 * a local Core 29.4 on 2026-09-24: h=170 232 vs 234, h=812400 -73742 vs
 * -74799). */
#define GBS_PER_UTXO_OVERHEAD 41
static u64 gbs_subsidy(long h){ long era=h/g_halving_interval; if (era>=64) return 0; return 5000000000ULL >> era; }
static long gbs_cs(u64 n){ if (n<253) return 1; if (n<=0xffff) return 3; if (n<=0xffffffffULL) return 5; return 9; }
static int gbs_unspendable(const u8* s, u64 len){ return (len>0 && s[0]==0x6a) || len>10000; }
/* Core's IsBIP30Repeat (validation.cpp): the two mainnet blocks whose
 * coinbase repeats an earlier coinbase's txid and so OVERWRITES that coin
 * instead of adding one. getblockstats leaves their coinbase outputs out of
 * utxo_increase_actual / utxo_size_inc_actual ("don't change the UTXO set
 * counts"); matched by height AND hash, so no other chain can trip it.
 * Caught against a local Core 29.4 on 2026-09-24: h=91842 actual 116 vs 0. */
static int gbs_bip30_repeat(long h, const u8* hdr){
    static const struct { long h; const char* hash; } k[] = {
        { 91842, "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec" },
        { 91880, "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721" },
    };
    for (unsigned i = 0; i < sizeof k / sizeof k[0]; i++){
        if (h != k[i].h) continue;
        u8 d[32]; char hx[65]; sha256d(d, hdr, 80); hex_rev(hx, d, 32);
        return !strcmp(hx, k[i].hash);
    }
    return 0;
}
static int gbs_cmp_u64(const void* a, const void* b){ u64 x=*(const u64*)a, y=*(const u64*)b; return (x<y)?-1:(x>y)?1:0; }
typedef struct { long long fr, wt; } gbs_frp;
static int gbs_cmp_frp(const void* a, const void* b){ long long x=((const gbs_frp*)a)->fr, y=((const gbs_frp*)b)->fr; return (x<y)?-1:(x>y)?1:0; }
static long long gbs_median(u64* a, long n){ if (n==0) return 0; qsort(a,(size_t)n,sizeof(u64),gbs_cmp_u64); if (n%2==0) return (long long)((a[n/2-1]+a[n/2])/2); return (long long)a[n/2]; }

static int gbs_cmp_str(const void* a, const void* b){ return strcmp(*(const char* const*)a, *(const char* const*)b); }
static int cmd_getblockstats(const rj_val* params, rj_val** res, long* ec, const char** em){
    /* stats (position 2): Core's RPCHelpMan type-checks it before anything
     * runs -- an array (or null / absent = every stat) of strings. */
    static char gbs_eb[256];
    const rj_val* a1 = (params && params->typ==RJ_ARR && params->nitems>=2) ? params->items[1] : NULL;
    if (a1 && a1->typ != RJ_NULL && a1->typ != RJ_ARR){ *ec=-3; *em=rj_wrong_type_msg(gbs_eb, sizeof gbs_eb, 2, "stats", a1, "array"); return 0; }
    if (a1 && a1->typ == RJ_ARR)
        for (size_t i = 0; i < a1->nitems; i++)
            if (!a1->items[i] || a1->items[i]->typ != RJ_STR){ *ec=-3; *em=rj_wrong_type_msg_bare(gbs_eb, sizeof gbs_eb, a1->items[i], "string"); return 0; }
    long tip = refresh(); long h;
    const rj_val* a0 = (params && params->typ==RJ_ARR && params->nitems>=1) ? params->items[0] : NULL;
    if (a0 && a0->typ==RJ_NUM){            /* height form */
        h = strtol(a0->str,0,10);
        if (h < 0 || h > tip){ *ec=-8; *em="Target block height out of range"; return 0; }
    } else {                                /* blockhash form */
        if (!lookup_block_param(params, 0, 1, &h, ec, em)) return 0;
    }
    long len = read_block(h);
    if (len < 0){ *ec=-1; *em="Block not available"; return 0; }
    const u8* blk=g_blockbuf; const u8* end=blk+len;
    u64 c; u64 ntx=read_varint(blk+80, end, &c);
    const u8* p = blk+80+c;

    static u64 uvals[600000]; static u32 uslens[600000];
    long undo_n = undo_block_prevouts(h, uvals, uslens, 600000);
    int have_undo = (undo_n >= 0); long undo_cur = 0;
    if (!have_undo && h > 0){ *ec=-1; *em="Can't read undo data from disk"; return 0; }   /* Core: GetUndoChecked */

    const int bip30_repeat = gbs_bip30_repeat(h, blk);
    long long inputs=0, outputs=0, total_out=0, total_size=0, total_weight=0;
    long long swtotal_size=0, swtotal_weight=0, swtxs=0;
    long long maxtxsize=0, mintxsize=0; int have_txsz=0;
    long long utxos=0, utxo_size_inc=0, utxo_size_inc_actual=0;
    long long maxfee=0, minfee=0, totalfee=0, maxfeerate=0, minfeerate=0; int have_fee=0;
    static u64 txsize_arr[600000]; long txsize_n=0;
    static u64 fee_arr[600000]; long fee_n=0;
    static gbs_frp frp[600000]; long frp_n=0;

    for (u64 i=0;i<ntx;i++){
        txw_t w;
        if (!tx_walk(p, end, &w)){ *ec=-1; *em="Block decode failed"; return 0; }
        int coinbase=(i==0);
        const u8* op=w.vout; u64 ccx; read_varint(op, end, &ccx); op += ccx;   /* skip vout count varint */
        u64 tx_total_out=0;
        for (u64 j=0;j<w.n_out;j++){
            u64 val=rd64(op); op+=8; u64 cc2; u64 sl=read_varint(op,end,&cc2); const u8* spk=op+cc2; op+=cc2+sl;
            tx_total_out += val;
            long out_size = 8 + gbs_cs(sl) + (long)sl + GBS_PER_UTXO_OVERHEAD;
            outputs++; utxo_size_inc += out_size;
            if (h==0 || (coinbase && bip30_repeat)) continue;   /* Core: genesis + IsBIP30Repeat coinbases */
            if (gbs_unspendable(spk, sl)) continue;
            utxos++; utxo_size_inc_actual += out_size;
        }
        if (coinbase){ p += w.len; continue; }
        inputs += (long long)w.n_in;
        total_out += (long long)tx_total_out;
        long long tx_size=(long long)w.len, weight=3*(long long)w.stripped+(long long)w.len;
        txsize_arr[txsize_n++]=(u64)tx_size;
        if (!have_txsz){ maxtxsize=mintxsize=tx_size; have_txsz=1; } else { if(tx_size>maxtxsize)maxtxsize=tx_size; if(tx_size<mintxsize)mintxsize=tx_size; }
        total_size += tx_size; total_weight += weight;
        if (w.segwit){ swtxs++; swtotal_size+=tx_size; swtotal_weight+=weight; }
        if (have_undo && undo_cur+(long)w.n_in <= undo_n){
            u64 tx_total_in=0;
            for (u64 k=0;k<w.n_in;k++){ tx_total_in += uvals[undo_cur+k];
                long ps=8+gbs_cs(uslens[undo_cur+k])+(long)uslens[undo_cur+k]+GBS_PER_UTXO_OVERHEAD; utxo_size_inc-=ps; utxo_size_inc_actual-=ps; }
            long long txfee=(long long)tx_total_in-(long long)tx_total_out;
            fee_arr[fee_n++]=(u64)txfee;
            if (!have_fee){ maxfee=minfee=txfee; have_fee=1; } else { if(txfee>maxfee)maxfee=txfee; if(txfee<minfee)minfee=txfee; }
            totalfee += txfee;
            long long feerate = weight ? (txfee*4)/weight : 0;
            frp[frp_n].fr=feerate; frp[frp_n].wt=weight; frp_n++;
            if (frp_n==1||feerate>maxfeerate) maxfeerate=feerate;
            if (frp_n==1||feerate<minfeerate) minfeerate=feerate;
        }
        if (have_undo) undo_cur += (long)w.n_in;
        p += w.len;
    }

    rj_val* o=rj_obj();
    long long vtxm1 = (long long)ntx - 1;
    char hx[65]; { u8 rec[48]; if (read_idx_rec(h, rec)) hex_rev(hx, rec, 32); else hx[0]=0; }
    if (have_undo){
        rj_obj_set(o,"avgfee", rj_numf("%lld", vtxm1>0 ? totalfee/vtxm1 : 0));
        rj_obj_set(o,"avgfeerate", rj_numf("%lld", total_weight ? (totalfee*4)/total_weight : 0));
    }
    rj_obj_set(o,"avgtxsize", rj_numf("%lld", vtxm1>0 ? total_size/vtxm1 : 0));
    if (hx[0]) rj_obj_set(o,"blockhash", rj_str(hx));
    if (have_undo){
        gbs_frp* a=frp; qsort(a,(size_t)frp_n,sizeof(gbs_frp),gbs_cmp_frp);
        long long pr[5]={0,0,0,0,0};
        if (frp_n>0){
            double wts[5]={total_weight/10.0,total_weight/4.0,total_weight/2.0,(total_weight*3.0)/4.0,(total_weight*9.0)/10.0};
            int idx=0; long long cum=0;
            for (long e=0;e<frp_n;e++){ cum+=a[e].wt; while(idx<5 && (double)cum>=wts[idx]){ pr[idx]=a[e].fr; idx++; } }
            for (int k=idx;k<5;k++) pr[k]=a[frp_n-1].fr;
        }
        rj_val* fa=rj_arr(); for(int k=0;k<5;k++) rj_arr_push(fa, rj_numf("%lld", pr[k])); rj_obj_set(o,"feerate_percentiles", fa);
    }
    rj_obj_set(o,"height", rj_numf("%ld", h));
    rj_obj_set(o,"ins", rj_numf("%lld", inputs));
    if (have_undo){
        rj_obj_set(o,"maxfee", rj_numf("%lld", maxfee));
        rj_obj_set(o,"maxfeerate", rj_numf("%lld", maxfeerate));
    }
    rj_obj_set(o,"maxtxsize", rj_numf("%lld", maxtxsize));
    if (have_undo) rj_obj_set(o,"medianfee", rj_numf("%lld", gbs_median(fee_arr, fee_n)));
    rj_obj_set(o,"mediantime", rj_numf("%ld", median_time_past(h)));
    rj_obj_set(o,"mediantxsize", rj_numf("%lld", gbs_median(txsize_arr, txsize_n)));
    if (have_undo){
        rj_obj_set(o,"minfee", rj_numf("%lld", have_fee?minfee:0));
        rj_obj_set(o,"minfeerate", rj_numf("%lld", have_fee?minfeerate:0));
    }
    rj_obj_set(o,"mintxsize", rj_numf("%lld", have_txsz?mintxsize:0));
    rj_obj_set(o,"outs", rj_numf("%lld", outputs));
    rj_obj_set(o,"subsidy", rj_numf("%llu", (unsigned long long)gbs_subsidy(h)));
    rj_obj_set(o,"swtotal_size", rj_numf("%lld", swtotal_size));
    rj_obj_set(o,"swtotal_weight", rj_numf("%lld", swtotal_weight));
    rj_obj_set(o,"swtxs", rj_numf("%lld", swtxs));
    { u8 hdr[80]; long t=0; if (read_block_prefix(h,hdr,80)==1) t=rd32(hdr+68); rj_obj_set(o,"time", rj_numf("%ld", t)); }
    rj_obj_set(o,"total_out", rj_numf("%lld", total_out));
    rj_obj_set(o,"total_size", rj_numf("%lld", total_size));
    rj_obj_set(o,"total_weight", rj_numf("%lld", total_weight));
    if (have_undo) rj_obj_set(o,"totalfee", rj_numf("%lld", totalfee));
    rj_obj_set(o,"txs", rj_numf("%llu", (unsigned long long)ntx));
    rj_obj_set(o,"utxo_increase", rj_numf("%lld", outputs-inputs));
    if (have_undo) rj_obj_set(o,"utxo_size_inc", rj_numf("%lld", utxo_size_inc));
    rj_obj_set(o,"utxo_increase_actual", rj_numf("%lld", utxos-inputs));
    if (have_undo) rj_obj_set(o,"utxo_size_inc_actual", rj_numf("%lld", utxo_size_inc_actual));
    /* The stats filter (2026-09-24; it used to be ignored -- every call got
     * all 31 keys). Core collects the names into a std::set -- so the reply
     * is in byte order with duplicates folded, whatever order they were
     * asked in -- and an empty list means every stat. A name that is not a
     * statistic is -8 "Invalid selected statistic '<name>'". */
    if (a1 && a1->typ == RJ_ARR && a1->nitems > 0){
        const char** names = malloc(a1->nitems * sizeof *names); size_t nn = 0;
        if (!names){ rj_free(o); *ec=-32603; *em="Out of memory"; return 0; }
        for (size_t i = 0; i < a1->nitems; i++) names[nn++] = a1->items[i]->str;
        qsort(names, nn, sizeof names[0], gbs_cmp_str);
        rj_val* sel = rj_obj();
        for (size_t i = 0; i < nn; i++){
            if (i && !strcmp(names[i], names[i-1])) continue;
            const rj_val* v = rj_obj_get(o, names[i]);
            if (!v){
                snprintf(gbs_eb, sizeof gbs_eb, "Invalid selected statistic '%s'", names[i]);
                free(names); rj_free(sel); rj_free(o); *ec=-8; *em=gbs_eb; return 0;
            }
            rj_obj_set(sel, names[i], rj_clone(v));
        }
        free(names); rj_free(o); o = sel;
    }
    *res=o;
    return 1;
}

/* ==== the remaining Blockchain category (2026-08-25) =====================
 * Same rule as the network and wallet slices: real state, or Core's exact
 * answer for this node's situation, or an explicit refusal naming the gap.
 * Shapes taken off the running oracle, not from memory. */

/* ---- getchainstates -----------------------------------------------------
 * Core reports one entry per chainstate; a node with no assumeutxo snapshot
 * loaded has exactly one, which is this node's permanent condition (there is
 * no snapshot loader -- see loadtxoutset below). So the single-element array
 * is the complete answer, not a first element. */
static int cmd_getchainstates(rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    u8 hdr[80]; if (read_block_prefix(tip, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u8 rec[48]; read_idx_rec(tip, rec);
    char hx[65];
    long hh = headers_height(tip);
    rj_val* cs = rj_obj();
    rj_obj_set(cs, "blocks", rj_numf("%ld", tip));
    hex_rev(hx, rec, 32); rj_obj_set(cs, "bestblockhash", rj_str(hx));
    u32 bits = rd32(hdr + 72);
    rj_obj_set(cs, "bits", rj_strf("%08x", bits));
    target_hex(bits, hx); rj_obj_set(cs, "target", rj_str(hx));
    rj_obj_set(cs, "difficulty", rj_double(difficulty_of(bits)));
    double prog = hh >= 0 ? (double)(tip + 1) / (double)(hh + 1) : 1.0;
    if (prog > 1.0) prog = 1.0;
    rj_obj_set(cs, "verificationprogress", rj_double(prog));
    /* coins_db_cache_bytes / coins_tip_cache_bytes are Core's LevelDB and
     * in-memory coin cache sizes. This node has neither -- its UTXO set is
     * an LSM with its own sizing -- so the fields are OMITTED rather than
     * filled with a number that would describe a cache that does not exist.
     * Re-checked 2026-09-18 against v31.1: there is no coins-DB read cache
     * here at all (reads go through the page cache), and the memtable is a
     * write buffer sized by mode inside the download worker, not a coin
     * cache this process could report. docs/CORE_DIVERGENCES.md. */
    rj_obj_set(cs, "validated", rj_bool(1));
    rj_val* arr = rj_arr(); rj_arr_push(arr, cs);
    rj_val* o = rj_obj();
    rj_obj_set(o, "headers", rj_numf("%ld", hh));
    rj_obj_set(o, "chainstates", arr);
    *res = o;
    return 1;
}

/* ---- getdeploymentinfo --------------------------------------------------
 * The heights come from script_flags_consts.h, which validation/
 * gen_script_flags.py generates from Core's own kernel/chainparams.cpp --
 * the SAME parse that produces the .inc the script-flag path assembles
 * against. So this reports what the node actually ENFORCES; it cannot drift
 * from consensus behaviour by being edited on its own, and a Core upgrade
 * that moved a height would move both together.
 *
 * P2SH and WITNESS are not listed: Core buries them at height 0
 * unconditionally (with two by-hash exceptions). TAPROOT's script flag is
 * unconditional in the same way, but v31.1 still LISTS taproot, as a BIP9
 * deployment -- see gdi_bip9 below.
 *
 * 2026-09-18: this comment used to say "this Core reports exactly the five
 * below", and a test pinned the count at five. "This Core" was the v31.99
 * development oracle, where taproot has since been buried and dropped from
 * the list. v31.1 -- the release this node tracks -- reports six on mainnet:
 * the five buried ones and taproot. */
static void gdi_dep(rj_val* o, const char* name, long h, long tip){
    rj_val* d = rj_obj();
    rj_obj_set(d, "type", rj_str("buried"));
    rj_obj_set(d, "active", rj_bool(tip + 1 >= h));   /* active AT the next block */
    rj_obj_set(d, "height", rj_numf("%ld", h));
    rj_obj_set(o, name, d);
}
/* ---- BIP9 deployments (Core v31.1 versionbits.cpp) ----------------------
 * v31.1 lists two: testdummy and taproot, in that order (DeploymentInfo).
 * Master has since buried taproot, which is how its absence here went
 * unnoticed -- the v31.99 oracle lists neither on mainnet.
 *
 * The parameters are per chain, from v31.1's kernel/chainparams.cpp:
 *   main      taproot    bit 2, start 1619222400, timeout 1628640000,
 *                        min_activation_height 709632, 1815 of 2016
 *   testnet4  taproot    ALWAYS_ACTIVE, 1512 of 2016
 *   signet    taproot    ALWAYS_ACTIVE, 1815 of 2016
 *   regtest   testdummy  bit 28, start 0, NO_TIMEOUT, 0, 108 of 144
 *             taproot    ALWAYS_ACTIVE, 108 of 144
 * testdummy is NEVER_ACTIVE outside regtest, and Core lists nothing for a
 * NEVER_ACTIVE deployment (DeploymentEnabled).
 *
 * TRANSCRIBED, not generated like the buried heights: gen_script_flags.py
 * reads a master tree, where DEPLOYMENT_TAPROOT no longer exists. The
 * values are checked against a live v31.1 instead (mainnet at the boundary
 * heights, and the regtest differential). Taproot's SCRIPT flag does not
 * come from this table -- it is unconditional, as in Core -- so an error
 * here could misreport, never misvalidate.
 *
 * The state of the block after `prev` is decided at period boundaries from
 * the previous period's blocks, exactly as GetStateFor walks them. The walk
 * runs forward from genesis and stops at a terminal state (ACTIVE, FAILED):
 * on mainnet that is one MTP per boundary until taproot's start, three
 * signalling periods, and a few LOCKED_IN boundaries -- ~10k header reads. */
typedef struct {
    const char* name;
    int bit;
    long long start, timeout;          /* Core's nStartTime / nTimeout */
    long min_act, period, threshold;
} b9_dep;
#define B9_ALWAYS_ACTIVE (-1LL)
#define B9_NO_TIMEOUT    9223372036854775807LL
static const b9_dep B9_MAIN_TAPROOT  = { "taproot",   2,  1619222400LL,     1628640000LL,  709632, 2016, 1815 };
static const b9_dep B9_T4_TAPROOT    = { "taproot",   2,  B9_ALWAYS_ACTIVE, B9_NO_TIMEOUT, 0,      2016, 1512 };
static const b9_dep B9_SIG_TAPROOT   = { "taproot",   2,  B9_ALWAYS_ACTIVE, B9_NO_TIMEOUT, 0,      2016, 1815 };
static const b9_dep B9_REG_TESTDUMMY = { "testdummy", 28, 0,                B9_NO_TIMEOUT, 0,      144,  108  };
static const b9_dep B9_REG_TAPROOT   = { "taproot",   2,  B9_ALWAYS_ACTIVE, B9_NO_TIMEOUT, 0,      144,  108  };

enum { TS_DEFINED, TS_STARTED, TS_LOCKED_IN, TS_ACTIVE, TS_FAILED };
static const char* ts_name(int s){ return s == TS_DEFINED ? "defined" : s == TS_STARTED ? "started" : s == TS_LOCKED_IN ? "locked_in" : s == TS_ACTIVE ? "active" : "failed"; }
/* 1 signals, 0 does not, -1 the header is not readable (pruned / hole) */
static int b9_signals(const b9_dep* d, long h){
    u8 v4[4]; if (read_block_prefix(h, v4, sizeof v4) != 1) return -1;
    u32 v = rd32(v4);
    return (v & 0xE0000000u) == 0x20000000u && (v & (1u << d->bit)) != 0;
}
/* median_time_past, except that a header it cannot read is a failure rather
 * than a shorter window: a state machine fed a wrong MTP reports a wrong
 * state. */
static int b9_mtp(long h, long* out){
    u32 t[11]; int n = 0;
    for (long i = h; i >= 0 && n < 11; i--){
        u8 hdr[80]; if (read_block_prefix(i, hdr, 80) != 1) return 0;
        t[n++] = rd32(hdr + 68);
    }
    if (n == 0) return 0;
    qsort(t, (size_t)n, sizeof t[0], cmp_u32);
    *out = (long)t[n/2]; return 1;
}
/* The state of the block after `prev` (-1: genesis, whose parent is null),
 * and in *since the first height of the period it has held since
 * (GetStateSinceHeightFor: 0 for DEFINED and for ALWAYS_ACTIVE). -1 when a
 * header the walk needs cannot be read. */
static int b9_state_for(const b9_dep* d, long prev, long* since){
    *since = 0;
    if (d->start == B9_ALWAYS_ACTIVE) return TS_ACTIVE;
    int state = TS_DEFINED; long s = 0;
    for (long b = d->period; b - 1 <= prev; b += d->period){
        long p = b - 1, m; int next = state;
        switch (state){
        case TS_DEFINED:
            if (!b9_mtp(p, &m)) return -1;
            if (m >= d->start) next = TS_STARTED;
            break;
        case TS_STARTED: {
            long count = 0;
            for (long k = b - d->period; k <= p; k++){ int sg = b9_signals(d, k); if (sg < 0) return -1; count += sg; }
            if (count >= d->threshold) next = TS_LOCKED_IN;
            else { if (!b9_mtp(p, &m)) return -1; if (m >= d->timeout) next = TS_FAILED; }
        } break;
        case TS_LOCKED_IN:
            if (p + 1 >= d->min_act) next = TS_ACTIVE;
            break;
        default: break;
        }
        if (next != state){ state = next; s = b; }
        if (state == TS_ACTIVE || state == TS_FAILED) break;   /* terminal */
    }
    *since = s; return state;
}
/* One deployment, shaped as rpc/blockchain.cpp SoftForkDescPushBack (BIP9).
 * A walk that hits an unreadable header (a pruned node asked about taproot's
 * signalling window) OMITS the deployment: every field here is derived from
 * those headers, and there is nothing true to put in their place. */
static void gdi_bip9(rj_val* o, const b9_dep* d, long tip){
    long since = 0, since_next = 0;
    int cur = b9_state_for(d, tip - 1, &since), next = b9_state_for(d, tip, &since_next);
    if (cur < 0 || next < 0) return;
    int has_signal = (cur == TS_STARTED || cur == TS_LOCKED_IN);
    rj_val* b9 = rj_obj();
    if (has_signal) rj_obj_set(b9, "bit", rj_numf("%d", d->bit));
    rj_obj_set(b9, "start_time", rj_numf("%lld", d->start));
    rj_obj_set(b9, "timeout", rj_numf("%lld", d->timeout));
    rj_obj_set(b9, "min_activation_height", rj_numf("%ld", d->min_act));
    rj_obj_set(b9, "status", rj_str(ts_name(cur)));
    rj_obj_set(b9, "since", rj_numf("%ld", since));
    rj_obj_set(b9, "status_next", rj_str(ts_name(next)));
    if (has_signal){
        long in_period = 1 + (tip % d->period), elapsed = 0, count = 0;
        char* sig = malloc((size_t)in_period + 1);
        if (!sig){ rj_free(b9); return; }
        memset(sig, '-', (size_t)in_period); sig[in_period] = 0;
        for (long k = tip; in_period > 0; k--){
            elapsed++; in_period--;
            int sg = b9_signals(d, k);
            if (sg < 0){ free(sig); rj_free(b9); return; }
            if (sg){ count++; sig[in_period] = '#'; }
        }
        rj_val* st = rj_obj(); rj_obj_set(st, "period", rj_numf("%ld", d->period)); rj_obj_set(st, "elapsed", rj_numf("%ld", elapsed)); rj_obj_set(st, "count", rj_numf("%ld", count));
        /* LOCKED_IN zeroes threshold and possible, and Core then prints neither */
        if (cur == TS_STARTED){ int possible = (d->period - d->threshold) >= (elapsed - count); rj_obj_set(st, "threshold", rj_numf("%ld", d->threshold)); rj_obj_set(st, "possible", rj_bool(possible)); }
        rj_obj_set(b9, "statistics", st); rj_obj_set(b9, "signalling", rj_str(sig));
        free(sig);
    }
    rj_val* rv = rj_obj(); rj_obj_set(rv, "type", rj_str("bip9"));
    int active = 0;
    if (cur == TS_ACTIVE){ rj_obj_set(rv, "height", rj_numf("%ld", since)); active = since <= tip + 1; }
    else if (next == TS_ACTIVE){ rj_obj_set(rv, "height", rj_numf("%ld", tip + 1)); active = 1; }
    rj_obj_set(rv, "active", rj_bool(active));
    rj_obj_set(rv, "bip9", b9);
    rj_obj_set(o, d->name, rv);
}

static int cmd_getdeploymentinfo(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    /* Core takes an optional blockhash; default is the tip. */
    if (params && params->typ == RJ_ARR && params->nitems >= 1 &&
        params->items[0]->typ == RJ_STR){
        long h;
        if (!lookup_block_param(params, 0, 1, &h, ec, em)) return 0;
        tip = h;
    }
    u8 rec[48]; if (!read_idx_rec(tip, rec)){ *ec = -1; *em = "Block not available"; return 0; }
    char hx[65]; hex_rev(hx, rec, 32);
    rj_val* o = rj_obj();
    rj_obj_set(o, "hash", rj_str(hx));
    rj_obj_set(o, "height", rj_numf("%ld", tip));
    /* the chain's heights (script_flags_consts.h carries every chain's;
     * 2026-09-08: this reported mainnet's on regtest -- bip34 at 227,931) */
    long h_bip34 = SFC_HEIGHT_BIP34, h_dersig = SFC_HEIGHT_DERSIG, h_cltv = SFC_HEIGHT_CLTV, h_csv = SFC_HEIGHT_CSV, h_segwit = SFC_HEIGHT_SEGWIT;
    int regtest = !strcmp(g_chain_name, "regtest");
    if (regtest){ h_bip34 = SFC_R_HEIGHT_BIP34; h_dersig = SFC_R_HEIGHT_DERSIG; h_cltv = SFC_R_HEIGHT_CLTV; h_csv = SFC_R_HEIGHT_CSV; h_segwit = SFC_R_HEIGHT_SEGWIT; }
    else if (!strcmp(g_chain_name, "testnet4")){ h_bip34 = SFC_T_HEIGHT_BIP34; h_dersig = SFC_T_HEIGHT_DERSIG; h_cltv = SFC_T_HEIGHT_CLTV; h_csv = SFC_T_HEIGHT_CSV; h_segwit = SFC_T_HEIGHT_SEGWIT; }
    else if (!strcmp(g_chain_name, "signet")){ h_bip34 = SFC_S_HEIGHT_BIP34; h_dersig = SFC_S_HEIGHT_DERSIG; h_cltv = SFC_S_HEIGHT_CLTV; h_csv = SFC_S_HEIGHT_CSV; h_segwit = SFC_S_HEIGHT_SEGWIT; }
    /* script_flags: Core's GetBlockScriptFlags for THIS block, names in
     * Core's sorted order. P2SH, WITNESS and TAPROOT are on for every block
     * except CMainParams' two script_flag_exceptions, which replace them
     * (by hash; generated into script_flags_consts.h); the buried four are
     * on from their height, DeploymentActiveAt the block itself.
     *
     * 2026-09-18: this reported the flags for the NEXT block, held WITNESS
     * back until segwit's height, and knew nothing of the two exceptions.
     * All three agree at the tip once everything is buried, which is the only
     * height the old differential asked about; a blockhash argument showed
     * them against v31.1 on mainnet (363724 listed DERSIG a block early,
     * 170060 must be empty, 692261 must lack TAPROOT). */
    unsigned f = (1u << SFC_BIT_P2SH) | (1u << SFC_BIT_WITNESS) | (1u << SFC_BIT_TAPROOT);
    if (!strcmp(g_chain_name, "main")){
        if (!strcmp(hx, SFC_EXC_BIP16_HASH_HEX))        f = SFC_EXC_BIP16_FLAGS;
        else if (!strcmp(hx, SFC_EXC_TAPROOT_HASH_HEX)) f = SFC_EXC_TAPROOT_FLAGS;
    }
    if (tip >= h_dersig) f |= 1u << SFC_BIT_DERSIG;
    if (tip >= h_cltv)   f |= 1u << SFC_BIT_CLTV;
    if (tip >= h_csv)    f |= 1u << SFC_BIT_CSV;
    if (tip >= h_segwit) f |= 1u << SFC_BIT_NULLDUMMY;
    static const struct { const char* name; int bit; } SFN[] = {
        { "CHECKLOCKTIMEVERIFY", SFC_BIT_CLTV }, { "CHECKSEQUENCEVERIFY", SFC_BIT_CSV },
        { "DERSIG", SFC_BIT_DERSIG }, { "NULLDUMMY", SFC_BIT_NULLDUMMY }, { "P2SH", SFC_BIT_P2SH },
        { "TAPROOT", SFC_BIT_TAPROOT }, { "WITNESS", SFC_BIT_WITNESS } };
    rj_val* sf = rj_arr();
    for (size_t i = 0; i < sizeof SFN / sizeof SFN[0]; i++)
        if (f & (1u << SFN[i].bit)) rj_arr_push(sf, rj_str(SFN[i].name));
    rj_obj_set(o, "script_flags", sf);
    rj_val* dep = rj_obj();
    gdi_dep(dep, "bip34",  h_bip34,  tip);
    gdi_dep(dep, "bip66",  h_dersig, tip);
    gdi_dep(dep, "bip65",  h_cltv,   tip);
    gdi_dep(dep, "csv",    h_csv,    tip);
    gdi_dep(dep, "segwit", h_segwit, tip);
    if (regtest){ gdi_bip9(dep, &B9_REG_TESTDUMMY, tip); gdi_bip9(dep, &B9_REG_TAPROOT, tip); }
    else if (!strcmp(g_chain_name, "testnet4")) gdi_bip9(dep, &B9_T4_TAPROOT, tip);
    else if (!strcmp(g_chain_name, "signet"))   gdi_bip9(dep, &B9_SIG_TAPROOT, tip);
    else                                        gdi_bip9(dep, &B9_MAIN_TAPROOT, tip);
    rj_obj_set(o, "deployments", dep);
    *res = o;
    return 1;
}

/* ---- getchaintxstats ----------------------------------------------------
 * Core keeps the cumulative transaction count (m_chain_tx_count, "nChainTx")
 * in every block-index entry, so getchaintxstats is O(1) there. This node
 * stores no such field, and until 2026-09-19 this handler cached the count for
 * exactly ONE height -- the tip it last answered -- and re-walked every block
 * from genesis whenever the tip moved. On production that was 46,616 ms after
 * each new block (12 ms the evening before, while the tip happened to stand
 * still), under the RPC execution lock, so every other call waited too.
 *
 * Now the count is a per-height cumulative array, built once and extended by
 * exactly the new blocks:
 *   cum[h] = transactions in blocks 0..h, tag[h] = first 8 bytes of block
 *   h's hash (sha256d of its header, which is what index.dat records).
 * The tip case costs O(new blocks) block-prefix reads (header + tx-count
 * varint, ~89 bytes); any historical height already covered is O(1).
 *
 * REORGS. The array is only ever read at a height whose tag still matches the
 * block index.dat names there; a mismatch means the chain changed under the
 * cache. Matching is monotone along a chain (true up to the fork, false
 * above), so the fork point is found by binary search over index records and
 * everything above it is dropped and re-walked. While extending, each new
 * header must link (prevhash prefix) to the tag below it; a break means a
 * reorg landed mid-walk, handled the same way.
 *
 * MEMORY: 16 bytes per height (15.5 MB at 967k heights), growing only with
 * the chain.
 *
 * THREADS. Everything here -- the array, the counters, and a private store
 * handle (g_ctx_st) -- belongs to g_ctx_mu. The handler touches nothing the
 * write-locked handlers share (the hash->height lookup takes g_idx_mu), so
 * the server runs it WITHOUT the execution lock: a cold first build blocks
 * only other getchaintxstats callers, never uptime or getblock.
 *
 * UNKNOWN COUNTS. If any height up to the one asked for is unreadable -- a
 * pruned or holed archive -- the count is unknown, and Core's rule for an
 * unknown m_chain_tx_count applies: txcount, window_tx_count and txrate are
 * omitted. A short count that looks like a real one would be worse than an
 * absent one, because the caller cannot tell the difference. */
static pthread_mutex_t g_ctx_mu = PTHREAD_MUTEX_INITIALIZER;
static u8   g_ctx_st[ST_SIZE]; static int g_ctx_st_ok;
static unsigned long long* g_ctx_cum;      /* cum[h]: txs in blocks 0..h */
static u64* g_ctx_tag;                     /* first 8 bytes (wire) of block h's hash */
static long g_ctx_n, g_ctx_cap;            /* heights [0, g_ctx_n) are cached */
static unsigned long long g_ctx_reads;     /* block prefixes read: the cost, for tests */
#define CTX_PREFETCH 4096                  /* prefixes requested ahead per batch */

static u64 ctx_tag_of(const u8* hash_wire){ u64 t; memcpy(&t, hash_wire, 8); return t; }

/* Is cached height h still the block the archive has at h? */
static int ctx_matches(long h){
    u8 rec[48];
    if (h < 0 || h >= g_ctx_n) return 0;
    if (!read_idx_rec(h, rec) || !rec_present(rec)) return 0;
    return ctx_tag_of(rec) == g_ctx_tag[h];
}
/* `bad` is a height known not to match (or the first one past the cache):
 * keep the longest prefix that still matches. */
static void ctx_unwind(long bad){
    long lo = 0, hi = (bad < g_ctx_n ? bad : g_ctx_n) - 1, keep = -1;
    while (lo <= hi){
        long mid = lo + (hi - lo) / 2;
        if (ctx_matches(mid)){ keep = mid; lo = mid + 1; } else hi = mid - 1;
    }
    g_ctx_n = keep + 1;
}
/* Extend the cache through height `to`. 1 covered, 0 some height is
 * unreadable (pruned, a hole, not stored yet), -1 the headers stopped linking
 * (a reorg landed mid-walk; the caller unwinds and retries). */
static int ctx_extend(long to){
    if (to < g_ctx_n) return 1;
    if (to >= g_ctx_cap){
        long cap = g_ctx_cap ? g_ctx_cap : 4096;
        while (cap <= to) cap *= 2;
        unsigned long long* c = realloc(g_ctx_cum, (size_t)cap * sizeof *c);
        if (!c) return 0;
        g_ctx_cum = c;
        u64* t = realloc(g_ctx_tag, (size_t)cap * sizeof *t);
        if (!t) return 0;
        g_ctx_tag = t; g_ctx_cap = cap;
    }
    long prefetched_to = g_ctx_n - 1;
    for (long h = g_ctx_n; h <= to; h++){
        /* A cold build is ~967k scattered 89-byte reads, one at a time --
         * 145 s against production's archive, all of it waiting on the disk
         * at queue depth 1. So ask for the next batch's prefixes up front
         * (POSIX_FADV_WILLNEED queues the reads asynchronously) and then
         * read them in order; the disk sees the whole batch at once. */
        if (h > prefetched_to && to - h >= 64){
            long end = h + CTX_PREFETCH - 1; if (end > to) end = to;
            prefetched_to = end;
            for (long k = h; k <= end; k++){
                u64 meta[3];
                if (store_get_at(CUR_ST, (u64)k, meta) != 1 || meta[1] == 0) continue;
                int fd = store_rd_fd(CUR_ST, (unsigned)meta[2]);
                if (fd >= 0) posix_fadvise(fd, (off_t)(meta[0] + 8), 89, POSIX_FADV_WILLNEED);
            }
        }
        u8 pre[89]; memset(pre, 0, sizeof pre);
        if (read_block_prefix(h, pre, sizeof pre) != 1) return 0;
        g_ctx_reads++;
        u64 c; u64 n = read_varint(pre + 80, pre + sizeof pre, &c);
        if (c == 0) return 0;
        if (h > 0 && memcmp(pre + 4, &g_ctx_tag[h - 1], 8) != 0) return -1;
        u8 id[32]; sha256d(id, pre, 80);
        g_ctx_tag[h] = ctx_tag_of(id);
        g_ctx_cum[h] = (h ? g_ctx_cum[h - 1] : 0) + n;
        g_ctx_n = h + 1;
    }
    return 1;
}
/* Cumulative count through height h on the CURRENT chain, -1 if unknown.
 * Caller holds g_ctx_mu with t_st == g_ctx_st (and has refreshed it). */
static long long ctx_at(long h){
    for (int attempt = 0; attempt < 4; attempt++){
        if (h < g_ctx_n){
            if (ctx_matches(h)) return (long long)g_ctx_cum[h];
            ctx_unwind(h);
            continue;
        }
        /* extending: the cached top must still be on the chain first */
        if (g_ctx_n > 0 && !ctx_matches(g_ctx_n - 1)){ ctx_unwind(g_ctx_n - 1); continue; }
        int r = ctx_extend(h);
        if (r == 0) return -1;
        if (r < 0){ ctx_unwind(g_ctx_n - 1); continue; }
        /* the walked headers must be the chain the index names at h */
        if (ctx_matches(h)) return (long long)g_ctx_cum[h];
        ctx_unwind(h);
    }
    return -1;
}
/* Test/diagnostic hook: block prefixes the cache has read so far. */
unsigned long long rpc_chain_chaintx_reads(void){
    pthread_mutex_lock(&g_ctx_mu); unsigned long long n = g_ctx_reads; pthread_mutex_unlock(&g_ctx_mu); return n;
}
/* The cumulative count through height h, -1 unknown -- the cache's own entry
 * point, safe from any thread. */
long long rpc_chain_chaintx_at(long h){
    if (!g_open || h < 0) return -1;
    pthread_mutex_lock(&g_ctx_mu);
    long long v = -1;
    if (lane_handle_open(g_ctx_st, &g_ctx_st_ok)){
        u8* prev = t_st; t_st = g_ctx_st;
        store_reload(g_ctx_st);
        v = ctx_at(h);
        t_st = prev;
    }
    pthread_mutex_unlock(&g_ctx_mu);
    return v;
}

/* Open every lane's handle now, while the cwd is certainly the archive
 * (rpc_chain_open chdir()ed there) -- not lazily on a first call. A reopen
 * replaces the handles and forgets the counts: it may be a different chain. */
static void lanes_open(void){
    pthread_mutex_lock(&g_fast_mu);
    if (g_fst_ok){ lane_handle_close(g_fst); g_fst_ok = 0; }
    lane_handle_open(g_fst, &g_fst_ok);
    pthread_mutex_unlock(&g_fast_mu);
    pthread_mutex_lock(&g_ctx_mu);
    if (g_ctx_st_ok){ lane_handle_close(g_ctx_st); g_ctx_st_ok = 0; }
    lane_handle_open(g_ctx_st, &g_ctx_st_ok);
    g_ctx_n = 0;
    pthread_mutex_unlock(&g_ctx_mu);
}

/* Core ParseHashV(v, "blockhash"): the NAME, not a position, in the text. */
static int ctx_parse_blockhash(const char* s, u8 disp[32], long* ec, const char** em){
    size_t n = strlen(s);
    if (n != 64){
        snprintf(g_hasherr, sizeof g_hasherr, "blockhash must be of length 64 (not %zu, for '%s')", n, s);
        *ec = -8; *em = g_hasherr; return 0;
    }
    if (!is_hex_str(s)){
        snprintf(g_hasherr, sizeof g_hasherr, "blockhash must be hexadecimal string (not '%s')", s);
        *ec = -8; *em = g_hasherr; return 0;
    }
    for (int i = 0; i < 32; i++) disp[i] = (u8)((hexv(s[i*2])<<4) | hexv(s[i*2+1]));
    return 1;
}

/* The body, under g_ctx_mu with t_st == g_ctx_st. Core v31.1
 * rpc/blockchain.cpp getchaintxstats, statement for statement:
 *   - the window defaults to one month of blocks (30*24*60*60 / 600), clamped
 *     to max(0, min(that, height - 1));
 *   - an explicit window must satisfy 0 <= n and (n == 0 or n < height);
 *   - window_interval is the MEDIAN-TIME-PAST difference between the final
 *     block and the block `window` below it (not the header times);
 *   - window_tx_count = count(final) - count(past), only when both are known;
 *     txrate only when window_interval > 0 as well. */
static int gcts_body(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    long final_h = tip;
    if (param_present(params, 1)){
        u8 disp[32]; long h;
        if (!ctx_parse_blockhash(params->items[1]->str, disp, ec, em)) return 0;
        if (!height_by_hash_raw(disp, &h)){ *ec = -5; *em = "Block not found"; return 0; }
        /* the by-hash table never forgets a hash, so a block reorged away still
         * resolves to its old height -- Core knows such a block and says -8, not
         * -5; and a stored block above the connected tip is not in the active
         * chain either */
        u8 rec[48], wire[32];
        for (int i = 0; i < 32; i++) wire[i] = disp[31 - i];
        if (h > tip || !read_idx_rec(h, rec) || memcmp(rec, wire, 32) != 0){
            *ec = -8; *em = "Block is not in main chain"; return 0; }
        final_h = h;
    }
    long window;
    if (!param_present(params, 0)){
        window = 30L * 24 * 60 * 60 / 600;              /* 4320 */
        if (window > final_h - 1) window = final_h - 1;
        if (window < 0) window = 0;
    } else {
        long long v; if (!rpc_param_i64(params, 0, &v, ec, em)) return 0;
        if (v < 0 || (v > 0 && v >= final_h)){
            *ec = -8; *em = "Invalid block count: should be between 0 and the block's height - 1";
            return 0; }
        window = (long)v;
    }

    u8 hdr[80];
    if (read_block_prefix(final_h, hdr, 80) != 1){ *ec = -1; *em = "Block not available"; return 0; }
    u8 rec[48];
    if (!read_idx_rec(final_h, rec)){ *ec = -1; *em = "Block not available"; return 0; }
    char hx[65]; hex_rev(hx, rec, 32);

    long long total = ctx_at(final_h);
    long long past  = window > 0 && total >= 0 ? ctx_at(final_h - window) : -1;

    rj_val* o = rj_obj();
    rj_obj_set(o, "time", rj_numf("%u", rd32(hdr + 68)));
    if (total > 0) rj_obj_set(o, "txcount", rj_numf("%lld", total));
    rj_obj_set(o, "window_final_block_hash", rj_str(hx));
    rj_obj_set(o, "window_final_block_height", rj_numf("%ld", final_h));
    rj_obj_set(o, "window_block_count", rj_numf("%ld", window));
    if (window > 0){
        long interval = median_time_past(final_h) - median_time_past(final_h - window);
        rj_obj_set(o, "window_interval", rj_numf("%ld", interval));
        if (total > 0 && past > 0){
            long long wtx = total - past;
            rj_obj_set(o, "window_tx_count", rj_numf("%lld", wtx));
            if (interval > 0)
                rj_obj_set(o, "txrate", rj_double((double)wtx / (double)interval));
        }
    }
    *res = o;
    return 1;
}

static int cmd_getchaintxstats(const rj_val* params, rj_val** res, long* ec, const char** em){
    /* Core type-checks both arguments before the body runs (RPCHelpMan) */
    rj_typeerrs te; rj_typeerr_init(&te);
    if (param_present(params, 0) && params->items[0]->typ != RJ_NUM)
        rj_typeerr_add(&te, 1, "nblocks", params->items[0], "number");
    if (param_present(params, 1) && params->items[1]->typ != RJ_STR)
        rj_typeerr_add(&te, 2, "blockhash", params->items[1], "string");
    if (rj_typeerr_fail(&te, ec, em)) return 0;
    pthread_mutex_lock(&g_ctx_mu);
    int r;
    if (!lane_handle_open(g_ctx_st, &g_ctx_st_ok)){ *ec = -28; *em = "Loading block index..."; r = 0; }
    else {
        u8* prev = t_st; t_st = g_ctx_st;
        r = gcts_body(params, res, ec, em);
        t_st = prev;
    }
    pthread_mutex_unlock(&g_ctx_mu);
    return r;
}

/* ---- verifychain --------------------------------------------------------
 * Core's checklevels are cumulative: 0 read from disk, 1 verify block
 * validity, 2 verify undo data, 3 disconnect, 4 reconnect. This node
 * implements 0-2 for real -- it reads each block, recomputes its header
 * hash and checks it against the index, checks the PoW against the header's
 * own bits, recomputes the merkle root from the transactions, and (level 2)
 * requires the undo file to be present and non-empty.
 *
 * Levels 3 and 4 need a full disconnect/reconnect through the UTXO writer,
 * which lives in the forked download worker and is not reachable from the
 * RPC thread. They are REFUSED rather than silently downgraded: verifychain
 * returns a bare boolean with no room to say "I did less than you asked",
 * so a `true` from a downgraded level 4 would be a straight untruth. Core's
 * default checklevel is 3, so a bare `verifychain` gets that refusal, with
 * the supported range named. */
static int vc_merkle_ok(const u8* blk, long blen, const u8 want_root[32]){
    const u8* p = blk + 80; const u8* end = blk + blen;
    u64 c; u64 ntx = read_varint(p, end, &c);
    if (c == 0 || ntx == 0 || ntx > 100000) return 0;
    p += c;
    u8 (*leaves)[32] = malloc((size_t)ntx * 32);
    if (!leaves) return 0;
    u8* scratch = NULL; size_t scap = 0;
    int ok = 1;
    for (u64 i = 0; i < ntx; i++){
        txw_t w;
        if (!tx_walk(p, end, &w)){ ok = 0; break; }
        if (w.len > scap){ u8* g = realloc(scratch, w.len); if (!g){ ok = 0; break; } scratch = g; scap = w.len; }
        if (tx_txid(leaves[i], p, w.len, scratch, w.len) != 1){ ok = 0; break; }
        p += w.len;
    }
    free(scratch);
    if (ok){
        u64 n = ntx;
        while (n > 1){
            u64 w2 = 0;
            for (u64 i = 0; i < n; i += 2){
                u8 pair[64];
                memcpy(pair, leaves[i], 32);
                memcpy(pair + 32, leaves[(i + 1 < n) ? i + 1 : i], 32);
                sha256d(leaves[w2++], pair, 64);
            }
            n = w2;
        }
        ok = memcmp(leaves[0], want_root, 32) == 0;
    }
    free(leaves);
    return ok;
}

/* PoW: sha256d(header) <= target(bits), both compared big-endian-wise over
 * the display order of the hash. */
static int vc_pow_ok(const u8 hash_wire[32], u32 bits){
    u8 tgt[32]; target_bytes(bits, tgt);          /* big-endian target */
    for (int i = 0; i < 32; i++){
        u8 hb = hash_wire[31 - i];                /* -> big-endian */
        if (hb < tgt[i]) return 1;
        if (hb > tgt[i]) return 0;
    }
    return 1;                                     /* exactly equal is valid */
}

static int cmd_verifychain(const rj_val* params, rj_val** res, long* ec, const char** em){
    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    long level = 3, nblocks = 6;                  /* Core's defaults */
    if (params && params->typ == RJ_ARR){
        if (params->nitems >= 1 && params->items[0]->typ == RJ_NUM) level = atol(params->items[0]->str);
        if (params->nitems >= 2 && params->items[1]->typ == RJ_NUM) nblocks = atol(params->items[1]->str);
    }
    if (level < 0 || level > 4){ *ec = -8; *em = "Invalid checklevel: must be 0-4"; return 0; }
    if (level > 2){
        *ec = -1;
        *em = "this node implements verifychain checklevel 0-2 (read, "
              "header/PoW/merkle, undo data present). Levels 3 and 4 disconnect "
              "and reconnect blocks through the UTXO writer, which lives in the "
              "forked download worker and is not reachable from the RPC thread. "
              "verifychain answers with a bare boolean, so returning true for a "
              "level it did not perform would be a plain untruth -- pass "
              "checklevel 2 or lower";
        return 0;
    }
    if (nblocks <= 0 || nblocks > tip + 1) nblocks = tip + 1;

    int ok = 1;
    for (long h = tip; h > tip - nblocks && h >= 0 && ok; h--){
        long blen = read_block(h);
        if (blen < 81){ ok = 0; break; }          /* level 0: readable */
        if (level >= 1){
            u8 hash[32]; sha256d(hash, g_blockbuf, 80);
            u8 rec[48];
            if (!read_idx_rec(h, rec) || memcmp(hash, rec, 32) != 0){ ok = 0; break; }
            u32 bits = rd32(g_blockbuf + 72);
            if (!vc_pow_ok(hash, bits)){ ok = 0; break; }
            if (!vc_merkle_ok(g_blockbuf, blen, g_blockbuf + 36)){ ok = 0; break; }
        }
        if (level >= 2){
            /* 2026-09-08: the block's undo run must exist and be closed (END) */
            { u8* ub = 0; int torn = 0; long ul = us_read_run(h, &ub, &torn); free(ub);
              if (ul < 0 || torn){ ok = 0; break; } }
        }
    }
    *res = rj_bool(ok);
    return 1;
}

/* ---- waitforblock / waitforblockheight / waitfornewblock ----------------
 * Real: the tip is polled through the same refresh() every other method
 * uses, so these see a new block as soon as the index does.
 *
 * DOCUMENTED DIVERGENCE: Core treats timeout 0 as "wait indefinitely". The
 * wait is capped at WFB_CAP_MS here. On expiry these return the CURRENT tip,
 * which is exactly what Core returns when its own timeout expires -- the
 * result shape is identical; only the ceiling on how long it will wait
 * differs, and the caller can simply call again.
 *
 * 2026-09-19: the wait no longer holds anything shared. It used to run under
 * the RPC execution lock like every chain handler, so one waitfornewblock
 * stalled every other RPC -- uptime included -- for up to 30 s. Core waits on
 * a condition variable without cs_main. Each wait now polls through a store
 * handle of its own (wfb_run), and the server runs these three without the
 * execution lock; a wait occupies one RPC thread, as it does in Core. */
#define WFB_CAP_MS 30000

/* Run a wait on a private handle, opened for this call and closed after. */
static int wfb_run(int (*body)(const rj_val*, rj_val**, long*, const char**),
                   const rj_val* params, rj_val** res, long* ec, const char** em){
    u8* st = malloc(ST_SIZE); int ok = 0;
    if (!st || !lane_handle_open(st, &ok)){ free(st); *ec = -28; *em = "Loading block index..."; return 0; }
    u8* prev = t_st; t_st = st;
    int r = body(params, res, ec, em);
    t_st = prev;
    lane_handle_close(st); free(st);
    return r;
}

static void wfb_result(long h, rj_val** res){
    u8 rec[48]; char hx[65];
    rj_val* o = rj_obj();
    if (read_idx_rec(h, rec)){ hex_rev(hx, rec, 32); rj_obj_set(o, "hash", rj_str(hx)); }
    rj_obj_set(o, "height", rj_numf("%ld", h));
    *res = o;
}

/* Poll until `done(tip)`, or the deadline. Returns the tip it stopped at. */
static long wfb_poll(long timeout_ms, int (*done)(long, const void*), const void* ctx){
    if (timeout_ms <= 0 || timeout_ms > WFB_CAP_MS) timeout_ms = WFB_CAP_MS;
    long waited = 0;
    for (;;){
        long tip = refresh();
        if (tip >= 0 && done(tip, ctx)) return tip;
        if (waited >= timeout_ms) return tip;
        struct timespec ts = {0, 100L * 1000 * 1000};   /* 100 ms */
        nanosleep(&ts, NULL);
        waited += 100;
    }
}
static int wfb_changed(long tip, const void* ctx){ return tip != *(const long*)ctx; }
static int wfb_atleast(long tip, const void* ctx){ return tip >= *(const long*)ctx; }
/* ctx is the caller's hash in WIRE order (already reversed from the display
 * string), matching how index.dat stores it -- comparing a display-order
 * buffer here would simply never match and the call would always time out. */
static int wfb_hash_is(long tip, const void* ctx){
    u8 rec[48];
    return read_idx_rec(tip, rec) && memcmp(rec, ctx, 32) == 0;
}

static long wfb_timeout_arg(const rj_val* params, size_t i){
    if (params && params->typ == RJ_ARR && params->nitems > i &&
        params->items[i]->typ == RJ_NUM) return atol(params->items[i]->str);
    return 0;
}

static int cmd_waitfornewblock(const rj_val* params, rj_val** res, long* ec, const char** em){
    long start = refresh();
    if (start < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    long tip = wfb_poll(wfb_timeout_arg(params, 0), wfb_changed, &start);
    wfb_result(tip < 0 ? start : tip, res);
    return 1;
}

static int cmd_waitforblockheight(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (refresh() < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_NUM){
        *ec = -8; *em = "waitforblockheight requires a height"; return 0; }
    long want = atol(params->items[0]->str);
    long tip = wfb_poll(wfb_timeout_arg(params, 1), wfb_atleast, &want);
    wfb_result(tip, res);
    return 1;
}

static int cmd_waitforblock(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (refresh() < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    const char* hs = rpc_param_str(params, 0, ec, em); if (!hs) return 0;
    u8 disp[32], wire[32];
    if (!parse_hash_param(hs, 1, disp, ec, em)) return 0;
    for (int i = 0; i < 32; i++) wire[i] = disp[31-i];
    long tip = wfb_poll(wfb_timeout_arg(params, 1), wfb_hash_is, wire);
    wfb_result(tip, res);
    return 1;
}

/* ==== BIP158 filters: getblockfilter / scanblocks / getdescriptoractivity =
 * The construction lives in block_filter.c and is validated byte-for-byte
 * against Core's own filters (tests/test_block_filter.c). What this layer
 * adds is the DATA: the block from the archive, and the spent-prevout
 * scripts from undo_<h>.dat via an injected undo_replay -- injected, like
 * every other cross-module dependency here, so rpc_chain does not pull the
 * daemon's undo module into every target that links it.
 *
 * THE HONEST BOUNDS, stated once here and enforced below:
 *   - undo files exist only inside the daemon's retention window (~200
 *     blocks below the tip). A filter for an older block cannot include the
 *     spent-prevout elements, and a filter missing elements is WRONG -- a
 *     light client would conclude "nothing relevant here" about a block that
 *     spends its coins. So getblockfilter refuses outside the window rather
 *     than serving a filter that lies by omission.
 *   - the filter HEADER chains from genesis, so computing it needs every
 *     filter before this one -- unknowable without a full index. The header
 *     field is OMITTED, never fabricated.
 *   - scanblocks/getdescriptoractivity walk the BLOCKS directly instead of
 *     a filter index. Exact (no false positives), and spends are detected
 *     for outpoints received within the scanned range (the same forward
 *     walk wallet_scan.c uses); a block that only spends a coin received
 *     BEFORE the range is not flagged. Each result says what was scanned. */
typedef int (*ch_undo_cb)(void* ctx, const unsigned char* txid, unsigned int index,
                          unsigned long long value, unsigned int height, unsigned char is_coinbase,
                          const unsigned char* script, unsigned short slen);
static long (*g_undo_replay)(long height, ch_undo_cb cb, void* ctx);
void rpc_chain_set_undo(long (*replay)(long, ch_undo_cb, void*)){ g_undo_replay = replay; }

#define GBF_MAX_PREV 40000
typedef struct {
    bf_script* v;
    unsigned char (*buf)[128];
    unsigned long n;
    int overflow;
} gbf_ctx;

static int gbf_cb(void* ctxp, const u8* txid, u32 index, u64 value, u32 height,
                  u8 is_coinbase, const u8* script, unsigned short slen){
    (void)txid; (void)index; (void)value; (void)height; (void)is_coinbase;
    gbf_ctx* c = (gbf_ctx*)ctxp;
    if (c->n >= GBF_MAX_PREV || slen > 128){ c->overflow = 1; return 1; }
    memcpy(c->buf[c->n], script, slen);
    c->v[c->n].script = c->buf[c->n];
    c->v[c->n].len = slen;
    c->n++;
    return 1;
}

/* STO-8 (audit 2026-09-03): how many prevouts this block spends.
 *
 * Same shape as STO-3's bfi_count_spends. undo_replay returns 0 for an ABSENT
 * file, which is indistinguishable from a block that genuinely spends nothing,
 * so the getblockfilter fallback below built a filter from OUTPUT scripts only
 * and returned it with a header computed from the wrong filter -- while its
 * own error text promises "no filter is served rather than a wrong one".
 *
 * Returns -1 on a malformed block, which the caller treats as unavailable. */
static long gbf_count_spends(const u8* blk, unsigned long blen){
    const u8* p = blk + 80; const u8* end = blk + blen;
    u64 cc;
    u64 ntx = read_varint(p, end, &cc); if (!cc) return -1;
    p += cc;
    long spends = 0;
    for (u64 t = 0; t < ntx; t++){
        if (p + 4 > end) return -1;
        p += 4;
        int sw = (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01);
        if (sw) p += 2;
        u64 nin = read_varint(p, end, &cc); if (!cc) return -1;
        p += cc;
        for (u64 i = 0; i < nin; i++){
            if (p + 36 > end) return -1;
            if (t != 0) spends++;
            p += 36;
            u64 sl = read_varint(p, end, &cc); if (!cc) return -1;
            p += cc + sl + 4;
            if (p > end) return -1;
        }
        u64 nout = read_varint(p, end, &cc); if (!cc) return -1;
        p += cc;
        for (u64 i = 0; i < nout; i++){
            if (p + 8 > end) return -1;
            p += 8;
            u64 sl = read_varint(p, end, &cc); if (!cc) return -1;
            p += cc;
            if (p + sl > end) return -1;
            p += sl;
        }
        if (sw){
            for (u64 i = 0; i < nin; i++){
                u64 items = read_varint(p, end, &cc); if (!cc) return -1;
                p += cc;
                for (u64 k = 0; k < items; k++){
                    u64 il = read_varint(p, end, &cc); if (!cc) return -1;
                    p += cc + il;
                    if (p > end) return -1;
                }
            }
        }
        if (p + 4 > end) return -1;
        p += 4;
    }
    return spends;
}

static int cmd_getblockfilter(const rj_val* params, rj_val** res, long* ec, const char** em){
    long h;
    if (!ix_on(g_ix_bfilter)){
        /* blockfilterindex=0: Core's order -- the hash's format, the
         * filter type, then "Index is not enabled", before any lookup */
        const char* bs = rpc_param_str(params, 0, ec, em); if (!bs) return 0;
        u8 bd[32]; if (!parse_hash_param(bs, 1, bd, ec, em)) return 0;
        const char* ft = (params->nitems >= 2 && params->items[1]->typ == RJ_STR) ? params->items[1]->str : "basic";
        if (strcmp(ft, "basic")){ *ec = -5; *em = "Unknown filtertype"; return 0; }
        *ec = -1; *em = "Index is not enabled for filtertype basic"; return 0;
    }
    if (!lookup_block_param(params, 0, 1, &h, ec, em)) return 0;
    if (params->nitems >= 2 && params->items[1]->typ == RJ_STR &&
        strcmp(params->items[1]->str, "basic")){
        *ec = -5; *em = "Unknown filtertype"; return 0; }
    long blen = read_block(h);
    if (blen < 81){ *ec = -1; *em = "Block not available"; return 0; }
    /* the persistent index serves filter AND header without undo data --
     * try it before the undo-window path even collects prevouts */
    { extern int bfi_get_file(long, unsigned char*, unsigned long, unsigned long*, unsigned char*);
      static unsigned char iflt[1 << 20]; unsigned long ifl; unsigned char ihdr[32];
      if (bfi_get_file(h, iflt, sizeof iflt, &ifl, ihdr)){
          char* hx = malloc(ifl * 2 + 1);
          if (!hx){ *ec = -7; *em = "oom"; return 0; }
          for (unsigned long i = 0; i < ifl; i++){
              static const char* H = "0123456789abcdef";
              hx[i*2] = H[iflt[i]>>4]; hx[i*2+1] = H[iflt[i]&15];
          }
          hx[ifl*2] = 0;
          rj_val* o = rj_obj();
          rj_obj_set(o, "filter", rj_str(hx));
          free(hx);
          char hh[65]; hex_rev(hh, ihdr, 32);
          rj_obj_set(o, "header", rj_str(hh));
          *res = o;
          return 1;
      } }
    /* the spent-prevout scripts, from undo data */
    gbf_ctx c;
    c.v = malloc(GBF_MAX_PREV * sizeof *c.v);
    c.buf = malloc((size_t)GBF_MAX_PREV * 128);
    if (!c.v || !c.buf){ free(c.v); free(c.buf); *ec = -7; *em = "oom"; return 0; }
    c.n = 0; c.overflow = 0;
    long ur = g_undo_replay ? g_undo_replay(h, gbf_cb, &c) : -1;
    /* h == 0 is the one height with legitimately no undo data (the genesis
     * coinbase spends nothing), so an absent file there is not a gap */
    /* STO-8: an ABSENT undo file returns 0, exactly like a block that spends
     * nothing. The block itself says how many prevouts to expect; fewer undo
     * records than that means the data is missing or short, and this path
     * must then serve NOTHING rather than a filter without its prevout
     * elements. Core's getblockfilter errors "Filter not found" when the
     * index has no entry; it never constructs one ad hoc. */
    long want_sp = gbf_count_spends(g_blockbuf, (unsigned long)blen);
    if (want_sp < 0 || (ur >= 0 && ur < want_sp)) ur = -1;
    if ((ur < 0 && h != 0) || c.overflow){
        free(c.v); free(c.buf);
        *ec = -1;
        *em = ur < 0
            ? "no undo data for this block: it is outside the daemon's undo "
              "retention window (~200 blocks below the tip). A filter built "
              "without the spent-prevout scripts would be missing elements, and "
              "a light client would wrongly conclude the block does not touch "
              "its coins -- so no filter is served rather than a wrong one"
            : "this block's undo data exceeds the filter builder's bounds";
        return 0;
    }
    unsigned char hash[32]; sha256d(hash, g_blockbuf, 80);
    static unsigned char flt[1 << 20];
    long fl = bf_basic_build(g_blockbuf, (unsigned long)blen, hash,
                             c.v, c.n, flt, sizeof flt);
    free(c.v); free(c.buf);
    if (fl < 0){ *ec = -1; *em = "filter construction failed"; return 0; }
    char* hx = malloc((size_t)fl * 2 + 1);
    if (!hx){ *ec = -7; *em = "oom"; return 0; }
    for (long i = 0; i < fl; i++){
        static const char* H = "0123456789abcdef";
        hx[i*2] = H[flt[i]>>4]; hx[i*2+1] = H[flt[i]&15];
    }
    hx[fl*2] = 0;
    rj_val* o = rj_obj();
    rj_obj_set(o, "filter", rj_str(hx));
    free(hx);
    /* header: chains from genesis; unknowable without every prior filter.
     * OMITTED -- a fabricated chain head would poison every later link. */
    *res = o;
    return 1;
}

/* ---- scanblocks / getdescriptoractivity ---------------------------------
 * Direct block walk. The scan objects are expanded to concrete scriptPubKeys
 * through the SAME expansion cmd_scantxoutset uses (scan_expand_objects), so
 * addr()/raw()/wpkh()/ranged descriptors behave identically across the two. */
#define SB_MAX_OWN  65536

typedef struct { unsigned char txid[32]; unsigned int vout; } sb_op;

/* Scan ONE block, sharing the caller's matched-outpoint set so a spend of a
 * coin received in an earlier scanned block is recognised. */
static int sb_scan_block(long h,
                         unsigned char (*spks)[128], unsigned int* spklens, int nspk,
                         sb_op* own, unsigned long* nown_io,
                         rj_val* hits_arr, rj_val* activity_arr,
                         long* ec, const char** em){
    unsigned long nown = *nown_io;
    static const char* HEXC = "0123456789abcdef";
    static char sberr[128];
    {
        long blen = read_block(h);
        if (blen < 81){
            snprintf(sberr, sizeof sberr, "block %ld could not be read; the scan would be incomplete", h);
            *ec = -1; *em = sberr; return 0;
        }
        unsigned char bh[32]; sha256d(bh, g_blockbuf, 80);
        int block_hit = 0;
        const u8* p = g_blockbuf + 80;
        const u8* end = g_blockbuf + blen;
        u64 cc;
        u64 ntx = read_varint(p, end, &cc);
        if (cc == 0){ *ec = -1; *em = "malformed block"; return 0; }
        p += cc;
        for (u64 t = 0; t < ntx; t++){
            txw_t w;
            if (!tx_walk(p, end, &w)){ *ec = -1; *em = "malformed tx"; return 0; }
            u8 txid[32];
            { u8* scratch = malloc(w.len ? w.len : 1);
              if (scratch){ tx_txid(txid, p, w.len, scratch, w.len); free(scratch); }
              else memset(txid, 0, 32); }
            /* inputs: a spend of an outpoint matched earlier in this range */
            { const u8* q = w.vin;
              u64 n_in = read_varint(q, end, &cc); q += cc;
              for (u64 i = 0; i < n_in; i++){
                  unsigned int vo = (unsigned int)q[32] | ((unsigned int)q[33]<<8) |
                                    ((unsigned int)q[34]<<16) | ((unsigned int)q[35]<<24);
                  for (unsigned long k = 0; k < nown; k++)
                      if (own[k].vout == vo && !memcmp(own[k].txid, q, 32)){
                          block_hit = 1;
                          if (activity_arr){
                              rj_val* e = rj_obj();
                              rj_obj_set(e, "type", rj_str("spend"));
                              rj_obj_set(e, "height", rj_numf("%ld", h));
                              char hx[65];
                              for (int b2 = 0; b2 < 32; b2++){ unsigned char v2 = txid[31-b2];
                                  hx[b2*2]=HEXC[v2>>4]; hx[b2*2+1]=HEXC[v2&15]; }
                              hx[64]=0;
                              rj_obj_set(e, "txid", rj_str(hx));
                              rj_arr_push(activity_arr, e);
                          }
                          break;
                      }
                  u64 sl = read_varint(q + 36, end, &cc);
                  q += 36 + cc + sl + 4;
              } }
            /* outputs paying a watched script */
            { const u8* q = w.vout;
              u64 n_out = read_varint(q, end, &cc); q += cc;
              for (u64 i = 0; i < n_out; i++){
                  u64 val = 0;
                  for (int b2 = 0; b2 < 8; b2++) val |= (u64)q[b2] << (8*b2);
                  q += 8;
                  u64 sl = read_varint(q, end, &cc); q += cc;
                  const u8* spk = q; q += sl;
                  for (int k = 0; k < nspk; k++){
                      if ((u64)spklens[k] != sl || memcmp(spks[k], spk, sl)) continue;
                      block_hit = 1;
                      if (nown < SB_MAX_OWN){
                          memcpy(own[nown].txid, txid, 32);
                          own[nown].vout = (unsigned int)i;
                          nown++;
                      }
                      if (activity_arr){
                          rj_val* e = rj_obj();
                          rj_obj_set(e, "type", rj_str("receive"));
                          rj_obj_set(e, "height", rj_numf("%ld", h));
                          char hx[65];
                          for (int b2 = 0; b2 < 32; b2++){ unsigned char v2 = txid[31-b2];
                              hx[b2*2]=HEXC[v2>>4]; hx[b2*2+1]=HEXC[v2&15]; }
                          hx[64]=0;
                          rj_obj_set(e, "txid", rj_str(hx));
                          rj_obj_set(e, "vout", rj_numf("%llu", (unsigned long long)i));
                          { char am[32]; rpc_amounts((long long)val, am, sizeof am);
                            rj_obj_set(e, "amount", rj_numf("%s", am)); }
                          rj_arr_push(activity_arr, e);
                      }
                      break;
                  }
              } }
            p += w.len;
        }
        if (block_hit && hits_arr){
            char hx[65];
            for (int b2 = 0; b2 < 32; b2++){ unsigned char v2 = bh[31-b2];
                hx[b2*2]=HEXC[v2>>4]; hx[b2*2+1]=HEXC[v2&15]; }
            hx[64]=0;
            rj_arr_push(hits_arr, rj_str(hx));
        }
    }
    *nown_io = nown;
    return 1;
}

static int sb_scan_range(long from, long to,
                         unsigned char (*spks)[128], unsigned int* spklens, int nspk,
                         rj_val* hits_arr, rj_val* activity_arr,
                         long* ec, const char** em){
    sb_op* own = malloc((size_t)SB_MAX_OWN * sizeof *own);
    if (!own){ *ec = -7; *em = "oom"; return 0; }
    unsigned long nown = 0;
    for (long h = from; h <= to; h++)
        if (!sb_scan_block(h, spks, spklens, nspk, own, &nown, hits_arr, activity_arr, ec, em)){
            free(own); return 0; }
    free(own);
    return 1;
}

/* Defined with cmd_scantxoutset below; identical redefinition there is
 * permitted by C and keeps the two textually adjacent uses in sync. */
#define SCAN_MAX_TARGETS 4096
static int scan_expand_objects(const rj_val* objs, u8 (*targets)[128], u32* tlens,
                               int cap, int* ntgt_io, long* ec, const char** em);

/* scanblocks "start" [scanobjects] ( start_height stop_height ) --
 * a direct, EXACT walk over the blocks in range rather than a probabilistic
 * filter-index match (no false positives to re-check). DOCUMENTED
 * DIVERGENCES from Core's filter-backed form, also stated in the result:
 * spends are recognised for outpoints received WITHIN the scanned range (the
 * same forward walk wallet_scan.c uses); a block that only spends a coin
 * received before the range is not flagged. The walk reads every block, so
 * the range is capped where Core's index lookup is not. */
#define SB_MAX_RANGE 250000

static int cmd_scanblocks(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* action = rpc_param_str(params, 0, ec, em); if (!action) return 0;
    if (!strcmp(action, "status")){ *res = rj_null(); return 1; }
    if (!strcmp(action, "abort")){ *res = rj_bool(0); return 1; }
    if (strcmp(action, "start")){ *ec = -8; *em = "Invalid action"; return 0; }
    if (!ix_on(g_ix_bfilter)){
        /* blockfilterindex=0: Core refuses a scan outright, whatever this
         * node's exact block walk could have done without the index */
        const char* ft = (params && params->nitems >= 5 && params->items[4]->typ == RJ_STR) ? params->items[4]->str : "basic";
        if (strcmp(ft, "basic")){ *ec = -5; *em = "Unknown filtertype"; return 0; }
        *ec = -1; *em = "Index is not enabled for filtertype basic"; return 0;
    }
    if (!params || params->typ != RJ_ARR || params->nitems < 2 || params->items[1]->typ != RJ_ARR){
        *ec = -8; *em = "scanobjects argument is required for the start action"; return 0; }
    long tip = refresh();
    if (tip < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    long from = 0, to = tip;
    if (params->nitems >= 3 && params->items[2]->typ == RJ_NUM) from = atol(params->items[2]->str);
    if (params->nitems >= 4 && params->items[3]->typ == RJ_NUM) to = atol(params->items[3]->str);
    if (from < 0 || to < from){ *ec = -8; *em = "Invalid height range"; return 0; }
    if (to > tip) to = tip;
    if (to - from + 1 > SB_MAX_RANGE){
        *ec = -8;
        *em = "range too large: this node scans the blocks themselves (exact, no "
              "filter index), and this range would read too much. Narrow "
              "start_height/stop_height";
        return 0;
    }
    static u8 targets[SCAN_MAX_TARGETS][128];
    static u32 tlens[SCAN_MAX_TARGETS];
    int ntgt = 0;
    if (!scan_expand_objects(params->items[1], targets, tlens, SCAN_MAX_TARGETS, &ntgt, ec, em))
        return 0;
    if (!ntgt){ *ec = -8; *em = "scanobjects argument is required for the start action"; return 0; }
    rj_val* hits = rj_arr();
    if (!sb_scan_range(from, to, targets, tlens, ntgt, hits, NULL, ec, em)){
        rj_free(hits); return 0; }
    rj_val* o = rj_obj();
    rj_obj_set(o, "from_height", rj_numf("%ld", from));
    rj_obj_set(o, "to_height", rj_numf("%ld", to));
    rj_obj_set(o, "relevant_blocks", hits);
    rj_obj_set(o, "completed", rj_bool(1));
    /* the divergence, in the result itself, so a caller who never read the
     * docs still sees it */
    rj_obj_set(o, "note",
        rj_str("exact block scan (not a filter index): spends are detected only "
               "for outputs received within the scanned range"));
    *res = o;
    return 1;
}

/* getdescriptoractivity [blockhashes] [scanobjects] -- the same walk,
 * reporting the individual receives and spends instead of block hashes.
 * The given blocks are scanned in HEIGHT order sharing one matched-outpoint
 * set, so a spend in a later given block of a coin received in an earlier
 * given block is recognised. */
static int cmd_getdescriptoractivity(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 2 ||
        params->items[0]->typ != RJ_ARR || params->items[1]->typ != RJ_ARR){
        *ec = -8; *em = "getdescriptoractivity requires a blockhashes array and a scanobjects array";
        return 0; }
    if (refresh() < 0){ *ec = -28; *em = "Loading block index..."; return 0; }
    const rj_val* bhs = params->items[0];
    if (bhs->nitems > 1024){ *ec = -8; *em = "too many blocks"; return 0; }
    long heights[1024]; int nh = 0;
    for (size_t i = 0; i < bhs->nitems; i++){
        if (bhs->items[i]->typ != RJ_STR){ *ec = -8; *em = "blockhash must be a string"; return 0; }
        u8 disp[32];
        if (!parse_hash_param(bhs->items[i]->str, 1, disp, ec, em)) return 0;
        long h;
        if (!height_by_hash(disp, &h)){ *ec = -5; *em = "Block not found"; return 0; }
        heights[nh++] = h;
    }
    /* height order, so the shared outpoint set sees receives before spends */
    for (int i = 1; i < nh; i++){
        long k = heights[i]; int j = i - 1;
        while (j >= 0 && heights[j] > k){ heights[j+1] = heights[j]; j--; }
        heights[j+1] = k;
    }
    static u8 targets[SCAN_MAX_TARGETS][128];
    static u32 tlens[SCAN_MAX_TARGETS];
    int ntgt = 0;
    if (!scan_expand_objects(params->items[1], targets, tlens, SCAN_MAX_TARGETS, &ntgt, ec, em))
        return 0;
    rj_val* act = rj_arr();
    sb_op* own = malloc((size_t)SB_MAX_OWN * sizeof *own);
    if (!own){ rj_free(act); *ec = -7; *em = "oom"; return 0; }
    unsigned long nown = 0;
    for (int i = 0; i < nh; i++)
        if (!sb_scan_block(heights[i], targets, tlens, ntgt, own, &nown, NULL, act, ec, em)){
            free(own); rj_free(act); return 0; }
    free(own);
    rj_val* o = rj_obj();
    rj_obj_set(o, "activity", act);
    *res = o;
    return 1;
}

/* ---- dumptxoutset --------------------------------------------------------
 * Streams the live UTXO set to a file in Core's snapshot serialization --
 * asm/utxo_snapshot.c's encoder, pinned byte-for-byte against a snapshot
 * the oracle Core actually wrote. The walk itself is the injected runner in
 * daemon/utxo_setinfo_rpc.c, under the same quiescence discipline as
 * gettxoutsetinfo (fingerprint before and after; a set that changed mid-walk
 * discards the file rather than publishing a torn snapshot).
 *
 * Only type "latest" is supported: "rollback" reconstructs a historical
 * state, which is the reorg machinery's job and it lives in the forked
 * worker. txoutset_hash is OMITTED from the result -- computing it is a
 * second full walk (gettxoutsetinfo muhash), and gluing a hash from a
 * different walk onto this file would claim a correspondence nothing
 * verified. Core's nchaintx is omitted for the same reason (it comes from a
 * block-index field this node does not keep; getchaintxstats computes it on
 * request). */
static long (*g_utxo_dump)(const char*, int (*)(long, unsigned char*),
                           long*, unsigned long long*, char*, unsigned long);
void rpc_chain_set_utxodump(long (*run)(const char*, int (*)(long, unsigned char*),
                                        long*, unsigned long long*, char*, unsigned long)){
    g_utxo_dump = run;
}

static int gdump_hash_at(long height, unsigned char out[32]){
    u8 rec[48];
    if (!read_idx_rec(height, rec)) return 0;
    memcpy(out, rec, 32);                       /* index stores wire order */
    return 1;
}

/* RPX-4: the same lookup, exported. gettxout needs the tip hash for
 * `bestblock` and the tip height for `confirmations`; both were hardcoded
 * (all-zero hash, 0 confirmations) while this file already had the index
 * open. Returns wire order, like the index record it reads. */
int rpc_chain_hash_at(long height, unsigned char out[32]){ return gdump_hash_at(height, out); }

static int cmd_dumptxoutset(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* path = rpc_param_str(params, 0, ec, em); if (!path) return 0;
    if (params->nitems >= 2 && params->items[1]->typ == RJ_STR &&
        strcmp(params->items[1]->str, "latest")){
        *ec = -8;
        *em = "only type \"latest\" is supported: \"rollback\" reconstructs a "
              "historical UTXO state, which is the reorg machinery's job and it "
              "lives in the forked download worker";
        return 0;
    }
    if (!g_utxo_dump){ *ec = -1; *em = "UTXO dump unavailable in this process"; return 0; }
    long height = 0; unsigned long long coins = 0;
    static char msg[256];
    long r = g_utxo_dump(path, gdump_hash_at, &height, &coins, msg, sizeof msg);
    if (r == 0){ *ec = -1; *em = msg[0] ? msg : "UTXO set busy"; return 0; }
    if (r != 1){ *ec = -1; *em = msg[0] ? msg : "UTXO dump failed"; return 0; }
    rj_val* o = rj_obj();
    rj_obj_set(o, "coins_written", rj_numf("%llu", coins));
    { u8 rec[48]; char hx[65];
      if (read_idx_rec(height, rec)){ hex_rev(hx, rec, 32); rj_obj_set(o, "base_hash", rj_str(hx)); } }
    rj_obj_set(o, "base_height", rj_numf("%ld", height));
    rj_obj_set(o, "path", rj_str(path));
    *res = o;
    return 1;
}

/* ---- refusals -----------------------------------------------------------
 * Each names the specific thing that is missing, not "unimplemented". */
#define CH_NO_SNAPSHOT_LOAD \
    "this node will not load a UTXO snapshot: its UTXO set is built by full " \
    "validation from genesis, and every parity claim it makes (the muhash " \
    "match against Core) rests on every coin having been verified locally. " \
    "Loading foreign state would discard exactly that property, and there is " \
    "no second chainstate to background-validate it against as Core does. " \
    "dumptxoutset (the export) is supported"
#define CH_NO_FORKCHOICE_RPC \
    "fork choice is owned by the forked download worker (daemon/reorg.c), " \
    "which is not reachable from the RPC thread; there is no channel for the " \
    "parent to steer it, so this call would change nothing"
#define CH_NO_MEMPOOL_FILE \
    "this node does not persist its mempool: there is no mempool.dat writer " \
    "or reader, and Core's serialization is not implemented. The pool is " \
    "rebuilt from the network on restart"

/* ---- submitheader --------------------------------------------------------
 * Core decodes the header, and if it already knows it, returns null without
 * doing anything. That case this node can answer exactly: look the hash up
 * in the index and return null when it is a header we already have.
 *
 * A header we do NOT have would have to be added to the chain, and the
 * header chain belongs to the forked download worker (headers.dat is its
 * file). There is no channel for the parent to hand it one, so that case is
 * refused rather than answered with the null that means "accepted". */
static int cmd_submitheader(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* hx = rpc_param_str(params, 0, ec, em); if (!hx) return 0;
    if (strlen(hx) != 160 || !is_hex_str(hx)){
        *ec = -22; *em = "Block header decode failed"; return 0; }
    u8 hdr[80];
    for (int i = 0; i < 80; i++){
        int a = hx[i*2], b = hx[i*2+1];
        a = (a<='9') ? a-'0' : ((a|32)-'a'+10);
        b = (b<='9') ? b-'0' : ((b|32)-'a'+10);
        hdr[i] = (u8)((a<<4)|b);
    }
    u8 hash[32]; sha256d(hash, hdr, 80);
    u8 disp[32]; for (int i = 0; i < 32; i++) disp[i] = hash[31-i];
    long h;
    if (height_by_hash(disp, &h)){ *res = rj_null(); return 1; }
    *ec = -1;
    *em = "this header is not already in the chain, and adding one is the "
          "forked download worker's job -- headers.dat is its file and there "
          "is no parent-to-worker channel for a submitted header. A header "
          "this node already has returns null, as Core does";
    return 0;
}

static int ch_unsupported(const char* msg, long* ec, const char** em){
    *ec = -1; *em = msg; return 0;
}

/* Expose the archive to the wallet rescan (rpc_wallet_ops.c). The scan needs
 * exactly two things -- read a block by height, and know the tip -- and both
 * already exist here behind the same store handle every chain RPC uses, so
 * this hands them over rather than opening a second handle on the same
 * files. Returns < 81 for a height that cannot be read, which the scanner
 * treats as fatal (a skipped height would understate every total). */
long rpc_chain_read_block_at(long h, unsigned char* buf, long cap){
    if (!g_open) return -1;
    long r = store_read_at(g_st, (unsigned long)h, buf, cap);
    if (r < 0) return -3;
    return r;
}
long rpc_chain_tip_height(void){ return refresh(); }

/* ---- dispatch ---- */
static const char* const CHAIN_METHODS[] = {
    "getblockcount","getbestblockhash","getblockhash","getblockheader","getblock",
    "getblockchaininfo","getdifficulty","getrawtransaction","gettxoutproof","verifytxoutproof","decodescript","createmultisig",
    "getdescriptorinfo","deriveaddresses","getblockstats","getnetworkhashps","getmininginfo","getblocktemplate","gettxoutsetinfo","scantxoutset","getchaintips","getindexinfo","uptime","stop",
    /* the rest of Core's Blockchain category (2026-08-25) */
    "getchainstates","getdeploymentinfo","getchaintxstats","verifychain",
    /* EXTENSIONS (no Core equivalent): served from the live address index,
     * daemon/addr_index_tail.c, only when the operator set addrindex=1 */
    "getaddressbalance","getaddresstxids",
    "waitforblock","waitforblockheight","waitfornewblock",
    "getblockfilter","scanblocks","getdescriptoractivity",
    "dumptxoutset","loadtxoutset","preciousblock","pruneblockchain",
    "submitheader", NULL
};

const char* rpc_chain_method_at(int i){
    int n = 0;
    while (CHAIN_METHODS[n]) n++;
    return (i >= 0 && i < n) ? CHAIN_METHODS[i] : NULL;
}
int rpc_chain_known_method(const char* m){
    for (int i = 0; CHAIN_METHODS[i]; i++) if (!strcmp(m, CHAIN_METHODS[i])) return 1;
    return 0;
}

/* Public full-tx decoder (Core decoderawtransaction shape: txid/hash/version/
 * size/vsize/weight/locktime/vin/vout with scriptPubKey asm+desc+address). The
 * same tx_to_json getblock verbosity>=1 uses, so it is Core-verified. Standalone
 * (no chain state). Returns 1, or 0 with *ec / *em on a malformed/trailing tx. */
int rpc_chain_decode_rawtx(const u8* tx, long txlen, rj_val** result, long* ec, const char** em){
    txw_t w;
    if (txlen < 10 || !tx_walk(tx, tx + txlen, &w) || (long)w.len != txlen){
        *ec = -22; *em = "TX decode failed"; return 0; }
    rj_val* o = tx_to_json(tx, &w, -1);
    if (!o){ *ec = -7; *em = "out of memory"; return 0; }
    /* tx_to_json emits "hex" for getblock/getrawtransaction; decoderawtransaction
     * and decodepsbt's tx do NOT include it. Strip it. */
    for (size_t i = 0; i < o->nmembers; i++){
        if (!strcmp(o->members[i].key, "hex")){
            free(o->members[i].key); rj_free(o->members[i].val);
            for (size_t j = i + 1; j < o->nmembers; j++) o->members[j-1] = o->members[j];
            o->nmembers--; break;
        }
    }
    *result = o;
    return 1;
}

/* getindexinfo (Core rpc/blockchain.cpp): status of every optional index the
 * node runs (txindex, coinstatsindex, blockfilterindex). This node runs NONE
 * of them -- getrawtransaction requires a blockhash (no txindex), there is no
 * coinstatsindex or blockfilterindex -- so, exactly as Core does when no such
 * index is enabled, the result is an empty object (an optional index_name
 * filter cannot match anything either). The block/UTXO index that IS present
 * is core chainstate, not one of getindexinfo's optional indexes. */
/* The coinstats-index fast path (daemon/coinstats_index.c, via the daemon's
 * adapter): same out-contract as the walk. Tried FIRST; returns 1 with the
 * running state (instant), or 0 meaning "no valid index -- walk instead".
 * Coverage semantics are identical: both describe the UTXO APPLIED height. */
static long (*g_csi_run)(int, void*, char*, unsigned long);
#include "daemon/coinstats_hist_fmt.h"
static int  (*g_csi_hist)(long, int, csi_hist_out_t*) = 0;   /* the per-height rows (2026-09-08) */
static long (*g_csi_hist_first)(void) = 0, (*g_csi_hist_last)(void) = 0;
void rpc_chain_set_coinstats_hist(int (*q)(long, int, csi_hist_out_t*), long (*first)(void), long (*last)(void)){ g_csi_hist = q; g_csi_hist_first = first; g_csi_hist_last = last; }
static const char* (*g_csi_hist_status)(void) = 0;   /* one line on the history base's health / repair (2026-09-08) */
void rpc_chain_set_coinstats_hist_status(const char* (*fn)(void)){ g_csi_hist_status = fn; }
void rpc_chain_set_coinstats(long (*run)(int, void*, char*, unsigned long)){
    g_csi_run = run;
}
static long (*g_csi_h)(void);           /* light height probe for getindexinfo */
void rpc_chain_set_coinstats_height(long (*fn)(void)){ g_csi_h = fn; }

/* ---- EXTENSION RPCs: the live address index --------------------------------
 * Bitcoin Core has NO address index and no RPC of these names; these exist in
 * the spirit of the old addrindex patch set (getaddressbalance /
 * getaddresstxids) and are served from daemon/addr_index_tail.c's journal.
 * They answer only when the operator enabled addrindex=1; otherwise the error
 * says exactly how to turn the index on. Input: a single address string, an
 * array of addresses, or the addrindex patch's {"addresses":[...]} object.
 * getaddressbalance: {"balance","received","utxos"} summed over the inputs
 * (satoshis; "received" = every output ever created for the address).
 * getaddresstxids: deduplicated txids (display hex) of every transaction that
 * created an output for -- or spent one from -- the given addresses, in index
 * (chain) order. */
extern long axt_read_address(int type, const unsigned char hash[32],
                             unsigned long long* balance, unsigned long long* received,
                             long* nutxo, unsigned char* txids, long txid_cap);
extern long axt_probe_covered(void);

#define AXR_TXID_CAP 100000
#include "daemon/addr_hist_fmt.h"    /* ah_lookup / ah_to_height / ah_available: the history runs */
#include "daemon/addr_index_fmt.h"   /* AXF_OP_* : the journal records */
#include "daemon/txi_format.h"       /* txi_rd_varint */

/* collect the address strings from any accepted param shape; returns count
 * or -1 on a malformed request */
static long axr_collect(const rj_val* params, const rj_val** out, long cap){
    if (!params || params->typ != RJ_ARR || params->nitems < 1) return -1;
    const rj_val* a = params->items[0];
    if (a->typ == RJ_STR){ out[0] = a; return 1; }
    if (a->typ == RJ_OBJ){
        const rj_val* arr = rj_obj_get((rj_val*)a, "addresses");
        if (!arr || arr->typ != RJ_ARR) return -1;
        a = arr;
    }
    if (a->typ != RJ_ARR) return -1;
    long n = 0;
    for (unsigned long i = 0; i < a->nitems && n < cap; i++){
        if (a->items[i]->typ != RJ_STR) return -1;
        out[n++] = a->items[i];
    }
    return n;
}

/* decode one address into the index key; 1 ok / 0 invalid */
static int axr_key(const char* addr, int* type, unsigned char key[32]){
    int t = 0; unsigned char ver, h160[20], prog[32];
    if (!wallet_validate_address(addr, &t, &ver, h160, prog)) return 0;
    if (t < 1 || t > 5) return 0;               /* WAL_ADDR_* 1..5 == AXF_* */
    memset(key, 0, 32);
    if (t == 4 || t == 5) memcpy(key, prog, 32);        /* P2WSH / P2TR */
    else                  memcpy(key, h160, 20);        /* 20-byte types */
    *type = t;
    return 1;
}

static int axr_enabled(long* ec, const char** em){
    if (axt_probe_covered() >= 0 || ah_available()) return 1;
    *ec = -1;
    *em = "Address index not available (extension; set addrindex=1 in bitcoin.conf "
          "before the node syncs -- Core itself has no address index)";
    return 0;
}

/* ---- 2026-09-16: balances and txids from the history RUNS + the journal --
 * The journal (addrindex.tail) used to hold the whole chain and every query
 * scanned all of it (89 GB at 43% of mainnet on run 24: one getaddressbalance
 * starved the sync for ten minutes). Now the trailing builder folds it into
 * sorted history runs (addr_hist_fmt.h) and rotates the journal, so a query
 * is: the key's events from the runs (sparse-indexed), then the journal
 * above the runs' reach. Balance = funds - spends, received = funds, utxos =
 * #funds - #spends; the two sources carry the same facts in two shapes
 * (events name the transaction by (height, txpos); journal records carry
 * the txid), so getaddresstxids resolves a run event's txid by reading its
 * block -- one read per distinct height, cached across the call. */
extern long axt_read_events(int type, const unsigned char hash[32], long min_height,
                            int (*cb)(void* ctx, int op, const unsigned char txid[32], unsigned vout, unsigned long long value, unsigned height), void* ctx);
typedef struct { unsigned long long bal_fund, bal_spend; long nfund, nspend; unsigned char* txids; long ntxid, cap;
                 long lo, hi;   /* txid window, inclusive; hi < 0 = open end */ } axr_acc;
/* Deduplication used to be a linear scan of everything pushed so far, which is
 * O(n^2) in the number of distinct txids: at the AXR_TXID_CAP of 100,000 that
 * is 5e9 32-byte compares for one call. An open-addressed set keyed on the
 * first 8 bytes of the txid makes it O(n). The table holds indices into
 * a->txids (so the txid bytes live in one place) and is reset per call --
 * the RPC server services one call at a time on one thread, which is what
 * lets it be static, exactly as axr_txid_at's block cache below is. */
#define AXR_TXID_HASHN (1u << 18)          /* > 2 * AXR_TXID_CAP, power of two */
static int32_t axr_txid_tab[AXR_TXID_HASHN];
static void axr_txid_reset(void){ memset(axr_txid_tab, 0xff, sizeof axr_txid_tab); }
static void axr_txid_push(axr_acc* a, const unsigned char txid[32]){
    if (a->cap <= 0 || a->ntxid >= a->cap) return;
    uint64_t k; memcpy(&k, txid, 8);
    uint32_t i = (uint32_t)((k * 0x9E3779B97F4A7C15ULL) >> 46) & (AXR_TXID_HASHN - 1);
    while (axr_txid_tab[i] >= 0){
        if (!memcmp(a->txids + (size_t)axr_txid_tab[i] * 32, txid, 32)) return;   /* already have it */
        i = (i + 1) & (AXR_TXID_HASHN - 1);
    }
    memcpy(a->txids + a->ntxid * 32, txid, 32);
    axr_txid_tab[i] = (int32_t)a->ntxid;
    a->ntxid++;
}
static int axr_tail_cb(void* ctx, int op, const unsigned char txid[32], unsigned vout, unsigned long long value, unsigned height){
    axr_acc* a = ctx; (void)vout;
    /* The balance is a property of the whole address and is always summed over
     * everything; only the txid LIST is windowed. */
    int in = ((long)height >= a->lo) && (a->hi < 0 || (long)height <= a->hi);
    if (op == AXF_OP_ADD){ a->bal_fund += value; a->nfund++; if (in) axr_txid_push(a, txid); }
    else if (op == AXF_OP_DEL){ a->bal_spend += value; a->nspend++; }
    else if (op == AXF_OP_TOUCH){ if (in) axr_txid_push(a, txid); }
    return 1;
}
/* the txid of the txpos-th transaction of block h (wire order), or 0.
 *
 * This used to compute tx_txid() for EVERY transaction in the block in order
 * to return one of them. A modern block carries ~3,000 transactions, so one
 * event cost ~3,000 double-SHA256 passes over full transaction bytes, and the
 * cache held a single height -- so a getaddresstxids over N distinct heights
 * hashed N whole blocks. Measured on run 26 at the tip, that was 13 s for a
 * busy address and 15 s for a nearly empty one: the cost tracked how many
 * BLOCKS the address touched, not how many events it had, which is the shape
 * that gave it away.
 *
 * Now the block is walked once per height to record each transaction's extent
 * -- pointer arithmetic, no hashing -- and a txid is computed lazily, only for
 * the txpos actually asked for, then memoised. Several events in one block
 * still share the walk, which is what the original cache was for.
 *
 * Only the transaction EXTENTS are cached, not the bytes. Copying each block
 * out cost more than it saved on an address that touches ~100,000 distinct
 * heights -- that is ~100,000 whole-block memcpys. g_blockbuf_h says which
 * block the shared buffer holds, so the lazy hash re-reads only when something
 * else has been through the buffer since the parse, which inside one query is
 * never. */
static int axr_txid_at(long h, long txpos, unsigned char out[32]){
    static long cached_h = -1; static long cached_n, cached_cap;
    static unsigned char* cached;        /* cached_cap * 32 txids                 */
    static unsigned char* have;          /* cached_cap flags: txid computed yet   */
    static unsigned long* txoff;         /* per-tx offset into the block          */
    static unsigned long* txlen;         /* per-tx length                         */
    if (h != cached_h){
        cached_h = -1;                   /* invalid until the walk completes */
        long blen = read_block(h); if (blen < 81) return 0;
        const u8* blk = g_blockbuf;
        const u8* p = blk + 80; const u8* end = blk + blen; uint64_t cc;
        uint64_t ntx = txi_rd_varint(p, end, &cc); if (!cc) return 0; p += cc;
        if ((long)ntx > cached_cap){
            long cap = (long)ntx + 64;
            unsigned char* c1 = realloc(cached, (size_t)cap * 32); if (!c1) return 0; cached = c1;
            unsigned char* h1 = realloc(have, (size_t)cap);        if (!h1) return 0; have = h1;
            unsigned long* o1 = realloc(txoff, (size_t)cap * sizeof *txoff); if (!o1) return 0; txoff = o1;
            unsigned long* l1 = realloc(txlen, (size_t)cap * sizeof *txlen); if (!l1) return 0; txlen = l1;
            cached_cap = cap;
        }
        cached_n = 0;
        for (uint64_t t = 0; t < ntx; t++){
            const u8* s0 = p;
            if (p + 4 > end) return 0;
            p += 4;
            int sw = (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01);
            if (sw) p += 2;
            uint64_t nin = txi_rd_varint(p, end, &cc); if (!cc) return 0;
            p += cc;
            for (uint64_t i = 0; i < nin; i++){ if (p + 36 > end) return 0; p += 36; uint64_t sl = txi_rd_varint(p, end, &cc); if (!cc) return 0; p += cc + sl + 4; if (p > end) return 0; }
            uint64_t nout = txi_rd_varint(p, end, &cc); if (!cc) return 0;
            p += cc;
            for (uint64_t i = 0; i < nout; i++){ if (p + 8 > end) return 0; p += 8; uint64_t sl = txi_rd_varint(p, end, &cc); if (!cc) return 0; p += cc + sl; if (p > end) return 0; }
            if (sw){ for (uint64_t i = 0; i < nin; i++){ uint64_t items = txi_rd_varint(p, end, &cc); if (!cc) return 0; p += cc; for (uint64_t k = 0; k < items; k++){ uint64_t il = txi_rd_varint(p, end, &cc); if (!cc) return 0; p += cc + il; if (p > end) return 0; } } }
            if (p + 4 > end) return 0;
            p += 4;
            txoff[cached_n] = (unsigned long)(s0 - blk);
            txlen[cached_n] = (unsigned long)(p - s0);
            cached_n++;
        }
        memset(have, 0, (size_t)cached_n);
        cached_h = h;
    }
    if (txpos < 0 || txpos >= cached_n) return 0;
    if (!have[txpos]){
        static u8 scratch[4u << 20];
        /* the extents are this block's; make sure the shared buffer still is */
        if (g_blockbuf_h != h && read_block(h) < 81) return 0;
        if (tx_txid(cached + (size_t)txpos * 32, g_blockbuf + txoff[txpos], txlen[txpos], scratch, sizeof scratch) != 1) return 0;
        have[txpos] = 1;
    }
    memcpy(out, cached + (size_t)txpos * 32, 32);
    return 1;
}
/* runs + journal for one key. txid_cap 0 = counts only. -1 on a read failure */
/* runs + journal for one key, into an accumulator that may already hold txids
 * from a previous address in the same call (ntxid_seed). [lo,hi] windows the
 * TXID LIST only -- hi < 0 means "to the tip". Windowing before axr_txid_at is
 * the point of it: an event outside the window costs nothing, where resolving
 * its txid costs a block read. */
static long axr_read(int type, const unsigned char key[32], axr_acc* a, unsigned char* txids, long txid_cap,
                     long ntxid_seed, long lo, long hi){
    memset(a, 0, sizeof *a); a->txids = txids; a->cap = txid_cap;
    a->ntxid = ntxid_seed; a->lo = lo; a->hi = hi;
    const ah_event* ev = 0; long n = ah_lookup((uint8_t)type, key, &ev);
    long runs_to = ah_to_height();
    for (long i = 0; i < n; i++){
        ah_event e; memcpy(&e, (const unsigned char*)ev + i * AH_EVENT_BYTES, sizeof e);
        if (e.kind == AH_FUND){ a->bal_fund += e.value; a->nfund++; } else { a->bal_spend += e.value; a->nspend++; }
        if (txid_cap > 0 && a->ntxid < txid_cap && (long)e.height >= lo && (hi < 0 || (long)e.height <= hi)){
            unsigned char t[32]; if (axr_txid_at((long)e.height, (long)e.txpos, t)) axr_txid_push(a, t);
        }
    }
    /* A journal read failure must NEVER be swallowed. This used to be
     * `... < 0 && n < 0`, so whenever the history runs had anything at all the
     * journal's error was discarded and the answer was computed from the runs
     * alone -- a confidently wrong balance, with no error and nothing logged.
     * That is exactly how the pread() truncation below went unseen: once the
     * journal passed 2 GB every query silently ignored up to a full run
     * interval of address activity. A failure here is an error to the caller. */
    if (axt_read_events(type, key, runs_to, axr_tail_cb, a) < 0) return -1;
    /* ah_lookup answers -1 both for "the runs are unreadable" and for "there
     * are no run files", and the second is the normal state of a node that has
     * not built its first history run yet -- the whole early sync. Only the
     * first is an error, so ask whether runs exist before treating it as one.
     * Getting this wrong made every address query fail on a journal-only node. */
    if (n < 0 && ah_available()) return -1;
    return a->ntxid;
}

static int cmd_getaddressbalance(const rj_val* params, rj_val** res, long* ec, const char** em){
    const rj_val* addrs[64];
    long na = axr_collect(params, addrs, 64);
    if (na < 1){ *ec = -8; *em = "getaddressbalance(address | [addresses] | {\"addresses\":[...]})"; return 0; }
    if (!axr_enabled(ec, em)) return 0;
    unsigned long long bal = 0, rcv = 0; long utxos = 0;
    for (long i = 0; i < na; i++){
        int t; unsigned char key[32];
        if (!axr_key(addrs[i]->str, &t, key)){ *ec = -5; *em = "Invalid address"; return 0; }
        axr_acc a;
        if (axr_read(t, key, &a, 0, 0, 0, 0, -1) < 0){ *ec = -1; *em = "Address index unreadable"; return 0; }
        bal += a.bal_fund - a.bal_spend; rcv += a.bal_fund; utxos += a.nfund - a.nspend;
    }
    rj_val* o = rj_obj();
    rj_obj_set(o, "balance",  rj_numf("%llu", bal));
    rj_obj_set(o, "received", rj_numf("%llu", rcv));
    rj_obj_set(o, "utxos",    rj_numf("%ld", utxos));
    *res = o;
    return 1;
}

/* getaddresstxids(address | [addresses] | {"addresses":[...], "start":h, "end":h})
 *
 * `start`/`end` are inclusive block heights and page the result the way the
 * addrindex patch set and its descendants do -- Core has no address index, so
 * that lineage is the only convention there is to match. Both are optional:
 * without them the call behaves exactly as before, up to AXR_TXID_CAP txids.
 *
 * The window is not sugar over a full read. It is applied BEFORE a run event's
 * txid is resolved, and resolving one costs a block read: on run 26 at the tip
 * an unwindowed query for a heavily-used address resolved 100,000 txids from
 * 100,000 distinct blocks across a 716 GB archive. Asking for a range of
 * heights reads only that range's blocks.
 *
 * Dedup spans the whole call through one hash set (axr_txid_reset once, and
 * each address seeded with the running count), so the result is unique across
 * addresses. It used to be a strcmp() scan of the JSON array built so far --
 * O(n^2), ~5e9 compares at the cap, the same shape as the two other quadratic
 * dedups this path had. */
static int cmd_getaddresstxids(const rj_val* params, rj_val** res, long* ec, const char** em){
    const rj_val* addrs[64];
    long na = axr_collect(params, addrs, 64);
    if (na < 1){ *ec = -8; *em = "getaddresstxids(address | [addresses] | {\"addresses\":[...], \"start\":h, \"end\":h})"; return 0; }
    if (!axr_enabled(ec, em)) return 0;
    long lo = 0, hi = -1;
    if (params->items[0]->typ == RJ_OBJ){
        const rj_val* s = rj_obj_get((rj_val*)params->items[0], "start");
        const rj_val* e = rj_obj_get((rj_val*)params->items[0], "end");
        if (s && s->typ != RJ_NULL){
            if (s->typ != RJ_NUM){ *ec = -3; *em = "start must be a block height"; return 0; }
            lo = (long)strtoll(s->str, NULL, 10);
            if (lo < 0){ *ec = -8; *em = "start must not be negative"; return 0; }
        }
        if (e && e->typ != RJ_NULL){
            if (e->typ != RJ_NUM){ *ec = -3; *em = "end must be a block height"; return 0; }
            hi = (long)strtoll(e->str, NULL, 10);
            if (hi < 0){ *ec = -8; *em = "end must not be negative"; return 0; }
        }
        if (hi >= 0 && hi < lo){ *ec = -8; *em = "end must not be below start"; return 0; }
    }
    static unsigned char txids[AXR_TXID_CAP * 32];
    axr_txid_reset();
    long total = 0;
    for (long i = 0; i < na; i++){
        int t; unsigned char key[32];
        if (!axr_key(addrs[i]->str, &t, key)){ *ec = -5; *em = "Invalid address"; return 0; }
        axr_acc a;
        long n = axr_read(t, key, &a, txids, AXR_TXID_CAP, total, lo, hi);
        if (n < 0){ *ec = -1; *em = "Address index unreadable"; return 0; }
        total = n;
    }
    rj_val* arr = rj_arr();
    for (long k = 0; k < total; k++){
        char hx[65];
        hex_rev(hx, txids + k * 32, 32);        /* wire -> display order */
        rj_arr_push(arr, rj_str(hx));
    }
    *res = arr;
    return 1;
}

/* getindexinfo runs in the FAST lane (no execution lock), so it reads the
 * index files through state of its own rather than the txid/txo-spender
 * readers the lookups use:
 *   - its own run sets (irs_* is single-threaded per set), and
 *   - an O(1) probe of each tail: the height of its LAST whole record. The
 *     writers append in strictly ascending height order, one block per
 *     write(2) (tx_index_tail.c, txosp_tail.c), so the last record carries
 *     the tail's highest height -- the same fact bfi_probe_count and
 *     axt_probe_covered already read that way.
 * It used to call txi_have()/tsp_have(), which map and scan the tails. The
 * txospender scan restarted from byte 0 whenever the file grew, and on run 27
 * (2026-09-19, IBD) the file was 61.6 GB and grew every block: every
 * getindexinfo read it end to end under the execution lock, the RPC process
 * held 15.7 GB of it resident, and uptime took 44 s behind it. */
static irunset_t g_gii_txi, g_gii_tsp; static int g_gii_init;
static long gii_txi_height(const u8* r){ u32 hh = 0; for (int b = 0; b < 4; b++) hh |= (u32)r[8+b] << (8*b); return (long)hh; }
static long gii_tsp_height(const u8* r){ tsp_rec x; tsp_unpack(&x, r); return (long)x.height; }
static long gii_tail_last(const char* file, int rec, long (*height_of)(const u8*), int* present){
    *present = 0;
    int fd = open(file, O_RDONLY);
    if (fd < 0) return -1;
    struct stat sb; long h = -1; u8 r[64];
    if (fstat(fd, &sb) == 0 && sb.st_size >= rec && rec <= (int)sizeof r){
        long n = (long)(sb.st_size / rec);
        *present = 1;
        if (pread(fd, r, (size_t)rec, (off_t)(n - 1) * rec) == rec) h = height_of(r);
    }
    close(fd);
    return h;
}
static int cmd_getindexinfo(const rj_val* params, rj_val** res, long* ec, const char** em){
    (void)ec; (void)em;
    /* Core does not type-check the arg -- it returns {} for a non-matching
     * or nonsense filter (verified live: `getindexinfo 123` gives {}). */
    const char* want = NULL;
    if (params && params->typ == RJ_ARR && params->nitems >= 1 &&
        params->items[0]->typ == RJ_STR) want = params->items[0]->str;
    rj_val* o = rj_obj();
    if (!g_gii_init){
        irs_init(&g_gii_txi, "txindex", "BMCTXIDX", TXI_REC, TXI_SPARSE);
        irs_init(&g_gii_tsp, "txospender", TSP_MAGIC, TSP_REC, TSP_SPARSE);
        g_gii_init = 1;
    }
    long tip = g_open ? refresh() : -1;
    if (ix_on(g_ix_txindex) && (!want || !strcmp(want, "txindex"))){
        /* Core reports {synced, best_block_height}. Coverage is the index's
         * sorted runs plus the daemon-maintained tail (contiguous by
         * construction -- the tail backfills any gap above the runs), so
         * "synced" means that combined range reaches the tip; a partial
         * index reports false with its own best height, which is the honest
         * reading and what a caller needs to decide whether to trust a
         * miss. */
        int present; long th = gii_tail_last("txindex.tail", TXI_REC, gii_txi_height, &present);
        long rt = irs_covered_to(&g_gii_txi);
        if (g_gii_txi.n > 0 || present){
            long cov_to = th > rt ? th : rt;
            rj_val* e = rj_obj();
            rj_obj_set(e, "synced", rj_bool(tip >= 0 && cov_to >= tip));
            rj_obj_set(e, "best_block_height", rj_numf("%ld", cov_to));
            rj_obj_set(o, "txindex", e);
        }
    }
    if (ix_on(g_ix_txospender) && (!want || !strcmp(want, "txospenderindex"))){
        int present; long th = gii_tail_last(TSP_TAIL_FILE, TSP_REC, gii_tsp_height, &present);
        long rt = irs_covered_to(&g_gii_tsp);
        if (g_gii_tsp.n > 0 || present){
            long cov_to = th > rt ? th : rt;
            rj_val* e = rj_obj();
            rj_obj_set(e, "synced", rj_bool(tip >= 0 && cov_to >= tip));
            rj_obj_set(e, "best_block_height", rj_numf("%ld", cov_to));
            rj_obj_set(o, "txospenderindex", e);
        }
    }
    { extern long bfi_probe_count(void);
      long bn = ix_on(g_ix_bfilter) ? bfi_probe_count() : -1;
      if (bn >= 0 && (!want || !strcmp(want, "basic block filter index"))){
          rj_val* e = rj_obj();
          rj_obj_set(e, "synced", rj_bool(tip >= 0 && bn - 1 >= tip));
          rj_obj_set(e, "best_block_height", rj_numf("%ld", bn - 1));
          rj_obj_set(o, "basic block filter index", e);
      } }
    { long an = ix_on(g_ix_addrindex) ? axt_probe_covered() : -1;
      if (an >= 0 && (!want || !strcmp(want, "addressindex"))){
          /* EXTENSION index (Core has no address index); reported here so an
           * operator can see coverage the same way as the real Core indexes */
          rj_val* e = rj_obj();
          rj_obj_set(e, "synced", rj_bool(tip >= 0 && an >= tip));
          rj_obj_set(e, "best_block_height", rj_numf("%ld", an));
          rj_obj_set(o, "addressindex", e);
      } }
    if (g_csi_h && ix_on(g_ix_coinstats) && (!want || !strcmp(want, "coinstatsindex"))){
        long ch = g_csi_h();
        if (ch >= 0){
            rj_val* e = rj_obj();
            /* "synced" against the UTXO applied height would always be true
             * by construction; against the CHAIN tip it reports whether the
             * apply loop itself is caught up -- the honest reading. */
            rj_obj_set(e, "synced", rj_bool(tip >= 0 && ch >= tip));
            rj_obj_set(e, "best_block_height", rj_numf("%ld", ch));
            rj_obj_set(o, "coinstatsindex", e);
        }
    }
    *res = o;
    return 1;
}

/* ---- gettxoutsetinfo -------------------------------------------------------
 * The reader (daemon/utxo_setinfo_rpc.c -- the SAME machinery as the
 * standalone parity tool) is injected by the daemon; the standalone rpcd has
 * none and reports unavailable. DOCUMENTED DIVERGENCES from Core: our default
 * hash_type is muhash (the one hash we implement; Core defaults
 * hash_serialized_3, which we refuse by name), and the coinstatsindex-only
 * extras (total_unspendable_amount, block_info) are absent -- we run no such
 * index, matching Core-without-the-index behavior. height is the UTXO
 * APPLIED height (the state the numbers describe), which on a catching-up
 * node intentionally lags the header tip.
 *
 * CSI-2 (2026-09-05, /mnt/2tbssd benchmark): Core's height/blockhash second
 * argument works ONLY with coinstatsindex because Core's index persists a
 * digest at EVERY height. This index (coinstats.dat, CSI_MAGIC "BMCCSI1")
 * persists ONE record: the running state at the applied tip. Computing
 * historical digests would mean either persisting 448 bytes/height x 965k
 * (~430 MB) or replaying undo from the tip backward -- both are genuine
 * feature work, not a gap to paper over. Until then historical queries are
 * REFUSED (the guard in cmd_gettxoutsetinfo, Core's own error text), which
 * is why getindexinfo's coinstatsindex entry means "current-state O(1)",
 * not Core's "any-height O(1)". The seam for the feature: append-per-height
 * records in this file + the guard lifted for heights <= best_block_height
 * of the index. */
typedef struct {
    long height;
    unsigned long long txouts, bogosize, total_amount;
    unsigned char muhash[32];
    int muhash_valid;
} rpc_usi_out_t;
static long (*g_usi_run)(int, void*, char*, unsigned long);
void rpc_chain_set_utxosetinfo(long (*run)(int, void*, char*, unsigned long)){
    g_usi_run = run;
}
static int cmd_gettxoutsetinfo(const rj_val* params, rj_val** res, long* ec, const char** em){
    static char embuf[256];   /* >= msg[256]: the snprintf below copies it whole */
    /* CSI-1 (2026-09-05, /mnt/2tbssd bmc-vs-Core benchmark): Core's second
     * argument selects a HEIGHT or BLOCKHASH and is ONLY valid with
     * coinstatsindex, whose per-height digests make the query O(1). This
     * node's index persists the running digest for the APPLIED tip only
     * (coinstats.dat: one record), and the LSM walk has no height history.
     * The previous behavior accepted the parameter and returned the TIP set
     * -- a silently wrong answer: the caller asked for 963,967 and received
     * 965,626 with the right "height" field but the wrong data for what
     * they actually queried. Core's own error text, same meaning. */
    int want_muhash = 1;   /* OUR default (documented divergence, see above) */
    /* EVERY argument's TYPE is checked before ANY argument's VALUE, and the
     * lowest-positioned type failure wins. Measured against Core v31.1 on
     * 2026-09-15 across five methods: `gettxoutsetinfo "bogus" null "x"`
     * reports Position 3 (use_index), not the invalid hash_type at position 1.
     * These checks therefore sit ahead of the block-specific refusals below,
     * which are value errors. */
    if (params && params->typ == RJ_ARR){
        rj_typeerrs te; rj_typeerr_init(&te);
        if (params->nitems >= 1 && params->items[0]->typ != RJ_STR &&
            params->items[0]->typ != RJ_NULL)
            rj_typeerr_add(&te, 1, "hash_type", params->items[0], "string");
        if (params->nitems >= 3 && params->items[2]->typ != RJ_BOOL &&
            params->items[2]->typ != RJ_NULL)
            rj_typeerr_add(&te, 3, "use_index", params->items[2], "bool");
        if (rj_typeerr_fail(&te, ec, em)) return 0;
    }
    if (params && params->typ == RJ_ARR && params->nitems >= 2 && params->items[1]->typ != RJ_NULL){   /* Core's order: the block-specific refusals first */
        if (params->items[0]->typ == RJ_STR && !strncmp(params->items[0]->str, "hash_serialized", 15)){
            *ec = -8; *em = "hash_serialized_3 hash type cannot be queried for a specific block"; return 0; }
        if (params->nitems >= 3 && params->items[2]->typ == RJ_BOOL && params->items[2]->str[0] == '0'){
            *ec = -8; *em = "Cannot set use_index to false when querying for a specific block"; return 0; }
    }
    if (params && params->typ == RJ_ARR && params->nitems >= 1){
        const char* ht = params->items[0]->str;
        if (!strcmp(ht, "muhash")) want_muhash = 1;
        else if (!strcmp(ht, "none")) want_muhash = 0;
        else if (!strcmp(ht, "hash_serialized_3") || !strcmp(ht, "hash_serialized_2") || !strcmp(ht, "hash_serialized")){
            snprintf(embuf, sizeof embuf, "%s hash type not implemented (this node computes muhash)", ht);
            *ec = -8; *em = embuf; return 0; }
        else {
            snprintf(embuf, sizeof embuf, "'%s' is not a valid hash_type", ht);
            *ec = -8; *em = embuf; return 0; }
    }
    /* ---- a specific block (Core's hash_or_height, 2026-09-08) --------------
     * Answered from the index's per-height rows (coinstats_hist.dat; the
     * design note above described the seam). Core's checks and texts first;
     * then Core's output shape: the set at that height, and block_info as
     * the difference from the previous row. total_unspendable_amount is
     * sum(subsidy 0..h) - total_amount, an identity of Core's accounting
     * (verified against the oracle at 800,000 and 966,000). */
    if (params && params->typ == RJ_ARR && params->nitems >= 2 && params->items[1]->typ != RJ_NULL){
        if (!g_csi_hist){ *ec = -8; *em = "Querying specific block heights requires coinstatsindex"; return 0; }
        long h; long tip = refresh();
        if (params->items[1]->typ == RJ_NUM){                       /* a height (Core: ParseHashOrHeight) */
            long long v; if (!rpc_param_i64(params, 1, &v, ec, em)) return 0;
            if (v < 0){ *ec = -8; snprintf(embuf, sizeof embuf, "Target block height %lld is negative", v); *em = embuf; return 0; }
            if (v > tip){ *ec = -8; snprintf(embuf, sizeof embuf, "Target block height %lld after current tip %ld", v, tip); *em = embuf; return 0; }
            h = (long)v;
        } else if (!lookup_block_param(params, 1, 1, &h, ec, em)) return 0;   /* a block hash */
        csi_hist_out_t ho; int r = g_csi_hist(h, want_muhash, &ho);
        if (r == 0){
            long f = g_csi_hist_first ? g_csi_hist_first() : -1, l = g_csi_hist_last ? g_csi_hist_last() : -1;
            snprintf(embuf, sizeof embuf, "coinstatsindex has no record for height %ld (its rows cover heights %ld to %ld; %s)", h, f, l,
                     g_csi_hist_status ? g_csi_hist_status() : "earlier heights need the history build");
            *ec = -8; *em = embuf; return 0; }
        if (r < 0){ snprintf(embuf, sizeof embuf, "coinstatsindex row %ld is the baseline of its generation: block_info needs the previous row", h); *ec = -8; *em = embuf; return 0; }
        rj_val* out = rj_obj();
        rj_obj_set(out, "height", rj_numf("%ld", h));
        { u8 hdr[80]; char hx[65];
          if (read_block_prefix(h, hdr, 80) == 1){ u8 hh[32]; sha256d(hh, hdr, 80); hex_rev(hx, hh, 32); rj_obj_set(out, "bestblock", rj_str(hx)); } }
        rj_obj_set(out, "txouts", rj_numf("%llu", (unsigned long long)ho.txouts));
        rj_obj_set(out, "bogosize", rj_numf("%llu", (unsigned long long)ho.bogo));
        if (want_muhash && ho.digest_valid){ char mh[65]; hex_rev(mh, ho.digest, 32); rj_obj_set(out, "muhash", rj_str(mh)); }
        rj_obj_set(out, "total_amount", amount_json(ho.amount));
        { unsigned long long sum = 0; long hh = 0; unsigned long long sub = 5000000000ULL;
          while (hh <= h){ long n = g_halving_interval - (hh % g_halving_interval); if (hh + n > h + 1) n = h + 1 - hh; sum += sub * (unsigned long long)n; hh += n; sub >>= 1; }
          rj_obj_set(out, "total_unspendable_amount", amount_json(sum - ho.amount)); }
        rj_val* bi = rj_obj();
        rj_obj_set(bi, "prevout_spent", amount_json(ho.d_prevout));
        rj_obj_set(bi, "coinbase", amount_json(ho.d_coinbase));
        rj_obj_set(bi, "new_outputs_ex_coinbase", amount_json(ho.d_new_ex_cb));
        rj_obj_set(bi, "unspendable", amount_json(ho.d_genesis + ho.d_bip30 + ho.d_scripts + ho.d_unclaimed));
        rj_val* un = rj_obj();
        rj_obj_set(un, "genesis_block", amount_json(ho.d_genesis));
        rj_obj_set(un, "bip30", amount_json(ho.d_bip30));
        rj_obj_set(un, "scripts", amount_json(ho.d_scripts));
        rj_obj_set(un, "unclaimed_rewards", amount_json(ho.d_unclaimed));
        rj_obj_set(bi, "unspendables", un);
        rj_obj_set(out, "block_info", bi);
        *res = out; return 1;
    }
    if (!g_usi_run && !g_csi_run){ *ec = -1; *em = "UTXO set info unavailable in this process"; return 0; }
    rpc_usi_out_t o; memset(&o, 0, sizeof o);
    static char msg[256];
    long r = 0;
    if (g_csi_run) r = g_csi_run(want_muhash, &o, msg, sizeof msg);
    /* -2 (2026-09-06, fold worker): the index EXISTS but cannot answer for
     * the applied height yet -- the fold worker's watermark is behind the
     * connect thread's last commit (waited, still behind), or the index is
     * deferred for the whole bulk catch-up. Refuse, in Core's warm-up code;
     * do NOT fall through to the walk reader, which would either refuse as
     * busy or spend minutes walking a set the index is seconds from
     * describing. */
    if (r == -2){ *ec = -28; snprintf(embuf, sizeof embuf, "%s", msg[0] ? msg : "coinstats index not ready"); *em = embuf; return 0; }
    if (r != 1 && g_usi_run) r = g_usi_run(want_muhash, &o, msg, sizeof msg);
    if (r == 0){ *ec = -1; snprintf(embuf, sizeof embuf, "%s", msg[0] ? msg : "UTXO set busy"); *em = embuf; return 0; }
    if (r != 1){ *ec = -1; snprintf(embuf, sizeof embuf, "%s", msg[0] ? msg : "UTXO set read failed"); *em = embuf; return 0; }
    rj_val* out = rj_obj();
    rj_obj_set(out, "height", rj_numf("%ld", o.height));
    { u8 hdr[80]; char hx[65];
      if (read_block_prefix(o.height, hdr, 80) == 1){
          u8 hh[32]; sha256d(hh, hdr, 80); hex_rev(hx, hh, 32);
          rj_obj_set(out, "bestblock", rj_str(hx));
      } }
    rj_obj_set(out, "txouts", rj_numf("%llu", o.txouts));
    rj_obj_set(out, "bogosize", rj_numf("%llu", o.bogosize));
    /* Core prints the digest as a uint256 (GetHex: byte-reversed), as the
     * coinstatsindex path above already does with hex_rev. This live-walk
     * path printed it forward, so a set identical to Core's read as a
     * mismatch (2026-09-25: Mac mainnet at 968,570, every other field equal;
     * reversed, the digest was Core's exactly). */
    if (o.muhash_valid){ char mh[65]; hex_rev(mh, o.muhash, 32); rj_obj_set(out, "muhash", rj_str(mh)); }
    rj_obj_set(out, "total_amount", rj_numf("%llu.%08llu",
        o.total_amount/100000000ULL, o.total_amount%100000000ULL));
    *res = out;
    return 1;
}

/* ---- scantxoutset ----------------------------------------------------------
 * action start: expand the scanobjects (descriptor strings or {desc,range})
 * into concrete scriptPubKeys with the SAME descriptor engine
 * deriveaddresses uses, hand them to the injected whole-set scanner
 * (daemon/utxo_setinfo_rpc.c's utxo_scan_rpc_run -- the tool-derived reader
 * with the fingerprint/quiescence discipline), and render Core's exact
 * result shape. Scans here are SYNCHRONOUS (the walk takes ~90s), so
 * "status" is always null and "abort" always false, exactly what Core
 * answers when no scan is in progress. Checksums on scan descriptors are
 * optional (verified when present), unlike deriveaddresses.
 * height/confirmations are relative to the UTXO APPLIED height -- the state
 * that was scanned. */
typedef struct {
    unsigned char txid[32]; unsigned int vout;
    unsigned long long value; unsigned long long height; int coinbase;
    unsigned char spk[128]; unsigned int spklen;
} rpc_scan_hit_t;
static long (*g_scan_run)(const unsigned char*, const unsigned int*, int,
                          void*, long, long*, long*, unsigned long long*,
                          unsigned long long*, int*, char*, unsigned long);
void rpc_chain_set_utxoscan(long (*run)(const unsigned char*, const unsigned int*, int,
                                        void*, long, long*, long*, unsigned long long*,
                                        unsigned long long*, int*, char*, unsigned long)){
    g_scan_run = run;
}
#define SCAN_MAX_TARGETS 4096
#define SCAN_MAX_HITS    32768
/* Expand scanobjects (descriptor strings or {desc,range}) into concrete
 * scriptPubKeys. Shared by scantxoutset, scanblocks and
 * getdescriptoractivity so the three cannot drift in what they accept. */
static int scan_expand_objects(const rj_val* objs, u8 (*targets)[128], u32* tlens,
                               int cap, int* ntgt_io, long* ec, const char** em){
    static char perr[320];
    int ntgt = *ntgt_io;
    for (unsigned long oi = 0; oi < objs->nitems; oi++){
        const rj_val* ob = objs->items[oi];
        const char* dstr = 0; long rbegin = 0, rend = -1;
        if (ob->typ == RJ_STR) dstr = ob->str;
        else if (ob->typ == RJ_OBJ){
            rj_val* dv = rj_obj_get((rj_val*)ob, "desc");
            if (!dv || dv->typ != RJ_STR){ *ec=-8; *em="Descriptor needs to be provided in scan object"; return 0; }
            dstr = dv->str;
            rj_val* rv = rj_obj_get((rj_val*)ob, "range");
            if (rv){
                if (rv->typ==RJ_NUM){ rbegin=0; rend=(long)strtoll(rv->str,NULL,10); }
                else if (rv->typ==RJ_ARR && rv->nitems==2 && rv->items[0]->typ==RJ_NUM && rv->items[1]->typ==RJ_NUM){
                    rbegin=(long)strtoll(rv->items[0]->str,NULL,10);
                    rend=(long)strtoll(rv->items[1]->str,NULL,10); }
                else { *ec=-8; *em="Invalid range"; return 0; }
                if (rbegin<0 || rend<rbegin){ *ec=-8; *em="Invalid range"; return 0; }
                if (rend-rbegin > 100000){ *ec=-8; *em="Range is too large"; return 0; }
            }
        } else { *ec=-8; *em="Invalid scan object"; return 0; }
        /* checksum optional here (Core scan accepts bare descriptors) */
        char core[320];
        { const char* hash = strchr(dstr, '#');
          size_t cl = hash ? (size_t)(hash-dstr) : strlen(dstr);
          if (cl >= sizeof core){ *ec=-5; *em="Descriptor too long"; return 0; }
          memcpy(core, dstr, cl); core[cl]=0;
          if (hash){
              char cks[9];
              if (!desc_checksum(core, cks)){ *ec=-5; *em="Invalid characters in descriptor"; return 0; }
              if (strlen(hash+1)!=8 || strcmp(hash+1,cks)){
                  snprintf(perr,sizeof perr,"Provided checksum '%s' does not match computed checksum '%s'", hash+1, cks);
                  *ec=-5; *em=perr; return 0; } } }
        static descr_t d;   /* ~45 KB: not on the RPC thread's stack; the dispatcher is single-threaded */
        { char e[256]; if (!descr_parse(core, &d, e, sizeof e)){ snprintf(perr,sizeof perr,"%s",e); *ec=-5; *em=perr; return 0; } }
        long lo = 0, hi = 0;
        if (d.ranged){ lo = rbegin; hi = (rend >= 0) ? rend : 1000; }   /* Core's default range */
        for (int sel = 0; sel < descr_multipath_n(&d); sel++){          /* BIP389: every expansion is scanned */
        descr_multipath_select(&d, sel);
        for (long i = lo; i <= hi; i++){
            descr_spk_t sp[4]; int n = descr_expand(&d, i, sp, 4);   /* combo: all four forms are scanned */
            if (n < 0){ snprintf(perr,sizeof perr,"%s", descr_last_error()); *ec=-5; *em=perr; return 0; }
            for (int q = 0; q < n; q++){
                if (ntgt >= cap){ *ec=-8; *em="Too many scan targets"; return 0; }
                if (sp[q].len > 128){ *ec=-5; *em="Descriptor script too large"; return 0; }
                memcpy(targets[ntgt], sp[q].spk, (size_t)sp[q].len); tlens[ntgt] = (u32)sp[q].len; ntgt++;
            }
        }
        }   /* expansions */
    }
    *ntgt_io = ntgt;
    return 1;
}

static int cmd_scantxoutset(const rj_val* params, rj_val** res, long* ec, const char** em){
    static char perr[256];   /* >= msg[256] */
    const char* action = rpc_param_str(params, 0, ec, em); if (!action) return 0;
    if (!strcmp(action, "status")){ *res = rj_null(); return 1; }
    if (!strcmp(action, "abort")){ *res = rj_bool(0); return 1; }
    if (strcmp(action, "start")){
        snprintf(perr, sizeof perr, "Invalid action '%s'", action);
        *ec = -8; *em = perr; return 0; }
    if (!params || params->typ != RJ_ARR || params->nitems < 2 || params->items[1]->typ != RJ_ARR){
        *ec = -8; *em = "scanobjects argument is required for the start action"; return 0; }
    if (!g_scan_run){ *ec = -1; *em = "UTXO scan unavailable in this process"; return 0; }

    static u8 targets[SCAN_MAX_TARGETS][128];
    static u32 tlens[SCAN_MAX_TARGETS];
    int ntgt = 0;
    const rj_val* objs = params->items[1];
    if (!scan_expand_objects(objs, targets, tlens, SCAN_MAX_TARGETS, &ntgt, ec, em)) return 0;
    if (!ntgt){ *ec=-8; *em="scanobjects argument is required for the start action"; return 0; }

    static rpc_scan_hit_t hits[SCAN_MAX_HITS];
    long hits_n = 0, sheight = 0; int overflow = 0;
    unsigned long long scanned = 0, total_sat = 0;
    static char msg[256];
    long r = g_scan_run(&targets[0][0], tlens, ntgt, hits, SCAN_MAX_HITS, &hits_n,
                        &sheight, &scanned, &total_sat, &overflow, msg, sizeof msg);
    if (r == 0){ *ec=-1; snprintf(perr,sizeof perr,"%s",msg[0]?msg:"UTXO set busy"); *em=perr; return 0; }
    if (r != 1){ *ec=-1; snprintf(perr,sizeof perr,"%s",msg[0]?msg:"UTXO scan failed"); *em=perr; return 0; }
    if (overflow){ *ec=-1; *em="Scan matched more outputs than this node can return"; return 0; }

    rj_val* o = rj_obj();
    rj_obj_set(o, "success", rj_bool(1));
    rj_obj_set(o, "txouts", rj_numf("%llu", scanned));
    rj_obj_set(o, "height", rj_numf("%ld", sheight));
    { u8 hdr[80]; char hx[65];
      if (read_block_prefix(sheight, hdr, 80) == 1){
          u8 hh[32]; sha256d(hh, hdr, 80); hex_rev(hx, hh, 32);
          rj_obj_set(o, "bestblock", rj_str(hx)); } }
    rj_val* uns = rj_arr();
    for (long i = 0; i < hits_n; i++){
        rpc_scan_hit_t* h = &hits[i];
        rj_val* e = rj_obj();
        { char hx[65]; hex_rev(hx, h->txid, 32); rj_obj_set(e, "txid", rj_str(hx)); }
        rj_obj_set(e, "vout", rj_numf("%u", h->vout));
        { char* sh2 = malloc((size_t)h->spklen*2+1);
          if (sh2){ hex_of(sh2, h->spk, h->spklen); rj_obj_set(e, "scriptPubKey", rj_str(sh2)); free(sh2); } }
        { char* di = desc_inner_of(h->spk, h->spklen); char* dc = desc_with_checksum(di);
          if (dc){ rj_obj_set(e, "desc", rj_str(dc)); free(dc); } free(di); }
        rj_obj_set(e, "amount", rj_numf("%llu.%08llu", h->value/100000000ULL, h->value%100000000ULL));
        rj_obj_set(e, "coinbase", rj_bool(h->coinbase));
        rj_obj_set(e, "height", rj_numf("%llu", h->height));
        { u8 hdr[80]; char hx[65];
          if (read_block_prefix((long)h->height, hdr, 80) == 1){
              u8 hh[32]; sha256d(hh, hdr, 80); hex_rev(hx, hh, 32);
              rj_obj_set(e, "blockhash", rj_str(hx)); } }
        rj_obj_set(e, "confirmations", rj_numf("%lld", (long long)sheight - (long long)h->height + 1));
        rj_arr_push(uns, e);
    }
    rj_obj_set(o, "unspents", uns);
    rj_obj_set(o, "total_amount", rj_numf("%llu.%08llu", total_sat/100000000ULL, total_sat%100000000ULL));
    *res = o;
    return 1;
}

/* The fast lane: g_fast_mu and its private handle (see "lanes" at the top).
 * Everything run here is a handful of preads and stats, never a walk. */
#define FAST_LANE(call) do {                                                  \
        pthread_mutex_lock(&g_fast_mu);                                       \
        int r_;                                                               \
        if (!lane_handle_open(g_fst, &g_fst_ok)){                             \
            *ec = -28; *em = "Loading block index..."; r_ = 0; }              \
        else { u8* p_ = t_st; t_st = g_fst; r_ = (call); t_st = p_; }        \
        pthread_mutex_unlock(&g_fast_mu);                                     \
        return r_;                                                            \
    } while (0)

/* Methods whose handlers here need NO execution lock: they run in a lane of
 * their own (see "lanes" at the top). rpc_server.c asks this to decide how to
 * dispatch; 1 = fast (bounded, may run on the connection's own thread),
 * 2 = lock-free but possibly slow (a first getchaintxstats build, a 30 s
 * wait), 0 = the execution lock is required. */
int rpc_chain_method_lane(const char* m){
    if (!strcmp(m, "uptime") || !strcmp(m, "getblockcount") || !strcmp(m, "getbestblockhash")
     || !strcmp(m, "getblockchaininfo") || !strcmp(m, "getdifficulty") || !strcmp(m, "getindexinfo"))
        return 1;
    if (!strcmp(m, "getchaintxstats") || !strcmp(m, "waitfornewblock")
     || !strcmp(m, "waitforblockheight") || !strcmp(m, "waitforblock"))
        return 2;
    return 0;
}

int rpc_chain_dispatch(const char* m, const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!rpc_chain_known_method(m)) return -1;
    if (!strcmp(m, "uptime")) return cmd_uptime(res);
    if (!strcmp(m, "stop")) return cmd_stop(res);
    /* pure util methods: no chain state needed (Core serves them always). */
    if (!strcmp(m, "getdescriptorinfo")) return cmd_getdescriptorinfo(params, res, ec, em);
    if (!strcmp(m, "deriveaddresses")) return cmd_deriveaddresses(params, res, ec, em);
    if (!strcmp(m, "decodescript")) return cmd_decodescript(params, res, ec, em);
    if (!strcmp(m, "createmultisig")) return cmd_createmultisig(params, res, ec, em);
    if (!strcmp(m, "getindexinfo")){
        if (!g_open){ pthread_mutex_lock(&g_fast_mu); int r = cmd_getindexinfo(params, res, ec, em); pthread_mutex_unlock(&g_fast_mu); return r; }
        FAST_LANE(cmd_getindexinfo(params, res, ec, em));
    }
    if (!strcmp(m, "getaddressbalance")) return cmd_getaddressbalance(params, res, ec, em);
    if (!strcmp(m, "getaddresstxids")) return cmd_getaddresstxids(params, res, ec, em);
    if (!g_open){ *ec = -28; *em = "Loading block index..."; return 0; }
    if (!strcmp(m, "getblockcount")) FAST_LANE(cmd_getblockcount(res));
    if (!strcmp(m, "getbestblockhash")) FAST_LANE(cmd_getbestblockhash(res, ec, em));
    if (!strcmp(m, "getchaintips")) return cmd_getchaintips(res, ec, em);
    if (!strcmp(m, "getblockhash")) return cmd_getblockhash(params, res, ec, em);
    if (!strcmp(m, "getblockheader")) return cmd_getblockheader(params, res, ec, em);
    if (!strcmp(m, "getblock")) return cmd_getblock(params, res, ec, em);
    if (!strcmp(m, "getblockstats")) return cmd_getblockstats(params, res, ec, em);
    if (!strcmp(m, "getnetworkhashps")) return cmd_getnetworkhashps(params, res, ec, em);
    if (!strcmp(m, "getmininginfo")) return cmd_getmininginfo(res, ec, em);
    if (!strcmp(m, "getblocktemplate")) return cmd_getblocktemplate(params, res, ec, em);
    if (!strcmp(m, "gettxoutsetinfo")) return cmd_gettxoutsetinfo(params, res, ec, em);
    if (!strcmp(m, "scantxoutset")) return cmd_scantxoutset(params, res, ec, em);
    if (!strcmp(m, "getblockchaininfo")) FAST_LANE(cmd_getblockchaininfo(res, ec, em));
    if (!strcmp(m, "getdifficulty")) FAST_LANE(cmd_getdifficulty(res, ec, em));
    if (!strcmp(m, "submitheader")) return cmd_submitheader(params, res, ec, em);
    if (!strcmp(m, "getchainstates")) return cmd_getchainstates(res, ec, em);
    if (!strcmp(m, "getdeploymentinfo")) return cmd_getdeploymentinfo(params, res, ec, em);
    if (!strcmp(m, "getchaintxstats")) return cmd_getchaintxstats(params, res, ec, em);
    if (!strcmp(m, "verifychain")) return cmd_verifychain(params, res, ec, em);
    if (!strcmp(m, "waitfornewblock")) return wfb_run(cmd_waitfornewblock, params, res, ec, em);
    if (!strcmp(m, "waitforblockheight")) return wfb_run(cmd_waitforblockheight, params, res, ec, em);
    if (!strcmp(m, "waitforblock")) return wfb_run(cmd_waitforblock, params, res, ec, em);
    if (!strcmp(m, "getblockfilter")) return cmd_getblockfilter(params, res, ec, em);
    if (!strcmp(m, "scanblocks")) return cmd_scanblocks(params, res, ec, em);
    if (!strcmp(m, "getdescriptoractivity")) return cmd_getdescriptoractivity(params, res, ec, em);
    if (!strcmp(m, "dumptxoutset")) return cmd_dumptxoutset(params, res, ec, em);
    if (!strcmp(m, "loadtxoutset"))
        return ch_unsupported(CH_NO_SNAPSHOT_LOAD, ec, em);
    if (!strcmp(m, "preciousblock") || !strcmp(m, "pruneblockchain"))
        return ch_unsupported(CH_NO_FORKCHOICE_RPC, ec, em);
    if (!strcmp(m, "getrawtransaction")) return cmd_getrawtransaction(params, res, ec, em);
    if (!strcmp(m, "gettxoutproof")) return cmd_gettxoutproof(params, res, ec, em);
    if (!strcmp(m, "verifytxoutproof")) return cmd_verifytxoutproof(params, res, ec, em);
    return -1;
}

static int pmt_put_cs(u8* d, u64 v){ return pmt_put_cs_pad(d, v, 0); }
