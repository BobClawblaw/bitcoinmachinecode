/* tests/test_reorg.c -- Stage B integration harness: fork detection, fork-point
 * location, block disconnect, block reconnect, mempool reconciliation, and the
 * real multi-hash locator, driven against the REAL production code paths
 * (daemon/reorg.c, daemon/utxo_live.c, daemon/undo_log.c, the real LSM UTXO
 * store, the real block store, the real mempool + policy layer).
 *
 * Chains are synthetic but genuinely mined (pow_check-satisfying nonces) and
 * genuinely spendable: every block carries a real coinbase and most carry
 * real spends of earlier coinbase outputs, so there is actual UTXO state to
 * disconnect and reconnect -- not just empty blocks.
 *
 * THE LOAD-BEARING ASSERTION in every reorg case is the UTXO comparison. The
 * expected set is computed by an INDEPENDENT model in this file (a flat
 * array, updated straight from the chain-builder's own record of what each
 * transaction creates and spends -- it never calls utxo_walk, apply_block or
 * anything else from the code under test) by replaying ONLY the winning
 * branch from scratch. That model is then compared against the live LSM in
 * both directions: every entry the model says should exist must be present
 * with the exact value and script, and every outpoint that exists only on the
 * losing branch must be absent, with the total live count matching. A reorg
 * that merely "does not crash" fails this.
 *
 * Each case runs in a FORKED child in its own temp directory, because
 * daemon/utxo_live.c owns process-global LSM state (mmaps, fds, applied
 * height) that must not bleed between cases.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/file.h>
#include "../daemon/reorg.h"
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

/* ---- code under test / supporting asm ---- */
extern long store_init(void* st);
extern long store_reload(void* st);
extern int  store_get_at(void* st, u64 height, u64 out_meta[3]);
extern long idxscan_append_locked(void* st, const u8 hash[32], const void* raw, long len);
extern long idxscan_append_nolocked(void* st, const u8 hash[32], const void* raw, long len);
extern int  store_validates_prevhash(void* st, const u8 header[80]);
extern int  store_get_tip_hash(void* st, u8 out[32]);
extern long store_truncate_to(void* st, long target);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern int  store_set_prune(void* st, int h);

extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern void sha256d(u8 out[32], const void* m, long len);
extern void merkle_root(u8 out[32], u8* hashes, long n);
extern int  cons_verify(const void* blk, long len, void* scratch, unsigned cap);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

extern void block_work(u8 work[16], u32 bits);
extern void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16]);
extern long chainwork_cmp(const u8 a[16], const u8 b[16]);
extern int  store_chainwork_init(void* st);
extern int  store_chainwork_append(void* st, long h, const u8 w[16]);
extern int  store_chainwork_get_at(void* st, long h, u8 out[16]);
extern int  store_chainwork_get_tip(void* st, u8 out[16]);
extern long store_chainwork_reload(void* st);
extern long store_chainwork_truncate(void* st, long target);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index,
                         u64 value, u64 height, u64 is_coinbase,
                         const u8* script, u32 slen);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                         u64* value, u64* height, u64* is_coinbase,
                         const u8** script, unsigned long* slen);
/* daemon/utxo_live.c exports these two globals so this harness can query the
 * very same live LSM instance the code under test just wrote to. */
extern void* utxo_live_table(void);
extern void* utxo_live_lst(void);

extern void idx_init(void* idx, unsigned long slots);
extern long idx_build_from_file(void* idx, const char* path);
extern long idx_count(void* idx);

extern long locator_build(void* store_buf, u8* out);
extern long node_sync(int fd, void* st, void* loc, void* buf, long buflen, long* out_count);
extern long node_sync_multi(int fd, void* st, void* loc, long loc_count,
                            void* buf, long buflen, long* out_count);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd[12], void* pl, unsigned cap, unsigned* len);
extern long p2p_getheaders(void* out, const void* loc, int count, const void* stop);
extern long p2p_headers_count(const void* pl, long plen);

extern size_t mpool_struct_size(unsigned long slots);
extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long cap);
extern long   mpool_put(void* mp, const u8 txid[32], const u8* tx, unsigned long len);
extern long   mpool_count(void* mp);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* out_len);
extern void   mpool_policy_init(void* pol, u64 relay, unsigned ma, unsigned mab,
                                unsigned md, unsigned mdb, unsigned rbf);
extern size_t mpool_policy_state_size(unsigned n);
extern void   mpool_policy_state_init(void* st, unsigned n);
extern long   mpool_policy_add(void* pol, void* st, void* mp, const u8* tx,
                               unsigned long txlen, const u8 txid[32], void* utxo);

/* bitcoin_mempool_policy.c resolves confirmed prevouts through this hook (see
 * its own extern's comment). Here it goes straight at the live LSM, which is
 * exactly the confirmed set the reorg just rewrote -- so mempool acceptance
 * is judged against the post-reorg chain, which is the whole point. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;
    u64 h_unused, cb_unused;
    return utxo_lsm_get(utxo_live_lst(), utxo_live_table(), txid, (u32)index, value, &h_unused, &cb_unused, script, slen);
}

/* ===================== tiny test scaffolding ============================= */
static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ckm(const char* l, int cond){
    if (cond) printf("PASS %s\n", l);
    else { printf("FAIL %s\n", l); failures++; }
}

/* ===================== chain builder ==================================== */
#define MAXTX      6
#define TXCAP      512
#define BLKCAP     8192
#define MAXBLK     48

typedef struct {
    u8  raw[TXCAP];
    long len;
    u8  txid[32];
    /* model metadata -- what this tx does, recorded by the BUILDER so the
     * expected-UTXO model never has to re-parse anything the code under test
     * also parses */
    int is_coinbase;
    u8  spend_txid[32];
    u32 spend_idx;
    u64 out_value;
} tx_t;

typedef struct {
    u8   raw[BLKCAP];
    long len;
    u8   hash[32];
    long ntx;
    tx_t tx[MAXTX];
    u32  bits;
} blk_t;

/* tx_txid ALWAYS reconstructs the unwitnessed serialisation into the caller's
 * buffer before hashing (see bitcoin_tx.asm's header) -- it returns 0 and
 * leaves `out` untouched if that buffer is too small. Passing NULL/0 here
 * silently produced all-zero txids, which made every UTXO key collide and
 * every merkle root wrong; give it real scratch. */
static u8 g_txid_scratch[1<<16];

static void put32(u8* p, u32 v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }

/* coinbase: null prevout, 4-byte scriptSig carrying `tag` (makes every
 * branch's coinbase txids distinct), one OP_TRUE output. */
static void mk_coinbase(tx_t* t, u32 tag, u64 value){
    u8* q = t->raw;
    put32(q,1); q+=4;
    *q++ = 1;
    memset(q,0,32); q+=32;
    put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, value); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    t->len = q - t->raw;
    t->is_coinbase = 1;
    t->out_value = value;
    memset(t->spend_txid, 0, 32); t->spend_idx = 0;
    if (!tx_txid(t->txid, t->raw, t->len, g_txid_scratch, sizeof g_txid_scratch)) { printf("FAIL tx_txid\n"); failures++; }
}

/* spend: one input (prev,idx), empty scriptSig, one OP_TRUE output. */
static void mk_spend(tx_t* t, const u8 prev[32], u32 idx, u64 value){
    u8* q = t->raw;
    put32(q,1); q+=4;
    *q++ = 1;
    memcpy(q, prev, 32); q+=32;
    put32(q, idx); q+=4;
    *q++ = 0;
    put32(q,0xfffffffdu); q+=4;   /* BIP125-replaceable, so RBF paths are live */
    *q++ = 1;
    put64(q, value); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    t->len = q - t->raw;
    t->is_coinbase = 0;
    t->out_value = value;
    memcpy(t->spend_txid, prev, 32); t->spend_idx = idx;
    if (!tx_txid(t->txid, t->raw, t->len, g_txid_scratch, sizeof g_txid_scratch)) { printf("FAIL tx_txid\n"); failures++; }
}

/* Assemble + mine. b->tx[0..ntx-1] and b->bits must already be set. */
static void mk_block(blk_t* b, const u8 prev[32], u32 tstamp){
    u8 leaves[MAXTX*32];
    for (long i=0;i<b->ntx;i++) memcpy(leaves+i*32, b->tx[i].txid, 32);
    u8 mr[32];
    if (b->ntx == 1) memcpy(mr, leaves, 32);
    else merkle_root(mr, leaves, b->ntx);

    u8* o = b->raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, mr, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, b->bits); o+=4;
    put32(o, 0); o+=4;
    *o++ = (u8)b->ntx;
    for (long i=0;i<b->ntx;i++){ memcpy(o, b->tx[i].raw, b->tx[i].len); o += b->tx[i].len; }
    b->len = o - b->raw;

    u32 nonce = 0;
    while (!pow_check(b->raw)) { nonce++; put32(b->raw+76, nonce); }
    block_hash(b->hash, b->raw);
}

/* ===================== independent expected-UTXO model ================== */
typedef struct { u8 txid[32]; u32 idx; u64 val; } uo_t;
#define MODEL_CAP 512
static uo_t model[MODEL_CAP];
static int  model_n;

static void model_reset(void){ model_n = 0; }
static int  model_find(const u8 txid[32], u32 idx){
    for (int i=0;i<model_n;i++) if (model[i].idx==idx && memcmp(model[i].txid,txid,32)==0) return i;
    return -1;
}
static void model_del(const u8 txid[32], u32 idx){
    int i = model_find(txid, idx);
    if (i < 0) return;
    model[i] = model[model_n-1]; model_n--;
}
static void model_add(const u8 txid[32], u32 idx, u64 v){
    if (model_n >= MODEL_CAP) { printf("FAIL model overflow\n"); failures++; return; }
    memcpy(model[model_n].txid, txid, 32); model[model_n].idx = idx; model[model_n].val = v;
    model_n++;
}
/* Replay one block, tx order, inputs-then-outputs -- the plain textbook
 * definition, written from the builder's metadata only. */
static void model_apply(const blk_t* b){
    for (long i=0;i<b->ntx;i++){
        const tx_t* t = &b->tx[i];
        if (!t->is_coinbase) model_del(t->spend_txid, t->spend_idx);
        model_add(t->txid, 0, t->out_value);
    }
}

/* Compare the model against the live LSM, in both directions. */
static void verify_utxo_against_model(const char* label, const blk_t* losing, long nlosing){
    char buf[128];
    long live = utxo_live_count();
    snprintf(buf,sizeof buf,"%s: live UTXO count == model count", label);
    ck(buf, live, model_n);

    int missing = 0, badval = 0, badscript = 0;
    for (int i=0;i<model_n;i++){
        u64 v = 0, h = 0, cb = 0; const u8* sc = 0; unsigned long sl = 0;
        long r = utxo_lsm_get(utxo_live_lst(), utxo_live_table(), model[i].txid, model[i].idx, &v, &h, &cb, &sc, &sl);
        if (r != 1) { missing++; continue; }
        if (v != model[i].val) badval++;
        if (sl != 1 || !sc || sc[0] != 0x51) badscript++;
    }
    snprintf(buf,sizeof buf,"%s: every expected UTXO present", label);       ck(buf, missing, 0);
    snprintf(buf,sizeof buf,"%s: every expected UTXO has the right value", label); ck(buf, badval, 0);
    snprintf(buf,sizeof buf,"%s: every expected UTXO has the right script", label); ck(buf, badscript, 0);

    /* Nothing that only ever existed on the losing branch may survive. */
    int ghosts = 0;
    for (long b=0;b<nlosing;b++){
        for (long i=0;i<losing[b].ntx;i++){
            const tx_t* t = &losing[b].tx[i];
            if (model_find(t->txid, 0) >= 0) continue;   /* also on the winner */
            u64 v, h, cb; const u8* sc; unsigned long sl;
            if (utxo_lsm_get(utxo_live_lst(), utxo_live_table(), t->txid, 0, &v, &h, &cb, &sc, &sl) == 1) ghosts++;
        }
    }
    snprintf(buf,sizeof buf,"%s: no losing-branch output survives in the UTXO set", label);
    ck(buf, ghosts, 0);
}

/* ===================== store harness ==================================== */
static u8 store_buf[4096];
static u8* g_ht = 0;
#define HT_SLOTS (1u<<16)

static void rebuild_index(void){
    if (!g_ht) return;
    idx_init(g_ht, HT_SLOTS);
    idx_build_from_file(g_ht, "index.dat");
}

/* Stage D (2026-08-19): build_base's very first spend has no earlier
 * non-coinbase output in the synthetic chain to draw from, and a fresh
 * coinbase is always immature (spending block height - creation height is
 * always 1 for "spend the immediately preceding block's own coinbase",
 * which build_base does -- always < COINBASE_MATURITY regardless of the
 * chain's absolute height). Seed ONE already-live, non-coinbase, OP_TRUE-
 * spendable UTXO directly into the live LSM (bypassing block application
 * entirely, the same "seed state block application never produced" pattern
 * tests/test_undo_log.c already uses) so build_base's block-1 spend has a
 * real, maturity-EXEMPT (is_coinbase=0, so the 100-block rule never
 * applies) prevout to reference. Every later block's spend chains off the
 * PREVIOUS block's own spend output instead of a coinbase -- see build_base
 * / build_branch's own updated comments. */
static const u8 ROOT_SEED_TXID[32] = {
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
};
#define ROOT_SEED_VALUE 50000000ULL

static void harness_open(void){
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    int apfd = open("append.lock", O_RDWR|O_CREAT, 0644);
    if (apfd >= 0) *(int*)((char*)store_buf+40) = apfd;
    ck("reorg_chainwork_open", reorg_chainwork_open(store_buf), 1);
    ckm("utxo_live_init", utxo_live_init(".") == 1);
    {
        static const u8 op_true[1] = {0x51};
        long r = utxo_lsm_put(utxo_live_lst(), utxo_live_table(), ROOT_SEED_TXID, 0,
                              ROOT_SEED_VALUE, 0, 0, op_true, 1);
        ckm("seed root spendable UTXO (non-coinbase, maturity-exempt)", r == 1);
    }
    g_ht = malloc(24 + (size_t)HT_SLOTS*48 + 64);
    idx_init(g_ht, HT_SLOTS);
    reorg_set_index_rebuild(rebuild_index);
}

/* Store + chainwork + apply one block, exactly the way the live download
 * worker does it (append -> chainwork catch-up -> UTXO catch-up). */
static long harness_store(const blk_t* b){
    long h = idxscan_append_locked(store_buf, b->hash, b->raw, b->len);
    if (h < 0) return -1;
    if (reorg_chainwork_sync(store_buf, 0) < 0) return -1;
    if (utxo_live_catchup(store_buf) < 0) return -1;
    rebuild_index();
    return h;
}

/* Feed a branch's headers into a candidate exactly as a peer's `headers`
 * message would (via the REAL p2p headers payload encoding + the real
 * ingest path), rather than poking the struct directly. */
static void cand_from_blocks(reorg_cand_t* c, const blk_t* blks, long n){
    static u8 payload[1 + MAXBLK*81];
    payload[0] = (u8)n;
    for (long i=0;i<n;i++){
        memcpy(payload+1+i*81, blks[i].raw, 80);
        payload[1+i*81+80] = 0;
    }
    ck("headers ingest", reorg_headers_ingest(c, payload, 1 + n*81), n);
}

/* Block source over an in-memory branch. */
typedef struct { const blk_t* b; long n; } memsrc_t;
static long memsrc(void* ctx, long i, u8* out, uint64_t cap){
    memsrc_t* s = (memsrc_t*)ctx;
    if (i < 0 || i >= s->n) return -1;
    if ((uint64_t)s->b[i].len > cap) return -1;
    memcpy(out, s->b[i].raw, s->b[i].len);
    return s->b[i].len;
}

/* Byte-for-byte on-disk verification of the final chain. */
static void verify_ondisk_chain(const char* label, const blk_t* chain, long n){
    char buf[128];
    store_reload(store_buf);
    snprintf(buf,sizeof buf,"%s: on-disk tip height", label);
    ck(buf, (long)*(int*)(store_buf+24), n-1);

    int bad_hash = 0, bad_bytes = 0, bad_meta = 0;
    int idx_fd = *(int*)(store_buf+8);
    for (long h=0; h<n; h++){
        u8 rec[48];
        if (pread(idx_fd, rec, 48, h*48) != 48) { bad_meta++; continue; }
        if (memcmp(rec, chain[h].hash, 32) != 0) bad_hash++;
        u64 meta[3];
        if (store_get_at(store_buf, h, meta) != 1) { bad_meta++; continue; }
        if ((long)meta[1] != chain[h].len) { bad_meta++; continue; }
        char name[16]; snprintf(name,sizeof name,"blk%05u.dat",(unsigned)meta[2]);
        int bf = open(name, O_RDONLY);
        if (bf < 0) { bad_bytes++; continue; }
        static u8 rb[BLKCAP];
        if (pread(bf, rb, meta[1], meta[0]+8) != (ssize_t)meta[1]) bad_bytes++;
        else if (memcmp(rb, chain[h].raw, chain[h].len) != 0) bad_bytes++;
        close(bf);
    }
    snprintf(buf,sizeof buf,"%s: index.dat hash at every height matches the winning branch", label); ck(buf, bad_hash, 0);
    snprintf(buf,sizeof buf,"%s: block bytes at every height match the winning branch", label);      ck(buf, bad_bytes, 0);
    snprintf(buf,sizeof buf,"%s: index metadata consistent at every height", label);                 ck(buf, bad_meta, 0);

    /* No stray heights beyond the new tip. */
    struct stat sb;
    snprintf(buf,sizeof buf,"%s: index.dat length == heights*48 (nothing left above the tip)", label);
    ck(buf, stat("index.dat",&sb)==0 ? (long)sb.st_size : -1, n*48);

    /* chainwork.dat must be truncated in lockstep, and its tip must equal an
     * independently summed total over the winning branch. */
    snprintf(buf,sizeof buf,"%s: chainwork.dat length == heights*16", label);
    ck(buf, stat("chainwork.dat",&sb)==0 ? (long)sb.st_size : -1, n*16);
    u8 expect[16]; memset(expect,0,16);
    for (long h=0;h<n;h++){ u8 w[16]; u32 bits; memcpy(&bits, chain[h].raw+72, 4); block_work(w,bits); chainwork_add(expect,expect,w); }
    u8 got[16]; store_chainwork_reload(store_buf); store_chainwork_get_tip(store_buf, got);
    snprintf(buf,sizeof buf,"%s: cumulative chainwork tip == independent sum over the winning branch", label);
    ck(buf, memcmp(got,expect,16)==0, 1);

    snprintf(buf,sizeof buf,"%s: UTXO applied height == new tip", label);
    ck(buf, utxo_live_applied_height(), n-1);
}

/* ===================== case runner (fork per case) ====================== */
typedef void (*case_fn)(void);
static int run_case(const char* name, case_fn fn){
    printf("\n---- %s ----\n", name);
    fflush(stdout);
    /* Each case gets its own subdirectory of this process's private working
     * directory. The child _exit()s, so it must not own the teardown -- the
     * parent's tt_isolate() cleanup removes the whole tree. */
    static int case_no = 0;
    char sub[64]; snprintf(sub, sizeof sub, "case%02d", case_no++);
    if (mkdir(sub, 0700) != 0){ printf("FAIL %s: mkdir %s\n", name, sub); return 1; }
    pid_t p = fork();
    if (p == 0){
        if (chdir(sub) != 0){ printf("FAIL %s: tmpdir\n", name); _exit(1); }
        failures = 0;
        fn();
        fflush(stdout);
        _exit(failures > 120 ? 120 : failures);
    }
    int st = 0; waitpid(p, &st, 0);
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    printf("FAIL %s: child died (signal %d)\n", name, WTERMSIG(st));
    return 1;
}

/* ======================================================================== */
/* CASE: new chainwork primitives in isolation                              */
/* ======================================================================== */
static void case_chainwork_primitives(void){
    u8 a[16], b[16];
    memset(a,0,16); memset(b,0,16);
    ck("cmp equal zero", chainwork_cmp(a,b), 0);
    a[0] = 1;
    ck("cmp a>b on low limb", chainwork_cmp(a,b), 1);
    ck("cmp b<a on low limb", chainwork_cmp(b,a), -1);
    memset(a,0,16); memset(b,0,16);
    a[15] = 1;    /* high limb set */
    b[0]  = 0xff; b[1]=0xff; b[2]=0xff; b[3]=0xff; b[4]=0xff; b[5]=0xff; b[6]=0xff; b[7]=0xff;
    ck("cmp high limb dominates a full low limb", chainwork_cmp(a,b), 1);
    /* -1 must be a true 64-bit -1, not a zero-extended 0xFFFFFFFF */
    ckm("cmp -1 is a real long -1", chainwork_cmp(b,a) == -1L);

    u8 st[256]; memset(st,0,sizeof st);
    ck("chainwork_init", store_chainwork_init(st), 1);
    ck("reload on empty file == 0 records", store_chainwork_reload(st), 0);
    u8 tip[16]; store_chainwork_get_tip(st, tip);
    ckm("empty store tip work is zero", memcmp(tip,(u8[16]){0},16)==0);

    u32 bits[5] = {0x207fffffu,0x207fffffu,0x1f00ffffu,0x207fffffu,0x207fffffu};
    u8 running[16]; memset(running,0,16);
    for (long h=0;h<5;h++){
        u8 w[16]; block_work(w, bits[h]); chainwork_add(running,running,w);
        ck("append", store_chainwork_append(st,h,w), 1);
    }
    ck("reload sees 5 records", store_chainwork_reload(st), 5);
    store_chainwork_get_tip(st, tip);
    ckm("reload restored the tip cache exactly", memcmp(tip,running,16)==0);

    /* A fresh init on an EXISTING file zeroes the cache -- the bug reload
     * exists to close. Prove reload fixes it. */
    u8 st2[256]; memset(st2,0,sizeof st2);
    store_chainwork_init(st2);
    store_chainwork_get_tip(st2, tip);
    ckm("init alone leaves a stale-zero cache (documented)", memcmp(tip,(u8[16]){0},16)==0);
    store_chainwork_reload(st2);
    store_chainwork_get_tip(st2, tip);
    ckm("reload after init recovers the real tip work", memcmp(tip,running,16)==0);

    /* truncate */
    u8 at2[16]; store_chainwork_get_at(st, 2, at2);
    ck("truncate to 2", store_chainwork_truncate(st, 2), 1);
    struct stat sb; stat("chainwork.dat",&sb);
    ck("truncate shrank the file to 3 records", (long)sb.st_size, 3*16);
    store_chainwork_get_tip(st, tip);
    ckm("truncate refreshed the cache to record 2", memcmp(tip,at2,16)==0);
    ck("truncate above the tip is a no-op success", store_chainwork_truncate(st, 99), 1);
    stat("chainwork.dat",&sb);
    ck("no-op truncate did NOT extend the file", (long)sb.st_size, 3*16);
    ck("truncate to -1 empties", store_chainwork_truncate(st, -1), 1);
    stat("chainwork.dat",&sb);
    ck("emptied file size 0", (long)sb.st_size, 0);
    store_chainwork_get_tip(st, tip);
    ckm("emptied tip work is zero", memcmp(tip,(u8[16]){0},16)==0);

    /* ---- REGRESSION GUARD for the struct-collision bug class ----
     * Chainwork's per-process state used to live INSIDE the caller's store
     * struct: Stage A at +56/+72, Stage B first at +128/+144. Both collided
     * with bitcoin_store_fast.asm, which claims +56 (read-fd magic),
     * +64..+127 (read-fd slots), +120 (mapping magic) and +128..+255 (mapping
     * slots) of the same 256-byte struct -- i.e. there is no free hole in it
     * at all. The fix was to stop putting state there entirely, so the
     * invariant worth pinning is not "chainwork lives at offset N" but
     * "chainwork writes NOTHING into that struct". Hand it a fully poisoned
     * buffer, run the whole lifecycle, and require it to come back
     * byte-identical. This test keeps passing no matter how the store struct
     * is later rearranged, which is exactly the point. */
    {
        unsigned char probe[256], before[256];
        memset(probe, 0xAB, sizeof probe);
        memcpy(before, probe, sizeof probe);
        u8 w[16], o[16];
        block_work(w, 0x207fffffu);
        ck("poisoned-struct: init",     store_chainwork_init(probe), 1);
        ck("poisoned-struct: reload",   store_chainwork_reload(probe), 0);
        ck("poisoned-struct: append",   store_chainwork_append(probe, 0, w), 1);
        ck("poisoned-struct: get_at",   store_chainwork_get_at(probe, 0, o), 1);
        ck("poisoned-struct: get_tip",  store_chainwork_get_tip(probe, o), 1);
        ckm("poisoned-struct: get_tip returned the appended work", memcmp(o, w, 16)==0);
        ck("poisoned-struct: truncate", store_chainwork_truncate(probe, -1), 1);
        ckm("chainwork writes ZERO bytes into the store struct it is handed",
            memcmp(probe, before, sizeof probe) == 0);
    }

    /* Uninitialised state must be a hard error, never a syscall on fd 0
     * (stdin). cw_fd starts at -1 in .data precisely so this holds -- but
     * this process has already initialised, so the check that matters here is
     * the documented empty-chain contract of get_tip. */
    {
        u8 t2[16];
        ck("get_tip still returns 1 after a full truncate", store_chainwork_get_tip(st, t2), 1);
        ckm("...and reports zero work", memcmp(t2,(u8[16]){0},16)==0);
    }
}

/* ======================================================================== */
/* Shared reorg scenario builder.                                           */
/*   base[0..nbase-1]           common prefix                               */
/*   lose[0..nlose-1]           our branch above the fork                   */
/*   win [0..nwin-1]            the competing branch above the fork         */
/* ======================================================================== */
static blk_t base[MAXBLK], lose[MAXBLK], win[MAXBLK];

/* Build a common prefix of `nbase` blocks. Block 0 is coinbase-only; every
 * later block also spends a NON-coinbase output, so there is real, moving
 * UTXO state (creations AND spends) throughout WITHOUT tripping the
 * 100-block coinbase maturity rule (Stage D, 2026-08-19): block 1 spends
 * the synthetic ROOT_SEED_TXID harness_open() seeds directly (is_coinbase=0,
 * maturity-exempt); every later block spends the PRECEDING block's own
 * spend-tx output (also is_coinbase=0). A fresh coinbase spent by the very
 * next block is ALWAYS immature regardless of the chain's absolute height
 * (spending height - creation height is always 1), so this chain must never
 * spend block (h-1)'s coinbase directly. */
static void build_base(long nbase, u32 bits){
    u8 prev[32]; memset(prev,0,32);
    for (long h=0;h<nbase;h++){
        blk_t* b = &base[h];
        memset(b,0,sizeof *b);
        b->bits = bits;
        b->ntx = 1;
        mk_coinbase(&b->tx[0], 0x10000000u + (u32)h, 50000000ULL);
        if (h >= 1){
            if (h == 1) mk_spend(&b->tx[1], ROOT_SEED_TXID, 0, 49000000ULL);
            else        mk_spend(&b->tx[1], base[h-1].tx[1].txid, 0, 49000000ULL);
            b->ntx = 2;
        }
        mk_block(b, prev, 1600000000u + (u32)h);
        memcpy(prev, b->hash, 32);
    }
}

/* Build a branch of `n` blocks on top of base[nbase-1]. `tagbase` keeps the
 * two branches' coinbase txids (and therefore every derived outpoint)
 * disjoint. Each block spends the PREVIOUS block-in-this-branch's own spend
 * output (never a coinbase -- see build_base's comment on why), except the
 * first, which spends base[nbase-1]'s own spend output -- so both branches
 * contest the same pre-fork output, which is what makes the mempool and UTXO
 * outcomes interesting. Every caller passes nbase>=2, so base[nbase-1]
 * always has a tx[1] to reference. */
static void build_branch(blk_t* out, long n, long nbase, u32 tagbase, u32 bits){
    u8 prev[32]; memcpy(prev, base[nbase-1].hash, 32);
    for (long i=0;i<n;i++){
        blk_t* b = &out[i];
        memset(b,0,sizeof *b);
        b->bits = bits;
        mk_coinbase(&b->tx[0], tagbase + (u32)i, 50000000ULL);
        if (i == 0) mk_spend(&b->tx[1], base[nbase-1].tx[1].txid, 0, 48000000ULL);
        else        mk_spend(&b->tx[1], out[i-1].tx[1].txid, 0, 48000000ULL);
        b->ntx = 2;
        mk_block(b, prev, 1700000000u + tagbase + (u32)i);
        memcpy(prev, b->hash, 32);
    }
}

/* ======================================================================== */
/* CASE: chainwork catch-up over a PRUNED range.                            */
/*                                                                           */
/* A pruned height's block data is deleted by design, so its work cannot be  */
/* recomputed. Stopping the sync there would leave chainwork.dat permanently */
/* short of the tip on any pruned node -- which makes store_chainwork_get_at */
/* fail at every fork height and silently disables reorg handling forever.   */
/* Instead pruned heights record zero work and the sync continues; fork      */
/* choice is unaffected because both sides of every comparison share the     */
/* same (possibly understated) baseline at the fork point.                   */
/* ======================================================================== */
static void case_chainwork_pruned_range(void){
    const long n = 6;
    build_base(n, 0x207fffffu);

    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("chainwork_open", reorg_chainwork_open(store_buf), 1);
    for (long h=0;h<n;h++) ckm("append block", store_append(store_buf, base[h].hash, base[h].raw, base[h].len) == h);

    /* Gate heights below 3 as unavailable, exactly as a pruned store does. */
    ck("store_set_prune(3)", store_set_prune(store_buf, 3), 1);
    u64 meta[3];
    ck("height 2 now reads back as pruned", store_get_at(store_buf, 2, meta), -3);

    long added = reorg_chainwork_sync(store_buf, 0);
    ck("chainwork sync covered every height despite the pruned range", added, n);
    struct stat sb; stat("chainwork.dat", &sb);
    ck("chainwork.dat has one record per height", (long)sb.st_size, n*16);

    u8 zero[16]; memset(zero,0,16);
    u8 r0[16], r2[16], r3[16], r5[16];
    store_chainwork_get_at(store_buf, 0, r0);
    store_chainwork_get_at(store_buf, 2, r2);
    store_chainwork_get_at(store_buf, 3, r3);
    store_chainwork_get_at(store_buf, 5, r5);
    ckm("pruned heights contribute zero work", memcmp(r0, zero, 16)==0 && memcmp(r2, zero, 16)==0);
    ckm("the first readable height contributes real work", chainwork_cmp(r3, r2) > 0);
    ckm("cumulative work keeps increasing above the prune point", chainwork_cmp(r5, r3) > 0);

    /* And the cumulative DELTA above the prune point still equals an
     * independent sum -- which is the only quantity fork choice uses. */
    u8 expect[16]; memset(expect,0,16);
    for (long h=3;h<n;h++){ u8 w[16]; u32 bits; memcpy(&bits, base[h].raw+72, 4); block_work(w,bits); chainwork_add(expect,expect,w); }
    u8 delta[16];
    { unsigned long long lo5,hi5,lo2,hi2,dl,dh;
      memcpy(&lo5,r5,8); memcpy(&hi5,r5+8,8); memcpy(&lo2,r2,8); memcpy(&hi2,r2+8,8);
      dl = lo5 - lo2; dh = hi5 - hi2 - (lo5 < lo2 ? 1 : 0);
      memcpy(delta,&dl,8); memcpy(delta+8,&dh,8); }
    ckm("work delta above the prune point matches an independent sum", memcmp(delta, expect, 16)==0);
}

/* Store base + lose, i.e. bring the node to the state it is in before the
 * competing chain shows up. */
static void store_chain(long nbase, long nlose){
    for (long h=0;h<nbase;h++) ckm("store base block", harness_store(&base[h]) == h);
    for (long i=0;i<nlose;i++) ckm("store losing block", harness_store(&lose[i]) == nbase+i);
}

static int lock_is_free(void){
    pid_t p = fork();
    if (p == 0){
        int fd = open("append.lock", O_RDWR);
        if (fd < 0) _exit(2);
        int got = (flock(fd, LOCK_EX | LOCK_NB) == 0);
        _exit(got ? 0 : 1);
    }
    int st = 0; waitpid(p, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

/* Run one full reorg and verify everything. */
static void do_reorg_case(long nbase, long nlose, long nwin, u32 winbits, const char* label){
    build_base(nbase, 0x207fffffu);
    build_branch(lose, nlose, nbase, 0x20000000u, 0x207fffffu);
    build_branch(win,  nwin,  nbase, 0x30000000u, winbits);

    harness_open();
    store_chain(nbase, nlose);

    char lbuf[160];
    snprintf(lbuf,sizeof lbuf,"%s pre-reorg tip", label);
    ck(lbuf, (long)*(int*)(store_buf+24), nbase+nlose-1);

    /* snapshot pre-reorg UTXO count so we can prove it actually changed */
    long pre_count = utxo_live_count();

    static reorg_cand_t c;
    memset(&c,0,sizeof c);
    ckm("build locator", reorg_build_locator(store_buf, &c) > 0);
    cand_from_blocks(&c, win, nwin);

    long v = reorg_analyze(store_buf, &c);
    snprintf(lbuf,sizeof lbuf,"%s analyze -> fork AND heavier", label);
    ck(lbuf, v, 2);
    snprintf(lbuf,sizeof lbuf,"%s fork point located correctly", label);
    ck(lbuf, c.fork_height, nbase-1);
    snprintf(lbuf,sizeof lbuf,"%s first new header index", label);
    ck(lbuf, c.first_new, 0);

    memsrc_t src = { win, nwin };
    snprintf(lbuf,sizeof lbuf,"%s reorg_execute", label);
    ck(lbuf, reorg_execute(store_buf, c.fork_height, nwin, memsrc, &src), 1);
    /* reorg_execute holds the append lock across pre-flight + disconnect +
     * truncate + the whole reconnect loop, and must release it exactly once
     * on the way out -- a leak here would wedge every future inbound append. */
    snprintf(lbuf,sizeof lbuf,"%s released the append lock on completion", label);
    ckm(lbuf, lock_is_free());

    /* ---- independent expected UTXO: replay ONLY the winning chain ---- */
    model_reset();
    for (long h=0;h<nbase;h++) model_apply(&base[h]);
    for (long i=0;i<nwin;i++)  model_apply(&win[i]);

    static blk_t chain[MAXBLK];
    for (long h=0;h<nbase;h++) chain[h] = base[h];
    for (long i=0;i<nwin;i++)  chain[nbase+i] = win[i];

    verify_ondisk_chain(label, chain, nbase+nwin);
    verify_utxo_against_model(label, lose, nlose);

    snprintf(lbuf,sizeof lbuf,"%s UTXO set actually changed (not a no-op)", label);
    ckm(lbuf, pre_count != utxo_live_count() || nlose != nwin);

    /* the hash index must no longer resolve anything above the new tip */
    ck("rebuilt hash index height count", idx_count(g_ht), nbase+nwin);

    utxo_live_close();
}

static void case_reorg_depth1(void){ do_reorg_case(6, 1, 2, 0x207fffffu, "depth1"); }
static void case_reorg_depth3(void){ do_reorg_case(8, 3, 4, 0x207fffffu, "depth3"); }
static void case_reorg_depth12(void){ do_reorg_case(10, 12, 13, 0x207fffffu, "depth12"); }
/* Shorter branch, MORE work: 5 easy blocks lose to 1 hard one. A height-based
 * fork choice would get this backwards; a work-based one must not. */
static void case_reorg_shorter_but_heavier(void){ do_reorg_case(6, 5, 1, 0x1f00ffffu, "heavier-but-shorter"); }

/* ======================================================================== */
/* CASE: a chain that is NOT heavier must be ignored, with zero side effects */
/* ======================================================================== */
static void case_not_heavier(void){
    const long nbase = 6, nlose = 4, nwin = 2;
    build_base(nbase, 0x207fffffu);
    build_branch(lose, nlose, nbase, 0x20000000u, 0x207fffffu);
    build_branch(win,  nwin,  nbase, 0x30000000u, 0x207fffffu);

    harness_open();
    store_chain(nbase, nlose);

    long tip_before = *(int*)(store_buf+24);
    long count_before = utxo_live_count();
    u8 tiphash_before[32]; store_get_tip_hash(store_buf, tiphash_before);
    u8 work_before[16]; store_chainwork_reload(store_buf); store_chainwork_get_tip(store_buf, work_before);

    static reorg_cand_t c; memset(&c,0,sizeof c);
    reorg_build_locator(store_buf, &c);
    cand_from_blocks(&c, win, nwin);
    ck("analyze reports a fork that is NOT heavier", reorg_analyze(store_buf,&c), 1);
    ck("fork point still located correctly", c.fork_height, nbase-1);
    ckm("candidate work is genuinely lighter", chainwork_cmp(c.cand_work, c.our_work) < 0);

    store_reload(store_buf);
    u8 tiphash_after[32]; store_get_tip_hash(store_buf, tiphash_after);
    u8 work_after[16]; store_chainwork_reload(store_buf); store_chainwork_get_tip(store_buf, work_after);
    ck("tip height unchanged", (long)*(int*)(store_buf+24), tip_before);
    ckm("tip hash unchanged", memcmp(tiphash_before,tiphash_after,32)==0);
    ckm("cumulative work unchanged", memcmp(work_before,work_after,16)==0);
    ck("UTXO count unchanged", utxo_live_count(), count_before);

    /* EQUAL work must also lose (first seen wins) */
    static reorg_cand_t c2; memset(&c2,0,sizeof c2);
    reorg_build_locator(store_buf, &c2);
    cand_from_blocks(&c2, lose, nlose);   /* literally our own branch */
    ck("our own branch replayed back at us is not a fork", reorg_analyze(store_buf,&c2), 0);

    utxo_live_close();
}

/* ========================================================================
 * CASE: the nBits schedule check is actually WIRED into reorg_analyze.
 *
 * bitcoin_pow_rules.c is proven on its own (test_pow_rules) and against
 * every header of the real mainnet and testnet4 chains
 * (validation/pow_replay). Neither proves the thing that actually protects
 * this node: that ARMING the rules makes reorg_analyze reject. Enforcement
 * is injected and default-OFF so the hermetic suites can keep building
 * synthetic chains with arbitrary bits -- which means a wiring bug (setter
 * never called, height off by one, reader handing back the wrong ancestor)
 * would enforce NOTHING while every other test stayed green. That is the
 * worst failure mode consensus code has, so it gets its own case.
 *
 * run_case forks per case, so arming the global here cannot leak into any
 * other case in this binary.
 * ======================================================================== */
static void case_bad_diffbits_wired(void){
    const long nbase = 6, nwin = 2;
    build_base(nbase, 0x207fffffu);
    build_branch(win, nwin, nbase, 0x30000000u, 0x207fffffu);

    harness_open();
    store_chain(nbase, 0);

    /* regtest knobs: fPowNoRetargeting means the required bits at every
     * height are simply the parent's -- so "same bits as base" is
     * schedule-valid and any other value is bad-diffbits. */
    reorg_set_pow_rules(1 /*no_retarget*/, 0 /*min_diff*/, 0 /*bip94*/,
                        0x207fffffu);

    static reorg_cand_t c; memset(&c,0,sizeof c);
    reorg_build_locator(store_buf, &c);
    cand_from_blocks(&c, win, nwin);
    ckm("a candidate carrying the scheduled bits survives the check",
        reorg_analyze(store_buf,&c) != -1);

    /* identical shape, one bit harder than the parent: still valid PoW (the
     * nonce is ground until pow_check passes) but NOT the scheduled bits. */
    build_branch(win, nwin, nbase, 0x40000000u, 0x207ffffeu);
    static reorg_cand_t c2; memset(&c2,0,sizeof c2);
    reorg_build_locator(store_buf, &c2);
    cand_from_blocks(&c2, win, nwin);
    ck("a candidate with unscheduled nBits is REJECTED",
       reorg_analyze(store_buf,&c2), -1);

    utxo_live_close();
}

/* ======================================================================== */
/* CASE: hostile / invalid candidate chains are rejected BEFORE any damage  */
/* ======================================================================== */
static void case_invalid_candidates(void){
    const long nbase = 6, nlose = 2;
    build_base(nbase, 0x207fffffu);
    build_branch(lose, nlose, nbase, 0x20000000u, 0x207fffffu);

    harness_open();
    store_chain(nbase, nlose);

    long tip_before = *(int*)(store_buf+24);
    long count_before = utxo_live_count();
    u8 work_before[16]; store_chainwork_reload(store_buf); store_chainwork_get_tip(store_buf, work_before);

    /* (a) BAD PROOF OF WORK: a long, otherwise well-formed branch whose
     * headers do not meet their own claimed target. Would be far heavier if
     * accepted -- so this proves PoW is checked before work is even summed. */
    {
        build_branch(win, 8, nbase, 0x40000000u, 0x1f00ffffu);
        for (long i=0;i<8;i++){
            /* break the nonce so the mined hash no longer satisfies the target */
            put32(win[i].raw+76, 0xdeadbeefu);
            block_hash(win[i].hash, win[i].raw);
        }
        static reorg_cand_t c; memset(&c,0,sizeof c);
        reorg_build_locator(store_buf, &c);
        cand_from_blocks(&c, win, 8);
        ck("bad-PoW chain REJECTED", reorg_analyze(store_buf,&c), -1);
    }

    /* (b) BROKEN PREVHASH LINKAGE: individually valid headers that do not
     * form a chain. */
    {
        build_branch(win, 6, nbase, 0x50000000u, 0x207fffffu);
        /* re-point block 3's prevhash at garbage, then re-mine it so its own
         * PoW is still valid -- isolating the linkage check from the PoW one */
        u8 garbage[32]; memset(garbage, 0xAB, 32);
        memcpy(win[3].raw+4, garbage, 32);
        put32(win[3].raw+76, 0);
        { u32 n=0; while(!pow_check(win[3].raw)){ n++; put32(win[3].raw+76,n);} }
        block_hash(win[3].hash, win[3].raw);
        static reorg_cand_t c; memset(&c,0,sizeof c);
        reorg_build_locator(store_buf, &c);
        cand_from_blocks(&c, win, 6);
        ck("broken-prevhash chain REJECTED", reorg_analyze(store_buf,&c), -1);
    }

    /* (c) UNATTACHABLE: a heavy, internally consistent chain that forks off a
     * block we have never heard of. */
    {
        u8 fakeprev[32]; memset(fakeprev, 0x5C, 32);
        for (long i=0;i<4;i++){
            blk_t* b = &win[i]; memset(b,0,sizeof *b);
            b->bits = 0x1f00ffffu; b->ntx = 1;
            mk_coinbase(&b->tx[0], 0x60000000u + (u32)i, 50000000ULL);
            mk_block(b, i==0 ? fakeprev : win[i-1].hash, 1800000000u + (u32)i);
        }
        static reorg_cand_t c; memset(&c,0,sizeof c);
        reorg_build_locator(store_buf, &c);
        cand_from_blocks(&c, win, 4);
        ck("unattachable chain REJECTED", reorg_analyze(store_buf,&c), -1);
    }

    /* (d) TOO DEEP: forks below REORG_MAX_DEPTH from our tip are refused
     * outright (checked here through reorg_execute's own guard, which is the
     * last line of defence before anything destructive happens). */
    ck("reorg_execute refuses an over-deep disconnect",
       reorg_execute(store_buf, tip_before - (REORG_MAX_DEPTH+1), 1, memsrc, &(memsrc_t){win,1}), 0);
    ck("reorg_execute refuses a fork height above our tip",
       reorg_execute(store_buf, tip_before + 5, 1, memsrc, &(memsrc_t){win,1}), 0);
    ck("reorg_execute refuses an empty replacement branch",
       reorg_execute(store_buf, tip_before - 1, 0, memsrc, &(memsrc_t){win,0}), 0);

    /* NOTHING may have changed through any of the above. */
    store_reload(store_buf);
    u8 work_after[16]; store_chainwork_reload(store_buf); store_chainwork_get_tip(store_buf, work_after);
    ck("tip height untouched by every rejected candidate", (long)*(int*)(store_buf+24), tip_before);
    ck("UTXO count untouched by every rejected candidate", utxo_live_count(), count_before);
    ckm("cumulative work untouched by every rejected candidate", memcmp(work_before,work_after,16)==0);

    utxo_live_close();
}

/* ======================================================================== */
/* CASE: undo-data pre-flight refuses a disconnect it cannot complete       */
/* ======================================================================== */
static void case_undo_preflight_gate(void){
    const long nbase = 5, nlose = 3;
    build_base(nbase, 0x207fffffu);
    build_branch(lose, nlose, nbase, 0x20000000u, 0x207fffffu);
    build_branch(win,  nlose+1, nbase, 0x30000000u, 0x207fffffu);

    harness_open();
    store_chain(nbase, nlose);
    long tip_before = *(int*)(store_buf+24);
    long count_before = utxo_live_count();

    /* Delete one height's undo data, simulating it having been pruned away or
     * lost. The reorg MUST refuse rather than produce a wrong UTXO set. */
    char p[64]; snprintf(p,sizeof p,"undo_%ld.dat", tip_before-1);
    ck("undo file existed before we removed it", unlink(p), 0);

    ck("reorg_execute REFUSES when undo data is missing",
       reorg_execute(store_buf, nbase-1, nlose+1, memsrc, &(memsrc_t){win,nlose+1}), 0);
    store_reload(store_buf);
    ck("refusal left the tip untouched", (long)*(int*)(store_buf+24), tip_before);
    ck("refusal left the UTXO set untouched", utxo_live_count(), count_before);

    utxo_live_close();
}

/* ======================================================================== */
/* CASE: mempool reconciliation                                             */
/* ======================================================================== */
static void case_mempool(void){
    const long nbase = 6, nlose = 2, nwin = 3;
    build_base(nbase, 0x207fffffu);
    build_branch(lose, nlose, nbase, 0x20000000u, 0x207fffffu);
    build_branch(win,  nwin,  nbase, 0x30000000u, 0x207fffffu);

    harness_open();
    store_chain(nbase, nlose);

    /* mempool + policy */
    static u8 mp[40 + 1024*48 + 8];
    static u8 mpblob[1<<20];
    mpool_init(mp, 1024, mpblob, sizeof mpblob);
    static u8 pol[128];
    mpool_policy_init(pol, 0 /* no min-fee floor: these synthetic txs pay
                              * whatever the builder chose, and fee policy is
                              * not what this case is testing */,
                      25, 101000, 25, 101000, 1);
    /* synthetic reorg fixtures are non-standard by construction: run under
     * Core's own regtest escape hatch (-acceptnonstdtxn). */
    { extern void mpool_policy_set_acceptnonstd(void*, unsigned);
      mpool_policy_set_acceptnonstd(pol, 1); }
    unsigned pol_n = 512;
    void* pol_state = malloc(mpool_policy_state_size(pol_n));
    mpool_policy_state_init(pol_state, pol_n);

    /* SURVIVOR: spends base[nbase-2]'s COINBASE output. Every base spend-tx
     * output is consumed by the next block in the chain (Stage D,
     * 2026-08-19: blocks now chain off the PRECEDING block's own spend
     * output rather than its coinbase -- see build_base's comment), and
     * base[nbase-1]'s own spend output is the one BOTH branches deliberately
     * contest (build_branch's comment) -- so a coinbase strictly before that
     * is the only kind of output left that is genuinely untouched by base,
     * lose, AND win alike. Never mined/applied through the real
     * block-connect path here (mpool_policy_add is a separate code path
     * from tx_verify_block_connect), so its own coinbase-maturity is moot. */
    tx_t survivor; mk_spend(&survivor, base[nbase-2].tx[0].txid, 0, 40000000ULL);
    ck("survivor accepted into mempool",
       mpool_policy_add(pol, pol_state, mp, survivor.raw, survivor.len, survivor.txid, (void*)1), 1);

    /* DOOMED: spends an output created ONLY on the losing branch (its LAST
     * block's coinbase, which nothing else in that branch consumes). After
     * the reorg that output never existed, so it must be evicted. */
    tx_t doomed; mk_spend(&doomed, lose[nlose-1].tx[0].txid, 0, 40000000ULL);
    ck("doomed accepted into mempool (valid on the losing branch)",
       mpool_policy_add(pol, pol_state, mp, doomed.raw, doomed.len, doomed.txid, (void*)1), 1);

    ck("mempool holds 2 before the reorg", mpool_count(mp), 2);

    /* keep copies of the disconnected blocks for reconciliation */
    static const u8* disc[MAXBLK]; static uint32_t disclen[MAXBLK];
    for (long i=0;i<nlose;i++){ disc[i] = lose[i].raw; disclen[i] = (uint32_t)lose[i].len; }

    static reorg_cand_t c; memset(&c,0,sizeof c);
    reorg_build_locator(store_buf, &c);
    cand_from_blocks(&c, win, nwin);
    ck("mempool case analyze", reorg_analyze(store_buf,&c), 2);
    memsrc_t src = { win, nwin };
    ck("mempool case reorg_execute", reorg_execute(store_buf, c.fork_height, nwin, memsrc, &src), 1);

    reorg_mempool_t rm = { mp, pol, pol_state, pol_n, (void*)1 };
    /* Disconnected blocks are offered oldest-first. */
    long after = reorg_mempool_reconcile(&rm, disc, disclen, nlose);
    ckm("reconcile returned a count", after >= 0);

    unsigned long l;
    ckm("survivor (still valid on the winning branch) is STILL in the mempool",
        mpool_get(mp, survivor.txid, &l) != NULL);
    ckm("doomed (spends a losing-branch-only output) was EVICTED",
        mpool_get(mp, doomed.txid, &l) == NULL);

    /* The losing branch's own spend transaction spent base[nbase-1]'s
     * coinbase -- but so does the winning branch's first block, so that
     * output is spent again on the winner and the disconnected transaction
     * must NOT come back. */
    ckm("a disconnected tx whose input the winner also spent does NOT re-enter",
        mpool_get(mp, lose[0].tx[1].txid, &l) == NULL);
    /* The losing branch's LATER spend spent lose[0]'s coinbase, an output
     * that no longer exists at all -- also must not come back. */
    if (nlose > 1)
        ckm("a disconnected tx spending a vanished output does NOT re-enter",
            mpool_get(mp, lose[1].tx[1].txid, &l) == NULL);
    /* No coinbase may ever enter a mempool. */
    ckm("no disconnected coinbase entered the mempool",
        mpool_get(mp, lose[0].tx[0].txid, &l) == NULL);

    /* Now the positive re-entry case: a transaction that was confirmed only
     * on the losing branch and whose input SURVIVES on the winner must come
     * back. base[nbase-1]'s COINBASE output is untouched by both branches
     * (Stage D, 2026-08-19: branches now chain off base[nbase-1]'s spend
     * output, not its coinbase -- see build_branch's comment; distinct from
     * `survivor`'s own target above so the two don't both reference the
     * same outpoint), so a disconnected block containing a spend of it
     * should be reinjected. Never actually mined/applied through the real
     * block-connect path here, so its own coinbase-maturity is moot -- this
     * is purely exercising reorg_mempool_reconcile. */
    {
        static blk_t extra; memset(&extra,0,sizeof extra);
        extra.bits = 0x207fffffu; extra.ntx = 2;
        mk_coinbase(&extra.tx[0], 0x70000000u, 50000000ULL);
        mk_spend(&extra.tx[1], base[nbase-1].tx[0].txid, 0, 30000000ULL);
        mk_block(&extra, base[nbase-1].hash, 1900000000u);

        const u8* d2[1] = { extra.raw }; uint32_t l2[1] = { (uint32_t)extra.len };
        reorg_mempool_reconcile(&rm, d2, l2, 1);
        ckm("a still-spendable tx from a disconnected block IS reinjected",
            mpool_get(mp, extra.tx[1].txid, &l) != NULL);
        ckm("survivor survived the second reconcile too",
            mpool_get(mp, survivor.txid, &l) != NULL);
    }

    utxo_live_close();
}

/* ======================================================================== */
/* CASE (MEM-8): the reconcile snapshot is sized from the POOL, so a pool     */
/*       larger than the old fixed bound leaves no ghosts.                   */
/*                                                                          */
/* reorg_mempool_reconcile snapshotted at most REORG_MEMPOOL_MAX_TX (8,192)  */
/* entries into a fixed 16 MB arena, and called mpool_del only for the       */
/* snapshotted prefix. Everything past the bound stayed in the structural    */
/* pool while mpool_policy_state_init wiped the graph out from under it:     */
/* present to getdata and to mpool_count, but with no registry node, no      */
/* outreg and no claims. Such an entry never expires (mempool_forget is only */
/* reached through the registry), never evicts, and leaves its inputs        */
/* unclaimed -- so a later double-spend of those inputs is admitted next to  */
/* it.                                                                      */
/*                                                                          */
/* The fixture puts 8,193 transactions straight into the STRUCTURAL pool     */
/* with mpool_put -- which is where ghosts live, and which is fast, unlike   */
/* driving 8,193 accepts through the policy layer. None of them resolves     */
/* against the UTXO set, so every candidate is refused on re-offer and a     */
/* correct reconcile must leave the pool EMPTY. The old code left exactly    */
/* the entries it never snapshotted.                                        */
/* ======================================================================== */
static void case_mempool_ghosts(void){
    enum { NGHOST = 8193 };          /* one past the old REORG_MEMPOOL_MAX_TX */
    /* The re-offer pass runs the real mpool_policy_add, which resolves inputs
     * through the live UTXO store -- so that store has to be open even though
     * every lookup here is expected to miss. */
    build_base(3, 0x207fffffu);
    harness_open();
    static u8 mp[40 + 16384*48 + 8];
    static u8* mpblob;
    if (!mpblob) mpblob = (u8*)malloc(32u<<20);
    ckm("ghost fixture blob allocated", mpblob != NULL);
    if (!mpblob) return;
    mpool_init(mp, 16384, mpblob, 32u<<20);

    static u8 pol[128];
    mpool_policy_init(pol, 0, 25, 101000, 25, 101000, 1);
    { extern void mpool_policy_set_acceptnonstd(void*, unsigned);
      mpool_policy_set_acceptnonstd(pol, 1); }
    unsigned pol_n = 512;
    void* pol_state = malloc(mpool_policy_state_size(pol_n));
    mpool_policy_state_init(pol_state, pol_n);

    long stored = 0;
    for (int i = 0; i < NGHOST; i++){
        tx_t t; u8 prev[32];
        memset(prev, 0, 32);
        prev[0] = (u8)i; prev[1] = (u8)(i >> 8); prev[2] = 0xc7;
        mk_spend(&t, prev, 0, 10000ULL);
        if (mpool_put(mp, t.txid, t.raw, (unsigned long)t.len) == 1) stored++;
    }
    ck("MEM-8 fixture: pool holds more than the old 8192-entry bound", (int)(stored > 8192), 1);

    reorg_mempool_t rm = { mp, pol, pol_state, pol_n, (void*)1 };
    long after = reorg_mempool_reconcile(&rm, NULL, NULL, 0);
    long left = mpool_count(mp);
    printf("      (stored %ld, reconcile returned %ld, pool now %ld)\n", stored, after, left);
    ckm("MEM-8 reconcile returned a count", after >= 0);
    /* None of these transactions can resolve its input, so every one must be
     * refused on re-offer and NOTHING may remain. */
    ck("MEM-8 no entry survives the rebuild unsnapshotted (no ghosts)", (int)left, 0);
    ck("MEM-8 ...and the returned count agrees with the pool", (int)after, (int)left);
    free(pol_state);
    utxo_live_close();
}

/* ======================================================================== */
/* CASE (STO-7): reorg_execute reconciles the mempool BY ITSELF once one is  */
/*       registered -- no manual reorg_mempool_reconcile call.               */
/*                                                                          */
/* case_mempool above proves the reconcile function is correct. This proves  */
/* it is actually REACHED, which is the whole of STO-7: the function was     */
/* implemented and tested but had no caller outside the test suite, so a     */
/* real reorg left the pool holding transactions the new branch had          */
/* invalidated. It also proves reorg_execute captured the disconnected       */
/* blocks itself -- nothing here hands it the losing branch's bytes, and     */
/* archive_truncate_safe has unlinked them by the time reconciliation runs.  */
/* ======================================================================== */
static void case_mempool_wired(void){
    const long nbase = 6, nlose = 2, nwin = 3;
    build_base(nbase, 0x207fffffu);
    build_branch(lose, nlose, nbase, 0x20000000u, 0x207fffffu);
    build_branch(win,  nwin,  nbase, 0x30000000u, 0x207fffffu);

    harness_open();
    store_chain(nbase, nlose);

    static u8 mp[40 + 1024*48 + 8];
    static u8 mpblob[1<<20];
    mpool_init(mp, 1024, mpblob, sizeof mpblob);
    static u8 pol[128];
    mpool_policy_init(pol, 0, 25, 101000, 25, 101000, 1);
    { extern void mpool_policy_set_acceptnonstd(void*, unsigned);
      mpool_policy_set_acceptnonstd(pol, 1); }
    unsigned pol_n = 512;
    void* pol_state = malloc(mpool_policy_state_size(pol_n));
    mpool_policy_state_init(pol_state, pol_n);

    /* Same two fixtures as case_mempool: one that survives the reorg, one
     * that spends an output only the losing branch ever created. */
    tx_t survivor; mk_spend(&survivor, base[nbase-2].tx[0].txid, 0, 40000000ULL);
    ck("wired: survivor accepted into mempool",
       mpool_policy_add(pol, pol_state, mp, survivor.raw, survivor.len, survivor.txid, (void*)1), 1);
    tx_t doomed; mk_spend(&doomed, lose[nlose-1].tx[0].txid, 0, 40000000ULL);
    ck("wired: doomed accepted into mempool",
       mpool_policy_add(pol, pol_state, mp, doomed.raw, doomed.len, doomed.txid, (void*)1), 1);
    ck("wired: mempool holds 2 before the reorg", mpool_count(mp), 2);

    /* THE WIRING UNDER TEST. Nothing below passes disconnected blocks. */
    reorg_mempool_t rm = { mp, pol, pol_state, pol_n, (void*)1 };
    reorg_set_mempool(&rm);

    static reorg_cand_t c; memset(&c,0,sizeof c);
    reorg_build_locator(store_buf, &c);
    cand_from_blocks(&c, win, nwin);
    ck("wired: analyze", reorg_analyze(store_buf,&c), 2);
    memsrc_t src = { win, nwin };
    ck("wired: reorg_execute", reorg_execute(store_buf, c.fork_height, nwin, memsrc, &src), 1);

    unsigned long l;
    ckm("wired: reorg_execute EVICTED the losing-branch-only tx with no manual reconcile",
        mpool_get(mp, doomed.txid, &l) == NULL);
    ckm("wired: reorg_execute KEPT the still-valid tx",
        mpool_get(mp, survivor.txid, &l) != NULL);
    /* The losing branch's own spend txs were captured by reorg_execute and
     * offered back; both spend outputs the winner also spent or vanished, so
     * neither may re-enter. If the capture had been skipped entirely these
     * would also be absent -- which is why the eviction assertion above, not
     * these, is what proves the wiring. */
    ckm("wired: no disconnected coinbase entered the mempool",
        mpool_get(mp, lose[0].tx[0].txid, &l) == NULL);

    /* Second half of STO-7: the daemon reads this to rewind its new-block
     * choke-point baseline, so replacement blocks at or below the old tip
     * still reach tx_accept_block_connect_h. */
    ck("wired: reorg_last_fork_height reports the fork", (int)reorg_last_fork_height(), (int)c.fork_height);

    reorg_set_mempool(NULL);   /* leave the later cases unarmed */
    utxo_live_close();
}

/* ======================================================================== */
/* CASE: fake peer -- the real multi-hash locator finds the true common      */
/*       ancestor where the old single-hash locator could not.               */
/* ======================================================================== */
static long g_peer_nbase, g_peer_nwin;

/* A peer holding base[0..nbase-1] + win[0..nwin-1]. Answers getheaders by
 * Bitcoin Core's actual rule: find the FIRST locator hash it knows, reply
 * with the headers that follow it; if it recognises none, reply from its own
 * genesis. Answers getdata(MSG_BLOCK) with the matching block. */
static void fake_peer(int cfd){
    static u8 buf[1<<20];
    char cmd[12]; unsigned plen = 0;
    for (int iter=0; iter<512; iter++){
        int r = p2p_read(cfd, cmd, buf, sizeof buf, &plen);
        if (r <= 0 && r != -1) return;
        if (r == -1) continue;
        if (strncmp(cmd,"getheaders",10)==0){
            unsigned cnt = buf[4];
            long start = 0;   /* index into the peer's own chain of the first header to send */
            int found = 0;
            for (unsigned i=0;i<cnt && !found;i++){
                const u8* h = buf + 5 + i*32;
                for (long k=0;k<g_peer_nbase;k++)
                    if (memcmp(h, base[k].hash, 32)==0){ start = k+1; found = 1; break; }
                if (found) break;
                for (long k=0;k<g_peer_nwin;k++)
                    if (memcmp(h, win[k].hash, 32)==0){ start = g_peer_nbase+k+1; found = 1; break; }
            }
            long total = g_peer_nbase + g_peer_nwin;
            long n = total - start;
            if (n < 0) n = 0;
            if (n > 200) n = 200;
            static u8 out[1 + 256*81];
            out[0] = (u8)n;
            for (long i=0;i<n;i++){
                long gi = start + i;
                const blk_t* b = (gi < g_peer_nbase) ? &base[gi] : &win[gi-g_peer_nbase];
                memcpy(out+1+i*81, b->raw, 80);
                out[1+i*81+80] = 0;
            }
            p2p_write(cfd, "headers", 7, out, (unsigned)(1 + n*81));
        } else if (strncmp(cmd,"getdata",7)==0){
            const u8* h = buf + 5;
            const blk_t* found = 0;
            for (long k=0;k<g_peer_nbase && !found;k++) if (memcmp(h, base[k].hash,32)==0) found=&base[k];
            for (long k=0;k<g_peer_nwin  && !found;k++) if (memcmp(h, win[k].hash,32)==0)  found=&win[k];
            if (found) p2p_write(cfd, "block", 5, found->raw, (unsigned)found->len);
        } else if (strncmp(cmd,"ping",4)==0){
            p2p_write(cfd, "pong", 4, buf, 8);
        }
    }
}

static void case_fakepeer_locator_and_reorg(void){
    const long nbase = 12, nlose = 3, nwin = 5;
    build_base(nbase, 0x207fffffu);
    build_branch(lose, nlose, nbase, 0x20000000u, 0x207fffffu);
    build_branch(win,  nwin,  nbase, 0x30000000u, 0x207fffffu);
    g_peer_nbase = nbase; g_peer_nwin = nwin;

    harness_open();
    store_chain(nbase, nlose);

    /* ---- listen + fork the peer ---- */
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls,(struct sockaddr*)&a,sizeof a)!=0){ printf("FAIL bind\n"); failures++; return; }
    socklen_t al = sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls, 4);

    pid_t pid = fork();
    if (pid == 0){
        for (int i=0;i<2;i++){ int c = accept(ls,0,0); if (c>=0){ fake_peer(c); close(c);} }
        _exit(0);
    }

    /* ---------- part 1: the locator regression the old code would fail ----
     * Ask the SAME peer with a single-hash locator (what the pre-Stage-B sync
     * loop sent) and with the real multi-hash one, and compare what comes
     * back. With one hash -- our tip, which is on the losing branch -- the
     * peer recognises nothing and answers from its own genesis, which does
     * not attach to us at all. With the doubling-gap locator it recognises a
     * shared ancestor and answers from there. */
    {
        int fd = socket(AF_INET,SOCK_STREAM,0);
        struct timeval tv = {2,0};
        setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
        ckm("connect to fake peer (single-hash locator probe)", connect(fd,(struct sockaddr*)&a,sizeof a)==0);

        u8 tip[32]; store_get_tip_hash(store_buf, tip);
        u8 gh[128], stop[32]; memset(stop,0,32);
        long gl = p2p_getheaders(gh, tip, 1, stop);
        ck("single-hash getheaders payload length", gl, 69);
        p2p_write(fd,"getheaders",10,gh,(unsigned)gl);
        static u8 rb[1<<20]; char cmd[12]; unsigned plen=0;
        int got = 0;
        for (int i=0;i<8;i++){ int r=p2p_read(fd,cmd,rb,sizeof rb,&plen); if(r==-1) continue; if(r<=0) break; if(strncmp(cmd,"headers",7)==0){got=1;break;} }
        ck("peer answered the single-hash locator", got, 1);
        long hc = p2p_headers_count(rb, plen);
        ckm("single-hash locator got headers", hc > 0);
        /* first header's prevhash is the peer's genesis prev (all zeros) --
         * i.e. the reply does NOT start at our common ancestor */
        u8 zero[32]; memset(zero,0,32);
        ckm("single-hash locator reply starts at the peer's GENESIS, not our common ancestor",
            memcmp(rb + 1 + 4, zero, 32) == 0);
        close(fd);
    }

    /* ---------- part 2: the real thing, end to end over the socket ------- */
    {
        int fd = socket(AF_INET,SOCK_STREAM,0);
        struct timeval tv = {5,0};
        setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
        ckm("connect to fake peer (real probe)", connect(fd,(struct sockaddr*)&a,sizeof a)==0);

        /* prove the locator we are about to send really does contain the
         * common ancestor the peer will recognise */
        static reorg_cand_t probe; memset(&probe,0,sizeof probe);
        long ln = reorg_build_locator(store_buf, &probe);
        ckm("multi-hash locator has more than one entry", ln > 1);
        int has_common = 0;
        for (long i=0;i<ln;i++)
            for (long k=0;k<nbase;k++)
                if (memcmp(probe.loc[i], base[k].hash, 32)==0) has_common = 1;
        ck("multi-hash locator contains a block the peer also has", has_common, 1);

        long r = reorg_probe_peer(fd, store_buf, "fakepeer");
        ck("reorg_probe_peer completed a reorg over the wire", r, 1);
        close(fd);
    }

    /* ---------- verify the outcome ---------- */
    model_reset();
    for (long h=0;h<nbase;h++) model_apply(&base[h]);
    for (long i=0;i<nwin;i++)  model_apply(&win[i]);

    static blk_t chain[MAXBLK];
    for (long h=0;h<nbase;h++) chain[h] = base[h];
    for (long i=0;i<nwin;i++)  chain[nbase+i] = win[i];
    verify_ondisk_chain("fakepeer", chain, nbase+nwin);
    verify_utxo_against_model("fakepeer", lose, nlose);

    kill(pid, SIGKILL); waitpid(pid,0,0); close(ls);
    utxo_live_close();
}

/* ======================================================================== */
/* CASE: append-lock scope, and the inbound prevhash gate's predicate.       */
/*                                                                           */
/* A reorg has to exclude the OTHER writer into this archive (an inbound      */
/* serve child's .do_block) for its ENTIRE window, not just the disconnect.   */
/* The bug: idxscan_append_locked delegates to store_append_shared, which     */
/* unconditionally LOCK_UNs on the way out -- so a reorg holding the lock     */
/* externally had it silently dropped by its own FIRST reconnected block,     */
/* leaving every later append (and the gaps between them) unprotected.        */
/* idxscan_append_nolocked is the same append with that pair removed.         */
/*                                                                           */
/* flock is per-OPEN-FILE-DESCRIPTION, so "is the lock held?" is probed from  */
/* a forked child that open()s append.lock FRESH -- an inherited descriptor   */
/* would see our own lock as its own and always succeed.                      */
/* ======================================================================== */
static void case_append_lock_scope(void){
    const long nbase = 4;
    build_base(nbase, 0x207fffffu);
    harness_open();
    for (long h=0;h<nbase;h++) ckm("store base block", harness_store(&base[h]) == h);

    int lfd = *(int*)((char*)store_buf+40);
    ckm("append.lock fd is configured on the store", lfd > 0);
    ckm("lock is free before we take it", lock_is_free());

    /* Two further blocks that legitimately extend the chain. */
    static blk_t nxt[2];
    { u8 prev[32]; memcpy(prev, base[nbase-1].hash, 32);
      for (int i=0;i<2;i++){
        memset(&nxt[i],0,sizeof nxt[i]);
        nxt[i].bits = 0x207fffffu; nxt[i].ntx = 1;
        mk_coinbase(&nxt[i].tx[0], 0x90000000u + (u32)i, 50000000ULL);
        mk_block(&nxt[i], prev, 1950000000u + (u32)i);
        memcpy(prev, nxt[i].hash, 32);
      } }

    /* ---- the NOLOCK variant must leave our outer hold intact ---- */
    ck("take the append lock ourselves", flock(lfd, LOCK_EX), 0);
    ckm("lock reads as held once we take it", !lock_is_free());
    long h4 = idxscan_append_nolocked(store_buf, nxt[0].hash, nxt[0].raw, nxt[0].len);
    ck("idxscan_append_nolocked appended at the right height", h4, nbase);
    ckm("OUR LOCK IS STILL HELD after idxscan_append_nolocked", !lock_is_free());
    ck("nolocked append updated the cached tip", (long)*(int*)(store_buf+24), nbase);
    ck("release", flock(lfd, LOCK_UN), 0);
    ckm("lock is free once we release it", lock_is_free());

    /* ---- and the ordinary variant stays self-contained (takes AND drops) --
     * i.e. exactly the behaviour that made it unusable inside a reorg. */
    long h5 = idxscan_append_locked(store_buf, nxt[1].hash, nxt[1].raw, nxt[1].len);
    ck("idxscan_append_locked appended at the right height", h5, nbase+1);
    ckm("idxscan_append_locked left the lock free (it releases its own)", lock_is_free());

    /* both blocks must be genuinely on disk and readable */
    store_reload(store_buf);
    ck("tip after both appends", (long)*(int*)(store_buf+24), nbase+1);
    int bad = 0, idx_fd = *(int*)(store_buf+8);
    for (int i=0;i<2;i++){
        u8 rec[32];
        if (pread(idx_fd, rec, 32, (nbase+i)*48) != 32 || memcmp(rec, nxt[i].hash, 32) != 0) bad++;
    }
    ck("both appended blocks are indexed correctly", bad, 0);

    /* ---- the predicate bitcoin_serve.asm's .do_block now gates on ----
     * The branch itself lives in assembly and is covered end-to-end by
     * tests/test_keepup.c (which pushes a real chaining block through
     * .do_block and requires it to be stored and served back); what is pinned
     * here is the accept/reject decision on the exact inputs that path feeds
     * it -- a raw 80-byte header at the start of the block buffer. */
    {
        static blk_t good, bad_chain;
        memset(&good,0,sizeof good);
        good.bits = 0x207fffffu; good.ntx = 1;
        mk_coinbase(&good.tx[0], 0x91000000u, 50000000ULL);
        mk_block(&good, nxt[1].hash, 1960000000u);
        ck("prevhash gate ACCEPTS a block that extends our tip",
           store_validates_prevhash(store_buf, good.raw), 1);

        memset(&bad_chain,0,sizeof bad_chain);
        bad_chain.bits = 0x207fffffu; bad_chain.ntx = 1;
        mk_coinbase(&bad_chain.tx[0], 0x92000000u, 50000000ULL);
        mk_block(&bad_chain, base[0].hash, 1960000001u);   /* forks way back */
        ck("prevhash gate REJECTS a block from a competing branch",
           store_validates_prevhash(store_buf, bad_chain.raw), 0);

        u8 bogus[32]; memset(bogus, 0x77, 32);
        static blk_t orphan;
        memset(&orphan,0,sizeof orphan);
        orphan.bits = 0x207fffffu; orphan.ntx = 1;
        mk_coinbase(&orphan.tx[0], 0x93000000u, 50000000ULL);
        mk_block(&orphan, bogus, 1960000002u);
        ck("prevhash gate REJECTS a block chaining to nothing we have",
           store_validates_prevhash(store_buf, orphan.raw), 0);
    }

    utxo_live_close();
}

/* ======================================================================== */
/* CASE: node_sync_multi -- the assembly sync loop driven with a REAL          */
/*       multi-hash locator.                                                   */
/*                                                                             */
/* This is the highest-risk change in the stage: node_sync's getheaders payload */
/* used to be built at rbp-0x140 with exactly 69 bytes of clearance -- the size */
/* of a ONE-hash message and not a byte more. A 32-hash locator serialises to   */
/* 1061 bytes, which from that offset would have run 741 bytes PAST rbp,        */
/* through the whole callee-saved save area and the return address. The payload */
/* buffer and the new loc_count local were moved into the frame's deep unused   */
/* tail; this case proves the relocated frame is sound by running the real      */
/* assembly against a real socket with a real multi-entry locator, storing real */
/* blocks, and returning cleanly (a corrupted save area shows up as a crash or  */
/* garbage in the caller's registers the moment node_sync_multi returns).       */
/* ======================================================================== */
static void case_node_sync_multi(void){
    /* p2p_getheaders' own bound first: the frame arithmetic above assumes a
     * 32-hash payload is exactly 1061 bytes. */
    {
        static u8 loc32[32*32]; memset(loc32, 0xA5, sizeof loc32);
        static u8 gh[5 + 32*32 + 32 + 64]; u8 stop[32]; memset(stop,0,32);
        memset(gh, 0xEE, sizeof gh);
        long gl = p2p_getheaders(gh, loc32, 32, stop);
        ck("p2p_getheaders(count=32) payload length", gl, 5 + 32*32 + 32);
        ck("p2p_getheaders wrote the count varint", gh[4], 32);
        ck("p2p_getheaders did not write past the payload", gh[gl], 0xEE);
        ck("p2p_getheaders(count=1) still 69 bytes (byte-compatible)", p2p_getheaders(gh, loc32, 1, stop), 69);
        ck("p2p_getheaders(count=0) rejected", p2p_getheaders(gh, loc32, 0, stop), -1);
        ck("p2p_getheaders(count=253) rejected", p2p_getheaders(gh, loc32, 253, stop), -1);
    }

    const long nbase = 9, nwin = 4;
    build_base(nbase, 0x207fffffu);
    build_branch(win, nwin, nbase, 0x30000000u, 0x207fffffu);
    g_peer_nbase = nbase; g_peer_nwin = nwin;

    harness_open();
    for (long h=0;h<nbase;h++) ckm("store base block", harness_store(&base[h]) == h);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls,(struct sockaddr*)&a,sizeof a)!=0){ printf("FAIL bind\n"); failures++; return; }
    socklen_t al = sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
    listen(ls, 4);
    pid_t pid = fork();
    if (pid == 0){ int c = accept(ls,0,0); if (c>=0){ fake_peer(c); close(c);} _exit(0); }

    int fd = socket(AF_INET,SOCK_STREAM,0);
    struct timeval tv = {3,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    ckm("connect to fake peer", connect(fd,(struct sockaddr*)&a,sizeof a)==0);

    static u8 loc[REORG_LOCATOR_MAX*32];
    long nloc = locator_build(store_buf, loc);
    ckm("locator_build produced a multi-entry locator", nloc > 1);

    /* Drive the WORST CASE deliberately: a full 32-entry locator, which is
     * the 1061-byte payload the relocated frame was sized for. The real
     * locator is only ~5 entries on a 9-block chain, so the natural call
     * would never write anywhere near the end of that buffer -- and the bug
     * this guards against is precisely a write past its end. Padding the
     * unused slots with the oldest ancestor hash is behaviourally
     * transparent: the peer still matches entry 0 (our tip) first. */
    for (long i = nloc; i < REORG_LOCATOR_MAX; i++)
        memcpy(loc + i*32, loc + (nloc-1)*32, 32);
    nloc = REORG_LOCATOR_MAX;

    /* Sentinel values in the callee-saved registers node_sync_multi's frame
     * would trash if the payload buffer overran its save area. */
    register long s_rbx asm("rbx") = 0x1111111111111111L;
    register long s_r12 asm("r12") = 0x2222222222222222L;
    register long s_r13 asm("r13") = 0x3333333333333333L;
    register long s_r14 asm("r14") = 0x4444444444444444L;
    register long s_r15 asm("r15") = 0x5555555555555555L;
    asm volatile("" : "+r"(s_rbx), "+r"(s_r12), "+r"(s_r13), "+r"(s_r14), "+r"(s_r15));

    static u8 cbuf[4<<20];
    long cnt = 0;
    long ok = node_sync_multi(fd, store_buf, loc, nloc, cbuf, (long)sizeof cbuf, &cnt);

    asm volatile("" : "+r"(s_rbx), "+r"(s_r12), "+r"(s_r13), "+r"(s_r14), "+r"(s_r15));
    ckm("node_sync_multi preserved rbx", s_rbx == 0x1111111111111111L);
    ckm("node_sync_multi preserved r12", s_r12 == 0x2222222222222222L);
    ckm("node_sync_multi preserved r13", s_r13 == 0x3333333333333333L);
    ckm("node_sync_multi preserved r14", s_r14 == 0x4444444444444444L);
    ckm("node_sync_multi preserved r15", s_r15 == 0x5555555555555555L);

    ck("node_sync_multi returned ok", ok, 1);
    ck("node_sync_multi stored the whole extension", cnt, nwin);
    store_reload(store_buf);
    ck("tip advanced to the peer's tip", (long)*(int*)(store_buf+24), nbase+nwin-1);

    int badhash = 0;
    int idx_fd = *(int*)(store_buf+8);
    for (long i=0;i<nwin;i++){
        u8 rec[32];
        if (pread(idx_fd, rec, 32, (nbase+i)*48) != 32 || memcmp(rec, win[i].hash, 32) != 0) badhash++;
    }
    ck("every block node_sync_multi stored is the right one", badhash, 0);

    /* loc_count is clamped to [1,32] inside node_sync_multi, because the
     * payload buffer is sized for exactly 32 hashes while p2p_getheaders
     * itself would happily serialise up to 252. An out-of-range count must
     * therefore be absorbed, never forwarded. */
    {
        long c3 = 0;
        ck("node_sync_multi clamps an over-large loc_count instead of overflowing",
           node_sync_multi(fd, store_buf, loc, 9999, cbuf, (long)sizeof cbuf, &c3), 1);
        long c4 = 0;
        ck("node_sync_multi clamps a zero/negative loc_count",
           node_sync_multi(fd, store_buf, loc, 0, cbuf, (long)sizeof cbuf, &c4), 1);
    }

    /* The 6-argument node_sync shim must still behave identically (nothing to
     * fetch now, so it just has to complete cleanly). */
    u8 tiph[32]; store_get_tip_hash(store_buf, tiph);
    long cnt2 = 0;
    ck("node_sync 6-arg shim still returns ok", node_sync(fd, store_buf, tiph, cbuf, (long)sizeof cbuf, &cnt2), 1);
    ck("node_sync 6-arg shim stored nothing new", cnt2, 0);

    close(fd);
    kill(pid, SIGKILL); waitpid(pid,0,0); close(ls);
    utxo_live_close();
}

/* ======================================================================== */
int main(void){
    tt_isolate();
    int total = 0;
    total += run_case("chainwork primitives",           case_chainwork_primitives);
    total += run_case("chainwork over a pruned range",  case_chainwork_pruned_range);
    total += run_case("reorg depth 1",                  case_reorg_depth1);
    total += run_case("reorg depth 3",                  case_reorg_depth3);
    total += run_case("reorg depth 12 (undo window)",   case_reorg_depth12);
    total += run_case("reorg shorter-but-heavier",      case_reorg_shorter_but_heavier);
    total += run_case("competing chain not heavier",    case_not_heavier);
    total += run_case("invalid candidate chains",       case_invalid_candidates);
    total += run_case("nBits schedule wired into analyze", case_bad_diffbits_wired);
    total += run_case("undo pre-flight gate",           case_undo_preflight_gate);
    total += run_case("mempool reconciliation",         case_mempool);
    total += run_case("mempool reconcile is WIRED (STO-7)", case_mempool_wired);
    total += run_case("reconcile leaves no ghosts (MEM-8)", case_mempool_ghosts);
    total += run_case("fake peer locator + reorg",      case_fakepeer_locator_and_reorg);
    total += run_case("node_sync_multi (asm frame)",    case_node_sync_multi);
    total += run_case("append-lock scope + prevhash gate", case_append_lock_scope);

    printf("\n%s (%d failures)\n", total ? "TESTS FAILED" : "ALL TESTS PASSED", total);
    return total ? 1 : 0;
}
