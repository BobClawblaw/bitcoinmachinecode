/* daemon/utxo_setinfo_rpc.c -- `gettxoutsetinfo` as an RPC, over the SAME
 * machinery as the standalone verification tool.
 *
 * The tool (daemon/utxo_setinfo.c) is the measuring instrument for the UTXO
 * parity capstone, so this file deliberately does NOT touch or refactor it:
 * it #includes the tool's translation unit (main renamed away, the
 * test_dial_budget.c pattern), inheriting its fingerprint/quiescence
 * discipline, its applied-height reading and its memtable sizing VERBATIM --
 * zero drift between what the tool measures and what the RPC reports. After
 * the capstone, the two are also each other's cross-check: two readers, one
 * discipline, one answer.
 *
 * Differences from the tool, all forced by living inside a daemon:
 *   - fills a struct instead of printing;
 *   - REFUSES (returns 0, "busy") instead of exiting when the datadir is
 *     being written -- the caller retries in the quiet window between
 *     blocks; there is no --force here, an RPC must never hand out a number
 *     computed over a moving datadir;
 *   - munmaps everything it mapped: the tool's process exits, this one
 *     serves the next request.
 */
#define main usi_tool_main          /* keep the tool's main() out of the link */
#include "utxo_setinfo.c"
#undef main

typedef struct {
    long height;
    unsigned long long txouts, bogosize, total_amount;
    unsigned char muhash[32];
    int muhash_valid;
} usi_rpc_out_t;

/* 1 ok / 0 busy-or-inconsistent (msg says why) / -1 hard error (msg set).
 * Runs in the RPC thread of the serve parent; the datadir is the process
 * cwd, same as every other reader here. */
long utxo_setinfo_rpc_run(int want_muhash, usi_rpc_out_t* out,
                          char* msg, unsigned long mcap){
#define MSG(...) do{ if (msg && mcap) snprintf(msg, mcap, __VA_ARGS__); }while(0)
    if (msg && mcap) msg[0] = 0;

    fingerprint fp0, fp1, fp2;
    char why[512] = "";
    if (!fingerprint_take(&fp0)){ MSG("fingerprint failed"); return -1; }
    sleep_ms(1500);
    if (!fingerprint_take(&fp1)){ MSG("fingerprint failed"); return -1; }
    if (fingerprint_diff(&fp0, &fp1, why, sizeof why)){
        MSG("UTXO set is being written (%s) -- retry between blocks", why);
        return 0;
    }

    long height = read_applied_height();
    if (height < 0){ MSG("no readable utxo_applied_height.dat"); return -1; }

    /* memtable geometry from the datadir itself, exactly as the tool sizes
     * it (utxo_setinfo.c's own comment explains why the files' sizes are
     * the authority). */
    unsigned long slots;
    { u64 tsz = file_size_or("utxo_lsm_table.map", 0);
      slots = tsz > 48 ? (unsigned long)((tsz - 48) / 48) : (1UL << 22);
      if (slots < (1UL << 20)) slots = 1UL << 20; }
    u64 blob_cap = file_size_or("utxo_lsm_blob.map", 1UL << 30);
    if (blob_cap < (256UL << 20)) blob_cap = 256UL << 20;
    u64 tomb_cap = (u64)slots * 2;
    u64 manifest_cap = 4096;

    /* every mapping tracked for the munmap sweep below */
    struct { void* p; u64 n; } maps[8]; int nmaps = 0;
    long rc = -1;
#define XMAP(var, size, what) do{ \
        void* _m = mmap(0, (size), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0); \
        if (_m == MAP_FAILED){ MSG("mmap %s failed", what); goto done; } \
        maps[nmaps].p = _m; maps[nmaps].n = (size); nmaps++; (var) = _m; }while(0)

    void* u = 0; void* blob = 0; void* tomb = 0; void* mani = 0; void* scr = 0;
    long ustruct = utxo_struct_size(slots);
    XMAP(u, (u64)ustruct, "memtable");
    XMAP(blob, blob_cap, "memtable blob");
    utxo_init(u, slots, blob, blob_cap);

    lsm_state_t lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = (u64)slots * 2;
    lst.fill_threshold = (u64)slots * 3 / 4;
    XMAP(tomb, tomb_cap * 36, "tombstone list");
    lst.tomb_buf = (u64)(uintptr_t)tomb;
    lst.tomb_cap = tomb_cap;
    XMAP(mani, manifest_cap * 16, "manifest");
    lst.manifest_buf = (u64)(uintptr_t)mani;
    lst.manifest_cap = manifest_cap;
    XMAP(scr, 1UL << 20, "scratch");
    lst.scratch_buf = (u64)(uintptr_t)scr;
    lst.scratch_cap = 1UL << 20;

    { long replayed = utxo_lsm_reload_ro(&lst, u);
      if (replayed < 0){ MSG("utxo_lsm_reload_ro failed"); goto done; } }
    long lsm_count = utxo_lsm_count(&lst);

    utxo_stats_t st;
    memset(&st, 0, sizeof st);
    utxo_stats_init(&st, (unsigned long)want_muhash, 0);
    long walked = utxo_lsm_walk(&lst, u, (void*)utxo_stats_add, &st);
    if (walked < 0){ MSG("utxo_lsm_walk failed"); goto done; }
    utxo_stats_finalize(&st);

    if (!fingerprint_take(&fp2)){ MSG("fingerprint failed"); goto done; }
    if (fingerprint_diff(&fp0, &fp2, why, sizeof why)){
        MSG("UTXO set changed during the read (%s) -- result discarded", why);
        rc = 0; goto done;
    }
    if ((long)st.raw_txouts != walked || walked != lsm_count || st.zero_height > 1){
        MSG("inconsistent read (walk=%ld lsm=%ld raw=%lu zero_h=%lu) -- result discarded",
            walked, lsm_count, st.raw_txouts, st.zero_height);
        rc = 0; goto done;
    }

    out->height = height;
    out->txouts = st.txouts;
    out->bogosize = st.bogosize;
    out->total_amount = st.total_amount;
    memcpy(out->muhash, st.muhash, 32);
    out->muhash_valid = want_muhash;
    rc = 1;
done:
    for (int i = 0; i < nmaps; i++) munmap(maps[i].p, maps[i].n);
    return rc;
#undef XMAP
#undef MSG
}

/* ---- scantxoutset's runner (2026-08-25) -----------------------------------
 * Same quiescence discipline, same datadir sizing, same munmap-everything
 * life cycle as utxo_setinfo_rpc_run above -- one TU, one set of the tool's
 * inherited statics. The walk callback matches each live UTXO's script
 * against the caller's target set and collects bounded hits. */
typedef struct {
    u8  txid[32]; u32 vout;
    u64 value; u64 height; int coinbase;
    u8  spk[128]; u32 spklen;
} usi_scan_hit_t;

typedef struct {
    const u8* spks;        /* nspk fixed 128-byte slots */
    const u32* spklens;
    int nspk;
    usi_scan_hit_t* hits;
    long hits_cap, hits_n;
    unsigned long long total_sat;
    u64 scanned;
    int overflow;          /* more matches than hits_cap -- reported, not hidden */
} usi_scan_ctx_t;

static void usi_scan_cb(void* ctxv, const u8 key36[36], u64 value, u64 code,
                        const u8* script, u64 slen){
    usi_scan_ctx_t* c = (usi_scan_ctx_t*)ctxv;
    c->scanned++;
    for (int i = 0; i < c->nspk; i++){
        if (c->spklens[i] != (u32)slen) continue;
        if (memcmp(c->spks + (size_t)i*128, script, slen) != 0) continue;
        if (c->hits_n >= c->hits_cap){ c->overflow = 1; return; }
        usi_scan_hit_t* h = &c->hits[c->hits_n++];
        memcpy(h->txid, key36, 32);
        memcpy(&h->vout, key36+32, 4);
        h->value = value;
        h->height = code >> 1;
        h->coinbase = (int)(code & 1);
        h->spklen = (u32)(slen > 128 ? 128 : slen);
        memcpy(h->spk, script, h->spklen);
        c->total_sat += value;
        return;
    }
}

/* 1 ok / 0 busy-or-inconsistent / -1 error; msg as in utxo_setinfo_rpc_run.
 * spks: nspk 128-byte slots; out_height/out_scanned/out_total set on 1. */
long utxo_scan_rpc_run(const unsigned char* spks, const unsigned int* spklens, int nspk,
                       usi_scan_hit_t* hits, long hits_cap, long* hits_n,
                       long* out_height, unsigned long long* out_scanned,
                       unsigned long long* out_total, int* out_overflow,
                       char* msg, unsigned long mcap){
#define MSG(...) do{ if (msg && mcap) snprintf(msg, mcap, __VA_ARGS__); }while(0)
    if (msg && mcap) msg[0] = 0;
    fingerprint fp0, fp1, fp2;
    char why[512] = "";
    if (!fingerprint_take(&fp0)){ MSG("fingerprint failed"); return -1; }
    sleep_ms(1500);
    if (!fingerprint_take(&fp1)){ MSG("fingerprint failed"); return -1; }
    if (fingerprint_diff(&fp0, &fp1, why, sizeof why)){
        MSG("UTXO set is being written (%s) -- retry between blocks", why); return 0; }
    long height = read_applied_height();
    if (height < 0){ MSG("no readable utxo_applied_height.dat"); return -1; }

    unsigned long slots;
    { u64 tsz = file_size_or("utxo_lsm_table.map", 0);
      slots = tsz > 48 ? (unsigned long)((tsz - 48) / 48) : (1UL << 22);
      if (slots < (1UL << 20)) slots = 1UL << 20; }
    u64 blob_cap = file_size_or("utxo_lsm_blob.map", 1UL << 30);
    if (blob_cap < (256UL << 20)) blob_cap = 256UL << 20;
    u64 tomb_cap = (u64)slots * 2, manifest_cap = 4096;

    struct { void* p; u64 n; } maps[8]; int nmaps = 0;
    long rc = -1;
#define XMAP(var, size, what) do{ \
        void* _m = mmap(0, (size), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0); \
        if (_m == MAP_FAILED){ MSG("mmap %s failed", what); goto done; } \
        maps[nmaps].p = _m; maps[nmaps].n = (size); nmaps++; (var) = _m; }while(0)
    void* u = 0; void* blob = 0; void* tomb = 0; void* mani = 0; void* scr = 0;
    long ustruct = utxo_struct_size(slots);
    XMAP(u, (u64)ustruct, "memtable");
    XMAP(blob, blob_cap, "memtable blob");
    utxo_init(u, slots, blob, blob_cap);
    lsm_state_t lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = (u64)slots * 2;
    lst.fill_threshold = (u64)slots * 3 / 4;
    XMAP(tomb, tomb_cap * 36, "tombstone list");
    lst.tomb_buf = (u64)(uintptr_t)tomb; lst.tomb_cap = tomb_cap;
    XMAP(mani, manifest_cap * 16, "manifest");
    lst.manifest_buf = (u64)(uintptr_t)mani; lst.manifest_cap = manifest_cap;
    XMAP(scr, 1UL << 20, "scratch");
    lst.scratch_buf = (u64)(uintptr_t)scr; lst.scratch_cap = 1UL << 20;

    if (utxo_lsm_reload_ro(&lst, u) < 0){ MSG("utxo_lsm_reload_ro failed"); goto done; }

    usi_scan_ctx_t ctx; memset(&ctx, 0, sizeof ctx);
    ctx.spks = spks; ctx.spklens = spklens; ctx.nspk = nspk;
    ctx.hits = hits; ctx.hits_cap = hits_cap;
    if (utxo_lsm_walk(&lst, u, (void*)usi_scan_cb, &ctx) < 0){
        MSG("utxo_lsm_walk failed"); goto done; }

    if (!fingerprint_take(&fp2)){ MSG("fingerprint failed"); goto done; }
    if (fingerprint_diff(&fp0, &fp2, why, sizeof why)){
        MSG("UTXO set changed during the read (%s) -- result discarded", why);
        rc = 0; goto done; }

    *hits_n = ctx.hits_n;
    *out_height = height;
    *out_scanned = ctx.scanned;
    *out_total = ctx.total_sat;
    *out_overflow = ctx.overflow;
    rc = 1;
done:
    for (int i = 0; i < nmaps; i++) munmap(maps[i].p, maps[i].n);
    return rc;
#undef XMAP
#undef MSG
}
