/* tests/test_rpc_chunk_scale.c -- bulk getrawmempool with chunkweight and
 * fees.chunk on a production-shaped pool (2026-09-19).
 *
 * Core v31.1 reports every entry's chunk (GetMainChunkFeerate). This node's
 * bulk getrawmempool used to omit it for every cluster member because a
 * cluster build per entry would be quadratic; the fix builds each cluster
 * once per call and hands the answer to every member. This pins that cost
 * model on a pool shaped like production's on 2026-09-18 (mostly 25-deep
 * chains, the rest singletons):
 *
 *   - cluster builds during ONE bulk call == multi-member clusters in the pool
 *     (a per-member build would be 25x that);
 *   - every entry carries both keys;
 *   - the bulk answer equals the per-txid getmempoolentry answer for a sample;
 *   - (2026-10-06) the pool-lock hold: the verbose call copies what it needs
 *     under the lock and builds after it, so its hold is a fraction of the
 *     call, and its answer is byte-identical to the old all-under-the-lock
 *     build (rpc_node_set_grm_snapshot(0)) -- with arrival times, wtxids and
 *     prioritisetransaction deltas in play, the three inputs the snapshot
 *     carries that the pool used to supply mid-build;
 *   - (2026-10-06) the same for verbose getmempoolancestors /
 *     getmempooldescendants, which now snapshot the transaction's connected
 *     component under the lock and render after it: byte-identical answers
 *     on chain heads, middles, tails and a singleton, a shorter hold;
 *   - (2026-10-06) the tables are sized by the pool's LIVE count, not its slot
 *     capacity: with a quarter of the entries gone from the pool but still in
 *     the registry -- more stale nodes than the first buffer's headroom -- the
 *     graph still covers them (it was retried at capacity until the graph
 *     became compact and self-sized) and the snapshot path still answers,
 *     byte-identical, with the short hold. Run with a production-shaped slot
 *     table: ./tests/test_rpc_chunk_scale 68000 1048576.
 *
 * The call's wall time is printed, not asserted (the number to compare is
 * before/after on the same box, see docs/PARITY_RPC_FIELDS.md). The lock hold
 * is asserted only relative to the old path's, on the same pool.
 *
 * Usage: ./tests/test_rpc_chunk_scale [entries] [slots]   (default 32000, and
 *        a slot table of the next power of two >= 2 x entries; production's is
 *        1,048,576 slots at maxmempool=300MB, ~15x a 68k pool)
 */
#include "../rpc_node.h"
#include "../rpc_json.h"
#include "../mempool_entry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

/* confirmed prevouts: every outpoint the policy cannot find in its own outreg
 * resolves to a 100000-sat P2WPKH (the same stub as test_rpc_node.c) */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char* txid, unsigned long index,
                                    unsigned long long* val, const unsigned char** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;
    static const unsigned char SPK[22] = {0x00,0x14, 0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,
                                          0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99};
    *val = 100000; *spk = SPK; *spklen = 22;
    return 1;
}

extern void   mpool_init(void*, unsigned long, void*, unsigned long);
extern unsigned long mpool_struct_size(unsigned long);
extern long   mpool_count(void*);
extern long   mpool_del(void* mp, const unsigned char txid[32]);
extern const unsigned char* mpool_get(void*, const unsigned char*, unsigned long*);
extern void   mpool_policy_init(void*, unsigned long long, unsigned, unsigned, unsigned, unsigned, unsigned);
extern unsigned long mpool_policy_state_size(unsigned long);
extern void   mpool_policy_state_init(void*, unsigned long);
extern long   mpool_policy_add(void*, void*, void*, const unsigned char*, unsigned long,
                               const unsigned char*, void*);
extern long   mpool_policy_entry(void*, const unsigned char*, unsigned long long*, unsigned long long*);
extern long   mpool_policy_entry_info(void*, const unsigned char*, struct mp_entry_info*);
extern long   mpool_policy_graph_all(void*, struct mp_graph*);
extern int    tx_txid(unsigned char*, const unsigned char*, unsigned long, unsigned char*, unsigned long);

static int fails;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static double now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
                            return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6; }

/* the pool lock, timed: the longest single hold since the last reset */
static double g_lock_at, g_hold_max; static long g_takes, g_releases;
static void t_lock(void){ g_lock_at = now_ms(); g_takes++; }
static void t_unlock(void){ double h = now_ms() - g_lock_at; if (h > g_hold_max) g_hold_max = h; g_releases++; }
/* an arrival time that differs per entry, so a snapshot that paired it with
 * the wrong txid would show in the byte comparison */
static long t_time_of(const unsigned char* txid){ return 1700000000L + txid[0] * 257L + txid[1]; }
/* the REAL sha256d, as daemon/main.c installs it (2026-10-06): the bulk
 * snapshot reads the pool slot's cached wtxid, which mpool_put computed with
 * this function, while the old path hashes through the hook -- so the byte
 * comparison checks the cache against a fresh hash. A fake hook here would
 * make the two paths disagree by construction. Every wtxid differs from its
 * txid only for witness transactions, so the singletons carry a witness
 * (mk_tx1w) and a check below counts entries whose wtxid != txid. */
extern void sha256d(unsigned char* out, const void* msg, unsigned long len);
static void t_sha256d(unsigned char* out, const void* p, unsigned long n){ sha256d(out, p, n); }

/* a count hook that under-reports by 4x, so the walk outgrows the first
 * vsize buffer and must grow it (the live count is only an estimate to the
 * call: the walk is what is authoritative) */
static long t_count_low(void* mp){ return mpool_count(mp) / 4; }

static unsigned long mk_tx1(unsigned char* t, const unsigned char prev[32],
                            unsigned long long val, unsigned tag){
    unsigned long n = 0;
    t[n++]=2;t[n++]=0;t[n++]=0;t[n++]=0;
    t[n++]=1; memcpy(t+n, prev, 32); n+=32; t[n++]=0;t[n++]=0;t[n++]=0;t[n++]=0;
    t[n++]=0; t[n++]=0xff;t[n++]=0xff;t[n++]=0xff;t[n++]=0xff;
    t[n++]=1; for (int i=0;i<8;i++) t[n++]=(unsigned char)(val>>(8*i));
    t[n++]=22; t[n++]=0x00; t[n++]=0x14;
    for (int i=0;i<20;i++) t[n++]=(unsigned char)(tag >> (8*(i%4)));
    t[n++]=0;t[n++]=0;t[n++]=0;t[n++]=0;
    return n;
}

/* mk_tx1 with a segwit marker and a two-item witness (a 71-byte "signature"
 * and a 33-byte "pubkey", the P2WPKH shape the stub prevout has): the txid is
 * unchanged by the witness, the wtxid is not */
static unsigned long mk_tx1w(unsigned char* t, const unsigned char prev[32],
                             unsigned long long val, unsigned tag){
    unsigned char b[128]; unsigned long l = mk_tx1(b, prev, val, tag), n = 0;
    memcpy(t, b, 4); n = 4; t[n++] = 0x00; t[n++] = 0x01;      /* version, marker, flag */
    memcpy(t + n, b + 4, l - 8); n += l - 8;                     /* inputs and outputs */
    t[n++] = 2;
    t[n++] = 71; for (int i = 0; i < 71; i++) t[n++] = (unsigned char)(0x30 + ((tag + i) & 0x3f));
    t[n++] = 33; t[n++] = 0x02; for (int i = 0; i < 32; i++) t[n++] = (unsigned char)(tag >> (i % 4) * 8);
    memcpy(t + n, b + l - 4, 4); n += 4;                         /* locktime */
    return n;
}

int main(int argc, char** argv){
    unsigned want = argc > 1 ? (unsigned)strtoul(argv[1], 0, 10) : 32000u;
    const unsigned DEPTH = 25;                     /* production's modal cluster */
    unsigned chains = (want * 31 / 32) / DEPTH;    /* ~97% of entries in chains */
    unsigned singles = want - chains * DEPTH;
    unsigned long slots = 1; while (slots < (unsigned long)want * 2) slots <<= 1;
    if (argc > 2){ unsigned long s2 = strtoul(argv[2], 0, 10); while (slots < s2) slots <<= 1; }

    void* pool = calloc(1, mpool_struct_size(slots));
    unsigned long blobcap = (unsigned long)want * 96 + 4096;
    void* blob = calloc(1, blobcap);
    static unsigned char polcfg[128];
    void* polstate = malloc(mpool_policy_state_size(want + 64));
    if (!pool || !blob || !polstate){ printf("FAIL: allocation\n"); return 1; }
    mpool_init(pool, slots, blob, blobcap);
    mpool_policy_init(polcfg, 1000, 25, 101000, 25, 101000, 1);
    mpool_policy_state_init(polstate, want + 64);

    unsigned char tx[256], id[32], prev[32];
    static unsigned char scratch[4096];
    unsigned tag = 1, added = 0, refused = 0;
    double t0 = now_ms();
    for (unsigned c = 0; c < chains; c++){
        memset(prev, 0, 32); prev[0] = 0xc7; memcpy(prev + 1, &c, sizeof c);
        unsigned long long in = 100000;
        for (unsigned d = 0; d < DEPTH; d++){
            /* fees vary along the chain so chunks split and merge: 100..5000 sat */
            unsigned long long fee = 100 + ((c * 7919u + d * 131u) % 50u) * 100u;
            unsigned long l = mk_tx1(tx, prev, in - fee, tag++);
            tx_txid(id, tx, l, scratch, sizeof scratch);
            if (mpool_policy_add(polcfg, polstate, pool, tx, l, id, (void*)1) == 1) added++;
            else { refused++; break; }
            memcpy(prev, id, 32); in -= fee;
        }
    }
    for (unsigned s = 0; s < singles; s++){
        memset(prev, 0, 32); prev[0] = 0x5e; memcpy(prev + 1, &s, sizeof s);
        unsigned long l = mk_tx1w(tx, prev, 100000 - 200 - (s % 40) * 50, tag++);
        tx_txid(id, tx, l, scratch, sizeof scratch);
        if (mpool_policy_add(polcfg, polstate, pool, tx, l, id, (void*)1) == 1) added++;
        else refused++;
    }
    printf("  pool: %u entries (%u chains of %u, %u singletons) built in %.0f ms, %u refused\n",
           added, chains, DEPTH, singles, now_ms() - t0, refused);
    ck("the synthetic pool was accepted whole", refused == 0 && (long)added == mpool_count(pool));

    rpc_mempool_hooks h; memset(&h, 0, sizeof h);
    h.mp = pool; h.maxbytes = 300000000; h.count = mpool_count; h.get = mpool_get;
    h.polstate = polstate; h.pol_entry = mpool_policy_entry;
    h.pol_entry_info = mpool_policy_entry_info;
    h.pol_graph_all = mpool_policy_graph_all;
    h.lock = t_lock; h.unlock = t_unlock;
    h.time_of = t_time_of; h.sha256d = t_sha256d;
    rpc_node_set_mempool(&h);

    long ec = 0; const char* em = NULL;
    /* the first verbose call's peak-memory growth, on the server's path: the
     * request arena around the call and the compact body written from it
     * (rpc_server.c render_request). The per-call tables, the reply and the
     * body are the only large allocations it makes (ru_maxrss is bytes on
     * Darwin, KB on Linux) */
    { struct rusage ru0, ru1; getrusage(RUSAGE_SELF, &ru0);
      rj_arena_begin();
      rj_val* pv = rj_parse("[true]", 6); rj_val* r = NULL;
      g_hold_max = 0;
      rpc_node_dispatch("getrawmempool", pv, &r, &ec, &em);
      long ab = rj_arena_bytes(), bl = 0;
      char* body = rj_write_alloc(r, 0, &bl);
      getrusage(RUSAGE_SELF, &ru1);
      free(body);
      rj_arena_end();
#ifdef __APPLE__
      double mb = (double)(ru1.ru_maxrss - ru0.ru_maxrss) / 1048576.0;
#else
      double mb = (double)(ru1.ru_maxrss - ru0.ru_maxrss) / 1024.0;
#endif
      double live = (double)mpool_count(pool);
      printf("  first verbose call: %lu-slot table, pool-lock hold %.1f ms, peak RSS +%.0f MB, "
             "arena %.1f MB for a %.1f MB body\n", slots, g_hold_max, mb, ab / 1048576.0, bl / 1048576.0);
      /* 2026-10-06: the one-pass graph is compact (mempool_entry.h mp_graph).
       * It was an ~8.3 KB mp_entry_info per registry node -- ~12 KB of peak
       * RSS per entry with the reply on top. The bound sits well above what
       * is left. */
      { char w2[160]; snprintf(w2, sizeof w2, "the first verbose call's peak RSS is under 8 KB per entry (%.1f KB)",
                               mb * 1024.0 / live);
        ck(w2, mb * 1048576.0 / live < 8192.0); }
      /* 2026-10-06: each entry is frozen to its text as it is built
       * (rj_freeze): the arena held every entry's tree until the body was
       * written, ~3.0 KB per entry for ~0.6 KB of text. Bound: twice the
       * body. */
      { char w2[200]; snprintf(w2, sizeof w2, "the reply's arena is under twice its body (%.1f MB for %.1f MB): entries are kept as text",
                               ab / 1048576.0, bl / 1048576.0);
        ck(w2, ab > 0 && bl > 0 && ab < 2 * bl); } }
    double best = 1e18; rj_val* all = NULL; unsigned long builds = 0;
    for (int rep = 0; rep < 3; rep++){
        if (all) rj_free(all);
        all = NULL;
        rj_val* pv = rj_parse("[true]", 6);
        unsigned long b0 = rpc_node_cluster_builds();
        double a = now_ms();
        rpc_node_dispatch("getrawmempool", pv, &all, &ec, &em);
        double ms = now_ms() - a;
        builds = rpc_node_cluster_builds() - b0;
        rj_free(pv);
        if (ms < best) best = ms;
    }
    printf("  getrawmempool true: %.1f ms best of 3 over %u entries (%.2f us/entry), "
           "%lu cluster builds\n", best, added, best * 1000.0 / (added ? added : 1), builds);

    int n = all ? (int)all->nmembers : 0, have = 0;
    for (int m = 0; m < n; m++){
        rj_val* e = all->members[m].val; rj_val* f = rj_obj_get(e, "fees");
        rj_val* cw = rj_obj_get(e, "chunkweight"); rj_val* cf = f ? rj_obj_get(f, "chunk") : NULL;
        if (cw && cf) have++;
    }
    char what[256];
    snprintf(what, sizeof what, "every one of %d entries carries chunkweight and fees.chunk (%d do)", n, have);
    ck(what, n == (int)added && have == n);
    snprintf(what, sizeof what, "%lu cluster builds for %u chains: ONE per cluster (per member would be %u)",
             builds, chains, chains * DEPTH);
    ck(what, builds == chains);

    /* bulk == per-txid for a sample: the per-txid path builds its own cluster
     * with the registry lookup, the bulk path reads the call's graph */
    int agree = 1, sampled = 0;
    for (int m = 0; m < n && sampled < 300; m += (n / 300 ? n / 300 : 1), sampled++){
        char one[80]; snprintf(one, sizeof one, "[\"%s\"]", all->members[m].key);
        rj_val* op = rj_parse(one, strlen(one)); rj_val* o1 = NULL;
        rpc_node_dispatch("getmempoolentry", op, &o1, &ec, &em);
        rj_val* b = all->members[m].val;
        rj_val* bw = rj_obj_get(b, "chunkweight"); rj_val* sw = o1 ? rj_obj_get(o1, "chunkweight") : NULL;
        rj_val* bf = rj_obj_get(rj_obj_get(b, "fees"), "chunk");
        rj_val* sf = o1 ? rj_obj_get(rj_obj_get(o1, "fees"), "chunk") : NULL;
        if (!bw || !sw || !bf || !sf || strcmp(bw->str, sw->str) || strcmp(bf->str, sf->str)){
            if (agree) printf("  (first disagreement at %s)\n", all->members[m].key);
            agree = 0;
        }
        rj_free(o1); rj_free(op);
    }
    snprintf(what, sizeof what, "bulk chunk fields equal getmempoolentry's on %d sampled entries", sampled);
    ck(what, agree && sampled > 0);

    /* ---- the pool-lock hold, and the same answer, old path vs snapshot ----
     * three prioritisetransaction deltas first (a chain's head, a chain's
     * middle, a singleton): the delta moves fees.modified and, through the
     * cluster's modified fees, the chunk -- read from the pool's table by the
     * old path mid-build, from the snapshot by the new one */
    if (n > 40){
        const int pick[3] = { 0, 12, n - 1 };
        for (int q = 0; q < 3; q++){
            char pa[160]; snprintf(pa, sizeof pa, "[\"%s\", 0, %d]", all->members[pick[q]].key, 4000 + 1000 * q);
            rj_val* pp = rj_parse(pa, strlen(pa)); rj_val* pr = NULL;
            rpc_node_dispatch("prioritisetransaction", pp, &pr, &ec, &em);
            rj_free(pr); rj_free(pp);
        }
    }
    char* body[2] = { NULL, NULL }; long blen[2] = { 0, 0 };
    double hold[2] = { 0, 0 }, wall[2] = { 0, 0 };
    long takes0 = g_takes, rel0 = g_releases;
    for (int mode = 0; mode < 2; mode++){
        rpc_node_set_grm_snapshot(mode);
        hold[mode] = 1e18; wall[mode] = 1e18;
        for (int rep = 0; rep < 3; rep++){
            rj_val* pv = rj_parse("[true]", 6); rj_val* r = NULL;
            g_hold_max = 0;
            double a = now_ms();
            rpc_node_dispatch("getrawmempool", pv, &r, &ec, &em);
            double ms = now_ms() - a;
            if (g_hold_max < hold[mode]) hold[mode] = g_hold_max;
            if (ms < wall[mode]) wall[mode] = ms;
            if (rep == 0 && r){ free(body[mode]); body[mode] = rj_write_alloc(r, 0, &blen[mode]); }
            rj_free(r); rj_free(pv);
        }
    }
    rpc_node_set_grm_snapshot(1);
    /* a release missed would read as NO hold (nothing timed it), so the
     * hold check below is only meaningful with the takes and releases paired */
    snprintf(what, sizeof what, "every pool-lock take was released (%ld takes, %ld releases)",
             g_takes - takes0, g_releases - rel0);
    ck(what, g_takes - takes0 == g_releases - rel0 && g_takes > takes0);
    { /* the deltas took: the comparison above covered a moved fees.modified */
      int moved = 0;
      rj_val* pv = rj_parse("[true]", 6); rj_val* r = NULL;
      rpc_node_dispatch("getrawmempool", pv, &r, &ec, &em);
      for (int m = 0; r && m < (int)r->nmembers; m++){
          rj_val* f = rj_obj_get(r->members[m].val, "fees");
          rj_val* fb = f ? rj_obj_get(f, "base") : NULL; rj_val* fm = f ? rj_obj_get(f, "modified") : NULL;
          if (fb && fm && strcmp(fb->str, fm->str)) moved++;
      }
      rj_free(r); rj_free(pv);
      snprintf(what, sizeof what, "the three prioritisetransaction deltas show in fees.modified (%d entries)", moved);
      ck(what, n <= 40 || moved == 3); }
    printf("  pool-lock hold, best of 3: %.1f ms building under the lock (call %.1f ms), "
           "%.1f ms copying under it (call %.1f ms)\n", hold[0], wall[0], hold[1], wall[1]);
    { /* the witness singletons: their wtxid (the slot's cache, on the
       * snapshot path) is not their txid */
      int differ = 0;
      rj_val* pv = rj_parse("[true]", 6); rj_val* r = NULL;
      rpc_node_dispatch("getrawmempool", pv, &r, &ec, &em);
      for (int m = 0; r && m < (int)r->nmembers; m++){
          rj_val* w = rj_obj_get(r->members[m].val, "wtxid");
          if (w && strcmp(w->str, r->members[m].key)) differ++;
      }
      rj_free(r); rj_free(pv);
      snprintf(what, sizeof what, "the witness singletons report a wtxid that is not their txid (%d of %u)", differ, singles);
      ck(what, differ > 0 && (unsigned)differ == singles); }
    ck("the snapshot answer is byte-identical to the all-under-the-lock answer",
       body[0] && body[1] && blen[0] == blen[1] && !memcmp(body[0], body[1], (size_t)blen[0]));
    snprintf(what, sizeof what, "the pool lock is held for under half the old hold (%.1f ms against %.1f ms)",
             hold[1], hold[0]);
    ck(what, hold[1] < hold[0] * 0.5);
    free(body[0]); free(body[1]);

    /* ---- verbose ancestors / descendants: old path vs the component snapshot ---- */
    if (n > 40){
        const int pick[6] = { 0, 1, 12, 24, 25 * 7 + 13, n - 1 };
        const char* meth[2] = { "getmempoolancestors", "getmempooldescendants" };
        int same = 1, calls = 0, nonempty = 0;
        double rhold[2] = { 0, 0 };
        long tk0 = g_takes, rl0 = g_releases;
        for (int q = 0; q < 6; q++) for (int d = 0; d < 2; d++){
            char pa[160]; snprintf(pa, sizeof pa, "[\"%s\", true]", all->members[pick[q]].key);
            char* rb[2] = { NULL, NULL }; long rl[2] = { 0, 0 };
            for (int mode = 0; mode < 2; mode++){
                rpc_node_set_grm_snapshot(mode);
                rj_val* pp = rj_parse(pa, strlen(pa)); rj_val* r = NULL;
                g_hold_max = 0;
                rpc_node_dispatch(meth[d], pp, &r, &ec, &em);
                if (g_hold_max > rhold[mode]) rhold[mode] = g_hold_max;
                if (mode == 1 && r && r->nmembers) nonempty++;
                rb[mode] = r ? rj_write_alloc(r, 0, &rl[mode]) : NULL;
                rj_free(r); rj_free(pp);
            }
            calls++;
            if (!rb[0] || !rb[1] || rl[0] != rl[1] || memcmp(rb[0], rb[1], (size_t)rl[0])){
                if (same) printf("  (first relatives disagreement: %s on member %d)\n", meth[d], pick[q]);
                same = 0;
            }
            free(rb[0]); free(rb[1]);
        }
        rpc_node_set_grm_snapshot(1);
        printf("  verbose ancestors/descendants, longest pool-lock hold over %d calls: %.2f ms building "
               "under the lock, %.2f ms copying under it\n", calls, rhold[0], rhold[1]);
        snprintf(what, sizeof what, "verbose ancestors/descendants are byte-identical on both paths (%d calls, %d non-empty)",
                 calls, nonempty);
        ck(what, same && nonempty >= 6);
        snprintf(what, sizeof what, "...with every take released (%ld takes, %ld releases)",
                 g_takes - tk0, g_releases - rl0);
        ck(what, g_takes - tk0 == g_releases - rl0 && g_takes > tk0);
        snprintf(what, sizeof what, "...and a shorter longest hold (%.2f ms against %.2f ms)", rhold[1], rhold[0]);
        ck(what, rhold[1] < rhold[0]);
    }

    /* ---- stale registry nodes beyond the live count ----
     * every fourth entry leaves the structural pool only (the registry keeps
     * it, as it does for a moment after an eviction): live drops by a
     * quarter, the registry does not, so the live-count buffer is too small
     * for a live-sized graph (the old fixed-record buffer needed a retry at
     * capacity) -- and a graph that missed them would fall back to the slow
     * under-the-lock path, which the hold check catches */
    if (n > 40){
        unsigned dropped = 0;
        for (int m = 0; m < n; m += 4){
            unsigned char id2[32]; const char* k = all->members[m].key;
            for (int b = 0; b < 32; b++){ unsigned v; sscanf(k + 2 * b, "%2x", &v); id2[31 - b] = (unsigned char)v; }
            if (mpool_del(pool, id2) == 1) dropped++;
        }
        char* sb[2] = { NULL, NULL }; long sl[2] = { 0, 0 }; double sh[2] = { 0, 0 };
        long tk0 = g_takes, rl0 = g_releases;
        for (int mode = 0; mode < 2; mode++){
            rpc_node_set_grm_snapshot(mode);
            sh[mode] = 1e18;
            for (int rep = 0; rep < 3; rep++){
                rj_val* pv = rj_parse("[true]", 6); rj_val* r = NULL;
                g_hold_max = 0;
                rpc_node_dispatch("getrawmempool", pv, &r, &ec, &em);
                if (g_hold_max < sh[mode]) sh[mode] = g_hold_max;
                if (rep == 0 && r){ free(sb[mode]); sb[mode] = rj_write_alloc(r, 0, &sl[mode]); }
                rj_free(r); rj_free(pv);
            }
        }
        rpc_node_set_grm_snapshot(1);
        printf("  %u entries dropped from the pool, kept in the registry (live %ld): hold %.1f ms "
               "under-the-lock build, %.1f ms snapshot\n", dropped, mpool_count(pool), sh[0], sh[1]);
        ck("with stale registry nodes the snapshot answer is still byte-identical",
           sb[0] && sb[1] && sl[0] == sl[1] && !memcmp(sb[0], sb[1], (size_t)sl[0]));
        snprintf(what, sizeof what, "...and it took the snapshot path (hold %.1f ms against %.1f ms): the graph covers the stale nodes",
                 sh[1], sh[0]);
        ck(what, dropped > (unsigned)n / 8 && sh[1] < sh[0] * 0.5);
        ck("...with every take released", g_takes - tk0 == g_releases - rl0);
        free(sb[0]); free(sb[1]);

        /* the count under-reports: the vsize buffer must grow mid-walk */
        h.count = t_count_low; rpc_node_set_mempool(&h);
        char* gb[2] = { NULL, NULL }; long gl[2] = { 0, 0 }; double gh[2] = { 0, 0 };
        for (int mode = 0; mode < 2; mode++){
            rpc_node_set_grm_snapshot(mode);
            rj_val* pv = rj_parse("[true]", 6); rj_val* r = NULL;
            g_hold_max = 0;
            rpc_node_dispatch("getrawmempool", pv, &r, &ec, &em);
            gh[mode] = g_hold_max;
            gb[mode] = r ? rj_write_alloc(r, 0, &gl[mode]) : NULL;
            rj_free(r); rj_free(pv);
        }
        rpc_node_set_grm_snapshot(1);
        h.count = mpool_count; rpc_node_set_mempool(&h);
        snprintf(what, sizeof what, "with the live count under-reported 4x the buffer grows: same answer, snapshot hold "
                 "(%.1f ms against %.1f ms)", gh[1], gh[0]);
        ck(what, gb[0] && gb[1] && gl[0] == gl[1] && !memcmp(gb[0], gb[1], (size_t)gl[0])
                 && gh[1] < gh[0] * 0.5);
        free(gb[0]); free(gb[1]);
    }

    rj_free(all);
    rpc_node_set_mempool(NULL);
    free(pool); free(blob); free(polstate);
    printf(fails ? "SOME TESTS FAILED (%d)\n" : "ALL TESTS PASSED\n", fails);
    return fails ? 1 : 0;
}
