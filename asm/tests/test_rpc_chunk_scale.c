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
 *     on chain heads, middles, tails and a singleton, a shorter hold.
 *
 * The call's wall time is printed, not asserted (the number to compare is
 * before/after on the same box, see docs/PARITY_RPC_FIELDS.md). The lock hold
 * is asserted only relative to the old path's, on the same pool.
 *
 * Usage: ./tests/test_rpc_chunk_scale [entries]   (default 32000)
 */
#include "../rpc_node.h"
#include "../rpc_json.h"
#include "../mempool_entry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
extern const unsigned char* mpool_get(void*, const unsigned char*, unsigned long*);
extern void   mpool_policy_init(void*, unsigned long long, unsigned, unsigned, unsigned, unsigned, unsigned);
extern unsigned long mpool_policy_state_size(unsigned long);
extern void   mpool_policy_state_init(void*, unsigned long);
extern long   mpool_policy_add(void*, void*, void*, const unsigned char*, unsigned long,
                               const unsigned char*, void*);
extern long   mpool_policy_entry(void*, const unsigned char*, unsigned long long*, unsigned long long*);
extern long   mpool_policy_entry_info(void*, const unsigned char*, struct mp_entry_info*);
extern long   mpool_policy_entry_info_all(void*, struct mp_entry_info*, unsigned char (*)[32], unsigned);
extern int    tx_txid(unsigned char*, const unsigned char*, unsigned long, unsigned char*, unsigned long);

static int fails;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static double now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
                            return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6; }

/* the pool lock, timed: the longest single hold since the last reset */
static double g_lock_at, g_hold_max; static long g_takes, g_releases;
static void t_lock(void){ g_lock_at = now_ms(); g_takes++; }
static void t_unlock(void){ double h = now_ms() - g_lock_at; if (h > g_hold_max) g_hold_max = h; g_releases++; }
/* an arrival time and a "wtxid" that differ per entry, so a snapshot that
 * paired them with the wrong txid would show in the byte comparison */
static long t_time_of(const unsigned char* txid){ return 1700000000L + txid[0] * 257L + txid[1]; }
static void t_sha256d(unsigned char* out, const void* p, unsigned long n){
    const unsigned char* b = (const unsigned char*)p; unsigned long long h = 1469598103934665603ULL;
    for (unsigned long i = 0; i < n; i++){ h ^= b[i]; h *= 1099511628211ULL; }
    for (int i = 0; i < 32; i++){ h ^= (unsigned long long)i; h *= 1099511628211ULL; out[i] = (unsigned char)(h >> 29); }
}

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

int main(int argc, char** argv){
    unsigned want = argc > 1 ? (unsigned)strtoul(argv[1], 0, 10) : 32000u;
    const unsigned DEPTH = 25;                     /* production's modal cluster */
    unsigned chains = (want * 31 / 32) / DEPTH;    /* ~97% of entries in chains */
    unsigned singles = want - chains * DEPTH;
    unsigned long slots = 1; while (slots < (unsigned long)want * 2) slots <<= 1;

    void* pool = calloc(1, mpool_struct_size(slots));
    unsigned long blobcap = (unsigned long)want * 96 + 4096;
    void* blob = calloc(1, blobcap);
    static unsigned char polcfg[128];
    void* polstate = malloc(mpool_policy_state_size(want + 64));
    if (!pool || !blob || !polstate){ printf("FAIL: allocation\n"); return 1; }
    mpool_init(pool, slots, blob, blobcap);
    mpool_policy_init(polcfg, 1000, 25, 101000, 25, 101000, 1);
    mpool_policy_state_init(polstate, want + 64);

    unsigned char tx[128], id[32], prev[32];
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
        unsigned long l = mk_tx1(tx, prev, 100000 - 200 - (s % 40) * 50, tag++);
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
    h.pol_entry_info_all = mpool_policy_entry_info_all;
    h.lock = t_lock; h.unlock = t_unlock;
    h.time_of = t_time_of; h.sha256d = t_sha256d;
    rpc_node_set_mempool(&h);

    long ec = 0; const char* em = NULL;
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

    rj_free(all);
    rpc_node_set_mempool(NULL);
    free(pool); free(blob); free(polstate);
    printf(fails ? "SOME TESTS FAILED (%d)\n" : "ALL TESTS PASSED\n", fails);
    return fails ? 1 : 0;
}
