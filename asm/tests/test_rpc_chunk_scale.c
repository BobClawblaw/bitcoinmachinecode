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
 *   - the bulk answer equals the per-txid getmempoolentry answer for a sample.
 *
 * The call's wall time is printed, not asserted: the whole call runs under the
 * pool lock, so it IS the lock hold other work waits on, and the number to
 * compare is before/after on the same box (see docs/PARITY_RPC_FIELDS.md).
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

    rj_free(all);
    rpc_node_set_mempool(NULL);
    free(pool); free(blob); free(polstate);
    printf(fails ? "SOME TESTS FAILED (%d)\n" : "ALL TESTS PASSED\n", fails);
    return fails ? 1 : 0;
}
