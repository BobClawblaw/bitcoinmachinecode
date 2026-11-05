/* tests/test_mempool_cluster_cache.c -- MPL-3, MPL-4, MPL-6 (audit
 * 2026-10-23): the cluster work the pool does under its lock is bounded by
 * what CHANGED, not by the size of the pool, and the answers do not move.
 *
 *   MPL-3  worst_chunk re-linearized every cluster in the pool on every call,
 *          and the room-making loop calls it once per eviction. It now keeps
 *          each cluster's last chunk on its nodes and re-linearizes only
 *          clusters an insert or removal touched. The cached answer must be
 *          the SAME chunk the old full scan names (kept in the file as
 *          worst_chunk_excl_scan): checked here after every one of a few
 *          hundred random mutations -- inserts, merges, evictions at a full
 *          pool, RBF replacements, block connects -- with and without an
 *          exclusion set. Then the cost: a call after one change may
 *          linearize a handful of clusters, never all of them.
 *   MPL-4  the cluster-limit walk in admission tested every pool node for a
 *          link to each popped node. Admitting a child into a pool of
 *          thousands of unrelated entries must look at its own cluster only.
 *   MPL-6  each replacement candidate rebuilt a whole-pool children index.
 *          A stream of replacements that fail the feerate-diagram check must
 *          not pay a pass over the pool each.
 *
 * Synthetic non-standard transactions under -acceptnonstdtxn, the fixture
 * style of test_mempool_chunks / test_mempool_evict. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/mman.h>

typedef unsigned char u8;
typedef unsigned long long u64;

extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* len);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value, unsigned long height, unsigned long cb, const u8* script, unsigned long slen);
extern long   utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value, unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);
extern void   mpool_policy_init(void* pol, u64 relay_fee_kvb, unsigned max_anc, unsigned max_anc_bytes, unsigned max_desc, unsigned max_desc_bytes, unsigned rbf);
extern void   mpool_policy_set_acceptnonstd(void* pol, int on);
extern unsigned long mpool_policy_state_size(unsigned n);
extern void   mpool_policy_state_init(void* st, unsigned n);
extern void   mpool_policy_set_poolcap(void* st, unsigned long long cap);
extern long   mpool_policy_add(void* pol, void* st, void* mp, const u8* tx, unsigned long txlen, const u8 txid[32], void* utxo);
extern long   mpool_policy_remove_package(void* st, void* mp, const u8 txid[32]);
extern long   mpool_policy_block_connect(void* st, void* mp, const u8* block, unsigned long blen);
extern const char* mpool_policy_reason(void* pol);
extern int    tx_txid(u8 out[32], const u8* tx, unsigned long len, u8* scratch, unsigned long cap);
extern int    mpool_policy_test_worst_chunk(void* st, int legacy, const u8 (*excl)[32], int n_excl,
                                            u8 (*txids)[32], int* n_out, u64* fee, u64* size);
extern void   mpool_policy_test_counters(u64* relin, u64* cx_builds, u64* bfs_steps, u64* fallbacks);
extern long   mpool_policy_test_ck_audit(void* st);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index, u64* value, const u8** script, unsigned long* slen){
    unsigned long h, cb; return utxo_get(u, txid, index, value, &h, &cb, script, slen);
}

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static u8 sc[1 << 16];
static unsigned long long rng = 0x9E3779B97F4A7C15ull;
static unsigned rnd(unsigned m){ rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (unsigned)(rng % m); }
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }

/* an unspent output we can spend: confirmed coins and pool outputs alike */
typedef struct { u8 txid[32]; unsigned idx; u64 v; int cl; int live; } coin_t;
#define MAXCOIN 400000
static coin_t* coins; static int ncoin, nconf, next_conf;
/* each cluster's coins, so a member can be found without sampling the lot */
#define CLMAX 16384
static int* clist[CLMAX]; static int cln[CLMAX], clcap[CLMAX];
static void cl_add(int cl, int ci){
    if (cl < 0 || cl >= CLMAX) return;
    if (cln[cl] == clcap[cl]){ clcap[cl] = clcap[cl] ? clcap[cl] * 2 : 8; clist[cl] = realloc(clist[cl], (size_t)clcap[cl] * sizeof(int)); }
    clist[cl][cln[cl]++] = ci;
}

/* nin inputs, nout outputs of equal value, fee taken from the total */
static long mk(u8* out, const coin_t* const* in, int nin, int nout, u64 fee, int pad){
    u8* p = out; *p++ = 2; *p++ = 0; *p++ = 0; *p++ = 0;
    *p++ = (u8)nin;
    u64 tot = 0;
    for (int i = 0; i < nin; i++){
        memcpy(p, in[i]->txid, 32); p += 32;
        for (int b = 0; b < 4; b++) *p++ = (u8)(in[i]->idx >> (8*b));
        *p++ = 0; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff;
        tot += in[i]->v;
    }
    *p++ = (u8)nout;
    u64 each = (tot - fee) / (u64)nout, last = (tot - fee) - each * (u64)(nout - 1);
    for (int o = 0; o < nout; o++){
        u64 v = o == nout - 1 ? last : each;
        for (int b = 0; b < 8; b++) *p++ = (u8)(v >> (8*b));
        unsigned sl = 1 + (o == 0 ? (unsigned)pad : 0);
        if (sl < 0xfd) *p++ = (u8)sl; else { *p++ = 0xfd; *p++ = (u8)sl; *p++ = (u8)(sl >> 8); }
        *p++ = 0x51;
        if (o == 0) for (int k = 0; k < pad; k++) *p++ = 0;
    }
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    return p - out;
}

#define SLOTS 65536
static u8 pol[128];
static void* st; static void* mp; static void* mblob; static void* ux; static void* ublob;
static unsigned long blob_cap;
static u8 txbuf[4096];
/* raw bytes of everything we put in, by txid, for block building */
typedef struct { u8 id[32]; u8* raw; long len; } rec_t;
static rec_t* recs; static int nrec;

static void reset(unsigned long cap){
    unsigned long psz = mpool_policy_state_size(SLOTS);
    if (!st){
        st = mmap(0, psz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        mp = malloc(40 + (unsigned long)SLOTS * 80 + 8);
        mblob = malloc(64UL << 20);
        ublob = malloc(64UL << 20);
        ux = malloc(40 + 300000UL * 48 + 8);
        coins = calloc(MAXCOIN, sizeof *coins);
        recs = calloc(MAXCOIN, sizeof *recs);
    }
    for (int i = 0; i < nrec; i++) free(recs[i].raw);
    nrec = 0; ncoin = 0; nconf = 0; next_conf = 0;
    for (int i = 0; i < CLMAX; i++) cln[i] = 0;
    blob_cap = cap;
    mpool_policy_init(pol, 1000, 25, 101000, 25, 101000, 1);
    mpool_policy_set_acceptnonstd(pol, 1);
    { extern void mpol_policy_set_min_size(void*, unsigned); mpol_policy_set_min_size(pol, 0); }
    mpool_policy_state_init(st, SLOTS);
    mpool_policy_set_poolcap(st, cap);
    mpool_init(mp, SLOTS, mblob, cap);
    utxo_init(ux, 300000, ublob, 64UL << 20);
}
static void confirmed_coins(int n){
    for (int i = 0; i < n; i++){
        coin_t* c = &coins[ncoin++];
        memset(c, 0, sizeof *c);
        c->txid[0] = (u8)i; c->txid[1] = (u8)(i >> 8); c->txid[2] = (u8)(i >> 16); c->txid[3] = 0xC7;
        c->idx = 0; c->v = 50000000ULL; c->cl = -1; c->live = 1;
        utxo_put(ux, c->txid, 0, c->v, 0, 0, (const u8*)"\x51", 1);
    }
    nconf = ncoin;
}
/* submit; on accept the outputs become spendable coins of cluster `cl` */
static long submit(const coin_t* const* in, int nin, int nout, u64 fee, int pad, int cl, u8 id_out[32]){
    long n = mk(txbuf, in, nin, nout, fee, pad);
    u8 id[32]; tx_txid(id, txbuf, (unsigned long)n, sc, sizeof sc);
    long r = mpool_policy_add(pol, st, mp, txbuf, (unsigned long)n, id, ux);
    if (id_out) memcpy(id_out, id, 32);
    if (r != 1) return r;
    u64 tot = 0; for (int i = 0; i < nin; i++) tot += in[i]->v;
    u64 each = (tot - fee) / (u64)nout, last = (tot - fee) - each * (u64)(nout - 1);
    for (int i = 0; i < nin; i++) ((coin_t*)in[i])->live = 0;
    for (int o = 0; o < nout && ncoin < MAXCOIN; o++){
        coin_t* c = &coins[ncoin++];
        memcpy(c->txid, id, 32); c->idx = (unsigned)o; c->v = o == nout - 1 ? last : each; c->cl = cl; c->live = 1;
        cl_add(cl, ncoin - 1);
    }
    if (nrec < MAXCOIN){ recs[nrec].raw = malloc((size_t)n); memcpy(recs[nrec].raw, txbuf, (size_t)n);
                         recs[nrec].len = n; memcpy(recs[nrec].id, id, 32); nrec++; }
    return r;
}
static int in_pool(const u8 id[32]){ unsigned long l; return mpool_get(mp, id, &l) != 0; }
/* a live coin of cluster cl whose transaction is still in the pool (or confirmed) */
static coin_t* pick_coin(int cl){
    if (cl < 0 || cl >= CLMAX || !cln[cl]) return 0;
    for (int tries = 0; tries < 2 * cln[cl] + 4; tries++){
        coin_t* c = &coins[clist[cl][rnd((unsigned)cln[cl])]];
        if (!c->live) continue;
        if (!in_pool(c->txid)){ c->live = 0; continue; }
        return c;
    }
    return 0;
}
static coin_t* pick_confirmed(void){ return next_conf < nconf ? &coins[next_conf++] : 0; }

/* the cached and the reference answer must be the same chunk, member for member */
static long n_cmp, n_cmp_bad, n_stale;
static int same_answer(const u8 (*excl)[32], int n_excl){
    static u8 a[64][32], b[64][32];
    int na = 0, nb = 0; u64 fa = 0, sa = 0, fb = 0, sb = 0;
    int ra = mpool_policy_test_worst_chunk(st, 0, excl, n_excl, a, &na, &fa, &sa);
    int rb = mpool_policy_test_worst_chunk(st, 1, excl, n_excl, b, &nb, &fb, &sb);
    n_cmp++;
    /* the cache, not just the answer: a missed invalidation can hide behind
     * an answer that happens to agree (or behind the fallback to the scan) */
    long stale = mpool_policy_test_ck_audit(st);
    if (stale){ n_stale++; if (n_stale <= 3) printf("  %ld node(s) hold a stale chunk cache\n", stale); }
    int ok = ra == rb && na == nb && (ra != 1 || (fa == fb && sa == sb && !memcmp(a, b, (size_t)na * 32)));
    if (!ok){
        n_cmp_bad++;
        if (n_cmp_bad <= 3)
            printf("  mismatch: cached r=%d n=%d %llu/%llu, scan r=%d n=%d %llu/%llu\n",
                   ra, na, fa, sa, rb, nb, fb, sb);
    }
    return ok;
}
static void random_excl_check(void){
    static u8 ex[8][32]; int ne = 0;
    for (int k = 0; k < 1 + (int)rnd(6) && nrec; k++){
        const rec_t* r = &recs[rnd((unsigned)nrec)];
        if (in_pool(r->id)) memcpy(ex[ne++], r->id, 32);
    }
    same_answer((const u8 (*)[32])ex, ne);
}

/* build a cluster of up to `members` transactions over one confirmed coin;
 * returns how many went in */
static int grow_cluster(int cl, int members){
    const coin_t* in[3]; u8 id[32];
    coin_t* root = pick_confirmed(); if (!root) return 0;
    in[0] = root;
    if (submit(in, 1, 4, 200 + rnd(20000), (int)rnd(40), cl, id) != 1) return 0;
    int got = 1;
    for (int m = 1; m < members; m++){
        int nin = 1 + (int)rnd(3), k = 0;
        for (int q = 0; q < nin; q++){
            coin_t* c = pick_coin(cl); if (!c) break;
            int dup = 0; for (int z = 0; z < k; z++) if (in[z] == c) dup = 1;
            if (!dup) in[k++] = c;
        }
        if (!k) break;
        /* fees spread wide and skewed, so chunks merge and split in many ways */
        u64 fee = rnd(4) == 0 ? 50 + rnd(400) : 200 + rnd(60000);
        if (submit(in, k, 2 + (int)rnd(3), fee, (int)rnd(60), cl, id) == 1) got++;
    }
    return got;
}

int main(void){
    printf("== MPL-3: the cached worst chunk is the full scan's, through every kind of change ==\n");
    reset(48UL << 20);                       /* room for everything: no evictions while building */
    confirmed_coins(30000);
    int ncl = 0, ntx = 0;
    for (int c = 0; c < 140; c++){ ntx += grow_cluster(c, 20 + (int)rnd(44)); ncl++; }
    for (int i = 0; i < 1500; i++){ const coin_t* in[1]; in[0] = pick_confirmed(); if (in[0] && submit(in, 1, 1, 100 + rnd(30000), 0, 1000 + i, 0) == 1){ ntx++; ncl++; } }
    printf("  built %d transactions in %d clusters\n", ntx, ncl);
    ck("MPL-3 cached == scan on the freshly built pool", same_answer(NULL, 0));
    random_excl_check();
    for (int round = 0; round < 300; round++){
        int what = (int)rnd(6);
        if (what == 0){                                      /* a new member of an existing cluster */
            int cl = (int)rnd(140); const coin_t* in[2]; int k = 0;
            coin_t* c = pick_coin(cl); if (c) in[k++] = c;
            if (k){ u8 id[32]; submit(in, k, 2, 100 + rnd(40000), (int)rnd(30), cl, id); }
        } else if (what == 1){                               /* a transaction joining two clusters */
            int c1 = (int)rnd(140), c2 = (int)rnd(140);
            coin_t* a = pick_coin(c1); coin_t* b = pick_coin(c2);
            if (a && b && a != b){ const coin_t* in[2] = { a, b }; submit(in, 2, 2, 100 + rnd(40000), 0, c1, 0); }
        } else if (what == 2){                               /* evict the worst chunk, as TrimToSize does */
            static u8 w[64][32]; int nw = 0; u64 f, s;
            if (mpool_policy_test_worst_chunk(st, 1, NULL, 0, w, &nw, &f, &s) == 1)
                for (int q = 0; q < nw; q++) mpool_policy_remove_package(st, mp, w[q]);
        } else if (what == 3){                               /* drop a random package (RBF / expiry path) */
            const rec_t* r = &recs[rnd((unsigned)nrec)];
            mpool_policy_remove_package(st, mp, r->id);
        } else if (what == 4){                               /* a block confirming a few roots and leaves */
            static u8 blk[1 << 16]; long bl = 80; memset(blk, 0, 80);
            int cnt = 0; long cntpos = bl++;
            for (int k = 0; k < 6; k++){
                const rec_t* r = &recs[rnd((unsigned)nrec)];
                if (!in_pool(r->id) || bl + r->len > (long)sizeof blk) continue;
                /* only a transaction whose parents are all confirmed can be mined first */
                memcpy(blk + bl, r->raw, (size_t)r->len); bl += r->len; cnt++;
            }
            blk[cntpos] = (u8)cnt;
            if (cnt) mpool_policy_block_connect(st, mp, blk, (unsigned long)bl);
        } else {                                             /* a singleton */
            const coin_t* in[1]; in[0] = pick_confirmed();
            if (in[0]) submit(in, 1, 1, 100 + rnd(30000), 0, 5000 + round, 0);
        }
        same_answer(NULL, 0);
        if (round % 3 == 0) random_excl_check();
    }
    { u64 fb; mpool_policy_test_counters(0, 0, 0, &fb);
      printf("  %ld comparisons, %ld mismatches, %ld with a stale cache, %llu fallbacks to the scan\n", n_cmp, n_cmp_bad, n_stale, fb);
      ck("MPL-3 cached == scan after every insert, merge, eviction, removal and block connect", n_cmp_bad == 0);
      ck("MPL-3 ...with every cached cluster matching a fresh computation (no missed invalidation)", n_stale == 0);
      ck("MPL-3 ...and the answer always came from the cache, never the fallback scan", fb == 0); }

    printf("== MPL-3: eviction at a FULL pool picks what the scan picks ==\n");
    {   /* fill a small blob, then keep admitting: every admission runs the real
         * room-making loop. Before each one, ask the scan what it would evict;
         * if the admission evicted, that chunk must be what left. */
        reset(160000UL);
        confirmed_coins(20000);
        for (int c = 0; c < 30; c++) grow_cluster(c, 10 + (int)rnd(30));
        long evictions = 0, agree = 0;
        for (int i = 0; i < 1200; i++){
            static u8 w[64][32]; int nw = 0; u64 f, s;
            int have = mpool_policy_test_worst_chunk(st, 1, NULL, 0, w, &nw, &f, &s) == 1;
            const coin_t* in[1]; in[0] = pick_confirmed(); if (!in[0]) break;
            u8 id[32];
            long r = submit(in, 1, 1, 2000 + rnd(80000), (int)rnd(40), 9000 + i, id);
            if (r == 1 && have && !in_pool(w[0])){
                evictions++;
                int all_gone = 1; for (int q = 0; q < nw; q++) if (in_pool(w[q])) all_gone = 0;
                agree += all_gone;
            }
            same_answer(NULL, 0);
        }
        printf("  %ld admissions evicted; %ld removed the scan's chunk whole\n", evictions, agree);
        ck("MPL-3 the room-making loop evicted at all (the fixture is full)", evictions > 20);
        ck("MPL-3 ...and every eviction removed the chunk the scan names", agree == evictions);
        ck("MPL-3 cached == scan throughout, the cache never stale", n_cmp_bad == 0 && n_stale == 0);
    }

    printf("== MPL-3: the cost follows what changed, not the pool ==\n");
    {
        reset(48UL << 20);
        confirmed_coins(40000);
        int built = 0;
        for (int c = 0; c < 400; c++) built += grow_cluster(c, 40 + (int)rnd(24));
        for (int i = 0; i < 3000; i++){ const coin_t* in[1]; in[0] = pick_confirmed(); if (in[0]) built += submit(in, 1, 1, 100 + rnd(30000), 0, 2000 + i, 0) == 1; }
        printf("  pool: %d transactions, 400 large clusters + 3000 singletons\n", built);
        static u8 w[64][32]; int nw; u64 f, s, r0, r1, r2, r3, b0, b1;
        mpool_policy_test_worst_chunk(st, 0, NULL, 0, w, &nw, &f, &s);     /* warm: every cluster is new */
        mpool_policy_test_counters(&r0, &b0, 0, 0);
        double t0 = now();
        mpool_policy_test_worst_chunk(st, 0, NULL, 0, w, &nw, &f, &s);
        double t_cached = now() - t0;
        mpool_policy_test_counters(&r1, &b1, 0, 0);
        printf("  an unchanged pool: %llu linearizations, %.3f ms\n", r1 - r0, t_cached * 1e3);
        ck("MPL-3 a call on an unchanged pool linearizes one cluster (to name the chunk)", r1 - r0 == 1);
        ck("MPL-3 ...and builds no children index", b1 == b0);
        for (int q = 0; q < nw; q++) mpool_policy_remove_package(st, mp, w[q]);
        mpool_policy_test_counters(&r1, 0, 0, 0);
        mpool_policy_test_worst_chunk(st, 0, NULL, 0, w, &nw, &f, &s);
        mpool_policy_test_counters(&r2, 0, 0, 0);
        printf("  after one eviction: %llu linearizations\n", r2 - r1);
        /* the evicted chunk's cluster may fall apart into several; nothing
         * outside it was touched, so at most its 64 members' worth of
         * clusters (plus one to name the answer) are linearized again */
        ck("MPL-3 after one eviction only what was left of that cluster is linearized again", r2 - r1 <= 65);
        t0 = now();
        mpool_policy_test_worst_chunk(st, 1, NULL, 0, w, &nw, &f, &s);
        double t_scan = now() - t0;
        mpool_policy_test_counters(&r3, 0, 0, 0);
        printf("  the full scan, for comparison: %llu linearizations, %.3f ms\n", r3 - r2, t_scan * 1e3);
        ck("MPL-3 (control) the scan linearizes every cluster", r3 - r2 >= 3000);
    }

    printf("== MPL-4: admitting a child walks its own cluster, not the pool ==\n");
    {
        reset(48UL << 20);
        confirmed_coins(30000);
        for (int i = 0; i < 20000; i++){ const coin_t* in[1]; in[0] = pick_confirmed(); if (in[0]) submit(in, 1, 1, 1000 + rnd(3000), 0, 3000 + i, 0); }
        const coin_t* in[1]; in[0] = pick_confirmed();
        u8 pid[32]; ck("MPL-4 parent in", submit(in, 1, 2, 5000, 0, 77, pid) == 1);
        coin_t* pc = pick_coin(77);
        u64 s0, s1;
        mpool_policy_test_counters(0, 0, &s0, 0);
        in[0] = pc; ck("MPL-4 child in", pc && submit(in, 1, 1, 5000, 0, 77, 0) == 1);
        mpool_policy_test_counters(0, 0, &s1, 0);
        printf("  neighbour checks for one child in a 20,000-entry pool: %llu\n", s1 - s0);
        ck("MPL-4 the cluster-limit walk made a handful of checks, not one per pool entry", s1 - s0 < 100);
    }

    printf("== MPL-6: failing replacements do not each rebuild a whole-pool index ==\n");
    {
        reset(48UL << 20);
        confirmed_coins(30000);
        for (int i = 0; i < 20000; i++){ const coin_t* in[1]; in[0] = pick_confirmed(); if (in[0]) submit(in, 1, 1, 1000 + rnd(3000), 0, 3000 + i, 0); }
        coin_t* c = pick_confirmed();
        const coin_t* in[1] = { c };
        coin_t saved = *c;
        u8 aid[32]; ck("MPL-6 original in (high feerate)", submit(in, 1, 1, 20000, 0, 88, aid) == 1);
        *c = saved;                                            /* spend the same coin again */
        u64 b0, b1; long failed = 0;
        mpool_policy_test_counters(0, &b0, 0, 0);
        for (int k = 0; k < 50; k++){
            /* more absolute fee, far lower feerate: passes the fee rules, fails the diagram */
            long r = submit(in, 1, 1, 30000 + (u64)k * 10, 3000, 88, 0);
            *c = saved;
            if (r != 1 && strstr(mpool_policy_reason(pol), "replacement-failed")) failed++;
        }
        mpool_policy_test_counters(0, &b1, 0, 0);
        printf("  %ld replacements refused by the diagram check; whole-pool index builds: %llu\n", failed, b1 - b0);
        ck("MPL-6 the candidates reached the diagram check and failed it", failed == 50);
        ck("MPL-6 ...without a whole-pool index build per candidate", b1 - b0 <= 1);
        ck("MPL-6 the original stays", in_pool(aid));
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
