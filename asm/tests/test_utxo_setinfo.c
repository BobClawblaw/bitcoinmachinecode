/* test_utxo_setinfo.c -- the filtered UTXO-set view (`gettxoutsetinfo` on our
 * side) must see EXACTLY the live set, apply EXACTLY Core's unspendable rule,
 * and produce a set hash that MOVES when the set does.
 *
 * The last clause is the point. A set-hash comparison that cannot fail is
 * worthless, so most of this file is negative controls: five separate
 * one-entry perturbations (value, script byte, script length, height,
 * coinbase flag) plus adding and removing a single entry, each of which must
 * change the hash. If any of them did not, the acceptance test they support
 * would be decorative.
 *
 * What is asserted, and against what:
 *   1. utxo_script_unspendable == Core's CScript::IsUnspendable at every
 *      boundary: empty script (SPENDABLE -- `size() > 0 &&` guards the
 *      first-byte test), leading OP_RETURN, OP_RETURN not first, exactly
 *      MAX_SCRIPT_SIZE (spendable), one over (not).
 *   2. The walk visits the live set exactly once each -- proven by comparing
 *      every aggregate against an independent reference model maintained by
 *      this test, across a datadir shaped so the live set is split three ways:
 *      entries in old flushed runs, entries in the current memtable, and
 *      keys shadowed by this generation's tombstones.
 *   3. Output indices >= 256 are present on purpose. Our key comparator
 *      orders the index field by its little-endian BYTES, so index 256 sorts
 *      before index 1 -- the exact reason hash_serialized_3 was rejected in
 *      favour of MuHash (see bitcoin_muhash.asm's header). With a multiset
 *      hash the walk's order must not matter, and the reference model here
 *      inserts in a DIFFERENT order from the walk to prove it.
 *   4. utxo_lsm_reload_ro reproduces the identical figures AND leaves the
 *      datadir byte-identical -- no utxo.idx created, no file's size or mtime
 *      touched. The tool this supports is pointed at a datadir it is
 *      forbidden to write to, so "did not write" is a post-condition worth
 *      asserting rather than assuming (ENGINEERING_RULES.md 2).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned long long u64;

extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], unsigned index,
                         u64 value, unsigned long height, unsigned long is_coinbase,
                         const u8* script, unsigned slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], unsigned index);
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_reload_ro(void* lst, void* u);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);

extern void utxo_stats_init(void* st, unsigned long want_muhash,
                            unsigned long exclude_genesis_coinbase);
extern void utxo_stats_add(void* st, const u8 key36[36], u64 value, u64 code,
                           const u8* script, u64 slen);
extern void utxo_stats_finalize(void* st);
extern long utxo_script_unspendable(const u8* script, u64 slen);

extern void muhash_init(void* acc);
extern void muhash_insert(void* acc, const void* data, unsigned long len);
extern void muhash_finalize(u8 out[32], const void* acc);

/* Mirrors bitcoin_utxo_stats.asm's state struct. */
typedef struct {
    u64 txouts, total_amount, bogosize;
    u64 unspendable_txouts, unspendable_amount;
    u64 raw_txouts, zero_height, want_muhash;
    u8  muhash[32];
    u8  acc[384];
    u64 excl_genesis, genesis_excluded;
} stats_t;

/* Mirrors bitcoin_utxo_lsm.asm's state struct (168 bytes). */
struct LST {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask;
};

#define BLOOM_MAX_BYTES   (4*1024*1024)
#define SCRIPT_MAX_BYTES  65536
#define SLOTS          1024
#define BLOB           (16<<20)
#define FILL_THRESHOLD 24
#define OP_THRESHOLD   48
#define TOMB_CAP       256
#define MANIFEST_CAP   4096
#define DESC_CAP       512
#define SCRATCH_CAP    ((u64)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)

#define MAX_SCRIPT_SIZE 10000
#define N 260

static int fails = 0;
static void ok_(const char* l, int cond, const char* extra)
{
    if (cond) printf("ok  : %s%s\n", l, extra ? extra : "");
    else { printf("FAIL: %s%s\n", l, extra ? extra : ""); fails++; }
}
static void cku(const char* l, u64 got, u64 exp)
{
    char b[160];
    snprintf(b, sizeof b, " (got %llu exp %llu)", got, exp);
    ok_(l, got == exp, b);
}

/* ---------------- the reference model ---------------- */

typedef struct {
    u8  txid[32];
    unsigned index;
    u64 value;
    unsigned long height;
    unsigned long coinbase;
    u8* script;
    unsigned slen;
    int live;
} coin;

static coin model[N];

static void make_txid(u8* t, unsigned i)
{
    for (int j = 0; j < 32; j++) t[j] = (u8)(0x41 + ((i * 7 + j * 13) & 0x7f));
    t[0] = (u8)(i & 0xff);
    t[1] = (u8)((i >> 8) & 0xff);
}

/* Core's TxOutSer, written here independently of the assembly so the two can
 * disagree. Returns the serialized length. */
static unsigned ser_coin(const coin* c, u8* out)
{
    unsigned p = 0;
    memcpy(out + p, c->txid, 32); p += 32;
    unsigned n = c->index;      memcpy(out + p, &n, 4); p += 4;
    unsigned code = (unsigned)((c->height << 1) | (c->coinbase ? 1u : 0u));
    memcpy(out + p, &code, 4); p += 4;
    u64 v = c->value;           memcpy(out + p, &v, 8); p += 8;
    if (c->slen < 0xfd) { out[p++] = (u8)c->slen; }
    else { out[p++] = 0xfd; out[p++] = (u8)(c->slen & 0xff); out[p++] = (u8)(c->slen >> 8); }
    memcpy(out + p, c->script, c->slen); p += c->slen;
    return p;
}

static int ref_unspendable(const coin* c)
{
    return (c->slen > 0 && c->script[0] == 0x6a) || c->slen > MAX_SCRIPT_SIZE;
}

/* Aggregate the model. `skip`/`bump` drive the negative controls: skip==-2
 * means "no perturbation". */
typedef struct { u64 txouts, amount, bogosize, unsp_n, unsp_amt, raw; u8 hash[32]; } agg;

typedef enum { PERT_NONE, PERT_VALUE, PERT_SCRIPT_BYTE, PERT_SCRIPT_LEN,
               PERT_HEIGHT, PERT_COINBASE, PERT_DROP, PERT_ADD } pert;

static void model_agg(agg* a, pert what, int which)
{
    u8 acc[384], buf[16384];
    memset(a, 0, sizeof *a);
    muhash_init(acc);
    /* Deliberately the REVERSE of the order the LSM walk emits, so an
     * accidental order dependence would show up as a mismatch. */
    for (int i = N - 1; i >= 0; i--) {
        if (!model[i].live) continue;
        if (what == PERT_DROP && i == which) continue;
        coin c = model[i];
        u8 alt[16384];
        if (i == which) {
            switch (what) {
            case PERT_VALUE:       c.value += 1; break;
            case PERT_HEIGHT:      c.height += 1; break;
            case PERT_COINBASE:    c.coinbase = !c.coinbase; break;
            case PERT_SCRIPT_BYTE:
                memcpy(alt, c.script, c.slen); alt[c.slen / 2] ^= 0x01; c.script = alt; break;
            case PERT_SCRIPT_LEN:
                memcpy(alt, c.script, c.slen); alt[c.slen] = 0x51; c.slen += 1; c.script = alt; break;
            default: break;
            }
        }
        a->raw++;
        if (ref_unspendable(&c)) { a->unsp_n++; a->unsp_amt += c.value; continue; }
        a->txouts++;
        a->amount += c.value;
        a->bogosize += 50 + c.slen;
        unsigned n = ser_coin(&c, buf);
        muhash_insert(acc, buf, n);
    }
    if (what == PERT_ADD) {
        coin c;
        memset(&c, 0, sizeof c);
        make_txid(c.txid, 0xBEEF);
        c.index = 3; c.value = 12345; c.height = 99; c.coinbase = 0;
        u8 s[4] = { 0x51, 0x52, 0x53, 0x54 };
        c.script = s; c.slen = 4;
        a->raw++; a->txouts++; a->amount += c.value; a->bogosize += 50 + c.slen;
        unsigned n = ser_coin(&c, buf);
        muhash_insert(acc, buf, n);
    }
    muhash_finalize(a->hash, acc);
}

/* ---------------- datadir fingerprint (the read-only post-condition) ------ */

typedef struct { int n; char name[64][64]; u64 size[64], sec[64], nsec[64]; } dirfp;

static void dirfp_take(dirfp* f)
{
    f->n = 0;
    DIR* d = opendir(".");
    struct dirent* de;
    while (d && (de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        if (f->n >= 64) break;
        struct stat sb;
        if (stat(de->d_name, &sb) != 0) continue;
        snprintf(f->name[f->n], 64, "%s", de->d_name);
        f->size[f->n] = (u64)sb.st_size;
        f->sec[f->n] = (u64)sb.st_mtim.tv_sec;
        f->nsec[f->n] = (u64)sb.st_mtim.tv_nsec;
        f->n++;
    }
    if (d) closedir(d);
    /* insertion sort by name so the comparison is order-independent */
    for (int i = 1; i < f->n; i++)
        for (int j = i; j > 0 && strcmp(f->name[j - 1], f->name[j]) > 0; j--) {
            char t[64]; u64 a, b, c;
            memcpy(t, f->name[j], 64); memcpy(f->name[j], f->name[j - 1], 64); memcpy(f->name[j - 1], t, 64);
            a = f->size[j]; f->size[j] = f->size[j - 1]; f->size[j - 1] = a;
            b = f->sec[j];  f->sec[j]  = f->sec[j - 1];  f->sec[j - 1]  = b;
            c = f->nsec[j]; f->nsec[j] = f->nsec[j - 1]; f->nsec[j - 1] = c;
        }
}

static int dirfp_same(const dirfp* a, const dirfp* b, char* why, size_t n)
{
    if (a->n != b->n) { snprintf(why, n, "file count %d -> %d", a->n, b->n); return 0; }
    for (int i = 0; i < a->n; i++) {
        if (strcmp(a->name[i], b->name[i]) || a->size[i] != b->size[i] ||
            a->sec[i] != b->sec[i] || a->nsec[i] != b->nsec[i]) {
            snprintf(why, n, "%s changed", a->name[i]);
            return 0;
        }
    }
    return 1;
}

/* ---------------- driver ---------------- */

static u8* scripts[N];

static void build_scripts(void)
{
    for (int i = 0; i < N; i++) {
        unsigned len;
        if (i % 17 == 3) len = 0;                       /* empty: SPENDABLE by Core's rule */
        else if (i == 40) len = MAX_SCRIPT_SIZE;         /* exactly at the limit: spendable */
        else if (i == 41) len = MAX_SCRIPT_SIZE + 1;      /* one over: unspendable */
        else len = 22 + (unsigned)(i % 41);
        scripts[i] = malloc(len ? len : 1);
        for (unsigned j = 0; j < len; j++) scripts[i][j] = (u8)(0x60 + ((i + j) & 0x1f));
        if (len) {
            if (i % 5 == 0) scripts[i][0] = 0x6a;        /* leading OP_RETURN: unspendable */
            else if (i % 5 == 1) { scripts[i][0] = 0x00; if (len > 1) scripts[i][1] = 0x6a; }
                                                          /* OP_RETURN, but not first: SPENDABLE */
            else scripts[i][0] = 0x76;
        }
        model[i].script = scripts[i];
        model[i].slen = len;
    }
}

int main(void)
{
    tt_isolate();

    /* ---- 1. the filter, at Core's exact boundaries ---- */
    {
        u8 s[MAX_SCRIPT_SIZE + 2];
        memset(s, 0x51, sizeof s);
        ok_("IsUnspendable(empty) == 0 (size()>0 guards the OP_RETURN test)",
            utxo_script_unspendable(s, 0) == 0, "");
        s[0] = 0x6a;
        ok_("IsUnspendable(leading OP_RETURN) == 1", utxo_script_unspendable(s, 1) == 1, "");
        ok_("IsUnspendable(leading OP_RETURN, long) == 1", utxo_script_unspendable(s, 80) == 1, "");
        s[0] = 0x00; s[1] = 0x6a;
        ok_("IsUnspendable(OP_RETURN not first) == 0", utxo_script_unspendable(s, 80) == 0, "");
        memset(s, 0x51, sizeof s);
        ok_("IsUnspendable(len == MAX_SCRIPT_SIZE) == 0",
            utxo_script_unspendable(s, MAX_SCRIPT_SIZE) == 0, "");
        ok_("IsUnspendable(len == MAX_SCRIPT_SIZE+1) == 1",
            utxo_script_unspendable(s, MAX_SCRIPT_SIZE + 1) == 1, "");
    }

    /* ---- 2. build a set spread over runs, memtable and tombstones ---- */
    build_scripts();
    void* blob = malloc(BLOB);
    void* u = malloc(40 + (u64)SLOTS * 48 + 8);
    struct LST lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = OP_THRESHOLD;
    lst.fill_threshold = FILL_THRESHOLD;
    lst.tomb_buf = malloc(TOMB_CAP * 36);
    lst.tomb_cap = TOMB_CAP;
    lst.manifest_buf = malloc(MANIFEST_CAP * 16);
    lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = malloc(SCRATCH_CAP);
    lst.scratch_cap = SCRATCH_CAP;
    utxo_init(u, SLOTS, blob, BLOB);
    if (utxo_lsm_init(&lst) != 1) { printf("FAIL: utxo_lsm_init\n"); return 1; }

    for (int i = 0; i < N; i++) {
        make_txid(model[i].txid, (unsigned)i);
        /* Indices deliberately span the 256 boundary: our key comparator
         * orders them by little-endian BYTES, so 256 sorts before 1. */
        model[i].index = (unsigned)((i % 3 == 0) ? (256 + i) : (i % 7));
        model[i].value = 1000ULL * (u64)(i + 1) + (u64)(i % 13);
        model[i].height = (unsigned long)(100 + i);
        model[i].coinbase = (unsigned long)(i % 11 == 0);
        model[i].live = 1;
        if (utxo_lsm_put(&lst, u, model[i].txid, model[i].index, model[i].value,
                         model[i].height, model[i].coinbase,
                         model[i].script, model[i].slen) < 0) {
            printf("FAIL: utxo_lsm_put(%d)\n", i);
            return 1;
        }
    }
    /* Spend a scattering, including some that by now live only in old runs. */
    for (int i = 5; i < N; i += 23) {
        if (utxo_lsm_del(&lst, u, model[i].txid, model[i].index) < 0) {
            printf("FAIL: utxo_lsm_del(%d)\n", i);
            return 1;
        }
        model[i].live = 0;
    }

    /* ---- 3. the walk must reproduce the model exactly ---- */
    stats_t st;
    memset(&st, 0, sizeof st);
    utxo_stats_init(&st, 1, 0);
    long walked = utxo_lsm_walk(&lst, u, (void*)utxo_stats_add, &st);
    utxo_stats_finalize(&st);

    agg ref;
    model_agg(&ref, PERT_NONE, -1);

    ok_("utxo_lsm_walk returned a live count", walked >= 0, "");
    cku("walk live count == model live count", (u64)walked, ref.raw);
    cku("raw_txouts", st.raw_txouts, ref.raw);
    cku("txouts (Core-comparable, unspendables filtered)", st.txouts, ref.txouts);
    cku("total_amount", st.total_amount, ref.amount);
    cku("bogosize", st.bogosize, ref.bogosize);
    cku("unspendable_txouts", st.unspendable_txouts, ref.unsp_n);
    cku("unspendable_amount", st.unspendable_amount, ref.unsp_amt);
    ok_("muhash == independently-modelled hash (inserted in reverse order)",
        memcmp(st.muhash, ref.hash, 32) == 0, "");
    ok_("the filter actually removed something (else this proves nothing)",
        ref.unsp_n > 0, "");
    ok_("some entries carry index >= 256 (the comparator-order trap)",
        model[0].index >= 256, "");

    /* ---- 4. NEGATIVE CONTROLS: the hash must move when the set does ---- */
    {
        static const struct { pert p; const char* name; int which; } cases[] = {
            { PERT_VALUE,       "one satoshi changed",           7 },
            { PERT_SCRIPT_BYTE, "one script byte flipped",       7 },
            { PERT_SCRIPT_LEN,  "one script one byte longer",    7 },
            { PERT_HEIGHT,      "one entry's height changed",    7 },
            { PERT_COINBASE,    "one entry's coinbase flag flipped", 7 },
            { PERT_DROP,        "one entry removed",             7 },
            { PERT_ADD,         "one entry added",              -1 },
        };
        for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
            agg bad;
            model_agg(&bad, cases[k].p, cases[k].which);
            char b[160];
            snprintf(b, sizeof b, " (%s)", cases[k].name);
            ok_("negative control: set hash DIVERGES", memcmp(st.muhash, bad.hash, 32) != 0, b);
        }
        /* And the control on the control: re-running the unperturbed model
         * must still agree, so a hash that diverged from everything (a broken
         * comparison) would be caught too. */
        agg again;
        model_agg(&again, PERT_NONE, -1);
        ok_("control: unperturbed model still matches", memcmp(st.muhash, again.hash, 32) == 0, "");
    }

    /* ---- 5. read-only reload reproduces it, and writes nothing ---- */
    utxo_lsm_close(&lst);
    /* utxo.idx is the (optional) checkpoint file; the write path created it.
     * Remove it so the next assertion is about what the READ-ONLY path does,
     * not about what the write path left behind -- a real datadir may or may
     * not have one, and the read-only path must create it in neither case. */
    unlink("utxo.idx");

    dirfp before, after;
    char why[128] = "";
    dirfp_take(&before);

    struct LST ro;
    memset(&ro, 0, sizeof ro);
    ro.op_threshold = OP_THRESHOLD;
    ro.fill_threshold = FILL_THRESHOLD;
    ro.tomb_buf = malloc(TOMB_CAP * 36);
    ro.tomb_cap = TOMB_CAP;
    ro.manifest_buf = malloc(MANIFEST_CAP * 16);
    ro.manifest_cap = MANIFEST_CAP;
    ro.scratch_buf = malloc(SCRATCH_CAP);
    ro.scratch_cap = SCRATCH_CAP;
    void* u2 = malloc(40 + (u64)SLOTS * 48 + 8);
    void* blob2 = malloc(BLOB);
    utxo_init(u2, SLOTS, blob2, BLOB);
    long rr = utxo_lsm_reload_ro(&ro, u2);
    ok_("utxo_lsm_reload_ro succeeded", rr >= 0, "");

    stats_t st2;
    memset(&st2, 0, sizeof st2);
    utxo_stats_init(&st2, 1, 0);
    long walked2 = utxo_lsm_walk(&ro, u2, (void*)utxo_stats_add, &st2);
    utxo_stats_finalize(&st2);

    cku("read-only reload: walk count", (u64)walked2, (u64)walked);
    cku("read-only reload: txouts", st2.txouts, st.txouts);
    cku("read-only reload: total_amount", st2.total_amount, st.total_amount);
    cku("read-only reload: bogosize", st2.bogosize, st.bogosize);
    ok_("read-only reload: identical set hash", memcmp(st2.muhash, st.muhash, 32) == 0, "");
    cku("read-only reload: utxo_lsm_count agrees with the walk",
        (u64)utxo_lsm_count(&ro), (u64)walked2);

    dirfp_take(&after);
    ok_("read-only reload wrote NOTHING to the datadir",
        dirfp_same(&before, &after, why, sizeof why), why[0] ? why : "");
    {
        struct stat sb;
        ok_("read-only reload did not create utxo.idx", stat("utxo.idx", &sb) != 0, "");
    }

    if (fails) { printf("\ntest_utxo_setinfo: %d FAILURES\n", fails); return 1; }
    printf("\ntest_utxo_setinfo: all checks passed\n");
    return 0;
}
