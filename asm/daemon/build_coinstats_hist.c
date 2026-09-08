/* daemon/build_coinstats_hist.c -- the coinstats index's history: one row per
 * height from genesis, built from the block archive alone.
 *
 * The live index (daemon/coinstats_index.c) writes a row per applied block
 * from the height it was seeded at. This tool fills the rows below that, so
 * gettxoutsetinfo answers at any height -- 963,967 included -- with the same
 * numbers Core's coinstatsindex holds. It needs no UTXO set: every coin's
 * life is in the archive, and a spend's prevout is found by joining spends
 * to outputs on the outpoint, the address history builder's technique.
 *
 * The MuHash at a height is the product over the coins in the set of
 * H(coin). Products commute, so each block's product over the coins it
 * CREATES (its additions) and, separately, over the coins it SPENDS (its
 * removals) is computed on its own, in parallel across height ranges, with
 * the same primitive the live fold uses (utxo_stats_add: Core's compressed
 * coin serialization, proven byte-identical at the parity capstone). A
 * final sequential pass multiplies the block products into a running
 * numerator and denominator -- exactly the live index's two accumulators --
 * and writes each height's row: counters, both accumulators, and the
 * cumulative per-block amounts Core's index keeps.
 *
 * Core's rules that shape the set, applied where the live path applies
 * them: the genesis coinbase never enters the set (its subsidy is
 * unspendables.genesis_block); the two BIP30 duplicate coinbases (91,842 and
 * 91,880, mainnet) are skipped (their subsidy is unspendables.bip30) and a
 * spend of one of those txids removes the ORIGINAL coin with its original
 * height, which is what the join produces; a provably unspendable output
 * (OP_RETURN, or over MAX_SCRIPT_SIZE) never enters the set and counts as
 * unspendables.scripts. utxo_stats_add applies that filter itself.
 *
 *   pass 1  W workers, each a height range: walk the blocks, fold each
 *           block's spendable outputs into a fresh stats object -> the
 *           block's ADD product + counters + coinbase/new-output/script
 *           amounts (addprod.tmp, one 448 B record per height); write every
 *           spendable output as an OUTREF (outpoint -> coin) and every
 *           non-coinbase input as a SPENDREF (outpoint -> spend height) into
 *           buckets by txid[0].
 *   pass 2  W workers, each a set of buckets: sort both sides, join on the
 *           outpoint, emit a REMOVE event (spend height, the original coin)
 *           into buckets by spend-height range. Unmatched spends are a
 *           FATAL inconsistency (the archive contradicts itself).
 *   pass 3  W workers, each a spend-height range: sort by height, fold each
 *           height's removed coins into a fresh stats object -> the block's
 *           REMOVE product + counters + prevout_spent (remprod.tmp).
 *   pass 4  one process: the prefix products and the rows.
 *
 * Usage: bmc_build_coinstats_hist <chaindir> [to_height] [workers]
 * Disk: ~500 GB of temporary files beside the archive at the mainnet tip,
 * deleted as they are consumed. Time on the reference box: ~2 h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "coinstats_hist_fmt.h"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
extern long store_init(void* st);
extern void store_reload(void* st);
extern void store_rd_init(void* st);
extern long store_read_at(void* st, unsigned long h, void* buf, unsigned long cap);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
extern void utxo_stats_init(void* st, unsigned long want_muhash, unsigned long excl_genesis);
extern void utxo_stats_add(void* st, const u8* key36, u64 value, u64 code, const u8* script, unsigned long slen);
extern void num3072_mul(void* a, const void* b);
extern void sha256_full(u8 out[32], const void* msg, long len);
#define ST_SIZE 512
#define ST_TXOUTS 0
#define ST_AMOUNT 8
#define ST_BOGO 16
#define ST_ACC 96
#define BLOCKBUF (4u << 20)
#define NB 256                       /* outpoint buckets by txid[0] */
#define NR 64                        /* spend-height ranges */
static u64 st_get(const u8* st, int off){ u64 v; memcpy(&v, st + off, 8); return v; }
/* per-height block products (pass 1 and pass 3 outputs) */
typedef struct __attribute__((packed)) { u8 acc[384]; u64 txouts, amount, bogo; u64 a1, a2, a3; } prod_t;   /* add: a1=coinbase a2=new_ex_cb a3=scripts; remove: a1=prevout_spent */
#define PROD_REC sizeof(prod_t)
/* refs and events */
typedef struct __attribute__((packed)) { u8 txid[32]; u32 vout; u64 value; u32 height; u8 cb; u16 slen; } outref_hdr;   /* followed by slen script bytes */
typedef struct __attribute__((packed)) { u8 txid[32]; u32 vout; u32 spend_h; } spendref;
typedef struct __attribute__((packed)) { u32 spend_h; u8 txid[32]; u32 vout; u64 value; u32 height; u8 cb; u16 slen; } remev_hdr;  /* followed by the script */
static long g_halving = 210000; static int g_mainnet = 1;
static u64 subsidy_at(long h){ long k = h / g_halving; return k >= 64 ? 0 : (5000000000ULL >> k); }
static int bip30_height(long h){ return g_mainnet && (h == 91842 || h == 91880); }
static int script_unspendable(const u8* s, unsigned long n){ return (n > 0 && s[0] == 0x6a) || n > 10000; }
static u64 rdvi(const u8* p, const u8* end, u64* used){
    if (p >= end){ *used = 0; return 0; }
    if (p[0] < 0xfd){ *used = 1; return p[0]; }
    if (p[0] == 0xfd){ if (p + 3 > end){ *used = 0; return 0; } *used = 3; return p[1] | ((u64)p[2] << 8); }
    if (p[0] == 0xfe){ if (p + 5 > end){ *used = 0; return 0; } *used = 5; u32 v; memcpy(&v, p + 1, 4); return v; }
    if (p + 9 > end){ *used = 0; return 0; } *used = 9; u64 v; memcpy(&v, p + 1, 8); return v;
}
static char* nm(char* b, const char* pfx, int w, int i){ sprintf(b, "csh_%s_w%02d_%03d.tmp", pfx, w, i); return b; }
static void die(const char* m){ fprintf(stderr, "[coinstats-hist] FATAL: %s\n", m); exit(1); }

/* ---- pass 1: one worker over [lo, hi] ------------------------------------------ */
static int pass1_worker(int w, long lo, long hi, u8* store_buf, int addprod_fd){
    char b[64]; FILE* ob[NB]; FILE* sb[NB];
    for (int i = 0; i < NB; i++){ ob[i] = fopen(nm(b, "o", w, i), "wb"); sb[i] = fopen(nm(b, "s", w, i), "wb"); if (!ob[i] || !sb[i]) die("open bucket"); }
    u8* blockbuf = malloc(BLOCKBUF); u8* scratch = malloc(BLOCKBUF); static u8 add_st[ST_SIZE] __attribute__((aligned(16)));
    if (!blockbuf || !scratch) die("oom");
    time_t t0 = time(NULL);
    for (long h = lo; h <= hi; h++){
        long blen = store_read_at(store_buf, (unsigned long)h, blockbuf, BLOCKBUF);
        if (blen < 81){ fprintf(stderr, "[coinstats-hist] FATAL: block %ld unreadable (%ld)\n", h, blen); return 1; }
        utxo_stats_init(add_st, 1, 0); u64 cb_amt = 0, newcb = 0, scripts = 0;
        const u8* p = blockbuf + 80; const u8* end = blockbuf + blen; u64 c;
        u64 ntx = rdvi(p, end, &c); if (!c) die("malformed block"); p += c;
        for (u64 t = 0; t < ntx; t++){
            const u8* s = p; if (p + 4 > end) die("malformed tx"); p += 4;
            int segwit = 0; if (p + 2 <= end && p[0] == 0 && p[1] == 1){ segwit = 1; p += 2; }
            u64 nin = rdvi(p, end, &c); if (!c) die("malformed tx"); p += c;
            const u8* ins = p;
            for (u64 i = 0; i < nin; i++){ if (p + 36 > end) die("malformed tx"); p += 36; u64 sl = rdvi(p, end, &c); if (!c) die("malformed tx"); p += c + sl; if (p + 4 > end) die("malformed tx"); p += 4; }
            u64 nout = rdvi(p, end, &c); if (!c) die("malformed tx"); p += c;
            const u8* outs = p;
            for (u64 o = 0; o < nout; o++){ if (p + 8 > end) die("malformed tx"); p += 8; u64 sl = rdvi(p, end, &c); if (!c) die("malformed tx"); p += c + sl; if (p > end) die("malformed tx"); }
            if (segwit){ for (u64 i = 0; i < nin; i++){ u64 ni = rdvi(p, end, &c); if (!c) die("malformed tx");
            p += c; for (u64 k = 0; k < ni; k++){ u64 il = rdvi(p, end, &c); if (!c) die("malformed tx"); p += c + il; if (p > end) die("malformed tx"); } } }
            if (p + 4 > end) die("malformed tx");
            p += 4;
            long tlen = p - s; u8 txid[32]; if (tx_txid(txid, s, (unsigned long)tlen, scratch, BLOCKBUF) != 1) die("txid");
            int coinbase = (t == 0);
            int skip_outputs = (h == 0) || (coinbase && bip30_height(h));   /* genesis; BIP30 duplicates: never in the set */
            const u8* q = outs;
            for (u64 o = 0; o < nout; o++){
                u64 value; memcpy(&value, q, 8); q += 8; u64 sl = rdvi(q, end, &c); q += c; const u8* script = q; q += sl;
                if (skip_outputs) continue;
                if (script_unspendable(script, sl)){ scripts += value; continue; }
                u8 key[36]; memcpy(key, txid, 32); u32 vo = (u32)o; memcpy(key + 32, &vo, 4);
                utxo_stats_add(add_st, key, value, ((u64)h << 1) | (u64)coinbase, script, sl);
                if (coinbase) cb_amt += value;
                else newcb += value;
                outref_hdr r; memcpy(r.txid, txid, 32); r.vout = vo; r.value = value; r.height = (u32)h; r.cb = (u8)coinbase; r.slen = (u16)sl;
                fwrite(&r, 1, sizeof r, ob[txid[0]]); fwrite(script, 1, sl, ob[txid[0]]);
            }
            if (!coinbase){
                const u8* q2 = ins;
                for (u64 i = 0; i < nin; i++){ spendref sr; memcpy(sr.txid, q2, 32); memcpy(&sr.vout, q2 + 32, 4); sr.spend_h = (u32)h; fwrite(&sr, 1, sizeof sr, sb[sr.txid[0]]);
                    q2 += 36; u64 sl = rdvi(q2, end, &c); q2 += c + sl + 4; }
            }
        }
        prod_t pr; memcpy(pr.acc, add_st + ST_ACC, 384); pr.txouts = st_get(add_st, ST_TXOUTS); pr.amount = st_get(add_st, ST_AMOUNT); pr.bogo = st_get(add_st, ST_BOGO); pr.a1 = cb_amt; pr.a2 = newcb; pr.a3 = scripts;
        if (pwrite(addprod_fd, &pr, PROD_REC, (off_t)h * PROD_REC) != (ssize_t)PROD_REC) die("addprod write");
        if ((h - lo) % 10000 == 0 && h > lo) fprintf(stderr, "[coinstats-hist] pass1 w%d %ld/%ld (%llds)\n", w, h, hi, (long long)(time(NULL) - t0));
    }
    for (int i = 0; i < NB; i++){ fclose(ob[i]); fclose(sb[i]); }
    return 0;
}
/* ---- pass 2: the join for a bucket ----------------------------------------- */
static u8* load_all(const char* pfx, int W, int i, size_t* len){
    char b[64]; size_t total = 0; for (int w = 0; w < W; w++){ struct stat st; if (stat(nm(b, pfx, w, i), &st) == 0) total += (size_t)st.st_size; }
    u8* a = malloc(total + 1); if (!a) die("oom join"); size_t off = 0;
    for (int w = 0; w < W; w++){ FILE* f = fopen(nm(b, pfx, w, i), "rb"); if (!f) continue; struct stat st; fstat(fileno(f), &st); if (fread(a + off, 1, (size_t)st.st_size, f) != (size_t)st.st_size) die("short read"); off += (size_t)st.st_size; fclose(f); unlink(nm(b, pfx, w, i)); }
    *len = off; return a;
}
typedef struct { const u8* p; } oidx;   /* pointer to an outref_hdr in the loaded buffer */
static int cmp_oidx(const void* a, const void* b){ const outref_hdr* x = (const outref_hdr*)((const oidx*)a)->p; const outref_hdr* y = (const outref_hdr*)((const oidx*)b)->p; int c = memcmp(x->txid, y->txid, 32); if (c) return c; return x->vout < y->vout ? -1 : x->vout > y->vout; }
static int cmp_spend(const void* a, const void* b){ const spendref* x = a; const spendref* y = b; int c = memcmp(x->txid, y->txid, 32); if (c) return c; return x->vout < y->vout ? -1 : x->vout > y->vout; }
static int pass2_bucket(int w, int i, int W, long to_h, u64* n_matched, u64* n_unmatched){
    size_t olen, slen; u8* o = load_all("o", W, i, &olen); u8* s = load_all("s", W, i, &slen);
    size_t no = 0; for (size_t p = 0; p + sizeof(outref_hdr) <= olen; ){ const outref_hdr* r = (const outref_hdr*)(o + p); p += sizeof *r + r->slen; no++; }
    oidx* ix = malloc((no + 1) * sizeof *ix); if (!ix) die("oom idx"); size_t k = 0;
    for (size_t p = 0; p + sizeof(outref_hdr) <= olen; ){ const outref_hdr* r = (const outref_hdr*)(o + p); ix[k++].p = o + p; p += sizeof *r + r->slen; }
    qsort(ix, no, sizeof *ix, cmp_oidx);
    size_t ns = slen / sizeof(spendref); spendref* sp = (spendref*)s; qsort(sp, ns, sizeof *sp, cmp_spend);
    char b[64]; FILE* rf[NR]; for (int r = 0; r < NR; r++){ rf[r] = fopen(nm(b, "r", w, r), "ab"); if (!rf[r]) die("open range"); }
    size_t a = 0;
    for (size_t j = 0; j < ns; j++){
        while (a < no){ const outref_hdr* r = (const outref_hdr*)ix[a].p; int c = memcmp(r->txid, sp[j].txid, 32); if (c < 0 || (c == 0 && r->vout < sp[j].vout)) a++; else break; }
        const outref_hdr* r = a < no ? (const outref_hdr*)ix[a].p : 0;
        if (!r || memcmp(r->txid, sp[j].txid, 32) != 0 || r->vout != sp[j].vout){ (*n_unmatched)++; continue; }
        remev_hdr e; e.spend_h = sp[j].spend_h; memcpy(e.txid, r->txid, 32); e.vout = r->vout; e.value = r->value; e.height = r->height; e.cb = r->cb; e.slen = r->slen;
        int range = (int)((long)e.spend_h * NR / (to_h + 1)); if (range >= NR) range = NR - 1;
        fwrite(&e, 1, sizeof e, rf[range]); fwrite((const u8*)r + sizeof *r, 1, r->slen, rf[range]); (*n_matched)++;
    }
    for (int r = 0; r < NR; r++) fclose(rf[r]);
    free(ix); free(o); free(s); return 0;
}
/* ---- pass 3: the remove products for a range ------------------------------------- */
typedef struct { const u8* p; } eidx;
static int cmp_eidx(const void* a, const void* b){ u32 x = ((const remev_hdr*)((const eidx*)a)->p)->spend_h, y = ((const remev_hdr*)((const eidx*)b)->p)->spend_h; return x < y ? -1 : x > y; }
static int pass3_range(int r, int W, int remprod_fd){
    size_t elen; u8* e = load_all("r", W, r, &elen);
    size_t ne = 0; for (size_t p = 0; p + sizeof(remev_hdr) <= elen; ){ const remev_hdr* h = (const remev_hdr*)(e + p); p += sizeof *h + h->slen; ne++; }
    eidx* ix = malloc((ne + 1) * sizeof *ix); if (!ix) die("oom eidx"); size_t k = 0;
    for (size_t p = 0; p + sizeof(remev_hdr) <= elen; ){ const remev_hdr* h = (const remev_hdr*)(e + p); ix[k++].p = e + p; p += sizeof *h + h->slen; }
    qsort(ix, ne, sizeof *ix, cmp_eidx);
    static u8 rem_st[ST_SIZE] __attribute__((aligned(16)));
    size_t i = 0;
    while (i < ne){
        u32 h = ((const remev_hdr*)ix[i].p)->spend_h; utxo_stats_init(rem_st, 1, 0); u64 prevout = 0;
        for (; i < ne && ((const remev_hdr*)ix[i].p)->spend_h == h; i++){
            const remev_hdr* ev = (const remev_hdr*)ix[i].p; u8 key[36]; memcpy(key, ev->txid, 32); memcpy(key + 32, &ev->vout, 4);
            utxo_stats_add(rem_st, key, ev->value, ((u64)ev->height << 1) | (u64)ev->cb, (const u8*)ev + sizeof *ev, ev->slen); prevout += ev->value;
        }
        prod_t pr; memcpy(pr.acc, rem_st + ST_ACC, 384); pr.txouts = st_get(rem_st, ST_TXOUTS); pr.amount = st_get(rem_st, ST_AMOUNT); pr.bogo = st_get(rem_st, ST_BOGO); pr.a1 = prevout; pr.a2 = 0; pr.a3 = 0;
        if (pwrite(remprod_fd, &pr, PROD_REC, (off_t)h * PROD_REC) != (ssize_t)PROD_REC) die("remprod write");
    }
    free(ix); free(e); return 0;
}
/* ---- pass 4: the prefix and the rows ------------------------------------------- */
static int pass4(long to_h, int addprod_fd, int remprod_fd){
    int fd = open(CSH_FILE, O_RDWR | O_CREAT, 0644); if (fd < 0) die("open " CSH_FILE);
    csh_header_t hd; memset(&hd, 0, sizeof hd);
    if (pread(fd, &hd, sizeof hd, 0) != (ssize_t)sizeof hd || hd.magic != CSH_MAGIC || hd.rec != CSH_REC){ memset(&hd, 0, sizeof hd); hd.magic = CSH_MAGIC; hd.version = 1; hd.rec = CSH_REC; hd.gen = 0; hd.first_height = -1; hd.last_height = -1; }
    static u8 num[ST_SIZE] __attribute__((aligned(16))), den[ST_SIZE] __attribute__((aligned(16)));
    utxo_stats_init(num, 1, 0); utxo_stats_init(den, 1, 0);
    u64 txouts = 0, amount = 0, bogo = 0, prevout = 0, coinbase = 0, newcb = 0, scripts = 0, genesis = 0, bip30 = 0, subsidy = 0;
    time_t t0 = time(NULL);
    for (long h = 0; h <= to_h; h++){
        prod_t a, r; int have_a = pread(addprod_fd, &a, PROD_REC, (off_t)h * PROD_REC) == (ssize_t)PROD_REC; int have_r = pread(remprod_fd, &r, PROD_REC, (off_t)h * PROD_REC) == (ssize_t)PROD_REC && r.txouts + r.amount + r.a1 + r.bogo != 0;
        if (!have_a) die("addprod row missing");
        { static u8 tmp[384] __attribute__((aligned(16))); memcpy(tmp, a.acc, 384); num3072_mul(num + ST_ACC, tmp); }   /* the products are packed; the multiply wants alignment */
        if (have_r){ static u8 tmp[384] __attribute__((aligned(16))); memcpy(tmp, r.acc, 384); num3072_mul(den + ST_ACC, tmp); }
        txouts += a.txouts; amount += a.amount; bogo += a.bogo; coinbase += a.a1; newcb += a.a2; scripts += a.a3;
        if (have_r){ txouts -= r.txouts; amount -= r.amount; bogo -= r.bogo; prevout += r.a1; }
        u64 sub = subsidy_at(h); subsidy += sub; if (h == 0) genesis += sub; if (bip30_height(h)) bip30 += sub;
        csh_row_t row; memset(&row, 0, sizeof row);
        row.tag = CSH_ROW_TAG; row.gen = 0; row.height = h; row.txouts = txouts; row.amount = amount; row.bogo = bogo;
        row.prevout_spent = prevout; row.coinbase = coinbase; row.new_ex_cb = newcb; row.unsp_scripts = scripts; row.unsp_genesis = genesis; row.unsp_bip30 = bip30; row.subsidy_sum = subsidy;
        memcpy(row.num_acc, num + ST_ACC, 384); memcpy(row.den_acc, den + ST_ACC, 384);
        sha256_full(row.sum, &row, sizeof row - 32);
        if (pwrite(fd, &row, sizeof row, CSH_HDR + (off_t)h * CSH_REC) != (ssize_t)sizeof row) die("row write");
        if (h % 50000 == 0) fprintf(stderr, "[coinstats-hist] pass4 %ld/%ld txouts=%llu (%llds)\n", h, to_h, (unsigned long long)txouts, (long long)(time(NULL) - t0));
    }
    if (pread(fd, &hd, sizeof hd, 0) != (ssize_t)sizeof hd || hd.magic != CSH_MAGIC){ memset(&hd, 0, sizeof hd); hd.magic = CSH_MAGIC; hd.version = 1; hd.rec = CSH_REC; hd.last_height = -1; }   /* re-read: a live daemon may have advanced it */
    hd.first_height = 0; if (hd.last_height < to_h) hd.last_height = to_h;
    if (pwrite(fd, &hd, sizeof hd, 0) != (ssize_t)sizeof hd) die("header write");
    fsync(fd); close(fd);
    fprintf(stderr, "[coinstats-hist] DONE: rows 0..%ld, txouts=%llu amount=%llu.%08llu prevout_spent=%llu coinbase=%llu scripts=%llu subsidy=%llu (%llds)\n", to_h,
            (unsigned long long)txouts, (unsigned long long)(amount / 100000000ULL), (unsigned long long)(amount % 100000000ULL), (unsigned long long)prevout, (unsigned long long)coinbase, (unsigned long long)scripts, (unsigned long long)subsidy, (long long)(time(NULL) - t0));
    return 0;
}
static void run_workers(int W, int (*fn)(int w, void* ctx), void* ctx){
    pid_t pids[64]; for (int w = 0; w < W; w++){ pid_t p = fork(); if (p < 0) die("fork"); if (p == 0) _exit(fn(w, ctx)); pids[w] = p; }
    for (int w = 0; w < W; w++){ int st = 0; waitpid(pids[w], &st, 0); if (!WIFEXITED(st) || WEXITSTATUS(st) != 0){ fprintf(stderr, "[coinstats-hist] worker %d failed\n", w); exit(1); } }
}
typedef struct { long to_h; int W; u8* store_buf; int addprod_fd, remprod_fd; } ctx_t;
static int p1(int w, void* c){ ctx_t* x = c; long n = x->to_h + 1, lo = n * w / x->W, hi = n * (w + 1) / x->W - 1; return pass1_worker(w, lo, hi, x->store_buf, x->addprod_fd); }
static int p2(int w, void* c){ ctx_t* x = c; u64 m = 0, u = 0; for (int i = w; i < NB; i += x->W) pass2_bucket(w, i, x->W, x->to_h, &m, &u);
    fprintf(stderr, "[coinstats-hist] pass2 w%d: %llu spends matched, %llu unmatched\n", w, (unsigned long long)m, (unsigned long long)u); return u ? 3 : 0; }
static int p3(int w, void* c){ ctx_t* x = c; for (int r = w; r < NR; r += x->W) pass3_range(r, x->W, x->remprod_fd); return 0; }
int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: bmc_build_coinstats_hist <chaindir> [to_height] [workers]\n"); return 2; }
    if (chdir(argv[1])){ perror("chdir"); return 1; }
    static u8 store_buf[4096]; if (store_init(store_buf) != 1) die("store_init");
    store_reload(store_buf); store_rd_init(store_buf);
    long tip = *(int*)(store_buf + 24); long to_h = argc > 2 ? atol(argv[2]) : tip; if (to_h > tip) to_h = tip;
    int W = argc > 3 ? atoi(argv[3]) : 8; if (W < 1) W = 1; if (W > 64) W = 64;
    { const char* c = getenv("BMC_CHAIN"); if (c && strcmp(c, "main")){ g_mainnet = 0; if (!strcmp(c, "regtest")) g_halving = 150; } }
    if (tip < 0) die("empty store");
    fprintf(stderr, "[coinstats-hist] dir=%s tip=%ld to=%ld workers=%d chain=%s\n", argv[1], tip, to_h, W, g_mainnet ? "main" : "other");
    int addprod_fd = open("csh_addprod.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644), remprod_fd = open("csh_remprod.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (addprod_fd < 0 || remprod_fd < 0) die("open products");
    ctx_t x = { to_h, W, store_buf, addprod_fd, remprod_fd };
    time_t t0 = time(NULL);
    run_workers(W, p1, &x); fprintf(stderr, "[coinstats-hist] pass1 done (%llds)\n", (long long)(time(NULL) - t0));
    run_workers(W, p2, &x); fprintf(stderr, "[coinstats-hist] pass2 done (%llds)\n", (long long)(time(NULL) - t0));
    run_workers(W, p3, &x); fprintf(stderr, "[coinstats-hist] pass3 done (%llds)\n", (long long)(time(NULL) - t0));
    if (pass4(to_h, addprod_fd, remprod_fd) != 0) return 1;
    close(addprod_fd); close(remprod_fd); unlink("csh_addprod.tmp"); unlink("csh_remprod.tmp");
    return 0;
}
