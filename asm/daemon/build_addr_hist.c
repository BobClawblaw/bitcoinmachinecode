/* daemon/build_addr_hist.c -- build the address history index (addr_hist_fmt.h)
 * from the block archive. Three passes, each bounded by one of 256 buckets:
 *
 *   pass 1  walk every block once. Each standard output -> a FUND event in
 *           its key's bucket (by hash[0]) and an OUTREF (outpoint -> key,
 *           value) in an outpoint bucket (by txid[0]); each input -> a
 *           SPENDREF (outpoint -> spender height/txpos/vin) in the same
 *           outpoint bucketing. Nothing needs the UTXO set.
 *   pass 2  per outpoint bucket: sort OUTREFs and SPENDREFs by outpoint,
 *           merge-join, and each match becomes a SPEND event in its key's
 *           bucket with the spent output's value. The bucket's temp files
 *           are deleted as soon as they are consumed.
 *   pass 3  per key bucket: sort by (key, height, txpos, kind, idx), write
 *           the groups and the sparse index; the header last; rename.
 *
 * Temp space peaks around 700 GB on mainnet (the outpoint buckets carry a
 * 33-byte key per output); the output is about 200 GB. Hours, once.
 *
 * Usage: build_addr_hist <datadir> [to_height]   (run in the chain dir's parent) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include "addr_hist_fmt.h"
#include "addr_index_fmt.h"
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
extern long store_init(void* st); extern void store_reload(void* st); extern void store_rd_init(void* st);
extern long store_read_at(void* st, unsigned long h, void* out, long cap);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
/* RUN MODE (2026-09-16): spends come from UNDO, not from a join over every
 * output in the chain. Undo is kept for every block now (undo_store.h), so a
 * range [from, to] is self-contained: each spent prevout's script and value
 * are in that block's own undo records, and the spender's (txpos, vin) are in
 * the block. That is what lets the daemon build this index in runs behind the
 * applied height during the sync (index_trail.h) instead of once, afterwards,
 * with 700 GB of temp. undo_replay is daemon/undo_log.c's reader. */
typedef int (*undo_cb_t)(void*, const u8*, u32, u64, u32, u8, const u8*, unsigned short);
extern long undo_replay(long height, undo_cb_t cb, void* ctx);
#define NB 256
#define BLOCKBUF (8u << 20)
#pragma pack(push,1)
typedef struct { u8 type; u8 hash[32]; ah_event ev; } krec;                              /* 54 B: a key-bucket record */
typedef struct { u8 txid[32]; u32 vout; u8 type; u8 hash[32]; u64 value; } outref;      /* 77 B */
typedef struct { u8 txid[32]; u32 vout; u32 height; u32 txpos; u32 vin; } spendref;      /* 48 B */
#pragma pack(pop)
static FILE* kb[NB]; static FILE* ob[NB]; static FILE* sb_[NB];
static int g_run_mode;                       /* [from,to] with undo: no outref/spendref join */
typedef struct { u8 prevout[36]; u32 txpos, vin; } run_in_t;
static run_in_t* g_ins; static long g_nins, g_inscap; static u32 g_run_height;
static u64 n_fund, n_out, n_spendref, n_spend, n_unmatched;
static char* nm(char* b, const char* pfx, int i){ sprintf(b, "%s_b%03d.tmp", pfx, i); return b; }
static u64 rdvi(const u8* p, const u8* end, u64* used){
    if (p >= end){ *used = 0; return 0; }
    if (p[0] < 0xfd){ *used = 1; return p[0]; }
    if (p[0] == 0xfd){ if (p + 3 > end){ *used = 0; return 0; } *used = 3; return p[1] | ((u64)p[2] << 8); }
    if (p[0] == 0xfe){ if (p + 5 > end){ *used = 0; return 0; } *used = 5; u32 v; memcpy(&v, p + 1, 4); return v; }
    if (p + 9 > end){ *used = 0; return 0; } *used = 9; u64 v; memcpy(&v, p + 1, 8); return v;
}
/* walk one block; 0 on a malformed block */
static int walk_block(const u8* blk, long blen, u32 height, u8* scratch){
    const u8* p = blk + 80; const u8* end = blk + blen; u64 c;
    u64 ntx = rdvi(p, end, &c); if (!c) return 0; p += c;
    for (u64 t = 0; t < ntx; t++){
        const u8* s = p; if (p + 4 > end) return 0; p += 4;
        int segwit = 0; if (p + 2 <= end && p[0] == 0 && p[1] == 1){ segwit = 1; p += 2; }
        u64 nin = rdvi(p, end, &c); if (!c) return 0; p += c;
        const u8* ins = p;
        for (u64 i = 0; i < nin; i++){
            if (p + 36 > end) return 0;
            p += 36;
            u64 sl = rdvi(p, end, &c); if (!c) return 0; p += c + sl; if (p + 4 > end) return 0; p += 4;
        }
        u64 nout = rdvi(p, end, &c); if (!c) return 0; p += c;
        const u8* outs = p;
        for (u64 o = 0; o < nout; o++){
            if (p + 8 > end) return 0;
            p += 8;
            u64 sl = rdvi(p, end, &c); if (!c) return 0; p += c + sl; if (p > end) return 0;
        }
        if (segwit){ for (u64 i = 0; i < nin; i++){ u64 ni = rdvi(p, end, &c); if (!c) return 0;
        p += c;
                for (u64 k = 0; k < ni; k++){ u64 il = rdvi(p, end, &c); if (!c) return 0; p += c + il; if (p > end) return 0; } } }
        if (p + 4 > end) return 0;
        p += 4;
        long tlen = p - s;
        u8 txid[32]; if (tx_txid(txid, s, (unsigned long)tlen, scratch, BLOCKBUF) != 1) return 0;
        /* outputs */
        const u8* q = outs;
        for (u64 o = 0; o < nout; o++){
            u64 value; memcpy(&value, q, 8); q += 8; u64 sl = rdvi(q, end, &c); q += c;
            u8 hash[32]; int type = axf_classify(q, (u32)sl, hash); q += sl;
            if (type != AXF_INVALID){
                krec k; k.type = (u8)type; memcpy(k.hash, hash, 32); k.ev.kind = AH_FUND; k.ev.height = height; k.ev.txpos = (u32)t; k.ev.idx = (u32)o; k.ev.value = value;
                fwrite(&k, 1, sizeof k, kb[hash[0]]); n_fund++;
                if (!g_run_mode){
                    outref r; memcpy(r.txid, txid, 32); r.vout = (u32)o; r.type = (u8)type; memcpy(r.hash, hash, 32); r.value = value;
                    fwrite(&r, 1, sizeof r, ob[txid[0]]); n_out++; }
            }
        }
        /* inputs (not the coinbase's) */
        if (t > 0){ q = ins;
            for (u64 i = 0; i < nin; i++){
                if (g_run_mode){
                    if (g_nins == g_inscap){ g_inscap = g_inscap ? g_inscap * 2 : 4096; g_ins = realloc(g_ins, (size_t)g_inscap * sizeof *g_ins); if (!g_ins){ fprintf(stderr, "oom\n"); exit(1); } }
                    memcpy(g_ins[g_nins].prevout, q, 36); g_ins[g_nins].txpos = (u32)t; g_ins[g_nins].vin = (u32)i; g_nins++;
                    q += 36; u64 sl = rdvi(q, end, &c); q += c + sl + 4;
                    continue;
                }
                spendref r; memcpy(r.txid, q, 32); memcpy(&r.vout, q + 32, 4); q += 36; u64 sl = rdvi(q, end, &c); q += c + sl + 4;
                r.height = height; r.txpos = (u32)t; r.vin = (u32)i;
                fwrite(&r, 1, sizeof r, sb_[r.txid[0]]); n_spendref++;
            } }
    }
    return 1;
}
/* run mode: one undo record (a spent prevout, script + value) -> SPEND event
 * for its address, attributed to the spender through the block's input table */
static int run_undo_cb(void* ctx, const u8* txid, u32 index, u64 value, u32 h, u8 coinbase, const u8* script, unsigned short slen){
    (void)ctx; (void)h; (void)coinbase;
    u8 hash[32]; int type = axf_classify(script, slen, hash);
    if (type == AXF_INVALID) return 1;
    u8 want[36]; memcpy(want, txid, 32); for (int i = 0; i < 4; i++) want[32+i] = (u8)(index >> (8*i));
    for (long i = 0; i < g_nins; i++){
        if (memcmp(g_ins[i].prevout, want, 36) == 0){
            krec k; k.type = (u8)type; memcpy(k.hash, hash, 32); k.ev.kind = AH_SPEND; k.ev.height = g_run_height; k.ev.txpos = g_ins[i].txpos; k.ev.idx = g_ins[i].vin; k.ev.value = value;
            fwrite(&k, 1, sizeof k, kb[hash[0]]); n_spend++;
            return 1;
        }
    }
    n_unmatched++;                              /* undo names a prevout the block does not spend: torn/foreign undo */
    return 1;
}
static int cmp_outref(const void* a, const void* b){ int c = memcmp(((const outref*)a)->txid, ((const outref*)b)->txid, 32); if (c) return c; u32 x = ((const outref*)a)->vout, y = ((const outref*)b)->vout; return x < y ? -1 : x > y; }
static int cmp_spendref(const void* a, const void* b){ int c = memcmp(((const spendref*)a)->txid, ((const spendref*)b)->txid, 32); if (c) return c; u32 x = ((const spendref*)a)->vout, y = ((const spendref*)b)->vout; return x < y ? -1 : x > y; }
static int cmp_krec(const void* a, const void* b){ const krec* x = a; const krec* y = b; int c = ah_key_cmp(x->type, x->hash, y->type, y->hash); if (c) return c; return ah_event_cmp(&x->ev, &y->ev); }
static void* load(const char* path, size_t rec, size_t* n){
    struct stat st; if (stat(path, &st) != 0){ *n = 0; return 0; }
    *n = (size_t)st.st_size / rec; if (!*n) return 0;
    void* a = malloc((size_t)st.st_size); if (!a){ fprintf(stderr, "oom loading %s (%lld bytes)\n", path, (long long)st.st_size); exit(1); }
    FILE* f = fopen(path, "rb"); if (!f || fread(a, rec, *n, f) != *n){ fprintf(stderr, "short read %s\n", path); exit(1); } fclose(f);
    return a;
}
int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: build_addr_hist <datadir> [to_height]          (whole chain, outref join)\n"
                                   "       build_addr_hist <datadir> <from> <to> <out>     (a RUN from blocks + undo)\n"); return 2; }
    if (chdir(argv[1])){ perror("chdir"); return 1; }
    static u8 store_buf[4096]; if (store_init(store_buf) != 1){ fprintf(stderr, "store_init failed\n"); return 1; }
    store_reload(store_buf); store_rd_init(store_buf);
    long tip = *(int*)(store_buf + 24);
    long from_h = 0, to_h = argc > 2 ? atol(argv[2]) : tip;
    const char* out_name = AH_FILE; char tmp_name[340];
    if (argc >= 5){ g_run_mode = 1; from_h = atol(argv[2]); to_h = atol(argv[3]); out_name = argv[4]; }
    if (to_h > tip) to_h = tip;
    if (tip < 0){ fprintf(stderr, "empty store\n"); return 1; }
    if (from_h < 0 || to_h < from_h){ fprintf(stderr, "empty height range\n"); return 1; }
    snprintf(tmp_name, sizeof tmp_name, "%s.tmp", out_name);
    fprintf(stderr, "[addrhist] dir=%s tip=%ld range=[%ld,%ld]%s -> %s\n", argv[1], tip, from_h, to_h, g_run_mode ? " (run: spends from undo)" : "", out_name);
    char b[64];
    /* The key buckets feed pass 3 and both modes need them. The outref and
     * spendref buckets belong to the whole-chain JOIN: a run takes its spends
     * from undo and skips pass 2 entirely -- and pass 2 is the only place that
     * unlinks them, so opening them in run mode left 512 empty files behind
     * after every run. Do not create what this mode never writes. */
    for (int i = 0; i < NB; i++){
        kb[i] = fopen(nm(b, "ahk", i), "wb"); if (!kb[i]){ perror("bucket"); return 1; }
        if (!g_run_mode){
            ob[i] = fopen(nm(b, "aho", i), "wb"); sb_[i] = fopen(nm(b, "ahs", i), "wb");
            if (!ob[i] || !sb_[i]){ perror("bucket"); return 1; }
        }
    }
    u8* blockbuf = malloc(BLOCKBUF); u8* scratch = malloc(BLOCKBUF); if (!blockbuf || !scratch){ fprintf(stderr, "oom\n"); return 1; }
    time_t t0 = time(NULL);
    for (long h = from_h; h <= to_h; h++){
        long blen = store_read_at(store_buf, (unsigned long)h, blockbuf, BLOCKBUF);
        if (blen < 81){ fprintf(stderr, "[addrhist] FATAL: block %ld unreadable (%ld)\n", h, blen); return 1; }
        g_nins = 0; g_run_height = (u32)h;
        if (!walk_block(blockbuf, blen, (u32)h, scratch)){ fprintf(stderr, "[addrhist] FATAL: block %ld malformed\n", h); return 1; }
        if (g_run_mode && h > 0){
            /* the block's own spends, from its undo. Fewer undo records than
             * inputs means the undo is missing or short: refuse the run
             * rather than write a history that under-reports spends
             * (addr_index_tail.c's STO-3 argument, applied here). */
            long ur = undo_replay(h, run_undo_cb, 0);
            if (ur < 0 || ur < g_nins){ fprintf(stderr, "[addrhist] FATAL: block %ld: undo has %ld record(s) for %ld input(s) -- run abandoned\n", h, ur, g_nins); return 1; }
        }
        if (h % 20000 == 0) fprintf(stderr, "[addrhist] pass1 %ld/%ld (%llu funds, %llu spendrefs, %llds)\n", h, to_h, (unsigned long long)n_fund, (unsigned long long)n_spendref, (long long)(time(NULL) - t0));
    }
    if (!g_run_mode) for (int i = 0; i < NB; i++){ fclose(ob[i]); fclose(sb_[i]); }
    fprintf(stderr, "[addrhist] pass1 done: %llu funds, %llu spendrefs, %llds\n", (unsigned long long)n_fund, (unsigned long long)n_spendref, (long long)(time(NULL) - t0));
    /* pass 2: join (whole-chain mode only; a run got its spends from undo) */
    for (int i = 0; i < NB && !g_run_mode; i++){
        size_t no, ns; outref* o = load(nm(b, "aho", i), sizeof(outref), &no); spendref* s = load(nm(b, "ahs", i), sizeof(spendref), &ns);
        if (o) qsort(o, no, sizeof(outref), cmp_outref);
        if (s) qsort(s, ns, sizeof(spendref), cmp_spendref);
        size_t oi = 0;
        for (size_t si = 0; si < ns; si++){
            while (oi < no && cmp_outref(&o[oi], (outref*)&s[si]) < 0) oi++;   /* outref and spendref share the (txid, vout) prefix layout */
            if (oi < no && memcmp(o[oi].txid, s[si].txid, 32) == 0 && o[oi].vout == s[si].vout){
                krec k; k.type = o[oi].type; memcpy(k.hash, o[oi].hash, 32); k.ev.kind = AH_SPEND; k.ev.height = s[si].height; k.ev.txpos = s[si].txpos; k.ev.idx = s[si].vin; k.ev.value = o[oi].value;
                fwrite(&k, 1, sizeof k, kb[k.hash[0]]); n_spend++;
            } else n_unmatched++;
        }
        free(o); free(s); unlink(nm(b, "aho", i)); unlink(nm(b, "ahs", i));
        if (i % 32 == 0) fprintf(stderr, "[addrhist] pass2 bucket %d/%d (%llu spends, %llu unmatched, %llds)\n", i, NB, (unsigned long long)n_spend, (unsigned long long)n_unmatched, (long long)(time(NULL) - t0));
    }
    for (int i = 0; i < NB; i++) fclose(kb[i]);
    fprintf(stderr, "[addrhist] pass2 done: %llu spends, %llu unmatched (non-standard prevouts are expected here), %llds\n", (unsigned long long)n_spend, (unsigned long long)n_unmatched, (long long)(time(NULL) - t0));
    /* pass 3: groups */
    FILE* out = fopen(tmp_name, "wb"); if (!out){ perror("open output"); return 1; }
    ah_header hd; memset(&hd, 0, sizeof hd); hd.magic = AH_MAGIC; hd.version = AH_VERSION; hd.to_height = (u32)to_h; hd.pad = (u32)from_h; hd.body_off = AH_HDR_BYTES;
    u8 zero[AH_HDR_BYTES] = {0}; fwrite(zero, 1, AH_HDR_BYTES, out);
    size_t sp_cap = 1 << 16, sp_n = 0; ah_sparse* sp = malloc(sp_cap * sizeof *sp); u64 body = 0, groups = 0;
    for (int i = 0; i < NB; i++){
        size_t n; krec* k = load(nm(b, "ahk", i), sizeof(krec), &n);
        if (k) qsort(k, n, sizeof(krec), cmp_krec);
        size_t j = 0;
        while (j < n){
            size_t e = j; while (e < n && ah_key_cmp(k[e].type, k[e].hash, k[j].type, k[j].hash) == 0) e++;
            if (groups % AH_SPARSE_STRIDE == 0){ if (sp_n == sp_cap){ sp_cap *= 2; sp = realloc(sp, sp_cap * sizeof *sp); } sp[sp_n].type = k[j].type; memcpy(sp[sp_n].hash, k[j].hash, 32); sp[sp_n].off = body; sp_n++; }
            ah_group_hdr gh; gh.type = k[j].type; memcpy(gh.hash, k[j].hash, 32); gh.n = (u32)(e - j);
            fwrite(&gh, 1, AH_GROUP_HDR, out); body += AH_GROUP_HDR;
            for (size_t x = j; x < e; x++){ fwrite(&k[x].ev, 1, AH_EVENT_BYTES, out); body += AH_EVENT_BYTES; }
            hd.n_events += e - j; groups++; j = e;
        }
        free(k); unlink(nm(b, "ahk", i));
        if (i % 32 == 0) fprintf(stderr, "[addrhist] pass3 bucket %d/%d (%llu keys, %llds)\n", i, NB, (unsigned long long)groups, (long long)(time(NULL) - t0));
    }
    hd.n_keys = groups; hd.body_len = body; hd.sparse_off = AH_HDR_BYTES + body; hd.sparse_n = sp_n;
    fwrite(sp, AH_SPARSE_BYTES, sp_n, out);
    if (fflush(out) != 0 || fseek(out, 0, SEEK_SET) != 0 || fwrite(&hd, 1, sizeof hd, out) != sizeof hd || fflush(out) != 0 || fsync(fileno(out)) != 0){ perror("write header"); return 1; }
    fclose(out);
    if (rename(tmp_name, out_name)){ perror("rename"); return 1; }
    fprintf(stderr, "[addrhist] DONE: %llu keys, %llu events (%llu funds, %llu spends), to height %ld, %.2f GB, %llds\n",
            (unsigned long long)groups, (unsigned long long)hd.n_events, (unsigned long long)n_fund, (unsigned long long)n_spend, to_h, (double)(hd.sparse_off + sp_n * AH_SPARSE_BYTES) / 1e9, (long long)(time(NULL) - t0));
    return 0;
}
