/* daemon/utxo_snapshot_diff.c -- the coin-by-coin comparison of two UTXO
 * snapshots in Core's serialization (dumptxoutset on either node).
 *
 * gettxoutsetinfo's MuHash says whether two sets are equal; this says WHICH
 * coin differs when they are not, so a disagreement is named rather than
 * argued about (2026-10-05, after the logged pair). Both files are what
 * Core's dumptxoutset and this node's write (asm/utxo_snapshot.c):
 *
 *   header: "utxo\xff" | u16 version | net magic (4) | base blockhash (32) |
 *           u64 coin count
 *   coins:  txid (32) | compactsize(n) | n x [ compactsize(vout) |
 *           VARINT(height<<1 | coinbase) | VARINT(CompressAmount(value)) |
 *           compressed scriptPubKey ]
 *
 * The comparison is on the serialized coin: the same bytes on both sides is
 * the same coin (height, coinbase flag, amount, script). Coins are matched
 * by (txid, vout). Both writers emit txids in ascending byte order, and this
 * tool checks that as it reads -- an out-of-order file is refused, never
 * mis-diffed -- while the vouts under one txid are matched as a set, since
 * the two writers may order them differently (Core by LevelDB key, this
 * node by its run key).
 *
 * Usage: bmc_utxo_snapshot_diff <a.dat> <b.dat> [max_reported=50]
 * Exit 0 when the sets are identical (headers included), 1 when they
 * differ, 2 on a malformed file. Every difference is one line:
 *   only-in-A <txid>:<vout> height=H cb=0|1 amount=N script=<hex>
 *   only-in-B ...
 *   differs   <txid>:<vout> A: height=.. amount=.. script=.. | B: ...
 * followed by a summary line. The decoders below follow Core's serialize.h
 * (VARINT) and compressor.cpp (DecompressAmount, script kinds 0..5). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    FILE* f; const char* name;
    unsigned char base[32]; unsigned long long count, read_coins;
    unsigned short version; unsigned char magic[4];
    /* the current txid group */
    unsigned char txid[32]; unsigned long long ngroup, igroup; int have_group, eof;
    unsigned char prev_txid[32]; int have_prev;
} usd_reader;

typedef struct {
    unsigned long long vout, height, amount; int coinbase;
    unsigned char ser[16 + 10000]; unsigned long serlen;   /* the serialized coin (vout..script) */
    unsigned char spk[10000]; unsigned long spklen;          /* the compressed script, for the message */
} usd_coin;

static int rd_u8(usd_reader* r, unsigned char* b){ int c = fgetc(r->f); if (c == EOF) return 0; *b = (unsigned char)c; return 1; }
static int rd_n(usd_reader* r, unsigned char* o, unsigned long n){ return fread(o, 1, n, r->f) == n; }
static int rd_compact(usd_reader* r, unsigned long long* v, unsigned char* ser, unsigned long* sl){
    unsigned char b; if (!rd_u8(r, &b)) return 0; if (ser) ser[(*sl)++] = b;
    if (b < 253){ *v = b; return 1; }
    int n = b == 253 ? 2 : b == 254 ? 4 : 8; unsigned char x[8]; if (!rd_n(r, x, n)) return 0;
    if (ser){ memcpy(ser + *sl, x, n); *sl += n; }
    *v = 0; for (int i = n - 1; i >= 0; i--) *v = (*v << 8) | x[i]; return 1;
}
/* serialize.h VARINT: big-endian base-128, each continuation byte's value is
 * one more than written (the "+1" that makes the encoding unique) */
static int rd_varint(usd_reader* r, unsigned long long* v, unsigned char* ser, unsigned long* sl){
    unsigned long long n = 0; for (int i = 0; i < 10; i++){
        unsigned char b; if (!rd_u8(r, &b)) return 0; if (ser) ser[(*sl)++] = b;
        n = (n << 7) | (b & 0x7f);
        if (b & 0x80) n++; else { *v = n; return 1; }
    }
    return 0;
}
/* compressor.cpp DecompressAmount */
static unsigned long long usd_decompress_amount(unsigned long long x){
    if (x == 0) return 0;
    x--; int e = (int)(x % 10); x /= 10; unsigned long long n;
    if (e < 9){ int d = (int)(x % 9) + 1; x /= 9; n = x * 10 + d; } else n = x + 1;
    while (e){ n *= 10; e--; }
    return n;
}
static int rd_header(usd_reader* r){
    unsigned char m[5]; if (!rd_n(r, m, 5) || memcmp(m, "utxo\xff", 5)) return 0;
    unsigned char v[2]; if (!rd_n(r, v, 2)) return 0; r->version = (unsigned short)(v[0] | (v[1] << 8));
    if (!rd_n(r, r->magic, 4) || !rd_n(r, r->base, 32)) return 0;
    unsigned char c[8]; if (!rd_n(r, c, 8)) return 0; r->count = 0; for (int i = 7; i >= 0; i--) r->count = (r->count << 8) | c[i];
    return 1;
}
/* the next coin, crossing txid groups; 1 = a coin, 0 = clean end, -1 = malformed/out of order */
static int rd_coin(usd_reader* r, usd_coin* c){
    for (;;){
        if (!r->have_group){
            if (r->read_coins >= r->count){ r->eof = 1; return 0; }
            if (!rd_n(r, r->txid, 32)) return -1;
            if (r->have_prev && memcmp(r->txid, r->prev_txid, 32) <= 0){ fprintf(stderr, "%s: txids out of order (or repeated) after coin %llu\n", r->name, r->read_coins); return -1; }
            memcpy(r->prev_txid, r->txid, 32); r->have_prev = 1;
            if (!rd_compact(r, &r->ngroup, 0, 0) || r->ngroup == 0) return -1;
            r->igroup = 0; r->have_group = 1;
        }
        if (r->igroup >= r->ngroup){ r->have_group = 0; continue; }
        c->serlen = 0;
        unsigned long long code, camt;
        if (!rd_compact(r, &c->vout, c->ser, &c->serlen)) return -1;
        if (!rd_varint(r, &code, c->ser, &c->serlen)) return -1;
        if (!rd_varint(r, &camt, c->ser, &c->serlen)) return -1;
        c->height = code >> 1; c->coinbase = (int)(code & 1); c->amount = usd_decompress_amount(camt);
        unsigned long long kind; unsigned long k0 = c->serlen;
        if (!rd_varint(r, &kind, c->ser, &c->serlen)) return -1;
        unsigned long body = kind == 0 || kind == 1 ? 20 : kind <= 5 ? 32 : (unsigned long)(kind - 6);
        if (body > sizeof c->spk - 8 || c->serlen + body > sizeof c->ser) return -1;
        if (!rd_n(r, c->ser + c->serlen, body)) return -1;
        c->serlen += body;
        c->spklen = c->serlen - k0; memcpy(c->spk, c->ser + k0, c->spklen);   /* the compressed form, kind byte(s) included */
        r->igroup++; r->read_coins++;
        return 1;
    }
}
static void hex(const unsigned char* p, unsigned long n, char* o){ static const char* h = "0123456789abcdef"; for (unsigned long i = 0; i < n; i++){ o[2*i] = h[p[i] >> 4]; o[2*i+1] = h[p[i] & 15]; } o[2*n] = 0; }
static void txid_disp(const unsigned char* w, char* o){ unsigned char r[32]; for (int i = 0; i < 32; i++) r[i] = w[31 - i]; hex(r, 32, o); }
static void coin_desc(const usd_coin* c, char* o, unsigned long cap){
    char s[2 * 10008 + 1]; hex(c->spk, c->spklen > 64 ? 64 : c->spklen, s);
    snprintf(o, cap, "height=%llu cb=%d amount=%llu script=%s%s", c->height, c->coinbase, c->amount, s, c->spklen > 64 ? "..." : "");
}

/* one txid group read whole, so the vouts can be matched as a set */
typedef struct { usd_coin* v; unsigned long n, cap; unsigned char txid[32]; int valid; } usd_group;
static int grp_push(usd_group* g, const usd_coin* c){
    if (g->n == g->cap){ unsigned long nc = g->cap ? g->cap * 2 : 8; usd_coin* nv = realloc(g->v, nc * sizeof *nv); if (!nv) return 0; g->v = nv; g->cap = nc; }
    g->v[g->n++] = *c; return 1;
}
/* reads the whole next group; returns 1, 0 at end, -1 malformed */
static int rd_group(usd_reader* r, usd_group* g, usd_coin* pending, int* have_pending){
    g->n = 0; g->valid = 0;
    usd_coin c; int rc;
    if (*have_pending){ c = *pending; *have_pending = 0; rc = 1; } else rc = rd_coin(r, &c);
    if (rc <= 0) return rc;
    memcpy(g->txid, r->txid, 32); g->valid = 1;
    /* rd_coin's r->txid is the group of the coin just returned; a pending coin
     * came from the next group, whose txid r->txid now holds too */
    if (!grp_push(g, &c)) return -1;
    for (;;){
        unsigned char cur[32]; memcpy(cur, r->txid, 32);
        rc = rd_coin(r, &c);
        if (rc < 0) return -1;
        if (rc == 0) return 1;
        if (memcmp(r->txid, cur, 32) != 0){ *pending = c; *have_pending = 1; return 1; }
        if (!grp_push(g, &c)) return -1;
    }
}
static const usd_coin* grp_find(const usd_group* g, unsigned long long vout){ for (unsigned long i = 0; i < g->n; i++) if (g->v[i].vout == vout) return &g->v[i]; return 0; }

long usnap_diff(const char* a_path, const char* b_path, FILE* out, long max_report){
    usd_reader A = {0}, B = {0}; A.name = a_path; B.name = b_path;
    A.f = fopen(a_path, "rb"); B.f = fopen(b_path, "rb");
    if (!A.f || !B.f){ fprintf(stderr, "cannot open %s\n", !A.f ? a_path : b_path); return -2; }
    if (!rd_header(&A) || !rd_header(&B)){ fprintf(stderr, "not a utxo snapshot (bad header)\n"); return -2; }
    long diffs = 0, reported = 0; char ta[65], da[2*10008+160], db[2*10008+160];
    if (memcmp(A.base, B.base, 32)){ char h1[65], h2[65]; txid_disp(A.base, h1); txid_disp(B.base, h2);
        fprintf(out, "base-block differs: A %s | B %s (the sets are at different heights; coins compared anyway)\n", h1, h2); diffs++; }
    if (A.count != B.count){ fprintf(out, "coin-count differs: A %llu | B %llu\n", A.count, B.count); diffs++; }
    usd_group ga = {0}, gb = {0}; usd_coin pa, pb; int hpa = 0, hpb = 0;
    int ra = rd_group(&A, &ga, &pa, &hpa), rb = rd_group(&B, &gb, &pb, &hpb);
    #define REPORT(...) do { if (reported < max_report){ fprintf(out, __VA_ARGS__); reported++; } diffs++; } while (0)
    while (ra > 0 || rb > 0){
        if (ra < 0 || rb < 0){ diffs = -2; break; }
        int cmp = ra > 0 && rb > 0 ? memcmp(ga.txid, gb.txid, 32) : (ra > 0 ? -1 : 1);
        if (cmp < 0){ txid_disp(ga.txid, ta); for (unsigned long i = 0; i < ga.n; i++){ coin_desc(&ga.v[i], da, sizeof da); REPORT("only-in-A %s:%llu %s\n", ta, ga.v[i].vout, da); }
            ra = rd_group(&A, &ga, &pa, &hpa); continue; }
        if (cmp > 0){ txid_disp(gb.txid, ta); for (unsigned long i = 0; i < gb.n; i++){ coin_desc(&gb.v[i], db, sizeof db); REPORT("only-in-B %s:%llu %s\n", ta, gb.v[i].vout, db); }
            rb = rd_group(&B, &gb, &pb, &hpb); continue; }
        txid_disp(ga.txid, ta);
        for (unsigned long i = 0; i < ga.n; i++){
            const usd_coin* cb = grp_find(&gb, ga.v[i].vout);
            if (!cb){ coin_desc(&ga.v[i], da, sizeof da); REPORT("only-in-A %s:%llu %s\n", ta, ga.v[i].vout, da); continue; }
            if (ga.v[i].serlen != cb->serlen || memcmp(ga.v[i].ser, cb->ser, cb->serlen)){
                coin_desc(&ga.v[i], da, sizeof da); coin_desc(cb, db, sizeof db);
                REPORT("differs   %s:%llu A: %s | B: %s\n", ta, ga.v[i].vout, da, db); }
        }
        for (unsigned long i = 0; i < gb.n; i++) if (!grp_find(&ga, gb.v[i].vout)){ coin_desc(&gb.v[i], db, sizeof db); REPORT("only-in-B %s:%llu %s\n", ta, gb.v[i].vout, db); }
        ra = rd_group(&A, &ga, &pa, &hpa); rb = rd_group(&B, &gb, &pb, &hpb);
    }
    #undef REPORT
    if (diffs == -2) fprintf(out, "MALFORMED: a file could not be read to its end (A %llu of %llu coins, B %llu of %llu)\n", A.read_coins, A.count, B.read_coins, B.count);
    else fprintf(out, "%s: A %llu coins, B %llu coins, %ld difference(s)%s\n", diffs ? "DIFFER" : "IDENTICAL", A.read_coins, B.read_coins, diffs,
                 diffs > reported && diffs > 0 ? " (first shown)" : "");
    free(ga.v); free(gb.v); fclose(A.f); fclose(B.f);
    return diffs;
}

#ifndef USNAP_DIFF_NO_MAIN
int main(int argc, char** argv){
    if (argc < 3){ fprintf(stderr, "usage: bmc_utxo_snapshot_diff <a.dat> <b.dat> [max_reported=50]\n"); return 2; }
    long d = usnap_diff(argv[1], argv[2], stdout, argc > 3 ? atol(argv[3]) : 50);
    return d < 0 ? 2 : d ? 1 : 0;
}
#endif
