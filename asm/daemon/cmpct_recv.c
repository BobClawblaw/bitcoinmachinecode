#include <string.h>
#include "cmpct_recv.h"
#include "../mempool_slot.h"
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen) __attribute__((weak));
extern void bip152_shortid(unsigned char out[6], const unsigned char hdr[80], unsigned long long nonce, const unsigned char wtxid[32]);
extern void tx_wtxid(unsigned char out[32], const unsigned char* tx, unsigned long txlen);
extern int  tx_parse(unsigned char info[64], const unsigned char* p, unsigned long cap);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);

static int g_enabled = 1; static cmpct_writer_t g_write = 0;
static unsigned long g_st_recon = 0, g_st_need = 0, g_st_fb = 0;
static int g_wtxid_cache = 1; static unsigned long g_st_hashed = 0;
void cmpct_recv_set_enabled(int on){ g_enabled = on; }
void cmpct_recv_set_wtxid_cache(int on){ g_wtxid_cache = on; }
unsigned long cmpct_recv_hashed(void){ return g_st_hashed; }
int  cmpct_recv_enabled(void){ return g_enabled; }
unsigned cmpct_getdata_type(int leg){ return (g_enabled && leg) ? MSG_CMPCT_BLOCK_T : MSG_WITNESS_BLOCK_T; }
void cmpct_recv_set_writer(cmpct_writer_t w){ g_write = w; }
void cmpct_recv_stats(unsigned long* r, unsigned long* n, unsigned long* f){ if (r) *r = g_st_recon; if (n) *n = g_st_need; if (f) *f = g_st_fb; }
static long wr(int fd, const char* cmd, unsigned cl, const void* p, unsigned pl){ cmpct_writer_t w = g_write ? g_write : (cmpct_writer_t)p2p_write; return w ? w(fd, cmd, cl, p, pl) : -1; }

static long get_cs(const unsigned char* p, unsigned long len, unsigned long long* v){
    if (len < 1) return 0;
    if (p[0] < 253){ *v = p[0]; return 1; }
    if (p[0] == 253){ if (len < 3) return 0; *v = p[1] | ((unsigned long long)p[2] << 8); return 3; }
    if (p[0] == 254){ if (len < 5) return 0; *v = 0; for (int i = 0; i < 4; i++) *v |= (unsigned long long)p[1+i] << (8*i); return 5; }
    if (len < 9) return 0;
    *v = 0; for (int i = 0; i < 8; i++) *v |= (unsigned long long)p[1+i] << (8*i);
    return 9;
}
static long put_cs(unsigned char* o, unsigned long long v){
    if (v < 253){ o[0] = (unsigned char)v; return 1; }
    if (v <= 0xffff){ o[0] = 253; o[1] = (unsigned char)v; o[2] = (unsigned char)(v >> 8); return 3; }
    o[0] = 254; for (int i = 0; i < 4; i++) o[1+i] = (unsigned char)(v >> (8*i)); return 5;
}
static unsigned long long sid_of(const unsigned char* six){ unsigned long long v = 0; for (int i = 0; i < 6; i++) v |= (unsigned long long)six[i] << (8*i); return v; }

/* the block being reconstructed (one at a time per process, as one leg fetches one block at a time) */
#define CR_MAX_TX 20000
static struct {
    int active; unsigned char hash[32]; unsigned char hdr[80]; unsigned long long nonce;
    unsigned long ntx;
    const unsigned char* ptr[CR_MAX_TX]; unsigned long len[CR_MAX_TX];   /* NULL = missing */
    unsigned char pre[4 << 20]; unsigned long pre_used;                  /* prefilled tx bytes (copied: the payload buffer is reused) */
    unsigned long nmiss;
} S;

/* shortid -> mempool tx: an open-addressing table over the pool's slot table
 * (mempool_slot.h: +0 count, +8 mask, +16 blob, +24 blob_cap, +32 fill, +40
 * slots of MPOOL_SLOT_BYTES: [len][txid32][blob_off][wtxid32]; empty len = ~0).
 * A short id that two pool entries share is dropped (Core: treated as missing).
 *
 * The wtxid comes from the slot's cache (mpool_put hashed the tx once at
 * admission), not from sha256d over the tx: with 50,000 entries this table
 * was rebuilt with 50,000 double-SHA256s of whole transactions for every
 * block. cmpct_recv_set_wtxid_cache(0) is the pre-cache behaviour, kept as
 * the test's negative control and as the fallback should a pool ever be
 * handed over without the cache (none is today: every writer is mpool_put). */
#define HT_BITS 21
static struct { unsigned long long sid; const unsigned char* tx; unsigned long len; unsigned char used, dup; } HT[1u << HT_BITS];
static unsigned long ht_slot(unsigned long long sid){ return (unsigned long)((sid * 0x9e3779b97f4a7c15ULL) >> (64 - HT_BITS)); }
static void ht_put(unsigned long long sid, const unsigned char* tx, unsigned long len){
    unsigned long i = ht_slot(sid);
    for (;;){ if (!HT[i].used){ HT[i].used = 1; HT[i].sid = sid; HT[i].tx = tx; HT[i].len = len; HT[i].dup = 0; return; }
              if (HT[i].sid == sid){ HT[i].dup = 1; return; }
              i = (i + 1) & ((1u << HT_BITS) - 1); }
}
static const unsigned char* ht_get(unsigned long long sid, unsigned long* len){
    unsigned long i = ht_slot(sid);
    for (;;){ if (!HT[i].used) return 0; if (HT[i].sid == sid){ if (HT[i].dup) return 0; *len = HT[i].len; return HT[i].tx; } i = (i + 1) & ((1u << HT_BITS) - 1); }
}
static void ht_build(void* mp, const unsigned char hdr[80], unsigned long long nonce){
    memset(HT, 0, sizeof HT);
    if (!mp) return;
    const unsigned char* m = (const unsigned char*)mp;
    unsigned long long mask = *(const unsigned long long*)(m + 8); const unsigned char* blob = *(const unsigned char* const*)(m + 16);
    unsigned long long blob_cap = *(const unsigned long long*)(m + 24);
    for (unsigned long long s = 0; s <= mask; s++){
        const unsigned char* slot = MPOOL_SLOT_AT(m, s); unsigned long long len = *(const unsigned long long*)slot;
        if (len == MPOOL_SLOT_EMPTY || len == 0) continue;
        unsigned long long off = *(const unsigned long long*)(slot + MPOOL_SLOT_OFF);
        if (off + len < off || off + len > blob_cap) continue;   /* torn slot (MEM-21): a miss, never a read past the blob */
        const unsigned char* tx = blob + off;
        unsigned char w[32], six[6]; const unsigned char* wp = g_wtxid_cache ? mpool_wtxid_at_slot(mp, (unsigned long)s) : 0;
        if (!wp){ tx_wtxid(w, tx, (unsigned long)len); g_st_hashed++; wp = w; }
        bip152_shortid(six, hdr, nonce, wp);
        ht_put(sid_of(six), tx, (unsigned long)len);
    }
}
static long assemble(unsigned char* out, unsigned long cap){
    unsigned long o = 0; if (cap < 80 + 9) return -1;
    memcpy(out, S.hdr, 80); o = 80; o += (unsigned long)put_cs(out + o, S.ntx);
    for (unsigned long i = 0; i < S.ntx; i++){ if (!S.ptr[i] || o + S.len[i] > cap) return -1; memcpy(out + o, S.ptr[i], S.len[i]); o += S.len[i]; }
    S.active = 0; g_st_recon++; return (long)o;
}
static long fallback_full(int fd){
    unsigned char gd[37]; gd[0] = 1; unsigned t = MSG_WITNESS_BLOCK_T; memcpy(gd + 1, &t, 4); memcpy(gd + 5, S.hash, 32);
    S.active = 0; g_st_fb++; wr(fd, "getdata", 7, gd, 37); return 0;
}
long cmpct_recv_cmpctblock(int fd, void* mp, const unsigned char* pl, unsigned long plen, unsigned char* out, unsigned long cap, const unsigned char want[32]){
    if (!g_enabled || plen < 80 + 8 + 1 + 1) return -1;
    unsigned char bh[32]; block_hash(bh, pl); if (memcmp(bh, want, 32) != 0) return -1;
    S.active = 1; memcpy(S.hash, bh, 32); memcpy(S.hdr, pl, 80); memcpy(&S.nonce, pl + 80, 8); S.pre_used = 0; S.nmiss = 0;
    unsigned long o = 88; unsigned long long nshort = 0, npre = 0; long c;
    if (!(c = get_cs(pl + o, plen - o, &nshort))) return fallback_full(fd);
    o += (unsigned long)c;
    if (o + nshort * 6 > plen) return fallback_full(fd);
    const unsigned char* sids = pl + o; o += (unsigned long)nshort * 6;
    if (!(c = get_cs(pl + o, plen - o, &npre))) return fallback_full(fd);
    o += (unsigned long)c;
    S.ntx = (unsigned long)(nshort + npre); if (S.ntx == 0 || S.ntx > CR_MAX_TX) return fallback_full(fd);
    for (unsigned long i = 0; i < S.ntx; i++) S.ptr[i] = 0;
    /* prefilled: (differential index, tx) -- copy the tx bytes, the payload buffer is reused by the next read */
    unsigned long idx = 0;
    for (unsigned long long k = 0; k < npre; k++){
        unsigned long long d; if (!(c = get_cs(pl + o, plen - o, &d))) return fallback_full(fd); o += (unsigned long)c;
        idx = k ? idx + (unsigned long)d + 1 : (unsigned long)d; if (idx >= S.ntx) return fallback_full(fd);
        unsigned char info[64]; if (!tx_parse(info, pl + o, plen - o)) return fallback_full(fd);
        unsigned long tl = (unsigned long)*(unsigned long long*)info; if (S.pre_used + tl > sizeof S.pre) return fallback_full(fd);
        memcpy(S.pre + S.pre_used, pl + o, tl); S.ptr[idx] = S.pre + S.pre_used; S.len[idx] = tl; S.pre_used += tl; o += tl;
    }
    /* short ids fill the gaps in order */
    ht_build(mp, S.hdr, S.nonce);
    unsigned long k = 0;
    for (unsigned long i = 0; i < S.ntx; i++){
        if (S.ptr[i]) continue;
        if (k >= nshort) return fallback_full(fd);
        unsigned long l; const unsigned char* tx = ht_get(sid_of(sids + k * 6), &l); k++;
        if (tx){ S.ptr[i] = tx; S.len[i] = l; } else S.nmiss++;
    }
    if (S.nmiss == 0){ long n = assemble(out, cap); return n > 0 ? n : fallback_full(fd); }
    /* getblocktxn: blockhash || count || differential indexes of the missing */
    unsigned char req[32 + 9 + CR_MAX_TX * 5]; unsigned long ro = 32; memcpy(req, S.hash, 32);
    ro += (unsigned long)put_cs(req + ro, S.nmiss); unsigned long last = 0; int first = 1;
    for (unsigned long i = 0; i < S.ntx; i++) if (!S.ptr[i]){ ro += (unsigned long)put_cs(req + ro, first ? i : i - last - 1); last = i; first = 0; }
    g_st_need++; wr(fd, "getblocktxn", 11, req, (unsigned)ro);
    return 0;
}
long cmpct_recv_blocktxn(int fd, const unsigned char* pl, unsigned long plen, unsigned char* out, unsigned long cap){
    if (!g_enabled || !S.active || plen < 33) return -1;
    if (memcmp(pl, S.hash, 32) != 0) return -1;
    unsigned long o = 32; unsigned long long n; long c;
    if (!(c = get_cs(pl + o, plen - o, &n)) || n != S.nmiss) return fallback_full(fd);
    o += (unsigned long)c;
    for (unsigned long i = 0; i < S.ntx; i++){
        if (S.ptr[i]) continue;
        unsigned char info[64]; if (!tx_parse(info, pl + o, plen - o)) return fallback_full(fd);
        unsigned long tl = (unsigned long)*(unsigned long long*)info; if (S.pre_used + tl > sizeof S.pre) return fallback_full(fd);
        memcpy(S.pre + S.pre_used, pl + o, tl); S.ptr[i] = S.pre + S.pre_used; S.len[i] = tl; S.pre_used += tl; o += tl;
    }
    long r = assemble(out, cap); return r > 0 ? r : fallback_full(fd);
}
