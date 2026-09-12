/* tests/test_cmpct_recv.c -- CC-2: compact blocks are reconstructed from the mempool; the missing ones fetched with getblocktxn.
 * 2026-09-06 (mempool wtxid cache): reconstruction reads each pool entry's wtxid from the slot cache mpool_put fills
 * and hashes ZERO entries; a 50,000-entry pool is timed cache-off vs cache-on on one pinned core; both give the same block. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <time.h>
#include "cmpct_recv.h"
#include "mempool_slot.h"
extern long cmpctblock_build(unsigned char* out, const unsigned char* blockbuf, unsigned long blen, unsigned long long nonce);
extern long p2p_blocktxn_build(unsigned char* out, const unsigned char bh[32], const unsigned char* const* txs, const long* lens, long n);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
extern unsigned long mpool_struct_size(unsigned long slots);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern long mpool_put(void* mp, const unsigned char txid[32], const unsigned char* tx, unsigned long txlen);
extern long mpool_del(void* mp, const unsigned char txid[32]);
extern long mpool_count(void* mp);
static double now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e3 + t.tv_nsec / 1e6; }
static int checks, fails; static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
static unsigned char cap[65536]; static unsigned long cap_n; static char cap_cmd[16]; static int writes;
static long capw(int fd, const char* cmd, unsigned cl, const void* p, unsigned pl){ (void)fd; memcpy(cap_cmd, cmd, cl); cap_cmd[cl]=0; memcpy(cap, p, pl); cap_n = pl; writes++; return pl; }
/* a minimal non-witness tx: version 1, one input (prevout = tag), empty scriptSig, seq, one output value=tag script=OP_TRUE, locktime */
static unsigned long mktx(unsigned char* t, unsigned tag){
    unsigned long o = 0; t[o++]=1; t[o++]=0; t[o++]=0; t[o++]=0; t[o++]=1;
    memset(t+o, 0, 32); t[o] = (unsigned char)tag; t[o+1] = (unsigned char)(tag>>8); o += 32; memset(t+o, 0, 4); o += 4; t[o++]=0; memset(t+o, 0xff, 4); o += 4;
    t[o++]=1; memset(t+o, 0, 8); t[o] = (unsigned char)tag; o += 8; t[o++]=1; t[o++]=0x51; memset(t+o, 0, 4); o += 4; return o;
}
/* a pool of `slots` slots holding the block's first nblk non-coinbase txs and nfill filler txs (tags 6000..) */
static unsigned char* mkpool(unsigned long slots, unsigned char* blob, unsigned long bcap, int nblk, unsigned nfill, unsigned char (*tx)[256], const unsigned long* tl){
    unsigned char* p = calloc(1, mpool_struct_size(slots)); mpool_init(p, slots, blob, bcap);
    for (int i = 1; i <= nblk; i++){ unsigned char id[32]; sha256d(id, tx[i], tl[i]); mpool_put(p, id, tx[i], tl[i]); }
    static unsigned char f[256]; for (unsigned k = 0; k < nfill; k++){ unsigned long fl = mktx(f, 6000 + k); unsigned char id[32]; sha256d(id, f, fl); if (mpool_put(p, id, f, fl) != 1){ printf("  put failed at %u\n", k); break; } }
    return p;
}
/* one cmpctblock call, everything it produced captured: the return, the block bytes or the message it sent */
typedef struct { long n; int writes; char cmd[16]; unsigned long msg_n; unsigned char msg[4096]; unsigned char out[8192]; } run_t;
static void run1(run_t* r, void* p, const unsigned char* cb, long cl, const unsigned char bh[32]){
    writes = 0; cap_n = 0; cap_cmd[0] = 0; r->n = cmpct_recv_cmpctblock(9, p, cb, (unsigned long)cl, r->out, sizeof r->out, bh);
    r->writes = writes; strcpy(r->cmd, cap_cmd); r->msg_n = cap_n < sizeof r->msg ? cap_n : sizeof r->msg; memcpy(r->msg, cap, r->msg_n);
}
static int run_same(const run_t* a, const run_t* b){
    if (a->n != b->n || a->writes != b->writes) return 0;
    if (a->n > 0) return !memcmp(a->out, b->out, (size_t)a->n);
    return !strcmp(a->cmd, b->cmd) && a->msg_n == b->msg_n && !memcmp(a->msg, b->msg, a->msg_n);
}
static int cls_stub_calls; static int cls_stub(const unsigned char* tx, unsigned long len){ (void)tx; (void)len; cls_stub_calls++; return 1; }
int main(void){
    static unsigned char blk[8192], tx[8][256]; unsigned long tl[8]; unsigned long bo = 80; memset(blk, 0x11, 80);
    blk[bo++] = 6; for (int i = 0; i < 6; i++){ tl[i] = mktx(tx[i], 1000 + i); memcpy(blk + bo, tx[i], tl[i]); bo += tl[i]; }
    unsigned char bh[32]; block_hash(bh, blk);
    unsigned long slots = 64; unsigned char* mp = calloc(1, mpool_struct_size(slots)); static unsigned char blob[65536]; mpool_init(mp, slots, blob, sizeof blob);
    for (int i = 1; i < 6; i++){ unsigned char id[32]; sha256d(id, tx[i], tl[i]); mpool_put(mp, id, tx[i], tl[i]); }   /* all but the coinbase */
    static unsigned char cb[8192]; long cl = cmpctblock_build(cb, blk, bo, 0x1122334455667788ULL); ok(cl > 0, "serve-side cmpctblock_build produced a compact block");
    cmpct_recv_set_writer(capw); static unsigned char out[8192];
    printf("== every tx in the mempool: reconstructed with no round trip ==\n");
    writes = 0; long n = cmpct_recv_cmpctblock(9, mp, cb, (unsigned long)cl, out, sizeof out, bh);
    ok(n == (long)bo && !memcmp(out, blk, bo), "block reconstructed byte-identical");
    ok(writes == 0, "no getblocktxn, no getdata");
    printf("== two missing: getblocktxn for exactly those, then blocktxn completes ==\n");
    { unsigned char id[32]; sha256d(id, tx[2], tl[2]); mpool_del(mp, id); sha256d(id, tx[4], tl[4]); mpool_del(mp, id); }
    writes = 0; n = cmpct_recv_cmpctblock(9, mp, cb, (unsigned long)cl, out, sizeof out, bh);
    ok(n == 0 && writes == 1 && !strcmp(cap_cmd, "getblocktxn"), "pending: one getblocktxn sent");
    ok(cap_n == 32 + 1 + 2 && !memcmp(cap, bh, 32) && cap[32] == 2 && cap[33] == 2 && cap[34] == 1, "getblocktxn: blockhash, count 2, differential indexes [2, +1 -> 4]");
    { const unsigned char* txs[2] = { tx[2], tx[4] }; long lens[2] = { (long)tl[2], (long)tl[4] }; static unsigned char bt[8192]; long btl = p2p_blocktxn_build(bt, bh, txs, lens, 2);
      writes = 0; n = cmpct_recv_blocktxn(9, bt, (unsigned long)btl, out, sizeof out);
      ok(n == (long)bo && !memcmp(out, blk, bo) && writes == 0, "blocktxn fills the two gaps: block byte-identical, nothing more sent"); }
    printf("== row 5 (2026-09-10): the block's accounting and the classifier ==\n");
    { extern void cmpct_recv_last_block(unsigned long*, unsigned long*, unsigned long*, unsigned long*, unsigned long*, unsigned long cls[5]);
      extern void cmpct_recv_set_classifier(int (*)(const unsigned char*, unsigned long));
      unsigned long ntx_, pool_, pre_, miss_, mb_, cls_[5]; cmpct_recv_last_block(&ntx_, &pool_, &pre_, &miss_, &mb_, cls_);
      ok(miss_ == 2 && pool_ + pre_ + miss_ == ntx_ && mb_ > 0, "after the blocktxn: 2 fetched, pool + prefilled + fetched = the block's tx count, bytes counted");
      ok(cls_[0] == 2 && cls_[1] + cls_[2] + cls_[3] + cls_[4] == 0, "no classifier: the fetched ones count as never announced");
      cmpct_recv_set_classifier(cls_stub);
      writes = 0; cmpct_recv_cmpctblock(9, mp, cb, (unsigned long)cl, out, sizeof out, bh);
      { const unsigned char* txs2[2] = { tx[2], tx[4] }; long lens2[2] = { (long)tl[2], (long)tl[4] }; static unsigned char bt2[8192]; long btl2 = p2p_blocktxn_build(bt2, bh, txs2, lens2, 2);
        n = cmpct_recv_blocktxn(9, bt2, (unsigned long)btl2, out, sizeof out); }
      cmpct_recv_last_block(&ntx_, &pool_, &pre_, &miss_, &mb_, cls_);
      ok(n > 0 && cls_stub_calls == 2 && cls_[1] == 2 && cls_[0] == 0, "with a classifier: called once per fetched tx, and their class is counted (2 announced)");
      cmpct_recv_set_classifier(0); }
    printf("== wrong block, junk, and the fallback ==\n");
    unsigned char other[32]; memset(other, 7, 32); ok(cmpct_recv_cmpctblock(9, mp, cb, (unsigned long)cl, out, sizeof out, other) == -1, "a compact block for another hash is ignored");
    writes = 0; n = cmpct_recv_cmpctblock(9, mp, cb, 90, out, sizeof out, bh); ok(n == 0 && writes == 1 && !strcmp(cap_cmd, "getdata") && cap[1] == 2 && cap[4] == 0x40, "a truncated payload falls back to a full MSG_WITNESS_BLOCK getdata");
    { unsigned char cb2[8192]; memcpy(cb2, cb, (size_t)cl); cb2[cl-1] ^= 0xff;   /* corrupt the coinbase's last byte: tx_parse still ok? we corrupt the prefilled count instead */
      writes = 0; cmpct_recv_cmpctblock(9, mp, cb, (unsigned long)cl, out, sizeof out, bh);   /* re-arm state (2 missing) */
      unsigned char bt[64]; memcpy(bt, bh, 32); bt[32] = 1;   /* wrong count */
      writes = 0; n = cmpct_recv_blocktxn(9, bt, 33, out, sizeof out); ok(n == 0 && writes == 1 && !strcmp(cap_cmd, "getdata"), "a blocktxn with the wrong count falls back to a full getdata"); }
    unsigned long r, need, fb; cmpct_recv_stats(&r, &need, &fb); ok(r == 3 && need >= 3 && fb == 2, "stats: 3 reconstructed (the row 5 scenario reconstructed once more), getblocktxn needed, 2 fallbacks");
    printf("== the inventory type we request with ==\n");
    ok(cmpct_getdata_type(1) == 4 && cmpct_getdata_type(0) == 0x40000002u, "a leg that negotiated sendcmpct is asked for MSG_CMPCT_BLOCK; one that did not, MSG_WITNESS_BLOCK");
    printf("== the wtxid cache: reconstruction hashes no pool entry ==\n");
    ok(cmpct_recv_hashed() == 0, "every reconstruction above took its wtxids from the slot cache: 0 tx_wtxid calls for pool entries");
    printf("== 50,000-entry pool, one pinned core: cache off (pre-cache ht_build) vs on, same block ==\n");
    { /* cpu_set_t/sched_setaffinity are Linux-only; on macOS the bench just
         runs unpinned (the pin is a noise-reduction nicety, not the gate). */
#ifdef __APPLE__
      if (0) printf("  (note: core pinning is Linux-only; running unpinned)\n");
#else
      cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs); if (sched_setaffinity(0, sizeof cs, &cs) != 0) printf("  (note: could not pin to cpu 0)\n");
#endif
      enum { BIG_SLOTS = 131072, NBIG = 50000 };
      static unsigned char bblob[8 << 20]; unsigned char* big = mkpool(BIG_SLOTS, bblob, sizeof bblob, 5, NBIG - 5, tx, tl);
      ok(mpool_count(big) == NBIG, "50,000 entries in the pool (the block's five among them)");
      cmpct_recv_set_enabled(1); cmpct_recv_set_writer(capw);
      unsigned long h0 = cmpct_recv_hashed(); double t_off = 1e30, t_on = 1e30; long n_off = -1, n_on = -1; static unsigned char out2[8192]; int same_off = 1, same_on = 1;
      cmpct_recv_set_wtxid_cache(0);                                       /* the control runs FIRST */
      for (int r = 0; r < 9; r++){ double a = now_ms(); writes = 0; n_off = cmpct_recv_cmpctblock(9, big, cb, (unsigned long)cl, out2, sizeof out2, bh); double b = now_ms() - a; if (b < t_off) t_off = b; if (n_off != (long)bo || memcmp(out2, blk, bo)) same_off = 0; }
      unsigned long h_off = cmpct_recv_hashed() - h0;
      cmpct_recv_set_wtxid_cache(1);
      for (int r = 0; r < 9; r++){ double a = now_ms(); writes = 0; n_on = cmpct_recv_cmpctblock(9, big, cb, (unsigned long)cl, out2, sizeof out2, bh); double b = now_ms() - a; if (b < t_on) t_on = b; if (n_on != (long)bo || memcmp(out2, blk, bo)) same_on = 0; }
      unsigned long h_on = cmpct_recv_hashed() - h0 - h_off;
      printf("  cache off: min %.2f ms/block, %lu tx_wtxid calls over 9 runs\n  cache on : min %.2f ms/block, %lu tx_wtxid calls over 9 runs\n", t_off, h_off, t_on, h_on);
      ok(h_off == 9UL * NBIG, "control: with the cache off ht_build hashes every entry -- 50,000 tx_wtxid calls per block");
      ok(same_off, "control: and still reconstructs the identical block");
      ok(h_on == 0, "cache on: zero tx_wtxid calls for pool entries");
      ok(same_on, "cache on: the identical block");
      ok(t_on * 1.2 < t_off, "cache on is faster than the per-block rehash of 50,000 transactions by more than 20%");
      printf("== 50,000-entry pool, one pinned core: the memset build (control: whole-table clear, full width, per-entry key) vs the stamped, pool-sized build ==\n");
      { double t_old = 1e30, t_new = 1e30; run_t a, b; int same_old = 1, same_new = 1;
        cmpct_recv_set_ht_clear(1);                                        /* the control runs FIRST */
        for (int r = 0; r < 9; r++){ double t0 = now_ms(); run1(&a, big, cb, cl, bh); double d = now_ms() - t0; if (d < t_old) t_old = d; if (a.n != (long)bo || memcmp(a.out, blk, bo)) same_old = 0; }
        ok(cmpct_recv_ht_bits() == 21, "control: the memset build probes at the full 2^21 width");
        cmpct_recv_set_ht_clear(0);
        for (int r = 0; r < 9; r++){ double t0 = now_ms(); run1(&b, big, cb, cl, bh); double d = now_ms() - t0; if (d < t_new) t_new = d; if (b.n != (long)bo || memcmp(b.out, blk, bo)) same_new = 0; }
        printf("  memset build : min %.2f ms/block\n  stamped build: min %.2f ms/block (%.1fx)\n", t_old, t_new, t_old / t_new);
        ok(same_old && same_new, "both builds reconstruct the identical block");
        ok(cmpct_recv_ht_bits() == 17, "50,000 entries: the stamped build probes 2^17 entries (next power of two >= 2 x count)");
        ok(t_new * 3 < t_old, "the stamped, pool-sized build is at least 3x faster than the memset build"); }
      free(big); }
    printf("== the short-id table: identical to the memset build for pools of 1, 100, 5,000 and 50,000 entries ==\n");
    { static unsigned char pblob[8 << 20]; struct { unsigned n; unsigned long slots; unsigned bits; } P[4] = { {1, 64, 12}, {100, 256, 12}, {5000, 16384, 14}, {50000, 131072, 17} };
      for (int q = 0; q < 4; q++){
        unsigned n = P[q].n; int nblk = n < 5 ? (int)n : 5; unsigned char* p = mkpool(P[q].slots, pblob, sizeof pblob, nblk, n - nblk, tx, tl); run_t a, b; char m[200];
        cmpct_recv_set_ht_clear(1); run1(&a, p, cb, cl, bh); unsigned ba = cmpct_recv_ht_bits();
        cmpct_recv_set_ht_clear(0); run1(&b, p, cb, cl, bh); unsigned bb = cmpct_recv_ht_bits();
        int full = nblk == 5 ? (b.n == (long)bo && !memcmp(b.out, blk, bo)) : (b.n == 0 && b.writes == 1 && !strcmp(b.cmd, "getblocktxn") && b.msg[32] == (unsigned char)(5 - nblk));
        snprintf(m, sizeof m, "pool of %u (count %ld): memset build and stamped build agree byte for byte -- %s", n, mpool_count(p), nblk == 5 ? "the full block" : "getblocktxn for the four not in the pool");
        ok(run_same(&a, &b) && full, m);
        snprintf(m, sizeof m, "pool of %u: the memset build probed 2^%u, the stamped build 2^%u (expected 2^%u)", n, ba, bb, P[q].bits);
        ok(ba == 21 && bb == P[q].bits, m);
        free(p); } }
    printf("== no stale entries: a rebuild after the pool changed misses what was removed ==\n");
    { static unsigned char sblob[65536], pblob[8 << 20]; unsigned char* p = mkpool(64, sblob, sizeof sblob, 5, 0, tx, tl); run_t a; unsigned char id3[32]; sha256d(id3, tx[3], tl[3]);
      cmpct_recv_set_ht_clear(0); run1(&a, p, cb, cl, bh); unsigned g1 = cmpct_recv_ht_gen();
      ok(a.n == (long)bo && !memcmp(a.out, blk, bo), "A (tx 3) in the pool: the block reconstructs in full");
      mpool_del(p, id3); run1(&a, p, cb, cl, bh);
      ok(a.n == 0 && a.writes == 1 && !strcmp(a.cmd, "getblocktxn") && a.msg_n == 34 && a.msg[32] == 1 && a.msg[33] == 3, "A removed, same width, nothing cleared: the rebuild misses A -- getblocktxn for index 3 alone");
      ok(cmpct_recv_ht_gen() == g1 + 1, "each build advances the generation by one");
      unsigned char* big = mkpool(131072, pblob, sizeof pblob, 5, 49995, tx, tl); run1(&a, big, cb, cl, bh);
      ok(a.n == (long)bo && cmpct_recv_ht_bits() == 17, "A in a 50,000-entry pool: full block at width 2^17");
      run1(&a, p, cb, cl, bh);
      ok(cmpct_recv_ht_bits() == 12 && a.n == 0 && a.writes == 1 && !strcmp(a.cmd, "getblocktxn") && a.msg_n == 34 && a.msg[33] == 3, "then the 4-entry pool at width 2^12, over the wide build's leftovers: A still missing, index 3 alone");
      printf("== the generation's wrap: the one memset left ==\n");
      cmpct_recv_ht_set_gen(0); mpool_put(p, id3, tx[3], tl[3]); run1(&a, p, cb, cl, bh);
      ok(cmpct_recv_ht_gen() == 1 && a.n == (long)bo, "A back in the pool, built at generation 1 (the first-ever build's stamp)");
      cmpct_recv_ht_set_gen(0xffffffffu); mpool_del(p, id3); run1(&a, p, cb, cl, bh);
      ok(cmpct_recv_ht_gen() == 1, "the counter wrapped: the table was cleared and the generation restarted at 1");
      ok(a.n == 0 && a.writes == 1 && !strcmp(a.cmd, "getblocktxn") && a.msg_n == 34 && a.msg[33] == 3, "A's generation-1 entry from before the wrap does not read live after it: index 3 missing");
      free(p); free(big); }
    printf("== the dup rule: a short id two pool entries share is missing ==\n");
    { static unsigned char sblob[65536], f[256]; unsigned char* p = mkpool(64, sblob, sizeof sblob, 5, 1, tx, tl); run_t a, b;
      unsigned long fl = mktx(f, 6000); unsigned char fid[32], w2[32]; sha256d(fid, f, fl); sha256d(w2, tx[2], tl[2]); int poked = 0;
      for (unsigned long i = 0; i < 64; i++){ unsigned char* sl = MPOOL_SLOT_AT(p, i); if (*(unsigned long long*)sl != MPOOL_SLOT_EMPTY && !memcmp(sl + MPOOL_SLOT_TXID, fid, 32)){ memcpy(sl + MPOOL_SLOT_WTXID, w2, 32); poked = 1; } }
      ok(poked, "the filler's cached wtxid overwritten with tx 2's: two pool entries now share tx 2's short id");
      cmpct_recv_set_ht_clear(1); run1(&a, p, cb, cl, bh); cmpct_recv_set_ht_clear(0); run1(&b, p, cb, cl, bh);
      ok(b.n == 0 && b.writes == 1 && !strcmp(b.cmd, "getblocktxn") && b.msg_n == 34 && b.msg[32] == 1 && b.msg[33] == 2, "tx 2 is treated as missing: getblocktxn for index 2 alone");
      ok(run_same(&a, &b), "the memset build says the same");
      free(p); }
    printf("== negative control: receive disabled (the pre-CC-2 node) ==\n");
    cmpct_recv_set_enabled(0); writes = 0;
    ok(cmpct_getdata_type(1) == 0x40000002u, "control: every block is requested in full");
    ok(cmpct_recv_cmpctblock(9, mp, cb, (unsigned long)cl, out, sizeof out, bh) == -1 && writes == 0, "control: a compact block is ignored, nothing reconstructed, nothing sent");
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails); return fails?1:0;
}
