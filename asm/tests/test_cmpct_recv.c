/* tests/test_cmpct_recv.c -- CC-2: compact blocks are reconstructed from the mempool; the missing ones fetched with getblocktxn. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cmpct_recv.h"
extern long cmpctblock_build(unsigned char* out, const unsigned char* blockbuf, unsigned long blen, unsigned long long nonce);
extern long p2p_blocktxn_build(unsigned char* out, const unsigned char bh[32], const unsigned char* const* txs, const long* lens, long n);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
extern unsigned long mpool_struct_size(unsigned long slots);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern long mpool_put(void* mp, const unsigned char txid[32], const unsigned char* tx, unsigned long txlen);
extern long mpool_del(void* mp, const unsigned char txid[32]);
static int checks, fails; static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
static unsigned char cap[65536]; static unsigned long cap_n; static char cap_cmd[16]; static int writes;
static long capw(int fd, const char* cmd, unsigned cl, const void* p, unsigned pl){ (void)fd; memcpy(cap_cmd, cmd, cl); cap_cmd[cl]=0; memcpy(cap, p, pl); cap_n = pl; writes++; return pl; }
/* a minimal non-witness tx: version 1, one input (prevout = tag), empty scriptSig, seq, one output value=tag script=OP_TRUE, locktime */
static unsigned long mktx(unsigned char* t, unsigned tag){
    unsigned long o = 0; t[o++]=1; t[o++]=0; t[o++]=0; t[o++]=0; t[o++]=1;
    memset(t+o, 0, 32); t[o] = (unsigned char)tag; t[o+1] = (unsigned char)(tag>>8); o += 32; memset(t+o, 0, 4); o += 4; t[o++]=0; memset(t+o, 0xff, 4); o += 4;
    t[o++]=1; memset(t+o, 0, 8); t[o] = (unsigned char)tag; o += 8; t[o++]=1; t[o++]=0x51; memset(t+o, 0, 4); o += 4; return o;
}
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
    printf("== wrong block, junk, and the fallback ==\n");
    unsigned char other[32]; memset(other, 7, 32); ok(cmpct_recv_cmpctblock(9, mp, cb, (unsigned long)cl, out, sizeof out, other) == -1, "a compact block for another hash is ignored");
    writes = 0; n = cmpct_recv_cmpctblock(9, mp, cb, 90, out, sizeof out, bh); ok(n == 0 && writes == 1 && !strcmp(cap_cmd, "getdata") && cap[1] == 2 && cap[4] == 0x40, "a truncated payload falls back to a full MSG_WITNESS_BLOCK getdata");
    { unsigned char cb2[8192]; memcpy(cb2, cb, (size_t)cl); cb2[cl-1] ^= 0xff;   /* corrupt the coinbase's last byte: tx_parse still ok? we corrupt the prefilled count instead */
      writes = 0; cmpct_recv_cmpctblock(9, mp, cb, (unsigned long)cl, out, sizeof out, bh);   /* re-arm state (2 missing) */
      unsigned char bt[64]; memcpy(bt, bh, 32); bt[32] = 1;   /* wrong count */
      writes = 0; n = cmpct_recv_blocktxn(9, bt, 33, out, sizeof out); ok(n == 0 && writes == 1 && !strcmp(cap_cmd, "getdata"), "a blocktxn with the wrong count falls back to a full getdata"); }
    unsigned long r, need, fb; cmpct_recv_stats(&r, &need, &fb); ok(r == 2 && need >= 2 && fb == 2, "stats: 2 reconstructed, getblocktxn needed, 2 fallbacks");
    printf("== the inventory type we request with ==\n");
    ok(cmpct_getdata_type(1) == 4 && cmpct_getdata_type(0) == 0x40000002u, "a leg that negotiated sendcmpct is asked for MSG_CMPCT_BLOCK; one that did not, MSG_WITNESS_BLOCK");
    printf("== negative control: receive disabled (the pre-CC-2 node) ==\n");
    cmpct_recv_set_enabled(0); writes = 0;
    ok(cmpct_getdata_type(1) == 0x40000002u, "control: every block is requested in full");
    ok(cmpct_recv_cmpctblock(9, mp, cb, (unsigned long)cl, out, sizeof out, bh) == -1 && writes == 0, "control: a compact block is ignored, nothing reconstructed, nothing sent");
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails); return fails?1:0;
}
