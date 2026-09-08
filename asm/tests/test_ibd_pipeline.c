/* tests/test_ibd_pipeline.c -- the whole chunk is asked for in ONE getdata,
 * and the blocks are placed by hash, not by arrival order.
 *
 * The finding (2026-09-06, fresh-sync benchmark): node_ibd_blocks_s asks for
 * one block, waits for it, stores it, then asks for the next. Every block
 * costs a full round trip before the next request leaves, so 16 helpers
 * against 16 real peers moved 0.23-1.2 MB/s each, 11.2 MB/s aggregate, with
 * every peer idle for most of every round trip. Core keeps up to 16 blocks
 * in flight per peer for exactly this reason.
 *
 * The externs are defined here, so this exercises the fetcher's logic against
 * a scripted peer with no socket: what it sends, what it accepts, where it
 * puts what it accepts, and what it refuses.
 *
 * Watched to fail first: with build_getdata emitting ONE hash per message
 * (the serial shape), checks 1-3 fail.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ibd_pipeline.h"

static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }

#define NB 40
#define NORD (NB + 4)
#define LO 500000L

/* ---- synthetic chain: block i's hash is 0xA0+i repeated, prev is block i-1's ---- */
static void hash_of(unsigned char out[32], int i){ memset(out, (unsigned char)(0xA0 + i), 32); }
static unsigned char g_blk[NB][200];
static unsigned g_blen[NB];

/* ---- the scripted peer ---- */
static int   g_getdata_msgs;          /* how many getdata messages the fetcher sent */
static int   g_getdata_entries;       /* entries in the FIRST one */
static int   g_pongs;
static int   g_order[NORD]; static int g_norder;   /* delivery order, block indices */
static int   g_pos;                   /* next delivery */
static int   g_inject_unasked;        /* deliver one block we never asked for, first */
static int   g_inject_ping;           /* answer one ping before the blocks */
static int   g_bad_prev;              /* corrupt one block's prevhash */
static int   g_bad_consensus;         /* one block fails cons_verify */

/* ---- externs the fetcher calls ---- */
long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned len){
    const unsigned char* payload = pl;
    (void)fd; (void)cmdlen;
    if (!strncmp(cmd, "getdata", 7)){
        if (g_getdata_msgs == 0) g_getdata_entries = payload[0];
        g_getdata_msgs++;
        /* the payload must be exactly count + entries*36 and every entry must
         * be MSG_WITNESS_BLOCK, or peers strip witnesses (2026-08-22). */
        if (len != 1u + (unsigned)payload[0] * 36u) { printf("      malformed getdata len %u\n", len); exit(2); }
        for (unsigned k = 0; k < payload[0]; k++){
            const unsigned char* e = payload + 1 + k*36;
            if (!(e[0]==0x02 && e[1]==0x00 && e[2]==0x00 && e[3]==0x40)){ printf("      entry %u is not MSG_WITNESS_BLOCK\n", k); exit(2); }
        }
    } else if (!strncmp(cmd, "pong", 4)) g_pongs++;
    return (long)len;
}
int p2p_read(int fd, char cmd[12], void* pl, unsigned cap, unsigned* outlen){
    unsigned char* buf = pl;
    (void)fd;
    if (g_inject_ping){ g_inject_ping = 0; memcpy(cmd, "ping\0\0\0\0\0\0\0", 12); memset(buf, 7, 8); *outlen = 8; return 8; }
    if (g_inject_unasked){ g_inject_unasked = 0;
        memcpy(cmd, "block\0\0\0\0\0\0", 12);
        memset(buf, 0, 100); buf[76] = (unsigned char)(NB + 5);   /* a height we never requested */
        *outlen = 100; return 100; }
    if (g_pos >= g_norder) return -1;                              /* peer went quiet */
    int i = g_order[g_pos++];
    memcpy(cmd, "block\0\0\0\0\0\0", 12);
    if (g_blen[i] > cap) return -1;
    memcpy(buf, g_blk[i], g_blen[i]); *outlen = g_blen[i];
    if (g_bad_prev == i + 1) memset(buf + 4, 0xEE, 32);            /* wrong prevhash */
    return (long)g_blen[i];
}
int hst_get_at(void* hst, unsigned long long idx, void* rec112){
    (void)hst; if (idx >= NB) return 0;
    unsigned char* r = rec112; memset(r, 0, 112);
    memcpy(r, g_blk[idx], 80);                 /* the 80-byte header */
    hash_of(r + 80, (int)idx);                 /* the block hash the store keeps at +80 */
    return 1;
}
int cons_verify(const void* blkv, long len, void* scratch, unsigned cap){
    const unsigned char* blk = blkv; (void)len; (void)scratch; (void)cap; if (g_bad_consensus && blk[76] == (unsigned char)g_bad_consensus - 1) return 0; return 1;
}
void block_hash(unsigned char out[32], const unsigned char* hdr80){ hash_of(out, hdr80[76]); }
static long g_stored_h[NB]; static int g_nstored; static int g_wrong_body;
static int g_progress; static void count_progress(void* a){ (void)a; g_progress++; }
static long g_bytes_seen; static void count_bytes(long n){ g_bytes_seen += n; }
long store_append_shared(void* st, long height, const unsigned char hash[32], const unsigned char* raw, unsigned len){
    (void)st; (void)raw; (void)len;
    unsigned char want[32]; hash_of(want, raw[76]);
    if (memcmp(hash, want, 32) != 0) g_wrong_body++;   /* record names one block, bytes are another */
    if (g_nstored < NB) g_stored_h[g_nstored++] = height;
    return height;
}

static void build_chain(void){
    for (int i = 0; i < NB; i++){
        memset(g_blk[i], 0, sizeof g_blk[i]);
        g_blk[i][0] = 1;                             /* version */
        if (i > 0) hash_of(g_blk[i] + 4, i - 1);     /* prevhash */
        g_blk[i][76] = (unsigned char)i;             /* the marker block_hash reads */
        g_blen[i] = 120;
    }
}
static void reset(void){
    g_getdata_msgs = g_getdata_entries = g_pongs = g_pos = g_nstored = g_wrong_body = 0;
    g_inject_unasked = g_inject_ping = g_bad_prev = g_bad_consensus = 0;
    memset(g_stored_h, 0, sizeof g_stored_h);
}
static void order_forward(void){ g_norder = NB; for (int i = 0; i < NB; i++) g_order[i] = i; }
static void order_reverse(void){ g_norder = NB; for (int i = 0; i < NB; i++) g_order[i] = NB - 1 - i; }

int main(void){
    static unsigned char buf[1 << 16];
    build_chain();

    printf("== the finding: ONE getdata carries the whole chunk ==\n");
    reset(); order_forward();
    long r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB, "all 40 blocks stored");
    ok(g_getdata_msgs == 1, "exactly ONE getdata message was sent for 40 blocks");
    ok(g_getdata_entries == NB && ibd_pipeline_last_batch() == NB, "that message carried all 40 hashes (40 round trips become 1)");
    { int inorder = 1; for (int i = 0; i < NB; i++) if (g_stored_h[i] != LO + i) inorder = 0;
      ok(inorder, "every block landed at its real height, LO..LO+39, in that order"); }

    printf("== a peer may answer in ANY order: blocks are placed by hash ==\n");
    reset(); order_reverse();
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB, "reverse-order delivery still completes the chunk");
    { int seen[NB]; memset(seen, 0, sizeof seen); int okh = 1;
      for (int i = 0; i < NB; i++){ long h = g_stored_h[i] - LO; if (h < 0 || h >= NB || seen[h]++) okh = 0; }
      ok(okh, "each of the 40 heights was written exactly once, none by arrival position"); }
    /* The invariant the interleaved connect depends on: the archive grows in
     * ASCENDING height order, whatever order the peer answers in. Storing in
     * arrival order is what made a real sync refuse a valid block at 48,585
     * with a false bad-txns-BIP30 on 2026-09-06. */
    { int ascending = 1; for (int i = 1; i < NB; i++) if (g_stored_h[i] <= g_stored_h[i-1]) ascending = 0;
      ok(ascending && g_stored_h[0] == LO,
         "stores are in ASCENDING height order even though delivery was reversed"); }

    printf("== the hold is a bump allocator: a drain must NOT move the pointer back ==\n");
    /* Every block in this fixture is the same length, as early-chain blocks
     * very often are. Deliver 1 and 3 (both parked), then 0: 0 is stored, 1
     * drains, 3 stays parked because 2 is still missing. The first cut then
     * subtracted 1's length from the bump pointer, which put it exactly at 3's
     * offset -- so 4, arriving next, was written OVER the parked 3, and 3 was
     * later drained with 4's bytes under 3's hash.
     * That is the "record names X, body is Y" archive run 5 left behind. */
    reset();
    /* park 1 and 3; deliver 0 -> 0 stored, 1 drained, 3 STAYS parked (2 is
     * missing). Old code: pointer -= len(1) == len(3) -> exactly 3's offset.
     * Deliver 4 -> parked ON TOP of 3. Deliver 2 -> 2 stored, 3 drained with
     * 4's bytes under 3's hash. */
    { int ord[NB]; int k = 0; ord[k++] = 1; ord[k++] = 3; ord[k++] = 0; ord[k++] = 4; ord[k++] = 2;
      for (int i = 5; i < NB; i++) ord[k++] = i;
      g_norder = NB; for (int i = 0; i < NB; i++) g_order[i] = ord[i]; }
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB, "the chunk still completes");
    ok(g_wrong_body == 0, "NO record was written with another block's bytes (the run-5 corruption)");
    if (g_wrong_body) printf("      %d record(s) carried the wrong body\n", g_wrong_body);
    { int ascending = 1; for (int i = 1; i < NB; i++) if (g_stored_h[i] <= g_stored_h[i-1]) ascending = 0;
      ok(ascending, "and the archive still grew in ascending height order"); }

    printf("== noise and abuse ==\n");
    reset(); order_forward(); g_inject_ping = 1;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB && g_pongs == 1, "a ping mid-chunk is answered and does not disturb the fetch");
    reset(); order_forward(); g_inject_unasked = 1;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB && g_nstored == NB, "a block we never asked for is drained, not stored");
    reset();                       /* deliver block 0 twice, then the rest: 41 messages for 40 blocks */
    g_norder = NB + 1; g_order[0] = 0; for (int i = 0; i < NB; i++) g_order[i + 1] = i;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB && g_nstored == NB, "a duplicate delivery is ignored, not stored twice");
    reset(); order_forward(); g_bad_prev = 6;      /* block 5's prevhash corrupted */
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == IBD_FAIL_LINK, "a block whose prevhash breaks the header chain fails the chunk -- with the LINK reason code");
    reset(); order_forward(); g_bad_consensus = 4; /* block 3 fails cons_verify */
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == IBD_FAIL_CONSENSUS, "a block that fails cons_verify fails the chunk (same gate as the serial path) -- CONSENSUS reason code");
    reset(); g_norder = NB / 2; for (int i = 0; i < g_norder; i++) g_order[i] = i;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == IBD_FAIL_READ, "a peer that goes quiet half way does NOT report a complete chunk -- READ reason code");

    printf("== the chunk budget is a STALL clock: the progress hook fires once per wanted block ==\n");
    /* 2026-09-07: the worker's 120 s alarm covered the WHOLE chunk, which at
     * 40 x 1.5 MB blocks is a ~470 KB/s absolute bar; it dropped 429 peers
     * above the pool-relative floor in seven hours. The alarm is now re-armed
     * from this hook, so only a peer that delivers NOTHING for 120 s trips it. */
    ibd_pipeline_set_progress(count_progress, NULL);
    reset(); order_forward(); g_progress = 0;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB && g_progress == NB, "forward delivery: the hook fired exactly once per block (40)");
    reset(); order_reverse(); g_progress = 0;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB && g_progress == NB, "reverse delivery: 40 firings -- progress is counted on ARRIVAL, so a peer whose blocks are parked is not a stalled peer");
    reset(); order_forward(); g_inject_unasked = 1; g_inject_ping = 1; g_progress = 0;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB && g_progress == NB, "a ping and an unasked block are NOT progress (still exactly 40)");
    reset(); order_forward(); g_norder = 7; g_progress = 0;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == IBD_FAIL_READ && g_progress == 7, "a peer that goes quiet after 7 blocks: 7 firings, then the chunk fails");
    /* 2026-09-07: the bytes hook charges bmc.downloadratelimit with every
     * block message's length, wanted or not */
    ibd_pipeline_set_bytes(count_bytes);
    reset(); order_forward(); g_inject_unasked = 1; g_bytes_seen = 0;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB && g_bytes_seen == (long)NB * 120 + 100, "bytes hook: 40 blocks of 120 bytes plus the 100-byte unasked one = 4,900 bytes charged");
    ibd_pipeline_set_bytes(NULL);
    ibd_pipeline_set_progress(NULL, NULL);
    reset(); order_forward(); g_progress = 0;
    r = ibd_fetch_chunk_pipelined(3, NULL, NULL, LO, NB, buf, (unsigned)sizeof buf, NULL, 0);
    ok(r == NB && g_progress == 0, "with no hook registered the fetch still completes (the hook is optional)");

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
