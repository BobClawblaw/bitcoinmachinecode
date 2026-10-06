/* tests/test_ibd_rolling.c -- Core's download shape (2026-10-04,
 * bmc.dlshape=core): at most 16 blocks in flight per peer, topped up as each
 * lands, ACROSS the chunk boundary, so the peer's pipe never drains between
 * chunks.
 *
 * The finding: ibd_fetch_chunk_pipelined asks for a whole chunk and waits for
 * every block of it before the worker can ask for more, so each peer goes
 * idle for a round trip at every chunk boundary -- every 16 blocks since
 * 2026-10-01. Run 33 (quiet box) finished 9.6% behind run 31, losing from
 * 400,000 on. Core tops each peer up to MAX_BLOCKS_IN_TRANSIT_PER_PEER on
 * every pass (net_processing.cpp:6168-6191).
 *
 * The scripted peer here answers what it was ASKED, in request order, one
 * block per read -- a FIFO per socket -- and records how many requests were
 * outstanding when it delivered each chunk's last block. Whole-chunk fetching
 * leaves zero there; the rolling fetch leaves the lookahead's requests.
 *
 * Watched to fail first: with the lookahead fill removed from
 * ibd_fetch_chunk_rolling, the boundary and carry checks fail. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ibd_pipeline.h"

static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }

#define NB 96
#define CH 16
#define LO 700000L
#define CAP 16

/* ---- a synthetic chain: block i is marked by i at [76..79] ---- */
static void hash_of(unsigned char out[32], long i){ memset(out, 0xA5, 32); memcpy(out, &i, 4); }
static unsigned char g_blk[NB][160];
static void build_chain(void){
    for (long i = 0; i < NB; i++){
        memset(g_blk[i], 0, sizeof g_blk[i]);
        g_blk[i][0] = 1;
        if (i > 0) hash_of(g_blk[i] + 4, i - 1);
        memcpy(g_blk[i] + 76, &i, 4);
    }
}
static long marker(const unsigned char* b){ long i = 0; memcpy(&i, b + 76, 4); return i; }

/* ---- the scripted peer: a FIFO of requested block indices per socket ---- */
#define FDS 8
static long q[FDS][4096]; static int qh[FDS], qt[FDS];
static long g_peer_max_out;               /* the most requests outstanding on any socket */
static long g_hashes_requested;           /* every hash in every getdata */
static long g_out_at_chunk_end[NB / CH];  /* outstanding requests when a chunk's last block was delivered */
static int  g_swap_pairs;                 /* 1: swap requests (0,1),(2,3)..; 2: swap (1,2),(3,4).. -- across each chunk boundary */
static long g_bad_prev_at = -1;           /* corrupt this block's prevhash on delivery */
long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned len){
    const unsigned char* p = pl; (void)cmdlen;
    if (!strncmp(cmd, "getdata", 7)){
        if (len != 1u + (unsigned)p[0] * 36u){ printf("      malformed getdata\n"); exit(2); }
        for (unsigned k = 0; k < p[0]; k++){
            const unsigned char* e = p + 1 + k * 36;
            if (!(e[0]==0x02 && e[1]==0 && e[2]==0 && e[3]==0x40)){ printf("      not MSG_WITNESS_BLOCK\n"); exit(2); }
            long i = 0; memcpy(&i, e + 4, 4);
            q[fd][qt[fd]++] = i; g_hashes_requested++;
        }
        long out = qt[fd] - qh[fd]; if (out > g_peer_max_out) g_peer_max_out = out;
    }
    return (long)len;
}
int p2p_read(int fd, char cmd[12], void* pl, unsigned cap, unsigned* outlen){
    if (qh[fd] >= qt[fd]) return -1;                    /* nothing asked: the fetcher waited on an empty pipe */
    if (g_swap_pairs && qt[fd] - qh[fd] >= 2 && (qh[fd] % 2) == (g_swap_pairs == 1 ? 0 : 1)){
        long t = q[fd][qh[fd]]; q[fd][qh[fd]] = q[fd][qh[fd] + 1]; q[fd][qh[fd] + 1] = t;
    }
    long i = q[fd][qh[fd]++];
    memcpy(cmd, "block\0\0\0\0\0\0", 12);
    if (sizeof g_blk[i] > cap) return -1;
    memcpy(pl, g_blk[i], sizeof g_blk[i]); *outlen = sizeof g_blk[i];
    if (i == g_bad_prev_at) memset((unsigned char*)pl + 4, 0xEE, 32);
    if ((i + 1) % CH == 0 && i / CH < NB / CH) g_out_at_chunk_end[i / CH] = qt[fd] - qh[fd];
    return (int)sizeof g_blk[i];
}
/* hst is a pointer to the chunk's first block index */
int hst_get_at(void* hst, unsigned long long idx, void* rec112){
    long base = *(long*)hst, i = base + (long)idx;
    if (i < 0 || i >= NB) return 0;
    unsigned char* r = rec112; memset(r, 0, 112);
    memcpy(r, g_blk[i], 80); hash_of(r + 80, i);
    return 1;
}
int cons_verify(const void* b, long len, void* s, unsigned c){ (void)b; (void)len; (void)s; (void)c; return 1; }
void block_hash(unsigned char out[32], const unsigned char* hdr80){ hash_of(out, marker(hdr80)); }
static long g_stored[NB * 2]; static int g_nstored; static int g_wrong_body;
long store_append_shared(void* st, long height, const unsigned char hash[32], const unsigned char* raw, unsigned len){
    (void)st; (void)len;
    unsigned char want[32]; hash_of(want, marker(raw));
    if (memcmp(hash, want, 32) != 0 || height != LO + marker(raw)) g_wrong_body++;
    if (g_nstored < NB * 2) g_stored[g_nstored++] = height;
    return height;
}

static void reset(void){
    memset(qh, 0, sizeof qh); memset(qt, 0, sizeof qt);
    g_peer_max_out = 0; g_hashes_requested = 0; g_nstored = 0; g_wrong_body = 0;
    g_swap_pairs = 0; g_bad_prev_at = -1;
    for (int k = 0; k < NB / CH; k++) g_out_at_chunk_end[k] = -1;
    ibd_pipeline_drop_carry();
}
static int stored_in_order(long first, long n){
    if (g_nstored != n) return 0;
    for (long i = 0; i < n; i++) if (g_stored[i] != LO + first + i) return 0;
    return 1;
}

int main(void){
    static unsigned char buf[1 << 16];
    long base[NB / CH]; for (int k = 0; k < NB / CH; k++) base[k] = (long)k * CH;
    build_chain();
    const int NCH = NB / CH;

    printf("== control: the whole-chunk fetch drains the pipe at every boundary ==\n");
    reset();
    for (int k = 0; k < NCH; k++)
        if (ibd_fetch_chunk_pipelined(3, NULL, &base[k], LO + base[k], CH, buf, sizeof buf, NULL, 0) != CH) ok(0, "control chunk failed");
    { int drained = 1; for (int k = 0; k < NCH - 1; k++) if (g_out_at_chunk_end[k] != 0) drained = 0;
      ok(drained, "control: nothing outstanding when each chunk's last block left the peer (the round trip Core avoids)"); }

    printf("== Core's shape: 16 in flight, refilled across the boundary ==\n");
    reset();
    int all = 1;
    for (int k = 0; k < NCH; k++){
        long* nx = (k + 1 < NCH) ? &base[k + 1] : NULL;
        long r = ibd_fetch_chunk_rolling(3, NULL, &base[k], LO + base[k], CH, nx, nx ? LO + *nx : 0, nx ? CH : 0, CAP,
                                         buf, sizeof buf, NULL, 0);
        if (r != CH){ all = 0; printf("      chunk %d returned %ld (%s)\n", k, r, ibd_pipeline_fail_name((int)r)); }
        if (ibd_pipeline_max_inflight() > CAP) all = 0;
    }
    ok(all, "every chunk completed, the fetcher never counted more than 16 in flight");
    ok(stored_in_order(0, NB) && !g_wrong_body, "all 96 blocks stored once, at their real heights, ascending");
    ok(g_peer_max_out <= CAP, "the peer never saw more than 16 requests outstanding (MAX_BLOCKS_IN_TRANSIT_PER_PEER)");
    { int kept_full = 1; for (int k = 0; k < NCH - 1; k++) if (g_out_at_chunk_end[k] <= 0) kept_full = 0;
      ok(kept_full, "when each chunk's last block left the peer, the next chunk's requests were already queued");
      printf("      outstanding at each boundary:"); for (int k = 0; k < NCH - 1; k++) printf(" %ld", g_out_at_chunk_end[k]); printf("\n"); }
    ok(g_hashes_requested == NB, "each block was requested exactly once");

    printf("== out-of-order answers: still stored ascending ==\n");
    reset(); g_swap_pairs = 1; all = 1;
    for (int k = 0; k < NCH; k++){
        long* nx = (k + 1 < NCH) ? &base[k + 1] : NULL;
        if (ibd_fetch_chunk_rolling(3, NULL, &base[k], LO + base[k], CH, nx, nx ? LO + *nx : 0, nx ? CH : 0, CAP,
                                    buf, sizeof buf, NULL, 0) != CH) all = 0;
    }
    ok(all && stored_in_order(0, NB) && !g_wrong_body, "swapped deliveries within a chunk: every block in place");
    reset(); g_swap_pairs = 2; all = 1; long carried_total = 0;
    for (int k = 0; k < NCH; k++){
        long* nx = (k + 1 < NCH) ? &base[k + 1] : NULL;
        if (ibd_fetch_chunk_rolling(3, NULL, &base[k], LO + base[k], CH, nx, nx ? LO + *nx : 0, nx ? CH : 0, CAP,
                                    buf, sizeof buf, NULL, 0) != CH) all = 0;
        carried_total += ibd_pipeline_carried();
    }
    ok(all && stored_in_order(0, NB) && !g_wrong_body, "the next chunk's first block answered BEFORE this chunk's last: every block in place");
    ok(carried_total == NCH - 1, "each early block of the next chunk was carried into that chunk's call (one per boundary)");
    ok(g_hashes_requested == NB, "a carried block is not asked for again");

    printf("== the carry is for ONE chunk on ONE socket ==\n");
    reset();
    if (ibd_fetch_chunk_rolling(3, NULL, &base[0], LO, CH, &base[1], LO + base[1], CH, CAP, buf, sizeof buf, NULL, 0) != CH) ok(0, "chunk 0");
    long before = g_hashes_requested;
    /* the worker gave chunk 1 away and fetches chunk 3 on the same socket:
     * chunk 1's requests arrive anyway and must be drained, not stored */
    long r = ibd_fetch_chunk_rolling(3, NULL, &base[3], LO + base[3], CH, NULL, 0, 0, CAP, buf, sizeof buf, NULL, 0);
    ok(r == CH, "a different chunk on the same socket completes");
    { int none_of_1 = 1; for (int i = 0; i < g_nstored; i++) if (g_stored[i] >= LO + CH && g_stored[i] < LO + 2 * CH) none_of_1 = 0;
      ok(none_of_1 && g_nstored == 2 * CH, "the abandoned lookahead's blocks were drained, never stored"); }
    ok(g_hashes_requested - before == CH, "chunk 3 requested in full");
    ok(g_peer_max_out <= CAP, "the stale requests counted against the 16: never more outstanding");
    reset();
    if (ibd_fetch_chunk_rolling(3, NULL, &base[0], LO, CH, &base[1], LO + base[1], CH, CAP, buf, sizeof buf, NULL, 0) != CH) ok(0, "chunk 0 on fd 3");
    before = g_hashes_requested;
    r = ibd_fetch_chunk_rolling(4, NULL, &base[1], LO + base[1], CH, NULL, 0, 0, CAP, buf, sizeof buf, NULL, 0);
    ok(r == CH && g_hashes_requested - before == CH, "the same chunk on a NEW socket is requested in full (the carry stayed with fd 3)");

    printf("== a bad block in the lookahead fails the call and drops the carry ==\n");
    reset(); g_swap_pairs = 2; g_bad_prev_at = CH;   /* block 16 arrives during chunk 0's call */
    r = ibd_fetch_chunk_rolling(3, NULL, &base[0], LO, CH, &base[1], LO + base[1], CH, CAP, buf, sizeof buf, NULL, 0);
    ok(r == -6, "a lookahead block whose prevhash breaks its headers fails the call (IBD_FAIL_LINK)");
    ok(ibd_pipeline_carried() == 0, "nothing is carried past a failure");
    g_bad_prev_at = -1; g_swap_pairs = 0; memset(qh, 0, sizeof qh); memset(qt, 0, sizeof qt); before = g_hashes_requested;
    r = ibd_fetch_chunk_rolling(5, NULL, &base[1], LO + base[1], CH, NULL, 0, 0, CAP, buf, sizeof buf, NULL, 0);
    ok(r == CH && g_hashes_requested - before == CH, "the retry on a fresh peer requests the whole chunk");

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
