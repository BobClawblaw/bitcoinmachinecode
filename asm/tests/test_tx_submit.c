/* test_tx_submit.c -- hermetic test of the sendrawtransaction worker-side
 * handler daemon/tx_submit.c (txsub_accept_and_relay), decoupled from the live
 * peer legs by driving it over a socketpair.
 *
 * Same seeded-LSM setup as tests/test_tx_accept_e2e.c:
 *   1. a genuine valid p2wpkh spend -> accepted (returns 1), stored in the
 *      mempool, AND framed as a "tx" P2P message on the peer socket, byte-for-
 *      byte the raw tx.
 *   2. a corrupted-signature spend -> rejected (negative Core code, reason set)
 *      and NOTHING written to the peer socket.
 *   3. peer_fds with a mix of live and -1 slots -> only the live legs receive
 *      the relay (relayed count matches).
 * The relay proof against REAL mainnet peers is deferred to post-sync (a real
 * tx can't validate against an incomplete UTXO set); this proves the plumbing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include "modern_spend.h"
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int u32;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, u64 value, u64 height, u64 is_coinbase, const u8* script, u32 slen);
extern void utxo_lsm_close(void* lst);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* out_len);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern int  tx_dispatch_init(void);
extern int  tx_policy_init(void);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern int  txsub_accept_and_relay(void* mp_area, const u8* tx, unsigned long len,
                                   const int* peer_fds, int n_fds,
                                   char* reason, unsigned long rcap, int* relayed_out);

struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask;
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

static u8 mp_area[40 + 1024*48 + 8];
static u8 mp_blob[2<<20];
static int g_fails = 0, g_checks = 0;
/* Strong definition of the announce hook: overrides the weak stub in
 * daemon/tx_submit.c, so this test can prove WHICH txid was queued without
 * linking daemon/tx_relay.c. The real queue is exercised in test_tx_relay. */
static u8  ann_txid[32];
static int ann_calls;
void txrelay_announce_own(const u8 txid[32]){ memcpy(ann_txid, txid, 32); ann_calls++; }

static void ck(const char* name, int cond){
    g_checks++;
    if (cond) printf("  ok  %s\n", name);
    else { g_fails++; printf("  FAIL %s\n", name); }
}

static void seed_utxos(const msend_t** specs, int n){
    unsigned long slots = 1UL<<16;
    long ustruct = utxo_struct_size(slots);
    void* table = malloc((size_t)ustruct);
    void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    u64 op_th = slots*2, fill_th = slots*3/4, tomb_cap = op_th, desc_cap = slots*3;
    u64 scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    lst.op_threshold = op_th; lst.fill_threshold = fill_th;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_buf = malloc(scratch_cap); lst.scratch_cap = scratch_cap;
    if (utxo_lsm_init(&lst) != 1) { fprintf(stderr, "seed: utxo_lsm_init failed\n"); exit(1); }
    for (int i=0;i<n;i++){
        const msend_t* s = specs[i];
        long r = utxo_lsm_put(&lst, table, s->txid, 0, s->prev_amount, 0, 0, s->prev_spk, (u32)s->prev_spklen);
        if (r != 1) { fprintf(stderr, "seed: utxo_lsm_put(%s) returned %ld\n", s->name, r); exit(1); }
    }
    utxo_lsm_close(&lst);
}

/* read exactly n bytes (socketpair is reliable + already buffered post-write) */

int main(void){
    tt_isolate();
    const msend_t* s  = &modern_spends[0];
    const msend_t* s2 = &modern_spends[1];
    const msend_t* seeds[2] = { s, s2 };
    seed_utxos(seeds, 2);

    if (!tx_dispatch_init()) { fprintf(stderr, "tx_dispatch_init failed\n"); return 1; }
    if (!tx_policy_init())   { fprintf(stderr, "tx_policy_init failed\n");   return 1; }
    mpool_init(mp_area, 1024, mp_blob, sizeof mp_blob);

    /* socketpair stands in for a peer leg. A read timeout on the peer end keeps
     * a missed relay from hanging the test (it fails the read assertion instead). */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0){ perror("socketpair"); return 1; }
    { struct timeval tv = {2,0}; setsockopt(sp[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); }

    printf("== valid spend: accept, queue an announcement, push NOTHING ==\n");
    { int fds[1] = { sp[0] };
      char reason[128]; int relayed = -1;
      ann_calls = 0; memset(ann_txid, 0, 32);
      int r = txsub_accept_and_relay(mp_area, s->tx, (unsigned long)s->txlen, fds, 1, reason, sizeof reason, &relayed);
      ck("valid tx accepted (result==1)", r == 1);
      ck("queued for the 1 live leg", relayed == 1);
      u8 txid[32], tb[4096]; tx_txid(txid, s->tx, (unsigned long)s->txlen, tb, sizeof tb);
      unsigned long mlen=0; const u8* found = mpool_get(mp_area, txid, &mlen);
      ck("accepted tx stored in mempool", found != NULL && mlen == (unsigned long)s->txlen);
      ck("announce hook called exactly once", ann_calls == 1);
      ck("announced the accepted txid", memcmp(ann_txid, txid, 32) == 0);
      /* The whole point of the change: an accepted transaction must NOT be
       * pushed at the peer unasked. The socket has to be silent -- Core
       * announces the txid and waits for getdata, and so do we now. */
      { int fl = fcntl(sp[1], F_GETFL, 0); fcntl(sp[1], F_SETFL, fl | O_NONBLOCK);
        u8 spill[64]; ssize_t got = read(sp[1], spill, sizeof spill);
        ck("nothing written to the peer socket (no unsolicited push)",
           got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        fcntl(sp[1], F_SETFL, fl); }
    }

    printf("\n== corrupted-signature spend: reject, NOTHING relayed ==\n");
    { static u8 badtx[1024]; memcpy(badtx, s2->tx, s2->txlen); int badlen = s2->txlen;
      const u8* sig0 = s2->wit[0]; int sig0len = s2->witlen[0]; int at=-1;
      for (int k=0;k+sig0len<=badlen;k++) if (memcmp(badtx+k, sig0, sig0len)==0){ at=k; break; }
      ck("located sig for corruption", at >= 0);
      if (at >= 0) badtx[at+6] ^= 0x01;
      int fds[1] = { sp[0] };
      char reason[128]; reason[0]=0; int relayed=-1;
      int r = txsub_accept_and_relay(mp_area, badtx, (unsigned long)badlen, fds, 1, reason, sizeof reason, &relayed);
      ck("corrupted-sig tx rejected (result<0)", r < 0);
      ck("reject reason is non-empty", reason[0] != 0);
      ck("nothing queued on reject", relayed == 0);
      ck("announce hook NOT called on reject", ann_calls == 1);
      /* peer socket must have no new bytes: set non-blocking, expect EAGAIN */
      int fl = fcntl(sp[1], F_GETFL, 0); fcntl(sp[1], F_SETFL, fl | O_NONBLOCK);
      u8 junk[8]; int r2 = (int)read(sp[1], junk, sizeof junk);
      ck("no wire bytes sent for a rejected tx", r2 <= 0);
      fcntl(sp[1], F_SETFL, fl);
      printf("     (reject reason: %s)\n", reason);
    }

    printf("\n== mixed peer_fds: only live legs are counted ==\n");
    { int sp2[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp2);
      { struct timeval tv = {2,0}; setsockopt(sp2[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); }
      /* Use the OTHER valid fixture (s2): the global mempool-policy state has
       * already seen s (case 1), so re-submitting it would be a genuine
       * duplicate reject even in a fresh mempool. s2's valid form was never
       * accepted (case 2 only rejected a corrupted copy at the txval stage). */
      int fds[3] = { -1, sp2[0], -1 };
      char reason[128]; int relayed=-1;
      int r = txsub_accept_and_relay(mp_area, s2->tx, (unsigned long)s2->txlen, fds, 3, reason, sizeof reason, &relayed);
      ck("valid s2 accepted", r == 1);
      ck("counted only the 1 live leg among {-1, fd, -1}", relayed == 1);
      ck("announce hook called for s2", ann_calls == 2);
      /* still nothing pushed: the announcement is tx_relay.c's to send */
      { int fl = fcntl(sp2[1], F_GETFL, 0); fcntl(sp2[1], F_SETFL, fl | O_NONBLOCK);
        u8 spill[64]; ssize_t got = read(sp2[1], spill, sizeof spill);
        ck("live leg received no unsolicited push",
           got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)); }
      close(sp2[0]); close(sp2[1]);
    }

    close(sp[0]); close(sp[1]);
    printf("\n%s (%d checks, %d failures)\n", g_fails==0 ? "ALL PASS" : "SOME FAILED", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
