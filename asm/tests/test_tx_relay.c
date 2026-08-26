/* tests/test_tx_relay.c -- hermetic test of the worker's receive-side
 * transaction relay (daemon/tx_relay.c, txrelay_poll_leg), driven over a
 * socketpair standing in for an outbound peer leg. Same seeded-LSM setup as
 * test_tx_submit.c / test_tx_accept_e2e.c.
 *
 * What must hold:
 *   1. an announced tx (inv type MSG_TX) is requested with a getdata whose
 *      entry type is MSG_WITNESS_TX (0x40000001) -- type 1 would fetch the
 *      witness-stripped serialization, incident #10's bug shape -- and the
 *      buffered `tx` reply is validated and stored in the mempool;
 *   2. re-announcing a tx the pool already holds sends NO getdata;
 *   3. a corrupted-signature tx is rejected and stays out of the pool, and
 *      its txid enters the recently-requested ring (a re-announcement inside
 *      the ring window is not re-fetched);
 *   4. a ping consumed by the drain is answered with a matching pong --
 *      losing it would eventually cost the connection.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
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
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern long txrelay_poll_leg(int fd, void* mp, int max_ms);
typedef long (*txacc_resolver_t)(const u8 txid[32], unsigned long index,
                                 unsigned long long* value, unsigned long* height,
                                 unsigned long* is_coinbase, const u8** script,
                                 unsigned long* slen);
extern void tx_accept_set_resolver(txacc_resolver_t fn);

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

static int read_n(int fd, u8* buf, int n){
    int got = 0;
    while (got < n){ int r = (int)read(fd, buf+got, n-got); if (r <= 0) break; got += r; }
    return got;
}

/* read one framed message from the peer end; returns payload length or -1 */
static int read_msg(int fd, char cmd_out[13], u8* pl, int cap){
    u8 hdr[24];
    if (read_n(fd, hdr, 24) != 24) return -1;
    memcpy(cmd_out, hdr+4, 12); cmd_out[12] = 0;
    int plen = (int)((unsigned)hdr[16] | ((unsigned)hdr[17]<<8) | ((unsigned)hdr[18]<<16) | ((unsigned)hdr[19]<<24));
    if (plen > cap) return -1;
    if (read_n(fd, pl, plen) != plen) return -1;
    return plen;
}

static int no_bytes_pending(int fd){
    int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    u8 junk[8]; int r = (int)read(fd, junk, sizeof junk);
    fcntl(fd, F_SETFL, fl);
    return r <= 0;
}

/* incident #48's fix, in miniature: resolution through an injected LIVE
 * resolver instead of the boot-latched snapshot. This stub stands in for
 * utxo_live_resolve, serving prevouts the snapshot has never seen. */
static long stub_resolve(const u8 txid[32], unsigned long index,
                         unsigned long long* value, unsigned long* height,
                         unsigned long* is_coinbase, const u8** script,
                         unsigned long* slen){
    for (int i = 0; i < modern_num_spends; i++){
        const msend_t* s = &modern_spends[i];
        if (!memcmp(txid, s->txid, 32) && index == 0){
            *value = s->prev_amount; *height = 1; *is_coinbase = 0;
            *script = s->prev_spk; *slen = s->prev_spklen;
            return 1;
        }
    }
    return 0;
}

static void send_inv1(int peer_fd, const u8 txid[32]){
    u8 inv[37];
    inv[0]=1; inv[1]=1; inv[2]=0; inv[3]=0; inv[4]=0;   /* count=1, type=MSG_TX */
    memcpy(inv+5, txid, 32);
    p2p_write(peer_fd, "inv", 3, inv, 37);
}

int main(void){
    tt_isolate();
    const msend_t* s  = &modern_spends[0];
    const msend_t* s2 = &modern_spends[1];
    const msend_t* seeds[2] = { s, s2 };
    seed_utxos(seeds, 2);

    if (!tx_dispatch_init()) { fprintf(stderr, "tx_dispatch_init failed\n"); return 1; }
    if (!tx_policy_init())   { fprintf(stderr, "tx_policy_init failed\n");   return 1; }
    mpool_init(mp_area, 1024, mp_blob, sizeof mp_blob);

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0){ perror("socketpair"); return 1; }

    u8 txid[32], txid2[32]; static u8 tb[1<<20];
    tx_txid(txid,  s->tx,  (unsigned long)s->txlen,  tb, sizeof tb);
    tx_txid(txid2, s2->tx, (unsigned long)s2->txlen, tb, sizeof tb);

    printf("== 1: announced tx is fetched (MSG_WITNESS_TX) and accepted ==\n");
    {
        /* stage BOTH the announcement and the reply before the drain runs --
         * the socketpair buffers them, so the single-threaded drain reads
         * the inv, sends its getdata, and finds the 'tx' already waiting */
        send_inv1(sp[1], txid);
        p2p_write(sp[1], "tx", 2, s->tx, (unsigned)s->txlen);
        long acc = txrelay_poll_leg(sp[0], mp_area, 200);
        ck("one tx accepted", acc == 1);
        unsigned long mlen=0; const u8* found = mpool_get(mp_area, txid, &mlen);
        ck("accepted tx stored in mempool", found != NULL && mlen == (unsigned long)s->txlen);
        char cmd[13]; static u8 pl[4096];
        int plen = read_msg(sp[1], cmd, pl, sizeof pl);
        ck("drain sent a getdata", plen == 37 && strcmp(cmd, "getdata") == 0);
        ck("entry type is MSG_WITNESS_TX (0x40000001), NOT bare MSG_TX",
           plen == 37 && pl[1]==0x01 && pl[2]==0x00 && pl[3]==0x00 && pl[4]==0x40);
        ck("entry hash is the announced txid", plen == 37 && memcmp(pl+5, txid, 32) == 0);
    }

    printf("\n== 2: re-announcing a pooled tx sends NO getdata ==\n");
    {
        send_inv1(sp[1], txid);
        long acc = txrelay_poll_leg(sp[0], mp_area, 200);
        ck("nothing accepted", acc == 0);
        ck("no getdata for a tx we already hold", no_bytes_pending(sp[1]));
    }

    printf("\n== 3: corrupted reply is rejected; ring suppresses a re-fetch ==\n");
    {
        static u8 badtx[4096]; memcpy(badtx, s2->tx, s2->txlen); int badlen = s2->txlen;
        const u8* sig0 = s2->wit[0]; int sig0len = s2->witlen[0]; int at=-1;
        for (int k=0;k+sig0len<=badlen;k++) if (memcmp(badtx+k, sig0, sig0len)==0){ at=k; break; }
        ck("located sig for corruption", at >= 0);
        if (at >= 0) badtx[at+6] ^= 0x01;
        send_inv1(sp[1], txid2);
        p2p_write(sp[1], "tx", 2, badtx, (unsigned)badlen);
        long acc = txrelay_poll_leg(sp[0], mp_area, 200);
        ck("corrupted tx not accepted", acc == 0);
        unsigned long mlen=0;
        ck("corrupted tx not in mempool", mpool_get(mp_area, txid2, &mlen) == NULL);
        char cmd[13]; static u8 pl[4096];
        int plen = read_msg(sp[1], cmd, pl, sizeof pl);
        ck("a getdata was sent for the announcement", plen == 37 && strcmp(cmd, "getdata") == 0);
        /* announce it again: still absent from the pool, but inside the
         * recently-requested ring window -- must NOT be re-fetched (the
         * window rolls, so this is a bounded suppression, not a permanent
         * blacklist) */
        send_inv1(sp[1], txid2);
        long acc2 = txrelay_poll_leg(sp[0], mp_area, 200);
        ck("nothing accepted on re-announce", acc2 == 0);
        ck("ring suppressed the re-fetch", no_bytes_pending(sp[1]));
    }

    printf("\n== 4: a ping consumed by the drain is answered ==\n");
    {
        u8 nonce[8] = {1,2,3,4,5,6,7,8};
        p2p_write(sp[1], "ping", 4, nonce, 8);
        txrelay_poll_leg(sp[0], mp_area, 200);
        char cmd[13]; static u8 pl[64];
        int plen = read_msg(sp[1], cmd, pl, sizeof pl);
        ck("pong sent", plen == 8 && strcmp(cmd, "pong") == 0);
        ck("pong echoes the nonce", plen == 8 && memcmp(pl, nonce, 8) == 0);
    }

    printf("\n== 5: injected live resolver replaces the snapshot (incident #48) ==\n");
    {
        /* modern_spends[2]'s prevout was never seeded into the LSM, so the
         * snapshot path CANNOT resolve it -- the exact shape of a live
         * writer outrunning a boot-latched snapshot. */
        const msend_t* s3 = &modern_spends[2];
        u8 txid3[32]; tx_txid(txid3, s3->tx, (unsigned long)s3->txlen, tb, sizeof tb);
        p2p_write(sp[1], "tx", 2, s3->tx, (unsigned)s3->txlen);
        long acc = txrelay_poll_leg(sp[0], mp_area, 200);
        ck("snapshot path cannot resolve the unseeded prevout", acc == 0);
        unsigned long mlen=0;
        ck("...and the tx is not pooled", mpool_get(mp_area, txid3, &mlen) == NULL);
        tx_accept_set_resolver(stub_resolve);
        p2p_write(sp[1], "tx", 2, s3->tx, (unsigned)s3->txlen);
        acc = txrelay_poll_leg(sp[0], mp_area, 200);
        ck("resolved and accepted via the injected resolver", acc == 1);
        ck("...and pooled", mpool_get(mp_area, txid3, &mlen) != NULL
                            && mlen == (unsigned long)s3->txlen);
        tx_accept_set_resolver(0);
    }

    close(sp[0]); close(sp[1]);
    printf("\n%s (%d checks, %d failures)\n", g_fails==0 ? "ALL PASS" : "SOME FAILED", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
