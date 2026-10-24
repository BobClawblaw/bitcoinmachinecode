/* tests/test_tx_relay_rejects.c -- the relay path's defences against work a
 * peer chooses for us (audit 2026-10-23: MPL-1, MPL-2, MPL-5, MPL-7, MPL-8).
 * Driven over socketpairs standing in for outbound legs, against a seeded
 * LSM and the real accept path, with the shared recent-rejects filter
 * attached as the daemon attaches it. Fixtures are anyone-can-spend (OP_TRUE)
 * and never-spendable (OP_FALSE) coins under -acceptnonstdtxn, so a script
 * failure is cheap to make and the script verifier's run counter says
 * exactly how much verification each step cost.
 *
 *   MPL-1  a refused transaction pushed again, unasked, is dropped before it
 *          is validated -- on a leg (txr_take_tx) and from an inbound serve
 *          child (tx_accept_serve_tx); its announcement is not requested;
 *          policy runs before scripts (a zero-fee, script-invalid tx is a fee
 *          refusal and costs no verification); refusals are filed by wtxid,
 *          so a copy with a mangled witness does not shut out the valid one.
 *   MPL-2  a fee-refused parent re-sent again and again does not re-verify
 *          its parked children; a child whose package fails for a final
 *          reason leaves the orphan pool and enters the reject filter.
 *   MPL-5  one peer flooding orphans evicts its own, not another peer's; one
 *          peer flooding announcements does not push another's requests out
 *          of the want table.
 *   MPL-7  a child with more than eight missing parents resolves when its
 *          last parent arrives; an accepted parent's every child is retried.
 *   MPL-8  "missing-ephemeral-spends" is a -26 refusal, not missing inputs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include "../daemon/node_config.h"
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned long long u64;
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
extern void tx_accept_set_tip(long tip);
extern long tx_accept_validate_p2p(void* mp, const u8 txid[32], const u8* tx, unsigned long len);
extern long tx_accept_serve_tx(void* mp, const u8 txid[32], const u8* tx, unsigned long len, long dv_ok);
extern long txacc_script_verify_count(void);
extern long txacc_test_reason_code(const char* r);
extern long txrelay_reject_filtered_count(void);
extern long txrelay_1p1c_attempts(void);
extern int  txrelay_classify_missing(const u8* tx, unsigned long len);
extern int  txrelay_test_want_present(const u8* h);
extern long txrelay_stats(long*, long*, long*, long*, long*, long*);
extern unsigned long serve_rejects_size(void);
extern void serve_rejects_attach(void* region);
extern int  serve_reject_has(const u8 h[32]);
extern void sha256d(unsigned char out[32], const void* msg, long len);

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

static int g_fails = 0;
static void ck(const char* name, int cond){ if (cond) printf("  ok  %s\n", name); else { g_fails++; printf("  FAIL %s\n", name); } }

static u8 mp_area[40 + 8192*80 + 8];
static u8 mp_blob[8 << 20];
static u8 sc[1 << 18];

/* ---- coins ---------------------------------------------------------------- */
static const u8 SPK_TRUE[1]  = { 0x51 };
static const u8 SPK_FALSE[1] = { 0x00 };
static u8 SPK_WSH[34];                         /* P2WSH of the script OP_TRUE */
#define NCOIN 48
typedef struct { u8 txid[32]; const u8* spk; u32 spklen; u64 v; } coin_t;
static coin_t coin[NCOIN];
static void seed_coins(void){
    { u8 ws = 0x51; extern void sha256_full(unsigned char out[32], const void* msg, long len);
      SPK_WSH[0] = 0x00; SPK_WSH[1] = 0x20; sha256_full(SPK_WSH + 2, &ws, 1); }
    for (int i = 0; i < NCOIN; i++){
        memset(coin[i].txid, 0, 32); coin[i].txid[0] = (u8)(i + 1); coin[i].txid[1] = 0xD7; coin[i].txid[31] = 0x5A;
        coin[i].v = 1000000;
        if (i < 40){ coin[i].spk = SPK_TRUE;  coin[i].spklen = 1; }
        else if (i < 44){ coin[i].spk = SPK_FALSE; coin[i].spklen = 1; }
        else { coin[i].spk = SPK_WSH; coin[i].spklen = 34; }
    }
    unsigned long slots = 1UL << 14;
    void* table = malloc((size_t)utxo_struct_size(slots));
    void* blob = malloc(32UL << 20);
    utxo_init(table, slots, blob, 32UL << 20);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    u64 op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    u64 scratch_cap = desc_cap*128 + 4*1024*1024 + 65536;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_buf = malloc(scratch_cap); lst.scratch_cap = scratch_cap;
    if (utxo_lsm_init(&lst) != 1){ fprintf(stderr, "utxo_lsm_init failed\n"); exit(1); }
    for (int i = 0; i < NCOIN; i++)
        if (utxo_lsm_put(&lst, table, coin[i].txid, 0, coin[i].v, 1, 0, coin[i].spk, coin[i].spklen) != 1){
            fprintf(stderr, "seed put failed\n"); exit(1); }
    utxo_lsm_close(&lst);
}

/* ---- transactions ----------------------------------------------------------
 * in[i] = (prev txid, index); outs[o] = (value, spk). wit: a one-item witness
 * for EVERY input when non-NULL (the item is the P2WSH witness script). */
typedef struct { const u8* prev; u32 idx; } in_t;
typedef struct { u64 v; const u8* spk; u32 spklen; } out_t;
static long mktx(u8* out, const in_t* in, int nin, const out_t* o, int nout, const u8* wit, int witlen){
    u8* p = out; *p++ = 2; *p++ = 0; *p++ = 0; *p++ = 0;
    if (wit){ *p++ = 0; *p++ = 1; }
    *p++ = (u8)nin;
    for (int i = 0; i < nin; i++){
        memcpy(p, in[i].prev, 32); p += 32;
        for (int b = 0; b < 4; b++) *p++ = (u8)(in[i].idx >> (8*b));
        *p++ = 0; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff;
    }
    *p++ = (u8)nout;
    for (int k = 0; k < nout; k++){
        for (int b = 0; b < 8; b++) *p++ = (u8)(o[k].v >> (8*b));
        *p++ = (u8)o[k].spklen; memcpy(p, o[k].spk, o[k].spklen); p += o[k].spklen;
    }
    if (wit) for (int i = 0; i < nin; i++){ *p++ = 1; *p++ = (u8)witlen; memcpy(p, wit, (size_t)witlen); p += witlen; }
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    return p - out;
}
/* one OP_TRUE coin -> two OP_TRUE outputs (big enough for the 65-byte floor) */
static long spend1(u8* out, const u8 prev[32], u32 idx, u64 inval, u64 fee, const u8* spk1, u32 spk1len){
    in_t in = { prev, idx };
    out_t o[2] = { { (inval - fee) / 2, SPK_TRUE, 1 }, { inval - fee - (inval - fee) / 2, spk1, spk1len } };
    return mktx(out, &in, 1, o, 2, 0, 0);
}
static void id_of(u8 id[32], const u8* tx, long n){ tx_txid(id, tx, (unsigned long)n, sc, sizeof sc); }
static int pooled(const u8 id[32]){ unsigned long l; return mpool_get(mp_area, id, &l) != 0; }

/* ---- the peer ends ---------------------------------------------------------- */
static void drain_peer(int fd){
    int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    u8 junk[8192];
    while (read(fd, junk, sizeof junk) > 0) {}
    fcntl(fd, F_SETFL, fl);
}
static long push(int leg[2], const u8* tx, long n){
    p2p_write(leg[1], "tx", 2, tx, (unsigned)n);
    long acc = txrelay_poll_leg(leg[0], mp_area, 50);
    drain_peer(leg[1]);
    return acc;
}
/* announce h, then see whether the leg asked for it */
static int asks_for(int leg[2], unsigned type, const u8 h[32]){
    drain_peer(leg[1]);
    u8 inv[37]; inv[0] = 1; inv[1] = (u8)type; inv[2] = 0; inv[3] = 0; inv[4] = 0; memcpy(inv + 5, h, 32);
    p2p_write(leg[1], "inv", 3, inv, 37);
    txrelay_poll_leg(leg[0], mp_area, 50);
    u8 buf[4096]; int got = 0, n;
    struct pollfd pf = { leg[1], POLLIN, 0 };
    while (poll(&pf, 1, 30) > 0 && (n = (int)read(leg[1], buf, sizeof buf)) > 0)
        for (int k = 0; k + 32 <= n; k++) if (!memcmp(buf + k, h, 32)) got = 1;
    return got;
}

int main(void){
    tt_isolate();
    setbuf(stdout, NULL);
    seed_coins();
    tx_accept_set_tip(500);
    if (!tx_dispatch_init()){ fprintf(stderr, "tx_dispatch_init failed\n"); return 1; }
    { extern node_config_t g_cfg; g_cfg.acceptnonstdtxn = 1; }
    if (!tx_policy_init()){ fprintf(stderr, "tx_policy_init failed\n"); return 1; }
    mpool_init(mp_area, 8192, mp_blob, sizeof mp_blob);
    void* rej = mmap(0, serve_rejects_size(), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    serve_rejects_attach(rej);
    int A[2], B[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, A) || socketpair(AF_UNIX, SOCK_STREAM, 0, B)){ perror("socketpair"); return 1; }
    static u8 t1[4096], t2[4096], t3[4096];
    u8 id1[32], id2[32], w1[32];
    long n1, n2, s0, f0;

    printf("== MPL-1: a refused transaction pushed again is dropped before validation ==\n");
    n1 = spend1(t1, coin[40].txid, 0, coin[40].v, 1000, SPK_TRUE, 1);      /* spends OP_FALSE: script-invalid */
    id_of(id1, t1, n1);
    s0 = txacc_script_verify_count(); f0 = txrelay_reject_filtered_count();
    ck("script-invalid tx refused", push(A, t1, n1) == 0 && !pooled(id1));
    ck("...after one script verification", txacc_script_verify_count() == s0 + 1);
    sha256d(w1, t1, n1);
    ck("...and its wtxid is in the reject filter", serve_reject_has(w1));
    s0 = txacc_script_verify_count();
    push(A, t1, n1); push(B, t1, n1);
    ck("MPL-1 pushed again on two legs: no verification at all", txacc_script_verify_count() == s0);
    ck("...both copies dropped by the filter", txrelay_reject_filtered_count() == f0 + 2);
    s0 = txacc_script_verify_count();
    ck("MPL-1 an inbound peer's copy (tx_accept_serve_tx) is dropped", tx_accept_serve_tx(mp_area, id1, t1, (unsigned long)n1, 1) == 0);
    ck("...without a verification", txacc_script_verify_count() == s0);
    ck("MPL-1 its announcement (MSG_TX; no witness, txid == wtxid) is not requested", !asks_for(A, 1, id1));
    { u8 other[32]; memset(other, 0x6b, 32);
      ck("(control) an unknown announcement is requested", asks_for(A, 1, other)); }

    printf("== MPL-1: policy runs before scripts ==\n");
    n2 = spend1(t2, coin[41].txid, 0, coin[41].v, 0, SPK_TRUE, 1);         /* zero fee AND script-invalid */
    id_of(id2, t2, n2);
    s0 = txacc_script_verify_count();
    long r2 = tx_accept_validate_p2p(mp_area, id2, t2, (unsigned long)n2);
    printf("  verdict %ld\n", r2);
    ck("MPL-1 a zero-fee, script-invalid tx is refused on fee (-28), as Core's PreChecks", r2 == -28);
    ck("...and its scripts were never run", txacc_script_verify_count() == s0);

    printf("== MPL-1: refusals are filed by wtxid, not txid ==\n");
    {   /* the same spend of a P2WSH(OP_TRUE) coin twice: once with the right
         * witness script, once with a wrong one -- one txid, two wtxids */
        static u8 good[512], bad[512];
        in_t in = { coin[44].txid, 0 };
        out_t o[2] = { { 499000, SPK_TRUE, 1 }, { 500000, SPK_TRUE, 1 } };
        const u8 ws_good[1] = { 0x51 }, ws_bad[1] = { 0x52 };
        long ng = mktx(good, &in, 1, o, 2, ws_good, 1), nb = mktx(bad, &in, 1, o, 2, ws_bad, 1);
        u8 gid[32], bid[32], bw[32]; id_of(gid, good, ng); id_of(bid, bad, nb); sha256d(bw, bad, nb);
        ck("one txid, two serializations", !memcmp(gid, bid, 32) && ng == nb);
        s0 = txacc_script_verify_count();
        ck("the mangled-witness copy is refused", push(A, bad, nb) == 0 && !pooled(bid));
        ck("...by its scripts", txacc_script_verify_count() == s0 + 1);
        ck("...filed under its WTXID", serve_reject_has(bw));
        ck("MPL-1 ...and NOT under the txid it shares with the valid transaction", !serve_reject_has(gid));
        s0 = txacc_script_verify_count();
        push(B, bad, nb);
        ck("the mangled copy again: dropped unverified", txacc_script_verify_count() == s0);
        ck("MPL-1 its MSG_WTX announcement is not requested", !asks_for(A, 5, bw));
        ck("MPL-1 the VALID transaction is still accepted", push(B, good, ng) == 1 && pooled(gid));
    }

    printf("== MPL-2: a fee-refused parent sent again does not re-verify its children ==\n");
    {   /* P pays nothing (refused on fee alone); C spends P's second output,
         * which is OP_FALSE, so no package can rescue it */
        static u8 P[512], C[512];
        long np = spend1(P, coin[0].txid, 0, coin[0].v, 0, SPK_FALSE, 1);
        u8 pid[32], cid[32], cw[32]; id_of(pid, P, np);
        u64 pv1 = coin[0].v - (coin[0].v) / 2;
        long nc = spend1(C, pid, 1, pv1, 20000, SPK_TRUE, 1);
        id_of(cid, C, nc); sha256d(cw, C, nc);
        ck("child first: parked as an orphan", push(A, C, nc) == 0 && txrelay_classify_missing(C, (unsigned long)nc) == 3);
        long a0 = txrelay_1p1c_attempts(); s0 = txacc_script_verify_count();
        ck("the parent arrives: refused on fee, the package fails", push(A, P, np) == 0 && !pooled(pid) && !pooled(cid));
        ck("...one package attempt", txrelay_1p1c_attempts() == a0 + 1);
        long s1 = txacc_script_verify_count();
        ck("MPL-2 the failed child left the orphan pool", txrelay_classify_missing(C, (unsigned long)nc) != 3);
        ck("MPL-2 ...and is in the reject filter (a final verdict)", serve_reject_has(cw));
        for (int k = 0; k < 6; k++) push(k & 1 ? B : A, P, np);
        printf("  scripts run by the first arrival: %ld; by six more: %ld\n", s1 - s0, txacc_script_verify_count() - s1);
        ck("MPL-2 six more arrivals of the parent: no verification", txacc_script_verify_count() == s1);
        ck("MPL-2 ...and no package attempt", txrelay_1p1c_attempts() == a0 + 1);
    }

    printf("== MPL-7: every parent of an orphan is remembered ==\n");
    {   /* K spends 10 parents; the old pool kept the first 8 */
        static u8 par[10][256]; long pn[10]; u8 pid[10][32];
        in_t in[10];
        for (int k = 0; k < 10; k++){
            pn[k] = spend1(par[k], coin[1 + k].txid, 0, coin[1 + k].v, 1000, SPK_TRUE, 1);
            id_of(pid[k], par[k], pn[k]);
            in[k].prev = pid[k]; in[k].idx = 0;
        }
        static u8 K[2048]; out_t o[1] = { { 10 * ((coin[1].v - 1000) / 2) - 5000, SPK_TRUE, 1 } };
        long nk = mktx(K, in, 10, o, 1, 0, 0); u8 kid[32]; id_of(kid, K, nk);
        ck("a 10-parent child is parked", push(A, K, nk) == 0 && txrelay_classify_missing(K, (unsigned long)nk) == 3);
        long acc = 0;
        for (int k = 0; k < 10; k++) acc += push(A, par[k], pn[k]);
        ck("MPL-7 its tenth parent's arrival lets it in", pooled(kid) && acc == 11);
    }
    {   /* X with two parked children: both must follow it in */
        static u8 X[256], Y1[256], Y2[256];
        long nx = spend1(X, coin[12].txid, 0, coin[12].v, 1000, SPK_TRUE, 1);
        u8 xid[32]; id_of(xid, X, nx);
        u64 half = (coin[12].v - 1000) / 2;
        long ny1 = spend1(Y1, xid, 0, half, 1000, SPK_TRUE, 1), ny2 = spend1(Y2, xid, 1, (coin[12].v - 1000) - half, 1000, SPK_TRUE, 1);
        u8 y1[32], y2[32]; id_of(y1, Y1, ny1); id_of(y2, Y2, ny2);
        push(A, Y1, ny1); push(A, Y2, ny2);
        long acc = push(A, X, nx);
        ck("MPL-7 a parent's arrival lets in BOTH parked children", acc == 3 && pooled(y1) && pooled(y2));
    }

    printf("== MPL-5: one peer's flood evicts its own orphans, not another's ==\n");
    {
        static u8 honest[4][256]; long hn[4];
        for (int k = 0; k < 4; k++){
            u8 nowhere[32]; memset(nowhere, 0x70 + k, 32);
            hn[k] = spend1(honest[k], nowhere, 0, 100000, 1000, SPK_TRUE, 1);
            push(B, honest[k], hn[k]);
        }
        int held = 0; for (int k = 0; k < 4; k++) held += txrelay_classify_missing(honest[k], (unsigned long)hn[k]) == 3;
        ck("peer B's four orphans are parked", held == 4);
        static u8 f[256];
        for (int i = 0; i < 2600; i++){
            u8 nowhere[32]; memset(nowhere, 0, 32); nowhere[0] = (u8)i; nowhere[1] = (u8)(i >> 8); nowhere[2] = 0xEE;
            long nf = spend1(f, nowhere, 0, 100000, 1000, SPK_TRUE, 1);
            p2p_write(A[1], "tx", 2, f, (unsigned)nf);
            /* a few at a time: the socketpair holds only a few dozen */
            if (i % 16 == 15){ txrelay_poll_leg(A[0], mp_area, 5); drain_peer(A[1]); }
        }
        txrelay_poll_leg(A[0], mp_area, 10); drain_peer(A[1]);
        long held_all = 0; txrelay_stats(0, 0, 0, 0, 0, &held_all);
        held = 0; for (int k = 0; k < 4; k++) held += txrelay_classify_missing(honest[k], (unsigned long)hn[k]) == 3;
        printf("  after 2,600 orphans from peer A: pool holds %ld, peer B's still parked: %d of 4\n", held_all, held);
        ck("the pool is full (the flood reached the limit)", held_all >= 2000);
        ck("MPL-5 peer B's orphans survive peer A's flood", held == 4);
    }
    printf("== MPL-5: one peer's announcements do not push another's requests out ==\n");
    {
        u8 hb[32]; memset(hb, 0x3c, 32);
        ck("peer B's announcement is requested", asks_for(B, 1, hb));
        ck("...and tracked", txrelay_test_want_present(hb));
        /* peer A announces 5,000 transactions (Core's per-message ceiling for
         * what it tracks), in one inv */
        static u8 inv[3 + 5000*36];
        inv[0] = 0xfd; inv[1] = (u8)(5000 & 0xff); inv[2] = (u8)(5000 >> 8);
        for (int i = 0; i < 5000; i++){
            u8* e = inv + 3 + i*36; e[0] = 1; e[1] = 0; e[2] = 0; e[3] = 0;
            memset(e + 4, 0, 32); e[4] = (u8)i; e[5] = (u8)(i >> 8); e[6] = 0xAB;
        }
        p2p_write(A[1], "inv", 3, inv, sizeof inv);
        txrelay_poll_leg(A[0], mp_area, 10); drain_peer(A[1]);
        ck("MPL-5 peer B's request is still tracked after peer A's 5,000", txrelay_test_want_present(hb));
        int kept = 0;
        for (int i = 0; i < 5000; i++){ u8 h[32]; memset(h, 0, 32); h[0] = (u8)i; h[1] = (u8)(i >> 8); h[2] = 0xAB; kept += txrelay_test_want_present(h); }
        printf("  peer A's announcements tracked: %d of 5000\n", kept);
        ck("MPL-5 peer A holds no more than its share (1,024) of the table", kept <= 1024 && kept > 0);
    }

    printf("== the policy test before the scripts must not lose the sigop count ==\n");
    {   /* txacc_prechecks parks the sigop cost; the policy layer reads AND
         * clears it on every call. Running the policy TEST first (Core's
         * order) left the commit pricing the entry at its plain vsize -- on
         * the RPC path since 2026-10-03, and on relay with MPL-1's reorder,
         * unless it is parked again. 100 sigops * 4 * 20 bytes = 8,000 WU:
         * a ~2,000 vB entry for a ~180-byte transaction (Core's
         * bytespersigop). */
        static u8 spk[100]; memset(spk, 0xac, sizeof spk);       /* 100 x OP_CHECKSIG */
        extern int txacc_entry_fee_vsize(const u8 txid[32], unsigned long long* fee, unsigned long long* vsize);
        extern long tx_accept_validate_reason(void*, const u8*, const u8*, unsigned long, char*, unsigned long);
        static u8 a[512], b[512]; u8 aid[32], bid[32]; char why[256];
        long na = spend1(a, coin[20].txid, 0, coin[20].v, 5000, spk, sizeof spk); id_of(aid, a, na);
        long nb = spend1(b, coin[21].txid, 0, coin[21].v, 5000, spk, sizeof spk); id_of(bid, b, nb);
        unsigned long long fa = 0, va = 0, fb = 0, vb = 0;
        ck("a sigop-heavy tx through the RPC path", tx_accept_validate_reason(mp_area, aid, a, (unsigned long)na, why, sizeof why) == 1);
        ck("...and one through relay", push(A, b, nb) == 1);
        txacc_entry_fee_vsize(aid, &fa, &va); txacc_entry_fee_vsize(bid, &fb, &vb);
        printf("  raw %ld / %ld bytes; entry vsize %llu / %llu\n", na, nb, va, vb);
        ck("the RPC entry is priced at the sigop-adjusted vsize (2,000)", va == 2000);
        ck("the relay entry is too", vb == 2000);
    }

    printf("== MPL-8: missing-ephemeral-spends is a policy refusal (-26) ==\n");
    ck("MPL-8 \"missing-ephemeral-spends\" -> -26", txacc_test_reason_code("missing-ephemeral-spends") == -26);
    ck("\"bad-txns-inputs-missingorspent\" -> -25", txacc_test_reason_code("bad-txns-inputs-missingorspent") == -25);
    (void)t3;

    printf("\n%s (%d failures)\n", g_fails ? "TESTS FAILED" : "ALL TESTS PASSED", g_fails);
    return g_fails ? 1 : 0;
}
