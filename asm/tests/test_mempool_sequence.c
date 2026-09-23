/* tests/test_mempool_sequence.c -- Core's -zmqpubsequence, end to end below
 * the daemon: the policy engine's events, the shared counter and ring, and
 * the bytes the publisher puts on the wire.
 *
 * WHAT CORE DOES (v31.1, read from the source, not from memory):
 *   txmempool.cpp removeUnchecked   takes GetAndIncrementSequence() for EVERY
 *                                   removal and signals TransactionRemoved-
 *                                   FromMempool for every reason EXCEPT
 *                                   BLOCK: expiry, sizelimit, reorg,
 *                                   conflict, replaced all publish 'R'.
 *   validation.cpp Finalize/Submit  TransactionAddedToMempool with the next
 *                                   number: 'A'. Replaced txs are removed
 *                                   first (R before A); LimitMempoolSize
 *                                   runs after (A before the evictions' R).
 *   removeForBlock                  walks the block: the tx itself (BLOCK:
 *                                   numbered, silent), then its conflicts.
 *   zmqpublishnotifier.cpp          body = hash (display order) + label
 *                                   (+ 8-byte LE sequence for A/R).
 *   txmempool.h                     m_sequence_number starts at 1.
 *
 * Every path is driven through the REAL engine (mpool_policy_add, _expire_one,
 * _block_connect) with the hook the daemon registers (mempool_seq_configure),
 * and the events are read back from the shared ring the worker drains -- so
 * the wiring is what is checked, not a re-implementation of it. The reorg
 * paths (D, and the reconcile's net A/R) are in tests/test_reorg.c, which has
 * the chain harness they need.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../daemon/mempool_seq.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern void  mpool_init(void*, unsigned long, void*, unsigned long);
extern const u8* mpool_get(const void*, const u8*, unsigned long*);
extern void  utxo_init(void*, unsigned long, void*, unsigned long);
extern long  utxo_put(void*, const u8*, unsigned long, u64, unsigned long, unsigned long, const u8*, unsigned long);
extern int   tx_txid(u8 out[32], const u8* tx, unsigned long len, u8* scratch, unsigned long scap);
extern unsigned long mpool_policy_state_size(unsigned);
extern void  mpool_policy_state_init(void*, unsigned);
extern void  mpool_policy_init(void*, u64, unsigned, unsigned, unsigned, unsigned, unsigned);
extern void  mpool_policy_set_acceptnonstd(void*, unsigned);
extern long  mpool_policy_add(void*, void*, void*, const u8*, unsigned long, const u8*, void*);
extern long  mpool_policy_expire_one(void*, void*, const u8*);
extern long  mpool_policy_block_connect(void*, void*, const u8*, unsigned long);
extern void  mpool_policy_set_poolcap(void*, unsigned long long);
extern void  mpool_policy_set_batch_connect(int);
extern void  mpol_package_fee_context(unsigned long long, unsigned long long);
extern void  mpol_package_context(const u8* const*, const unsigned long*, const u8*, int);
extern const char* mpool_policy_reason(void*);

extern int   zmqpub_add(const char* topic, const char* addr);
extern void  zmqpub_poll(void);
extern void  zmq_pub_set_hwm(const int*);
extern int   zmqn_drain_sequence(void);

extern long utxo_get(void* u, const u8 txid[32], unsigned long index,
                     u64* value, unsigned long* height, unsigned long* is_coinbase,
                     const u8** script, unsigned long* slen);
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    unsigned long h, cb;
    return utxo_get(u, txid, index, value, &h, &cb, script, slen);
}

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; printf("%s %s\n", c ? "ok  :" : "FAIL:", w); if (!c) fails++; }

/* ---- the ring, read back ------------------------------------------------ */
typedef struct { u8 label; u8 hash[32]; u64 mseq; } ev_t;
static unsigned long long g_mark;
static void mark(void){ g_mark = mpseq_area()->head; }
static int events(ev_t* out, int max){
    mpseq_area_t* a = mpseq_area(); int n = 0;
    for (unsigned long long s = g_mark; s < a->head && n < max; s++){
        const mpseq_ev* e = &a->ev[s % MPSEQ_RING];
        out[n].label = e->label; memcpy(out[n].hash, e->hash, 32); out[n].mseq = e->mseq; n++;
    }
    return n;
}
static int is_ev(const ev_t* e, u8 label, const u8* h){ return e->label == label && !memcmp(e->hash, h, 32); }

/* ---- fixtures (the shape tests/test_mempool_depart_reasons.c uses) -------- */
static long mk_tx_from(u8* out, const u8 prev[32], u64 invalue, u64 fee, int pad){
    u8* p = out;
    *p++=2;*p++=0;*p++=0;*p++=0;
    *p++=1;
    memcpy(p, prev, 32); p+=32;
    *p++=0;*p++=0;*p++=0;*p++=0;
    *p++=0;
    *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;
    *p++=1;
    u64 outv = invalue - fee;
    for (int i=0;i<8;i++) *p++ = (u8)(outv >> (8*i));
    *p++ = (u8)(1+pad);
    *p++ = 0x51;
    for (int i=0;i<pad;i++) *p++ = 0x00;
    *p++=0;*p++=0;*p++=0;*p++=0;
    return p - out;
}
static long mk_tx(u8* out, u8 in_tag, u64 invalue, u64 fee, int pad){
    u8 prev[32]; memset(prev, in_tag, 32);
    return mk_tx_from(out, prev, invalue, fee, pad);
}

static u8 g_pol[128];
static u8 g_st[1<<20];
static u8 g_mp[40 + 256*80 + 8];
static u8 g_mblob[1<<16];
static u8 g_ux[40 + 256*48 + 8]; static u8 g_ublob[1<<14];
static u8 g_sc[4096];
static void fresh_pool(unsigned long blob_cap){
    mpool_init(g_mp, 256, g_mblob, blob_cap);
    mpool_policy_state_init(g_st, 256);
    mpool_policy_set_poolcap(g_st, blob_cap);
}
static long add(const u8* tx, long n, u8 id[32]){
    tx_txid(id, tx, (unsigned long)n, g_sc, sizeof g_sc);
    return mpool_policy_add(g_pol, g_st, g_mp, tx, (unsigned long)n, id, g_ux);
}

/* ---- a raw ZMTP subscriber (tests/test_zmq_queue.c's, trimmed) ----------- */
typedef struct { int fd; u8* b; size_t n, cap; int greeted; } rsub;
typedef struct { char topic[32]; u32 seq; u8 body[64]; size_t blen; } rmsg;
static int free_port(void){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (struct sockaddr*)&a, sizeof a);
    socklen_t al = sizeof a; getsockname(s, (struct sockaddr*)&a, &al);
    int p = ntohs(a.sin_port); close(s); return p;
}
static int rsub_open(rsub* s, int port, const char* subscribe){
    memset(s, 0, sizeof *s);
    s->fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(s->fd, (struct sockaddr*)&a, sizeof a) != 0) return 0;
    u8 out[256]; size_t n = 0;
    memset(out, 0, 64); out[0] = 0xff; out[9] = 0x7f; out[10] = 3; out[11] = 1;
    memcpy(out + 12, "NULL", 4); n = 64;
    static const u8 ready[] = { 5,'R','E','A','D','Y', 11,'S','o','c','k','e','t','-','T','y','p','e',
                                0,0,0,3,'S','U','B' };
    out[n++] = 0x04; out[n++] = (u8)sizeof ready; memcpy(out + n, ready, sizeof ready); n += sizeof ready;
    size_t tl = strlen(subscribe);
    out[n++] = 0x04; out[n++] = (u8)(10 + tl);
    out[n++] = 9; memcpy(out + n, "SUBSCRIBE", 9); n += 9;
    memcpy(out + n, subscribe, tl); n += tl;
    return write(s->fd, out, n) == (ssize_t)n;
}
static void rsub_pump(rsub* s, int wait_ms){
    struct pollfd pf = { s->fd, POLLIN, 0 };
    if (poll(&pf, 1, wait_ms) <= 0) return;
    for (;;){
        if (s->cap - s->n < 65536){ s->cap = s->cap ? s->cap * 2 : (1 << 20); s->b = realloc(s->b, s->cap); }
        ssize_t r = recv(s->fd, s->b + s->n, s->cap - s->n, MSG_DONTWAIT);
        if (r > 0){ s->n += (size_t)r; continue; }
        return;
    }
}
static int rsub_next(rsub* s, rmsg* m){
    if (!s->greeted){ if (s->n < 64) return 0; memmove(s->b, s->b + 64, s->n - 64); s->n -= 64; s->greeted = 1; }
    size_t off = 0; const u8* part[3]; size_t plen[3]; int np = 0;
    for (;;){
        if (s->n - off < 2) return 0;
        u8 fl = s->b[off]; size_t len, hn;
        if (fl & 2){ if (s->n - off < 9) return 0; len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | s->b[off + 1 + i]; hn = 9; }
        else { len = s->b[off + 1]; hn = 2; }
        if (s->n - off < hn + len) return 0;
        const u8* body = s->b + off + hn; off += hn + len;
        if (fl & 4){ if (np == 0){ memmove(s->b, s->b + off, s->n - off); s->n -= off; off = 0; } continue; }
        if (np < 3){ part[np] = body; plen[np] = len; }
        np++;
        if (!(fl & 1)) break;
    }
    memset(m, 0, sizeof *m);
    if (np == 3 && plen[2] == 4 && plen[1] <= sizeof m->body){
        memcpy(m->topic, part[0], plen[0] < 31 ? plen[0] : 31);
        memcpy(m->body, part[1], plen[1]); m->blen = plen[1];
        m->seq = (u32)part[2][0] | (u32)part[2][1] << 8 | (u32)part[2][2] << 16 | (u32)part[2][3] << 24;
    }
    memmove(s->b, s->b + off, s->n - off); s->n -= off;
    return 1;
}
static double now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e3 + t.tv_nsec / 1e6; }
static int rsub_collect(rsub* s, rmsg* out, int max, int idle_ms){
    int got = 0; double last = now_ms();
    static rmsg sink;
    while (now_ms() - last < idle_ms){
        zmqpub_poll();
        rsub_pump(s, 2);
        for (;;){
            rmsg* m = got < max ? &out[got] : &sink;
            if (!rsub_next(s, m)) break;
            got++; last = now_ms();
        }
    }
    return got;
}

int main(void){
    mpool_policy_init(g_pol, 1000 /* sat/kvB */, 25, 101000, 25, 101000, 1);
    mpool_policy_set_acceptnonstd(g_pol, 1);
    { extern void mpol_policy_set_min_size(void*, unsigned); mpol_policy_set_min_size(g_pol, 0); }
    utxo_init(g_ux, 256, g_ublob, sizeof g_ublob);
    for (int i=1;i<=40;i++){ u8 t[32]; memset(t,(u8)i,32); utxo_put(g_ux, t, 0, 1000000ULL, 0, 0, (const u8*)"\x51", 1); }

    ck("the shared sequence area is created (the daemon's own init)", mempool_seq_configure() == 1);
    ck("Core's m_sequence_number starts at 1", mempool_sequence() == 1);

    static ev_t ev[128]; int n;
    u8 tx[256]; long tl;

    /* ---- ADD --------------------------------------------------------------- */
    fresh_pool(sizeof g_mblob);
    u8 a1[32];
    mark(); tl = mk_tx(tx, 1, 1000000ULL, 1000, 0);
    ck("ADD: accepted", add(tx, tl, a1) == 1);
    n = events(ev, 128);
    ck("ADD: exactly one event, 'A' for the accepted txid", n == 1 && is_ev(&ev[0], 'A', a1));
    ck("ADD: numbered 1 (the first number handed out)", n == 1 && ev[0].mseq == 1);
    ck("ADD: getrawmempool's value is now 2 (the next number)", mempool_sequence() == 2);

    /* a refused add takes no number and publishes nothing */
    mark(); { u8 dup[32]; long r = add(tx, tl, dup); ck("REFUSED: the duplicate is refused", r != 1); }
    ck("REFUSED: no event, no number", events(ev, 128) == 0 && mempool_sequence() == 2);

    /* ---- REPLACE (RBF): R(original) THEN A(replacement), consecutive ------- */
    u8 r1[32];
    mark(); tl = mk_tx(tx, 1, 1000000ULL, 9000, 1);        /* same coin, far higher fee */
    { long r = add(tx, tl, r1); ck("REPLACE: the replacement is accepted", r == 1);
      if (r != 1) printf("      reason: %s\n", mpool_policy_reason(g_pol)); }
    n = events(ev, 128);
    ck("REPLACE: two events", n == 2);
    ck("REPLACE: R of the original FIRST (Core FinalizeSubpackage)", n >= 1 && is_ev(&ev[0], 'R', a1));
    ck("REPLACE: then A of the replacement", n >= 2 && is_ev(&ev[1], 'A', r1));
    ck("REPLACE: consecutive numbers 2, 3", n == 2 && ev[0].mseq == 2 && ev[1].mseq == 3);

    /* ---- PACKAGE: each member an 'A', parent first ------------------------- */
    { u8 p0[256], c0[256], pid[32], cid[32];
      long pl = mk_tx(p0, 2, 1000000ULL, 1, 0);           /* below the relay floor alone */
      tx_txid(pid, p0, (unsigned long)pl, g_sc, sizeof g_sc);
      long cl = mk_tx_from(c0, pid, 999999ULL, 20000, 0); /* pays for both */
      tx_txid(cid, c0, (unsigned long)cl, g_sc, sizeof g_sc);
      mark();
      ck("PACKAGE: the parent ALONE is refused (fee)", add(p0, pl, pid) != 1);
      ck("PACKAGE: ...and its refusal is silent", events(ev, 128) == 0);
      const u8* txs[2] = { p0, c0 }; unsigned long lens[2] = { (unsigned long)pl, (unsigned long)cl };
      u8 ids[64]; memcpy(ids, pid, 32); memcpy(ids + 32, cid, 32);
      mpol_package_context(txs, lens, ids, 2);
      mpol_package_fee_context(20001, 120);
      long rp = add(p0, pl, pid), rc = add(c0, cl, cid);
      mpol_package_context(NULL, NULL, NULL, 0);
      mpol_package_fee_context(0, 0);
      ck("PACKAGE: parent and child both accepted under the package feerate", rp == 1 && rc == 1);
      n = events(ev, 128);
      ck("PACKAGE: A(parent) then A(child), consecutive",
         n == 2 && is_ev(&ev[0], 'A', pid) && is_ev(&ev[1], 'A', cid) && ev[1].mseq == ev[0].mseq + 1);

      /* ---- EXPIRE: the tx AND its descendants, each an 'R' ----------------- */
      mark(); u64 s0 = mempool_sequence();
      ck("EXPIRE: expire_one removes parent + child", mpool_policy_expire_one(g_st, g_mp, pid) == 2);
      n = events(ev, 128);
      int rp_i = -1, rc_i = -1;
      for (int i = 0; i < n; i++){ if (is_ev(&ev[i], 'R', pid)) rp_i = i; if (is_ev(&ev[i], 'R', cid)) rc_i = i; }
      ck("EXPIRE: an R for the expired tx", rp_i >= 0);
      ck("EXPIRE: an R for its descendant", rc_i >= 0);
      ck("EXPIRE: two numbers, contiguous from the counter", n == 2 && mempool_sequence() == s0 + 2 &&
         ev[0].mseq == s0 && ev[1].mseq == s0 + 1); }

    /* ---- EVICT: A(newcomer) BEFORE R(evicted) -- Core adds, then trims ------ */
    {
        fresh_pool(300);                                   /* 4 small txs fill it */
        u8 ids[5][32]; int inpool = 0;
        u64 fees[4] = {100,200,300,400};
        for (int i=0;i<4;i++){ tl = mk_tx(tx, (u8)(10+i), 1000000ULL, fees[i], 0); if (add(tx, tl, ids[i]) == 1) inpool++; }
        ck("EVICT: the tiny pool filled", inpool == 4);
        mark(); u64 s0 = mempool_sequence();
        tl = mk_tx(tx, 14, 1000000ULL, 5000, 0);
        ck("EVICT: a high-fee tx is accepted by evicting", add(tx, tl, ids[4]) == 1);
        unsigned long l;
        ck("EVICT: ...the cheapest really left", mpool_get(g_mp, ids[0], &l) == NULL);
        n = events(ev, 128);
        int ia = -1, ir = -1;
        for (int i = 0; i < n; i++){ if (is_ev(&ev[i], 'A', ids[4])) ia = i; if (is_ev(&ev[i], 'R', ids[0])) ir = i; }
        ck("EVICT: an A for the newcomer and an R for the evicted", ia >= 0 && ir >= 0);
        ck("EVICT: the A comes FIRST (the engine evicts before it stores; the R is held back)", ia >= 0 && ir > ia);
        ck("EVICT: numbered in that order, from the counter", ia == 0 && ev[0].mseq == s0 && ev[ir].mseq > ev[ia].mseq);
    }

    /* ---- BLOCK: mined = numbered, silent; conflict = 'R'; in BLOCK order --- */
    for (int batch = 1; batch >= 0; batch--){
        mpool_policy_set_batch_connect(batch);
        fresh_pool(sizeof g_mblob);
        const char* tag = batch ? "BLOCK(batch)" : "BLOCK(per-tx fallback)";
        char w[160];
        u8 victim[32], vchild[32], mined[32], winner[32];
        u8 vtx[256], ctx[256], mtx[256], wtx[256];
        /* the victim is admitted FIRST so it sits at a LOWER node index than
         * the mined tx: node order and block order then disagree, which is
         * what the block-order publication has to get right */
        long vl = mk_tx(vtx, 20, 1000000ULL, 600, 0);
        long cl; long ml = mk_tx(mtx, 21, 1000000ULL, 500, 0);
        long wl = mk_tx(wtx, 20, 1000000ULL, 900, 1);          /* the block's spend of the victim's coin */
        tx_txid(winner, wtx, (unsigned long)wl, g_sc, sizeof g_sc);
        snprintf(w, sizeof w, "%s: victim, its child and the to-be-mined tx admitted", tag);
        int ok = add(vtx, vl, victim) == 1;
        cl = mk_tx_from(ctx, victim, 999400ULL, 700, 0);
        ok = ok && add(ctx, cl, vchild) == 1 && add(mtx, ml, mined) == 1;
        ck(w, ok);

        u8 cb[128]; long cbl = mk_tx(cb, 30, 1000000ULL, 0, 2);
        static u8 blk[4096]; long b = 80; memset(blk, 0, 80);
        blk[b++] = 3;
        memcpy(blk + b, cb, cbl); b += cbl;
        memcpy(blk + b, mtx, ml); b += ml;                     /* j=1: mined        */
        memcpy(blk + b, wtx, wl); b += wl;                     /* j=2: the conflict */
        mark(); u64 s0 = mempool_sequence();
        long rm = mpool_policy_block_connect(g_st, g_mp, blk, (unsigned long)b);
        snprintf(w, sizeof w, "%s: the block removed mined + victim + victim's child", tag); ck(w, rm == 3);
        n = events(ev, 128);
        int im = -1, iv = -1, ic = -1;
        for (int i = 0; i < n; i++){
            if (!memcmp(ev[i].hash, mined, 32)) im = i;
            if (is_ev(&ev[i], 'R', victim)) iv = i;
            if (is_ev(&ev[i], 'R', vchild)) ic = i; }
        snprintf(w, sizeof w, "%s: the MINED tx is not published (Core: BLOCK)", tag); ck(w, im < 0);
        snprintf(w, sizeof w, "%s: the CONFLICTED tx is published as R", tag); ck(w, iv >= 0);
        snprintf(w, sizeof w, "%s: ...and so is its descendant", tag); ck(w, ic >= 0);
        snprintf(w, sizeof w, "%s: three numbers taken, the mined one silently", tag);
        ck(w, mempool_sequence() == s0 + 3);
        /* Core walks the block: j=1's own removal takes s0, then j=2's
         * conflicts take s0+1 and s0+2. Node order would have given the
         * victim s0 -- it was admitted first. */
        snprintf(w, sizeof w, "%s: the R's carry s0+1 and s0+2 (the mined tx took s0: block order)", tag);
        ck(w, iv >= 0 && ic >= 0 &&
              ((ev[iv].mseq == s0 + 1 && ev[ic].mseq == s0 + 2) || (ev[iv].mseq == s0 + 2 && ev[ic].mseq == s0 + 1)));
    }
    mpool_policy_set_batch_connect(1);

    /* ---- HOLD: the reorg rebuild's suppression ----------------------------- */
    fresh_pool(sizeof g_mblob);
    { u8 id[32]; u64 s0 = mempool_sequence(); mark();
      mempool_seq_hold(1);
      tl = mk_tx(tx, 35, 1000000ULL, 1000, 0);
      long r = add(tx, tl, id);
      mempool_seq_hold(0);
      ck("HOLD: an add while held is not published and takes no number",
         r == 1 && events(ev, 128) == 0 && mempool_sequence() == s0);
      mempool_seq_emit(id, 'A');
      n = events(ev, 128);
      ck("HOLD: mempool_seq_emit (the reconcile's net change) is NOT held", n == 1 && is_ev(&ev[0], 'A', id) && ev[0].mseq == s0); }

    /* ---- CROSS-PROCESS: the counter and ring are shared across fork -------- */
    { u64 s0 = mempool_sequence(); mark();
      u8 t[32]; memset(t, 0xC5, 32);
      pid_t pid = fork();
      if (pid == 0){ mempool_seq_note(t, 'A'); mempool_seq_note(t, 'R'); mempool_seq_block(t, 'C'); _exit(0); }
      int stt = 0; waitpid(pid, &stt, 0);
      n = events(ev, 128);
      ck("SHARED: a forked process's events land in the parent's ring, in order",
         n == 3 && is_ev(&ev[0], 'A', t) && is_ev(&ev[1], 'R', t) && is_ev(&ev[2], 'C', t));
      ck("SHARED: ...and its numbers in the parent's counter", mempool_sequence() == s0 + 2 &&
         ev[0].mseq == s0 && ev[1].mseq == s0 + 1); }

    /* ---- MONOTONIC: every A/R ever staged, strictly increasing ------------- */
    { mpseq_area_t* a = mpseq_area(); u64 last = 0; int mono = 1, cnt = 0;
      for (u64 s = 0; s < a->head; s++){
          const mpseq_ev* e = &a->ev[s % MPSEQ_RING];
          if (e->label != 'A' && e->label != 'R') continue;
          if (e->mseq <= last) mono = 0;
          last = e->mseq; cnt++; }
      ck("MONOTONIC: the A/R numbers along the ring strictly increase", mono && cnt > 10);
      ck("MONOTONIC: getrawmempool's value is above every number handed out", mempool_sequence() > last); }

    /* ---- THE WIRE: what zmqn_drain puts on the `sequence` topic ------------ */
    {
        int port = free_port(); char addr[64]; snprintf(addr, sizeof addr, "tcp://127.0.0.1:%d", port);
        int hwm[5] = { 0, 0, 0, 0, 0 };                    /* no count limit: the overrun below needs it */
        zmq_pub_set_hwm(hwm);
        ck("WIRE: the sequence topic binds", zmqpub_add("sequence", addr) == 1);
        zmqn_drain_sequence();                             /* everything above: published to nobody */
        rsub s; ck("WIRE: a subscriber connects", rsub_open(&s, port, "sequence"));
        for (int i = 0; i < 40; i++){ zmqpub_poll(); usleep(5000); }

        fresh_pool(sizeof g_mblob);
        u8 id[32]; u64 s0 = mempool_sequence();
        tl = mk_tx(tx, 36, 1000000ULL, 1000, 0);
        ck("WIRE: an add", add(tx, tl, id) == 1);
        u8 bh[32]; for (int i = 0; i < 32; i++) bh[i] = (u8)(0xB0 + i);
        mempool_seq_block(bh, 'C');
        mempool_seq_block(bh, 'D');
        ck("WIRE: the drain publishes the three staged events", zmqn_drain_sequence() == 3);
        static rmsg m[8];
        int got = rsub_collect(&s, m, 8, 300);
        ck("WIRE: three messages arrive", got == 3);
        int a_ok = got >= 1 && !strcmp(m[0].topic, "sequence") && m[0].blen == 41 && m[0].body[32] == 'A';
        for (int i = 0; a_ok && i < 32; i++) if (m[0].body[i] != id[31 - i]) a_ok = 0;
        u64 ms = 0; for (int i = 0; i < 8 && got >= 1; i++) ms |= (u64)m[0].body[33 + i] << (8 * i);
        ck("WIRE: A = 32-byte txid in DISPLAY order + 'A' + 8-byte LE sequence (41 bytes)", a_ok);
        ck("WIRE: ...carrying the mempool sequence the counter handed out", ms == s0);
        int c_ok = got >= 2 && m[1].blen == 33 && m[1].body[32] == 'C';
        for (int i = 0; c_ok && i < 32; i++) if (m[1].body[i] != bh[31 - i]) c_ok = 0;
        ck("WIRE: C = 32-byte block hash in DISPLAY order + 'C', no sequence (33 bytes)", c_ok);
        ck("WIRE: D likewise (33 bytes)", got >= 3 && m[2].blen == 33 && m[2].body[32] == 'D');
        ck("WIRE: the 4-byte topic sequence counts on", got == 3 && m[1].seq == m[0].seq + 1 && m[2].seq == m[1].seq + 1);
        u32 last_seq = got >= 3 ? m[2].seq : 0;

        /* OVERRUN: lap the ring. The consumer must skip to the oldest intact
         * slot, count the loss, and leave the gap in the TOPIC sequence -- the
         * signal a Core subscriber resynchronises on. */
        u8 t[32]; memset(t, 0x77, 32);
        unsigned long long lost0 = mpseq_area()->lost;
        for (unsigned i = 0; i < MPSEQ_RING + 5; i++) mempool_seq_emit(t, 'A');
        int pub = zmqn_drain_sequence();
        ck("OVERRUN: the drain publishes one ring's worth", pub == (int)MPSEQ_RING);
        ck("OVERRUN: the 5 lapped events are COUNTED", mpseq_area()->lost - lost0 == 5);
        got = rsub_collect(&s, m, 1, 1500);
        ck("OVERRUN: the subscriber's next topic sequence shows the gap of 5",
           got >= 1 && m[0].seq == last_seq + 1 + 5);
        close(s.fd); free(s.b);
    }

    /* ---- COST: the publish path, per event -------------------------------
     * The hook runs inside the pool lock on every accept and every removal,
     * so its price is paid on the consensus/mempool hot path. Measured
     * directly: an atomic increment, a slot claim and a 56-byte write. */
    {
        const int N = 2000000; u8 t[32]; memset(t, 0x33, 32);
        struct timespec a, b; clock_gettime(CLOCK_MONOTONIC, &a);
        for (int i = 0; i < N; i++){ t[0] = (u8)i; mempool_seq_note(t, (i & 1) ? 'R' : 'A'); }
        clock_gettime(CLOCK_MONOTONIC, &b);
        double ns = ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / N;
        printf("      publish-path cost: %.1f ns per event (%d events)\n", ns, N);
        ck("COST: under a microsecond per event (the accept path itself is ~100x that)", ns < 1000.0);
    }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
