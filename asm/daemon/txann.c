#include <string.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include "txann.h"

/* p2p_write lives in bitcoind.asm; the weak reference lets the unit test
 * substitute a capturing writer and lets tx_accept-only link sets omit it. */
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* payload, unsigned plen) __attribute__((weak));
/* tx_relay.c's libm-free exponential deviate, exported for tests as
 * txrelay_test_exp_draw; weak so link sets without tx_relay.c fall back to
 * the mean (deterministic, which is also what the unit test wants). */
extern long long txrelay_test_exp_draw(long mean_ms) __attribute__((weak));

static node_status_t* g_st = 0;
static int  g_my_slot = -1;
static txann_writer_t g_write = 0;
static long g_mean_ms = 5000;              /* Core INBOUND_INVENTORY_BROADCAST_INTERVAL */
static long g_idle_secs = 1200;            /* NET-3 / Core TIMEOUT_INTERVAL */
static int  g_enabled = 1;
static unsigned long long g_lapped = 0;

/* inbound child state */
static int  c_slot = -1, c_relay_ok = 0;
static unsigned long long c_cursor = 0;
static long long c_next_send = 0, c_last_msg = 0;
static unsigned char c_pend[TXANN_INV_MAX][32];
static int  c_pend_n = 0;
#define KNOWN 256
static unsigned char c_known[KNOWN][32];
static int  c_known_w = 0;
/* worker state */
static unsigned long long w_cursor = 0;

static long long now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (long long)t.tv_sec*1000 + t.tv_nsec/1000000; }
static long long draw_ms(void){ long long d = txrelay_test_exp_draw ? txrelay_test_exp_draw(g_mean_ms) : g_mean_ms; return d < 0 ? 0 : d; }

void txann_set_status(node_status_t* st){ g_st = st; }
void txann_set_my_slot(int slot){ g_my_slot = slot; }
int  txann_my_slot(void){ return g_my_slot; }
void txann_set_writer(txann_writer_t w){ g_write = w; }
void txann_set_mean_ms(long ms){ g_mean_ms = ms; }
void txann_set_idle_secs(long s){ g_idle_secs = s; }
void txann_set_enabled(int on){ g_enabled = on; }
unsigned long long txann_lapped(void){ return g_lapped; }

/* CC-3: eviction protects the peers that recently gave us a tx or a block. */
static void note_peer_time(volatile long long* field){
    if (g_st && g_my_slot >= 0 && g_my_slot < RPC_MAX_PEERS) *field = (long long)time(NULL);
}
void txann_note_block(void){ if (g_st && g_my_slot >= 0 && g_my_slot < RPC_MAX_PEERS) note_peer_time(&g_st->peers[g_my_slot].last_block_time); }

void txann_push(const unsigned char txid[32], unsigned long long fee, unsigned long vsize){
    node_status_t* st = g_st; if (!st) return;
    if (g_my_slot >= 0 && g_my_slot < RPC_MAX_PEERS) note_peer_time(&st->peers[g_my_slot].last_tx_time);
    unsigned long long seq = __sync_fetch_and_add(&st->ann_seq, 1ULL);
    unsigned k = (unsigned)(seq % RPC_ANN_RING);
    st->ann_ring[k].ready = 0;
    __sync_synchronize();
    memcpy((void*)st->ann_ring[k].txid, txid, 32);
    st->ann_ring[k].fee = fee; st->ann_ring[k].vsize = vsize; st->ann_ring[k].src_slot = g_my_slot;
    __sync_synchronize();
    st->ann_ring[k].ready = seq + 1;
}

/* Advance *cursor over filled entries, calling fn for each. A consumer that
 * fell more than a ring behind resyncs to the oldest entry still present and
 * counts the loss -- the same policy as the ZMQ ring: dropping is correct,
 * dropping silently is not. Returns 0 to stop early (fn asked). */
static void drain(unsigned long long* cursor, int (*fn)(const unsigned char*, unsigned long long, unsigned long, int)){
    node_status_t* st = g_st; if (!st) return;
    unsigned long long head = st->ann_seq;
    if (head - *cursor > RPC_ANN_RING){ g_lapped += head - *cursor - RPC_ANN_RING; *cursor = head - RPC_ANN_RING; }
    while (*cursor < head){
        unsigned k = (unsigned)(*cursor % RPC_ANN_RING);
        if (st->ann_ring[k].ready != *cursor + 1) break;        /* claimed, not yet filled: come back */
        unsigned char id[32]; memcpy(id, (const void*)st->ann_ring[k].txid, 32);
        unsigned long long fee = st->ann_ring[k].fee; unsigned long vs = st->ann_ring[k].vsize; int src = st->ann_ring[k].src_slot;
        if (st->ann_ring[k].ready != *cursor + 1) break;        /* overwritten under us: it will be re-read after resync */
        if (!fn(id, fee, vs, src)) return;                      /* consumer full: keep the cursor here */
        (*cursor)++;
    }
}

static int known(const unsigned char* id){
    for (int i = 0; i < KNOWN; i++) if (!memcmp(c_known[i], id, 32)) return 1;
    return 0;
}
static void remember(const unsigned char* id){ memcpy(c_known[c_known_w], id, 32); c_known_w = (c_known_w + 1) % KNOWN; }

static unsigned long long c_peerfee;
static int child_take(const unsigned char* id, unsigned long long fee, unsigned long vsize, int src){
    if (c_pend_n >= TXANN_INV_MAX) return 0;                    /* batch full: stop draining */
    if (src == c_slot) return 1;                                /* never back to the sender */
    if (c_peerfee && vsize && fee * 1000ULL / vsize < c_peerfee) return 1;   /* below the peer's feefilter */
    if (known(id)) return 1;
    memcpy(c_pend[c_pend_n++], id, 32); remember(id);
    return 1;
}

void txann_child_init(int slot, int relay_ok){
    c_slot = slot; c_relay_ok = relay_ok; c_pend_n = 0; c_known_w = 0; memset(c_known, 0, sizeof c_known);
    c_cursor = g_st ? g_st->ann_seq : 0;                        /* announce only what arrives from now on */
    c_last_msg = now_ms(); c_next_send = c_last_msg + draw_ms();
}

long txann_tick(int fd, long long now, unsigned long long peer_feefilter){
    if (!g_enabled || !c_relay_ok || !g_st) return 0;
    c_peerfee = peer_feefilter;
    drain(&c_cursor, child_take);
    if (now < c_next_send || c_pend_n == 0) return 0;
    unsigned char buf[1 + TXANN_INV_MAX * 36]; long n = c_pend_n, o = 0;
    buf[o++] = (unsigned char)n;
    for (int i = 0; i < n; i++){ buf[o++] = 1; buf[o++] = 0; buf[o++] = 0; buf[o++] = 0; memcpy(buf + o, c_pend[i], 32); o += 32; }   /* MSG_TX */
    txann_writer_t w = g_write ? g_write : (txann_writer_t)p2p_write;
    if (w) w(fd, "inv", 3, buf, (unsigned)o);
    c_pend_n = 0; c_next_send = now + draw_ms();
    return n;
}

long txann_wait(int fd, unsigned long long peer_feefilter){
    if (!g_enabled || !g_st || fd < 0) return 1;                /* pre-CC-1 behaviour: straight to the blocking read */
    for (;;){
        long long now = now_ms();
        long long idle_deadline = c_last_msg + (long long)g_idle_secs * 1000;
        if (now >= idle_deadline) return 0;
        /* CC-3: the accept path asked this connection to make room for a
         * newcomer (Core AttemptToEvictConnection). Leave cleanly. */
        if (c_slot >= 0 && c_slot < RPC_MAX_PEERS && g_st->peers[c_slot].evict_requested) return 0;
        txann_tick(fd, now, peer_feefilter);
        long long until = c_next_send > now ? c_next_send - now : 0;
        long long t = idle_deadline - now; if (until > 0 && until < t) t = until; if (t > 1000) t = 1000; if (t < 1) t = 1;
        struct pollfd p; p.fd = fd; p.events = POLLIN; p.revents = 0;
        int r = poll(&p, 1, (int)t);
        if (r > 0){ c_last_msg = now_ms(); return 1; }          /* readable, hung up or errored: let the read see it */
        if (r < 0) return 1;                                    /* EINTR etc.: let the read decide */
    }
}

static void (*w_announce)(const unsigned char[32]);
static int worker_take(const unsigned char* id, unsigned long long fee, unsigned long vsize, int src){
    (void)fee; (void)vsize;
    if (src >= 0 && w_announce) w_announce(id);                 /* inbound-origin only: the worker's own are already queued */
    return 1;
}
long txann_worker_drain(void (*announce)(const unsigned char txid[32])){
    if (!g_enabled || !g_st) return 0;
    unsigned long long before = w_cursor; w_announce = announce;
    drain(&w_cursor, worker_take);
    return (long)(w_cursor - before);
}
