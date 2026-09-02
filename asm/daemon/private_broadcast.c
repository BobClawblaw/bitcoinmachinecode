/* daemon/private_broadcast.c -- see private_broadcast.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <poll.h>
#include "private_broadcast.h"

typedef unsigned char u8;
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd[12], void* payload, unsigned cap, unsigned* plen);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* scratch, unsigned long scratchcap);
extern void tx_wtxid(u8 out[32], const u8* tx, unsigned long txlen);

static pb_tx_t g_q[PB_MAX_TX];

/* ------------------------------------------------------------------ queue */
void pb_queue_init(void){
    for (int i = 0; i < PB_MAX_TX; i++){ free(g_q[i].tx); }
    memset(g_q, 0, sizeof g_q);
}
long pb_queue_count(void){ long n = 0; for (int i = 0; i < PB_MAX_TX; i++) n += g_q[i].in_use; return n; }
int  pb_queue_has_pending(void){ return pb_queue_count() > 0; }
const pb_tx_t* pb_queue_at(int i){ return (i >= 0 && i < PB_MAX_TX && g_q[i].in_use) ? &g_q[i] : NULL; }

static int pb_find_txid(const u8 txid[32]){
    for (int i = 0; i < PB_MAX_TX; i++) if (g_q[i].in_use && !memcmp(g_q[i].txid, txid, 32)) return i;
    return -1;
}

int pb_queue_add(const u8* tx, unsigned long len, long long now){
    if (!tx || len < 60) return -2;
    u8 txid[32]; static u8 scratch[2000*81 + 8];
    if (!tx_txid(txid, tx, len, scratch, sizeof scratch)) return -2;
    if (pb_find_txid(txid) >= 0) return 0;
    int slot = -1; for (int i = 0; i < PB_MAX_TX; i++) if (!g_q[i].in_use){ slot = i; break; }
    if (slot < 0) return -1;
    u8* copy = malloc(len); if (!copy) return -1;
    memcpy(copy, tx, len);
    pb_tx_t* t = &g_q[slot]; memset(t, 0, sizeof *t);
    t->in_use = 1; t->tx = copy; t->len = len; memcpy(t->txid, txid, 32);
    tx_wtxid(t->wtxid, tx, len);
    t->time_added = now;
    return 1;
}

static long pb_acks(const pb_tx_t* t){ long n = 0; for (int i = 0; i < t->npeers; i++) n += t->peers[i].received != 0; return n; }

long pb_queue_remove(const u8 txid[32]){
    int i = pb_find_txid(txid); if (i < 0) return -1;
    long acks = pb_acks(&g_q[i]);
    free(g_q[i].tx); memset(&g_q[i], 0, sizeof g_q[i]);
    return acks;
}

long pb_queue_abort(const u8 id[32], u8 (*removed_txids)[32], u8 (*removed_wtxids)[32], int cap){
    long n = 0;
    for (int i = 0; i < PB_MAX_TX; i++){
        if (!g_q[i].in_use) continue;
        if (memcmp(g_q[i].txid, id, 32) && memcmp(g_q[i].wtxid, id, 32)) continue;
        if (n < cap){ if (removed_txids) memcpy(removed_txids[n], g_q[i].txid, 32); if (removed_wtxids) memcpy(removed_wtxids[n], g_q[i].wtxid, 32); }
        n++;
        free(g_q[i].tx); memset(&g_q[i], 0, sizeof g_q[i]);
    }
    return n;
}

/* Core PrivateBroadcast::PickTxForSend: fewest sends, then fewest receipts,
 * then the oldest last-send, then the oldest time_added. */
int pb_queue_pick(const char* addr, long long now, int* peer_slot){
    int best = -1; long bs = 0, ba = 0; long long bl = 0, bt = 0;
    for (int i = 0; i < PB_MAX_TX; i++){
        const pb_tx_t* t = &g_q[i]; if (!t->in_use) continue;
        if (t->npeers >= PB_MAX_PEERS_PER_TX) continue;
        long sends = t->npeers, acks = pb_acks(t);
        long long last = 0; for (int p = 0; p < t->npeers; p++) if (t->peers[p].sent > last) last = t->peers[p].sent;
        int better = best < 0 || sends < bs || (sends == bs && (acks < ba || (acks == ba && (last < bl || (last == bl && t->time_added < bt)))));
        if (better){ best = i; bs = sends; ba = acks; bl = last; bt = t->time_added; }
    }
    if (best < 0) return -1;
    pb_tx_t* t = &g_q[best];
    pb_peer_t* p = &t->peers[t->npeers];
    memset(p, 0, sizeof *p);
    snprintf(p->addr, sizeof p->addr, "%s", addr ? addr : "");
    p->sent = now;
    if (peer_slot) *peer_slot = t->npeers;
    t->npeers++;
    return best;
}

void pb_queue_mark_received(int tx_index, int peer_slot, long long now){
    if (tx_index < 0 || tx_index >= PB_MAX_TX || !g_q[tx_index].in_use) return;
    if (peer_slot < 0 || peer_slot >= g_q[tx_index].npeers) return;
    g_q[tx_index].peers[peer_slot].received = now;
}

void pb_queue_unpick(int tx_index, int peer_slot){
    if (tx_index < 0 || tx_index >= PB_MAX_TX || !g_q[tx_index].in_use) return;
    pb_tx_t* t = &g_q[tx_index];
    if (peer_slot < 0 || peer_slot >= t->npeers) return;
    for (int p = peer_slot + 1; p < t->npeers; p++) t->peers[p-1] = t->peers[p];
    t->npeers--;
}

int pb_queue_stale(long long now, int* out, int cap){
    int n = 0;
    for (int i = 0; i < PB_MAX_TX && n < cap; i++){
        const pb_tx_t* t = &g_q[i]; if (!t->in_use) continue;
        long long last = 0; for (int p = 0; p < t->npeers; p++) if (t->peers[p].sent > last) last = t->peers[p].sent;
        int stale = t->npeers == 0 ? (now - t->time_added >= PB_INITIAL_STALE_S) : (now - last >= PB_STALE_S);
        if (stale) out[n++] = i;
    }
    return n;
}

static const char* HEXD = "0123456789abcdef";
static void hex32_display(char* out, const u8* h){ for (int i = 0; i < 32; i++){ u8 b = h[31-i]; out[i*2] = HEXD[b>>4]; out[i*2+1] = HEXD[b&15]; } out[64] = 0; }

long pb_queue_snapshot(char* out, long cap){
    long o = 0;
    for (int i = 0; i < PB_MAX_TX; i++){
        const pb_tx_t* t = &g_q[i]; if (!t->in_use) continue;
        char tid[65], wid[65]; hex32_display(tid, t->txid); hex32_display(wid, t->wtxid);
        long need = 64 + 1 + 64 + 1 + 24 + 1 + 24 + 1 + (long)t->len * 2 + 1 + 8 + (long)t->npeers * (96 + 50) + 2;
        if (o + need >= cap) break;                    /* a snapshot that does not fit is truncated at a tx boundary */
        o += snprintf(out + o, cap - o, "%s %s %lld %lu ", tid, wid, t->time_added, t->len);
        for (unsigned long k = 0; k < t->len; k++){ out[o++] = HEXD[t->tx[k] >> 4]; out[o++] = HEXD[t->tx[k] & 15]; }
        o += snprintf(out + o, cap - o, " %d", t->npeers);
        for (int p = 0; p < t->npeers; p++)
            o += snprintf(out + o, cap - o, " %s %lld %lld", t->peers[p].addr, t->peers[p].sent, t->peers[p].received);
        out[o++] = '\n';
    }
    out[o] = 0;
    return o;
}

/* ------------------------------------------------------------- the wire */
static void pu32(u8* p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void pu64(u8* p, unsigned long long v){ for (int i = 0; i < 8; i++){ p[i] = v & 0xff; v >>= 8; } }

long pb_build_version(u8* out, long cap){
    if (cap < 120) return -1;
    u8* v = out; int o = 0;
    pu32(v+o, 70016); o += 4;                     /* protocol version */
    pu64(v+o, 0); o += 8;                         /* services: NODE_NONE */
    pu64(v+o, 0); o += 8;                         /* time: 0 */
    pu64(v+o, 0); o += 8; memset(v+o, 0, 16); o += 16; v[o++] = 0; v[o++] = 0;   /* addr_recv: nothing */
    pu64(v+o, 0); o += 8; memset(v+o, 0, 16); o += 16; v[o++] = 0; v[o++] = 0;   /* addr_from: nothing */
    { unsigned long long nonce = 0; int r = open("/dev/urandom", O_RDONLY);
      if (r >= 0){ if (read(r, &nonce, 8) != 8) nonce = 0; close(r); }
      if (!nonce) nonce = ((unsigned long long)time(NULL) << 20) ^ (unsigned long long)getpid();
      pu64(v+o, nonce); o += 8; }
    { const char* ua = PB_USER_AGENT; size_t ul = strlen(ua); v[o++] = (u8)ul; memcpy(v+o, ua, ul); o += (int)ul; }
    pu32(v+o, 0); o += 4;                         /* start height: 0 */
    v[o++] = 0;                                   /* relay: false */
    return o;
}

static long long mono_s(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec; }
/* one message or a 1 s slice: 1 = message in cmd/rb, 0 = nothing yet, -1 = peer gone or read error */
static int pb_read_slice(int fd, char cmd[12], u8* rb, unsigned cap, unsigned* plen){
    struct pollfd pf = { fd, POLLIN, 0 };
    int pr = poll(&pf, 1, 1000);
    if (pr == 0) return 0;
    if (pr < 0) return -1;
    if (pf.revents & (POLLERR | POLLNVAL)) return -1;
    int r = p2p_read(fd, cmd, rb, cap, plen);
    if (r <= 0) return -1;          /* 0 eof, -1 err, -2 truncated: all end the conversation */
    cmd[11] = 0;
    return 1;
}

int pb_exchange(int fd, const u8* tx, unsigned long len, const u8 txid[32], int deadline_s, char* why, long whycap){
    if (why && whycap) why[0] = 0;
#define WHY(...) do { if (why && whycap) snprintf(why, whycap, __VA_ARGS__); } while (0)
    long long t0 = mono_s();
    u8 v[160]; long vl = pb_build_version(v, sizeof v);
    if (vl <= 0 || p2p_write(fd, "version", 7, v, (unsigned)vl) <= 0){ WHY("version send failed"); return 0; }
    static u8 rb[1<<20]; char cmd[12]; unsigned plen = 0;
    /* handshake: read until the peer's verack. Answer NOTHING but our own
     * verack -- no pong, no sendaddrv2/wtxidrelay/sendheaders echoes. */
    int got_verack = 0;
    while (mono_s() - t0 < deadline_s){
        int r = pb_read_slice(fd, cmd, rb, sizeof rb, &plen);
        if (r < 0){ WHY("peer closed during handshake"); return 0; }
        if (r == 0) continue;
        if (!strncmp(cmd, "verack", 12)){ got_verack = 1; break; }
        /* version, sendaddrv2, wtxidrelay, sendheaders, sendcmpct, ping, ...: ignored */
    }
    if (!got_verack){ WHY("no verack within %ds", deadline_s); return 0; }
    if (p2p_write(fd, "verack", 6, "", 0) <= 0){ WHY("verack send failed"); return 0; }
    /* inv(MSG_TX, txid) */
    u8 inv[37]; inv[0] = 1; pu32(inv+1, 1); memcpy(inv+5, txid, 32);
    if (p2p_write(fd, "inv", 3, inv, 37) <= 0){ WHY("inv send failed"); return 0; }
    /* wait for the peer's getdata naming exactly our inv */
    int delivered = 0;
    while (mono_s() - t0 < deadline_s){
        int r = pb_read_slice(fd, cmd, rb, sizeof rb, &plen);
        if (r < 0){ WHY("peer closed before getdata"); return 0; }
        if (r == 0) continue;
        if (!strncmp(cmd, "getdata", 12)){
            if (plen != 37 || rb[0] != 1){ WHY("getdata with %u entries (want exactly 1)", plen >= 1 ? (unsigned)rb[0] : 0); return 0; }
            unsigned typ = rb[1] | rb[2]<<8 | rb[3]<<16 | ((unsigned)rb[4]<<24);
            if ((typ != 1 && typ != 0x40000001u) || memcmp(rb+5, txid, 32)){ WHY("getdata for something we never announced"); return 0; }
            if (p2p_write(fd, "tx", 2, tx, (unsigned)len) <= 0){ WHY("tx send failed"); return 0; }
            delivered = 1;
            break;
        }
        /* anything else (inv, ping, addr, feefilter, ...): ignored */
    }
    if (!delivered){ WHY("no getdata for our inv within %ds", deadline_s); return 0; }
    /* ping; the pong is the receipt */
    u8 nonce[8]; { int r = open("/dev/urandom", O_RDONLY); if (r >= 0){ if (read(r, nonce, 8) != 8) memset(nonce, 0x5a, 8); close(r); } else memset(nonce, 0x5a, 8); }
    if (p2p_write(fd, "ping", 4, nonce, 8) <= 0) return 1;     /* delivered, unconfirmed */
    while (mono_s() - t0 < deadline_s){
        int r = pb_read_slice(fd, cmd, rb, sizeof rb, &plen);
        if (r < 0) return 1;
        if (r == 0) continue;
        if (!strncmp(cmd, "pong", 12) && plen == 8 && !memcmp(rb, nonce, 8)) return 2;
    }
    return 1;
#undef WHY
}
