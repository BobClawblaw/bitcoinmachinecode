#include <string.h>
#include <strings.h>
#include <limits.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include "inbound_evict.h"
#include "netperm.h"
/* Core v31.1 node/eviction.cpp SelectNodeToEvict, transcribed (P2P-4, audit
 * 2026-10-23; the CC-3 version of 2026-09-06 followed an older Core). In
 * order, each step removing the candidates it protects:
 *   - NoBan peers, and anything not inbound
 *   - 4 by keyed netgroup         (an attacker cannot predict which groups)
 *   - 8 with the lowest min ping  (unmeasured = the worst: microseconds::max)
 *   - 4 that most recently sent us a transaction we accepted
 *   - 8 non-tx-relay peers with the wanted services that most recently sent
 *     us a novel block (block-relay-only)
 *   - 4 that most recently sent us a novel block
 *   - ProtectEvictionCandidatesByRatio: half of what is left, up to half of
 *     those reserved for CJDNS, I2P, localhost and onion peers (the
 *     disadvantaged networks), the rest by longest uptime
 *   - of what is left, the netgroup with the most members (ties: the group
 *     whose newest member is newest) loses its newest member.
 * Each "protect k by X" is Core's EraseLastKElements: a sort with Core's
 * comparator (tie-breaks included) and the last k removed. The sorts here
 * are stable (insertion), where Core's std::sort leaves exact ties in an
 * unspecified order.
 *
 * What the peer table cannot carry is left at Core's value for a peer
 * without it: fBloomFilter is false (this node offers no BIP37), and
 * prefer_evict is false (Core sets it for a discouraged address; this node
 * bans instead, and a banned address never reaches a slot). */
#define MAXC RPC_MAX_PEERS
#define NODE_NETWORK         1ull
#define NODE_WITNESS         8ull
#define NODE_NETWORK_LIMITED 1024ull
enum { EV_NET_OTHER = 0, EV_NET_ONION, EV_NET_I2P, EV_NET_CJDNS };
typedef struct {
    int slot; long long conn, tx, blk, ping; unsigned grp; unsigned long long kgrp;
    int relay_txs, relevant, is_local, net;
} cand_t;

/* Core's keyed netgroup: CSipHasher(nonce) over the group -- stable for the
 * process, unpredictable outside it. A splitmix-style keyed mix of the
 * group serves the same purpose; the key is drawn once per process. */
static unsigned long long g_key0, g_key1; static int g_key_set;
void inbound_evict_set_key(unsigned long long k0, unsigned long long k1){ g_key0 = k0; g_key1 = k1; g_key_set = 1; }
static unsigned long long mix64(unsigned long long z){
    z += 0x9e3779b97f4a7c15ull; z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull; return z ^ (z >> 31);
}
unsigned long long inbound_evict_keyed_group(unsigned grp){
    if (!g_key_set){
        unsigned long long k[2] = { 0, 0 };
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0){ if (read(fd, k, sizeof k) != (ssize_t)sizeof k){ k[0] = 0; k[1] = 0; } close(fd); }
        if (!k[0] && !k[1]){ k[0] = (unsigned long long)(uintptr_t)&g_key0 ^ (unsigned long long)getpid(); k[1] = mix64(k[0]); }
        inbound_evict_set_key(k[0], k[1]);
    }
    return mix64(mix64((unsigned long long)grp ^ g_key0) ^ g_key1);
}

/* the peer's address -> Core's m_is_local (CNetAddr::IsLocal: 127/8, 0/8,
 * ::1) and network (onion, i2p, cjdns -- fc00::/8, as daemon/netaddr.c
 * names it; anything else plays no part) */
static void classify(const char* a, int* is_local, int* net){
    *is_local = 0; *net = EV_NET_OTHER;
    char host[80]; size_t n = 0;
    if (a[0] == '['){ const char* e = strchr(a, ']'); n = e ? (size_t)(e - a - 1) : strlen(a + 1); if (n >= sizeof host) n = sizeof host - 1; memcpy(host, a + 1, n); }
    else { const char* c = strrchr(a, ':'); n = (c && c == strchr(a, ':')) ? (size_t)(c - a) : strlen(a); if (n >= sizeof host) n = sizeof host - 1; memcpy(host, a, n); }
    host[n] = 0;
    if (n > 6 && !strcasecmp(host + n - 6, ".onion")){ *net = EV_NET_ONION; return; }
    if (n > 4 && !strcasecmp(host + n - 4, ".i2p")){ *net = EV_NET_I2P; return; }
    if (!strncmp(host, "127.", 4) || !strncmp(host, "0.", 2) || !strcmp(host, "::1")){ *is_local = 1; return; }
    if (strchr(host, ':') && (host[0] == 'f' || host[0] == 'F') && (host[1] == 'c' || host[1] == 'C') && n > 4 && host[4] == ':'){ *net = EV_NET_CJDNS; return; }
}
/* Core HasAllDesirableServiceFlags (close to the tip, which is where an
 * inbound slot fills: NODE_NETWORK_LIMITED suffices in place of NODE_NETWORK) */
static int relevant_services(unsigned long long s){
    unsigned long long want = (s & NODE_NETWORK_LIMITED) ? (NODE_NETWORK_LIMITED | NODE_WITNESS) : (NODE_NETWORK | NODE_WITNESS);
    return (want & ~s) == 0;
}

/* comparators: "a sorts before b" -- before = more likely to be evicted */
static int c_netgroup(const cand_t* a, const cand_t* b){ return a->kgrp < b->kgrp; }
static int c_ping(const cand_t* a, const cand_t* b){ return a->ping > b->ping; }
static int c_conn(const cand_t* a, const cand_t* b){ return a->conn > b->conn; }
static int c_tx(const cand_t* a, const cand_t* b){
    if (a->tx != b->tx) return a->tx < b->tx;
    if (a->relay_txs != b->relay_txs) return b->relay_txs;
    return a->conn > b->conn;
}
static int c_blkrelay(const cand_t* a, const cand_t* b){
    if (a->relay_txs != b->relay_txs) return a->relay_txs;
    if (a->blk != b->blk) return a->blk < b->blk;
    if (a->relevant != b->relevant) return b->relevant;
    return a->conn > b->conn;
}
static int c_blk(const cand_t* a, const cand_t* b){
    if (a->blk != b->blk) return a->blk < b->blk;
    if (a->relevant != b->relevant) return b->relevant;
    return a->conn > b->conn;
}
/* CompareNodeNetworkTime(is_local, network) */
static int g_nt_local, g_nt_net;
static int c_nettime(const cand_t* a, const cand_t* b){
    if (g_nt_local && a->is_local != b->is_local) return b->is_local;
    if (!g_nt_local && (a->net == g_nt_net) != (b->net == g_nt_net)) return b->net == g_nt_net;
    return a->conn > b->conn;
}
static void sort_c(cand_t* c, int n, int (*lt)(const cand_t*, const cand_t*)){
    for (int i = 1; i < n; i++){ cand_t v = c[i]; int j = i - 1; while (j >= 0 && lt(&v, &c[j])){ c[j+1] = c[j]; j--; } c[j+1] = v; }
}
static int pred_all(const cand_t* x){ (void)x; return 1; }
static int pred_blkrelay(const cand_t* x){ return !x->relay_txs && x->relevant; }
static int pred_net(const cand_t* x){ return g_nt_local ? x->is_local : x->net == g_nt_net; }
/* EraseLastKElements: sort, then remove those of the last k that match */
static int erase_last_k(cand_t* c, int n, int (*lt)(const cand_t*, const cand_t*), int k, int (*pred)(const cand_t*)){
    sort_c(c, n, lt);
    int from = n - (k < n ? k : n), w = from;
    for (int i = from; i < n; i++) if (!pred(&c[i])) c[w++] = c[i];
    return w;
}
/* ProtectEvictionCandidatesByRatio */
typedef struct { int is_local, id, count; } ev_net_t;
static int protect_by_ratio(cand_t* c, int n){
    const int initial = n, total_protect = initial / 2;
    ev_net_t nets[4] = { {0, EV_NET_CJDNS, 0}, {0, EV_NET_I2P, 0}, {1, -1, 0}, {0, EV_NET_ONION, 0} };
    for (int k = 0; k < 4; k++) for (int i = 0; i < n; i++) if (nets[k].is_local ? c[i].is_local : c[i].net == nets[k].id) nets[k].count++;
    for (int i = 1; i < 4; i++){ ev_net_t v = nets[i]; int j = i - 1; while (j >= 0 && nets[j].count > v.count){ nets[j+1] = nets[j]; j--; } nets[j+1] = v; }   /* stable, ascending count */
    const int max_by_net = total_protect / 2;
    int protected_n = 0;
    while (protected_n < max_by_net){
        int num_nets = 0; for (int k = 0; k < 4; k++) if (nets[k].count) num_nets++;
        if (num_nets == 0) break;
        int per = (max_by_net - protected_n) / num_nets; if (per < 1) per = 1;
        int any = 0;
        for (int k = 0; k < 4; k++){
            if (!nets[k].count) continue;
            g_nt_local = nets[k].is_local; g_nt_net = nets[k].id;
            int before = n; n = erase_last_k(c, n, c_nettime, per, pred_net);
            if (before > n){
                any = 1; protected_n += before - n;
                if (protected_n >= max_by_net) break;
                nets[k].count -= before - n;
            }
        }
        if (!any) break;
    }
    return erase_last_k(c, n, c_conn, total_protect - protected_n, pred_all);
}

int inbound_select_victim(const node_status_t* st, long long now, int first_slot, int last_slot){
    (void)now;
    if (!st) return -1;
    cand_t c[MAXC]; int n = 0;
    for (int i = first_slot; i <= last_slot && i < MAXC; i++){
        const rpc_peer_t* q = &st->peers[i];
        if (!q->used || !q->inbound) continue;                    /* ProtectOutboundConnections */
        if (q->perms & NP_NOBAN) continue;                        /* ProtectNoBanConnections */
        if (q->evict_requested) continue;                         /* already going */
        cand_t* x = &c[n++];
        x->slot = i; x->conn = q->conn_time; x->tx = q->last_tx_time; x->blk = q->last_block_time;
        x->ping = q->min_ping_us > 0 ? q->min_ping_us : LLONG_MAX;   /* unmeasured: Core's microseconds::max() */
        x->grp = q->net_group; x->kgrp = inbound_evict_keyed_group(q->net_group);
        x->relay_txs = q->relaytxes ? 1 : 0; x->relevant = relevant_services(q->services);
        classify(q->addr, &x->is_local, &x->net);
    }
    n = erase_last_k(c, n, c_netgroup, 4, pred_all);
    n = erase_last_k(c, n, c_ping, 8, pred_all);
    n = erase_last_k(c, n, c_tx, 4, pred_all);
    n = erase_last_k(c, n, c_blkrelay, 8, pred_blkrelay);
    n = erase_last_k(c, n, c_blk, 4, pred_all);
    n = protect_by_ratio(c, n);
    if (n == 0) return -1;
    /* c is sorted newest first (the ratio step's last sort): the group with
     * the most members, ties to the group whose first (newest) member is
     * newest; its newest member goes */
    unsigned long long best = 0; int best_cnt = 0; long long best_time = 0;
    for (int i = 0; i < n; i++){
        int cnt = 0; long long first = 0; int seen_first = 0;
        for (int j = 0; j <= i; j++) if (c[j].grp == c[i].grp){ cnt++; if (!seen_first){ first = c[j].conn; seen_first = 1; } }
        if (cnt > best_cnt || (cnt == best_cnt && first > best_time)){ best_cnt = cnt; best_time = first; best = c[i].grp; }
    }
    for (int i = 0; i < n; i++) if (c[i].grp == best) return c[i].slot;
    return -1;
}
