/* tests/test_inbound_evict.c -- CC-3: Core's eviction rules over the shared peer table.
 * P2P-4 (audit 2026-10-23): the order is Core v31.1's SelectNodeToEvict
 * (node/eviction.cpp): 4 by keyed netgroup, 8 by min ping (unmeasured is the
 * worst), 4 by last tx, 8 block-relay-only by last block, 4 by last block,
 * then half of the rest with up to half of that reserved for CJDNS, I2P,
 * localhost and onion peers, then the biggest netgroup loses its newest.
 *
 * Every table here is built so Core's answer does not depend on how its
 * std::sort orders exact ties: each peer has its own ping (100000 + slot,
 * so older slots ping better) unless a case says otherwise, distinct
 * connect times, and four "shield" peers in the four groups with the highest
 * keyed value soak up the netgroup round. The cases marked [CC-3 differs]
 * had another answer under the 2026-09-06 transcription. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "inbound_evict.h"
#include "netperm.h"
static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
static node_status_t* st; static const long long NOW = 1000000;
#define F 64
#define L 127
static unsigned shield[4];
static void reset(void){ memset(st->peers, 0, sizeof st->peers); }
static rpc_peer_t* add(int slot, long long conn, unsigned grp){
    rpc_peer_t* q = &st->peers[slot]; memset(q, 0, sizeof *q); q->used = 1; q->inbound = 1; q->conn_time = conn; q->net_group = grp; q->pid = 1;
    q->relaytxes = 1; q->services = 1 | 8; q->min_ping_us = 100000 + slot;
    snprintf(q->addr, sizeof q->addr, "198.51.%u.%d:8333", grp & 0xff, slot);
    return q;
}
static int pick(void){ return inbound_select_victim(st, NOW, F, L); }
/* 40 old peers in group 777 (slots F..F+39, conn NOW-10000+i) and the four shields (slots F+60..F+63, older still) */
static void base(void){
    reset();
    for (int i = 0; i < 40; i++) add(F + i, NOW - 10000 + i, 777);
    for (int k = 0; k < 4; k++) add(F + 60 + k, NOW - 20000 + k, shield[k]);
}
int main(void){
    st = calloc(1, sizeof *st); if (!st) return 2;
    inbound_evict_set_key(0x0123456789abcdefULL, 0xfedcba9876543210ULL);
    /* the four groups with the highest keyed value among 100000..100999 */
    { unsigned long long kv[4] = {0,0,0,0};
      for (unsigned g = 100000; g < 101000; g++){
          unsigned long long v = inbound_evict_keyed_group(g);
          for (int k = 0; k < 4; k++) if (v > kv[k]){ for (int j = 3; j > k; j--){ kv[j] = kv[j-1]; shield[j] = shield[j-1]; } kv[k] = v; shield[k] = g; break; }
      }
      unsigned others[] = { 777, 7, 8, 0x80000001u, 0x80000002u }; int above = 1;
      for (unsigned i = 0; i < sizeof others / sizeof others[0]; i++) if (inbound_evict_keyed_group(others[i]) >= kv[3]) above = 0;
      ok(above, "setup: the four shield groups key above every other group the cases use"); }

    printf("== small tables: Core protects 4 + 8 + 4 + 4 before the ratio round ==\n");
    reset(); ok(pick() == -1, "no inbound peers: no victim");
    reset(); add(F, NOW-100, 1); ok(pick() == -1, "one peer: protected (the netgroup round)");
    reset(); for (int i = 0; i < 20; i++) add(F+i, NOW-1000+i, 7);
    ok(pick() == -1, "twenty peers: every one protected, the newcomer is refused [CC-3 differs]");
    reset(); for (int i = 0; i < 21; i++) add(F+i, NOW-1000+i, 7);
    ok(pick() >= F && pick() <= F+20, "twenty-one: one is left for the eviction");

    printf("== the ping round protects 8 ==\n");
    base();
    for (int i = 0; i < 8; i++){ rpc_peer_t* q = add(F+40+i, NOW-1-i, 777); q->min_ping_us = 1000 + i; }
    { rpc_peer_t* x = add(F+48, NOW-20, 777); x->min_ping_us = 0; }        /* unmeasured: the worst */
    { int v = pick(); ok(v == F+48, "eight young low-ping peers in the big group are all protected; the unmeasured one goes [CC-3 differs: it protected 4]");
      if (v != F+48) printf("      victim %d\n", v); }

    printf("== the tx round protects 4 ==\n");
    base();
    for (int i = 0; i < 6; i++){ rpc_peer_t* q = add(F+40+i, NOW-1-i, 777); q->last_tx_time = NOW - 10 - i; }
    { int v = pick(); ok(v == F+44, "six young tx senders in the big group: the 4 latest are protected, the newest of the other two goes [CC-3 differs: it protected 8]");
      if (v != F+44) printf("      victim %d\n", v); }

    printf("== the block-relay-only round protects 8 non-tx-relay block senders ==\n");
    base();
    for (int i = 0; i < 8; i++){ rpc_peer_t* q = add(F+40+i, NOW-1-i, 777); q->relaytxes = 0; q->last_block_time = NOW - 100 - i; }
    add(F+48, NOW-50, 777);
    { int v = pick(); ok(v == F+48, "eight young block-relay-only peers that sent blocks: protected; the next-newest goes [CC-3 differs: it protected 4]");
      if (v != F+48) printf("      victim %d\n", v); }
    base();
    for (int i = 0; i < 8; i++){ rpc_peer_t* q = add(F+40+i, NOW-1-i, 777); q->relaytxes = 0; q->services = 0; q->last_block_time = NOW - 100 - i; }
    { int v = pick(); ok(v >= F+44 && v <= F+47, "control: the same peers without the wanted services get only the 4 of the block round");
      if (!(v >= F+44 && v <= F+47)) printf("      victim %d\n", v); }

    printf("== the block round protects 4 recent block senders, even the newest ==\n");
    base();
    for (int i = 0; i < 4; i++){ rpc_peer_t* q = add(F+40+i, NOW-1, 777); q->last_block_time = NOW - i; }
    add(F+44, NOW-500, 777);
    { int v = pick(); ok(v == F+44, "four block senders protected though newest; the fifth goes"); if (v != F+44) printf("      victim %d\n", v); }

    printf("== the ratio round: onion and localhost peers keep a share of the protected half ==\n");
    base();
    for (int i = 0; i < 2; i++){ rpc_peer_t* q = add(F+40+i, NOW-1-i, 777); snprintf(q->addr, sizeof q->addr, "%056d.onion:8333", i); }
    for (int i = 0; i < 2; i++){ rpc_peer_t* q = add(F+42+i, NOW-3-i, 777); snprintf(q->addr, sizeof q->addr, "127.0.0.1:%d", 40000+i); }
    { int v = pick(); ok(v == F+39, "four young onion/localhost peers in the big group are protected by network; its newest other member goes [CC-3 differs: the newest onion peer]");
      if (v != F+39) printf("      victim %d\n", v); }
    base();
    for (int i = 0; i < 4; i++) add(F+40+i, NOW-1-i, 777);
    { int v = pick(); ok(v == F+40, "control: the same four as plain IPv4 get no share: the newest goes"); if (v != F+40) printf("      victim %d\n", v); }

    printf("== the end: the biggest group left loses its newest ==\n");
    reset(); for (int i = 0; i < 30; i++) add(F+i, NOW-10000+i, 7); for (int i = 0; i < 10; i++) add(F+30+i, NOW-5000+i, 8);
    for (int k = 0; k < 4; k++) add(F + 60 + k, NOW - 20000 + k, shield[k]);
    { int v = pick(); ok(v == F+39, "30 in group 7, 10 in group 8: after protection group 7 keeps 2, group 8 all 10 -- group 8's newest");
      if (v != F+39) printf("      victim %d\n", v); }

    printf("== NoBan, evicting, outbound ==\n");
    base(); { rpc_peer_t* q = add(F+40, NOW-1, 777); q->perms = NP_NOBAN; }
    ok(pick() == F+39, "the newest is NoBan: never chosen");
    base(); { rpc_peer_t* q = add(F+40, NOW-1, 777); q->evict_requested = 1; }
    ok(pick() == F+39, "a peer already leaving is not chosen twice");
    base(); { rpc_peer_t* q = add(3, NOW-1, 777); q->inbound = 0; }
    ok(pick() == F+39, "an outbound leg in slot 3 is never a candidate");

    printf("== a full table has a victim ==\n");
    reset(); for (int i = F; i <= L; i++) add(i, NOW-1000+(i-F), (unsigned)(i % 3));
    { int v = pick(); ok(v >= F && v <= L, "64 inbound slots in use: a victim is chosen"); printf("      victim slot %d, group %u\n", v, v >= 0 ? st->peers[v].net_group : 0); }
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
