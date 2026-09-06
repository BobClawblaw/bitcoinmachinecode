/* tests/test_inbound_evict.c -- CC-3: Core's eviction rules over the shared peer table. */
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
static void reset(void){ memset(st->peers, 0, sizeof st->peers); }
static rpc_peer_t* add(int slot, long long conn, unsigned grp){ rpc_peer_t* q = &st->peers[slot]; memset(q, 0, sizeof *q); q->used = 1; q->inbound = 1; q->conn_time = conn; q->net_group = grp; q->pid = 1; return q; }
static int pick(void){ return inbound_select_victim(st, NOW, F, L); }
int main(void){
    st = calloc(1, sizeof *st); if (!st) return 2;
    printf("== empty and trivial ==\n");
    reset(); ok(pick() == -1, "no inbound peers: no victim");
    reset(); add(F, NOW-100, 1); ok(pick() == F, "one peer: half of one is none protected, so it is the victim (Core evicts it)");
    printf("== round 5: the largest netgroup loses its youngest ==\n");
    reset(); for (int i = 0; i < 6; i++) add(F+i, NOW-1000+i, 7); add(F+6, NOW-1000, 9); add(F+7, NOW-1000, 10);
    ok(pick() == F+5, "6 in group 7, 1 each in 9 and 10: the youngest of group 7 (slot 69)");
    printf("== round 2: the 8 most recent tx senders are protected ==\n");
    reset(); for (int i = 0; i < 10; i++){ rpc_peer_t* q = add(F+i, NOW-1000, 7); q->last_tx_time = NOW - 10 - i; }
    add(F+10, NOW-5, 7);   /* youngest, never sent a tx */
    ok(pick() == F+10, "ten recent tx senders (8 protected) + one silent newcomer: the newcomer");
    printf("== round 3: the 4 most recent novel-block senders are protected ==\n");
    reset(); for (int i = 0; i < 4; i++){ rpc_peer_t* q = add(F+i, NOW-1, 7); q->last_block_time = NOW - i; }   /* youngest AND protected */
    add(F+4, NOW-500, 7);
    ok(pick() == F+4, "four block senders are protected even though youngest; the fifth goes");
    printf("== round 4: half the remainder, longest connected, is protected ==\n");
    reset(); add(F+0, NOW-5000, 1); add(F+1, NOW-4000, 2); add(F+2, NOW-10, 3); add(F+3, NOW-20, 4);
    int v = pick(); ok(v == F+2 || v == F+3, "two old, two young, all different groups: a young one goes");
    ok(v == F+2, "...the youngest (conn NOW-10)");
    printf("== NoBan is never evicted ==\n");
    reset(); { rpc_peer_t* q = add(F+0, NOW-1, 7); q->perms = NP_NOBAN; } add(F+1, NOW-100, 7);
    ok(pick() == F+1, "the youngest is NoBan: the other one goes");
    reset(); { rpc_peer_t* q = add(F+0, NOW-1, 7); q->perms = NP_NOBAN; }
    ok(pick() == -1, "only a NoBan peer: no victim (refuse the newcomer)");
    printf("== already-evicting peers are not chosen twice ==\n");
    reset(); { rpc_peer_t* q = add(F+0, NOW-1, 7); q->evict_requested = 1; } add(F+1, NOW-100, 7);
    ok(pick() == F+1, "slot 64 is already leaving: slot 65 is next");
    printf("== round 1: measured pings protect the 4 lowest ==\n");
    reset(); for (int i = 0; i < 4; i++){ rpc_peer_t* q = add(F+i, NOW-1, 7); q->min_ping_us = 1000 + i; }   /* youngest, best pings */
    add(F+4, NOW-900, 7);
    ok(pick() == F+4, "four low-ping peers protected though youngest; the fifth goes");
    reset(); for (int i = 0; i < 5; i++) add(F+i, NOW-1000+i, 7);   /* all ping 0 = unmeasured */
    ok(pick() == F+4, "unmeasured pings protect nobody (this node does not ping inbound peers yet)");
    printf("== outbound slots are never candidates ==\n");
    reset(); { rpc_peer_t* q = add(3, NOW-1, 7); q->inbound = 0; } add(F+0, NOW-100, 7);
    ok(pick() == F+0, "an outbound leg in slot 3 is ignored");
    printf("== the finding (negative control): full table, no eviction -> the newcomer is served unrecorded ==\n");
    reset(); for (int i = F; i <= L; i++) add(i, NOW-1000+(i-F), (unsigned)(i % 3));
    int free_slot = -1; for (int i = F; i <= L; i++) if (!st->peers[i].used){ free_slot = i; break; }
    ok(free_slot == -1, "control: 64 inbound slots all used, no free slot for a 65th (pre-CC-3 the child served anyway)");
    v = pick(); ok(v >= F && v <= L, "with CC-3: a victim is chosen from the full table");
    printf("      victim slot %d, group %u\n", v, st->peers[v].net_group);
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
