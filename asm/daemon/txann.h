/* daemon/txann.h -- CC-1 (2026-09-06): transaction announcement to and from
 * inbound peers. Core announces every accepted transaction to every peer that
 * negotiated relay, from a per-peer queue flushed on a Poisson timer (mean
 * INBOUND_INVENTORY_BROADCAST_INTERVAL = 5 s inbound), never back to the
 * peer it came from, filtered by that peer's feefilter. This node's inbound
 * serve loop announced nothing, and a transaction accepted from an inbound
 * peer reached no other peer at all.
 *
 * Three roles over one shared ring (rpc_node.h ann_ring):
 *   producer  txann_push()        -- tx_accept.c, in whichever process accepted
 *   inbound   txann_wait()/tick() -- each forked serve child, before its read
 *   worker    txann_worker_drain()-- feeds inbound-origin txs to the outbound legs
 */
#ifndef TXANN_H
#define TXANN_H
#include "../rpc_node.h"
void txann_set_status(node_status_t* st);          /* once, before fork */
void txann_set_my_slot(int slot);                  /* the serve child's peer-table slot; -1 = worker */
int  txann_my_slot(void);
void txann_push(const unsigned char txid[32], unsigned long long fee, unsigned long vsize);

void txann_child_init(int slot, int relay_ok);     /* after the handshake, before the serve loop */
long txann_wait(int fd, unsigned long long peer_feefilter);   /* asm: 1 = readable, 0 = idle bound hit */
long txann_tick(int fd, long long now_ms, unsigned long long peer_feefilter);  /* returns txids announced */

long txann_worker_drain(void (*announce)(const unsigned char txid[32]));

/* test seams */
typedef long (*txann_writer_t)(int fd, const char* cmd, unsigned cmdlen, const void* payload, unsigned plen);
void txann_set_writer(txann_writer_t w);
void txann_set_mean_ms(long ms);
void txann_set_idle_secs(long s);
void txann_set_enabled(int on);
unsigned long long txann_lapped(void);
#define TXANN_INV_MAX 35        /* Core INVENTORY_BROADCAST_TARGET per flush is larger; 35 keeps one inv under 1.3 KB */
#endif
