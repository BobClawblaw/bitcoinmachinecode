/* daemon/cmpct_recv.h -- CC-2 (2026-09-06): BIP152 compact block RECEIVE.
 *
 * The serve side (bitcoin_cmpct.asm) already answers MSG_CMPCT_BLOCK getdata
 * and getblocktxn. The download side fetched every block in full: it never
 * sent sendcmpct and had no handler for cmpctblock or blocktxn, so a peer's
 * compact block was dropped and the block re-fetched whole. Now an outbound
 * leg that negotiated sendcmpct is asked for MSG_CMPCT_BLOCK; the compact
 * block is reconstructed from the mempool, the missing transactions are
 * requested with getblocktxn, and the assembled block enters the unchanged
 * validate-and-store path exactly as a `block` message would.
 *
 * Low-bandwidth mode only (we send sendcmpct with high_bandwidth=0): a peer
 * announces with headers/inv, we request. High-bandwidth (unsolicited push)
 * is a follow-up. */
#ifndef CMPCT_RECV_H
#define CMPCT_RECV_H
#define MSG_WITNESS_BLOCK_T 0x40000002u
#define MSG_CMPCT_BLOCK_T   4u
void cmpct_recv_set_enabled(int on);
int  cmpct_recv_enabled(void);
unsigned cmpct_getdata_type(int leg_negotiated);           /* the inventory type to request a block with */
typedef long (*cmpct_writer_t)(int fd, const char* cmd, unsigned cmdlen, const void* payload, unsigned plen);
void cmpct_recv_set_writer(cmpct_writer_t w);              /* test seam; default p2p_write */
/* A cmpctblock payload for the block we asked for (want_hash, wire order).
 *   > 0  : the full block is in out (that many bytes) -- validate and store it
 *   0    : pending -- getblocktxn was sent, or (on any failure) a full
 *          MSG_WITNESS_BLOCK getdata was sent; keep reading
 *   -1   : not the block we wanted, or receive disabled -- ignore */
long cmpct_recv_cmpctblock(int fd, void* mp, const unsigned char* pl, unsigned long plen,
                           unsigned char* out, unsigned long cap, const unsigned char want_hash[32]);
/* A blocktxn payload: same contract (> 0 block ready, 0 fallback sent, -1 not ours) */
long cmpct_recv_blocktxn(int fd, const unsigned char* pl, unsigned long plen, unsigned char* out, unsigned long cap);
/* stats for the log */
void cmpct_recv_stats(unsigned long* reconstructed, unsigned long* needed_txn, unsigned long* fell_back);
/* The short-id table takes each pool entry's wtxid from the slot cache that
 * mpool_put fills (bitcoin_mempool.asm, 2026-09-06). Off = hash every entry
 * per block, the pre-cache behaviour; the test's negative control. */
void cmpct_recv_set_wtxid_cache(int on);
/* how many pool entries ht_build has hashed with tx_wtxid since start (0 with the cache on) */
unsigned long cmpct_recv_hashed(void);
#endif
