/* mempool_slot.h -- the C view of bitcoin_mempool.asm's slot table.
 *
 * The structural mempool is an asm object; several C walkers (the BIP35
 * `mempool` reply in daemon/main.c, rpc_node.c's getrawmempool, rpc_chain.c's
 * getblocktemplate, daemon/reorg.c's block reconcile, daemon/mempool_compact.c
 * and daemon/cmpct_recv.c's short-id table) index its slots directly. Until
 * 2026-09-06 each of them spelled the 48-byte stride as a literal; widening
 * the slot to carry the cached wtxid touched every one. This header is the
 * single place the layout lives on the C side -- change it in lockstep with
 * the asm header comment and mpool_struct_size.
 *
 *   +0   u64 n
 *   +8   u64 mask          (slot count = mask + 1, a power of two)
 *   +16  u8* blob
 *   +24  u64 blob_cap
 *   +32  u64 fill
 *   +40  slots, MPOOL_SLOT_BYTES each:
 *          [+0 u64 len][+8 txid[32]][+40 u64 blob_off][+48 wtxid[32]]
 *   empty slot: len == MPOOL_SLOT_EMPTY
 */
#ifndef MEMPOOL_SLOT_H
#define MEMPOOL_SLOT_H

#define MPOOL_HDR_BYTES     40UL
#define MPOOL_SLOT_BYTES    80UL
#define MPOOL_SLOT_LEN      0
#define MPOOL_SLOT_TXID     8
#define MPOOL_SLOT_OFF      40
#define MPOOL_SLOT_WTXID    48
#define MPOOL_SLOT_EMPTY    0xFFFFFFFFFFFFFFFFULL

/* mpool_struct_size(slots), as a constant expression for static buffers */
#define MPOOL_AREA_BYTES(slots) (MPOOL_HDR_BYTES + (unsigned long)(slots) * MPOOL_SLOT_BYTES + 8UL)

/* &slot[i] for a pool at base m (unsigned char*) */
#define MPOOL_SLOT_AT(m, i) ((m) + MPOOL_HDR_BYTES + (unsigned long)(i) * MPOOL_SLOT_BYTES)

/* bitcoin_mempool.asm: pointer to slot i's cached wtxid, or 0 if i is past the
 * table or the slot is empty. The wtxid is sha256d over the tx bytes as
 * stored (BIP152's hash; equals the txid for a non-witness tx), computed once
 * by mpool_put. */
const unsigned char* mpool_wtxid_at_slot(const void* mp, unsigned long i);

#endif
