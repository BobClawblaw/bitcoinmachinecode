/* daemon/addr_hist_fmt.h -- the address HISTORY index (2026-09-08): every
 * funding and spending event of every standard address, for the Esplora
 * facade's address routes (mempool.space's address pages).
 *
 * The existing address index (addr_index.dat + addrindex.tail) answers
 * "what does this address own NOW"; Esplora's /address routes want the
 * whole history: funded_txo_count/sum, spent_txo_count/sum, tx_count and
 * the transaction list. This index is that history, keyed exactly like the
 * other one (addr_index_fmt.h: type_tag + hash, so an address maps 1:1).
 *
 * File `addr_hist.dat` (chain directory), built offline by
 * daemon/bmc_build_addr_hist, kept current by the SAME tail journal the
 * live address index writes (addrindex.tail: ADD = a funding, DEL = a
 * spend, TOUCH = the spending txid), which the reader merges above
 * `to_height`.
 *
 *   header (64 B): magic 'UAHX' u32 | version u32 | to_height u32 | pad u32 |
 *                  n_keys u64 | n_events u64 | body_off u64 | body_len u64 |
 *                  sparse_off u64 | sparse_n u64
 *   body:  groups sorted by key: [type u8][hash 32][n u32] then n events,
 *          each [kind u8][height u32][txpos u32][idx u32][value u64] (21 B):
 *          kind 1 FUND (idx = vout), kind 2 SPEND (idx = vin of the spender;
 *          value = the spent output's value). Sorted by (height, txpos,
 *          kind, idx). height/txpos name the transaction in the block; the
 *          txid is one getblock away, and is not stored (32 B x 7 billion).
 *   sparse: every 256th group: [type u8][hash 32][body offset u64] (41 B).
 *
 * Size on mainnet: ~7 billion events x 21 B plus ~1.3 billion keys x 37 B,
 * about 200 GB uncompressed. */
#ifndef ADDR_HIST_FMT_H
#define ADDR_HIST_FMT_H
#include <stdint.h>
#include <string.h>
#define AH_FILE          "addr_hist.dat"
#define AH_MAGIC         0x58484155u
#define AH_VERSION       1u
#define AH_HDR_BYTES     64
#define AH_EVENT_BYTES   21
#define AH_GROUP_HDR     37
#define AH_SPARSE_BYTES  41
#define AH_SPARSE_STRIDE 256
#define AH_FUND  1
#define AH_SPEND 2
#pragma pack(push,1)
typedef struct { uint8_t kind; uint32_t height; uint32_t txpos; uint32_t idx; uint64_t value; } ah_event;
typedef struct { uint8_t type; uint8_t hash[32]; uint32_t n; } ah_group_hdr;
typedef struct { uint8_t type; uint8_t hash[32]; uint64_t off; } ah_sparse;
typedef struct { uint32_t magic, version, to_height, pad; uint64_t n_keys, n_events, body_off, body_len, sparse_off, sparse_n; } ah_header;
#pragma pack(pop)
/* The key order of the file: hash[0] first, then type, then the rest of
 * the hash. The builder buckets keys by hash[0] and writes the buckets in
 * order, sorting each one with this comparator; hash[0] is constant inside
 * a bucket, so the global sequence is sorted by exactly this order and the
 * reader's binary search over the sparse index is valid.
 *
 * 2026-09-08: the comparator was type-major (type, then the 32 bytes) while
 * the file was bucket-major -- the sparse search landed anywhere and every
 * base lookup on production returned nothing: the genesis address showed
 * its seven tail events, not its 78,688 fundings. The order below is the
 * order the buckets were written in, so the 207 GB base is valid as it is. */
static inline int ah_key_cmp(uint8_t ta, const uint8_t* ha, uint8_t tb, const uint8_t* hb){
    if (ha[0] != hb[0]) return ha[0] < hb[0] ? -1 : 1;
    if (ta != tb) return ta < tb ? -1 : 1;
    return memcmp(ha + 1, hb + 1, 31);
}
static inline int ah_event_cmp(const ah_event* a, const ah_event* b){
    if (a->height != b->height) return a->height < b->height ? -1 : 1;
    if (a->txpos != b->txpos) return a->txpos < b->txpos ? -1 : 1;
    if (a->kind != b->kind) return a->kind < b->kind ? -1 : 1;
    return a->idx < b->idx ? -1 : a->idx > b->idx ? 1 : 0;
}
/* the reader (daemon/addr_hist.c) */
int  ah_available(void);                       /* addr_hist.dat exists and opens */
long ah_to_height(void);                       /* the base's coverage, -1 if none */
long ah_lookup(uint8_t type, const uint8_t hash[32], const ah_event** events);   /* count (0 absent, -1 no index) */
#endif
