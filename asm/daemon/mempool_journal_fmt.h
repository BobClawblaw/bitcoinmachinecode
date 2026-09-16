/* daemon/mempool_journal_fmt.h -- the ONE definition of a mempool DEPARTURE
 * record, shared by the writer (daemon/mempool_journal.c), the RPC
 * (rpc_node.c bmcgetmempooljournal) and the Esplora facade (rpc_esplora.c).
 *
 * WHY THIS EXISTS. A mempool is a waiting room, not a ledger. Core caps it at
 * -maxmempool (300 MB by default) and evicts the cheapest packages when it is
 * full, and -mempoolexpiry drops anything older than 336 hours. When a
 * transaction leaves that way it is simply forgotten: Core cannot answer "what
 * happened to this txid" for anything it saw and dropped, so an explorer built
 * on it shows gaps, or "ghost" transactions that were broadcast and then
 * vanished with no explanation. The usual workaround is a "Big Node" -- raise
 * -maxmempool until nothing is ever evicted -- which trades unbounded memory
 * for an answer, and still loses everything on restart.
 *
 * This node instead writes one small record when a transaction LEAVES the
 * pool, naming the reason. The pool keeps Core's exact eviction and expiry
 * behaviour (consensus and policy are untouched); only the bookkeeping is new.
 *
 * Bitcoin Core has no counterpart to this file. Like addrindex, it is a
 * deliberate EXTENSION, off by default, and it changes no consensus or wire
 * behaviour.
 *
 * SHAPE: a fixed-capacity RING, not an unbounded log. Oldest departures are
 * overwritten. That bounds the file at capacity * 152 bytes for a box that
 * already carries a 200 GB address history, and it matches what the question
 * is actually for: "what happened to this transaction I just broadcast",
 * which is a recent-history question.
 *
 * TORN RECORDS. Records sit on a fixed grid and carry the same sequence
 * number at BOTH ends. A reader accepts a record only when seq_head ==
 * seq_tail, so a write interrupted by a crash (or seen mid-flight by another
 * process -- the pool is MAP_SHARED and the node forks per connection) reads
 * as absent rather than as a half-written record that looks whole. This is
 * the same discipline the rest of the tree states as "header written last, so
 * a crash leaves a file that reads as absent rather than a partial one".
 */
#ifndef MEMPOOL_JOURNAL_FMT_H
#define MEMPOOL_JOURNAL_FMT_H

#include <stdint.h>

#define MPJ_FILE        "mempool_journal.dat"
#define MPJ_MAGIC       "BMCMPJ\x01"          /* 7 bytes + NUL = 8 */
#define MPJ_VERSION     1u
#define MPJ_REC_BYTES   152u
#define MPJ_HDR_BYTES   64u

/* Why the transaction left the pool. Ordered so that "did it make it" is a
 * single comparison: MPJ_MINED is the only outcome where it did. */
enum {
    MPJ_MINED      = 1,   /* included in a block this node connected        */
    MPJ_REPLACED   = 2,   /* BIP125 / full-RBF: a conflicting tx paid more  */
    MPJ_EVICTED    = 3,   /* TrimToSize: the pool hit -maxmempool           */
    MPJ_EXPIRED    = 4,   /* older than -mempoolexpiry hours                */
    MPJ_CONFLICTED = 5,   /* a reorg left it spending a now-unspent output  */
    MPJ_REASON_MAX = 5
};

static inline const char* mpj_reason_name(uint32_t r) {
    switch (r) {
        case MPJ_MINED:      return "mined";
        case MPJ_REPLACED:   return "replaced";
        case MPJ_EVICTED:    return "evicted";
        case MPJ_EXPIRED:    return "expired";
        case MPJ_CONFLICTED: return "conflicted";
        default:             return "unknown";
    }
}

/* Record layout, little-endian, 152 bytes on a fixed grid:
 *
 *   +0    u64 seq_head      the write's sequence number (1-based; 0 = never written)
 *   +8    u8  txid[32]      wire order
 *   +40   u8  wtxid[32]     wire order; equals txid for a non-witness tx
 *   +72   u8  aux[32]       MPJ_REPLACED: the replacing txid
 *                           MPJ_MINED:    the block hash
 *                           otherwise:    zero
 *   +104  i64 first_seen    unix seconds when the pool accepted it, 0 if unknown
 *   +112  i64 departed_at   unix seconds when it left
 *   +120  u64 vsize         BIP141 virtual size at departure
 *   +128  u64 fee_sat       absolute fee in satoshis
 *   +136  u32 reason        MPJ_* above
 *   +140  u32 height        MPJ_MINED: the block height; otherwise 0
 *   +144  u64 seq_tail      == seq_head for a complete record
 */
typedef struct {
    uint64_t seq;
    uint8_t  txid[32];
    uint8_t  wtxid[32];
    uint8_t  aux[32];
    int64_t  first_seen;
    int64_t  departed_at;
    uint64_t vsize;
    uint64_t fee_sat;
    uint32_t reason;
    uint32_t height;
} mpj_rec;

#define MPJ_OFF_SEQ_HEAD    0u
#define MPJ_OFF_TXID        8u
#define MPJ_OFF_WTXID       40u
#define MPJ_OFF_AUX         72u
#define MPJ_OFF_FIRST_SEEN  104u
#define MPJ_OFF_DEPARTED    112u
#define MPJ_OFF_VSIZE       120u
#define MPJ_OFF_FEE         128u
#define MPJ_OFF_REASON      136u
#define MPJ_OFF_HEIGHT      140u
#define MPJ_OFF_SEQ_TAIL    144u

/* Header layout, little-endian, 64 bytes:
 *   +0   char magic[8]   MPJ_MAGIC
 *   +8   u32  version
 *   +12  u32  rec_bytes
 *   +16  u64  capacity    records in the ring
 *   +24  u64  next_seq    next sequence to hand out (1-based); slot = (seq-1) % capacity
 *   +32  u64  reserved[4]
 */
#define MPJ_HOFF_MAGIC     0u
#define MPJ_HOFF_VERSION   8u
#define MPJ_HOFF_RECBYTES  12u
#define MPJ_HOFF_CAPACITY  16u
#define MPJ_HOFF_NEXTSEQ   24u

/* file size for a ring of `cap` records */
#define MPJ_FILE_BYTES(cap) ((uint64_t)MPJ_HDR_BYTES + (uint64_t)(cap) * MPJ_REC_BYTES)

#endif
