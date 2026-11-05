/* daemon/hdr_tree.h -- the FORK TREE: headers of every branch that is not
 * the best chain, retained with their cumulative work, as Core's block index
 * keeps every valid header it has ever seen.
 *
 * headers.dat is the best header chain (one header per height, the chain the
 * archive follows). A branch that loses on work -- a candidate a reorg probe
 * found lighter, the branch a reorg disconnects, a page a header fetch
 * refused because it forked below our tip, blocks a keep-up leg stored off
 * the best chain, a block the operator invalidates -- used to be forgotten,
 * and the node re-adopted the same stale branch from the same stuck peer
 * thirty seconds after rewinding off it (2026-09-09, the bench at 961,632).
 * Retained here, a branch is known: its tip's work is comparable, and
 * getblockheader answers for its blocks (2026-11-04: LND's wallet processes a
 * reorg by asking for the header of the block it last saw; a node that
 * answers "Block not found" leaves it stuck at the fork for good).
 *
 * Persisted to HDRTREE_FILE beside the archive; bounded, the lightest tips
 * evicted first. The download worker owns the table; the RPC process reads
 * the file (hdrtree_file_lookup), which is only ever appended to whole
 * records or replaced by rename, so a reader sees whole records.
 *
 * Record layout (HDRTREE_REC bytes, little-endian, version 2, 2026-11-04):
 *   0 hash 32 | 32 prev 32 | 64 height 8 | 72 bits 4 | 76 work 16 |
 *   92 nTx 4 (0 = unknown) | 96 flags 4 (bit 0: the 80-byte header is
 *   present) | 100 header 80 | 180 pad 4
 * Version 1 (HDRTREE_FILE_V1, 96-byte records: the first 92 bytes above, no
 * header) is read once, rewritten as version 2 and renamed aside; its entries
 * keep working for work comparison but have no header to serve. */
#ifndef BMC_HDR_TREE_H
#define BMC_HDR_TREE_H
#define HDRTREE_FILE     "headers_forks2.dat"
#define HDRTREE_FILE_V1  "headers_forks.dat"
#define HDRTREE_MAX      8192
#define HDRTREE_REC      184
#define HDRTREE_REC_V1   96
#define HDRTREE_OFF_HEIGHT 64
#define HDRTREE_OFF_WORK   76
#define HDRTREE_OFF_NTX    92
#define HDRTREE_OFF_FLAGS  96
#define HDRTREE_OFF_HDR    100
#define HDRTREE_HAVE_HDR   1u
int  hdrtree_open(void);                                   /* load HDRTREE_FILE from the cwd (the chain dir); 1 ok */
long hdrtree_count(void);
/* add one header: hdr80 as on the wire; height = its height on its branch;
 * work = cumulative work through it. 1 added, 0 already known, -1 refused.
 * hdrtree_add_ntx also records the block's transaction count (0 = unknown). */
int  hdrtree_add(const unsigned char hdr80[80], long height, const unsigned char work[16]);
int  hdrtree_add_ntx(const unsigned char hdr80[80], long height, const unsigned char work[16], unsigned ntx);
int  hdrtree_has(const unsigned char hash[32]);
int  hdrtree_get(const unsigned char hash[32], unsigned char prev[32], long* height, unsigned char work[16]);
/* the heaviest retained tip (an entry no other entry names as prev); 1 found */
int  hdrtree_best(unsigned char hash[32], long* height, unsigned char work[16]);
long hdrtree_prune_below(long height);                     /* drop entries below height; returns dropped */
void hdrtree_reset(void);                                  /* tests: empty the table (the files too) */
/* Read-only lookup in HDRTREE_FILE (cwd) by wire-order hash, for a process
 * that does not own the table (daemon/hdr_tree_read.c). 1 found WITH its
 * header (hdr80, height, work, ntx filled; any may be NULL), 0 not found or
 * found without a header. */
int  hdrtree_file_lookup(const unsigned char hash[32], unsigned char hdr80[80], long* height,
                         unsigned char work[16], unsigned* ntx);
#endif
