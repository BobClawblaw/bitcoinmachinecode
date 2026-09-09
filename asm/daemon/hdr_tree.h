/* daemon/hdr_tree.h -- the FORK TREE: headers of every branch that is not
 * the best chain, retained with their cumulative work, as Core's block index
 * keeps every valid header it has ever seen.
 *
 * headers.dat is the best header chain (one header per height, the chain the
 * archive follows). A branch that loses on work -- a candidate a reorg probe
 * found lighter, the branch a handoff rewound off, a page a header fetch
 * refused because it forked below our tip, blocks a keep-up leg stored off
 * the best chain -- used to be forgotten, and the node re-adopted the same
 * stale branch from the same stuck peer thirty seconds after rewinding off
 * it (2026-09-09, the bench at 961,632). Retained here, a branch is known:
 * an extension onto it is refused, its tip's work is comparable, and
 * getchaintips can list it. Persisted to headers_forks.dat beside the
 * archive; bounded, the lightest tips evicted first. */
#ifndef BMC_HDR_TREE_H
#define BMC_HDR_TREE_H
#define HDRTREE_FILE "headers_forks.dat"
#define HDRTREE_MAX  8192
#define HDRTREE_REC  96      /* hash 32, prev 32, height 8, bits 4, work 16, pad 4 */
int  hdrtree_open(void);                                   /* load HDRTREE_FILE from the cwd (the chain dir); 1 ok */
long hdrtree_count(void);
/* add one header: hdr80 as on the wire; height = its height on its branch;
 * work = cumulative work through it. 1 added, 0 already known, -1 refused. */
int  hdrtree_add(const unsigned char hdr80[80], long height, const unsigned char work[16]);
int  hdrtree_has(const unsigned char hash[32]);
int  hdrtree_get(const unsigned char hash[32], unsigned char prev[32], long* height, unsigned char work[16]);
/* the heaviest retained tip (an entry no other entry names as prev); 1 found */
int  hdrtree_best(unsigned char hash[32], long* height, unsigned char work[16]);
long hdrtree_prune_below(long height);                     /* drop entries below height; returns dropped */
void hdrtree_reset(void);                                  /* tests: empty the table (the file too) */
#endif
