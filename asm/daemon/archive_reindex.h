/* daemon/archive_reindex.h -- Core -reindex: rebuild index.dat, headers.dat
 * and chainwork.dat from the blk*.dat frames. See archive_reindex.c. */
#ifndef ARCHIVE_REINDEX_H
#define ARCHIVE_REINDEX_H

/* The frame magic bitcoin_store.asm writes in front of every block, on EVERY
 * chain: a store-format constant (mainnet's message-start), not the network
 * magic. Pass this, never net_magic. */
#define BMC_FRAME_MAGIC 0xd9b4bef9u

typedef struct {
    long tip;              /* height of the rebuilt active chain */
    long files;            /* blk files scanned */
    long frames;           /* frames with a sane header found */
    long duplicates;       /* frames carrying a hash already seen (collapsed) */
    long orphans;          /* frames whose prev-hash no frame carries */
    long stale;            /* linked blocks not on the best chain */
    long bad_pow;          /* frames whose header fails its own nBits */
    long truncated_files;  /* files containing junk between or after frames */
    long junk_bytes;       /* bytes skipped while resyncing */
    int  tip_reappended;   /* the tip frame was copied to the end for append safety */
} archive_reindex_stats;

/* Rebuild the three derived files under <dir> from its blk*.dat frames.
 * `genesis` is the chain's genesis hash in wire (little-endian) order and
 * `magic` the frame magic the store writes (the network's message-start as
 * a little-endian dword). Returns 0 and fills `st` on success; -1 with a
 * reason in `err` otherwise, in which case nothing was renamed. */
int archive_reindex(const char* dir, const unsigned char genesis[32], unsigned magic,
                    archive_reindex_stats* st, char* err, unsigned long errcap);

#endif
