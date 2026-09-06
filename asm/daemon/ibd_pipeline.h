/* daemon/ibd_pipeline.h -- fetch a chunk of blocks with the WHOLE chunk in
 * flight, instead of one block at a time.
 *
 * node_ibd_blocks_s (bitcoind.asm) is strictly serial: getdata one block,
 * wait for it, verify, store, repeat. Every block therefore costs a full
 * round trip to the peer before the next request even leaves. Measured on the
 * 2026-09-06 fresh-sync benchmark, 16 helpers against 16 real peers: 0.23 to
 * 1.2 MB/s per peer, 11.2 MB/s aggregate, while each peer sat idle for most
 * of every round trip. Core asks for up to 16 blocks per peer at once
 * (MAX_BLOCKS_IN_TRANSIT_PER_PEER) precisely to avoid this.
 *
 * This sends ONE getdata carrying every hash in the chunk, then receives the
 * blocks as they come. Peers may answer out of order, so a block is placed by
 * its HASH against the chunk's local headers, not by arrival position -- the
 * headers are already PoW-checked and linked by the header phase, so hash
 * identity is what decides a block's height, and the prev-hash link is
 * re-checked against those headers rather than against arrival order.
 *
 * Same validation as the serial path, block for block: cons_verify, the
 * header-hash match, the prev-hash chain link, then store_append_shared at
 * the block's real height. Nothing is stored that the serial path would not
 * have stored. */
#ifndef IBD_PIPELINE_H
#define IBD_PIPELINE_H
/* Returns the number of blocks stored (== nloc on a clean chunk), or -1 if
 * the peer broke the protocol, sent a block that fails validation, or the
 * socket died. buf/buflen is the caller's block scratch. */
long ibd_fetch_chunk_pipelined(int fd, void* st, void* hst, long lo_real, long nloc,
                               unsigned char* buf, unsigned buflen,
                               void* scratch, unsigned scratch_cap);
/* test seam: how many hashes the last call put in ONE getdata (0 = never ran) */
long ibd_pipeline_last_batch(void);
/* test/bench seam: hashes per getdata. 0 (the default) means the whole chunk
 * in one message. 1 reproduces the serial shape node_ibd_blocks_s had -- ask
 * for one block, wait for it, ask for the next -- so the two can be timed
 * against the same peer, through the same code. */
void ibd_pipeline_set_wave(long hashes_per_getdata);
#endif
