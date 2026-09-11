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
/* Returns the number of blocks stored (== nloc on a clean chunk), or a
 * NEGATIVE reason code (below) when the peer broke the protocol, sent a
 * block that fails validation, the socket died, or the store refused. Every
 * failure used to be a bare -1, and a worker that failed 400 chunks in 45 s
 * on the 2026-09-07 run 10 left no line saying why. buf/buflen is the
 * caller's block scratch. */
enum { IBD_FAIL_ARGS = -1, IBD_FAIL_HEADERS = -2, IBD_FAIL_WRITE = -3, IBD_FAIL_READ = -4, IBD_FAIL_CONSENSUS = -5,
       IBD_FAIL_LINK = -6, IBD_FAIL_STORE = -7, IBD_FAIL_HOLD = -8, IBD_FAIL_BUDGET = -9 };
int ibd_pipeline_last_fail(void);                 /* the last call's reason code (0 = it succeeded) */
const char* ibd_pipeline_fail_name(int code);     /* a short reason for the log line */
long ibd_fetch_chunk_pipelined(int fd, void* st, void* hst, long lo_real, long nloc,
                               unsigned char* buf, unsigned buflen,
                               void* scratch, unsigned scratch_cap);
/* test seam: how many hashes the last call put in ONE getdata (0 = never ran) */
long ibd_pipeline_last_batch(void);
/* The last chunk's OCCUPANCY: how long the call sat blocked in the socket
 * read, against its whole wall clock. A worker that is 20% idle is a worker
 * whose peer cannot fill the pipe, and that is the difference between "add
 * peers" and "make the code faster" -- see docs/CORE_DIVERGENCES.md row 2. */
long ibd_pipeline_last_wait_ms(void);
long ibd_pipeline_last_wall_ms(void);
/* test/bench seam: hashes per getdata. 0 (the default) means the whole chunk
 * in one message. 1 reproduces the serial shape node_ibd_blocks_s had -- ask
 * for one block, wait for it, ask for the next -- so the two can be timed
 * against the same peer, through the same code. */
void ibd_pipeline_set_wave(long hashes_per_getdata);
/* progress hook: called ONCE per wanted, validated block the peer delivers
 * (stored or parked), never for pings, unasked blocks or duplicates. The
 * download worker re-arms its chunk alarm from it, so the alarm measures
 * "no block for N seconds" -- a stall -- rather than the whole chunk's
 * wall-clock, which at 40 blocks x ~1.5 MB was a hidden ~470 KB/s absolute
 * bar that dropped 429 peers (10.7 GB of half-received chunks) in seven
 * hours of the 2026-09-07 benchmark while the pool median was 764 KB/s. */
void ibd_pipeline_set_progress(void (*cb)(void*), void* arg);
/* bytes hook (2026-09-07): called with the length of EVERY block message
 * received, wanted or not -- the bytes were on the wire either way. The
 * download worker charges them to bmc.downloadratelimit. */
void ibd_pipeline_set_bytes(void (*cb)(long));
/* sink hook (2026-09-08): where each validated block goes. NULL (the
 * default) is store_append_shared, the archive in arrival order. The
 * download's in-order committer sets a sink that writes the chunk to a
 * staging file, so the archive is appended by ONE process in height order.
 * The sink sees (height, hash, raw, len) in ascending height order within the
 * chunk, exactly as the store did. Returns <0 to fail the chunk. */
typedef long (*ibd_sink_fn)(void* st, long height, const unsigned char hash[32], const unsigned char* raw, unsigned len);
void ibd_pipeline_set_sink(ibd_sink_fn sink);
#endif
