# 2026-09-10 — Eight download peers, the number Core uses

`bmc.catchupworkers` defaults to 8, matching Core's `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`. It was 64.

**64 was never measured.** It arrived in 43950d24, the commit that fixed `par` (Core's script-verification thread count had been wired to the download worker count). That commit argues Core's `par` arithmetic at length and says nothing about the new setting's default; 64 is `DLC_WORKERS_HARD_MAX`, the size of the worker arrays, adopted as a default. Before that fix the harness ran `par=8`, so the worker count *was* 8 — fixing the `par` bug is what moved us off Core's number, as a side effect nobody argued for.

**Core has no equivalent setting.** Its block-download concurrency is three hard constants: 8 outbound full-relay peers, `MAX_BLOCKS_IN_TRANSIT_PER_PEER` 16, `BLOCK_DOWNLOAD_WINDOW` 1024, all multiplexed by one `ThreadMessageHandler` thread. We expose a count only because `node_ibd_blocks_s` blocks for the length of a chunk and cannot multiplex, so concurrency here costs a process per peer.

**The measurements say 8 loses nothing.** This box's link is 2500 Mb/s and peer traffic sustains ~11 MB/s, about 88 Mbit, over the wired interface with nothing on the VPN and no local shaping — an external pipe, not a peer-supply limit. Against that ceiling the worker count barely registers:

| run | workers | sustained | 0:00:12 | 0:01:40 | 0:03:52 |
|---|---|---|---|---|---|
| 19 | 16 | 11.2 MB/s | 61,881 | 162,161 | 190,921 |
| 21 | 64 | 11.3 MB/s | 17,361 | 101,161 | 174,001 |

Four times the workers buys about one percent of throughput, and 16 led 64 at every early-chain mark. (Not a controlled A/B: different peer sets, different times, and run 21 also carries #177's peer ban. The direction is clear enough, and neither run supports 64.)

**It also makes the benchmark honest.** Core is pinned at 8 outbound full-relay by `net.h:1124` regardless of `maxconnections`, so the harness's `maxconnections=64` never gave Core more download peers. Every published comparison ran bmc with 16 to 64 downloading peers against Core's 8. At 8 the comparison is like for like.

The ceiling stays at 64 (`bmc.catchupworkers=1..64`) for an operator on a fatter link. Verified: `test_node_config` pins the default, watched to FAIL against 64.
