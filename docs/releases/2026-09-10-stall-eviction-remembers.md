# 2026-09-10 — A stalling peer is remembered, not handed the same chunk again

Run 20, the first fresh benchmark carrying Core's download shape (#157), stored 18,561 blocks in twelve minutes and then stopped. Run 19 was at 226,000 by the same point.

- **The stall eviction was memoryless.** `dlc_stall_tick` evicted the worker holding the window's oldest missing chunk, incremented a counter, and recorded nothing about the peer. `dlc_pick_peer` was then free to hand the evicted address the very chunk it had just been dropped for, and did: one AWS listener took chunk `[18561,18600]` **fourteen times**, while the adaptive timeout backed off to its 64 s ceiling. Every attempt read `0.0B/s, completed 0 chunk(s)`. All 64 workers parked at a full window behind that one chunk.
- **The older dead-weight eviction has banned its peer for the run since 2026-09-06**, with the comment "without this the replacement draw is memoryless: a worker killed for trickling at 5KB/s could immediately be handed the same IP again". The stall rule now does the same, under the same two guards: a manual peer (`addnode`/`connect`) is never banned, and the pool is never drawn below `bmc.peerminusable`. The eviction line names the verdict.
- Also here: `config/bitcoin.sample.conf` documented `bmc.cmpctrecv`, which the daemon stopped accepting when #148 landed, so the file advertised a setting that did nothing. Removed.

Verified: `test_dialhelper`'s stall scenario gained the ban assertion, watched to FAIL with `banned[bidx] = 1` reverted, plus a floor case proving a staller at `bmc.peerminusable` is still dropped but stays selectable.
