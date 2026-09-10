# Where this node still differs from Core — issues to resolve (2026-09-09)

An inventory taken after the 09-09 leg and compact-block work, extended the same night with the initial-sync rows from the run 19 measurements, ordered by measured payoff. Each row names what Core does, what this node does, the measured cost, and the fix. Rows move to "closed" with the PR that closes them. Consensus is not on this list: every consensus rule is proven against Core's vectors and the regtest differentials, and the two decided refusals (`assumeutxo`, testnet3) are documented in `FEATURE_GAPS.md`.

## Open

| # | area | Core | this node | cost measured | fix |
|---|---|---|---|---|---|
| 1 | header sync | `sendheaders`: peers push new headers; `getheaders` only with cause | `getheaders` on every leg, every rotation | one request per peer per rotation, ~30 s of latency to a new block, silence detectable only by timeout | act on pushed `headers`/`inv` from the sweep; request only when behind |
| 2 | compact blocks | up to 3 high-bandwidth peers push a compact block with no round trip | low-bandwidth only | one round trip per block before reconstruction starts | `sendcmpct` hb=1 to the 3 best legs; accept unsolicited `cmpctblock` from them |
| 3 | leg service | one event loop over all peers | legs served one at a time, 60 s budget each | a slow pass delays every other leg; pongs answered within a pass, not at once | an event-driven leg loop (largest change, smallest measured gain now) |
| 4 | history indexes | txindex, coinstatsindex, blockfilterindex built and repaired in the daemon; `-reindex` rebuilds all | offline `bmc_build_*` tools; the daemon adopts within a gap; only the coinstats history self-heals | the filter index sat at 964,359 for a day; the address history needs an operator | the coinstats self-heal shape for the filter index and the address history |
| 5 | long reorgs | staged and connected as one unit | above 32 blocks: rewind and hand off to the downloader | a rotation without legs after a handoff | keep the legs through the handoff |
| 6 | live coin counter after a crash | the count is the cache's, exact after replay | under the bulk memtable, a kill mid-block recovers with the counter 2 high (`test_utxo_crash_recovery`'s steady-state scenario forced to bulk: 153 vs 151, every key identical); the set is right, the counter is not | cosmetic until `gettxoutsetinfo` is asked after a crash mid-sync; the coinstats seed walk corrects it | find the double count in bulk-mode recovery (the interleaved verifier's spend accounting is the suspect); pin with the scenario at 2^22 slots |

## Closed today

| # | what | PR |
|---|---|---|
| n | the parallel download takes Core's shape: every live peer downloads (cap 64), the window scales and anchors to the connected tip, the window's tail evicts stallers, replacement only when a free peer exists | #157 |
| m | the coinstats index folds per block during a bulk sync through the fold worker (the walk-at-caught-up deferral is gone; history rows from block 0) | #156 |
| l | bulk mode checkpoints every 1,024 blocks or 60 s, a bounded pass carries its batch and never downshifts the memtable | #155 |
| k | a background merge waits while the apply is behind and yields when it runs | #154 |
| j | a fresh sync uses the dbcache: an empty set takes the bulk memtable | #153 |
| i | a block another leg just stored ends the pass well; the fetch gate skips hashes the store holds | #152 |
| g | one request per block across the legs (`daemon/inflight.c`, the sync loop's fetch gate) | #150 |
| h | pings every 2 min per leg, 20-minute timeout, the round trip recorded | #150 |
| a | compact-block receive completed nothing: `blocktxn` matched as `block` | #145 |
| b | a bad reconstruction cost the block: Core's full-block fallback, `bmc.cmpctrecv` removed | #148 |
| c | every close named (`ours/<reason>` / `theirs`), failed dials remembered with backoff, the streak per peer, pongs within a pass | #143, #146, #149 |
| d | the version message: wall-clock timestamp, random nonce, our port, our tip | #144 |
| e | chain selection like Core's: handoff, header mirror, fork tree, leg gate; the announced-height rule (median) | #137, #139, #140 |
| f | no consensus caps where Core has none; BIP30 originals | #129, #131, #133 |
