# Where this node still differs from Core — issues to resolve (2026-09-09)

An inventory taken after the 09-09 leg and compact-block work, ordered by measured payoff. Each row names what Core does, what this node does, the measured cost, and the fix. Rows move to "closed" with the PR that closes them. Consensus is not on this list: every consensus rule is proven against Core's vectors and the regtest differentials, and the two decided refusals (`assumeutxo`, testnet3) are documented in `FEATURE_GAPS.md`.

## Open

| # | area | Core | this node | cost measured | fix |
|---|---|---|---|---|---|
| 1 | block download at the tip | one request per block, tracked by hash, up to 16 in flight per peer, reassigned on a stall | every leg's pass requests the missing block itself | 8 requests per new block (09-09, 8 legs); 1,262 wasted compact round trips in a day | an in-flight table keyed by hash shared by the legs: claim before `getdata`, release on store or pass end, stale after 10 min |
| 2 | liveness | pings every 2 min, disconnects after 20 min of silence; the ping time feeds eviction protection | answers pings, never sends them; a dead peer is found when a pass fails | legs held for three failing passes; no ping time to offer full nodes | send a ping per leg every 120 s, track the pong, close `ours/ping-timeout` at 20 min |
| 3 | header sync | `sendheaders`: peers push new headers; `getheaders` only with cause | `getheaders` on every leg, every rotation | one request per peer per rotation, ~30 s of latency to a new block, silence detectable only by timeout | act on pushed `headers`/`inv` from the sweep; request only when behind |
| 4 | compact blocks | up to 3 high-bandwidth peers push a compact block with no round trip | low-bandwidth only | one round trip per block before reconstruction starts | `sendcmpct` hb=1 to the 3 best legs; accept unsolicited `cmpctblock` from them |
| 5 | leg service | one event loop over all peers | legs served one at a time, 60 s budget each | a slow pass delays every other leg; pongs answered within a pass, not at once | an event-driven leg loop (largest change, smallest measured gain now) |
| 6 | history indexes | txindex, coinstatsindex, blockfilterindex built and repaired in the daemon; `-reindex` rebuilds all | offline `bmc_build_*` tools; the daemon adopts within a gap; only the coinstats history self-heals | the filter index sat at 964,359 for a day; the address history needs an operator | the coinstats self-heal shape for the filter index and the address history |
| 7 | long reorgs | staged and connected as one unit | above 32 blocks: rewind and hand off to the downloader | a rotation without legs after a handoff | keep the legs through the handoff |

## Closed today

| # | what | PR |
|---|---|---|
| a | compact-block receive completed nothing: `blocktxn` matched as `block` | #145 |
| b | a bad reconstruction cost the block: Core's full-block fallback, `bmc.cmpctrecv` removed | #148 |
| c | every close named (`ours/<reason>` / `theirs`), failed dials remembered with backoff, the streak per peer, pongs within a pass | #143, #146, #149 |
| d | the version message: wall-clock timestamp, random nonce, our port, our tip | #144 |
| e | chain selection like Core's: handoff, header mirror, fork tree, leg gate; the announced-height rule (median) | #137, #139, #140 |
| f | no consensus caps where Core has none; BIP30 originals | #129, #131, #133 |
