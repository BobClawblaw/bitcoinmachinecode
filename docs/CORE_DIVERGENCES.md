# Where this node still differs from Core — issues to resolve (2026-09-09)

An inventory taken after the 09-09 leg and compact-block work, extended the same night with the initial-sync rows from the run 19 measurements, ordered by measured payoff. Each row names what Core does, what this node does, the measured cost, and the fix. Rows move to "closed" with the PR that closes them. Consensus is not on this list: every consensus rule is proven against Core's vectors and the regtest differentials, and the two decided refusals (`assumeutxo`, testnet3) are documented in `FEATURE_GAPS.md`.

## Open

| # | area | Core | this node | cost measured | fix |
|---|---|---|---|---|---|
| 1 | leg service | one event loop over all peers, never blocked by a connect | legs served one at a time, 60 s budget each; since #161 no dial blocks the loop and passes run only on announcements | a slow pass still delays the other legs; the 27 s block on snapshot t (an inline top-up) is fixed | an event-driven leg loop for what remains |
| 2 | mempool overlap with the network | a peer's mempool holds nearly every transaction a new block carries (blocktxn a few KB); every peer relays transactions to it, inbound included | production holds 4,000-9,000 entries; the first measured blocks on snapshot x (2026-09-10 04:53Z): 966,304 had 40% of its 2,093 transactions in the mempool and fetched 690 KB, 966,305 had 65% of 1,398 and fetched 460 KB; of the fetched, 98% and 87% were NEVER ANNOUNCED to us, the rest orphans (28, 16), announced-not-requested (0, 43), policy rejects (0, 3), unanswered requests (2, 0) | the miss is coverage, not policy: three to eight full-relay legs and inbound relay at 50% see a fraction of the network's transactions; a 460 KB blocktxn is still seven round trips under slow start | the announced-not-requested class is closed (#168: the request queue drains like Core's tracker); what remains is coverage -- inbound peers (the router forward on 8333, inboundrelaypercent=100 already set), then remeasure the never-announced share |

## Closed today

| # | what | PR |
|---|---|---|
| w | the transaction request queue drains as Core's does (announced-not-requested closed) | #168 |
| v | a BIP324 session travels with its socket across the dial helper's fork (export/import); helper-dialed legs are v2 again where advertised | #167 |
| u | helper-dialed legs speak v1 (the v2 state stays in the child); the worker creates the dial memory (it was null on production since 09-09: "0 min" backoffs) | #163 |
| t | the block filter index and the address history repair themselves in the daemon (the coinstats supervisor as a module, one instance per index) | #162 |
| s | the live coin counter after a crash under the bulk memtable: the ghost rollback restores only what is gone (a lookup before the put) | #162 |
| r | the legs stay served through a reorg handoff (the sweep runs inside the parallel download); helpers bounded by the span | #162 |
| q | every outbound dial runs in a helper (re-dials fill their slot when they land, the top-up dials one at a time); the per-block mempool-overlap line and the missing-transaction classifier (row 5's measurement) | #161 |
| p | high-bandwidth compact blocks from the three most recent block sources, pushed blocks stored from the sweep, the apply right after a store | #159 |
| o | sendheaders after the handshake; announcements (inv, pushed headers) drive a leg's pass; no polling for headers between announcements (30 s safety net) | #159 |
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
