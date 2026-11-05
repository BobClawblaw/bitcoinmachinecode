# 2026-10-07 — The descriptor outage, and the header leader

Four changes after the performance release. #402 is a production fix,
deployed the same evening. #403 is a test. #404 and #405 are plan items B12
and B13 from the run 41 report. Production runs `deploy-20261007a`
(main `54ffb790`: #400 + #402) as of 18:42:56Z. #403 to #405 are not
deployed. #403 is test-only, and #404 and #405 change only a node's own
initial download, which a synced node does not run.

## The reader lane closes at thread exit (#402)

Production's RPC and Esplora facade stopped accepting connections at
16:26:22Z and stayed down for 2 h 17 m. P2P sync went on throughout, so the
service looked healthy and the tip advanced, while mempool.space stalled 11
blocks behind.

The cause was the getblock reader lane from the 10-05 lanes batch (#383).
It gave each thread a private store handle (three descriptors) and an 8 MB
block buffer the first time that thread called `getblock`, and nothing
released them. That is a fixed cost for the RPC worker pool. The Esplora
facade, though, runs a thread per connection and calls `getblock` in process,
so every facade block read left three descriptors behind. At 1,023 of 1,024,
accept() failed with EMFILE.

A pthread key's destructor now closes the lane and frees its buffer when any
thread that used it exits. `tests/test_rpc_chain`: 64 threads each call
`getblock` once and exit, and the descriptor count must not move. Watched to
fail with the fix reverted: 14 → 206.

Deployed as `deploy-20261007a` and verified on new blocks 970,378 and 970,379
(hashes equal to the Core v31.1 oracle's), `NRestarts=0` at 10+ minutes, and
the descriptor count flat at 66–67 under facade traffic. The full account is
in `devlog/INCIDENT_2026-10-07_reader_lane_fd_leak.md`.

The verification procedure gained a fourth criterion: the descriptor count
stays flat across client traffic (OPERATIONS.md, *Upgrading and rollback*).
Rollback note: every snapshot from `deploy-20261005a` to `deploy-20261006d`
carries the leak, and nothing before `deploy-20261006d` is a safe target at
all (the B3 WAL format).

## The flush writer is adopted between blocks: the test (#403)

#400 made the async flush (B3) adopt its finished writer from the worker's
idle loop and from a catch-up pass with nothing to apply. Before that, at the
tip, the writer sat as a zombie for a whole block interval (22.5 minutes on
production at 01:16Z). #403 adds the test #400 shipped without.
`tests/test_utxo_reap_at_tip` freezes a seeded memtable without waiting,
watches the writer become a zombie, then checks that each of the two paths
reaps it, adopts the run, and finds the 64 coins it wrote. Watched to fail
with either path's poll removed. Three test-only accessors were added to
`utxo_live.c`.

## The header leader is switched when it slows (#404, plan B12)

The header probe (B5) ranks four candidates by their first page, and the
winner used to serve all ~970k headers. The B9 fix arm drew a peer that
answered its first page fast and then streamed at 0.5 MB/s, which took 165 s
for the phase against run 40's 33 s.

The fetch now keeps the rate of its last 4 pages. Once that falls under half
the next candidate's probed rate, the next candidate continues from where the
leader stopped. Nothing is downloaded twice: stored headers stay, and the
low-work hold (on mainnet, every page below about 880k is held in memory, not
stored) is carried into the next fetch. A next candidate that does not know the
held tail drops the hold and starts from the stored tip.

Guards:
- The switch only moves forward through the candidates, so there is no
  ping-pong.
- If no one after a slow leader finishes, the slow one is let finish.
- `bmc.dlshape=core` never switches.

Log line: `[dlc] headers from X fell to N KB/s over its last 4 page(s), under
half of Y's probed M KB/s -- switching at height H (+S stored, P page(s) held
and carried)`.

`tests/test_dlc_header_probe` has two new cases: a leader slowed after its
first page, and the same with the minimum-work floor armed. The fake peers
count the pages they serve. Watched to fail with the switch removed, with the
hold not carried (the runner-up served 8 pages, not 5) and with the stored
pages rolled back.

Not done: fetching disjoint ranges from two peers in parallel. Target for the
next benchmark: boot to block 1 within 50 s on every sync.

## A staller is banned on its second stall (#405, plan B13)

Run 41 banned 34 of 132 peers in 12 minutes. 26 of its 29 window-stall lines
were a newly drawn peer that had completed nothing: it took the tail chunk
(16 blocks, about 16 MB) and had not finished it within the 2 s stall timeout.
Core's rule is the same 2 s, and Core only disconnects such a peer.

The first stall of an address is now that disconnect. The chunk goes to an
idle worker at once, as before, and the address is remembered. The second
stall of the same address bans it for the run, which still catches run 20's
case of one address handed the same chunk 14 times. The manual-peer and
usable-floor guards are unchanged. Verdicts: `disconnected, a first stall
(banned on a second)` and `BANNED for the run (its second stall)`.

`tests/test_dialhelper` (stall section): a first stall is not banned, the same
address's second stall is, and the usable-floor guard is exercised on a second
stall. Watched to fail with the old rule (ban on the first stall) and with no
ban at all.

Not done: the grace half, which would give a newly drawn peer's first chunk
more time. Target for the next benchmark: 5 bans or fewer per run (run 41:
34) at the same download rate.

## Open, not in this release

- The next benchmark measures #404 and #405.
- B9 part 1: the ranking's top churns from run to run (69–81 distinct peers
  against run 38's 25).
- A4: a 149.5 s `getmininginfo` freeze after one restart into catch-up,
  not reproduced since.
- Memory is still the category Core keeps.
- The production unit's descriptor limit (1,024) is an open decision.
