# 2026-09-07 — The download is monotonic, like Core's

## What run 10 did

Run 10 was the first fresh sync on boundary rotation. Eleven minutes in it
had abandoned 21,676 chunks, its connect was stuck at height 45,160, and
its hole count was above the in-flight bound. Three defects, one exposing
the other two:

1. **A per-worker counter that was never reset.** "stalled" counts
   consecutive rounds in which a worker found no peer to connect. It lived
   at worker scope, and "stalled > 40 -> peers exhausted" broke out of the
   chunk before the three-second sleep. Once a worker reached 40, every
   chunk it claimed afterwards was abandoned instantly: 21,669 of the
   21,676 abandons carry that line.
2. **The picker offered dead peers as untried, forever.** This morning's
   bar prefers never-tried peers over known-slow ones. A peer that failed
   to connect, failed the handshake, or lacked NODE_WITNESS kept a rate of
   zero and so counted as never tried. A rotating worker could spend all
   112 picks on such peers, forty rounds over, and reach defect 1. The
   worker now marks such a peer 1.0, tried and worthless, which the picker
   ranks below any measured peer and never as untried.
3. **Nothing revisited an abandoned chunk, and the claim counter only went
   up.** Workers ran ahead and left holes behind, the opposite of Core,
   whose download window of 1,024 blocks above the last connected block is
   never requested past.

## The rule now

"Write out monotonically, like Core does." The control block the workers
share carries the claim counter, a 4,096-entry retry ring, and the first
hole, which the parent publishes on every tick. A worker:

- pops the retry ring before claiming anything new;
- does not claim a chunk more than 1,024 blocks above the first hole. It
  waits, re-checking the ring each second, and after 120 seconds fetches
  the blocking chunk itself. That is a duplicate fetch whose appends are
  idempotent (`test_shared_stress`), so a worker that died cannot deadlock
  the window;
- pushes any chunk it abandons onto the ring and says so in the log.

The chunk fetcher also returns one of nine reason codes instead of a bare
-1, and the worker logs peer, chunk, attempt, elapsed time and the reason
for the first three failed attempts and every hundredth after. Run 10's
worker 9 failed 400 attempts in 45 seconds with no line between the
rotation before it and "reconnect budget"; that cannot happen again.

## Verification

`test_dialhelper` gains thirteen checks: the dead mark in the picker; the
window at exactly 1,024, at 1,025, and for a retry below the hole; the
ring empty, in order with chunk 0, full and refusing, draining from the
oldest. Watched to fail with the window stubbed to always allow.
`test_ibd_pipeline` asserts the reason codes on its three failure cases.

Run 10's logs are kept in `/mnt/2tbssd/run10-cascade`.
