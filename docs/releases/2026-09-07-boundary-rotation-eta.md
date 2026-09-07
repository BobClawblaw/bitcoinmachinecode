# 2026-09-07 — A slow peer is rotated at the chunk boundary; the status line shows an ETA

## The gap the stall clock left

This morning's PR #68 turned the flat 120-second chunk budget into a
stall clock, so a peer that keeps delivering is no longer dropped
mid-chunk. That removed the waste (902 kills and about 22 GB re-downloaded
in run 9, and a fifth of all worker slot-time spent at zero in the
reconnect cycle) but it also removed the only thing that had been
removing a delivering-but-slow peer. A worker keeps its peer after a clean
chunk, and the dead-weight floor is the smaller of 32 KB/s and a quarter
of the pool median, which at the tail is 32 KB/s. A 250 KB/s peer against
an 800 KB/s median would have held its slot for the rest of a run, and
slots would have drifted toward the slow end of the pool as fast peers
disconnected and slow ones never left.

## The rule

The verdict is taken when nothing is in flight. After a clean chunk, a
worker measures its own rate over that chunk (its /proc io bytes over
wall time). If that is under half the pool median, it closes the socket
and takes a fresh peer, the fastest unclaimed one. Nothing is discarded.
The parent publishes the median into every worker's shared stats slot on
each tick. Chunks shorter than two seconds, the early chain, are not
judged: they are round-trip bound and the rate would be noise. The log
line prints the chunk rate, the median, and the bar, and says "nothing
discarded". The bar is relative at every depth, per rule 11.

## ETA

The status line now reads `elapsed H:MM:SS | eta DD:HH:MM:SS`. The ETA is
the remaining block count at the block rate of the last ten minutes.
Blocks grow toward the tip, so on the tail it is optimistic, and it is
`--:--:--:--` until a rate exists.

## Verification

`test_dialhelper` gains twelve checks: the verdict at both ends of the
chain, the no-median and too-short cases, the formatter at zero, one
second short of a day, a day and an hour and a minute and a second, and
no-rate, plus the arithmetic on run 9's own numbers. With the verdict
stubbed to "keep", two fail. A scratch node on the real network shows the
ETA on its first status line and rotation lines with numbers once chunks
are long enough to judge.

## What the live proof found, and the two fixes it forced

A scratch node on the real network, sharing the box with benchmark run 9,
was the first to run the rule.

**The picker gave the dropped peer straight back.** 269 rotations in five
minutes among the same 16 addresses, each rotated about 18 times, and the
mean slot rate never moved. `dlc_pick_peer` ranked peers by their measured
EMA and every never-tried peer has none, so a known-slow peer outranked
all of them. The picker now takes the rotation bar: the fastest measured
peer at or above the bar; else someone never tried; else the best known
even below the bar, so a worker is never left without a peer; else the
plain rotation. Five checks pin it, and one was watched to fail with the
bar ignored. After the fix the same scratch node held 28 distinct peers
of 153 in six minutes and its mean slot rate went from a flat 5.6 KB/s to
16 to 22 KB/s on the same stretch of chain.

**The tick-EMA lags the verdict.** One peer whose EMA still read above the
bar was re-picked 17 times. A rotating worker now writes its measured
chunk rate into that peer's EMA slot, so the picker sees the number the
verdict was taken on.

**The header phase was silent for 71 MB.** An honest mainnet chain sits
below the minimum-chainwork floor for its first ~880,000 headers, and the
fetch printed one line at the first held page and nothing until the
release. On the starved scratch link that was 35 minutes at 125 KB/s, and
it was mistaken for a hang until the socket counters showed it moving.
Every 50 held pages the loop now reports pages, headers, megabytes,
seconds and rate.

## Open, found on the way

On boot the node trims `headers.dat` back to the archive tip ("ran N
records past the archive tip -- trimmed"), so a restart in the middle of a
sync refetches every header above the archive: 71 MB and the whole held
region again. Headers ahead of blocks is the normal headers-first state.
Not changed here; recorded for its own fix.
