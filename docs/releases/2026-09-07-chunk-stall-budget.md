# 2026-09-07 — The chunk budget is a stall clock, not a hidden ~470 KB/s bar

Run 9 of the fresh-sync benchmark, the first on the pipelined download,
was at height 622,000 after seven hours with 432 "dead weight" evictions in
its log. Three of them were the pool-relative dead-weight verdict landed in
PR #61. The other 429 were `DLC_CHUNK_BUDGET_SECS`, a flat 120-second
wall-clock budget for a whole 40-block chunk. Its comment stated the
consequence plainly: "requires ~467 KB/s sustained to survive". That is an
absolute rate threshold in disguise, the class rule 11 forbids, and it
rises with block size. A 424 KB/s peer that had served 1,560 blocks cannot
finish a 60 MB chunk in two minutes; it was dropped, and so were 428 others
whose measured rate was above the floor, while the pool median was 764 KB/s.
About 10.7 GB of half-received chunks went with them.

The fetcher now calls a progress hook once per wanted, validated block that
arrives, stored or parked, and the worker re-arms its alarm from it. The
alarm fires only when the peer delivers nothing for 120 seconds. Per block
that is about 12 KB/s for a 1.5 MB block, below the 32 KB/s absolute floor,
so the pool-relative rule decides who is slow and this constant only
catches a connection that has actually gone quiet. Core's per-block
download timeout is ten minutes; this remains stricter, as it was.

The signal handler records which signal fired. The log line reads
"stalled: no block for 120s" for the alarm and keeps "dead weight" for the
parent's early-kill, so a grep for either now counts one mechanism.

`test_ibd_pipeline` gains five checks: the hook fires exactly once per
block in forward and reverse delivery, not for pings or unasked blocks,
seven times for a peer that goes quiet after seven blocks, and is optional.
With the two hook calls removed, four of the five fail.

Run 9 continues on the previous build so its number is a clean measurement
of the pipelined download; this fix is measured on the next run.
