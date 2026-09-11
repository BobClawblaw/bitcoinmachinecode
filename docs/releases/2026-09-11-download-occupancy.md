# 2026-09-11 — The download reports its occupancy

`bmcgetdownloadinfo` gains `pool_idle_pct` and a per-worker `idle_pct`; the `[dlc]`
tick line gains `pool idle N%` and each worker's row gains `idle=N%`.

**Why.** Run 22 was compared with Core v31.1 at equal peer counts, the first
like-for-like comparison (Core is pinned at 8 outbound full-relay peers by
`net.h:1124` regardless of `maxconnections`). The two are level to height 500,000
and bmc is then a steady 8-12% slower to 900,000. The apparent lead past 800,000
is one 261-minute Core segment, not a bmc win.

Finding the cause needed a number the node did not report. Measured from outside
the process instead, at 96% of the chain:

| | |
|---|---|
| aggregate receive | 10.1 MB/s, 99% of 6,157 samples inside 9-11 MB/s, for 19 hours |
| per-worker receive | 0.94 to 1.74 MB/s |
| worker blocked in the socket read | 11-20% of wall time |
| idle gaps in 30 s across 8 workers | 332, median 50 ms, p90 350 ms, none over 0.7 s |
| worker CPU | 0.2-0.6% each |
| applier CPU | 20% of one core; iowait 0 |
| link | 2500 Mb/s, no shaping |

Everything else was healthy: 8/8 workers on all 206 status samples, six chunk
failures in nineteen hours, no stalls, no gaps, apply lag zero. The gaps are not
ours. They are not the staging writes either, measured separately: 0% of samples
showed a read gap while the worker was writing. The workers are asleep waiting
for peer bytes.

**The line that hid it.** The status line said `8/8 worker(s) active`. That is
true, and useless: a worker holding a peer that cannot fill the pipe is active
and idle at the same time. Occupancy is now printed beside it.

**What this does NOT change.** No default moves. `bmc.catchupworkers` stays 8.
The register has twice been given an unmeasured number here — 64 arrived as the
size of the worker arrays, and 8 replaced it on two runs a day apart with
different peer sets that the note itself called "not a controlled A/B".
`validation/download_worker_sweep.sh` runs short randomised-order arms at 8, 16,
24 and 32 workers from the same fresh state and reads throughput together with
occupancy, which distinguishes the three cases that look identical in a single
run:

* idle low, throughput flat as workers rise — a shared ceiling, the wide-area link
* idle low, throughput rising — per-peer limited, so add peers
* idle high — the slots are held by peers that cannot fill the pipe, so peer
  selection is the lever and more peers will not help

Verified: `tests/test_ibd_pipeline` gains four checks, each watched to FAIL
against the unmeasured code. The first version of the failure-path check passed
either way, because the fixture's reads were instantaneous and both clocks read
zero; the stub now takes measurable time, which is what makes the check mean
anything.
