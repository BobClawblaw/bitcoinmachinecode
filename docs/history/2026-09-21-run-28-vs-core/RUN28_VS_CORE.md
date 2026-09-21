# RUN 28: BITCOIN MACHINE CODE vs BITCOIN CORE v31.1

*A from-genesis mainnet sync, measured from the nodes' own logs, 2026-09-19 to 2026-09-21*

"The Measuring Equipment" (2026-09-19) left two numbers marked PENDING: an
unpolled rerun of Core v31.1 and run 28, a fresh bmc sync on the current code
with nothing calling its RPC. Both runs have finished. This post gives their
results, how they were measured, and what was not clean about them.

## The result

| | bmc, run 28 | Core v31.1, rerun |
|---|---|---|
| start | 2026-09-20 21:36:53Z | 2026-09-19 14:28:33Z |
| end of IBD, from its own log | 2026-09-21 16:00:55Z (`[dlc] catch-up done`) | 2026-09-20 10:01:27Z (`Leaving InitialBlockDownload`) |
| **elapsed to the end of IBD** | **18 h 24 m 02 s** | **19 h 32 m 54 s** |
| elapsed to the live tip | 18 h 25 m 28 s (height 967,924) | 19 h 33 m 09 s (height 967,813) |
| UTXO set | MuHash identical to Core at 968,025 | |

**bmc finished 1 h 08 m 52 s sooner, 5.9% of Core's time.**

The UTXO set check ran after the sync. The harness turned off bmc's networking,
waited for a stable height, and compared bmc's MuHash with a separate Core v31.1
node at the same height:

> `2026-09-21T17:45:46Z PASS muhash identical at 968025 (6e867a52c419fef00cec1768da7e8fbdf38a610c410cd4c4d01f02eef017fe2e)`
> *-- run28/phase.log*

## How it was measured

Both runs used the same machine and the same drive, one after the other:

- AMD Ryzen 9 9950X3D (16 cores, 32 threads), 123 GiB RAM
- Corsair MP600 PRO XT 8 TB NVMe for both datadirs
- the public mainnet peer-to-peer network, no local peers

Both nodes had the same settings:

| setting | bmc | Core |
|---|---|---|
| dbcache | 8192 | 8192 |
| txindex, blockfilterindex, coinstatsindex | on | on |
| maxconnections | 48 | 48 |
| peers downloading blocks at once | 8 | 8 (fixed in Core) |
| assumevalid | Core's default block, height 938,343 | default, same block |
| CPU niceness | 0 | 0 (systemd default) |
| build | commit `1562ae86` | v31.1 release, built from source |

**Nobody called either node's RPC during IBD.** This rule was added after
run 27, when a monitoring tool polled that run for 14 hours. Its polls made
bmc's RPC side read 10.2 TB from disk, and each `gettxoutsetinfo` sent to the
first Core baseline forced a UTXO cache flush. This time, all progress came
from each node's own log. The IBD-end times in the tables are timestamps
written by the nodes themselves, not the moment a monitor noticed.

## Time to height

The heights come from each node's own log: bmc's
`[utxo_live] catchup progress: height=N` and Core's `UpdateTip ... height=N`.
Elapsed time is counted from each run's start. The segment columns give the
time each node took for that stretch of 100,000 blocks.

| height | bmc elapsed | Core elapsed | bmc ahead by | % | bmc segment | Core segment |
|---:|---:|---:|---:|---:|---:|---:|
| 100,000 | 0:02:58 | 0:06:01 | 0:03:03 | 50.7% | 0:02:58 | 0:06:01 |
| 200,000 | 0:08:52 | 0:11:25 | 0:02:33 | 22.3% | 0:05:54 | 0:05:24 |
| 300,000 | 0:30:49 | 0:36:14 | 0:05:25 | 14.9% | 0:21:57 | 0:24:49 |
| 400,000 | 1:31:36 | 1:43:35 | 0:11:59 | 11.6% | 1:00:47 | 1:07:21 |
| 500,000 | 3:36:20 | 3:54:13 | 0:17:53 | 7.6% | 2:04:44 | 2:10:38 |
| 600,000 | 5:54:41 | 6:20:15 | 0:25:34 | 6.7% | 2:18:21 | 2:26:02 |
| 700,000 | 8:44:09 | 9:19:15 | 0:35:06 | 6.3% | 2:49:28 | 2:59:00 |
| 800,000 | 11:56:48 | 12:39:54 | 0:43:06 | 5.7% | 3:12:39 | 3:20:39 |
| 900,000 | 15:53:25 | 16:50:44 | 0:57:19 | 5.7% | 3:56:37 | 4:10:50 |
| end of IBD | 18:24:02 | 19:32:54 | 1:08:52 | 5.9% | 2:30:37 | 2:42:10 |

Four things stand out in this table:

- The large early percentages are only minutes. At 100,000 blocks bmc is 51%
  ahead, but that is three minutes. The early blocks are small.
- bmc was slower in one segment. It took 5 m 54 s for blocks 100,000 to
  200,000, where Core took 5 m 24 s.
- From 500,000 on, bmc was 4% to 7% faster in every segment, and its total
  lead settled at about 6% of elapsed time.
- Both nodes spent about two-thirds of their run above height 600,000:
  12 h 29 m for bmc, 13 h 13 m for Core.

## What was not clean

- **The runs were not simultaneous.** Core ran on 09-19 and 09-20, and bmc on
  09-20 and 09-21. They used different peers under different network
  conditions. Running both at once on one drive would have measured contention
  for that drive, not the two implementations.
- **Each side ran once.** Nobody has measured the run-to-run spread yet.
- **Run 28's RPC was hit once.** This line is in phase.log:
  `2026-09-21T05:07:06Z WARN 15 connection(s) to the RPC port closed in the last minute during IBD -- something is polling the run`.
  The caller was never identified. The check only sees sockets that have
  already closed, so it cannot name a process. A 30-minute watch later in the
  day saw no further connections. This was one minute of unknown calls, not
  14 hours of UTXO walks as in run 27, but it is on the record.
- **Core's rerun was disturbed once.** Production was redeployed at 18:54:57Z
  on a different NVMe drive. Core's block rate dropped for about one minute.
  The estimated cost is 30 to 40 seconds.
- **The two nodes mark the end of IBD differently.** bmc logs `catch-up done`
  when it has stored and connected every block up to the best header it saw
  at startup (967,898). Core logs `Leaving InitialBlockDownload` when its tip
  is less than 24 hours old. The table also gives the time each node reached
  the live tip: 86 seconds later for bmc, 15 seconds later for Core. The gap
  between them is 1 h 07 m 41 s by that measure, against 1 h 08 m 52 s by the
  logged end of IBD.
- **The benchmark harness had a defect.** Once bmc logged `catch-up done`,
  it stopped writing the progress lines the harness was reading. The harness
  therefore never saw the run finish, and it warned that the heartbeat had
  stopped moving. The monitor script was restarted with a fix. The node was
  not restarted, and it kept following the live chain in the meantime. The
  UTXO check ran at 17:45Z, 1 h 45 m after the end of IBD. The end time
  itself comes from the node's own log line, so the defect did not change it.
  The fix is PR #289, with tests built from run 28's own log lines.

## Against the first pair

| | bmc | Core v31.1 |
|---|---|---|
| first pair, both polled by a monitor | run 27: 18 h 40 m 23 s | 19 h 40 m 09 s |
| this pair, neither polled during IBD | run 28: 18 h 24 m 02 s | 19 h 32 m 54 s |

The first pair gave about 5% and this pair gives about 6%. The two bmc runs
used different code: run 27 was on 09-18 and run 28 on 09-20. Run 27's time
was taken from its own "at the tip" line. On the same measure, run 28 took
18 h 25 m 28 s.

## What this does and does not show

This pair shows that on this machine, with Core's settings, bmc synced mainnet
from genesis about 6% faster than Core v31.1. It also shows that bmc ended
with a UTXO set identical to Core's. This is the tenth full comparison of a
bmc UTXO set with Core's, and every one that actually ran has matched.

It does not show that bmc is faster in general, on other hardware, or by
design. There is one run per side, on one machine. This post does not say
where the difference comes from. The micro-benchmarks from August, which
have not changed since, put bmc's hashing and signature primitives at or
behind Core's.

## Sources

- `run28/phase.log`: start, configuration, the RPC warning, IBD_END, the capstone
- `run28/data/main/debug.log`: the per-height `catchup progress` lines, and
  `[dlc] catch-up done` at 16:00:55.219
- `core31/debug.log`: `UpdateTip` lines, and `Leaving InitialBlockDownload` at
  10:01:27Z
- `core31/watch.log`: the rerun's start, its IBD_END (70,374 s), and the
  record that nothing called its RPC
- `docs/reports/2026-09-18-run27/README.md`: run 27 and the first Core baseline
- PR #289: the harness fix
