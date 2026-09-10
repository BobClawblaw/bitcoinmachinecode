# Benchmark run 19 (2026-09-09): bmc fresh mainnet IBD vs Core v31.1

Scripts as run from `/mnt/2tbssd`: `fresh_run.sh <tag>` (clone at the tag,
build, `bitcoin.conf` = sample + port 8462/rpcport 8461/dbcache 8192/
`bmc.bootcatchup=0`/printtoconsole, launch detached, hand off) and
`monitor_fixed.sh` (phase log, progress every 5 min, TIP -> `gettxoutsetinfo
muhash` against the Core oracle, the inbound probe). Baseline to beat: Core
v31.1 21.0 h, bmc 24.1 h (2026-09-04).

| start | tag | outcome |
|---|---|---|
| 19a 11:47:25Z | `one-record-per-key-2026-09-09` | header phase refused every honest peer (two liars above the tip); stopped, PR #140 |
| 19b 12:56:20Z | `announced-median-2026-09-09` | stalled at block 560 (the picker's dead mark under a fresh sync's bar 0); stopped, PR #141 |
| 19c 13:19:44Z | `picker-dead-mark-2026-09-09` | running; 226k blocks in the first 10 min, 46% at 2h23m; 634,561 at 6h52m (Core 6h55m); 800,000 at 12h05m (Core 12h06m, run 16 13h24m) |

Marks so far (elapsed from the 19c epoch), against Core v31.1 on the same box
and the best earlier bmc run:

| height | run 19 | Core v31.1 | best earlier bmc |
|---|---|---|---|
| 634,561 | 6h52m | 6h55m | run 18 7h27m |
| 800,000 | 12h05m | 12h06m | run 16 13h24m |

Run 19 ran the whole way on the 64 MB steady-state memtable (PR #153 found
why) with 11.1 MB/s from 16 workers against 124 live peers; the download was
the bound from 700,000 on (apply lag 0 on most ticks). The batches of the
night of 09-09/10 (#153 dbcache sizing, #154 merges under the apply, #155
checkpoint cadence, #156 coinstats per block, #157 Core's download shape)
are measured by the next fresh run against these marks.

Logs of the stopped starts: `/mnt/2tbssd/bench-logs/run19a-20260909`,
`run19b-20260909`. Run 18's datadir and run 17's are archived under
`/mnt/10gbusb1/archive2`.
