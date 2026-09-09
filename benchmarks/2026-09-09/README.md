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
| 19c 13:19:44Z | `picker-dead-mark-2026-09-09` | running; 226k blocks in the first 10 min, 46% at 2h23m |

Logs of the stopped starts: `/mnt/2tbssd/bench-logs/run19a-20260909`,
`run19b-20260909`. Run 18's datadir and run 17's are archived under
`/mnt/10gbusb1/archive2`.
