# Benchmark run 20 (2026-09-10): bmc fresh mainnet IBD on the night's batches

Launched 12:00:36Z from `/mnt/2tbssd/fresh_run.sh bench-2026-09-10` (tag at
commit 24d74ec5 = main through PR #174), the same harness and conf as run 19
(port 8462/rpcport 8461, dbcache 8192, `bmc.bootcatchup=0`, the daemon under
`nice 10 ionice -c3`, `monitor_fixed.sh` for the phase log and the muhash
check at the tip -- patched today to measure over HTTP with an hour's
timeout and to FAIL on an empty value instead of the empty-equals-empty
PASS run 19 printed).

What this run measures against run 19 (tag `picker-dead-mark-2026-09-09`):
dbcache sizing at boot (#153 -- the boot line now reads `sizing: BULK ...
slots=2^25 blob=6144MB`, where run 19 read `steady-state ... slots=2^16
blob=64MB`), merges under the apply (#154), the checkpoint cadence (#155),
coinstats per block (#156), Core's download shape (#157), tip latency and
the helper passes (#159-#174).

Marks to beat (elapsed from the epoch; run 19 and Core v31.1 on this box):

| height | run 19 | Core v31.1 |
|---|---|---|
| 634,561 | 6h52m | 6h55m |
| 800,000 | 12h05m | 12h06m |
| 900,000 | 16h03m | 18h27m |
| 950,000 | 17h55m | 20h21m |
| 965,703 | 18h38m | 21h10m |

Run 19's datadir is archived at `/mnt/10gbusb1/archive2/run19-20260909`
(976 GB, file-by-file match); `/mnt/10gbusb1/archive2` is the archive for
past runs from now on (a 10 TB platter drive, 6.7 TB free).
