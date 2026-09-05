# BMC vs Bitcoin Core benchmark — durable test memory

## What this test is
Fresh-install IBD + serve benchmark, bmc vs Bitcoin Core, on a dedicated
1.8 TB SSD (/mnt/2tbssd, ext4, /dev/sdc3), host = 32-core Linux box at
192.168.5.242. Oracle: long-synced Core v31.99 at /storage/core-oracle
(muhash parity + tip height).

## Status checkpoint (2026-09-04 05:1x UTC)
- bmc (fix/dlc-peer-floor-depth @ 2b36678) downloading: 354k/965k (37%),
  9.1 MB/s, daemon pid in /mnt/2tbssd/bmc-bench/daemon.pid, started ~04:22.
- Core v31.1 queued: /mnt/2tbssd/core_after_bmc.sh launches
  run_core_bench.sh the moment bmc's RESULT file says PASS/FAIL.

## Headline finding (already fixed + pushed)
- 93fab72 (2026-09-02) AND-ed a block-rate exemption into the dl_catchup
  dead-peer byte floor -> fresh syncs crawl at 77KB/s (22/22 workers under
  floor, 0 evictions). Fixed with "Rule C": byte floor binds at every depth;
  stalled-block + marginal-byte peers also die; healthy peers (1.5MB/s/1blk
  near tip, 50 tiny blk/s early) stay. Live: 9.1 MB/s. ALL test_dialhelper
  corners pass. Pushed to github branch fix/dlc-peer-floor-depth (2b36678).

## Timings recorded so far
- install: bmc clone 8s + build 8s (0 warn); Core download 10s/87MB + sha256 + extract 1s
- bmc boot: P2P bind ~5s; dns 143 peers +1s; 416k headers in ~129s (fixed run)
- bmc dl on Rule C: 7.2 -> 9.1 MB/s as archive grows; ~23k blocks/min early
- disk baseline: 0.40 GiB/s seq write / 0.42 GiB/s cold read (4k IOPS test was
  cancelled mid-run by user interrupt; re-run if needed: /mnt/2tbssd/disk_baseline.py)

## Still to measure (the "serve" half)
- bmc: RPC up time, UTXO-served (gettxoutsetinfo live), P2P inbound probe
  (validation/p2p_inbound_probe.py against 127.0.0.1:8462 magic f9beb4d9),
  first inbound getheaders/getblock answer with UTXO, muhash parity vs oracle
  -> monitor_fixed.sh stamps phases + writes RESULT PASS/FAIL
- Core v31.1: run_core_bench.sh same contract (P2P 8563, RPC 8562, dbcache
  8192, par 8, maxconnections 64); phases: RPC_READY, P2P_INBOUND_OK, TIP,
  MUHASH parity; then compare block-for-block vs bmc

## Deliverable
Consolidated report in /mnt/2tbssd/bench-repo (private repo
BobClawblaw/bmc-benchmark-2026-09, pushed continuously via ticker +
tick_push.sh every 15 min; final report pushed when Core finishes).

## Ops notes
- NEVER run two node syncs simultaneously on this box (user decision).
- Peer pool: bmc selects naturally now (no peers.good seeding — user
  explicitly rejected the good-list approach).
- Watch for: bmc FATAL/HALTED/SEGV markers (auto FAIL), disk usage (1.7T
  free, archive will land ~1TB full-history; bmc datadir is blk archive +
  LSM UTXO, fits), oracle tip drift (chain tip 965427 at start).
- Stale watch-pattern replays from ab_test/ab_test2/floor_hunt/old monitors
  are noise: verify-then-ignore, do not restart anything on them.

## Restart/recovery
- bmc daemon died? bash /mnt/2tbssd/relaunch_rulec.sh, then
  bash /mnt/2tbssd/monitor_fixed.sh (background).
- tick pusher: bash /mnt/2tbssd/ticker.sh (background, silent).
- core queue: bash /mnt/2tbssd/core_after_bmc.sh (background, notifies).
- Full phase/monitor contract lives in the scripts themselves.
