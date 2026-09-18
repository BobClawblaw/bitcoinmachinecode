# Run 27 vs Core v31.1: same device, same protocol

Both configs are in this directory, copied at launch. The bmc file is the exact
`data/bitcoin.conf` the harness wrote. The Core file is the node's live conf.

## The baseline (finished)

| | Core v31.1 (`9be056a8`) |
|---|---|
| datadir | `/mnt/nvme8tb/core-oracle` (Corsair MP600 PRO XT, ext4) |
| started | 2026-09-17 23:26:54Z (`BENCH_START.txt`, fresh datadir) |
| left IBD | 2026-09-18 19:07:03Z (`Leaving InitialBlockDownload`) |
| **wall clock** | **19 h 40 m 09 s** |
| protocol | dbcache=8192, txindex + coinstatsindex + blockfilterindex, maxconnections=48, public network, default logging, Nice=0 |

Two caveats that belong with the figure:

- **One restart.** At 06:12:19Z, around height 620k, the node was stopped and
  restarted within 12 s to move it under the `bitcoin-oracle-nvme` systemd unit.
  The stop flushed a ~5 GB coins cache and the node resumed with it cold. The
  figure includes that cost, so it slightly favours bmc.
- **Early segment timings are gone.** Core shrinks `debug.log` on startup, so the
  restart kept only the last ~10 MB. The log now begins at 05:08Z (height ~580k).
  Per-segment comparison is possible only from there.

## Run 27 (running)

| | bmc |
|---|---|
| build | `ad77e46e` (main), `bmc_build_dirty=false`, verified over RPC |
| datadir | `/mnt/nvme8tb/bench/run27/data`, same device as the baseline |
| launched | 2026-09-18 19:15:37Z (epoch 1789758929) |
| harness | `validation/fresh_ibd_run.sh`, DEST=/mnt/nvme8tb/bench/run27, NICE=0, WORKERS=8 |
| protocol | dbcache=8192, bmc.bootcatchup=0, 8 download workers, txindex + coinstatsindex + blockfilterindex, maxconnections=48, public network |
| capstone oracle | the baseline node above (RPC 8337): the muhash at bmc's quiesced height, O(1) through its coinstatsindex |

Progress is written every 5 min to `/mnt/nvme8tb/bench/run27/progress.log`, and
phases to `phase.log`. `RESULT` holds the capstone verdict.

Other load on the box during run 27 matches the baseline's: production bmc, the
v31.99 oracle, run 26 at the tip (`~/bmc-run26`, a different device),
and blockyard. Exceptions, noted as they happen:

- 2026-09-18 ~19:15Z: a test gate (`make -j8 test`) for an RPC batch was running
  in a worktree.
