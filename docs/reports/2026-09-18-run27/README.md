# Run 27 vs Core v31.1: same device, same protocol

Both configs are in this directory, copied at launch. The bmc file is the exact
`data/bitcoin.conf` the harness wrote. The Core file is the node's live conf.

## The baseline (finished)

**Core v31.1 synced once, continuously, from an empty datadir to the tip.**
It never re-synced and its data was never reset or reused. The 19 h 40 m 09 s
is one from-scratch IBD, measured from datadir creation to `Leaving
InitialBlockDownload`.

| | Core v31.1 (`9be056a8`) |
|---|---|
| datadir | `/mnt/nvme8tb/core-oracle` (Corsair MP600 PRO XT, ext4) |
| started | 2026-09-17 23:26:54Z on an empty datadir (`BENCH_START.txt`; `blk00000.dat` and `chainstate/` created 23:26:55) |
| left IBD | 2026-09-18 19:07:03Z (`Leaving InitialBlockDownload`) |
| **wall clock** | **19 h 40 m 09 s**, one continuous sync |
| protocol | dbcache=8192, txindex + coinstatsindex + blockfilterindex, maxconnections=48, public network, default logging, Nice=0 |

Footnotes, neither of which touches the data:

- **One 12-second process restart, same data.** At 06:12:19Z, around height
  620k, the process was stopped and started again to move it under the
  `bitcoin-oracle-nvme` systemd unit. It resumed from 620k on the same datadir.
  The cost was ~12 s of downtime plus rebuilding an in-memory coins cache (the
  stop flushed ~5 GB to disk). The figure includes that cost, so if anything
  it slightly favours bmc.
- **Early log lines are gone, not the data.** Core trims `debug.log` when it
  starts, so that restart kept only the last ~10 MB and the log now begins at
  05:08Z (height ~580k). The per-height timeline before that is recovered
  from the block files (below).
- **Not this run: an earlier, abandoned attempt.** A first attempt at 23:16Z
  ran with `debug=net` and `debug=validation` on, which slows a sync. It was
  stopped at ~152k after ten minutes and moved aside, untouched, to
  `core-oracle-ABORTED-logging-handicap-20260917-2326`. None of its data or
  time is in the baseline.

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

- 2026-09-18 ~19:15–20:10Z: a worktree agent built and gated PR #271
  (`make -j8 test` plus regtest differentials against Core v31.1).
- 2026-09-18 ~20:58–21:11Z: the full gate on merged `main` (`make -j8 test`).
- 2026-09-18 21:16Z: production bmc restarted onto `deploy-20260918a`. It
  rebooted in ~7 min, reloaded a 78k-transaction mempool and rejoined the network.

## Core's timeline, recovered from its block files

Core's `debug.log` lost everything before 05:08Z (height ~580k) when it
restarted. Its `blocks/rev*.dat` files still carry the timeline. Each one was
created when the first block in the matching `blk` file was connected, and
that block's height comes from the file's first header. v31.1 XOR-obfuscates
the files, so they are decoded with the 8-byte key in `blocks/xor.dat` before
hashing. Checked against the surviving `UpdateTip` lines at ten heights between
616k and 951k, the file time runs 0–143 s earlier than the log, and under 60 s
at nine of the ten.

| height | Core v31.1 elapsed | last 50k took |
|---|---|---|
| 400,000 | 1 h 40 m | |
| 450,000 | 2 h 39 m | 1.0 h |
| 500,000 | 3 h 50 m | 1.2 h |
| 550,000 | 4 h 54 m | 1.1 h |
| 600,000 | 6 h 14 m | 1.3 h |
| 650,000 | 7 h 36 m | 1.4 h (includes the 12 s process restart at 06:12Z) |
| 700,000 | 9 h 08 m | 1.5 h |
| 750,000 | 10 h 33 m | 1.4 h |
| 800,000 | 12 h 24 m | 1.9 h |
| 850,000 | 14 h 37 m | 2.2 h |
| 900,000 | 16 h 51 m | 2.2 h |
| 950,000 | 18 h 58 m | 2.1 h |
| 967,568 (IBD end) | 19 h 40 m | |

At 20:25Z, run 27 had applied 376,320 blocks in 1 h 10 m. Core took 1 h 17 m
to reach the same height, so bmc was 7.7 min ahead, and the lead had grown at
every 25k mark from 200k onward.

## A second Core v31.1 run (queued)

The baseline above is one continuous sync, but a 12 s process restart in the
middle of it is too easy to misread, so it will be rerun with no restart at all.
It is queued to start automatically when run 27 finishes. The two never share
the NVMe.

- **datadir:** `/mnt/nvme8tb/bench/core31`, empty; config in
  `core-v31.1-run2.bitcoin.conf`. The protocol is the same. Only the ports differ,
  the loopback binds are gone, and `shrinkdebugfile=0` keeps the whole log.
- **unit:** `bitcoin-core-bench.service`, under systemd from its first second.
  It is not enabled and has `Restart=no`, so a reboot or a crash ends the run
  visibly instead of resuming it quietly. It refuses to start on a non-empty
  datadir and writes `BENCH_START.txt` itself the instant before `bitcoind`
  starts.
- **trigger:** `bitcoin-core-bench.path` watches for run 27's `RESULT`. The
  harness writes that file after the capstone, which has already disabled run
  27's networking. The trigger fires once and switches itself off. A throwaway
  copy of the pair was tested: one start, and no second start when the service
  exited.

## Run 27 result (2026-09-19)

**PASS: the UTXO set is identical to Core's.** At height 967,712, bmc's muhash equals
the v31.1 node's: `09f5cd877189dc269f505f2066aa2a0b39eb0b8e3384a48449880affd6490ee7`.

| | bmc run 27 | Core v31.1 (first run) |
|---|---|---|
| download complete | 18 h 36 m 24 s (13:53:40Z, every block stored, ~485 still to apply) | |
| at the tip | **≤ 18 h 43 m 11 s** (13:58:40Z, from the harness's 5-minute RPC check) | **19 h 40 m 09 s** (`Leaving InitialBlockDownload`) |

bmc was about 57 min (~5%) faster. **Treat that as indicative, not clean.** Both runs
were perturbed:
- Blockyard polled Core for 17 h, and each `gettxoutsetinfo` forced a UTXO flush.
- Blockyard polled run 27 for 14 h (until 09:07Z). Its RPC side read 10.2 TB.
- Run 27 also maintained an unrequested 61.6 GB txo-spender tail, and its txindex
  was never folded (the harness did not build the helpers).
- Run 27's last hour overlapped a test gate (13:31–13:45Z) and a production
  restart (13:46Z).

The unpolled Core rerun below and run 28 (#275, #280, #281) are the clean pair.

## Core v31.1 rerun: started 14:28:33Z

- **Status:** running, unpolled, watched without RPC (`core31/watch.log`). Its config
  is `core-v31.1-run2.bitcoin.conf`, updated.
- **The first launch failed in its first second** (13:59:41Z). With no `bind=` line,
  Core also binds its onion listener on 127.0.0.1 at P2P port + 1 = 8339, and RPC
  had been put on 8339. RPC is now on 8340.
- **The failed datadir** (one second old) was moved aside, not deleted, as
  `core31-FAILED-onion-port-clash-20260919-1359`.
- **The rerun began 29 min after run 27 ended.** Run 27's node is still up with
  networking off: 3.4% of one core and no disk reads.
