# Deployment Guide

> ## ⚠️ No sane or rational human should ever run this software.
>
> That is not a liability disclaimer; it is the project's own considered
> deployment advice. This is a Bitcoin node whose every line of assembly was
> written by an AI, audited by no independent human, exposed to an adversarial
> peer-to-peer network, and developed at a pace that found **four production
> incidents in the last two days alone** (`LOG.md` #43–#46 — each root-caused
> and fixed, which is the good news; each *existing in production first*, which
> is the honest news). It has diverged from Bitcoin Core's consensus in the
> false-ACCEPT direction before, in ways no chain replay could detect
> (`README.md`, the SETcc incident). It can wedge, corrupt its own metadata,
> or follow the wrong chain, and its recovery paths — good as they have proven
> to be — exist because all of those things have actually happened.
>
> Run it only if you are studying it, on a machine you can afford to lose,
> with no funds anywhere near it. If you want a Bitcoin node, run
> [Bitcoin Core](https://bitcoincore.org).

Everything below assumes you have read the warning and are proceeding as a
researcher, not an operator.

## What you are deploying

One binary, `asm/daemon/bitcoind`, running as a fork-model daemon:

- a **parent** that accepts inbound peers (forking one serve child per
  connection) and runs the embedded JSON-RPC server on its own thread;
- a forked **download worker** that owns the outbound peer legs, block
  download/keep-up, UTXO application, and the reorg machinery;
- shared state bridged across the fork boundary by `MAP_SHARED` regions
  allocated before it: the live-status/RPC-submission block, and (since
  2026-08-25) the mempool and its fee-policy registry, mutated under a
  `PTHREAD_PROCESS_SHARED` lock.

Everything lives in one datadir: the block archive (`blk*.dat` + positional
`index.dat`), `headers.dat`, `chainwork.dat`, the LSM UTXO store
(`utxo.dat` WAL, `utxo_run_*.dat`, `utxo_manifest.dat`,
`utxo_applied_height.dat`), `peers.dat`, and optionally a wallet store
(`bmcwallet.dat` + `.txlog` journal).

## Prerequisites

- Linux x86-64 (the assembly is NASM ELF64, System V ABI; nothing else runs).
- `nasm`, `gcc`, `make`, `python3` (build + test harnesses).
- ~1 TB of disk for a full archive + UTXO store, and several GB of RAM
  (the bulk-mode memtable alone is multi-GB during initial sync).
- For any verification work: a synced Bitcoin Core node you trust, reachable
  over RPC. The project calls this "the oracle" and treats every claim as
  unproven until diffed against it. You should too.

## Build

```sh
cd asm
make daemon/bitcoind        # the daemon
make prereq-check           # Makefile hygiene gate
make test                   # the full suite; REAL_EXIT must be 0
```

The full suite is the deployment gate. This project has shipped a red gate to
its main branch exactly once, by chaining git commands after a log `tail`;
the rule since: **read the gate result in one step, act in a separate step**
(`ENGINEERING_RULES.md`).

## Configure

A minimal `config/bitcoin.conf` (path given to the daemon at start):

```ini
# P2P
listen=1                 # accept inbound peers (fork-per-connection)
# port defaults to 8332 in this project's config; see node_config.c

# RPC (HTTP Basic; no cookie support)
rpcport=8331
rpcuser=CHOOSE_A_USER
rpcpassword=CHOOSE_A_LONG_RANDOM_PASSWORD

# Mempool (0 = built-in 2 MiB static; >0 mmaps a shared, locked pool)
maxmempool=300
mempoolexpiry=336
```

Notes:

- The RPC server binds `127.0.0.1` only. Do not "fix" that.
- With `maxmempool` set, the mempool is one shared pool across the worker,
  every inbound child, and the parent's RPC — `getrawmempool` on the parent
  reports what the children accepted. With it unset, each process has a
  private 2 MiB pool and the mempool RPCs honestly report an empty one.
- If `bmcwallet.dat` exists in the datadir, the RPC layer loads it at start
  (passphrase from `BMC_WALLET_PASS` or `<store>.pass`) and the wallet
  methods go live. Absent store: wallet methods report unconfigured.

## Run

Directly:

```sh
asm/daemon/bitcoind serve /path/to/datadir
```

Or as the systemd unit this project actually uses:

```ini
[Unit]
Description=Bitcoin Machine Code Daemon (experimental AI-authored asm node)
After=network-online.target

[Service]
WorkingDirectory=/path/to/repo/asm
ExecStart=/path/to/repo/asm/daemon/bitcoind serve /path/to/datadir
Restart=on-failure
# Give shutdown time: a flush or compaction can legitimately run long, and a
# SIGKILL mid-write is exactly how incidents #45 (counter drift) and the
# original resume-REJECT class were born. The daemon honours SIGTERM.
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
```

First start on an empty datadir bootstraps everything itself: DNS-seed peer
discovery, headers-first sync, chunked parallel block download, then a
from-genesis UTXO build with full script verification. Expect **days**, and
expect it to be CPU-bound on signature verification for most of them. The
`[dl] heartbeat:` log line is the pulse: tip height, live peers, live UTXO
count, uptime.

## Operating it

- **Upgrade** = `git pull && make daemon/bitcoind && make test` (gate green,
  read properly) `&& systemctl restart bmc-bitcoind`. The binary is executed
  from the repo checkout; a restart is the deploy.
- **Keep a rollback binary.** `cp asm/daemon/bitcoind asm/daemon/bitcoind.prev-$(date +%Y%m%d)`
  before building. This project has needed it.
- **Watch the log, not just the exit code.** The strings worth alerting on:
  `REJECT`, `FATAL`, `DEGRADED`, `ghost-rollback FAILED`, `INCONSISTENT`.
  A `rolled back ghost application` line is *healthy* crash recovery; a
  `ghost-rollback FAILED` line is not.
- **`gettxoutsetinfo` / `scantxoutset` refuse while the set is being
  written.** That is correct behavior, not an error: a set hash over a moving
  datadir is meaningless. Call again in the quiet window between blocks, or
  stop the daemon for an authoritative measurement (that is how the parity
  capstone was run).
- **The standalone verifiers are the instruments of record.**
  `daemon/utxo_setinfo <datadir> --muhash` against a quiesced datadir, diffed
  against your Core oracle's `gettxoutsetinfo muhash <height>`, is the
  strongest statement this software can make about itself. Run it after
  anything eventful.
- **Never point tools at a datadir a daemon is writing** unless the tool has
  the fingerprint/quiescence discipline (`utxo_setinfo` and the RPC readers
  do; ad-hoc scripts do not).
- **If catch-up wedges on a REJECT at tip+1**: check whether the store tip
  block's prev-hash actually links (incident #46). The linkage gate now
  prevents the known cause, but the remedy pattern is documented in `LOG.md`:
  stop, drop exactly the offending index record
  (`store_truncate_index_only` — the non-monotonic-safe primitive; plain
  `store_truncate_to` will refuse on this archive's layout, by design),
  restart.

## What "working" looks like

A healthy steady-state node: heartbeat tip tracking the network within a
block, `peers=8/8`, UTXO applied height equal to the tip, live count within
sight of Core's `txouts` (~165.7M at height ~964k), and an RPC surface that
answers `getblockchaininfo`, `getblocktemplate '{"rules":["segwit"]}'`,
`getmempoolinfo`, and — given patience or a stopped daemon —
`gettxoutsetinfo muhash` with numbers you can diff against Core yourself.

Do that diff. This project's entire epistemology is that a claim without an
oracle comparison is a hope, and that applies to your deployment of it too.
