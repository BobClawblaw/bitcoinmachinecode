# Deployment Guide

> ## ⚠️ No sane or rational human should ever run this software.
>
> That is not a liability disclaimer; it is the project's own considered
> deployment advice. This is a Bitcoin node whose every line of assembly was
> written by an AI, audited by no independent human, exposed to an adversarial
> peer-to-peer network, and developed at a pace that has found **fifty-odd
> production/consensus incidents** so far (`LOG.md` #1–#50+, plus the
> 2026-08-27 mempool freeze at exactly 4096 — each root-caused and fixed,
> which is the good news; each *existing in production first*, which is the
> honest news). It has diverged from Bitcoin Core's consensus in the
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
# Chain (default main). "regtest" runs Core's regtest chain in a
# subdirectory of the datadir — see "Regtest" below.
chain=main

# P2P
listen=1                 # accept inbound peers (fork-per-connection)
port=8332                # P2P listen/dial port; chain default if omitted
                         # (8333 main, 18444 regtest — see node_config.c)

# RPC (HTTP Basic; no cookie support)
rpcport=8331             # MUST NOT collide with the P2P port (was 8332;
                         # fixed 2026-08-26, commit 6469c2f)
rpcuser=CHOOSE_A_USER
rpcpassword=CHOOSE_A_LONG_RANDOM_PASSWORD

# Mempool (0 = built-in 2 MiB static; >0 mmaps a shared, locked pool)
maxmempool=300
mempoolexpiry=336

# Mempool policy (Core-exposed, defaults == Core's). Since 2026-08-27 the
# pool is byte-budgeted with feerate eviction (TrimToSize) and a dynamic
# mempoolminfee, not "reject when full".
minrelaytxfee=0.00001
incrementalrelayfee=0.00001
limitancestorcount=25
limitancestorsize=101
limitdescendantcount=25
limitdescendantsize=101
mempoolfullrbf=1
```

Notes:

- The RPC server binds `127.0.0.1` only. Do not "fix" that.
- With `maxmempool` set, the mempool is one shared pool across the worker,
  every inbound child, and the parent's RPC — `getrawmempool` on the parent
  reports what the children accepted. With it unset, each process has a
  private 2 MiB pool and the mempool RPCs honestly report an empty one.
- The `[config] mpol` line at boot echoes the resolved policy values; the
  `[config]` block echoes everything else — check it after any config change.
- If `bmcwallet.dat` exists in the datadir, the RPC layer loads it at start
  (passphrase from `BMC_WALLET_PASS` or `<store>.pass`) and the wallet
  methods go live. Absent store: wallet methods report unconfigured. If an
  encrypted store (`bmcwallet.enc`) is present it is adopted **locked** —
  `walletpassphrase` unlocks it for a chosen number of seconds (see
  "Wallet encryption" below).

### Where logs go

Since 2026-08-27 the asm logger writes under the datadir's own `logs/`
subdirectory, and the filename is chain-tagged so an aggregated view can
never confuse chains:

- mainnet → `<datadir>/logs/bitcoind.log`
- regtest → `<datadir>/regtest/logs/bitcoind.regtest.log`

The production node picks up the new path on its next deploy (the one
carrying commit `7acf207` or later). Point your log tail / alerting there.

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

- **Deploy sequence.** The systemd unit executes `asm/daemon/bitcoind` from
  the repo checkout directly, so a deploy is a rebuild + restart — but do it
  in this exact order, which is also how it snapshots a rollback binary:

  ```sh
  cd asm
  git pull
  make daemon/bitcoind          # ld unlinks+recreates the file, so this is
                                # safe while the OLD binary is still running
                                # (the live process keeps the old inode)
  make test                     # gate; read the result in a SEPARATE step
  sudo systemctl stop  bmc-bitcoind
  cp daemon/bitcoind daemon/bitcoind.deploy-$(date +%Y%m%d)<letter>   # snapshot
  sudo systemctl start bmc-bitcoind
  systemctl is-active bmc-bitcoind
  ```

  The snapshot names march a letter per deploy on a given day
  (`…-20260827o`, `p`, `q`, …), doubling after `z` (`aa`, `ab`, …). As of
  2026-08-28 the live binary is **`bitcoind.deploy-20260828ae`**; the
  rollback one step back is `…-20260827ad`.

  These snapshots are NOT in git (they are ~31 MB build products, and a
  `git add -A` once swept twenty of them plus a scratch datadir into a
  commit — see `.gitignore`). They live on the host, which is the whole
  point: the rollback path must not depend on the network.

  NOTE ON BOOT TIME from `z` onward: boot now includes a ~60 s
  `[boot] tx-validation snapshot ready (61.49s)` step. That is deliberate --
  the read-only UTXO snapshot moved from per-inbound-connection to once
  pre-fork (see `y`/`z` below), so the cost is paid while the node is
  starting instead of by every peer that connects. A boot that seems to hang
  for a minute there is working as intended; the line is printed when it
  finishes.

  The eleven that changed live behaviour most, newest first:
  - **`ae`** (`057c87d`) — **this node can serve the blocks it downloads
    again.** The serve path's hash index was built once at boot; new blocks
    are appended by the download WORKER, a different process, so the serve
    parent and its children never learned about them. Every block received
    during a run was a silent `getdata` miss, so the node never helped
    propagate recent blocks — the only propagation that matters.

    It passed the `y`/`z` serving checks because a caught-up node mostly
    answers for HISTORICAL blocks, and those were in the archive at boot.
    Found by `validation/p2p_inbound_probe.py`, which asks as a stranger.

    What to watch after this deploy: a `[hashidx] +N height(s) now servable`
    line should appear as new blocks arrive. If it never does, the top-up is
    not running and serving is stale again.
  - **`ad`** (`90531b9`) — `addhdkey`, the last wallet refusal. **Carries an
    on-disk format bump**: the wallet record file gains an `hdkey` byte
    (BMCWSCN3 → BMCWSCN4), without which two HD keys resolve to each other's
    addresses.

    That bump is INERT until something writes the file. Formats 2 and 3 still
    read, and `hdkey = 0` is the truth for them rather than a default — they
    predate added keys. Verified on the live node: the wallet's answers
    (`getbalance`, `getwalletinfo`, `gethdkeys`, `listdescriptors`) are
    byte-identical across the restart and `walletscan.dat` is untouched, still
    BMCWSCN2. It is rewritten as v4 only by a rescan or a
    pruned-funds call.

    Also fixes a defect that was never about addhdkey: every xpub this node
    produced carried MAINNET version bytes, so Core rejected them outright on
    regtest and testnet4. Mainnet output is unchanged (verified: still
    `xpub…`).

    Before deploying this one the wallet files were copied to
    `/mnt/archive/bmc-backup/20260828-predeploy-ad/`, which is the right
    reflex for any deploy that can rewrite them.
  - **`ac`** (`ad59611`) — five of the six remaining wallet refusals were not
    actually blocked: `migratewallet` and `createwalletdescriptor` answer
    Core's own verdict for a wallet of this shape, `importprunedfunds` /
    `removeprunedfunds` are real (they import no key material, only the
    knowledge that an output we already own exists), and `setwalletflag`
    implements `avoid_reuse` end to end.

    Verified live: all five answer with Core's exact codes and messages.
    `avoid_reuse` is OFF by default and the flag file does not exist, so the
    production wallet's coin selection is unchanged by this deploy.

    NOTE for operators: `removeprunedfunds` and `importprunedfunds` are the
    first RPCs that WRITE the wallet's record file outside a rescan. They act
    only when called, and `wscan_write` writes its header last, so an
    interrupted call leaves the previous complete record set rather than a
    partial one.
  - **`ab`** (`e9b0d93`) — `getrawtransaction` falls back to the mempool,
    which is Core's order and what its help promises ("by default, this call
    only returns a transaction if it is in the mempool"). Before this it
    consulted only the OFFLINE txid index, so an unconfirmed transaction —
    the common case the call is reached for — came back `-5`, with a message
    about index coverage that was true and beside the point. Found while
    verifying deploy `aa` on the live node.

    Verified live on five real unconfirmed mainnet transactions: each
    returned serialization hashes to the txid that was asked for. The verbose
    form on an unconfirmed transaction carries no `blockhash`,
    `confirmations`, `time`, `blocktime` or `in_active_chain` — an
    unconfirmed transaction is in no block, and filling any of those in
    asserts a confirmation that has not happened. A confirmed transaction
    still carries its block context.
  - **`aa`** (`9404ffb`) — package relay, closed end to end: p2p 1p1c
    relay, BIP431 TRUC/v3, ephemeral dust, `replaced-transactions`, and
    `testmempoolaccept` package mode; plus `exportwatchonlywallet` and the
    bumpfee replaced-by linkage made reachable.

    A POLICY deploy, so the number to watch is the `policy` count in the
    30-second `[tx_accept]` summary — a new rule that is subtly too strict
    shows up there as mainnet transactions this node refuses and the rest of
    the network accepts. Measured over the first ten minutes: 0–2 policy
    rejects per window against 39–81 accepts, versus a baseline of ~5 before
    the deploy. Not over-rejecting.

    New in the heartbeat: a `[txrelay] orphans:` line. Those counters
    existed from the start and NOTHING EVER READ THEM, so a pool silently
    dropping everything looked exactly like a quiet one. First live reading
    was `79 held, 346 parked, 73 resolved, 194 dropped` — the 256-entry pool
    is evicting more than it resolves under real mainnet orphan traffic,
    which is bounded-by-design rather than broken (the network re-announces),
    but it is exactly the kind of thing the line exists to show.

    `1p1c: 0 accepted, 0 failed` at first reading. That path is proven
    against Core on regtest; it had not yet been exercised on mainnet, which
    needs a below-floor parent whose child also reaches us.
  - **`z`** (`1b62d67`) — inbound serving no longer stalls. Every forked
    serve child used to open its own UTXO snapshot (60–83 s) before
    answering anything; now opened once pre-fork and inherited. Measured:
    63 s to serve a block before, under a second after.
  - **`y`** (`392872b`) — the boot hash index was keyed BACKWARDS
    (index.dat holds wire order, the loader reversed it), so the node served
    no block requested by getdata, ever. Verify after any deploy touching
    this: a getdata for a known block must return it promptly.

  - **`x`** (`386dc22`) — `savemempool`/`importmempool` in Core's
    `mempool.dat` format. Verified live: a 284 KB dump of 184 real
    transactions that an independent parser walks to exactly the file
    length. `importmempool` was deliberately NOT run on the live node —
    it would re-submit every transaction through admission for no
    operational reason.

  - **`w`** (`385c9bb`) — `submitpackage` real; `gettxout` answers via the
    download-worker IPC; `getbalance`/`listunspent` answer from the wallet
    rescan. Verified live: `submitpackage` returns Core's `-8` parameter
    errors rather than the old `-1` refusal, and `gettxout` returns a real
    coin whose value and scriptPubKey match the block.
  - **`v`** (`8c19627`) — the `gettxout` IPC and the `connect=` per-peer
    port fix. Before this, `gettxout` answered `null` for every outpoint on
    the live node, which does not mean "unknown" — it means "spent".
  - **`u`** (`d291510`) — **nBits schedule enforcement** (`bad-diffbits`).
    A consensus change: watch the first blocks after this kind of deploy for
    a `bad-diffbits` reject, and roll back to the previous snapshot if one
    appears. None did — 32 blocks applied cleanly on the first run.

  A consensus-affecting deploy earns a look at the log before you walk away;
  the earlier letters (`o`–`t`) were mempool management, wallet encryption
  and chain selection, all of which are inert on mainnet or additive.
- **Never `cp` onto the running binary path** (`cp new daemon/bitcoind` while
  the service runs) — that is `ETXTBSY`. `make`/`ld` is fine because it
  unlinks first; a plain `cp` is not. Stop first, or write to a new name.
- **Never a broad `pkill`.** `pkill -f "bitcoind serve"` once took down
  production AND a benchmark node at the same time (incident #40 /
  `feedback_never_broad_pkill`). Kill by full path or PID only; when in doubt
  check `readlink /proc/<pid>/exe`.
- Old snapshots ARE the rollback: `systemctl stop`, `cp` the chosen
  `bitcoind.deploy-*` over `daemon/bitcoind`, `start`. Keep a few; prune the
  rest.
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
- **Exercise the reorg path deliberately, because mainnet rarely will.**
  A 1-block mainnet reorg happens every few weeks, so a node can run for
  months with its most destructive code path (disconnect, UTXO rewrite,
  archive truncate, mempool reconcile) never executed on real data.
  `asm/tests/reorg_drill <datadir-COPY> --depth 3` disconnects the last N
  real blocks and reconnects the SAME blocks, requiring the UTXO walk and
  the tip hash to return to exactly their prior values -- a total assertion,
  since the expected end state IS the start state. Build the copy from a
  STOPPED daemon in one pass (index/headers/chainwork, the utxo_* state, the
  undo_<h>.dat files for the depth being drilled, and the blk file holding
  the tip blocks -- typically ~13 GB, not the whole 1.4 TB archive). The
  drill refuses the production datadir by path; do not override that.
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

## Regtest

Since 2026-08-27 the node runs Core's **regtest** chain, selected by config —
the intended way to test wallet/mining/relay behavior deterministically
against a local Core instead of waiting on mainnet or testnet conditions.

`chain=regtest` (or `regtest=1`) changes the network magic, ports, genesis,
consensus schedule (everything active from height ≤ 1, no PoW retargeting,
150-block halving), address encodings (`bcrt…`, base58 versions 0x6f/0xc4),
and turns DNS seeding off. **State is fully isolated:** regtest lives in
`<datadir>/regtest/` (Core's layout), sharing only `bitcoin.conf` at the
datadir root, so a regtest run can never touch mainnet block/UTXO/wallet
state.

A regtest `bitcoin.conf` connecting to a local Core regtest node:

```ini
chain=regtest
port=18555               # bmc P2P (any free port; 18444 is Core's default)
rpcport=18445            # bmc RPC — NOTE: Core's regtest RPC default is
                         # ALSO 18443/18445-ish; pick non-colliding numbers
rpcuser=bmcreg
rpcpassword=CHANGE_ME
connect=127.0.0.1:18444  # the ONLY peer(s); disables discovery, like Core
```

Bring up a scratch Core regtest oracle alongside it (the project's authorized
oracle pattern — never the production Core):

```sh
CORE=/storage/bitcoin-core-source/build/bin
mkdir -p /storage/core-regtest
cat > /storage/core-regtest/bitcoin.conf <<EOF
regtest=1
[regtest]
port=18444
rpcport=18460            # keep clear of bmc's rpcport AND of 18443/18445
rpcuser=regoracle
rpcpassword=CHANGE_ME
fallbackfee=0.0001
EOF
setsid nohup $CORE/bitcoind -datadir=/storage/core-regtest -daemon=0 \
  > /storage/core-regtest/run.log 2>&1 &

CLI="$CORE/bitcoin-cli -datadir=/storage/core-regtest -rpcport=18460"
$CLI createwallet reg
$CLI generatetoaddress 160 "$($CLI getnewaddress)"   # mine a chain
```

Then start bmc pointed at its own regtest datadir; it syncs from Core in
seconds. Port note learned the hard way: keep bmc's `rpcport`, Core's
`rpcport`, and the P2P ports all distinct — Core's regtest also listens on an
onion-target port in the 18443–18445 range, and a collision shows up as
`bind() failed on port …` in the bmc log.

What this proves (all run 2026-08-27, `test_chainparams` + live diff):
block hashes 0..N byte-identical after syncing Core's chain; `gettxoutsetinfo
muhash` identical; a block built from **bmc's own `getblocktemplate`** is
accepted by Core via `submitblock`; live tip-follow; and a Core wallet tx
reaching bmc's mempool over the wire.

## Wallet encryption

If `bmcwallet.dat` is present and plaintext, `encryptwallet "<passphrase>"`
seals its mnemonic at rest (AES-256-CBC under Core's BytesToKeySHA512AES KDF),
removes the plaintext store, writes `bmcwallet.enc`, and leaves the wallet
**locked**. From then on:

- boot adopts the encrypted store locked (the live RPC seed is NULL);
- `walletpassphrase "<passphrase>" <seconds>` unlocks it for that many
  seconds (re-deriving the seed and installing it into the live wallet);
- `walletlock` re-locks immediately; the timer re-locks on expiry;
- `walletpassphrasechange "<old>" "<new>"` re-wraps in place.

Error semantics are Core's exactly (−15 on an unencrypted wallet, −14 wrong
passphrase, −8 usage, −4 not loaded). This is **inert until you run
`encryptwallet`** — an unencrypted node behaves as before. Do not encrypt a
wallet you cannot afford to lock yourself out of; there is no recovery path
without the passphrase, by design.

## What "working" looks like

A healthy steady-state node: heartbeat tip tracking the network within a
block, `peers=8/8`, UTXO applied height equal to the tip, live count within
sight of Core's `txouts` (~165.7M at height ~964k), and an RPC surface that
answers `getblockchaininfo`, `getblocktemplate '{"rules":["segwit"]}'`,
`getmempoolinfo`, and — given patience or a stopped daemon —
`gettxoutsetinfo muhash` with numbers you can diff against Core yourself.

Do that diff. This project's entire epistemology is that a claim without an
oracle comparison is a hope, and that applies to your deployment of it too.
