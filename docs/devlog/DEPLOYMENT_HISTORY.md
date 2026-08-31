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
  allocated before it: the live-status/RPC-submission block, the mempool and
  its fee-policy registry (mutated under a `PTHREAD_PROCESS_SHARED` lock),
  and (since 2026-08-30) the peer misbehaviour scores — those must be shared,
  because the serve loop that detects violations runs in a forked child and a
  process-local table could never accumulate across connections;
- a **ZMQ servicing thread** in the download worker, when a publisher is
  configured, so subscriber accepts and subscription frames never run on the
  block-download path.

Everything lives in one datadir: the block archive (`blk*.dat` + positional
`index.dat`), `headers.dat`, `chainwork.dat`, the LSM UTXO store
(`utxo.dat` WAL, `utxo_run_*.dat`, `utxo_manifest.dat`,
`utxo_applied_height.dat`), `peers.dat`/`peers2.dat`, and optionally a wallet
store — either `bmcwallet.enc` (the encrypted container: 100k-iteration KDF,
AES-256-CBC, key separation) or the older plaintext/`BMCWAL v2` store, plus a
`.txlog` journal.

The wallet **passphrase does not live in the datadir**. See `walletpassfile`
under *Configure*: a datadir backup should never carry the key to the wallet
it also contains.

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
# Chain (default main): main | signet | testnet4 | regtest. Anything but
# mainnet runs in a subdirectory of the datadir — see "Regtest" and "Signet"
# below. Legacy testnet3 ("testnet"/"test") is refused, not run.
chain=main
# signetchallenge=<hex>   # a CUSTOM signet. It also determines the network
                          # magic, so a custom signet cannot hear the public
                          # one. Omit for the public signet.

# P2P
listen=1                 # accept inbound peers (fork-per-connection)
port=8332                # P2P listen/dial port; chain default if omitted
                         # (8333 main, 38333 signet, 48333 testnet4,
                         #  18444 regtest — see node_config.c)

# RPC. The COOKIE is the default credential: <datadir>/.cookie is written
# 0600 at start, deleted on shutdown, and bitcoin-cli finds it on its own.
# Do NOT set rpcuser/rpcpassword unless you need a fixed credential -- they
# put a plaintext secret on disk, Core warns against them, and this project
# removed its own after the password reached a public repository.
# For a fixed credential use rpcauth= (salted HMAC), never rpcpassword.
rpcport=8331             # MUST NOT collide with the P2P port (was 8332;
                         # fixed 2026-08-26, commit 6469c2f)

# BIP324 v2 encrypted transport (default 1). Accepts inbound v2 and dials v2
# to peers advertising NODE_P2P_V2; v1 peers are detected in band and are
# unaffected. Set 0 for v1 only.
v2transport=1

# Wallet passphrase, if the wallet is encrypted. Absolute path, OUTSIDE the
# datadir -- a file beside the wallet travels in every backup of it. Refused
# if world-accessible, group-writable, or inside the datadir. Intended shape:
#   sudo install -d -m 0755 /etc/bmc
#   sudo install -o root -g <service-group> -m 0640 secret /etc/bmc/wallet.pass
#walletpassfile=/etc/bmc/wallet.pass

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
# Give shutdown time: a flush can legitimately run long, and a SIGKILL
# mid-write is exactly how incidents #45 (counter drift) and the original
# resume-REJECT class were born. The daemon honours SIGTERM. (Compaction no
# longer holds shutdown up: it runs in a forked child that is killed on stop;
# its partial output is swept at the next boot and the merge redone.)
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

## Deploying a new build

The convention is a dated snapshot per deploy, so a rollback is a file copy
rather than a rebuild:

```sh
cd asm
make -k test 2>&1 | tee /tmp/gate.log; echo "MAKE_EXIT=$?" >> /tmp/gate.log
make gate-log-check LOG=/tmp/gate.log   # the actual gate check -- see below
sudo systemctl stop bmc-bitcoind   # the binary is busy while it runs;
                                   # "Text file busy" means you skipped this
cp -a daemon/bitcoind daemon/bitcoind.deploy-$(date +%Y%m%d)a
sudo systemctl start bmc-bitcoind
```

Roll back by copying the previous `bitcoind.deploy-*` snapshot over
`daemon/bitcoind` and restarting.

**Verify the restart rather than assuming it.** Boot takes a couple of minutes
(archive reload, UTXO load) before the RPC answers. Check, in order:

```sh
systemctl is-active bmc-bitcoind
grep -aE "BIP324|\[rpc\]|encrypted wallet" logs/bitcoind.production.log | tail
ss -ltn | grep -E ":833|:2833"     # P2P, RPC, and any ZMQ endpoints
bitcoin-cli -datadir=... getblockcount
```

The lines worth reading on a fresh boot:

```
[net] BIP324 v2 transport enabled (services=0x809); N of M known peers advertise v2
[rpc] no rpcuser/rpcpassword -- using cookie authentication
[rpc] encrypted wallet adopted and unlocked from the configured passphrase source
[rpc] JSON-RPC server on 127.0.0.1:8331
```

**A green gate is not the same as a green wrapper, and "no failures" is not
the same as "it passed."** Both have burned this project, the second one as
recently as 2026-08-30:

- The *wrapper* trap: backgrounding or piping `make -k test` gives you the
  exit status of the last thing in the pipeline, not make's. Always record
  `MAKE_EXIT` explicitly and read that.
- The *empty gate* trap, which is nastier. A test failing to LINK stops the
  `test:` recipe from running at all, because a prerequisite of it failed. The
  log then contains no `FAIL` lines and no `TESTS FAILED` — for the simple
  reason that no test ever ran. Grepping for failure words cannot tell that
  apart from a clean run: **a log with zero failures is exactly what a gate
  that ran nothing looks like.**

So do not grep. Run:

```sh
make gate-log-check LOG=/path/to/gate.log
```

`scripts/gate_log_audit.py` reads the `test:` recipe, and requires that make
exited 0, that **every** gated test appears in the log as actually executed,
and that no failure or crash markers appear. It reports which tests never ran
by name. Its own correctness is gated by `gate-log-selftest`, which is a
prerequisite of `test:` — it builds synthetic logs with known verdicts,
including the two that matter most: a gate missing exactly one test at the
end, and one missing a test from the middle.

### The three build audits

Each covers a class the other two structurally cannot see. All three run as
prerequisites of `test:`, so they fail in the first seconds of a gate rather
than mid-build.

| audit | the question it answers | what it cannot see |
|---|---|---|
| `prereq-check` | does a recipe use a file the rule never declared as a prerequisite? | a file named in NEITHER the recipe nor the prerequisites |
| `link-check` | does a rule link the file that DEFINES a symbol one of its sources needs? | flags: it compiles with a generic set, not each rule's own |
| `gate-log-check` | did the gate actually run every gated test? | whether a test that ran and printed nothing was meaningful |

`link-check` exists because adding signet hit the same defect four times: a
source grew a dependency on a symbol from another file, and the rules linking
the first were not updated to link the second. Each surfaced only as a link
error in a full gate — minutes to run, and because a failed prerequisite stops
the `test:` recipe entirely, the log holds no `FAIL` lines. It resolves
symbols the way the linker will (compile each source, read `nm`, take each
rule's expanded prerequisites as its link set) and reports what is unresolved
**only when another file in this project defines it**, naming that file. Every
finding therefore reads "add this file to that rule"; libc and pthread are
unresolvable by definition and are skipped.

Its value is that it reports the whole class at once. When `node_config.c`
grew a call into `netperm.c`, it named all **46** affected rules in under a
second, before a gate ran.

Using prerequisites as the link set is sound *because* `prereq-check` enforces
the other direction. The two audits lean on each other deliberately.


**Since 2026-08-31 the unit runs a pinned snapshot, not the tree binary.**
`ExecStart` points at `asm/daemon/bitcoind.live`, a symlink to the current
`bitcoind.deploy-YYYYMMDD<letter>` snapshot. A rebuild in the tree therefore
changes nothing until you relink; a plain `systemctl restart` always boots the
snapshot it booted last time. Deploy = build, snapshot, relink, restart:

```
cd /storage/bitcoinmachinecode/asm
make daemon/bitcoind
cp -a daemon/bitcoind daemon/bitcoind.deploy-$(date +%Y%m%d)x     # pick the next letter
ln -sfn bitcoind.deploy-$(date +%Y%m%d)x daemon/bitcoind.live
sudo systemctl restart bmc-bitcoind
```
Rollback is `ln -sfn <previous snapshot> daemon/bitcoind.live` + restart.

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
  2026-08-28 the live binary is **`bitcoind.deploy-20260828af`**; the
  rollback one step back is `…-20260828ae`.

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

  The twelve that changed live behaviour most, newest first:
  - **`af`** (`cab7e75`) — a `getdata` miss is answered with `notfound`
    instead of silence, and BIP157 compact filters are SERVED
    (`getcfilters`/`getcfheaders`/`getcfcheckpt`). Verified on the live
    mainnet node: `notfound` for an unknown txid, and all three filter
    messages answered for a covered height (10.8 KB + 15.6 KB of real
    filters, a 130 B cfheaders, a 12.8 KB cfcheckpt).

    **Operational note this exposed:** the mainnet filter index covers
    heights 0–425,210 of 964,405 — the backfill was never finished, and the
    daemon logs `[bfilter] index at 425211, tip N -- waiting for the backfill
    to close in` on every block. Filters BELOW that height serve; above it we
    correctly answer nothing, because we do not have them. Finishing the
    backfill (`daemon/build_block_filters`) is what makes filter serving
    useful to a light client on the current chain.
  - **`ae`** (`057c87d`) — **this node can serve the blocks it downloads
    again.** The serve path's hash index was built once at boot; new blocks
    are appended by the download WORKER, a different process, so the serve
    parent and its children never learned about them. Every block received
    during a run was a silent `getdata` miss, so the node never helped
    propagate recent blocks — the only propagation that matters.

    It passed the `y`/`z` serving checks because a caught-up node mostly
    answers for HISTORICAL blocks, and those were in the archive at boot.
    Found by `validation/p2p_inbound_probe.py`, which asks as a stranger.

    CONFIRMED on mainnet 2026-08-28: `[hashidx] +1 height(s) now servable
    (through 964405)`, and the live node then served that block — 1,636,818
    bytes — to a probe that asked for it. That is the exact case that
    returned silence before.
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

## Signet

`chain=signet` runs Core's public signet. On signet the block **signature** is
the consensus rule in place of meaningful proof of work (BIP325), so a node
that did not check it would accept any block anyone offered.

```ini
chain=signet
# signetchallenge=<hex>   # only for a CUSTOM signet
```

Everything lands under `<datadir>/signet/`, on ports 38333 (P2P) and 38332
(RPC). The lines worth reading at boot:

```
[chain] signet: default challenge (71 bytes), magic 0a 03 cf 40
[boot] signet genesis seeded at height 0
```

The magic is **derived** from the challenge, not configured: the first four
bytes of `sha256d(CompactSize(len) || challenge)`. That is why a custom
signet is isolated automatically — a different challenge is a different magic,
and the two networks cannot talk. Core also drops the minimum-chain-work floor
and the DNS seeds for a custom signet, and so does this node; a mainnet-scale
floor would stall a private network forever.

**Verifying it is actually enforcing.** A node that syncs proves nothing on
its own — an inert check would sync just as happily. The decisive test is to
re-apply the same blocks under a challenge differing by one character:

```sh
# same archive, one hex character changed in signetchallenge
[utxo_live] REJECT h=1: bad-signet-blksig
```

If that does not appear, the check is not running.

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

## Catch-up performance (2026-08-31)

Five changes, each benchmarked before/after (numbers in the commit messages
`a9a2709`, `ff11807`, `a499003`, `cff3a38` and the leveled-compaction commit):

| What | Before -> after | Knob |
|---|---|---|
| Compaction I/O buffering | 10.6 s -> 1.7 s per merge of 3M records | -- |
| Parallel download while running | 1903 s -> 245 s to 10k blocks | `bmc.bootcatchup=0` skips only the boot run |
| Background compaction | apply stalled for the whole merge (163-326 s on production) -> never waits | -- |
| Checkpoint batching in catch-up | 46 s -> 17 s (NVMe), 62 s -> 16 s (HDD) for 15k blocks | -- (64 blocks / 2 s far from the tip; per block near it) |
| Leveled compaction | 22.5x -> 5.3x write amplification on a 500 MB set | `bmc.utxocompactthreshold` (default 12) |

Operational notes:

- **Background compaction** forks a child per merge. It appears as a second
  `bitcoind` process with the same command line for the duration; killing it
  is harmless (the merge is redone), but do not run a *second daemon* on the
  datadir -- match processes by `/proc/PID/exe`, not by name, when checking.
  Log lines: `compaction of N run(s) [lo..hi) of M started in background pid P`
  and `background compaction done in Xs: manifest_n A -> B (... flushed
  meanwhile)`. A merge whose result cannot be reconciled is discarded and
  logged; nothing is lost.
- **Checkpoint batching** widens the crash window during catch-up from one
  block to at most 64. Boot recovery rolls the ghost run back from the undo
  files before anything else looks at the set (`RECOVERY: rolled back N ghost
  block(s)`), then re-applies. This is the same path a one-block ghost always
  took; `tests/test_utxo_ckpt_batch` crashes a child mid-batch to prove it.
- **`bmc.utxocompactthreshold`** is the number of runs that triggers a
  compaction (it was parsed and ignored before 2026-08-31). Which runs get
  merged is decided by size ratio: fresh runs fold into a medium one, the base
  is rewritten only when everything above it has grown to a quarter of its
  size. Lowering the threshold makes lookups consult fewer runs at the cost of
  more frequent small merges; the base rewrite cadence does not change.
- Orphan run files (a crash between a merge's publish and its unlink, or an
  abandoned background merge) are swept at boot: `init: swept N orphan
  file(s)`. The sweep refuses to act unless the manifest file matches memory.

## Relay floors, mempool reload and RPC availability (2026-08-31)

- **Relay fee floor follows Core v30.** `minrelaytxfee` and `incrementalrelayfee`
  now default to `0.000001` BTC/kvB (0.1 sat/vB), Core's
  `DEFAULT_MIN_RELAY_TX_FEE{100}`. The old default (1 sat/vB, Core <= v29) made
  this node refuse every transaction its peers relay between 0.1 and 1 sat/vB:
  the parents were rejected on fee, their children arrived as orphans that
  could never resolve, and production logged ~99,000 parked / ~98,300 dropped
  orphans in six hours with only ~1.5 tx/s accepted. Found by feeding a parked
  orphan's chain root (from a Core signet node's mempool) to our
  `testmempoolaccept`: "min relay fee not met" at exactly 0.1 sat/vB. Internally
  the floors are kept in sat/kvB (integer sat/vB could not express 0.1).
- **RPC comes up before the mempool reload.** `mempool.dat` used to be replayed
  before the RPC server started, one transaction per download-worker rotation
  (~2 tx/s): 13 minutes dark for 353 saved transactions on deploy `a`, longer
  on `b`. The worker now services a stream of submissions without returning to
  its rotation between them, and the reload runs after the RPC listener is up
  (`getrawmempool` is briefly partial, as in Core).
- **The reload is order-independent.** The dump is written in pool order, not
  parent-before-child; entries rejected for missing inputs are retried in
  passes until nothing more is admitted (`loaded mempool.dat: ... (N waited
  for a parent, M of them then accepted)`).

## Relay: orphans, confirmed transactions, chain limits (2026-08-31, later)

- **`notfound` clears the request ring.** A parked orphan's parent is requested
  from the announcing peer; if that peer answers `notfound` (Core will not serve
  a transaction it has not announced to us until it is 2 minutes old), the
  parent's txid used to stay in the "recently requested" ring and every later
  announcement of it was ignored -- the child expired. Production after the
  fee-floor fix still showed 6,324 parked / 538 resolved / 5,530 dropped in an
  hour. The ring entry is now dropped on `notfound`; `test_tx_relay` case 12
  replays request -> notfound -> inv -> request again.
- **A request is forgotten after 60 s.** The "recently requested" ring used to
  keep an entry until 4,096 later requests pushed it out (~14 minutes at 5
  tx/s). A getdata whose reply never came -- the leg dropped and re-dialed,
  the peer ignored it -- therefore blocked every later announcement of that
  transaction, and every child announced meanwhile died as an orphan. Entries
  now carry a timestamp and expire after Core's `GETDATA_TX_INTERVAL` (60 s);
  the next announcer is asked. Case 14. The heartbeat gained a second line:
  `orphan drops: N ttl, N evicted, N rejected | parents requested N, notfound
  N, re-requested after timeout N`.
- **Per-peer request tracking** (Core's TxRequestTracker, simplified): every
  announcement remembers up to 4 announcing legs; a request unanswered for 5 s
  is retried on a DIFFERENT leg (an untried announcer first, else any other
  live leg -- any peer serves getdata from its mempool), a `notfound` fails
  over immediately, a dead leg is dropped and the next candidate tried, and an
  entry gives up after 4 requests (a later inv recreates it). Entries clear on
  arrival by both txid and wtxid. Before this, a lost request simply waited up
  to 60 s for the same tx to be announced again -- for a parked orphan's
  parent, usually never. Heartbeat: `retried on another peer N (gave up N, in
  flight N)`. `test_tx_relay` case 16.
- **The orphanage is sized against Core v31's reservations** (404k weight units
  and a 3,000-announcement score per peer): 2,048 slots / 8 MB, up from 256 /
  2 MB, which sat pinned at capacity after every restart and made eviction the
  dominant drop cause once nothing expired by TTL. `getorphantxs` still shows
  at most 256 entries (the shared snapshot's size).
- **The sync pass waits for replies the relay layer is owed.** The relay poll
  waited at most 250 ms for a getdata reply; anything slower sat in the socket
  buffer and the header-sync pass that runs next on the same fd discarded it
  unexamined (`.drain`). Every parent fetched for a parked orphan from a peer
  slower than that was lost -- production 2026-08-31: 822 parents requested,
  65 notfound, 37 resolved. Outstanding requests are now remembered per leg
  (carried into the next poll, expiring after 1.5 s) and the worker skips that
  leg's sync pass while replies are pending; the heartbeat line counts `sync
  passes deferred for pending replies`. Case 15.
- **Recently confirmed transactions are "already known".** Block connect records
  every txid the block carried (64K rolling); a copy arriving over p2p
  afterwards is answered -27 instead of being parked as an orphan and having
  its parents requested. Counted as `already confirmed` in the `[tx_accept]`
  summary line. Case 13.
- **Chain limits follow Core v31.** Core now accepts by *cluster* (64
  transactions / 101 kvB) and keeps `-limitancestorcount` (25) only for wallet
  coin selection. Our defaults for `limitancestorcount`/`limitdescendantcount`
  are 64 so a chain the network relays is not refused at 26. Wide trees are
  admitted slightly more permissively than Core's cluster count (a known gap;
  it affects only this node's own mempool, not consensus).
- **Boot warning "block data is NOT laid out monotonically"** is pre-existing
  and expected on any archive filled by the parallel downloader (chunks land
  out of order in the blk files). It is informational: only archive truncation
  and pruning refuse to run on such a layout. Fixing it means rewriting the
  block files in height order -- a maintenance tool, not a runtime change.

## Genesis coinbase incident (2026-08-31)

Core stores NO chain's genesis coinbase in its chainstate. `genesis_skip.h`
enforced that for mainnet/regtest/testnet4 but predated signet, so a signet
node built by the live catch-up carried the genesis coinbase as a spendable
50 BTC UTXO -- found as "one extra output, exactly 50 BTC" the first time the
whole set was compared against a Core oracle's `gettxoutsetinfo` at an
identical tip. Fixed: signet's hash in the skip list, plus the ACTIVE chain's
derived genesis hash (covers custom signet challenges) checked in the apply
path; `test_chainparams` pins all four. The affected datadir was repaired
surgically with `tests/tool_utxo_del` (appends an ordinary WAL tombstone;
remove `coinstats.dat` alongside so the index re-seeds) and then verified
muhash-identical to the oracle. Mainnet was never affected (its hash was in
the list from the start).

## Policy parity vs Core v30/v31, round two (2026-08-31, later)

Verified live against the local Core v31 node (`/home/svc/bitcoin`, mainnet,
txindex): **production's whole UTXO set is muhash-identical to Core at height
964914** -- the first mainnet oracle comparison since 963967.

New policy enforcement (all in the mempool accept path, before script
verification, Core's PreChecks order; `tests/test_policy_v31` and new
`test_mempool_policy` scenarios pin them):

- `MAX_TX_LEGACY_SIGOPS` (2,500, v30) over input scriptSigs + output
  scriptPubKeys ("bad-txns-legacy-sigops");
- `MAX_STANDARD_TX_SIGOPS_COST` (16,000) using the accurate BIP141 walker
  ("bad-txns-too-many-sigops");
- `bytespersigop` (20): fee floors judge a sigop-dense tx at
  max(vsize, sigop_cost x 5) vbytes;
- IsWitnessStandard for P2WSH: <= 100 stack items, <= 80 bytes each,
  witnessScript <= 3,600 ("bad-witness-nonstandard"); tapscript judged
  conservatively (annexed inputs skipped);
- **cluster limits** (v31's too-large-cluster): the connected component a tx
  joins may not exceed 64 transactions / 101 kvB, found by a bounded BFS at
  admission -- catches wide shapes (64 independent parents + one child) that
  ancestor/descendant counts alone admit.

Also: mempool reload orphan tuning (orphan TTL 5 min, per-leg in-flight cap
100), `bitcoin_cli` client timeouts (10 s connect, 60 s read/write), gettxout
retries briefly instead of erroring while the worker is busy, and the per-tx
"reject (policy)" line is muted like the txval one.

**Archive re-layout tool**: `tests/tool_archive_relayout <archive> <out>` reads
index.dat, rewrites every frame in height order (128 MiB rotation), writes a
matching index, verifies every block hash, and leaves the swap to the
operator. Clears the "NOT laid out monotonically" boot warning so truncation
and pruning can run. Run it offline (daemon stopped).

## Log rotation (2026-08-31)

`bmc-logrotate.timer` (systemd, every 15 min) runs logrotate against
`config/logrotate-bmc.conf` -- the repo-tracked config whose `size` value
(2M by default) is THE knob. `copytruncate` keeps systemd's append fd valid;
60 compressed rotations are kept in `logs/`. The 84.7 MB log that prompted
this was rotated on install.

## Datadir layout (2026-08-31): every chain in its own subdirectory

`chainparams_datadir` now returns `<datadir>/<chain>` for EVERY chain --
`data/main/`, `data/signet/`, ... -- instead of Core's mainnet-at-the-root.
No block files live at the datadir top level any more. The daemon's own
leveled log is `<chaindir>/logs/bitcoind.log` (per-chain by location; the old
`.chain.` suffix is gone), and the repo `logs/` directory houses the
service-level logs per chain (`logs/main/bitcoind.production.log`, signet
consoles under `logs/signet/`). Migration for an existing mainnet datadir,
BEFORE first boot of a build with this:

```
systemctl stop bmc-bitcoind
cd /storage/bitcoinmachinecode/data && mkdir -p main && mv $(ls | grep -v '^main$') main/
systemctl start bmc-bitcoind
```
The unit's ExecStart still passes the datadir root; the cookie moves to
`data/main/.cookie` (bitcoin_cli resolves it); log rotation matches
`logs/*/ *.log` via config/logrotate-bmc.conf.

## 2026-08-31 (evening): relay/policy tail + mainnet archive re-layout

Commit `6b1d07c`, full gate green (gate_tail1, 286 tests), deploy `m`.

**Per-peer notfound memory** (`tx_relay.c`): a peer's notfound for a tx is
remembered for 10 minutes (fd + 8-byte txid prefix, 512-slot ring). The
failover picker and the orphan parent fetch skip such peers instead of
re-asking for an answer already given; a fresh announcement from the same
peer is still honoured (a new claim, as in Core). Test: relay case 17.

**Taproot witness standardness now matches Core verbatim** (`tx_accept.c`):
annexed spends are REJECTED (the old code accepted them "conservatively" --
a real accept/reject divergence), an empty control block is refused, and for
tapscript leaves (control[0] & 0xfe == 0xc0) stack items below script+control
are capped at 80 bytes. Key-path spends and non-tapscript leaves are not
judged. Seven new gated cases.

**Cluster measured post-eviction** (`bitcoin_mempool_policy.c`): the 64/101kvB
cluster walk skips members of the RBF eviction set, so a replacement is
judged against the diagram it creates -- thinning a full cluster is no longer
refused for the very size it frees. Gated RBF scenario proves it.

**Testing trap for the suite's okv() macro**: it evaluates its condition
TWICE (printf + count). A call with side effects inside okv() prints "ok"
and still counts a failure -- hoist the call, pass a variable.

**Mainnet archive re-layout**: same height-order rewrite the signet archive
got (tool_archive_relayout), run HOT against the live daemon -- the tool only
reads index-committed frames, so a concurrent append is simply not captured
and the daemon re-fetches the missing tail on its next boot. Scratch on the
same NVMe (`data/main-relayout`, 1.1T); the swap happens inside the deploy-m
stop window; the old blk files are the rollback until the new boot verifies.

## 2026-08-31 (night): anonymity networks live + truthful getnetworkinfo (deploy n)

Tor/I2P/CJDNS were already coded and gated; this round wired production to
the local daemons (onion=127.0.0.1:9050, torcontrol=9051, i2psam=7656,
cjdnsreachable=1) and fixed getnetworkinfo, which hardcoded onion/i2p/cjdns
as unreachable and never listed localaddresses. It now reports the dialer's
real per-network reachability, the onion service hostname and the i2p b32
destination (`06cad5b`). The onion service is ephemeral ADD_ONION with a
persisted key: it exists only while the daemon's tor-control connection is
open, and creating it takes minutes -- early in a boot the loopback 8334
listener plus the established 9051 connection are the evidence, not the log.
cjdroute is hand-run: `sudo cjdroute < /storage/cjdns-rt/cjdroute.conf`.

Console logs are now `logs/<chain>/bitcoin.<chain>.log` for every chain.

## 2026-08-31 (late): quiet-log series (deploys o, p, q)

Three rounds against console-log noise, each gated and deployed alone:
- **o** `69675cf`: the 5-second mutes were metronomes -- steady mainnet churn
  always has a missing-inputs reject in any 5 s window, so "one line per 5 s
  at most" meant one line every 5 s forever. missing-inputs now logs nothing
  per event (the 30 s `tx_accept` summary is the record); policy rejects
  1/min; `sendrawtransaction accepted` 1/5 min.
- **p** `5fd0782`: ZMQ notification ring 16 -> 64 slots (404 KB payload each,
  ~26 MB of the MAP_SHARED block; 256 would be 103 MB) and the overrun report
  at most once a minute -- its total is cumulative anyway. A mempool.dat
  reload still laps the ring (thousands of accepts in seconds while the
  worker is the one accepting); that loss is reported, and matters only to a
  ZMQ subscriber, which must resync via RPC on sequence gaps as with Core.
- **q** `3991c92`: the per-leg `[txrelay:N] +N tx accepted` line (~35/min)
  became one `[txrelay] last 60s` line with the per-leg breakdown.

Result: ~60 lines/min -> ~17 lines/min of real events (heartbeat, summaries,
dial/leg churn, tor/i2p/cjdns state). The `size 2M` rotation now covers
hours instead of minutes.
