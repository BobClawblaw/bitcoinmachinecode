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

Verified live against the local Core v31 node (the operator's Core checkout, mainnet,
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

## 2026-09-05 (evening): deploy a — the audit-closure build, and NET-10 migrating a live address book

`bitcoind.deploy-20260905a`, main @ `9d9e93c`. The node had been running
`deploy-20260904a` for 26 hours: a build that predated CSI-1 (it answered
`gettxoutsetinfo muhash <height>` with the TIP set for a historical query) and
every consensus fix of the 2026-09-05 interpreter review.

What this build carries: IR-1 through IR-14 and IR-17 (two consensus
false-accepts, three valid-block DoS shapes, two policy divergences, a latent
memory-unsafety), IR-5's per-transaction sighash memo, IR-6's handle-based
stack, CSI-1, SCR-9/SCR-10, and NET-10.

**The rollout doubled as NET-10's first real migration.** `peers2.dat` was
`BMCADBK2`, 46,079 records; the writer upgraded it in place on first open.
Measured against a backup taken immediately before
(`/storage/peers2.dat.pre-net10-20260905-2039`):

| | |
|---|---|
| before | 2,211,808 bytes = 46,079 records at 48 B (v2) |
| after | 2,582,064 bytes = 46,108 records at 56 B (v3) |
| header count field | 46,108 — matches the file size exactly |
| marked tried | **4,096** — exactly `AB2_V2_TRIED_HEAD`, the head the dialer already trusted |
| carrying a source netgroup | 1 within the first minutes (gossip is rate-limited to 0.1 addr/s per leg) |

The 29-record difference is gossip the old process accepted between the backup
and the stop. Nothing was lost, and the head that `DL_POOL_V4_WINDOW` depends
on is now protected by a flag rather than by insertion order.

**Verified after restart:** clean stop ("Deactivated successfully", no
timeout), height 965,665 — **the same block as the Core oracle** — with
`headers == blocks` and `initialblockdownload false`; peers climbing from 0 to
4 within a minute; zero FATAL/SEGV/HALTED lines; `NRestarts=0`.

**~~Still true and not fixed here: the node has no inbound P2P listener.~~
CORRECTED, same evening — the claim above was wrong.** The node *was*
listening for inbound the whole time, on `0.0.0.0:8332`. There is no
`data/bitcoin.conf`, but the repo-level fallback `config/bitcoin.conf` — which
both the daemon and `bmc_cli` read — sets `port=8332` and `rpcport=8331`, and
the daemon was using both. What I actually saw was `connections_in 0`, which
means *nobody had dialled in*, not *nothing is listening*; and I read the
`0.0.0.0:8332` line in `ss` as the RPC socket when it was the P2P one. Two
different mistakes pointing the same wrong way. See the entry below.

**Incidental audit resolution.** `docs/releases/2026-09-05-audits-closed.md`
had, at that point, recorded `LimitCORE`/systemd hardening as an operator
attestation not checkable from the tree, because no `.service` unit is in the
repository.
It can be checked from the *host*, and now has been: `systemctl show` reports
`LimitCORE=0`, `NoNewPrivileges=yes`, `ProtectSystem=full`,
`ProtectHome=read-only`, `PrivateTmp=yes` — the base unit's
`LimitCORE=infinity` is overridden by the `50-hardening.conf` drop-in — and
the running process shows `Max core file size 0` in `/proc/<pid>/limits`. The
09-03 audit's closure was correct. The unit remaining outside version control
was noted as the residual; later the same day the operator ruled it a local
artifact, deliberately not vendored, and it is closed by that decision
(`releases/2026-09-05-audits-closed.md`). `docs/OPERATIONS.md`'s reference
unit now carries the hardening block so a node built from the docs gets it.


## 2026-09-05 (later): P2P moved to 8433 — and a correction, plus a config-precedence defect

**The correction first.** The deploy-a entry above said this node had no
inbound P2P listener. That was wrong. `config/bitcoin.conf` (the repo-level
fallback both the daemon and `bmc_cli` consult) sets `port=8332` and
`rpcport=8331`; with no datadir config, the node used them. It had been
listening on `0.0.0.0:8332` for its whole life. The evidence I misread was
`connections_in 0` — which says nobody had dialled in, not that nothing was
listening — and an `ss` line for `0.0.0.0:8332` that I took for the RPC socket
when it was P2P. The same wrong claim went into
`docs/reports/forum_reply_muhash_2026-09-05.bbcode` and is corrected there.

**What was actually done.** `data/bitcoin.conf` now sets `port=8433`,
`rpcport=8331`, `listen=1`. Moving P2P off 8332 is still worth doing — 8332 is
Bitcoin Core's *RPC* port, and running our P2P listener there is confusing to
anyone reading `ss` output, as this episode demonstrates.

**A real defect this surfaced: the daemon and the CLI resolve config
differently.** The first attempt set only `port=` and `listen=`. Then:

* the **daemon**, having found a datadir config, took its own default for
  `rpcport` (8332) rather than the fallback file's 8331;
* the **CLI** (`cli_conf.c`'s `conf_lookup`) resolves *per key*: absent from
  the datadir config, `rpcport` fell back to `config/bitcoin.conf` → 8331.

So the daemon served RPC on 8332 while `bmc_cli` dialled 8331, and the CLI
could not reach its own node without `-rpcport=`. Neither component is wrong
on its own; they simply disagree about what a second config file means. The
workaround is to state `rpcport` explicitly in the datadir config, which the
committed file now does and says why. **The fix is a code change and is not
made here:** the two must agree on precedence, and choosing which semantics
wins (Core merges a single conf with defaults; this tree searches two files)
needs its own change and its own test. Worth filing before someone else loses
an hour to it.

**Verified after the restart:** P2P listening on `0.0.0.0:8433` and
`[::]:8433`; a raw stranger handshake on 8433 returns
`version, wtxidrelay, sendaddrv2, verack`, so inbound genuinely works; RPC
back on `127.0.0.1:8331` with `bmc_cli` needing no flags; height 965,669 —
**the same block as the Core oracle** — `headers == blocks`, `ibd false`;
`NRestarts=0`, no FAILURE/FATAL lines. The v3 address book carries 46,274
records, 4,096 tried, and 154 with a source netgroup attributed since the
upgrade — NET-10's attribution path working in production.


## 2026-09-05 (night): rolled back to 8332, and the config-precedence defect fixed

**Rolled back.** `data/bitcoin.conf` was deleted and the node restarted, so it
is back on the repo-level `config/bitcoin.conf`: **P2P `0.0.0.0:8332` and
`[::]:8332`, RPC `127.0.0.1:8331`** — the arrangement it had before this
evening. Verified: a raw stranger handshake on 8332 returns
`version, wtxidrelay, sendaddrv2, verack`; 8433 is closed; `bmc_cli` needs no
flags; height 965,669 with `headers == blocks` and `ibd false`; `NRestarts=0`,
no FAILURE lines. The 8433 config is kept at
`/storage/bitcoin.conf.8433-rollback-20260905-2126` if it is ever wanted.

**Why the rollback was right, and my 8433 change wrong-headed.** I moved the
listener to avoid a clash with Core. There was no clash to avoid, and the
existing arrangement was already designed around Core:

| | Core (pid 106094) | BMC |
|---|---|---|
| P2P | 8333, bound to sixteen *specific* aliases `127.0.0.1`–`127.0.0.16` | 8332 on `0.0.0.0` + `[::]` |
| RPC | 8335 (`rpcbind=127.0.0.1`) | 8331 |

Core never binds `0.0.0.0`. That is precisely why BMC cannot take
`0.0.0.0:8333` — a wildcard bind collides with any specific bind on the same
port — and why the repo config puts BMC's P2P on 8332. The port sets are
disjoint and always were.

**The defect the episode surfaced is real and is now fixed** (`d0bc1c2`). The
daemon reads exactly ONE config file — `$BITCOIN_CONF`, else
`<datadir>/bitcoin.conf` when readable, else `<datadir>/../config/bitcoin.conf`
— and never merges (`node_config.c`, `node_config_path`), which matches Core.
`cli_conf.c`'s `conf_lookup` resolved *per key* across both, so a datadir
config setting `port` but not `rpcport` left the daemon on its own default
while the CLI still read the repo file's `rpcport`. The CLI now resolves the
file once with the daemon's precedence, with a regression test watched to fail
first.

**What this cost, stated plainly:** three restarts of a production node and two
published claims that were wrong (a listener that was never missing, and a
clash that never existed). The node was never in danger — every restart was
clean and it returned to the tip each time — but the diagnosis should have
started with `ss -ltnp` read carefully and `config/bitcoin.conf` read at all,
before anything was changed.

## 2026-09-06: two things observed on the host while the replay ran

Neither changed the live node. Both are recorded because the next person to
see them should not have to rediscover them.

- **The bench node (`/mnt/2tbssd/bmc-bench`) shut down cleanly at 01:50Z.**
  Its cookie is gone and `mempool.dat` / `fee_estimates.dat` were written
  that minute — the SIGTERM path, not a crash — and the kernel log has no
  OOM or segfault. No console log survived (the harness redirects to a
  `console.log` that is not there), so who sent the signal is unknown; every
  kill this session issued was by the replay's exact process name or pid.
- **The replay's leg to the live node blocked for ten minutes** in the boot
  header fetch (40 silent reads at 15 s), while the live node answers a raw
  `getheaders` probe with 253 headers instantly. Not reproduced. The replay
  now syncs from the Core oracle. The ten-minute tolerance is filed against
  the fetch, not the live node.

## 2026-09-06 (early): the CC-8 replay restarted twice — the interleave, then a CC-5 regression

Not the live node; `/storage/bmc-fullverify` (`assumevalid=0`, one loopback
peer, the Core oracle). Recorded because the second restart found a defect
that would have hit any fresh sync of the live build.

- **04:55Z, restart on `305c1b4`** (the interleave, PR #27) from the
  250,913-block archive, 2h50m into its first download. Clean stop: SIGTERM
  to the parent, worker gone in 3 s, "catch-up done: 240320 new blocks
  written (10172.69s)". Same command, same datadir, previous binary kept as
  `bitcoind.replay.prev-77b6c1f`. The worker applied the 240k-block
  backlog at ~20,000 blocks/s in the early chain, ~500 by height 200k.
- **04:59:38Z, the parallel downloader gave up in 0.3 s.** CC-5's
  four-page hold: "4 full pages and still below -minimumchainwork --
  abandoning this chain", then "archive already complete through 250913",
  "parallel downloader wrote 0 block(s)". The node fell back to its serial
  leg (~110 blocks/s at height ~280k, 60 s re-dial cycles,
  `sync_failing=1`). It kept running while the fix was built.
- **Correction.** The first run's download was the parent's BOOT catch-up
  (the shutdown line: "shutdown requested during the catch-up -- exiting
  before the worker starts"), not the worker's far-behind run as stated
  earlier that hour. The restart went straight to the worker.
- **Restart on the fix** (`4c3e8fc`, hold bounded by memory): see the
  entry that follows.

## 2026-09-06 (05:25–05:33Z): the replay on the CC-5 fix, then `bmc.bootcatchup=0` — the interleave is live

- **05:25Z, restart on `ab7087e`** (PR #28, the hold bounded by memory).
  SIGTERM to the parent; it exited in 2 s but its download worker finished
  its bounded step first and the binary was still busy, so the copy failed
  and the relaunch ran the OLD file — which refused the datadir lock and
  exited ("FATAL: cannot obtain a lock"). Nothing ran twice. The worker
  stopped cleanly at 05:26:38 ("stopping catch-up cleanly after height
  361806, checkpoint persisted"); the copy and launch were redone at
  05:26:53. **Lesson:** wait for the WORKER, not the parent, before
  swapping the binary.
- **The fix, verified live at 05:27:10:** "chain from 127.0.0.1 crossed
  -minimumchainwork -- storing 284 held page(s)" — 568,000 headers held in
  the mapping and released in order; span [369648, 965598]; download at
  8.9 MB/s on the one loopback worker.
- **But "connect deferred (no UTXO engine in this process)":** with the
  gap now visible at boot, the download ran in the parent's boot catch-up
  again, the path that cannot interleave. Exactly the case
  `UTXO_INLINE_BUILD_PERF_SCOPE.md` step 1 documents.
- **05:28Z, restart with `bmc.bootcatchup=0`** in `data/bitcoin.conf`
  (clean stop in 3 s: "shutdown requested during the catch-up -- exiting
  before the worker starts"). Boot: "skipping the boot catch-up; the
  worker's far-behind trigger will run". At 05:32:26 the worker ran the
  parallel downloader from 371,511; its first progress line at 05:32:51:
  `applied=371745 lag=1`. **The UTXO set is connecting one block behind
  the download** — the first time this node has done what step 1 was for.

## 2026-09-08 22:36Z — `deploy-20260908m`: the addrindex boot race (PR #123)

- **Why:** every boot since 17:16Z disabled the live address index
  ("undo has 0 records but the block spends N" at 966097, 966106,
  966110, 966111). `axt_boot` ran before the UTXO engine with the
  archive tip as its target and read undo for blocks the engine had not
  applied yet. Address pages on the facade were off all evening.
- **What:** `cp -a daemon/bmcbitcoind daemon/bmcbitcoind.deploy-20260908m`,
  relink `bmcbitcoind.live`; binary from `617f1154` (main), gate green.
- **Restart:** the operator's (`sudo systemctl restart bmcbitcoind`).
  Expected on the next boot: "[addrindex] LIVE: covered=<applied>
  (backfilled N; the archive is ahead, the rest lands as the engine
  applies it)" and no "boot backfill failed" line.

## 2026-09-08 23:49Z — `deploy-20260908n`: the coinstats history heals itself (PR #125)

- **Why:** the history build died in the 19:05Z OOM and nothing noticed;
  the base is now a separate file the fold worker checks once a heartbeat
  and rebuilds through a supervised child.
- **What:** snapshot from `86d48a66`, relink, `systemctl restart` (the
  operator's sentence, 23:49Z). Boot 2 m 20 s to the fold worker.
- **Verified live at 23:53:51Z:** "[coinstats] repair: history base
  absent -- building rows 0..966124 with 8 worker(s) (pid 1884083,
  attempt 1 of 3)"; the builder discarded the 252 old-layout `csh_*.tmp`
  (209 GB) first; `gettxoutsetinfo muhash 500000` refuses with "the
  history base is being rebuilt (builder pid 1884083, rows 0..966124,
  attempt 1)". Pass 1 at ~1.7k blocks/s per worker.


## 2026-09-18 21:16Z — `deploy-20260918a`: v31.1 RPC parity (PRs #269, #271)

- **Why:** `getpeerinfo` never reported `addrlocal` and omitted
  `last_block`/`last_transaction` at 0 (#269). Against the v31.1 release node
  (RPC 8337), `getdeploymentinfo` lacked taproot and mempool entries lacked
  `bip125-replaceable` while carrying two dev-build-only fields (#271). #270
  (harness) and #266–#268 (archive frontier guard, `+44` position file number)
  ride along; the previous deploy was `deploy-20260916h`.
- **What:** `main` at `323e657b`, full gate green on the merged tree
  (MAKE_EXIT=0). `cp -a daemon/bmcbitcoind daemon/bmcbitcoind.deploy-20260918a`,
  atomic relink of `bmcbitcoind.live`, `sudo systemctl restart bmcbitcoind`.
- **The first start failed, and systemd retried it.** The parent exited at
  21:16:18 while its download worker (pid 24243, SIGTERM forwarded at
  18.850) still held the datadir lock. The new process hit `FATAL: cannot obtain
  a lock` at 21:16:19. `Restart=on-failure` started it again at 21:16:29, and
  that start succeeded. This is the 2026-09-06 lesson again ("wait for the
  WORKER, not the parent"): the service reports stopped before its worker has
  released the lock. Not fixed here.
- **Verified live:**
  - `bmc_build_commit 323e657b`, `dirty false`, at the tip (967,610).
  - The UTXO engine reloaded at 967,610 with `live=165258639`, exactly the
    shutdown's `txouts=`.
  - The mempool reloaded 78,256 of 78,278 saved transactions (21:23:41).
  - `getpeerinfo`: 4 of 6 peers carry `addrlocal` (the other two sent Core's
    empty `addr_recv`), and every entry has both times and both byte maps.
  - The v31.1 field diff now matches on `getdeploymentinfo` and
    `bip125-replaceable`.
- **Still open, found by the same diff:** `chunkweight`/`fees.chunk` are
  missing on every mempool entry that belongs to a multi-transaction cluster
  (71,710 of 79,626); only singletons carry them. Core reports both on every
  entry. This predates the deploy.

## 2026-09-19 11:50Z — `deploy-20260919a`: the 2026-09-19 batches (PRs #273–#280)

- **What:** `main` at `d66005c9`, full gate green on the merged tree (MAKE_EXIT=0,
  all six new suites ran). Binary and all five index helpers from the same build.
  `cp -a`, atomic relink of `bmcbitcoind.live`, then `systemctl stop`, a wait until no
  process ran the old binary, and `systemctl start`. The old build stopped in under
  1 s with nothing left over. The new one started first time (`NRestarts=0`) and
  answered RPC 102 s later.
- **Config, same step** (backup `bitcoin.conf.bak-20260919-deploy`): `txindex=1` and
  `txospenderindex=1`. #275 gates each index on its key and production had neither
  line, though the Esplora facade serves /tx and outspends from both.
  `zmqpubsequence=tcp://127.0.0.1:28334`, which #278 implemented.
- **Verified live:**
  - `bmc_build_commit d66005c9`, not dirty, at the tip (967,700); all five indexes synced.
  - `getzmqnotifications`: five topics, hwm 1000 each.
  - The index tails resumed from their runs: txindex base 964,174, txospender base
    966,038.
  - No false "not a usable number" warnings (#274).
  - RPC: uptime 2 ms, getblockcount 1 ms, getblockchaininfo 1 ms, getindexinfo
    18 ms. getchaintxstats took 22.9 s on its first call (a cold build of the
    per-height array) and 1 ms after that (#280).
  - `getrawmempool false true` returns `mempool_sequence`.
  - getpeerinfo: 5 of 6 peers carry addrlocal, every entry has
    last_block/last_transaction, and all 6 show bytessent > 0.
  - A real libzmq subscriber on all three sockets got a 1,532,344-byte rawblock
    whose header hash equals its hashblock (#274; before this, rawblock was never
    delivered), and a `sequence` stream of A 721 / R 4 / C 1 with 0 per-topic gaps.
- **Found:** `[zmq] notification ring overrun: N transaction(s) not published`.
  Mempool accepts that never reach hashtx/rawtx/sequence. This predates the deploy:
  the old build logged 77,683 since 01:05, a few at a time in steady state. The new
  one dropped 56,243 during the boot reload of mempool.dat, when 78k transactions
  enter at once.

## 2026-09-19 13:46Z — `deploy-20260919b`: ZMQ notifications no longer lost (PR #283)

- **What:** `main` at `e8152f88`, full gate green (MAKE_EXIT=0).
  Stop, wait for every old process, start. `NRestarts=0`.
- **The first production stop under #276/#279's shutdown code.** The fold worker
  stopped cleanly ("coinstats.dat through height 967712"). The parent saw the
  worker still holding the lock on its way out, waited 0.1 s for its exit, and
  only then released it.
- **Verified live:** a real libzmq subscriber, connected through the
  mempool.dat reload (72,366 transactions), received 74,280 `hashtx` and
  74,280 `sequence` A events: the same set, 0 gaps, and 0 "ring overrun" lines.
  The previous build had dropped 56,243 notifications during the same kind of
  reload.
- Timed to land before run 27 ended, so the restart fell on run 27's last minutes
  and not on the Core rerun's first.

## 2026-09-19 18:55Z — `deploy-20260919c`: log literal lengths (PR #287)

- **What:** `main` at `3f02898a`. Its tree is identical to the gated #287 branch
  (MAKE_EXIT=0), so it was rebuilt to stamp the commit, not re-gated.
  Stop at 18:54:57Z, all old processes gone 1 s later, start 18:54:58Z, RPC up
  at 18:56:32Z. `NRestarts=0`.
- **Verified live:**
  - `bmc_build_commit 3f02898a`, not dirty, at the tip (967,731).
  - 5 indexes synced; 5 ZMQ topics.
  - No FATAL and no false config warnings.
  - Production's debug.log has 0 NUL bytes.
- **Effect on the Core v31.1 rerun, which was running on a different NVMe:**
  - Its blocks per minute were 443 at 18:56, against 507 to 1,465 (mean 889) in
    the 15 minutes before. From 18:57 it was at its usual pace while
    production's mempool reload ran (to 19:01:18).
  - At most ~30 to 40 s of Core time, within Core's own minute-to-minute noise
    (it did 507 at 18:34 with no restart).
  - Recorded in docs/reports/2026-09-18-run27/README.md.

## Backfill, 2026-09-25 to 2026-10-07: how these entries were reconstructed

The entries below were written on 2026-10-07, after the fact, from the records
that survive. Nothing in them is new measurement.

- **Commit:** the `bmc_build_commit` string compiled into each
  `asm/daemon/bmcbitcoind.deploy-*` snapshot, and its dirty flag read from the
  compiled `rj_bool` argument. Every snapshot below is clean except
  `deploy-20260927f`.
- **PRs carried:** the first-parent merges between one snapshot's commit and the
  next.
- **Restart times:** each process's first `[config] loaded` line in
  `logs/main/bitcoin.main.log*` and the `[serve] shutting down (signal 15)` line
  before it. The systemd journal on this box starts at 2026-09-30 21:03Z, and it
  agrees with the log from there on.
- **Why and verification:** worklog/ (2026-09-27 to 2026-10-05), the
  resume notes, docs/releases/, docs/reports/2026-10-06-core-vs-bmc-performance-release.md,
  INCIDENT_2026-10-07_reader_lane_fd_leak.md, and the session notes. Where none
  of them says why a deploy was made or how it was checked, the entry says
  "not recorded".
- **Restarts with no snapshot on disk:** 2026-09-24 21:51:39Z, 2026-09-25
  00:05:20Z, 2026-09-25 14:10:22Z (#303, below), 2026-09-25 15:20:08Z (the
  rollback, below) and 2026-09-25 20:29:50Z. Which binary the first two and the
  last one ran is not recorded.
- **Two snapshots were never started:** `deploy-20260927b` and
  `deploy-20261003a`.

## 2026-09-25 08:25Z — `deploy-20260925b`: the batches since 09-19 (PRs #288–#302)

- **Why:** not recorded in a worklog. A session note from that day says the
  day's two deploys before 14:10Z each had a next-block watch because the
  operator asked for one. Their results are not recorded.
- **What:** `main` at `4a5c95e2` (merge of #302), clean build. Since
  `deploy-20260919c` it carries:
  - #289, the catch-up-done heartbeat;
  - #295, the Mac's shared fixes;
  - #296, the txvb worker pool on mutex+condvar;
  - #298, no dial without a free candidate;
  - #299, the per-thread mapping cache made fully associative (LRU);
  - #300 and #301: the 481,827 fixture, and dial helpers that close inherited fds;
  - #302, getpeerinfo's `synced_headers`/`synced_blocks` from the peer's
    best-known block;
  - direct commits: `bmc.bootcatchup` defaults to 0, the license, and the
    run 29 report;
  - docs PRs #288, #290 and #292.

  The gate is not recorded. Process start 08:25:49Z.
- **Verified live:** not recorded.

## 2026-09-25 15:38Z — `deploy-20260925d`: the boot fill's double close (PRs #303, #306)

- **Why:** #303 (a new leg is asked for headers from pprev, as Core does) was
  deployed at 14:10:22Z from a build that has no snapshot on disk. It was
  checked for what it changed, peers' synced heights, and passed. But the apply
  had stalled at 968,555: six blocks were stored and none applied (heartbeat
  `tip=968555 stored=968561`), and RPC served a stale tip for 70 minutes.
  - #303 made the boot fill read the store, which exposed a double `close()` on
    a failed candidate. The second close took the store's cached blk-file fd,
    and the next file opened reused that number. bmc_osx `132c6f7e` named it.
  - Production was rolled back to the pre-#303 build at 15:20:08Z and caught up
    with Core in about 80 s.
- **What:** `main` at `593aff66` (merge of #306: each failed candidate's fd is
  set to -1 after its close; `test_leg_close_labels` checks the rule). Carries
  #303 as well. Clean build. Process start 15:38:41Z. The gate is not recorded.
- **Verified live:** not recorded beyond "production has run it since 15:38"
  (worklog/2026-09-25-note-for-osx-2.md, in git history at `0b9e27a3`).
- **Found:** a deploy is not verified until a new block has been applied: tip
  and hash equal to the oracle's, and heartbeat `tip == stored`. Watch for this
  even when the deploy is about something else. This became the standing deploy
  rule.
- The process was stopped at 20:24:04Z and a process started at 20:29:50Z with
  no new snapshot. That restart is not recorded.

## 2026-09-26 00:04Z — `deploy-20260926a`: compact-block short-id count (PRs #305, #307–#310)

- **Why:** cmpctblock_build wrote the short-id count as a single byte. Every
  compact block served for a block of 254 or more transactions was malformed
  (from bmc_osx 360b06e6).
- **What:** `main` at `0704f377` (merge of #310), clean. It also carries:
  - #305, the dial-helper ack byte;
  - #307, the 481,827 test's Mac path;
  - #308, the live-walk MuHash printed byte-reversed, as Core prints it
    (`695a719c`; #321 later found this a double reversal);
  - #309, an SCR-1d test.

  Process start 00:04:41Z. The gate is not recorded.
- **Verified live:** not recorded.

## 2026-09-26 01:58Z — `deploy-20260926b`: ban-table slot claim (PRs #311–#314)

- **What:** `main` at `32857aae` (merge of #314), clean. Fixes from the Mac's
  note-for-x86-2:
  - #314: every ban-table writer claims its slot under `mis_lock`;
  - #312: a ban expires by CAS;
  - #313: `mpool_get` builds its pointer from the `blob_off` it checked;
  - #311: the mempool journal checks TAIL before copying a body.

  Process start 01:58:24Z. The gate is not recorded.
- **Why / Verified live:** not recorded beyond the PR subjects.

## 2026-09-26 05:12Z — `deploy-20260926c`: banlist.json persists (PR #315)

- **What:** `main` at `92d536cc`, clean. Saves to banlist.json are serialised by
  an flock, and `setban` now persists. Process start 05:12:49Z.
- **Why / Verified live:** not recorded beyond the PR subject.

## 2026-09-26 09:57Z — `deploy-20260926d`: no strike during a local outage (PR #316)

- **Why:** a host-wide network silence had closed every long-lived peer as
  `sync-failed-3x`.
- **What:** `main` at `1d36e282`, clean. A sync pass's failure is not a strike
  when no leg received anything during it. Process start 09:57:51Z.
- **Verified live:** not recorded for the deploy.
- **Found later (09-27):** zero singleton strikes in 34 hours. A second
  three-minute silence (09-27 12:44Z) still cost five legs their third strike in
  its tail, and that is still open as a design question.

## 2026-09-26 12:43Z — `deploy-20260926e`: reorg probe held during an outage (PR #317)

- **What:** `main` at `7dacd8ab`, clean. No reorg probe starts while no leg has
  heard anything for 20 s. Snapshot written 12:35Z, process start 12:43:17Z.
- **Why / Verified live:** not recorded beyond the PR subject.

## 2026-09-26 14:55Z — `deploy-20260926f`: the announced-block claim (PR #318)

- **What:** `main` at `a3e598f9`, clean. The in-flight claim on an announced
  block is taken when the pass starts. Before this, a skipped pick held the
  claim for up to 600 s and every other leg was refused the block. Process start
  14:55:14Z.
- **Why / Verified live:** not recorded beyond the PR subject. The same commit
  ran the assumevalid=0 full-verification sync that finished 09-27.

## 2026-09-27 09:10Z — `deploy-20260927a`: safegcd scalar inverse (PR #319)

- **What:** `main` at `0a28906a`, clean. `sc_inv_var` by safegcd: 3.55 →
  0.67 µs, and ECDSA verify 21.9 → 20.7 µs. Revert-checked three ways.
  Process start 09:10:20Z.
- **Verified live:** 968,821 stored 2.7 s after Core (worklog/2026-09-27.md).

## 2026-09-27 09:43Z — `deploy-20260927b`: `fe_pow_sqrt` + `fe_inv_var` (PR #320), never made live

- **What:** `main` at `0151dd8c`, clean. BIP340 verify 25.9 → 22.4 µs. Gate
  MAKE_EXIT=0.
- **Never started.** The snapshot was written at 09:43:40Z, but production
  logged no restart between 09:10 and 12:07. #320 first ran in production in
  `deploy-20260927c`.

## 2026-09-27 12:07Z — `deploy-20260927c`: the MuHash byte order (PR #321)

- **Why:** the no-height `gettxoutsetinfo` MuHash was printed byte-reversed: a
  double reversal since 09-25 (`csi_rpc_run` plus #308's `hex_rev`).
- **What:** `main` at `781bc354`, clean. Carries #320 too. Process start
  12:07:04Z.
- **Verified live:** the live answer, the coinstats row and Core agree at
  968,837 (`b0982e65…`). 968,843 was stored 0.0 s after Core.

## 2026-09-27 13:05Z — `deploy-20260927d`: the Mac's shared fixes (PR #322)

- **What:** `main` at `33843749`, clean. The `addr_hist` race (TSan: 22 reports
  before, 0 after; the facade calls it from a thread per connection), the
  passphrase flush, and related fixes. Process start 13:05:14Z.
- **Verified live:** `/address` returned 200, and 4 concurrent `/address/txs`
  calls returned 200. The worklog gives the same next-block line as for
  deploy e ("968,889 stored 2.8 s after Core"). 968,889 is after this
  process's lifetime (the tip was 968,842 at 13:05 and 968,888 at 20:43),
  so this deploy's next-block figure is not recorded.

## 2026-09-27 20:43Z — `deploy-20260927e`: the map-cache magic (PR #323)

- **What:** `main` at `caa0f2da`, clean. `MAP_MAGIC` lived at st+120, which is
  fd-cache slot 7, and now lives at the dword at st+52. This was latent in
  production, where the block-filter builder maps the archive itself. Process
  start 20:43:37Z.
- **Verified live:** 968,889 stored 2.8 s after Core.

## 2026-09-27 22:49Z — `deploy-20260927f`: mutated compact block (PRs #324, #325) — a dirty build

- **What:** `main` at `ca255a15` (merge of #325):
  - #325, the Mac's item 16: a mutated compact block is dropped and
    re-fetched, never marked invalid;
  - #324, store-CLI and `multisig_verify` fixes, which link into no runtime
    binary.

  Process start 22:49:49Z.
- **The binary's dirty flag is set.** It is the only snapshot in this backfill
  built from a tree with uncommitted changes. What the change was is not
  recorded. The docs PR #326 was being prepared in the same checkout that
  evening, which could explain it, but that is not established.
- **Verified live:** not recorded. The worklog says production ends the day on
  this snapshot. Production had not hit the #325 case: no `invalid.dat`, and
  968,824 applied normally.

## 2026-09-28 00:52Z — `deploy-20260928a`: MuHash safegcd inverse (PR #329)

- **What:** `main` at `240c1ece`, clean. It carries:
  - #329: `num3072_inv.c`, a port of Core's `Num3072::GetInverse`.
    `MuHashFinalize` went from 1,861 to 27.9 µs (Core 28.0).
  - #327: the module bench suite.
  - Docs PRs #326 and #328.

  Gated as its own PR. Process start 00:52:10Z.
- **Verified live:** confirmed on the next block, 968,911, against Core (tip,
  hash, ≤ 1 s lag). The MuHash digest was checked live against Core at the
  same height.

## 2026-09-28 01:39Z — `deploy-20260928b`: ElligatorSwift constant-time and unbiased (PR #330)

- **What:** `main` at `11bbe4b8`, clean.
  - A constant-time comb for k·G and a w=4 window for k·P.
  - A Jacobi square test.
  - The encoder now draws the branch from the hash. The fixed order had biased
    the 64 wire bytes.

  ElligatorSwift create went from 108 to 21 µs, and ECDH from 65 to 40 µs.
  Process start 01:39:19Z.
- **Verified live:** real BIP324 v2 handshakes observed completing. The
  next-block figure is not recorded separately.

## 2026-09-28 02:08Z — `deploy-20260928c`: ChaCha20 in AVX2 (PR #331)

- **What:** `main` at `25b1a33f`, clean. `chacha20_avx2.asm`, which the MuHash
  keystream dispatches to: 1 MB went from 1.15 to 0.30 ns/B. Process start
  02:08:56Z.
- **Verified live:** confirmed on 968,921. The live MuHash digest equalled
  Core's at 968,920, and v2 handshakes completed.

## 2026-09-28 02:28Z — `deploy-20260928d`: SHA-1 SHA-NI, SHA-512 unrolled, Base58 limbs (PR #332)

- **What:** `main` at `21ac9750`, clean. Process start 02:28:37Z.
- **Verified live:** confirmed on 968,922.

## 2026-09-28 04:07Z — `deploy-20260928e`: GLV, the comb everywhere, SHA-256 and GCS (PRs #333, #334)

- **What:** `main` at `31c65846` (merge of #334), clean. It carries:
  - GLV for ECDH: 39.7 to 30.9 µs;
  - the comb at every k·G caller;
  - SHA-256 at Core's speed;
  - the block-filter builder: 21.6 to 3.7 ms;
  - script rows in a sighash session;
  - #333, docs.

  Process start 04:07:36Z.
- **Verified live:** confirmed on 968,934.

## 2026-09-28 11:34Z — `deploy-20260928f`: three Mac testnet4 fixes (PRs #335, #336)

- **What:** `main` at `982fd78b`, clean. #336 cherry-picked three fixes from
  bmc_osx with `-x`:
  - the archive frame check accepts the chain's magic;
  - a hole below the archive tip is re-fetched whatever `bmc.bootcatchup`
    says;
  - the reorg apply moves past the gap.

  Each was revert-checked by mutation. `-Werror`, gate MAKE_EXIT=0. Process
  start 11:34:23Z. #335 is docs.
- **Verified live:** confirmed on 968,987.

## 2026-09-28 18:35Z — `deploy-20260928g`: memtable shape sizing, the cluster claim memo (PRs #337, #338)

- **What:** `main` at `99285ae3`, clean. The Mac's PR #337, landed the x86
  way:
  - issue #294: a third sizing rule on the store's shape, so a restart in the
    middle of a sync no longer sizes the memtable for the steady state;
  - issue #304: two rules about which peers are believed, so a cluster of
    Knots peers on a rejected fork no longer starts the parallel downloader.

  Revert-checked by mutation, gate MAKE_EXIT=0 with 402 markers. Process start
  18:35:30Z. #338 is docs.
- **Verified live:** confirmed on 969,033 at 18:39:35Z. The first boot logged
  the new shape line.

## 2026-09-28 22:44Z — `deploy-20260928h`: the reorg probe's rejection memo (PRs #339–#341)

- **What:** `main` at `5dae51ae` (the Mac's PR #340, merged from their branch).
  A leg whose probe rejected a candidate chain is not probed again for an hour
  (`PROBE_REJECT_MEMO_S` 3600). Before this, the #304 fork was re-probed every
  30 s.
  - Revert-checked: with `probe_memo_active` forced to 0, 2 checks fail.
  - Gate MAKE_EXIT=0 with 402 markers.
  - The merged tree diffs empty against the gated cherry-pick.

  Process start 22:44:32Z. #339 and #341 are docs.
- **Verified live:** confirmed on 969,060.

## 2026-09-29 02:22Z — `deploy-20260929a`: Core's download shape (PRs #342–#344)

- **Why:** asked to match Core's default network settings for a fair A/B. bmc
  had used 8 download peers to Core's 10 (8 full-relay + 2 block-relay-only), a
  4,096-block window to Core's 1,024, and idle legs held beside the workers.
- **What:** `main` at `0dde606d`, clean.
  - `bmc.catchupworkers` is derived as `bmc.maxoutbound + bmc.blockrelayonly`
    (10).
  - The window is 1,024.
  - Idle legs are closed by name before the parallel download and re-dialled
    after it.

  Process start 02:22:01Z. #342 and #343 are docs.
- **Verified live:** confirmed on 969,089.

## 2026-09-29 13:42Z — `deploy-20260929b`: the even comparison (PRs #345–#347)

- **What:** `main` at `b27e3c18`, clean. bmc's defaults now equal Core's:
  - dbcache 450 MiB;
  - no transaction announcements taken during IBD;
  - the script-thread count stated at boot.

  The harness runs Core's bench protocol by default. Process start 13:42:30Z.
  #345 and #346 are docs.
- **Verified live:** RPC up with the tip equal to the oracle's at 969,161.
  Confirmed on 969,162 at 14:06:25Z: hash equal, lag 0 s, tip = stored.
- **Found later (09-30 14:05 restart):** with no announcements taken in IBD, a
  restart took no transactions until the next block connected, 7 m 48 s that
  time. #357 fixed it in `deploy-20260930e`.

## 2026-09-30 00:16Z — `deploy-20260930a`: the exec-lock wait/hold log (PR #348)

- **Why:** four times in three days, the whole RPC surface (JSON-RPC and the
  facade) answered nothing for over 90 s within two seconds of a new block, and
  the log could not say who held `g_exec_lock`.
- **What:** `main` at `8d7988e9`, clean. Every take and release of the lock is
  timed. A wait or hold of 2 s or more (`BMC_RPC_EXEC_LOG_MS`) logs one
  `[rpc] exec lock:` line that names the method or route.
  - `make -k test` MAKE_EXIT=0.
  - `gate-log-check` flagged only `test_rpc_signer`'s intentional segfault, and
    the deploy went ahead on that reading, on the operator's word.

  Restart at 00:16:15Z. RPC was up at 00:16:54Z.
- **Verified live:** `bmcgetcapabilities` build `8d7988e9`, not dirty. 5 indexes
  synced, tip 969,229 = Core's, and peers went from 0 to 3 in the first minutes.
  Stop saved 80,150 mempool transactions.
- **Found:** the first named holders, at 07:21Z: `getrawmempool (excl) held
  3467 ms` and `getmempoolinfo (shared) held 2885 ms`, at a 77,800-tx pool. These
  led to #355.

## 2026-09-30 01:13Z — `deploy-20260930b`: RPC waits on the worker without the lock (PRs #349–#351)

- **What:** `main` at `49e26354`, clean. #349 means a handler that waits on the
  worker no longer holds the execution lock, which was the shape of the 90 s
  stalls. #350 is the signer fixture's stderr, test only. #351 is docs, with
  one direct worklog commit. Process start 01:13:04Z.
- **Verified live:** confirmed on 969,234.

## 2026-09-30 09:42Z — `deploy-20260930c`: block lookups off the lock (PRs #352–#354)

- **What:** `main` at `75563b6f`, clean. #353 moves `getblockhash` and
  `getblockheader` into the fast lane: the pollers' per-block lookups answer
  during any slow holder. #352 and #354 are docs. Process start 09:42:00Z.
  The gate waited for run 31 to finish.
- **Verified live:** confirmed on 969,289, hash equal and tip = stored. That
  block landed during the 30 s RPC start-up, so the watch shows a start-up lag,
  not an apply lag.

## 2026-09-30 14:05Z — `deploy-20260930d`: the mempool readers cached and in their own lane (PR #355)

- **What:** `main` at `9b0bb505`, clean.
  - A per-slot parse cache (`mpc_weight`) for `getmempoolinfo` and
    `getrawmempool`.
  - The seven mempool readers run in a NOLOCK lane of their own.

  Revert-checked both ways. Process start 14:05:05Z.
- **Verified live:** confirmed on 969,307 at 14:12:31Z, in the same second as
  Core, hash equal, tip = stored.
- **Found:** this restart took no transaction announcements for 7 m 48 s,
  until 969,307 connected. That was #347's IBD gate, fixed by #357.

## 2026-09-30 22:52Z — `deploy-20260930e`: the relay gate at the heartbeat; the pool lock timed (PRs #356–#359)

- **What:** `main` at `d1d332fa`, clean.
  - #357: the relay's IBD gate is refreshed at the heartbeat (from bmc_osx
    `f8611830`).
  - #359: the pool lock is timed and named, and `getrawtransaction`'s mempool
    consult moved off the execution lock (from bmc_osx `71f4369d`).

  Each was gated on its own head. #359 was gated again rebased on #357:
  MAKE_EXIT=0, `GATE LOG AUDIT OK`, 442 tests. #359's revert check: without the
  yield, `getchaintips` waited 1,700 ms. #356 and #358 are docs. Restart
  22:52:33Z, RPC up 22:53:23Z.
- **Verified live:** confirmed on 969,359, applied 22:58:46Z with the oracle's
  hash. "tx announcements are taken again" was logged at the first heartbeat
  (22:54:42). The mempool.dat reload took 72,674 of 72,951 transactions in
  9 m 12 s.
- **Found:** the first pool-lock lines were a convoy, not one long holder. At
  23:01:35, waits of about 1.2 s followed releases of 0–3 ms.

## 2026-10-01 16:06Z — `deploy-20261001a`: the download chunk as a setting (PRs #360, #361)

- **What:** `main` at `a19a624f`, clean. #361 adds `bmc.dlcchunk` (default 16),
  and cursor help can fire again inside Core's 1,024 window. In an A/B to
  300k, 16 beat 40 by 19.5% and 14.1%. #360 is docs. Process start 16:06:04Z.
- **Verified live:** confirmed on 969,463, hash equal to the oracle's.
- The restart overlapped the first minutes of run 32's first attempt, and that
  attempt was later cut.

## 2026-10-01 18:51Z — `deploy-20261001b`: mempool policy to Core v31.1 (PRs #362, #363)

- **Why:** BlockYard's differential found 15 + 14 of 35 missing children, and
  2 of 246 clusters differing from Core.
- **What:** `main` at `f332e791`, clean. #363:
  - cluster limits only (ancestor and descendant counts deprecated);
  - `limitclustercount` capped at 64 and actually wired;
  - v31.1 RBF: rule 5, PaysForRBF and the feerate-diagram check;
  - optimal linearization.

  #362 adds `MAIN_C_HDRS` and `make header-check`. Process start 18:51:28Z.
- **Verified live:** confirmed on 969,480, hash equal. `getmempoolinfo` reports
  `limitclustercount 64`, `limitclustersize 101000`, `optimal true`.

## 2026-10-02 03:58Z — `deploy-20261002a`: eviction by cluster, the facade batch, the Core-parity batch (PRs #364–#369) — crash-looped, production down 23 h

- **What:** `main` at `1606aa36`, clean. It carries:
  - #366, eviction scores whole clusters;
  - #368, the facade's `POST /internal/mempool/txs` reads under one pool-lock
    hold per slice;
  - #369, the 17-commit Core-parity batch: no `wtxidrelay` sent, Core's fee
    rounding, `submitpackage` with package RBF, `stopatheight`, the IBD latch,
    and more;
  - #364, the one-oracle move (scripts and config).

  Each was gated 442/442 with the audit OK. Restart 03:58:54Z.
- **Reported verified, and it was not.** It applied 969,530 with the oracle's
  hash and logged the new IBD latch. It then segfaulted at 04:02:02Z, and
  crash-looped about 40 s after every restart, once mempool.space re-synced
  through the facade. systemd gave up after 12 restarts at 04:28:05Z.
  Production was down until 2026-10-03 13:16:40Z. Nobody looked until the next
  session ran `systemctl status`.
- **Cause:** #368's batch route called `rpc_chain_tx_blockhash` from the facade
  thread without the execution lock, and `irs_refresh` zeroes each kept run's
  map in place. All 11 crashes faulted at `0x6a61e3bd8`, which is NULL plus the
  run's sparse-index offset plus the first binary-search probe. That named the
  bug without a core dump. Fixed by #373.
- **Found:** one good block proves only the apply path. A deploy is verified
  only after 10+ minutes with `NRestarts=0`, once the RPC clients have
  reconnected. Check `systemctl is-active` at the start of every session.

## 2026-10-03 03:30Z — `deploy-20261003a`: ECDH by the Jacobian port (PR #371, #372), never made live

- **What:** `main` at `4483e11d`, clean. #372: ECDH k·P by the Jacobian
  `ecmult_const` port, 1.06× Core. #371 is docs.
- **Never started.** The snapshot was written while production sat in the
  failed state. The next process start, 10-03 13:16:40Z, ran a later build.

## 2026-10-03 13:16Z — `deploy-20261003b`: the crash fix (PR #373)

- **What:** the head of the #373 branch, `af04f538`, clean. Its tree is
  identical to the merge `1af4432b`, which the resume note names for this
  snapshot.
  - The facade batch route's txid-index lookup takes the execution lock.
  - `gettxspendingprevout` left the lock-free mempool lane, which had had the
    same race since 09-30.

  Snapshot written 04:12Z. Production was started on it at 13:16:40Z, ending the
  23 h outage.
- **Verified live:** not recorded beyond its listing as the rollback from 03c.
- **Found:** `getmininginfo` held the exclusive exec lock from 13:17:27 to
  13:19:57, a ~150 s RPC freeze after a restart into catch-up.
  `chainwork.dat` was ruled out. #376 added per-step timings, and the cause is
  still unexplained.

## 2026-10-03 15:07Z — `deploy-20261003c`: wtxid relay; the serve child follows the archive; buffered v2 messages (PR #374)

- **What:** `main` at `ace3a684`, clean, gated on its head (443 tests, audit OK).
  - `wtxidrelay` is sent again, with `MSG_WTX` announcements, and both getdata
    servers serve `MSG_WTX`.
  - The serve process follows `index.dat`. Its tip had been frozen at the boot
    height: the old process reported `tip=969479` at shutdown, 49 blocks stale.
  - A decrypted v2 message no longer waits for the peer's next packet.

  Restart 15:07:36Z.
- **Verified live:** RPC up at 15:07:52, tip equal to the oracle's at 969,739,
  and 0 restarts 12 minutes in. Every outbound leg negotiated `addrv2=1
  wtxid=1`.

## 2026-10-03 15:37Z — `deploy-20261003d`: Core's reject details (PR #375)

- **What:** `main` at `4302ed6f`, clean. `sendrawtransaction`,
  `testmempoolaccept` and `submitpackage` now give Core's `reason, debug` text
  and decode-failure messages, and TRUC's checks run in Core's order.
  `validation/reject_details_core_diff.sh` gave 16/16 byte for byte. Process
  start 15:37:46Z.
- **Verified live:** on 969,741. A clean restart: the longest exec-lock wait was
  3 s, and the 150 s freeze did not reproduce.

## 2026-10-03 16:22Z — `deploy-20261003e`: the crash handler; the chainwork tail (PR #376)

- **What:** `main` at `d09d2bd3`, clean.
  - `crash_trace.c`: a fatal signal writes the crashing stack, as text-segment
    addresses only, and the process still dies of the signal. `LimitCORE=0`
    stays, because the wallet seed is in memory.
  - Chainwork lookups past the end of `chainwork.dat` read only the missing
    headers.
  - `getmininginfo` logs per-step timings for a call over 1 s.

  Restart 16:22:58Z.
- **Verified live:** not recorded.

## 2026-10-03 16:45Z — `deploy-20261003f`: Core's script-failure reasons (PR #377)

- **What:** `main` at `5ca25aee`, clean. Script failures are reported as
  `mempool-script-verify-flag-failed (<ScriptErrorString>)`, with Core's input
  and prevout detail. The differential gave 22/22. Process start 16:45:58Z.
- **Verified live:** not recorded separately.

## 2026-10-03 20:40Z — `deploy-20261003g`: RPC admission in Core's stage order (PR #378)

- **What:** `main` at `230074a4`, clean. The RPC paths check inputs, then
  fees/RBF/TRUC, then scripts, so a transaction failing two stages is named by
  the stage Core names. Reject-details differential 26/26. Process start
  20:40:37Z.
- **Verified live:** on 969,760.

## 2026-10-03 23:45Z — `deploy-20261003h`: six audit fixes (PR #379)

- **What:** `main` at `f1b7d66c`, clean. Its tree equals the gated `4d0e904a`:
  a clean gate, 444/444, with the audit, link and header checks OK. The six
  fixes:
  - an `axt_read_events` mutex;
  - outbound v2 buffering;
  - helper-dialed services and the self vote;
  - the serve side's `reorg_gen`;
  - the inbound version tip;
  - the gbt reason on the stack.

  4 tests revert-checked. Restart 23:45:17Z. Run 33 was restarted fresh within
  seconds of it.
- **Verified live:** a next-block watch was started. Its result is not recorded.
- **Found later:** this build logged 21 `[rpc] exec lock:` lines in two days,
  each a 2.1–2.7 s wait behind holders of 0–16 ms. That fed the 10-05 RPC lanes
  plan.

## 2026-10-05 17:46Z — `deploy-20261005a`: the RPC lanes (PRs #380–#383)

- **What:** `6ed54746`, "integrate: RPC lanes (A0, A1, A2, A3, A5)", clean:
  the head of the #383 branch. Its tree equals #383's merge `0319e1eb` except
  for 18 lines of `docs/PERFORMANCE.md`. It carries:
  - lanes for the txid index and for `getblock` (the reader lane, `3b807cc6`);
  - a class-aware facade lock;
  - O(1) `getmempoolinfo`;
  - the undo capture taking Phase 1's prevout (B1+B2);
  - the header phase asking four peers;
  - #380 `bmc.dlshape=core` and the benchlog lines;
  - #381 coinstats from genesis;
  - #382 housekeeping.

  Snapshot written 17:28Z, restart 17:46:19Z. The gate is not recorded.
- **Verified live:** not recorded as a next-block check. Run 37's row (10-06)
  says 0 exec-lock waits ≥ 2 s since this deploy, and `getmempoolinfo` takes
  5 ms.
- **Found later (10-07):** the getblock reader lane kept a store handle (3 fds)
  and an 8 MB buffer in `__thread` storage, never released. The Esplora facade
  runs a thread per connection, so it leaked on every facade block read.
  Every snapshot from this one through `deploy-20261006d` carries the leak;
  see `deploy-20261007a` and INCIDENT_2026-10-07_reader_lane_fd_leak.md.

## 2026-10-06 05:41Z — `deploy-20261006a`: getrawtransaction by byte range; BIP9 cached (PRs #384–#387)

- **Why:** run 37's RPC rows (A7, A8). `getrawtransaction` took 14 ms single
  and 382 ms at 32 clients, against Core's 4 / 5. `getdeploymentinfo` held the
  exclusive lock for 2.0–2.1 s.
- **What:** `main` at `c2229ded`, clean. It carries:
  - #387: `getrawtransaction` reads the record's byte range, and the BIP9 walk
    is cached per period boundary;
  - #384 and #385: eviction accounting;
  - #386: docs.

  Restart 05:41:43Z.
- **Verified live:** on the next block, with zero restarts.
  `getdeploymentinfo` took 1.6 s once after the restart, then 4 ms.

## 2026-10-06 06:08Z — `deploy-20261006b`: the txindex tail hash-indexed (PR #388)

- **What:** `main` at `01f9c7fa`, clean. A recent transaction now costs what a
  run record costs. Before this, every lookup scanned the unsorted tail
  linearly, and the tail is 564 MB on production. The serve process now holds
  the tail's hash table, 128–256 MB over the fold cycle. Restart 06:08:55Z.
- **Verified live:** on the next block, with zero restarts. Measured on
  production after it: `getrawtransaction` 3 ms single and 5 ms at 32 clients
  (Core 3 / 5).

## 2026-10-06 11:59Z — `deploy-20261006c`: the JSON arena; the index worker (PRs #389–#392)

- **What:** `main` at `01d235f6`, clean. It carries:
  - #392: one JSON arena per request, a span-copying escaper, and hex encoded
    in place. getblock v2 single went from 73 to 58 ms, and the 32-client
    median reached parity. The peer probes also end on their own clocks
    (B9 part 1).
  - #390: index writes moved off the applier into a forked index worker.
  - #389 and #391: docs.

  Restart 11:59:34Z.
- **Verified live:** thirteen saved responses byte-identical to the previous
  build's.
- **Not a rollback target.** Like every build before `deploy-20261006d`, it
  replays the UTXO WAL from byte 0. It would drop tombstones from a datadir
  that 06d or later has written, because B3 punches a hole over the retired
  WAL bytes and `utxo.idx` holds the first live byte. It also carries the
  reader-lane fd leak.

## 2026-10-06 20:03Z — `deploy-20261006d`: B3 async flush, B8 chainwork in step, M1 memory naming (PRs #393–#396)

- **What:** `main` at `b194dd01`, clean. It carries:
  - #394 M1: named memory regions, and the `[mem]` lines;
  - #395 B8: the chainwork records kept in step during the parallel download;
  - #396 B3: the memtable flush freezes a private copy, and a forked writer
    builds the run. The WAL is hole-punched below the checkpoint.
  - #393: docs.

  The gate passed in a worktree at 19:24Z: main+M1+B8+B3 plus the
  `test_utxo_catchup_timing` fix `e53301a3`, MAKE_EXIT=0. Deployed at 20:03:56Z
  on the operator's "run the deploy commands".
- **Verified live:**
  - 970,223 applied 20:05:55Z with the oracle's hash.
  - Tip 970,225 = oracle at 20:16, and the facade answered.
  - `NRestarts=0` 11 minutes in.
  - mempool-backend had been failed since 10:04Z (V8 heap OOM). It came back
    on a 16 GB heap at 21:33:41Z and was in sync by 21:34:43Z. The client-load
    check closed at 21:49Z: production pid 3144426, `NRestarts=0`.
- **Found:**
  - **The getblock reader-lane fd leak,** latent since `deploy-20261005a` (the
    lanes integration `6ed54746`, reader lane `3b807cc6`). This process ran out
    of descriptors on 10-07 at 16:26:22Z (1,023/1,024), and RPC and the facade
    were dead for 2 h 17 m. See `deploy-20261007a`.
  - **The B3 tip zombie.** The writer is reaped only by `fz_poll`, which runs
    once per applied block, right after the fork. The flush writer forked at
    block 970,267 (pid 1959235, 2026-10-07 01:16:41Z) sat as a zombie for
    22.5 min, until block 970,268. The adopt, the WAL hole-punch and the frozen
    copy's release lagged one block interval. This is safe: a crash replays the
    WAL, the hook waits before the next freeze, and shutdown reaps. Fixed in
    #400 (the idle-rest poll), with the test in #403.
- **Rollback:** do not roll back past 06d. Every snapshot before it replays the
  UTXO WAL from byte 0 and would drop tombstones from a datadir that 06d or
  later has written.

## 2026-10-07 18:42Z — `deploy-20261007a`: the reader lane released at thread exit (PR #402, with #400)

- **Why:** production RPC was dead from 16:26:22Z. `accept()` got EMFILE at
  1,023/1,024 fds: the Esplora facade's thread per connection leaked 3 fds per
  getblock lane. mempool.space stalled at 970,365. P2P sync went on, so
  `is-active` and the tip looked healthy. The operator noticed at 18:22Z.
- **What:** `main` at `54ffb790`, clean.
  - #402: the reader lane closes its store handle and frees its 8 MB buffer at
    thread exit, via a pthread-key destructor (`asm/rpc_chain.c`).
    `test_rpc_chain` was watched to fail on the unfixed code (14 → 206
    descriptors over 64 threads).
  - #400: B9 part 2, the idle tick; B11, the anonymous memtable; B10, the
    claim clamp; and B3's reap at the tip.
  - Docs PRs #397–#399.

  Built in a clean worktree at the merge commit, full gate MAKE_EXIT=0. The
  operator chose "fix first, then deploy" over a restart on the leaking build.
  Started 18:42:56Z (systemd `ActiveEnterTimestamp`).
- **Verified live:**
  - RPC answering at 18:43:46Z.
  - New blocks 970,378 and 970,379 hash-identical to the Core v31.1 oracle's.
  - `NRestarts=0` at 10+ minutes.
  - fd count flat at 66–67 across facade traffic, against 1,023 before.
  - mempool backend synced to the tip.
  - At 20:42Z, still healthy at 970,389 with 66 fds.
- **Rollback:** `deploy-20261006d` is the only rollback target. It leaks fds, so
  use it only as a bridge and watch the descriptor count. Do not roll back past
  06d: every snapshot from `deploy-20261005a` through `deploy-20261006d`
  carries the fd leak, and every snapshot before 06d replays the UTXO WAL from
  byte 0 and would drop tombstones from a datadir that 06d or later has
  written. Never `deploy-20261006c`.
- #403 (the B3 reap-at-tip test) and #404 (B12, the header leader switch)
  landed after this deploy without a redeploy. #403 is test-only, and B12 only
  matters for fresh syncs.
