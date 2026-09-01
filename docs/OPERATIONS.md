# Bitcoin Machine Code — Operations Guide

This guide covers installing, configuring, running, upgrading and
troubleshooting the `bitcoind` daemon of Bitcoin Machine Code on a Linux
x86-64 host under systemd. It describes the system as it is; what the node
does and does not implement is in `README.md` and `docs/FEATURE_GAPS.md`.

## Overview

One binary, `asm/daemon/bitcoind`, runs the node as a fork-model daemon:

- a **parent** accepts inbound peers (one forked serve child per connection)
  and runs the embedded JSON-RPC server on its own thread;
- a forked **download worker** owns the outbound peer legs, block download
  and keep-up, UTXO application and reorg handling;
- a background **UTXO compaction** forks a short-lived child per merge; it
  appears as a second `bitcoind` process with the same command line.

Everything the node persists lives in one datadir, and every chain gets its
own subdirectory of it: `<datadir>/main`, `<datadir>/signet`,
`<datadir>/testnet4`, `<datadir>/regtest`. `bitcoin.conf` is shared at the
datadir root (or `../config/bitcoin.conf`); all other state is per chain, so
two chains never share block, UTXO or wallet state.

The companion client is `asm/daemon/bitcoin_cli`. With `-datadir=<dir>` it
reads the chain, RPC port and credentials from that datadir's `bitcoin.conf`
and cookie, so no other flags are usually needed.

## Installation

### Prerequisites

- Linux x86-64 (NASM ELF64, System V ABI).
- `nasm`, `gcc`, `make`, `python3` (build, test suite, build audits).
- Disk: the mainnet block archive is about 0.7 TB at the current height
  (713 GB across 5,733 `blk*.dat` files) and grows with the chain; the UTXO
  store is about 13–15 GB; the optional indexes add about 27 GB
  (`txindex.dat`), 30 GB (`addr_index.dat`) and 13 GB (`bfilters.dat`).
  The archive re-layout tool needs archive-sized scratch space (about
  1.1 TB). Pruned mode fits in a few GB.
- RAM: several GB; the initial-sync memtable is sized from `dbcache`
  (default 1024 MiB, 4096 MiB in the reference configuration).
- Optional: `tor` (SOCKS 9050, control 9051), `i2pd` (SAM 7656), `cjdroute`.

### Build

```sh
cd /path/to/repo/asm
make daemon/bitcoind              # the daemon (about 31 MB)
make daemon/bitcoin_cli           # the RPC client
make tests/tool_archive_relayout  # archive maintenance tool (optional)
```

`asm/build.sh` is an equivalent wrapper. The build uses `gcc -no-pie -O2`
and `nasm -f elf64`.

### User and directories

The reference deployment runs the service as an unprivileged user with:

| path | purpose |
|---|---|
| `/path/to/repo/asm` | service working directory; binaries under `asm/daemon/` |
| `/path/to/repo/data` | the datadir (root of all chains) |
| `/path/to/repo/config/bitcoin.conf` | configuration (git-ignored) |
| `/path/to/repo/logs/<chain>/bitcoin.<chain>.log` | console (stdout/stderr) log per chain |
| `/etc/bmc/wallet.pass` | wallet passphrase file, outside the datadir (optional) |

Create the datadir and `logs/<chain>` before the first start. The datadir
may be a symlink or mount point; the daemon resolves it with `realpath` and
changes directory into `<datadir>/<chain>`.

A first start on an empty datadir bootstraps itself: DNS-seed discovery,
headers-first sync, parallel block download, then a from-genesis UTXO build
with full script verification. Expect days, CPU-bound on signature
verification. The pulse is `[dl] heartbeat: tip=<h> peers=<live>/<wanted>
txouts=<utxo count> uptime=<d:hh:mm:ss>`.

## Configuration

### Location

`bitcoind serve <datadir>` resolves its configuration in this order:
a `-conf=<path>` argument (an unreadable file is fatal, never a fallback);
`$BITCOIN_CONF`; `<datadir>/bitcoin.conf` if readable;
`<datadir>/../config/bitcoin.conf`. The path used is echoed at boot as
`[config] loaded <path>: N setting(s) applied`, followed by a `[config]`
block with every resolved value (`conns`, `utxo`, `pool`, `mpol`, `net`,
`chain`). Check it after any change; values are read once at start-up.
Unknown keys are ignored with a message; a Core option the node does not
implement is named at boot as having no effect.

`config/bitcoin.sample.conf` lists every key with its default. Keys are
Bitcoin Core's names and defaults unless the comment says otherwise.

### Chain and ports

```ini
chain=main                 # main | testnet4 | signet | regtest (testnet4=1 / signet=1 / regtest=1 also accepted)
# signetchallenge=<hex>    # CUSTOM signet; also determines the network magic
port=8333                  # P2P; chain default if omitted (see Reference)
rpcport=8332               # RPC; chain default if omitted
listen=1                   # IPv4 and IPv6 listeners on `port`
```

`chain=test`/`testnet` (testnet3) is refused. A custom signet gets no
chain-work floor and no DNS seeds. `rpcport` must differ from `port`: the
P2P listener binds first and the RPC server then loses its bind, leaving the
node without RPC. A fresh non-main chain directory self-seeds its genesis.

### RPC authentication and access

- **Cookie (default).** `<datadir>/<chain>/.cookie` is written mode 0600 at
  start (`__cookie__:<64 hex>`) and deleted on shutdown. `rpccookiefile=`
  relocates it.
- **`rpcauth=user:salt$hash`** (repeatable, up to 8) for a fixed credential;
  a malformed entry is ignored with a log line. `rpcuser=`/`rpcpassword=`
  work too but keep a plaintext secret on disk.
- The server starts if any credential source is available and refuses to
  start when none is.
- **Bind and ACL.** The listener binds `127.0.0.1`. `rpcbind=` is honoured
  only with at least one `rpcallowip=` (up to 16 subnets; `127.0.0.0/8` and
  `::1` are always allowed); otherwise the log says `Option -rpcbind was
  ignored because -rpcallowip was not specified`. A malformed `rpcallowip`
  is fatal.
- **Peer permissions.** `whitelist=[perms@]<subnet>` grants `noban` (the
  only permission implemented); `whitebind=` attaches permissions to an
  extra listener. `whitelistrelay`/`whitelistforcerelay` are not implemented.

### Wallet passphrase source

An encrypted wallet (`bmcwallet.enc`) is adopted locked at boot. To unlock it
automatically, provide a passphrase source, in order of precedence:

1. `$BMC_WALLET_PASS` (visible in `systemctl show` and `/proc/<pid>/environ`);
2. `walletpassfile=<absolute path>` in `bitcoin.conf`.

The file is refused, with a `[wallet] walletpassfile ... not usable: <why>`
line, if it is not absolute, is **inside the datadir**, is world-accessible
(any `007` bit), is group-writable, is not a regular file, or is empty. The
first line is the passphrase. The intended shape:

```sh
sudo install -d -m 0755 /etc/bmc
sudo install -o root -g <service-group> -m 0640 secret /etc/bmc/wallet.pass
```

A legacy `<store>.pass` beside the wallet is not read and is warned about.

### Anonymity networks

```ini
proxy=127.0.0.1:9050       # SOCKS5 for every network
onion=127.0.0.1:9050       # SOCKS5 for .onion only (defaults to proxy; "0" disables)
onlynet=onion              # restrict networks (repeatable): ipv4 ipv6 onion i2p cjdns
discover=0                 # do not learn/announce our own address
torcontrol=127.0.0.1:9051  # tor control port: creates OUR onion service
torpassword=               # only if tor uses HashedControlPassword
i2psam=127.0.0.1:7656      # SAM bridge; empty = i2p off
cjdnsreachable=1           # the cjdns tun (fc00::/8) is present
v2transport=1              # BIP324 encrypted transport, default on
```

- `proxy=` (unlike `onion=` alone) also stops resolver lookups for peer
  names, skips the DNS seeds, randomises SOCKS5 credentials per connection
  (one Tor circuit each), and never advertises a clearnet address to onion or
  I2P peers. Seed the address book or use `addnode=`/`connect=`.
- **Onion service.** With `torcontrol=` (and `listen=1`, `listenonion=1`)
  the node authenticates on the control port (cookie file named by
  PROTOCOLINFO, or `torpassword`), issues `ADD_ONION` with a key persisted in
  `<chaindir>/onion_v3_private_key`, and listens on a loopback socket at the
  chain default P2P port + 1 (`127.0.0.1:8334` on mainnet). The service is
  ephemeral and exists only while the daemon holds the control connection.
  It takes a few minutes after start; the confirming line is
  `[tor] onion service <addr>.onion:<port> -> 127.0.0.1:<port+1> (key
  onion_v3_private_key)`. The service account needs read access to tor's
  control cookie: under systemd, `SupplementaryGroups=debian-tor` (group
  membership in the user database is not applied to a service). Outbound
  onion needs only `onion=`/`proxy=`.
- **I2P.** `i2psam=` opens a SAM session with a destination persisted in
  `<chaindir>/i2p_private_key`; boot line `[dial] i2p session up via SAM
  <ip:port>, our address <b32>.b32.i2p`. I2P is outbound only; inbound I2P
  streams are not accepted.
- **CJDNS.** Needs a running `cjdroute` (a systemd unit in the reference
  deployment; the node's unit is ordered after it) and IPv6 on the host; boot line
  `[dial] cjdns reachable (fc00::/8 over IPv6)`. Inbound cjdns peers arrive
  on the IPv6 listener. Without IPv6: `[dial] no IPv6 on this host: ipv6 and
  cjdns peers are unreachable`.
- **BIP324.** Inbound v2 accepted, v2 dialled to peers advertising
  `NODE_P2P_V2`, v1 detected in band. Boot line `[net] BIP324 v2 transport
  enabled (services=0x...); N of M known peers advertise v2`.

`getnetworkinfo` reports per-network reachability, the onion hostname and the
I2P destination.

### ZMQ and other keys

- `zmqpubhashblock`, `zmqpubhashtx`, `zmqpubrawblock`, `zmqpubrawtx` take
  `tcp://<interface>:<port>`; `tcp://*:PORT` is refused, name an interface
  (`127.0.0.1` for local subscribers). A publisher has no authentication.
  `zmqpubsequence` is not supported and is refused.
- `txindex=1` has no effect on the daemon: the index is built offline
  (`daemon/build_tx_index <datadir>`) and used when `txindex.dat` exists.
  `blockfilterindex` and `coinstatsindex` are on; the keys only turn them off.
- `assumevalid` is parsed and ignored: every script in every block is verified.
- `pid=<file>` writes the pid once the RPC port is bound. `blocknotify`,
  `alertnotify`, `startupnotify`, `shutdownnotify` run a shell command with
  `%s` sanitised to `[A-Za-z0-9._:/-]`.
- `bmc.utxocompactthreshold` (default 12) is the run count that triggers a
  background compaction; `bmc.bootcatchup=0` skips the boot-time parallel
  download.
- `debuglogfile=<path>` relocates the daemon's own leveled log (relative to
  the chain directory or absolute; `0` disables it); `disablewallet=1` loads
  no wallet; `bytespersigop` (default 20) sets the sigop-adjusted size used
  for fee-rate checks.

## Running as a service

Reference unit, `/etc/systemd/system/bmc-bitcoind.service`:

```ini
[Unit]
Description=Bitcoin Machine Code Daemon (experimental AI-authored asm node)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=simple
User=<service-user>
Group=<service-group>
WorkingDirectory=/path/to/repo/asm
ExecStart=/path/to/repo/asm/daemon/bitcoind.live serve /path/to/repo/data
StandardOutput=append:/path/to/repo/logs/main/bitcoin.main.log
StandardError=append:/path/to/repo/logs/main/bitcoin.main.log
Restart=on-failure
RestartSec=10
TimeoutStopSec=90
KillSignal=SIGTERM
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
```

Drop-ins in `bmc-bitcoind.service.d/` in the reference deployment raise
`TimeoutStopSec=900` (headroom for a compaction in progress at stop time)
and add `SupplementaryGroups=debian-tor` (tor control cookie access).

- `ExecStart` runs **`bitcoind.live`**, a symlink to a dated snapshot
  `bitcoind.deploy-<YYYYMMDD><letter>`, not the tree binary. A rebuild
  changes nothing until the symlink moves; `systemctl restart` boots whatever
  it points at.
- The datadir argument is the root; `chain=` selects `<datadir>/<chain>`.
- stdout/stderr append to `logs/<chain>/bitcoin.<chain>.log`.
- SIGTERM is honoured (the parent forwards it to the download worker);
  `TimeoutStopSec` is the wait before systemd SIGKILLs.
- `Restart=on-failure`, `RestartSec=10`, at most 5 starts per 600 s.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now bmc-bitcoind
systemctl is-active bmc-bitcoind
```

### Log rotation

`config/logrotate-bmc.conf` rotates `logs/*/*.log` when a file exceeds
**`size 2M`** (the knob), keeps 60 compressed rotations, and uses
`copytruncate` so systemd's append descriptor stays valid. It is driven by
`bmc-logrotate.timer` (5 min after boot, then every 15 min) whose service
runs `logrotate -s /var/lib/logrotate/bmc-status <repo>/config/logrotate-bmc.conf`.

## Upgrading and rollback

An upgrade is build, audit, gate, snapshot, relink, restart. Snapshots are
host-local build products, not in git; keep the last few.

```sh
cd /path/to/repo/asm
git pull
make daemon/bitcoind          # safe while the old binary runs: ld unlinks first

# the three build audits (each is also a prerequisite of `make test`)
make prereq-check             # every file a recipe uses is a declared prerequisite
make link-check               # every rule links the files defining the symbols it needs
make runlist-check            # every test is gated or declared manual with a reason
make abi-check                # SysV stack-alignment audit of asm->C call sites

# the gate: record make's OWN exit status, then audit the finished log
make -k test > gate.log 2>&1; echo MAKE_EXIT=$? >> gate.log
make gate-log-check LOG=gate.log
echo GATE_CHECK_EXIT=$?       # act on THIS status only
```

`gate-log-check` (`scripts/gate_log_audit.py`) exits 0 only if make exited
0, every test named in the `test:` recipe actually ran, and no failure or
crash marker appears; it prints `GATE LOG AUDIT OK` or `GATE LOG AUDIT
FAILED` with the tests that never ran. Read its exit status directly, never
through a pipe (a pipeline reports the last command's status), and do not
grep the log for failure words: a gate whose `test:` recipe never ran because
a prerequisite failed to link contains no `FAIL` lines.

Deploy:

```sh
cp -a daemon/bitcoind daemon/bitcoind.deploy-$(date +%Y%m%d)a   # next free letter
ln -sfn bitcoind.deploy-$(date +%Y%m%d)a daemon/bitcoind.live
sudo systemctl restart bmc-bitcoind
```

Letters advance per deploy on the same day (`a`..`z`, `aa`, ...). Never
`cp` onto the path of a running binary (`ETXTBSY`); write a new name and
relink. Copy the wallet files (see *Backup*) before a deploy that changes
wallet or index formats.

Rollback:

```sh
ln -sfn bitcoind.deploy-<previous> daemon/bitcoind.live
sudo systemctl restart bmc-bitcoind
```

## Verifying a restart

The RPC server comes up about 40 s after start on the reference host; allow
about a minute. Check, in order:

```sh
systemctl is-active bmc-bitcoind
ss -ltnp | grep bitcoind             # P2P, RPC, onion target, ZMQ endpoints
daemon/bitcoin_cli -datadir=/path/to/repo/data getblockcount
```

Expected lines in `logs/<chain>/bitcoin.<chain>.log`, in order:

```
===== bmc-bitcoind  LOG START: ...   pid N  vX.Y.Z  built ...  mode=serve
[config] loaded <path>: N setting(s) applied
[net] BIP324 v2 transport enabled (services=0x...); N of M known peers advertise v2
[boot] chain=<chain> datadir=<datadir>/<chain> port=<p> dnsseed=<0|1>
[boot] tx-validation snapshot ready (NN.NNs) -- inbound peers inherit it
[boot] chain archive loaded: tip=<h> (N.NNs)
[boot] archive check clean (N.NNs)         # or "found N problem(s) -- see [check] lines above"
[boot] catch-up check done: N block(s) written
[boot] boot phase complete (NN.NNs total)
[rpc] no rpcuser/rpcpassword -- using cookie authentication
[rpc] encrypted wallet adopted and unlocked from the configured passphrase source
                                           # or "adopted (locked -- use walletpassphrase)"
[rpc] JSON-RPC server on 127.0.0.1:<rpcport> (live-node + chain, user=...)
[rpc] cookie authentication enabled (.cookie, mode 0600)
[utxo_live] init dir=... reload applied_height=<h> manifest_n=N live=<count>
[mempool] loaded mempool.dat: N accepted, M rejected of T (...)
[tor] onion service <addr>.onion:<port> -> 127.0.0.1:<port+1> (key onion_v3_private_key)
serving on port <p> (N outbound peer(s))...
```

`applied_height` equals the archive tip once caught up, and the heartbeat's
`tip` tracks the network within a block. The mempool reload runs after the
RPC server is listening, so `getrawmempool` is briefly partial. The onion
service line appears a few minutes after start.

## Operating

### Logs

- **Console log**: `logs/<chain>/bitcoin.<chain>.log` (systemd stdout/stderr):
  `[boot]`, `[config]`, `[rpc]`, `[dl]`, `[tx_accept]`, `[tor]`, `[zmq]`.
- **Daemon's own leveled log**: `<datadir>/<chain>/logs/bitcoind.log`.
- `journalctl -u bmc-bitcoind` holds only systemd's lines (start, stop,
  `Killing` on a stop timeout).

### Lines to monitor

| line | meaning |
|---|---|
| `[dl] heartbeat: tip=.. peers=a/b txouts=.. uptime=..` | the pulse; tip should track the network |
| `[tx_accept] last 30s: +N accepted (mempool M) \| rejected: N missing-inputs, N invalid, N policy \| N already confirmed` | relay summary; missing-inputs rejects are normal churn |
| `[txrelay] last 60s ...`, `[txrelay] orphans: ...` | relay and orphan-pool counters |
| `[mempool] block <h>: removed N pool tx (confirmed/conflicted)` | a block connected |
| `compaction of N run(s) ... started in background pid P` / `background compaction done in Xs` | UTXO maintenance |
| `RECOVERY: rolled back N ghost block(s)`, `rolled back ghost application`, `init: swept N orphan file(s)` | healthy crash recovery at boot |
| `REJECT`, `FATAL`, `DEGRADED`, `ghost-rollback FAILED`, `INCONSISTENT` | alert on these |

### RPC access

```sh
daemon/bitcoin_cli -datadir=/path/to/repo/data getblockchaininfo
daemon/bitcoin_cli -datadir=/path/to/repo/data -chain=signet getblockcount
daemon/bitcoin_cli -rpcport=<n> -rpcuser=<u> -rpcpassword=<p> <method> [params...]
```

`gettxoutsetinfo` and `scantxoutset` refuse while the UTXO set is being
written; call again between blocks or stop the daemon for an authoritative
value. `gettxout` retries briefly while the worker is busy.

### Wallet

With `bmcwallet.enc` present the wallet boots locked unless a passphrase
source is configured. `walletpassphrase "<pass>" <seconds>` unlocks it for
that long, `walletlock` re-locks, `walletpassphrasechange` re-wraps in place.
`encryptwallet` on a plaintext `bmcwallet.dat` seals it and writes
`bmcwallet.enc`. There is no recovery without the passphrase.

### Shutdown

`systemctl stop bmc-bitcoind` sends SIGTERM. The parent logs `[serve]
shutting down (signal 15): tip=...`, saves the mempool (`[mempool] saved N
transaction(s) to mempool.dat`), forwards SIGTERM to the download worker
(`[dl] shutting down (signal 15): ...`), runs `shutdownnotify` if set,
removes `.cookie` and the pidfile, and exits. A normal stop takes seconds.
A signal during the UTXO reload exits immediately, leaving the state the
previous clean shutdown left.

If a stop stalls: after `TimeoutStopSec` systemd sends SIGKILL (`journalctl`
shows `Killing`) and boot recovery repairs the interrupted write. To
intervene by hand, identify the process by PID and `readlink
/proc/<pid>/exe` (it points at the deployed snapshot) and signal that PID.
Do not use a broad `pkill -f bitcoind`: other Bitcoin daemons on the host
match it. A compaction child shares the daemon's command line; killing it is
harmless (the merge is redone).

## Backup and recovery

| item | files in `<datadir>/<chain>/` | notes |
|---|---|---|
| wallet | `bmcwallet.enc` (or `bmcwallet.dat` + `bmcwallet.dat.txlog`), `walletkeys.dat`, `walletscan.dat` | copy with the daemon stopped |
| wallet passphrase | `/etc/bmc/wallet.pass` (outside the datadir) | **store separately** from the wallet backup |
| network identity (optional) | `onion_v3_private_key`, `i2p_private_key` | private keys; keep to preserve the `.onion`/`.b32.i2p` address |
| address book (optional) | `peers2.dat` | faster re-bootstrap |
| configuration | `config/bitcoin.conf`, unit file and drop-ins | holds any `rpcauth`/`rpcuser` credential |

The block archive, headers, UTXO store, indexes and `mempool.dat` are
re-downloadable or rebuildable. Never keep the passphrase file with the
wallet files: a backup carrying both is the failure the `walletpassfile`
rules prevent, which is why the daemon refuses a passphrase file inside the
datadir. Do not copy UTXO files or point tools at a datadir while the daemon
writes it; stop it first. `daemon/utxo_setinfo <datadir> --muhash` on a
stopped datadir is the instrument for comparing the set with a trusted
node's `gettxoutsetinfo muhash`.

Recovery:

- **Unclean stop or crash.** Start the service. Boot rolls back any ghost
  block application from `undo_<h>.dat` before anything reads the set,
  sweeps orphan run files and re-applies. No operator action.
- **Missing archive blocks.** The node fills gaps and the tail itself
  (`[boot] checking for archive gaps / missing blocks...`).
- **Corrupt or lost block index.** Set `reindex=1` in `bitcoin.conf` and
  start. Before opening the archive the node rebuilds `index.dat`,
  `headers.dat` and `chainwork.dat` from the `blk*.dat` frames alone --
  every block on disk is re-linked from genesis by prev-hash, the best
  chain by cumulative work wins, and duplicates, orphans, stale forks and
  frames that fail their own proof of work are left out -- then drops the
  UTXO set and the height-positional indexes so they rebuild. The previous
  index files stay as `*.pre-reindex`. The key is one-shot (`reindex.done`
  marks it done); remove it afterwards. The rebuild itself takes seconds
  (an archive of 150,000 blocks in 93 files rebuilds in about five); the
  UTXO rebuild that follows is the long part. The log line to expect is
  `[reindex] rebuilt: tip=<h> from <n> frame(s) in <f> file(s); ...`.
- **Reorg rehearsal.** `asm/tests/reorg_drill <datadir-COPY> --depth N`
  disconnects and reconnects the last N blocks on a copy and requires the
  UTXO walk and tip hash to return to their prior values. It refuses the
  production datadir by path.

## Maintenance

### Archive re-layout

Archives filled by the parallel downloader are not in height order, and every
boot reports `[check] block data is NOT laid out monotonically (first break
at height H) -- truncation and pruning will refuse to run`. This is
informational; only truncation and pruning refuse.

`tests/tool_archive_relayout <archive-dir> <out-dir>` reads `index.dat`,
copies every block frame into new `blk*.dat` files in height order (128 MiB
rotation), writes a matching `index.dat`, verifies every block hash and
leaves the result in `<out-dir>`. It reads only index-committed frames, so it
can run against a live daemon; blocks appended meanwhile are not captured and
are re-fetched at the next boot. The swap is done stopped:

```sh
tests/tool_archive_relayout /path/to/data/main /path/to/scratch/main-relayout
sudo systemctl stop bmc-bitcoind
mkdir /path/to/backup && mv /path/to/data/main/blk*.dat /path/to/data/main/index.dat /path/to/backup/
mv /path/to/scratch/main-relayout/* /path/to/data/main/
sudo systemctl start bmc-bitcoind
```

Keep the old files until the new boot's archive check is clean; they are the
rollback. The scratch copy needs as much space as the archive.

## Troubleshooting

| symptom | cause and action |
|---|---|
| `bitcoin_cli` connection refused right after start | RPC is not up yet. Boot runs config, the tx-validation snapshot (tens of seconds), archive load and check, catch-up check and hash index before starting RPC (about a minute). Wait for `[rpc] JSON-RPC server on ...`. |
| active service, but no RPC ever | `rpcport` equals `port` (the RPC bind is lost), or no credential source exists. Read the `[rpc]` lines. |
| bind failure at start / node exits | The port is in use. `ss -ltnp \| grep :<port>` shows the PID holding it: a stale daemon from a previous run or another node. Stop that PID. |
| `systemctl stop` stalls | See *Shutdown*. After `TimeoutStopSec` systemd SIGKILLs; boot recovery repairs the interrupted write. |
| `[zmq] notification ring overrun: N transaction(s) not published (total T)` | Producers lapped the 64-slot ring (typical during the mempool reload). Harmless unless a subscriber needs every event; a subscriber must resync via RPC on a per-topic sequence gap, as with Core. Logged at most once a minute; the total is cumulative. |
| `missing-inputs` rejects in the `[tx_accept] last 30s` summary | Normal relay churn (parents not yet seen). The summary is the record; there is no per-event line. |
| `[tor] no onion service: ...` | Control-port authentication failed or the port is unreachable. Check `torcontrol=`, cookie readability (`SupplementaryGroups=debian-tor`) or set `torpassword=`. Outbound onion is unaffected. |
| `[dial] no IPv6 on this host: ipv6 and cjdns peers are unreachable` | Enable host IPv6 (and run `cjdroute`) for `cjdnsreachable=1`. |
| `[wallet] walletpassfile "..." not usable: <why>` / `is inside the datadir -- refusing` | Fix path and mode (absolute, outside the datadir, 0640 or stricter, not group-writable). The wallet stays locked until then. |
| `[boot] archive check found N problem(s)` | Read the `[check]` lines above it. The non-monotonic layout notice is expected on a parallel-downloaded archive (see *Maintenance*); other findings name the height. |
| a second `bitcoind` with the same command line | A compaction child. Check `/proc/<pid>/exe` and the parent PID before assuming a duplicate daemon; never run two daemons on one chain directory. |

## Running more than one chain

One `bitcoin.conf` selects one chain, so a second chain needs its own
configuration:

1. **Separate datadir.** Give the second chain its own datadir root with its
   own `bitcoin.conf` (`chain=signet`, distinct `port=`/`rpcport=`) and start
   a second daemon on it, by hand or as a copy of the unit with a different
   name, `ExecStart` datadir and log path (`logs/signet/bitcoin.signet.log`,
   already covered by the logrotate glob).
2. **Wrapper datadir with a symlinked chain directory.** The wrapper
   `<wrapper>/bitcoin.conf` selects the chain and `<wrapper>/<chain>/` holds
   the state, while `<maindatadir>/<chain>` is a symlink to
   `<wrapper>/<chain>`. The main datadir then shows every chain under one
   root, and each daemon reads its own configuration.

Ports must not collide between daemons. Each daemon writes its own `.cookie`
in its chain directory, so `bitcoin_cli -datadir=<that datadir>` resolves
the right one. Regtest and testnet4 configurations usually pin peers with
`connect=<ip:port>`, which disables discovery and DNS seeding.

## Reference

### Default ports per chain (`asm/daemon/chainparams.c`)

| chain | P2P | RPC | magic (wire) |
|---|---|---|---|
| main | 8333 | 8332 | `f9 be b4 d9` |
| testnet4 | 48333 | 48332 | `1c 16 3f 28` |
| signet | 38333 | 38332 | `0a 03 cf 40` (derived from the challenge) |
| regtest | 18444 | 18443 | `fa bf b5 da` |

Extra listeners: onion service target at chain default P2P port + 1
(loopback); ZMQ endpoints as configured (commonly 28332/28333).

### File inventory (`<datadir>/<chain>/`)

| file | contents |
|---|---|
| `blk*.dat`, `index.dat` | block archive (framed blocks, 128 MiB rotation) and positional height index (48-byte records) |
| `headers.dat`, `chainwork.dat` | header chain and cumulative work |
| `utxo.dat`, `utxo_run_*.dat`, `utxo_manifest.dat`, `utxo_applied_height.dat`, `utxo_lsm_*.map` | LSM UTXO store: WAL, sorted runs, manifest, applied height, memtable maps |
| `undo_<h>.dat` | per-block undo data for the recent tail (reorg and crash rollback) |
| `append.lock` | archive append lock |
| `mempool.dat` | mempool saved at shutdown, reloaded after RPC start |
| `peers2.dat` (`peers.dat` legacy) | address book |
| `.cookie` | RPC cookie, mode 0600, removed at shutdown |
| `bmcwallet.enc` / `bmcwallet.dat` (+ `.txlog`), `walletkeys.dat`, `walletscan.dat` | wallet container / plaintext store and journal, HD keys, rescan records |
| `onion_v3_private_key`, `i2p_private_key` | persisted onion service key and I2P destination |
| `txindex.dat` + `txindex.tail`, `addr_index.dat`, `bfilters.dat` + `bfilters.idx`, `coinstats.dat` | optional indexes |
| `logs/bitcoind.log` | the daemon's own leveled log |

Outside the chain directory: `<datadir>/bitcoin.conf` or
`<repo>/config/bitcoin.conf`; `<repo>/logs/<chain>/bitcoin.<chain>.log`;
`<repo>/asm/daemon/bitcoind.live` and `bitcoind.deploy-*`;
`<repo>/config/logrotate-bmc.conf`.
