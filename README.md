# Bitcoin Machine Code

Bitcoin Machine Code (`bmc`) is a full validating Bitcoin node for Linux
x86-64, written in hand-authored NASM assembly with a C orchestration layer.
Every line of assembly and C in the tree is AI-authored. It downloads and
verifies the chain from genesis with full script verification (no
`assumevalid`), maintains a chain-scale UTXO set that matches Bitcoin Core's
chainstate entry for entry, runs a Core-style mempool and transaction relay,
serves Bitcoin Core's JSON-RPC surface, maintains the optional `txindex`,
`coinstatsindex` and `blockfilterindex` indexes, and includes an HD wallet
with at-rest encryption. It speaks the Bitcoin P2P protocol over IPv4, IPv6,
Tor, I2P and CJDNS, with BIP324 encrypted transport, and runs on mainnet,
testnet4, signet (public or custom) and regtest.

> **Status: experimental.** The code has been through internal and external
> security review (see `docs/audits/`) but has not received an independent
> human audit of its consensus and cryptographic assembly. Run it for study
> and evaluation, on a machine you can afford to lose, with no funds near it.
> For a production node, run [Bitcoin Core](https://bitcoincore.org).

## Highlights

**Consensus and validation**

- Full script verification on every block from genesis: legacy, P2SH,
  segwit v0 (BIP143), taproot key-path and script-path (BIP341/342), BIP30,
  BIP141 witness commitment, CSV/CLTV/NULLDUMMY at Core's activation heights,
  `MAX_MONEY` range checks, and exact `nBits` schedule enforcement
  (`bad-diffbits`) including testnet4's min-difficulty rules and BIP94.
- Script-verification flags are generated from Bitcoin Core's own source
  (`validation/gen_script_flags.py`), including the historical exception
  blocks matched by hash.
- `assumevalid` is parsed and deliberately ignored: every signature in every
  block is verified.
- Signet (BIP325) block-signature enforcement through the same script
  interpreter used for transactions.
- Reorg handling with cumulative-work fork choice, an undo log, and crash
  recovery of a partially applied block.

**Storage**

- One append-only framed block archive (`blk*.dat` + positional `index.dat`
  + `headers.dat` + `chainwork.dat`) per chain.
- A custom LSM UTXO store: bounded memtable, sorted Bloom-filtered runs,
  leveled compaction in a background child process, WAL-checkpointed.
- The stored set holds exactly what Core's chainstate holds (provably
  unspendable outputs are filtered at write time); its MuHash3072 digest is
  compared against Core's `gettxoutsetinfo muhash` as the parity check.
- Pruning (`prune=<MiB>`), with whole-file-granular deletion and a refusal to
  delete anything below a sync hole.
- Startup verification (`checkblocks`/`checklevel`) at Core's defaults;
  `reindex-chainstate`.

**Mempool (Core policy)**

- Byte-budgeted pool (`maxmempool`) shared across all node processes, with
  Core's `TrimToSize` feerate eviction, blob compaction, and a dynamic
  `mempoolminfee`.
- BIP125 replace-by-fee with full-RBF on by default; ancestor/descendant
  limits and Core v31's cluster limits (64 transactions / 101 kvB) measured
  on the post-replacement diagram.
- TRUC (BIP431 / v3) topology rules, ephemeral dust, `submitpackage` with
  child-pays-for-parent effective feerate, and 1-parent-1-child (1p1c)
  package relay.
- Taproot witness standardness, `datacarrier`/`datacarriersize`,
  `permitbaremultisig`, `dustrelayfee`, `minrelaytxfee`,
  `incrementalrelayfee`, `mempoolexpiry`, `acceptnonstdtxn`.
- Mempool admission runs the consensus verifier (legacy + full taproot)
  against the confirmed set plus in-mempool parents.
- `mempool.dat` persistence in Core's format (`persistmempool`,
  `savemempool`, `importmempool`); `estimatesmartfee` over the node's own
  accepted-feerate estimator.

**P2P and relay**

- Headers-first initial sync with a chunk-claiming, work-stealing parallel
  block downloader; inbound serving starts as soon as the listener is bound.
- Transaction relay with witness-complete fetching, an orphan pool with
  parent fetch, re-announcement to peers, per-peer `notfound` memory, and
  `MSG_TX`/`MSG_WITNESS_TX` `getdata` service.
- BIP339 `wtxidrelay`, BIP144 witness transport with witness-only peer
  preference, stripped-block serving to legacy peers, `sendheaders`,
  `feefilter`.
- BIP152 compact blocks in both directions.
- BIP157/158 compact block filter serving (`getcfilters`, `getcfheaders`,
  `getcfcheckpt`) backed by the whole-chain filter index.
- BIP324 v2 encrypted transport, inbound and outbound, with in-band v1
  fallback (`v2transport`, default on).
- BIP155 `addrv2` with a version-2 address book covering all five networks
  (IPv4, IPv6, Tor onion v3, I2P, CJDNS), `getaddr` gossip ingest, self-
  address advertisement, `addpeeraddress`.
- Misbehaviour scoring and banning (`setban`/`listbanned`/`clearbanned`,
  `bantime`), `whitelist` (noban) and `whitebind`, `asmap` bucketing,
  `minimumchainwork`, `maxuploadtarget`, `blocksonly`.

**Wallet**

- HD wallet (BIP32/BIP39); `getnewaddress` hands out bech32 addresses; signs
  P2PKH, P2SH multisig, P2WPKH, P2WSH and P2TR spends.
- At-rest encryption (`encryptwallet`, `walletpassphrase`,
  `walletpassphrasechange`, `walletlock`) using AES-256-CBC under Core's
  `BytesToKeySHA512AES` key derivation.
- PSBT: `createpsbt`, `decodepsbt`, `converttopsbt`, `combinepsbt`,
  `joinpsbts`, `analyzepsbt`, `finalizepsbt`, `utxoupdatepsbt`,
  `walletprocesspsbt`.
- Descriptors and watch-only: `importdescriptors`, `listdescriptors`,
  `createwalletdescriptor`, `addhdkey`, `exportwatchonlywallet`.
- Wallet lifecycle: `createwallet`, `loadwallet`, `unloadwallet`,
  `restorewallet`, `listwallets`; `bumpfee`/`psbtbumpfee` with Core's
  feebumper arithmetic; branch-and-bound coin selection; external signer
  (`signer=`, HWI-style); message signing.

**RPC, indexes and notifications**

- Bitcoin Core's JSON-RPC method set (155 methods; only `rpc.discover` is
  absent), with Core's result shapes, error codes and messages. See
  [`docs/RPC_LIVE_NODE.md`](docs/RPC_LIVE_NODE.md).
- `txindex`, `coinstatsindex` (incremental MuHash, so `gettxoutsetinfo`
  answers without a UTXO walk) and `blockfilterindex` (BIP158 basic filters
  plus the filter-header chain), all tip-following; `getindexinfo`.
- `addrindex` (an extension with no Core equivalent): `getaddressbalance`
  and `getaddresstxids`.
- `getblocktemplate`/`submitblock`/`submitheader`,
  `prioritisetransaction`, `dumptxoutset` (assumeutxo snapshot export).
- ZMQ publishers for `hashblock`, `hashtx`, `rawblock`, `rawtx` with per-topic
  high-water marks; `blocknotify`, `alertnotify`, `startupnotify`,
  `shutdownnotify` shell hooks.

**Chains**

- `main`, `testnet4`, `signet` (public, or a custom `signetchallenge` whose
  network magic is derived from the challenge) and `regtest`. Legacy
  testnet3 is refused rather than run under the wrong rules.

## Requirements

- Linux on x86-64. The assembly is NASM ELF64 targeting the System V ABI;
  nothing else runs it.
- `nasm`, `gcc`, GNU `ld`, `make`, and `python3` (build tooling, audits and
  test oracles).
- Disk: about 1 TB for a full mainnet archive plus the UTXO store. A pruned
  node fits in a few GB.
- Memory: several GB. The UTXO memtable (`dbcache`, default 1024 MiB) grows
  to multiple GB in bulk catch-up mode during initial sync.
- Optional: a `tor` daemon (SOCKS and control port), an I2P router with the
  SAM bridge (`i2pd`), and `cjdroute` for the respective networks.
- Optional: a CUDA toolchain and NVIDIA GPU for the `asm/cuda/` batch-hash
  tier; the dispatcher falls back to CPU without it.

## Build

```sh
cd asm
make daemon/bitcoind      # the node daemon (asm/daemon/bitcoind)
make test                 # the full gate: audits + every test harness
```

`make` with no target is `make test`. The gate runs about 290 test binaries
(crypto vectors, consensus differentials against Bitcoin Core, mempool
policy, P2P codecs, BIP324 vectors, RPC shapes, storage and crash-recovery
cases) after a set of static audits that run in the first seconds:

| audit | checks |
|---|---|
| `abi-check` / `callee-saved-check` | every C-to-asm call site honours the SysV stack-alignment and callee-saved contract |
| `prereq-check` | no Makefile recipe reads a file it does not declare as a prerequisite |
| `link-check` | every rule links the object that defines each symbol its sources need |
| `runlist-check` | every test is either in the gate or declared manual with a reason |
| `gate-log-check LOG=<file>` | a saved gate log shows make exiting 0 and every gated test actually executed |

Other binaries built under `asm/daemon/`: `bitcoin_cli` (Core-compatible
JSON-RPC client), `cli` (query the stored chain directly), `wallet_cli`,
and the archive tools (`check_chain`, `verify`, `dumpblock`, `unified_ibd`,
`chainctl`).

## Quick start

1. **Create a configuration.** Copy the reference file and edit it:

   ```sh
   cp config/bitcoin.sample.conf config/bitcoin.conf
   ```

   The daemon reads `<datadir>/bitcoin.conf`, then `<datadir>/../config/bitcoin.conf`,
   or the path in `$BITCOIN_CONF`. The file is shared by every chain; keep
   it at the datadir root, not inside a chain subdirectory.

2. **Run the daemon.**

   ```sh
   asm/daemon/bitcoind serve /path/to/datadir [port] [nwant] [workers]
   ```

   `serve` is the production mode: it binds the P2P listener, discovers
   peers, syncs headers, fills any archive gap with parallel download
   workers (default 16), builds the UTXO set with full script verification,
   then follows the tip while serving inbound peers and RPC. A first mainnet
   sync takes days and is CPU-bound on signature verification. The `[dl]
   heartbeat:` log line reports tip height, live peers, UTXO count and uptime.
   The daemon honours `SIGTERM` and the `stop` RPC.

3. **Talk to it.** Cookie authentication is on by default:
   `<datadir>/<chain>/.cookie` is written (mode 0600) at startup and deleted
   at shutdown. `bitcoin_cli` resolves the port and cookie from the datadir:

   ```sh
   asm/daemon/bitcoin_cli -datadir=/path/to/datadir getblockchaininfo
   asm/daemon/bitcoin_cli -datadir=/path/to/datadir -signet getblockcount
   ```

   Any JSON-RPC client works, including Bitcoin Core's `bitcoin-cli` and
   `curl`:

   ```sh
   curl --user "$(cat /path/to/datadir/main/.cookie)" \
        --data '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' \
        http://127.0.0.1:8332/
   ```

**Datadir layout.** Every chain lives in its own subdirectory, mainnet
included:

```
<datadir>/
  bitcoin.conf                 shared configuration (optional location)
  main/                        one directory per chain: main, testnet4, signet, regtest
    blk*.dat index.dat headers.dat chainwork.dat     block archive
    utxo.dat utxo_run_*.dat utxo_manifest.dat ...    LSM UTXO store
    txindex.dat, filters, coinstats, addrindex       optional indexes
    peers2.dat                 address book (all networks)
    bmcwallet.enc | bmcwallet.dat, *.txlog           wallet store and journal
    mempool.dat                mempool persistence
    .cookie                    RPC cookie (while running)
    logs/bitcoind.log          the daemon's own leveled log
```

**Running under systemd.** A minimal unit:

```ini
[Unit]
Description=Bitcoin Machine Code daemon
After=network-online.target

[Service]
User=bitcoin
WorkingDirectory=/path/to/repo/asm
ExecStart=/path/to/repo/asm/daemon/bitcoind serve /path/to/datadir
StandardOutput=append:/path/to/repo/logs/main/bitcoin.main.log
StandardError=append:/path/to/repo/logs/main/bitcoin.main.log
Restart=on-failure
KillSignal=SIGTERM
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
```

The console log (boot banner, `[config]` echo, `[net]`/`[rpc]`/`[tor]`
state, heartbeats) goes wherever the unit sends stdout/stderr; the
convention is `logs/<chain>/bitcoin.<chain>.log` under the repository, with
`config/logrotate-bmc.conf` as the logrotate configuration. A boot takes a
couple of minutes (archive reload, UTXO load, tx-validation snapshot) before
RPC answers; give shutdown time for a UTXO flush. To create an onion service
the service account needs read access to tor's control cookie
(`SupplementaryGroups=debian-tor` on Debian-family hosts).

## Configuration

[`config/bitcoin.sample.conf`](config/bitcoin.sample.conf) lists every key
the node reads at its default value and is the reference. Keys are Bitcoin
Core's names and units; unknown keys are ignored with a message, and any
Core option the node does not implement is named at startup as having no
effect. Values are read once at startup. The `[config]` block in the console
log echoes the resolved values.

| key | default | meaning |
|---|---|---|
| `chain` | `main` | `main`, `testnet4`, `signet`, `regtest`; `testnet4=1` / `signet=1` / `regtest=1` are the boolean forms |
| `signetchallenge` | public signet | hex challenge for a custom signet; determines the network magic |
| `listen` / `port` / `bind` | `1` / chain default / all interfaces | inbound P2P; ports 8333 main, 48333 testnet4, 38333 signet, 18444 regtest. IPv6 listens alongside IPv4 |
| `connect` / `addnode` / `seednode` / `dnsseed` | — / — / — / `1` | outbound peer policy; `connect=` disables discovery |
| `maxconnections` / `timeout` / `peertimeout` | `200` / `5000` ms / `60` s | connection budget and timeouts |
| `rpcport` | chain default | 8332 main, 48332 testnet4, 38332 signet, 18443 regtest |
| `rpccookiefile` / `rpcauth` / `rpcuser`+`rpcpassword` | cookie | authentication; `rpcauth` is Core's salted-HMAC format, repeatable |
| `rpcbind` / `rpcallowip` | loopback / none | listener address (IPv4) and per-connection allow list; `rpcbind` is ignored without `rpcallowip`, as in Core |
| `proxy` / `onion` / `proxyrandomize` | — / `proxy` / `1` | SOCKS5 proxy for all networks / for `.onion` only; per-connection credentials for stream isolation |
| `torcontrol` / `torpassword` / `listenonion` | `127.0.0.1:9051` / — / `1` | control port used to create the node's own onion service |
| `i2psam` / `i2pacceptincoming` | — / `1` | SAM bridge address; empty disables I2P |
| `cjdnsreachable` | `0` | declare the host's CJDNS `fc00::/8` interface reachable |
| `onlynet` / `discover` / `externalip` / `dns` | — / `1` / — / `1` | network restriction (repeatable), self-address learning, resolver use |
| `v2transport` | `1` | BIP324 encrypted transport inbound and outbound |
| `maxmempool` / `mempoolexpiry` | `300` MiB / `336` h | mempool budget and age limit |
| `minrelaytxfee` / `incrementalrelayfee` / `dustrelayfee` | Core defaults | relay floors, BTC/kvB |
| `limitancestorcount` / `limitdescendantcount` / `*size` | `64` / `64` / `101` kvB | chain limits; 64 admits the same chains Core's cluster limit admits |
| `mempoolfullrbf` / `datacarrier` / `datacarriersize` / `permitbaremultisig` / `acceptnonstdtxn` | `1` / `1` / `100000` / `1` / `0` | relay policy |
| `bytespersigop` | `20` | fee rate is judged against `max(vsize, sigops * bytespersigop / 4)` |
| `dbcache` | `1024` MiB | UTXO memtable sizing |
| `par` | `0` (auto) | script-verification threads |
| `prune` | `0` | `0` off, `1` manual-only, `>=550` target size in MiB |
| `txindex` / `addrindex` / `blockfilterindex` / `coinstatsindex` | `0` / `0` / `1` / `1` | optional indexes; `txindex` is adopted automatically when `txindex.dat` exists |
| `checkblocks` / `checklevel` / `stopatheight` / `minimumchainwork` | `6` / `3` / `0` / chain default | startup verification and sync bounds |
| `persistmempool` | `1` | reload `mempool.dat` at boot, write it at shutdown |
| `walletpassfile` | — | absolute path, outside the datadir, to the wallet passphrase; refused if world-readable, group-writable or inside the datadir |
| `disablewallet` | `0` | `1` loads no wallet; wallet RPCs report that none is loaded |
| `debuglogfile` | `logs/bitcoind.log` | the daemon's own leveled log, relative to the chain directory or absolute; `0` disables it |
| `signer` | — | external signer command |
| `zmqpubhashblock` / `zmqpubhashtx` / `zmqpubrawblock` / `zmqpubrawtx` (+`hwm`) | — | ZMQ endpoints; `tcp://*` is refused, name an interface |
| `blocknotify` / `alertnotify` / `startupnotify` / `shutdownnotify` | — | shell hooks; `%s` is sanitised before substitution |
| `whitelist` / `whitebind` / `asmap` / `bantime` / `maxuploadtarget` / `blocksonly` | — / — / — / `86400` / `0` / `0` | peer permissions, AS bucketing, bans, upload budget, no tx relay |
| `bmc.utxocompactthreshold` / `bmc.bootcatchup` | `12` / `1` | project-specific: UTXO runs that trigger compaction; run the parallel downloader at boot |

## Networks: Tor, I2P, CJDNS, IPv6

- **IPv4 and IPv6** need no configuration. With `listen=1` the node opens a
  v6-only listener beside the IPv4 one and dials IPv6 peers whenever the host
  has IPv6 connectivity. Restrict with `onlynet`.
- **Tor.** Reaching `.onion` peers needs a SOCKS5 port (`onion=127.0.0.1:9050`
  or `proxy=`). With `listenonion=1` and a reachable `torcontrol` port the
  node creates its own ephemeral v3 onion service (ED25519 key persisted in
  the datadir) that targets a loopback-only listener, keeps the control
  connection open for the daemon's lifetime, and announces the onion address
  to onion peers only. Cookie authentication on the control port is used
  when offered; `torpassword` is the fallback. Setting `proxy=` also stops
  the node using the system resolver for peer hostnames (names are handed to
  the proxy), skips the DNS seeds, gives every proxied connection its own
  SOCKS5 credentials (`proxyrandomize`) so Tor isolates circuits, and never
  advertises a clearnet address to an onion or I2P peer. A Tor-only node is
  `onion=127.0.0.1:9050`, `onlynet=onion`, `discover=0`.
- **I2P.** `i2psam=127.0.0.1:7656` points at a router's SAM 3.1 bridge. The
  node keeps one destination across restarts (`i2p_private_key` in the
  datadir) and dials I2P peers through it. Inbound I2P streams are not
  accepted.
- **CJDNS.** A CJDNS address is an `fc00::/8` IPv6 address on `cjdroute`'s
  tun interface, so it needs working IPv6 on the host. The node cannot detect
  the interface; set `cjdnsreachable=1` to enable dialing and accepting CJDNS
  peers.
- `getnetworkinfo` reports the real per-network reachability, the onion
  service hostname and the I2P destination under `localaddresses`; all five
  networks are stored in the address book, relayed via `addrv2`, and
  returned by `getaddr`.

## RPC and compatibility

- The embedded HTTP JSON-RPC server binds loopback by default (`rpcbind` +
  `rpcallowip` to change that), speaks Core's HTTP/JSON-RPC 1.0/2.0
  envelopes, and serves Bitcoin Core's method set with Core's field shapes,
  error codes and messages. `help` is generated from the dispatch tables.
- Authentication: the cookie (Core's `__cookie__:<hex>` format), `rpcauth`
  entries produced by Core's `share/rpcauth/rpcauth.py`, or
  `rpcuser`/`rpcpassword`. The server refuses to start with no credential
  available.
- Methods that need live node state (`getpeerinfo`, `getmempoolinfo`,
  `sendrawtransaction`, `gettxout`, `submitblock`, ...) are bridged across the
  daemon's fork boundary through shared memory and control channels; the
  design and the per-category method notes are in
  [`docs/RPC_LIVE_NODE.md`](docs/RPC_LIVE_NODE.md), and the method-by-method
  verification record is in [`docs/PARITY_PLAN.md`](docs/PARITY_PLAN.md).
- A method the node cannot honour returns an explicit refusal naming the
  gap rather than an approximate answer.
- ZMQ: a native ZMTP 3.1 PUB implementation (no libzmq dependency) publishes
  `hashblock`, `hashtx`, `rawblock` and `rawtx`; `getzmqnotifications` lists
  the endpoints. Subscribers that observe a sequence gap resynchronise via
  RPC, as with Core.
- Wire identity: user agent `/BitcoinMachineCode:0.0.1/`, protocol version
  70016, defined once in `asm/version.inc`.

## Differences from Bitcoin Core

Intentional differences and known gaps, each documented at its call site or
in [`docs/FEATURE_GAPS.md`](docs/FEATURE_GAPS.md):

- **Storage format.** Blocks live in the project's own framed archive and
  the UTXO set in a custom LSM store, not `blk*.dat` + LevelDB. Core
  datadirs are not interchangeable with this node's. `-reindex` does not
  exist; archive repair truncates and re-downloads instead
  (`reindex-chainstate` is supported).
- **Mempool eviction is per-leaf.** `TrimToSize` evicts the lowest-feerate
  leaf transaction and works inward, where Core evicts by linearization
  chunk. Sibling eviction is not implemented.
- **`assumevalid` is ignored.** Every block is fully script-verified.
- **`gettxoutsetinfo` defaults to `muhash`**; `hash_serialized_3` is refused,
  and the coinstats "extras" beyond the core fields are omitted (stated in
  the result).
- **`addrindex`** and the `getaddressbalance`/`getaddresstxids` methods are
  an extension with no Core equivalent.
- **ZMQ `sequence` topic** is refused by configuration rather than
  published; the other four topics are supported.
- **Wallet.** There is no general descriptor engine; `descriptorprocesspsbt`
  refuses rather than guessing, and `createwalletdescriptor` answers only for
  the address type the wallet holds.
- **Mining.** `getblocktemplate` reports a lower-bound `sigops` and orders
  transactions validly but not fee-optimally; BIP23 proposal mode and any
  stratum/pool interface are absent.
- **Erlay (BIP330).** The `sendtxrcncl` negotiation is implemented and
  tested but not emitted on the wire; reconciliation rounds are not built.
- **Not implemented:** REST interface, UPnP/NAT-PMP, BIP37 bloom filters
  (`peerbloomfilters`), `whitelistrelay`/`whitelistforcerelay`, GUI,
  `loadtxoutset` (assumeutxo import; export via `dumptxoutset` works),
  inbound I2P, `walletnotify`, `maxtxfee` enforcement, `uacomment`,
  `rpcthreads`/`rpcworkqueue`, `includeconf`/`settings`. Each unimplemented
  Core option is named in the startup log when set.
- **Chains.** Legacy testnet3 (`testnet=1`, `chain=test`) is refused.
- **One relay edge.** A transaction announced exactly once during a leg's
  sync pass can be drained unexamined; Core's periodic re-announcement
  delivers it on the next pass.

## Documentation map

| document | contents |
|---|---|
| [`docs/README.md`](docs/README.md) | index of everything under `docs/` |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | operations guide: running, configuring, monitoring, upgrading and recovering the node |
| [`docs/RPC_LIVE_NODE.md`](docs/RPC_LIVE_NODE.md) | the embedded JSON-RPC server and its methods |
| [`docs/FEATURE_GAPS.md`](docs/FEATURE_GAPS.md) | what the node does and does not implement, against Bitcoin Core |
| [`docs/PARITY_PLAN.md`](docs/PARITY_PLAN.md) | how parity with Core is established and checked, method by method |
| [`docs/ENGINEERING.md`](docs/ENGINEERING.md) | architecture, binaries and command lines, on-disk formats, validation gates |
| [`docs/ENGINEERING_RULES.md`](docs/ENGINEERING_RULES.md) | the rules the codebase is written under |
| [`docs/ABI_STACK_ALIGNMENT.md`](docs/ABI_STACK_ALIGNMENT.md) | the SysV stack-alignment contract and the audit that enforces it |
| [`docs/audits/`](docs/audits/) | external security audits and the project's responses |
| [`docs/devlog/`](docs/devlog/) | development log: incident log, plans, benchmarks, assessments |
| `worklog/` | dated development action logs |
| [`config/bitcoin.sample.conf`](config/bitcoin.sample.conf) | every configuration key at its default |
| [`validation/`](validation/) | differential test corpus and oracle scripts against Bitcoin Core |

## Status

Experimental software, AI-authored throughout, verified differentially
against Bitcoin Core rather than independently audited by humans. It is not
a replacement for Bitcoin Core and should not hold funds.
