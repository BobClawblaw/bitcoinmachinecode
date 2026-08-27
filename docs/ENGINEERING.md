# Bitcoin Machine Code — Engineering & Operations Reference

**Living document.** This is the authoritative technical reference for how the
software in this repository works: what it is, how it is built, how each
binary is invoked, the on-disk formats, the operational procedures, and the
validation/compliance gates. It is intended to be **updated as features
mature** and must be maintained in step with `README.md` (user-facing
overview / status), `PLAN.md` (roadmap + verified state), `LOG.md` (long-form
engineering history), `worklog/` (terse daily log), and `KANBAN.md` (task
board mirror).

> **Companion documents — read these first for context**
> - `README.md` — project overview, delivered/verified feature status,
>   hard-won "golden rules," and the security-untested warning.
> - `PLAN.md` — project plan, exact build/test commands, field/ABI
>   conventions, stage roadmap, and golden rules (superseded designs flagged).
> - `LOG.md` — exhaustive engineering history (bugs, root-cause hunts).
> - `validation/SECURITY_AUDIT.md` — internal security audit status.
> - `worklog/` — terse per-day log of actions + evidence.

---

## 0. What this software is

A Bitcoin node for Linux built as **100% AI-authored x86-64 assembly** (NASM),
verified by C harnesses and Python big-int oracles. Every line of assembly is
written by an AI; the C/Python layers exist only to prove the machine code is
correct against trusted references. The security-critical cryptography
(SHA-256, secp256k1 field/point/scalar arithmetic, ECDSA, Schnorr) is written
directly in assembly.

Two machine roles are implemented in assembly and are exercised against the
**real Bitcoin mainnet**:

1. **Outbound full node** — DNS-seed bootstrap, peer discovery, headers-first
   initial block download (IBD), per-block consensus validation, and durable
   storage of blocks/headers.
2. **Inbound (server) node** — accepts real peers and serves stored blocks /
   headers / compact blocks entirely in assembly.

Above this sits a **wallet / validation bridge** (also AI-authored) that can
generate keys and addresses, derive BIP32/BIP39 wallets, validate and sign
real transactions (legacy P2PKH, P2SH/multisig, P2WPKH/P2WSH, P2TR), and speak
a Bitcoin-Core-compatible JSON-RPC over HTTP.

**Delivered capability, 2026-08-27.** Beyond the roles above, the node now
serves Core's full RPC surface (155/155 methods), runs a Core-style mempool
(byte-budgeted with feerate eviction and a dynamic `mempoolminfee`, all limits
config-wired), maintains live `txindex`, `coinstatsindex` (incremental muhash
proven byte-identical to Core), and BIP158 `blockfilterindex`, encrypts the
wallet at rest (`encryptwallet`/`walletpassphrase`/`walletlock`, Core's
BytesToKeySHA512AES + AES-256), and supports **regtest chain selection** (§4.3). `FEATURE_GAPS.md` is the current gap inventory; `LOG.md` (2026-08-27
entries) has the detail.

**Status:** Inside this repo the internal AI-driven security audit is complete
and green, but the software has **not** had an independent *human* security
audit. Treat it as untrusted until it has. See the warning banner in
`README.md`.

---

## 1. Directory layout

> Current archive state (as of this documentation revision, branch `main`,
> HEAD `62a8225`): `data/` holds ~664 GB of real mainnet block data across
> ~4,851 `blkNNNNN.dat` files. Chain tip is ~962,831 during normal operation;
> the daemon self-heals holes and catches up on every boot.

```
/storage/bitcoinmachinecode/
|-- asm/                      # ALL of the software: assembly core + C glue
|   |-- *.asm                 #   x86-64 NASM modules (the actual node)
|   |-- *.c                   #   C glue / policy / shims (non-node scaffolding)
|   |-- *.o                   #   assembled objects (build artifacts; gitignored)
|   |-- *.inc                 #   include tables (BIP39 wordlist, g_comb_table)
|   |-- build.sh              #   assemble-all + make test + shared libs
|   |-- Makefile              #   make asm | test | clean | <target>
|   |-- config/               #   (now empty; wallet user data moved to data/)
|   |-- cuda/                 #   optional CUDA batch-acceleration tier (crypto)
|   |-- daemon/               #   C orchestration + CLI drivers + tools
|   |-- tests/                #   C harnesses proving each asm module correct
|   |-- validation/           #   Python big-int / Core oracles + differentials
|   `-- wallet_*.c            #   wallet glue (core/store/txlog/msgsign/book)
|-- config/
|   `-- bitcoin.conf          #   RPC/network configuration (bitcoin_rpcd reads)
|-- data/                     #   DURABLE CHAIN STORAGE (single unified archive)
|   |-- blk00000.dat ...      #   append-only framed block files (rolling)
|   |-- index.dat             #   positional height -> (offset/len/hash) index
|   |-- headers.dat           #   persistent header chain (80B hdr + 32B hash each)
|   |-- utxo.dat              #   persistent UTXO write-ahead log (WAL)
|   |-- utxo.idx              #   persistent UTXO checkpoint index
|   |-- utxo_blob.map / utxo_table.map
|   |-- peers.dat             #   persisted peer address book ("amr" book)
|   |-- append.lock           #   flock file serializing shared appends
|   |-- peerclaims*           #   flock-locked per-peer claim table
|   |-- *.log (bitcoind.log, chainctl.log, backfill.log, ...)
|   |-- *.txt / *.dat         #   dev notes (build_utxo_bad_heights.txt etc.)
|   `-- blk*.dat              #   (also see "The durable archive" below)
|-- docs/                     #   <-- this engineering reference lives here
|-- logs/                     #   production daemon logs (bitcoind.*.log)
|-- scripts/                  #   start/stop/status/worklog helpers
|-- seeds.txt                 #   initial DNS seeds list
|-- internet_peers.txt        #   harvested peer list (raw, regenerable)
|-- good_internet_peers.txt   #   verified-good peers (regenerable)
|-- soak/  soak-store/
|   .worktrees/               #   long-duration soak logs/state; git worktrees
|-- validation/               #   (root-level) differential report artifacts
|-- README.md  PLAN.md  LOG.md  KANBAN.md
|-- .gitignore                #   build artifacts + runtime/chain data ignored
`-- worklog/                  #   per-day worklog (YYYY-MM-DD.md), newest top
```

### 1.1 The durable archive (`data/`)

The node stores the whole chain as **one unified, single-directory archive** —
there are no per-worker shards. The directory contains only these files:

- `blk00000.dat` .. `blkNNNNN.dat` — rolling, append-only framed block files.
  Each append is serialized via `flock(append.lock)` (`store_append_shared`);
  every worker opens its **own** fd to `append.lock` because flock locks
  belong to the open file description, not the path — a fork-inherited fd
  would not exclude sibling workers.
- `index.dat` — a positional height→(offset/len/hash?) index, pre-sized and
  grow-only. Records are 48 bytes each, written positionally at `height*48`;
  a record is "present" iff its first 4 bytes are non-zero (sparse pre-sizing
  means the file is normally full of zeroed trailing records).
- `headers.dat` — persistent header chain: one (80-byte header, 32-byte block
  hash) pair per entry = 112 bytes/entry, appended.
- `utxo.dat` / `utxo.idx` — persistent unspent-output store: a framed
  PUSH/DEL write-ahead log (`utxo.dat`, the durable source of truth) plus a
  checkpoint index (`utxo.idx`: a snapshot of the live set + the log offset it
  covers). Restart resume = restore checkpoint, then replay the WAL tail.

The same lock/append discipline protects concurrent writers (the built-in
`dl_catchup` workers, the standalone `unified_ibd` tool, and the continuous
download worker) and makes concurrent serving reads safe.

---

## 2. Build, test, verify

### 2.1 Toolchain requirements

- `nasm` (the Makefile drives `nasm -f elf64`) — repo verified with 2.16.01.
- `gcc` (System V AMD64; `-no-pie -O0/-O2`) — 13.3 used.
- `GNU ld` (2.42), Linux x86_64. Python 3 for the oracles/tests.
- Optional: CUDA toolchain (`nvcc`) + an NVIDIA GPU only for the optional
  `asm/cuda/` tier; the dispatcher itself builds and runs with zero CUDA
  (falls back to CPU).

### 2.2 Build & run the full verification suite

```bash
cd /storage/bitcoinmachinecode/asm

# 1) Assemble every .asm -> .o, build + run every C harness, build ctypes .so
./build.sh

# 2) Or just the test suite (against current objects):
make test

# 3) Targeted builds/clean:
make asm            # assemble all .asm sources only
make clean          # remove generated objects + binaries
```

`make test` builds and runs **146 harness invocations**. Check that count --
`grep -cE '^\t\./' asm/Makefile` -- whenever the suite is green but you did not
expect it to be: a test that stops running looks identical to a test that
passes, and this repository has been bitten by exactly that. **Exit code 0
means the assembly hashes/verdicts match the trusted references.** A few
harnesses are
deliberately large/network-dependent and are **not** part of the default
`test` target (e.g. `tests/test_ibd_scale`, the outbound-mux soak harness,
live-network probes). Several networked/binary-glue harnesses are built at
`-O0` because gcc `-O2` interacts badly with the deep asm call chain — the
assembly is identical; do not "fix" these to `-O2` without re-verifying.

#### Test working directories

The storage layer opens its files by bare relative name (`index.dat`,
`blk%05u.dat`, `utxo.dat`, `headers.dat`, `chainwork.dat`, `peers.dat`, …), so
a harness that links it writes an archive into whatever its CWD happens to be.
Every such harness now calls `tt_isolate()` from `tests/test_tmpdir.h` as the
first statement of `main()`: it `mkdtemp()`s a private directory, `chdir()`s
into it, and removes it on **every** exit path including `SIGSEGV`/`SIGABRT`.

Consequences you can rely on:

- the suite is **order-independent** — no harness can see state another left;
- it is **concurrency-safe** — several harnesses, or several whole suites, can
  run at once, and other work in `asm/` while the suite runs is harmless;
- `make test` in a used tree behaves identically to `make test` in a fresh
  clone, because nothing persists between runs.

Two knobs:

| variable | effect |
|---|---|
| `BMC_TEST_TMPDIR` | root the private directories are created under (default `$TMPDIR`, else `/tmp`). These harnesses write real block data — point this at a filesystem with room if `/tmp` is a small tmpfs. |
| `BMC_TEST_KEEP` | if set and non-empty, keep the directory and print its path, for post-mortem inspection. |

Paths that must still resolve against the source tree after the `chdir` —
fixtures, `daemon/bitcoind`, the shim executables — go through `tt_src("…")`.
A harness that hands a datadir to a forked child or a spawned daemon passes
`tt_workdir()`. When adding a harness that touches storage, add `tt_isolate()`
and list `$(TEST_TMPDIR_H)` in its Makefile prerequisites.

### 2.3 Manually rebuild the daemon binary

`bitcoind.o`, `node_log.o`, and `bitcoin_headers.o` are **not** Makefile
targets — the daemon binary must be rebuilt by hand:

```bash
cd /storage/bitcoinmachinecode/asm
gcc -no-pie -O0 -o daemon/bitcoind daemon/main.c sha256.o bitcoin_hash.o \
    bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o \
    bitcoind.o node_log.o bitcoin_headers.o
```

(Other standalone tools under `asm/daemon/` — `verify`, `check_chain`,
`chainctl`, `unified_ibd`, `dumpblock`, `crawler`, `addrgather`, `peertest`,
etc. — are similarly built ad hoc; see each file's header for the intended
link set, or the `.gitignore` for the expected output names.)

### 2.3b Calling an asm symbol from C: check the real contract

Four separate bugs on 2026-08-27 came from C declaring an asm symbol
differently from what the asm actually does. The compiler cannot catch any of
them, and every one passed the whole test suite:

| symbol | asm truth | what C claimed | consequence |
|---|---|---|---|
| `utxo_lsm_walk` | returns `long` | implicit → `int` | live count truncated to 32 bits |
| `csi_read_file` | defined later in the file | implicit | six pointer args unchecked |
| `tx_txid` | returns `int` (`.fail` is `xor eax,eax`) | `void` in two files | a failed txid computation was invisible; the unwritten buffer was then used to evict mempool entries |
| `tx_wtxid` | sets **no** return value | `int`, checked `!= 1` | read whatever was in `rax`; silently dropped every `submitpackage` result |

So, before declaring one: read the asm's return path. `xor eax, eax` on a
failure label means it returns a value and you must check it. No `eax`/`rax`
write before `ret` means it returns nothing and you must not.

Two of these were only found because a change gave a previously-infallible
path a real failure mode. Prefer one declaration per symbol in a shared
header over a local `extern` per file; where the codebase already has a
declaration, adopt it rather than writing a second one.

### 2.3c Adding a call to a widely-linked object

`rpc_node.o` is linked by roughly a dozen targets. Adding one `tx_wtxid` call
to it broke **ten** of them at link time — the daemon built fine, because the
daemon happens to link `bitcoin_cmpct.o`. Only `make -k test` shows this.

The codebase's convention for an optional dependency is
`__attribute__((weak))` plus a guard that refuses when the symbol is absent
(`bitcoin_mempool_policy.c` does this for `tx_parse`/`tx_txid`). Prefer that
to adding an object to a dozen link lines. Put the guard AFTER parameter
validation, so a malformed call still gets the normal error in every build.

Related, same family: a new `daemon/*.c` must be added to `DIALSRCS` too
(anything `#include`-ing `daemon/main.c` as a TU), and an object must appear
in exactly ONE of the bundles that get linked together — `bitcoin_pow_rules.o`
in both `DAEMON_RPCOBJS` and `DAEMONSRCS` produced "multiple definition" and
a daemon that would not link.

### 2.4 Randomized ctypes stress (optional, shared-lib targets)

```bash
cd /storage/bitcoinmachinecode/asm
python3 tests/inv_stress.py        # fe_inv: 10k iters
python3 tests/stress_scalar.py     # scalar arith: 3k iters
```
(Requires `libsecpfe.so` / `libsecpscalar.so`, built by `build.sh`.)

---

## 3. Binaries and their command lines

All binaries live under `asm/daemon/`. Paths below assume
`cd /storage/bitcoinmachinecode/asm/daemon`.

### 3.1 `bitcoind` — the node daemon (primary deliverable)

`main.c` is a thin CLI driver over the all-assembly node core. It resolves
`<dir>` to an absolute path, `chdir`s into it, and operates on the store there.

```
bitcoind sync  <dir>                  # connect to a built-in loopback fake
                                      # peer, run node_sync (IBD), report height
bitcoind ibd   <dir>                  # FULL IBD as one asm pass (node_ibd =
                                      # headers-first persist + getdata block
                                      # bodies + cons_verify + store)
bitcoind follow <dir>                 # realtime keep-up on one connection
                                      # (re-runs node_sync, inv-announces tip)
bitcoind serve <dir> <port> [nwant] [catchup_workers]
                                      # PRODUCTION MODE: self-healing catch-up,
                                      # then continuous download + inbound serve
bitcoind serve-test <dir> <port> <peer_host> <out_port>
                                      # loopback outbound-mux test (no network)
bitcoind server-test <dir>            # end-to-end serve test (socketpair)
```

**`serve` mode (production)** — the mode you run to operate the node:

1. Binds+listens on `<port>` immediately (so the node is reachable during the
   long catch-up).
2. Runs **`dl_catchup`** synchronously (self-healing): discovers peers via
   DNS-seed bootstrap into the persisted book, extends `headers.dat` to the
   real chain tip, computes the combined archive gap from `index.dat` (holes
   below stored tip + everything missing to the real tip as one span), and
   forks `catchup_workers` (default **16**, clamp 1..64) chunk-claiming,
   work-stealing download workers to fill it. Dead/low-bandwidth peers are
   dropped and replaced. A node already caught up returns almost instantly
   (pure disk reads), so this is safe to run unconditionally on every boot.
3. Builds the in-memory O(1) hash→height index for serving.
4. Forks a dedicated **continuous download worker** (the sole aggressive block
   writer) that grinds from the on-disk tip toward mainnet.
5. Runs a **pure-inbound serve loop** (`serve_mux`) that accepts peers and
   forks each to `node_serve_loop` for getdata/getheaders/getblocktxn/sendcmpct
   etc. — so the node stays live to inbound peers while downloading.

Optional args: `nwant` (steady-state outbound leg count; default 3, used only
in `serve-test`), `catchup_workers` (chunk-claiming worker count for the
boot-time catch-up).

Other modes are **tests/demos**, not production operation:
- `sync` / `ibd` / `follow` connect to a fork-in-process loopback fake peer
  (not real seeds) and report the resulting height. `ibd` requires the
  whole-chain peer and reports success only if it stored exactly the expected
  8-block demo chain.
- `server-test` runs an in-process socketpair serve self-test (getdata-exact /
  getheaders / ping→pong / inv keep-up) and prints `ALL TESTS PASSED`.
- `serve-test` is a loopback variant of the outbound multiplexer used by
  `test_outbound_mux` — one outbound leg to a local peer.

### 3.2 `cli` — query the stored chain (all-asm)

```
cli <dir> <command> [args...]
```
Commands handled in pure assembly (`cli_main`): `getblockcount`,
`getbestblockhash`, `getblockhash <h>`, `getblock <h|hash64>`, `gettx
<txid64>`, `getbalance`, `stop`, `help`. Hashes print in Bitcoin display
(BE) order.

### 3.3 `wallet_cli` — wallet / CLI surface

```
wallet_cli <command> [args...]
```

Crypto is the verified asm primitives glued by `asm/wallet_core.c`. Pure
wallet commands (no block store needed):

```
gen                                  # random keypair + P2PKH mainnet address
addr <privkey_hex>                   # compressed pubkey + P2PKH address
netaddr <privkey_hex>                # network-prefix address
sign <tx_hex> <privkey_hex> <input_idx>     # legacy SIGHASH_ALL P2PKH sign
send <priv_hex> <dest_h160_hex> <amount> <fee> <txid:idx:value>...
                                     # build + sign + emit a send tx
balance <utxo_value_sat> [...]       # sum of wallet UTXOs
signmessage <priv_hex> <message>     # BIP137 digest sign
verifymessage <pub_hex|address> <message> <sig>   # incl. Core-compatible
                                     # recoverable (65-byte base64 compact) form
mnemonic                             # fresh recoverable seed: mnemonic -> seed -> xprv -> address
seed "<mnemonic sentence>" [pass]    # derive seed/xprv/address from a mnemonic
```

BIP84 / Core-aligned command surface:

```
getnewaddress <seed_hex64> [index]        # m/84'/0'/0'/i/0 P2WPKH bech32
getrawchangeaddress <seed_hex64> [index]  # .../1 change address
validateaddress <address>                 # classify base58check / bech32
getaddressinfo <address>                  # full address info
gettxout <txid_hex64> <vout> <value> <script_hex>
listunspent <txid:idx:value:script_hex> [...]
decoderawtransaction <tx_hex>
signrawtransactionwithkey <tx_hex> <priv:prevout_script_hex> [...]
sendtoaddress <priv_hex> <dest_h160_hex> <amount> <fee> <txid:idx:value> [...]
```

Persistent-wallet / address-book commands:

```
init [password]                        # create persistent wallet (data/bmcwallet.dat)
load [password]                        # load it, report addresses
getaddress                             # derive/print addresses from loaded wallet
getprivkey                             # print secret (from loaded wallet)
abook <add|set|get|rm|list> <label> [address] [book]
history [path]                         # render the transaction journal (own format)
listtransactions [path]                # alias of history
```

Run bare to print the full one-line usage summary.

### 3.4 `bitcoin_cli` — Core-compatible JSON-RPC *client*

```
bitcoin_cli [-rpcport=<n>] [-rpcuser=<u>] [-rpcpassword=<p>]
            [-rpcconnect=<host>] <method> [params...]
```

Behaves bit-for-bit like Bitcoin Core's `bitcoin-cli` against a local HTTP
JSON-RPC endpoint: frames a JSON-RPC 2.0 request, POSTs it with HTTP Basic
auth, and renders the reply exactly as bitcoin-cli does (string results
printed raw; objects/arrays via Core's `write(2)` pretty format; RPC errors →
`error code:`/`error message:` on stderr, non-zero exit). Only loopback
connect is supported (`-rpcconnect=` is accepted and ignored).

Commands available: `getnewaddress`, `getrawchangeaddress`, `getaddressinfo`,
`validateaddress`, `listunspent`, `gettxout`, `getbalance`,
`decoderawtransaction` (+ more as the dispatch/render layer grows — see
`asm/rpc_commands.c`).

### 3.5 `bitcoin_rpcd` — the HTTP JSON-RPC *server*

```
bitcoin_rpcd [-conf=<path>] [-rpcport=<n>] [-rpcuser=<u>] [-rpcpassword=<p>]
```

Production server side of the RPC transport. Loads `rpcport`/`rpcuser`/
`rpcpassword` from `config/bitcoin.conf` by default, binds a loopback listen
socket + accept thread, and serves Core-bit-exact HTTP + JSON-RPC (405 on
non-POST, 401 + `WWW-Authenticate`, `-32700` parse error, V2/V1 envelopes with
id echo, V2-notification 204). Runs until SIGINT/SIGTERM. All dispatch goes
through the same `rpc_dispatch()` as `bitcoin_cli`.

### 3.6 Standalone / ops tools (`asm/daemon/`)

These are NOT load-bearing for normal operation (the daemon self-heals), but
are kept as ops/audit tools:

```
unified_ibd <dir> <nw> [start_h] [end_h]    # standalone bulk download (same
                                            # chunk-claiming engine as dl_catchup)
backfill_holes.sh <dir> <nw>                # one combined-span unified_ibd over gaps
sync_chain.sh <dir> <nw>                    # gaps, then extend to the real tip
hole_ranges.py <dir> [--span]               # find gaps in index.dat
chainctl <dir> <num_workers> [chunk] [sleep_sec]  # chunked full-chain orchestrator
check_chain <dir> [deep]                    # integrity audit: dups/holes/corruption
verify <dir> [start] [end]                  # hash/chain/PoW/consensus validation
pverify <dir> [start] [end]                 # parallel variant of verify
dumpblock <dir> <height> [raw]              # inspect a stored block
nodecheck.sh <dir>                          # one-shot health: audit+progress+serve
chainprogress.sh <dir>                      # coverage toward a complete 0..tip
peerstats.sh                                # tail -f live dl_catchup status
crawler <seed_file> <out_file> [parallel] [wait_s]   # parallel getaddr harvester
addrgather <seed_file> [parallel] [wait_s]  # getaddr -> addr/addrv2 -> peers.dat
peertest <peers_file> <max_tested> <out_good_file>   # verify which serve blocks
seedprobe <...>         testpeer <...>      # peer probing utilities
discover <peers.txt> [wait] [verbose]       # peer discovery
inbound_client <host> <port>                # P2P handshake probe
multipeer <num_peers> <storedir>            # multi-peer test demo
merge_only <src_dir> <dst_dir> [nw] [start] [end]    # archive merge
paribd / paribd_asm <dir> <nw> <start_h> <end_h> [peer...]   # parallel IBD (C/asm)
```

### 3.7 `scripts/` — process helpers

These wrap a hypothetical system `bitcoind`/`bitcoin-cli` (the Core-tool
names); if you run the project's own binaries, invoke them directly (see 3.1)
instead of relying on these:

```
scripts/start.sh        # start daemon (-daemon -conf -datadir)
scripts/status.sh       # pgrep + bitcoin-cli getblockchaininfo
scripts/stop.sh         # bitcoin-cli stop || killall bitcoind
scripts/worklog.sh [YYYY-MM-DD]   # open (create+seed) today's daily worklog
```

---

## 4. Configuration

### 4.1 `config/bitcoin.conf`

Read by `bitcoin_rpcd` (and modeled after Bitcoin Core). Current contents:

> **Ports, corrected 2026-08-27.** RPC and P2P must not collide. Production
> runs `port=8332` (P2P) and `rpcport=8331` (JSON-RPC). The embedded `serve`
> RPC server binds `rpcport` from this file, defaulting to the selected chain's
> RPC port when unset (8332 mainnet / 18443 regtest).

| key | value | meaning |
|-----|-------|---------|
| `rpcport` | `8331` | RPC/JSON-RPC listen port (must differ from `port`) |
| `port` | `8332` | P2P listen port |
| `chain` | `main` | chain selection: `main` or `regtest` (`regtest=1` also works); see §4.3 |
| `listen` | `1` | accept inbound |
| `maxconnections` | `256` | connection cap |
| `rpcuser` / `rpcpassword` | `bitcoin`/`bitcoin` | HTTP Basic auth |
| `dbcache`, `prune`, `blocksonly` | `4096`/`0`/`0` | resource/cache hints |
| `prune` | (commented `=5000`) | uncomment to enable pruned storage |
| mempool policy | Core defaults | `minrelaytxfee`, `incrementalrelayfee`, `limit{ancestor,descendant}{count,size}`, `mempoolfullrbf` — all read here (LOG.md 2026-08-27) |
| `privacy`, `whitelist`, `txindex`, `paranoid` | ... | misc flags |

### 4.2 Environment / invocation defaults

- `scripts/*.sh` honor `BITCOIN_DATA_DIR` and `BITCOIN_CONF` (defaults point
  at `data/` and `config/bitcoin.conf`).
- The daemon and CLI get their data directory as a positional `<dir>` argument
  (they `chdir` into it), not via `-datadir`. Point them at
  `/storage/bitcoinmachinecode/data`.
- Port 8333 is often occupied by a co-located real Bitcoin Core instance; the
  project's own node is frequently run on **28333** to avoid the clash (see
  worklog).

### 4.3 Chain selection (`main` / `regtest`, 2026-08-27)

`chain=regtest` (or `regtest=1`) in `bitcoin.conf` runs the node on Bitcoin
Core's regression-test chain instead of mainnet. Everything chain-specific
lives behind `daemon/chainparams.{h,c}`; the compiled default is mainnet, so a
config without a `chain` key is byte-identical to before this existed.

- **Datadir isolation.** Mainnet state lives at the datadir root; every other
  chain gets its own subdirectory (`<datadir>/regtest/`, Core's own layout),
  so chains can never share block/UTXO/wallet state. `bitcoin.conf` stays
  shared at the root. Logs live under `<chain-datadir>/logs/` and the filename
  is chain-tagged: `bitcoind.log` on mainnet, `bitcoind.regtest.log` on
  regtest.
- **What is chain-selected:** P2P message magic (regtest `fabfb5da`), default
  ports (P2P 18444 / RPC 18443), the genesis block (derived from the mainnet
  bytes and hash-asserted against Core's `hashGenesisBlock` before selection
  succeeds), the script-flag activation schedule (regtest heights generated
  from `CRegTestParams`), subsidy halving (150), `getblocktemplate` next-work
  (`fPowNoRetargeting`), address encodings (`0x6f`/`0xc4`/`bcrt`), and DNS
  seeds (off). Proven differentially against a scratch Core regtest node:
  161/161 identical block hashes, identical `gettxoutsetinfo` muhash, and a
  block built from the node's own `getblocktemplate` accepted by Core via
  `submitblock`. See LOG.md 2026-08-27 and `tests/test_chainparams.c`.

### 4.4 Seeds & peer lists

- `seeds.txt` — the initial DNS seed hostnames.
- `internet_peers.txt` / `good_internet_peers.txt` — harvested peer address
  lists (regenerable via `crawler`/`addrgather`/`peertest`; gitignored).
- Peer discovery is fully internet-based: seeds are used **only as
  bootstraps** — the node getaddrs from them, folds discovered peers into the
  persisted `peers.dat` book, then downloads/serves across *discovered* peers
  (distinct-peer selection via the flock-locked `peerclaims` table).

---

## 5. How the software works (architecture)

### 5.1 Layering

```
+---------------------------------------------------------------+
| CLI/RPC layer   wallet_cli · bitcoin_cli · bitcoin_rpcd · cli  |
|                 (JSON-RPC transport: rpc_json/rpc_net/         |
|                  rpc_commands/rpc_server)                      |
+---------------------------------------------------------------+
| Wallet/validation layer  wallet_core / _store / _txlog /       |
|                          _msgsign / _book  (C glue over asm)   |
+---------------------------------------------------------------+
| Node application layer  bitcoind(node_ibd_*), node_serve_loop, |
|                         mempool policy, DPiP/peer book, idx    |
|                         (asm: bitcoind/headers/idx/idxscan/    |
|                          serve/cmpct/cons/aggrmgr ...)         |
+---------------------------------------------------------------+
| Cryptographic ASM core   sha256/sha512/hmac/ripemd160,         |
|                          secp256k1 fe/point/scalar/ecdsa/      |
|                          schnorr/taproot, bech32, bip32, bip39 |
+---------------------------------------------------------------+
| System layer             bitcoin_net.asm raw-syscall sockets + |
|                          P2P framer; node_log all-asm logger   |
+---------------------------------------------------------------+
```

The entire node's data path (sockets, IBD, consensus validate, store, serve)
is assembly. C exists only as (a) thin orchestration drivers (`daemon/*.c`),
(b) policy glue that isn't consensus crypto, and (c) the test/verification
harnesses. Python is present only as trusted-reference oracles and vector
generators.

### 5.2 Core data & message flow

- **IBD (download):** `node_ibd_headers` paged-getheaders persists the whole
  header chain (chain-continuity verified per header); `node_ibd_blocks` walks
  every stored header, getdata's its block, validates it (`cons_verify`: PoW +
  per-tx parse + coinbase-first + merkle-root recheck over txids), re-derives
  the block hash and requires it to equal the stored header hash (wrong-block
  guard), then appends to the archive.
- **Serving (inbound):** `node_accept_handshake` answers a peer's `version`,
  then `node_serve_loop` (pure assembly) dispatches over the on-disk archive:
  `ping`→`pong`, `getaddr`→`addr`, `getdata`→`block` (O(1) hash→height via the
  in-memory `bitcoin_idx` table), `getheaders`→canonical `headers` pages,
  `inv`, and BIP152 `sendcmpct`/`cmpctblock`/`getblocktxn`/`blocktxn`.
- **Self-healing catch-up:** `dl_catchup` (built into `serve` boot) extends
  headers, computes the single combined gap+extend span from `index.dat`
  (via the asm `idxscan_*` module), and forks chunk-claiming work-stealing
  workers over distinct live peers.
- **Wallet/validation:** real transactions are validated against the UTXO set
  (prevout presence + per-input ECDSA/Schnorr verify + fee) and signed via the
  verified asm crypto; modern outputs (P2WPKH/P2WSH/P2TR) run through the
  witness-v0 / taproot sighash + interpreter pipeline.
- **Block-connection script verification (in progress, 2026-08-19/20):**
  `apply_block_inner` (`daemon/utxo_live.c`) calls
  `tx_verify_block_connect_all` (`daemon/tx_verify.c`) ahead of every block's
  UTXO puts/dels — matching Core's `CheckInputs`-before-`UpdateCoins`
  ordering. Per non-coinbase input: resolve the confirmed prevout (an
  in-block outpoint index first, for same-block chained spends, then the
  live UTXO LSM), enforce the 100-block coinbase-maturity rule, classify the
  prevout scriptPubKey's shape, and dispatch to `sv_verify_script` (legacy)
  or the witness primitives (P2WPKH/P2WSH/P2TR-keypath) — plus an explicit
  whole-block duplicate-outpoint pre-check. Verification is parallelized
  across every input in the block via a persistent worker pool. Being
  proven by a full from-scratch replay of the real archive; see
  `PLAN_SCRIPT_VERIFY.md` Stage D and `worklog/2026-08-20.md` for status and
  the two real bugs the replay has found and fixed so far.

### 5.3 Durability & crash-safety design

- Append-only stores + positional indices (block archive, header chain, UTXO),
  mirroring each other's restart-resume pattern.
- Concurrent appends are serialized by `flock(append.lock)` with per-worker
  fds (flock belongs to the open-file-description, not the path).
- Any operation logs to the all-asm leveled logger (`bitcoind.log`) via
  `node_log_*`; the daemon is `-O0`-linked and signal-hardened
  (`SIGPIPE`/`SIGCHLD` ignored).

---

## 6. Validation, differential compliance, security

### 6.1 The compliance gate (differential vs real Bitcoin Core)

`validation/consensus_diff.py` + `asm/tests/consensus_shim` feed the **same**
real mainnet block/tx bytes to (a) the ASM consensus stack and (b) a real
Bitcoin Core node's RPC, and require every verdict byte-for-byte equal. Two
passes:

- **ACCEPT path:** every real mainnet block the active chain accepted must be
  `cons_verify`-valid and its ASM block hash must equal Core's height→hash.
- **REJECT path:** deterministic mutations of real blocks must be rejected by
  both.
- Per-tx **txid differential** over sampled real txs.

Clean (zero divergences) across the consensus-critical epochs: genesis, BIP16
(173805), BIP34 (227931), SegWit (481824), Taproot (709632), recent mainnet
(~918000). Build with `make`; drive with:

```bash
cd /storage/bitcoinmachinecode/asm && make tests/consensus_shim
python3 validation/consensus_diff.py --start H --count N
```

Other differential scripts under `validation/` (e.g. `fullchain_diff.py`,
`bip30_diff.py`, `p2sh_diff.py`, `corpus_diff.py`, `bip152_ref.py`,
`capture_sendheaders_fee.py`) follow the same pattern against their respective
shims. Reports land in `validation/*_report.{json,txt,md}` and
`validation/fullchain_state/` (resume progress; gitignored).

### 6.2 Security audit

`validation/SECURITY_AUDIT.md` records two completed internal audit passes
(2026-08-15, 2026-08-16) of the asm crypto + consensus + wallet core:

- **PASS 1 (fully fixed):** non-constant-time signing path (fixed via the
  constant-time `point_scalar_mul_ct` complete-form ladder, repointed onto the
  two secret-scalar call sites), branch-y field arithmetic made branch-free,
  and legacy-sighash OOB read/write-cap defects (regression-guarded by
  `test_sighash_oob.c`).
- **PASS 2:** no new CRITICAL/HIGH across the newest crypto/networking
  surfaces; two LOW/INFO hardening items open (journal durability, recovery-
  scan efficiency / Core-header extension bit).

The signing path is now constant-time end-to-end. The standing warning is only
that an **independent human audit** has not yet happened.

### 6.3 Hard-won engineering rules (do not regress)

These are the project's own "golden rules" (full text in `README.md` /
`PLAN.md` §9). Extract of the most critical:

- **Never** write stack scratch inside `[rbp-8..-40]` (the callee-saved save
  area); keep scratch below it and keep RSP 16-byte aligned at every nested
  call.
- **Never** join 2+ asm instructions on one line with `;` — in NASM `;`
  starts a comment.
- Preserve callee-saved registers across `fe_*`/point calls; push exactly
  what you pop, in matching order and matching sizes (a mismatched
  prologue/epilogue corrupts the return address).
- When building a runtime filename, **explicitly write the terminating NUL**
  byte; a 4-byte store can silently drop it and create corrupted long
  filenames.

---

## 7. The optional CUDA tier (`asm/cuda/`)

> **Not wired into the node binary** — it is a proven, runtime-gated PoC.
> See `asm/cuda/WORKING.md` for the feasibility analysis + integration seam.

A dispatcher (`cuda_autodetect.c`) auto-detects a usable GPU at runtime and
uses CUDA **only** when a device is present AND the batch is large enough to
amortize launch/copy (≥512) AND not disabled (`BMC_CUDA=0`); otherwise it
falls back bit-exact to the assembly SHA-256(d). The GPU wins only on
*batched independent* crypto throughput (~17.7x at N=1,000,000 on an RTX 5090;
CPU wins below ~100); single-hash SHA-NI remains the right tool.

Build/run (requires `nvcc` + GPU):
```
cd /storage/bitcoinmachinecode/asm/cuda
make verify | make bench | make detect | make all
```

---

## 8. Operational runbook (getting the node up)

Assemble + verify once:

```bash
cd /storage/bitcoinmachinecode/asm && ./build.sh        # exit 0 = asm correct
```

Run the node in production (self-healing catch-up + continuous download +
inbound serve). Use 28333 if 8333 is taken by a co-located Core:

```bash
cd /storage/bitcoinmachinecode/asm/daemon
./bitcoind serve /storage/bitcoinmachinecode/data 28333 &
```

Query the stored chain:

```bash
./cli /storage/bitcoinmachinecode/data getblockcount
./cli /storage/bitcoinmachinecode/data getbestblockhash
./cli /storage/bitcoinmachinecode/data getblockhash 0
```

Use the JSON-RPC layer (start server, then query with the client):

```bash
./bitcoin_rpcd &                       # reads config/bitcoin.conf
./bitcoin_cli getnewaddress  # ...  (against 127.0.0.1:8332)
```

Health / integrity / progress:

```bash
./nodecheck.sh /storage/bitcoinmachinecode/data
./chainprogress.sh /storage/bitcoinmachinecode/data
./check_chain /storage/bitcoinmachinecode/data
./verify /storage/bitcoinmachinecode/data <lo> <hi>
```

Wallet one-off work:

```bash
./wallet_cli mnemonic                          # fresh recoverable seed
./wallet_cli seed "word word ..." [pass]       # seed -> address
./wallet_cli getnewaddress <seed_hex64>        # receive address
./wallet_cli sendtoaddress <priv> <dest_h160> <amount> <fee> <utxo...>
```

---

## 9. Keeping this document current

This is a **living document**. When features mature, update it. The contract:

1. **Every new binary / subcommand / flag** gets a row in §3 and §2 as
   relevant, including exact usage lines (read them from the source's
   `usage:` strings / `main()` dispatch — do not invent).
2. **Every on-disk format change** updates §1.1 (record sizes, framing,
   filenames, locking).
3. **Every new validation gate** (differential harness, audit pass, vector
   suite) updates §6, including how to run it.
4. **Every new assembly module** is listed in the §5.1 layering note and
   §1 layout, and — if it changes security posture — flagged in §6.2.
5. Bump the archive-state line in §1 when chain-tip scale changes
   materially, and update the runbook defaults if port/peer conventions change.

Cross-reference with `README.md` (user-facing status), `PLAN.md` (roadmap +
verified state), `LOG.md` / `worklog/` (history), and `KANBAN.md` (board) —
keep them consistent so there is one source of truth per concern.

---

*Document created 2026-08-17 against branch `main` (HEAD `62a8225`), archive
~664 GB / ~4,851 block files, chain tip ~962,831 during normal operation.*
