# Feature gaps vs. Bitcoin Core

Written 2026-08-21, during Stage D's full-chain replay (see
`PLAN_SCRIPT_VERIFY.md`). This is a survey of what this project does **not**
do relative to real Bitcoin Core — not a roadmap commitment, just an honest,
evidence-based inventory to work from. Every item below was confirmed against
this repo's actual code (grep, direct file reads, dispatch tables) or an
explicit log/config message — not inferred from general Bitcoin-protocol
knowledge. Where something is a positive surprise (more complete than
expected), that's noted too, so this stays a fair picture rather than a
one-sided gap list.

Effort sizing is a rough small/medium/large based on what similar-shaped work
has cost in this codebase, not a precise estimate.

## Summary

Strongest area: P2P protocol depth and core consensus verification (script,
segwit, taproot key-path, real mempool policy) — closer to Core than a
project at this stage might suggest. Weakest area, by a wide margin: **the
RPC surface**. Also fully absent as clean categories: mining, PSBT,
multi-wallet/descriptor/watch-only wallets, chain selection (testnet/signet/
regtest), and modern light-client indexing (blockfilter/coinstats). This
tracks with the project's actual focus to date — proving consensus
correctness via full historical replay — rather than general node
operability.

**Update 2026-08-22.** Closed since this survey was written: taproot
script-path + `OP_CODESEPARATOR` (`e789df8`, `b2ccb2d`); 9 blockchain-query
RPCs (`090a109`); reorg truncation and whole-file pruning on the
non-monotonic archive (`9269a86`, `a051f21`); genesis injected so store
index == height (`5f36dee`); clean shutdown + crash recovery of a
partially-applied block (`f2faf3b`, `96b555e`). A scratch Bitcoin Core
(`/storage/core-oracle`, `txindex`+`coinstatsindex`) is now an authorized
development oracle: block hashes cross-validated at 14 heights, and after
the genesis fix index/body/header/Core agree at 12 heights including 0.

## RPC surface — still the biggest gap, first tranche landed 2026-08-21

**Implemented** (`asm/rpc_chain.c`, dispatched from `rpc_dispatch` in
`asm/rpc_commands.c`; shapes follow Core v31's `blockchain.cpp` /
`rawtransaction.cpp` / `core_io.cpp` field-for-field so a scratch-Core diff
harness can compare JSON directly):

- Blockchain query: `getblockcount`, `getbestblockhash`, `getblockhash`,
  `getblockheader` (verbose + raw hex), `getblock` (verbosity 0/1/2; 3 acts
  like 2 — no undo data, same as Core without it), `getblockchaininfo`.
- Raw tx: `getrawtransaction <txid> [verbosity] <blockhash>` — the exact
  behaviour Core has with **no txindex and an empty mempool**: succeeds only
  with a block hash, otherwise Core's own `-5 "No such mempool transaction.
  Use -txindex or provide a block hash…"`.
- Node: `uptime`, `stop` (these apply to the `bitcoin_rpcd` process).

How it reaches chain state: `bitcoin_rpcd` is a **standalone process**, not
hosted in `bitcoind serve`. `rpc_chain.c` opens `-datadir` read-only —
`index.dat`/`blk*.dat` through `bitcoin_store.asm`'s read path, its own
hash→height table, `chainwork.dat` (recomputed from headers when absent),
`headers.dat` for the headers count — and `store_reload`s on every request,
so it tracks the live daemon's appends without a restart. Tested by
`tests/test_rpc_chain.c` (124 checks: real mainnet genesis as oracle, a
segwit coinbase, a legacy spend with Core's `[ALL]` sighash decode in
`scriptSig.asm`, a P2WPKH spend with witness, every error path).

Deliberate, documented divergences (things we refuse to fabricate):
scriptPubKey `desc` is omitted (no descriptor engine); `address` omitted for
`witness_unknown`/`anchor`; `verificationprogress` is blocks/headers;
`initialblockdownload` is "tip older than 24 h".

**Still missing — needs live-node state the RPC process does not have:**
`getpeerinfo`, `getconnectioncount`, `getnetworkinfo`, `getmempoolinfo`,
`sendrawtransaction`, `getrawtransaction` without a block hash (mempool
lookup), `getchaintips` (reorg candidates are not persisted). The honest
plumbing for these is either hosting the RPC server inside `bitcoind serve`
(where the peer table and mempool live) or a small IPC/shared-memory
snapshot the serve process publishes; neither exists yet. Until then these
return `-32601 Method not found` rather than stubbed answers.
`createrawtransaction` was skipped as out of scope (the tx builder lives in
the wallet CLI). Still absent as categories: wallet RPCs beyond the original
8, mining (`getblocktemplate`/`submitblock`), `estimatesmartfee`, util.

**Effort for the remainder: medium** — the blockchain-query breadth is now
done; what's left is the one architectural step (RPC ↔ live node state)
plus straightforward methods on top of it.

## Observed while wiring RPC — not fixed here, flagged for the consensus/storage owners

- **`index.dat` hash byte order vs `bitcoin_idx.asm`.** Verified on the
  production archive (`pread` of record 0, read-only): records store the
  hash in **wire (raw sha256d) order**. `bitcoin_idx.asm`'s
  `idx_build_from_file` header comment says DISPLAY order and byte-reverses
  every record before `idx_put`, so the table `main.c`'s boot builds from
  `index.dat` is keyed on reversed hashes. Whether the serve path's
  `idx_get` compensates was not checked. `rpc_chain.c` sidesteps it by
  building its own table from raw record bytes.
- ~~**Production archive record 0 is block 1, not genesis.**~~ — **FIXED
  2026-08-22.** Confirmed against Core that record index was consistently
  real height − 1 across the whole archive, so `apply_block_at` handed
  `script_flags_for_block` a height one too low and every buried soft fork
  activated one block LATE: DERSIG (363,725), CLTV (388,381), CSV (419,328)
  and NULLDUMMY (481,824) each missed their own activation block. Direction
  was false-ACCEPT (we applied looser rules than Core for one block at each
  boundary), i.e. a chain-split risk — and structurally invisible to the
  replay, because looser rules accept a superset and real chain data is
  valid under the stricter ones. Re-downloading could never have fixed it:
  the P2P locator for "from the beginning" is the all-zero hash and peers
  answer from block 1, so genesis is never transmitted (see
  `bitcoind.asm:1247`). Genesis was injected from its known constant instead
  — 285 bytes appended to the last `blk` file, `index.dat`/`headers.dat`
  shifted by one record, `chainwork.dat` dropped to be rebuilt (its
  cumulative values all change). Re-verified against Core: index hash, block
  body, header record and `getblockhash` agree at 12 heights including 0.
  `apply_block_inner` now skips genesis's coinbase, matched by hash, so the
  UTXO set matches Core's.

## Consensus / validation

- **`assumevalid`** — explicitly ignored (`daemon/node_config.c:272-273`
  logs "IGNORED"). Small to wire (config parsing already exists) but
  deliberately not worth doing until Stage D's replay finishes — using it
  now would mean skipping the exact verification this project is currently
  proving. Revisit after.
- **`assumeutxo`** (Core's UTXO-snapshot-import) — absent. No real hits for
  assumeutxo/utxo.snapshot/dumptxoutset/loadtxoutset. **Large** — needs a
  new snapshot format plus a background-validation state machine; nothing
  like it exists today.
- ~~**Taproot script-path spending (BIP342 tapscript)**~~ — **DONE
  2026-08-21** (`e789df8`). `taproot_verify_input`
  (`bitcoin_taproot_sighash.c`) now does BIP341 witness classification
  (annex, key-path vs script-path), control-block Merkle commitment, and
  tapscript execution through the shared `script_eval` interpreter
  (OP_SUCCESSx, OP_CHECKSIGADD, validation-weight budget), wired at both
  `tx_verify.c` call sites. Before this, every script-path spend was
  false-rejected (fail-closed, never false-accept — verified before
  touching it). Two dependency bugs found and fixed on the way: an
  unbounded write in `tap_leaf_hash` for scripts over ~288 bytes, and a
  wrong sighash for script-path spends carrying an annex. 9 independent
  vectors in `tests/test_taproot_scriptpath.c`.
  - ~~**Remaining, narrow:** `OP_CODESEPARATOR` *inside a tapscript*~~ —
    **DONE 2026-08-21.** `script_eval` now tracks the BIP342 `codesep_pos`
    (opcode position of the last *executed* `OP_CODESEPARATOR`, `0xffffffff`
    if none, unexecuted branches excluded — Core `interpreter.cpp`
    `opcode_pos`/`execdata.m_codeseparator_pos`) and passes it to the
    tapscript checksig callback via `interp_slice`'s third field. The
    byte-level `0xab` refuse scan is gone (it also rejected any tapscript
    whose *push data* happened to contain `0xab`, e.g. a pubkey). 12 new
    generated vectors (positions before CHECKSIG/CHECKSIGADD, not-taken
    branch, last-executed-wins, wrong-position and none-committed
    rejections, `0xab` inside a pubkey push) — all negatives pin the exact
    rejection reason. No remaining known taproot consensus gap other than
    the deferred items below.
- **Chain selection** — mainnet only. No testnet/signet/regtest handling in
  `node_config.c`; mainnet magic bytes are hardcoded directly in
  `bitcoin_net.asm`/`bitcoin_store.asm` (3 literal occurrences each), no
  chain-params abstraction layer. **Large** — would need a real indirection
  threaded through many files.
- **Package relay** (Core's v3/ephemeral-dust multi-tx package acceptance,
  distinct from the RBF/ancestor-limit checks below) — not confirmed either
  way with high confidence; worth a closer look if it matters.
- Mempool policy (RBF/BIP125 replacement-fee checks, ancestor/descendant
  count+byte-budget limits) is **genuinely implemented**, not stubbed
  (`bitcoin_mempool_policy.c:256-339`) — positive surprise, expected this to
  be thin.

## Indexing

- **`txindex`** — explicitly ignored (confirmed this session);
  `getrawtransaction` by bare txid won't work.
- **Address index** — `build_addr_index.c` exists but is a **standalone
  offline batch tool only**, zero references from `daemon/main.c`'s live
  boot path. Not a live, queryable index.
- **`blockfilterindex`** (BIP157/158, "neutrino" light-client support) —
  absent. No hits for blockfilter/bip157/bip158/cfilter/golomb-rice.
- **`coinstatsindex` / `gettxoutsetinfo`** — absent. **Now the most
  valuable gap to close:** the scratch Core oracle has `coinstatsindex`
  on, so a UTXO-set hash on our side (`hash_serialized_3` or MuHash3072
  over the live LSM set) would turn Stage D's acceptance test from "no
  block rejected" into "byte-identical UTXO set to Core at height H" —
  which is the only test that could have caught incident #6 (a rule
  applied too loosely is invisible to a replay). **Medium.**

## Wallet

Real, substantial: HD wallet (BIP32/39), message signing
(`bitcoin_bip32.asm`, `bitcoin_bip39.asm`, `wallet_msgsign.c`).

Missing:
- **PSBT (BIP174)** — absent, zero hits anywhere.
- **Descriptor wallets** — Core's modern default wallet type isn't present.
- **Watch-only wallets** — absent.
- **Multi-wallet** (`loadwallet`/`createwallet`/`listwallets`) — absent,
  single implicit wallet only.
- Coin selection — present but basic (`listunspent`/`getbalance` exist); no
  evidence of a sophisticated algorithm like Core's Branch-and-Bound. Not
  confirmed in depth either way.

## P2P / networking — stronger than expected

Confirmed genuinely wired into the real serve loop (`bitcoin_serve.asm`),
not just present as unused/tested-in-isolation code:
- **BIP152 compact blocks** — both directions (`cmpctblock_build`,
  `p2p_blocktxn_build`, full message handling).
- **wtxid relay, addrv2 (BIP155), feefilter, sendheaders** — all genuinely
  implemented and exchanged during real handshakes.
- **Witness transport (BIP144) — FIXED 2026-08-22** (`31eac9a`, `fe3addb`):
  block requests were `MSG_BLOCK`, so every post-segwit block was fetched
  *stripped* and the archive held 482k witness-less bodies (incident #10,
  `LOG.md`); the server side also ignored `MSG_WITNESS_*` requests, so this
  node could not serve blocks to a modern peer. Now requests and serves
  `MSG_WITNESS_BLOCK`. **Remaining:** prefer/require `NODE_WITNESS` (0x8)
  peers; serve the stripped form to a bare `MSG_BLOCK` request; and
  **`MSG_WITNESS_TX` for transaction relay** — the mempool path still fetches
  transactions without witnesses (same bug shape, not yet hit).
- **Thread stacks / sighash buffers — FIXED 2026-08-22** (`9445268`): every
  daemon thread now gets an explicit 64 MB stack (`bmc_thread.h`,
  `BMC_THREAD_STACK_MB`); BIP143/BIP341 midstate hashes use bounded per-thread
  heap buffers; static TLS 12.0 → 4.4 MB. **Remaining:** `lsm_get_scratch`
  (4 MiB asm TLS, only the non-mmap fallback uses it) should move to heap.
- **Nested segwit (P2SH-P2WPKH / P2SH-P2WSH) and general P2WSH — DONE
  2026-08-22** (`11f7aa9`): were absent / two hard-coded shapes; now
  witness-v0 scripts execute through `script_eval` (`bitcoin_witness_v0.c`),
  native and wrapped, with CHECKMULTISIG's FindAndDelete gated on BASE and
  mixed legacy+segwit sighash serialization fixed. Incident #12.
- **P2WPKH BIP143 scriptCode — FIXED 2026-08-22** (`b3800f0`): was the witness
  program; now `76a914<h160>88ac`. Lesson recorded: vector generators must be
  derived from Core or the BIP's worked example, never from the verifier's
  own assumptions (`validation/bip143_ref.py` now anchors on BIP143's example).
- **BIP141 witness-commitment validation — DONE 2026-08-22** (`191df6c`,
  `daemon/block_witness.c`): the consensus check that makes a stripped block
  unacceptable. Core had it; we did not, which is why the archive could be
  stripped silently.

Confirmed absent:
- **Tor / I2P / onion support** — zero hits for tor/.onion/torcontrol.
- **ZMQ notification interface** — zero hits.
- **REST interface** (separate from JSON-RPC) — zero hits.
- **UPnP / NAT-PMP** automatic port forwarding — zero hits.

## Mining

**Entirely absent.** No `getblocktemplate`, no `submitblock`, no block
template construction, no stratum/pool-facing interface — confirmed via
direct grep, zero hits across the whole `daemon/`/`rpc_commands.c` surface.
This node can validate and relay blocks but cannot help build them.

## Ops / misc

- ~~Clean shutdown during catch-up~~ — **FIXED 2026-08-22** (`f2faf3b`):
  every `systemctl stop` during a replay had been a 90 s SIGKILL because
  the catch-up loop ignored SIGTERM; now 10 s, checkpoint persisted.
  `TimeoutStopSec=900` drop-in as compaction headroom.
- ~~Crash consistency of the UTXO checkpoint~~ — **FIXED** (`96b555e`): a
  kill between a block's WAL writes and its checkpoint no longer makes the
  next resume reject that block; boot rolls it back from the undo log
  (proved on real data at height 343087).
- Full-verification IBD benchmark against Core (`-assumevalid=0
  -stopatheight`, second scratch datadir) — not run yet; the only
  like-for-like end-to-end comparison. Planned once our replay reaches tip.
- `-checkblocks`/`-checklevel` startup verification — genuinely implemented,
  matching Core's own defaults exactly (`node_config.c:61-62`:
  `checkblocks=6`, `checklevel=3`). Positive, real parity.
- GUI (Bitcoin-Qt equivalent) — absent, as expected; this is an asm/daemon
  -only project by design, not a meaningful gap given project scope.
- Multi-process architecture (Core's own ongoing migration) — not checked
  in depth, not consensus-relevant.

## Methodology note

Compiled by systematically checking this repo's own documentation first
(`README.md`, `PLAN.md`, `PLAN_SCRIPT_VERIFY.md`, `KANBAN.md`, `LOG.md`),
then grepping for literal RPC method names, config keys, and protocol
feature names across `asm/` and `asm/daemon/`, cross-referencing against
Bitcoin Core's real source (`/storage/bitcoin-core-source`) where a direct
comparison was useful. Every gap cites what was actually found, not general
Bitcoin-protocol assumptions.
