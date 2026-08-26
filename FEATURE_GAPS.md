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
RPC surface** *(retired 2026-08-25 — see the update below)*. Also fully
absent as clean categories *(2026-08-21; mining and PSBT no longer absent —
same update)*: mining, PSBT,
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

**Update 2026-08-25.** The "weakest area by a wide margin" verdict above is
retired. Closed in one sustained push (each method's verification standard
recorded in `docs/PARITY_PLAN.md`, divergences documented at the call site):
the full mempool tranche (`getmempoolinfo`/`getrawmempool`/`getmempoolentry`/
`getmempoolancestors`/`getmempooldescendants`/`prioritisetransaction`/
`getprioritisedtransactions`) over a mempool made genuinely coherent — one
MAP_SHARED, cross-process-locked pool replacing the per-process
copy-on-write copies; `estimatesmartfee` (Core's contract over our own
accepted-feerate EMA, stated as such); mining's `getblocktemplate`
(frame diffed against Core at the same tip; retarget reproduces 8/8 real
historical boundaries) and `submitblock` end-to-end (8 MB transport, 4 MB
worker channel, BIP22 strings, connect gated on a dry run of the real apply
path); `gettxoutsetinfo` + `scantxoutset` (the parity-capstone instruments
as RPCs — scan verified against Core to the satoshi on 165.7M outputs);
PSBT `analyzepsbt` (14-vector oracle diff) and `joinpsbts`; journal-backed
`listtransactions`/`gettransaction`/`getwalletinfo` with the no-oracle
verification bound stated in code; `getindexinfo`. Still absent, still
honest: `sendtoaddress`/`sendmany` via RPC (needs a wallet-UTXO source and
a fee policy — a design, not a wiring job), txindex/blockfilter index
builds, coinstatsindex, testnet/signet/regtest chains, longpoll, BIP23
proposal mode, and everything in the wallet-management tranche
(multiwallet, descriptors, encryption). The same day also proved the UTXO
set byte-identical to Core's (MuHash, no filters, no overrides — see
`README.md`), which converts several of this document's "unverified"
hedges below into verified facts.

## RPC surface — the biggest gap until 2026-08-25; first tranche 2026-08-21

**Implemented** (`asm/rpc_chain.c`, dispatched from `rpc_dispatch` in
`asm/rpc_commands.c`; shapes follow Core v31's `blockchain.cpp` /
`rawtransaction.cpp` / `core_io.cpp` field-for-field so a scratch-Core diff
harness can compare JSON directly):

- Blockchain query: `getblockcount`, `getbestblockhash`, `getblockhash`,
  `getblockheader` (verbose + raw hex), `getblock` (verbosity 0/1/2; 3 acts
  like 2 — no undo data, same as Core without it), `getblockchaininfo`,
  `getdifficulty`.
- Raw tx: `getrawtransaction <txid> [verbosity] <blockhash>` — the exact
  behaviour Core has with **no txindex and an empty mempool**: succeeds only
  with a block hash, otherwise Core's own `-5 "No such mempool transaction.
  Use -txindex or provide a block hash…"`.
- SPV proofs: `gettxoutproof [txids] <blockhash>` / `verifytxoutproof <hex>` —
  BIP37 `CMerkleBlock` (partial merkle tree). Proofs are **byte-identical** to
  Core's and each node verifies the other's (bidirectional differential against
  the scratch oracle over blocks 100000 and 800000; see `worklog/2026-08-24`).
  Like `getrawtransaction`, `gettxoutproof` **requires** the block hash (no
  txindex to locate the tx otherwise) — Core's own no-txindex behaviour.
- Util: `decodescript <hex>` — classify a redeem/scriptPubKey exactly as Core's
  `rawtransaction.cpp` does: `asm`/`desc`/`type`/`address`, the `p2sh` wrapper,
  and the `segwit` sub-object with `p2sh-segwit`, gated by Core's own `can_wrap`
  / `can_wrap_P2WSH` rules (uncompressed-key and `OP_CHECKSIGADD`/`OP_SUCCESSx`
  exclusions included). The inferred `desc` field is now emitted too — Core's
  `InferDescriptor` no-keystore behaviour (`pk`/`multi`/`rawtr`/`addr`/`raw`,
  and `wsh(inner)` for the segwit-of-a-known-script case) with the descriptor
  checksum. **Fully identical to Core** — `validation/decodescript_diff.py`
  compares the whole object (desc included) over every wrapper branch plus real
  on-chain scripts: 37/37.
- Util: `validateaddress <address>` — decode + classify (base58check and
  bech32/bech32m) into Core's `DescribeAddress` shape: `isvalid`, canonical
  `address`, `scriptPubKey`, `isscript`, `iswitness`, `witness_version`,
  `witness_program`. `validation/validateaddress_diff.py` diffs it against the
  oracle for every type (valid cases byte-for-byte; invalid on `isvalid` only).
  Writing that differential caught three field bugs in the pre-existing
  builder — a garbage P2WSH `witness_program` (copied 32 bytes from a 20-byte
  buffer), P2TR `isscript=false`, and a stray `ischange` — now fixed.
  (`getaddressinfo` shares the decoder; wallet-context fields are still stubs.)
- Util: `createmultisig <n> <keys> [address_type]` — validate the pubkeys
  (on-curve, via `pubkey_parse` = Core's `IsFullyValid`), assemble the m-of-n
  redeemScript, and derive the address for `legacy` (P2SH), `p2sh-segwit`
  (P2SH-P2WSH) or `bech32` (P2WSH); uncompressed keys force legacy and add
  Core's warning; `bech32m` is refused as Core refuses it. **Fully identical to
  Core, `descriptor` included** — the `multi()`/`sh`/`wsh` string plus Core's
  8-char descriptor checksum (`descriptor.cpp DescriptorChecksum`), which is
  mechanical here because every key is known (no descriptor *engine* needed).
  `validation/createmultisig_diff.py` diffs 17 cases vs the oracle — every
  type, 15/16/17-key count encoding, the uncompressed path, every error code —
  all byte-identical.
- Node: `uptime`, `stop` (these apply to the `bitcoin_rpcd` process).

How it reaches chain state: `bitcoin_rpcd` is a **standalone process**, not
hosted in `bitcoind serve`. `rpc_chain.c` opens `-datadir` read-only —
`index.dat`/`blk*.dat` through `bitcoin_store.asm`'s read path, its own
hash→height table, `chainwork.dat` (recomputed from headers when absent),
`headers.dat` for the headers count — and `store_reload`s on every request,
so it tracks the live daemon's appends without a restart. Tested by
`tests/test_rpc_chain.c` (124 checks: real mainnet genesis as oracle, a
segwit coinbase, a legacy spend with Core's `[ALL]` sighash decode in
`scriptSig.asm`, a P2WPKH spend with witness, every error path) and
`tests/test_txoutproof.c` (BIP37 partial-merkle known-answer vector on block
100000 + proof round-trips, incl. the odd-width duplicate-node path).

scriptPubKey now includes the inferred `desc` (InferDescriptor no-keystore
rules + checksum), matching Core on `getblock`/`getrawtransaction`/`decodescript`
output. Remaining deliberate divergences: `address` omitted for
`witness_unknown`/`anchor`; `verificationprogress` is blocks/headers;
`initialblockdownload` is "tip older than 24 h".

**Live-node RPCs — in progress (`rpc_node.c`, see docs/RPC_LIVE_NODE.md).**
The plumbing chosen is exactly the shared-memory route: the serve parent
publishes a `MAP_SHARED` `node_status_t` (peer counts, tip, start time) that
the forked children populate, and the RPC server is embedded in the serve
daemon to read it. `getnetworkinfo` (mostly static: our wire identity from
`version_gen.h`) and `getconnectioncount` are implemented, dispatch-wired, and
**the RPC server is now embedded in the serve daemon** (`daemon/main.c`): the
download worker publishes peer counts / tip into a `MAP_SHARED` `node_status_t`
before the fork, and the parent serves them on the RPC thread — verified on an
isolated scratch serve (server starts in-process, answers live-node + chain
RPCs, serve loop coexists). Landed: `getconnectioncount`, `getnetworkinfo`,
`getpeerinfo` (outbound peer table over shared memory), `getmempoolinfo` /
`getrawmempool` (the serve process's own mempool + accurate config), and
`getchaintips` (active tip — side branches aren't persisted, which matches
Core for a node with no forks). **Remaining** *(as written then; audited
2026-08-25 — nearly all closed)*: ~~`sendrawtransaction`~~ — **done** (the
parent→worker channel exists; `submitblock` later rode the same pattern);
`getrawtransaction` without a block hash — **still absent** (needs txindex
or a mempool lookup, neither built); ~~a mempool coherent across the fork
tree~~ — **done 2026-08-25** (`MAP_SHARED` pool + policy state under a
`PTHREAD_PROCESS_SHARED` lock at every mutation site; an inbound child's
accepts now appear in the parent's `getrawmempool`, proven cross-fork in
`test_mempool_shared`). ~~`createrawtransaction` skipped as out of scope~~
— later done, with Core-byte-identical KATs. ~~Still absent as
categories~~ — **all since closed**: wallet-state RPCs (journal-backed
`listtransactions`/`gettransaction`/`getwalletinfo`), mining
(`getblocktemplate`/`submitblock`/`prioritisetransaction`),
`estimatesmartfee`, the descriptor engine with `deriveaddresses`/
`getdescriptorinfo` (plus `addr()`/`raw()` and scantxoutset's expansion path
on top of it), and `getindexinfo`.

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

- ~~**`txindex`** — explicitly ignored; `getrawtransaction` by bare txid
  won't work.~~ — **DONE 2026-08-26**: offline base build
  (`daemon/build_tx_index`, ~29 GB, 8-byte prefix keys exact-by-
  verification) + daemon-maintained incremental tail
  (`daemon/tx_index_tail.c`) that backfills at boot and follows the tip, so
  `getrawtransaction <txid>` works with no block hash and `getindexinfo`
  reports the real combined coverage.
- **Address index** — `build_addr_index.c` exists but is a **standalone
  offline batch tool only**, zero references from `daemon/main.c`'s live
  boot path. Not a live, queryable index.
- **`blockfilterindex`** (BIP157/158, "neutrino" light-client support) —
  absent. No hits for blockfilter/bip157/bip158/cfilter/golomb-rice.
- **`coinstatsindex` / `gettxoutsetinfo`** — **the read side now exists**
  (2026-08-23, branch `utxo-set-hash`). `daemon/utxo_setinfo` computes
  `txouts`, `total_amount`, `bogosize` and a **MuHash3072** set hash over a
  filtered view of the LSM set, and `validation/diff_utxo_setinfo.py` diffs
  those against a live Core node's `gettxoutsetinfo` at the same height.
  There is still no RPC and no live index — this is a tool, and it needs a
  QUIESCED datadir (it detects a busy one and refuses; see below).
  - **The result, on the PRODUCTION datadir at height 792,979:** `txouts`
    102,532,574, `total_amount` 19,393,405.70154310 BTC, `bogosize`
    7,739,642,957 and MuHash `e7e65c06...649e776a` — **all four identical to
    Core**, with two entries' height field corrected for the BIP30 issue
    below. Our raw live set there is 155,001,147 entries, of which 52,468,573
    are filtered out as provably unspendable; the surviving 102,532,574 match
    Core's count to the unit. At height 91,721, before any BIP30 duplicate
    exists, all four match with no correction at all. That is the acceptance
    test ASSESSMENT.md §4 asked for, actually run.
  - **Which hash, and why not the other one.** `gettxoutsetinfo
    hash_serialized_3 <height>` is REFUSED by Core ("hash type cannot be
    queried for a specific block"): only `muhash` is answerable at an
    arbitrary height, because only `muhash` is what `coinstatsindex` stores,
    and our replay is never at the oracle's tip. Separately, MuHash is
    order-independent, which matters because our key comparator (`mac_cmp_key`)
    orders the output index by its LITTLE-ENDIAN BYTES — index 256 sorts
    before index 1 — while Core hashes a txid's outputs in NUMERIC index
    order. hash_serialized_3 over our iteration order would have been wrong
    for every transaction with ≥256 simultaneously-live outputs.
  - **The unspendable blocker is solved as a VIEW, not a rebuild.**
    `bitcoin_utxo_stats.asm` applies Core's `CScript::IsUnspendable` (leading
    `OP_RETURN`, or size > `MAX_SCRIPT_SIZE` = 10,000) while ITERATING, so the
    ~22.2M dead entries stay on disk and stop counting. No rebuild, no cost to
    the running replay. Filtering at write time remains the (optional) storage
    change, and is still not done.
  - **Two real divergences from Core's chainstate were found by it**, both
    invisible to the count/amount/bogosize stages and visible only to the
    hash — which is precisely the argument for having a set hash at all:
    1. **The genesis coinbase.** `daemon/utxo_live.c` excludes it (Core never
       writes it to the chainstate); `daemon/build_utxo.c` does NOT. A
       batch-seeded set is one entry, 50 BTC and 117 bogosize richer than
       Core forever. `utxo_setinfo --exclude-genesis-coinbase` compensates at
       read time; the two writers still disagree with each other, and that
       should be fixed at the source.
    2. **BIP30 duplicate coinbases.** Core's exception path calls
       `AddCoin(..., possible_overwrite=true)`, so the LATER block's coin wins
       and Core's chainstate holds height 91,880 / 91,842. `utxo_lsm_put`
       returns "duplicate" and keeps the EARLIER coin, height 91,722 / 91,812.
       Same txid, index, value and script — so cardinality and value are blind
       to it. Proven exactly: with those two heights overridden, our MuHash at
       height 200,000 is byte-identical to Core's. **This is a false-accept
       shape**: our copy of a coinbase looks 158 blocks older than Core's, so
       between heights 91,880 and 91,980 we would have accepted a spend Core
       rejects as immature. Long past, and no such transaction exists — but
       the mechanism (duplicate put does not overwrite) is live code.
  - **Reading a live LSM.** `data/` is written continuously; a read that
    straddles a flush or compaction mixes states. The tool fingerprints every
    UTXO file's inode/size/nanosecond-mtime plus the directory itself, twice
    before the read and once after, and REFUSES on any change rather than
    guessing. `utxo_lsm_reload_ro` / `utxo_store_init_ro` make the whole read
    path genuinely read-only (the ordinary reload's `O_RDWR|O_CREAT` on
    utxo.dat/utxo.idx was the only write in the chain).
  - ~~Still missing, and deliberately: a live `gettxoutsetinfo` RPC~~ —
    **done 2026-08-25**; ~~the incrementally-maintained index~~ — **DONE
    2026-08-26** (`daemon/coinstats_index.c`): per-block MuHash fold with
    Fermat-inverse removal, persisted at the block durability point,
    seeded once by walk, adopted instantly thereafter; the RPC answers in
    ~33 ms and the incremental digest is PROVEN character-identical to the
    oracle's at a height folded incrementally (964204). Still refused by
    name: `hash_serialized_3` (muhash is our default).

## Wallet

Real, substantial: HD wallet (BIP32/39), message signing
(`bitcoin_bip32.asm`, `bitcoin_bip39.asm`, `wallet_msgsign.c`).

Missing:
- **PSBT (BIP174)** — ~~absent, zero hits anywhere~~ **substantially present
  since 2026-08-25**: `createpsbt`, `decodepsbt`, `converttopsbt`,
  `combinepsbt`, `joinpsbts` (all oracle-verified, several byte-identical)
  and `analyzepsbt` (full role machine, 14-vector oracle diff). Still
  missing from the tranche: `finalizepsbt`/`walletprocesspsbt` (need a PSBT
  signer) and `utxoupdatepsbt` (needs a UTXO lookup path) —
  `docs/PARITY_PLAN.md` T8 has the per-method state.
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
  `MSG_WITNESS_BLOCK`. ~~`MSG_WITNESS_TX` for transaction relay~~ — **DONE
  2026-08-26** with the receive-side tx relay (`daemon/tx_relay.c`, LOG
  slice-20 entry): announced transactions are now actually fetched (they
  were previously discarded unread), and fetched witness-complete.
  ~~Prefer/require `NODE_WITNESS` (0x8) peers~~ — **DONE 2026-08-26**:
  every outbound dial that can lead to fetching blocks or transactions
  (mux legs, parallel leg fill, boot catch-up, dlc header/chunk workers)
  checks the peer's advertised services right after the handshake and
  drops non-witness peers at dial time (`peer_has_witness`,
  daemon/main.c). ~~Re-announcing relay-received transactions~~ — **DONE
  2026-08-26**: accepts queue their txid, one inv per leg per rotation
  announces them (never back to the source), the drain serves
  MSG_TX/MSG_WITNESS_TX getdata from the pool and answers misses with
  notfound, and an ORPHAN POOL parks missing-inputs children, fetches
  their parents witness-typed, and cascades them in when the parent
  lands. Mempool admission itself now runs the CONSENSUS verifier
  (tx_verify_mempool: legacy scripts, full taproot, confirmed set +
  mempool parents, tip-anchored maturity). **Remaining:** serve the
  stripped form to a bare `MSG_BLOCK` request (affects only legacy
  inbound peers, of which this node currently has none) and BIP339
  `wtxidrelay`.
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
- ~~Addr self-advertisement~~ — **DONE 2026-08-26** (`daemon/addr_self.c`):
  external IPv4 from two agreeing peers' addr_recv views, announced with
  the CONFIGURED port on the 24h cadence.

## Mining

~~**Entirely absent.**~~ **Substantially present since 2026-08-25.**
`getblocktemplate` (BIP22/23: deterministic frame diffed against Core at the
same tip, the 2016-block retarget bit-exact against 8/8 real historical
boundaries, witness commitment recomputed per template; documented gaps —
sigops is a lower bound, tx ordering is valid but not fee-optimal, no
longpoll), `submitblock` end-to-end (8 MB transport, 4 MB worker channel,
BIP22 reason strings, connect gated on a dry run of the real apply path),
and `prioritisetransaction`/`getprioritisedtransactions`. Still absent: any
stratum/pool-facing interface, and BIP23 proposal mode.

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
