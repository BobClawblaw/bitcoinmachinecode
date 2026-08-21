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

## RPC surface — the single biggest gap

`rpc_dispatch` (`asm/rpc_commands.c:576`) implements exactly **8 methods**:
`getnewaddress`, `getrawchangeaddress`, `validateaddress`, `getaddressinfo`,
`gettxout`, `listunspent`, `getbalance`, `decoderawtransaction`. Everything
else falls through to `-32601 "Method not found"` — confirmed by reading the
function directly.

Checked for these as literal method-name strings across `asm/daemon/*.c` and
`asm/*.c` — **zero matches, every one**:
`getblockcount`, `getbestblockhash`, `getblockhash`, `getblock`,
`getblockheader`, `getrawtransaction`, `sendrawtransaction`,
`createrawtransaction`, `getpeerinfo`, `getconnectioncount`,
`getnetworkinfo`, `getblockchaininfo`, `getmempoolinfo`, `stop`, `uptime`,
`getmininginfo`, `estimatesmartfee`.

There is currently no JSON-RPC way to query chain state, broadcast a raw
transaction, or inspect node/network/peer status. (`sendtoaddress`/`send`/
`sign` exist, but only in the separate local CLI tool `wallet_cli.c`, not
over RPC transport.)

**Effort: large.** This is breadth, not depth — dozens of straightforward
methods across many categories (blockchain query, network status, raw tx,
util), each individually small, but there's a lot of it.

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
- **Taproot script-path spending (BIP342 tapscript)** — the crypto is
  written (`bitcoin_taproot_sighash.c`'s `tapscript_checksig`, ~340 lines)
  but has **zero callers** in the live verify path; `daemon/tx_verify.c`
  only calls `taproot_keypath_verify` (2 call sites). Script-path taproot
  spends would not validate correctly today even though the primitive
  exists. **Medium** — the hard crypto is done, this is a dispatch/wiring
  job, but consensus-critical, so needs the same rigor as everything else
  in this project.
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
- **`coinstatsindex` / `gettxoutsetinfo`** — absent.

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
