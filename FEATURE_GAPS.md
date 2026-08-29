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

**Update 2026-08-27 (late) — this document was itself audited.** The
"REMAINING gaps" list below had drifted badly: wallet management, the live
address index, mining polish, testnet4 and ZMQ were all still filed as
missing after they shipped, and the "two live UTXO-writer divergences" were
wrong on both counts (the genesis-coinbase one is in the OFFLINE batch tool,
not the live writer; the BIP30 one was fixed). A gap inventory that
overstates is exactly as misleading as one that understates — it sends work
at problems that are already solved. Every remaining item has now been
re-checked by reading the dispatch tables and the writers, not this file.
Also closed the same day: nBits schedule enforcement, `bumpfee`/
`psbtbumpfee`, and `gettxout` — which had been returning `null`, i.e.
"spent", for EVERY outpoint on the live node.

**Update 2026-08-27 — current state.** A large batch has landed since the
08-25 survey. This block is the authoritative "where we are"; the sectioned
body below is the older narrative, annotated inline where an item has closed.

CLOSED since 08-25 (evidence in parentheses; each verified against `asm/`).
The last four landed 2026-08-27 and are listed first:
- **nBits schedule enforcement** (`bad-diffbits`) — one shared rule engine
  (`asm/bitcoin_pow_rules.c`) behind getblocktemplate, the apply path and
  fork evaluation, replayed against EVERY header of the real mainnet
  (964,265 heights / 478 boundaries) and testnet4 (149,954 / 101,009
  min-difficulty / 16,491 walk-backs) chains.
- **`bumpfee` / `psbtbumpfee`** — Core feebumper semantics; proven end to
  end against a real Core (`validation/bumpfee_regtest_e2e.sh`), which
  ACCEPTS the replacement and drops the original.
- **`gettxout`** — the RPC now asks the download worker over a socketpair;
  diffed against Core's answer on the same outpoint. It had been returning
  `null` for every outpoint, which means "spent", not "unknown".
- **`getbalance`/`listunspent`** — answer from the wallet rescan rather than
  the (default-OFF) address index, so a funded wallet no longer reports
  `0.00000000`.
- **txindex** — offline base build + daemon-maintained incremental tail
  (`daemon/tx_index_tail.c`); `getrawtransaction <txid>` works with no block
  hash.
- **coinstatsindex** — incremental per-block MuHash fold, persisted, adopted
  instantly on boot; `gettxoutsetinfo` answers in ~33 ms and the digest is
  proven character-identical to Core's oracle at a folded height
  (`daemon/coinstats_index.c`).
- **blockfilterindex** (BIP157/158) — whole-chain filter index AND filter
  headers, tip-following (`daemon/bfilter_index.c`,
  `daemon/build_block_filters.c`).
- **Receive-side tx relay + orphan pool + re-announce + getdata service** —
  announced txs are fetched witness-typed, missing-parent children parked and
  cascaded, accepts re-announced to peers, MSG_TX/MSG_WITNESS_TX getdata
  served (`daemon/tx_relay.c`). Mempool admission runs the CONSENSUS verifier
  (`tx_verify_mempool`).
- **Core-style mempool management** — TrimToSize feerate eviction of
  lowest-feerate leaves, blob compaction, dynamic `mempoolminfee`, and the
  Core-exposed limits (`minrelaytxfee`/`incrementalrelayfee`/
  `limitancestor{count,size}`/`limitdescendant{count,size}`/`mempoolfullrbf`)
  wired to `bitcoin.conf` (`bitcoin_mempool_policy.c`, `daemon/mempool_compact.c`).
  This also fixed a production freeze at exactly 4096 txs.
- **Wallet at-rest encryption** — `encryptwallet` / `walletpassphrase` /
  `walletpassphrasechange` / `walletlock`, AES-256 (FIPS-197) + Core's
  BytesToKeySHA512AES crypter proven byte-identical to OpenSSL
  (`bitcoin_aes.c`, `daemon/wallet_crypter.c`, `daemon/wallet_enc_state.c`).
- **`walletprocesspsbt`** — the PSBT Signer role by delegation
  (`rpc_wallet_ops.c`); `finalizepsbt`/`utxoupdatepsbt` are real
  (`rpc_commands.c`).
- ~~**`gettxout` cannot reach the live UTXO set**~~ — **FIXED 2026-08-27**
  (`refusal` then the real fix). The embedded RPC server runs in the serve
  PARENT and has no UTXO handle; it used to answer `null` for every outpoint,
  which does not mean "unknown" — it means "spent". The node was asserting
  that about every coin in existence.
  Building a read-only view in the parent was measured and REJECTED on cost,
  not safety: `utxo_lsm_reload_ro` takes 60.4/61.9/72.1/73.2/79.4/82.6 s on
  the real 165M-entry set (six production boots) and every block invalidates
  it. Instead the parent ASKS the download worker over a socketpair created
  before the fork; the worker already has the set open and answers
  `utxo_lsm_get` in microseconds.
  The worker replies only at a QUIESCENT point in its loop (after the
  catch-up call). `utxo_lsm_get` is thread-safe on its own — `lsm_get_scratch`
  is TLS — but this module guarantees `get()` and `flush()` never overlap *by
  construction*, and a query thread would have broken exactly that.
  Every failure is a REFUSAL, never a guess: no worker, timeout, short read,
  lost framing. The response echoes the outpoint it answers, because a
  timed-out query leaves its reply in the socket and the next query would
  otherwise read a well-formed answer about the WRONG coin (`test_txoq_ipc`
  pins this; verified fail-then-pass).
  Proven in `validation/bumpfee_regtest_e2e.sh`: `gettxout` on an unspent coin
  matches **Core's `gettxout` exactly**, and a spent outpoint is null from both.
  That first real diff also caught `value` being emitted as a JSON *string*
  where Core emits a *number* — fixed here, along with the same shape bug in
  `listunspent.amount` and `getbalance`.
- ~~**`connect=<host>:<port>` ignores a non-default port**~~ — **FIXED
  2026-08-27** (`be7ef33`): any port is honoured, the host stays stored bare
  and the port rides a parallel array read via `node_config_peer_port()`.
- ~~**`getbalance`/`listunspent` read the address index**~~ — **FIXED
  2026-08-27** (`0994198`): with no address argument they enumerate the
  wallet's coins from the rescan records (spent-ness from the scan's own
  spend records); an explicit address still uses the index. Scan format grew
  `is_coinbase` (BMCWSCN3) so coinbase maturity is respected; older BMCWSCN2
  files are still read.
- **nBits schedule enforcement (Core's `bad-diffbits`)** — a peer's headers
  must now carry exactly the bits `GetNextWorkRequired` demands for their
  height, checked in fork evaluation (`reorg_analyze`) AND at apply
  (`utxo_live`), including the submitblock/GBT-proposal dry run. One shared
  rule engine (`asm/bitcoin_pow_rules.c`) also backs `getblocktemplate`, so
  mining and validation cannot drift. Chain-aware: fPowNoRetargeting,
  fPowAllowMinDifficultyBlocks + the 20-minute exception + Core's walk-back,
  BIP94. Replayed against every header of the real mainnet chain (964,265
  heights, 478 boundaries) and the real testnet4 chain (149,954 heights,
  101,009 min-difficulty blocks, 16,491 walk-back re-anchors) —
  `validation/pow_replay.c`, both exact. This closes the gap `reorg.c`
  itself used to call out: "retarget validation is a real gap in this node's
  consensus rules ... chainwork comparison is what contains it."
- **wtxidrelay (BIP339)** + **stripped-block serving to bare MSG_BLOCK** +
  **addr self-advertisement** (`daemon/addr_self.c`) + **NODE_WITNESS peer
  preference** — the networking gaps the 08-25 P2P section listed as remaining.
- **Chain selection — regtest** — `chain=regtest`/`regtest=1` selects Core's
  regtest chain: runtime network magic, derived+hash-asserted regtest
  genesis, generated regtest script-flag schedule, subsidy halving 150,
  fPowNoRetargeting, `bcrt`/0x6f/0xc4 addresses, per-chain datadir
  (`<datadir>/regtest/`) and chain-tagged logs (`daemon/chainparams.c`,
  `bitcoin_net.asm` `net_magic`, `bitcoin_script_flags.asm` `sfc_chain`).
  Differentially proven against a scratch Core regtest: 161/161 block hashes
  identical, `gettxoutsetinfo` muhash identical, a block built from bmc's own
  `getblocktemplate` mined and ACCEPTED by Core, live tip-follow, wallet tx
  relayed into bmc's mempool. `tests/test_chainparams` (29 checks).

REMAINING gaps, precisely (this is the real backlog).

**Re-verified 2026-08-27 against the code, not against this document.** The
previous version of this list had gone stale in five places and was
OVERSTATING the backlog — wallet management, the live address index, mining
polish and testnet were all listed as missing after they had shipped, and the
"two live UTXO-writer divergences" were wrong on both counts. An inventory
that overstates is no more honest than one that understates; both are wrong
about where the work is. What follows was checked by reading the dispatch
tables and the writers themselves.

- ~~**Blocks downloaded after boot cannot be served**~~ — **CLOSED
  2026-08-28**, hours after being found. `serve_idx_topup` folds in every
  height `index.dat` has gained since this process last looked: the parent
  tops up before forking a serve child (so the child inherits a current
  index) and the getdata handler tops up too (so a long-lived connection
  cannot go stale). The same incremental top-up `rpc_chain.c`'s `refresh()`
  already did for the RPC side — borrowed, not invented, which is why the RPC
  layer never had the bug. Proven on regtest against Core: a block mined
  minutes after boot is served without a restart.
- ~~**A `getdata` miss is answered with SILENCE**~~ — **CLOSED 2026-08-28.**
  Misses are collected and returned as `notfound`, the entries copied
  verbatim. An unrecognised inv TYPE is still ignored rather than reported,
  which is what Core does.
- ~~**BIP157 compact filters are BUILT but never SERVED**~~ — **CLOSED
  2026-08-28.** `getcfilters`, `getcfheaders` and `getcfcheckpt` are all
  answered (`daemon/serve_cfilters.c`), from stateless `bfi_get_file`
  lookups. Verified against Core on the same chain and not merely by message
  name: the `cfilter`, `cfheaders` and `cfcheckpt` payloads are
  **byte-identical** to Core's for the same request. Requires the filter
  index to have been built (`daemon/build_block_filters`), exactly as Core
  requires `-blockfilterindex`.
- ~~**addrv2 (BIP155) is parsed but never NEGOTIATED.**~~ — **CLOSED
  2026-08-28.** Both handshake roles offer `sendaddrv2` after version and
  before verack, gated on peer protocol >= 70016 as Core does, and remember
  the peer's own offer; such a peer gets BIP155-encoded `addrv2` for getaddr
  replies and self-announcements. Proven against a real Core: it logs
  `received: sendaddrv2` from us with no after-verack complaint, receives a
  42-byte `addrv2` for its getaddr (its own size for those records), and its
  getnodeaddresses lists every planted address. *(The claim that
  `bitcoin_addrmgr.asm` "has the addrv2 codec" was also wrong: it had a
  v1 encoder only, and the v1 encoder was itself wrong -- IPv4 at the wrong
  offset with no ::ffff: marker, one-byte count -- with its test pinning the
  mistake. And the serve loop's getaddr reply had NEVER answered anyone: its
  loop bound lived in a register the callee took as an argument. All three
  fixed the same day; `addrv2` decoding for the book exists only in
  `daemon/addr_ingest.c`.)* An adversarial review before merge found two
  more, both pre-existing and both fixed: the book stored ports in two byte
  orders (604 of the live node's 5,990 records byte-swapped;
  `validation/peers_dat_port_audit.py` repairs it), and the v1 ingest parser
  read the IPv4 from the wrong offset and fabricated addresses from
  timestamps. Later the same day: outbound legs fold addr/addrv2 gossip
  into the book (Core's per-address token bucket + the existing quotas), a
  post-verack sendaddrv2/wtxidrelay disconnects as in Core (the probe now
  reports `<disconnected>` and reads identically for both nodes), and the
  real daemon's per-leg negotiation is asserted end to end. Still IPv4-only
  storage: Tor/I2P/CJDNS addresses now arrive but are not kept -- a
  record-format change, and the node has no Tor/I2P transport to use them.
- **Full-verification IBD benchmark vs Core** (`-assumevalid=0
  -stopatheight`, second scratch datadir) — **still never run.** The one
  like-for-like end-to-end speed comparison, and the only item here that is
  purely a measurement rather than a capability.
- **`assumevalid`** — parsed and then IGNORED, with a loud `[config]` line
  saying so. This node verifies every script in every block
  (`tx_verify_block_connect_all`, called from `daemon/utxo_live.c`'s apply
  path ahead of any UTXO write, and proven by the full-archive replay);
  honouring assumevalid would mean *skipping* that, so it is a deliberate
  refusal rather than an unimplemented feature. Small to wire if ever wanted.
  *(The `[config]` line itself was STALE until 2026-08-28 — it claimed block
  connection did no script verification at all, describing the node as it was
  before Stage D. It was believed over the code and briefly propagated into
  this file. Log strings that explain a decision age exactly like refusal
  strings do; see the wallet refusals deleted 2026-08-27.)*
- **`assumeutxo` / `loadtxoutset`** — refuses BY DESIGN. Every parity claim
  this project makes rests on locally-validated coins, and importing a
  snapshot would hollow that out. `dumptxoutset` is real (proven at full
  165.7M-coin scale).
- ~~**Mempool persistence (`savemempool`/`importmempool`)**~~ — **CLOSED
  2026-08-27.** Core's `mempool.dat`, verified in BOTH directions against a
  running Core: it loads the dump this node writes, and this node loads the
  dump it writes. We write version 1 (Core's own `-persistmempoolv1` form,
  read unconditionally; v2's obfuscation key is random so no writer can
  produce a byte-comparable artifact) and read both. `importmempool`
  re-submits each transaction through the normal admission path. Not
  restored: entry times, fee deltas, and the unbroadcast set — each stated at
  the call site. *(This item was missing from the 2026-08-27 audit of this
  list, which tracked it only in `docs/RPC_LIVE_NODE.md`. The audit was more
  accurate than what it replaced but not complete.)*
- ~~**Package relay**~~ — **CLOSED 2026-08-27 (evening).** All five parts:
  - `submitpackage` (context-free package policy with Core's reason strings,
    in-package parent resolution, Core's effective feerate);
  - **p2p 1p1c package RELAY** — a parent rejected for fee ALONE is now
    classed `-28` "reconsiderable" (Core's `TX_RECONSIDERABLE`) instead of
    being collapsed into the general reject class, and the drain submits it
    with a waiting orphan child as a package (Core's `Find1P1CPackage`).
    Both arrival orders work: a reconsiderable parent buys a bounded number
    of request-ring bypasses so a child arriving later can trigger a
    re-fetch, which is exactly why Core keeps that filter separate from
    recent-rejects;
  - **BIP431 TRUC/v3** topology, both directions of the inheritance rule;
  - **ephemeral dust** (one dust output, 0-fee carrier, child must sweep);
  - **`replaced-transactions`** — top level of `submitpackage`, as the union
    across members (NOT per member);
  - **`testmempoolaccept` package mode** — the array is staged as one package
    through the same path `submitpackage` uses, stopped before the commit.

  The wire path and the RPC path share one implementation of package
  validation, so a package off the wire and one off the RPC socket cannot
  disagree. Proven against Core v31.99 on regtest
  (`validation/bumpfee_regtest_e2e.sh`, 46 checks).

  STATED GAPS, both strictly more conservative than Core:
  - **TRUC sibling eviction** is not implemented, so a second TRUC child is
    refused rather than being allowed to replace its sibling under RBF rules.
  - Core's `package-error` is `"TOKEN, debug detail"` naming the offending
    txid and wtxid in prose; ours carries the token alone. The verdict
    matches; the diagnostic string is shorter.
- ~~**Wallet-import RPCs**~~ — **ONE left, 2026-08-27.** Five of the six were
  not actually blocked; they shared a reason ("a single BIP32 seed with no
  import path") that was wrong for them, or had stopped being true:
  - **`migratewallet`** and **`createwalletdescriptor`** answer Core's OWN
    verdict for a wallet of this shape — "already a descriptor wallet", and
    "Descriptor already exists" for the type it has. Real answers reached the
    same way Core reaches them. `createwalletdescriptor`'s other three types
    are refused with the SPECIFIC reason: the key derivation is trivial, but
    a descriptor whose outputs the rescan cannot recognise and
    `getnewaddress` will never hand out would be a descriptor in name only.
  - **`importprunedfunds` / `removeprunedfunds`** import no KEY material —
    only the knowledge that an output we already own exists, which is what
    made them look blocked. Built from pieces that existed: `verifytxoutproof`
    for the BIP37 walk and in-chain check, `wscan_spk_h160` for "is this
    ours", and a new `wscan_write` that owns the on-disk layout.
  - **`setwalletflag`** implements `avoid_reuse` for real — coin selection
    skips a destination this wallet has already spent from, and
    `getwalletinfo` reports it. A stored-and-ignored flag would be worse than
    refusing.

  ~~**Still refused: `addhdkey`**~~ — **CLOSED 2026-08-27 (late).** It was the
  only one genuinely blocked, and closing it needed three things, not one:
  the key is stored through the mnemonic's OWN KDF/cipher/tag (an xprv in
  plaintext beside an encrypted seed would be the weakest thing in the
  directory, so without a passphrase it refuses); the record format gained an
  `hdkey` byte (**BMCWSCN4**) because two HD keys collide on
  (keyidx, branch) and an output paying one resolved to the other's address;
  and the signer now holds the added keys, since a wallet that watches
  outputs it cannot sign reports coins as spendable that are not. Formats 2
  and 3 still read, and `hdkey = 0` is the truth for them.

  Two real bugs surfaced doing it: `bip32_extkey_serialize` hardcodes
  **mainnet** version bytes in assembly, so every xpub this node produced was
  rejected by Core on regtest/testnet4 ("key is not valid") — the pair now
  lives in chainparams; and a chaincode aliasing bug in the second derivation
  step.

  **No wallet RPC is refused wholesale any more.**

  Proven on regtest against a real chain: removing a confirmed wallet output
  drops the balance by exactly its 50 BTC, importing it back with a real
  `gettxoutproof` restores it to the satoshi, a second import does not
  double-count, and a garbage proof is refused.
- ~~**`build_utxo.c` includes the genesis coinbase**~~ — **CLOSED
  2026-08-27.** The rule now lives in `daemon/genesis_skip.h`, included by
  both the live writer and the offline builder, because a second copy of
  three chain hashes is how two writers come to disagree about what the UTXO
  set is. Proven on real regtest blocks in the e2e.
  Found while fixing it: **`daemon/build_utxo` had not LINKED** since
  `utxo_script_unspendable` was added to it — missing from its object list,
  and the tool is not part of `make test`, so nothing caught it. It is in the
  gate now, which is the actual fix.
- ~~**`bumpfee`'s replaced-by linkage is write-only in practice**~~ —
  **CLOSED 2026-08-27.** The cause was one layer down from where this was
  filed: `gettransaction` answers from the wallet SEND JOURNAL, and *nothing
  in the daemon ever wrote that journal* — only the `wallet_cli` tool did. A
  bump performed over RPC therefore recorded a linkage no RPC could read
  back. Both transactions are journalled now, not just the replacement:
  `replaced_by_txid` on the ORIGINAL is the direction a caller actually asks
  for. Both directions proven in the regtest e2e.
- **`lsm_get_scratch` is 4 MiB + 64 KiB of per-thread TLS** — MEASURED
  2026-08-27 and deliberately NOT changed. The download worker runs 33
  threads, so this is ~134 MiB of demand-paged `.tbss` against that process's
  3.8 GB RSS, on a 60 GB machine with 45 GB available. Buying it back means
  calling `malloc` from hand-written assembly at four sites in the UTXO read
  path — the hottest and most safety-critical code in the tree. Bad trade at
  this size; recorded as a measurement rather than left as vague debt. (It is
  a FOOTPRINT item, not a correctness one: an earlier note here called it
  non-thread-safe and pending — it has been thread-local, `section .tbss`,
  Initial-Exec, since the incident-#13 work.)
- **testnet / signet** — REFUSED by design (`daemon/chainparams.c` rejects
  `chain=test`/`signet` loudly rather than run the wrong rules). Supported:
  **main, regtest and testnet4** — testnet4's whole chain synced with a
  byte-identical muhash vs Core.
- **Tor/I2P/onion, REST interface, UPnP/NAT-PMP, Bitcoin-Qt GUI** — absent by
  design (not gaps for an asm/daemon consensus project).

CLOSED since the previous revision of this list, each with its evidence in
LOG.md: wallet management (multiwallet + watch-only descriptors + BnB coin
selection), the live address index (`addrindex=1`), mining polish (CPFP
templates, exact sigops, BIP23 proposal mode, longpoll), chain selection for
regtest AND testnet4, nBits schedule enforcement, `bumpfee`/`psbtbumpfee`,
and `gettxout` (which had been answering `null` — i.e. "spent" — for every
outpoint on the live node).


**Update 2026-08-29.** A security + parity audit, then three days of closing
what it found. Every finding is fixed and deployed (`am`, `an`, `ao`).

*Measured, not estimated.* Both sides were re-extracted from source rather
than trusted:

| surface | state |
| --- | --- |
| **Public RPC methods** | **155 / 155.** The 16 Core methods absent here are *all* in Core's own `hidden` category — mining, test scaffolding, chain manipulation, debug introspection. Two of those were added anyway because the data already existed: `getrawaddrman` and `getorphantxs`. |
| **Config options** | **~73 / 163 (45%).** Of the ~90 missing, ~40 are not applicable (18 wallet — this node has its own format; 16 debug/test; 4 block creation — it does not mine; IPC). |
| **Chains** | main, testnet4, regtest. **signet and testnet3 absent** — and refused explicitly at startup rather than started with the wrong rules. |
| **Indexes** | txindex, coinstatsindex, blockfilterindex, addrindex. **txospenderindex absent.** |
| **P2P protocol** | addrv2, compact blocks, BIP157/158, package relay, all five BIP155 networks, **inbound Tor**. **BIP324 v2 transport and Erlay absent.** |

*Closed since 08-28:* `minimumchainwork` (was absent entirely); RPC **cookie
authentication** plus a constant-time credential compare; `bantime` with
automatic misbehaviour scoring **and ban enforcement on inbound**, which had
been outbound-only; `-datadir`/`-conf`; operator control of both indexes;
`permitbaremultisig` as a real gate; `networkactive`; `forcednsseed`; `pid`;
four `-*notify` hooks; **inbound Tor** end to end; **`asmap`** AS-level
bucketing; `maxreceivebuffer` (which had been parsed and read *nowhere*);
`maxsendbuffer`; the five ZMQ high-water marks.

*The systemic fix matters more than any single option.* There is now an
explicit list of Core options this node does **not** implement, and each one
present in the config is named at startup:

```
[config] whitelist= is a Bitcoin Core option this node does not implement -- it has NO EFFECT
```

That retires a failure mode this codebase reproduced repeatedly: `externalip`
parsed and never read, `permitbaremultisig` *reported* by `getmempoolinfo`
while nothing could set it, `whitelist=rpc` sitting in the live config doing
nothing, `maxreceivebuffer` and `walletnotify` both parsed and inert. A test
asserts the list and the implementation move together in **both** directions.

*Deliberately not done, and why.* `bytespersigop` needs Core's
`max(weight, sigop_cost x bytes_per_sigop)` at fee-check time, but this
node's `vsize` comes from weight alone and the sigop cost is recorded after
acceptance — implementing it means restructuring when that cost is computed,
and a half-wired fee policy is worse than an absent option.
`persistmempool`'s machinery (`mempool_dump_write`/`read`) is written and
tested but called from nowhere; wiring the save path touches shutdown, which
must stay fast for the SIGKILL window. `fixedseeds` gates a hardcoded IP seed
list this node does not have. All three stay on the warning list.

*Remaining, in the order worth doing it:* BIP324 v2 transport (the only major
protocol gap, and a multi-session piece on its own); signet; `reindex` and
`persistmempool`; `whitelist`/`whitebind` peer permissions; the RPC surface
(`rpcauth`, `rpcallowip`, `rpcbind`, `server`, `rest`) — lower urgency now
that cookie auth exists and the listener cannot leave loopback; then Erlay.

*A caveat on the headline number.* 45% badly understates the node. It
implements every public RPC, all five BIP155 networks, package relay, compact
blocks, BIP157/158, wallet encryption, pruning, and a consensus layer verified
block-by-block against the real chain. What it lacks is mostly
**operator-facing configurability** plus two protocol features. RPC parity is
essentially complete while config parity is under half — a node can be nearly
complete functionally and still look half-finished by option count.

## How this list is checked (2026-08-28)

Claims here were audited against evidence rather than against each other,
after a `[config]` log string was believed over the code and briefly
propagated into this file (see `assumevalid`). Two tools do it:

- `validation/p2p_inbound_probe.py` — speaks the wire protocol as a stranger
  and records what a node answers to each inbound message. Run it against
  Bitcoin Core and against this node on the same chain and diff the reports.
  A message Core answers and we ignore is a gap; it found three on the day it
  was written.
- an RPC-surface diff against a live Core: **155 Core methods, and the only
  one missing here is `rpc.discover`** (OpenRPC). Re-verified 2026-08-28
  against Core v31.99 rather than taken from an earlier claim.

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

- ~~**`index.dat` hash byte order vs `bitcoin_idx.asm`**~~ — **CHECKED AND
  FIXED 2026-08-27** (`392872b`), and it was worse than this entry guessed.
  index.dat holds WIRE order; the loader reversed every record believing it
  held display order, so the boot hash index was keyed on DISPLAY hashes
  while the serve loop looks up with the hash as it arrives on the p2p wire.
  `.gd_block` could never hit: **the node served no block requested by
  getdata, ever** — not even a notfound. Three tests missed it because each
  encoded the loader's belief rather than the file's contents (test_serve
  built its own index without reversing, bench_hashidx compared against a
  reference that reversed identically, test_truncate reversed its lookups);
  all three now build and look up the way production and the wire do.
- ~~**Inbound serving stalled 63 s per connection**~~ — **FIXED 2026-08-27**
  (`1b62d67`), found while proving the above. Every forked serve child opened
  its own read-only UTXO snapshot before its read loop, and
  `utxo_lsm_reload` costs 60–83 s on the real set, so a peer got no response
  at all — not even the feefilter — until it had long since hung up. Now
  opened once in the parent pre-fork and inherited copy-on-write, the same
  discipline the shared mempool beside it already used and the same thing
  Core does (`InitCoinsDB` once in `LoadChainstate`; Core never re-opens the
  UTXO per connection and never forks per connection). Measured on mainnet:
  63 s to serve a block before, under a second after. It also stopped each of
  245 possible inbound peers mapping its own copy of the snapshot.
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

- **`assumevalid`** — explicitly ignored, with a `[config]` line saying so.
  Small to wire (config parsing already exists), and still declined: it
  exists to skip the per-input script verification that block connection
  performs, which is the thing this project is for.
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
- ~~**Chain selection** — mainnet only. No testnet/signet/regtest handling in
  `node_config.c`; mainnet magic bytes are hardcoded directly in
  `bitcoin_net.asm`/`bitcoin_store.asm` (3 literal occurrences each), no
  chain-params abstraction layer.~~ — **REGTEST DONE 2026-08-27**
  (`daemon/chainparams.c`). `chain=regtest`/`regtest=1` selects Core's
  regtest chain through a single chain-params layer: the network magic is now
  a runtime dword (`bitcoin_net.asm` `net_magic`), the script-flag schedule
  branches on a runtime selector (`bitcoin_script_flags.asm` `sfc_chain`) with
  regtest heights generated from `CRegTestParams`, the genesis is derived from
  the mainnet bytes and hash-asserted against Core's own value, and each chain
  gets its own datadir (`<datadir>/regtest/`) + chain-tagged logs. Proven
  block-for-block and muhash-identical against a scratch Core regtest, with a
  bmc-built `getblocktemplate` block accepted by Core. testnet/signet remain
  REFUSED by design (only main and regtest supported). The block-archive
  container marker stays mainnet's `f9beb4d9` deliberately — it is this
  project's own file format, not the wire protocol, and chains never share a
  datadir.
- **Package relay** (Core's v3/ephemeral-dust multi-tx package acceptance,
  distinct from the RBF/ancestor-limit checks below) — not confirmed either
  way with high confidence; worth a closer look if it matters.
- Mempool policy (RBF/BIP125 replacement-fee checks, ancestor/descendant
  count+byte-budget limits) is **genuinely implemented**, not stubbed
  (`bitcoin_mempool_policy.c`) — positive surprise, expected this to be thin.
  **Extended 2026-08-27:** now also does Core-style TrimToSize (evict
  lowest-feerate leaves + blob compaction), a dynamic `mempoolminfee`, and
  reads the Core-exposed limits from `bitcoin.conf`
  (`minrelaytxfee`/`incrementalrelayfee`/`limitancestor{count,size}`/
  `limitdescendant{count,size}`/`mempoolfullrbf`). Divergence from Core:
  individual-leaf eviction, not descendant-package eviction.

## Indexing

- ~~**`txindex`** — explicitly ignored; `getrawtransaction` by bare txid
  won't work.~~ — **DONE 2026-08-26**: offline base build
  (`daemon/build_tx_index`, ~29 GB, 8-byte prefix keys exact-by-
  verification) + daemon-maintained incremental tail
  (`daemon/tx_index_tail.c`) that backfills at boot and follows the tip, so
  `getrawtransaction <txid>` works with no block hash and `getindexinfo`
  reports the real combined coverage.
- ~~**Address index**~~ — **LIVE since 2026-08-27** (`addrindex=1`, default
  OFF because Core has no address index at all; this is a deliberate
  extension). `daemon/addr_index_tail.c` maintains it at the same new-block
  choke point as the txid and filter tails, sharing one classifier with the
  offline builder so the two structurally cannot disagree. Described here as
  "offline batch tool only" after it had shipped — corrected 2026-08-27.
  Note the consequence recorded in the Wallet section: `getbalance`/
  `listunspent` read this index for an explicit address, but answer from the
  wallet RESCAN when no address is given.
- ~~**`blockfilterindex`** (BIP157/158, "neutrino" light-client support) —
  absent.~~ — **DONE 2026-08-26** (`daemon/bfilter_index.c`,
  `daemon/build_block_filters.c`): whole-chain BIP158 basic filters AND the
  filter-header chain, tip-following; `getblockfilter` serves them.
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
**At-rest encryption DONE 2026-08-27** (`bitcoin_aes.c`,
`daemon/wallet_crypter.c`, `daemon/wallet_enc_state.c`): `encryptwallet` /
`walletpassphrase` / `walletpassphrasechange` / `walletlock`, AES-256 under
Core's BytesToKeySHA512AES KDF (proven byte-identical to OpenSSL), the live
RPC seed gated behind an unlock timer.

Missing:
- **PSBT (BIP174)** — ~~absent, zero hits anywhere~~ **substantially present
  since 2026-08-25**: `createpsbt`, `decodepsbt`, `converttopsbt`,
  `combinepsbt`, `joinpsbts` (all oracle-verified, several byte-identical)
  and `analyzepsbt` (full role machine, 14-vector oracle diff).
  ~~Still missing from the tranche: `finalizepsbt`/`walletprocesspsbt` /
  `utxoupdatepsbt`.~~ — **DONE 2026-08-26**: `walletprocesspsbt` is the PSBT
  Signer role by delegation (`rpc_wallet_ops.c`), and `finalizepsbt` /
  `utxoupdatepsbt` are real (`rpc_commands.c`). `descriptorprocesspsbt`
  honestly refuses (no descriptor engine). `docs/PARITY_PLAN.md` T8 has the
  per-method state.
- ~~**Descriptor wallets**~~ — **`importdescriptors` is REAL** since the
  wallet-management merge; watch-only descriptors are tracked and rescanned.
  *(This paragraph claimed `createwalletdescriptor` and `addhdkey` were
  "still refused" until 2026-08-28, when all three methods below were probed
  against the LIVE node and answered. Both had closed on 08-27; the summary
  block above said so while this line did not. Stale in the same direction as
  the `assumevalid` log string — see "How this list is checked".)*
  `addhdkey` is REAL (a second HD key the wallet can actually spend);
  `createwalletdescriptor` answers Core's own verdict for the type this
  wallet has and refuses the other three with a specific reason.
- ~~**Watch-only wallets**~~ — watch-only descriptors are supported, and
  `exportwatchonlywallet` is REAL (closed 2026-08-27; this line claimed it
  still refused until 2026-08-28).
- ~~**Multi-wallet**~~ — **REAL**: `createwallet`, `loadwallet`,
  `unloadwallet`, `restorewallet` and `listwallets` all work; the lifecycle
  is exercised end-to-end in `tests/test_rpc_wallet_ops`. This was described
  here as "the largest remaining gap" long after it had shipped — corrected
  2026-08-27.
- Coin selection — present but basic (`listunspent`/`getbalance` exist); no
  evidence of a sophisticated algorithm like Core's Branch-and-Bound. Not
  confirmed in depth either way.

## P2P / networking — stronger than expected

Confirmed genuinely wired into the real serve loop (`bitcoin_serve.asm`),
not just present as unused/tested-in-isolation code:
- **BIP152 compact blocks** — both directions (`cmpctblock_build`,
  `p2p_blocktxn_build`, full message handling).
- **wtxid relay, feefilter, sendheaders** — all genuinely
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
  mempool parents, tip-anchored maturity). ~~**Remaining:** serve the
  stripped form to a bare `MSG_BLOCK` request and BIP339 `wtxidrelay`.~~ —
  **BOTH DONE 2026-08-26/27** (`daemon/block_strip.c`; `wtxidrelay`
  handshake in `bitcoind.asm`).
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
- ~~**Tor / I2P / onion support** — zero hits for tor/.onion/torcontrol.~~ —
  **IN PROGRESS 2026-08-28, phase 1 of 4 landed:** a generic BIP155 address
  type (`daemon/netaddr.c`, with SHA3-256 and RFC 4648 base32 for onion v3 /
  b32.i2p names), a version-2 address book for every network
  (`daemon/addrbook.c`, migrated from the IPv4-only `peers.dat`), ingest and
  getaddr replies for all networks, real per-network RPC fields, and Core's
  `addpeeraddress`. Proven against Core: it accepts our onion/i2p/cjdns
  entries into its own addrman. **Phases 2-3 also landed 2026-08-28: this
  node now DIALS BITCOIN PEERS OVER TOR AND I2P.** `daemon/socks5.c`
  (Core's netbase Socks5 byte for byte), `daemon/torcontrol.c` (ADD_ONION
  ED25519-V3, key persisted as Core names it), `daemon/i2psam.c` (SAM 3.1)
  and `daemon/dialer.c` (per-network routing, `-onlynet`, stream isolation).
  Proven with Bitcoin Core behind its own onion service on the real tor:
  Core reports us as an inbound peer with `"network": "onion"` and a
  completed handshake; and with a real remote I2P stream. **Phase 4 also
  landed 2026-08-28: IPv6 sockets (`daemon/net6.c`, v6-only listener beside
  the IPv4 one) and therefore CJDNS.** Proven against a real cjdroute with
  its tun up: Core binds its P2P port to our `fc00::/8` address, this node
  dials it, and Core reports the peer as `"network": "cjdns"` with a
  completed handshake; without `-cjdnsreachable` the peer is refused, as in
  Core. **All five BIP155 networks are now storable, relayable and
  dialable.** Remaining, and stated: no inbound onion service of our own
  (`-listenonion` parses but this node does not yet ADD_ONION for itself --
  `daemon/torcontrol.c` exists and is tested, it is not yet called at boot),
  and I2P inbound (`STREAM ACCEPT`) is implemented but not yet wired to the
  serve loop.
- ~~**ZMQ notification interface**~~ — **REAL since 2026-08-26**:
  `hashblock`/`hashtx`/`rawblock`/`rawtx` publish over a hand-written ZMTP
  3.1 PUB socket (`daemon/zmq_notify.c`, `daemon/zmq_pub.c`), with
  `getzmqnotifications` dispatched. Core only exposes that method when built
  WITH zmq, which the census Core was not — so this is one method BEYOND the
  surface the census measured.
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
