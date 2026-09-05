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
copy-on-write copies; `estimatesmartfee` (*until 2026-09-01* Core's contract
over our own accepted-feerate EMA — since then Core's CBlockPolicyEstimator
itself, see the fee-estimation update below); mining's `getblocktemplate`
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
- **txospenderindex** (Core v30+ `-txospenderindex`) — **DONE 2026-09-01**: the
  same shape as txindex — an offline sorted base (`daemon/build_txospender_index`,
  28-byte records keyed by spent outpoint, ~35 GB for mainnet) plus a
  daemon-maintained tail (`daemon/txosp_tail.c`, contiguous by boot
  backfill, watermark follows reorg truncation); every candidate is verified
  against the archive before it is answered. `gettxspendingprevout` gains
  Core's `options` (`mempool_only` defaults to "true if the index is
  unavailable", `return_spending_tx`), answers confirmed spends with
  `spendingtxid` + `blockhash`, and raises Core's "Mempool lacks a relevant
  spend, and txospenderindex is unavailable." exactly when Core would;
  `getindexinfo` reports it. Enabled by the presence of `txospender.dat`
  (like txindex). `tests/test_txospender_index` runs the real builder on a
  synthetic archive end to end (28 checks, incl. a prefix-collision reject).
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

- **Chain selection — signet (BIP325)** *(closed 2026-08-30)* —
  `chain=signet`, plus `signetchallenge=` for a custom signet. The genesis is
  derived from mainnet's and PROVEN against Core's asserted hash at selection
  time; the network magic is DERIVED (`sha256d(CompactSize(len) || challenge)`
  → `0a03cf40`), not pasted, so a custom challenge yields a different magic and
  the two networks cannot hear each other.

  On signet the block SIGNATURE replaces meaningful proof of work, so it is
  the one rule that cannot be approximated. It runs through the SAME
  interpreter and secp256k1 as mainnet script (`daemon/signet*.c`), gated at
  both full-block sites through one inline so they cannot drift, and on
  `check_pow` in `blk_submit` exactly as Core gates on `fCheckPOW` (BIP23
  proposal mode has no signature yet).

  Evidence: a live sync of the public signet holding the same chain as Core
  (hashes identical at heights 1/1000/5000/9000/9201, UTXO set built, zero
  rejects); 18 real blocks verified through this node's own interpreter, with
  the vectors anchored to the miner's real signatures (the generator refuses
  to emit one whose sighash the block's own signature does not verify
  against); and — the part a sync alone cannot show — under a challenge
  differing by ONE HEX CHARACTER the same blocks are rejected as
  `bad-signet-blksig`, so the check is what decides.

  Two bugs surfaced only by running it, neither reachable from any hermetic
  test: the genesis block was rejected (Core exempts it; its coinbase predates
  segwit and carries no witness commitment, and a syncing node seeds genesis
  rather than applying it), and signet was left on MAINNET's fork-activation
  schedule — which gates on HEIGHT, so real block 1 was judged pre-segwit and
  rejected as `unexpected-witness`. `tests/test_signet_{solution,txs,verify,block}`.

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

  *One stated caveat on "byte-identical" (STO-14, audit 2026-09-03):
  `block_filter.c` de-duplicates elements on the 64-bit SipHash, where Core's
  `GCSFilter` de-duplicates the byte-wise element SET before hashing. If two
  distinct scripts in one block ever collided on 64 bits, N would be one less
  than Core's -- and since N scales the Golomb-Rice range, the WHOLE filter
  would differ, not one entry. That is ~n²/2^65 per block, about 2^-40 at a
  few thousand elements. Left as-is deliberately: byte-wise dedup means
  sorting (pointer, length) pairs by content inside a KAT-backed generator
  whose output peers consume, which is a worse trade than carrying a 2^-40
  divergence knowingly. Recorded so the parity claim above is read with it.*
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
- **`assumevalid`** — IMPLEMENTED 2026-09-01, both modes. `node_config.c`
  parses it into `assumevalid_mode` (1 = skip script evaluation at or below the
  given block, Core's semantics; 2 = `assumevalid=0`, evaluate everything), the
  per-chain defaults come from `chainparams.c`, and `tx_verify.c`'s script
  switch is what `utxo_live.c` turns off per block while applying at or below
  the height. Every other consensus check still runs at every height.

  *(This entry read "parsed and then IGNORED, with a loud `[config]` line
  saying so" until 2026-09-05 — BLD-5. It sat in the "REMAINING gaps, precisely
  (this is the real backlog)" section describing a refusal the code had stopped
  making. The `[config]` line beside it had ALREADY been corrected once, on
  2026-08-28, for claiming block connection did no script verification at all;
  the prose outlived that correction by another week. Documentation that
  explains a deliberate refusal ages exactly like the refusal string does.)*

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

  STATED GAPS, strictly more conservative than Core:
  - ~~**TRUC sibling eviction**~~ — **DONE 2026-09-03**, see the update at the
    end of this file.
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
- **legacy testnet (testnet3)** — REFUSED by design (`daemon/chainparams.c`
  rejects `chain=test`/`testnet` loudly rather than run the wrong rules; say
  `chain=testnet4`). Supported: **main, signet, testnet4 and regtest** —
  testnet4's whole chain synced with a byte-identical muhash vs Core, and
  signet closed 2026-08-30 (below).
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
| **Config options** | **133 / 181 implemented, 48 accepted without effect (each named with its reason at start-up), 0 not recognised** — see the 2026-09-01 config-surface update below for the full table. |
| **Chains** | main, testnet4, regtest. **signet and testnet3 absent** — and refused explicitly at startup rather than started with the wrong rules. |
| **Indexes** | txindex, coinstatsindex, blockfilterindex, addrindex, **txospenderindex (2026-09-01)**. |
| **P2P protocol** | addrv2, compact blocks, BIP157/158, package relay, all five BIP155 networks, **inbound Tor**. **BIP324 v2 transport COMPLETE, live on mainnet in both directions, proven against Bitcoin Core v31.99. Erlay: BIP330 negotiation implemented and tested, not wired to the wire; reconciliation deliberately not built (see below).** |

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
[config] whitebind= is a Bitcoin Core option this node does not implement -- it has NO EFFECT
```

That retires a failure mode this codebase reproduced repeatedly: `externalip`
parsed and never read, `permitbaremultisig` *reported* by `getmempoolinfo`
while nothing could set it, `whitelist=rpc` sitting in the live config doing
nothing, `maxreceivebuffer` and `walletnotify` both parsed and inert. A test
asserts the list and the implementation move together in **both** directions.

*(`whitelist` was the example here until 2026-08-30, when it stopped being
true: it is implemented now — `noban` only, and every other Core permission
token is a startup error naming the token rather than an accepted no-op. The
example moved to `whitebind`, which was implemented on 2026-09-01
(node_config.c calls netperm_whitebind_add; see the table below). An
example that has quietly become false is the same defect this section is
about.)*

*Deliberately not done, and why.* ~~`bytespersigop`~~ — **DONE 2026-09-03**,
see the update at the end of this file; the restructuring this paragraph
called for turned out to be small, and finding it half-wired was worse than
either state.
`persistmempool`'s machinery (`mempool_dump_write`/`read`) is written and
tested but called from nowhere; wiring the save path touches shutdown, which
must stay fast for the SIGKILL window. `fixedseeds` gates a hardcoded IP seed
list this node does not have. All three stay on the warning list.

## Update 2026-08-30 — Erlay: a deliberate stopping point

BIP330 splits into negotiation (`sendtxrcncl`: version and salt exchange, and
the rules about who may offer it to whom) and reconciliation proper
(`reqrecon`/`sketch`/`reqsketchext`/`reconcildiff`, PinSketch set difference).

**The negotiation half is implemented and tested** — `daemon/txrecon.c`, 38
assertions, with the combined salt checked against an independent Python
implementation of Core's `TaggedHash("Tx Relay Salting")`. It is not yet
emitted from the handshake, so nothing appears on the wire.

**The reconciliation half is deliberately NOT built**, and the reason is worth
recording rather than leaving as an unexplained gap:

> **Bitcoin Core does not implement it either.** `node/txreconciliation.cpp`
> contains exactly four functions — `PreRegisterPeer`, `RegisterPeer`,
> `ForgetPeer`, `IsPeerRegistered`. There are no sketches and no reconciliation
> rounds anywhere in Core, and `net_processing.cpp` states it plainly: *"While
> Erlay support is incomplete, it must be enabled explicitly via
> -txreconciliation."*

This project's method is differential testing against a running Core. For the
reconciliation rounds there is no running implementation anywhere to test
against — the only reference is `minisketch/tests/pyminisketch.py`, a Python
model of the sketch library, which can pin the arithmetic but not the protocol
integration.

Building it would mean shipping set-reconciliation code that relays
transactions on a live mainnet node, unproven against any peer, to speak a
protocol no deployed node currently speaks. That is a worse trade than the gap
it closes, so the gap stays — and stays documented, rather than being quietly
half-filled.

Revisit when Core's own Erlay progresses.

## Update 2026-09-01 — fee estimation is Core's estimator, not an EMA

`estimatesmartfee` used to answer Core's *contract* over this node's own
accepted-feerate EMA, and `estimaterawfee` did not exist. Both now run on a
C port of Core's `CBlockPolicyEstimator` (`asm/daemon/fee_estimator.c`,
v31.99's `policy/fees/block_policy_estimator.cpp`): the three
TxConfirmStats horizons (short 12×1 decay .962, medium 24×2 .9952, long
42×24 .99931), the 100…1e7 sat/kvB ×1.05 feerate buckets, transactions
tracked from admission (only when the chainstate is current — tip within
3 h — with no in-mempool parents and not part of a package, exactly Core's
`validForFeeEstimation`) to the block that confirms them, every other
removal booked as a failure for the periods it outlived, the same
`EstimateMedianVal` walk, the 60 % / 85 % / 95 % smart-fee ladder with the
conservative variant, `MaxUsableEstimate` (so a fresh node answers
`blocks: 0` like Core), and `fee_estimates.dat` (own format, Core's content;
hourly + shutdown flush with `FlushUnconfirmed`; ignored when older than
60 h). The estimator is one MAP_SHARED region beside the mempool under its
process-shared lock, so the download worker, the serve parent and the RPC
readers agree. `estimaterawfee conf_target [threshold]` returns Core's
per-horizon `feerate/decay/scale/pass/fail/errors` with Core's rounding.
Evidence: `asm/tests/test_fee_estimator` ports Core's
`policyestimator_tests` scenario with the same expectations at the same
block numbers; `validation/feeest_core_diff.sh` runs this node against a
regtest Core over P2P with a fixed feerate/confirmation schedule and demands
byte-identical `estimatesmartfee` and `estimaterawfee` output at several
checkpoints (result recorded in `worklog/2026-09-01.md`). Not carried over:
Core's `-acceptstalefeeestimates` knob (the 60 h cut-off is fixed) and the
"tip at least best-header−1" half of `IsCurrentForFeeEstimation` (the
worker does not see the header count at the block-connect site; the 3 h
tip-age test stands in).

## Update 2026-08-30 — security audit round

An independent audit (`docs/audits/SECURITY_AUDIT_2026-08-29.md`) found 11
issues; 10 are resolved. Several were gaps this document had not listed,
because they were absent *checks* rather than absent features:

- **no consensus `MAX_MONEY` check anywhere** — output values were summed as
  raw `u64` off the wire with no per-output or running bound (CVE-2010-5139
  shape). Now matching Core, verified against 1,172 real mainnet transactions.
  *(VAL-16 flagged this line and README's matching claim as contradicting the
  code. It did when the audit was written on 2026-09-03 — the check existed on
  the mempool/RPC parser only, not the BLOCK path. VAL-2 closed that gap;
  `daemon/utxo_live.c:916-955` now applies Core's `MAX_MONEY` on both arms of
  the apply path. Re-verified 2026-09-05: the claim is true as written, so it
  is left standing rather than corrected.)*
- **no P2P message-size limit** — the framer acted on the announced length
  unbounded, so `0xFFFFFFFF` ground a serve child through ~4 GB of reads.
- **inbound `inv`/`getdata` counts read as a single byte**, silently
  misparsing any vector above 252 entries — routine traffic from Core.
- **unbounded JSON parser recursion**, reachable from any RPC body and
  demonstrated as a stack-exhaustion crash.
- **executable stack** (24 of 63 `.asm` files lacked `.note.GNU-stack`).
- **misbehaviour scoring had zero call sites**, and its table could not have
  accumulated across connections even with one.

The remaining finding is structural — hand-written consensus assembly with a
documented false-ACCEPT history — and is not closeable by a patch.

*Remaining, in the order worth doing it:* (`reindex` and `persistmempool` are implemented);
`whitebind` (a second listener carrying its own permissions — `whitelist`
itself is done, noban only); the RPC surface (`rpcauth`, `rpcallowip`,
`rpcbind`, `server`, `rest`) — lower urgency now that cookie auth exists and
the listener cannot leave loopback. **Signet closed 2026-08-30.**

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
  REFUSED by design (only main and regtest supported) *(as of that entry —
  testnet4 landed later, and signet on 2026-08-30; legacy testnet3 is still
  refused)*. The block-archive
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
- **Multipath descriptors (BIP389) + the PSBT Updater + partial signatures**
  — **DONE 2026-09-01 (late):** `/<a;b;...>` derivation steps parse with
  Core's rules and error texts everywhere keys appear (multi, tr subscripts
  and internal key, miniscript, musig participants); one `descr_t` holds all
  expansions (`descr_multipath_select`); `getdescriptorinfo` reports
  `multipath_expansion`, `deriveaddresses` answers one list per expansion,
  `scantxoutset` scans all of them, `importdescriptors` imports one
  descriptor per path, `descriptorprocesspsbt` treats each expansion as a
  descriptor. The Updater role is real (`psbt_update.c`, run inside
  `psbt_process` on the v0-shaped buffer, version preserved): scripts,
  bip32 origins (Core's fingerprint rules), and for `tr()` every leaf as
  `tap_leaf_script` with its control block, derivations with leaf hashes,
  internal key, merkle root, output-side tree (Core's right-most-first
  order), and `witness_utxo` materialised for (nested) segwit inputs;
  `utxoupdatepsbt`'s descriptors argument works and `walletprocesspsbt`
  updates from the wallet's own descriptors. Partial signatures now flow
  BOTH ways for multisig and miniscript inputs (P2WSH and tapscript): the
  signer's placed signatures become `partial_signatures` /
  `taproot_script_path_sigs` under `finalize=false`, and partials already
  in the PSBT are merged into witnesses (a 0-of-k attempt is "keys not
  provided", never an empty partial). Evidence: Core's 12 CheckMultipath +
  14 unparsable vectors (`test_descriptor_vectors` 720 checks),
  `tests/test_psbt_update` (40), and `validation/updater_core_diff.py` —
  getdescriptorinfo/deriveaddresses byte-for-byte, Core's own
  `utxoupdatepsbt(descriptors)` output field-for-field, and two-signer
  hand-offs in both orders judged by Core's finalizer: **145/145**;
  miniscript 436/436 and musig 110/110 differentials re-run green.
- **PSBT (BIP174)** — ~~absent, zero hits anywhere~~ **substantially present
  since 2026-08-25**: `createpsbt`, `decodepsbt`, `converttopsbt`,
  `combinepsbt`, `joinpsbts` (all oracle-verified, several byte-identical)
  and `analyzepsbt` (full role machine, 14-vector oracle diff).
  ~~Still missing from the tranche: `finalizepsbt`/`walletprocesspsbt` /
  `utxoupdatepsbt`.~~ — **DONE 2026-08-26**: `walletprocesspsbt` is the PSBT
  Signer role by delegation (`rpc_wallet_ops.c`), and `finalizepsbt` /
  `utxoupdatepsbt` are real (`rpc_commands.c`). `descriptorprocesspsbt`
  signs from the keys a descriptor carries (descriptor.c, 2026-09-01). `docs/PARITY_PLAN.md` T8 has the
  per-method state. **Taproot (BIP371) 2026-09-01 (late):** the PSBT input
  fields `PSBT_IN_TAP_KEY_SIG/SCRIPT_SIG/LEAF_SCRIPT/BIP32_DERIVATION/
  INTERNAL_KEY/MERKLE_ROOT` and the output-side internal key / tree /
  derivations are parsed, serialized and named in `decodepsbt` exactly as
  Core does (plus `partial_signatures`, `sighash`, `bip32_derivs`,
  `final_scriptwitness`, which `decodepsbt` had also been omitting). The
  signer signs the key path of a `tr()` WITH a tree (internal key + merkle
  root) and the script path of `pk()` / `multi_a()` leaves; a PSBT with
  several leaves is signed in rounds (key path, then each leaf), partial
  `TAP_SCRIPT_SIG`s from another signer are carried into the witness, and
  the wallet derives leaf keys named by a bip32 origin under its own
  fingerprint. Core's VerifyScript judges every form
  (`validation/signer_core_diff.sh`: 18/18 incl. the negative cases);
  `tests/test_rpc_psbt_taproot` pins the PSBT plumbing. *(2026-09-01, later:
  leaves other than pk/multi_a are signed by the miniscript satisfier and
  `musig()` keys parse, expand and update -- see the Miniscript / musig()
  update below.)*
  **PSBT v2 (BIP370) 2026-09-01 (late):** every PSBT RPC accepts version 2 —
  the unsigned tx is synthesized from `tx_version`, the per-input previous
  txid/index/sequence, the required locktimes folded as Core's
  `ComputeTimeLock` does, and the per-output amount/script; results come
  back in the caller's version with Core's serialization order (a v2 Core
  produced round-trips byte-identical); `createpsbt`/`converttopsbt`/
  `walletcreatefundedpsbt` default to v2 like Core master and take
  `psbt_version`; `decodepsbt` prints the v2 globals and per-input/output
  fields, plus `witness_utxo`/`non_witness_utxo`/`fee` and the
  redeem/witness/final scripts as Core's objects (it had printed hex
  strings); `combinepsbt` is sequence-blind for v2 and refuses mixed
  versions, `joinpsbts` refuses v2, every validation error carries Core's
  text. `validation/psbt_v2_core_diff.py` (scratch regtest Core): Core's v2
  decoded and signed by us, finalized and mined by Core, and the reverse,
  for five script kinds, creator/converter bytes identical, an injected
  height locktime, combine bytes: 75/75, full `decodepsbt` JSON identical.
  `tests/test_psbt_v2` 35 checks.
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
- **BIP152 compact blocks — SERVE SIDE ONLY** (`cmpctblock_build`,
  `p2p_blocktxn_build`). This node answers `MSG_CMPCT_BLOCK` getdata and
  `getblocktxn`, and negotiates `sendcmpct`. It does NOT receive compact
  blocks: `bitcoin_serve.asm` writes `cmpctblock` and `blocktxn` and has no
  inbound handler for either, so a peer's compact block is ignored and the
  block is fetched in full. NET-9 (audit 2026-09-03) found this entry
  claiming "both directions … full message handling"; the send side is real
  and now handles any transaction count (SER-4 fixed the one-byte count that
  had capped it at 252, i.e. at almost every mainnet block), but the receive
  side has never existed. Corrected rather than left overstating the surface.
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

## Update 2026-09-01 — MuSig2 (BIP327 / BIP373)

Closed: MuSig2 signing. `asm/musig2.c` is BIP327 in plain C over the node's
own secp256k1 kernels (KeyAgg with the second-key rule, plain and x-only
tweaks, NonceGen, NonceAgg, partial Sign with self-verify, PartialSigVerify,
PartialSigAgg), proven on libsecp256k1's copy of the BIP vectors -- every
group, including the failing cases (`tests/test_musig2`, 57 checks). The
PSBT signer speaks BIP373: `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` / `PUB_NONCE`
/ `PARTIAL_SIG` and `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS`, with Core's
`decodepsbt` shapes, and runs Core's `SignMuSig2` order for P2TR key-path
aggregates (direct, derived through the synthetic xpub with chaincode
`868087ca…8965`, or taproot-tweaked): nonce round, partial-signature round,
aggregation into `PSBT_IN_TAP_KEY_SIG`, which `finalizepsbt` turns into the
witness. Secret nonces live in an in-process session table keyed as Core's
`MuSig2SessionID` and are erased on use. Evidence:
`validation/musig_core_diff.py` -- Core regtest wallets as two of three
participants, this node as the third through `descriptorprocesspsbt`,
`combinepsbt` between rounds, Core's `finalizepsbt` + `testmempoolaccept` +
its own aggregation of the same partial signatures (identical transaction)
+ a mined block as judges, `decodepsbt` compared field-by-field on every
intermediate PSBT, five patterns (`tr(musig(keys/*))`, `rawtr(...)`, derived
`musig(...)/<0;1>/*` under both, `ALL|ANYONECANPAY`): 110/110.

Still open: **`musig()` in descriptors** (BIP390) -- `descriptor.c` refuses
it by name; the parser/expander hook it needs is specified in `musig2.h`
(the miniscript workstream owns descriptor.c). **MuSig2 inside tapscript
leaves** (`tr(H, pk(musig(...)))`): the signer handles key-path aggregates
only; the same rounds keyed by leaf hash are a small extension once
script-path signing exists. The wallet's own key oracle for MuSig2 covers
its HD window (the same keys it hands the raw signer) and imported HD keys.

## Update 2026-09-01 — config surface: every Core v31.99 option classified

Method: `bitcoind -help-debug` of the scratch Core build (181 options) against
every parse site here (`daemon/node_config.c`, `daemon/main.c` for the RPC
credentials/port/prune, the command line for `-datadir`/`-conf`). Three
states, and nothing else: **implemented** (parsed, with Core's semantics
behind it), **accepted, no effect** (parsed, named at every start-up with the
reason it is inert here — the table `k_noeffect` in node_config.c is the
same list), or **not recognised** (ignored silently, as Core ignores unknown
keys). Counts: 133 implemented, 48 accepted without effect, 0 not recognised.

Landed today (branch `feat/config-surface`): `uacomment` (runtime user agent,
on the wire and in `getnetworkinfo`), `blockmaxweight` / `blockreservedweight`
/ `blockmintxfee` / `blockversion` / `printpriority` (template budget, fee
floor and version), `maxtipage` (IBD flag), `addresstype` / `changetype`,
`txconfirmtarget`, `walletrbf`, `walletbroadcast`, `mintxfee` / `fallbackfee`
(estimation failure is Core's error when it is 0) / `discardfee` /
`consolidatefeerate` / `avoidpartialspends` / `maxapsfee` /
`spendzeroconfchange`, `wallet=` (start-up load; one active wallet here),
`walletnotify` (mempool arrival and confirmation), `rpcthreads` /
`rpcworkqueue` (503 past the depth) / `rpcservertimeout`, `rpcwhitelist` /
`rpcwhitelistdefault` (HTTP 403), `rpccookieperms`, `includeconf`,
`logtimestamps` / `logtimemicros` / `logthreadnames` / `logsourcelocations` /
`shrinkdebugfile`, `peerblockfilters` (NODE_COMPACT_FILTERS + serving, Core's
default 0), `inboundrelaypercent` (fRelay=0 past the share),
`whitelistrelay` / `whitelistforcerelay` (permission flags; `relay@` and
`forcerelay@` are now accepted in `whitelist=`), `signetseednode`,
`limitclustercount` / `limitclustersize` (mapped onto the ancestor and
descendant limits), `keypool` / `fixedseeds` / `txreconciliation` (accepted).
Evidence: `tests/test_node_config`, `tests/test_rpc_whitelist`,
`tests/test_netperm`, and `validation/config_surface_core_diff.sh` — the
same option on a scratch regtest Core and on this node, compared on the
observable it changes (subversion on the wire, address type, IBD flag,
template contents and version, HTTP status, cookie mode, log prefix): 18/18.

Known partial: `whitelistrelay`/`whitelistforcerelay` set the permission
bits but nothing enforces them yet (`blocksonly` itself is parsed and not
enforced, so `relay` is trivially satisfied; `forcerelay` re-announcement
is not done). `inboundrelaypercent` counts all inbound connections rather
than relaying ones. `peerblockfilters` follows Core's default of 0: a node
that served BIP157 before this change must now set it explicitly.

| option | Core meaning | this node |
| --- | --- | --- |
| `acceptnonstdtxn` | Relay and mine "non-standard" transactions (test networks only; default: 0) | implemented |
| `acceptstalefeeestimates` | Read fee estimates even if they are stale (regtest only; default: 0) fee estimates are considered stale if the… | implemented 2026-09-01: reads fee_estimates.dat regardless of age |
| `addnode` | Add a node to connect to and attempt to keep the connection open (see the addnode RPC help for more info). Thi… | implemented |
| `addresstype` | What type of addresses to use ("legacy", "p2sh-segwit", "bech32", "bech32m", default: "bech32") | implemented |
| `alertnotify` | Execute command when an alert is raised (%s in cmd is replaced by message) | implemented |
| `allowignoredconf` | For backwards compatibility, treat an unused bitcoin.conf file in the datadir as a warning, not an error. | accepted, no effect: -conf is always honoured |
| `asmap` | Specify asn mapping used for bucketing of the peers. Relative paths will be prefixed by the net-specific datad… | implemented |
| `assumevalid` | If this block is in the chain assume that it and its ancestors are valid and potentially skip their script ver… | implemented |
| `avoidpartialspends` | Group outputs by address, selecting many (possibly all) or none, instead of selecting on a per-output basis. P… | implemented |
| `bantime` | Default duration (in seconds) of manually configured bans (default: 86400) | implemented |
| `bind` |  | implemented |
| `blockfilterindex` | Maintain an index of compact filters by block (default: 0, values: basic). If <type> is not supplied or if <ty… | implemented |
| `blockmaxweight` | Set maximum BIP141 block weight (default: 4000000) | implemented |
| `blockmintxfee` | Set lowest fee rate (in BTC/kvB) for transactions to be included in block creation. (default: 0.00000001) | implemented |
| `blocknotify` | Execute command when the best block changes (%s in cmd is replaced by block hash) | implemented |
| `blockreconstructionextratxn` | Extra transactions to keep in memory for compact block reconstructions (default: 100) | accepted, no effect: compact-block reconstruction draws on the mempool only |
| `blockreservedweight` | Reserve space for the fixed-size block header plus the largest coinbase transaction the mining software may ad… | implemented |
| `blocksdir` | Specify directory to hold blocks subdirectory for *.dat files (default: <datadir>) | accepted, no effect: the archive lives under <datadir>/<chain> and is not relocatable |
| `blocksonly` | Whether to reject transactions from network peers. Disables automatic broadcast and rebroadcast of transaction… | implemented 2026-09-01: fRelay=0 in every version, tx/tx-inv from peers without `relay` is a violation (disconnect, no score), no feefilter, localrelay false, whitelistrelay->0 / maxmempool->5 interactions; RPC submissions still relay (Core). Wire-proven: validation/relay_policy_core_diff.sh |
| `blocksxor` | Whether an XOR-key applies to blocksdir *.dat files. The created XOR-key will be zeros for an existing blocksd… | accepted, no effect: the archive is never XOR-obfuscated |
| `blockversion` | Override block version to test forking scenarios | implemented |
| `bytespersigop` | Equivalent bytes per sigop in transactions for relay and mining (default: 20) | implemented |
| `capturemessages` | Capture all P2P messages to disk | accepted, no effect: no P2P message capture |
| `chain` | Use the chain <chain> (default: main). Allowed values: main, test, testnet4, signet, regtest | implemented |
| `changetype` | What type of change to use ("legacy", "p2sh-segwit", "bech32", "bech32m"). Default is "legacy" when -addressty… | implemented |
| `checkaddrman` | Run addrman consistency checks every <n> operations. Use 0 to disable. (default: 0) | accepted, no effect: address-book invariants are checked in the test suite, not on a timer |
| `checkblockindex` | Do a consistency check for the block tree, chainstate, and other validation data structures every <n> operatio… | accepted, no effect: index invariants are checked at boot (archive self-heal) and in the test suite, not on a timer |
| `checkblocks` | How many blocks to check at startup (default: 6, 0 = all) | implemented |
| `checklevel` | How thorough the block verification of -checkblocks is: level 0 reads the blocks from disk, level 1 verifies b… | implemented |
| `checkmempool` | Run mempool consistency checks every <n> transactions. Use 0 to disable. (default: 0, regtest: 1) | accepted, no effect: mempool invariants are checked in the test suite, not on a timer |
| `cjdnsreachable` | If set, then this host is configured for CJDNS (connecting to fc00::/8 addresses would lead us to the CJDNS ne… | implemented |
| `coinstatsindex` | Maintain coinstats index used by the gettxoutsetinfo RPC (default: 0) | implemented |
| `conf` | Specify path to read-only configuration file. Relative paths will be prefixed by datadir location (only useabl… | implemented (command line) |
| `connect` | Connect only to the specified node; -noconnect disables automatic connections (the rules for this peer are the… | implemented |
| `consolidatefeerate` | The maximum feerate (in BTC/kvB) at which transaction building may use more inputs than strictly necessary so … | implemented |
| `daemon` | Run in the background as a daemon and accept commands (default: 0) | accepted, no effect: a systemd unit (or the shell) backgrounds the process |
| `daemonwait` | Wait for initialization to be finished before exiting. This implies -daemon (default: 0) | accepted, no effect: a systemd unit (or the shell) backgrounds the process |
| `datacarrier` | Relay and mine data carrier transactions (default: 1) | implemented |
| `datacarriersize` | Relay and mine transactions whose data-carrying raw scriptPubKeys in aggregate are of this size or less, allow… | implemented |
| `datadir` | Specify data directory | implemented (command line) |
| `dbbatchsize` | Maximum database write batch size in bytes (default: 33554432) | accepted, no effect: no LevelDB |
| `dbcache` | Maximum database cache size <n> MiB (minimum 4, default: 1024). Make sure you have enough RAM. In addition, un… | implemented |
| `debug` | Output debug and trace logging (default: -nodebug, supplying <category> is optional). If <category> is not sup… | accepted, no effect: no log categories |
| `debugexclude` | Exclude debug and trace logging for a category. Can be used in conjunction with -debug=1 to output debug and t… | accepted, no effect: no log categories |
| `debuglogfile` | Specify location of debug log file (default: debug.log). Relative paths will be prefixed by a net-specific dat… | implemented |
| `deprecatedrpc` | Allows deprecated RPC method(s) to be used | accepted, no effect: no deprecated-RPC toggles |
| `disablewallet` | Do not load the wallet and disable wallet RPC calls | implemented |
| `discardfee` | The fee rate (in BTC/kvB) that indicates your tolerance for discarding change by adding it to the fee (default… | implemented |
| `discover` | Discover own IP addresses (default: 1 when listening and no -externalip or -proxy) | implemented |
| `dns` | Allow DNS lookups for -addnode, -seednode and -connect (default: 1) | implemented |
| `dnsseed` | Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect used or -maxconnectio… | implemented |
| `dustrelayfee` | Fee rate (in BTC/kvB) used to define dust, the value of an output such that it will cost more than its value i… | implemented |
| `externalip` | Specify your own public address | implemented |
| `fallbackfee` | A fee rate (in BTC/kvB) that will be used when fee estimation has insufficient data. 0 to entirely disable the… | implemented |
| `fastprune` | Use smaller block files and lower minimum prune height for testing purposes | accepted, no effect: debug-only pruning knob; this node prunes by its own MiB budget |
| `fixedseeds` | Allow fixed seeds if DNS seeds don't provide peers (default: 1) | accepted, no effect: no compiled-in seed list: DNS seeds, seednode= and peers.dat only |
| `forcednsseed` | Always query for peer addresses via DNS lookup (default: 0) | implemented |
| `help` | Print this help message and exit (also -h or -?) | accepted, no effect: command-line only |
| `i2pacceptincoming` | Whether to accept inbound I2P connections (default: 1). Ignored if -i2psam is not set. Listening for inbound I… | implemented |
| `i2psam` | I2P SAM proxy to reach I2P peers and accept I2P connections | implemented |
| `inboundrelaypercent` | Permit a maximum percent of inbound connections to relay transactions, to limit memory utilization (0 to 100, … | implemented 2026-09-01: static_cast<int>(pct/100*inbound limit) full-relay inbound peers; only peers that negotiated tx relay count; the rest get fRelay=0 (Core evicts instead of refusing -- here the share is applied at handshake) |
| `includeconf` | Specify additional configuration file, relative to the -datadir path (only useable from configuration file, no… | implemented (node_config.c) |
| `incrementalrelayfee` | Fee rate (in BTC/kvB) used to define cost of relay, used for mempool limiting and replacement policy. (default… | implemented |
| `keypool` | Set key pool size to <n> (default: 1000). Warning: Smaller sizes may increase the risk of losing funds when re… | accepted, no effect: the descriptor wallet derives keys on demand; there is no keypool |
| `limitancestorcount` | Deprecated setting to not accept transactions if number of in-mempool ancestors is <n> or more (default: 25); … | implemented |
| `limitclustercount` | Do not accept transactions into mempool which are directly or indirectly connected to <n> or more other unconf… | implemented |
| `limitclustersize` | Do not accept transactions whose virtual size with all in-mempool connected transactions exceeds <n> kilobytes… | implemented |
| `limitdescendantcount` | Deprecated setting to not accept transactions if any ancestor would have <n> or more in-mempool descendants (d… | implemented |
| `listen` | Accept connections from outside (default: 1 if no -proxy, -connect or -maxconnections=0) | implemented |
| `listenonion` | Automatically create Tor onion service (default: 1) | implemented |
| `loadblock` | Imports blocks from an external file on startup. Obfuscated blocks are not supported. | accepted, no effect: the block archive is this node's own format (index.dat + blk files); Core blk*.dat files are not imported |
| `logips` | Include IP addresses in log output (default: 0) | accepted, no effect: peer addresses are always logged |
| `loglevel` |  | accepted, no effect: no per-category log levels |
| `loglevelalways` | Always prepend a category and level (default: 0) | accepted, no effect: no per-category log levels |
| `logratelimit` | Apply rate limiting to unconditional logging to mitigate disk-filling attacks (default: 1) | accepted, no effect: no log rate limiting |
| `logsourcelocations` | Prepend debug output with name of the originating source location (source file, line number and function name)… | implemented |
| `logthreadnames` | Prepend debug output with name of the originating thread (default: 0) | implemented |
| `logtimemicros` | Add microsecond precision to debug timestamps (default: 0) | implemented |
| `logtimestamps` | Prepend debug output with timestamp (default: 1) | implemented |
| `maxapsfee` | Spend up to this amount in additional (absolute) fees (in BTC) if it allows the use of partial spend avoidance… | implemented |
| `maxconnections` | Maintain at most <n> automatic connections to peers (default: 200). 11 slots of these are reserved for outgoin… | implemented |
| `maxmempool` | Keep the transaction memory pool below <n> megabytes (default: 300) | implemented |
| `maxreceivebuffer` | Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000) | implemented |
| `maxsendbuffer` | Maximum per-connection memory usage for the send buffer, <n>*1000 bytes (default: 1000) | implemented |
| `maxsigcachesize` | Limit sum of signature cache and script execution cache sizes to <n> MiB (default: 32) | accepted, no effect: no signature cache: each block's scripts are verified once by the parallel verifier |
| `maxtipage` | Maximum tip age in seconds to consider node in initial block download (default: 86400) | implemented |
| `maxtxfee` | Maximum total fees (in BTC) to use in a single wallet transaction; setting this too low may abort large transa… | implemented |
| `maxuploadtarget` | Tries to keep outbound traffic under the given target per 24h. Limit does not apply to peers with 'download' p… | implemented |
| `mempoolexpiry` | Do not keep transactions in the mempool longer than <n> hours (default: 336) | implemented |
| `minimumchainwork` | Minimum work assumed to exist on a valid chain in hex (default: 0000000000000000000000000000000000000001128750… | implemented |
| `minrelaytxfee` | Fees (in BTC/kvB) smaller than this are considered zero fee for relaying, mining and transaction creation (def… | implemented |
| `mintxfee` | Fee rates (in BTC/kvB) smaller than this are considered zero fee for transaction creation (default: 0.00001) | implemented |
| `mocktime` | Replace actual time with UNIX epoch time (default: 0) | accepted, no effect: no mock clock: regtest tests drive time through block timestamps |
| `natpmp` | Use PCP or NAT-PMP to map the listening port (default: 1) | accepted, no effect: no NAT-PMP/UPnP port mapping by design |
| `networkactive` | Enable all P2P network activity (default: 1). Can be changed by the setnetworkactive RPC command | implemented |
| `onion` | Use separate SOCKS5 proxy to reach peers via Tor onion services, set -noonion to disable (default: -proxy). Ma… | implemented |
| `onlynet` | Make automatic outbound connections only to network <net> (ipv4, ipv6, onion, i2p, cjdns). Inbound and manual … | implemented |
| `par` | Set the number of script verification threads (0 = auto, up to 15, <0 = leave that many cores free, default: 0… | implemented |
| `peerblockfilters` | Serve compact block filters to peers per BIP 157 (default: 0) | implemented |
| `peerbloomfilters` | Support filtering of blocks and transaction with bloom filters (default: 0) | accepted, no effect: BIP37 bloom filtering is not implemented; NODE_BLOOM is never advertised (Core's default is 0 too) |
| `peertimeout` | Specify a p2p connection timeout delay in seconds. After connecting to a peer, wait this amount of time before… | **NOT implemented** (DMN-14, 2026-09-05: this said "implemented". `daemon/main.c:543` states plainly that the timeout it *does* have is NOT Core's `-peertimeout`, which is a CONNECT timeout; nothing reads the option. See DMN-3.) |
| `permitbaremultisig` | Relay transactions creating non-P2SH multisig outputs (default: 1) | implemented |
| `persistmempool` | Whether to save the mempool on shutdown and load on restart (default: 1) | implemented |
| `persistmempoolv1` | Whether a mempool.dat file created by -persistmempool or the savemempool RPC will be written in the legacy for… | accepted, no effect: mempool.dat is written in the current format only |
| `pid` | Specify pid file. Relative paths will be prefixed by a net-specific datadir location. (default: bitcoind.pid) | implemented |
| `port` | Listen for connections on <port> (default: 8333, testnet3: 18333, testnet4: 48333, signet: 38333, regtest: 184… | implemented |
| `prevoutfetchthreads` | Set the number of threads used to prefetch block input prevouts from the chainstate database (0 disables, up t… | accepted, no effect: prevouts come from the in-process UTXO set |
| `printpriority` | Log transaction fee rate in BTC/kvB when mining blocks (default: 0) | implemented |
| `printtoconsole` | Send trace/debug info to console (default: 1 when no -daemon. To disable logging to file, set -nodebuglogfile) | accepted, no effect: stderr IS the log (systemd appends it to the log file) |
| `privatebroadcast` | Broadcast transactions submitted via sendrawtransaction RPC using short-lived connections through the Tor or I… | implemented 2026-09-02: sendrawtransaction is validated and queued, three short-lived anonymous connections over Tor/I2P (or clearnet through the Tor proxy) deliver it, the tx stays out of the mempool until heard back; getprivatebroadcastinfo / abortprivatebroadcast; see the 2026-09-02 update |
| `proxy` |  | implemented |
| `proxyrandomize` | Randomize credentials for every proxy connection. This enables Tor stream isolation (default: 1) | implemented |
| `prune` | Reduce storage requirements by enabling pruning (deleting) of old blocks. This allows the pruneblockchain RPC … | implemented |
| `regtest` | Enter regression test mode, which uses a special chain in which blocks can be solved instantly. This is intend… | implemented |
| `reindex` | If enabled, wipe chain state and block index, and rebuild them from blk*.dat files on disk. Also wipe and rebu… | implemented |
| `rest` | Accept public REST requests (default: 0) | accepted, no effect: no REST interface by design |
| `rpcallowip` | Allow JSON-RPC connections from specified source. Valid values for <ip> are a single IP (e.g. 1.2.3.4), a netw… | implemented |
| `rpcauth` | Username and HMAC-SHA-256 hashed password for JSON-RPC connections. The field <userpw> comes in the format: <U… | implemented |
| `rpcbind` |  | implemented |
| `rpccookiefile` | Location of the auth cookie. Relative paths will be prefixed by a net-specific datadir location. (default: dat… | implemented |
| `rpccookieperms` | Set permissions on the RPC auth cookie file so that it is readable by [owner\|group\|all] (default: owner [via u… | implemented |
| `rpcdoccheck` | Throw a non-fatal error at runtime if the documentation for an RPC is incorrect (default: 0) | accepted, no effect: debug-only |
| `rpcpassword` | Password for JSON-RPC connections | implemented (daemon/main.c (RPC server)) |
| `rpcport` | Listen for JSON-RPC connections on <port> (default: 8332, testnet3: 18332, testnet4: 48332, signet: 38332, reg… | implemented (daemon/main.c (RPC server)) |
| `rpcservertimeout` | Timeout during HTTP requests (default: 30) | implemented |
| `rpcthreads` | Set the number of threads to service RPC calls (default: 16) | implemented |
| `rpcuser` | Username for JSON-RPC connections | implemented (daemon/main.c (RPC server)) |
| `rpcwhitelist` | Set a whitelist to filter incoming RPC calls for a specific user. The field <whitelist> comes in the format: <… | implemented |
| `rpcwhitelistdefault` | Sets default behavior for rpc whitelisting. Unless rpcwhitelistdefault is set to 0, if any -rpcwhitelist is se… | implemented |
| `rpcworkqueue` | Set the maximum depth of the work queue to service RPC calls (default: 64) | implemented |
| `seednode` | Connect to a node to retrieve peer addresses, and disconnect. This option can be specified multiple times to c… | implemented |
| `server` | Accept command line and JSON-RPC commands | accepted, no effect: the JSON-RPC server is always on |
| `settings` | Specify path to dynamic settings data file. Can be disabled with -nosettings. File is written at runtime and n… | accepted, no effect: no settings.json: values set over RPC are not persisted |
| `shrinkdebugfile` | Shrink debug log file on client startup (default: 1 when no -debug) | implemented |
| `shutdownnotify` | Execute command immediately before beginning shutdown. The need for shutdown may be urgent, so be careful not … | implemented |
| `signer` | External signing tool, see doc/external-signer.md | implemented |
| `signet` | Use the signet chain. Equivalent to -chain=signet. Note that the network is defined by the -signetchallenge pa… | implemented |
| `signetchallenge` | Blocks must satisfy the given script to be considered valid (only for signet networks; defaults to the global … | implemented |
| `signetseednode` | Specify a seed node for the signet network, in the hostname[:port] format, e.g. sig.net:1234 (may be used mult… | implemented |
| `spendzeroconfchange` | Spend unconfirmed change when sending transactions (default: 1) | implemented |
| `startupnotify` | Execute command on startup. | implemented |
| `stopafterblockimport` | Stop running after importing blocks from disk (default: 0) | accepted, no effect: no block import step |
| `stopatheight` | Stop running after reaching the given height in the main chain (default: 0). Blocks after target height may be… | implemented |
| `test` | Pass a test-only option. Options include : addrman (use deterministic addrman), reindex_after_failure_noninter… | accepted, no effect: debug-only |
| `testactivationheight` |  | accepted, no effect: regtest deployments are active from genesis here |
| `testnet` | Use the testnet3 chain. Equivalent to -chain=test. Support for testnet3 is deprecated and will be removed in a… | accepted, no effect: testnet3 is refused by design; use testnet4=1 |
| `testnet4` | Use the testnet4 chain. Equivalent to -chain=testnet4. | implemented |
| `timeout` | Specify socket connection timeout in milliseconds. If an initial attempt to connect is unsuccessful after this… | implemented |
| `torcontrol` |  | implemented |
| `torpassword` | Tor control port password (default: empty) | implemented |
| `txconfirmtarget` | Include enough fee so transactions begin confirmation on average within n blocks (default: 6) | implemented |
| `txindex` | Maintain a full transaction index, used by the getrawtransaction rpc call (default: 0) | implemented |
| `txospenderindex` | Maintain a transaction output spender index, used by the gettxspendingprevout rpc call (default: 0) | implemented 2026-09-01 — the index is enabled by the presence of `txospender.dat` (offline base + live tail), the key is accepted and changes nothing |
| `txreconciliation` | Enable transaction reconciliations per BIP 330 (default: 0) | accepted, no effect: Erlay: BIP330 negotiation is built but reconciliation is a deliberate stop |
| `txsendrate` | Set the maximum ongoing rate for sending transactions to (inbound) peers (default: 14 tx/s) | accepted, no effect: no inbound tx send-rate limiter (debug-only in Core) |
| `uacomment` | Append comment to the user agent string | implemented |
| `unsafesqlitesync` | Set SQLite synchronous=OFF to disable waiting for the database to sync to disk. This is unsafe and can cause d… | accepted, no effect: no sqlite |
| `v2transport` | Support v2 transport (default: 1) | implemented |
| `vbparams` |  | accepted, no effect: regtest deployments are active from genesis here |
| `version` | Print version and exit | accepted, no effect: command-line only |
| `wallet` | Specify wallet path to load at startup. Can be used multiple times to load multiple wallets. Path is to a dire… | implemented |
| `walletbroadcast` | Make the wallet broadcast transactions (default: 1) | implemented |
| `walletcrosschain` | Allow reusing wallet files across chains (default: 0) | accepted, no effect: one chain per datadir |
| `walletdir` | Specify directory to hold wallets (default: <datadir>/wallets if it exists, otherwise <datadir>) | implemented |
| `walletnotify` | Execute command when a wallet transaction changes. %s in cmd is replaced by TxID, %w is replaced by wallet nam… | implemented |
| `walletrbf` | (DEPRECATED) Send transactions with full-RBF opt-in enabled (default: 1) | implemented |
| `walletrejectlongchains` | Wallet will not create transactions that violate mempool chain limits (default: 1) | accepted, no effect: the mempool's cluster limits bound unconfirmed chains |
| `whitebind` | Bind to the given address and add permission flags to the peers connecting to it. Use [host]:port notation for… | implemented: perms@addr:port; the same permission set as whitelist (2026-09-01) |
| `whitelist` | Add permission flags to the peers using the given IP address (e.g. 1.2.3.4) or CIDR-notated network (e.g. 1.2.… | implemented 2026-09-01: noban, relay, forcerelay, mempool, download, addr, in enforced (Core NetPermissionFlags); bloomfilter/out refused with the reason; getpeerinfo `permissions` identical to Core for the same line |
| `whitelistforcerelay` | Add 'forcerelay' permission to whitelisted peers with default permissions. This will relay transactions even i… | implemented 2026-09-01: implicit forcerelay (feefilter withheld, tx accepted even if known); onward RE-announcement of an inbound peer's tx is not done (inbound-accepted txs are not announced to legs -- pre-existing gap, see relay section) |
| `whitelistrelay` | Add 'relay' permission to whitelisted peers with default permissions. This will accept relayed transactions ev… | implemented 2026-09-01: implicit relay; Core's SoftSet interactions with blocksonly/whitelistforcerelay |
| `zmqpubhashblock` | Enable publish hash block in <address> | implemented |
| `zmqpubhashblockhwm` | Set publish hash block outbound message high water mark (default: 1000) | implemented |
| `zmqpubhashtx` | Enable publish hash transaction in <address> | implemented |
| `zmqpubhashtxhwm` | Set publish hash transaction outbound message high water mark (default: 1000) | implemented |
| `zmqpubrawblock` | Enable publish raw block in <address> | implemented |
| `zmqpubrawblockhwm` | Set publish raw block outbound message high water mark (default: 1000) | implemented |
| `zmqpubrawtx` | Enable publish raw transaction in <address> | implemented |
| `zmqpubrawtxhwm` | Set publish raw transaction outbound message high water mark (default: 1000) | implemented |
| `zmqpubsequence` | Enable publish hash block and tx sequence in <address> | **REFUSED** (MEM-22, 2026-09-05: this said "implemented"; `node_config.c:950` rejects the option outright, and `zmq_pub.c` never publishes the topic. See the refusal's own comment for why: Core's `sequence` carries A/R alongside C/D, and this node has no single choke point for "removed" -- eviction, expiry and reorg each call `mpool_del` independently.) |
| `zmqpubsequencehwm` | Set publish hash sequence message high water mark (default: 1000) | parsed, but inert -- the topic it sizes is refused (MEM-22) |
## Update 2026-09-01 — Miniscript and `musig()` descriptors

Closed: **Miniscript** (`asm/miniscript.c/.h`, Core's `script/miniscript.h`
in C). The textual grammar with every wrapper and sugar form, the B/V/K/W
type system with z/o/n/d/u, e/f/s/m, x and the g/h/i/j/k timelock
properties, script size, ops (+ the CHECKMULTISIG worst case), stack size
(P2WSH witness items / tapscript execution depth), witness size, script
emission, script decoding (DecomposeScript's minimal-push and decomposed-
VERIFY rules) and the satisfier with Core's InputStack algebra. The engine
uses a flat node pool and explicit stacks -- nothing recurses -- because
the daemon's threads have ~150 KB of stack and a valid tapscript
miniscript can be thousands of nodes deep. `descriptor.c` accepts it inside
`wsh()` and as `tr()` leaves with Core's sanity errors verbatim
(`... is not sane: malleable witnesses exist`, `is invalid`, `is not
satisfiable`, timelock mix, duplicate keys, resource limits) and the
"only in wsh or tr" rule. The raw signer (`signrawtransactionwithkey`,
and through it `walletprocesspsbt` / `descriptorprocesspsbt`) hands any
witnessScript that is not CHECKSIG/CHECKMULTISIG, and any tapscript leaf
that is not pk()/multi_a(), to the satisfier (`miniscript_sign.c`): keys
held, the PSBT's `PSBT_IN_*_PREIMAGES`, the tx's nSequence/nLockTime as
BIP68/BIP65 judge them, other signers' `TAP_SCRIPT_SIG` partials. Evidence:
`tests/test_miniscript` -- all 97 literal vectors of Core's
`miniscript_tests.cpp` in BOTH contexts plus the programmatic ones (21-key
multi_a, 99/110/200-key and_b chains, 998/999-deep stack-limit chains),
with every satisfaction run through this node's own interpreter under nine
locktime/sequence contexts (44,921 checks); `tests/test_descriptor_vectors`
carries Core's 11 miniscript error strings and 13 Check() vectors;
`validation/miniscript_core_diff.py` -- a scratch regtest Core: 58
descriptors, `getdescriptorinfo` and `deriveaddresses` byte-identical in
private and public forms, then 41 funded spends built by Core
(`createpsbt` v0 + `utxoupdatepsbt`), signed by `descriptorprocesspsbt` with
only the granted keys and judged by `testmempoolaccept` + mining: 36
positive (P2WSH and sh(wsh) fragments, older/after, all four hash
challenges, a ranged tprv, seven tapscript leaves) mined, 5 negatives
incomplete here and unfinalizable by Core. RESULT 436/436 (with the musig
session below).

Closed: **`musig()` descriptors** (BIP390). `musig(KEY,...)[/path][/*]` as
the key of `tr()`/`rawtr()` and inside their leaves' `pk()`/`multi_a()`,
with Core's `ParsePubkey` rules and messages; the aggregate is
`musig2_key_agg` over the participants SORTED as Core's
`MuSigPubkeyProvider` sorts them (Core v31.99 sorts -- `musig2.h`'s
"written order" note was wrong; Core's own vectors settle it); the
musig()'s derivation is BIP32 CKDpub over the synthetic xpub.
`descriptorprocesspsbt` performs the Updater step Core's `UpdatePSBTInput`
performs: `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` keyed by the underived
aggregate, `PSBT_IN_TAP_INTERNAL_KEY`, `PSBT_IN_TAP_BIP32_DERIVATION` for the
derived aggregate (fingerprint hash160(aggregate)[0..4] + the musig() path)
and for every participant (origin, or the xpub's own fingerprint, or a
bare key's hash160 prefix). Evidence: Core's nine non-multipath musig()
Check() vectors (public form, private reprint, scriptPubKeys at three
indices) and eight error strings in `tests/test_descriptor_vectors`; three
MuSig2 sessions in `validation/miniscript_core_diff.py` (part 3) where two
Core wallets and this node are the participants and the funded PSBT's
musig/taproot fields are STRIPPED before this node sees it -- its Updater
must recreate them: Core's `decodepsbt` of our PSBT shows the identical
participants and internal key, the rounds complete, Core finalizes to the
same transaction and mines it.

Still open, by measurement: **multipath** `/<a;b>/*` key expressions (Core's
multipath musig()/miniscript vectors use them; this engine has no multipath
at all -- a separate item); **PSBT v2** in the signer (`psbt_process` takes
v0 only; master Core's `createpsbt` defaults to v2 -- ask for
`psbt_version=0`); `descriptorprocesspsbt` does not synthesize
`tap_leaf_script`/control blocks for a tr() descriptor's leaves the way
Core's Updater does (they must already be in the PSBT, as
`utxoupdatepsbt` puts them); partial-signature EXTRACTION (`finalize=false`)
for miniscript inputs stays limited to the P2WPKH/P2PKH/taproot forms.

## Update 2026-09-02 — private broadcast (Core v30 `-privatebroadcast`)

Implemented and proven against a real Core on regtest
(`validation/private_broadcast_regtest_e2e.sh`, 24 checks). With
`privatebroadcast=1`, `sendrawtransaction` test-accepts the transaction and
QUEUES it (`daemon/private_broadcast.c`) instead of admitting it to the
mempool; the download worker owes three connections per transaction and
opens each in a forked helper child (the same shape as its background
dials): a random reachable network among tor, i2p and clearnet-through-the-
tor-proxy, a random routable address of that network from the book, a fresh
transient I2P session or random SOCKS5 credentials per connection, then
Core's exact conversation — an anonymous `version` (services 0, time 0,
zero addresses, height 0, relay 0, user agent `/pynode:0.0.1/`), `verack`,
one `inv`, the peer's `getdata` for exactly that inv, the `tx`, a `ping`,
and the `pong` as the receipt; nothing else is ever sent (no pong, no
sendaddrv2/wtxidrelay echoes). The transaction leaves the queue when it
comes back from the network over an ordinary peer; stale entries are
re-tested every 2–3 minutes and re-broadcast or dropped with the reason.
`getprivatebroadcastinfo` and `abortprivatebroadcast` are Core's shapes;
both refuse with Core's text when the option is off. Boot refuses the option
without Tor or I2P reachability (Core's words) and warns on
`proxyrandomize=0`.

What Core proved on the wire: its `getpeerinfo` shows our connections as
`/pynode:0.0.1/`, services `0000000000000000`, `relaytxes` false; its
mempool gains the transaction; the SOCKS5 stub standing in for Tor saw
three connections with three distinct credential pairs (stream isolation);
the transaction returned to our node over the normal leg and the queue
emptied.

Divergences, on purpose:
- Core refuses `-privatebroadcast` together with `-connect`; this node WARNS
  instead. Core's private dials share the connection budget `connect=`
  restricts; ours come from the address book regardless, so the pairing
  works — the warning says the private connections go outside the
  `connect=` list.
- Private connections are not itemised in `getpeerinfo` (they live in
  helper children for seconds); Core lists them with
  `connection_type: private_broadcast`.
- The queue holds 64 transactions (Core: 10,000) and 8 concurrent
  connections (Core: 64) — a personal node's numbers.
- v1 transport only for the private connections (Core uses v2 when the
  peer advertises it).

Observed about Core v31.99 while testing, recorded because it will confuse
the next person: after accepting a transaction from an inbound peer Core
sometimes held its announcement to our (inbound-to-Core) leg for 60–120 s
until another transaction bumped its inbound tx-send-rate bucket; once
bumped, both went out in one `inv`. The harness waits 90 s and then sends
one Core wallet transaction as the bump, saying so.

Also fixed on the way: `addnode=host:port` now keeps its port in the boot
book fold-in, the liveness probe and the download worker's re-dial (it
silently dialled the chain default before).

## Update 2026-09-02 — audit finding N4: the legacy wallet-file scheme is gone from the write paths

Two wallet stores existed. The descriptor wallet's container (`bmcwallet.enc`,
`BMCWENC1`, daemon/wallet_crypter.c: Core's BytesToKeySHA512AES with 100,000
iterations, random salt, AES-256-CBC) has been the live wallet's since
2026-08-27. The OLDER store in `asm/wallet_store.c` — the CLI's mnemonic file
(`BMCWAL v2`) and addhdkey's extra-xprv blob (`BMCHDK v1`) — kept its own
scheme: PBKDF2-HMAC-SHA512 at 2,048 iterations with an EMPTY salt, a custom
CTR cipher keyed from the same bytes, and a custom tag. It predates the
crypter and nothing ever routed it through the strong container, so
`wallet_cli init <passphrase>` and `addhdkey` still wrote the weak shape
(audit 2026-09-02, N4).

Now: both write the strong container — `BMCWAL v3` / `format=wcrypt` lines
holding the hex of a `wcrypt_seal` blob — and never the legacy shape again.
Legacy files still open (read-only code kept for exactly that), and a
successful open rewrites the file upgraded, atomically (tmp + rename, 0600),
with a `[wallet] … upgraded legacy …` line. `tests/test_wallet_store` proves
it against genuine legacy fixtures written by the pre-change code:
right/wrong passphrase, the in-place upgrade, the second open through the
strong path, the secret blob likewise, and that no `.tmp` is left behind.

## Update 2026-09-02 — audit N3/N5/N6/N7/N11 remediation

See the remediation record at the end of `docs/audits/SECURITY_AUDIT_2026-09-02.md`.
In short: three more misbehaviour classes are scored (parse failures, never
policy or consensus rejects -- the self-partition argument is in the asm
comment at `.do_block`); the service runs under a systemd sandbox with core
dumps off; log rotation actually works now (it never had) and runs as the
service user from a root-owned config; the build's hardening is explicit and
every shipped tool is linked `BIND_NOW`; `-Werror` is blocked by 433 existing
warnings (209 incompatible-pointer-types) -- **open item: a warning-cleanup
pass, then `-Werror`**.

## Update 2026-09-02 (later) — audit N1 evidence, N8 closed, manual wallet decryption

- **N1:** the audit quoted two Makefile comments about harnesses pinned below
  -O2. Both quoted harnesses have in fact been -O2 since 2026-08-23; the two
  rules still pinned (`test_sigops` -O1, `pverify` -O1) were rebuilt at -O2:
  the test passes and pverify's verdicts are identical to the -O1 build over
  three real block ranges. Pins lifted, comments corrected. The structural
  point stands (hand asm, no root-cause narrative for the historical
  mis-parse), but there is no longer a rule in the tree that *avoids* -O2.
- **N8:** `config/bmcwallet.testnet4.pass` deleted; it was never tracked. The
  testnet4 wallet is provably empty (see `docs/PARITY_ATTESTATION.md` for
  the mainnet side; the testnet4 scan is in the worklog).
- **Manual wallet decryption:** `wallet_cli` now asks for the passphrase
  (echo off) when nothing supplied it and the wallet is encrypted, reads it
  from a pipe when stdin is not a terminal, and `init` asks twice and stores
  no `.pass` file for a typed passphrase. `bmc_cli` gained Core's
  `-stdinwalletpassphrase` and `-stdin`. Pinned by `tests/test_cli_prompt`
  (a real pty). Parity attestation heights are now published in
  `docs/PARITY_ATTESTATION.md` (audit recommendation 8).

## Update 2026-09-02 — every C compile is `-Wall -Werror` (audit N7, the deferred half)

The tree carried 3,166 warning lines per full build (287 unique sites once
the per-rule repeats are removed; 57 of the object rules had never been
compiled with `-Wall` at all, hiding 27 more). All were fixed at the root
(prototypes corrected, results checked, buffers bounded, indentation made to
say what the code does, dead helpers removed), never with pragmas or blanket
casts, and `WARNFLAGS := -Wall -Werror` is now appended to every C compile in
the Makefile. The classes and what they turned out to be are recorded in
`worklog/2026-09-02.md`. nasm followed the same day: `NASMFLAGS := -f elf64 -I. -Werror`. Its ten
warning sites hid four real defects, one of them consensus-relevant: the
CHECKSEQUENCEVERIFY disable-flag test used a sign-extended immediate and
turned enforced 5-byte operands into NOPs (`tests/test_csv_disable_flag`).
Details in `worklog/2026-09-02.md`.

## Update 2026-09-02 — randomized script differential against Core (audit §6.9): DONE, and it paid

`tests/fuzz_script_diff` (manual; needs `validation/build_core_oracle.sh`
to build Core's `EvalScript` as a line oracle) compares verdict, error code
and the entire final stack on random scripts. The first 20,000 cases found
728 divergences; all traced to five root causes in the interpreter, every
one of them a policy-flag behaviour (MINIMALDATA scriptnum encoding, MINIMALIF
error code, the 0x81 push rule, STRICTENC pubkey encoding, NULLDUMMY
precedence) -- mempool/relay parity, never block validation. After the fixes:
1.62 million cases over four seeds, zero mismatches. Seventeen vectors are
pinned in `tests/test_interp_core_vectors` so the gate does not need Core.
Not yet covered by the generator: tapscript (sigversion 3, needs execution
data on both sides) and real signatures (the checker fails every signature on
both sides by construction). Those are the next extension.

## Update 2026-09-02 — the differential now covers real signatures and taproot

`tests/fuzz_verify_diff` (manual) compares our whole-input verification --
the exact `sv_verify_script` / `sv_verify_witness_v0` / `taproot_verify_input`
calls `daemon/tx_verify.c` makes -- against Core's `VerifyScript`, on random
transactions whose signatures Core itself produces (ECDSA over legacy and
BIP143 sighashes, Schnorr over BIP341 key-path and BIP342 script-path
sighashes with annexes, code separators and two-leaf trees). Verdicts never
disagreed; error codes under the standard policy flags did, which is how
NULLFAIL, LOW_S, the STRICTENC hashtype rule and CONST_SCRIPTCODE arrived in
the interpreter. 63,000 whole-input cases and 400,000 more EvalScript cases
now match exactly. `tests/test_verify_core_vectors` keeps 71 of the Core-signed
spends in the gate. Not covered: tapscript at the EvalScript level with
execution data (the whole-input path covers it end to end instead), and
MuSig2/PSBT flows (a different layer).

## Update 2026-09-02 — fresh-install acceptance test: two findings before the first 100k headers

`validation/fresh_install_ibd.sh` (clone from GitHub, README build, minimal
configuration, unattended sync, muhash against Core at the tip) found, within
its first minutes: (1) the quick start's configuration copy is invisible to a
daemon whose datadir is not `<repo>/data` -- the daemon then runs on compiled
defaults; (2) the header-sync guard added after the 2026-09-01 incident capped
the number of headers per session at 100,000 and rolled the session back,
so a node syncing from genesis could never pass 100k headers. The guard now
limits how deep below our tip an answer may attach (the incident's case),
not how many headers follow. (3) The download workers' dead-weight rule
(bytes per second only) banned honest peers serving the tiny early blocks;
it now also requires a low block rate. The run continues from a fresh clone of the
fixed tree; `phase.log` / `progress.log` / `RESULT` in the run directory.

## Update 2026-09-03 — our own transactions now announce like Core's, instead of being pushed

Transactions this node originates (`sendrawtransaction`, and every wallet send,
which routes through it) went out as an unsolicited `tx` message written to
every peer leg in the same instant. Relay-*received* transactions had used the
proper `inv` path since 2026-08-26; own transactions never joined them, and the
gap was not written down here before now.

Both halves of the old behaviour identified this node as the origin. An
unsolicited transaction is not what a relaying node sends: anything merely
passing one along announces the txid and waits for `getdata`, so a peer handed
the bytes unprompted can tell it is talking to the source. And Core spreads
announcements over an independent Poisson timer per peer precisely because
simultaneous delivery on every leg is the signature of the node a transaction
started at — a relayer's announcements have already been smeared by the hop
that reached it.

The justification in `daemon/tx_submit.c` was that the download worker runs no
serve loop to answer a follow-up `getdata`. That had stopped being true:
`daemon/tx_relay.c`'s drain answers `getdata(MSG_TX/MSG_WITNESS_TX)` from the
shared mempool, which is how relayed transactions already propagate. Own
transactions now use the same announce queue.

The queue gained a per-leg timer to match Core: each leg draws its own
next-send time from an exponential with mean 2 s (`m_next_inv_send_time`,
`OUTBOUND_INVENTORY_BROADCAST_INTERVAL`), starting the moment the leg appears
so the first announcement of a session is staggered too. The deviate is
computed without `libm`, which nothing in this build links: for uniform 64-bit
`r`, `-ln(r/2^64)` is `(clz+1)*ln2` minus the log of the normalised mantissa,
taken from a 65-entry table with linear interpolation. `test_tx_relay` holds it
to the distribution rather than the mean alone — over 200,000 draws, measured
mean 1998.3 ms against 2000, `P(>m)` 0.3678 against `1/e`, `P(>2m)` 0.1352
against `1/e²`.

One defect surfaced only because the test went looking. A descriptor is
recycled the instant a leg closes, so a re-dialled leg inherited the previous
peer's slot — including a timer already due, announcing to the new peer at once
and defeating the stagger exactly when legs churn most. `txrelay_leg_reset` is
called from all three sites that hand a leg a fresh descriptor, and
`txrelay_announce` independently re-arms any descriptor absent on the previous
call, so a dial site added later and left unwired cannot degrade the stagger
silently.

`sendrawtransaction` now returns once the transaction is in the mempool, with
the invs following on the worker's next rotations; Core returns at the same
point for the same reason. Still not matched: inbound peers are served by the
serve process on its own schedule, so the 5 s inbound interval Core uses is not
modelled separately, and BIP339 `wtxidrelay` announcement remains txid-based.

## Update 2026-09-03 — TRUC sibling eviction

A second TRUC child was refused outright. It spends a different output of the
parent, so it double-spends nothing and ordinary RBF cannot reach it; only the
TRUC descendant rule saw it at all, and that rule said no.

Core does not simply refuse. `SingleTRUCChecks` returns the existing child
alongside the error, and `MemPoolAccept` adds it to the to-be-replaced set so
the ordinary replacement arithmetic decides. The reason is the point of TRUC:
a parent's fee is meant to be raisable through its one child, and without
sibling eviction a child sitting at a low feerate means the only party who can
ever rescue that parent is whoever owns the child. That is the pin the
topology exists to abolish.

Implemented in `bitcoin_mempool_policy.c`, offered only in the narrow shape
Core insists on, because a wider one needs a rule for CHOOSING which
descendant dies and Core deliberately has none: the parent must have exactly
itself and one child, and that child exactly itself and the parent. Reorgs can
leave wider shapes behind and those are still refused, as are package contexts
(Core allows sibling eviction for a single transaction only). The sibling then
faces the same replacement cap and the same `PaysForRBF` arithmetic as any
other conflict, priced over the whole to-be-replaced set. What is deliberately
NOT asked of it is BIP125 signalling — Core skips that here and says why, since
a TRUC transaction can only acquire a non-signalling descendant through a
reorg.

`test_truc_policy` covers both outcomes, since only having the refusal proves
nothing: an equal-paying challenger is refused **on fee rather than on
topology** (a `TRUC-violation` there would mean the eviction path never ran),
a challenger clearing the sibling's fee plus its own incremental relay cost is
accepted and the sibling leaves the pool, the parent survives, and a third
child must then beat the new incumbent rather than accumulating.

~~NOT yet done: a regtest differential against real Core for this path.~~
**DONE 2026-09-03**, closing the gap the same day it was raised —
`validation/truc_sibling_core_diff.sh`. See the update further down this file
for what it proves and how it was checked against a deliberate regression.

## Update 2026-09-03 — TRUC sibling eviction, proven against real Core on regtest

The sibling-eviction implementation above was checked against Core's SOURCE,
not its running behaviour — weaker than this project's usual bar for exactly
this kind of policy work. `validation/truc_sibling_core_diff.sh` closes that
the same day: two disconnected regtest nodes (severed with
`setnetworkactive false` right after height sync, so relay cannot let one
node's verdict leak into the other's mempool), Core acting as BOTH the
transaction factory and the judge — it builds, signs, and broadcasts every
transaction, so nothing in the proof depends on this project's own signer —
and each transaction submitted to both nodes over their own RPC.

15 checks, all agreeing: a version-3 parent with two spendable outputs; the
one child TRUC allows; a second child paying the same as the first, refused by
both (on fee, `insufficient fee` on ours, `insufficient fee (including sibling
eviction)` on Core's — the topology is no longer the reason either node gives);
a second child paying well over the incumbent's fee, ACCEPTED by both, with the
incumbent gone from both mempools by direct query, not just by an overall
match; a third child that would have beaten the ORIGINAL incumbent but not the
new one, refused by both. Mempools are compared as full txid sets after every
step, not just spot-checked at the end.

Checked in both directions, not just that it passes: the same harness run
against the pre-sibling-eviction code (`bitcoin_mempool_policy.c` from before
c43f97c) reproduces exactly the shape of bug this exists to catch —
`core=accept bmc=reject(TRUC-violation)` on the eviction case, and the
divergence then cascades into a mempool mismatch and a wrong verdict on the
third-child case, because that one's correctness depends on the eviction
having happened. A differential that cannot be made to fail proves nothing;
this one fails in exactly the place the feature exists to fix, and only
there.

## Update 2026-09-03 — `bytespersigop`, and the sigop count that outlived its transaction

This was recorded above as deliberately not done, on the grounds that vsize
came from weight alone and the sigop cost was recorded after acceptance. Half
of that had already stopped being true. A `mpol_pending_sigops` hook existed,
`daemon/tx_accept.c` set it from its prechecks (where the UTXO view needed for
the P2SH and witness counts is already open), and the two entry fee floors were
already using `max(vsize, sigops*bytespersigop/4)`. The option was neither
absent nor implemented, which is the state the paragraph above rightly called
worse than either.

**Three things were wrong, and the third was a live bug.**

*The adjustment reached only the fee floors.* Core does not keep a real vsize
and adjust it at the fee gate: `CTxMemPoolEntry::GetTxSize()` **is** the
adjusted figure, so the replacement arithmetic, the ancestor and descendant
byte budgets, the TRUC size caps, eviction, mining and `getmempoolentry` all
see it. Ours saw the plain BIP141 vsize everywhere after the fee check, so a
sigop-dense transaction paid Core's price to get in and then occupied a smaller
footprint than Core in every limit that followed. The adjustment is now
computed once, at the top of `mpol_accept`, and is the entry's size.

*The rounding was Core's formula rearranged.* Core takes the max on the
**weight** scale and rounds once at the end:
`ceil(max(weight, sigop_cost * bytespersigop) / 4)`. Taking the max after
dividing rounds the sigop term down and undercharges by a byte whenever
`sigop_cost * bytespersigop` is not a multiple of 4. Invisible at the default
`bytespersigop` of 20, which is itself a multiple of 4 — so the test uses a
value that is not.

*A rejected transaction left its sigop count parked for the next one.* The
count arrives through a global that the caller sets before the call, and it was
cleared at the fee gate — with eight rejection paths between the top of the
function and that point. A sigop-dense transaction rejected on any of them left
its count behind, and the next transaction, a different one that might carry no
sigops at all, was priced as though it did. `mpol_accept` now reads and clears
it in the same breath, as its first act. The test proves the bug rather than
the fix: run it against the previous code and the follow-up transaction is
refused with "min relay fee not met".

Also fixed while here: `test_mempool_policy`'s `okv` macro evaluated its
condition **twice**, once for the label and once for the counter. A check whose
condition had a side effect ran it twice, so `okv(mpool_policy_add(...) == 1)`
submitted the transaction again, the duplicate was refused, and the case
printed "ok" while quietly incrementing the failure count. It evaluates once
now.

~~Still unmatched: package effective-feerate aggregates.~~ **CLOSED the same
day.** Both aggregate sites — `daemon/main.c`'s `submitpackage` and
`daemon/tx_relay.c`'s 1p1c relay — summed the plain BIP141 vsize from
`mpol_package_well_formed`'s structural walker, which cannot count sigops
because those need the UTXO view. Core aggregates over entry sizes, and an
entry's size is the adjusted figure, so a sigop-dense member was priced
slightly cheaply inside a package.

The adjusted figure now comes back out of the dry run: `mpool_policy_test`
gained a `vsize_out` alongside its existing `fee_out`, published as soon as the
size is known and therefore reported even when the transaction is REJECTED —
a member failing only on fee still contributes its size to the package total.
Both callers use it, falling back to the walker's figure only for a member
rejected before the policy layer ran, which never joins a total anyway.

Deliberately a per-call out-parameter rather than another "last value" global.
The bug fixed hours earlier in this same area was precisely a global set before
a call and consumed later; adding a second one to carry the fix would have been
the same mistake twice.


## Update 2026-09-03 — the false-accept differential oracle was silently dead for over a day

Asked for targeted differential tests aimed at accept-direction bugs in the
hand-written assembly — this project's own stated structural risk, the one
finding across three audits marked "not closeable by a patch" — the first
useful action was checking whether the infrastructure that already exists for
exactly this purpose still worked. It did not.

`validation/core_verify_oracle.cpp` is the ground-truth `VerifyScript` oracle
for two mature harnesses: `spend_corpus_diff.py` (random real mainnet spends
plus generic mutations) and `synth_corpus_diff.py` (rule-targeted synthesis
for multisig, CLTV, CSV, taproot, and the numeric resource limits). Their own
git history is a genuine record of what this class of testing is for: incident
#18, incident #21, a BIP66 false accept above height 363,725, two BIP341
sighash false accepts, and the CHECKMULTISIG opcode-budget bug. The 2026-09-02
commit that gave `tests/fuzz_verify_diff.c` its own oracle commands (lowercase
`key`/`verify`/`signecdsa`/`signschnorr`) **replaced this file wholesale**
instead of extending it, silently deleting the uppercase `VERIFY`/`TAPVERIFY`
protocol the two older harnesses depend on.

Nothing caught it for over a day. The build script still produced a valid
binary. Both harnesses still ran to completion, exit 0. Every case timed out
waiting 20 seconds for an answer this binary no longer gave, was correctly
counted as an "engine failure" (the harness's own honest name for exactly this
situation), and the headline verdict — **ZERO DIVERGENCES** — was technically
true and completely meaningless, because nothing had actually been compared.
A vacuous pass looks exactly like success; the only tell was an "engine
failures: 7879" line buried at the bottom of output nobody had read since.

Restored `VERIFY` and `TAPVERIFY` into the current file, reusing its own
helpers rather than the deleted file's separate ones, so both protocols now
coexist: the lowercase commands `fuzz_verify_diff.c` needs are untouched
(reconfirmed clean), and the restored uppercase ones unblock the two Python
harnesses. One thing the naive restoration got wrong, caught only by actually
running mutation cases rather than trusting a clean compile: a transaction
mutated past the point of deserializing at all now threw an uncaught
exception instead of the original code's graceful `OK 0 tx-decode-fail`
verdict, silently routing a handful of otherwise-comparable cases into the
same "engine failure" bucket the missing commands had caused — a smaller
copy of the exact bug being fixed. Fixed by wrapping the decode step locally;
confirmed by a targeted reproduction going from 3 failures to 0.

**Run for real, at scale, for the first time in over a day:**

| Harness | Cases | Mutations agreed | Divergences |
|---|---|---|---|
| `spend_corpus_diff.py` (real mainnet spends) | 1,670 | 10,019 | 0 |
| `synth_corpus_diff.py` (synthesized features) | 74 (+7,805 interpreter probes) | 95 | 0 |
| `tests/fuzz_verify_diff` (whole-input, real sigs) | 5,000 | — | 0 |
| `tests/fuzz_script_diff` (raw EvalScript) | 20,000 | — | 0 |

One residual engine failure in the largest `spend_corpus_diff.py` run (1 in
~11,700 round trips), not reproduced on an isolated re-run of the identical
seed and logic — consistent with the harness's 20-second read timeout under
the concurrent CPU load of the full `make -k test` gate running at the same
time, not a functional defect.

**The lesson this leaves behind, independent of the specific bug:** a
differential harness that reports "zero divergences" without also reporting
"and I actually compared something" can go silently blind. Both harnesses
already had the right instinct — counting engine failures separately from
divergences rather than folding them into the same number — but neither put
that count anywhere a human would see it before believing the headline.
Worth a follow-up: make a high engine-failure rate fail the run's exit code,
not just its own line in the report, so a repeat of this specific mistake
cannot again pass silently for a day.

## Update 2026-09-03 — new targeted mutations: the SIGHASH_SINGLE three-way split, and P2WSH's size exemption

Asked to extend coverage specifically for resource-limit and sighash edge
cases, on top of the oracle restoration above. Two genuinely new differential
classes, both found by reading Core's source and this project's own code
side by side rather than by guessing at likely bug shapes.

**The SIGHASH_SINGLE-with-no-matching-output rule is not one rule with three
implementations — it is three DIFFERENT rules, one per sigversion, and only
one of them had a differential before now.** Legacy substitutes the whole
sighash with the constant `uint256(1)` (`SignatureHash`'s own historic
compatibility hack, gated `sigversion != WITNESS_V0`). BIP143/witness v0
zero-fills only the `hashOutputs` mid-hash inside an otherwise ordinary
preimage — a narrower, different substitution, excluded from the legacy path
by that same guard. BIP341/taproot does neither: `SigningDataSighash` returns
`false` outright, so the sighash cannot even be computed and the spend is
unconditionally invalid. `synth_sighash_single_bug()` tested only the first
of these. `synth_sighash_single_v0_no_output()` and
`synth_sighash_single_taproot_no_output()` add the other two.

The taproot case is a regression test for a REAL, ALREADY-FIXED consensus
false accept (`bitcoin_taproot_sighash.c`, 2026-08-22): the taproot sighash
used to carry BIP143's zero-fill behaviour over verbatim, computing a
signable hash where Core computes none, and accepting spends Core has always
rejected — 130 of 945 vectors in the corpus that caught it were this exact
case on real mainnet transactions, not a constructed corner. That diagnostic
script is gone and nothing else in the tree names this input shape, so the
fix has had zero regression coverage against Core since the day it landed.
The new test signs with the OLD, WRONG formula on purpose — not a garbage
signature that would be rejected for any reason, but the exact bytes a
regressed implementation would happily accept — confirmed by computing both
formulas over the same otherwise-valid inputs and checking they produce
materially different hashes, so the test is known to discriminate rather
than accidentally coincide.

**P2WSH's witnessScript is not bounded by the 520-byte push-size limit the
way a P2SH redeemScript is, and the reason is structural rather than a
special case written for witness scripts.** A P2SH redeemScript must arrive
as a scriptSig push, so the generic `MAX_SCRIPT_ELEMENT_SIZE` caps it at 520
bytes before it is even considered. A P2WSH witnessScript instead arrives as
the LAST witness stack item, popped off (`VerifyWitnessProgram`'s
`SpanPopBack`) before Core's "no witness item over 520 bytes" check ever runs
over what remains — so the script itself is invisible to that check, and its
only real ceiling is the generic 10,000-byte `MAX_SCRIPT_SIZE` that also
bounds a bare script. A hand-rolled implementation that applies "witness
items are capped at 520 bytes" uniformly, without excluding the one that got
popped, would reject spends Core accepts.
`sv_verify_witness_v0` (`bitcoin_witness_v0.c`) gets this right by excluding
index `nwit-1` from its per-item size loop — confirmed correct by reading it
before writing the test, and now checked against Core rather than only
against a reading of the file: `synth_p2wsh_script_size` proves a 521-byte
witnessScript (over the P2SH cap) and a 10,000-byte one are both legal, and
10,001 bytes is rejected.

**A third case was designed, built, found genuinely infeasible, and dropped
rather than shipped anyway.** The witness stack's own item-count check
(`nstack > MAX_STACK` in `sv_verify_witness_v0`, evaluated before the script
ever runs — distinct from `EvalScript`'s execution-time
`stack.size()+altstack.size()` accumulation) looks like a candidate for the
same treatment: 1000 pre-supplied witness arguments accepted, 1001 rejected.
The reject side is trivially constructible (an empty or trivial witnessScript
with too many leftover items fails the implicit witness-cleanstack rule
regardless of the reason). The accept side is not: consuming anywhere near
1000 pre-existing stack items down to the required single element costs more
opcodes than the 201-opcode budget allows by any mechanism Bitcoin Script
has — `OP_2DROP` needs 500 calls for 1000 items, and `OP_CHECKMULTISIG`
charges its own pubkey count against the same budget it would need to spend,
so large-N consumption is not just hard here but appears to be structurally
impossible to construct as a genuinely valid spend at all. Confirmed
numerically (402 items is the most `OP_2DROP` alone could ever clear within
budget) before writing anything that would have tested the wrong thing under
a misleading name.

Full run after adding these: 79 synthesized cases (up from 74), 96 rule
mutations, 7,805 interpreter probes, zero divergences, zero engine failures,
zero synthesis errors.

## Update 2026-09-03 — a full re-audit, requested after finding the document had drifted again

This document has now self-corrected for drift twice before (2026-08-25,
2026-08-27) and had drifted a third time. Four categories were re-audited
from scratch — every "still open" / "absent" / "not implemented" claim was
checked against the CURRENT source, not against this document's own prose,
because the prose is exactly what was found unreliable.

### The one finding that matters more than any doc correction

**`assumevalid` is implemented and has been ACTIVE BY DEFAULT since
2026-09-01** — `asm/daemon/utxo_live.c`'s `utxo_live_resolve_assumevalid`
and `apply_block_at_inner`, defaulting to Core's own chain-default
assumevalid hash rather than to `assumevalid=0`. Confirmed live on both the
production-equivalent daemon and the fresh-install acceptance run currently
in progress: both logged `assumevalid: block found at height 938343 --
script evaluation skipped through it, resumed above` at boot. Every earlier
passage in this document describing script verification as unconditional
("this node verifies every script in every block", used to justify
declining `assumevalid` as a "deliberate refusal") describes a true fact
about 2026-08-21 that stopped being the default behavior on 2026-09-01, and
was never corrected.

**What this means for every "verified against Core, zero divergences"
claim from a normal sync:** the UTXO set, proof-of-work, block structure,
and every non-script consensus rule are still checked for the whole chain
— those claims stand. *(VAL-16, 2026-09-03, disputed this on the strength of
VAL-1..VAL-6, which were open at the time. All six are closed as of the
2026-09-05 remediation, so the sentence is accurate again; re-verified rather
than re-worded.)* But under the default config, ONLY the top ~27,000
of ~965,000 blocks have their scripts independently checked against Core
during that sync; the ~938,000 below the assumevalid height are trusted,
exactly as real Core trusts them by default. The stronger claim —
"every script in the whole chain, independently verified" — requires
`assumevalid=0` explicitly, which is exactly what the item below still
needs to prove.

### Real bugs found (not documentation drift — actual defects)

- **`gettxoutproof` still refuses without a block hash, citing "no
  txindex"** (`asm/rpc_chain.c` around the `-5` error), even though
  `txindex` has existed since 2026-08-26. The justification is false; the
  refusal itself may or may not still be intended, but the STATED REASON
  is wrong and should be fixed or restated.
- **`getnetworkinfo` reports `proxy_randomize_credentials: false` and an
  empty `proxy` string unconditionally** (`asm/rpc_node.c`'s `net_entry()`),
  even though per-connection SOCKS5 credential randomization is real and
  active (`asm/daemon/dialer.c`). The RPC answer misreports the node's own
  configured behavior.
- **`getaddressinfo`'s wallet-context fields are hardcoded stubs**
  (`ismine`, `iswatchonly`, `ischange` always `false`, `pubkey` always
  empty — `asm/rpc_commands.c`), regardless of whether the address is
  actually the wallet's own. Filed under wallet gaps below as well, but
  it is a correctness bug against a live wallet, not merely an absent
  feature.

### Confirmed genuinely still open (verified against source, not stale)

- **Full-verification IBD benchmark vs Core** (`-assumevalid=0
  -stopatheight`, second scratch datadir) — still never run. Now doubly
  the point, given the finding above: this is the one way to get the
  strong "every script, every block" claim rather than the default
  "matches Core's own trust boundary" one.
- `assumeutxo` / snapshot import — absent, large lift, no current need.
- MuSig2 signing inside tapscript LEAF scripts (key-path MuSig2 is done;
  a script-path leaf using MuSig2 is not signed — `asm/rpc_commands.c`).
- `getaddressinfo` wallet-context stubs (see bugs above).
- No keypool (`keypoolrefill` returns null) — deliberate, this node signs
  on demand rather than pre-generating.
- BIP331 package-relay WIRE NEGOTIATION (`sendpackages`/`pkgtxns`/
  `ancpkginfo`) — package ACCEPTANCE (1p1c, the TRUC/ephemeral-dust rules)
  is real and proven against Core; the separate wire protocol to announce
  and request packages is not built. The project's own P2P summary row
  overstates this as done; it is half-done.
- Erlay/BIP330 reconciliation — negotiation only, wire-off, a deliberately
  declared stopping point, unchanged since 2026-08-30.
- REST interface, UPnP/NAT-PMP, `blockreconstructionextratxn`, `rpc.discover`
  — all absent by explicit design, consistently described as such.
- **Inbound-accepted transactions are not re-announced to this node's other
  peer connections** (`asm/daemon/tx_relay.c`'s `txrelay_poll_leg` is only
  ever called with outbound mux legs, `asm/daemon/main.c`). Distinct from
  the 2026-09-03 own-transaction announcement work earlier today, which
  fixed how WE originate an announcement, not how we relay one someone
  else handed us onward past our outbound legs.

### Confirmed CLOSED, contradicting older passages elsewhere in this file

A representative sample, not exhaustive — each was independently confirmed
against source before being listed here: BIP16/P2SH VerifyScript
build-out; sigop/`bytespersigop` cost accounting (closed the same day, see
above); pruning; MuSig2 key-path (BIP327); Branch-and-Bound coin selection
(`asm/wallet_bnb.c`); `musig()` descriptors (BIP390); multipath descriptors
(BIP389, `<a;b>`); PSBT v2 in the signer; `descriptorprocesspsbt` leaf/
control-block synthesis; miniscript partial-signature extraction;
`createwalletdescriptor`'s legacy/P2SH-segwit/bech32m activation;
`-acceptstalefeeestimates`; `getrawtransaction` by bare txid;
`coinstatsindex`'s RPC and live index; BIP23 `getblocktemplate` proposal
mode; signet; roughly 27 keys in `config/bitcoin.sample.conf`'s own "CORE
OPTIONS NOT SUPPORTED" table (that file, not this one, was the most
out-of-date artifact found — it is described as authoritative and had not
been updated to match `node_config.c` in some time); Tor/I2P/CJDNS address
storage and re-gossip (BIP155/addrv2, all networks); Tor onion
self-hosting; I2P inbound; CJDNS both directions; per-connection proxy
randomization (the CODE is correct; only `getnetworkinfo`'s report of it
is wrong, see bugs above); package relay ACCEPTANCE (distinct from the
wire negotiation, still open, above).

**Overall assessment.** This project is closer to Core parity than this
document, even now, fully states — most of what it has called "open" in
the last two weeks was already closed by the time it was read. The
consensus interpreter, mempool/relay policy, wallet, RPC surface,
indexing, and P2P networking are all substantially complete and checked
against Core wherever a differential exists. What remains that is real:
three small RPC-correctness bugs (above), a handful of deliberately
declined features, the package-relay wire protocol, and — the one item
worth treating as a priority — actually running a full, unconditional,
`assumevalid=0` verification of this chain against Core, now that it is
clear the routine sync path no longer does that by default.

## Update 2026-09-05 — the four audit LOWs that are design gaps, not defects

The 2026-09-03 audit's LOW tier is now closed. Four of its findings resisted
being "fixed" because they are not defects — they are consequences of design
decisions this node has made, and the right remediation is to state them
plainly rather than patch around them. Each was re-verified against the code
before being written down here; none is a restatement of the audit's text.

### `prioritisetransaction` deltas are display-only (MEM-18)

`prioritisetransaction` records a fee delta and `getprioritisedtransactions`
lists it back, but the delta reaches **nothing that makes a decision**.
`pri_delta_of` (`rpc_node.c:1531`) has exactly three consumers: `:1220`, where
`getmempoolentry` reports `fees.modified`, and `:1661`/`:1687`, where the
listing prints the deltas. Core applies `GetModifiedFee` to block assembly,
eviction, RBF and the fee floors; here the policy layer has no delta concept at
all, and the block template (`rpc_chain.c:1035`) uses `infs[i].fee`, the base
fee.

There is a second reason it could not work as-is even if the policy layer
consulted it: the delta table is **parent-local**. It lives in the RPC process,
while the download worker owns mempool admission and template construction, so
a delta set over RPC is not visible to the process that would have to honour
it. Wiring this properly means putting the deltas in the shared mempool state,
not adding a lookup.

An operator prioritising a transaction on this node changes what
`getmempoolentry` prints and nothing else. That is the whole behaviour.

### One execution lock behind every long wait (RPC-12)

Every request runs `handle_request` under `g_exec_lock` (`rpc_server.c:808`
and `:969`), so the RPC surface executes strictly one call at a time. The
serial model is deliberate and is what the longpoll design is built on. The
consequence that was never written down is what happens when the call in
progress is a **slow** one:

- `submitblock` waits up to 90 s for the worker;
- `sendrawtransaction` likewise;
- `importmempool` waits up to 90 s **per entry**, with no bound on entries;
- `walletdisplayaddress` `popen`s HWI (`rpc_signer.c:80`) and waits for a
  **human to press a button on a hardware wallet**.

For the duration, every other RPC blocks — including `getblockcount` and
including `stop`. A wedged worker turns the whole surface into a sequence of
90-second timeouts. Core runs handlers concurrently on `-rpcthreads` and takes
specific locks around specific state.

This is not being changed here. Moving the signer or the channel waits outside
the lock means those handlers execute concurrently with others against wallet
and mempool state that the serial model currently protects for free, and that
is a design change with its own correctness argument to make — not audit
cleanup. What was wrong was that the cost was undocumented.

### The wallet has no reorg awareness (WAL-13)

`wallet_scan.c`'s on-disk record is `u32 height | txid | vout | value`
(the format comment at `:36`). **There is no block hash.** A record therefore
cannot be checked against the chain it came from: if a reorg replaces the block
at that height, nothing in the wallet can notice.

The visible consequence: until the operator re-runs `rescanblockchain`,
`getbalance` and `listunspent` report an orphaned coin as confirmed, with a
confirmation count that keeps *growing*, and a spend of it fails at broadcast.
The file's own header explains why the scan runs forward in height order; it
does not say what happens when history changes underneath it.

Two things would have to change together: store the block hash per record and
drop records whose `(height, hash)` no longer matches the header chain on read.
Separately, `rescanblockchain` walks the whole archive on the single RPC thread
— hours on mainnet, and per RPC-12 above, with the entire RPC surface blocked
for the duration.

### Inbound peer-slot claim race (RPC-13) — FIXED, not documented

Listed here only to close the set: this one was a real defect and is fixed in
code. `inbound_slot_claim` CAS'd `used` 0→1 to take a slot, and then
`rpc_fill_peer_slot`'s `memset` zeroed `used` again for the duration of the
fill — advertising the slot as free, so a sibling child could claim the same
one. The loser's later `used = 0` would free the *winner's* entry.
`rpc_fill_peer_slot_ex` now preserves an existing claim across the memset. The
outbound path, which is not claimed by CAS and where zeroing `used` first is
what stops a reader seeing a half-filled record, keeps the old behaviour.

## Update 2026-09-05 — the audit's INFO tier: what was fixed, and what was decided

The 2026-09-03 audit's 33 INFO findings are worked through. Most became code
(see the commits naming each ID). This section records the ones whose right
answer was a DECISION rather than a patch, so nobody re-opens them expecting a
fix — and the two that turned out to be already-closed.

### Decisions, not defects

**NET-16 — the node introduces itself as software it is not.** The feeler and
block-relay-only handshakes send `/Satoshi:25.0.0/` (`net_policy.c:97`), and
the seednode/getaddr path sends `/Satoshi:0.18.0/` with a fabricated
`start_height` of 789000 (`addr_ingest.c:180`). Neither matches the daemon's
own `node_ua_buf`, which carries this project's real user agent.

This is not laziness and it is not an oversight — someone chose it, and the
reason is real: a node advertising an unknown user agent is treated
differently by peers and by crawlers, so borrowing Core's string makes those
paths behave like everyone else's. But it also means this node is
**misreporting itself to the network**, including to the crawlers that publish
node-population statistics, and that is a choice the project should make out
loud rather than leave sitting in two string literals.

**Recorded, not changed.** Changing it is a one-line edit either way; what it
needs is a decision about how this node wants to appear, taken deliberately.
Until that decision is made, the current behaviour stands and is documented
here rather than implied.

**RPC-18 — the RPC listener is IPv4-only.** `rpc_server.c` creates an
`AF_INET` socket and parses `-rpcbind` with `inet_pton(AF_INET)`, so
`rpcbind=::1` is a startup error and every IPv6 `-rpcallowip` entry is
unreachable. `rpc_acl.c` seeds `::1` into the default allow list, where it can
never match.

Adding `AF_INET6` is a contained change (socket, `inet_pton`, and
`server_thread`'s peer formatting), but it is a feature with its own testing —
dual-stack binding, v4-mapped addresses, and the ACL semantics for both — not
audit cleanup. **The dead `::1` seed is kept**, because it is the correct
default the moment the listener learns IPv6 and deleting it would silently
narrow the default from "loopback, both families" to "IPv4 loopback only" at
exactly that moment. It is now annotated as inert at the line itself.

### Accepted risks, closed

**CRY-8 — AES timing and the lazy S-box.** The inverse S-box is built lazily
through an idempotent racy write (benign on x86: every writer stores the same
bytes), and both the S-box lookups and the PKCS#7 padding check are
variable-time. Correctly scoped out: this AES decrypts the wallet at rest, and
no attacker-chosen ciphertext is decrypted online, so there is no oracle to
time. Closed with no change.

**SCR-11 — CONST_SCRIPTCODE check ordering.** `bitcoin_interp.asm` runs the
signature and pubkey encoding checks before the FindAndDelete callback, where
Core's `EvalChecksigPreTapscript` runs FindAndDelete first. Both reject the
same scripts; only the reported error differs when a script trips both, and
the flag is policy-only. Reordering consensus-adjacent interpreter code to
change which of two rejections is named is not a trade worth making. Closed.

**BLD-6 — the gate is one recipe with ~350 command lines**, and a recipe stops
at its first failing line even under `-k`, so an early failure skips every
later test. That is real, understood, and already mitigated: `gate-log-check`
exists precisely to detect a truncated run and is itself gated. No change.

**BLD-10 — repo hygiene**, re-verified 2026-09-05: 1,070 tracked files,
largest is `validation/corpus_diff_report.json` at 2.6 MB, `git status` clean.
No key material in tracked files other than BLD-3. No action.

### Already closed by other findings

**UTX-13** claimed the 32-bit `mov eax, -1` error-return defect was "live in
`utxo_lsm_put`". It is not, as of UTX-3 in this same audit round: both
`utxo_lsm_put` (`.lp_err`) and `utxo_lsm_del` (`.ld_err`) return a full 64-bit
`mov rax, -1`. The stale explanation in `daemon/flush_wal_tail.c` has been
corrected — the test there compares against the SUCCESS value, which is why it
kept working when the convention changed underneath it.

**UTX-12's premise no longer holds.** It says a non-empty WAL tail at boot
forces a full `mac_lsm_recount` "because the v2 manifest cannot say whether the
tail is folded", and recommends adding a folded-through field. That field
exists: `MAGIC_MANIFEST2` ("UMN2") carries a trailing `total_live` qword, and
`bitcoin_utxo_lsm.asm:198-205` states its contract — the persisted value is the
RUNS-ONLY count with WAL and memtable excluded, precisely so reload can add the
current tail's net (pushes − dels) on top without double-counting. The full
recount is the fallback for an OLD-format (`MAGIC_MANIFEST`) manifest only.
Verified 2026-09-05; no change needed.

**WAL-20** was a re-verification request, and it verifies. `wallet_store.c`
marks the v2 format legacy/read-only; every write path goes through
`store_write_sealed` → `wcrypt_seal`, and v2 files are decrypted on load and
immediately rewritten as v3. It remains subject to WAL-4 (that rewrite is not
fsynced), which is tracked under its own ID.

**BLD-9's headline** — ops scripts driving a *system* `bitcoind`, with a
`killall bitcoind` fallback — was fixed under DMN-11 earlier in this
remediation; they point at `asm/daemon/bitcoind` now. Its remaining items are
done here: `utxo_progress.sh` gains `set -u` and `pipefail` (not `set -e`: the
watch loop is meant to survive a transient read failure), with its `sudo dd
if=/proc/<pid>/mem` root-read of live process memory stated at the top rather
than discovered at the sudo prompt; `signer_core_diff.sh`'s `rm -rf $TMP` is
quoted.
