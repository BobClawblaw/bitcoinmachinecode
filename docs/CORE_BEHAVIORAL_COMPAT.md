# Core behavioral compatibility — the complete list

**Date:** 2026-09-06. **Reference:** Bitcoin Core v30/v31 default behavior.
**Method:** every row below was checked against `asm/` source or the gate
on 2026-09-06 (and re-checked while scoping the same day — five rows changed), not copied from `FEATURE_GAPS.md` — where the two disagree,
this file says so and `FEATURE_GAPS.md` is corrected in the same commit.

**Status vocabulary**

| | meaning |
|---|---|
| **DONE** | matches Core's observable behavior; proven against a real Core where the row says so |
| **PARTIAL** | one direction or one mode present; the missing half is named |
| **GAP** | Core does it, this node does not, and nothing has decided it away |
| **DECIDED** | deliberately different, with the reasoning written down where the row points |
| **PROOF** | the code is there; what is missing is the run that proves it |

The **work list** at the end orders every GAP, PARTIAL and PROOF row.

---

## 1. Consensus and validation

| Behavior | Core | This node | Status |
|---|---|---|---|
| Script interpreter, all sigversions | `EvalScript` | asm interpreter, differential-fuzzed against Core in the gate (`validation/`), 17-finding line review closed 2026-09-05 | **DONE** |
| Stack size / ops / element limits | 1000 / 201 / 520 | same (IR-1 closed: 17 sites) | **DONE** |
| DER / hashtype boundaries | `ecdsa_signature_parse_der_lax` pops hashtype first | same (IR-2: 11 sites) | **DONE** |
| Taproot key-path, script-path, tapscript, sigops budget, annex | BIP341/342 | same; annex refused, sigop budget per witness size | **DONE** |
| Segwit v0, nested segwit, witness commitment | BIP141/143/144 | same | **DONE** |
| BIP30, BIP34, BIP65, BIP66, BIP68/112/113, nBits schedule | height/MTP activations | same; nBits replayed against every mainnet + testnet4 header | **DONE** |
| `MAX_MONEY`, coinbase maturity, sigops per block (80,000) | | same (VAL-2, SCR-6) | **DONE** |
| `assumevalid` | skip scripts at/below a pinned block; `=0` verifies all | both modes, per-chain defaults | **DONE** |
| **Full-verification replay of mainnet** (`assumevalid=0`) | Core has been run this way by many parties | **never completed here**. Two false-accepts found on 2026-09-05 sat *below* the assumevalid height — the region a default sync never executes. Run reached **744,367 of 965,599 blocks (77%)** on 2026-09-06 and is PARKED at that archive to give the box to the fresh-sync benchmark; it resumes with the same command | **PROOF** |
| `assumeutxo` snapshot load | `loadtxoutset` | absent | **DECIDED** (`FEATURE_GAPS.md` "genuinely still open": large lift, no need) |
| UTXO set identity | | MuHash byte-identical to Core at two heights on two datadirs; re-runnable (`validation/muhash_vs_core.sh`) | **DONE** |
| Reorg handling, undo, crash consistency | | same; tested | **DONE** |
| `invalidateblock` / `reconsiderblock` | mark, disconnect, stay below the mark until a heavier chain avoids it | same: persisted mark (`invalid.dat`), disconnect through the reorg module's own unapply path, header fetch and reorg analyzer refuse marked chains (CC-10, `32f3e5b`) | **DONE** |
| Chain selection | main / testnet4 / signet / regtest; testnet3 deprecated | same; testnet3 refused outright | **DONE** |

## 2. Mempool policy

| Behavior | Core | This node | Status |
|---|---|---|---|
| Standardness (`IsStandardTx`, script flags, dust, `bytespersigop`) | | same; STANDARD flags forwarded to tapscript (IR-9) | **DONE** |
| Ancestor / descendant limits, package limits | 25 / 101 KvB | same | **DONE** |
| RBF | full-RBF default (`mempoolfullrbf`) | config-driven, same default | **DONE** |
| TRUC (v3) incl. sibling eviction, ephemeral dust | | same; proven against real Core on regtest | **DONE** |
| Package acceptance (1p1c, `submitpackage`) | | same, effective feerate | **DONE** |
| `TrimToSize`, `mempoolminfee`, expiry, persistence (`mempool.dat`) | | same | **DONE** |
| Fee estimation | `CBlockPolicyEstimator` | same estimator, persisted | **DONE** |
| `prioritisetransaction` affecting selection/eviction | delta changes ordering | delta is **display-only** (MEM-18) | **DECIDED** (`FEATURE_GAPS.md` §MEM-18) |
| Orphan pool with limits and expiry | | same (`tx_relay.c`) | **DONE** |
| Reject cache (`recentRejects` by wtxid) | | same (`serve_rejects.c`) | **DONE** |

## 3. P2P wire protocol — messages

| Message / BIP | Core | This node | Status |
|---|---|---|---|
| `version`/`verack`, protocol 70016, services bits | NETWORK, WITNESS, NETWORK_LIMITED, P2P_V2, COMPACT_FILTERS | same; `NODE_BLOOM` never advertised (Core default off too) | **DONE** |
| BIP324 v2 encrypted transport | default on, inbound + outbound | same; v1 detected in band | **DONE** |
| BIP339 `wtxidrelay`, BIP133 `feefilter`, BIP130 `sendheaders` | | same, both directions | **DONE** |
| BIP155 `addrv2` / `sendaddrv2`, all five networks | | same; Core accepts our onion/i2p/cjdns entries | **DONE** |
| `getaddr` / `addr` serving, self-advertisement (24 h, two-peer agreement) | | same | **DONE** |
| `inv`/`getdata`/`notfound`, witness-typed fetch | | same | **DONE** |
| `getheaders`/`headers` (2000, locator) | | same | **DONE** |
| `getblocks` (legacy) | still answered | answered | **DONE** |
| `mempool` (BIP35) gated by permission | | same (`NP_MEMPOOL`) | **DONE** |
| **BIP152 compact blocks — serve side** | answers `MSG_CMPCT_BLOCK`, `getblocktxn`, negotiates `sendcmpct` | same | **DONE** |
| BIP152 compact blocks — receive side | high- and low-bandwidth modes; reconstruct from mempool, `getblocktxn` for the rest, `blockreconstructionextratxn` | **low-bandwidth mode**: `sendcmpct` sent after verack on outbound legs, `MSG_CMPCT_BLOCK` requested on a leg that negotiated, reconstruction from the shared mempool, `getblocktxn`/`blocktxn` for the rest, full-block fallback on any failure (`cmpct_recv.c`, CC-2, `49c1c6f`). High-bandwidth push and the extra-txn pool are follow-ups | **DONE** (low-bandwidth) |
| BIP157/158 `getcfilters`/`getcfheaders`/`getcfcheckpt` | when `-peerblockfilters` | same (`serve_cfilters.c`), service bit gated the same way | **DONE** |
| BIP37 bloom (`filterload` etc.) | default off, `NODE_BLOOM` off | not implemented, bit never set | **DECIDED** (matches Core's default) |
| BIP61 `reject` | removed in 0.20 | absent | **DONE** (parity by absence) |
| BIP330 Erlay `sendtxrcncl` + reconciliation | negotiation + reconciliation (off by default) | negotiation only, wire-off | **DECIDED** (`FEATURE_GAPS.md` 2026-08-30 "deliberate stopping point") |
| BIP331 package relay `sendpackages`/`pkgtxns`/`ancpkginfo` | **not shipped in Core** as of v30/v31: Core relays 1p1c packages *opportunistically* through orphan resolution, with no new messages | same: opportunistic 1p1c via `txr_orphan_resolve` sharing `submitpackage`'s validation; `sendpackages` recognised and ignored, as Core does | **DONE** (parity by absence; CC-9 decided 2026-09-06) |
| `-blockversion` scope | honoured **only on chains that mine on demand**: `node/miner.cpp:148` guards it with `chainparams.MineBlocksOnDemand()`, which is `consensus.fPowNoRetargeting` (`kernel/chainparams.h:107`) | same predicate, from `g_chainp->pow_no_retargeting` (`rpc_chain.c`, `rpc_chain_gbt_version_effective`); `test_rpc_chain` pins ignored-off-chain, honoured-on-regtest, and unset-means-node-decides. Applied on every chain until 2026-09-06 | **DONE** |
| Misbehavior scoring + ban list | `Misbehaving()`, discouragement, `banlist.json` persisted | scored for inv/getdata bounds, header rules, tx violations via `txr_report_violation`; shared ban list (`ctl_ban_add`) **persisted to `banlist.json`** since 2026-09-06 — Core's filename, Core's four keys (`address`, `version`, `ban_created`, `banned_until` from `net_types.cpp`), written on every add/remove/clear with tmp+fsync+rename, loaded at boot with expired entries swept as Core sweeps them (`test_banlist_persist`, 17 checks) | **DONE** |

## 4. P2P behavior — connections and relay

| Behavior | Core | This node | Status |
|---|---|---|---|
| Outbound full-relay legs | 8 | configurable, default 8 (`MUX_WANT_OUT`) | **DONE** |
| Block-relay-only outbound | 2 extra legs that never relay tx/addr; eclipse resistance | same: `bmc.blockrelayonly` legs (default 2) dialled with fRelay=0, excluded from tx announce/poll and addr ingest (`anchors.c`, CC-4, `fc358ec`) | **DONE** |
| `anchors.dat` | reconnect to last block-relay-only peers on restart | same, Core's file format byte for byte, deleted on read (CC-4) | **DONE** |
| Feeler connections | 1 short-lived every ~2 min, tests a book entry | same (`net_policy.c`) | **DONE** |
| Extra outbound when tip is stale | +1 full-relay peer if no block in >30 min | same (`stale_tip.c`, CC-6, `c6598b5`) | **DONE** |
| Netgroup diversity in outbound selection | one per /16 (asmap) | same, asmap supported | **DONE** |
| Tor / I2P / CJDNS outbound, `-onlynet`, stream isolation | | same; proven against Core over real tor, i2p, cjdroute | **DONE** |
| Inbound onion service (`-listenonion`) | ADD_ONION at boot | same: `tor_onion_listener(port)` runs at boot (`main.c:8271`, `8296`); the 08-28 note in `FEATURE_GAPS.md` was stale | **DONE** |
| Inbound I2P (`i2pacceptincoming`) | SAM `STREAM ACCEPT` | same: `i2p_inbound_start()` at boot, accept thread hands fds to the serve path | **DONE** |
| Inbound slot limit, `-maxconnections`, per-connection permissions (`-whitelist`/`-whitebind`) | | same | **DONE** |
| Inbound eviction when full (`AttemptToEvictConnection`) | protect by netgroup, ping, last block, last tx; evict the worst | same (`inbound_evict.c`, CC-3, `60486ce`); min-ping round inert until inbound peers are pinged. A full table no longer serves unrecorded peers | **DONE** |
| `-peertimeout` (handshake bound) | default 60 s | same (`peer_timeout.c`, CC-7, `c6598b5`; DMN-14 closed) | **DONE** |
| Inactivity disconnect | 20 min | same (NET-3) | **DONE** |
| `-maxuploadtarget`, `-blocksonly` | | same | **DONE** |
| Address manager: source-netgroup cap, tried/new, eviction never touching tried | `CAddrMan` buckets | v3 book: per-source cap, tried flag, terrible-then-oldest eviction (NET-10, 2026-09-05, migrated live) | **DONE** (design differs; behavior matches on the properties that matter) |
| Addrman test-before-evict | probe incumbent before replacing | absent | **DECIDED** (`NET-10_ADDRMAN_SCOPE.md` §5: no place for a connect inside a file-backed insert) |
| DNS seeds, `-seednode`, `-addnode`, `-connect` | + compiled-in fixed seeds | DNS seeds (13, all chains), the three options; **no fixed-seed list** | **DONE** (fixed seeds: DECIDED, config table) |
| Transaction announcement to **outbound** legs | inv with per-peer queue, feefilter honored, wtxid | same (`tx_relay.c`, `main.c:5647`) | **DONE** |
| Transaction announcement to inbound peers | every peer that negotiated relay gets invs (Poisson-timed) | same: a shared announce ring drained by each serve child before its read, Poisson 5 s, feefilter-honouring, never back to the sender (`txann.c`, CC-1, `612159c`) | **DONE** |
| Re-announcement of transactions received from inbound peers | relayed onward to all other peers | same: the worker drains the ring into the outbound announcer (CC-1) | **DONE** |
| Own-transaction announcement (`sendrawtransaction`) | announced like any other tx, not pushed | same (2026-09-03) | **DONE** |
| Private broadcast (`-privatebroadcast`) | v30 | same | **DONE** |
| Block announcement to peers (BIP130 headers, inv fallback) | to every peer | inbound: `node_announce_tip`; outbound: inv (`main.c:5647`) | **DONE** |
| Transaction `getdata` service to inbound peers, witness-typed | | same | **DONE** |

## 5. Headers sync and anti-DoS

| Behavior | Core | This node | Status |
|---|---|---|---|
| Headers-first sync, PoW checked per header, contextual rules | | same; boot header fetch PoW-gates before append (VAL-5) | **DONE** |
| Minimum chain work at fork evaluation | never reorg to a chain below `nMinimumChainWork` | same (`minchainwork.c`, `reorg.c:708`, floor per chain) | **DONE** |
| `-par` script-verification threads | total threads doing script checks, caller included: 0 = cores, -n = leave n free, 1 = single-threaded (`chainstatemanager_args.cpp`) | same arithmetic, floor of one thread (`tx_verify.c`, `par_script_threads`), read by both verify pools; the download chunk-worker count is `bmc.catchupworkers`. **Was wired to the download count and ignored by the verifier until 2026-09-06** (`74dc317`) | **DONE** |
| Low-work headers sync / presync | do not store a headers chain until it crosses the floor (24.0 presync) | bounded HOLD: full pages below the floor are held (linkage+PoW only), released when the chain crosses it, abandoned only at a memory bound of 1,000 pages / 162 MB mapped per fetch (`hdr_lowwork.c`, CC-5, `799fba3`, bound fixed `4c3e8fc`: the first cut abandoned after FOUR pages, which abandoned every honest sync below ~880k — seen on the CC-8 replay); Core's bit-commitment presync not replicated | **DONE** (stage 1) |
| Checkpoints | still present for the early chain | present | **DONE** |
| Stale-tip detection | warn + extra outbound | same (CC-6) | **DONE** |
| Time offset | v28+ no longer adjusts; warns on large peer skew | no adjustment | **DONE** (parity by absence; warning: verify) |
| Per-message size caps, framer limits, inv/getdata bounds | | same; 4 MB cap before drain | **DONE** |

## 6. Indexes and RPC

| Behavior | Core | This node | Status |
|---|---|---|---|
| `txindex`, `blockfilterindex`, `txospenderindex`, address index | | same (address index is an extension) | **DONE** |
| `coinstatsindex` at **any height** | one record per block | **tip only** (CSI-2); historical `gettxoutsetinfo muhash <h>` needs the oracle | **DECIDED** (`BENCH_DEFECT_LEDGER_2026-09-04.md`) |
| RPC surface (~157 methods), cookie auth, `rpcauth`, `rpcwhitelist`, loopback default | | same, verified per method in `PARITY_PLAN.md` | **DONE** |
| Long-running RPC concurrency | parallel workers | one execution lock (RPC-12) | **DECIDED** |
| REST interface | `-rest`: fourteen `/rest/` routes on the RPC port, unauthenticated, `.json`/`.hex`/`.bin` | the same (`rest=1`, 2026-09-08): every route from the node's RPC handlers, Core's status codes and error texts; `mempool_sequence=true` is refused (no sequence counter) | **DONE** |
| ZMQ `hashblock`/`hashtx`/`rawblock`/`rawtx` | | same; `zmqpubsequence` refused (MEM-22) | **DONE** / sequence **DECIDED** |
| `settings.json` persistence of RPC-set values | | absent | **DECIDED** (config table) |

## 7. Wallet

| Behavior | Core | This node | Status |
|---|---|---|---|
| Descriptor wallets, encryption (v3), PSBT create/sign/finalize/analyze/join, `bumpfee` | | same; `bumpfee` proven against real Core | **DONE** |
| Miniscript, MuSig2 key-path, `musig()` descriptors | | same | **DONE** |
| Taproot **script-path** PSBT signing and finalization (`PSBT_IN_TAP_SCRIPT_SIG` 0x14, `PSBT_IN_TAP_LEAF_SCRIPT` 0x15, control blocks) | signed and finalized | **finalization DONE** 2026-09-06: `finalizepsbt` builds `[sig, leaf script, control block]` from 0x14/0x15, matching the leaf by its tagged hash and picking the cheapest control block when a wallet signed several leaves. Verified byte-for-byte against a spend Core signed and finalized on regtest (`tests/psbt_tapscript_vec.h`, descriptor `tr(NUMS,{pk(A),pk(B)})` so only the script path can spend; `testmempoolaccept` allows Core's tx). **SIGNING DONE 2026-09-08**: `descriptorprocesspsbt` and `walletprocesspsbt` (the same `srw` engine, wallet keys) sign `pk()` leaves, `multi_a` leaves (partials as 0x14 keyed by `xonly||leafhash`, completed by a second signer) and miniscript leaves; `test_rpc_psbt_taproot` now runs every spend it produces (key path with a tree, a pk() leaf, a multi_a 2-of-2 built from two partial 0x14s) through the **consensus** taproot verifier, calibrated on Core's own finalized fixture and on a flipped-byte negative. The register had this row stale: the partial-signature export existed since 2026-09-06 and was pinned by the test's section 4, but nothing had proven the signatures valid | **DONE** |
| BIP389 multipath descriptors | `<a;b>` expands to one descriptor per path | same (`descr_multipath_n`, `rpc_desc_multipath_expand`; `importdescriptors` imports one per expansion, `getdescriptorinfo` lists them). The register's first draft called this absent; a re-read of `descriptor.c` on 2026-09-06 found it | **DONE** |
| Coin selection (BnB / knapsack / SRD, waste metric) | | same: BnB first, then knapsack and SRD over the same effective values, the lower waste taken; largest-first remains the last resort (`wallet_coinsel.c`, CC-10) | **DONE** |
| Keypool | pre-generated | derives on demand | **DECIDED** |
| Reorg awareness in the wallet | rescans/updates on disconnect | none (WAL-13) | **DECIDED** |
| Secrets hygiene (mlock, DONTDUMP) | | same (WAL-3) | **DONE** |

## 8. Mining

| Behavior | Core | This node | Status |
|---|---|---|---|
| `getblocktemplate` (frame, retarget, longpoll), `submitblock` end to end | | same; frame diffed against Core at the same tip | **DONE** |
| BIP23 proposal mode | | same (`rpc_node_submit_proposal`, hooked `main.c:6431`) | **DONE** |
| Stratum / pool interface | not in Core either | absent | **DONE** (parity by absence) |

## 9. Configuration surface

Every Core v31.99 option is classified in `FEATURE_GAPS.md` ("config surface",
2026-09-01): implemented, accepted-no-effect with the reason, or refused. The
behavioral ones that are *accepted with no effect* and are not already rows
above: `peerbloomfilters` (BIP37), `txreconciliation` (Erlay), `natpmp`,
`rest`, `fixedseeds`, `loadblock`, `blocksdir`/`blocksxor`, `debug`
categories, `mocktime`, `maxsigcachesize` (no sig cache: verified once by
the parallel verifier), `settings`. Each is a DECIDED row by reference.

Config **file resolution** now matches Core: one file, `$BITCOIN_CONF`, else
`<datadir>/bitcoin.conf`, else the repo fallback — daemon and CLI agree
(`d0bc1c2`, 2026-09-05).

## 10. Operations

| Behavior | Core | This node | Status |
|---|---|---|---|
| Clean shutdown on SIGTERM during any phase; crash-consistent UTXO | | same | **DONE** |
| Pruning by MiB budget | | same | **DONE** |
| Log rotation, systemd hardening | operator's | same; unit local by decision | **DONE** |
| `-checkblocks`/`-checklevel` | | same | **DONE** |

---

## Work list — every GAP, PARTIAL and PROOF row, in recommended order

Ordering is by consequence to the network and to this node's safety, then
by size. Each carries the test that would prove it.

| # | Item | Why it is first | Size | Scope |
|---|---|---|---|---|
| 8 | **Full-verification replay** (`assumevalid=0`, §1) | **RUNNING** since 2026-09-06 01:12Z from the Core oracle; `stopatheight=965598`. Restarted 04:55Z on `305c1b4` (interleave) from its 250,913-block archive; that binary's header phase was abandoned by CC-5's four-page bound and the node fell back to its serial leg; restarted 05:26Z on the bound fix (`ab7087e`; 284 held pages released) and 05:28Z with `bmc.bootcatchup=0` — from 05:32Z the worker downloads and connects together (`applied=371745 lag=1`) | wall-clock | CC-8 |
| 10 | taproot script-path PSBT signing and finalization (all key types) | **done 2026-09-08**: signing proven under the consensus verifier (`test_rpc_psbt_taproot`), finalization byte-identical to Core (`test_rpc_psbtfinal`) | — | CC-10 |

Every row is scoped in `docs/audits/CORE_COMPAT_SCOPES_2026-09-06.md`.

Items 1–3 are the ones a Core node on the other end of a connection would
notice. Items 4–6 are what protects *this* node. Item 8 is the proof. The
rest is completeness. Inbound onion/I2P and BIP23 were on the first draft of
this list and are not gaps (see the scopes document's corrections).

**Explicitly not on the list, by decision:** Erlay reconciliation, addrman
test-before-evict, `assumeutxo`, UPnP/NAT-PMP, BIP37 bloom, keypool,
tip-only coinstats index (CSI-2), display-only `prioritisetransaction`
(MEM-18), single RPC execution lock (RPC-12), wallet reorg awareness
(WAL-13), opcode dispatch table (IR-16), systemd unit in version control.
Each has its reasoning where the row points; reopen one by arguing with the
reasoning, not by re-filing it.

---

## Initial block download (added 2026-09-07)

Checked against `asm/daemon/main.c` and `asm/daemon/ibd_pipeline.c` on 2026-09-07; the runs are in `worklog/2026-09-07.md`.

| Behavior | Core | This node | Status |
|---|---|---|---|
| Headers-first, then blocks | yes | yes; a fresh datadir seeds genesis on every chain; `headers.dat` ahead of the archive is kept across a restart (PR #75) | **DONE** |
| Blocks in flight per peer | 16 (`MAX_BLOCKS_IN_TRANSIT_PER_PEER`) | one 40-block chunk per worker in ONE `getdata`, placed by hash as they arrive (PR #66) | **DONE** (different shape, same effect) |
| Download window | 1,024 blocks above the last connected block (`BLOCK_DOWNLOAD_WINDOW`) | 4,096 above the first unfilled height: Core's slack ratio at 640 in flight; abandoned chunks go to a retry ring (PRs #77, #78) | **DECIDED** (`docs/releases/2026-09-07-monotonic-download.md`) |
| Block file layout | `blk*.dat` in arrival order; the index finds blocks; pruning deletes whole files | height order: workers stage verified chunks, one committer appends the archive in height order from the first hole; the archive never has a hole (PR: in-order committer) | **DIVERGED, deliberately** (`docs/releases/2026-09-08-in-order-committer.md`) |
| Undo data retention | every block's undo in `rev*.dat`, deleted only by pruning | the same since 2026-09-08 (`rev%05u.dat` + `undo.idx`); was a 200-block window of per-height files | **DONE** (`docs/releases/2026-09-08-undo-keep-all.md`) |
| Esplora REST | none (Core has REST for blocks/tx, not Esplora's contract) | `bmc.esploraport`: Esplora's routes answered in process from the RPC handlers, for mempool.space's `BACKEND: esplora`; address routes pending the history index | **EXTENSION** (`docs/releases/2026-09-08-esplora-facade.md`) |
| Stalling peer | re-request from another peer after 2 s (`BLOCK_STALLING_TIMEOUT_DEFAULT`), disconnect the staller | an idle worker fetches the blocking chunk after 2 s; the owner keeps going (its appends are idempotent) | **DONE** |
| Per-block download timeout | 10 min base (`BLOCK_DOWNLOAD_TIMEOUT_BASE`) | a stall clock: nothing for 120 s drops the peer (PR #68) | **DECIDED** (stricter; relative rules decide who is slow) |
| Peer selection for download | none beyond outbound selection | timed 2,000-header sample ranks the pool; boundary rotation under half the pool median; a failed fetch halves a peer's standing and backs off (PRs #61, #74, #81) | **DECIDED** |
| Write order | blocks written on arrival, connected in order | same; the status line reports what is in flight and the age of the oldest gap (PR #82) | **DONE** |
| Progress reporting | `debug.log` progress= and ETA in the GUI | `eta DD:HH:MM:SS` on the status line at the last ten minutes' block rate (PR #74) | **DONE** |
| Rate limits | `-maxuploadtarget` (MiB per day; historical blocks refused once spent) only | the same key with the same semantics, plus three node-wide rates of this node's own: `bmc.dialratelimit` (connection attempts/s), `bmc.downloadratelimit` (KB/s pulled), `bmc.uploadratelimit` (KB/s sent, paced at `p2p_write` for both transports); all default off (PRs of 2026-09-08) | **DECIDED** |
| Logging | everything to `<chaindir>/debug.log`; `-printtoconsole` adds stdout; `-debuglogfile=0` off; `-shrinkdebugfile` trims a >10 MB file at start | same since 2026-09-08 (PR of that day): fd 2 becomes the file after the chdir into the chain directory, every forked child inherits it; with printtoconsole a forked pump tees to the console; the early lines (config echo, chain selection, lock failures) reach the launcher as Core's do. Before that stderr was the log | **DONE** |

