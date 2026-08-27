# Live-node RPCs in the serve daemon — design

> **Status 2026-08-27 (design doc, now implemented).** The bridge described
> here shipped and grew well past the seven methods below: the `serve` daemon
> now answers Core's full RPC surface (155/155), including the live mempool
> (with feerate eviction and a dynamic `mempoolminfee`), wallet-encryption
> RPCs (`encryptwallet`/`walletpassphrase`/`walletlock`), and the index
> queries (`txindex`/`coinstatsindex`/`blockfilterindex`). The embedded RPC
> server binds `rpcport` from `bitcoin.conf` (production `8331`; default per
> chain is 8332 mainnet / 18443 regtest). This file remains the design record
> of how the fork-boundary state bridge was built.

Goal: answer the RPCs that need **live** node state — `getconnectioncount`,
`getpeerinfo`, `getnetworkinfo`, `getmempoolinfo`, `getrawmempool`,
`sendrawtransaction`, `getchaintips` — which the standalone `bitcoin_rpcd`
(a separate read-only process over the datadir) structurally cannot.

## The constraint that shapes everything: the fork model

`serve` mode is a multi-process fork tree, and the process that can host the
RPC server (the `serve_mux` parent, `daemon/main.c`) holds almost none of the
live state:

- **Outbound peers** live in a forked child, `serve_download_worker`
  (`main.c:2066`). The parent runs `serve_mux(... nwant=0 ...)` (`main.c:3237`)
  so its own `mux_out_*` arrays stay empty; the worker resets `mux_n_out=0`
  after fork (`main.c:2235`) and builds its own set.
- **Inbound peers** are one forked child each, running the asm serve loop
  (`main.c:2721`). The parent keeps only a count (`g_inbound_n`, `main.c:663`)
  and PIDs for upload metering — no per-peer table anywhere.
- **The mempool** (`mp_ext_area`) is `MAP_SHARED|MAP_ANONYMOUS` since
  2026-08-25 (previously `MAP_PRIVATE` → copy-on-write per fork, each inbound
  child accepting into its own invisible copy). One pool now, init'd ONCE
  pre-fork (`mp_ext_inited` tells `bitcoin_serve.asm` to adopt, not re-init),
  mutations under a `PTHREAD_PROCESS_SHARED` lock (`mp_lock`/`mp_unlock` in
  `mempool_cfg.c`), and the tx-accept policy state (fees) shared alongside it
  (`mp_ext_polstate`).

So the work is not "start a thread" — it is "**bridge the fork boundary**"
(shared memory published by the children, read by the parent's RPC thread),
then start the thread. The RPC plumbing (new module + dispatch + build) is the
easy part; the state bridge is the design.

## Sliced plan (lowest-risk first)

Each slice is independently testable and shippable. The live daemon
(`bmc-bitcoind`) is production, so every slice is built + tested on a scratch
serve instance and only deployed behind the normal gate.

### Slice 1 — foundation: shared status + connection counts  ← this change
- Allocate a `MAP_SHARED|MAP_ANONYMOUS` `node_status_t` **before** the worker
  fork (`main.c:3230`). Small, fixed-size, POD.
- The download worker writes `n_out` / `live_peers` / `tip_height` into it
  (it already computes `live_peers` at `main.c:2344`). The parent writes
  `n_inbound` (from `g_inbound_n`, in the accept/reap paths).
- New module `rpc_node.c` (mirrors `rpc_chain.c`): `NODE_METHODS[]`,
  `rpc_node_known_method`, `rpc_node_dispatch`. Reads the status via a setter
  `rpc_node_set_status(const node_status_t*)`, the same idiom as
  `rpc_commands_set_utxo_store`.
- Implement `getconnectioncount` (= n_out + n_inbound) and `getnetworkinfo`
  (mostly static from `version_gen.h`: version, subversion
  `/BitcoinMachineCode:0.0.1/`, protocolversion 70016, localservices,
  localrelay, networkactive; `connections`/`connections_in`/`connections_out`
  from the status). No per-peer data yet.
- Embed `rpc_server_start` on its background thread in the serve parent (before
  `serve_mux`, `main.c:3237`); `rpc_server_stop` in the shutdown path.
- Build: link `rpc_server.o rpc_commands.o rpc_chain.o rpc_json.o rpc_net.o
  rpc_node.o` + the missing wallet prims into `daemon/bitcoind`; guard against
  TUs already in `DAEMONOBJS`.

### Slice 2 — `getpeerinfo`
Design a per-peer record (addr, services, version, subver, inbound,
bytessent/recv, conntime, last_send/recv) in a `MAP_SHARED` peer table sized
`MUX_MAX_OUT + inbound cap`. Outbound slots written by the worker; inbound
slots claimed by each inbound child after `node_accept_handshake`
(`main.c:2724`) — the child already materializes version/services text in
`format_peer_version_info` (`main.c:839`), today only logged.

### Slice 3 — `getmempoolinfo` / `getrawmempool` — IMPLEMENTED (2026-08-25)
`mp_ext_area`/`mp_ext_blob`/policy state flipped to `MAP_SHARED`; pool init'd
once pre-fork (`mp_ext_inited`, adopted -- never re-init -- by
`bitcoin_serve.asm`'s lazy init); every C mutation site (tx-accept policy add,
expiry, reorg reconcile) under the new cross-process `mp_lock`. The RPC layer
gets the pool via `rpc_node_set_mempool` (pointer injection, no link fanout)
and walks slots with the same documented-layout C walk `daemon/reorg.c` uses.
`getrawmempool` returns real txids (display order; verbose: vsize/weight/time/
fees.base). `getmempoolinfo` reports real size / bytes (BIP141 vsize sum) /
usage / total_fee / configured maxmempool. Hermetic proof:
`tests/test_mempool_shared` (child writes under the lock, parent sees; init-
once survives fork) + injected-pool KATs in `tests/test_rpc_node`. KNOWN
NARROW RACE (documented in `mempool_cfg.c`): `bitcoin_serve.asm`'s lock-free
`mpool_get` when serving getdata can see a mid-delete/mid-rebuild slot; worst
case is relaying a dropped tx, which peers re-validate. NOT yet deployed to
the live daemon — batched with the post-rebuild deploy; live verification
(inbound child accepts a tx → parent getrawmempool shows it) happens then.

### Slice 4 — `sendrawtransaction` — IMPLEMENTED (2026-08-25)
The parent→worker submission channel. `node_status_t` (rpc_node.h) carries a
staging buffer + `tx_submit_seq`/`tx_submit_ack`/`tx_submit_result`/reason. The
RPC parent (`cmd_sendrawtransaction`, rpc_node.c) parses the hex, computes the
txid, stages the raw tx under a mutex, bumps `tx_submit_seq`, and blocks on the
ack. The download worker polls the seq at the top of its loop (`main.c`), lazily
inits the mempool + UTXO snapshot on first submit, calls
`txsub_accept_and_relay` (`daemon/tx_submit.c`) — `tx_accept_validate_reason`
(the reason-capturing variant of `tx_accept_validate`, `tx_accept.c`) then an
unsolicited `tx` push to every live peer leg via `p2p_write` — and writes the
verdict + reason back, acking the seq. Core error codes (-22/-25/-26/-27) are
mapped from the reject reason. The accept+relay path is unit-tested over a
socketpair (`tests/test_tx_submit.c`, 17 checks); the live peer-relay proof is
deferred until the UTXO rebuild completes (a real tx cannot validate against a
partial UTXO set). Chosen the worker-side design (not in-parent accept) because
the worker owns both the peer legs and the live UTXO-writer state, so no
cross-process mempool coherence is needed — the mempool lives in the worker.
Known limitation: the worker's UTXO snapshot is taken once on the first
submission (a future refinement can re-snapshot per submit for freshness).

### Slice 5 — `getchaintips`
Reuse `daemon/reorg.c` fork-choice data for reorg candidates (not persisted
today; may need a small shared record of known-but-not-active tips).

## Verification note
The scratch Core oracle is bleeding-edge (31.99.0, protocol 70017). Live-node
RPC output cannot be byte-matched against a moving master, so these are
verified against the **documented Core v31 shapes** (as the rest of the RPC
layer is) with the stable fields checked against the oracle — an honest bound,
not a claimed byte-identity.

## Slice 6 — the network/ops twelve — IMPLEMENTED (2026-08-25)
`getnettotals`, `getnodeaddresses`, `getaddrmaninfo`, `getaddednodeinfo`,
`listbanned`, `clearbanned`, `addnode`, `disconnectnode`, `setban`,
`setnetworkactive`, `ping` (eleven methods; `getpeerinfo` already existed and
completes Core's twelve-method Network category).

Shapes were taken from the running oracle, not from memory: `getaddrmaninfo`'s
key set and order (`ipv4`, `ipv6`, `onion`, `i2p`, `cjdns`, `all_networks`,
each `{new,tried,total}`), `getnettotals`'s `uploadtarget` sub-object, and
`getaddednodeinfo`'s `-24 "Error: Node has not been added."`.

**Backed by real state.**
- `getnettotals` sums the `bytes_sent`/`bytes_recv` counters the peer table
  already carries (kernel `TCP_INFO`, per socket).
- `getnodeaddresses` and `getaddrmaninfo` read the persistent address book
  (`bitcoin_addrmgr.asm`, 18-byte records) through an injected handle. The
  RPC thread opens its own handle because the download worker's lives in the
  forked child; `amr_*` re-reads `peers.dat` per call, so both see one file.
- `getaddednodeinfo` reports the operator's `addnode=` entries from
  `bitcoin.conf` and marks each connected by matching a live peer slot —
  anchored so `1.2.3.4` does not match a peer at `1.2.3.45`.

**Documented divergences** — each is a real difference, not an approximation
presented as a total:
- `getnettotals` counts the **live** peer table. Core counts the process
  lifetime including closed connections; this node keeps no such accumulator.
- `getnettotals.uploadtarget` reports an unset target (`target: 0`,
  `serve_historical_blocks: true`). There is no upload cap to report.
- `getaddrmaninfo` has no new/tried split — the address book is one flat
  table fed by contact, so every record counts as `tried` and `new` is 0.
  The book is IPv4-only, so the other five networks are genuinely zero and a
  `getnodeaddresses` filter for them returns empty rather than relabelled
  IPv4 rows.
- `listbanned` returns `[]` and `clearbanned` returns null — the same answers
  Core gives with nothing banned. The divergence is that nothing can ever
  populate the list, because there is no ban list to populate.
- **The five mutators refuse.** `addnode`, `disconnectnode`, `setban`,
  `setnetworkactive` and `ping` return `-1` with a reason. Peer connections
  are owned by the forked download worker, which dials and redials from the
  address book on its own policy; there is no runtime peer-control path, no
  ban list, and no network-disable switch. Returning success while changing
  nothing would be worse than an honest error — a caller that trusts a
  `setban` that did not ban is strictly worse off than one told it cannot.
  `addnode=` in `bitcoin.conf` plus a restart is the supported route, and the
  error message says so.

`tests/test_rpc_node.c` covers all twelve, including the dead-slot exclusion
in the byte sum, the endianness of every decoded address-book field (IP u32
LE, port u16 BE, services u64 LE), Core's default `count=1`, the
`count=0`-means-all form, the network filter, the prefix-match anchor, and
that each mutator returns `-1` with a non-empty reason rather than a silent
no-op.

## Slice 7 — the Wallet category, part 1 — IMPLEMENTED (2026-08-25)
`rpc_wallet_ops.c` adds 38 methods, chained from `rpc_dispatch()` exactly as
`rpc_node`/`rpc_chain` are. Each is in one of three states, marked in the
source and repeated here so nothing is mistaken for more than it is.

**Backed by real wallet state.**
- `setlabel` / `listlabels` / `getaddressesbylabel` over a new
  `wallet_labels.c` store (`data/labels.dat`). Core's model is keyed by
  ADDRESS — one label per address, many addresses per label — which is the
  inverse of the pre-existing `wallet_book.c` (keyed by label, the CLI's
  nickname book). The inversion cannot be expressed in the book's format, so
  labels got their own store rather than a reinterpretation of another
  module's file. The record puts the address first and takes the rest of the
  line as the label, so Core labels containing spaces survive verbatim; a
  label over 255 bytes or containing a newline is refused, never truncated.
- `listwallets` / `listwalletdir` over the wallet file's presence.
- `lockunspent` / `listlockunspent`. Core's lock set lives in memory and is
  documented as lost when the node stops, so a process-lifetime set is exact
  parity — persisting it would be the divergence. The list is validated
  whole before anything mutates, so a bad entry cannot leave a half-applied
  set.
- `signmessage`, over BIP32-derived keys. Core signs only for a P2PKH
  destination, so this does too, with Core's `-5` / `-3` / `-4` ladder. The
  key search is bounded at 1000 indexes across both branches; beyond that it
  reports "Private key not available", which is honest — this code did not
  find the key — rather than wrong.
- `backupwallet` really copies the file and really fails if it cannot,
  removing a partial destination rather than reporting a success that left
  a truncated backup.
- `listdescriptors` / `gethdkeys`. Both were cross-checked against Core: the
  emitted `#checksum` on each descriptor matches `getdescriptorinfo`
  byte-for-byte, and Core deriving `<our account xpub>/0/0` yields the same
  address as our own key at `m/84'/0'/0'/0/0` — which validates the xpub's
  depth, parent fingerprint and child index, not just its shape.

**Exactly Core's answer for this node's situation** — verified against the
oracle, not merely plausible:
- `walletlock`, `walletpassphrase`, `walletpassphrasechange` return `-15`
  "Error: running with an unencrypted wallet, but `<method>` was called."
  This wallet IS unencrypted, so that is the correct answer, not a stub.
- `abortrescan` returns `false`. No rescan can be in flight here, and `false`
  is the only answer this method could ever give.
- `keypoolrefill` returns null. Keys are derived on demand from a BIP32 seed,
  so "at least N keys are available" already holds for every N.

**Refused, with the specific missing capability named.** `encryptwallet`
(no keystore); `createwallet` / `loadwallet` / `unloadwallet` /
`restorewallet` / `migratewallet` / `setwalletflag` (one wallet, loaded at
startup, no multi-wallet manager); `importdescriptors` /
`createwalletdescriptor` / `addhdkey` / `importprunedfunds` /
`removeprunedfunds` / `exportwatchonlywallet` (a single seed with no import
path); `walletdisplayaddress` (no external signer); and the receive-side
family — `rescanblockchain`, `getreceivedbyaddress`, `getreceivedbylabel`,
`listreceivedbyaddress`, `listreceivedbylabel`, `listaddressgroupings`,
`listsinceblock`, `abandontransaction` — which all need a wallet rescan that
does not exist. The wallet learns of its outputs only from the sends it
journals. Answering `0.00000000` for `getreceivedbyaddress` would be a wrong
answer wearing the costume of a real one: the caller could not tell it apart
from an address that genuinely received nothing.

### Known divergence: the derivation path is not a ranged descriptor
This wallet derives `m/84'/0'/0'/<i>/<0|1>` — account index at depth 4,
receive/change branch LAST. That is the reverse of BIP84's ordering, and no
ranged descriptor can express it, because `*` has to be the final step. So
`listdescriptors` emits the concrete, non-ranged descriptor for each key the
wallet actually uses. Since `getnewaddress` and `getrawchangeaddress` always
derive index 0, that is exactly two keys and the output is complete — it is
not a truncation of a longer list.

## Slice 8 — the Wallet category, part 2: the spend family — (2026-08-25)
The last ten. Two are real; eight refuse, for one specific reason.

**`signrawtransactionwithwallet`** — real, and it delegates. Core's method is
`signrawtransactionwithkey` with the key list taken from the wallet instead
of the caller, so it builds that list and calls the existing implementation
rather than growing a second signer that could drift from the first. The
delegate already handles legacy, P2SH, BIP143 v0 and P2SH-wrapped v0, so the
reuse costs nothing. Note the argument shift: Core's wallet form is
`(hexstring, prevtxs, sighashtype)` with no key array.

The key window is bounded at indexes 0–19 across both branches, because
"the wallet's keys" is not a finite set for an on-demand deriver. An input
funded beyond that window is not silently skipped — it lands in `errors[]`
with `complete: false`, which is Core's own shape for an input it could not
sign.

**`simulaterawtransaction`** — real, and needs no funding machinery: an input
is ours when its outpoint is in the wallet's UTXO list, an output is ours
when its scriptPubKey is one of our derived P2WPKH scripts. `rpc_wallet`'s
`utxo_txid` is in DISPLAY order (that is how `bin_to_hex` renders it for
callers), while the raw tx's outpoint is in wire order, so the comparison
reverses. Getting that wrong would not crash — it would silently never
match and report every spend of our own coins as a zero balance change.

### Why `sendtoaddress` and its seven relatives refuse
This is the one gap worth stating precisely, because the pieces look present
and are not.

`wallet_core.c` does have a send path — `wallet_sendtoaddress` /
`wallet_send_tx` — but it is **legacy P2PKH end to end**: every prevout is
assumed to be the spending key's P2PKH script, the destination is a P2PKH
hash160, change returns to a P2PKH, and signing produces legacy
`SIGHASH_ALL` scriptSigs with no witness. Meanwhile `getnewaddress` and
`getrawchangeaddress` hand out **P2WPKH** addresses, so the wallet's actual
outputs are witness outputs that this path cannot spend.

Wiring `sendtoaddress` onto it would build a transaction carrying an empty
witness and a legacy scriptSig against a v0 witness prevout. The RPC would
return a txid and the network would reject the transaction. A refusal is
strictly better than a plausible txid for something that can never confirm.

So `sendtoaddress`, `sendmany`, `send`, `sendall` and `walletcreatefundedpsbt`
all return `-1` naming the
mismatch, and pointing at what does work: `createrawtransaction` followed by
`signrawtransactionwithwallet`. Closing this properly means segwit wallet
signing plus coin selection, change policy and fee estimation — a subsystem,
not an RPC shim.

### Category status
All 57 of Core's Wallet methods now dispatch. Counting honestly: 21 are
backed by real wallet state, 6 reproduce Core's exact answer for this node's
situation, and 30 refuse with the specific missing capability named. The
methods that would need a wallet rescan and the eight above are the whole of
what remains, and both are subsystem-sized rather than method-sized.

## Slice 9 — the Blockchain category — (2026-08-25)
The last 19. Eight are real, eleven refuse.

**`getdeploymentinfo` reports what the node enforces, not what Core says.**
The buried-deployment heights come from `script_flags_consts.h`, which
`validation/gen_script_flags.py` now generates alongside the existing `.inc`
— the same parse of Core's `kernel/chainparams.cpp`, with a self-check that
refuses to let the two drift. Hand-copying `481824` into `rpc_chain.c` would
have reintroduced exactly the drift that generator exists to prevent. The
five heights match the oracle's `getdeploymentinfo` exactly.

**`getchainstates`** always reports exactly one chainstate, which is this
node's permanent condition — there is no snapshot loader. Core's
`coins_db_cache_bytes` / `coins_tip_cache_bytes` describe a LevelDB and a
coin cache this node does not have (its UTXO set is an LSM), so those fields
are omitted rather than zeroed.

**`getchaintxstats`** reads only the tx-count varint after each 80-byte
header — ~89 bytes per block, not the blocks. The cumulative `txcount` is
the same cheap scan over the whole chain, cached against the tip so the
first call pays once. If any height is unreadable (a pruned or holed
archive) the field is **omitted rather than reported low**: a short count
that looks real is worse than an absent one, because the caller cannot tell
the difference.

**`verifychain`** implements checklevels 0–2 for real: read from disk,
recompute the header hash and check it against the index, check PoW against
the header's own bits, recompute the merkle root from the transactions, and
require undo data to be present. Levels 3 and 4 disconnect and reconnect
through the UTXO writer, which lives in the forked download worker and is
not reachable from the RPC thread — so they are **refused, not silently
downgraded**. `verifychain` returns a bare boolean with no room to say "I did
less than you asked", so a `true` from a downgraded level 4 would be a plain
untruth. Core's default is checklevel 3, so a bare `verifychain` gets that
refusal with the supported range named.

The test exercises this on a fixture whose synthetic headers carry
`0x1d00ffff` with nonce 0 — no valid proof of work — and asserts level 1
returns **false**. A level-1 check that passed there would not be checking
anything.

**`waitforblock` / `waitforblockheight` / `waitfornewblock`** poll the same
`refresh()` every other method uses. *Documented divergence:* Core treats
timeout 0 as "wait indefinitely". This node's RPC server accepts and services
one connection at a time on a single thread (`rpc_server.c`), so an
indefinite wait would wedge every other RPC for as long as no block arrived.
The wait is capped at 30 s; on expiry these return the current tip, which is
exactly what Core returns when its own timeout expires. The result shape is
identical — only the ceiling differs, and the caller can call again.

**`gettxspendingprevout`** lives in `rpc_node.c` with the pool enumeration,
though Core files it under Blockchain. An outpoint nothing spends still
yields an entry with no `spendingtxid`, as Core does — omitting it would
silently shift the caller's indexes. The whole list is validated before the
pool is touched, so a bad entry cannot produce a partially-answered array.

**Refused, each naming the specific gap:** `getblockfilter`, `scanblocks`,
`getdescriptoractivity` (no BIP157/158 filter index — the block and undo data
needed to build one are both on disk, so this is a missing index, not missing
information); `loadtxoutset` (no assumeutxo: no second chainstate to
load a snapshot into — `dumptxoutset` became real later and is proven at
full 165.7M-coin scale); `preciousblock`, `pruneblockchain` (fork choice is
owned by the forked download worker); `getmempoolcluster` (the pool tracks
the ancestor/descendant graph but not Core's cluster structure);
`getblockfrompeer` (peer connections belong to the worker, and no targeted
block request is wired through the control channel that slice 17 added).

*Corrected 2026-08-27: `dumptxoutset` and the `savemempool`/`importmempool`
pair are real and left this list; `getblockfrompeer`'s stated reason — "no
parent-to-worker channel" — was superseded by slice 17, which built one.*

### Category status
All 38 of Core's Blockchain methods now dispatch.

## Slice 10 — the Rawtransactions category — (2026-08-25)
The last nine. Four are real, five refuse.

### `testmempoolaccept` — one implementation, not two
It rides the same parent→worker channel as `sendrawtransaction`, with a new
`tx_submit_test` flag. On the worker side `tx_accept_test_reason` runs the
identical consensus/script validation and the identical mempool policy
checks, stopping at the policy **commit boundary**.

That boundary is real, not a reimplementation: `mpool_policy_add` became a
thin wrapper over a shared `mpol_add_core(..., commit)`, which returns 1 at
the `/* commit */` marker when `commit` is 0 — the same shape as
`utxo_live_dryrun_block()` returning at its Phase 5 boundary. The committing
path is byte-for-byte the code it always was; a second copy of these rules
would answer about a mempool this node does not have.

`sendrawtransaction` now clears `tx_submit_test` explicitly. A stale `1` left
by a dry run would turn a real broadcast into a no-op that still returned a
txid — the test asserts the worker sees the flag cleared.

**Documented divergence — package policy.** Core validates the array as a
package: a child may spend a parent earlier in the same call. This node
evaluates each transaction independently against the mempool as it stands,
because the dry run deliberately inserts nothing, so an earlier entry is
invisible to a later one. When more than one transaction is passed, every
entry carries Core's own `package-error` field saying so, and a child
spending an in-array parent reports `missing-inputs` — the truth about what
was checked. `effective-feerate` and `effective-includes` describe package
feerate and are omitted rather than guessed.

### `finalizepsbt` — verified against the signer, not against itself
Implements BIP174's Finalizer and Extractor for P2PKH, P2WPKH and
P2SH-P2WPKH. An input of any other form is left untouched and `complete`
comes back false, which is exactly what Core does for an input it cannot
finalize.

The test is a round trip with teeth: a PSBT is assembled carrying the real
signature `signrawtransactionwithkey` produced for that input, and the
extractor's output must come back **byte-identical** to the signer's own
network serialization. A finalizer that assembled the witness stack even
slightly differently fails that comparison; a shape check on
`{hex, complete}` would not. Finalizing with `extract=false` and then
finalizing the result again must extract the same bytes, proving the final
fields were written, not merely reported.

### `combinerawtransaction` — merges, or refuses; never silently drops
For each input, if at most one supplied transaction carries signature data,
that one is taken. If two carry **different** non-empty data for the same
input, combining them needs Core's signature combiner (for multisig,
assembling separate signatures into one scriptSig), which this node does not
have — so it errors and points at `combinepsbt`, which merges properly at the
PSBT level. Keeping one side would hand back a transaction missing signatures
the caller supplied. Identical data on both sides is not a conflict and
combines cleanly.

Tested by signing one two-input transaction twice, each time with the prevout
for only one input, and requiring the combination to reproduce the
transaction signed with both at once.

### `utxoupdatepsbt`
Fills `PSBT_IN_WITNESS_UTXO` from the UTXO set for inputs whose scriptPubKey
is a witness program — exactly what the method is documented to do. A
non-witness input needs its whole previous transaction, which needs a txindex
this node does not build, so those are left alone. The `descriptors`
argument is **refused**, not ignored: a caller who passed descriptors and got
a PSBT back without them would reasonably believe they had been applied.

### Refused, each naming the gap
`fundrawtransaction` (no coin selection, change policy or fee estimation, and
the same P2WPKH-wallet / legacy-P2PKH-signer mismatch that blocks
`sendtoaddress`); `descriptorprocesspsbt` (the descriptor engine derives
addresses and scripts but has no path from a descriptor to a spending key);
`getprivatebroadcastinfo` and `abortprivatebroadcast` (no private
broadcast queue; `sendrawtransaction` relays to every live peer leg at once).
`submitpackage` left this list on 2026-08-27 — see slice 21.

### Category status
All 20 of Core's Rawtransactions methods now dispatch.

## Slice 11 — Control, and the last three — (2026-08-25)
`help`, `logging`, `getrpcinfo`, `getmemoryinfo`, `getopenrpcinfo`,
`rpc.discover`, plus `submitheader`, `exportasmap` and `enumeratesigners`.
**With these, all 155 of Bitcoin Core's RPC methods dispatch.**

### `help` is generated, and it is now an invariant
`help` builds its list by merging the four dispatch tables through new
per-module enumerators (`rpc_wallet_method_at`, `rpc_wops_method_at`,
`rpc_node_method_at`, `rpc_chain_method_at`), sorted and de-duplicated. A
method added to a dispatcher appears automatically; there is no second
hand-maintained list to fall out of step.

That makes a cross-module test possible for the first time:
`tests/test_rpc_control.c` sweeps **every** method `help` advertises through
`rpc_dispatch` and asserts none answers `-32601 Method not found`. A method
that reached a table but never got a line in its module's dispatch ladder
would be advertised, reported known, and then fail — and no per-module test
can see that, because it needs all four modules linked together. The sweep
currently covers 155 methods. (`stop` and the `waitfor*` family are skipped
by name — one fires the shutdown handler, the others block for their
timeout; both are exercised in their own tests.)

`help` does **not** carry Core's per-method usage text. Those are ~150
hand-written blocks that would have to be kept in step with the
implementations by hand, and a usage string that has drifted from its method
is worse than none. `help "<method>"` says whether the method is served and
points at this document; an unknown command gets Core's exact
`help: unknown command: <x>`.

### `getrpcinfo`
`active_commands` is a one-element array naming `getrpcinfo` itself. That is
not a simplification: the RPC server accepts and services one connection at a
time on a single thread, so while `getrpcinfo` runs it is necessarily the
only active command. `logpath` resolves the bare `bitcoind.log` the daemon
opens against the datadir it runs in, so it is the real path.

### `logging` reports this node's kinds, and refuses to pretend they toggle
`node_log.asm` emits eight fixed kinds — INFO, HSHK, HDRS, BLOCK, CONS,
STORE, ERROR, SERVE — with no runtime gate: every event is written
unconditionally, deliberately, so the logger holds no global mutable state
and can link anywhere. The read form reports those eight, all true, because
they really are all emitted. **These are not Core's category names**, because
they are not Core's categories, and claiming Core's list with invented
booleans would be worse. The mutating form is refused: a caller who switched
a category "off" and kept seeing it in the log would be worse off than one
told the switch does not exist.

### `getmemoryinfo`
Mode `"mallocinfo"` is real — glibc's `malloc_info(3)` XML, the same document
Core forwards. The default mode `"stats"` reports Core's **secure allocator**
locked-page pool; this node has no secure allocator, so those six numbers
would describe nothing, and it is refused with that said rather than zeroed.

### `submitheader`
Core returns null for a header it already has. That case this node answers
exactly: the hash is looked up in the index and null returned. A header it
does not have would have to be added to the chain, and the header chain
belongs to the forked download worker (`headers.dat` is its file) with no
parent-to-worker channel — so that case is refused rather than answered with
the null that means "accepted". Bad input gets Core's `-22 Block header
decode failed`.

### Refused
`getopenrpcinfo` / `rpc.discover` (an OpenRPC document restates every
method's schema — a second specification to hand-maintain; `help` gives the
generated list instead); `exportasmap` (no asmap: peers are not bucketed by
AS); `enumeratesigners` (no external signer interface at all — there is no
`-signer` to restart with, and `walletdisplayaddress` reports the same gap).

## Parity status: complete
All 155 of Core's RPC methods dispatch, across 11 slices. Counting honestly,
the node answers most of them from real state, reproduces Core's exact answer
where its own situation makes that the correct one, and refuses the rest with
the specific missing capability named. The refusals are concentrated in five
subsystems this node does not have: a wallet rescan, segwit wallet
signing/coin selection, BIP157/158 filters, assumeutxo snapshots, and
external signer support. Every one of them is named at the point of refusal,
so no caller is told a capability exists when it does not.

## Slice 12 — subsystem 1 of 5: the wallet rescan — (2026-08-25)
The eight methods that had to refuse for want of a receive-side view of the
chain now answer from real data: `rescanblockchain`, `getreceivedbyaddress`,
`getreceivedbylabel`, `listreceivedbyaddress`, `listreceivedbylabel`,
`listaddressgroupings`, `listsinceblock`, `abandontransaction`.

### What was missing, precisely
The wallet knew about money from two places, neither of which was a history.
`daemon/build_addr_index.c` inverts the **UTXO set**, so it answers "what does
this address own right now" but knows nothing about outputs since spent and
nothing about when anything arrived. `wallet_txlog.c` journals the sends this
node itself made. So "how much has this address received" had no data behind
it at all.

`asm/wallet_scan.c` produces the missing thing: an ordered record of every
wallet event with the height it happened at. Confirmations, received totals
and since-block listings all follow from that.

### What is matched
An output is ours when its scriptPubKey is P2WPKH **or P2PKH** over one of the
wallet's derived hash160s. Both forms are checked because they are the same
key — `getnewaddress` hands out the bech32 rendering, but a payer given the
P2PKH address of that key is still paying this wallet.

An input is ours when its outpoint is one the scan already recorded as a
receive. That is why the scan runs forward in height order keeping its own
set of owned outpoints: a spend can only be recognised after the output it
spends has been seen.

The derivation window is 1000 indexes across both branches. That is a **real
bound** — an output paid to a key beyond it is not found — which is why it is
stated here and at the constant rather than buried.

### Two places it refuses rather than under-report
- **A height it cannot read abandons the whole scan.** A pruned or holed
  archive is not "no wallet activity there", it is unknown, and a scan that
  silently skipped it would understate every total derived from the result
  with no way for the caller to tell. The error names the height.
- **A full owned-outpoint set abandons too**, because past that point the scan
  would start failing to recognise spends.

On either failure nothing at the output path is disturbed: the header is
written **last**, after every record is durable, so a crash or an abort leaves
a file whose header still describes the previous complete scan — never a
partial one that looks whole. A short or magic-less file reads as absent,
which is the honest reading: no scan has completed.

### No scan is a distinct state from a scan that found nothing
Every receive-side method checks first, and refuses with `-4` naming the
missing scan. Answering `0.00000000` before a scan has run would be
indistinguishable to the caller from an address that genuinely received
nothing. An address the wallet does not own is likewise Core's `-4 "Address
not found in wallet"`, never a zero.

### Notes
- `getreceivedby*` counts **arrivals** and does not net out later spends — a
  wallet's received total must not shrink as it pays people. The test asserts
  this against a coin that is received and then spent.
- `listaddressgroupings` returns exactly one group. A single-seed wallet has
  one owner, and there is no partition of it into distinct owners — that is
  the correct grouping, not a simplification.
- `listsinceblock` emits the height and confirmations it scanned, and **omits**
  `blockhash`/`blocktime`/`blockindex`: the scan records the height, and the
  rest would have to be invented.
- `abandontransaction` refuses a transaction the scan has seen with Core's
  exact `-5 "Transaction not eligible for abandonment"`; an unseen one is
  recorded in a marker store and the call is idempotent.
- The derived key window is cached against the seed bytes. Without that, every
  `getreceivedbyaddress` would repeat 2000 BIP32 derivations and 2000 point
  multiplications, and `listreceivedbyaddress` would repeat them per candidate.

### Cost, stated plainly
A full rescan reads the archive. The RPC server services one connection at a
time on a single thread, so a rescan blocks every other RPC for its duration —
as it must, there being nowhere else to run it. `rescanblockchain` takes
Core's `start_height`/`stop_height`, and a bounded range is the way to keep
that window short.

## Slice 13 — subsystem 2 of 5: coin selection, change, fees, the spend family — (2026-08-25)
`sendtoaddress`, `sendmany`, `send`, `sendall`, `fundrawtransaction` and
`walletcreatefundedpsbt` now work end to end: select coins from the rescan,
add change, compute a fee from the node's own estimator, sign through the
existing signer, broadcast through the existing channel.

### Signing is delegated, deliberately
The spend path builds the transaction and then calls
`signrawtransactionwithwallet` through `rpc_dispatch`. `rpc_commands.c`'s
signer already handles legacy, P2SH, BIP143 v0 and P2SH-wrapped v0, and its
P2WPKH output is Core-validated. A second signer here would be a second thing
to keep correct — and this is the one place in the node where getting signing
subtly wrong loses money rather than returning a wrong number. Nothing in the
spend path calls `wallet_core.c`'s legacy-P2PKH `wallet_send_tx`; the gap
recorded in slice 8 is closed by never touching it.

To make that delegation work, `signrawtransactionwithwallet` now synthesizes
prevout entries from the wallet's own rescan records for any input outpoint
the wallet owns (BIP143 commits to each input's value and scriptPubKey, and
the scan carries both). Core's wallet knows its own outputs when signing;
without this, signing a `fundrawtransaction` result would demand the caller
re-supply data the wallet already has. Caller-provided prevtxs win over
synthesized ones.

### The scan format grew a field, and why
A spend record now carries `prev_txid` — the outpoint that was **spent** —
alongside the spending transaction's own txid (format bumped to `BMCWSCN2`).
Without it, "is this output still unspent" could only be answered by matching
on (vout, key, value), which collides whenever a wallet receives two
equal-valued outputs at the same index to the same key. A collision there
makes coin selection spend an already-spent output — an **invalid
transaction**, not merely a wrong number. The selector now matches on the
actual outpoint.

### Selection, change, fees
- Largest-first selection, iterating because the fee depends on the input
  count. This is simpler than Core's branch-and-bound and says so: it always
  pays a correct fee for the transaction it builds; it does not search for
  the cheapest input set.
- Size is modelled in weight units (P2WPKH inputs: 41 vB base + 108 WU of
  witness), so vsize is Core's ceil(weight/4).
- Change below 294 sat (P2WPKH dust) is dropped into the fee rather than
  created — an output that costs more to spend than it is worth. Change goes
  to `m/84'/0'/0'/0/1`, exactly what `getrawchangeaddress` hands out.
- The fee rate comes from the node's own `estimatesmartfee` (the EMA over
  accepted transactions), floored at the 1000 sat/kvB minimum relay rate
  when the estimator has no data — a floor, not an invented confidence.
- **Locked outputs are excluded from selection.** The test locks the
  wallet's only coin and asserts funding then fails rather than spending a
  coin the operator reserved.

### The inputless/segwit ambiguity
An inputless transaction's serialization — `version | 00 | n_out` — is
byte-identical to a segwit marker+flag, which is exactly why Core's
`fundrawtransaction` carries an `iswitness` heuristic parameter. This node
funds ONLY the inputless form (it cannot value inputs it did not select — no
txindex), so the inputless reading wins by construction, and a transaction
that genuinely carries inputs is refused either way. Stated at the parse.

### Still refusing
Nothing in this group. `walletprocesspsbt` became real 2026-08-26 (Signer
role by delegation); `bumpfee`/`psbtbumpfee` became real 2026-08-27 — the
original transaction's input set and fee are read from the MEMPOOL entry
rather than a txindex, which is where an unconfirmed original actually
lives. See LOG.md for the Core-parity notes and the documented
divergences.

### Tested
The funded transaction is signed to completion **with a real witness** and
the spend path is driven to the broadcast step (this harness has no download
worker, so reaching `sendrawtransaction`'s own "no download worker" error is
proof that selection, change, fee and signing all succeeded). Insufficient
funds is Core's `-6` naming the amount actually available.

## Slice 14 — subsystem 3 of 5: BIP157/158 compact block filters — (2026-08-25)
`getblockfilter`, `scanblocks` and `getdescriptoractivity` now answer.

### The builder is Core-byte-validated
`asm/block_filter.c` implements BIP158's basic filter — element collection
(output scripts + spent-prevout scripts, OP_RETURN and empty excluded,
de-duplicated), SipHash-2-4 keyed with the block hash's first 16 bytes, the
128-bit-multiply mapping onto [0, N·M), and Golomb-Rice coding at P=19,
M=784931. `tests/test_block_filter.c` compares it **byte-for-byte** against
Bitcoin Core's own filters for two real mainnet blocks, frozen from the
oracle: 501726 (coinbase-only — N=1, filter `019170b8`, so a wrong SipHash
rotation fails pinpointed) and 700038 (91 txs, 129 spent prevouts, 827
filter bytes — collection, dedup and the encoder at realistic size). Both
filter-header chain links are verified against Core's too, and the RPC test
confirms the real mainnet genesis block yields Core's `017fa880`.

### Where the data comes from, and the honest bounds
The spent-prevout scripts come from the daemon's per-block undo data
(`undo_<h>.dat`, injected via `rpc_chain_set_undo`). Undo files exist only
inside the retention window (~200 blocks below the tip), so:
- `getblockfilter` REFUSES outside the window rather than serving a filter
  missing its spent-prevout elements — a light client shown such a filter
  would wrongly conclude a block does not touch its coins. Genesis is the
  one height with legitimately no undo data and is served always.
- The `header` field is **omitted**: it chains from genesis, so computing it
  honestly needs every prior filter, and a fabricated chain head would
  poison every later link.

### `scanblocks` / `getdescriptoractivity` scan blocks, not filters
Both walk the blocks directly — exact, no false positives to re-check —
expanding scan objects through the same descriptor path `scantxoutset` uses,
so `addr()`/`raw()`/`wpkh()`/ranged descriptors behave identically across
the three methods. Documented divergence, also carried in the `scanblocks`
result itself: spends are recognised for outpoints received **within** the
scanned set (the same forward walk `wallet_scan.c` uses); a block that only
spends a coin received before the range is not flagged. The range is capped
(250k blocks) because the walk reads every block, where Core's index lookup
does not. `getdescriptoractivity` scans the given blocks in height order
sharing one matched-outpoint set, so cross-block receive→spend pairs within
the given set are reported.

## Slice 15 — subsystem 4 of 5: assumeutxo snapshots — (2026-08-26)
`dumptxoutset` is real; `loadtxoutset` refuses by design.

### The encoder is pinned against a snapshot Core actually wrote
`asm/utxo_snapshot.c` implements Core's snapshot serialization — the 51-byte
header (magic, version 2, mainnet magic, base hash, coin count), Core's
`VARINT`, `CompressAmount`, and all six special script-compression kinds plus
the raw form. `tests/test_utxo_snapshot.c` pins it against **14 coin records
lifted verbatim from a real snapshot the oracle Core wrote** (dumptxoutset at
height 964065): every script kind, coinbase coins, amounts from 330 sat to
50 BTC, all byte-identical, and the header against the oracle file's own
first 51 bytes.

### Proven at full scale against production data
The dump runner (`daemon/utxo_setinfo_rpc.c`, same fingerprint/quiescence
discipline as `gettxoutsetinfo`) was run against the reorg-drill copy of the
production UTXO set: **165,710,384 coins — exactly the known walk count —
streamed to an 11 GB file**, which an independent reference decoder then
walked end-to-end: every record decodes, the file ends exactly at the last
record boundary, and the header's count matches. Two real bugs were found by
that run and fixed: the encoder's script bound was a "reasonable" 128 bytes
where the real set carries junk up to the consensus 10,000 (the bound is now
the consensus bound), and the runner's own temp file tripped the quiescence
fingerprint via the datadir mtime — it is now created before the first
fingerprint, so the only changes the check can see are the daemon's.

### Layout divergence, stated
Core groups all coins of one txid under a single `(txid, count)` prefix,
because its chainstate iterates in txid order. The LSM walk does not, so
every coin is written as its own single-coin group. The format permits it,
the loader adds coins group by group, and the header's coin count is exact;
the file is merely larger than Core's would be.

Only type `"latest"` is served — `"rollback"` reconstructs historical state,
which is the reorg machinery's job in the forked worker. `txoutset_hash` and
`nchaintx` are omitted rather than glued on from unrelated walks
(`gettxoutsetinfo` and `getchaintxstats` compute them on request).

### Why loadtxoutset refuses
This node's UTXO set is built by full validation from genesis, and every
parity claim it makes — the muhash match against Core — rests on every coin
having been verified locally. Loading foreign state would discard exactly
that property, and there is no second chainstate to background-validate it
against as Core does. The export is supported; the import is declined with
that reasoning at the call site.

### Note: the BIP158 KAT fixtures are now force-tracked
The blockfilters slice froze its oracle fixtures into `tests/fixtures/`,
which `asm/tests/.gitignore` ignores wholesale — so they died with the
worktree and the suite broke in a fresh tree. They are regenerated
(deterministic oracle bytes) and force-tracked: 30 KB of frozen KAT anchors
that must never drift or go missing.

## Slice 16 — subsystem 5 of 5: the external signer — (2026-08-26)
`enumeratesigners` and `walletdisplayaddress` now speak Core's `-signer`
protocol (HWI): the operator names a signing program with `signer=` in
`bitcoin.conf`, and the node shells out to it — `<cmd> enumerate` for the
device list, `<cmd> --fingerprint <fp> displayaddress --desc <descriptor>`
to show an address on the device. With no signer configured, both answer
Core's exact `Error: restart bitcoind with -signer=<cmd>`.

The one sharp edge is quoting: the descriptor reaches a shell, and
descriptors legitimately contain `()`, `'` and `#`. Every argument is
single-quoted with embedded quotes rewritten via the POSIX `'\''` idiom.
The test drives a fake HWI (a shell script written by the test) and asserts
the descriptor comes back **byte-for-byte** — including a hostile one
carrying `');echo pwned;'`, which must survive unexecuted. A device without
a fingerprint is dropped from `enumeratesigners`, as Core drops it; a signer
that exits nonzero or emits non-JSON produces an error naming what happened.
`walletdisplayaddress` echoes the address the *signer* confirmed, not the
one asked about — if the device shows something unexpected, the caller must
see that.

## The five subsystems: closed
With this slice, everything the RPC surface once refused for want of a
subsystem is either implemented or declined by design with the reasoning at
the call site. What remains declined, and why, in one place:

- **loadtxoutset** — every parity claim rests on locally-validated coins.
- ~~**bumpfee / psbtbumpfee / walletprocesspsbt**~~ — all three are REAL
  now (walletprocesspsbt 2026-08-26, the bump pair 2026-08-27). The bump
  reads the original from the mempool entry; it draws the increase from
  change only and refuses `outputs`/`original_change_index`, both stated at
  the call site.
- **preciousblock / pruneblockchain / getblockfrompeer** — the forked
  download worker owns fork choice and the header chain. *(The
  addnode-family mutators, `setnetworkactive` and `ping` left this entry in
  slice 17 — the parent→worker control channel below made them real —
  and `submitheader` is handled. Corrected 2026-08-27.)*
- ~~**savemempool / importmempool**~~ — **REAL 2026-08-27**: Core's
  `mempool.dat`, written as version 1 and read as either, verified in both
  directions against a real Core.
- ~~**submitpackage**~~ — **REAL 2026-08-27** (slice 21): package policy,
  in-package parent resolution and Core's effective feerate, so a parent
  below the relay floor is accepted when its child pays for it. Still
  refused: **getmempoolcluster** (no cluster mempool).
- ~~**encryptwallet + multi-wallet lifecycle**~~ — both REAL (encryption
  2026-08-27, the multi-wallet lifecycle the same week). Of the
  import/export family only seven remain refused, all needing a path to
  ADOPT foreign key material a single-seed wallet does not have:
  `migratewallet`, `setwalletflag`, `createwalletdescriptor`, `addhdkey`,
  `importprunedfunds`, `removeprunedfunds`, `exportwatchonlywallet`.
  `importdescriptors` is real.
- **getopenrpcinfo / rpc.discover / exportasmap** — no OpenRPC document, no
  asmap.

*This catalogue is a point-in-time snapshot that later slices supersede; the
entries above were re-checked against the dispatch tables on 2026-08-27
because several had gone stale in the direction of overstating what is
missing.*

## Slice 17 — the parent→worker control channel — (2026-08-26)
Seven RPCs refused for one structural reason: the forked download worker owns
the peer legs, and the parent's RPC thread had no way to command it. That
channel now exists, and `addnode`, `disconnectnode`, `setban`, `clearbanned`,
`listbanned`, `setnetworkactive` and `ping` are real.

### The channel
Same seq/ack discipline as the `sendrawtransaction` and `submitblock`
channels: the parent fills `ctl_op`/`ctl_arg`/`ctl_num` under
`g_submit_lock`, bumps `ctl_seq` last, and waits for `ctl_ack`; the worker
polls at the top of its loop and executes, because it is the process holding
the legs.

Every branch reports **what it actually did** — 1 done, 0 no-op — so the
parent maps a no-op onto Core's error rather than a success that changed
nothing: `-24` for removing a node never added, `-29` for disconnecting an
unknown peer, `-30` for a duplicate ban or an unban of something not banned.

### The ban list is shared, not channelled
It lives in the shared status block because **both** sides need it: the
parent serves `listbanned` straight out of it, and the worker checks it
before every dial and drops any live leg a new ban covers. A ban only one
side could see would be a ban that does not ban.

Subnet matching handles a bare address and `/8`, `/16`, `/24`, `/32`. A
prefix outside that set is **refused at `setban`** rather than stored and
silently never enforced — the failure mode that would otherwise look exactly
like a working ban.

### Two places the enforcement had to go
`mux_next_peer` is the single path to a new outbound leg, so both the ban
check and the `net_active` gate live there. Gating anywhere else would have
been undone by the next rotation — `setnetworkactive false` drops the current
legs *and* stops them coming back, which is the difference between the toggle
working and appearing to work for a few seconds.

`net_active` is initialised to 1 explicitly. The status block is zeroed
shared memory and 0 means "disabled", so leaving it at the default would have
gated every dial and produced a node that silently never connects.
`getnetworkinfo` now reports the real flag instead of a hardcoded `true`.

### Still refusing
`getblockfrompeer` and `preciousblock` also need the worker, but they need
more than a command: a targeted block request and a fork-choice override
respectively. The channel they would ride now exists.

## Slice 18 — the txid index — (2026-08-26)
`getrawtransaction <txid>` with no blockhash now works. It was the single
most likely thing to break an application swapping this node in for Core.

### The index
`daemon/build_tx_index <datadir> [from] [to]` walks the archive and emits
`txindex.dat`: 20-byte records sorted by an **8-byte txid prefix**, with a
sparse sample every 256th record.

The key is truncated for size — mainnet is ~1.43 billion transactions, and a
full 32-byte key plus location would be ~63 GB plus as much again for the
external sort. At 20 bytes it is ~29 GB. **The truncation is not a
probabilistic shortcut:** a lookup reads every record sharing the prefix,
pulls that transaction out of the archive, recomputes its txid and compares
all 32 bytes. A prefix collision costs one extra read and is then rejected,
so the answer is always the transaction asked for, or none. With ~1.4e9 keys
in a 2^64 space a handful of collisions is expected, which is exactly why the
reader scans neighbours instead of trusting the first prefix match.

Two-pass external sort (as `build_addr_index` does, for the same reason the
set does not fit in memory): bucket by `prefix[0]` into 256 files, then sort
each bucket alone and concatenate — bucket *k* holds exactly the records
starting with *k*, so concatenation is globally sorted. Header written last,
so a crash leaves a file that reads as absent rather than a partial index
that looks whole.

A height it cannot read **abandons the build**. An index silently missing a
block would answer "no such transaction" for everything in it.

### Measured, on real blocks
500 real mainnet blocks (963500–964000): 2,379,082 transactions in 3 seconds,
48 MB. Extrapolated to the full chain: **~30 GB, ~30 minutes.** Structure
verified independently — zero sort violations, zero sparse-index mismatches —
and 25 randomly sampled records were resolved through Core: every recorded
`(height, offset, len)` landed exactly on the transaction whose prefix it
carried.

### Reader
One render path serves both lookups: the index supplies the height and byte
offset, the blockhash argument supplies the height, and from there the same
code runs — so the two cannot drift in what they emit. The test asserts the
index path returns **byte-identical** output to the blockhash path.

`txi_open` latches on **success**, not on first attempt, so an index built
against a running node is picked up on the next lookup rather than needing a
restart.

A miss reports the index's covered **range**: "not found" from a partial
index is a different fact from "not found" on the whole chain, and a caller
who cannot tell them apart will draw the wrong conclusion.

`getindexinfo` now reports `txindex` with `best_block_height`, and `synced`
only when the index actually reaches the tip.

### The honest limit
The daemon does **not** maintain the index — it is built offline and does not
follow the tip. `txindex=1` in the config therefore still changes nothing,
and now says exactly that rather than claiming the feature is absent.
Incremental maintenance is the obvious next step.

## Slice 19 — ZMQ notifications — (2026-08-26)
`zmqpubhashblock` / `zmqpubhashtx` / `zmqpubrawblock` / `zmqpubrawtx` in
bitcoin.conf now work, speaking to any libzmq subscriber. This is the
notification interface most Bitcoin infrastructure (explorers, indexers,
LND) expects from a node it replaces Core with.

### ZMTP written out, not linked
libzmq exists on this box only as a runtime .so — no headers — and linking it
would be this project's first external dependency beyond libc, against the
grain of a codebase that writes its own secp256k1 and JSON. The publisher
side of ZMTP 3.1 is small (a 64-byte greeting, one READY each way,
length-prefixed frames), so `daemon/zmq_pub.c` implements it directly.

That choice is only defensible if it interoperates, so the proof is
`tests/zmq_interop.py`: a REAL libzmq 4.3.5 subscriber receives the
handshake, Core's three-part message shape `[topic][body][seq u32 LE]`,
5000-byte LONG frames (the 8-byte big-endian length path every real block
takes), and contiguous per-topic sequence numbers. The harness itself was
proven able to fail: two deliberately sabotaged publishers (little-endian
LONG lengths; subscriptions ignored) are both detected.

The sabotage round found a harness bug worth recording: publisher-side
filtering CANNOT be checked through a libzmq SUB socket, because libzmq
also filters on receive — a publisher that floods everything looks
identical. That check now reads raw bytes off the TCP socket and asserts on
what was actually sent.

### The cross-process ring
Transactions are accepted by the inbound serve CHILDREN, but a PUB socket's
subscriber fds live in one process (the download worker). The bridge is a
16-slot MPSC ring in the pre-fork MAP_SHARED status block: producers claim
slots with an atomic increment and set `ready` last behind a barrier; the
worker drains each rotation. Overrun drops (correct for PUB — a slow
subscriber must never stall consensus) but is COUNTED and logged, never
silent. `tests/test_zmq_ring` exercises it with real forked producers,
including the lapped-ring and mid-write cases.

### The byte order Core actually uses
Core's notifier REVERSES hashes before sending — `data[31-i] =
hash.begin()[i]` — so hashblock/hashtx carry the DISPLAY-order hash, the
same string `getblockhash` prints. The first draft of this slice published
wire order: plausible, self-consistent, and matching nothing a subscriber
would ever compare against. Caught by writing the wire bytes into the
real-block check below and reading them against Core's own output.
`tests/zmq_realblock_check` now asserts, for real archived blocks, that
hex(published bytes) equals Core's `getblockhash` string exactly.

### What refuses, and why
`zmqpubsequence` is refused at config parse, loudly. Core's `sequence`
topic exists to track mempool MEMBERSHIP — adds and removes. This node has
one clean choke point for "accepted" but none for "removed" (eviction,
expiry and reorg each call mpool_del independently), so it could publish
adds without removes: a subscriber's mempool model would grow forever and
never learn it was wrong. A stream that quietly lies is worse than a
refusal that explains itself.

Blocks are published from the tip-watch choke point in the worker, one
notification per block even in catch-up bursts — a subscriber must see
every block, not just the last of a burst. Publishing binds in the worker;
a busy port logs and continues, because notifications must never stop the
node syncing.

## Slice 20 — the mempool gets fed: tx relay receive side, the shared-pool split, and the txindex tail — (2026-08-26)

### The mempool had never held a P2P transaction
The version message advertises relay=1, so peers announce transactions on
all eight outbound full-relay legs — and the sync loop's drains read every
`inv` off the socket and discarded it unexamined. The one code path with a
`tx` handler (the inbound serve children) has had zero real peers. So every
mempool-shaped answer this node gave was truthful about an empty pool that
should not have been empty: getrawmempool `[]`, estimatesmartfee's EMA
starved, getblocktemplate templates with only the coinbase.

`daemon/tx_relay.c` is the missing receive half. Between sync passes on
each worker leg it drains buffered messages: an announced tx it does not
hold is requested and the reply validated through the same
`tx_accept_validate` (full signature + policy) the inbound path uses. A
consumed ping is answered — losing it would eventually cost the connection.
When nothing is buffered the cost is one empty poll(2).

### MSG_WITNESS_TX, learned the hard way once already
Requests carry type 0x40000001, not bare MSG_TX: type 1 returns the
witness-STRIPPED serialization — the same wire behaviour that silently
stripped the whole segwit-era block archive (incident #10) — and a stripped
segwit tx fails signature validation, so each would be fetched, rejected
and re-announced forever. The hermetic test asserts on the getdata's actual
type bytes.

### Stated non-goals
No re-announcement to other peers (user-originated txs are pushed by the
sendrawtransaction path, which is the case where this node is the only
holder); no BIP339 wtxidrelay (peers announce txids to us without it); no
tx getdata service on worker legs. Each is written at the module head, not
implied.

### Incident #47: the worker's accepts were invisible to RPC
`txsub_accept_and_relay` inserted into the worker's PRIVATE 1024-slot pool
while the parent's mempool RPCs read the SHARED pool — sendrawtransaction
returned a txid that getrawmempool then denied knowing. The submission path
simply predates the shared-mempool tranche and was never re-pointed.
`txsub_pool()` now prefers `mp_ext_area` exactly as the asm serve children
do; the relay path uses the same, so P2P-accepted transactions are visible
to the parent's RPCs.

### The txid index follows the tip now
Slice 18 left the index "built offline, does not follow the tip".
`daemon/tx_index_tail.c` closes that: an append-only unsorted tail of the
same 20-byte records, backfilled at boot from the archive (covering the
offline-build→deploy gap and any downtime), appended per new block from the
same choke point that publishes ZMQ (one block read feeds both), strictly
monotonic by height so a from-genesis UTXO replay appends nothing. A reorg
rolls the covered-height watermark back through the post-truncation
index-rebuild callback; stale records are inert because every reader
candidate is verified by recomputing the full txid from the current archive
bytes — the property that also makes torn crash-writes safe. The reader
scans the tail after a base miss and reports combined coverage in
getindexinfo and the covered-range refusal. The per-block walk lives once,
in `daemon/txi_format.h`, shared by the offline builder and the tail
writer.

## Slice 21 — gettxout answers, the wallet view, and submitpackage — (2026-08-27)

Three RPCs that were answering the wrong thing, or nothing, now answer.

### gettxout stopped lying
`gettxout` returned `null` for every outpoint on the live node. `null` is not
"I cannot say" — in `gettxout` it means "that output is not unspent". The
node was asserting that about **every coin in existence**, and the cause was
structural: only the standalone `rpcd` calls `rpc_commands_set_utxo_store`,
so `g_utxo_lst` was NULL in the embedded server and the handler took its
"no store" path on every request.

Giving the RPC its own read-only view was measured and rejected on COST, not
safety. It is safe — the manifest and compaction publish tmp+fsync+rename so
a cross-process reader sees old-or-new and never torn, and `lsm_get_scratch`
is thread-local. But `utxo_lsm_reload_ro` takes 60–83 s on the real
165M-entry set (six production boots), and every new block invalidates the
view, so even a cached one would block the first call after each block for a
minute.

Instead the parent ASKS the download worker over a socketpair created before
the fork. The worker already holds the set open and answers `utxo_lsm_get` in
microseconds. It replies only at a QUIESCENT point in its loop, after the
catch-up call: `utxo_lsm_get` is thread-safe on its own, but this module
guarantees `get()` and `flush()` never overlap *by construction*, and a query
thread inside the worker would have broken exactly that.

Every failure REFUSES — no worker, timeout, short read, lost framing — and
the response ECHOES the outpoint it answers, because a query that times out
leaves its reply in the socket and the next query would otherwise read a
well-formed answer about a different coin. `tests/test_txoq_ipc` pins that,
verified fail-then-pass.

Proven against Core: `gettxout` on an unspent coin matches Core's answer
exactly, and a spent outpoint is `null` from both nodes.

### getbalance / listunspent read the wallet, not an extension
Both answered from the ADDRESS INDEX, which is an extension gated behind
`addrindex=1` and OFF by default — so a fully funded wallet reported
`0.00000000` with an empty `listunspent` while `walletscan.dat` held every
receive. With no address argument they now enumerate the wallet's coins from
the rescan records; an explicit address still uses the index, which is the
only thing that knows addresses that are not ours.

Spent-ness comes from the scan's own spend records. Coinbase maturity needed
a fact the scan never stored, so the format grew one byte (`BMCWSCN3` adds
`is_coinbase`); an older `BMCWSCN2` file is still read rather than rejected.

With no completed rescan these now ERROR rather than answering `0.00000000`:
"I have not looked" and "you have nothing" are different answers.

### submitpackage
Real, in Core's shape: `package_msg`, `tx-results` keyed by wtxid with
`txid` / `vsize` / `vsize_bip141` / `fees{base, effective-feerate,
effective-includes}` / `error`, and Core's own `package-not-validated` for
members that never got an individual verdict. `replaced-transactions` is
absent, which is Core's convention (the field is optional there); this node
does not track package-driven RBF evictions.

Two passes, and the order is the design: a DRY RUN with the in-package
overlay learns every member's real fee without inserting anything, and only
then does the commit run with the package feerate in effect. Inserting
optimistically and checking the aggregate afterwards would mean removing
transactions that should never have been accepted.

The two fee floors are the ONLY checks a package may relax. A member that
fails anything else is invalid or non-standard on its own terms, and no
amount of fee from a child changes that.

Proven end to end: the parent is refused ALONE with "min relay fee not met",
then accepted as part of the package — and Bitcoin Core accepts the identical
package (`validation/bumpfee_regtest_e2e.sh`).

STILL OPEN: p2p 1-parent-1-child package RELAY (this is submission), TRUC/v3
and ephemeral-dust policy, `replaced-transactions`, and
`testmempoolaccept`'s package mode, which still evaluates each member
independently and says so at its own call site.

## Slice 22 — mempool.dat, both directions — (2026-08-27)

`savemempool` and `importmempool` are real, and the interop is proven BOTH
ways against a running Core: it loads the dump this node writes, and this
node loads the dump it writes.

We WRITE version 1. That is Core's own `-persistmempoolv1` form, which it
reads unconditionally; v2's obfuscation exists to stop antivirus software
mangling the file and its key is random, so no writer could produce a
byte-comparable artifact anyway. We READ both, because a file handed to us
was most likely written by a default Core.

**The bug the interop test caught.** The v2 obfuscation key is serialized as
a VECTOR — a compact-size length prefix, then the bytes — so the body starts
at offset 17, not 16. Core says so in a comment. Reading it as a bare 8-byte
key decodes the transaction COUNT correctly, because that is 8 bytes at an
8-aligned offset, and then fails on the first transaction.

The unit test did not catch it, and that is the point worth keeping: the v2
fixture was built by the test itself, from the same wrong assumption the
reader held, so the two agreed and both were wrong. A self-built fixture only
tests a format if it is built FROM the format.

**Where each half runs.** The dump reads the shared pool under the same lock
`getrawmempool` uses and writes while still holding it — the entry pointers
are into the shared blob, and releasing first would let an eviction move the
bytes out from under the writer. The load cannot happen in the parent:
admitting a transaction is the worker's job, so import re-submits each one
through the channel `sendrawtransaction` uses and every entry gets the full
consensus and policy treatment on the way back in. Core re-validates on load
too — a dump is a hint about what was interesting, never a licence to skip
checks.

**Not restored**, stated rather than glossed: entry times and fee deltas (a
re-admitted transaction gets a fresh time, and there is no
`prioritisetransaction` path to replay a delta into), and the unbroadcast
set, which this node does not track because `sendrawtransaction` relays to
every live leg immediately.

Verified on the live mainnet node: a 284,485-byte dump of 184 real
transactions that an independent parser walks to exactly the file length,
zero trailing bytes, all entry times nonzero.
