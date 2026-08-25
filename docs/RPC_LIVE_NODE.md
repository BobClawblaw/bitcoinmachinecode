# Live-node RPCs in the serve daemon — design

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

So `sendtoaddress`, `sendmany`, `send`, `sendall`, `walletcreatefundedpsbt`,
`walletprocesspsbt`, `bumpfee` and `psbtbumpfee` all return `-1` naming the
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
information); `dumptxoutset`, `loadtxoutset` (no assumeutxo: no writer for
Core's snapshot format and no second chainstate to load one into);
`preciousblock`, `pruneblockchain` (fork choice is owned by the forked
download worker, with no channel for the parent to steer it);
`savemempool`, `importmempool` (no `mempool.dat` reader or writer);
`getmempoolcluster` (the pool tracks the ancestor/descendant graph but not
Core's cluster structure); `getblockfrompeer` (no parent-to-worker channel
for a targeted block request).

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
`submitpackage` (no package validation — submit the parent first, then the
child); `getprivatebroadcastinfo` and `abortprivatebroadcast` (no private
broadcast queue; `sendrawtransaction` relays to every live peer leg at once).

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
`walletprocesspsbt` (PSBT signing needs per-input PSBT field surgery the
signer does not do), `bumpfee`/`psbtbumpfee` (RBF replacement needs the
original transaction's full input set and fee, which needs a txindex).

### Tested
The funded transaction is signed to completion **with a real witness** and
the spend path is driven to the broadcast step (this harness has no download
worker, so reaching `sendrawtransaction`'s own "no download worker" error is
proof that selection, change, fee and signing all succeeded). Insufficient
funds is Core's `-6` naming the amount actually available.
