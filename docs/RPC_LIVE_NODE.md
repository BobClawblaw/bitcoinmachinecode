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
