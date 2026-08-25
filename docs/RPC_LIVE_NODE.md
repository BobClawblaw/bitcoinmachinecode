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
- **The mempool** (`mp_ext_area`) is `MAP_PRIVATE|MAP_ANONYMOUS`
  (`mempool_cfg.c:67-68`) → copy-on-write per fork. Each inbound child accepts
  txs into its **own** private copy; the parent never sees them.

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

### Slice 3 — `getmempoolinfo` / `getrawmempool`
Flip `mp_ext_area`/`mp_ext_blob` to `MAP_SHARED` (`mempool_cfg.c:67-68`) so
children's `mpool_put`s are parent-visible; add a slot-walk iterator to
`bitcoin_mempool.asm` (only txid-keyed `mpool_get` exists). Reuse
`mpool_policy_estimate_feerate` for the fee fields. Target the **documented v31
field set**; the scratch oracle is master (31.99) and emits fields no release
has (`tx_send_rate`, `inv_buckets`, cluster limits) — verify stable fields
only.

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
