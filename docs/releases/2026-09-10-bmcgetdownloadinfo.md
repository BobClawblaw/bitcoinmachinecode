# 2026-09-10 — `bmcgetdownloadinfo`, the first RPC of our own

The parallel download's live state, for operators and for bmcmonitor: which worker holds which peer, what each is pulling and how fast, and the window state that explains why the tail is or is not moving.

**Core has no counterpart, by construction.** Core's block download is 8 outbound peers driven from one `ThreadMessageHandler` thread, so there is no worker to report and no window an operator can act on. Here `node_ibd_blocks_s` blocks for the length of a chunk and cannot multiplex, so every downloading peer is a forked process, and the mapping worker → peer → chunk → rate is the only way to see what a sync is doing. `getpeerinfo` already lists the peers; it has nowhere to put the window, the tail, the adaptive stall timeout or the ban count.

**Naming.** The `bmc` prefix is the same rule the `bmc.*` config keys follow: a Core name must carry Core's exact semantics, so a call Core does not have must not take a name Core might later use.

Returns `{"active": false, "bytes_total": N}` outside a download rather than failing, so a poller can call it unconditionally. While a download runs it adds `workers`, `pool`, `banned`, `free_peers`, `window`, `first_hole`, `claim`, `applied`, `end_height`, `staged`, `stall_timeout_s`, `stall_evictions`, `median_bps`, and a `peers` array of `{worker, addr, subver, services, startingheight, conntime, bytes_recv, bps_recv, inflight_lo, inflight_hi}`.

Every one of those numbers was already being computed; the run 20 stall was diagnosed by grepping them out of the console log. Now they are queryable.

## Adding another one

Three registrations in `rpc_node.c` and a test:

1. `cmd_<name>(rj_val** res)` building the object with `rj_obj` / `rj_obj_set` / `rj_arr`.
2. the name in `NODE_METHODS[]`, which is what `rpc_node_handles()` matches to route the method here.
3. a `strcmp` line in `rpc_node_dispatch()`.
4. a case in `tests/test_rpc_node.c`, which fills a static `node_status_t` the way the serve parent would and dispatches directly.

Data the RPC server cannot see must first reach the shared `node_status_t` (`rpc_node.h`), published by whichever process owns it. Append new fields at the end: existing offsets stay put. This change added `bps_recv` to `rpc_peer_t` and a `dl_*` aggregate block, published by the catch-up parent on the same tick as `dlpeers`.

Verified: `test_rpc_node` covers the active shape, the worker mapping and the inactive answer, watched to FAIL with the `window` field unpublished. Note a trap hit on the way: reverting by deleting the dispatch line does not compile under `-Werror` (unused function), so the suite runs against a stale binary and passes. Revert a value, not a registration.
