# 2026-09-12 — Verbose `getrawmempool` carries the ancestor graph

`getrawmempool true` now returns the same per-entry object `getmempoolentry`
returns: `depends`, `spentby`, `ancestorcount`, `ancestorsize`,
`descendantcount`, `descendantsize`, `wtxid`, `height`, `unbroadcast`, and a
full `fees` object, alongside the `vsize`/`weight`/`time` it already had.

**We already had the data.** The accept-path policy registry has held the real
ancestor graph for weeks, and `getmempoolentry` has been serving it per txid.
Verbose `getrawmempool` was landed as a first slice whose own comment said the
aggregates would come with `getmempoolentry`. They did. Nobody widened the bulk
call.

**The gap was load-bearing.** Building CPFP clusters over the whole pool needs
the graph for every entry, and the only way to get it was one `getmempoolentry`
per transaction — against an RPC server that handles one request at a time. So
bmcmonitor's Mining page could only show ancestor packages for the block
template, via `getblocktemplate`'s own `depends`, and said so rather than
pretending otherwise. Core's equivalent view was genuinely better.

## The naive version was 33x slower than Core

Simply calling the existing builder per entry works and is unusably slow:

| | entries | wall |
|---|---|---|
| Core v31.99 | 22,992 | 0.38 s |
| naive per-entry | 15,302 | 8.38 s |

`mpool_policy_entry_info` answers for one transaction, and every question costs
a full scan of the node array: the self lookup, the `spentby` sweep, and a fresh
sweep for each node popped during the descendant walk. That is right for one
txid and quadratic for n of them. An 8-second RPC on this node is an outage for
every other consumer, which is exactly how a previous `gettxout` change starved
this same server.

A first attempt cached each transaction's vsize to stop re-parsing set members.
It moved 8.38 s to 7.64 s — the parsing was never the dominant term, and the
measurement said so before any more effort went into it.

`mpool_policy_entry_info_all` fills every entry in one pass instead. Children
are indexed once by counting-sort over the parent edges, so both sweeps become
adjacency walks and the closures stay bounded by `MPE_MAX_SET`.

| | entries | wall | per entry |
|---|---|---|---|
| Core | 22,992 | 0.38 s | 16.5 µs |
| this node, one-pass | 11,112 | **0.18 s** | **16.2 µs** |

## Verification

Against the live pool, 12 transactions compared across 11 fields each between
the bulk answer and `getmempoolentry`: all match. 9,954 of 11,697 entries carry
a non-empty `depends`, with a maximum ancestor count of 25 — a real cluster
graph, not an empty field.

`tests/test_rpc_node` runs every assertion through **both** paths, the one-pass
build and the per-txid fallback, because a fast path is only worth having if it
agrees with the slow one. Ten checks, watched to FAIL against the old four-field
entry.

**The test caught a bug in the fix.** The first cut made the per-txid branch
conditional on there being no bulk cache, so a node that exposes no
`pol_entry_info_all`, or whose bulk allocation fails, got an entry with *no
graph at all* rather than the slower correct one. The fallback is now
unconditional.

## Still absent, deliberately

`vsize_adjusted` (this RPC surface has no `-bytespersigop` concept anywhere, and
adding it in one place while the package RPCs report plain vsize would be worse
than omitting it consistently), and `chunkweight`/`vsize_bip141`, which are
cluster-mempool fields from Core master rather than the v31.1 release this node
tracks.
