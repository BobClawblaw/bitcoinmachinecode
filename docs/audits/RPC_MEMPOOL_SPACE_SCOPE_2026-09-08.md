# RPC scope against mempool.space's backend — 2026-09-08

The operator wants a local mempool.space instance fed by this node, and
asked what our RPC surface does wrong for it. This is what its backend
(commit `8158a23`, cloned to `/mnt/2tbssd/mempool-src`) calls, what it
got, and what is still missing. Nothing here touched production beyond the
backend's own read-only calls.

## Methods

The backend's `rpc-api/commands.ts` uses 24 methods. All 24 exist in this
node's 163-method dispatch: getblockchaininfo, getblockcount, getblockhash,
getblock, getblockheader, getblockstats, getrawtransaction, getmempoolinfo,
getrawmempool, getmempoolentry, getmempoolancestors, getnetworkinfo,
getpeerinfo, getnettotals, gettxout, gettxoutsetinfo, getindexinfo,
estimatesmartfee, sendrawtransaction, testmempoolaccept, submitpackage,
getblocktemplate, uptime, validateaddress.

## What was wrong, and is fixed

| Found | Fix | Landed |
|---|---|---|
| `bmc_cli getblock <hash> 2` sent the verbosity as the string "2" | bitcoin-cli's argument conversion (true/false/null, numbers, JSON) | PR #96 |
| replies over 64 KB were "malformed" at the CLI, and over 64 KB the reply parser silently returned no result (the CLI printed nothing, exit 0) | 64 MB buffers; the result subtree is detached, no size at all (the parser is in the daemon too) | PR #96 |
| getpeerinfo showed only the relay legs; getnettotals 3 KB against a 50 GB archive | the download workers are published each tick: ids 100000+, `inflight`, `bmc_download_worker`; getnettotals adds the download's bytes | PR #95 |

## What the backend hit on this box

1. **"Parse Error: Expected HTTP/, RTSP/ or ICE/" on every call to
   production (port 8332).** Resolved 06:37Z: the 09-07 build had its P2P
   listener on 8332 and its RPC on 8331 (one below the defaults), so the
   backend was speaking JSON-RPC to the P2P port. Today's build listens
   on the correct 8333/8332; production was redeployed on it (worklog
   session 28) and the backend runs without RPC errors.
2. **MySQL 8 rejects the schema migration** ("error in your SQL syntax");
   mempool.space targets MariaDB 10.5+. A MariaDB 10.11 container now
   runs on 127.0.0.1:3307 (`mempool-mariadb`, data in
   `/mnt/2tbssd/mempool-mariadb-data`, credentials in the 0600 env file
   `/mnt/2tbssd/mempool-mariadb.env`); the schema initialized cleanly.
3. **No egress to raw.githubusercontent.com** for `pools-v2.json`, without
   which it refuses to index blocks. The file is served locally from
   `/mnt/2tbssd/pools-serve` on 127.0.0.1:8998 (with a tree.json carrying
   its git sha); `MEMPOOL.POOLS_JSON_URL` and `POOLS_JSON_TREE_URL` point
   there. Refresh: `git -C /mnt/2tbssd/mining-pools pull` and copy.
4. **rust-gbt** (the native block-template generator) could not be built
   (cargo fetch has no egress); a stub package satisfies the import and
   `MEMPOOL.RUST_GBT` is false.

## Field gaps that remain (this node's side)

| RPC | Core | Here | Effect on mempool.space |
|---|---|---|---|
| `getblock` verbosity 2 | each tx carries `fee`; verbosity 3 adds `prevout` on inputs | `fee`/`prevout` only for blocks inside the undo window (`UTXO_UNDO_WINDOW` = 200, per-block `undo_<h>.dat`); older blocks omit them | fee statistics for old blocks come from `getblockstats`, which has the same window; indexing the whole chain's fees needs undo for every block |
| `getrawtransaction` verbosity 2 | `fee` and prevouts from undo data | inside the window only | same |
| `getblockstats` | any height with undo data | inside the window only | same |
| `getrawmempool` verbose | `height` = the height the tx entered | 0 ("entry height untracked") | shown as the entry height in the UI; cosmetic |
| `getindexinfo` | lists txindex/coinstatsindex/blockfilterindex when enabled | `{}` on the bench node (no indexes configured) | mempool.space requires `txindex=1` on the node; enable it in production's conf |
| `gettxoutsetinfo none@height` | needs coinstatsindex | same rule | enable `coinstatsindex=1` if the coin-stats page is wanted |
| block-level keys of `getblock` | 20 keys | all 20 present | none |
| tx-level keys of `getblock` 2 | txid hash version size vsize weight locktime vin vout hex fee | all but `fee` outside the window | see above |

## Decided 2026-09-08: keep all undo, like Core

Landed as `docs/releases/2026-09-08-undo-keep-all.md`: every "outside the
window" row above becomes "for every block the node has applied on this
build"; production's history before the deploy needs `-reindex-chainstate`
once. The section below is kept as the record of the choice.

## The one design decision (as it stood before the decision)

Core keeps undo data for every block (the `rev*.dat` files) unless the
node is pruned; this node keeps a 200-block ring of per-block undo files.
Every "outside the window" row above is that one choice. Options:

- keep all undo, packed like Core's rev files (one file per blk file,
  offsets in the index), deleted only by pruning; the cost is Core's:
  about 8% of the block data on disk;
- keep the ring and accept that fee history is available only for the
  last 200 blocks;
- keep the ring, and let mempool.space's own indexer compute fees from
  `getrawtransaction` of each input (it can, at the price of one RPC per
  input; slow for a full-chain index).

The first is the Core-compatible answer and is what a full mempool.space
instance expects. The operator decides.

## How to run the backend here

```
cd /mnt/2tbssd/mempool-src/backend && node dist/index.js      # reads mempool-config.json (0600)
```

Config: `CORE_RPC` 127.0.0.1:8332 with the production cookie
(`/storage/bitcoinmachinecode/data/main/.cookie`); `DATABASE`
127.0.0.1:3307 user `mempool`; `MEMPOOL.BACKEND` none, `HTTP_PORT` 8999,
`INDEXING_BLOCKS_AMOUNT` 100, `RUST_GBT` false, `CACHE_DIR`
`/mnt/2tbssd/mempool-cache`. Logs to wherever stdout goes
(`/mnt/2tbssd/mempool-backend.log` in this session's runs). The frontend
is not built yet.
