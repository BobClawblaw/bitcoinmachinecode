# Running mempool.space against the node

mempool.space's backend needs a Bitcoin Core-compatible JSON-RPC server and,
in its `esplora` mode, an Esplora REST backend for blocks, transactions
and addresses. This node provides both from one process: the JSON-RPC
server, and an Esplora-contract listener (the *facade*) that answers
Esplora's routes in-process from the same RPC dispatch. Nothing in
mempool.space is patched; the backend is configured, not modified.
Landed 2026-09-08 (#99, #100, #102-#108, #111).

## What the node serves

| route family | source | needs |
|---|---|---|
| `/blocks/tip/*`, `/block/*`, `/block-height/*`, `/v1/block/*/summary` | the archive and headers | — |
| `/tx/*` with fees and prevouts, `/tx/*/status`, `/tx/*/outspends`, `/tx/*/merkle-proof` | the archive, the tx index, the rev store, the txospender index | `txindex=1`, `txospenderindex=1` |
| `/mempool`, `/mempool/txids`, `/fees/*`, `POST /tx` | the live mempool | — |
| `/address/:a`, `/address/:a/txs*`, `/address/:a/utxo` | the address history runs + the live journal + the mempool | `addrindex=1`, set BEFORE the sync |
| `/scripthash/*` | — | refused (501) |

Fees and prevouts exist for every block because undo data is kept for the
whole chain in `rev*.dat` files (Core's model). A node that ran before
2026-09-08 holds undo only from the upgrade height on; a full history
needs `-reindex-chainstate`.

## Configuration on the node

```ini
bmc.esploraport=3005          # the facade; 0 (default) leaves it off
bmc.esplorabind=127.0.0.1     # loopback unless a proxy fronts it
addrindex=1                   # BEFORE the sync (see below)
txindex=1                     # the daemon builds these during the sync
txospenderindex=1
blockfilterindex=1
coinstatsindex=1
```

Since 2026-09-16 the daemon builds every one of these **during** the sync,
as sorted runs trailing the applied height, so a fresh node is ready for
mempool.space when it reaches the tip and there is no build step afterwards
(`docs/devlog/INDEX_RUNS.md`).

The facade is unauthenticated: keep it on loopback or behind a proxy that
mempool.space's frontend reaches. It takes the RPC lock per dispatch, not
per request, so a batch route (`/internal/block/txs`, a thousand
transactions) cannot starve JSON-RPC callers; the 2026-09-08 starvation
incident (twelve minutes of RPC stalls under one batch) is why.

## The address history index

Address pages need every funding and spend event per address for the whole
chain. Set `addrindex=1` **before the node syncs** and the daemon does the
rest: the live journal records every event from genesis, and every
`bmc.indexrunblocks` heights (default 20,000) the trailing builder folds the
next range into a sorted run whose spends come from undo, rotates the
journal, and merges runs when they pile up. The facade's `/address` routes
read the runs plus the journal, so they answer from the first run onward.

`addrindex=1` cannot be enabled on an already-synced node: undo below
tip−200 is pruned, so historic spends are unreconstructable and boot refuses
loudly rather than serve a history that under-reports. For a node in that
position there is still the one-off whole-chain build:

```sh
asm/daemon/bmc_build_addr_hist /path/to/data/main       # hours; ~200 GB out, ~700 GB temp
```

which writes `addr_hist.dat` — the same format, simply the run that starts at
0. Nothing on a fresh sync needs it.

## Configuring mempool.space

In `backend/mempool-config.json`:

```json
"MEMPOOL":  { "BACKEND": "esplora", "INDEXING_BLOCKS_AMOUNT": 100 },
"CORE_RPC": { "HOST": "127.0.0.1", "PORT": 8331, "USERNAME": "...", "PASSWORD": "..." },
"ESPLORA":  { "REST_API_URL": "http://127.0.0.1:3005" },
"DATABASE": { "ENABLED": true, "POOL_SIZE": 1, ... }
```

- `INDEXING_BLOCKS_AMOUNT` is how far back the backend indexes blocks
  (fees, pools, the hashrate/difficulty graph). Every indexed block needs
  `getblockstats` with fees, which needs undo data: on a node whose undo
  starts above genesis the indexer dies on the oldest block it reaches
  (2026-09-08, undo from 965,826: the depth was capped at 20). After
  `reindex-chainstate=1` (2026-09-09) undo covers the whole chain and
  the depth is a year, 52,560. The backend reads it at start; restart it
  after a change.
- `CORE_RPC` is the node's JSON-RPC server (`rpcport`, the credentials
  from `rpcauth` or `rpcuser`/`rpcpassword`).
- `POOL_SIZE: 1` matters: mempool's pools importer commits its mining-pool
  table through a transaction opened on one connection of its pool and
  finished on another, so with a larger pool the import never commits and
  every block reads as "Unknown" miner. One connection serializes it. This
  is a configuration choice, not a patch.
- The frontend's dev server proxies `/api/*` to the backend, which
  forwards Esplora routes to the facade.

## Limits on the address routes

- `/address/:a/utxo` refuses an address with more than 500 unspent outputs
  (HTTP 400 `too many unspent transaction outputs`), Esplora's own
  `utxos_limit` rule: every funding event would need its transaction id,
  one block read each.
- The stats route resolves no transaction ids; a page of `/txs` resolves
  its own 25. The mempool view is a cache refreshed by a background thread
  in bounded slices, so a request only reads it; a fresh node's view is
  complete a minute or two after boot.

## What to expect

Blocks, block summaries, miner identification, transactions with fees and
prevouts, outspends, the mempool, recommended fees and the difficulty
adjustment work against the node. Address pages work once the history
index is built and `addrindex=1` is on, and include unconfirmed activity
from the mempool. Lightning routes are mempool's own lightning backend and
are unrelated. The genesis coinbase 404s, as on Core.

## Ports on the reference box

The production node serves P2P on 8332, JSON-RPC on 8331 and the facade
on 3005; 8333 belongs to the Bitcoin Core oracle used for differential
tests. mempool's backend listens on 8999 and its frontend on 4200.
