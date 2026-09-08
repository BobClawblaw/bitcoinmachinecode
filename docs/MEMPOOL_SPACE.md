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
| `/tx/*` with fees and prevouts, `/tx/*/status`, `/tx/*/outspends`, `/tx/*/merkle-proof` | the archive, the tx index, the rev store, the txospender index | `txindex.dat` (`bmc_build_tx_index`), `txospender.dat` (`bmc_build_txospender_index`) |
| `/mempool`, `/mempool/txids`, `/fees/*`, `POST /tx` | the live mempool | — |
| `/address/:a`, `/address/:a/txs*`, `/address/:a/utxo` | the address history index + the live address index + the mempool | the history build, then `addrindex=1` |
| `/scripthash/*` | — | refused (501) |

Fees and prevouts exist for every block because undo data is kept for the
whole chain in `rev*.dat` files (Core's model). A node that ran before
2026-09-08 holds undo only from the upgrade height on; a full history
needs `-reindex-chainstate`.

## Configuration on the node

```ini
bmc.esploraport=3005          # the facade; 0 (default) leaves it off
bmc.esplorabind=127.0.0.1     # loopback unless a proxy fronts it
addrindex=1                   # after the history build (below)
```

The tx index and the txospender index are built offline
(`daemon/bmc_build_tx_index <datadir>`, `daemon/bmc_build_txospender_index
<datadir>`) and used when their files exist; the daemon's `txindex=1` key
has no effect on that. `OPERATIONS.md` has both procedures.

The facade is unauthenticated: keep it on loopback or behind a proxy that
mempool.space's frontend reaches. It takes the RPC lock per dispatch, not
per request, so a batch route (`/internal/block/txs`, a thousand
transactions) cannot starve JSON-RPC callers; the 2026-09-08 starvation
incident (twelve minutes of RPC stalls under one batch) is why.

## The address history index

Address pages need every funding and spend event per address for the
whole chain. Build it once, offline from the daemon's point of view:

```sh
asm/daemon/bmc_build_addr_hist /path/to/data/main       # hours; ~200 GB
```

Three bucketed passes over the archive; the build needs about 700 GB of
temporary space on the same filesystem, prints one line per bucket, and
writes `addr_hist.dat`. Then set `addrindex=1` and restart once: the live
address index's tail journal adopts the build height and carries the
history forward from there. The facade answers 501 for addresses until
the file exists and remaps to a rebuilt file on its own.

## Configuring mempool.space

In `backend/mempool-config.json`:

```json
"MEMPOOL":  { "BACKEND": "esplora", "INDEXING_BLOCKS_AMOUNT": 100 },
"CORE_RPC": { "HOST": "127.0.0.1", "PORT": 8331, "USERNAME": "...", "PASSWORD": "..." },
"ESPLORA":  { "REST_API_URL": "http://127.0.0.1:3005" },
"DATABASE": { "ENABLED": true, "POOL_SIZE": 1, ... }
```

- `CORE_RPC` is the node's JSON-RPC server (`rpcport`, the credentials
  from `rpcauth` or `rpcuser`/`rpcpassword`).
- `POOL_SIZE: 1` matters: mempool's pools importer commits its mining-pool
  table through a transaction opened on one connection of its pool and
  finished on another, so with a larger pool the import never commits and
  every block reads as "Unknown" miner. One connection serializes it. This
  is a configuration choice, not a patch.
- The frontend's dev server proxies `/api/*` to the backend, which
  forwards Esplora routes to the facade.

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
