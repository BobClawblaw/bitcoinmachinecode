# 2026-09-08 — The address history index (Esplora facade, stage 2)

mempool.space's address pages need Esplora's `/address` routes: the funded
and spent output counts and sums, the transaction count, the transaction
list newest first with paging, and the unspent outputs. The address index
on disk was a reverse UTXO index plus a tail journal: what an address owns
now, not what it ever did. This is the history, native to the node, in
the same key space as the existing index.

## The index

`addr_hist.dat` in the chain directory, built offline by
`daemon/bmc_build_addr_hist <chaindir>`: groups sorted by (type, hash),
each a list of 21-byte events, FUND (height, txpos, vout, value) and
SPEND (height, txpos, vin, the spent value), sorted by height and
position, with a sparse index every 256 groups. A base event names its
transaction by height and position in the block; the txid is one
`getblock` away and is not stored (32 bytes times seven billion events).
Roughly 7 billion events and 1.3 billion keys on mainnet: about 200 GB.

The builder needs only the block archive, in three passes over 256
buckets: every standard output becomes a FUND event and an outpoint
record, every input a spend reference; outpoints and references are
joined per bucket into SPEND events carrying the spent value; the key
buckets are sorted into groups. No UTXO set, no undo data. Temp space
peaks around 700 GB on mainnet; the first build on production is running
as this is written.

## The live part

The tail journal the address index already writes (`addrindex.tail`,
`addrindex=1`) is the history's tail: ADD is a funding, DEL a spend, TOUCH
the spending transaction. The reader merges it above the base's
`to_height`. A fresh journal on a node with the base adopts the base's
coverage and backfills from there; undo data is kept for every block, so
the replay reaches any distance.

## The routes

`/address/:addr` (chain_stats from base and tail; mempool_stats zero in
this cut), `/address/:addr/txs` and `/txs/chain/:lastSeen` (newest first,
25 a page, deduplicated by transaction), `/address/:addr/txs/mempool`
(empty in this cut), `/address/:addr/utxo` (the funding events with no
spender per the txospender index, each with its block height). Scripthash
routes answer 501: the index is keyed by address.

## Tests

`test_addr_hist`: the builder over a fixture archive (a coinbase to A, a
transaction spending it into two addresses, a later spend of one), every
event read back with its height, position, index and value in order; a
synthetic 700-key file exercises the sparse search at every key and the
gaps. `test_rpc_esplora` +13: the address routes over a synthetic base and
a canned tail. `test_addr_index_tail` +2: the adoption.
