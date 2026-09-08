# 2026-09-08 — The Esplora facade (stage 1)

mempool.space serves address pages, per-block transaction lists with
prevouts and outspends only through an Esplora-compatible REST backend; its
own production runs on one. With a plain bitcoind it refuses address
lookups outright and fetches every input's previous transaction with one
RPC call at a time, about twenty thousand calls for a full block. The
operator asked for the node to adapt to the app, not the other way round.

`bmc.esploraport=<port>` (and `bmc.esplorabind`, default 127.0.0.1) opens a
second listener in the RPC server, without authentication, because Esplora
has none and mempool's client sends none. Keep it on loopback or behind a
proxy. Every route is answered in process by the same `rpc_dispatch` the
JSON-RPC server uses, under the same execution lock, so the facade can
never disagree with the RPC surface, and its JSON is reshaped into
Esplora's exactly as mempool's own converter shapes Core JSON, with the two
places where real Esplora differs and mempool consumes Esplora's form: a
coinbase input carries the all-zero txid and vout 4294967295. Amounts are
integer satoshis computed from Core's decimal strings without a double.

## Routes served

| route | source |
|---|---|
| `/blocks/tip/height`, `/blocks/tip/hash`, `/block-height/:h` | getblockchaininfo, getblockhash |
| `/block/:hash`, `/header`, `/raw`, `/txids`, `/txid/:i`, `/status`, `/txs[/:start]` | getblock 0/1/3 |
| `/internal/block/:hash/txs` (every transaction with prevouts and fee) | getblock verbosity 3, the undo data |
| `/tx/:txid`, `/hex`, `/raw`, `/status`, `/merkle-proof` | getrawtransaction verbosity 2, getblockheader, getblock (the branch is computed here) |
| `/tx/:txid/outspends`, `/outspend/:n`, `POST /internal/txs/outspends/by-txid` | gettxspendingprevout when the txospender index exists, gettxout otherwise (spent or not, no spender) |
| `/mempool`, `/mempool/txids`, `/mempool/recent`, `/internal/mempool/txs[/:lastSeen]?max_txs=` | getmempoolinfo, getrawmempool, getmempoolentry, gettxout for prevouts |
| `POST /internal/txs`, `POST /internal/mempool/txs` | batch transaction loads |
| `POST /tx` | sendrawtransaction |
| `/address/...`, `/scripthash/...` | 501 until stage 2 |

## Stage 2

Address and scripthash routes need a history index: the address index on
disk is a reverse UTXO index plus a tail journal, not the full history
Esplora's `chain_stats`, `txs` and `utxo` want. That index, its builder over
the undo data that is now kept for every block, and the routes are the next
change.

## Tests

`test_rpc_esplora`: 49 checks against a canned `rpc_dispatch` the test
defines itself, so every route runs without a node: the tips, block fields
(bits as a number), header and raw block, txids, all block transactions
with the coinbase shape, fees and prevouts in satoshis, esplora types and
asm, an OP_RETURN output, paging, a confirmed and an unconfirmed
transaction, hex, status, the merkle proof (a three-leaf tree rebuilt from
its branch), outspends with and without the spender index, the mempool
routes, batch loads, broadcast success and rejection, the 501 and the 404.
The asm formatter is checked against mempool's own notation (OP_PUSHBYTES_n,
OP_PUSHNUM_n, OP_CLTV, OP_CSV, OP_RETURN_n for unknown opcodes).
