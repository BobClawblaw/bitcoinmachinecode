# The mempool departure journal

**Status:** landed 2026-09-16. Off by default; `bmc.mempooljournal=<records>`.

Bitcoin Core has no counterpart to this. It is an extension, in the same
spirit as `addrindex`, and it changes no consensus or wire behaviour.

## The gap it closes

A mempool is a waiting room, not a ledger. Core caps it at `-maxmempool`
(300 MB by default) and evicts the cheapest packages when it fills;
`-mempoolexpiry` drops anything older than 336 hours. When a transaction
leaves either way, **Core forgets it completely**. Ask a Core-backed explorer
what became of a transaction a user broadcast an hour ago and it cannot
distinguish "mined", "replaced by a higher fee", "evicted when the pool
filled" and "never existed". The user sees a gap, or a *ghost* — a
transaction that was there and then was not.

The usual workaround is a **"Big Node"**: raise `-maxmempool` until nothing is
ever evicted. That trades unbounded memory for the answer, and still loses
everything on restart.

This node keeps Core's eviction and expiry behaviour **exactly** — policy and
consensus are untouched — and writes one small record when a transaction
leaves, naming the reason.

## What is recorded

One 152-byte record per departure, in a fixed-capacity ring
(`mempool_journal.dat` in the chain datadir):

| field | meaning |
|---|---|
| `txid` | the departing transaction |
| `reason` | `mined`, `replaced`, `evicted`, `expired`, `conflicted` |
| `first_seen` | when the pool accepted it — **the fact Core destroys** |
| `departed_at` | when it left |
| `waited` | derived: how long it sat in the pool |
| `vsize`, `fee` | as of departure |
| `replaced_by` / `block_hash`, `height` | where applicable |

`first_seen` is the reason the hook sits where it does. It lives in the
arrival-time table that `mempool_forget` clears immediately afterwards; once
the pool has dropped the entry there is nowhere left to learn when the
transaction arrived. "Broadcast at T, evicted at T+6h, never mined" is only
answerable if it is captured at that moment.

`wtxid` **is recorded as of 2026-09-16.** The pool caches one per slot but
exposes it only *by slot*, and adding a by-txid getter means editing
`bitcoin_mempool.asm`'s probe — which carries the MEM-21 coherence rules and
is not a file to touch for a display field. It does not need touching: the
cached value is `sha256d` over the transaction's stored bytes, and the
departure hook fires **before** `mpool_del`, so the bytes are still readable
and recomputing gives the same answer. One hash per departure, paid only when
the journal is enabled.

`tests/test_mempool_shared.c` pins the equality that makes the shortcut
legitimate — the recomputed value against the pool's own cached one. Without
it, a change to what `mpool_put` caches would silently write a *different*
wtxid into every record, and a wrong one is worse than the zero it replaced:
a zero is documented as "not recorded", a wrong value is not detectable at
all. A record still carrying all-zero means the transaction had already left
the structural pool.

## Reading it

```
bmcgetmempooljournal              stats + the most recent departures
bmcgetmempooljournal <txid>       that transaction's latest departure
bmcgetmempooljournal <count>      the most recent <count> (max 5000)
```

Over the Esplora facade, for mempool.space:

```
GET /tx/:txid                 unchanged, plus a "departure" key when there is one
GET /tx/:txid/departure       the departure alone; 404 when none is recorded
GET /mempool/departures[/N]   the most recent N (default 25, Esplora's page size)
```

`/tx/:txid` keeps its exact Esplora shape — the departure is added under its
own key, so a client that does not know about it sees no difference.

## Why a ring, not a log

Bounded on purpose: one record is 152 bytes, so a million departures is
~152 MB on a box that already carries a 200 GB address history. The question
it answers — "what happened to the transaction I just broadcast" — is a
recent-history question. Oldest records are overwritten.

An existing file's capacity **wins over the configured one**. Slot is
`(seq-1) % capacity`, so adopting a new capacity in place would re-point every
record at a different sequence and scramble the history the file exists to
keep. Changing capacity means removing the file.

## Crash and concurrency

Records sit on a fixed grid and carry the same sequence number at **both
ends**. A reader accepts a record only when the two stamps agree, so a write
interrupted by a crash — or caught in flight by another process, since the
node forks per connection and the pool is `MAP_SHARED` — reads as absent
rather than as a half-written record that looks whole. The sequence counter is
bumped with an atomic fetch-add, so two processes removing at the same moment
take different slots instead of the same one.

A ring read is a snapshot of a moving structure. The guarantee is that every
record **returned** was really written, not that the set is complete.

The journal failing to open is never fatal: the node runs exactly as before,
minus the journal, and says so on stderr. A file that is not a journal, or is
a future version, is **refused and left alone** — never rewritten.

## ~~`first_seen` resets on restart~~ FIXED 2026-09-16

The arrival-time table the hook reads (`g_seen` in `daemon/mempool_cfg.c`) is
anonymous shared memory, not a file, so a restart loses it. Transactions
restored from `mempool.dat` are re-accepted and get a *new* arrival time.

So after a restart, `waited` measures **how long the transaction sat in the
pool since this node last started**, not how long since it was first
broadcast. The first live block after the 2026-09-16 deploy recorded 2,189
`mined` rows with `waited: 1`, which is that effect, not a fast-confirming
mempool. Over a run of any length it converges on the real figure; read it
with the node's uptime in mind.

**Closed the same day.** The save path already wrote the real arrival time
into `mempool.dat`; the load path discarded it (`(void)t;`). It now applies it
after a successful accept, and carries it through the retry buffer as well —
a child deferred for its parent is exactly as old as the file says, and
dropping it there would have left a subset of the pool silently re-aged.

The value is **vetted, not trusted**. `mempool.dat` is read at startup before
anything else has checked it, and this field is an input to expiry: a time in
the future would keep a transaction in the pool forever, one past the expiry
window would evict it on the next sweep. Both are refused and the fresh stamp
stands. Four reintroductions cover it — trust the future, trust the stale,
insert a phantom entry for a transaction not in the pool, and make the restore
a no-op.

The load line now reports how many came back:
`loaded mempool.dat: N accepted, ... ; M arrival time(s) restored`.

## Coverage

Every reason is now driven through the real policy engine, not the store:

| reason | how it is exercised |
|---|---|
| `evicted` | a pool blob too small for a fifth transaction forces a genuine `TrimToSize` |
| `expired` | a real expiry sweep over an entry |
| `mined` | a constructed block containing the transaction |
| `conflicted` | a block carrying a *different* transaction that spends the same coin |
| `replaced` | RBF, exercised by the policy suite |

`mined` and `conflicted` share one exit and are told apart only by the removal
mark, so reporting a conflicted transaction as mined would say a broadcast
that is gone for good had made it into a block. That block fixture also covers
`block_connect`'s reason save/restore, which was previously listed here as
untestable.

One trap the fixture records: **the coinbase must come first.**
`block_connect` reconciles the pool only for `j > 0`, exactly as Core does,
so a transaction placed at index 0 is never matched. The first version of the
fixture put the mined transaction there and read the silence as a broken
`mined` path — the block was malformed, not the code.

## Known limits

- Departures are recorded, arrivals are not. "Every transaction this node ever
  saw" would be a different and much larger feature.
