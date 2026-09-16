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

`wtxid` is in the record format but **not recorded today**: the structural
pool caches it only by slot, and scanning that table on a path which runs
thousands of times per connected block is not a trade worth making for a
display field. Copying the txid in instead would be right only for
non-witness transactions and silently wrong for every segwit one. Readers
treat all-zero as "not recorded" and omit the field. A by-txid getter in
`bitcoin_mempool.asm` would close it with no format migration.

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

## `first_seen` resets on restart

The arrival-time table the hook reads (`g_seen` in `daemon/mempool_cfg.c`) is
anonymous shared memory, not a file, so a restart loses it. Transactions
restored from `mempool.dat` are re-accepted and get a *new* arrival time.

So after a restart, `waited` measures **how long the transaction sat in the
pool since this node last started**, not how long since it was first
broadcast. The first live block after the 2026-09-16 deploy recorded 2,189
`mined` rows with `waited: 1`, which is that effect, not a fast-confirming
mempool. Over a run of any length it converges on the real figure; read it
with the node's uptime in mind.

Persisting the arrival times alongside `mempool.dat` would close this. Core
does write an entry time per transaction into that file, so the data exists —
it simply is not plumbed back into the arrival table on load.

## Known limits

- `wtxid` is not populated (above).
- The `conflicted` reason is distinguished from `mined` inside
  `mpool_policy_block_connect` by the removal mark; the save/restore of the
  reason around *that* entry point is not covered by a test, because driving
  it needs a real block. `expire_one`'s is.
- `first_seen` resets on restart (above).
- Departures are recorded, arrivals are not. "Every transaction this node ever
  saw" would be a different and much larger feature.
