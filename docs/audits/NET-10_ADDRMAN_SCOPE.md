# NET-10 — the address manager has no bucketed structure

Scoping report, 2026-09-04. Companion to `CODEBASE_AUDIT_2026-09-03.md`
(NET-10, MEDIUM) and `AUDIT_2026-09-03_REMEDIATION.md`.

**Status: scoped, not started.** This is the last open MEDIUM. It is a design
change to the file that decides who this node connects to, and the failure
mode of getting it wrong is the very thing the finding is about — an eclipse.
It wants its own branch and its own review.

---

## 1. What the problem is

The address book is a flat array. `daemon/addrbook.c`, 197 lines,
`AB2_MAX = 65536`, 48 bytes per record:

```c
typedef struct {
    bmc_addr_t         a;          /* net, len, addr[32], port */
    unsigned long long services;
    unsigned           last_seen;
} ab2_rec_t;
```

There is **no source address, no tried flag, and no attempt counters**. When
the book is full, `ab2_add` evicts whichever record has the smallest
`last_seen` and overwrites it in place.

`last_seen` is peer-supplied. `addr_ingest.c` sanitises it — timestamps more
than five days old are pulled forward, and anything beyond `now + 600` is
clamped — but within that window a peer chooses the value. So an attacker's
addresses arrive looking fresh, and honest addresses we have not spoken to
recently look stale.

That single fact is the finding: **eviction is ordered by a number the
attacker controls.**

### What Core does instead

`AddrMan` keeps two tables. `new` holds addresses we have heard about;
`tried` holds addresses we have actually connected to. `new` is bucketed by
`(source group, address group)` — 1024 buckets of 64 — so an address's
position depends on **who told us about it**, and one source can occupy at
most a bounded fraction of the table no matter how many addresses it sends.
`tried` is 256 buckets of 64, keyed on the address group. Collisions are
resolved by *test-before-evict*: the incumbent is contacted, and if it answers
it stays. Entries are aged out by `IsTerrible`, not by a gossiped timestamp.

Relevant constants: `ADDRMAN_NEW_BUCKET_COUNT` 1024,
`ADDRMAN_TRIED_BUCKET_COUNT` 256, `ADDRMAN_BUCKET_SIZE` 64,
`ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP` 64.

---

## 2. Why it is worse than the finding states

`dl_pool_from_book` in `daemon/main.c` — which chooses the addresses this node
dials — already carries a workaround for the missing tried/new distinction.
Its own comment:

> The book carries no tried/new distinction and gossip refreshes `last_seen`,
> so recency cannot tell a once-connected peer from an address a stranger
> claimed; but the head is the migrated, once-connected set and gossip appends
> behind it. A uniform sample over all 17k IPv4 entries drew mostly dead
> addresses and odd ports — one live leg in five minutes (2026-09-01 02:20).

So clearnet dial candidates are taken **only from the first 4096 slots**
(`DL_POOL_V4_WINDOW`). That is a positional heuristic stading in for a `tried`
table, and it holds only while nothing overwrites the head.

Eviction picks `min(last_seen)` across the **whole array**, head included. The
head is exactly where the migrated, once-connected, not-recently-contacted
addresses live — the ones with the oldest honest timestamps. Attacker
addresses arrive with fresh ones.

**A flood does not merely dilute the book. It preferentially destroys the set
the dialer depends on, and the dialer has no other source of candidates.**

This is the strongest argument for doing the work: a real `tried` table would
let `dl_pool_from_book` delete the window heuristic entirely, rather than
depending on an insertion-order accident.

---

## 3. How close the precondition is

Measured on this node's live book, `data/main/peers2.dat`:

| | |
|---|---|
| records | 40,848 of 65,536 — **62.3% full** |
| headroom | 24,688 |
| age of the book | 42 days of `last_seen` span |
| composition | 28,499 IPv4, 6,439 IPv6, 5,086 I2P, 824 CJDNS |

Ingest is rate-limited to 0.1 addr/s per leg (`tx_relay.c`), across 8 outbound
legs: **69,120 addresses/day**.

**Headroom is therefore ~8.6 hours of sustained flooding.** Honest traffic got
the book to 62% in six weeks; a flood reaches capacity in under a day, and
every insertion after that evicts an honest record.

The attacker needs no privilege: any peer we dial, or anyone who persuades us
to dial them, may gossip addresses.

Existing partial mitigations, none of which change the outcome:

- per-response quotas (256/response, 16/netgroup) in `addr_ingest.c` — these
  bound a single ADDR message, not the total from one source over time;
- the 0.1/s token bucket — this sets the *rate* of the attack, not its
  eventual success;
- `asmap` — improves the netgroup key, but the structure it would inform does
  not exist here.

---

## 4. What resolving it requires

### 4.1 A disk-format change

The record has no spare bytes. Phase 1 needs, per entry: the **source
netgroup** (4 bytes), a **tried flag**, an **attempt count**, and **last-try**
(4 bytes). That is a new magic — `BMCADBK2` → `BMCADBK3` — plus a migration.

Precedent exists and is helpful: `addrbook.c` already migrates the legacy
`peers.dat` into `peers2.dat` on first open. Migrated entries should land in
`tried`, which is precisely what the head-window heuristic is approximating
today, so the migration and the fix reinforce each other.

Sizing: at ~56 bytes/record the file goes from ~3.1 MB to ~3.7 MB. Core's
equivalent holds 81,920 positions against our 65,536; matching it is optional.

### 4.2 Blast radius

`ab2_*` has **68 call sites across 9 files**: `daemon/addr_ingest.c`,
`daemon/serve_addr.c`, `daemon/main.c`, `rpc_node.c`, and five test files.

Most only iterate (`ab2_get`, `ab2_count`) and are unaffected if the iteration
API keeps its shape. Two care about the split:

- `dl_pool_from_book` — should prefer `tried`, and can then drop
  `DL_POOL_V4_WINDOW`;
- `getnodeaddresses` / `serve_addr.c` — Core serves from `new`, and gossiping
  our `tried` set leaks which peers we actually use.

### 4.3 The three rules, in the audit's own "at minimum" order

1. **Cap live entries per source netgroup.** Requires storing the source.
   Directly defeats the single-source flood, and is the highest value per line
   of code.
2. **A `tried` flag eviction never touches.** One bit. Protects the
   once-connected set and unblocks removing the dialer's positional
   workaround.
3. **Evict by `(tried, terrible, age)`** rather than by peer-supplied
   `last_seen`. `net_netgroup_v4` already exists in `net_policy.c` to key on.

### 4.4 Also worth fixing while in there

`ab2_add` at capacity is O(n) for the eviction scan **plus** an O(n) hash
rebuild — roughly 200,000 operations per inserted address. Under the flood
that is the attack paying for itself in our CPU. Bucketing makes eviction
O(bucket) and removes the rebuild.

---

## 5. What I would not do

**Full Core-shaped bucketing with test-before-evict.** Test-before-evict
requires making a connection attempt *inside the insert path*. This
architecture — forked inbound serve children sharing a file-backed book, with
`ab2_add` called from several processes — has nowhere natural to do that, and
bolting it on would mean either blocking an insert on network I/O or inventing
a deferred-probe queue. The security gain over rules 1–3 is small; the
structural cost is not.

Phase 1 (format bump + the three rules) is the recommendation. Phase 2 (full
bucket geometry) should be justified separately, if ever.

---

## 6. Testing

`tests/test_addrbook.c` and `tests/test_addr_ingest.c` cover quotas and record
encoding. **Neither covers eviction**, which is why this survived.

Phase 1 needs, all deterministic against the file-backed book with no network:

- a flood of N addresses from one source netgroup is bounded by the cap, and
  addresses from other netgroups are unaffected;
- a `tried` entry survives a full-book flood that would evict it under
  `min(last_seen)`;
- eviction prefers untried-and-stale over tried, whatever the gossiped
  timestamps say;
- migration: a `BMCADBK2` file opens, every record survives, and the migrated
  set is marked `tried`;
- the negative control that matters: with the source cap removed, the flood
  evicts honest records — i.e. the test reproduces the finding.

---

## 7. Summary

| | |
|---|---|
| **What breaks** | eviction is ordered by an attacker-supplied timestamp |
| **Consequence** | the dialer's candidate set can be replaced with attacker addresses; the head-window workaround is destroyed first |
| **Precondition** | a full book — ~8.6 hours of flooding, or six weeks of honest growth (already 62%) |
| **Fix** | source-netgroup cap, a `tried` flag eviction cannot touch, eviction by (tried, terrible, age) |
| **Cost** | disk-format bump + migration, ~0.6 MB, 2 of 68 call sites |
| **Explicitly out of scope** | test-before-evict; does not fit a forked, file-backed design |
