# RPC field parity with Bitcoin Core v31.1 — the work, and how it was missed

2026-09-12.

## How this was missed

`docs/PARITY_PLAN.md` tracked **method names**. Every Core method exists here —
167 of ours against Core's 156, nothing absent — so the surface read as done.
Nothing ever compared a **response shape**, and that is where every remaining
gap lives. `getrawmempool true` returned four fields where Core returns sixteen
for weeks, and it surfaced only because a consumer could not build CPFP
clusters. A name is not a contract.

The lesson was already written down once, on the REST surface: *compare whole
documents, name each divergence*. It was never applied to JSON-RPC.

`validation/rpc_field_parity.py` now does that, and should run in the gate.

## Measure against v31.1, not the oracle

The verification oracle on this box is a **v31.99 development build**, and
diffing against it invented work: it reported `inv_buckets` and `tx_send_rate`
as missing from `getnetworkinfo`, which v31.1 does not have at all, and inflated
`getpeerinfo` to 76 fields against v31.1's 38.

Every figure below was taken from **Bitcoin Core v31.1 run on regtest**, which is
the release this node tracks. Two connected regtest nodes give a real
`getpeerinfo`; a generated chain gives a real `getblock` and `getmininginfo`.

## The work

### 1. `getpeerinfo` — **38 of 38, DONE 2026-09-12**

Verified live against a production node: 38 fields, nothing missing, nothing
additive. Every field is emitted only where a real source exists.

| what had to be plumbed | fields |
|---|---|
| the socket's own facts, recorded by the process that holds it | `transport_protocol_type`, `session_id`, `addrbind` |
| BIP152 state | `bip152_hb_from` (the peer's own flag), `bip152_hb_to` (false as a fact: `_sendcmpct_pl` is a compile-time `high_bandwidth=0`) |
| BIP133 | `minfeefilter` — we sent a feefilter and never read the peer's |
| address relay | `addr_relay_enabled`, `addr_processed`, `addr_rate_limited` — the counts existed but were GLOBAL, so one peer flooding looked like a busy pool |
| ping timing | `pingtime`, `minping` — the round trip was already measured on every pong and never published, which also left the eviction logic's lowest-ping protection with nothing to protect by |
| announcement queue | `inv_to_send`, `last_inv_sequence` |
| activity timestamps | `last_block`, `last_transaction` — previously written only by `txann`, whose slot is set for INBOUND children alone, so on a nearly all-outbound node they never appeared at all |
| per-message byte maps | `bytessent_per_msg` via the asm write hook, extended to carry the command name; `bytesrecv_per_msg` in the drain loops, where the command is already in hand |
| removed for exactness | `startingheight` (v31.1 dropped it), `bmc_download_worker` (additive key in a Core call) |

Two things the work itself turned up. The asm write hook was `(fd, plen)` and now
carries `(fd, plen, cmd, cmdlen)`; the upload pacer ignores the extra arguments,
as SysV allows, and the hook is installed unconditionally now because it carries
accounting as well as pacing. And `presynced_headers` is emitted as Core's `-1`
unless a *positive* height was recorded: the unknown default is applied where a
leg slot is filled, but a slot published by any path that memsets the record
arrives as 0, and 0 read as a height would claim a presync at genesis.

### 2. `getmininginfo` — 7 fields, v31.1 has 12

- [ ] `blockmintxfee`, `target`
- [ ] `next` object: `next.bits`, `next.difficulty`, `next.height`, `next.target`
- [ ] `currentblocktx`, `currentblockweight` — conditional in Core, present once
      a block template exists. We hold a template; these should follow from it.

### 3. `getblock` — missing `coinbase_tx`

- [ ] `coinbase_tx` at verbosity 1, 2 and 3, with its nested `coinbase`,
      `locktime`, `sequence`, `version`, `witness`. Confirmed present in v31.1.

### 4. `getmempoolinfo` — 12 fields, v31.1 has 16

- [ ] `limitclustercount`, `limitclustersize`, `optimal` — cluster mempool, and
      confirmed to be in v31.1, not just master.
- [ ] `fullrbf`

### 5. `getmempoolentry` and `getrawmempool true` — 17 vs 21

- [ ] `chunkweight`, `fees.chunk`, `vsize_adjusted`, `vsize_bip141`.
      **Confirm against v31.1 first** — these come from the oracle, and the
      regtest node would not build a mempool transaction to check them
      directly. Cluster mempool *is* in v31.1 (see item 4), so `chunkweight`
      and `fees.chunk` are likely real. `vsize_adjusted` needs a
      `-bytespersigop` concept this RPC surface does not have anywhere, which
      is already a documented deliberate omission.

### 6. `getzmqnotifications` — not a gap, verify

- [ ] Ours returns an empty array because this node has no ZMQ configured; the
      oracle has three publishers. Enable ZMQ here and re-diff before calling
      it either way.

### 7. The process fix — do this first

- [ ] Wire `validation/rpc_field_parity.py` into the gate so a missing field
      fails a build rather than waiting for someone to notice a weak page.
- [ ] Extend its case table: it covers **42 calls**; the surface is 167 methods.
      The uncovered ones mostly need arguments or wallet state. Each addition
      is cheap and each one closes a blind spot of exactly the kind that hid
      `getrawmempool`.

## Current state

| call | ours | v31.1 | missing |
|---|---|---|---|
| `getpeerinfo` | 19 | 38 | 20 |
| `getmininginfo` | 7 | 12 | 5 |
| `getmempoolinfo` | 12 | 16 | 4 |
| `getmempoolentry` | 17 | 21* | 4* |
| `getblock` | 20 | 21 | 1 (+5 nested) |
| everything else diffed | — | — | none |

\* against the v31.99 oracle; v31.1 not yet confirmed.

Thirty-two of the 42 diffed calls match field for field, including
`getblockchaininfo`, `getblockstats`, `getblockheader`, `getblocktemplate`,
`getrawtransaction`, `getdeploymentinfo`, `getchaintxstats`, `gettxout` and
`decoderawtransaction`.

## 2026-09-12 — coverage past the original 39 calls

The case table was extended from 39 calls to 58, covering the node-level and
pure-function methods that can be diffed without a wallet and without mutating
either side: `getblockhash`, `getchainstates`, `getaddrmaninfo`,
`getprioritisedtransactions`, `getblockfilter`, `getmempoolcluster`,
`gettxspendingprevout`, `testmempoolaccept`, `verifychain`, `createmultisig`,
`createrawtransaction`, `scantxoutset status`, `scanblocks status`, the PSBT
family (`converttopsbt`, `decodepsbt`, `analyzepsbt`, `finalizepsbt`,
`utxoupdatepsbt`, `combinepsbt`, `joinpsbts`), `combinerawtransaction`, the
message-signing pair, and the wallet-directory listings.

**First fact established: no RPC method is missing.** All 156 of Core v31.1's
method names are present on this node, and none is a stub — the gap was never
the method list, it is the response shapes, which is what this document exists
for.

What the new coverage found:

| call | finding | disposition |
|---|---|---|
| `testmempoolaccept` | `reject-details` missing | **implemented** — matches Core's `TxValidationState::ToString()`, and is omitted for `missing-inputs` exactly as Core omits it |
| `getchainstates` | `coins_db_cache_bytes`, `coins_tip_cache_bytes` missing | **divergence, recorded** — this node has no LevelDB block cache and no `CCoinsViewCache`; see `CORE_DIVERGENCES.md` |
| `getmempoolcluster` | errors; Core returns a cluster | **feature gap** — Core's cluster mempool is a subsystem this node does not implement. Same root as the four missing `getmempoolentry`/`getrawmempool` fields below |
| `getmempoolentry`, `getrawmempool true` | `chunkweight`, `fees.chunk`, `vsize_adjusted`, `vsize_bip141` | **feature gap** — all four are cluster-mempool fields, not independent omissions |
| `listwalletdir`, `getprioritisedtransactions`, `getzmqnotifications` | fields "missing" | **not defects** — our collection is empty, so there is nothing to sample. See the false-positive note in the tool |

The four mempool-entry fields and `getmempoolcluster` are one item, not five:
implementing Core's cluster linearization. That is a subsystem decision, not a
field to add, and it is the largest remaining shape gap on the RPC surface.

### The survey that must not be repeated

The "is any method a stub?" question was first answered by looping over every
Core method name and invoking it against the **live production node**. Invoking
an API is not a read-only act: the loop called `clearbanned`, `ping` and then
`stop`, and took production down for ninety seconds. `rpc_field_parity.py` now
carries a `NEVER_CALL` deny list and refuses to run if any case names a method
that changes state, spends, signs from a wallet, or controls the process.

### `getmempoolcluster` implemented for the case that has one answer (2026-09-12)

Core returns a transaction's whole cluster in **linearization order**, split
into chunks by chunk feerate (`rpc/mempool.cpp` `clusterToJSON`). This node has
no cluster mempool and so no linearization — but a **singleton cluster has only
one possible answer**: a transaction with no unconfirmed parents and no
unconfirmed children is alone in its cluster and is its own single chunk, so
`clusterweight`, `txcount` and the one chunk are exactly determined. That case
is now answered, verified field for field against v31.1 on a live mempool
(`clusterweight 832`, `txcount 1`, `chunkfee 0.00062700`).

A cluster of two or more still refuses, because the chunk boundaries *are* the
linearization and nothing here can recover them — but the error now names the
cluster size and the reason, instead of claiming this node has no clusters.

The same arithmetic closed three of the four missing mempool-entry fields. Core's
adjusted weight is `max(weight, sigop_cost * bytes_per_sigop)` (`policy.cpp`
`GetSigOpsAdjustedWeight`); the registry stores each entry's BIP141 sigop cost
and the policy layer knows `-bytespersigop`, so:

| field | status |
|---|---|
| `vsize_bip141` | emitted always — `(weight + 3) / 4` |
| `vsize_adjusted` | emitted always — adjusted weight over 4, rounded up |
| `chunkweight` | emitted for a singleton cluster; omitted otherwise |
| `fees.chunk` | emitted for a singleton cluster; omitted otherwise |

The comment in `rpc_node.c` calling these "absent, and deliberately" was stale:
it was written before the registry carried `sigop_cost`, and the data had been
available for some time.

**Formulas were read from Core's source, not inferred from samples.**
`GetSigOpsAdjustedWeight` only differs from plain weight on sigop-heavy
transactions, so a sample of ordinary transactions shows the two as identical
and would have hidden the rule entirely.

### ~~Open~~ FIXED 2026-09-15: an error-code divergence, found in passing

The original note said "Core answers a null or absent txid with **-3**". Half
right: measuring every JSON type against Core v31.1 showed **three** answers,
not two, and *absent* is not one of the -3 cases.

| condition | Core |
|---|---|
| missing required argument | `-1` + the method's full help text |
| wrong JSON type | `-3` (`RPC_TYPE_ERROR`), `Wrong type passed: {"Position 1 (txid)": ...}` |
| right type, bad value | `-8` (`RPC_INVALID_PARAMETER`) + a specific message |

The three sites in `rpc_node.c` returned `-8` for the first two alike and named
the passed type as "null" whatever was really sent. Fixed, with the formatter
moved to `rpc_json.c` (`rj_wrong_type_msg`) so every emitter agrees. The `-1`
text cannot be matched: this node carries no per-method usage text by decision,
so it answers Core's code with a short usage line. Full account and the
verification in `CORE_DIVERGENCES.md`.

## 2026-09-18 — three v31.1 gaps the v31.99 oracle hid

Diffing against the **v31.1 release node** (RPC 8337) instead of the v31.99
development oracle turned up three things. Two of them had been "confirmed"
off the dev build, which has since buried taproot and changed the mempool
entry.

### `getdeploymentinfo`: taproot, and `script_flags` below the tip — FIXED

- v31.1 lists **taproot as a bip9 deployment** after the five buried ones
  (`DeploymentInfo`'s order; on regtest after `testdummy`). It was missing,
  and a test pinned the count at five. Now emitted from the real BIP9 state
  machine (`GetStateFor`, `GetStateSinceHeightFor`, `GetStateStatisticsFor`)
  walked over this node's headers, with v31.1's per-chain parameters: mainnet
  1619222400 / 1628640000 / min_activation_height 709632 / 1815 of 2016;
  ALWAYS_ACTIVE on testnet4, signet and regtest. `testdummy` goes through the
  same code.
- `script_flags` had three defects that only show with a `blockhash` below
  the tip: it described the NEXT block (Core describes the block itself), it
  held `WITNESS` back until segwit's height (Core sets it unconditionally), and
  it ignored the two `script_flag_exceptions` (170060 is `[]`, 692261 has no
  `TAPROOT`). The exception hashes and flag bits are now generated into
  `script_flags_consts.h` by `validation/gen_script_flags.py`.
- Verified: whole documents equal to v31.1 on **mainnet at 32 heights** —
  every buried activation boundary, both exception blocks, and taproot's
  DEFINED → STARTED (681408) → LOCKED_IN (687456) → ACTIVE (709632) path with
  its statistics and signalling strings (a header-only archive of mainnet
  0..712000 served through `rpc_chain.o`) — and on **regtest at 18 heights**
  across testdummy's whole lifecycle, including a failed signalling period
  (`validation/v311_rpc_gaps_regtest_diff.sh`).
- The BIP9 parameters are **transcribed**, not generated: the generator reads
  a master tree, where `DEPLOYMENT_TAPROOT` no longer exists. The mainnet walk
  above is what checks them. A pruned node that no longer has taproot's
  signalling headers omits the deployment rather than guessing its state.

### `getmempoolentry` / `getrawmempool true` / ancestors-descendants verbose — FIXED

| field | v31.1 | was | now |
|---|---|---|---|
| `bip125-replaceable` | present | missing | emitted: `IsRBFOptIn` — the tx signals (an input with nSequence ≤ 0xfffffffd) or an in-mempool ancestor does. Signalling, not full-RBF policy. |
| `vsize_adjusted`, `vsize_bip141` | **absent** (all of `rpc/`) | emitted | removed, also from `testmempoolaccept` / `submitpackage` |
| `vsize` | `GetTxSize()`: **sigops-adjusted** | plain BIP141 | adjusted — the number `vsize_adjusted` used to carry |
| `ancestorsize`, `descendantsize` | sums of the adjusted size | BIP141 sums | adjusted sums |

Item 5 above and the 2026-09-12 table listed `vsize_adjusted`/`vsize_bip141` as
v31.1 fields to emit; that came off the dev build and was wrong. Verified
against v31.1 on regtest: a signalling tx, a `replaceable=false` tx and a final
child of a signalling parent, field for field (`unbroadcast` excepted — see
below).

### `getchainstates`: `coins_db_cache_bytes`, `coins_tip_cache_bytes` — DIVERGENCE, KEPT

Both are real v31.1 fields: the configured LevelDB block cache for the coins
DB (`min(total/2, 8 MiB)` of what `-dbcache` leaves after the index caches)
and the `CCoinsViewCache` budget (the rest). This node has **no counterpart
to either**. Its UTXO set is an LSM: reads go to run files through the OS page
cache (there is no DB read cache), and the in-memory table is a *write buffer*
of pending changes, not a coin cache, sized by mode — `-dbcache`-derived in
bulk catch-up, a fixed 2^16 slots / 64 MB steady-state — in the download
worker, which the RPC side cannot see. Emitting `dbcache` or the memtable size
under these names would be an invented number with Core's label on it. The
omission is now a declared one in the frozen fixture test
(`declared_omission`) as well as in `CORE_DIVERGENCES.md`.

### Found, not fixed

- `unbroadcast` is a constant `false`. Core is `true` for a transaction its own
  RPC submitted until a peer requests it; this node keeps no unbroadcast set.
- `getmempoolinfo.bytes` is still the BIP141 vsize sum; v31.1 sums the adjusted
  entry size. Equal except for sigop-heavy transactions. The comment there
  keeps it independent of the policy registry on purpose, so it is left for a
  decision rather than changed in passing.
- `testmempoolaccept` (single-tx path) reports BIP141 `vsize`; v31.1 reports
  the adjusted one. `submitpackage` / package `testmempoolaccept` already
  report the adjusted size.
