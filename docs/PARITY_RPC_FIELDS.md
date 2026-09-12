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
