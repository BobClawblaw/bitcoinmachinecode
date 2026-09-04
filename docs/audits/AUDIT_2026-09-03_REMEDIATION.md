# Audit 2026-09-03 — remediation log

Companion to `CODEBASE_AUDIT_2026-09-03.md` (182 findings; 29 distinct
CRITICAL+HIGH after de-duplication). This file records what has been fixed,
what has not, and what was found along the way.

**Status as of 2026-09-04: 18 of the 29 CRITICAL+HIGH closed, 3 partial, 8
open. Everything MEDIUM and below is untouched** (one MEDIUM, UTX-3, was
closed because it sits on the same silent-coin-loss path as the HIGHs around
it).

Counted against the audit's own §2 priority ranks: closed are ranks 1-5, 8,
11-19, 24, 27, 28; partial are 6, 9, 10; open are 7, 20-23, 25, 26, 29.

This log is honest about the remainder rather than rounding it off; §4
enumerates every open item.

---

## 1. The thing to read first

**A consensus regression was introduced BY the remediation and is on `main`.**

`bd0e211` (VAL-1/VAL-2, 2026-09-03 22:12 UTC) added Phase 0.15 to
`apply_block_inner`, which calls `val_read_tx` on every transaction and
rejects the whole block when it returns 0. `val_read_tx` walked version, the
segwit marker and the inputs — and then jumped straight to the witness
sections, **never skipping the outputs**. The wire order is

    version | [marker flag] | n_in | inputs | n_out | outputs | [witness] | locktime

so the cursor was left on the output COUNT. For a segwit transaction the
witness walk then decodes the output section as witness stacks, runs off the
end, and returns `bad_shape` — which Phase 0.15 turns into
`bad-txns-prevout-null` and a **block rejection**. That is every mainnet block
since 481,824.

Verified against the compiled function rather than inferred: a real 223-byte
segwit transaction from block 700,038 returned 0.

**Production was never exposed.** The live node runs
`bitcoind.deploy-20260903av`, linked 16:15 UTC, six hours before `bd0e211`
landed; the deployed binary does not contain the Phase 0.15 reject string at
all. The next deploy from `main` would have stopped block connection dead.

Fixed in `b0c4231`, with `tests/test_val_read_tx.c` (26 checks over six real
mainnet transactions, segwit and legacy, from three eras, all with nonzero
locktimes). **That commit should reach `main` before any further deploy.**

Why no existing test caught it: nothing in the suite drives a real segwit
block through Phase 0.15. `test_val_connect`, `test_blk_dryrun`,
`test_witness_commitment` and `test_cross_tx_verify` all pass against the
broken walk, and still pass now. This is the audit's own §8 observation — *"the
test suite pins happy paths"* — landing on the remediation written for that
same audit.

---

## 2. Closed in this pass

| Finding | Sev | What it was | Commit |
|---|---|---|---|
| — | — | `val_read_tx` skipped the output section: every segwit block rejected (regression from `bd0e211`) | `b0c4231` |
| STO-2 | HIGH | BIP158 builder zeroed only 64 KiB of a reused buffer; longer filters inherited stale bits | `abb20d4` |
| UTX-3 | MED | `utxo_lsm_put` returned the zero-extended `0xFFFFFFFF`, so a failed WAL drain was not fatal and the coin was silently lost | `aadd750` |
| DMN-1 | HIGH | No single-instance lock on the datadir; two daemons became two archive/UTXO writers | `4941321` |
| MEM-2 | HIGH | `worst_chunk` hard-failed above 65,536 entries: byte-full pool wedged with no eviction and no fee-floor rise | `1846a39` |
| NET-2 | HIGH | BIP324 responder spun at 100% CPU forever on a partial v1 prefix | `51dd3c6` |

Every one of these has a regression test **and a verified negative control** —
the test was run against the reverted code and observed to fail (or, for
NET-2, to hang, which is the defect). A test that has never been seen to fail
proves nothing, and this codebase has been bitten by that before.

### Two results worth keeping

**STO-2: the live filter index is clean, and that was luck.** A scan of all
964,360 records in `data/main/bfilters.idx` finds exactly one filter over
65,536 bytes — height 826,052, at 66,745 bytes. Being the single largest
filter on the chain, it was the first and only write ever to reach past the
window, so the stale region it OR-ed against was still untouched zero. Its
bytes are byte-identical to the Core oracle's `getblockfilter`, and its stored
header matches Core's. **No rebuild of `bfilters.dat` is needed.** A second
>64 KiB filter anywhere on the chain would have been the first corruption.

**MEM-2's negative control reproduces the wedge exactly**: with the 65,536
ceiling restored, 919 consecutive "mempool full" refusals starting at entry
67,081, with `mempoolminfee` still reporting 0 — the audit's exact signature.

---

## 3. Closed earlier (2026-09-03, before this pass)

VAL-1, VAL-2, SCR-1, SCR-2, SCR-3 (all five CRITICALs), SCR-4, SCR-5/VAL-9,
SCR-6, VAL-6/SER-6, VAL-8/SER-2, VAL-11, CRY-1, CRY-2, NET-1, SER-1/WAL-1,
RPX-1 — plus SCR-7, a CHECKMULTISIG bounds defect found during remediation and
not in the audit.

---

## 4. NOT closed — the honest remainder

### 4.1 Partial

* **VAL-3** — the sigop budget landed as SCR-6 (`bad-blk-sigops`), but there
  is still **no block weight or serialized-size limit**. `MAX_BLOCK_WEIGHT`
  appears nowhere on the connect path. A 6,000,000-weight block is accepted
  here and rejected by Core: chain split.
* **VAL-5** — the boot header fetch now PoW-gates (`141c786`), but the MTP
  time-too-old / now+2h / legacy-version rules are still unenforced, in the
  fetch and in `reorg_analyze`. `141c786`'s own message says so.
* **VAL-7 / NET-5 / NET-6** — the header half is closed with a test
  (`test_pow_check`) and `pow_check_bits` runs on the apply path. Whether the
  raw archive-append of an inbound `block` push is gated has not been
  confirmed.

### 4.2 Open, CRITICAL+HIGH

| Finding | One line |
|---|---|
| VAL-4 / MEM-1 | No `nLockTime` finality or BIP68 sequence-lock check in block connect **or** mempool admission. Verified absent: `utxo_live.c:1194` parses the locktime with a comment naming `IsFinalTx`/BIP68, and nothing consumes it. Non-final txs enter GBT. |
| NET-3 / DMN-3 | No inbound inactivity timeout or eviction; `-peertimeout` unused. |
| UTX-1 | Generation tie-break resurrects spent coins after a partial prefix compaction (reproduced in the audit). |
| UTX-2 | A WAL reload that overfills the memtable is accepted as success; the first flush makes the loss permanent (reproduced). |
| STO-1 | Crash mid-reorg leaves the UTXO set rewound with an old applied height and no undo files; coinstats adopts it. |
| STO-3 | A missing undo file is read as "no spends": filter and address indexes go silently wrong after a >200-block catch-up burst. |
| STO-4 | Prune compaction assumes a monotonic layout above the prune height; a violation truncates retained block data. |
| MEM-3 / 4 / 5 | Parent links truncated at 24; claims/outreg tables drop entries when full; `TrimToSize` evicts the incoming tx's own parent. The pool holds txs whose inputs no longer exist, and GBT includes them. |

**VAL-4/MEM-1 is the one to do next.** It is the last remaining consensus
divergence of the "we accept what Core rejects" kind, it affects both the
block path and mempool admission, and `val_read_tx`'s locktime — the field it
would be built on — was returning garbage until `b0c4231`. Building
`IsFinalTx` on top of the pre-`b0c4231` walk would have produced a
confidently-wrong answer.

### 4.3 Open, MEDIUM and below

**All 145 of them** (44 MEDIUM, 68 LOW, 33 INFO). Nothing in this pass or the
2026-09-03 pass touched any. The audit's §5 step 9 — "everything MEDIUM and
below in the module reports" — has not been started.

---

## 5. The audit's §8 observation, restated

The audit wrote: *"no HIGH finding in this audit has a test."* That is now
partly false — every finding closed on 09-03 and 09-04 gained one. But the
eight open HIGHs in §4.2 still have none, and the regression in §1 is direct
evidence that the gap is not academic: a change written specifically to close
audit findings broke block connection for every segwit block, and 313 gated
harnesses did not notice.

The cheapest structural fix remains the one the audit named: drive **real
mainnet blocks** through `apply_block_inner` in the gate, not just through the
script verifier. `test_val_read_tx.c` is one transaction-level step toward
that; a block-level equivalent would have caught this in minutes.
