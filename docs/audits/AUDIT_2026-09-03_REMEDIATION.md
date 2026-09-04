# Audit 2026-09-03 — remediation log

Companion to `CODEBASE_AUDIT_2026-09-03.md` (182 findings; 29 distinct
CRITICAL+HIGH after de-duplication). This file records what has been fixed,
what has not, and what was found along the way.

**Status as of 2026-09-04 (overnight pass): 25 of the 29 CRITICAL+HIGH
closed, 3 partial, 1 open. Everything MEDIUM and below is untouched except
UTX-3** (one MEDIUM, UTX-3, was
closed because it sits on the same silent-coin-loss path as the HIGHs around
it).

Counted against the audit's own §2 priority ranks: closed are ranks 1-5, 6,
8, 11-19, 20-22, 24-28; partial are 7 and 10; open are 9 (in part), 23, 29.

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

### Closed in the overnight pass (2026-09-04)

| Finding | Sev | What it was | Commit |
|---|---|---|---|
| VAL-3 | HIGH | No block weight or serialized-size limit; a 6M-weight block was accepted here and rejected by Core | `c432c67` |
| VAL-4 (half) | HIGH | `IsFinalTx` / `bad-txns-nonfinal` absent from block connect; BIP113 median-time-past cutoff | `ead4067` |
| UTX-2 | HIGH | A WAL reload that overfilled the memtable counted as success; the next flush made the truncation permanent | `8e19d09` |
| UTX-1 | HIGH | Merge tie-breaks used generation, not manifest index: spent coins resurrected after a partial compaction | `1e25b02` |
| STO-3 | HIGH | A missing undo file read as "no spends": filters and the address index silently wrong | `36bcbbe` |
| STO-4 | HIGH | Prune guards checked only below the gate, the region `store_prune` never walks | `d725cc6` |
| NET-3 | HIGH | No inbound inactivity bound; 189 idle sockets refused every honest peer | `05c979b` |
| MEM-5 | HIGH | A high-feerate child could evict the parent it spends and be stored unlinked | `9510813` |
| STO-1 (part) | HIGH | An applied height ahead of the archive tip now halts loudly at boot instead of diverging silently | `4f0da7b` |

Every one carries a regression test and a verified negative control. Two are
worth singling out because the control reproduced the audit's own figures
exactly: UTX-2 returned `-2` with a count of 64, and UTX-1's walk visited 65
entries while the counter said 64, with key A returning live at value 999999
after a second compaction.

Two results found while fixing, not in the audit:

* **`val_read_tx` never walked the output section** (§1) — the segwit-block
  regression, found while scoping VAL-3.
* **`val_read_tx`'s `seqs[]` cap is unsafe for finality.** Its truncation rule
  treats surplus inputs as FINAL, which is right for BIP68 and exactly
  backwards for `IsFinalTx`, where missing a non-final input means accepting a
  block Core rejects. Finality now uses an exact flag set during the walk
  instead of reading the capped array.

---

### Two gate defects found by running `make test` end to end

Both predate this pass, and each was hiding the other.

* **`make test` was unrunnable.** `prereq-check` is the gate's FIRST target
  and had been failing since SCR-5 landed (`17bf36b`). All 17 findings were
  one rule: `tests/test_scr5_spkrun` uses `$(TAPSIGHASHOBJS)` 1,300 lines
  before it is defined, and Make expands a prerequisite list immediately while
  recipes expand lazily — so its prerequisites collapsed to just the `.c`
  file. It linked and passed while never rebuilding when the interpreter
  changed. Fixed in `bbb8990`; `prereq-check` now passes across all 443 rules
  for the first time.

* **SCR-5 left a stale assertion.** With the gate running, `make test` failed
  on `test_taproot_parallel_arena` section 5, which asserted that a
  >= 253-byte co-input prevout script is REFUSED — precisely the false reject
  SCR-5 removed as a consensus defect. Verified pre-existing by running it
  against `f725cb7` in a throwaway worktree, where it fails identically. The
  assertion was updated to the SCR-5 behaviour and inverted so a regression to
  the one-byte encoding fires it (`6021e94`). **No code changed.**

The pairing is worth stating plainly: a consensus fix shipped with a test that
contradicted it, and the tool that would have caught that was itself broken by
the same commit.

---

---

## 3. Closed earlier (2026-09-03, before this pass)

VAL-1, VAL-2, SCR-1, SCR-2, SCR-3 (all five CRITICALs), SCR-4, SCR-5/VAL-9,
SCR-6, VAL-6/SER-6, VAL-8/SER-2, VAL-11, CRY-1, CRY-2, NET-1, SER-1/WAL-1,
RPX-1 — plus SCR-7, a CHECKMULTISIG bounds defect found during remediation and
not in the audit.

---

## 4. NOT closed — the honest remainder

### 4.1 Partial

* **VAL-4** — `IsFinalTx` is enforced (`ead4067`); BIP68 `SequenceLocks` is
  not, on either the block or the mempool path. Doing BIP68 first would have
  been actively wrong: it is built on `vi->locktime`, which was returning
  bytes from the output section until `b0c4231`.
* **VAL-5** — the boot header fetch PoW-gates (`141c786`), but the MTP
  time-too-old / now+2h / legacy-version rules are still unenforced, in the
  fetch and in `reorg_analyze`. Note the MTP machinery now exists:
  `val_mtp()` landed with VAL-4 and is Core's `GetMedianTimePast`.
* **MEM-3 / MEM-4** — MEM-5 is fixed (`9510813`); MEM-3 and MEM-4 are not,
  and the reason is a finding in itself. **The audit's first suggested fix for
  MEM-3 is wrong for this codebase.** It proposes rejecting a transaction with
  more in-pool parents than can be recorded, "Core's pre-v31
  `too-long-mempool-chain` would fire at 25 anyway" — but this node implements
  Core v31 **cluster** limits (64 transactions / 101 kvB), not the 25-ancestor
  chain limit, so a child of 63 parents forming a 64-cluster is legal and Core
  accepts it. Implemented, it fails this project's own `test_mempool_policy`
  case *"child C joins them: cluster of exactly 64 accepted"* — a silent
  corruption traded for a false reject and a relay divergence.

  Raising `MPOL_MAX_PARENTS` to 63 was **measured, not estimated**:
  `mpol_node` grows 184 → 336 bytes, so the policy state grows **+152 MB** at
  the default 1,048,576-node sizing (184 MB → 336 MB) — not a silent change to
  a `MAP_SHARED` region several processes map. The real fix is the audit's
  second option, storing parents out of line, which is a shared-memory layout
  change and wants its own pass. MEM-4 (claims/outreg overflow) is the same
  shape and belongs with it.

* **STO-1** — the boot guard is in (`4f0da7b`): an applied height ahead of the
  archive tip halts loudly instead of appending a branch it never applies. The
  per-block ordering the audit asks for — `persist_applied_height(h-1)` →
  `unapply(h)` → `undo_discard(h)`, with an idempotent replay over the
  retained undo file — is NOT done. It changes the durability ordering of the
  UTXO set and needs a crash-injection test. The other crash window (applied =
  T with undo already discarded, so the set is at T−k while `tip == applied`
  and nothing looks wrong) is not detected by the guard and needs that
  ordering fix.

* **NET-3** — the inactivity bound is in (`05c979b`), so the DoS is capped at
  20 minutes per slot. Core's `AttemptToEvictConnection` is NOT implemented,
  so at capacity this node still refuses rather than evicting. `-peertimeout`
  also remains unwired: it is Core's CONNECT timeout, and repurposing it as an
  idle interval would be a fresh divergence rather than a fix (DMN-3).

### 4.2 Open, CRITICAL+HIGH

None outright. STO-1 is partial (below) and MEM-3/MEM-4 are partial; nothing
in the 29 is now completely untouched.

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
