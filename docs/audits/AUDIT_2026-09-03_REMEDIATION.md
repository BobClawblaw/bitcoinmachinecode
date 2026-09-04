# Audit 2026-09-03 — remediation log

Companion to `CODEBASE_AUDIT_2026-09-03.md` (182 findings; 29 distinct
CRITICAL+HIGH after de-duplication). This file records what has been fixed,
what has not, and what was found along the way.

**Status as of 2026-09-04 (third pass): all 29 CRITICAL+HIGH closed, and 43
of the 44 MEDIUM addressed (41 closed outright, 2 partial).** MEM-3, the last
CRITICAL+HIGH, is on branch `mem3-parent-overflow`. VAL-5 and UTX-4, both
previously partial, are complete apart from UTX-4's undo-file fsync.

**The remainder is larger than those numbers suggest, and this log should say
so plainly.** The audit has 182 findings. The 29 CRITICAL+HIGH and 44 MEDIUM
are 73 of them; **the 65 LOW and 32 INFO -- 97 findings, more than half the
audit -- have never been examined at all.** "All CRITICAL+HIGH and 43 of 44
MEDIUM" is true and is also the flattering way to say it.

The one MEDIUM still open is **NET-10** (the address manager has no bucketed
structure), which is a design change rather than a defect fix: Core's addrman
keeps separate tried/new tables, buckets `new` by source group so no single
source can fill more than a bounded fraction, and resolves collisions by
test-before-evict. This node has one flat 65,536-entry array evicting by
peer-supplied timestamp.

The full gate passes end to end. Two tests are quarantined with reasons a
reader can check (`test_outbound_mux`, `test_redial` -- both feed
regtest-difficulty blocks to a mainnet-params daemon, which VAL-11 correctly
refuses; bisected to `19e59df` in a throwaway worktree, and pre-existing).
Every fix in this log carries a regression test and a NEGATIVE CONTROL: the
fix was reverted and the test observed to fail before the commit landed. Four
of those negative controls found the test rather than the fix -- vacuous
fixtures that passed either way -- and one of them (CRY-4) does not fail an
assertion at all, it segfaults, which is the defect.

Counted against the audit's own §2 priority ranks: closed are ranks 1-5, 6,
8, 11-19, 20-22, 24-28; partial are 7 and 10; open are 9 (in part), 23, 29.

**Findings the remediation itself produced, all caught by the gate and fixed:**
the `val_read_tx` output-section regression in §1 (a consensus break on every
segwit block, found on `main`); a Makefile rule placed above the variable it
uses, three times, which only `link-check` catches; a pre-push hook written as
an allow-list of one identity, which silently blocked every push; and the
canonical-CompactSize change landed on the C parser but not its assembly twin
(§4.3). Two defects were found while writing tests for other findings and are
fixed here though the audit never listed them: `find_header` never saw the
last header line (a request body in a second TCP segment was a parse error,
and an Authorization header sent last got a 401), and `test_redial` had been
red since VAL-11 without anyone noticing, because the gate aborted at
`test_outbound_mux` first.

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
locktimes). Cherry-picked onto `main` as `70b2666`, so the warning above is
discharged: `main` no longer carries the regression.

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

### Closed in the second pass (2026-09-04)

| Finding | Sev | What it was | Commit |
|---|---|---|---|
| VAL-4 (BIP68) | HIGH | Relative timelocks absent from block connect; the nLockTime half was `ead4067` | `c954682` |
| MEM-1 | HIGH | `nLockTime` never decoded on the admission path; no finality or BIP68 in the mempool | `6079099` |
| VAL-5 (rest) | HIGH | No timestamp floor, 2-hour ceiling or legacy-version rules on headers | `a456bd4` |
| STO-1 (rest) | HIGH | Disconnect persisted its applied height once, after the loop; a crash left an unrepairable state | `355c37e` |
| MEM-4 | HIGH | Full claims/outreg tables silently registered nothing, so double-spends went undetected | `13b4a65` |

**VAL-4 and MEM-1 together close the last "we accept what Core rejects"
divergence of the finality kind**, on both the block and the mempool path,
sharing one implementation (`daemon/seqlocks.h`) so the two cannot drift.

Three of these needed a test correction that the negative control caught:

* **MEM-4's first fixture was vacuous.** With 1-input transactions the node
  table and the claims table fill together, so the node-slot check refused
  first and disabling the fix changed nothing. Four-input transactions make
  claims outrun nodes, which is the actual shape of the defect; the control
  then shows 6 transactions accepted with only 8 of their 24 inputs
  registered.
* **STO-1's first fixture was coinbase-only**, so it wrote no undo files at
  all and could not reach the state under test while appearing to run.
* **MEM-4's first placement stole other rules' reasons**, breaking
  `test_truc_policy`; it belongs at the commit boundary, not in the prechecks.

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

* **VAL-11 broke `test_outbound_mux`, and it is the fixture that is wrong.**
  With the gate running, a third failure surfaced. Bisected to the exact
  commit: `ca48c8d` passes, `19e59df` (VAL-11) fails.

  VAL-11 added Core's `CheckProofOfWork` range checks, including the per-chain
  powLimit. `tests/test_outbound_mux.c:71` mines its synthetic chain at
  `nBits = 0x207fffff` — regtest difficulty — while the node it spawns
  (`bitcoind serve-test`) runs with **mainnet** params, whose powLimit is
  `0x1d00ffff`. The node now correctly refuses every fixture block, so its tip
  stays at −1, nothing is stored, and the three assertions about serving and
  growth fail. The node's own log shows the handshake succeeding and
  `shutting down: tip=-1`.

  **The code is right and the test is stale.** Fixing it means giving the
  spawned daemon regtest params (its config lookup is `<datadir>/../config/
  bitcoin.conf`, outside the test's work directory, so this needs a `-conf=`
  argument threaded into the `execv`) or re-mining the fixture at a
  mainnet-valid target, which is not feasible at mainnet difficulty. Left
  OPEN — it is a test-fixture rework, not an audit finding.

  Sibling daemon e2e tests are unaffected: `test_ibd_full`, `test_keepup`,
  `test_shared2` and `test_bitcoind_sync` all pass.

**Three gate failures, three different causes, all hidden by the same broken
`prereq-check`.** Two were stale assertions left behind by correct consensus
fixes; one was the `prereq-check` defect itself. None was a live consensus
bug — but none could be seen either, which is the point.

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

* **MEM-3** — the only CRITICAL+HIGH not closed. The 24-parent cap silently
  truncates `parent[]`, and descendants are discovered only through it, so
  replacing or evicting the 25th parent orphans the child in the pool. **The
  audit's first suggested fix is wrong for this codebase** — see §2 — and the
  naive alternative was measured, not estimated: raising `MPOL_MAX_PARENTS` to
  63 grows `mpol_node` from 184 to 336 bytes, **+152 MB** of shared policy
  state at the default 1,048,576-node sizing. The real fix is out-of-line
  parent storage, a layout change to a `MAP_SHARED` region several processes
  map, and it wants its own pass. MEM-4, the sibling table-overflow defect,
  is closed (`13b4a65`).

* **NET-3** — the inactivity bound is in (`05c979b`), so the DoS is capped at
  20 minutes per slot. Core's `AttemptToEvictConnection` is NOT implemented,
  so at capacity this node still refuses rather than evicting.
  `-peertimeout` also remains unwired: it is Core's CONNECT timeout, and
  repurposing it as an idle interval would be a fresh divergence (DMN-3).

* **VAL-5** — the fetch path enforces all of it (`a456bd4`); `reorg_analyze`
  is not yet wired to the same rules.

### 4.2 CRITICAL+HIGH: none open

**VAL-5 is now fully closed.** Its remaining half -- Core's
ContextualCheckBlockHeader trio on the REORG path -- landed after the boot
fetch and block-connect halves. `reorg_analyze` checked PoW, linkage and the
nBits schedule but not time-too-old, time-too-new or bad-version, so a
candidate chain carrying such a header was judged on WORK alone and, if it
won, every one of its blocks was connected. Armed by the daemon next to
`reorg_set_pow_rules` and default-off for the hermetic suites, with the
median-time-past read through the same composite header reader
`pow_check_bits` already uses for the retarget window.

**MEM-3 (HIGH) -- the 24-parent cap. CLOSED** on branch
`mem3-parent-overflow` (`80f66c6`), kept off the main batch branch because it
changes a MAP_SHARED layout and deserves to be reviewed on its own.

The two cheap options were both tried and both fail, which is why the finding
sat open through the earlier passes:

* *Reject when a transaction has more in-pool parents than can be recorded*
  rests on Core's PRE-v31 25-ancestor CHAIN limit -- which is what the old
  code comment cited. This node implements v31 CLUSTER limits (64
  transactions), under which a child of 63 parents is legal and Core accepts
  it. Implemented, and reverted: it fails this project's own
  `test_mempool_policy` case "child C joins them: cluster of exactly 64
  accepted".

* *Raise the cap to 63 inline* was measured, not estimated: `mpol_node` grows
  192 -> 348 bytes, **+156 MB** at the default 1,048,576-node sizing.

* *Have getblocktemplate verify each input resolves* would close the dangerous
  OUTCOME rather than the cause, but `rpc_chain.c` reaches the mempool through
  injected hooks and has no UTXO view -- it cannot tell "this parent
  confirmed" from "this parent vanished", which is exactly the distinction the
  check needs.

**What landed instead:** the audit's remaining option, out-of-line storage.
The first 8 parents stay in the node and the rare node needing more borrows a
fixed block from a pool appended after the node array. The node SHRINKS
192 -> 128 bytes, and the pool (one block per eight nodes, a deliberately
pessimistic ratio) costs 27.5 MB -- a **net 36.5 MB saving** against the
layout it replaces, and 192 MB cheaper than 63 inline. All twenty `parent[]`
access sites go through accessors; overflowing 63 is refused as
`too-large-cluster`, which is the rule such a transaction actually breaks.

Three things each cost a debugging round and are worth knowing before touching
this again: the block must be released BEFORE `remove_node`'s swap-with-last
overwrites the slot; the availability check must run BEFORE the RBF evictions
in step 1a, or a failure repeats MEM-6's atomicity defect; and the refusal
reason matters, because the existing 64-parent case pins it.

The negative control reproduces the finding as an executable claim: against
the previous file the child reports 24 parents and SURVIVES its parent's
replacement -- the invalid-block path.

### 4.3 MEDIUM and below

44 MEDIUM, 68 LOW, 33 INFO in the audit. **Thirty-nine MEDIUM have been
addressed: 37 closed outright, and 2 partial** -- WAL-3 and NET-9, each with
its residual named in the row or the note below it. CRY-4 is now complete, and
SER-3's remaining piece is `bitcoin_tx.asm`'s structural walker, which both
acceptance gates in front of it now cover. LOW and
INFO are untouched.

(VAL-5 is a HIGH and is accounted for in §4.2, not here, even though its
remaining half landed in the same pass.)

| Finding | What it was | Commit |
|---|---|---|
| SCR-7 | CHECKMULTISIG read below the stack bottom | `c0941c2` |
| VAL-11 | `pow_check` had no powLimit / negative / overflow test | `19e59df` |
| SER-2 | `tx_parse` read length bytes before bounding the cursor | `fb96a89` |
| UTX-3 | `utxo_lsm_put` returned the zero-extended `0xFFFFFFFF` | `aadd750` |
| UTX-4 (part) | Checkpoint fsynced before the WAL it certifies | `82f10a8` |
| BLD-1 | `make clean` deleted a tracked source | `0c97799` |
| DMN-5 | Worker shutdown skipped `utxo_live_close()` | `aacd678` |
| WAL-5 | `wallet_cli init` overwrote an existing wallet silently | `aacd678` |
| NET-7 | `getdata` count parsed as one byte, unbounded walk | `9766158` |
| NET-8 | `getheaders` answered from genesis on an unknown first locator hash | `ed665fb` |
| MEM-11 | P2A outputs got the non-witness dust threshold | `dccaa57` |
| RPX-3 | `getaddressinfo` emitted a fabricated `pubkey`/`iscompressed` | `dccaa57` |
| RPC-1 | fd + response body leaked; `accept()` spun on EMFILE | `5f2a3e0` |
| DMN-6 | Serve children held the RPC listener and ignored SIGTERM | `5f2a3e0` |
| SER-4 | BIP152 read the tx count as one byte: no block with >=253 txs could be served | `4cd988c` |
| STO-8 | `getblockfilter` fell back to a prevout-less filter | `4cd988c` |
| WAL-4 | Wallet writes were not atomic and the temp file was world-readable | `cf57efa` |
| RPC-2 | The authenticated user was a process global across RPC threads | `cf57efa` |
| STO-7 | The mempool was never reconciled after a reorg: `reorg_mempool_reconcile` had no caller | `cbaeff6` |
| UTX-5 | A failed manifest publish deleted the merged run memory was already pointing at | `8bb4950` |
| STO-6 | `cfheaders`/`cfcheckpt` rewrote the count varint in place, producing an unparseable reply | `60d58c7` |
| UTX-6 | An unreadable or over-capacity manifest read as "no runs" and returned success | `a0cda89` |
| RPC-3 | `getpeerinfo.id` and `disconnectnode` used different numbering | `6e0c4ec` |
| RPC-4 | A slow, unauthenticated sender pinned an RPC worker indefinitely | `d13c7ea` |
| (unlisted) | `find_header` never saw the last header line: a body in a second segment was a parse error, and an Authorization header sent last got 401 | `d13c7ea` |
| MEM-7 | RBF accepted a replacement paying more in total at a fraction of the feerate | `204b9d8` |
| MEM-6 | The RBF eviction was applied even when the replacement could not be stored | `204b9d8` |
| MEM-13 | Dead blob bytes forced a spurious eviction and a 12-hour mempoolminfee bump | `204b9d8` |
| MEM-8 | Reorg reconcile left ghosts above 8,192 transactions | `204b9d8` |
| VAL-10 | Non-canonical CompactSize and a superfluous witness record both parsed | `e99bd1c` |
| SER-3 (part) | The shared C readers now enforce canonical CompactSize and MAX_SIZE | `e99bd1c` |
| CRY-4 (part) | The BIP39 passphrase had no bound; the HMAC key stayed in .bss | `e99bd1c` |
| DMN-4 | Config sections and `no` negation were not implemented | `e99bd1c` |
| BLD-2 | Four `_diff` harnesses took Core's bench block as a literal path and aborted the whole recipe without it | `cadb742` |
| WAL-3 (part) | The seed, the BIP39 passphrase and the wallet passphrase stayed in `.bss` after `walletlock` | `cadb742` |
| NET-6 | Closed by VAL-11: all five checks plus the `diff_target` clamp, and every caller it named now runs `pow_check` | `19e59df` |
| UTX-4 (rest) | A torn WAL tail was never truncated, so every later append landed after it and every future reload stopped there | `51447cb` |
| NET-9 (part) | The one-byte BIP152 tx count was SER-4; the documentation claiming "both directions" is corrected here. The RECEIVE side has never existed and is a feature, not a fix -- `bitcoin_serve.asm` writes `cmpctblock`/`blocktxn` and has no inbound handler for either | `4cd988c` + docs |
| MEM-9 | Inv processing was O(entries x table) with no per-peer bound: ~10^8 byte-compares per message, 64 messages per pass, in the download worker | `045ef64` |
| MEM-10 | Inbound peers could force unbounded re-fetch and re-verification: no memory of an already-refused transaction | `4989ff0` |
| WAL-2 | The spend path told the signer every coin was P2WPKH, so every non-bech32 coin was unspendable while listunspent said otherwise | `f04a52b` |
| WAL-3 | Secrets survived `walletlock` in `.bss`, and could reach swap, hibernation or a core file | `cf57efa`, `9f992b6` |
| STO-5 | `submitblock` and an inbound serve child appended through the UNLOCKED `store_append`, at a cached file position | (this commit) |
| MEM-12 | Policy tables hash-indexed (accepts flat, 250x at 80k) and block connect batched (O(n) not O(n*m), 5x at 260k) | `44f6064`, `6f89c24` |
| CRY-4 | SHA-512's schedule and HMAC's key block were process-global .bss: two threads corrupted each other silently | `54aa254` |
| SER-3 | The mempool admission reader accepted non-canonical CompactSize, so a transaction Core cannot deserialize could be relayed from here | `fdea2f1` |

**MEM-12 is now fully closed**, and the numbers scope both halves. The audit's
verdict was "CONFIRMED for complexity; timings PLAUSIBLE (not measured)", so
`tests/bench_mempool_scale.c` was written first.

*Accepts* were exactly linear in pool size and are now flat -- 250x at 80,000
entries, and the gap widens with every entry added:

| entries | us/accept before | after |
|---|---|---|
| 10,000 | 12.6 | **0.7** |
| 40,000 | 74.6 | **0.6** |
| 80,000 | 151.6 | **0.6** |
| 260,000 | (~490 extrapolated) | **0.7** |

*Block connect* needed a different fix, and the middle column below is why:
indexing the lookups barely helped, because `remove_node` is O(n) whatever the
lookups cost -- three of its steps are full sweeps, not lookups -- and it ran
once per confirmed transaction, so an m-transaction block cost O(n*m). Marking
the whole block and compacting ONCE makes it O(n + links):

| entries | original | indexed only | **batch** |
|---|---|---|---|
| 10,000 | 4.02 ms | 2.31 ms | **0.99 ms** |
| 40,000 | 15.77 ms | 8.55 ms | **4.80 ms** |
| 80,000 | 33.41 ms | 17.92 ms | **8.04 ms** |
| 260,000 | (~107 ms) | 158.14 ms | **31.02 ms** |

The O(n) claim is checked directly rather than asserted: a TEN TIMES larger
block costs the same -- 7.91 ms for 200 transactions against 8.03 ms for
2,000, at 80,000 entries.

The batch had to preserve the distinction between Core's `removeForBlock` (a
CONFIRMED transaction leaves alone; its children stay) and `removeRecursive`
(a CONFLICTED one leaves with its descendants). Two bugs came from getting
that wrong, both caught by the existing suite: a single-level mark swept the
children of every confirmed transaction, and -- less obvious -- a confirmed
transaction CLAIMS ITS OWN INPUTS, so `find_claim` answers with the
transaction itself. The per-transaction path never saw the second, because
`remove_confirmed` had already deleted those claims by the time it looked.

The child-index alternative was costed and not taken: threading a reverse
index through the existing parent slots needs a parallel `next` array of the
same shape, growing the node 128 -> 160 bytes and the overflow pool 27.5 ->
55 MB -- about +60 MB, erasing the saving this work otherwise makes. Batch
removal needs no new storage at all.



**A regression this pass produced, and caught.** `e99bd1c` enforced canonical
CompactSize in the three shared C readers and left
`bitcoin_txv_parse.asm`'s `RDCS` macro alone. The two parsers are compared
case-for-case by `tests/test_txv_parse_diff`, so the gate over that commit
went red with 339 mismatches -- one for every fixture shape emitting
`fd 03 00` for a length of 3. `main` was red between `e99bd1c` and `cadb742`.
Recorded because it is the second time this pass that a change to one side of
a differential was landed without the other, and because the gate is what
found it: no reviewer would have.

**NET-6 needs no separate change: VAL-11 closed it.** The audit asked for
Core's four `CheckProofOfWork` checks and a clamp on `diff_target`'s
out-of-buffer write; VAL-11 implemented all five (`fNegative`, mantissa 0,
`fOverflow` in each of its three forms, the armed chain `powLimit`, and the
`e3 >= 32` clamp) and `tests/test_pow_check.c` pins them. NET-6 also listed
three callers that skipped the schedule: the boot header fetch is PoW-gated by
VAL-5 (`141c786`), `reorg.c`'s `headers_chain_valid` calls `pow_check`
directly, and `.do_block` reaches it through `cons_verify`. Recorded here
rather than left in the open column, because "closed by another finding's fix"
is a different thing from "not done".

**DMN-2 is materially closed by the same work.** Its failure scenario -- a
peer answering the boot `getheaders` with 2,000,000 zero-work headers -- needs
headers that pass no PoW check, and VAL-5 now gates every one before
`hst_append` with the armed mainnet `powLimit`. Forging that many headers at
mainnet difficulty is not a thing an attacker does. What DMN-2 asked for and
is still absent: the nBits retarget schedule on the boot path, and a
second-peer cross-check before extending `index.dat` by a large span.

Each has a regression test and a verified negative control, on the same terms
as the CRITICAL+HIGH work.

**A fourth stale assertion turned up here.** `test_rpc_wallet_ops` asserted
*"pubkey stays empty for an address we cannot sign for"* — pinning RPX-3's
defect rather than Core's behaviour, which is to omit the field entirely. That
makes four tests found this pass that encoded behaviour a later fix had
deliberately changed (SCR-5's 253-byte reject, VAL-11's powLimit fixture,
`test_outbound_mux`'s difficulty, and this one).

**UTX-4's second half is now closed too.** A torn WAL tail is truncated on
reload: the replay records where each record starts, and on the path taken by
a short prefix, a short body or an unrecognised op byte it sets `log_len` to
that offset and `ftruncate`s the file there. Truncating to the CONSUMED offset
would not have worked -- a record whose 8-byte prefix reads cleanly and whose
op byte is unrecognised has already advanced the counter past itself, so the
cut would keep the very bytes that break every future replay. Undo files are
still unsynced, which is the remaining piece of UTX-4.

---

## 2026-09-04 — the last untouched HIGH, and a corrected accounting

This log had drifted from the tree. Three IDs (`DMN-1`, `MEM-2`, `UTX-1`)
appeared in the table while a second check listed them as outstanding, and
fixes that had landed (`SCR-6`, `CRY-1`) were never recorded here at all. The
authoritative check is git history, not this file. Re-running the 180 findings
against it, every CRITICAL and HIGH carries a commit except three:

| ID | Severity | Status after this pass |
|----|----------|------------------------|
| VAL-9 | HIGH | ALREADY CLOSED by SCR-5 (`17bf36b`) -- the same defect filed under two IDs. `daemon/tx_verify.c:416-424` writes a real CompactSize for the spent scriptPubKey run. Two comments (lines 376, 395) still say "one length byte" and are now stale. |
| NET-4 | HIGH | SUBSTANTIALLY CLOSED by `141c786` plus VAL-5/VAL-11: `dlc_fetch_headers` PoW-gates every header before `hst_append`, checks the nBits range, applies the contextual rules, and bounds both the page count (`cnt > DLC_HDR_PAGE`) and the round count (1000). The zero-work chain the finding describes cannot be built once each header must carry real work. The minimum-chain-work floor is enforced on the reorg/connect path (`daemon/minchainwork.c`). |
| NET-5 | HIGH | FIXED HERE. |

### NET-5 — contextual header rules on the inbound-block path

`bitcoin_serve.asm`'s `.do_block` wrote a peer-pushed block to the durable
archive after exactly two gates: `cons_verify`, which is entirely context-FREE
(PoW against the header's own nBits, every tx parses, first tx is a coinbase,
merkle root matches), and `store_validates_prevhash`, which only asks that the
block extend our tip. Core refuses a header far earlier, in
`ContextualCheckBlockHeader`: the nBits RETARGET SCHEDULE for the height, the
median-time-past floor, the 2-hour future ceiling, and the BIP34/66/65
version rules.

Consensus was never at risk -- `daemon/utxo_live.c` re-checks the schedule when
a block is CONNECTED and would refuse it there. The ARCHIVE was. A block has to
extend our tip to reach this path, so a header Core rejects became our durable
tip at a height it can never connect at, and the node stalls behind it. That
stall is the confirmed half of the finding.

`serve_block_ctx_ok` (new `daemon/serve_hdrctx.c`) applies all four rules
before the append, and is INJECTED and default-OFF exactly like
`reorg_set_pow_rules` / `reorg_set_header_rules`, for the same reason: the
hermetic serve suites build synthetic chains with arbitrary bits, timestamps
and versions. `daemon/main.c` arms it after `chainparams_select`. A rejected
block is dropped and NEVER scored -- our verifier is not the reference, so a
false reject here must not ban an honest peer, the same reasoning the
`cons_verify` result above it already carries.

Gated by `tests/test_serve_block_ctx`: all four rejections with Core's own
reason strings, two accepts, and it OPENS with the unarmed negative control
(every rejected header is accepted while the rules are off), so removing the
gate makes the suite fail rather than pass vacuously.

**Two build-structure notes, both caught by the audits and not by review.**
The code first went into `daemon/tx_accept.c`, which pulled `pow_check_bits`,
`store_get_at` and `store_rd_fd` into nine unrelated targets -- `link-check`
named all nine. Splitting it into its own file fixed that. The object is built
at the REPO ROOT rather than in `daemon/` because
`scripts/makefile_link_audit.py:220` globs `*.o` and not `daemon/*.o`, so a
`daemon/`-local object is invisible to the link audit.

**And one self-inflicted regression.** Adding `bitcoin_pow_rules.o` to
`DAEMONOBJS` put it on nine link lines twice (`multiple definition of
pow_retarget_bits` and friends) -- straight past the Makefile comment at line
170 that says the object "lives HERE ONLY" in `DAEMON_RPCOBJS` for precisely
this reason. `link-check` stayed GREEN through it: it verifies every needed
symbol is supplied, not that none is supplied twice. Only the clean build
caught it, the second time this pass that a duplicate listing was invisible to
both incremental builds and the audits. It now lives in `DAEMON_RPCOBJS` and
`SERVEOBJS` (whose targets link no `DAEMON_RPCOBJS`), plus the two
`test_bitcoind*` rules, which link neither bundle.

Clean gate: 284 suites, 0 failures. prereq-check 461 rules, runlist-check 338
gated, link-check 412 rules, abi-check, callee-saved-check and clean-check OK.

### What remains

No CRITICAL, HIGH or MEDIUM finding is now unaddressed except `NET-10`, which
is scoped and deliberately not started (`docs/audits/NET-10_ADDRMAN_SCOPE.md`).
**67 LOW and 33 INFO findings have never been examined.**

**Correction (same day).** An earlier revision of this section, and the commit
message of `13d2317`, claimed `MEM-10` was half-wired -- that its filter was
attached and cleared but never consulted or populated. That was WRONG, and the
error was a grep for the wrong symbol names: the functions are
`serve_reject_has` / `serve_reject_note` (singular), not `serve_rejects_*`.
MEM-10 is fully wired and matches Core's `AlreadyHaveTx` / `m_recent_rejects`
semantics: `bitcoin_serve.asm:591` consults the filter before sending a
getdata, and `daemon/tx_accept.c` records a refusal at both final-verdict
sites (script failure, line 953; final policy failure, line 971), while
deliberately NOT recording the reconsiderable fee class (-28, which a CPFP
child can overturn) or missing inputs (-25, which the orphan pool re-tries).
The startup line reports a filter that does exactly what it says.
