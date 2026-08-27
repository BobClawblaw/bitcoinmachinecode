# Honest assessment: capability and speed vs Bitcoin Core

Written 2026-08-22, with the Stage D replay at height ~721,000 of a 963,000-block
chain. Speed numbers and their methodology live in `BENCHMARKS.md`; this document
is the judgement that the numbers alone do not carry.

The short version, stated before the detail so it cannot be skipped:

> **This is a consensus-verification engine, not a node.** It cannot replace
> Bitcoin Core for any real user today. On the one primitive that can be
> compared like-for-like it is within ~1.2× of libsecp256k1. Its end-to-end
> speed against Core has **never been measured**. Its consensus correctness is
> being actively established and is not yet established: **forty-two** defects
> have been found (as of 2026-08-25), at least **eight** of them in the
> chain-splitting direction, and the discovery rate is not yet decelerating.
> The most recent five were found *after* a clean genesis-to-963,000 replay,
> by differential testing against Core rather than by replaying — which is the
> point: a clean replay proves only that no real block was refused.

---

**Addendum 2026-08-25.** Two things changed materially since this was
written, one in each direction of the ledger. For capability: the UTXO set
is now proven **byte-identical to Bitcoin Core's** at height 963,967 —
MuHash, txout count, total amount and bogosize all exact, no read-time
filter, no overrides — and the node serves most of Core's RPC surface,
including `getblocktemplate`, `submitblock`, the mempool tranche over a
genuinely shared mempool, and the set-verification instruments as RPCs.
For humility: getting there surfaced four production incidents in two days
(`LOG.md` #43–#46) — a corrupt chainwork file, a non-Core RPC shape, a
live-counter drift of +7.89M with a crash-window root cause, and a
duplicate-append race on the live node. All four are root-caused, fixed and
regression-tested, and all four existed in production first. The summary
judgement below stands; the capability section under-claims.

**Addendum 2026-08-27.** The capability ledger has moved substantially again;
the summary judgement's *spirit* still holds (end-to-end IBD speed vs Core is
STILL unmeasured, so "not a drop-in node" remains true) but several specific
"cannot do" lines below are now false. Landed since 08-25 (all in `main`,
evidence in `FEATURE_GAPS.md`'s 2026-08-27 update):

- **RPC parity is complete** — all methods and all five subsystems (155/155,
  2026-08-26). The "largest gap by a wide margin" line in §2 is fully retired.
- **The full indexing tier exists** — txindex (base + live tail),
  coinstatsindex (incremental MuHash, instant `gettxoutsetinfo`),
  blockfilterindex (BIP157/158).
- **Mempool is a real mempool** — consensus-verifier admission, Core-style
  TrimToSize feerate eviction, dynamic `mempoolminfee`, config-wired limits,
  and receive-side tx relay with an orphan pool. (This also fixed a live
  production freeze at exactly 4096 txs — a 43rd-plus incident, root-caused.)
- **Wallet-at-rest encryption** — AES-256 under Core's BytesToKeySHA512AES,
  proven byte-identical to OpenSSL.
- **Regtest chain selection, differentially proven** — this is the important
  one for §4's argument. The node now runs Core's regtest chain, and against
  a scratch Core regtest oracle it produced **161/161 identical block hashes**
  after syncing Core's chain, an **identical `gettxoutsetinfo` muhash**, and a
  block built from its **own `getblocktemplate` that Core accepted** via
  `submitblock`. That gives this project, for the first time, a *deterministic
  differential harness against Core* (regtest mines instantly) instead of only
  the mainnet replay — exactly the "differential testing against Core rather
  than replaying" §4 argues is the real correctness signal. The UTXO set is
  now proven byte-identical to Core on **two** chains (mainnet h=963,967 and
  regtest), not one.

What has NOT changed, and keeps the headline honest: end-to-end IBD speed vs
Core is still unmeasured (the benchmark in §5 remains un-run); wallet
management (multiwallet/descriptors/watch-only) is still absent; and the
defect-discovery process is the reason to trust the above — the regtest work
itself surfaced four latent bugs (a fresh-`headers.dat` off-by-one that would
have hit a fresh mainnet datadir too, a worker chdir splitting one chain's
state across two dirs, a connect-only peer-filter bug, and hardcoded ports),
all found by differential testing, none by replay.

## 1. What it can do

Real, and stronger than the project's age suggests:

- **Full script verification** — legacy, P2SH, segwit v0 (native and
  P2SH-wrapped), taproot key-path and script-path (BIP341/342), executed
  through one shared interpreter rather than shape-matched special cases.
- **The activation schedule**, including both of Core's hash-identified
  exception blocks.
- **A full-archive replay** with no `assumevalid`: every historical signature
  actually verified.
- **An LSM UTXO store** with WAL, crash recovery, compaction and an mmap read
  path, sustaining the replay at ~15 blocks/s through the taproot era.
- **P2P depth** — headers-first sync, compact blocks (BIP152), addrman,
  outbound peer management. `FEATURE_GAPS.md` rates this "stronger than
  expected".
- **Mempool acceptance with real policy checks.**

## 2. What it cannot do

From `FEATURE_GAPS.md`, and this list is the reason the headline above says
"not a node":

- **The RPC surface is the largest gap by a wide margin.** *(Retired
  2026-08-25 — see the addendum above; most of Core's API now exists, with
  per-method verification recorded in `docs/PARITY_PLAN.md`.)*
- **No mining support.** *(No longer true: `getblocktemplate`,
  `submitblock`, `prioritisetransaction` landed 2026-08-25 — template frame
  and retarget oracle-verified; the template's tx ordering is valid but not
  fee-optimal, and per-tx sigops is a documented lower bound.)*
- **No PSBT (BIP174).** *(No longer true: six methods since 2026-08-25,
  mostly oracle-byte-exact; the signer-gated three remain absent.)* No
  descriptor, multi-wallet, or watch-only wallets — still true.
- **No chain selection** — no testnet, signet, or regtest. Mainnet only.
- **No `blockfilterindex` (BIP157/158)**, so no light-client service.
- **No `coinstatsindex`/`gettxoutsetinfo`** ~~, which matters far more than
  it sounds — see §4~~ *(half-retired 2026-08-25: `gettxoutsetinfo` now
  exists as an RPC and as the standalone tool, and the §4 concern it stood
  for — proving the set — is settled: MuHash byte-identical to Core at the
  live tip. The incremental `coinstatsindex` itself remains absent; every
  measurement is a full O(set) walk.)*
- **No `txindex`.**
- **It has never served a peer at tip.** The keep-up serve path was crashing
  on the first block a peer pushed until today (incident #18), which means it
  had never been exercised in production at all.

## 3. Where it is genuinely fast

The honest ranking of what is known, from strongest evidence to weakest:

1. **`ecdsa_verify` vs libsecp256k1 — measured, same CPU, same moment.** The
   only true apples-to-apples comparison available. The gap has closed from
   5.5× slower to roughly 1.2× slower over two days of work. Our 4×64 field
   multiply now *beats* libsecp's 5×52 on latency and trails it on throughput.
2. **Internal speedups, measured against our own previous code**: the BIP143
   sighash path 27.4× on real blocks, the BIP341 path 18.8×, `ecdsa_verify`
   1.37×, end-to-end replay throughput 1.36× (a floor — see `PERF_SCOPE.md`
   §9). These say nothing about Core.
3. **End-to-end vs Core: unmeasured.** This is the number a reader actually
   wants and we do not have it.

**Why "faster than Core" would be an unsound claim even if the number came out
favourably:** Core with `-assumevalid=0` maintains a mempool, a block index,
chainwork, an addrman, an RPC server, P2P serving, and a chainstate it
obfuscates on disk. Our replay verifies blocks and applies UTXOs. Neither side
is a superset of the other, and the comparison is only meaningful with those
differences enumerated. `BENCHMARKS.md` states them per measurement.

There is also a handicap running the other way that is worth stating plainly:
**our UTXO set is not the same object as Core's.** We store ~22.2 million
provably-unspendable outputs that Core never writes to its chainstate — 77.2M
entries against Core's 55.0M at the same height. (As of 2026-08-23 this no
longer blocks the comparison — the entries are filtered out while iterating —
but they are still on disk, and still cost storage and compaction.) We are
doing measurably more
storage work for the same chain.

## 4. The correctness picture, which matters more than the speed

**Forty-two numbered defects** (`LOG.md`, incidents #1–#42; this section's
distribution analysis was written at #24 and the shape has held since; #39–#42,
added 2026-08-25, are an RPC memory-disclosure, an operator pkill that took down
production, the UTXO resume-REJECT window it exposed, and a handshake frame
overlap that blanked peer versions — memory-safety/liveness, not chain-split).
The
five most recent are worth separating out, because none of them was reachable
by replaying the chain: a `SETcc` that wrote eight bits where eleven numeric
opcodes needed sixty-four (**5,050 false-ACCEPT divergences** from Core across
generated scripts, #28); coinbase outputs that must overwrite and did not
(#29); **BIP30 tested by a shim that implemented it while the daemon did not**
(#30); a taproot primitive writing its loop counter onto its own saved
register (#31); and unbounded UTXO probe loops (#32). Core-running miners
never mined a block that exercises the first three.

The distribution is the interesting part:

- Most were **false rejects** — the safe direction. They stop the replay
  loudly and cost time, not correctness.
- **At least five were false accepts** — the chain-splitting direction: soft
  forks activating one block late (#6), a 521-byte tapscript stack item (#19),
  two BIP341 sighash shapes (#23, #24), and an unenforced BIP66 signature
  encoding rule found this evening and still being fixed.
- **Several were reachable only by asking Core, never by replaying the chain.**
  No such transaction exists in the chain, because Core-running miners never
  mined one. The replay could have run to tip, clean, with all of them still
  present.

That last point is the most important sentence in this document. **A clean
full-chain replay would not have proven consensus correctness.** It proves the
node accepts what the chain contains; it says nothing about what the node
would accept that Core rejects. The differential corpus work — asking Core for
the answer to thousands of constructed vectors — is what found the false
accepts, and that method has only been applied to a few paths so far.

**The acceptance test was weaker than it should be, and now is not.** Stage D's
criterion was "no block rejected". The criterion it *should* be is "UTXO set
byte-identical to Core's at height H", and as of 2026-08-23 that comparison
exists and has been run: `daemon/utxo_setinfo` plus
`validation/diff_utxo_setinfo.py` produce `txouts`, `total_amount`, `bogosize`
and a **MuHash3072** set hash over a filtered view of our LSM set, and diff them
against a live Core node at any height. **On the production datadir at height
792,979, all four match Core: 102,532,574 txouts, 19,393,405.70154310 BTC,
bogosize 7,739,642,957, and MuHash `e7e65c06...649e776a` — with two entries'
height field corrected for the BIP30 issue below. At height 91,721, before any
BIP30 duplicate exists, all four match with no correction at all.** The 22.2M unspendable-output divergence turned out not to
require the rebuild it appeared to: Core's `IsUnspendable` is applied while
iterating, so those entries stay on disk and stop counting.

The comparison immediately earned its keep, twice, in the way §4 predicts:
both findings are invisible to the count, the value and the size metric, and
visible only to the hash.

- **Incident #28 — BIP30 duplicate coinbases keep the wrong height.** Core's
  exception path calls `AddCoin(..., possible_overwrite=true)`, so its
  chainstate holds those two coins at heights 91,880 / 91,842. `utxo_lsm_put`
  returns "duplicate" and keeps the earlier copies, 91,722 / 91,812. Height
  feeds the 100-block coinbase maturity rule, so this is a **false-accept
  shape**: between heights 91,880 and 91,980 we would have accepted a spend
  Core rejects as immature. Proven exactly — overriding just those two heights
  reproduces Core's height-200,000 muhash byte for byte.
- **The genesis coinbase.** `utxo_live.c` excludes it and says why;
  `build_utxo.c` does not. Two writers for the same set, disagreeing.

Neither could have been found by replaying the chain, and neither was. That is
the fifth and sixth entry in the "reachable only by asking Core" column.

**The discovery rate is not decelerating.** Six of the twenty-four were found
today, in the last several hours, in code that had already been reviewed and
tested. Two more consensus divergences were found by a fixture agent in a path
that had just been rewritten. The reasonable inference is that more remain.

## 5. What would change this assessment

In rough order of how much each would move it:

1. ~~**A UTXO set hash matching Core at a given height.**~~ **Fully done
   (2026-08-25): MuHash byte-identical to Core at height 963,967 — the live
   tip — with no filters, no overrides, no corrected fields; the two
   divergences the earlier runs found were rebuilt away.** Nothing remains
   of this item.
2. ~~**The differential corpus method applied to every consensus path**, not
   the three or four it has reached.~~ **Extended 2026-08-25 to the surface
   that mattered most: SCRIPT EXECUTION on real mainnet spends.** Every
   block-level differential before it drove `cons_verify` (merkle, PoW,
   sizes, sigops) and never executed a script -- which is exactly why the
   SETcc false-ACCEPT was invisible to a clean full-chain replay.
   `validation/spend_corpus_diff.py` now runs real spends through the real
   verifiers on both sides across all five script eras and mutates them to
   force disagreement: **1,128 mutations, 1,128 agreements, zero
   divergences, zero false-accepts**. It remains the only method that has
   ever found a false accept here. **Deepened 2026-08-26 to exactly the
   per-path coverage this item asked for** (`validation/synth_corpus_diff.py`):
   because those constructs are rare or absent in random blocks they are now
   SYNTHESIZED and correctly signed rather than harvested -- multisig (bare /
   P2SH / P2WSH, with NULLDUMMY, signature-ordering and threshold mutations),
   CLTV and CSV (nLockTime / nSequence / tx-version predicate flips),
   OP_CODESEPARATOR (signing over the wrong subscript), and taproot
   script-path with and without an ANNEX. Core's own VerifyScript validates
   every synthesized spend before the comparison, so a construction error
   fails loudly instead of comparing garbage.

   **It immediately found a second false accept, and a worse one.** The
   BIP341 script-path commitment check compared only the tweaked output key's
   X coordinate and ignored the control block's low bit -- the tweaked key's
   Y PARITY, which Core verifies inside `CheckTapTweak`. Since Q = P + tG is
   one point, its x and its parity are both determined, so that bit was
   entirely unconstrained: flipping it on any otherwise-valid script-path
   spend produced a transaction this node ACCEPTED and Core REJECTED
   (`WITNESS_PROGRAM_MISMATCH`) -- a chain-split-direction false accept,
   reachable by flipping one bit of witness data, with no key material and no
   grinding. Fixed the same day, with a hermetic regression test
   (`tests/test_taproot_parity.c`) confirmed to FAIL against the old code. The
   exercise also exposed three frozen taproot vectors that hard-coded parity
   `0xc0` without ever computing it: they were never valid spends, and passed
   only because the verifier ignored the bit.

   **Breadth added the same day**, which is what that finding made the next
   bar: 35 synthesized features and 95 rule-targeted mutations, zero
   divergences. Every SIGHASH type (ALL/NONE/SINGLE x ANYONECANPAY) across
   legacy, BIP143 v0 and taproot key-path -- including taproot DEFAULT's
   64-byte signature form and the **SIGHASH_SINGLE bug** (input index past
   the last output, where the sighash is the constant uint256(1) and a
   signature over it is valid, so both engines must ACCEPT); P2SH-wrapped
   witness in both P2WPKH and P2WSH form, exercising the unwrapping rather
   than just the inner script; and multi-leaf taproot trees (2/3/4 leaves)
   whose control blocks carry a real merkle PATH, mutated by corrupting a
   sibling, truncating a level, flipping the parity, and substituting the
   wrong leaf script. The real-spend corpus re-ran clean alongside it (99
   spends / 594 mutations).

   Generalizing the sighash functions also corrected a latent harness error
   (the BIP341 SINGLE-output commitment matched NONE as well) that had never
   fired because only DEFAULT was previously exercised -- and one genuine
   harness artifact, where a P2SH scriptSig mutation reached Core but not the
   ASM shim, briefly looked like a false accept until the two engines were
   confirmed to be seeing different bytes. That is the standing hazard of
   this method and the reason every reported divergence is chased to its
   cause before it is believed.

   **The interpreter surface followed** -- the one this item named as the
   place the SETcc false accept originally lived. 7,797 bare-script probes,
   all agreeing with Core, driven by a different assertion from the spend
   synthesizers: most are deliberately invalid, so what is required is
   AGREEMENT rather than acceptance, which makes wide coverage cheap.

   The bulk is a systematic sweep of the arithmetic and comparison opcodes --
   every binary op over 25 boundary operands (sign changes, byte-width
   boundaries at 127/128/255/256/32767/65535/8388607, the CScriptNum 4-byte
   ceiling), plus the unary ops and OP_WITHIN's range boundaries. That is
   precisely the shape of the original bug: a wrong SETcc/movzx width flips
   the verdict for some operand pair and nothing else.

   The rest pins the structural rules an implementation can plausibly get
   wrong in the ACCEPT direction: disabled opcodes and the 201-opcode limit
   failing even in an UNEXECUTED branch (Core checks both before the fExec
   gate); OP_VERIF/OP_VERNOTIF always invalid while OP_RESERVED/OP_VER are
   fine when unexecuted; the 520-byte element and 1,000-element stack
   ceilings at their exact boundaries; unbalanced conditionals; CScriptNum
   4-vs-5-byte operands; and push-encoding edges. BIP342's OP_SUCCESSx is
   covered across every disjoint range of Core's own IsOpSuccess, including
   the cases that matter most -- OP_SUCCESS wins over an unparseable
   remainder, over an unexecuted branch, and over a preceding OP_RETURN --
   with opcode 186 (just below the range) asserted to still FAIL, so the
   boundary is proven rather than assumed, and an unknown leaf version
   succeeding after the commitment check alone.

   Two harness faults surfaced and were fixed, neither a node bug: an empty
   scriptSig sent as an empty whitespace-delimited field shifted every later
   field left (a wall of phantom divergences on the first run), and the
   negative cases needed explicit "Core must REJECT" support rather than
   being counted as construction failures.

   **Resource accounting followed, and found a THIRD false accept.**
   OP_CHECKMULTISIG's key count is charged to the 201-opcode budget in Core
   (`nOpCount += nKeysCount`, then the limit re-check); this interpreter
   validated the count against MAX_PUBKEYS_PER_MULTISIG but never charged it.
   Ten 0-of-20 multisigs are ten opcodes and two hundred keys -- 210, over the
   limit -- and verified here while Core rejected them with
   SCRIPT_ERR_OP_COUNT. Accept direction again, and 0-of-N checks no
   signatures, so no key material was needed to build one. Fixed in
   `bitcoin_interp.asm`, with `tests/test_multisig_opcount.c` pinning the
   9-vs-10 boundary (a fix that merely rejected multisig-heavy scripts would
   fail the nine case) and confirmed to FAIL against the unfixed code.

   The rest of the resource surface agrees: MAX_SCRIPT_SIZE at exactly
   10,000/10,001, MAX_PUBKEYS_PER_MULTISIG at 20/21, and -- the cases most
   likely to be got wrong by reusing the legacy limits -- the two that
   tapscript does NOT inherit. Core gates both the 10,000-byte bound and the
   201-opcode limit on (BASE || WITNESS_V0), so the SAME bytes must be legal
   as a tapscript and rejected as legacy; both directions are asserted.
   OP_CHECKMULTISIG(VERIFY) is confirmed disabled in tapscript. BIP342's
   validation-weight budget is swept across its boundary (1..15 sigops
   against a single duplicated signature) WITHOUT hardcoding where the
   boundary falls -- Core defines it, and both engines must simply agree,
   which they do, at 10.

   Standing totals for this item: 74 synthesized spend cases, 95
   rule-targeted mutations, 7,805 interpreter probes, zero divergences, on
   top of the real-spend corpus. Three consensus bugs found by this method in
   total, all in the accept direction, none reachable by sampling real blocks.
3. **A measured, fairly-controlled end-to-end comparison against Core with
   `-assumevalid=0`.** Until then, no end-to-end speed claim should be made.
4. ~~**A full replay to tip, clean**~~ — **done (2026-08-25): the
   full-verification rebuild reached the live tip.** Necessary, and — as
   this document said — demonstrably not sufficient, which is why item 1
   mattered more.
5. ~~**Serving at tip without crashing**, which has never happened.~~
   **Happening (2026-08-25): the node serves at tip and follows the network,
   through multiple deliberate restarts and one live incident (#46, a
   duplicate-append race) in which the daemon did NOT crash — the verify
   layer refused the bad block and the node kept serving in a bounded
   degraded loop until the one-block remedy.** The honest residue: hours of
   at-tip service so far, not months.

## 6. Summary judgement

The engineering is real and the performance work is real: on the primitive
that can be compared honestly, this is within ~20% of the reference
implementation, having been 5.5× behind two days earlier. The verification
architecture handles the whole modern chain — segwit, taproot, script-path
spends at inscription scale — on real data.

But **"can it replace Bitcoin Core" is not a close question today**: no
multiwallet/descriptor wallets, no testnet, no light-client indexes, an RPC
surface that (as of 2026-08-25) now spans blockchain/util/live-node/mempool/
mining/PSBT/submit but still lacks the wallet-management tranche and
RPC-side spending,
and a node that until today crashed the first time a peer pushed it a block.
And **"is it consensus-correct" is an open question**, not a settled one, with
at least eight known chain-split-direction defects found so far (incidents
#33–#42, added 2026-08-24/25, are liveness and memory-safety rather than
chain-split: a keep-up failure, four cons_verify buffer-cap errors two of
which smash the stack on peer data, a `connect=` flag the fallback path
ignored, an RPC memory disclosure, a UTXO resume-REJECT window, and a handshake
frame overlap) and a discovery
rate that has not levelled off — the most recent found by differential testing
*after* a clean full-chain replay, which is the strongest available evidence
that a clean replay is not the finish line it looks like.

The right characterisation is: a fast and increasingly capable **consensus
verification engine**, in the middle of the work that would establish whether
it is actually correct.

---

**Addendum 2026-08-27 (late).** A full day of feature work is the sort of
thing that tempts a document like this to soften. It should not: the day's
evidence STRENGTHENS the summary judgement above rather than weakening it.

Roughly a dozen defects surfaced in one session, in code that had passed the
suite. The instructive part is the split by how each was found:

- **The full suite found what reading could not** — a new test wired into the
  Makefile as an *argument* to another test, so it never ran while the suite
  stayed green; a duplicated object that meant the daemon would not link; a
  call added to a widely-linked object that broke ten targets; a JSON-RPC 2.0
  notification answering with a body when its method failed.
- **Differential reading against Core's source found the rest** — a fee-bump
  that overpaid because it rounded the base feerate up *and* applied Core's
  compensating `+1`; and four C-vs-asm declaration mismatches, one of which
  silently discarded every result of a new RPC.

Two of those only became visible *because* an earlier fix gave a
previously-infallible code path a real failure mode. That is the same
mechanism as the 08-25 finding: the defects were always there; nothing had
yet asked the question that exposes them.

One live defect is worth naming plainly, because it is the shape of thing
this document exists to be honest about. `gettxout` returned `null` for every
outpoint on the production node. `null` there does not mean "I don't know" —
it means "that output is not unspent". The node had been confidently
asserting that **every coin in existence is spent**, and no test caught it
because the RPC had never been asked on a node that could answer.

Against that, one real consensus gap closed: `nBits` schedule enforcement
(`bad-diffbits`), verified against every header of the real mainnet and
testnet4 chains. Before it, a peer could serve headers claiming any
difficulty; only cumulative-work fork choice contained the damage, and
containment is not validation.

Net: capability keeps moving, end-to-end speed vs Core is **still**
unmeasured, and the discovery rate is **still** not decelerating. The
judgement stands.
