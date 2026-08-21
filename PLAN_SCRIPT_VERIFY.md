# PLAN — Block-level script verification

Status: Written 2026-08-18. **Stages A, B, and C done, 2026-08-19** (legacy
SignatureHash complete, FindAndDelete, OP_CODESEPARATOR strip, dispatch
verified across P2PK/P2PKH/P2SH/bare-multisig, activation-height flag
schedule) -- see "Stage B0/B1/B2 done", its "CLOSED" follow-up, and "Stage C
done" below.

**Stage D: wired and mid-replay as of 2026-08-21, not yet DONE.**
Verification is connected to block connection and running its own
acceptance test -- a full from-scratch replay of the real mainnet archive,
currently past height ~364,000 of 963,445 (see Stage D section below for
the full incident list: the replay has found and fixed real consensus bugs
directly, exactly as this stage's acceptance bar requires). Stage E
(assumevalid, then production) not started.

## The gap

This node accepts any block with valid proof-of-work, well-formed
transactions, a coinbase-shaped first transaction, and a matching merkle
root. It does **not** check that the transactions' signatures are valid.

Evidence, not inference:

- `cons_verify` (`bitcoin_cons.asm:4`) documents its own checks: PoW, tx
  parsing, coinbase, merkle root. No scripts.
- `utxo_live.c`'s connect path (`apply_block_inner`, line 243) walks each
  transaction with `utxo_walk_tx_io` and moves UTXOs. No validator call.
- `txval_modern` — the only real script/signature validator — is called from
  exactly one place: `daemon/tx_accept.c:189`, the **mempool** admission path.

So a miner willing to spend real hashpower can hand us a block whose
signatures are garbage and we will accept it and build on it. Proof-of-work
is a real cost, so this is not free to exploit, but it is a genuine consensus
gap rather than a tuning choice.

A second consequence: Core's `-assumevalid` exists precisely to bound the
cost of block script verification. We have nothing for it to skip, which is
why phase 5 parses the key only to warn.

## What already exists

Considerably more than a fresh start. The expensive, hard parts are built.

| Piece | Where | State |
|---|---|---|
| Full Script interpreter, **all opcodes** | `bitcoin_interp.asm` → `script_eval` | done; sigversion + Core flag word + pluggable `checksig_fn` callback |
| Core-parity `VerifyScript` incl. BIP16/P2SH | `bitcoin_verify.c:565` → `verify_script` | done for **legacy**; two-pass eval, P2SH sub-script, cleanstack, SIGPUSHONLY, Core `ScriptError` codes |
| Segwit/taproot tx validator | `bitcoin_txval_modern.c:174` → `txval_modern` | P2WPKH, P2WSH (CHECKSIG + one multisig form), P2TR **key-path only** |
| Legacy sighash | `bitcoin_sighash.asm` | done |
| BIP143 sighash | `bitcoin_segwit.c` | done |
| BIP341 sighash | `bitcoin_taproot_sighash.c` | done |
| ECDSA / Schnorr verify | `secp256k1_ecdsa.o`, `secp256k1_schnorr.o` | done, optimised (adcx/adox `fe_mul`) |
| UTXO lookup by outpoint | `utxo_lsm_get` via `mempool_resolve_confirmed_utxo` | done, real set (the `placeholder_utxo` pointer in tx_accept is ignored by design) |
| Differential harness vs Core | `validation/core_verify_oracle.cpp`, `consensus_diff.py`, `tests/consensus_shim`, `tests/verify_p2sh_shim` | exists and is used |
| Core oracle binary | `/storage/bitcoin/bin/bitcoind` v31.99.0 | available |

## What is missing

**As of 2026-08-21, items 1-5 below are DONE (verified against the current
code, not assumed) -- kept here as history of the original gap. Only item 6
(`assumevalid`) remains genuinely open, deferred to Stage E.**

1. ~~`txval_modern` rejects every legacy script type.~~ **DONE.** Stage D's
   dispatch (`daemon/tx_verify.c`'s `txvb_verify_one`) classifies each
   input's prevout shape and routes LEGACY (P2PK/P2PKH/P2SH/bare-multisig)
   to `sv_verify_script` (`bitcoin_scriptverify.c`), P2WPKH/P2WSH to the
   witness primitives, P2TR key-path to `taproot_keypath_verify` -- see
   "Stage D" below.

2. ~~Nothing joins legacy and witness into one per-input verifier.~~
   **DONE.** `txvb_verify_one` is that one entry point -- every shape
   converges on parsing `(z, r, s, Qx, Qy)` and calling the shared
   `ecdsa_verify`/Schnorr-verify primitives, dispatched per-input across the
   whole block (`tx_verify_block_connect_all`).

3. ~~Two interpreters.~~ **RESOLVED** in favor of the asm interpreter
   (`bitcoin_interp.asm`'s `script_eval`, via `sv_verify_script`) as the
   live consensus path, matching the project's asm-authored ethos.
   `bitcoin_verify.c`'s `eval_script` is demoted to differential-reference
   status only -- confirmed it is linked into `tests/test_scriptverify_parity`
   and no daemon build target (`asm/Makefile`). See the error-code item
   below for the numbering consequence of this choice.

4. ~~No soft-fork activation schedule.~~ **DONE**, Stage C (2026-08-19) --
   see "Stage C done" below.

5. ~~No call from block connection, and no coinbase skip / 100-block
   coinbase maturity check.~~ **DONE**, Stage D -- `apply_block_inner`
   (`daemon/utxo_live.c`) calls `tx_verify_block_connect_all` ahead of every
   block's puts/dels, skips the coinbase, enforces 100-block maturity.

6. **No `assumevalid`.** Still open -- Stage E.

## Cost — measured, not estimated

`tests/bench_ecdsa` (added while scoping, wired into the Makefile):

```
8,731 ECDSA verifications/s per core (114.5 us each)
1e9 signatures -> 31.8 core-hours -> ~2.0 h on 16 cores
```

This box has 32 cores. **Full-chain script verification is a 1–2 hour
parallel job here, not a prohibitive one.** That is the single most important
scoping result: `assumevalid` is an optimisation, not a prerequisite, and the
work can be sequenced with correctness first and speed later.

For reference, Core's libsecp256k1 achieves roughly 4–5x this per core, so
there is real headroom left in our implementation if it ever matters.

## Ordering constraint

A later transaction in a block may spend an output created by an earlier one
in the same block. Verification therefore has to be **interleaved with
application**, against a view that grows as the block connects — not run as a
pre-pass against the pre-block UTXO set.

`apply_block_inner` already walks transactions in order and mutates the UTXO
set as it goes, so it is the right shape. Verification belongs there, not in
the download path — which matters, because the parallel chunked downloader
writes blocks out of height order and has no usable UTXO view at all.

## Staged plan

Each stage is independently buildable, testable, and useful on its own.
Work happens on a worktree; nothing touches the running production daemon
until Stage E.

### Stage A — one verifier entry point
Define `txval_verify_input(tx, txlen, nIn, prev_spk, spklen, amount, flags,
sigversion) -> ScriptError`, dispatching legacy vs witness and delegating to
the chosen interpreter. No new script semantics — this is the seam that
stages B and C fill in.
*Verify:* existing `test_verify_p2sh`, `test_interp`, `test_taproot`,
`test_segwit_sighash` still pass through the new seam unchanged.

### Stage B — legacy script types
Dispatch P2PK, P2PKH, P2SH, and bare multisig to the interpreter with the
correct sighash. This is mostly wiring: `verify_script` already implements
Core's two-pass + P2SH semantics with Core error codes.
*Verify:* differential against `core_verify_oracle` over generated vectors
per type, error-for-error — the parity bar `bitcoin_verify.c` already set.

### Stage C — activation-height flag schedule -- DONE (2026-08-19)

Turned out NOT to be a pure `script_flags_for_height(h)` function -- reading
Core's actual `GetBlockScriptFlags` (`src/validation.cpp`) rather than
assuming the textbook "P2SH activates at height 173805" shape found
something the plan didn't anticipate: in current Core, P2SH/WITNESS/TAPROOT
are active from height 0 UNCONDITIONALLY, with exactly TWO historical
mainnet blocks -- identified by HASH, not height -- where Core overrides the
flags down to something weaker (one pre-BIP16, one pre-Taproot violation).
DERSIG/CLTV/CSV/NULLDUMMY (NULLDUMMY activates with segwit, BIP147) ARE each
independently height-gated the textbook way. So the real signature is
`script_flags_for_block(height, hash32) -> flags`.

This also meant an EXISTING function, `verify_flags_for_height` in the
demoted `bitcoin_verify.c`, was flagged and removed: it gated P2SH at a
hardcoded 173805 and applied DERSIG/CLTV/CSV/NULLDUMMY at every height
including 0 -- both wrong, and it was never called anywhere.

Implemented in `bitcoin_script_flags.asm`, reading `script_flags_consts.inc`
-- itself GENERATED, not transcribed, by `validation/gen_script_flags.py`
straight from Core's `kernel/chainparams.cpp` (the 4 heights + both
exception hashes) and `script/interpreter.h` (the `SCRIPT_VERIFY_*` bit
positions), self-checking that it can re-parse its own output (the same
discipline `gen_script_error_defines.py` already established, after a real
incident recorded in `ENGINEERING_RULES.md`) -- and the self-check caught a
real bug in this generator's own inconsistent column-padding before it ever
reached a test.

*Verified:* `validation/gen_script_flags_vectors.py` independently
re-derives expected flag values from the SAME Core source via a SEPARATE
extraction path (not from the .inc the implementation reads), covering the
h-1/h boundary of all four buried deployments, both extremes (nothing
active / everything active -- which lands on exactly `0x20e15`, matching
the pre-existing `FLAGS_MODERN` constant already used in
`test_scriptverify_parity.c`, an independent cross-check), and both
exception hashes (including a near-miss hash that must NOT trigger the
override, and an exception-hash block past all four height thresholds,
proving the height-gated bits still get ORed in on top of the override --
Core does this unconditionally, and a first draft of the vector generator
got this wrong before the test ever ran). `tests/test_script_flags.c`:
**13/13**. No live Core process used (ground truth from
`/storage/bitcoin-core-source` only, per this session's standing
constraint) -- the "differential run against Core on real blocks" the plan
originally called for was deliberately not done for that reason; the
source-derived + independently-cross-checked verification above is judged
sufficient. Full `make test` green, no regressions.

### Stage D — connect it, and prove it against the real chain
Call the verifier from `apply_block_inner`, interleaved with UTXO
application; skip the coinbase; add the 100-block coinbase maturity check.
*Verify:* **replay the real archive** and require every block to validate.
This is the acceptance test that matters — ~1–2 hours on this box per the
measurement above, so it is affordable to run repeatedly. Any single
rejection is either a bug or a genuine chain-data problem, and both need
explaining before this ships.

**IN PROGRESS (2026-08-19/20).** Wired: `tx_verify_block_connect_all`
(`daemon/tx_verify.c`, new file) runs from `apply_block_inner`, ahead of
every block's puts/dels, with the 100-block coinbase-maturity check and an
explicit whole-block duplicate-outpoint pre-check (see below). Made fast
enough to actually run a full replay: single-threaded verification measured
~1/32 cores in use, fixed via a sequence of profiling-driven changes (ELF-TLS
thread safety for the legacy interpreter, fork()->pthread, per-tx->
whole-block dispatch, persistent scratch arenas, a persistent worker pool)
— full detail in `worklog/2026-08-19.md` Session 4 and
`worklog/2026-08-20.md` Session 1.

A dedicated design-review pass (a `Plan` subagent, independent read of
`utxo_live.c`/`tx_verify.c`/the LSM store) caught a real correctness gap in
the initial whole-block-dispatch sketch before it landed: in-block
double-spend detection used to be an ACCIDENTAL side effect of the old
strictly-sequential verify-then-apply loop (the second spender's
`utxo_lsm_get` failed only because the first spender's output was already
deleted) — that accidental detection disappears once verification runs
before any apply. Fixed with an explicit whole-block duplicate-outpoint
check, required before verification starts, not an afterthought. Covered by
`tests/test_cross_tx_verify.c` (same-block chained spend accepts;
in-block double-spend rejects the WHOLE block, not a half-apply; a
many-tx block with a poisoned tx buried mid-list rejects at the correct
tx/reason under real parallel dispatch).

**A long tail of real bugs found and fixed by the live replay itself** —
exactly the "any single rejection ... needs explaining before this ships"
bar this stage exists to enforce. Full root-cause writeups for the first
three live in `worklog/2026-08-20.md` (Sessions 2-4) and `LOG.md`'s
2026-08-19/20 and 2026-08-21 entries. Every REJECT/FATAL height the replay
has hit across its whole history, height-ordered, with its cause and fix
(the last three columns reconstructed 2026-08-21 by correlating rejection
timestamps against fix-commit timestamps and message content, not
individually re-traced line-by-line -- flagged where confidence is lower):

| Height | Symptom | Cause | Fixed in |
|---|---|---|---|
| 202471 | FATAL, no recovery attempt | Pre-Stage-D, during the LSM live-wiring rework (2026-08-18); superseded by later work, not independently re-traced | — |
| 142998, 120000, 349021, 363897 | "input references a missing/already-spent UTXO" | **One root cause, four occurrences across three days**, not four bugs: `applied_height` was only persisted at rare compactions/end-of-call, so a crash could leave real durable state hours ahead of the checkpoint; resume then re-verified an already-applied block and its already-spent input looked fatal. See incident #5 below. | `2fd4a14` |
| 184390 | "legacy script verification failed", then (post-recovery) the same missing-UTXO symptom | Two stacked bugs: LSM compaction manifest-order inversion, then a dangling pointer into a realloc'd byte pool | `e12dcbb`, `4ec089c` |
| 212613 | "legacy script verification failed" | `OP_NOP1`/`OP_NOP4`..`OP_NOP10` treated as bad opcodes instead of no-ops | `757a377` |
| 243015 | "prevout script too large" | `TXV_SPK_CAP` capped at 252 bytes, below the real consensus max (10000) | `e5c8c08` |
| 251683 | "legacy script verification failed" | `OP_SIZE` 64-bit-load bug + `OP_SHA1` entirely unimplemented | `8caa5ac` |
| 256960 | "legacy script verification failed" | `OP_WITHIN` compared against a leftover pointer, not the popped value | `a62f032` |
| 269613 | "legacy script verification failed" | `stack_push`'s data pointer offset by `ELEM_DATA_OFF` too little | `b4cab22` |
| 290328 | "legacy script verification failed" | `CHECKMULTISIG` didn't strip ALL on-stack sigs from scriptCode up front | `d0f0339` |
| 299916 | "legacy script verification failed" | `CHECKMULTISIG` rejected `nKeys=0` instead of accepting it | `05015cb` |
| 324663 | "legacy script verification failed" | `OP_CHECKMULTISIGVERIFY` never popped-and-checked its bool | `670b6a7` |
| 349617 | "legacy script verification failed" | `sv_push_only`'s direct-push boundary excluded `0x4b` itself | `e1bdee2` |
| 388431 | "legacy script verification failed" | `CHECKLOCKTIMEVERIFY`/`CHECKSEQUENCEVERIFY` were wired as no-op stubs, not real BIP65/BIP112 checks | `fbeff60` |

### Incident #5 (2026-08-21): checkpoint could lag real durable state by an unbounded amount
The four missing-UTXO occurrences in the table above share one root cause,
finally isolated this session after being misattributed as one-off
oddities for two days: `utxo_live_catchup` persisted `applied_height` only
at compactions or once at the end of a (possibly hours-long) call, while
every `utxo_lsm_put`/`del` is durable the instant it runs. An unclean
process death (this occurrence: an unrelated HOST reboot, not a daemon
crash) could leave true durable state hours ahead of the last checkpoint;
resume then re-verified an already-applied block and treated its
already-spent input as fatal instead of a safe no-op. Fixed by persisting
`applied_height` after every block — correct by construction, no gap ever
exists to reconcile. New regression test
(`tests/test_utxo_catchup_crash_resume.c`) proven against the pre-fix code
via disabling the fix line; `make -k test` 1582/1582 both pre- and
post-merge. `2fd4a14`. Full writeup: `LOG.md`'s 2026-08-21 entry.

Every fix above is on `main` and pushed, and every one that changed
behavior (not the doc-only correlation work) has a regression test proven
(via `git stash` or an equivalent disable-the-fix check) to fail against
the pre-fix code with the real production failure signature and pass with
the fix. `bmc-bitcoind.service` is running its third from-scratch replay
attempt as of this writing (the first two were interrupted -- by the
CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY bug, then by the host reboot that
surfaced incident #5), currently past height ~364,000 of 963,445, confirmed
clean past every rejection height in the table above except 388431 (not yet
re-reached by this attempt, but independently confirmed clean once already
during the CLTV/CSV fix's own post-fix redeploy); **not yet DONE** — the
replay has not reached chain tip yet.

### Stage E — assumevalid, then production
Implement `-assumevalid` for real (skip script checks at or below the named
block, keep every structural check), and only then redeploy.

## Decisions taken (2026-08-18)

1. **`script_eval` (asm) is the consensus interpreter.** `bitcoin_verify.c`'s
   private C `eval_script` is demoted to a differential reference and
   eventually retired. This is the larger job and the one consistent with the
   project's central claim.
2. **`assumevalid` defaults OFF.** Full verification is the out-of-the-box
   behaviour. At ~1-2 h on this box that is affordable, and it is the
   stronger claim.
3. **Verification is inline in `apply_block_inner`.** The UTXO catch-up
   already runs as a sequential in-order pass over the archive, so inline
   verification IS the batch pass during IBD and becomes live verification
   for new blocks -- one code path serves both.

## CORRECTION to Stage B sizing (found while starting Stage A)

Stage B was scoped as "mostly wiring". That was wrong.

**Legacy signature hashing supports SIGHASH_ALL and nothing else.**
`sighash_all` (`bitcoin_sighash.asm:4`) is the only legacy sighash entry
point in the codebase and hardcodes `hashtype(4)=1` in the preimage. The
Core-parity `verify_script` rejects every other type outright:

```c
if ((hb & 0x1f)!=1) return 0;   /* bitcoin_verify.c:274 */
if (ht!=1) return 0;            /* bitcoin_verify.c:283 */
```

There is also **no FindAndDelete** implementation anywhere -- only
OP_CODESEPARATOR position tracking (`bitcoin_verify.c:454`).

BIP143 (segwit) sighash DOES handle the full set (`bitcoin_segwit.c:34`), so
the gap is specific to the legacy path.

Stage B therefore additionally requires, before any dispatch work:

- **B0. Legacy SignatureHash, complete.** SIGHASH_ALL / NONE / SINGLE, the
  ANYONECANPAY modifier, and the SIGHASH_SINGLE out-of-range quirk (when
  `nIn >= n_out`, consensus returns the hash `uint256(1)` rather than
  failing -- a real chain behaviour that must be reproduced exactly).
- **B1. FindAndDelete.** Pre-segwit consensus removes the signature being
  checked from the scriptCode. Rare on chain but real, and Stage D's
  "every block validates" bar means rare is not optional.
- **B2. OP_CODESEPARATOR scriptCode truncation.**

Each is a well-known consensus footgun with real chain data exercising it.
This is implementation in asm, not wiring, and it makes B the dominant stage
by a wide margin.

## Stage B0/B1/B2 done (2026-08-19)

Implemented in `bitcoin_sighash.asm` (asm, not C -- consensus semantics stay
in asm per the project's own rule): `legacy_sighash` generalizes
`sighash_all` (kept unchanged, still used by its existing callers) to every
legacy hashtype -- ALL/NONE/SINGLE x ANYONECANPAY, including the
SIGHASH_SINGLE-out-of-range `uint256(1)` quirk. Two shared primitives
(`script_op_len`, `script_find_and_delete`) implement Core's own
`FindAndDelete` exactly -- and turn out to BE the OP_CODESEPARATOR strip
too: Core's `SerializeScriptCode` is `FindAndDelete` with a needle of the
single byte `0xab`, so `legacy_sighash` calls the same primitive twice (once
by its caller, for the real signature; once internally, for codeseparators)
rather than needing separate logic. `script_push_encode` builds the needle
for real signature removal.

**Verification, in order:**
1. Hand-derived the exact algorithm from Core's C++ (`interpreter.cpp`'s
   `SignatureHash`/`CTransactionSignatureSerializer`, `script.cpp`'s
   `FindAndDelete`/`GetScriptOp`), then checked it in Python against Core's
   own **official 500-vector fixture**
   (`/storage/bitcoin-core-source/src/test/data/sighash.json`) *before
   writing any assembly* -- caught the byte-order convention (the fixture's
   expected hash is reversed relative to the raw sha256d bytes this codebase
   uses directly; settled empirically, not assumed) and validated the whole
   algorithm design cheaply.
2. `script_find_and_delete`/`script_op_len`/`script_push_encode` unit-tested
   against Core's own `BOOST_AUTO_TEST_CASE(script_FindAndDelete)` cases,
   transcribed from `script_tests.cpp` (`tests/test_find_and_delete.c`, 23
   checks).
3. `legacy_sighash` run against all 500 `sighash.json` vectors via a
   generated header (`validation/gen_sighash_vectors.py` ->
   `tests/sighash_vec.h`, consumed by `tests/test_legacy_sighash.c`):
   **500/500 pass.**
4. Wired into `bitcoin_scriptverify.c`'s `sv_checksig` (removed the
   SIGHASH_ALL-only gate; `der_parse_sig`'s own hashtype output turned out
   to be hardcoded to recognize only byte==1 too -- a leftover of the same
   era -- so the real hashtype now comes from the signature's own trailing
   byte, not that field). Proved END TO END through the real interpreter
   (`sv_verify_script`, not just the hash math) with genuine ECDSA-signed
   P2PK spends per hashtype, each paired with a tamper of a field that
   hashtype is supposed to ignore (must still ACCEPT -- proves the field is
   really unbound) and a tamper of a field it binds (must REJECT -- proves
   this isn't just accepting everything): `validation/gen_hashtype_vectors.py`
   -> `tests/hashtype_vec.h`, `tests/test_hashtype_e2e.c`, 11/11 pass. Also
   confirmed the SIGHASH_SINGLE out-of-range quirk reproduces (a genuinely
   signed degenerate `uint256(1)` hash verifies, matching Core's known
   behaviour).

Full `make test` green throughout (no regressions; `sighash_all` itself is
untouched, used unchanged by its existing ~15 call sites).

No live Bitcoin Core process was used anywhere in this verification --
deliberately: `/storage/bitcoin` (the production data/binary) was touched
only by an accidental `ls`/failed RPC probe early on and is now off-limits
for this work entirely; ground truth came from Core's own SOURCE and
bundled TEST FIXTURES (`/storage/bitcoin-core-source`), which this project
already treats as authoritative for Core facts.

**Stage B's "dispatch P2PK/P2PKH/P2SH/bare-multisig" item -- CLOSED
(2026-08-19).** The inference above (that `sv_verify_script`'s generic,
type-agnostic execution meant P2PKH/P2SH/bare-multisig were already covered
by the P2PK proof) is now a vector-checked fact, not an inference:
`validation/gen_hashtype_vectors.py` extended to P2PKH, P2SH(P2PK redeem),
and P2SH(2-of-2 multisig redeem), same genuine/tamper-unbound/tamper-bound
battery per shape, plus -- specific to multisig -- two co-signers using
DIFFERENT hashtypes on the SAME input (NONE + SINGLE), which is genuinely
separate coverage: `interp_checksig` and CHECKMULTISIG's `.cms_loop` build
their `interp_slice` at two different sites in `bitcoin_interp.asm`.
`tests/test_hashtype_e2e.c`: **38/38** (11 P2PK + 11 P2PKH + 11 P2SH-P2PK +
5 P2SH-multisig, incl. a wrong-key negative control proving 2-of-2 count
enforcement survives non-ALL hashtypes). Full `make test` green throughout.

**Next:** Stage C (activation-height flag schedule).

## Stage A work item: error-code translation -- RESOLVED (2026-08-20)

**Neither of the two options below was taken as originally framed.** The
project instead made `bitcoin_interp.asm` emit Core's own `SCRIPT_ERR_*`
values directly (the "renumber the asm" option, previously marked
NOT-preferred here) -- but mechanically, not by hand: `asm/script_error_codes.h`
is generated by `validation/gen_script_error_defines.py` from Core's own
`script_error.h`, and the asm interpreter includes/uses those generated
defines rather than a hand-typed enum. This sidesteps the original tradeoff
entirely -- "renumber by hand across many sites" was the risk that made a
translation table look preferable, and generation removes that risk without
paying for an extra seam.

This was **not** bulletproof on the first pass: the generator originally only
value-checked names the asm already had, so a name Core defines that the asm
simply never typed (`SCRIPT_ERR_CHECKMULTISIGVERIFY`) was invisible to it --
found the hard way when a real mainnet block needed exactly that code (see
Stage D's incident list, height 324663). Fixed in `9218101` to also walk
Core's enum and ADD missing names, not just verify existing ones. Now the
asm interpreter and Core are numerically identical for every current
`SCRIPT_ERR_*` name, checked by generation rather than by a comparison test
that itself could be hand-typed wrong the same way.

`bitcoin_verify.c`'s `eval_script`/Core-numbered scheme (the table below,
still accurate as history) is no longer the live consensus path either way
-- see "Decision 1" below, resolved in favor of the asm interpreter; `bitcoin_verify.c`
is linked only into `tests/test_scriptverify_parity`, a differential
reference, not the daemon binary (`asm/Makefile` confirms `bitcoin_verify.c`
appears in no daemon build target).

The two interpreters used DIFFERENT ScriptError numbering, and the
difference was deliberate on the asm side, at the time this was written.

Authoritative values, read from
`/storage/bitcoin-core-source/src/script/script_error.h` (Core v31.99.0):

| name | Core | `bitcoin_verify.c` | `bitcoin_interp.asm` |
|---|---|---|---|
| SCRIPTNUM | 4 | 4 | 18 |
| SCRIPT_SIZE | 5 | 5 | 4 |
| PUSH_SIZE | 6 | 6 | 5 |
| OP_COUNT | 7 | 7 | 6 |
| STACK_SIZE | 8 | 8 | 7 |
| BAD_OPCODE | 16 | 16 | 8 |
| INVALID_STACK_OPERATION | 18 | 18 | 16 |
| MINIMALDATA | 25 | 25 | 19 |
| SIG_NULLDUMMY | 28 | 28 | n/a |
| CLEANSTACK | 30 | 30 | 53 |

So `bitcoin_verify.c` matches Core exactly, and the asm interpreter uses its
own scheme -- including a private high range for tapscript-era codes
(TAPSCRIPT_MINIMALIF 50, TAPSCRIPT_CHECKMULTISIG 51, DISCOURAGE_OP_SUCCESS 52,
CLEANSTACK 53).

(Recorded because it was initially claimed the other way round, from memory,
before the header was read. The header is the authority; assertions about
Core's constants in this project must come from
`/storage/bitcoin-core-source/src`, never from recall.)

Consequence for Stage A, as originally framed: making `script_eval` the
consensus interpreter means the seam must TRANSLATE asm error codes into
Core codes, because the differential harness compares error-for-error
against the Core oracle.

Two options considered at the time:
- translation table in the C seam. Leaves the audited asm interpreter
  untouched, keeps one place where the mapping lives, and is directly
  testable: assert every asm code maps to the Core code of the same name,
  with a test that fails if either enum gains a member.
- renumber the asm to Core's values. Single source of truth, but edits a
  verified interpreter across many sites for no behavioural gain --
  **this is what actually happened, generated rather than hand-edited; see
  above.**

## Original decision list (now resolved -- kept for the reasoning)

1. **Which interpreter is consensus?** The project's stated ethos is
   assembly-authored with thin C wrappers, which argues for `script_eval`
   (asm, all opcodes) as the consensus path, with `bitcoin_verify.c`'s C
   `eval_script` retired or demoted to a differential reference. That is the
   cleaner end state and the larger job. The alternative — keep the C one,
   since it already has Core error-code parity — is faster but leaves the
   asm interpreter as dead weight and weakens the project's central claim.

2. **Do we ship a default `assumevalid` hash** as Core does, or default it
   off and make full verification the out-of-the-box behaviour? Off-by-default
   is the stronger claim and, at 1–2 hours, affordable here.

3. **Verify during IBD, or as a separate pass over the completed archive?**
   A separate pass parallelises trivially across 32 cores and keeps IBD
   throughput where it is; in-line verification is simpler and is what a
   real node does.

## Sizing

Comparable to the reorg work (Stages A+B of that took a full session each),
and consensus-critical in the same way. Rough shape: Stage A small, Stage B
the bulk of the script work, Stage C small but exacting, Stage D dominated by
replay time and by whatever the replay turns up, Stage E small. Decision 1
materially changes B.

## Related known issues

- The archive is **not laid out monotonically** (`[check]` reports the first
  break at height 41 on a test archive) because the parallel chunked
  downloader writes out of height order. This already blocks reorg
  truncation and pruning. It does not block script verification, which
  reads via the index, but it is the same underlying limitation and may be
  worth fixing in the same push.
