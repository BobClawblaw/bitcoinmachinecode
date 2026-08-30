# PLAN — Block-level script verification

> **Status 2026-08-27.** Complete and in production. Stage E (assumevalid,
> then production), described below as "not started", is done: the verifier
> runs in the live mainnet daemon and the node has followed the tip
> unattended for days. Regtest chain selection later re-proved the same
> verifier on Core's regtest chain (identical block hashes and UTXO muhash).
> The rest of this file is the historical plan-of-record.

Status: Written 2026-08-18. **PLAN COMPLETE — Stage D's end state achieved
2026-08-25:** the from-genesis, full-verification rebuild reached the live
tip and the resulting UTXO set was proven byte-identical to Bitcoin Core's
(`gettxoutsetinfo muhash` at height 963,967: count, amount, bogosize and
MuHash all exact, with no filters and no overrides — the acceptance test
this plan was written to reach; see `README.md` Status and `LOG.md`).
Original status trail follows.

 **Stages A, B, and C done, 2026-08-19** (legacy
SignatureHash complete, FindAndDelete, OP_CODESEPARATOR strip, dispatch
verified across P2PK/P2PKH/P2SH/bare-multisig, activation-height flag
schedule) -- see "Stage B0/B1/B2 done", its "CLOSED" follow-up, and "Stage C
done" below.

**Stage D: wired, replaying, not yet DONE (2026-08-22).** Verification is
connected to block connection and running its acceptance test -- a full
from-scratch replay of the real mainnet archive. The replay was restarted
from block 0 at 02:40 UTC on 2026-08-22 after incident #6 (genesis absent
from the archive, every buried soft fork one block late) invalidated the
previous attempt; it is now past ~386,000 of 963,446 with every fix below
deployed, at 4.4-5.7x the throughput of the 08-21 baseline over identical
heights (`PERF_SCOPE.md`). At 481824 it found incident #10: the archive was
witness-stripped for the whole segwit era; the UTXO checkpoint at 481823 is
valid, the ~482k affected blocks are being re-fetched from the local Core
oracle, and the replay resumes from there. See the Stage D section for
incidents #1-#10.
**Caveat learned from #6:** a clean replay cannot detect a rule applied too
*loosely* -- real chain data is valid under the strict rules too -- so
"every block validated" is necessary, not sufficient. Stage E
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
| Segwit/taproot tx validator | `bitcoin_txval_modern.c:174` → `txval_modern`; block path `daemon/tx_verify.c` → `sv_verify_witness_v0` / `taproot_verify_input` | P2WPKH, **general P2WSH via `script_eval`**, **P2SH-wrapped P2WPKH/P2WSH** (`11f7aa9`), P2TR key-path **and script-path** (BIP342 incl. annex, `OP_CHECKSIGADD`, `OP_CODESEPARATOR` position — `e789df8`, `b2ccb2d`, 2026-08-21) |
| Legacy sighash | `bitcoin_sighash.asm` | done |
| BIP143 sighash | `bitcoin_segwit.c` | done |
| BIP341 sighash | `bitcoin_taproot_sighash.c` | done |
| ECDSA / Schnorr verify | `secp256k1_ecdsa.o`, `secp256k1_schnorr.o` | done, optimised (adcx/adox `fe_mul`) |
| UTXO lookup by outpoint | `utxo_lsm_get` via `mempool_resolve_confirmed_utxo` | done, real set (the `placeholder_utxo` pointer in tx_accept is ignored by design) |
| Differential harness vs Core | `validation/core_verify_oracle.cpp`, `consensus_diff.py`, `tests/consensus_shim`, `tests/verify_p2sh_shim` | exists and is used |
| Core oracle | scratch instance from the **source build** `/storage/bitcoin-core-source/build/bin/` at `/storage/core-oracle` (RPC 8335, `txindex`+`coinstatsindex`) | running since 2026-08-21; the production install `/storage/bitcoin` is off-limits |

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

*(Historical: the 2026-08-18 measurement that sized the plan. As of
2026-08-22 `ecdsa_verify` is ~39 µs and the replay runs 4.4–5.7× the 08-21
baseline — see `PERF_SCOPE.md` §5 for current numbers.)*

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
| 202471 | FATAL: apply_block failed (no reason logged -- pre-dates per-input REJECT reasons) | Pre-Stage-D LSM manifest-cap deadlock: `utxo_live_catchup` only called `utxo_lsm_compact()` once, at the end of its loop, so a from-scratch replay flushed far more runs than `UTXO_LIVE_MANIFEST_CAP` was sized for and `utxo_lsm_put`/`del` started returning -1 (fatal) partway through. Root-caused via git history, not log content (this run predates per-input REJECT reasons): `646c3cf`'s own commit message describes hitting the identical wall at height 202134 "tonight" (2026-08-18), landing ~5h after this exact log entry (12:21:39) -- two occurrences of the same architectural gap, not two bugs. | `646c3cf` |
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
| 318148 | "input references a missing/already-spent UTXO" on the first resume after deploying the LSM mmap read path | NOT the read path (exonerated on 80,000 keys from four real production runs). `systemctl stop` SIGKILLed the worker at 90 s because the catch-up loop ignored SIGTERM; the kill landed between block N's WAL writes and its checkpoint, and Stage D verifies before applying. Incident #8. | `f2faf3b`, `96b555e` |
| 481824 | "p2wpkh needs exactly 2 witness items" at the first segwit block | The ARCHIVE, not the verifier: every block >= 481824 was stored witness-stripped because `getdata` asked for `MSG_BLOCK`; the merkle root cannot detect it and this node had no BIP141 witness-commitment check. Incident #10. | `31eac9a`, `fe3addb`, `191df6c` |
| 481824 (again) | "p2wpkh signature invalid" once the block was witness-complete | Our BIP143 scriptCode for P2WPKH was the witness program, not the implied P2PKH script; the vector generator shared the mistake. Incident #11. First real P2WPKH spend ever verified by this node. | `b3800f0`, `b6c92fa` |
| 481825 | "legacy script verification failed" (input 1 is P2SH-P2WPKH) | Nested segwit not implemented; P2WSH verifier had two hard-coded shapes. Now general witness-v0 via `script_eval`, native + wrapped. Three bugs underneath: CHECKMULTISIG FindAndDelete not gated on BASE; legacy-input sighash in a mixed tx must use the stripped serialization; NULLDUMMY/sig-order in the synthetic vectors. Incident #12. | `11f7aa9` |
| 481827 | worker SEGFAULT (no reject line) | `segwit_v0_sighash` built the BIP143 midstate hashes into 4096-byte stack buffers; a 500-input tx needs 18,000. Same latent bug in the taproot aggregate hashes. Underneath: 12 MB static TLS on 2 MB default thread stacks (`LimitSTACK=infinity` makes glibc default to 2 MB). Incident #13. | `9445268` |
| 482566 | "p2wpkh signature invalid" on an ordinary 1-in/2-out native P2WPKH, after 742 witness blocks had passed | `in->wprog` pointed INTO the per-input scratch `g_txv_in[i].spk`, which Phase 1 keeps refilling for later inputs before Phase 2 verifies -- so the BIP143 program/scriptCode was read from clobbered bytes. Data-dependent, hence the 742-block delay. Fixed with a stable `wprog_off`. Incident #14. | `d4d7d7c` |
| 498787 | "too many witness items" on a routine 17-item P2SH-P2WSH spend | `TXV_MAX_WIT_ITEMS` was 8 and items lived in inline per-input arrays. No consensus rule caps the item COUNT at parse time (the real bounds are per-item 520 and MAX_STACK 1000). Now a growable pool addressed by per-input OFFSET, cap 1004. Incident #15. | `d1a2259` |
| ~775k-826k (predicted by the census before the replay arrived; reproduced at 806500) | "p2tr tapscript execution failed" on BIP342 script-path spends | `OP_CHECKSIGVERIFY` was routed to `.bad_opcode` under SIGVERSION_TAPSCRIPT -- BIP342 KEEPS CHECKSIG/CHECKSIGVERIFY and disables only CHECKMULTISIG(VERIFY), so HTLC-style leaves died before reaching their timelock. Second, too-permissive bug alongside it: the script-eval context was zeroed, so tapscript CLTV/CSV were gated off as silent NOPs. Incident #16. | `4dc5941` |
| (none -- telemetry only, never gates validation) | `live_utxo` logged NEGATIVE (-2610837) | reload re-derived `total_live` from the current memtable generation only, ignoring every flushed run (~51M too low), and tombstone deletes decrement unconditionally. Count now persisted runs-only in a versioned manifest and restored as base + WAL-tail net. Incident #17. | `72ee5f6` |
| (none -- structurally undetectable by replay) | every buried soft fork active one block LATE; false-accept | genesis absent from the archive: record index == real height - 1. Incident #6. | `5f36dee` |
| (none -- ~2^-64 per random operand) | wrong `s^-1` / affine x on structured operands; fail-closed | lost carries in `sc_mul` MULACC and `fe_mul` fold-2. Incident #7. | `54cc988` |

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

### Incidents #6-#13 (2026-08-22)
Narratives in `LOG.md`'s 2026-08-22 entry; one line each here. **#6** genesis
was never in the archive (record index == real height - 1), so
`script_flags_for_block` ran a block behind and DERSIG/CLTV/CSV/NULLDUMMY
each missed their own activation block -- false-accept, invisible to the
replay, fixed by injecting genesis from its constant (`5f36dee`; a
re-download could not have done it, peers serve from block 1). **#7** lost
carries in `sc_mul`/`fe_mul`, deterministic on structured operands, ~2^-64
on random ones (`54cc988`). **#8** every stop during a replay had been a
90 s SIGKILL (catch-up never read the shutdown flag); a kill in the
WAL-write->checkpoint window made the next resume re-verify an already-
applied block -- misattributed to the new mmap read path for an hour and
the first reproducer was destroyed by dropping state; fixed by honouring
SIGTERM per block (`f2faf3b`, stop now 10 s) and rolling back a partially-
applied block on boot from the undo log (`96b555e`, proved on real data at
343087 on first deploy). **#9** GLV's C helper segfaulted on the
CHECKMULTISIG path from an rsp misaligned by 8 -- caught by the suite
before deploy (`3b00f63`).

Every fix above is on `main` and pushed, and every one that changed
behavior (not the doc-only correlation work) has a regression test proven
(via `git stash` or an equivalent disable-the-fix check) to fail against
the pre-fix code with the real production failure signature and pass with
the fix. `bmc-bitcoind.service` is running its fourth from-scratch replay
(started 2026-08-22 02:40 after #6 invalidated the third), past ~386,000 of
963,446 with all of the above deployed, clean past every rejection height
in the table including 388431 and past the DERSIG boundary at its correct
height; **not yet DONE** -- the replay has not reached chain tip yet.
The real acceptance test beyond "no rejects" is UTXO-set-hash parity with
the scratch Core oracle (`gettxoutsetinfo`, `coinstatsindex` enabled there)
-- not yet possible, this node computes no such hash (`FEATURE_GAPS.md`).

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
  break at height 40/41 on the real archive) because the parallel chunked
  downloader writes blocks to disk in whatever order their downloads finish,
  not in height order. It does not block script verification, which reads
  via the index, not by physical position.

  **2026-08-21: TRUNCATION-FROM-THE-TIP fixed for this case; PRUNING is
  not, and is a separate, harder problem -- see below.** Both used to
  either refuse outright or (before `store_layout_monotonic`'s guard
  existed) risk a repeat of the ~600GB archive loss documented in that
  primitive's own header comment: physical `store_truncate_to` genuinely
  cannot be trusted on a non-monotonic archive, since it assumes a
  height's on-disk position tells you where all HIGHER heights' data
  starts, which is exactly false here.

  The fix is `store_truncate_index_only` (`bitcoin_store.asm`) +
  `archive_truncate_safe` (`daemon/archive_verify.c`): index.dat is
  positional-by-height by construction (record h always lives at byte
  h*48, independent of where that record's block DATA physically sits in
  the blk files), so shrinking it to drop heights above a target is
  unconditionally sound regardless of layout. `archive_truncate_safe` uses
  the physical, space-reclaiming `store_truncate_to` when the archive
  genuinely is monotonic below the target, and this index-only fallback
  otherwise -- at the cost of not reclaiming the disconnected heights'
  disk space (their bytes stay physically present, just unreachable via
  the index). That tradeoff is fine for what actually calls it: reorg's
  disconnect path (`daemon/reorg.c`'s `reorg_execute`) and this project's
  own duplicate/corruption self-repair (`archive_verify_and_repair`) --
  both truncate from the TIP going backward, and both are typically
  shallow (a handful of blocks), not the whole archive. Both now route
  through `archive_truncate_safe` and can make real progress on a
  non-monotonic archive instead of refusing. Regression-tested against a
  synthetic non-monotonic archive plus a normal monotonic one (no
  behavior change for the common case) in
  `tests/test_archive_truncate_nonmonotonic.c`.

  **2026-08-21: PRUNING fixed too**, via a third option neither (a) nor
  (b) above anticipated: whole-FILE-granular reclamation. `archive_prune_
  file_granular` (`daemon/archive_verify.c`) does one sequential
  `index.dat` scan to compute each `blk*.dat` file's min/max height, then
  deletes an entire file only when every block it holds is safely below
  the target -- real disk space reclaimed, no byte-range rewriting needed,
  no requirement that the archive ever become physically monotonic. The
  file holding the current tip is unconditionally protected. Wired as the
  `ARCHIVE_PRUNE_REFUSE_LAYOUT` fallback in `main.c`, alongside (not
  replacing) the existing scalar `prune_height` path for genuinely
  monotonic archives. Pruned records are marked with a distinct sentinel
  (`data_size = 0xFFFFFFFF`) from the all-zero "hole" marker used
  elsewhere -- reusing the hole sentinel would have made the downloader
  re-fetch every pruned block from peers on every boot, silently
  defeating pruning entirely; `store_get_at` (`bitcoin_store.asm`) gained
  the matching read-side check. Regression-tested in
  `tests/test_prune_nonmonotonic.c` against a synthetic non-monotonic
  multi-file archive (34 assertions: wholly-old files deleted, a
  straddling file retained whole, tip-file protection, idempotent
  re-pruning). Pruning remains strictly opt-in, matching prior default
  behavior. Mirrors Bitcoin Core's own real approach to this identical
  problem (Core also tolerates non-monotonic block files and prunes by
  whole file using per-file height metadata, not physical reordering).

  Separately, and not addressed here: making the downloader itself write
  in height order in the first place (so future archives are monotonic
  from the start) was considered and deliberately not pursued -- it would
  touch the performance-sensitive parallel download path for a benefit
  the index-only truncation fix above already captures for the case that
  actually matters (reorg/repair), while pruning would need the
  fine-grained fix above regardless of write order for any ALREADY
  non-monotonic archive (like the one currently in production).

- **Replay throughput vs. Core** — `PERF_SCOPE.md`. Scoped 2026-08-21
  (~53 % secp256k1 arithmetic, ~31 % kernel file-read path from the UTXO
  LSM's per-lookup bloom copies, NOT the non-monotonic archive); all three
  levers built, verified and deployed 2026-08-22: 4.2 A+B (`ecdsa_verify`
  115 -> 56 us), 4.1 mmap run cache (kernel share 31 % -> 5 %), 4.3
  GLV+wNAF (56 -> ~39 us). End-to-end over identical heights vs the 08-21
  baseline: 4.39x. libsecp256k1 measured at 21.8 us on this CPU; we are at
  ~1.65x of it. What remains is the 4x64 field multiply (`fe_mul` = 56 % of
  all cycles post-GLV); libsecp's 5x52 lazy reduction is the next lever.
