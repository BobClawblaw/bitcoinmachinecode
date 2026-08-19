# PLAN — Block-level script verification

Status: Written 2026-08-18. **Stage A and Stage B done, 2026-08-19** (legacy
SignatureHash complete, FindAndDelete, OP_CODESEPARATOR strip, dispatch
verified across P2PK/P2PKH/P2SH/bare-multisig) -- see "Stage B0/B1/B2 done"
and its "CLOSED" follow-up below. Stages C-E not started.

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

1. **`txval_modern` rejects every legacy script type.** Its dispatch chain
   (`bitcoin_txval_modern.c:193`+) handles P2WPKH, P2WSH, P2TR key-path, and
   falls through to `g_reason = "unsupported prevout script type"` → reject.
   No P2PK, P2PKH, P2SH, bare multisig, no tapscript path. Wiring it into
   block connection **as it stands would reject nearly the whole chain**:
   P2PK dominates the earliest blocks, P2PKH most of the history.

2. **Nothing joins legacy and witness into one per-input verifier.**
   `verify_script` is legacy-only — its signature takes `scriptSig`,
   `scriptPubKey`, `tx`, `nIn` with **no amount and no witness**, so it
   cannot do BIP143. `txval_modern` is witness-only. Consensus needs one
   entry point that dispatches both.

3. **Two interpreters.** `script_eval` (asm, all opcodes) and `eval_script`
   (C, private to `bitcoin_verify.c`). Only one can be the consensus
   interpreter. See Decisions below.

4. **No soft-fork activation schedule.** Script flags must be selected by
   block height (BIP16, BIP66, BIP65, CSV, segwit, taproot). Applying
   today's flags to a 2011 block would reject valid history; applying no
   flags to a modern block would accept what consensus forbids.

5. **No call from block connection**, and no coinbase skip / 100-block
   coinbase maturity check.

6. **No `assumevalid`.**

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

### Stage C — activation-height flag schedule
A pure `script_flags_for_height(h)` function. Heights **must be read out of
Core's `chainparams.cpp`, not from memory** — Core defaults were misremembered
twice already this session.
*Verify:* unit tests at each activation boundary (h-1 vs h), plus a
differential run against Core on real blocks straddling each fork.

### Stage D — connect it, and prove it against the real chain
Call the verifier from `apply_block_inner`, interleaved with UTXO
application; skip the coinbase; add the 100-block coinbase maturity check.
*Verify:* **replay the real archive** and require every block to validate.
This is the acceptance test that matters — ~1–2 hours on this box per the
measurement above, so it is affordable to run repeatedly. Any single
rejection is either a bug or a genuine chain-data problem, and both need
explaining before this ships.

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

## Stage A work item: error-code translation

The two interpreters use DIFFERENT ScriptError numbering, and the difference
is deliberate on the asm side.

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

Consequence for Stage A: making `script_eval` the consensus interpreter means
the seam must TRANSLATE asm error codes into Core codes, because the
differential harness compares error-for-error against the Core oracle.

Two options:
- **(preferred) translation table in the C seam.** Leaves the audited asm
  interpreter untouched, keeps one place where the mapping lives, and is
  directly testable: assert every asm code maps to the Core code of the same
  name, with a test that fails if either enum gains a member.
- renumber the asm to Core's values. Single source of truth, but edits a
  verified interpreter across many sites for no behavioural gain.

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
