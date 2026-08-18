# PLAN — Block-level script verification

Status: **scoped, not started.** Written 2026-08-18.

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

## Decisions needed before Stage A

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
