# LEGACY INTERP CHECKMULTISIG GAP — RESOLVED (2026-08-16)

## STATUS: CLOSED

The OP_CHECKMULTISIG stub in the ASM interpreter has been replaced with a real
implementation, and the probe now verifies genuine ECDSA spends end-to-end
through bitcoin_interp.asm. See history below for how this conclusion evolved.

## RESOLUTION
`interp_checkmultisig` (bitcoin_interp.asm) is now a full consensus implementation
that mirrors the Core-differential `bitcoin_verify.c` EvalMultisig layout and the
`check_multisig` matching loop exactly:

- Reads nKeys (stacktop 1) and nSigs (stacktop nkeys+2), validating 1..20 / 0..nKeys.
- Collects keys[]/sigs[] as live-stack references in the SAME order the C reference
  builds them (`stacktop(2+j)` = keys top-first; `stacktop(nkeys+3+j)` = sigs top-first),
  so the Top-sig-vs-Top-pub walk-down matching semantics are identical.
- Runs the Core matching loop via the ECDSA checksig_fn with the current
  scriptCode slice (interp_slice) for the sighash — identical to interp_checksig.
- Pops all operands (incl. the dummy) and pushes the boolean result.

## PROOF
`tests/test_interp_legacy_spend.c` now ALL PASS (6 checks, 0 failures):
  1. P2PKH genuine OP_CHECKSIG -> accept (real ECDSA)
  2. P2PKH wrong pubkey          -> reject
  3. 2-of-3 two valid sigs       -> accept (real ECDSA through the interpreter)
  4. 2-of-3 one valid sig        -> reject
  5. 2-of-3 wrong-message sig    -> reject
  6. raw-limb sign->verify roundtrip (controls the primitives)

No regressions: test_verify_p2sh (C oracle), test_interp (40 vectors),
test_taproot_sighash (48), test_ecdsa, test_point, test_scalarmul_ct,
test_tapscript_interp, smoke_interp all still pass.

## Debugging history (honest record)
- Initial "legacy OP_CHECKSIG not wired" claim was WRONG: a test artifact.
- The OP_RETURN (gerr=3) seen in the 2-of-3 runs was a BUFFER OVERFLOW in the
  probe (sc2[80] held a 105-byte script) — masked the interpreter entirely.
- The genuine sig "not verifying" was a DER byte-order bug in the probe's
  limb->BE serializer (v[0] is the LEAST significant limb; its low byte goes at
  the END of the BE value). Fixed to mirror wallet_core limbs_to_be32.
- With these probe bugs fixed, both the wiring AND the implementation verify.

## Remaining caveats
- NULLDUMMY strict enforcement and the sig-public-key-encoding checks
  (check_sig_encoding / check_pubkey_encoding) are not duplicated in the
  interpreter path here; they are caller/flag responsibilities, as documented
  in the code. The Core-differential bitcoin_verify.c path enforces them.
- This validates the interpreter's CHECKMULTISIG matching logic. Differential
  fuzzing across key/sig orderings is a reasonable follow-up card.
