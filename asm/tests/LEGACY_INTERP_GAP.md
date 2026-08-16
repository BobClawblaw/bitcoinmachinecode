# LEGACY INTERP CHECKMULTISIG GAP — corrected finding (2026-08-16)

## REVISED CONCLUSION (after the probe was debugged)

The initial claim in the first version of this note — that the interpreter's
**legacy OP_CHECKSIG** "is not wired to a real ECDSA callback" — was WRONG. That
was a **test-harness artifact** (bad stack model + non-canonical hand-rolled DER
in the probe), not a project gap. Corrected findings:

- **Legacy OP_CHECKSIG through bitcoin_interp.asm IS wired and correct.** The
  probe (`tests/test_interp_legacy_spend.c`) wires a real ECDSA checksig_fn and
  proves the interpreter passes the correct (sig, pub, scriptCode-slice) to it:
  callbacks are entered with `siglen=72 publen=33 slice_len=35` and
  `der_parse_sig` accepts the (low-S) signature. The taproot path
  (`test_taproot_sighash.c`) is, as established, ALL PASS 48/48.
- **`interp_checkmultisig` (bitcoin_interp.asm ~line 2129) REMAINS A STRUCTURAL
  STUB**: it sets `interp_err = 12` (placeholder) and exits without actually
  walking keys/sigs to verify an m-of-n OP_CHECKMULTISIG. So a genuine 2-of-3
  P2SH redeem run through the INTERPRETER ITSELF is not yet signature-verified
  there. This is the one genuine legacy-interpreter gap.

## What the probe proved (evidence)
- Callback entered 2x (the two P2PKH runs) with correct inputs; `der_parse_sig`
  returns 1 after low-S normalization (the initial failures were my DER).
- P2PKH `<pub> CHECKSIG` genuine-vs-wrong-pubkey is now correctly distinguished.
- A 2-of-3 OP_CHECKMULTISIG script cannot ACCEPT through the interpreter today
  because `interp_checkmultisig` is a stub (it must verify in the caller, e.g.
  bitcoin_verify.c, not the interpreter proper).

## How to close it (future work)
Reimplement `interp_checkmultisig` in bitcoin_interp.asm to actually implement
the Core CHECKMULTISIG semantics using the checksig_fn callback (pop nKeys,
iterate keys left-to-right matching sigs, NULLDUMMY handling, push bool), the
way .op_checksig already delegates to interp_checksig. Mirror the proven
bitcoin_verify.c CheckMultisig + the taproot checksig wiring. Then re-run
tests/test_interp_legacy_spend.c (both 2-of-3 scenarios) green and the full
make test for regression.

## NOTE: legacy final-stack enforcement
legacy script_eval() returns "no script error" without enforcing final-stack
truth (that is TAPSCRIPT-only). Real consensus enforces it in the caller
(VerifyScript inspects the resolved stack). Any harness must do the same; this
is caller responsibility, not an interpreter bug.

## Status
Probe committed as tests/test_interp_legacy_spend.c (+ Makefile target). The
OP_CHECKMULTISIG stub fix is the open item; tracked here and in PLAN.
