test_interp_legacy_spend.c -- DIAGNOSTIC PROBE of the SO-far-uncovered gap.

PURPOSE: verify whether real LEGACY (ECDSA) OP_CHECKSIG / OP_CHECKMULTISIG
spends run through the ASM script interpreter (bitcoin_interp.asm) with a
GENUINE ECDSA checksig_fn wired in, the same way the taproot path is wired
(test_taproot_sighash.c wires a real schnorr fn and is ALL PASS).

FINDING (2026-08-16, empirical): THE LEGACY PATH IS NOT WIRED.
- checksig_fn was invoked only 2 times across all 6 runs; the standalone P2PKH
  OP_CHECKSIG runs never invoked it (cb_calls stayed 0 through them).
- Consequently `script_eval()` returns "no script error" for legacy (sigversion
  0) regardless of signature validity -- it does NOT enforce final-stack truth
  (that enforcement is TAPSCRIPT-only in the .final_ok path), and the sig
  callback isn't reached, so legacy OP_CHECKSIG acceptance/rejection is NOT
  actually signature-verified through the interpreter.
- Contrast: the taproot path (sigversion 2) IS fully wired + enforced, and
  test_taproot_sighash.c is ALL PASS (48/48) with a real schnorr callback.

So: a real legacy mainnet P2PKH/P2SH spend that must be verified by the asm
interpreter's own OP_CHECKSIG/OP_CHECKMULTISIG is not yet proven -- the correct,
audited legacy verification lives in asm/bitcoin_verify.c (bitcoin_verify.c
check_sig: sighash_all + der_parse_sig + pubkey_parse + ecdsa_verify, verified
differential vs Core in test_verify_p2sh), but it is NOT wired into the
interpreter the way the taproot callback is.

This file is a DIAGNOSTIC: it wires a real ECDSA checksig_fn (same audited
primitives as bitcoin_verify.c) and the P2PKH "genuine ACCEPT" passes when the
callback IS structurally reached, but the legacy path's non-enforcement and the
OP_CHECKMULTISIG structural stub (interp_checkmultisig sets a placeholder error,
line ~1794: "simplified structural implementation") mean the checks are not yet
ALL GREEN. The 2 known-failing checks (P2PKH corrupt-sig reject, 2-of-3 two-sig
accept) are the honest, reproducible evidence of the uncovered work.

CLOSING IT (future card): wire the legacy OP_CHECKSIG/OP_CHECKMULTISIG through a
real ECDSA checksig_fn in the interpreter and add final-stack enforcement for
legacy (or verify in the caller), mirroring the working taproot path. Until then
legacy spends through the interpreter are not signature-verified.
