# 2026-09-08 — Taproot script-path signing, proven under the consensus verifier

The compatibility register's last PARTIAL row said this node could not
produce a `PSBT_IN_TAP_SCRIPT_SIG` (0x14) of its own. That was stale: the
signer behind `descriptorprocesspsbt` and `walletprocesspsbt` has signed
`pk()` leaves, `multi_a` leaves and miniscript leaves since September 6,
exporting partial signatures as 0x14 keyed by `xonly || leafhash`, and
the test's own section 4 pinned a partial 0x14 for a `multi_a(2,...)`
leaf being completed by a second signer.

What nothing had proven was that the signatures are valid. The tests
checked the witness's shape. `test_rpc_psbt_taproot` now links the
consensus taproot verifier, the code that validates blocks, and runs
every spend the signer produces through it against the funding output
the PSBT declared: the key-path spend with a tree, the `pk()` leaf spend,
and the `multi_a(2, x0, x1)` spend assembled from two partial 0x14
signatures. All three verify.

The harness is calibrated both ways before it judges our signatures:
Core's own finalized script-path spend from `tests/psbt_tapscript_vec.h`
passes it, and the same transaction with one byte of the signature
flipped is refused. It was not right the first time, which is why the
calibration is there: the verifier takes the witness-stripped
serialization, as `tx_verify.c` hands it, and the first harness passed
the full one; Core's transaction failed too, which pointed at the harness
and not the signer.

The register row is DONE, and the work list's row 10 with it. No signer
code changed.
