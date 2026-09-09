# 2026-09-09 — No per-transaction input cap in the single-transaction verifier; the connect path proven capless

The audit of fixed ledgers on the block-connect path that followed the sequence-cap bug. The block-connect verifier (`tx_verify_block_connect_all`) already sizes its input ledger to the block, and a test now proves it: a 24,000-input transaction, the most a 4,000,000-weight block can carry at 41 bytes per input counted four times, connects. The single-transaction verifier (the mempool's path through `tx_verify_mempool`, and `txv_test_parse`) held its per-input table in a fixed 20,000-entry array and answered "input count out of bounds" above it. Core's `tx.vin` is a vector. The table grows to the transaction now, bounded by the transaction's own bytes; the constant is gone.

The rest of the audit, for the record:
- Bounds a valid block cannot reach, kept as buffer guards: witness items per transaction (4,000,000; one weight unit each), the tapleaf preimage (4 MB), the undo record script (10,000; a spent script larger than that fails Core's script-size rule and is never spent), the prevout script for evaluation (10,000; rejection matches Core's MAX_SCRIPT_SIZE outcome, tapscript takes its own path).
- Core's own rules, present and matching: stack 1000, element 520, ops 201, multisig keys 20, script 10,000, sigops cost 80,000, money range.
- Still open: the UTXO store's record keeps an output script's length in two bytes, so a consensus-valid output script longer than 65,535 bytes cannot be represented -- a record format change (version 3), scheduled. `submitblock` refuses a block above 16,384 transactions where a pathological valid block could hold 16,666 (mining path); compact-block receive falls back to a full block above 20,000 (harmless).

`test_txv_many_inputs` (new): 150 coinbases, a 24,000-output fan-out at 150, the 24,000-input spend at 151 through the live engine, and the same transaction through the single-transaction parser. **Watched to fail** on the fixed table (the parser assertion). A first gate caught a differential-parser mismatch from a pre-check on the claimed input count (the tables grow inside the loop instead; a bogus count fails on truncation as before). Gate `make -j8 test`: MAKE_EXIT 0, 0 failures (the expected test_rpc_signer segfault); audits exit 0.

---

PR #131 (`batch/2026-09-09-no-input-cap`), merged 01:58Z as `6a3064c0`; tag `no-input-cap-2026-09-09`.
