# formal/arith: bmc's consensus arithmetic against Bitcoin Core v31.1

Goal: show that bmc's consensus arithmetic accepts exactly what Bitcoin Core
v31.1 accepts, bit for bit, for all inputs, or say precisely where it does
not. The code under test is the security integration branch
`integ/2026-10-23-sec-all` (b841251b). The reference is Core v31.1's source.

`run.sh` runs every group and exits 0 only if every proof holds, every
REACH witness is found and every mutant is caught. Each group also has its
own `run.sh` and notes:

| dir | rules | notes |
|---|---|---|
| `money/` | MoneyRange, CheckTransaction output sums, CheckTxInputs, fees, subsidy, bad-cb-amount, coinbase maturity | this file |
| `locks/` | BIP113 median time past, IsFinalTx, BIP68 sequence locks, header time and version floors | this file |
| `pow/` | SetCompact/GetCompact, CheckProofOfWork, retarget, GetBlockProof/chainwork, BIP94 timewarp | `pow/NOTES.md` |
| `limits/` | block size and weight, sigop cost, sigop-adjusted vsize, CompactSize, nVersion | `limits/NOTES.md` |
| `scriptnum/` | CScriptNum and arithmetic opcodes | `scriptnum/NOTES.md` |

## Tools and how to reproduce

- CBMC 6.11.0 (cbmc-6.11.0), with its bundled CaDiCaL (`--sat-solver cadical`) where noted.
- z3 5.3.1 (Python API), Python 3.12.3.
- Tools are found under `$FORMAL_TOOLS` (default `$HOME/.local/opt/formal`):
  `$FORMAL_TOOLS/cbmc/usr/bin/cbmc`, `$FORMAL_TOOLS/venv/bin/python`.
- Every solver run goes through `lib/runlib.sh`'s `_lim`:
  `systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 1800 ...`.
- `./run.sh` from this directory reproduces everything. A single check can be
  run by hand. For example, M2 on mainnet's interval is
  `cd money && ./gen.sh && cbmc -DINTERVAL=210000 m2_ledger.c --unwind 5 --unwindset strcmp.0:48 --unwinding-assertions`.

## How the real code gets into a proof

The harnesses do not keep a copy of the code they verify. Each group's
`gen.sh` calls `lib/extract.py` to cut the exact text out of the product
file (a function, a typedef, the brace block around an anchor line, or a
line range) into `gen/`. It does this on every run, with a `#line` directive
back to the product file. An anchor that is missing or matches twice stops
the run. The harness then compiles that text against stubs for its callees
and against a transcription of Core's function. The transcriptions are
`money/core_amount.h` and `locks/core_locks.h`, and each line cites its Core
source. CBMC checks that the outputs are equal for nondeterministic inputs.

Each harness is shown to be able to fail in two ways:

- **REACH.** The harness is compiled with `-DREACH`, which adds assertions that
  must fail: an accepted case and each reject reason. When they fail, the
  assumptions are known to be satisfiable and the interesting paths reachable.
- **Mutants.** `cbmc_mutant` copies the tree, applies one `sed` to the cut
  product code (or to the model, for z3), requires that the sed changed the
  file, and requires CBMC to report a failure. The output records the
  mutation and CBMC's first FAILURE line.

## Results: money (group 1)

Times are from the last full `money/run.sh` (4 min 6 s).

| ID | bmc code | claim | method | bound | result | time | mutant caught |
|---|---|---|---|---|---|---|---|
| M1 | `daemon/utxo_live.c` idxbuild_on_output | Block path: the per-output `[0,MAX_MONEY]` and running-total MoneyRange checks reject exactly what CheckTransaction rejects. The per-tx total passed on (ptx_out) equals GetValueOut. | CBMC, real code. Inductive step over relation R, base checked. | unbounded (induction over outputs) | PROVED | 0.15 s | per-output check removed (`if (0)`); running-total check removed |
| M1m | `bitcoin_txval_modern.c` output loop | The same rules on the mempool/relay parser. | CBMC, real lines. Inductive step. | unbounded | PROVED | 0.05 s | running-total check removed |
| M2 | `utxo_live.c` Phase 4.5 block + val_subsidy | Accept/reject of the fee ledger (inputvalues-outofrange, in-belowout, fee range, accumulated fees, bad-cb-amount) equals Core's ConnectBlock/CheckTxInputs. Reject strings are equal except one (see note). | CBMC, real code | ≤4 txs × ≤3 inputs. All values and heights free. Interval 210000 and 150 | BOUNDED-OK | 112 s + 98 s | `in_t <= out_t`; `cap + 1`; fee-total check removed |
| M2-IND | same, transcribed | The per-input and per-tx steps preserve equality of verdict and totals, which makes M2 unbounded in txs and inputs. The coinbase cap never overflows. IN-WIDTH: k·MAX_MONEY < 2^64 for k ≤ 8784 (tight at 8785). | z3 bit-vector (64 bit, 128-bit exact sums) | unbounded | PROVED | 0.2 s | 5 model mutants (limit +1, `<=`, fee limit, B1 removed, cb `>=`), each SAT |
| M3 | `utxo_live.c` val_subsidy | val_subsidy == GetBlockSubsidy for every height 0..INT_MAX | CBMC, real code | each chain interval (210000, 150) | PROVED per interval | 0.07 s | `halvings >= 32` (height 6752769) |
| M4 | `tx_verify.c` txvb_classify (C) and `bitcoin_txv_classify.asm` (4 instrs) | coinbase maturity: `height - coin_height < 100` rejects iff Core does | z3, hand-written instruction semantics. A grep pins the modelled lines | heights 0..2^31-1 | PROVED | 0.08 s | MATURITY 99; `jge`→`jae` |

Notes:

- **A-UTXO (assumption of M2).** Every spent coin is in `[0, MAX_MONEY]`. Each
  coin was an output that passed M1 when its block connected. M2 still
  evaluates Core's per-coin check.
- **Width of the input sum.** bmc adds each tx's input values into a u64 and
  checks only the total (`in_t > MAX_MONEY`). Core checks every running
  prefix. IN-STEP shows the two agree as long as the true sum stays below
  2^64. IN-WIDTH shows that this holds for every transaction with at most
  8784 inputs. Beyond that, the u64 can wrap only if the coins spent are worth
  more than 2^64 sat (about 1.8e11 BTC). The coins in one tx are distinct
  (the duplicate-input check comes first) and all sit in the UTXO set at the
  same time, so their total is bounded by issuance, which is below
  MAX_MONEY. This last step is an argument about chain state, not a
  machine-checked proof.
- **Reject string.** When the accumulated block fee leaves MoneyRange, bmc
  says `bad-txns-fee-outofrange` and Core says
  `bad-txns-accumulated-fee-outofrange`. Accept/reject is identical, and
  under A-UTXO plus the issuance bound the case is unreachable. Cosmetic.
- **Subsidy interval.** CBMC did not close a symbolic halving interval in
  10 min: it needed the equivalence of 64-bit and 32-bit signed division.
  z3 returned `unknown` after 120 s. So the claim is per chain interval.
  These are all the intervals bmc's `daemon/chainparams.c` defines, and they
  equal Core's. bmc's fallback (no chain selected, or interval ≤ 0 → 50 BTC)
  lies outside Core's domain.

## Results: locks (group 3)

Times are from the last full `locks/run.sh` (7 min 49 s).

| ID | bmc code | claim | method | bound | result | time | mutant caught |
|---|---|---|---|---|---|---|---|
| L1 | `utxo_live.c` val_mtp | It returns Core's GetMedianTimePast: the element at sorted index n/2 of the up-to-11 window. This is specified as an order statistic, not as a second sort. | CBMC, real code, cadical | every height (n = 1..11, including short chains). For n ≤ 8 all u32 times are free. For n = 9..11 times are in [0,15], complete by order-isomorphism (see l1_mtp.c) | PROVED | 0.6–17 s per n | `ts[(n-1)/2]` |
| L2 | `daemon/seqlocks.h` val_is_final + val_is_final_tx | IsFinalTx on both the block and mempool paths | CBMC, real code | unbounded (all u32 locktimes and cutoffs, int heights) | PROVED | 0.05 s | `locktime <= cutoff` |
| L3 | `utxo_live.c` Phase 4.55 block + seqlocks.h | Block-path BIP68: accept iff Core's CalculateSequenceLocks + EvaluateSequenceLocks accept. This covers the u32 version ≥ 2 gate, the disable and type flags, `<< 9`, the -1, max(h-1, 0), and the ≥ comparisons. | CBMC, real code, cadical | ≤3 txs × ≤2 inputs. Versions, sequences, coin heights, heights and MTPs are free | BOUNDED-OK | 243 s | version read as int32; time `- 1` dropped; `>=` → `>` on height |
| L4 | `daemon/hdrrules.h` hdr_contextual_ok | time-too-old, time-too-new and bad-version equal Core's ContextualCheckBlockHeader (including CON-5: nVersion is int32) | CBMC, real code | unbounded | PROVED | 0.07 s | `uint32_t ver` (the pre-CON-5 code); `<` for `<=`; `+ 1` on the 2 h limit |

Trusted environment and what was not covered:

- **L1.** The header-store read is stubbed.
- **L3.** script_flags_for_block's CSV bit, val_read_tx's parse,
  tx_verify.c's coin-height ledger and val_mtp are stubbed. val_mtp is
  modelled as a consistent free function of height, and L1 covers it.
- **L4.** The deployment heights behind script_flags_for_block are not
  re-checked against Core's chainparams. The callers' sentinels (prev_mtp = 0
  and now = 0 disable a check) are outside the claim. Core's sub-second clock
  is reduced to whole seconds; the equivalence is shown in l4_hdrtime.c.
- **The IsFinalTx cutoff choice is not machine-checked.** At the call site,
  the cutoff is the MTP of h-1 when CSV is active and the block nTime when it
  is not. That matches Core by reading.
- **Mempool BIP68 (`bitcoin_mempool_policy.c`).** Height-based locks use the
  same seqlocks.h functions that L2/L3 cover. But a transaction with any
  time-based input skips the BIP68 rule entirely (`evaluable = 0`), so the
  height-based inputs of such a transaction are not checked at admission
  either. This is relay policy, the code documents it on purpose, and the
  block path (L3) still rejects such a transaction. It is listed as an
  observation, not as a consensus finding.

## Findings (confirmed on the compiled code)

- **F1: powr_compact (asm/bitcoin_pow_rules.c) mis-encodes targets below 2^16.**
  - *Cause.* For a short mantissa (size < 3), the byte loop already
    left-aligns it, and then `if (size < 3) word <<= 8*(3-size)` shifts it a
    second time. Core's arith_uint256::GetCompact shifts once.
  - *Concrete case.* `pow_retarget_bits(0x03000100, 302400, 0x1d00ffff)`
    returns 0x01000000; Core gives 0x01400000. Details are in
    `pow/NOTES.md` and `pow/confirm_p3c.c`.
  - *Reachability.* It needs a retarget base target below 2^18, which means
    a block hash at or below about 2^18 (about 2^238 expected hashes).
  - *Severity.* Latent/informational: unreachable on any real chain, but
    wrong code in a consensus function.

Other divergences are not consensus findings, because accept/reject cannot
differ on a reachable input. They are characterized in the group notes:

- The reject string for the accumulated fee (money).
- pow_check refuses exponent < 3, where Core needs hash < 2^15 to accept.
- pow_check runs unarmed (`pow_pow_limit_bits == 0`) in the offline tools.
- block_work returns 0 for exponents 33/34, and chainwork_add saturates at
  2^128.
- The lenient CompactSize readers that sit behind canonical ones (limits).
- An empty P2WPKH witness counts 0 sigops where Core counts 1.
- The mempool BIP68 path skips the rule for transactions with time-based
  inputs (locks).
