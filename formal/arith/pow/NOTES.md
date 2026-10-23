# Proof of work (rule group 2): bmc vs Bitcoin Core v31.1

Everything here runs from `formal/arith/pow/run.sh` (exit 0 only if every proof
holds, every REACH witness is found and every mutant is caught). Each solver,
compiler and assembler call goes through `lib/runlib.sh`'s `_lim`:
`systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15`,
plus a `timeout`. The calls run one at a time.

Tools: CBMC 6.11.0 (`$FORMAL_TOOLS/cbmc/usr/bin/{cbmc,goto-cc,goto-instrument}`,
SAT back end CaDiCaL via `--sat-solver cadical`), z3 5.3.1 (Python API,
`z3.get_version_string()`), Python 3.12.3, angr/pyvex/cle/archinfo 10.0.5 (claripy as
bundled with angr), NASM 2.16.01, gcc 13.3.0. `$FORMAL_TOOLS` defaults to
`$HOME/.local/opt/formal`.

Reproduce everything: `formal/arith/pow/run.sh` (about 17.5 min total, almost
all of it P1's angr runs and P4s mode 2). `build.sh` builds the real product
objects into `.build/` (ignored by git): `bitcoin_hash.o`, `bitcoin_chainwork.o`,
`sha256.o` from NASM with the product's flags (`-f elf64 -I asm/ -Werror`),
and `bitcoin_pow_rules.o` from gcc (`-no-pie -O2 -Wall -Werror`). Nothing is
built inside `asm/`.

## The Core reference

`core_port.h` is a line-for-line C port of the arith_uint256 operations the
PoW code uses: `operator<<=`, `>>=`, `*=(uint32_t)`, `/=`, `CompareTo`, `bits()`,
`SetCompact`, `GetCompact`, `~`, `+=`, `++`. It also ports `CalculateNextWorkRequired`
(the arithmetic), `DeriveTarget`, `CheckProofOfWorkImpl` and `GetBlockProof`,
and holds the chains' full `consensus.powLimit` values from
`kernel/chainparams.cpp`. `core_spec.py` is the same set in claripy bit-vectors,
used by P1.

To catch transcription errors, the PORT check compares `core_port.h` with an
independent Python big-integer transcription (`check_core_port.py`) on 200,000
vectors (SetCompact and its flags, GetBlockProof, GetCompact, the retarget).
Result: 0 mismatches.

Core facts relied on, each read from the v31.1 source:
- `bnNew *= nActualTimespan` takes `int64_t`, which resolves to
  `operator*=(uint32_t)` (a standard conversion beats the user-defined one) and
  wraps mod 2^256. `bnNew /= nPowTargetTimespan` goes through
  `base_uint(uint64_t)`.
- In `SetCompact`, fNegative and fOverflow use nWord AFTER the size<=3 shift.
  The overflow test is `nSize > 34 || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32)`.
- regtest has fPowAllowMinDifficultyBlocks = true and fPowNoRetargeting = true.
  testnet4 has min-difficulty and enforce_BIP94. Main and signet have neither.

## Properties

| ID | bmc code | claim | method | bound | result | time |
|---|---|---|---|---|---|---|
| P1 | `pow_check` (bitcoin_hash.asm: range checks, `diff_target`, hash<=target) | for each powLimit (main/testnet4 0x1d00ffff, signet 0x1e0377ae, regtest 0x207fffff) and the unarmed mode (pow_pow_limit_bits=0, compared with "no limit"): bmc accepts => Core CheckProofOfWorkImpl accepts, for all nBits and all 256-bit hashes; Core accepts and bmc rejects ONLY when exponent < 3, and then hash < 2^15 | angr lift of the real object; block_hash hooked to a free 256-bit hash; the exponent split into its 256 concrete values (a guard aborts on any symbolic memory address); claripy/z3 | unbounded (all inputs) | PROVED | ~230 s |
| P2a | `powr_target_bytes` (bitcoin_pow_rules.c) | == Core SetCompact whenever Core's flags are clear and exponent <= 32; for exponent 33/34 with a nonzero mantissa bmc decodes 0 where Core decodes a nonzero target | CBMC, real file `#include`d | complete (fixed loops) | PROVED | 0.3 s |
| P2b | `diff_target` (asm) | == SetCompact on exponent >= 3, sign clear, no overflow | differential test only (2M) and its role inside P1 | - | BOUNDED-OK (testing) | in DIFF |
| P2c | `compact_to_target_le` (bitcoin_chainwork.asm) | == SetCompact for exponent 3..32 with the sign bit clear; 0 for exponent < 3 or 33/34 | z3, hand-written instruction semantics (P5 C2T) plus the diff | unbounded | PROVED (hand semantics) | in P5 |
| P3 | `powr_compact` | == Core GetCompact(false) for every 256-bit target t with t == 0 or t >= 2^16; for 0 < t < 2^16 it ALWAYS differs (finding F1) | CBMC | complete | PROVED (with the divergence characterized) | 2.4 s |
| P4-LEM | `pow_retarget_bits` multiply and divide loops, clamp | MUL/DIV step lemmas (no u64 wrap, exact u8 digits, carry < ts, rem < T); composition: the 40 output bytes are exactly floor(N*ts/T); for main/testnet4/signet, target <= powLimit times 4T is < 2^256, so Core's mod-2^256 multiply never wraps on the reachable domain (signet's margin is under 1300 s of clamp) | z3 (bit-vector steps, integer compositions), modelled lines grepped from the product | unbounded | PROVED | 10 s |
| P4-CAP | the powLimit cap | decode(Lb) <= full powLimit; GetCompact(decode(Lb)) == powr_compact(decode(Lb)) == Lb; GetCompact(x) == Lb for EVERY x in (decode(Lb), full]. So capping at decode(Lb) (bmc) and at the full powLimit (Core) give the same compact | CBMC, per chain | complete | PROVED | 1 s |
| P4 | `pow_retarget_bits`, whole function | == Core CalculateNextWorkRequired | CBMC end to end | - | OPEN: timed out at 15 min (and at 5 min with the exponent fixed). Covered by P2a+P3+P4-LEM+P4-CAP (composition on paper, below) and by the differential test | - |
| P4s | `pow_expected_bits` (the schedule) | == Core GetNextWorkRequired: height%2016, the 20-minute rule, the min-difficulty walk-back (stops at a period boundary or at genesis), BIP94's first-block bits, fPowNoRetargeting. Retarget called iff Core retargets, with Core's base bits and timespan | CBMC; `goto-instrument --replace-calls pow_retarget_bits:stub_retarget` isolates the arithmetic; header oracle is free and memoised | BOUNDED: height = 2016*B + r, B free (< 2^29), r <= 3 (walk-back of at most 3 steps); per chain mode 1-4 | BOUNDED-OK | 8 s / 170 s / 8 s / 34 s |
| P5 | `u256_div`, `block_work`, `chainwork_add` (bitcoin_chainwork.asm) | u256_div == floor(A/B) for B != 0 (inductive step + composition, no unrolling); bit select and quotient-bit set are exact; block_work == the low 128 bits of Core GetBlockProof for pow-valid bits with exponent 3..32; chainwork_add == a+b when a+b < 2^128, else 2^128-1 | z3, hand-written instruction semantics (not lifted), backed by the differential test | unbounded | PROVED (hand semantics) | 2.3 s |
| P6 | `hdr_timewarp_ok` (daemon/hdrrules.h) | == Core's BIP94 time-timewarp-attack rule, for every int height >= 1, both flag values, all times | CBMC | complete | PROVED | 1.8 s |
| DIFF | all of the above as compiled | 2,000,000 iterations each: pow_check (4 limit modes), diff_target, u256_div (including divisors >= 2^255), block_work, chainwork_add, pow_retarget_bits (Core-valid bases <= powLimit on main and signet, int64 timespans including INT64_MIN/MAX and the clamp edges) | real objects vs core_port.h | random + edge cases | 0 unexpected mismatches (the classified out-of-domain counts are printed) | 11 s |

The P4 composition, for the domain of main, testnet4 and signet: base bits are
Core-valid and <= powLimit, with any int64 timespan.
1. P2a gives bmc's decoded target N == Core's.
2. Both clamp ts the same way: the clamp lines are grepped, and the clamp is
   in core_port.h.
3. P4-LEM: bmc's quotient q == floor(N*ts/T) exactly. Core's q is the same,
   because N*ts < 2^256 (BOUND). Also q < 2^256, so bmc's `over` stays 0.
4. If q > decode(Lb), bmc returns powr_compact(decode(Lb)) == Lb and Core
   returns GetCompact(min(q, full)) == Lb (P4-CAP).
5. Otherwise neither caps: bmc returns powr_compact(q) and Core returns
   GetCompact(q). These are equal iff q == 0 or q >= 2^16 (P3). With
   ts >= T/4, q >= floor(N/4), so a base target N >= 2^18 is enough.
6. The lexicographic big-endian byte compare and the LE/BE byte reversals were
   checked by reading the code, not modelled. The differential test drives the
   whole compiled function.

regtest never reaches this arithmetic, because of fPowNoRetargeting. P4s
mode 4 shows that bmc returns the parent's bits there, and that Core's
min-difficulty path returns the same powLimit bits on any chain whose
ancestors all carry powLimit bits (the inductive invariant of every
acceptable regtest chain).

## Vacuity (REACH) and mutants

Every check has a satisfiability or REACH witness. For P1, both-accept,
both-reject and the residual set are each satisfiable. P4-LEM and P5 print
SAT-OK for every assumption set. P4-CAP-main, P4s modes 1 and 2, and P6 have
REACH runs that must FAIL, and they do.

Mutants, each applied to a scratch copy of the PRODUCT file (or of the model
for z3), with the checker's output:

| mutant | where | checker output |
|---|---|---|
| `ja .invalid` (target > powLimit) -> `jae` | bitcoin_hash.asm, P1 limit 0x1d00ffff | `core&!bmc&exp>=3: CEX ... bits=0x14000020` |
| sign test `0x00800000` -> `0` | bitcoin_hash.asm, P1 regtest | `bmc=>core: CEX` |
| `xor eax, 1` -> `nop` (commit = borrow) | bitcoin_chainwork.asm, DIFF | `MISMATCH u256_div`, `MISMATCH block_work bits=1e001df4` |
| clamp `4T` -> `4T + 1` | bitcoin_pow_rules.c, DIFF | `MISMATCH retarget base=1c00178b ts=2008883516363777277 got=1b5e2c01 want=1b5e2c00` |
| powr_compact drops `size++` | P3 | `P3 powr_compact == Core GetCompact (t == 0 or t >= 2^16): FAILURE` |
| powr_target_bytes `3 - size` -> `2 - size` | P2a | `P2a powr_target_bytes == Core SetCompact ...: FAILURE` |
| BIP94 base = last_bits | P4s mode 2 | `P4s retarget called iff Core retargets, with Core's base bits and timespan: FAILURE` |
| 20-minute rule `>` -> `>=` | P4s mode 2 | `P4s pow_expected_bits == GetNextWorkRequired (schedule): FAILURE` |
| `- HDR_MAX_TIMEWARP` -> `- HDR_MAX_TIMEWARP - 1` | hdrrules.h, P6 | `P6 hdr_timewarp_ok == Core BIP94 timewarp rule: FAILURE` |
| carry `>> 8` -> `>> 7`; divisor T+1; signet clamp +1300 s | P4-LEM models | `MUTANT-CAUGHT` (sat) for each |
| COUT dropped; offset bound 29 -> 30; no saturation | P5 models | `MUTANT-CAUGHT` for each |

One mutation was rejected as EQUIVALENT: dropping `or eax, r10d` (the
257th-bit COUT) in u256_div is undetectable, because COUT is provably always 0
in the real loop. The remainder entering the step for bit i is
(A >> (i+1)) mod B < 2^255. The code is harmless dead logic; see the p5_work.py
docstring.

## Findings (confirmed on the compiled code)

**F1. `powr_compact` encodes targets below 2^16 wrongly (GetCompact divergence).**
`asm/bitcoin_pow_rules.c` powr_compact gathers the size<3 mantissa bytes
already left-aligned (zero-filled), and then shifts again with
`if (size < 3) word <<= 8 * (3 - size);`. Core's GetCompact shifts the value
once (`GetLow64() << 8*(3-nSize)`). The result: P3 proves bmc differs from
Core for EVERY target 0 < t < 2^16, and is equal everywhere else.

Concrete reproduction on the compiled `bitcoin_pow_rules.o` (`confirm_p3c`):
- `pow_retarget_bits(0x03000100, 302400, 0x1d00ffff)` gives 0x01000000.
  Core CalculateNextWorkRequired gives 0x01400000 (target 64).
- `pow_retarget_bits(0x03004000, 302400, 0x1d00ffff)` gives 0x02000000.
  Core gives 0x02100000 (target 0x1000).

The only caller is pow_retarget_bits, so the effect is a wrong required nBits
(bad-diffbits against Core's value) at a retarget boundary.

Reachability: the new target must be < 2^16, so the base target must be
< 2^18 (or < 2^14 at the 4x clamp). That base target is a block nBits that
passed PoW, i.e. a block hash <= 2^18: about 2^238 expected hashes. It is
unreachable on any real chain, and the differential counts it only under that
synthetic domain (P3c class). Severity: informational/latent (not exploitable).

Core reference: arith_uint256.cpp GetCompact. rpc_chain.c has no separate
GetCompact copy (its `target_bytes` is a display-only SetCompact for
getblocktemplate's "target" field and is not consensus).

No other divergence was confirmed. The characterized out-of-domain behaviours
below are recorded as notes, not findings:

- **pow_check, exponent < 3** (P1): Core accepts nBits like 0x0201xxxx (a tiny
  nonzero target) when hash <= target < 2^15, and bmc rejects every exponent
  < 3. That needs a block hash below 2^15, so it is unreachable. bmc is never
  more permissive than Core (P1 soundness, all four modes).
- **Unarmed powLimit** (pow_pow_limit_bits == 0): bmc then accepts targets
  above every chain's powLimit (P1 witnesses: bits 0x1d400080 on main,
  0x1f006b64 on signet, 0x21008022 on regtest). chainparams_select arms it on
  every successful selection, and the daemon calls it at boot
  (`daemon/main.c`). The offline tools `bmc_pverify` (daemon/pverify.c),
  `verify.c` and `testpeer.c` never call chainparams_select, so their
  pow_check runs unarmed. Not a node consensus path.
- **block_work, exponent 33/34 or < 3**: compact_to_target_le decodes these
  to 0 (work 0) where Core has a nonzero target. Exponent 33 with mantissa
  <= 0x7fff is <= regtest's powLimit, but regtest's schedule requires exactly
  0x207fffff (P4s mode 4), and exponent < 3 needs hash < 2^15. Not reachable
  on an accepted chain. The 128-bit truncation of work is exact for targets
  >= 2^128, i.e. for anything a real chain carries.
- **chainwork_add saturates at 2^128-1** where Core's 256-bit sum would
  continue. Equal below 2^128; mainnet's cumulative work is about 2^97.
- **u256_div COUT**: dead logic (see Mutants). It does no harm.

## Assumptions and trusted base

- angr's VEX lifting of bitcoin_hash.o (P1). SHA-256 is not modelled: the
  hash is a free input.
- For P5 and P2c: hand-written semantics of rcl/sub/sbb/setc/not/add/adc/jnc and
  of the 4-limb addressing. These are backed by the 2M-iteration differential
  test on the real object.
- P4's composition argument (steps 1-6 above), and the whole-function
  equivalence that stayed OPEN. Backed by the differential test on the real
  compiled function: 2M bases and timespans, 0 unexpected mismatches.
- P4s: the bound r <= 3 on the walk-back length, the header store read
  (oracle), and the regtest invariant that every ancestor carries powLimit
  bits.
- Chain constants: the compact powLimits bmc is configured with
  (daemon/chainparams.c) and Core's full powLimit uint256 values are copied by
  hand into core_port.h / core_spec.py from kernel/chainparams.cpp.

Not covered: Core's PermittedDifficultyTransition (a header-sync
anti-DoS check, not a block-validity rule, and bmc has no such function under
that name). Not covered either: getblocktemplate's display `target_bytes`
(rpc_chain.c), and whether every caller passes the right chain flags to
pow_check_bits (call-site wiring, not arithmetic).
