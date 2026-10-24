# formal/secp: the secp256k1 field and scalar arithmetic, proved on the assembled code

Area: the secp256k1 field (mod p = 2^256 - 2^32 - 977) and scalar (mod n)
arithmetic of bmc, as built from `asm/` at the security integration branch
(`integ/2026-10-23-sec-all`, b841251b). Every proof runs on the real objects:
the worktree's `asm/*.o` (built by `make`) linked into `build/img.elf`. The
lifter decodes that image with GNU objdump. Nothing in `asm/` is edited.

    formal/secp/run.sh          # build + every proof + differential tests + mutants; exits 0 only if all pass
    SKIP_MUTANTS=1 formal/secp/run.sh
    cd formal/secp && ./lim 3600 $FORMAL_TOOLS/venv/bin/python run_all.py --only FE-RED   # one group

`lim` wraps every solver and build: a `systemd-run --user --scope` with
MemoryMax=8G and MemorySwapMax=0, `nice -n15`, and a timeout. Only one solver
process runs at a time.

Tools: z3 5.3.1.0 (Python API, `$FORMAL_TOOLS/venv`, Python 3.12.3), NASM
2.16.01, gcc 13.3.0, GNU objdump/ld 2.42. No CBMC, TLC or angr is used.

## Files

| file | what it is |
|---|---|
| `x86sym.py` | Bit-precise symbolic executor for x86-64. It decodes with objdump (Intel syntax) and holds its own semantics for the instruction subset the code uses. Values are Python ints (concrete) or z3 bit-vectors. It has a fork mode (explores symbolic branches under path conditions) and a ct mode (any symbolic branch or address raises). |
| `linform.py` | Exact algebraic shadow of the carry chains (CryptoLine-style). Each add/sub records `r + 2^w*c = a + b + cin`. Values get polynomial forms over integer atoms. A claim holds as a polynomial identity, or else z3 LIA proves it over the recorded range facts. `selfcheck()` proves the two identities against the executor's own BV semantics. |
| `proofs_fe.py`, `proofs_sc.py`, `proofs_misc.py`, `proofs_ct.py` | The proofs. `run_all.py` runs them all and writes `build/results.tsv`. |
| `diff.py` | Differential tests: real objects (`build/drv`) vs Python big integers. Also runs the lifter vs the real objects, in both the concrete and the z3 path. |
| `mutate.py` | 24 one-line mutants of product code, each in a scratch copy of `asm/` that is rebuilt from scratch. Each must be caught. |
| `src/drv.c` | The differential driver, linked against the real objects. |
| `src/fe_inline_wrap.asm` | Callable wrappers around the real macros of `secp256k1_fe_inline.inc`, which are included verbatim. |
| `build.sh` | `make` of the real objects, then the image, the driver and the wrapper. `ASM=`/`B=` select another tree (used for the mutants). |

## Method

* **Products.** The proofs never bit-blast a 64x64 product. For two
  symbolic operands, `mul`/`mulx` give an abstract (hi, lo) pair with
  `hi*2^64 + lo = x*y`, where x*y is a degree-2 monomial and
  `hi <= floor(max(x)max(y)/2^64)`. A product by a constant is the exact z3
  term. This over-approximation is sound: the real product satisfies it.
* **Carry chains.** These are proved algebraically. A carry is the constant 0
  when interval arithmetic over the operands shows it cannot fire; otherwise
  it is a {0,1} atom. The schoolbook identity sum a_i b_j 2^(64(i+j)) is then
  checked by expanding polynomials. Dropped carries, where the code relies on
  "cannot carry", go to z3 LIA. Bit-blasting the same identity did not finish:
  4-term folds took 58 s abstracted and more than 120 s exact.
* **Selects, masks and conditional subtractions.** These are z3 QF_BV proofs
  on small cut-point states: fresh symbols at a probe address, with only the
  proved bound assumed.
* **Addition chains** (fe_inv, fe_pow_sqrt, the C fe_sqrt, sc_inv) are proved
  by exponent tracking. Each value is a 4-limb token a^e. Hooks for fe_mul and
  fe_sqr (or sc_mul) add or double e, which relies on their proofs for ALL
  inputs. Branches and loop counters run concretely.
* **Constant time** uses mode `ct`. The secrets are symbolic and pointers and
  public inputs are concrete, so every branch condition and every memory
  address must be a concrete value. A callee already proved CT is summarised
  by a hook: it writes fresh symbols to r[], clobbers caller-saved registers
  and leaves flags undefined.
* **Lifter cross-checks.** Every proved function is also run concretely by the
  lifter and compared with the real CPU on the same inputs (2342 runs). A few
  runs per function also go through the z3 path.

## What is proved (all unbounded: every input of the stated domain)

| ID | function | claim | precondition |
|---|---|---|---|
| FE-MUL-P / FE-SQR-P | fe_mul, fe_sqr | at `fe_mul.reduce`, r8..r15 = a*b exactly (a*a for sqr); one path; ABI and write set OK | none |
| FE-RED.1-5 | fe_mul.reduce (shared by fe_sqr) | for ANY 512-bit T: r < p and r ≡ T (mod p), proved in 4 exact steps plus the 2^256 ≡ C glue | none |
| FE-ADD, FE-ADD-AL, FE-SUB | fe_add, fe_sub | r = (a ± b) mod p, r < p; r may alias a | a, b < p (FE-*.pre shows it is needed) |
| FE-ADDM, FE-DBL, FE-SUBM | FE_ADDM / FE_DBL / FE_SUBM macros (inlined in all point code) | same | a, b < p |
| FE-HALF | FE_HALF (cut from the real pointj_add_ge_ct) | 2r ≡ V (mod p), r < p | V < p |
| FE-EQZ | fe_is_zero, fe_equal (gcc output) | 1 iff zero / equal; branch-free | field equality needs canonical inputs |
| FE-INV, FE-INV-AL | fe_inv | chain builds a^(p-2) exactly (255 sqr, 15 mul); r may alias a | none; 0 maps to 0 |
| FE-SQRT, FE-SQRT-C | fe_pow_sqrt; fe_sqrt (C) | a^((p+1)/4); the C version returns 1 exactly when that value squares to a, else returns 0 and leaves r untouched | none |
| SC-ADD, SC-SUB | sc_add, sc_sub | r = (a ± b) mod n, r < n | a, b < n (needed, .pre) |
| SC-MUL.* | sc_mul / sc_sqr | 16 MULACC = a*b exactly; each of the 8 FOLDs: X' = X_lo + X[4..8]*DELTA; the bound chain shows limb 9 is always 0 and X_8 <= 2^256-1 (4 FOLDs would be enough); the 3 CONDS give X mod n | none: any 256-bit a, b |
| SC-M512 | sc_mul_512 | the 8 limbs = a*b exactly | none |
| SC-HALF | sc_half_ct | 2r ≡ a (mod n), r < n | a < n |
| SC-INV | sc_inv | builds a^(n-2); branches read only the public exponent | none |
| SC-SPLIT | sc_split_lambda | c_i = round(k*g_i/2^384) (rounding bit 383 included); r2 = c1(-b1) + c2(-b2); r1 = k - λr2; returns (λr2 + r1 == k) | callees per their proofs |
| SC-SPLIT-M | GLV math | for every k < n, the integers k1 = k - c1a1 - c2a2 and k2 = c1(-b1) - c2a1 satisfy \|k1\|, \|k2\| < 2^128, with r_i ≡ k_i (mod n). So the sign rule the callers use (bit 255 set means negative) recovers k_i, and the 129-bit (glvj, v = s + 2^128) and 132-bit (glv) windows suffice. The check returns 1 iff k < n. | k < n (callers range-check) |
| SC-RANGE | scalar_small_nonzero | returns 1 iff 0 < k < n, over all 2^256 inputs (51 paths). **The audit fix holds: k = n and all of [n, 2^256) return 0, and so does k = 0.** | none |
| SC-INRANGE | ecdsa_in_range | 1 iff 0 < x < n | none |
| B340-RED | reduce_n (bip340_sign.c, real -O2 code; sub4+sel4 inlined) | r = a mod n for every a < 2^256; constant time | none |
| B340-CNEG | cneg_n | r = (flag odd ? n - a : a), r in [1, n), for all a and all 32-bit flags, including the CRY-2 all-ones limbs; constant time in a and flag | a in [1, n) (needed: a = 0 gives n) |
| CT-* | fe_add/sub/mul/sqr/inv/pow_sqrt, the macros, sc_add/sub/mul/sqr/mul_512/half_ct/inv, sc_split_lambda, pointh_add, pointh_double, pointj_add_ge_ct, point_scalar_mul_gen_ct / _ct / _win_ct, and _glv_ct / _glvj_ct (both the AVX2 and the cmov scan) | no branch or memory address depends on the secret | for the GLV routines: k < n. Their only data-dependent branch is the identity check in sc_split_lambda, which SC-SPLIT proves is never taken for k < n; the CT run forces it and reports it |

### Preconditions, and why chains of operations stay valid

* **Representation.** Every field and scalar value is four little-endian
  64-bit limbs. There is no lazy reduction anywhere: every function's
  canonical output range is proved (r < p or r < n).
* **Producers.**
  * fe_mul, fe_sqr, fe_inv, fe_pow_sqrt and fe_sqrt produce r < p for any input.
  * fe_add, fe_sub, FE_ADDM, FE_DBL, FE_SUBM and FE_HALF produce r < p from canonical inputs.
  * sc_mul, sc_sqr, sc_inv and reduce_n produce r < n for any input.
  * sc_add, sc_sub, sc_half_ct and cneg_n produce canonical results from canonical inputs.
  So every value one of these functions computes meets the precondition of
  every consumer.
* **Values from outside.** These are the only place canonicity must be
  established by a check:
  * bitcoin_pubkey.asm's FE_REQUIRE_LT_P rejects x, y >= p (not proved here).
  * The secret keys' 0 < d < n range is proved for scalar_small_nonzero and
    ecdsa_in_range, and bip340_sign uses `limb_cmp(d, N) >= 0`.
  * Hashes are reduced by reduce_n (proved).
  * The ElligatorSwift u and t are reduced mod p (read, not proved).
* **Needed preconditions.** The `.pre` rows give z3 counterexamples showing
  fe_add, fe_sub, the macros, sc_add, sc_sub and cneg_n really need theirs.
  They are not defects: no caller passes non-canonical operands.

## Differential tests (`diff.py`, seeded)

Edge values: 0, 1, 2, p±1, p±2, n±1, n±2, 2^256-1, 2^255, C, 2^256-C, the
(p±1)/2 and (n±1)/2 halves, every all-ones-limb pattern and its complement.
Pairs cover EDGE×EDGE, plus 300 random inputs (biased to extreme limbs) per
function.

* Every proved function matches Python on its whole domain.
* fe_inv_var and sc_inv_var (safegcd, not proved) match on all 256-bit
  inputs, including returning 0 with r untouched for 0 mod m, as documented.
* sc_inv_batch matches on 102 batches.
* The lifter agrees with the CPU on 2342 runs.

## Mutants (`mutate.py`): every proof can fail

Each mutant changes one line, or the FOLD lines, in a scratch copy of `asm/`.
The scratch tree is rebuilt with every relevant object deleted first: the
Makefile has no `secp256k1_fe_inline.inc` dependency, so without the deletion a
stale object hid the first CT mutant. The mutant then runs the covering
proofs, and then the concrete differential test on the mutated code.

All 24 are caught:
* fe_mul's row carry (`adc→add`)
* C 977→976
* the reduction's second-fold carry
* fe_add's cmovc→cmovnc
* fe_sub's sbb→sub
* FE_ADD_TAIL's `adc rdi,rdi`→add
* FE_HALF's rcr→shr
* fe_inv one squaring short
* the C sqrt chain
* sc_add's cmovnc→cmovc
* sc_sub's mask
* MULACC's carry
* the FOLD carry
* DELTA off by one
* 8 FOLDs→3
* N_EXP
* the split's rounding bit 383→382
* the pre-fix `jae .ok` of scalar_small_nonzero (counterexample k = n)
* ecdsa_in_range accepting n
* reduce_n's select
* the CRY-2 lost-borrow expression restored in sub4
* and three constant-time mutants:
  * FE_ADD_TAIL's cmov→branch
  * sc_add's cmov→branch
  * a k-indexed G_COMB_TABLE load

Two mutants leave every concrete vector right:
* **8 FOLDs → 3.** The proof catches it through the bound chain (an
  over-approximation). Whether some input really breaks three folds is not
  established.
* **FE_HALF.** The driver does not exercise this inline macro.

Neither of these is a gap in the proofs.

## Trusted base

* **GNU objdump's decoder.**
* **The semantics in `x86sym._exec`** for: mov/movabs/movzx/movsx(d), lea,
  add/adc/sub/sbb/cmp/neg/inc/dec, adcx/adox, and/or/xor/test/not,
  shl/shr/sar/shld/shrd/rcr(1), mul/mulx/imul, cmovcc/setcc/jcc/jmp/call/ret,
  push/pop, bt, bswap, xchg, `rep movsq`, the SSE moves/pxor/por/psrldq/movq,
  and the AVX2 vmovd/vpbroadcastd/vpxor/vpaddd/vpcmpeqd/vpblendvb/vmovdqu.
  * Flags: CF, OF, ZF and SF are modelled. A read of an undefined flag (after
    mul/imul/bt, or a shift of more than 1) is an error. PF and AF are never
    modelled, and the code under proof never reads them.
  * A 32-bit write zero-extends.
  * The add/sub identities are machine-checked (LF-SELF), and 2342
    co-simulation runs against the CPU check the rest of the table.
* **Product bound.** hi(x*y) <= floor(max x · max y / 2^64).
* **Interval arithmetic** over non-negative atoms (`linform.interval`).
* **Integer facts, checked in Python or z3 LIA:** p ≡ 3 (mod 4); Fermat, by
  spot check (p and n prime are taken as known); λ^3 ≡ 1; λ(-b1) ≡ a1 and
  -λa1 ≡ a2 (mod n).
* **Hooks.** These summarise callees whose own proofs cover all inputs.
* **ct_scan_path** is set to 1 (AVX2) or 2 (cmov) instead of running cpuid.
  Both paths are checked.

## Not covered

* **fe_inv_var / sc_inv_var** (Bernstein-Yang safegcd, variable time, public
  inputs): differential tests only. A proof needs the safegcd termination and
  divstep-matrix argument.
* **C helpers:** sc_inv_batch and sc_inv_c (C) have differential tests only;
  glv_wnaf (C, variable time, verification only) is not covered.
* **The point formulas themselves** (that pointh_add / pointj_add_ge_ct
  compute the group law): only constant time is proved, and the field
  operations they inline are proved.
* **The variable-time verifier routines** in secp256k1_point.asm,
  ecdsa_verify / schnorr_verify, ecdsa_x_eq_mod_n and FE_REQUIRE_LT_P.
* **bip340_sign as a whole:** its helpers reduce_n and cneg_n are proved and
  constant time, but bip340_sign's own glue and its inlined `sub4` in
  self_verify are not lifted.
* **The macro instances inside the point routines** are the textual expansion
  of the proved macro. They are not proved one by one, except FE_HALF, which
  is cut from the real code.
* **Constant time is control flow and addresses only.** Instruction timing of
  mul/mulx/cmov is assumed data-independent, as on all current x86-64.

## Observations (not defects in the arithmetic)

* `asm/Makefile` gives secp256k1_point.o and secp256k1_point_ct.o no
  dependency on `secp256k1_fe_inline.inc`. An edit to the macros does not
  rebuild the point objects (seen here: a mutant was first missed on a stale
  object).
* point_scalar_mul_win_ct reads its scratch slot T at [rbp-0x100] before the
  first write. This is benign: the scan over i = 0..15 always matches exactly
  one digit and overwrites all 12 limbs. The proof models the old contents as
  arbitrary symbols.

## Last full run (2026-10-23)

`formal/secp/run.sh`: **ALL PASS in 1416 s**.

| stage | result | time |
|---|---|---|
| proofs | 80 rows, all PROVED | 627 s |
| differential tests | 0 mismatches; 2342 lifter runs agree with the CPU | |
| mutants | 24 of 24 caught | |

The slowest rows are the bit-blasted add/sub selects, 15-95 s each. Every
algebraic row takes under 7 s.
