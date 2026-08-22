# Performance scope — bulk UTXO rebuild / full-verification replay

Written 2026-08-21, during Stage D's full-chain replay (see
`PLAN_SCRIPT_VERIFY.md`). This is a profile-grounded inventory of where the
replay's cycles actually go and what the real levers are — not a roadmap
commitment. Every number below comes from a `perf record` of the live
production process at the stated height, symbol-resolved against a copy of
the exact running binary; nothing is estimated from general knowledge.

**Deployment rule, stated up front:** every lever in §4 touches the live
verify or storage path. Per this project's established discipline, none of
them gets built into the running daemon until the current replay reaches tip
clean. Scoping now, landing later.

## 1. The comparison basis — read this before the numbers

"Match Bitcoin Core" only means something if the two are doing the same work,
and by default they are not.

- This node runs **full signature verification on every historical block,
  unconditionally.** `assumevalid` is deliberately ignored
  (`daemon/node_config.c:272`) because the whole point of Stage D's replay
  is to prove the verifier against real chain data.
- Real Core, by default, uses `assumevalid` to **skip script verification**
  for every block below a hard-coded known-good hash. Its advertised IBD
  time reflects that shortcut.
- The only fair target is therefore Core with `-assumevalid=0` (full
  verification). That mode is far slower than Core's typical sync and is the
  number this project should be measured against.
- **Running Core for benchmarking and as an oracle is authorized as of
  2026-08-21** — from the separate source build
  (`/storage/bitcoin-core-source/build/bin/`), never the production install.
  `/storage/bitcoin` and `bitcoind.service` remain off-limits.

### Measured: libsecp256k1 vs this project, same CPU, same moment

Built libsecp256k1 from Core's vendored source in isolation, with Core's own
shipped configuration (x86-64 asm, `ECMULT_WINDOW_SIZE=15`, comb gen table),
and ran its `bench ecdsa_verify` back-to-back with `tests/bench_ecdsa`, both
under the same load (the live replay was consuming ~6 cores):

    cmake -S /storage/bitcoin-core-source/src/secp256k1 -B <scratch> \
      -DCMAKE_BUILD_TYPE=Release -DSECP256K1_BUILD_BENCHMARK=ON \
      -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
      -DSECP256K1_BUILD_CTIME_TESTS=OFF -DSECP256K1_BUILD_EXAMPLES=OFF
    cmake --build <scratch> --target bench
    SECP256K1_BENCH_ITERS=20000 <scratch>/bin/bench ecdsa_verify

| | µs / verify | verifies / s / core |
|---|---|---|
| libsecp256k1 (Core v31.99 config) | **21.8** (min 21.4, max 23.1) | **≈ 45,900** |
| bitcoinmachinecode `ecdsa_verify` | 120.9 | 8,271 |

**The crypto gap is 5.5×, not the ~1.5–2.5× assumed earlier from public
figures.** That single measurement reframes §4: the secp256k1 side is a far
bigger lever than the first GLV scoping estimated, and libsecp256k1's
advantage is the *stack* of techniques (GLV split, wNAF with a 15-bit
window, 5×52 field representation, lazy reduction, batch inversion), not
GLV alone.

Sub-conclusion: the gap is real but it is a **two-front problem** — crypto
and storage I/O — not the single crypto optimisation the first GLV scoping
(§4.3) implied.

## 2. Where the cycles go (live profile, 2026-08-21, height ≈ 430,000)

Method: `perf record -p <download-worker> -g --call-graph dwarf`, 10 s
sample, 94,607 events. The on-disk `daemon/bitcoind` had been rebuilt several
times since the process loaded it, so `perf report` printed raw offsets
against `bitcoind (deleted)`. Ground truth was recovered by copying
`/proc/<pid>/exe` and bisecting samples against its `nm` table after
correcting for the fact that perf printed **file offsets, not virtual
addresses** (`VA = offset + 0x400000`; validated — offset `0x368d8` rebases
to exactly the `fe_mul.zero` label). 100 % of the previously-unresolved
userspace samples resolved.

DSO split: **bitcoind 60.2 % · kernel 37.9 % · libc 3.9 %.**

Top bitcoind self-time (share of bitcoind's own 60 %):

| share | symbol | note |
|---|---|---|
| 42.0 % | `fe_mul.zero` | secp256k1 field multiply, `secp256k1_fe.asm` |
| ~38 % | `..@28.zt` … `..@35.zt` (8 labels) | `sc_mul`'s internal loop, `secp256k1_scalar.asm` |
| 3.4 % | `sc_mul.zero_cur` | |
| 2.2 % | `fe_mul` (prologue) | |
| 1.8 % | `fe_sub` | |
| 1.7 % | `mac_read_exact2.re` | LSM run-file `read()` wrapper, `bitcoin_utxo_lsm.asm:259` |
| 1.7 % | `fe_add` | |
| 1.0 % | `point_double` | |
| 0.6 % | `sha256_block_shani` | |
| 0.3 % | `mac_run_lookup.ml_scan_loop` | LSM multi-run scan |
| 0.2 % | `sc_inv.inv_loop` | Fermat inversion driver |

Kernel self-time is almost entirely the file-read path:
`_copy_to_iter` (24.2 % of **all** cycles) → `copy_page_to_iter` →
`filemap_read` → `ext4_file_read_iter` → `vfs_read` ← `read()` syscall.

Rolled up as a share of **all** cycles:

- **secp256k1 field/scalar arithmetic ≈ 52–55 %** (`fe_*` + `sc_*` +
  `point_*`).
- **kernel file-read path ≈ 31 %.**
- everything else ≈ 15 %.

Two things this profile *corrects* from earlier in the same session:

1. The `..@2X.zt` labels are **not** a naive double-and-add `sc_mul`. That
   implementation was replaced with a constant-time schoolbook multiply on
   2026-08-16 (`5e39cc5`, `71985ca`); a stale header comment misled an
   earlier diagnosis (fixed in `5e9f8bc`). What the profile shows is the
   genuine cost of the optimised multiply, amplified by `sc_inv` calling it
   ~255 times per verify. This is near a floor, not a bug.
2. Actual EC point arithmetic (`point_double`, `point_scalar_mul_fixed`) is
   only ≈ 1.2 % of cycles. The crypto cost is field-multiply **volume**, not
   doubling count — which matters for how much GLV can deliver (§4.3).

## 3. The I/O finding — root cause

The 31 % read-path cost was not visible in a profile taken hours earlier at a
lower height; it is real and growing with the UTXO set.

Two code paths issue `read()` on this node:

- `mac_read_exact2` (`bitcoin_utxo_lsm.asm:259`) — raw `read()` in a retry
  loop, used by `utxo_lsm_get` to pull records from on-disk run files.
- `store_read_at` (`bitcoin_store_fast.asm:334`) — "two syscalls total on a
  warm fd cache (pread index, pread body)", one call per block.

**Verdict: UTXO LSM lookups dominate, not block-archive reads.** Evidence:
LSM-path symbols (`mac_read_exact2.re`, `mac_run_lookup.*`) appear in the
resolved top 25; no `store_read_at`-family symbol does. Call frequency
agrees — an LSM lookup fires once per transaction *input*, an archive read
once per *block*. (Not 100 % certain without tracing past the syscall
boundary, which perf's caller graph did not cleanly do; well-supported.)

This rules out a hypothesis raised the same day: the archive's
non-monotonic layout (`PLAN_SCRIPT_VERIFY.md`, "Related known issues") is
**not** the I/O cost — sequential-height reads against scattered `blk*.dat`
files would show up under `store_read_at`, and they don't.

Why LSM reads are expensive: `utxo_lsm_get` scans on-disk runs newest →
oldest until it finds the key, so read volume per lookup scales with
`manifest_n` — the number of unmerged runs sitting between compactions
(threshold `UTXO_LIVE_COMPACT_THRESHOLD` = 12). The same mechanism was
observed directly at the 21:24 restart the same day: with 11 unmerged runs
after reload, throughput was visibly degraded until the first compaction
collapsed them to 1.

## 4. Levers, prioritised

### 4.1 Reduce LSM read amplification — **top priority**

- *What:* compact more often (lower the run threshold from 12), and/or
  replace the newest→oldest linear run scan in `utxo_lsm_get` with a
  per-key index (e.g. a generation map or a single merged bloom over all
  runs) so a lookup touches far fewer run files.
- *Evidence:* ≈ 31 % of all cycles, measured; LSM symbols present in the
  resolved profile; read-amplification mechanism confirmed empirically at
  the 21:24 restart.
- *Impact:* **large** — currently the single biggest cost, roughly
  1.5–2× the crypto-side gap the original GLV scoping targeted.
- *Risk / effort:* threshold tuning is small; a lookup-structure change is
  medium. Consensus-adjacent: a wrong lookup is a wrong verify result, so
  it needs the same differential testing bar as the verifier itself, plus
  the "no test ever exercises this scale" caution recorded in
  `project_utxo_flush_compact_bug`'s history — the compaction path has hidden
  a scale-only bug before.
- *Timing:* wait for tip.

### 4.2 Inversions on the verify path — scoped 2026-08-21

Measured with callgrind on a single fixture verify (scratch harness linking
the repo's `.o` files; verify ≈ 2.72 M instructions). There are exactly
two inversions per `ecdsa_verify` (`grep 'call fe_inv\|call sc_inv'`:
`secp256k1_ecdsa.asm:138` and `:204`, nothing else on the path):

| callee | calls / verify | cost | share of verify |
|---|---|---|---|
| `sc_inv` (`:138`, Fermat `s^(n−2)`) | 1 → **450 `sc_mul`** (255 sq + 195 mul, `secp256k1_scalar.asm:450`) | 1.22 M Ir | **45 %** |
| `fe_inv` (`:204`, Jacobian→affine x) | 1 → **503 `fe_mul`** (255 sq + 248 mul, `secp256k1_fe.asm:700`) | 0.15 M Ir | 5.4 % |
| point arithmetic (`point_double` 253×, `point_add` 58×, `point_add_mixed` 73×) | ≈ 3,750 `fe_mul` + 4,700 `fe_add/sub` | 1.29 M Ir | ≈ 47 % |
| everything else | 2 `sc_mul`, 2 `fe_mul`, parsing | — | ≈ 2 % |

Two facts the live profile could not show: **`sc_mul` costs ≈ 9.4× a
`fe_mul` per call** (2,719 vs 290 Ir — the fold-based mod-n reduction), so
450 of them cost as much as all ~4,250 field multiplies; and the point
formulas are already standard (dbl 2M+5S, add 11M+5S, madd 7M+4S) — the
remaining point cost is op *count* (no GLV/wNAF), not formula choice. At
120.9 µs/verify: `sc_inv` ≈ 54 µs, point arithmetic ≈ 57 µs, `fe_inv`
≈ 6.5 µs.

**What Core does** (`ecdsa_impl.h:195` `secp256k1_ecdsa_sig_verify`):
`secp256k1_scalar_inverse_var` — a variable-time safegcd inverse, neither
Fermat nor batched — then ecmult, then **no field inversion at all**:
`secp256k1_gej_eq_x_var` (`:257`) checks `r·Z² == X`; if that fails and
`r < p − n` (`secp256k1_ecdsa_const_p_minus_order`, `:261`) it retries with
`r + n` (`:266`). Valid because `2n > p`. Core never batches ECDSA
inversions.

**Why batching is the wrong first move.** Legacy-script inputs — the whole
current replay range and nearly all pre-2017 history — reach
`ecdsa_verify` from *inside* the interpreter (`script_eval` →
`checksig_fn` → `sv_checksig`, `bitcoin_scriptverify.c:217`),
synchronously, because `OP_CHECKSIG`'s result can steer script control
flow. Batching there needs a deferred-verify restructure; only the
witness-v0 direct calls (`bitcoin_segwit.c:375/:388/:448`) and the worker
slices in `txvb_verify_all` (`tx_verify.c:891-909`) offer a clean batch
point. So the levers, in order:

**A — inversion-free x-compare (drop `fe_inv`).** Replace
`ecdsa.asm:196-244` with Core's projective test; Z² is already computed at
`:200`. Pure algebra, identical verdict on every input. −5.4 % ≈ −6.5 µs.
*Small* (~40–60 asm lines). The `r + n` branch fires with probability
≈ 2⁻¹²⁷ for a real signature, so it must be tested at function level with
a constructed `(X, Z)` where `X = (r+n)·Z²`, plus the `r ≥ p − n` negative.

**B — variable-time scalar inverse (the real prize).** `sc_inv_var`:
binary extended GCD over 256-bit limbs (~10–15 k Ir, ≈ 4–6 µs) or
libsecp's safegcd (~1–2 µs, harder, ~600 lines). Dispatch it at
`ecdsa.asm:138` only; keep Fermat `sc_inv` for secret-scalar paths. Within
policy: `secp256k1_point_ct.asm`'s header and `ENGINEERING_RULES.md`
confine constant-time to secret scalars, and `s` is public. `ecdsa_in_range`
(`:126-135`) already rejects `s = 0` / `s ≥ n` before `:138` — keep that
ordering. −45 % ≈ −50 µs → **~70 µs/verify (1.7×)**; with A, ~63 µs —
**gap to libsecp256k1 5.5× → ~2.9×**. Also makes `sc_mul`'s per-call cost
irrelevant to verify (2 calls left). *Medium* (~200–300 asm lines);
exactness provable by differential test vs Fermat over ≥ 10⁶ random `a`
plus `1, 2^k, n−1, n−2^k`, and `a·inv(a) ≡ 1`.

**B′ — Montgomery batching, after B, witness-v0 only.** Per worker slice:
range-check every `s` first (one zero poisons the prefix-product chain),
one `sc_inv_var` + 3(k−1) `sc_mul`. After B this saves ≤ 5 %; not worth
the `txvb_verify_one` restructure until a post-B profile says otherwise.

**A′ — Schnorr.** `secp256k1_schnorr.asm:302/:313` do two `fe_inv` per
verify; the same projective trick applies. Taproot-era only
(> 709,632) — flagged, not scoped.

*Effort* (calibrated: CLTV/CSV ≈ 310 lines/session, taproot script-path
≈ 933 lines/long session): A ≈ ⅓ session, B ≈ 1 session incl. harness,
B′ ≈ 1 session deferred. *Timing:* all change `ecdsa_verify`'s instruction
stream — branch now, merge after the replay reaches tip, and require the
second full-chain replay to match the first's accept/reject decisions
before deploy.

**Status 2026-08-21 — A and B BUILT on branch `perf-inverse`, not merged.**
`ecdsa_x_eq_mod_n` (projective compare, exported for the `r+n` branch test)
and `sc_inv_var` (binary xgcd, dispatched only at `ecdsa.asm`'s
`w = s^{-1}`; Fermat `sc_inv` untouched for signing) are in, with
`tests/test_ecdsa_inverse.c`: 1,001,023 `sc_inv_var` vs `sc_inv` cases
(10⁶ random + every edge listed above), 6,008 `ecdsa_x_eq_mod_n` cases
including the constructed `r+n` branch and the `r == p−n` boundary, and
113,315 `ecdsa_verify` new-vs-frozen-reference cases (1,024
libsecp256k1-signed fixtures × 13 variants + 10⁵ random tuples) — 0
mismatches. Out-of-tree: 5,000 `sc_inv_var` outputs vs Python
`pow(a,−1,n)` and 10⁵ further libsecp256k1-signed signatures through new
and reference — 0 mismatches.

| same moment, replay + Core sync loading the box | µs / verify | /s/core |
|---|---|---|
| before (`main`, min of 3) | 115.4 | 8,662 |
| after (branch, min of 3) | **56.8** | **17,599** |
| libsecp256k1 bench | 22.0 | ~45,500 |

**2.03× on ecdsa_verify; gap to libsecp256k1 5.2× → 2.6×.**

Building this found two pre-existing lost-carry bugs in the multiplies
themselves, both fixed as the branch's first commit with exact-vector
regression tests (`tests/test_mul_carry_regression.c`):
`sc_mul`'s MULACC propagated carries only two limbs (lost `2^256 ≡ DELTA`
when the third limb was `0xFFFF…`; `sc_inv(6)`, `sc_inv(n−2)`, `sc_inv(n−k)`
were wrong), and `fe_mul`'s fold 2 dropped the carry out of limb 3 (lost
`2^256 ≡ C`; `fe_inv(p−k)` wrong). Random-operand probability ~2⁻⁶⁴ and
~2⁻¹⁹⁰ per product — invisible to every random differential, deterministic
on structured chains. Those fixes are independent of A/B and
cherry-pickable to `main` ahead of the post-tip gate.

### 4.3 GLV endomorphism split — **revised down**

- *What:* decompose the `u2·Q` scalar via the curve's efficient
  endomorphism and run a dual-scalar Strauss/Shamir ladder — halves the
  doubling chain for the variable-point multiply. Full scope (constants,
  `sc_split_lambda`, `point_scalar_mul_dual`, signed-scalar handling,
  required test campaign, 2–4 session estimate) was produced earlier the
  same day and stands.
- *Evidence for the revision:* this profile shows point arithmetic at only
  ≈ 1.2 % of cycles. GLV cuts doubling *count*; it does not cut the
  `fe_mul`/`sc_mul` volume that actually dominates. The earlier scoping
  reasonably assumed point ops were the crypto cost; they are not.
- *Impact:* **medium**, down from the earlier estimate. Still real; still
  the standard reason libsecp256k1 is faster.
- *Risk / effort:* large / high, unchanged. Most GLV bugs in the wild are
  sign-handling errors in the split scalars.
- *Timing:* wait for tip; do after 4.1 and a scoping of 4.2.

### 4.4 Archive read-ahead tuning

- *What:* `store_rd_advise` (`bitcoin_store_fast.asm`) already does
  fadvise-based prefetch for block-archive reads.
- *Impact:* **low** — archive reads are not the I/O bottleneck (§3).
- *Timing:* orthogonal to the verify path, could be built now; not worth
  the attention yet.

### Not levers (ruled out this session)

- **`sc_mul` algorithm** — already optimised (see §2); nothing to fix.
- **Downloader write ordering / monotonic archive** — not the I/O cost
  (§3); the reorg and pruning problems it blocked were solved without it
  (`9269a86`, `a051f21`).
- **CUDA offload** — a validated batch ECDSA kernel exists
  (`asm/cuda/`, `1e648af`), but per-launch overhead (~170 ms measured for
  the SHA sibling) makes per-block offload a net loss, and the host GPU is
  currently saturated by an unrelated process (header audit measured the
  CPU path 1.46× *faster* than GPU on 2026-08-21). Shelved until the node
  is stable at tip and GPU capacity is actually available.

## 5. Summary

At height ≈ 430 k with full verification on, ~85 % of all cycles are split
between secp256k1 field/scalar arithmetic (≈ 53 %) and UTXO LSM read I/O
(≈ 31 %). Reaching full-verification Core parity means attacking both.

The measured 5.5× crypto gap (§1) means the two fronts are closer in size
than the cycle split alone suggests: if the crypto side reached
libsecp256k1 speed, its 53 % would shrink to roughly 10 % of today's
cycles, leaving LSM I/O as the dominant cost by a wide margin.

Order of attack once the replay reaches tip, revised after the §4.2
inventory: **4.1 (LSM) → 4.2 A+B (projective compare + var-time scalar
inverse, ~25 % of all cycles for two contained routines) → 4.3 (GLV+wNAF,
which attacks the ~57 µs of point arithmetic that remains) → 4.2 B′**.
4.2 and 4.3 together have a measured ceiling to aim at — 21.8 µs/verify on
this CPU — not a guessed one.
