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

**Status 2026-08-22 — BUILT on branch `lsm-mmap`, not merged.** The root
cause turned out to be sharper than "too many runs are scanned": for every
lookup, for every run, `mac_run_lookup` (`bitcoin_utxo_lsm.asm:1197`)
`open`ed the run file and read the **entire bloom filter**
(`BLOOM_MAX_BYTES` = 4 MiB at bulk scale) into TLS scratch in order to test
exactly **3 bits**, then `lseek`/`read` its way through the sparse index and
records, then `close`d. That copy is the `_copy_to_iter` the profile put at
24 % of all cycles.

`asm/utxo_lsm_mm.c` adds a per-thread cache of read-only `mmap`s: a run is
opened and mapped once, and every later lookup against it is pure memory
access. `mac_run_lookup` calls it first and falls back to its original,
untouched code on `-2` (open/mmap failure, malformed run, any out-of-bounds
offset), so the audited asm remains the correctness anchor. Cache is
`__thread` (no locks; `MAP_SHARED PROT_READ` pages ARE the page cache, so
per-thread mappings cost page-table entries, not memory), direct-mapped over
64 slots keyed by `run_no % 64`, entries tagged with the run's generation.

Measured on identical work (`tests/test_utxo_lsm` under `strace -c -f`):

| syscall | before | after | |
|---|---|---|---|
| `read` | 480,714 | 28,723 | −94 % |
| `lseek` | 193,039 | 2,304 | −99 % |
| `open` | 24,982 | 1,820 | −93 % |
| `close` | 25,016 | 2,270 | −91 % |
| `mmap`/`munmap` | 141 | 975 | (the cache) |
| **total syscalls** | **781,882** | **94,918** | **−88 %** |
| **time in syscalls** | **0.778 s** | **0.125 s** | **−84 %** |

`tests/bench_lsm_get` (10 runs, lookups skewed to misses — the bloom-reject
path): **44,664 → 2,111,432 lookups/s, 47×**, with `fallbacks=0` confirming
the fast path serves every lookup rather than quietly degrading. That
microbench has small blooms and a warm page cache, so it is an upper bound;
the syscall table above is the honest structural number.

**`UTXO_LIVE_COMPACT_THRESHOLD` (12): leave it alone.** Lowering it was the
other half of the original proposal, and it is now the wrong lever. Its
purpose was to bound how many runs a lookup scans, because each run cost an
open + a multi-MiB read. Post-fix a scanned run costs three memory loads
against an already-resident mapping, so scan width barely registers, while
lowering the threshold would buy that irrelevance with strictly more
compaction I/O — the expensive direction. Revisit only if a profile taken
*after* this lands still shows run-scan cost.


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

**Status 2026-08-22 — A and B MERGED to `main` and deployed.**
The post-tip gate (§4 preamble: merge only after the running replay reaches
tip and a second replay reproduces the first's accept/reject decisions) was
resolved differently than planned, and deliberately: an unrelated
store-height off-by-one (genesis absent from the archive, so record index ==
real height − 1, shifting every height-gated activation by one block)
invalidated the in-flight replay anyway, forcing a restart from zero. That
fresh full-chain replay — on the fixed archive, with A+B in — IS the
gate: it must validate every block to tip. Verdict-equivalence is separately
covered by the 113,315-case differential against a frozen copy of the
pre-change verifier (below), which is the stronger of the two checks.
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
cherry-pickable, and landed as the first of the two commits.

### 4.3 GLV endomorphism + wNAF for `u2·Q` — scoped 2026-08-22, implementation-ready

*What:* replace the single `point_scalar_mul(P2, Q, u2)` at
`secp256k1_ecdsa.asm:319-322` with a GLV-split, dual-stream wNAF
Strauss/Shamir ladder: `u2 = r1 + λ·r2 (mod n)` with both halves ≤ 128 bits
(`scalar_impl.h:142-178`), one odd-multiples table of Q at window w=5
(`ecmult_impl.h:32,:73-123`) with the λ-table derived for free as `(β·x, y)`
(`group_impl.h:917-923`, `ecmult_impl.h:315-317`), and one ladder over both
digit streams (`ecmult_impl.h:252-365`): **~128 doublings instead of 252**.
The G side (comb table, zero doublings) and the 4.2-A projective compare are
untouched.

*Constants* (4×64 LE limbs, limb0 first — transcribed from Core and
**numerically verified**: λ³≡1 mod n, β³≡1 mod p, and `λ·G == (β·Gx, Gy)`
on the real curve, so this is the matching pair, not the conjugate):

| name | source | limbs |
|---|---|---|
| `LAMBDA` (mod n) | `scalar_impl.h:83` | `DF02967C1B23BD72 122E22EA20816678 A5261C028812645A 5363AD4CC05C30E0` |
| `BETA` (mod p) | `field.h:69` | `C1396C28719501EE 9CF0497512F58995 6E64479EAC3434E9 7AE96A2B657C0710` |
| `MINUS_B1` | `scalar_impl.h:144` | `6F547FA90ABFE4C3 E4437ED6010E8828 0 0` |
| `MINUS_B2` | `:148` | `D765CDA83DB1562C 8A280AC50774346D FFFFFFFFFFFFFFFE FFFFFFFFFFFFFFFF` |
| `G1` | `:152` | `E893209A45DBB031 3DAA8A1471E8CA7F E86C90E49284EB15 3086D221A7D46BCD` |
| `G2` | `:156` | `1571B4AE8AC47F71 221208AC9DF506C6 6F547FA90ABFE4C4 E4437ED6010E8828` |

*Algorithm:* split — `c1 = round((k·G1) >> 384)`, `c2 = round((k·G2) >> 384)`
via a 512-bit product taking limbs [6,7] plus the rounding bit (bit 383,
`scalar_4x64_impl.h:893-915`); `r2 = c1·MINUS_B1 + c2·MINUS_B2`;
`r1 = k − r2·λ` (all mod n). Sign rule: a half is negative iff bit 255 is
set (`ecmult_impl.h:176-179`, valid because n > 2²⁵⁵); negative → magnitude
`n − r` and negate every wNAF digit. wNAF (`:162-222`): length **129** (bit
128 can carry), w=5, odd digits |d| ≤ 15, index `pre[(|d|−1)/2]`, negate y
for d < 0. Table (`:73-123`): `d = 2Q`, isomorphism `C = d.z`, 7 mixed adds
recording z-ratios, then `ge_table_set_globalz` (`group_impl.h:289-310`) so
every entry shares one Z — **no inversion anywhere**; λ-table `aux[i] =
pre[i].x · β`. Ladder: per bit, double, then up to two mixed adds (one per
stream); finish with `R.z *= Z` (`:359-361`) **before** `P = P1 + R` so the
4.2-A compare sees a real-curve point.

*New vs existing in this codebase:* `sc_mul_512` (~40 lines, extract
`sc_mul`'s Phase-1 product at `secp256k1_scalar.asm:262-299` — `sc_mul` is a
*reduced* product and cannot be reused); `sc_split_lambda` (~120 lines);
`glv_wnaf` (~80 lines C, precedent `secp256k1_scalar_c.o`/`utxo_lsm_mm.c`);
`fe_neg` is absent — use `fe_sub(r, ZERO, y)`; `point_add_mixed_zr` (+10
lines, the z-ratio is `H` at `secp256k1_point.asm:205-212`);
`point_scalar_mul_glv` (~350-450 lines, model on `point_scalar_mul`
`:422-614`); kill switch `BMC_ECDSA_GLV=0` like `BMC_LSM_MMAP`.
**Latent bug to close first:** `point_add`/`point_add_mixed` do not handle a
Z=0 *operand* (return infinity instead of the other point; `:54-90` only
handles equal-X). Unreachable via `point_scalar_mul` today (it seeds R from
the top digit), reachable in a dual ladder — guard inside the primitives.

*Expected gain, derived from §4.2's measured costs* (dbl 2,320 Ir, add 4,640,
madd 3,162, fe_mul 290; verify ≈ 1.35 M Ir ≈ 56.3 µs):

| component | today | GLV w=5 + globalz |
|---|---|---|
| split + wNAF | — | ≈ 15.5 k |
| table | 14 madd = 44.3 k | 37.2 k |
| doublings | 252 × 2,320 = 584.6 k | **128 × 2,320 = 297.0 k** |
| window adds | 58 add = 269.1 k | ≈ 43 madd = 136.9 k |
| **`u2·Q`** | **898 k ≈ 37.4 µs** | **≈ 487 k ≈ 20.3 µs** |
| **`ecdsa_verify`** | **56.3 µs** | **≈ 39 µs** |
| gap to libsecp256k1 (21.8 µs) | 2.58× | **1.8×** |

A Jacobian-table variant without globalz gets ≈ 85 % of this (≈ 41.8 µs).
What remains afterwards is field representation — libsecp's 5×52
lazy-reduction `fe_mul` is ~4-5× cheaper per call than our 4×64 — and the
G-side comb (≈ 7.9 µs; libsecp's `WINDOW_G`=15 tables would be a "4.5").

*Risk:* sign handling in three places (half negativity, negative digit,
λ-table shares y); lattice rounding off-by-one (halves still satisfy the
identity but exceed 128 bits — caught only by **exact** comparison against
Python's split, not by the identity); wNAF needs 129 digit slots; the
globalz direction and the forgotten `R.z *= Z` are *silent* (only the
point-level differential catches them); Z=0 mid-ladder (~2⁻¹²⁸/step, guard
anyway). **Permanent runtime check:** after every split assert
`r1 + λ·r2 == k` (≈ 0.1 µs; libsecp does it in VERIFY builds) and on failure
**fall back to `point_scalar_mul`** — never abort a verify.

*Tests:* `sc_mul_512` vs Python 10⁶; `sc_split_lambda` vs Python **exact**
10⁶ + `{0,1,n−1,n−2,2¹²⁸,2¹²⁸−1,2²⁵⁵,n>>1,λ,n−λ}`; `glv_wnaf` 10⁶ reconstruct;
`point_scalar_mul_glv` vs `point_scalar_mul` ≥ 10⁵ `(k,Q)` compared
projectively incl. `Q ∈ {G, 2G, −G, λG}`; then the existing 113,315-case
`tests/test_ecdsa_inverse.c` campaign vs the frozen `ecdsa_verify_ref.asm`
unchanged — it is already the right gate.

*Staging:* branch `glv`, each commit suite-green: (a) Z=0 guards in
`point_add`/`point_add_mixed` (cherry-pickable bug fix); (b) `sc_mul_512` +
`sc_split_lambda`; (c) `glv_wnaf`; (d) `point_add_mixed_zr` +
`point_scalar_mul_glv` standalone + differential; (e) wire into
`ecdsa_verify` behind `BMC_ECDSA_GLV`. Deploy gate as 4.2, plus tonight's
lesson: watch the first checkpoint resume. **Effort ≈ 1,100-1,400 lines
incl. tests, 2-3 long sessions**, the risk concentrated in (d).

**Status 2026-08-22 — BUILT on branch `glv`, (a)–(e) all landed, not
merged.** Exactly the staging above: `3853c3f` Z=0 guards (the old code
failed all 10 infinity cases of `tests/test_point_inf.c`); `efa0606`
`sc_mul_512` + `sc_split_lambda` with the permanent identity check
(1,000,016 product cases vs a C schoolbook, 2,018 exact vectors vs the
Python oracle — which re-derives g1/g2/−b1/−b2 from Core's basis and
asserts they match the asm — 10⁶ identity+bounds, and 1,002,018 exact
out-of-tree); `82371b1` `glv_wnaf` (10⁶ reconstructed, both signs);
`45d6c65` `point_add_mixed_zr` + `point_scalar_mul_glv` with globalz
(102,056 projective cases vs `point_scalar_mul`, incl. `λG == (βGx, Gy)`,
the k×Q grid, every sign combination of the halves); (e) wired behind
`BMC_ECDSA_GLV` — the 113,315-case `test_ecdsa_inverse` campaign vs the
frozen reference passes with GLV on **and** with the switch off, and
`tests/test_ecdsa_glv_switch.c` pins glv/plain/reference to identical
verdicts on 30,240 cases. The globalz variant shipped, not the Jacobian
fallback.

| same moment, replay + oracle loading the box, min of 3 | µs / verify | /s/core |
|---|---|---|
| `main` (4.2 A+B) | 54.7 | 18,271 |
| `glv`, `BMC_ECDSA_GLV=0` | 54.8 | 18,238 |
| **`glv`, GLV on** | **35.3** | **28,350** |
| libsecp256k1 bench | 22.0 | ~45,500 |

Standalone `u2·Q`: 46.2 → 25.7 µs (1.8×). **`ecdsa_verify` 1.55×; gap to
libsecp256k1 2.5× → 1.6×** (the model above said 1.8×; the table build and
the adds came in cheaper than the derivation assumed). What remains is
field representation and the G side, as noted above.

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

## 4.6 Post-deploy profile — 2026-08-22 04:45 UTC, height ≈ 390 k

All of 4.1, 4.2 A+B and 4.3 deployed. Clean self-time `perf` (no call
graph), symbol-resolved against `/proc/<pid>/exe`, 204 k samples:

| share of all cycles | what |
|---|---|
| **74.0 %** | secp256k1 / hashing (`fe_*`, `sc_*`, `point_*`, `sha256`) |
| 14.2 % | libc (`memcpy`/`memmove` in block parsing and the verify pool) |
| 5.1 % | kernel — **was 31–38 %**; the LSM I/O wall is gone |
| 1.1 % | script interpreter |
| 0.9 % | UTXO apply / LSM |
| 0.1 % | verify-pool dispatch |

Top symbols: **`fe_mul` 55.9 %**, `fe_add` 4.1 %, `sc_inv_var` 3.6 %,
`fe_sub` 3.3 %, `sha256_block_shani` 1.4 %, `point_scalar_mul_glv` 1.2 %,
`point_double` 1.1 %. `point_scalar_mul` (the non-GLV path) is 0.00 % —
GLV is executing, no fallback; `sc_inv`/`fe_inv` are 0.00 %;
`mac_read_exact2` is 0.00 % — the mmap path serves every lookup.

**Reading:** the replay is now almost purely bound by the field multiply.
GLV cut the *number* of point operations (≈ 252 → 128 doublings) but each
still costs our ~290-instruction 4×64-limb `fe_mul` with full reduction.
libsecp256k1's 5×52-limb lazy-reduction `fe_mul` is ~4–5× cheaper per call;
that representation change is the next lever and the last large one on the
crypto side (then the G-side `WINDOW_G`=15 tables, ≈ 5–6 µs).

## 5. Summary

Session result, all deployed and running on the live rebuild:

| | before (08-21 AM) | after (08-22 04:45) |
|---|---|---|
| `ecdsa_verify` | 115–121 µs | **~39 µs** (loaded: 44) |
| vs libsecp256k1 on this CPU (21.8 µs) | 5.2× slower | **1.65× slower** |
| kernel (I/O) share of cycles | 31–38 % | **5 %** |
| replay, identical heights 343087→363086 (before GLV) | 7.8 blk/s | **34.1 blk/s (4.39×)** |
| replay, identical heights 378845→398844 (with GLV) | 3.9 blk/s | **22.2 blk/s (5.68×)** |

The two walls the first profile found — inversions and bloom copies — are
both gone. What remains is `fe_mul` at 56 % of cycles: **field
representation (5×52 lazy reduction) is the next scope**, projected to take
`fe_mul` from ~290 to ~70 Ir and the verify from ~39 µs to the low 20s —
i.e. parity with libsecp256k1 is now one representation change away, not a
stack of them. Order after that: G-side tables (4.5), then whatever the next
clean profile shows.

### 5.1 Sustained throughput at depth — 2026-08-22 evening

The multipliers above are **baseline-matched**: same heights, old code vs
new. They are the honest way to measure a code change, but they are not the
number you want for "how long to tip", because block density keeps rising.
One clean uninterrupted run, measured end to end on the deployed binary:

| span | wall clock | rate |
|---|---|---|
| 537,616 → 575,833 (38,217 blocks) | 16:35:23 → 17:38:59 (3,816 s) | **10.0 blk/s** |

Full signature verification, no `assumevalid`, 16 verify threads, mmap run
cache on. That is ~3.4× slower than the 34.1 blk/s measured at 343k–363k —
almost entirely block density (inputs per block), not a regression: the
343k-era blocks predate segwit and carry a fraction of the signature work.
Treat 10 blk/s as the current realistic planning figure for the 500k–600k
band and expect it to keep falling through the taproot/inscription era.

A caveat for anyone projecting from this: raising `stopatheight` to extend
the download ceiling **pauses the replay entirely** for the duration of the
download leg (they do not interleave), so wall-clock to tip includes those
pauses — roughly 20 minutes per 58k blocks fetched from the local oracle at
~30 blk/s.

### 5.2 The field rewrite — BUILT on branch `fe-repr`, not merged

Scoped in §5 as "5×52 lazy reduction", targeting `fe_mul` from ~290 to ~70 Ir
and the verify from ~39 µs to the low 20s. **What shipped is not 5×52.** The
first measurement of the session invalidated the premise, so the plan changed;
the numbers that forced that are below, and they are the main deliverable of
this section along with the code.

#### The premise that was wrong

§4.6 recorded, from public knowledge rather than measurement, that
"libsecp256k1's 5×52-limb lazy-reduction `fe_mul` is ~4–5× cheaper per call".
Built libsecp256k1's own `bench_internal` and, separately, a single process
linking libsecp's field code **and** this repo's `secp256k1_fe.o` so both run
in one harness under one load (`scratch hh.c`, CPU-time, min-of-25):

| ns per call, min-of-25 | this repo (main `cb20051`) | libsecp256k1 5×52 | ratio |
|---|---|---|---|
| `fe_mul`, serial dependency chain | 12.87 | 9.36 | 1.38× |
| `fe_mul`, 4 independent chains | 10.46 | 4.33 | **2.42×** |
| `fe_sqr`, serial chain | 13.12 | 8.20 | 1.60× |

So the representation gap was **2.4×, not 4–5×**, and only in the
throughput-bound regime. Two further facts settled the direction:

- libsecp256k1 ships **no x86-64 field assembly at all** (`src/asm/` contains
  only `field_10x26_arm.s`); its 5×52 `fe_mul` is `__int128` C. It was beating
  hand-written assembly.
- Probing this CPU directly (scratch `uarch.asm`, serial-`add` clock
  reference): `mulx` 0.664 cyc/op throughput, `adcx`+`adox` on two interleaved
  chains 0.501 cyc/op, achieved clock 5.48 GHz. A 4×64 `fe_mul` needs 21
  multiplies; libsecp's 4.33 ns is 23.7 cycles, i.e. libsecp's 25-multiply
  5×52 kernel was already sitting near the multiplier port limit. **A 4×64
  kernel that also sat near that limit would be at parity or better** — with
  no representation change, no lazy-reduction magnitude bookkeeping, and no
  edit to `secp256k1_point.asm` (84 `fe_*` sites), `secp256k1_point_ct.asm`
  (59), `bitcoin_pubkey.asm`, `bitcoin_keys.asm`, `secp256k1_ecdsa.asm`,
  `secp256k1_schnorr.asm`, `secp256k1_taproot.asm` or `wallet_msgsign.c`.

Diagnosis of the real problem: `main`'s `fe_mul` was 290 instructions for
work that needs ~110. It materialised each row `a_i*B` into its own 40-byte
stack buffer, merged the four buffers with memory-to-memory `add`/`adc`, then
reduced through memory using `mul` (which forces rax/rdx) with three-
instruction `xor edx,edx / add / adc rdx,0` carry captures. **The
representation was never the cost; the constant factor was.**

**Choice made: keep 4×64 canonical, rewrite the kernels.** Stated plainly
because it is a deviation from the scope: this trades ~20 % of the remaining
theoretical field gain for a change that touches ONE file, keeps every
existing test applicable unchanged, and is provable limb-for-limb against the
implementation that has been validating the chain. On consensus code that
trade is not close.

#### What changed (`asm/secp256k1_fe.asm`, one file, no API change)

- **`fe_mul`** — same algorithm, same two-fold reduction, zero memory traffic.
  The 512-bit product and both folds live in registers (15 of the 15 usable
  GPRs); every carry is captured by ADCX/ADOX on two interleaved chains
  instead of by an `add`/`adc` pair. 21 multiplies, ~36 ADX ops.
- **`fe_sqr`** — was `jmp fe_mul`. Now a dedicated square: 10 multiplies
  instead of 16 (six off-diagonal products accumulated once, doubled with one
  shift-left chain, then the four diagonal squares on a single ripple carry).
  Squaring is ~40 % of the field multiplies on the verify path.
- **`fe_add` / `fe_sub`** — rewritten around the identity `p = 2^256 - C`, so
  "subtract p" is "add C" and the carry out of `v + C` *is* the predicate
  `v >= p`. No `P_LIMBS` load, no four-limb comparison, and no callee-saved
  spills at all. **Bit-identical to the previous code on every 512-bit input
  pair, in range or not** — "add p" and "subtract C" are the same operation on
  wrapping 4-limb arithmetic — which is why this was safe to do without first
  proving no caller ever passes a non-canonical value.
- The reduction has exactly **one** implementation: `fe_sqr` jumps to
  `fe_mul.reduce` (documented entry contract) rather than carrying a copy.
  That code has already produced one consensus bug; two copies could drift.

| instructions in the function | before | after |
|---|---|---|
| `fe_mul` | 290 | 113 |
| `fe_sqr` | 291 (`jmp fe_mul`) | 105 (56 + the 49-instruction shared reduce) |
| `fe_add` | 48 | 31 |
| `fe_sub` | 36 | 19 |

Callgrind on a 100,000-call `fe_mul` chain: **296 → 112 Ir/call.**

#### Measured

`tests/bench_fe` — new in-tree microbenchmark. CPU time
(`CLOCK_THREAD_CPUTIME_ID`), min-of-25 rounds of 200,000 calls, spread
printed; the same discipline commit `879554b` applied to
`test_scalarmul_ct`, and mandatory here because the live replay was consuming
~10 of 32 threads throughout. Two regimes are reported because they bracket
the real cost: a serial dependency chain (latency) and four independent chains
(throughput — closer to what point arithmetic achieves).

| ns per call | before | after | speedup | libsecp256k1 |
|---|---|---|---|---|
| `fe_mul` latency chain | 12.87 | **8.53** | 1.51× | 9.36 |
| `fe_mul` 4 indep. chains | 10.46 | **5.52** | **1.90×** | 4.33 |
| `fe_sqr` latency chain | 13.12 | **7.67** | 1.71× | 8.20 |
| `fe_sqr` 4 indep. chains | 10.73 | **4.68** | **2.29×** | — |
| `fe_add` latency chain | 2.20 | 2.20 | 1.00× (48→31 instructions) | ~0 (inlined) |
| `fe_sub` latency chain | 1.68 | **1.28** | 1.31× | — |

Head-to-head again afterwards, both implementations in ONE process under one
load (the same `hh.c` harness that produced the "premise was wrong" table):

| ns per call, min-of-25 | this branch | libsecp256k1 5×52 | |
|---|---|---|---|
| `fe_mul`, serial chain | **8.92** | 9.65 | **1.08× faster** |
| `fe_sqr`, serial chain | **7.79** | 8.21 | **1.05× faster** |
| `fe_mul`, 4 indep. chains | 5.76 | 4.48 | 1.28× slower |

So the 4×64 kernel now **beats** libsecp's 5×52 on latency and remains 1.28×
behind on throughput. That residual is precisely what lazy reduction buys and
this change deliberately did not take: libsecp's `fe_mul` returns a
non-canonical result of bounded magnitude, skipping the conditional subtract,
and its `fe_add` is five adds with no reduction at all (measured at 0.000 ns
because it inlines to nothing) against our 2.31 ns canonical add. Closing
that last 1.28× is what a real 5×52 lazy-reduction conversion would be for —
and it is now worth ~11 % of a verify, not the 2× the original scope assumed.

Spreads were tight: `fe_mul` after, 25 rounds, min 5.515 / median 5.646 /
max 7.700 ns. `fe_add`'s *latency* is unchanged — it is a serial
load→add→cmov→store chain and always was — but it costs 35 % fewer
instructions, which is what its share of a throughput-bound verify responds to.

`tests/bench_ecdsa`, upgraded to CPU-time min-of-N in the same commit,
alternating old and new binaries in one session so drift lands on both:

| µs / verify, min-of-7 rounds x 20,000 | | /s/core |
|---|---|---|
| `main` `cb20051` field, best of 3 runs | 35.28 | 28,342 |
| **this branch, best of 3 runs** | **25.66** | **38,964** |
| libsecp256k1 `bench ecdsa_verify`, best of 3 | 20.6 | ~48,500 |

**`ecdsa_verify` 1.37×; gap to libsecp256k1 1.71× → 1.25×.** The §5 target was
"low 20s"; 25.7 µs is close but short of it, and the honest reading is that
the remaining gap is no longer mostly field representation — after this
change, a callgrind attribution of one verify puts `fe_mul`(+`fe_sqr`) at
61.7 % of retired instructions, `fe_add` at 9.3 %, `sc_mul` 6.7 %, `fe_sub`
6.6 %, and the whole verify at 415 k Ir / 140 k cycles (IPC 2.95). The next
lever is the G-side comb table (§4.5), not another field pass.

#### Correctness — what was actually proved

`tests/test_fe_repr.c` (new, in the `test` target) plus
`validation/fe_oracle.py` (new) and `tests/fe_ref.asm` (new: a FROZEN copy of
`main`'s field, symbols suffixed `_ref` — the implementation that replayed the
chain to height ~575,000, including the incident #7 fixes). **39,266,927
checks, 0 failures, 1.3 s.**

1. **Python ground truth, explicit.** 1,600 `(a, b, a+b, a-b, a*b, a², a⁻¹)`
   tuples from Python big integers. Shares nothing with the assembly.
2. **Python ground truth, exhaustive over the structured space.** A 1,547-value
   structured family — every `2^i`, `2^i±1`, `p-2^i`, `p-2^i±1` for all 256
   bit positions, `0..7`, `p-1..p-8`, `C-1/C/C+1/2C/p-C/p-2C`, and per-limb
   saturation patterns — crossed with itself: **2,393,209 ordered pairs**,
   `a*b`, `a+b` and `a-b` for each, folded into one digest that the harness
   recomputes from the assembly and compares to Python's. Every limb boundary
   against every other limb boundary.
3. **Differential vs the frozen `fe_ref`**, limb-exact: the same 2,393,209
   structured pairs, plus 4,000,000 random in-range pairs
   (mul/add/sub/sqr) — 0 differences.
4. **Non-canonical input.** 4,000,000 full-range `[0, 2^256)` pairs plus a
   structured sweep with `p` deliberately added to one operand, proving the
   `fe_add`/`fe_sub` bit-identity claim on inputs neither implementation
   defines a result for. 0 differences.
5. **Algebraic identities** independent of both implementations: 800,000 of
   `(a+b)-b == a`, `a*(b+c) == a*b+a*c`, `a*a⁻¹ == 1`, `fe_sqr(a) ==
   fe_mul(a,a)`, and canonicality of every result.
6. **Incident #7's exact operand** is pinned in this file as well as in
   `test_mul_carry_regression`: `(p-2^31)² == 2^62`.

**Sensitivity proven by mutation, both ways.** Eight deliberate carry bugs
were injected and every one is caught: dropping the pending CF at the end of
phase-1 row 3; deleting the fold-2 carry correction (literally re-introducing
incident #7); dropping the fold-1 carry absorb; deleting the bit that
`fe_sqr`'s doubling chain carries into T7; removing `fe_add`'s carry fold;
flipping `fe_sub`'s correction sign; removing `fe_mul`'s canonicalisation;
and moving one `fe_sqr` diagonal term a limb too low. The pre-existing
`tests/test_fe` **misses** the fold-2 mutation, and
`test_mul_carry_regression` misses both `fe_sqr` mutations — which is the
argument for the new file existing.

Whole-stack equivalence, out of tree: a digest harness ran the 1,024
libsecp256k1-signed fixtures × 13 mutated variants, 200,000 random verify
tuples, and a 200,000-step `fe_inv`/`fe_mul`/`fe_sqr` chain **digesting every
intermediate**, built twice — once against the new field, once against
`main`'s. All three digests identical (`717fb4cf77f2d725`,
`a04995f0966e4025`, `48249430d5520df1`). In tree, the existing
`tests/test_ecdsa_inverse` campaign (1,001,023 `sc_inv_var` cases, 6,008
`ecdsa_x_eq_mod_n`, 113,315 verify-vs-frozen-reference) and
`test_ecdsa_glv_switch` (30,240 three-way) pass unchanged, as does
`test_scalarmul_ct` — **the constant-time guard, which matters because
`fe_mul`'s canonicalisation stayed branch-free `cmov` rather than becoming a
conditional jump.** Nothing on the signing path became variable-time; no
variable-time optimisation was introduced at all in this change.

**One hazard this change created, and how it was closed.** The new `fe_mul`
reuses `rsi` as the fold's fifth limb and the new `fe_add` reuses `rsi`/`rdx`
as canonicalisation scratch. Both are caller-saved under SysV so this is
legal, but the OLD `fe_add`/`fe_sub`/`fe_mul` happened to leave `rsi` intact,
and 163 hand-written call sites across `secp256k1_point.asm` (78),
`secp256k1_point_ct.asm` (54), `bitcoin_pubkey.asm` (10), `bitcoin_keys.asm`
(6), `secp256k1_schnorr.asm` (6), `secp256k1_taproot.asm` (6) and
`secp256k1_ecdsa.asm` (3) could have been relying on that accident. A static
scan found no site reading `rsi`/`rdx` after an `fe_*` call before writing it,
and then the point was settled dynamically: a build with EVERY caller-saved
register (`rsi, rdx, rcx, rdi, r8-r11`) deliberately poisoned with `0xDEAD…`
at every `ret` in `secp256k1_fe.asm` passes `test_fe`, `test_point`,
`test_point_inf`, `test_addm`, `test_add`, `test_scalarmul`,
`test_glv_pointmul`, `test_ecdsa`, `diff_add_ct_homog`, `test_scalarmul_ct`,
`test_mul_carry_regression`, `test_schnorr`, `test_pubkey` and `test_keys`
unchanged. Nothing depends on the old register-preservation accident.

Not verified: no replay of real chain data was run against this branch (the
live daemon is mid-replay and is not to be touched), so the deploy gate of
§4's preamble still applies.

### 5.3 AVX-512 IFMA — evaluated, measured, and NOT built

libsecp256k1 ships no IFMA field backend, so this is where this project could
exceed it rather than approach it. Per the scoping rule, the CPU was measured
before anything large was built.

**Instruction-level probes** (scratch `uarch.asm`/`uarch.c`, min-of-15,
CPU-time, clock established by a serial `add rax,1` chain = exactly 1 cyc/op):

| | cyc/op | note |
|---|---|---|
| achieved clock | — | **5.478 GHz** under the live replay |
| `mulx`, independent | 0.664 | ~1.5/cycle |
| `adcx`+`adox`, two interleaved chains | 0.501 | 2/cycle — the fe_mul design target |
| `vpmadd52luq` zmm, 8 independent accumulators | **0.550** | ~1.8/cycle × 8 lanes |
| `vpmadd52luq` zmm, serial chain | 4.008 | latency 4 cycles |
| `vpmadd52luq` ymm | 0.557 | identical to zmm — no 512-bit penalty |

**Downclocking: there is none worth modelling on this part.** Immediately
after a sustained AVX-512 burst the scalar clock read 5.469 GHz against a
5.478 GHz baseline. Under **eight** concurrently running sustained IFMA hogs
(on top of the replay) the scalar clock moved 5.429 → 5.305 GHz (−2.3 %,
explicable by the added load alone) and scalar `fe_mul` was unchanged:
8.686 → 8.677 ns latency, 5.675 → 5.791 ns throughput. This is the Zen 5
answer, and it is not Intel's.

**A real 8-way kernel was then built and validated**, not extrapolated:
5×52 limbs, one field element per lane, 25 lane-parallel products as 50
`VPMADD52{LU,HU}Q`, a ten-limb carry normalisation, and the `2^260 ≡ C·2^4`
fold — 63 IFMA and ~91 other vector instructions. Checked against this repo's
scalar `fe_mul` over 20,000 chained rounds × 8 lanes = 160,000 products, with
the structured shapes (`0`, `1`, `p-1`, `p-2^31`, `2^255`, `2^64-1`, a
limb-2-all-ones value, `p-2`) pinned into specific lanes: identical.

| ns per field multiply | |
|---|---|
| scalar `fe_mul` after §5.2, 4 indep. chains | 5.52 |
| **IFMA 8-way, 4 indep. chains** | **1.343** (min-of-15; med 1.446, max 1.722) |
| IFMA 8-way, single chain | 2.619 |

**4.11× on the field multiply, and the hardware objection does not apply.**
One trap worth recording: with `acc[10]` written as a loop over an array, gcc
kept the accumulators on the stack and the kernel measured **4.28 ns** — 3.2×
worse than the unrolled version, and a number that would have produced the
wrong verdict. The measurement is only valid because the disassembly was
checked (27 `vmovdqa64` and 6 `vpmadd52` in a loop, versus 63 `vpmadd52` and
no spills after unrolling).

**Verdict: a genuine win at the kernel, correctly deferred as a project.**
Not because of the silicon — the silicon is willing — but because of what
lane-parallelism costs *above* the kernel:

- Every consumer must be rewritten 8-wide. `fe_add`/`fe_sub` become nearly
  free, but the point formulas, the GLV ladder, the wNAF digit handling and
  the scalar side are a **second complete implementation of the EC stack**,
  in vector form, on the consensus path — beside the scalar one, which cannot
  be retired because odd-sized batches still need it.
- The per-lane table read is solvable but not free: each lane has its own
  `Q`, so the eight w=5 table entries for a lane cannot be packed into one
  zmm and selected with a single `vpermq`. A table read becomes ~8 blends per
  limb (or a `vpgatherqq`, which is slow on Zen) — with the globalz table's
  two coordinates × 5 limbs that is ~80 vector ops per windowed add, on top
  of the add itself. Estimated, not measured.
- **The batching point does not exist yet for most of the remaining work.**
  §4.2 already recorded this: legacy-script inputs — nearly all pre-2017
  history — reach `ecdsa_verify` synchronously from inside the interpreter
  because `OP_CHECKSIG`'s result steers script control flow. Only the
  witness-v0 direct calls and the `txvb_verify_all` worker slices offer a
  clean place to collect eight independent verifications.

So the honest ordering is: **the deferred-verify restructure is the
prerequisite, and it is worth doing on its own merits** (it also unlocks
§4.2 B′ Montgomery batching). IFMA is what you build *after* that exists, and
only if a profile at that point still says the field multiply is the wall.
Recorded here with the numbers so the next scoping does not have to
re-measure the CPU.

Ceiling, for whoever picks this up: if the whole 74 % crypto share went 4×,
Amdahl gives 1/(1 − 0.74·0.75) = **2.3×** on replay — real, but a second EC
implementation's worth of consensus risk for it.

### 5.4 Projected effect on replay throughput — and the Amdahl bound

From §4.6's post-deploy profile: `fe_mul` (which then included every
`fe_sqr`, since `fe_sqr` was `jmp fe_mul`) was **55.9 %** of *all* replay
cycles, `fe_add` 4.1 %, `fe_sub` 3.3 %; crypto+hashing together 74.0 %.

**State the bound first: even an infinitely fast `fe_mul` only removes its own
55.9 %**, capping the whole lever at 1/(1 − 0.559) = **2.27×** on replay. Every
number below is a fraction of that ceiling, not of the runtime.

Applying the measured throughput-regime speedups to their measured shares:

| component | share of all cycles | speedup | cycles removed |
|---|---|---|---|
| `fe_mul` + `fe_sqr` | 55.9 % | 1.90× (sqr better, 2.29×) | 26.5 % |
| `fe_add` + `fe_sub` | 7.4 % | ~1.4× (instruction count 84→50) | 2.1 % |
| everything else | 36.7 % | 1.00× | 0 |

→ 1/(1 − 0.286) = **≈ 1.40× on replay block throughput**, i.e. ~47 % of the
theoretical `fe_mul` headroom captured. That projection is corroborated
rather than assumed: the independently measured end-to-end `ecdsa_verify`
improvement is **1.37×**, and `ecdsa_verify` is the dominant consumer of
those same cycles.

Against §5.1's measured 10.0 blk/s in the 537,616 → 575,833 band, that
projects **≈ 14 blk/s** in the same band. Caveats, stated because this number
will be quoted: the 55.9 % share was measured at height ~390 k and block
composition keeps shifting toward more signature work per block (which, if
anything, makes the crypto share *larger* and the projection conservative);
the projection assumes the replay is CPU-bound, which §4.6 supports (kernel
5.1 %); and no replay was actually run on this branch, so this is a
projection from two measurements, not an observation.


## 6. Beyond parity — what would actually beat Bitcoin Core

Scoped 2026-08-22 evening. Sections 1-5 aim at *parity* with libsecp256k1.
This section is about exceeding it, and starts with the uncomfortable part.

### 6.0 We have not measured Core, so "faster than Core" is currently unfalsifiable

Every multiplier in this document is **this code against itself**, old vs
new, at matched heights. That is the right way to measure a change and it
says nothing about Core. The only like-for-like comparison is Core doing a
full-verification IBD (`-assumevalid=0 -stopatheight`) in a scratch datadir
on this machine, and it has never been run. Until it is, any claim to beat
Core is unsupported.

It is deliberately **not** run while the replay is live: it would contend
for CPU and disk with the thing being measured, giving Core an artificially
bad number and slowing our own replay. Queue it for a quiet window, pin
cores, and state the pinning.

Note also the asymmetry that makes the honest comparison harder: Core
defaults to `assumevalid`, skipping historical signature verification
entirely. Our replay always verifies in full. A fair contest must force
`-assumevalid=0`; a *useful* framing also records what Core's default does,
because that is what users actually run.

### 6.1 The hardware we are on (measured, not assumed)

`AMD Ryzen 9 9950X3D` (Zen 5), 16C/32T, **128 MiB L3**, plus:
`avx512f avx512dq avx512vl avx512ifma adx bmi2 sha_ni gfni vaes avx512_vnni`.
GPU: `RTX 5090`, 32 GB, compute 12.0 — already driving the CUDA `sha256d`
path (~17-18× CPU at N=1,000,000).

Two of these matter a great deal and were not being exploited:
**`avx512ifma`** and the **128 MiB L3**.

### 6.2 Parity lever: 5×52 lazy reduction (§4.6, in progress)

`fe_mul` is 55.9 % of all replay cycles at ~290 Ir/call against
libsecp256k1's 5×52. Closing this is worth ~39 µs → low 20s on
`ecdsa_verify` and is the whole of the remaining primitive gap. It is
parity work: it makes us as fast as Core's crypto, not faster.

### 6.3 Exceed lever: AVX-512 IFMA lane-parallel field arithmetic

`VPMADD52LUQ`/`VPMADD52HUQ` perform 8 lanes of 52-bit multiply-accumulate.
**libsecp256k1 ships no IFMA field backend**, so unlike §6.2 this is not a
gap to close but an instruction set Core does not use.

The shape that fits: block validation verifies many **independent**
signatures. Eight independent verifications in flight across lanes suits
IFMA; vectorising *inside* one verification mostly does not, because the
carry chain serialises. Caveats to measure rather than assume: Zen 5's IFMA
throughput differs from Intel's, and AVX-512 downclocking can eat the win.
A measured "not worth it" is a valid and useful outcome here.

### 6.4 Exceed lever: BIP340 batch verification

Core verifies Schnorr signatures **individually** in consensus. BIP340
supports batch verification at roughly 2-3× individual, and a block is
almost always valid, so the fallback-to-individual path on failure is rare
and cheap. This gets more valuable exactly where the replay is heading:
script-path taproot spends are heavy from ~775,000 (one sampled block held
44,933 script-path inputs — see `CHAIN_AHEAD_CENSUS.md`).

Not started yet, deliberately: it touches `bitcoin_taproot_sighash.c`,
which had in-flight work at the time of writing. Sequence it after that
lands to avoid a merge conflict in consensus code.

### 6.5 Exceed lever, highest risk: GPU signature verification

The 5090 already does `sha256d`. Batch ECDSA/Schnorr on GPU is the largest
theoretical win and by far the largest correctness risk — consensus
verification returning a wrong verdict is a chain split. It should come
last, behind a byte-exact differential against the asm path over millions
of real chain signatures, and behind a bit-exact CPU fallback on any CUDA
error (the pattern `sha256d` already uses).

### 6.6 What Amdahl allows

Crypto is 74 % of replay cycles, `fe_mul` 55.9 %. Even an *infinitely* fast
`fe_mul` leaves 44 % of the work, i.e. a ceiling of about 2.3× end-to-end
from field arithmetic alone. Getting past that requires the UTXO/apply path
and the archive read path to come down too — which is why §4.1's mmap work
(kernel 31 % → 5 %) mattered so much and why the next profile after §6.2
lands should be taken before choosing anything here.

## 7. The re-profile that changed the answer — 2026-08-22, height ≈ 617,000

§6.6 said to re-profile before choosing the next lever. Doing so immediately
after deploying the field rewrite (§5.2) invalidated the ranking in §6.

Method: `perf record -p <worker> -F 999` for 20 s, **no call-graph** (self
time only — an inclusive `-g` profile misled a diagnosis earlier the same
day), 132,785 samples, live replay at height ~617,000.
DSO split: bitcoind 92.3 % · libc 6.0 % · kernel 1.8 %.

| self time | symbol | where |
|---|---|---|
| **22.44 %** | **`read_cs`** | `bitcoin_segwit.c` compactsize reader |
| 17.10 % | `fe_mul.reduce` | field |
| 15.89 % | `fe_mul` | field |
| 5.92 % | `sw_seq` | `bitcoin_segwit.c` |
| 5.71 % | `sw_prevout` | `bitcoin_segwit.c` |
| 3.85 % | `__memmove_avx512` | libc |
| 3.69 % | `fe_add` | field |
| 2.36 % | `fe_sub` | field |
| 1.66 % | `point_double` | EC |
| 1.45 % | `sha256_block_shani` | hashing |
| 1.37 % | `fe_sqr` | field |

**Two shifts, both decisive.**

**1. Crypto is no longer dominant.** It was 74 % of cycles at height ~390 k
(§2/§4.6); it is now roughly 45 %, and `fe_mul`+`reduce` is 33 % where
`fe_mul` alone was 55.9 %. Part of that is §5.2's own doing; the rest is
that the UTXO set has grown to ~106 M entries, so the storage and
serialisation sides have grown around the crypto. This is why the deployed
field rewrite delivered **~1.15 × end-to-end** (10.31 vs 8.95 blk/s at
comparable depth) against a ~1.40 × projection computed from the *old*
shares. The projection arithmetic was right; its input was stale. Amdahl
inputs age — re-measure them, never carry them forward.

**2. `read_cs` + `sw_seq` + `sw_prevout` = 34 %, and it is an O(n²) bug,
not a constant factor.**

`sw_prevout(t,i)` and `sw_seq(t,i)` each walk the input list **from the
start** to reach input `i`, parsing a compactsize per step — and BIP143's
hashPrevouts/hashSequence call them once per input. That is O(nin²)
varint reads. `sw_ser_txout(t,i)` is worse: it re-walks every input *and*
the first `i` outputs on each call, so hashOutputs is O(nin·nout + nout²).
For the 1,372-input transaction in `CHAIN_AHEAD_CENSUS.md` that is ~1.9 M
redundant reads for hashPrevouts alone.

Core does not have this cost at all: `PrecomputedTransactionData` walks the
transaction **once** and hashes the three vectors in a single pass.

**The fix is a single-pass precompute** — walk the tx once recording each
input's and output's offset, then index. It removes a super-linear term
whose weight grows with transaction size, which is exactly the direction
the remaining chain is heading (segwit-era blocks carry far larger
transactions than the ~390 k blocks the original profile sampled).

**Revised lever order**, replacing §6's:

1. **Single-pass BIP143 precompute** — ~34 % of cycles, removes an O(n²)
   term, contained to one file, no new instruction set, no consensus-format
   change. Biggest and safest win available.
2. Re-profile again. The shares will have moved again.
3. G-side comb table (§4.5) — `fe_mul` is still ~33 %, so the field path
   still matters, just less than it did.
4. §6.3 IFMA / §6.4 BIP340 batch — both still real, both still gated on the
   deferred-verify restructure that §5.2(b) identified as the actual
   prerequisite.

The general lesson, twice over in one session: a performance plan built on
a profile is only as current as the profile. This one was ~227,000 blocks
stale and it inverted the top of the list.

**Amendment (incident #21): these three functions just got slower, on
purpose, and the single-pass rewrite must not undo the reason.**

`read_cs` was unbounded — a compactsize's width comes from its own first
byte, so every walk in `bitcoin_segwit.c` could read up to 8 bytes past the
end of the transaction — and `sw_ser_txout` wrote an output's scriptPubKey
into a 600-byte stack buffer with no check at all, which real mainnet
transactions from height ~927,500 onward overflow. Both are fixed;
`read_cs` now takes the buffer end, and `sw_prevout`/`sw_seq` bound each
step of their walk.

That is not free, and it lands exactly on the 34% this section is about.
Measured on `segwit_v0_sighash` alone (min of 12–15 runs, `-O2`, the
census's 1,372-input shape, 100 outputs):

| build | ms/call | vs main |
|---|---|---|
| before the fix | 2.44 | — |
| bounded `read_cs` only | 2.54 | +4% |
| as shipped (walk steps bounded too) | 2.84 | +16% |

Most of the cost is *not* the bounded reader: it is the per-iteration bound
in `sw_prevout`/`sw_seq`, which is redundant in the sense that `swtx_parse`
has already validated the identical byte range before either is called. It
was kept anyway, because "a distant function already checked this" is how
incidents #13 and #21 both happened, and because the fix below deletes these
loops entirely.

**So lever 1 is now worth more, not less.** A single-pass precompute walks
the transaction once with one bounded pass and indexes afterwards — it
removes the O(n²) *and* the repeated bound checks, which together are the
whole of this 34%. When it is written: the single walk must keep the
`end`-bounded reader and must bound each `q += sl` against the remaining
length rather than forming `q + sl` first (a wire-derived length near 2^64
overflows the pointer into a comparison that passes). The `cap` on
`sw_ser_txout` is a consensus-safety bound, not a policy one, and must
survive in whatever replaces it.

**Amendment (2026-08-22, see §10): item 3 of that order changes.** "5×52 lazy
reduction" was tested and rejected — measured at 1.07 × on `ecdsa_verify` in
its cheapest *correct* form, against 49 field-element value-inspection sites
it would have to normalise, four of which decide a doubling branch by limb
equality and would silently return infinity where they should return 2P.
The same measurement pass found that `fe_sqr` was being called **zero** times
per verification (this table's `fe_sqr` 1.37 % was the symptom, read at the
time as "squaring is rare") and that `point_double` carried a dead `fe_mul`
and a dead `fe_sub`. Fixing those is worth ≈ 1.11 × on `ecdsa_verify`
(nine alternating pairs over three sessions, median 1.107) with no change to
any field kernel. The remaining field lever is a small-constant
multiply and inlining the field ops into the EC formulas — **not** the
representation. §10 has the numbers.

## 8. Lever 1 built and measured — single-pass BIP143 precompute, 2026-08-22

§7's lever 1 is implemented (`asm/bitcoin_segwit.c`, branch
`bip143-precompute`). This section is the measurement; the design is in the
file's own comments and in `LOG.md`.

**What it does.** One bounded pass over the transaction records the offset of
every input and every output; `sw_prevout`/`sw_seq` become array indexes, and
the CTxOut serialization disappears entirely because a CTxOut's BIP143
encoding *is* its wire encoding — so `hashOutputs` is a `sha256d` over a
contiguous slice of the transaction, in place, with no copy. The walks
`read_cs` was called from are gone, and so are the per-iteration bounds §7's
amendment measured at +16%: the loop they guarded no longer exists.

### 8.1 Microbenchmark — `tests/bench_segwit_sighash`

New and permanent (`make tests/bench_segwit_sighash`), `-O2`, CPU time
(`CLOCK_PROCESS_CPUTIME_ID`), min of 15 runs, both builds back to back.

| shape | tx size | before | after | factor |
|---|---|---|---|---|
| 1 in / 2 out | 189 B | 0.3960 µs | **0.3718 µs** | 1.07× |
| 2 in / 2 out | 304 B | 0.4364 µs | **0.4052 µs** | 1.08× |
| 100 in / 5 out | 11,667 B | 16.830 µs | **2.510 µs** | 6.7× |
| 1,372 in / 100 out | 160,894 B | 2.633 ms | **30.57 µs** | 86× |
| 2 in / 3,000 out | 93,244 B | 5.115 ms | **42.14 µs** | 121× |

Spread (min / median / max) on the two extremes: before, 2.633 / 2.640 /
2.652 ms and 5.115 / 5.134 / 5.297 ms; after, 30.57 / 30.72 / 30.87 µs and
42.14 / 42.19 / 42.40 µs. The 1,372-input row is §7's shape; its "before" min
of 2.63 ms is consistent with incident #21's 2.84 ms on a busier machine.

**The common case is not pessimised** — that was the thing to check, because
an asymptotic win that cost the 1- and 2-input shapes would be a bad trade on
this chain. Both are slightly *faster*: even at two inputs the old code walked
the input list twice per aggregate hash.

### 8.2 The measurement that matters — real blocks at the profiled height

The microbenchmark says the asymptote moved; it does not say what the replay
will feel. So: 20 real mainnet blocks, heights 616,980–617,018 — the exact
window §7 profiled — pulled from the Core oracle, with every one of their
**53,400 witness inputs** driven through `segwit_v0_sighash` (taproot
activates at 709,632, so at these heights every witness input is segwit v0).
CPU time, min of 9:

| | total | per witness input |
|---|---|---|
| before | 5,735.90 ms (med 5,765.87, max 6,913.13) | 107.41 µs |
| after | **209.00 ms** (med 212.54, max 218.50) | **3.91 µs** |

**27.4× on the real workload.**

`read_cs` call counts over the same 20 blocks, from an instrumented build —
this is what apportions §7's 22.44%:

| | BIP143 sighash path | `strip_witness` (1× per tx) | total |
|---|---|---|---|
| before | 4,339,573,177 | 437,615 | 4,340,010,792 |
| after | 32,451,774 | 437,615 | 32,889,389 |

**131.9× fewer `read_cs` calls.** The middle column is why it is here:
`strip_witness` also calls `read_cs`, runs once per transaction, and is *not*
changed by this work — and it is 0.010% of the old total. So essentially all
of §7's `read_cs` share is the BIP143 aggregate hashes, and essentially all of
it goes.

### 8.3 End-to-end projection, and the Amdahl bound stated

§7's shares at height ≈617,000: `read_cs` 22.44% + `sw_seq` 5.92% +
`sw_prevout` 5.71% = **34.07%** of all replay cycles.

**Amdahl ceiling: 1 / (1 − 0.3407) = 1.517×.** Nothing in this change can beat
that, because 65.93% of the profiled cycles are untouched by it.

Residual, two ways:
- from the whole-function measurement (27.4×): 34.07 / 27.4 = 1.24% →
  **1.489×**;
- from the `read_cs` counts (131.9×, with `sw_seq`/`sw_prevout` deleted
  outright rather than reduced): ≈0.2% → **1.512×**.

So the projection is **1.49–1.51×** — within a couple of points of the
ceiling, and the gap between the two methods is smaller than the uncertainty
in the share itself.

**Independent corroboration that the benchmark drives the profiled work.**
The old path costs 107.41 µs per witness input and §1 measured `ecdsa_verify`
at 120.9 µs, so sighashing cost about as much as the signature check. 96.4% of
that sighash cost is removed here, which predicts the three symbols at
**45.3%** of that pair's cycles. §7's profile puts them at 34.07% against
42.07% for the field/EC symbols (`fe_mul.reduce`, `fe_mul`, `fe_add`,
`fe_sub`, `point_double`, `fe_sqr`), i.e. **44.75%**. Two independent routes,
0.6 points apart.

**What this projection is not.** §7 exists because a projection built on a
227,000-block-stale profile said 1.40× and delivered 1.15×. The share above is
measured at height ≈617,000 and the replay has moved on; blocks further up the
chain carry different transaction shapes, and past 709,632 they carry taproot
inputs that do not use this code at all. **Re-profile at the height the replay
is actually at before believing 1.49×.** The number that does not depend on
the share, and will hold at any height, is the 27.4× on the component.

Also excluded: this is a userspace-cycles projection. §7's DSO split was
bitcoind 92.3% / libc 6.0% / kernel 1.8%, so there is little else in the
sample, but storage I/O behaves differently under different cache states.

No post-change profile of the daemon was taken. The change is not deployed —
the deployment rule at the top of this file says nothing lands until the
replay reaches tip clean — and `perf_event_paranoid` is 4 on this host, which
blocks `perf` for a non-root user; changing a system setting to take a profile
was out of scope.

### 8.4 One real behaviour change, and it is toward Core

Hashing each CTxOut in place instead of re-serializing it is only equivalent
if the transaction's compactsizes are **minimally encoded**. The old
`sw_ser_txout` wrote `put_cs(len)`, i.e. the canonical form, so a padded
length (`fd 00 00` for 0, say) was silently rewritten before hashing; the raw
bytes are not rewritten, and the two answers differ. Neither answer is Core's:
Core's `ReadCompactSize()` throws "non-canonical ReadCompactSize()" and
refuses to deserialize such a transaction at all, so it cannot appear in any
block Core accepts.

So `read_cs` now enforces minimality — Core's exact rule — and refuses instead
of hashing. That makes in-place hashing *provably* identical to canonical
re-serialization for every transaction not refused, rather than merely
identical on the transactions that happen to exist. It costs the hot path
nothing (the single-byte encoding returns before the test).

Found while proving this, and **not** fixed here: nothing else in the tree
enforces minimality — `bitcoin_tx.asm`'s compactsize readers do not — so a
peer's non-canonical transaction is still mis-parsed everywhere else, which is
a pre-existing divergence from Core at the block-acceptance level, not
something this path introduced.

### 8.5 What this says about the next lever

Two things, in order of confidence.

1. **`bitcoin_taproot_sighash.c` is the same bug, unfixed, and it goes hot at
   height 709,632.** `tx_seq`, `tx_outpoint`, `ser_txout` and `ser_txout_len`
   each walk the input (and output) list from the start on every call, and
   BIP341's aggregate hashes call them once per input — the identical O(n²).
   `ser_txout_len` walks the output list *twice* per call. Worse, that file's
   `read_cs` is **unbounded** (it takes no `end`) and its bound tests are
   written in the `q + sl > end` pointer form that incident #21 had to remove
   from `bitcoin_segwit.c` because a wire-derived length near 2^64 overflows
   it. The taproot path is script-path-heavy from ~775,000 (one sampled block
   in `CHAIN_AHEAD_CENSUS.md` had 44,933 script-path inputs). Same fix, same
   bounds class; not done here because a performance restructure and a
   consensus-path bounds fix should not land in one commit.
2. **Re-profile.** With 34% removed, everything else's share rises by ~1.5×
   and the ranking will move again — the standing lesson of §7. The field
   kernels (`fe_mul` + `reduce`, 33%) become ~49% of what is left, which puts
   §4.5's G-side comb table back at the top on share alone.

### 8.6 What was deliberately not done

A per-transaction *cache* of the three hashes across the inputs of one
transaction — Core's `PrecomputedTransactionData` proper — was scoped and
rejected on measurement. `segwit_v0_sighash` is called once per executed
`OP_CHECKSIG` from deep inside the interpreter (`sv_checksig_witness_v0`),
which has no transaction-scoped context to hang a cache on, so it would have
to be a thread-local keyed on the transaction's address and length. That key
is not sound on its own — a different transaction can land at the same address
with the same length — and making it sound needs a full byte-compare against a
retained copy on every call. Priced out: on the 1,372-input shape the compare
costs about half of what the rebuild now costs, so the cache would buy ~2× on
the rarest shape and ~0 on the common one, against a wrong-sighash failure
mode if the key ever aliased. After this change the sighash is 3.91 µs against
`ecdsa_verify`'s 120.9 µs — 3.1% of a witness input's cost — so there is
little left to win. Revisit only if a re-profile puts this path back near the
top.

## 9. Deployed end-to-end result — measured 2026-08-22 evening

Both of the day's performance changes are live: the field-kernel rewrite
(§5.2, deployed 19:40) and the single-pass BIP143 precompute (§8, deployed
21:35).

| | height band | rate |
|---|---|---|
| before both | 537,616 → 575,833 (38,217 blk / 3,816 s) | **10.01 blk/s** |
| after both | 656,104 → 666,855 (10,751 blk / 790 s) | **13.61 blk/s** |

**1.36×, and that is a floor rather than the figure.** The two bands are not
the same work: the second sits ~120,000 blocks deeper, where transactions
carry far more inputs and outputs. Measuring the true same-depth factor would
mean reverting and re-replaying identical heights — hours of wall clock for a
number that would only revise an already-known-conservative result upward. It
was not done, and the figure is quoted as a floor accordingly.

**A warning about every other rate number from this session: they are
contaminated.** Full `make -k test` suites and up to four verification agents
ran on this same 32-thread box throughout the evening, competing with the
replay for CPU. One window containing a change that cost a measured +16 % on
one function shows a 43 % end-to-end drop — that is contention, not code. The
two rows above were both taken during comparatively quiet periods, and the
component benchmarks in §5.2 and §8 (CPU-time, min-of-N, both builds back to
back) are the numbers to trust. **If a future session wants a clean
end-to-end figure, take it with nothing else running.**

**Do not compose the component factors.** §8's sighash path got 27.4× on real
blocks, and §5.2's `ecdsa_verify` 1.37×. The end-to-end result is neither,
nor their product: §8 removed ~34 % of cycles, which caps it at 1.52× by
Amdahl regardless of how fast that component became, and §5.2's share was
smaller than the profile it was planned against. Component speedups multiply
against their own share only.

## 10. 5×52 lazy reduction — TESTED AND REJECTED; what shipped instead

Scoped 2026-08-22 as the largest remaining field-layer lever, on the strength
of §7's profile (`fe_mul.reduce` 17.10 % self time, `fe_mul` 15.89 % — the
reduction costing more than the multiply it reduces) and §5.2's closing note
that the residual 1.28 × throughput gap to libsecp256k1 "is precisely what
lazy reduction buys and this change deliberately did not take".

**The hypothesis was tested directly and it is wrong.** The measurements are
below; they are the deliverable of this section. What shipped is a different
change, found while measuring, that is worth *more* than the correct-and-safe
version of lazy reduction would have been and costs no representation change
at all.

### 10.1 The hypothesis, stated so it can fail

> 4×64 has no headroom, so every product must be reduced immediately. 5×52
> exists to create 12 spare bits per limb, and *that* is what makes lazy
> reduction possible — accumulate several results, reduce once. libsecp256k1's
> speed is the representation **plus** lazy reduction as a system. §5.2
> measured 5×52's *multiply* and correctly found no advantage; it may have
> been right about the multiply and wrong about the system.

The premise is sound. The conclusion does not follow, for a reason that only
shows up when you measure the *whole* field API rather than `fe_mul`.

### 10.2 Where the cycles inside `fe_mul` actually are

`tests/bench_fe` methodology throughout (CPU time, `CLOCK_THREAD_CPUTIME_ID`,
min-of-25 rounds × 200,000 calls, spread printed, live replay consuming ~5-10
of 32 threads). Four cut-down variants of the shipped kernel were assembled,
each stopping one stage earlier. **`p1` and `p1+fold1` do not compute a
correct result** — they exist only to attribute cost.

| ns/call, min-of-25 | LAT (serial chain) | THRU (4 indep. chains) |
|---|---|---|
| phase 1 only — the 512-bit product, 16 `mulx` | 3.213 | 3.133 |
| + fold 1 (4 `mulx`) | 4.642 | 4.009 |
| + fold 2 and its carry re-fold (1 `mulx`) | 7.421 | 4.714 |
| + canonicalisation (the shipped `fe_mul`) | 8.307 | 5.390 |

So the reduction is **43 % of `fe_mul` in the throughput regime and 62 % in
the latency regime** — §7's 17.10 % is real, not a symbol-attribution
artifact. Of that, the final conditional subtract of *p* — the one step
lazy reduction actually skips — is 0.68 ns THRU / 0.89 ns LAT, i.e. 12.6 % /
10.6 % of a whole `fe_mul`.

### 10.3 The ceiling of laziness, measured

Build the field with the canonicalisation deleted from `fe_mul`/`fe_sqr` and
from `fe_add`. This is **not correct code** — nothing normalises anywhere —
but it is an honest upper bound on what any lazy scheme can return in this
representation, and `tests/bench_ecdsa` still accepts its fixture, so the
timing is real work.

| min-of-25 / min-of-7×20,000 | shipped | lazy ceiling |
|---|---|---|
| `fe_mul` LAT / THRU | 8.53 / 5.50 | **7.56 / 4.77** |
| `fe_sqr` LAT / THRU | 7.60 / 4.62 | **6.60 / 4.10** |
| `fe_add` LAT | 2.18 | **1.29** |
| `ecdsa_verify`, best of 3 alternating runs | 27.77 µs | **24.91 µs** |

**Ceiling: 1.115 × on `ecdsa_verify`.** And note where that lands `fe_mul`:
4.77 ns THRU, against libsecp256k1's 5×52 at 4.33-4.48 ns and 9.36-9.65 ns
LAT. **Those libsecp figures are §5.2's, from a different session under
different load** — the one-process head-to-head harness was not rebuilt here,
so treat the cross-comparison as ±5 % and the same-build comparisons above as
tight. On that basis laziness closes the throughput gap from ≈ 1.25 × to
≈ 1.08 ×, i.e. **most of §5.2's 1.28 × was the canonicalisation, not the
representation** — and on latency 4×64 is already 1.24-1.28 × *faster* than
5×52.

That is already most of the answer: after laziness, the representation itself
is worth ≈ 8 % of `fe_mul` throughput and is a ~25 % latency *regression*.

### 10.4 Why the ceiling is not reachable in 4×64 — and why 5×52 exists

The ceiling build is wrong in a specific, instructive way. Once `fe_mul` may
return a value in [0, 2^256) rather than [0, p), **`fe_add` and `fe_sub` both
need a second correction round**:

- `fe_add`: with a, b < 2^256 the sum can reach 2^257 − 2. The fold of the
  257th bit adds C; that add can itself carry out, and today's single fold
  would silently drop a 2^256. Reachable (a = b = p + C − 1), not theoretical.
- `fe_sub`: on borrow the wrapped value can be < C, so the single "subtract
  C" correction borrows again and lands a full C low.

Both are provably terminating after one more round (when the second carry
fires the survivor is < C, so limbs 1..3 are zero and a bare `add r8, C`
cannot carry), so the fix is 3 instructions each. Measured with those
3-instruction fixes in place — the cheapest *correct* lazy 4×64 field:

| min-of-25 | shipped | lazy, correct |
|---|---|---|
| `fe_mul` LAT / THRU | 8.46 / 5.44 | 7.55 / 4.99 |
| `fe_sqr` LAT / THRU | 7.93 / 4.82 | 6.99 / 3.95 |
| `fe_add` LAT | 2.18 | **2.31 — no better** |
| `fe_sub` LAT | 1.27 | **2.32 — 1.8 × worse** |
| `ecdsa_verify`, best of 3 alternating | 27.09 µs | 25.31 µs |

**1.070 ×, not 1.115 ×.** The second fold in `fe_add` gives back exactly what
deleting the canonicalisation won, and `fe_sub` — which needed no
canonicalisation in the first place — becomes a straight regression. There
are 1,243 `fe_add` and 1,436 `fe_sub` per verification against 2,262
`fe_mul` (counted, not estimated: instrumented entry counters, below), so
add+sub outnumber mul and their regression eats most of the gain.

**This is precisely the headroom argument, and it is what kills 4×64
laziness — but it does not save 5×52.** In 5×52 the add is five bare `add`s
with no carry propagation and no correction, which is why libsecp's `fe_add`
benched at 0.000 ns in §5.2: it *inlines to nothing*. Behind a function-call
boundary with memory-resident operands — which is what this codebase has, 163
hand-written `fe_*` call sites across seven `.asm` files — a 5×52 add is
still 5 loads, 5 adds and 5 stores. Measured here: a 4×64 add with no
correction at all is 0.97 ns THRU. **The one structural advantage of 5×52 is
realisable only by inlining the field ops into the EC formulas, which is a
different lever and independent of the representation.**

### 10.5 The blast radius, since it decides the trade

A full read of the non-test tree found **49 places that inspect a field
element's value** rather than feeding it back into another `fe_*`: 8
zero/infinity tests, 8 limb-by-limb field equalities, 6 parity tests, 6
serialisations, and 15 range checks or hand-rolled `p − x` corrections
(`secp256k1_point.asm` 7, `secp256k1_point_ct.asm` 1, `secp256k1_ecdsa.asm`
5, `secp256k1_schnorr.asm` 7, `secp256k1_taproot.asm` 5, `bitcoin_pubkey.asm`
5, `bitcoin_keys.asm` 2, `wallet_core.c` 2, `wallet_msgsign.c` 15).

Four of them are the dangerous kind. `point_add`'s `U1 == U2` and
`point_add_mixed`'s `U2 == X1` decide the doubling branch by limb equality.
A non-canonical operand makes two field-equal values compare unequal, so the
routine takes `.distinct`, computes H = 0, and returns **infinity where it
should return 2P** — a wrong consensus verdict, silently, on an
input-dependent basis. That is the incident-#7 failure class made worse, and
it is the class this project has already been bitten by twice.

**Verdict: 1.07 × on `ecdsa_verify` (≈ 1.03 × end-to-end) in exchange for
non-canonical field elements flowing through 49 inspection sites and 163 call
sites in consensus code. Rejected. Not built.** 5×52 is rejected a fortiori:
it buys ≈ 8 % of `fe_mul` throughput over lazy 4×64, loses ~25 % of its
latency, and requires all of the above *plus* a representation change.

### 10.6 What shipped instead — found while instrumenting, worth more

Counting `fe_*` entries per `ecdsa_verify` (counters at each function's first
instruction) produced the finding that made this section worth writing:

    before   fe_add 1243   fe_sub 1436   fe_mul 2262   fe_sqr 0   fe_inv 0

**`fe_sqr` was called zero times.** The dedicated squaring kernel added in
§5.2 — 10 multiplies instead of 16, measured at 4.62 ns THRU against
`fe_mul`'s 5.50 — was dead on the verification path, because the EC layer
spelled every squaring `fe_mul(r, a, a)`. Its 1.37 % in §7's table is
`pubkey_parse` (2 calls per input, `bitcoin_pubkey.asm`) and
`scalar_to_pubkey` — the only `fe_sqr` callers in the tree. The signal was
there and was read as "squaring is rare" rather than "the EC layer never
dispatches it". Two changes, both contract-preserving:

**(a) 20 `fe_mul(a, a)` call sites routed through `fe_sqr`** — 14 in
`secp256k1_point.asm`, 3 in `secp256k1_point_ct.asm`, 1 each in
`secp256k1_ecdsa.asm`, `secp256k1_schnorr.asm`, `secp256k1_taproot.asm`.
Sites were identified by abstract-interpreting the `rdi`/`rsi`/`rdx` setup
before every `call fe_mul` and keeping those where `rsi` and `rdx` resolve to
the same effective address; the now-dead `rdx` setup was removed with the
call. `fe_sqr` is branch-free, so `point_scalar_mul_ct` and the rest of the
signing path stay constant-time.

**(b) A dead `fe_mul` and a dead `fe_sub` deleted from `point_double`.** It
computed `E*(D − X3)` into slot S6, then unconditionally overwrote S6 with
the `Y1*Z1` stash before anything read it, then recomputed `E*(D − X3)` from
scratch. The comment left in place ("was clobbered by S6 above; recompute")
shows the recompute was added deliberately and the now-dead original was
never removed. `point_double` runs 126 times per verification — it is the GLV
ladder's inner step — so this is 126 wasted `fe_mul` and 126 wasted `fe_sub`
per signature.

    after    fe_add 1243   fe_sub 1310   fe_mul 1169   fe_sqr 967   fe_inv 0

252 field operations per verification deleted outright, and 967 of the
remaining 2,136 multiplications now dispatch to the cheaper kernel.

**No field kernel changed.** `asm/secp256k1_fe.asm` is byte-identical to
`main`; `fe_mul`, `fe_sqr`, `fe_add` and `fe_sub` cost exactly what §5.2
measured. The win is entirely in *which* kernel is called and *how often*.

### 10.7 Measured

`tests/bench_ecdsa`, CPU-time min-of-7 rounds × 20,000, old and new binaries
alternated so drift lands on both. **Three independent sessions**, three
pairs each — because the first session's spread was wide enough that a single
best-of-3 would have overstated the result. Session 2 was run after the full
suite; session 3 after rebasing onto §8:

| µs / verify | before | after | pair ratio |
|---|---|---|---|
| session 1, pair 1 | 27.43 | 24.77 | 1.107 |
| session 1, pair 2 | 27.52 | 24.54 | 1.122 |
| session 1, pair 3 | 28.50 | 24.67 | 1.155 |
| session 2, pair 1 | 28.96 | 25.92 | 1.117 |
| session 2, pair 2 | 27.44 | 25.15 | 1.091 |
| session 2, pair 3 | 28.28 | 25.87 | 1.093 |
| session 3, pair 1 | 29.66 | 27.11 | 1.094 |
| session 3, pair 2 | 28.92 | 25.57 | 1.131 |
| session 3, pair 3 | 29.20 | 26.46 | 1.104 |
| **best-of-3 per session** | 27.43 / 27.44 / 28.92 | 24.54 / 25.15 / 25.57 | **1.118 / 1.091 / 1.131** |

**`ecdsa_verify` ≈ 1.11 ×** — nine pairwise ratios spanning 1.091-1.155,
**median 1.107**, mean 1.113, and three independent best-of-3 estimates of
1.118, 1.091 and 1.131. Everything below uses **1.11 ×**. Quoting the single
best pair (1.155 ×) would be exactly the mistake §7 was written about, and so
would quoting one session. Per-core rate at the best-of-3 points: 36,462 →
40,756 /s, 36,447 → 39,768 /s, 34,578 → 39,106 /s. Absolute µs drifts by ~8 %
between sessions with the replay's load; the *ratio* is stable to ±3 %, which
is the argument for alternating rather than comparing across sessions.

For calibration, measured the same alternating way in the same conditions,
this is at or above the *correct* lazy-reduction build (1.070 ×) and near the
*incorrect* lazy ceiling (1.115 ×) — with no change to the field
representation, no magnitude bookkeeping, and no new value domain anywhere.
Those two lazy figures are single-session best-of-3 and carry the same ±3 %
uncertainty this table exposes; the ordering is what the comparison supports,
not the third digit.

A caution that cost half a day here: **`bench_fe` is sensitive to code
alignment at the ±0.5 ns level.** A variant that changed only `fe_add` moved
`fe_mul` LAT from 8.46 to 9.14 ns. Any field micro-optimisation claiming less
than ~1 ns must be confirmed at the `ecdsa_verify` level, where the effect is
averaged over 2,000+ calls at many alignments. Three contract-preserving
restructurings of the reduction (fusing the carry re-fold with the
canonicalisation into ADCX/ADOX chains committed by `CMOVO`; a short
`AND`-tree canonicalisation predicate; the same for `fe_add`) were built and
proved bit-identical to the shipped kernels — a digest over 1,695,204
structured pairs (mul, add and sub each) plus 400,000 **full-range**
(deliberately non-canonical) random pairs, 6,686,918 results folded into one
64-bit digest, identical for all four builds — and **all three measured
inside alignment noise**. None is worth taking.

### 10.8 Correctness

`asm/tests/point_ref.asm` and `asm/tests/point_ct_ref.asm` are new: FROZEN
copies of `main`'s EC layer with every exported symbol suffixed `_ref`, the
point-layer analogue of `tests/fe_ref.asm`. They link against the live
(unchanged) field, so any difference they report is a difference in the point
layer. `asm/tests/test_point_repr.c` drives both implementations over the
same operands and compares limb for limb:

- `point_double`, `point_add`, `point_add_mixed`, `point_add_mixed_zr` (result
  *and* the `zr` out-parameter), `pointh_double`, `pointh_add` — every
  iteration, **out-of-place and in-place (r == p)**, because the deleted code
  sat inside an in-place-aliasing workaround.
- `point_scalar_mul`, `point_scalar_mul_glv`, `point_scalar_mul_fixed`,
  `point_scalar_mul_ct` — sampled every 64th iteration.
- The degenerate shapes the formulas branch on, forced one per iteration mod
  7: p = infinity, q = infinity, q == p, mixed-add with x2 == X1 and Z1 == 1,
  Y1 == 0, affine (0,0). Random operands never reach these.
- Operands are canonical field elements drawn 2-in-3 from a structured family
  (0, 1, p−1, p−k, every 2^i, 2^i^1, C, per-limb saturation) and 1-in-3
  uniform. Off-curve inputs are deliberate: both sides evaluate the same
  straight-line formula, so agreement must hold for any 12-limb input, and
  the off-curve space is enormously larger than the curve.
- `fe_sqr(a) == fe_mul(a, a)` over 2,000,000 operands from the same
  distribution — the identity all 20 rewritten call sites rest on.

**8,037,500 checks, 0 failures**, 2.8 s. An out-of-tree build of the same
harness that additionally differentials `ecdsa_verify` against a frozen
`ecdsa_verify_ref` ran 8,075,000 checks with the same result.

**Mutation-tested, on real instructions.** Six bugs were injected into the new
code and every one is caught:

| mutation | caught |
|---|---|
| `point_double`'s `A = X1^2` fed `Y1` instead (`lea rsi` operand changed) | yes |
| `Z3 = 2*Y1*Z1` doubling dropped (`call fe_add` → `nop`) | yes |
| `point_add_mixed`'s `Z1Z1 = Z1^2` fed `X1` | yes |
| a converted site left as `call fe_mul` after its `rdx` setup was removed — the exact failure mode of the mechanical rewrite | yes (SIGSEGV: `rdx` holds a stale non-pointer) |
| `pointh_double`'s `t0 = Y*Y` fed `Z` (constant-time path) | yes |
| `Y3` built from the stale F slot instead of `E*(D − X3)` — i.e. the overwrite bug the dead code was working around | yes |

All six are caught at **4,000 iterations**, 1/150th of the committed size, so
the harness has a wide sensitivity margin rather than only just catching them.
The unmutated control passes at that size (60,252 checks, 0 failures).

The rest of the campaign passes unchanged, and two existing tests are
independent cross-checks of exactly this change rather than incidental
coverage: `test_ecdsa_inverse` differentially compares `ecdsa_verify` (which
now squares via `fe_sqr` inside `ecdsa_x_eq_mod_n`) against the frozen
`ecdsa_verify_ref`, which reaches the same verdict by a completely different
route (`fe_inv` + Fermat `sc_inv`); and `test_ecdsa_glv_switch` compares the
GLV path (`point_double` + `point_add_mixed`) against the plain path
(`point_double` + `point_add`) three ways. `test_scalarmul_ct` passes,
which is the constant-time guard for change (a): `fe_sqr` introduces no
branch and no variable-time step on the signing path.

Full `make -k test`: **MAKE_RC=0, zero failures.** `make abi-check` passes
(1,119 reachable external call sites, RSP ≡ 0 mod 16).

### 10.9 End-to-end projection, and the Amdahl bound — read §7 first

**This is a projection, not a measurement.** The change is not deployed; §4's
deploy gate still applies (the replay must reach tip clean first), and §7
exists because a projection from a stale profile overstated a result 1.40 ×
against 1.15 × actual. The inputs below are §7's profile, taken 2026-08-22 at
height ≈ 617,000 — hours old, but the same day.

From §7's self-time table the field and point rows are
`fe_mul` 15.89 + `fe_mul.reduce` 17.10 + `fe_add` 3.69 + `fe_sub` 2.36 +
`fe_sqr` 1.37 + `point_double` 1.66 = **42.07 %** of replay cycles. Taking
that as the share this change accelerates by 1.11 ×:

    1 / (0.579 + 0.421/1.11) = 1.044x end-to-end

**Amdahl, stated: even an infinitely fast crypto path leaves 58 % of the
replay, a ceiling of 1.73 × from this direction at today's shares.** 1.044 ×
is 6 % of that headroom. Carried through the 1.091-1.155 × measurement band
the projection is 1.036-1.058 ×.

**§8's BIP143 precompute has since landed, and this branch is rebased onto
it, so the second calculation is the live one.** §8 removes `read_cs` +
`sw_seq` + `sw_prevout` — 34.07 % of §7's cycles — down to a measured
residual of 0.2-1.24 %. The field and point rows are untouched in absolute
terms, so their share of the *new*, smaller total rises to
42.07 / 0.662-0.672 ≈ **63 %**, and this change becomes worth

    1 / (0.37 + 0.63/1.11) = 1.067x end-to-end

while the Amdahl ceiling from the crypto direction rises to 1/0.37 = **2.70 ×**.

Both figures are still arithmetic on a profile taken *before* §8 landed, and
§9 now measures the deployed reality: 10.01 → 13.61 blk/s for §5.2 and §8
together, quoted there as a floor because the two bands sit ~120,000 blocks
apart. §7's lesson applies to this section as much as to any other: **the
shares have moved twice in one day, so the next lever must be chosen from a
fresh profile, not from this table.** §8's own §8.5 and this section's §10.11
both reason from the same pre-§8 denominator.

§9's contamination warning does **not** apply to §10.7's table: those are
`CLOCK_THREAD_CPUTIME_ID`, min-of-7, with the two binaries alternated inside
each session, which is exactly the component-benchmark discipline §9 says to
trust. It *does* apply to the end-to-end projection above, which is why it is
labelled a projection and why the deployed figure must be taken with nothing
else running.

### 10.10 Not verified

- **No replay of real chain data ran against this branch.** The live daemon
  is mid-replay and is not to be touched, so the 1.044 × / 1.067 × figures
  above are arithmetic on §7's profile, not observed throughput.
- **The full suite and the benchmarks in §10.7 were run at the pre-rebase
  base (`91b7c9d`) and again after rebasing onto §8's merge.** The two
  changes touch disjoint sources (`bitcoin_segwit.c` against the
  `secp256k1_*.asm` layer); only `asm/Makefile`, `.gitignore` and this file
  conflicted, all textually.
- No new profile was taken. §7's shares are reused as-is.
- `bench_ecdsa` measures one fixture signature; the call counts in §10.6 are
  from that same fixture. GLV wNAF digit density varies slightly with the
  scalar, so 126 doublings/verify is representative, not invariant.
- The three restructurings dismissed in §10.7 were dismissed on
  `bench_ecdsa`-level noise, not proven neutral by a cycle-accurate model.

### 10.11 What the next field-layer lever is, sized from these measurements

Not the representation. The remaining structure is in the call *pattern*:

- `point_double` now makes 21 field-op calls (5 `fe_sqr`, 2 `fe_mul`, 9
  `fe_add`, 5 `fe_sub`), and **5 of the 9 adds are small-constant
  multiplies**: `E = 3A` (2 adds) and `8C` (3 adds). One `fe_mul_int(r, a, k)`
  for k ≤ 8 — four `mulx`, one single-limb fold, and no second fold needed
  because the top limb is < 8 — replaces both chains. At the measured 2.18 ns
  per `fe_add` against an estimated ~2.5-3 ns for the new primitive, five
  adds (≈ 11 ns) become two calls (≈ 5-6 ns): ~5.6 ns per `point_double`,
  ×126 doublings ≈ 0.7 µs, or **~3 % of a verification**. That is a *new*
  field primitive, so it needs its own Python oracle and mutation campaign;
  it is sized here so the decision is informed, and deliberately not taken in
  this change. (Consistency check on the counts: 126 × 9 = 1,134 of the 1,243
  `fe_add` per verification are `point_double`'s.)
- Inlining `fe_add`/`fe_sub` into the EC formulas (§10.4) is the larger and
  much more invasive one: `fe_add` + `fe_sub` are 2,553 calls per
  verification at ~2.2 and ~1.3 ns, ≈ 4.4 µs or 18 % of a verify, most of it
  loads, stores and call overhead rather than arithmetic. This — not 5×52 —
  is where libsecp256k1's remaining advantage lives.

## 10. Lever 1, taproot half — single-pass BIP341 precompute, 2026-08-22

§8.5 named `bitcoin_taproot_sighash.c` as the next lever and as the same bug:
`tx_seq`, `tx_outpoint`, `ser_txout` and `ser_txout_len` each walked from the
start on every call, `ser_txout_len` walked the outputs *twice*, and BIP341's
aggregates call them once per input/output while `taproot_sighash()` is itself
called once per input — O(nin³) per transaction. All of that is confirmed and
fixed (branch `taproot-precompute`); the design is in the file's comments and
in `LOG.md`, and the two consensus divergences found while proving it are in
`LOG.md` too, not here, because they are not performance.

One design point that had to be checked rather than assumed, since BIP341 is
not BIP143: **a CTxOut's BIP341 serialization is also byte for byte its wire
encoding**, so `sha_outputs` is one sha256 over a contiguous slice of the
transaction, in place. BIP341's separate `sha_amounts` and `sha_scriptpubkeys`
are over the *spent* outputs, which are not in this transaction at all, so
they are not a counterexample — and they turn out to need no copying either,
because the caller already supplies them contiguously.

### 10.1 Microbenchmark — `tests/bench_taproot_sighash`

New and permanent (`make tests/bench_taproot_sighash`), `-O2`, CPU time
(`CLOCK_PROCESS_CPUTIME_ID`), min of 15, both builds back to back. Same five
shapes as §8.1 so the two tables are directly comparable. Key-path;
script-path is +0.03–0.04 µs on both builds and otherwise identical.

| shape | before | after | factor |
|---|---|---|---|
| 1 in / 2 out | 0.4001 µs | **0.3875 µs** | 1.03× |
| 2 in / 2 out | 0.4699 µs | **0.4487 µs** | 1.05× |
| 100 in / 5 out | 9.7203 µs | **4.3148 µs** | 2.25× |
| 1,372 in / 100 out | 1.1254 ms | **54.360 µs** | 20.70× |
| 2 in / 3,000 out | 18.177 ms | **43.318 µs** | 419× |

**The common case is not pessimised**, checked the same way §8.1 checked it
and then three more times: across four interleaved min-of-15 repeats the new
build is at or below the old in *every* repeat of the 1- and 2-input shapes,
key-path and script-path, by 2–5%, with non-overlapping distributions on the
2-input rows. Per-thread resident scratch also falls, 4 MiB → 2.29 MiB.

### 10.2 Real blocks

19,870 taproot inputs across 12,014 transactions from heights 825,000 /
830,000 / 842,000 / 865,000 / 910,000 — the five largest taproot input counts
out of 38 blocks scanned in 709,700–963,000, capturing both the
inscription-era script-path regime and the large-consolidation regime. Real
witness-stripped serializations (real input/output counts and script sizes);
spent outputs synthetic 34-byte P2TR, which is the correct size and does not
affect cost. CPU time, min of 15:

| | total | µs / taproot input |
|---|---|---|
| before | 4,577.85 ms | 230.39 |
| after | **243.35 ms** | **12.25** |
| | **18.81×** | |

| height | taproot inputs | before | after | factor |
|---|---|---|---|---|
| 825,000 | 3,379 | 2.25 ms | 1.68 ms | 1.33× |
| 830,000 | 3,661 | 3,833.15 ms | 195.65 ms | **19.59×** |
| 842,000 | 4,274 | 68.00 ms | 5.39 ms | 12.61× |
| 865,000 | 4,295 | 2.87 ms | 2.15 ms | 1.33× |
| 910,000 | 4,261 | 766.24 ms | 65.72 ms | 11.66× |

Ordinary 1–3 input taproot blocks gain a flat ~1.33×; the block carrying a
1,500-input consolidation goes from 3.83 s of sighashing to 196 ms.

### 10.3 No end-to-end projection, deliberately

§7 exists because a projection off a stale share said 1.40× and delivered
1.15×. This path is worse than stale: it has **never been profiled live**,
because the replay has not reached 709,632. Its share of taproot-era cycles is
unknown, so no Amdahl bound can honestly be stated here. The figure that does
not depend on a share is the 18.81× on the component. Re-profile after the
replay passes activation — that is the measurement that would let this be
turned into an end-to-end number.

### 10.4 What is left on this path — and it is bigger here than it was for BIP143

`taproot_sighash()` still runs the single pass and re-hashes the O(nin)
prevouts/amounts/spks arrays on **every** call, once per input. Only the inner
re-walk was removed. That is why the 1,372-input shape is still 54 µs/call and
why block 830,000 still costs 53 µs per taproot input afterwards.

Core hoists exactly this to once per transaction. §8.6 priced the equivalent
for BIP143 and rejected it — no transaction-scoped context to hang a cache on,
and a thread-local keyed on the transaction's address and length is not sound.
The same objection applies, but the *prize* is larger here: BIP341 has four
aggregate hashes rather than three, and one of them (`sha_scriptpubkeys`) is
over variable-length data. §8.6's arithmetic said the BIP143 cache would buy
~2× on the rarest shape and ~0 on the common one; here the 1,372-input shape
would go from 74.6 ms per transaction to roughly one call plus 1,372 cheap
tail assemblies. If this path is ever re-profiled hot, this is the lever —
and the sound way to do it is to thread a real per-transaction context down
from `taproot_verify_input()`, which already exists per input and would only
need to be created one level up, rather than to key a cache on an address.

## 11. Re-profile after the sighash work — 2026-08-22 22:45, height ~700,000

Taken with everything from §5.2, §8, §10 and the taproot sighash rewrite
deployed. Method as §7: `perf record -F 999`, **no call graph**, 25 s,
117,989 samples, live worker. DSO: bitcoind 91.1 % · libc 6.1 % · kernel 2.8 %.

| self time | symbol | note |
|---|---|---|
| **22.50 %** | `fe_mul.reduce` | modular reduction |
| 14.31 % | `fe_mul` | |
| 9.03 % | `fe_sqr` | **was 1.37 %** — §10 made it actually get called |
| 5.48 % | `fe_add` | |
| 5.14 % | `sha256_block_shani` | already SHA-NI accelerated |
| 3.82 % | `__memmove_avx512` | libc |
| 3.32 % | `fe_sub` | |
| 2.25 % | `point_double` | |
| 1.78 % | `__memset_avx512` | libc |
| 1.53 % | `swtx_parse` | §8's single pass — cheap, as designed |
| 1.45 % | `lsm_run_lookup_mm` | **the entire UTXO store** |
| 1.31 % | `copy_bytes.cb_loop` | |
| **1.27 %** | **`read_cs`** | **was 22.44 % in §7** |

**§8 is confirmed in production.** `read_cs` was the single largest symbol in
the whole profile at 22.44 %; it is now 1.27 % and thirteenth. The benchmark
predicted 27.4× on the component and the live profile agrees.

**The shape of the problem has changed completely.** Serialization and
storage are effectively finished: sighash parsing is ~3 % (`swtx_parse` +
`read_cs` + `w32le`), the UTXO store is **1.45 %**, the kernel 2.8 %. Field
and EC arithmetic is now ~64 % of all cycles, and hashing another ~5.8 %.
There is no longer a "two-front problem" (§1): it is one front.

### 11.1 What is ruled out, by measurement, and should not be retried

- **Lazy reduction / 5×52** (§10a): the *correct* implementation measures
  **1.07×**, because `fe_add`/`fe_sub` each need an extra correction round
  once `fe_mul` may return [0, 2²⁵⁶), and there are more of them (1,243 +
  1,436) than multiplies (2,262). §10 also found four sites where
  `point_add`/`point_add_mixed` select the doubling branch by **limb**
  equality — a non-canonical operand there returns infinity instead of 2P,
  silently.
- **Micro-optimising `reduce`**: three contract-preserving restructurings
  (ADCX/ADOX-fused carry refold, `CMOVO` canonicalisation, AND-tree
  predicate) were built and proved bit-identical over 6,686,918 results.
  All measured inside the ±0.5 ns alignment noise. `bench_fe` is
  alignment-sensitive enough that a change touching only `fe_add` moved
  `fe_mul` LAT by 0.68 ns — do not trust sub-ns deltas from it.
- **G-side comb table** (§4.5, and ranked next by §6): `point_scalar_mul_fixed`
  is **0.73 %**. This lever is now worth almost nothing and should be dropped
  from the plan.

### 11.2 What is left

1. **Inline `fe_add`/`fe_sub` into the EC formulas** — §10.11's conclusion,
   now corroborated by this profile: the two are **8.8 %** of all cycles
   across ~2,553 calls per verify that are mostly loads, stores and call
   overhead, and inlining additionally lets a multiply feeding an add skip an
   intermediate canonicalisation. The only remaining lever with double-digit
   headroom, and it is contained to the EC layer.
2. **`fe_mul_int(r, a, k)` for small k** replacing the `3A`/`8C` patterns
   (~3 % of a verify).
3. **Attribute the 6.9 % in `memmove`/`memset`/`copy_bytes`** — source
   unknown without a call-graph profile; worth one targeted run.
4. Re-profile again afterwards. The shares have now moved three times in one
   day, and each time they inverted the ranking.

## 12. Inlining the field add/sub into the EC formulas — BUILT, 2026-08-22

§11.2's item 1, and the last lever with double-digit headroom. **1.10× on
`ecdsa_verify`, 1.22× on `point_double`.** Branch `ec-inline`.

### 12.1 What the lever actually is

`fe_add` (5.48 %) + `fe_sub` (3.32 %) were **8.8 % of all replay cycles**
across 2,553 calls per verification (§11). Both are tiny — 31 and 19
instructions — so most of that is not arithmetic. It is three `lea`s of
argument setup, a `call`/`ret`, and above all **four stores and four loads
through the caller's stack frame** on every result, including results the
very next operation consumes.

§10.4 had already located this precisely: 5×52's one structural advantage
over 4×64 is not the representation, it is that libsecp256k1's field ops are
*inlined into the EC formulas*, so consecutive values stay in registers.
This change gives 4×64 the same property, and it is independent of the
representation — which is why §10 could reject 5×52 and this could still pay.

`asm/secp256k1_fe_inline.inc` holds the macros; `secp256k1_point.asm` and
`secp256k1_point_ct.asm` include it. The two files had **58** `call fe_add` /
`call fe_sub` sites (30 + 28); **57** are gone, replaced by 57 inline field
operations grouped into **40 register chains** (19 + 21). **One** call
survives, in `point_scalar_mul_glv`'s wNAF y-negation, because `rbx` holds
the digit there and `rbx` is the macros' home for C. It runs ~25× per verify,
not 2,553×.

The *operation* count is deliberately unchanged -- this banks no algebraic
shortcut. What disappears is 57 `call`/`ret` pairs, ~150 argument `lea`s, and
**17 whole field elements' worth of store-then-reload** (57 results now cost
40 stores and 40 loads instead of 57 of each, because the value the next
operation consumes never leaves the register file).

### 12.2 Register pressure — why nothing spills

A field element is four registers, so the design question is whether an
accumulator fits without displacing anything.

* Accumulator `V` = `r8:r9:r10:r11`; fold constant C = 2³²+977 pinned in
  `rbx`, loaded once per function (`FE_C_INIT`); scratch `rax, rcx, rdx,
  rsi, rdi`.
* In `point_double`, `point_add`, `point_add_mixed`, `pointh_add` and
  `pointh_double` those nine registers are **already dead between calls** —
  `rax/rcx/rdx/rsi/rdi` exist only to pass arguments and `r8..r11` are
  caller-saved and unused. Every live pointer (`r12` out, `r13` p, `r14` q,
  `r15` zr, `rbp` frame) is callee-saved and untouched by the macros.
* `rbx` was pushed by all five prologues and used by none of them, so C is
  free real estate. `fe_mul`, `fe_sqr` and `point_double` all preserve it,
  so it survives every nested call and is never reloaded.
* **Zero spills, zero added stack slots, no frame-size change** — which is
  also why `make abi-check` is unaffected (1,026 call sites, still all
  16-byte aligned).

A *full* inline — expanding `fe_mul`/`fe_sqr` too — was deliberately not
attempted. Those need all 15 GPRs for the 512-bit product and would spill
immediately, they are 21 multiplies each so the call is noise against them,
and §10 established that the reduction is the one part of this codebase that
has produced a lost-carry consensus bug, so it keeps having exactly one copy.

### 12.3 The fusions the call boundary was hiding

Chains that now cost one load, N register operations and one store:

| site | was | now |
|---|---|---|
| `point_double` D | `T-A`, `T-C`, `T+T` — 3 calls, 3 slot round trips | one chain |
| `point_double` E = 3A | `A+A`, `+A` | one chain |
| `point_double` 8C | 3 chained `fe_add` | 3 `FE_DBL` |
| `point_double` X3 | `S6 = D+D`; `F - S6` | `F - D - D`, slot S6 never written |
| `point_add` / `point_add_mixed` X3 | `2V` into a slot; `R²-2V`; `-HHH` | `R² - V - V - HHH` |
| `pointh_add` 7+8, 12+13, 17+18 | `t4 = ta+tb`; `t = t - t4` | `t - ta - tb`, temp never written |
| `pointh_add` 19+20, `pointh_double` 11+12 | `X3 = 2t0`; `t0 = X3+t0` | `t0 = 3t0` in registers |
| `pointh_double` 2-4 | 3 chained `fe_add` | 3 `FE_DBL` |

Each dropped temp was verified dead by inspection *and* by the differential:
in every case the slot is overwritten by a later step before anything reads
it. Note that these fusions do not *remove* reductions -- `F - 2D` becomes
`F - D - D`, still two -- they remove the slot the intermediate was parked
in, and with it the store and the reload.

### 12.4 The one algebraic change, and its proof

`FE_ADD_TAIL` merges `fe_add`'s two reduction steps — fold the 257th bit,
then conditionally subtract p — into **one** conditional select:

    s = a + b = CF1·2²⁵⁶ + s0
    t = s0 + C   (with carry CF2)          ; t == s - p  (mod 2²⁵⁶)
    result = (CF1 | CF2) ? t : s0

It is the same 256 bits `fe_add` returns, not merely congruent:

* **CF1 = 0**: `t` and CF2 *are* `fe_add`'s own shadow sum and predicate, and
  its fold added nothing. Identical by inspection.
* **CF1 = 1**: with a, b < p, s ≤ 2p−2, so s0 ≤ 2²⁵⁶−2C−2 and
  t = s0+C ≤ 2²⁵⁶−C−2 < p. `fe_add`'s second step therefore keeps `t`
  unchanged — which is what this returns.

The two forms can only differ when a+b ≥ 2²⁵⁷−2C, which is **impossible for
a, b < p = 2²⁵⁶−C**. `tests/test_fe_inline` constructs that boundary
explicitly and demonstrates the divergence on an out-of-contract pair
(a = 2²⁵⁶−1), so the claim is shown rather than asserted.

**No non-canonical intermediate is introduced anywhere.** Every macro takes
canonical operands and leaves the accumulator canonical, so §10.5's hazard —
`point_add`'s `U1 == U2` and `point_add_mixed`'s `U2 == X1` deciding the
doubling branch by **limb** equality, returning infinity instead of 2P — is
untouched. That hazard is the reason lazy reduction was rejected and it is
the reason this change deliberately banks none of the same headroom.

### 12.5 Measured

Methodology throughout: CPU time (`CLOCK_THREAD_CPUTIME_ID`), min-of-N,
spread printed, `taskset -c 20`, both builds run **alternately** in the same
session (the before build is the shipped `secp256k1_point{,_ct}.asm` from
`6df20c7`, assembled and linked identically). A full-chain replay was
consuming ~5-10 of 32 threads throughout, which is why the absolute numbers
drift between repeats and only the paired comparison is quoted.

New permanent harnesses: `tests/bench_point` (`point_double`, `point_add`,
`point_add_mixed` as serial chains over real curve points, plus the field
additive ops both ways in the same binary — deliberately, because `bench_fe`
is alignment-sensitive at ±0.5 ns and a cross-binary comparison of a 1 ns
operation would not survive it).

**`tests/bench_point`, 200,000 (50,000 for the adds) calls/round, min-of-15,
4 alternating repeats.** Each cell is the min over the 4 repeat minima; the
4 repeat minima are listed so the spread is visible.

| ns/call | before | after | factor |
|---|---|---|---|
| `point_double` | **71.75** (72.11, 71.75, 71.83, 73.16) | **58.72** (58.86, 58.72, 60.11, 59.91) | **1.222×** |
| `point_add_mixed` | **97.44** (97.44, 97.79, 100.67, 98.97) | **93.62** (93.62, 93.81, 95.53, 95.40) | 1.041× |
| `point_add` | **134.68** (135.29, 134.68, 136.72, 137.72) | **131.52** (131.52, 132.12, 134.48, 134.02) | 1.024× |

`point_double`'s distributions do not overlap. `point_add_mixed`'s do not
overlap. `point_add`'s overlap by 2 ns across repeats, but the *paired*
comparison is in the same direction in all four.

The field ops, measured in one binary at one moment (`fe_*_inl` are the same
macro bodies wrapped as SysV functions, so they still pay three push/pop
pairs and a `ret` that the in-situ expansion does not — these are an **upper
bound** on the inline cost):

| ns/call, LAT | call | inline (wrapped) | factor |
|---|---|---|---|
| `fe_add` | 2.225 | **1.467** | 1.517× |
| `fe_sub` | 1.302 | 1.301 | **1.00× — no change** |

That `fe_sub` row is the honest part of the result: standalone, `fe_sub` is
already latency-bound on its own four-limb `sbb` chain and the call/ret hides
inside it. **All** of `fe_sub`'s gain comes from chaining — not paying the
store and the reload when the next operation consumes the value — which is
invisible to a single-operation benchmark and is exactly what `point_double`
measures.

**`tests/bench_ecdsa`, 20,000 verifications × min-of-9, 8 alternating
repeats, `taskset -c 20`:**

| µs / verify | before | after |
|---|---|---|
| repeat minima | 23.49, 23.41, 23.66, 23.50, 25.14, 25.44, 25.91, 26.13 | 21.38, 21.29, 21.28, 21.41, 23.77, 23.61, 23.60, 21.44 |
| **best** | **23.41** | **21.28** |

**1.100×.** Paired ratios: 1.099, 1.100, 1.112, 1.098, 1.058, 1.078, 1.098,
1.219 — median 1.099. Unpinned, 3 alternating repeats: 22.75 → 20.76 µs,
1.096×. `tests/bench_fe` (the field file is untouched — control) is
unchanged within noise: `fe_mul` 8.39/5.36, `fe_sqr` 7.37/4.50, `fe_add`
2.13, `fe_sub` 1.24.

**The saving reconciles with the component numbers.** Instrumented entry
counters on the benchmark fixture: **126 `point_double`, 109
`point_add_mixed`, 1 `point_add` per `ecdsa_verify`**. Predicted saving
126×13.03 + 109×3.82 + 1×3.16 = **2.06 µs**; measured 23.41 − 21.28 =
**2.13 µs**. Agreement to 3.3 %, so the gain is where the microbenchmarks say
it is and not somewhere else. (Counts are for one fixed fixture signature;
real digit streams vary by a few counts either way.)

### 12.6 Code size — measured, not assumed

`.text` bytes in the NASM objects:

| | before | after |
|---|---|---|
| `point_double` | 481 | 1,336 |
| `point_add.distinct` | 344 | 762 |
| `point_add_mixed.distinct` | 360 | 748 |
| `pointh_add` | 850 | 2,186 |
| `pointh_double` | 483 | 1,140 |
| `secp256k1_point.o` `.text` | 4,764 | 6,530 (+37 %) |
| `secp256k1_point_ct.o` `.text` | 2,153 | 4,146 (+93 %) |

`point_double` nearly triples and runs 126× per verify, so this was the real
risk. The verification hot loop is now `point_double` (1.3 K) +
`point_add_mixed` (~1.2 K) + `point_scalar_mul_glv` (~1.2 K) + `fe_mul` /
`fe_sqr` (~0.9 K) ≈ **4.6 KB against a 32 KB L1I**, and the measurement above
is the answer: it got faster, so on this core the I-cache did not care. On a
machine with a smaller L1I this trade could invert, and that is not tested.

### 12.7 End-to-end projection, and the Amdahl bound stated

**Not measured end to end. Projected.** §7 and §9 exist because projections
off stale shares overstated results, so the arithmetic is spelled out.

§11's live profile (height ~700,000, 117,989 samples) puts field + EC
arithmetic at ~64 % of all replay cycles, essentially all of it under
`ecdsa_verify`. A 1.100× on that component removes 9.1 % of its cycles:

    end-to-end ≈ 1 / (1 − 0.091 × 0.64) ≈ 1.062×

**The Amdahl bound for this lever specifically** is set by the two symbols it
attacks: `fe_add` + `fe_sub` were 8.8 % of all cycles, so making field
addition *entirely free* would give 1/(1−0.088) = **1.096× end-to-end**. This
change realises about two thirds of that (5.8 of the 8.8 points). The
remaining third is the arithmetic itself, which no amount of inlining removes.

The wider bound is unchanged: even a free `ecdsa_verify` is 1/(1−0.64) =
2.78×.

This projection is only as good as §11's share, which is hours old and was
taken at one height. **Re-profile before quoting an end-to-end number.**

### 12.8 What this changes about the remaining plan

**§11.2's item 2 — `fe_mul_int(r, a, k)` for the `3A` / `8C` patterns — has
been mostly consumed by this change and should be re-sized before it is
built.** §10.11 priced it at ~3 % of a verify against `fe_add` at 2.18 ns per
call. Those five calls are now five inline operations costing ~0.87 ns each
(derived: `point_double` lost 13.03 ns across 14 inlined operations), so the
whole `3A` + `8C` chain is now ~4.4 ns, not ~11 ns. A shift-based small
multiply might halve that: ~2 ns per `point_double`, 126× = 0.25 µs ≈ **1.2 %
of a verify, ~0.8 % end-to-end** — for a *new* field primitive needing its own
Python oracle and mutation campaign. That is now below the bar.

What is left after this:

1. **Re-profile.** The shares have moved four times in two days and the EC
   layer's internal composition just changed again.
2. Attribute the 6.9 % in `memmove`/`memset`/`copy_bytes` (§11.2 item 3) —
   still unexplored, still needs one call-graph run.
3. `fe_mul`/`fe_sqr` are now ~46 % of all cycles between them and there is no
   known lever on them: §10 measured lazy reduction (1.07×, rejected on the
   consensus hazard), 5×52 (worse), AVX-512 IFMA (§5.3, rejected), and three
   contract-preserving `reduce` restructurings (all inside ±0.5 ns).

### 12.9 Correctness evidence

* `tests/test_point_repr` — **8,037,500 checks, 0 failures**: every point
  routine against the frozen `tests/point_ref.asm` / `point_ct_ref.asm`, out
  of place *and* in place, with the degenerate shapes forced (infinity,
  q == p, mixed-add doubling, Y = 0, (0,0)).
* `tests/test_fe_inline` — **NEW, 24,000,720 checks, 0 failures**: the macros
  driven directly (`tests/fe_inline_probe.asm`) against `fe_add`/`fe_sub`
  *and* an independent C big-integer oracle, over 3,000,000 structured and
  random canonical pairs **plus 90 constructed carry-boundary pairs** around
  p, 2²⁵⁶, 2²⁵⁶+C, 2p, 0 and C. Wired into `make test`.
* `tests/test_ecdsa_inverse` (113,315 cases vs a frozen reference reaching
  the verdict by a different route) and `tests/test_ecdsa_glv_switch`
  (30,240, three-way): pass.
* `tests/test_scalarmul_ct`: passes, including its timing check — CT ratio
  **1.000×** against a variable-time control that leaks 14.6×. The macros are
  straight-line `adc`/`sbb`/`cmov`; no branch and no data-dependent address
  was introduced on the signing path.
* `make abi-check`: OK, 1,026 call sites. No frame size changed.
* `make -k test`: **MAKE_RC=0, zero failures**, 108 harnesses.

**Mutation campaign: 18 mutants, 18 caught, 0 survivors.** Every mutant is a
real instruction edit (never a comment), applied to the shipped source and
rebuilt: broken `adc`→`add` carry chains in `FE_ADDM` and `FE_DBL`; inverted
`cmovnz`→`cmovz`; **dropping CF1 from `FE_ADD_TAIL`'s predicate** (caught only
by the constructed a+b ≥ 2²⁵⁶ boundary — the case §12.4's proof turns on);
fold constant C → C−1; dropping `FE_SUBM`'s borrow correction; wrong limb
offsets in `FE_LD` and `FE_ST`; and ten formula-level edits — `X3 = F−D`,
`8C → 4C`, `E = 3A → 2A`, swapped `D−X3`, swapped `H = U2−X1`, a dropped `V`
in `point_add`, `zr = Y1` instead of `2Y1`, a wrong slot in `pointh_add`'s
fused 7+8, `Z3 = 4t0`, `t2 = 2t2`.

### 12.10 Not verified

* **No live profile of the new code.** The replay is running the previously
  deployed binary; nothing here was deployed. §12.7 is arithmetic, not
  measurement.
* The 8.8 % / 64 % shares are §11's, from one 25-second window at one height.
* Whether the code-size growth costs anything on a core with a smaller L1I.
* `fe_mul` / `fe_sqr` inlining was reasoned about (§12.2) and **not measured**.
* `tests/bench_point`'s operands are one fixed pair of curve points; the
  routines are straight-line over the field so this is not a correctness
  concern, but the digit-dependent call counts in §12.5 are fixture-specific.

## 13. Closing the two largest gaps to Core — BUILT, 2026-08-23

`BENCHMARKS.md` (2026-08-22) measured this project against Bitcoin Core
operation by operation and named the two biggest gaps: **BIP340 Schnorr verify
at 3.35×** and **the SHA-256d/merkle pair at 2.24×**. Both diagnoses in that
document were correct. This section records what they cost, what was done, and
— for the second one — the measurement that says it was worth far less than
the ratio suggests.

Every number below is CPU time (`CLOCK_THREAD_CPUTIME_ID`), min-of-15 rounds,
`taskset -c 25`, taken on 2026-08-23 with the live replay (~470 % CPU), the
Core oracle (~46 %) and another agent on the box. Before and after were
measured in the same sitting on the same core, which is why the "before"
column does not always match `BENCHMARKS.md`'s absolute numbers — that run was
a different night with different contention. **Compare the columns, not the
documents.**

### 13.1 Schnorr — the diagnosis confirmed, and three separate causes

`BENCHMARKS.md` guessed one cause. There were three, and they are worth
separating because two of them are not about Schnorr at all.

**Cause 1 — Schnorr never received the ECDSA multiply work.**
`secp256k1_ecdsa.asm` has used `point_scalar_mul_fixed` for the G-side and
`point_scalar_mul_glv` for the point-side since §4.3. `secp256k1_schnorr.asm`
called plain `point_scalar_mul` **twice**. BIP340's `R = s·G − e·P` is
structurally the same shape — one fixed base, one variable — so both
substitutions apply directly.

*The sign.* `s·G − e·P` is not `u1·G + u2·Q`, and the two obvious ways to
handle that are not equivalent. Negating the **scalar** (`e' = n − e`) costs a
subtraction and then makes `e' = 0` mean "infinity" for what was `e = n`, which
never happens but has to be reasoned about. Negating the **Jacobian Y**
(`(X, Y, Z) → (X, p−Y, Z)`) is four `sub`/`sbb`, is exact for every input, and
leaves `Z` alone so the infinity case stays infinity. The code already did the
second and it was kept unchanged; only the multiply above it moved.

*The x-only lift.* `lift_x` goes through `pubkey_parse` on `0x02 || pk`, which
is the even-Y root by construction, and is untouched. The even-Y check on `R`
is untouched. What changed underneath them is only how `s·G` and `e·P` are
computed.

**Cause 2 — two field inversions where one was needed, and neither was
needed for x.** `PERF_SCOPE.md` §4.2's item A′ flagged this a day early and
nobody had done it: the tail did `fe_inv(Z²)` **and** `fe_inv(Z³)`. The
`x(R) == r` test needs no inversion at all — `r` is a field element and the
caller has already rejected `r ≥ p`, so

    x(R) == r   ⟺   r · Z² == X   (mod p)

exactly as `ecdsa_x_eq_mod_n` does for ECDSA, minus the `r + n` retry that
only exists because ECDSA's `r` is a scalar mod `n`. The even-Y test genuinely
does need the affine `y` — parity is not a projective invariant, and no
Legendre-symbol trick recovers it (that trick works for the *square*-y variant
BIP340 abandoned) — but it needs `Z⁻¹` once, not `Z⁻²` and `Z⁻³` separately.
The x compare is now done **first**, so a rejected signature never reaches the
inversion at all.

**Cause 3 — `fe_inv` itself was doing 248 multiplies it did not need.**
Once the count was down to one inversion, that one inversion measured
**4,712 ns — 17 % of a whole verify.** The reason is that `fe_inv` walked the
256 bits of `EXP = p−2` with `fe_mul(R,R,R)` for the squarings: `p−2` has 247
set bits, so 255 squarings **plus 248 multiplies**, 503 `fe_mul` calls in all
(the count §4.2 already recorded, without noticing it was the fixable half).
`p − 2 = 2²⁵⁶ − 2³² − 979` is a long run of 1-bits, and the classical
`x_k = a^(2^k − 1)` ladder reaches it in **255 squarings and 15 multiplies**.
Fermat is unchanged; only the addition chain and the use of `fe_sqr` for the
squares are new.

Deliberately **not** done: a variable-time inversion. The obvious candidate is
a binary xgcd like `sc_inv_var`, which is right there and measures **3,590 ns**
for the scalar field — *slower than the 2,091 ns the addition chain now costs*.
libsecp256k1's safegcd would land near 1,000 ns, saving a further ~1.1 µs
(4 % of a verify) for ~600 lines of new consensus-critical primitive. That
trade is not worth taking today and is written down here so the next session
does not rediscover it.

### 13.2 SHA-256d / merkle — the diagnosis confirmed, the VALUE measured, and
it is small

`BENCHMARKS.md` attributed the 2.24× entirely to Core's 2-way SHA-NI batch.
**That is exactly right, and it is now measured on our own kernel rather than
inferred.** A scratch harness alternating N independent `sha256_block_shani`
chains on this CPU (Zen 5):

| independent chains in flight | ns per compression | vs 1 |
|---|---|---|
| 1 | 26.88 | 1.000× |
| **2** | **16.91** | **1.590×** |
| 3 | 16.72 | 1.608× |
| 4 | 16.75 | 1.605× |
| 5 | 16.78 | 1.602× |
| 6 | 16.67 | 1.612× |

**Two is the right width on this CPU and three is not better** — measured, not
assumed. The whole 2.24× is that 1.59× plus per-call overhead: `sha256d(x, 64)`
cost 100.84 ns per pair, of which 3 × 26.88 = 80.6 ns is the three serial
compressions and **20.1 ns (19.9 %) is `sha256_init`, a `rep movsb` of the 64
input bytes, and building a padding block whose contents are a compile-time
constant.**

**But the end-to-end value of fixing it is ~0.2 %, and that is the finding
that matters.** `merkle_root` has exactly **one** caller in the node
(`cons_verify`, `bitcoin_cons.asm:175`) — there is no other 64-byte
double-hash on any path. Counting SHA-256 compressions over three real mainnet
blocks pulled from the Core oracle:

| height | txs | inputs | merkle compressions | share of the block's SHA-256 |
|---|---|---|---|---|
| 772,000 | 515 | 1,055 | 1,566 | **6.7 %** |
| 850,000 | 3,163 | 6,087 | 9,504 | **11.6 %** |
| 963,000 | 4,321 | 8,541 | 12,987 | **10.2 %** |

§11's live profile puts **all** of `sha256_block_shani` at 5.14 % of replay
cycles, so merkle is **0.34 – 0.60 % of all cycles**. The Amdahl bound is
therefore blunt: making `merkle_root` *infinitely fast* is worth at most
**1.006×** end to end, and the 1.90× actually achieved is worth **≈1.002×**.
Put the other way: at height 963,000 `merkle_root` costs 0.43 ms against
191.8 ms of signature verification for the same block — **0.22 %**.

It was built anyway, and the reason is the risk side rather than the reward
side: it needed **no new cryptographic kernel**. `sha256d64` calls the
existing, already-validated `sha256_block` twice per step with two independent
states, and both padding blocks are `.rodata` constants because the two
message lengths are always 512 and 256 bits. Nothing in it computes a hash
round. A translation of Core's `Transform_2way` — 16 live `__m128i` and ~430
lines of intrinsics — would have been the wrong trade for 0.2 %; this was not.

`merkle_root` stages a **batch** of nodes before calling `sha256d64`, because
one pair per call leaves consecutive pairs unable to overlap across the call
boundary. Measured, at 9,001 leaves: 1 pair/call **76.8 ns/leaf**, 2 → 60.0,
4 → 54.9, 8 → 53.2, 16 → 53.2. The curve is flat from 8; **16** is what
shipped (1 KB of stack).

### 13.3 Measured

**Methodology, and why it is not the one at the top of this section.** The box
got much busier partway through this session (load average went from ~5 to
~40 — another agent started a 30-way parallel job). `PERF_SCOPE.md` §9 and
`BENCHMARKS.md` both warn that a "before" from one window and an "after" from
another is worthless, and this run proved it: the same untouched
`ecdsa_verify` measured 22.46 µs at load 5 and 31.63 µs at load 42.

So the before/after table below was taken by **building the baseline commit
(`cffe48b`) into a second worktree and ALTERNATING the two binaries on the
same core, base/new, base/new, three passes** — whatever the box is doing hits
both sides inside the same few seconds. Each figure is the minimum over the
three passes of a min-of-15 CPU-time (`CLOCK_THREAD_CPUTIME_ID`) measurement,
2,000 operations per round, `taskset -c 25`. Load average was 39.9 at the
start and 32.1 at the end, which is why the absolute numbers are worse than
§13.1's — **the ratios are what this table is for.**

| | baseline `cffe48b` | this branch | factor |
|---|---|---|---|
| `schnorr_verify` | **60.65 µs** | **25.45 µs** | **2.38×** |
| `merkle_root`, 9,001 leaves | 100.50 ns/leaf | 53.89 ns/leaf | 1.86× |
| SHA256D64 shape (1024 × 64 B) | 1.5733 ns/B | 0.8084 ns/B | 1.95× |
| **`ecdsa_verify` — untouched control** | **21.20 µs** | **21.23 µs** | **1.00×** |

The control is the point of the table: `ecdsa_verify` shares `fe_mul`,
`fe_sqr`, `point_add`, `point_double`, the comb and the GLV ladder with
everything that changed, and it did not move — 21.20 vs 21.23 µs, a 0.1 %
difference against a 3-pass spread of 21.20–24.94. Whatever made Schnorr 2.38×
faster did not come from a measurement artefact that would have moved ECDSA
too. (`ecdsa_verify` does not call `fe_inv` at all since §4.2's item A, which
is why the addition chain does not show up here.)

Per-pass, so the spread is visible rather than described:

| pass | base schnorr | new schnorr | base merkle | new merkle | base ecdsa | new ecdsa |
|---|---|---|---|---|---|---|
| 1 | 64.82 µs | 27.95 µs | 111.36 ns | 58.81 ns | 23.24 µs | 23.25 µs |
| 2 | 60.65 | 25.45 | 100.50 | 53.89 | 21.20 | 21.23 |
| 3 | 63.72 | 31.24 | 119.26 | 62.42 | 24.88 | 24.94 |

Two component measurements were taken earlier in the session, on the quiet
box (load ~5), and are quoted with that caveat:

| | before | after | factor |
|---|---|---|---|
| `fe_inv` (scratch harness, 20,000 calls/round, min-of-15) | 4,712.4 ns | 2,091.2 ns | **2.25×** |
| `sha256d64` vs `sha256d`, per 64-byte pair | 100.74 ns | 51.99 ns | 1.94× |

**The Schnorr decomposition.** Each step was measured on its own as it was
built, in one sitting on the quiet box (so this column's baseline is 58.99 µs
rather than the 60.65 µs above — same code, quieter machine):

| step | µs/verify | share of the total gain |
|---|---|---|
| baseline (`point_scalar_mul` twice, two `fe_inv`) | 58.99 | — |
| + fixed-base comb for `s·G`, GLV+wNAF for `e·P` | 31.99 | **82 %** |
| + projective `x(R) == r`, one inversion instead of two | 27.69 | 13 % |
| + `fe_inv` addition chain | **25.92** | 5 % |

**Schnorr is now within ~20 % of this project's own ECDSA verify** (25.45 vs
21.23 µs in the same window), which is the right internal sanity check: the
two do the same two multiplies, and what is left between them is Schnorr's one
`fe_inv` (2.09 µs) and two tagged `sha256_full` calls against ECDSA's
`sc_inv_var` (3.59 µs) and two `sc_mul`.

### 13.3a A live consensus bug found on the way, and fixed

Reading `secp256k1_schnorr.asm` closely enough to rewrite it turned up
something that has nothing to do with performance: **the function was not
thread-safe, and the node verifies blocks on worker threads.**

The BIP340 challenge preimage was built in a process-global `.data` buffer
(`schnorr_preimg`). `asm/daemon/tx_verify.c` spawns verify workers
(`bmc_pthread_create`, `tx_verify.c:451` and `:955`), so two taproot key-path
inputs verified at the same moment overwrote each other's preimage and each
computed the *other's* challenge `e`. A wrong `e` gives a wrong `R`, so
`x(R) != r` and **a valid signature is rejected** — which, inside a block,
rejects a valid block.

Reproduced rather than inferred: 8 threads × 20,000 verifications of the
official BIP340 vectors — signatures the same binary accepts single-threaded —
gave **1,982 false rejects**. With the preimage moved into `schnorr_verify`'s
own stack frame: **0**. `tests/test_schnorr_thread_stress.c` is that harness,
now in `make test`, and `scripts/mutate_check.py` puts the global buffer back
to confirm the test fails when it should.

The direction matters: false *reject*, not false accept — a corrupted preimage
would have to hash to the exact challenge that particular signature commits to,
a ~2⁻²⁵⁶ accident. So this is a chain-split/liveness bug, not a theft bug. It
is also the shape that shows up in a replay as an unexplained "block rejected"
and gets attributed to something else.

The same commit adds the message-length bound the buffer never had: an
over-long message used to run off the end of a 320-byte `.data` buffer, and
now rejects cleanly, exactly as `secp256k1_taproot.asm`'s `tap_leaf_hash` was
hardened to do on 2026-08-21.

**The same bug class is still live one file over and is NOT fixed here.**
`secp256k1_taproot.asm`'s `tagh_buf` and `tap_preimg` are process-global — its
own header calls them "single-threaded global" — and they are on the taproot
verify path that the same worker threads reach for every script-path spend.
The 2026-08-19 TLS conversion covered the interpreter's scratch and never
reached the secp256k1 layer. That is a separate change with its own tests; it
does not belong in a performance branch. See `LOG.md`, 2026-08-23.

### 13.3b The refreshed comparison against Core, taken in one window

`scripts/bench_vs_core.sh` was re-run and its output at load 42 was
**discarded** — Core's nanobench and libsecp256k1's `bench` both time with a
WALL clock, so on a loaded box their numbers are inflated by descheduling that
our `CLOCK_THREAD_CPUTIME_ID` harnesses do not see, which biases every ratio
in our favour. The table below was taken instead by the same alternating
method as §13.3: **Core's binary and ours, back to back on `taskset -c 25`,
three passes, minimum of each.** Two such windows were run, at load ~40 and
again at load ~15; the quieter one is reported and the busier one agreed to
within 3 % on every row.

Ratios are ours ÷ theirs, so > 1 means we are slower.

| operation | Core, this window | ours, this window | ratio | published 2026-08-22 |
|---|---|---|---|---|
| SHA-256, 1,000,000 B | 0.3825 ns/B | 0.4376 ns/B | **1.14×** | 1.15× |
| SHA-256, 32 B | 39.06 ns | 36.20 ns | **0.93× (we are faster)** | 0.94× |
| **SHA-256d, 64 B × 1024** | 0.7255 ns/B | **0.8499 ns/B** | **1.17×** | **2.24×** |
| *— the same window, through the OLD `sha256d` path* | 0.7255 | *1.5839 ns/B* | *2.18×* | *2.24×* |
| **Merkle root, 9,001 leaves** | 47.88 ns/leaf | **55.94 ns/leaf** | **1.17×** | **2.24×** |

**Three of those five rows are controls, and all three land on their published
values.** The two SHA-256 rows are code this branch never touched and they
reproduce 2026-08-22's 1.15× and 0.94× to within 1 %. The italic row is
better still: `bench_hash_core` deliberately still carries the OLD
one-node-at-a-time `sha256d` shape next to the new `sha256d64` one, and in
this window it measures **2.18× Core** against the 2.24× published on a quiet
box — 2.5 % apart. So the alternating method is sound here, and the 1.17× next
to it is a real change and not a measurement artefact. Core's own
`bench_bitcoin` measured **CPU/wall = 0.992** across the passes, comfortably
inside `BENCHMARKS.md`'s own rule for keeping the Core column.

**The two crypto rows could not be measured this way tonight, and the reason
is worth stating rather than papering over.** libsecp256k1's `bench` reports a
wall clock and carries no CPU/wall check of its own. In the quiet window it
read **31.0 µs for `ecdsa_verify` and 31.4 µs for `schnorrsig_verify`**,
against its own published quiet-box 21.10 and 21.40 — inflated by ~47 %. A
ratio taken against that would flatter us by half, so by this document's own
rule the Core crypto column is discarded.

What can honestly be said instead uses the **untouched ECDSA control to
calibrate our column**: `ecdsa_verify` read **21.98 µs** here, against
**23.70 µs** published for the *identical binary* on 2026-08-22. Our side is
therefore at or better than quiet-box quality, so comparing it to Core's
published quiet figures is sound in the direction that matters:

| | ours | libsecp256k1 (published quiet) | ratio |
|---|---|---|---|
| ECDSA verify — **untouched control** | 21.98 µs (best of night 21.20) | 21.10 µs | **1.00–1.04×** |
| **Schnorr verify (BIP340)** | 27.56 µs (best of night 25.45) | 21.40 µs | **1.19–1.29×** |

The control reading 1.00–1.04× where 2026-08-22 published 1.12× is the check
that this composition is not quietly generous: it errs slightly *against* the
published number, not for it. Call Schnorr **~1.2×, down from 3.35×**, and
re-run `scripts/bench_vs_core.sh` end to end on a genuinely idle machine for a
single-sitting figure.

**The two gaps this session set out to close are closed to within ~20 %.**
Schnorr 3.35× → ~1.2×, SHA-256d 2.24× → 1.17×, merkle 2.24× → 1.17×. What
that is worth end to end is §13.4, and for merkle the answer is "almost
nothing".

### 13.4 End-to-end projection, and the Amdahl bound stated plainly

**These are projections from §11's shares, not measurements.** Nothing here has
been deployed; the replay is running the previous binary.

§11's profile was taken at height ~700,000, where the verify mix is
overwhelmingly ECDSA, so it contains **almost no Schnorr at all**. That makes
it the wrong instrument for this change and the right one for the merkle
change:

- **Merkle.** `sha256_block_shani` is 5.14 % of cycles; §13.2 measures merkle
  at 6.7–11.6 % of a block's SHA-256 work, i.e. **0.34–0.60 % of cycles**.
  At 1.90× that recovers 0.16–0.28 % → **1.002–1.003× end to end**. The
  ceiling, at infinite speed, is **1.006×**.
- **Schnorr.** At §11's height the share is near zero, so the projection there
  is **~1.00× and meaningless**. The number that matters is per-input:
  `BENCHMARKS.md`'s tier-2 lower bound for a P2TR key-path input falls from
  **≥ 72.04 µs to ≥ 26.30 µs**, and Core's `VerifyScriptP2TR_KeyPath` is
  20.66 µs, so the floor on that input type goes from **≥ 3.49× to ≥ 1.27×**.
  For Core's own `ConnectBlockMixedEcdsaSchnorr` shape (1 Schnorr : 4 ECDSA,
  which Core's comment calls representative of blocks 848,000–868,000) the
  composed lower bound falls from **≥ 1.48× to ≥ 1.09×**.

**The Schnorr share is going to grow, and §11 cannot see it.** Taproot
key-path spends are common from ~713,500; the replay is at ~772,000 and
climbing. A profile taken today would put a materially larger share on
`schnorr_verify` than the one this projection is built from, and every month
of chain makes that worse. Re-profiling after deploy is the only honest way to
close this — §11's shares have already inverted the ranking three times.

### 13.5 Correctness

**BIP340's official vectors.** `tests/test_schnorr` — 19 checks, 0 failures,
including every published failure case.

**Differential against Bitcoin Core, per signature.** A new `SCHNORR` command
in `validation/core_verify_oracle.cpp` calls `XOnlyPubKey::VerifySchnorr`
(libsecp256k1's `secp256k1_schnorrsig_verify`) directly, with no script, no
transaction and no flags — so a malformed signature can be handed to Core and
its verdict taken. `validation/gen_schnorr_diff_vectors.py` builds the corpus
from a small independent pure-Python BIP340 implementation (not a port of
anything in this repo, so a shared misunderstanding cannot cancel out).

| class | what it is | committed | bulk run |
|---|---|---|---|
| `valid` | correct signatures | 1,200 | 100,000 |
| `oddy` | **x(R) == r but y(R) ODD** — signed without BIP340's k-negation | 450 | 37,500 |
| `infinity` | **s·G − e·P is the point at infinity** — r chosen freely, s = e·d | 150 | 12,500 |
| `nolift` | pk is not any curve point's x (x³+7 not a QR) | 240 | 20,000 |
| `bitflip` | one bit flipped, spread over r / s / msg / pk | 960 | 80,000 |
| `s_ge_n`, `r_ge_p`, `pk_ge_p`, `pk_zero`, `s_zero`, `r_zero` | every range edge, incl. s == n, r == p, pk == p | 20 | 500 |

**3,020 committed cases and 250,500 bulk cases, each run twice (GLV on and
`BMC_ECDSA_GLV=0`), agree with Core exactly — 501,000 comparisons, 0
mismatches, 0 false accepts.** The committed set is `tests/test_schnorr_diff`,
wired into `make test`; the bulk set is out of tree.

On "small-order-adjacent": secp256k1 has **prime** order, so there is no
non-trivial small subgroup — the point at infinity is the entire story and it
is the `infinity` class above.

**`fe_inv`'s chain.** `asm/validation/fe_inv_chain.py` **parses the assembly**,
evaluates the exponent each `FEINV_SQN` / `FEINV_MUL` produces over Python's
integers, and asserts it equals `p − 2` exactly (255 squarings, 15 multiplies);
change a rung in the `.asm` and it fails. `tests/test_fe_repr` adds **252,555
addition-chain cases against the frozen naive-binary `fe_inv_ref`** — 250,000
random plus structured `k`, `p−k`, `2^k`, `2^k−1`, `p−2^k` for k = 1..256 and
zero — 0 differences, on top of the 1,600 Python ground-truth vectors and the
1,547-value structured digest it already carried.

**Merkle.** `tests/test_merkle_batch` (new, in `make test`): `sha256d64` ==
`sha256d` for every batch count 0..128 over 200 random fills including the
odd tail and a no-overrun check, and `merkle_root` == the one-node-at-a-time
algorithm it replaced for **every leaf count 1..2050** — which covers every
odd level, every batch boundary, and the in-place overwrite. Real chain data:
`cons_verify` recomputes every txid and the merkle root and compares it to the
header, and it accepts **989 real mainnet blocks** pulled from the Core
oracle: 389 spread across heights 0–963,000 (dense around the segwit
activation at 481,824 and across the taproot era) **plus a contiguous run of
600, heights 850,000–850,599**. All 989 accepted, i.e. all 989 merkle roots
byte-identical to the header.

**ABI.** `sha256d64`, `merkle_root`, `fe_inv`, `schnorr_verify` and
`schnorr_x_eq_r` all probed with `tests/bench_abi_guard.S`'s sentinel probe:
**clean**, no callee-saved register destroyed.

**Mutation campaign — `scripts/mutate_check.py`, 11 mutants, 10 caught, 1
documented-unobservable.** Every mutant is a real instruction or numeric
constant in the shipped assembly; the script **refuses** a mutation whose
anchor text appears only inside a comment, because an earlier attempt in this
project was vacuous for exactly that reason. Mutants: drop the even-Y test;
compute `s·G + e·P`; `e·G` instead of `s·G`; drop the top limb from the x
compare; one squaring short in the `fe_inv` chain; the wrong operand in a
chain rung; a 256-bit length in `sha256d64`'s 512-bit padding block; no state
reset before the second SHA-256; `jae`→`ja` on the odd-level duplication; a
64-byte write stride where 32 is right.

The eleventh is worth reading, because finding it changed the code. Dropping
`schnorr_verify`'s **infinity check** survives the entire 250,500-case Core
corpus — `point_add` writes the canonical infinity `(1, 1, 0)`, so an infinite
`R` reaches the compare as `X == 1, Z == 0` and `r·0 == 1` is false, and the
signature is rejected by the x compare instead. No input can distinguish the
two versions. The check stays because the compare **alone** would accept a
`(0, ·, 0)` infinity against `r == 0`, and `tests/test_schnorr_diff` now
asserts exactly that hazard (`schnorr_x_eq_r(0,0,0) == 1`). The mutation is
marked `expect_survive` with that reasoning in the script rather than deleted.

Finding the *other* survivor changed the code too: "check only 3 of the 4
limbs of x(R)" is invisible to any corpus of real signatures, because it needs
an `(r, X, Z)` where `r·Z²` agrees with `X` in three limbs and differs in the
fourth — a ~2⁻¹⁹² accident that no signature can be steered into. The compare
was therefore lifted into an exported `schnorr_x_eq_r`, following the exact
precedent of `ecdsa_x_eq_mod_n` (exported "ONLY so tests can drive the r+n
branch"), and `tests/test_schnorr_diff` drives it with **179,377 constructed
triples** — matching ones plus every single-limb perturbation of `X` and of
`r`. The mutation is now caught.

### 13.6 Full test results

* `make -k test`: **MAKE_RC=0, zero failures, 152 harnesses run** (149 on
  `main` plus this branch's three: `test_schnorr_diff`,
  `test_schnorr_thread_stress`, `test_merkle_batch`). Every "N failures" line
  in the log reads 0; no `make` error lines. The count is stated because
  silent test loss has bitten this project four times.
* `make abi-check`: **OK**, 1,050 reachable call sites scanned, every call
  site leaving assembly at RSP == 0 mod 16. (The 234 latent asm→asm
  misalignments it also reports are pre-existing and tracked as LOG.md
  incident #20; this branch adds none — `sha256d64` and `schnorr_x_eq_r` are
  both 16-aligned at every nested call and `merkle_root`'s enlarged frame
  keeps the property it had.)
* Out of tree: 250,500 BIP340 cases × 2 GLV settings vs Core — 0 mismatches.
* Out of tree: `cons_verify` over **989 real mainnet blocks** from the Core
  oracle (389 spread over heights 0–963,000 plus a contiguous 850,000–850,599)
  — all accepted, i.e. every merkle root byte-identical to its header.

### 13.7 Not verified

* **Nothing here has been deployed and no live profile of it exists.** §13.4
  is arithmetic over §11's shares, and §11 predates the taproot-dense part of
  the chain the replay is now in.
* **No tier-3 end-to-end run.** `BENCHMARKS.md`'s reasons still hold: the box
  carries a ~470 % replay plus another agent, and `bench_tier3.sh check` does
  not pass.
* The Schnorr differential uses **32-byte messages only** for the Core half,
  because `XOnlyPubKey::VerifySchnorr` takes a `uint256` — which is also the
  only shape consensus ever uses. Variable-length BIP340 messages are covered
  only by the official vectors (which include 0, 1, 17 and 100-byte messages).
* `e ≥ n` as an input edge is **unreachable**: `e` is a SHA-256 digest reduced
  mod n by the verifier itself, and a digest ≥ n happens with probability
  ~2⁻¹²⁸. The reduction is exercised by every case; the ≥ n branch of it is
  not.
* The merkle share in §13.2 is counted from three blocks, and the compression
  model for the sighash side is analytic (preimage sizes), not instrumented.
* `MK_STAGE` was swept at 1, 2, 4, 8 and 16 only; 32 and 64 need the frame
  offsets recomputed and were not tried. The curve is flat from 8, so this is
  unlikely to matter.

## 14. The bottleneck is not arithmetic, it is serialization — MEASURED, 2026-08-23 02:30, height ~797,000

Every projection in §11–§13 assumed the verifier's cost is spread across the
worker pool. It is not. Measured on the live daemon, on a quiet box (load 6.9,
system 85% idle, iowait 2–3%):

    thread states, verification worker (pid 3459575):   32 sleeping,  1 running
    effective parallelism:                              ~1 core of 32

Thirty-three threads exist. The main thread runs; the thirty-two workers sleep.

### 14.1 Where the main thread's time goes

`perf record -F 999 -g -t <main tid>`, 24,893 samples, 30s:

| symbol | share of main thread |
|---|---|
| `fe_mul.reduce` | 33.52% |
| `fe_mul` | 14.02% |
| `fe_sqr` | 11.54% |
| `point_double` | 8.24% |
| `sha256_block_shani` | 3.38% |
| `lsm_run_lookup_mm` | 2.13% |

**67.3% of the main thread is field/EC arithmetic** — i.e. signature
verification. The whole-process profile (48,365 samples) agrees: 53.8% field
arithmetic, ~63% including the EC layer, and SHA-256 only 5.53%.

### 14.2 Why: the workers refuse taproot on purpose

Both worker loops in `daemon/tx_verify.c` skip P2TR outright —

    if (g_txv_in[i].shape == TXV_SHAPE_P2TR) { g_txv_results[i].ok = 1; continue; }   /* single-tx */
    if (w->flat[i].shape  == TXV_SHAPE_P2TR) { w->res[i].ok  = 1; continue; }         /* batch    */

— and every taproot input is then verified in a sequential loop after the
threads join, at both entry points (`tx_verify.c:593` and `:1220`). The code
says so: *"taproot pass 3 stays sequential/single-tx-at-a-time"*.

That is not a scheduling choice. It is a workaround for shared mutable state:
`secp256k1_taproot.asm` keeps `tagh_buf` in `.data` and `tap_preimg` in `.bss`
as process-global scratch, and its own header still asserts the assumption that
made that safe — *"Global scratch (tagh_buf, tap_preimg) used by the small
helpers is single-threaded."* Every taproot sighash, key-path included, is
built in that one shared buffer (`bitcoin_taproot_sighash.c:576` calls
`tagged_hash256(out32, "TapSighash", 10, pre, prelen)`).

This is the third time tonight a written-down assumption turned out to be a
scheduled outage; incidents #22 and #26 were both preceded by an explicit
"known divergence, deliberately left" note. **A documented assumption needs a
test that fails when it stops being true, or it needs fixing.**

### 14.3 What this means for §11–§13

§13 took Schnorr from 3.35x to ~1.2x vs Core and SHA-256d/merkle to ~1.17x.
That work is real and correctly measured. But it reduced **per-signature cost
on a path that runs on one core**, while Core verifies taproot across its
script-check thread pool. The remaining gap to Core is now mostly that we do
not.

It also explains the projection §13.4 could not make land: Schnorr's end-to-end
effect was computed as "~1.00x and meaningless" against a profile that predates
taproot density. The projection assumed a parallel execution that is not
happening.

**Ordering consequence: parallelising the taproot pass comes before any further
`fe_mul` work.** A 1.15x on 54% of one core is worth far less than moving that
work onto 32. `fe_mul` stays the right target afterwards, when it multiplies
against a parallel baseline instead of a serial one.

### 14.4 The blocker, and the shape of the fix

`tap_leaf_hash` is the only one of the four helpers that needs a large buffer:
BIP342 puts no cap on tapscript size, so `TAP_PREIMG_CAP` is 4 MiB and the true
bound is the block size itself. Shrinking it would trade a latent bug for a
false reject. `tagged_hash256` (64 + msglen) and `tap_branch_hash` (+64..+128)
are small.

Naive TLS therefore costs 4 MiB x up to `TXVB_MAX_WORKERS` (64) = 256 MiB of
`.tbss`. The codebase already has the better idiom: worker threads receive
`sv_work, 1<<20` as a **parameter** rather than reaching for a global. Threading
a caller-provided scratch pointer through the four helpers removes the global,
removes the latent race, and lets the P2TR skip in both worker loops be deleted.

### 14.5 Not verified

* The end-to-end win is **not** measured — only the headroom (31 idle cores and
  a main thread that is 67% signature crypto). Whether the catch-up loop can
  actually feed 32 workers is a separate question from whether the verifier can
  use them, and the UTXO apply is sequential regardless.
* An earlier parallelism sample read 1.90 cores rather than ~1.0; that window
  was contaminated by concurrent agent load. The 32-sleeping/1-running thread
  census is the reliable measurement, and it was taken on the quiet box.
* The taproot share of total verification at height ~797,000 was not counted
  directly (no per-shape input census); it is inferred from the main thread
  being 67% field arithmetic and the workers being the only other consumer.

### 14.6 The constant-time assertion, resolved — 2026-08-23 02:55, quiet box

§13.7 left "is close-core-gap constant-time clean" unverified, because
`tests/test_scalarmul_ct` was failing and the box was at load 60. Resolved by
alternating both binaries on one pinned core at load 3.3:

| run | baseline (pre-§13) | with §13 |
|---|---|---|
| 1..7 | 1.000, 1.001, 1.001, 1.000, 1.001, 1.001, 1.001 | 1.001, 0.999, 1.000, 1.001, 1.003, 1.002, 1.000 |

Both trees sit inside the +-3% window on every run. **§13 is constant-time
clean**, and the test is sound — at load 3.3 it reproduces its own calibration
band (0.986..1.009 at load 4-7) almost exactly.

What it did under load is worth recording, because it nearly caused a wrong
call. At load 60 the *same* binaries produced 0.906..1.129 in **both** arms.
Two of those readings were 0.952 and 0.956 — and the test's own comment
documents that an injected 4% data-dependent leak "is caught at 3% (ratio
~0.955)". The noise landed exactly on the signature the tolerance exists to
detect. An 8-run sample then showed the branch with ~3x the baseline's variance,
which looked like a real asymmetry; four more runs destroyed it, with the
*baseline* producing the two worst readings of the night.

Two lessons, both already paid for elsewhere in this log:

* **A calibrated instrument is calibrated for an environment.** This test is
  rigorous at load 4-7 and worthless at load 60, in both directions. Its window
  is not a safety margin against load; it is a claim about a measurement made
  under stated conditions. Run it outside them and it manufactures both false
  alarms and false confidence.
* **Do not conclude from the sample you have when the next sample is cheap.**
  The 3x-variance finding was real in its 8 points and wrong about the world.

### 14.7 Parallelising the taproot pass — the design, and the measurement that picked it

The prerequisite is done: `secp256k1_taproot.asm`'s two staging buffers are
thread-local as of 2026-08-23, gated by `tests/test_taproot_thread_stress`
(29,236 wrong digests of 96,000 against the pre-fix globals; 0 after). What
remains is to actually use the worker pool.

**Do not parallelise within a transaction.** Measured against Core at heights
825,000 and 825,001:

| | h825,000 | h825,001 |
|---|---|---|
| transactions (excl. coinbase) | 4,272 | 3,825 |
| taproot-bearing transactions | 2,988 (70%) | 2,051 (54%) |
| taproot inputs | 3,379 | 2,283 |
| mean taproot inputs per taproot tx | **1.13** | **1.11** |
| **txs with exactly one taproot input** | **96%** | **95%** |

Fanning a transaction's own taproot inputs across threads — which would need no
new memory management, since `po`/`am`/`sp`/`ns` are already built and
read-only by then — finds nothing to fan out 96% of the time. It is the
cheap design and it is worth approximately nothing.

**The axis is across transactions**, and the cost of that is that the
per-transaction aggregate sighash data has to be live for many transactions at
once instead of being rebuilt into one reused arena per transaction.

Shape that fits the existing code:

* **Phase A, sequential and cheap.** For each transaction that has at least one
  taproot input, build `po` (36B/input), `am` (8B/input), `sp`
  (1+spklen per input, *packed* — the existing arena is sized
  `nin*(1+TXV_SPK_CAP)` worst-case but only ever fills `1+spklen`) and the
  witness-stripped `ns`, into a per-BLOCK arena. Record one small descriptor
  per transaction: offsets plus `nin`. This is memcpy and `strip_witness`, not
  signature work — it is not what the profile is complaining about.
* **Phase B, parallel.** Fan every taproot input across `g_txvb_pool`. Each
  worker reads its transaction's descriptor and calls `taproot_verify_input`
  with pointers into the shared arena. The arena is **read-only** for the whole
  of phase B, so no per-worker duplication is needed — which is the entire
  reason phase A is worth doing separately rather than having each worker
  rebuild its own transaction's arrays.

Arena size is bounded by roughly `sum(stripped tx bytes) + 44 * inputs` over
the taproot-bearing transactions — a few MB per block, not the 8 MiB-per-worker
that duplicating `ns` would cost (`static u8 ns[8<<20]` x 32 workers).

**Then, and only then, delete the two `TXV_SHAPE_P2TR` skips** at
`tx_verify.c` (the single-tx worker loop and `txvb_worker_loop`) and the two
sequential passes that follow them.

**Expected effect, stated as a bound rather than a promise.** Section 14
measured the main thread at 67% field arithmetic with 31 cores idle. If that
whole 67% moves to the pool, Amdahl gives at most ~3x on the connect path;
the replay's other serial work (the UTXO apply, the LSM writes, the archive
read) does not move and will become the next ceiling. It has to be re-profiled
after, not projected — this section exists because section 13's projections
were made against a profile that predated taproot density and were wrong for
exactly that reason.

**Validation this must pass before deployment**, given the failure mode is a
corrupted sighash rather than a loud error:

1. `tests/test_taproot_thread_stress` (already in `make test`).
2. Whole-block differential against the Core oracle over a run of real
   taproot-dense blocks at height >= 800,000 — every transaction, both entry
   points, accept AND reject direction.
3. The block that a wrong shared arena would break first is one where two
   transactions with different input counts verify concurrently; a fixture
   with that shape specifically, not just "a busy block".

### 14.8 BUILT and measured — 2026-08-23, branch `taproot-parallel`

14.7's shape, implemented at both entry points in `daemon/tx_verify.c`. Two
`TXV_SHAPE_P2TR` skips and two sequential passes deleted; taproot inputs are
now ordinary entries in the flat verify array.

* **Phase A — `tapagg_build()`.** Sequential, cheap (memcpy + `strip_witness`,
  no signature work). For every transaction with at least one taproot input,
  appends `po` (36 B/input), `am` (8 B/input), `sp` (**packed** 1+spklen, not
  `nin*(1+TXV_SPK_CAP)`) and the witness-stripped `ns` to ONE per-block arena,
  and records a descriptor of byte offsets plus `nin`. One `bytepool_reserve`
  per transaction, so nothing can relocate the arena between reserving a
  region and filling it.
* **Phase B — `tapagg_verify()`.** A pure reader of that arena, called from
  `txv_verify_one`/`txvb_verify_one` like any other shape. The arena is
  read-only from the moment Phase 2 dispatches.
* Phase A exists exactly once (a `tapin_fn` adapter per entry point), so the
  single-transaction and whole-block paths cannot drift apart.

**One change 14.7 did not call for, and why.** Work claiming in the block pool
went from a fixed contiguous `[lo,hi)` slice per worker to one shared atomic
counter. Fixed slices were defensible while every entry cost roughly one
ECDSA verify; with taproot in the same round the per-entry cost now spans a
key-path Schnorr verify, a tapscript execution and a zero-work
`TXV_SHAPE_WPASS` entry, and those are not spread evenly through a block. The
measurement below separates the two changes.

#### Measured — `tests/bench_taproot_block`, 36 taproot-dense blocks

Heights 825,000–825,015, 840,000–840,007, 870,000–870,007, 850,000–850,001,
860,000–860,001. 143,952 non-coinbase transactions, 247,725 inputs, 98,814 of
them taproot. Blocks and prevouts from the scratch Core oracle. Box: AMD Ryzen
9 9950X3D, 16 physical cores / 32 threads, load 8–13. Three timed runs per
block after one untimed warm-up, A/B alternated; the two rounds of each arm
agreed to better than 1.5%. Built at **-O2** (the pin came off the same day);
an earlier -O0 measurement of the same three arms gave 4,035 / 777 / 563 ms,
i.e. the same picture — verification is hand-written asm and the C glue is not
where the time goes.

| tree | wall (36 blocks) | CPU | effective cores | inputs/s | vs baseline |
|---|---|---|---|---|---|
| `main` (taproot sequential) | 3,999 ms | 10,848 ms | **2.72** | 61,950 | 1.00x |
| + taproot in the pool, static slices | 715 ms | 13,444 ms | 18.80 | 346,300 | **5.59x** |
| + dynamic work claiming (shipped) | 534 ms | 14,225 ms | **26.62** | 463,600 | **7.49x** |

Dynamic claiming is worth 1.34x of that on its own — with static slices a
worker that draws a run of tapscript-heavy transactions holds the barrier
while the rest idle.

**CPU time rises 31% and that is SMT, not extra work.** Pinned to 8 logical
CPUs, where no two worker threads share a physical core, the same block costs
294.9 ms of CPU on `main` and 298.2 ms here — +1.1%, i.e. the arena build and
the atomic counter are noise — while wall time goes 192.9 ms → 38.5 ms (5.01x).
At full width the extra CPU is 26 threads sharing 16 cores, which is a real
cost paid for a much larger wall-time win, not a regression.

#### A secondary, measured effect: 218 MB less `.bss`

The old single-transaction taproot pass declared its arena as file statics
sized for the worst case — `sp[TXV_MAX_INPUTS*(1+TXV_SPK_CAP)]` alone is
20,000 x 10,001 = **200 MB**, plus `po`, `am`, `spk34`, `is_tap` and an
8 MiB `ns`; the block path carried a second 8 MiB `ns`. All of it is gone,
replaced by a bump-reset pool that is a few MB per block. Measured on
`tests/test_txvb_wprog_stable`, which links the same translation unit:

    .bss   428,437,288 -> 210,060,200 bytes   (-218 MB)

`.bss` is demand-paged, so most of that was address space rather than resident
memory — but it was also 200 MB of arena whose entries were spaced 10,001
bytes apart to hold scripts that are almost always 22 to 34 bytes long, which
is why the packed layout is both smaller and better for cache.

#### The Amdahl bound, stated honestly

**The 7.49x is the script-verification phase in isolation, and nothing else.**
It is not a connect-path number and it is emphatically not a replay-throughput
number:

* The bench feeds a fully-resolved in-memory prevout table. The live daemon
  resolves each prevout through the LSM, sequentially, which is why §14
  measured ~1.0 effective cores live where this bench measures 2.72 on the
  same code. The bench isolates verification; it therefore **overstates** the
  end-to-end effect.
* Everything else the connect path does — block parse, BIP141 commitment,
  BIP30, the in-block index and duplicate-outpoint check, the sequential UTXO
  apply, the LSM writes, the undo log, the archive read — is untouched.
* Applying §14's live figure (67% of the main thread was field arithmetic) to
  a 7.49x on that portion gives at most **1/(0.33 + 0.67/7.49) ≈ 2.4x** on the
  connect path, consistent with 14.7's "at most ~3x". The UTXO apply does not
  move and becomes the next ceiling.

**This has to be re-profiled on the live daemon after deployment, not
projected.** That is the whole reason 14.7 exists.

#### Validation — 14.7's three items, all executed

1. **`tests/test_taproot_thread_stress`** — 8 threads x 4,000 iterations =
   96,000 concurrent hashes, **0 wrong digests** (29,236 of 96,000 against the
   pre-fix globals).
2. **Whole-block differential against the Core oracle** —
   `tests/test_taproot_block_diff`, new, over the 36 blocks above. Every
   transaction, both entry points, both directions:

   | | count | result |
   |---|---|---|
   | whole-block ACCEPT runs (block path) | 288 (36 blocks x8) | 0 rejects |
   | per-transaction ACCEPT (single-tx path) | 143,952 | 0 rejects |
   | corrupted-witness REJECT (single-tx path) | 81,124 | all rejected, `p2tr*` reason |
   | corrupted-witness REJECT (block path) | 1,775 | all rejected, `fail_tx_index` exact |
   | prevout perturbations, per path | 3,454 | all rejected, blame exact |

   The prevout probes are the ones aimed at the arena specifically: bumping a
   **sibling** input's amount by one satoshi can only reject through
   `sha_amounts`, i.e. through the shared array.
3. **The different-input-counts fixture** — `tests/test_taproot_parallel_arena`,
   in `make test`, from real block 825,000 transactions spanning **14 distinct
   input counts** (1,2,3,4,5,6,7,8,11,12,14,19,28,36): 488 pairwise
   two-transaction blocks, one 483-transaction interleaved block of 4,284
   inputs x25 runs, 46 in-place corruption rejects with exact blame, and the
   single-transaction path over all 23 fixture transactions in both directions.

**Soaked, because the bug class is scheduling-dependent.** With 32 spinners
saturating the box: the arena fixture 40 times, 0 failures; and 600 whole-block
accepts (100 runs each over blocks 825,000 / 825,010 / 840,003 / 870,004 /
850,000 / 860,000), 0 rejects. A scheduling-dependent corruption that survives
that is not one a single run would have found.

**Two corpus facts that broke the first version of the probes**, recorded
because both are easy to get wrong again:

* 5 transactions spend taproot with **SIGHASH_ANYONECANPAY**, which drops
  `sha_amounts`/`sha_scriptpubkeys` entirely — perturbing a sibling input's
  amount is legitimately a no-op for them.
* 17 transactions are **script-path spends that never compute a sighash at
  all** (unknown leaf version, an `OP_SUCCESSx` leaf, or a tapscript with no
  CHECKSIG). Their own amount is not committed either. They are covered by
  breaking the control block's Merkle commitment instead, which every
  script-path spend must satisfy.

#### Mutation-tested, because a passing test proves nothing on its own

Ten deliberate bugs injected into the arena logic, each caught:

| mutation | caught by |
|---|---|
| descriptor index off by one | A (block accept) |
| global flat index passed instead of `local_idx` | A |
| `nin` off by one in the descriptor | A / pairwise |
| `ns` taken from the neighbouring transaction | pairwise |
| amounts written big-endian | A |
| `sp` strided instead of packed | A |
| `TXV_SHAPE_P2TR` silently ok (the old skip), block path | D / reject-in-place |
| `TXV_SHAPE_P2TR` silently ok, single-transaction path | single-tx reject |

The two false-ACCEPT mutations are the ones that matter: a corrupted sighash
never produces a false accept (a wrong sighash fails), but an input that is
never checked does.

#### Not verified

* **End-to-end replay throughput.** Not measured at all. It needs the live
  daemon restarted, which this work deliberately did not do. The 2.4x
  connect-path figure above is arithmetic on §14's live profile, not a
  measurement.
* **The re-profile §14.3 asks for** — whether `fe_mul` is still the right next
  target now that it multiplies against a parallel baseline — is not done.
* **Blocks below 800,000 and above 870,007**, and any block whose taproot
  usage is unlike this corpus's. The differential covers 36 blocks in four
  clusters, not a chain.
* **Constant-time behaviour.** `tests/test_scalarmul_ct` was not re-run for
  this change; nothing here touches the scalar-multiply path.
* **Taproot spending a SAME-BLOCK output.** The differential passes
  `bx = NULL`, so every prevout resolves through `utxo_lsm_get`; the live
  daemon resolves in-block chained spends through `bidx_get` first. Both write
  the same `value`/`spk_off` fields that Phase A then reads, so the exposure is
  small, but it is reasoned rather than measured. `tests/test_cross_tx_verify`
  covers `bidx_get` with non-taproot scripts only.
* **The `>= 0xfd` prevout-script guard on the taproot path.** Carried over
  verbatim, and no real block in the corpus has a prevout script that large on
  a taproot-bearing transaction, so the reject is untested here as it was
  before.
* **`tests/test_block_481827_pool_stack`** still SKIPs: its fixture has never
  existed in this tree. Generating one exposed a PRE-EXISTING defect, verified
  on unmodified `main` — the `.prevouts` format lists prevouts created by an
  earlier transaction in the SAME block, which is right for a verifier and
  wrong as a seed for the full apply path, where BIP30 then sees the block's
  own transaction overwriting an unspent output and rejects
  ("REJECT h=481827 tx=12: bad-txns-BIP30, output 32 already unspent"). A
  seeder must drop any prevout whose funding txid appears in the block. Not
  fixed here — unrelated to taproot, and the fixture is not committed.
* **Memory under adversarial blocks** was reasoned and then checked against
  the corpus, but not fuzzed. Measured maximum over the 38 fixture blocks:
  **2.29 MB** (height 840,000). The adversarial ceiling is small for a reason
  worth stating: `tapagg_build` rejects any prevout script `>= 0xfd` on a
  taproot-bearing transaction (BIP341's aggregate array has a one-byte length
  field), so `sp` costs at most 253 B/input, not `TXV_SPK_CAP`. An input costs
  at least 41 wire bytes, so a 4,000,000-byte block carries at most ~97,600 of
  them, giving `(36+8+253) * 97,600 + 4 MB ≈ 33 MB` — bounded, bump-reset per
  block, and bounded by data the block-level checks already accepted.
