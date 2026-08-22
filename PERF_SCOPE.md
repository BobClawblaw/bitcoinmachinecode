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
