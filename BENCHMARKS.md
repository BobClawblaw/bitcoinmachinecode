# Benchmarks — bitcoinmachinecode vs Bitcoin Core

Written 2026-08-22. Every number here was produced by `scripts/bench_vs_core.sh`
on one machine in one sitting; nothing is transcribed from memory or from a
previous session. Re-running that script is how you check any claim below.

**Read the methodology before the numbers.** A benchmark suite that only
produces favourable numbers is a broken benchmark suite, and the point of this
document is the fairness controls, not the ratios. Where this project is slower
than Core it says so in the same voice as where it is faster, and where the two
are not doing the same work it says that instead of printing a ratio.

---

## Contents

- [Methodology](#methodology)
- [The comparison basis, and why `-assumevalid=0` is not optional](#the-comparison-basis)
- [What this node does not do](#what-this-node-does-not-do)
- [Tier 1 — primitives, directly comparable](#tier-1--primitives-directly-comparable)
- [Tier 2 — components, comparable with stated caveats](#tier-2--components-comparable-with-stated-caveats)
- [Tier 3 — end-to-end full-verification replay](#tier-3--end-to-end-full-verification-replay)
- [Where we are slower](#where-we-are-slower)
- [What could not be measured, and why](#what-could-not-be-measured-and-why)
- [Bugs found while building this suite](#bugs-found-while-building-this-suite)
- [Reproducing](#reproducing)

---

## Methodology

### The box, and why that matters more than usual

| | |
|---|---|
| CPU | AMD Ryzen 9 9950X3D, 16 cores / 32 threads |
| governor | `powersave` (not pinned; frequency was **not** fixed — see caveats) |
| kernel | Linux 7.0.0-29-generic x86_64 |
| date | 2026-08-22T23:40Z |
| load average at start | 8.48 / 9.32 / 9.55 |
| concurrently running | a full-chain replay (`bmc-bitcoind.service`, ~500 % CPU), a Bitcoin Core oracle daemon (~49 % CPU), another agent's `test_ecdsa_inverse` (~100 % CPU), an unrelated VLLM engine |
| our git HEAD | `113d45a`, branch `bench-vs-core` |
| Bitcoin Core | v31.99.0-67efced1fc83, built `RelWithDebInfo` (Core's own default) |
| libsecp256k1 | Core's vendored copy, Core's shipped config: `ECMULT_WINDOW_SIZE=15 COMB_BLOCKS=43 COMB_TEETH=6 USE_ASM_X86_64=1` |

This machine was **busy**, and that is the single fact that shapes every
methodological choice below. `PERF_SCOPE.md` §9 documents a window on this same
box where a change measured at **+16 % on one function** showed up as a **43 %
end-to-end improvement** — entirely because the competing load happened to ease.
Wall-clock numbers taken here without care are worthless.

### The four controls

1. **One core, both sides.** Every binary runs under `taskset -c 25`. Both
   implementations therefore contend identically, and neither gets a different
   core's boost state. A consequence worth stating: Core's parallel
   script-verification threads are confined to that one core too, so **every
   Core figure here is Core's single-core performance**, not its real throughput
   on 16 cores. That is the right comparison for a per-operation table and the
   wrong one for a "how fast does Core sync" claim, which this document does not
   make.

2. **Minimum, not mean.** Interference can only ever *add* time, so the minimum
   over repetitions is the best estimate of intrinsic cost. Our harnesses use
   `CLOCK_THREAD_CPUTIME_ID` (or `CLOCK_PROCESS_CPUTIME_ID` for the sighash
   ones), which *stops while the thread is descheduled*, and report min-of-15
   rounds. Core's nanobench uses wall clock and prints a median, but its
   `-output-csv` carries a **per-epoch `min` column**, and that is the column the
   driver reads. Both sides are compared min-to-min.

3. **The wall-vs-CPU gap is measured, not assumed.** Because Core's inner timing
   is wall clock, the driver records each Core process's CPU/wall ratio. Across
   this run the worst ratio was **0.999 for the tier-1 hash processes and 1.000
   for the tier-2 ones** — i.e. Core was not descheduled during its measured
   windows, so its wall-clock minima are sound and the comparison to our
   CPU-time minima is valid. If that ratio ever drops materially below 1.0, the
   Core column must be discarded.

4. **Repetition at the process level too.** Each Core benchmark binary is run 3
   times and the smallest per-epoch minimum across those processes is taken, so
   a process that happened to start in a busy window cannot set the result.

### The spread is published, not hidden

Every one of our harnesses prints min, median and max. Selected spreads from
this run, so you can judge the noise yourself:

| measurement | min | median | max | max/min |
|---|---|---|---|---|
| `sha256_1MB` | 420,575 ns | 425,028 | 459,206 | 1.09 |
| `sha256_32b` | 35.55 ns | 35.85 | 39.52 | 1.11 |
| `cons_verify` (block 413567) | 739.73 µs | 743.19 | 747.28 | 1.01 |
| `merkle_root` 9001 leaves | 928.34 µs | 931.81 | 934.41 | 1.01 |
| BIP143 sighash, 1-in/2-out | 0.3799 µs | 0.3807 | 0.3840 | 1.01 |
| ECDSA verify (per round) | 23.70 µs | — | 27.28 µs | 1.15 |

### Caveats that apply to every number here

- **CPU frequency was not fixed.** The governor is `powersave` and boost was not
  disabled. nanobench's own help recommends `pyperf system tune`; that requires
  root and was not done. Min-of-N mitigates this but does not eliminate it.
- **`bench_fe` is alignment-sensitive.** `PERF_SCOPE.md` §11.1 records that a
  change touching only `fe_add` moved `fe_mul`'s measured latency by 0.68 ns.
  Sub-nanosecond deltas from field-level harnesses are not trustworthy and none
  are quoted here.
- **The two codebases were built with different compilers and flags.** Ours:
  `gcc 13.3.0 -no-pie -O2` for benchmark harnesses over hand-written NASM.
  Core: `g++ 13.3.0 -O2 -g` plus its full hardening set
  (`-fstack-protector-all -fcf-protection=full -fstack-clash-protection
  -D_FORTIFY_SOURCE=3`), which our harnesses do not carry. That hardening costs
  Core something on every C++ row; it does not touch libsecp256k1's assembly or
  Core's SHA-NI intrinsics, so the tier-1 crypto and hash rows are unaffected.

---

## The comparison basis

`PERF_SCOPE.md` §1 establishes the framing point and it is repeated here because
every end-to-end claim depends on it:

- This node runs **full signature verification on every historical block,
  unconditionally**. `assumevalid` is parsed and then explicitly ignored
  (`daemon/node_config.c:272` logs "IGNORED").
- Real Core, **by default**, uses `assumevalid` to skip script verification for
  every block below a hard-coded known-good hash. Its advertised IBD times
  reflect that shortcut.
- The only fair end-to-end target is therefore **Core with `-assumevalid=0`**.
  Anything else compares a node that checks signatures against a node that does
  not.

Tier 1 and tier 2 are unaffected by this — they measure named operations, and
both sides really do perform them.

---

## What this node does not do

A speed comparison between a node that does less and a node that does more is
not a like-for-like comparison. `FEATURE_GAPS.md` is the full inventory; the
parts that bear on these numbers:

- **No mining, no PSBT, no descriptor/watch-only/multi-wallet, no
  testnet/signet/regtest, no txindex, no blockfilterindex, no coinstatsindex, no
  Tor/I2P, no ZMQ, no REST, no assumeutxo.** Core carries the code for all of
  these; some of it is on paths this suite times (Core's block storage layer, its
  `CCoinsViewCache`, its `CBlock` deserialization) and some is not.
- **Our UTXO set is not the same object as Core's.** At height 575,833 we held
  **77,191,281** entries against the oracle's **54,953,225** — we carry
  **22,238,056 more**, because `daemon/utxo_live.c:339` writes every output to
  the store with no script inspection, while Core never writes a
  provably-unspendable output (`OP_RETURN`-leading, or over `MAX_SCRIPT_SIZE`) to
  its chainstate. **We are doing measurably more storage work for the same
  chain.** This is not a consensus divergence — an `OP_RETURN` output is
  unspendable either way — but any UTXO-store or end-to-end number must be read
  with it in mind.
- The RPC surface is thin, and `bitcoin_rpcd` is a separate process that opens
  the datadir read-only rather than being hosted in the node. Nothing in this
  suite measures RPC.

---

## Tier 1 — primitives, directly comparable

Same operation, both implementations, same core, same sitting. **These are the
only numbers here that are apples-to-apples without caveats.** Ratios are
ours ÷ theirs, so >1 means we are slower.

### Crypto

Both sides are the implementations' own benchmark harnesses:
libsecp256k1's `bench ecdsa_verify` / `bench schnorrsig_verify`
(`SECP256K1_BENCH_ITERS=2000`, min over 10 internal epochs, min over 3
processes) against `asm/tests/bench_ecdsa` and `asm/tests/bench_schnorr`
(2,000 verifications per round, min-of-15 CPU-time rounds).

| operation | libsecp256k1 | bitcoinmachinecode | ratio |
|---|---|---|---|
| **ECDSA verify** | **21.10 µs** (47,400/s/core) | **23.70 µs** (42,199/s/core) | **1.12× slower** |
| **Schnorr verify (BIP340)** | **21.40 µs** (46,700/s/core) | ~~71.66 µs~~ → **see below** | ~~3.35×~~ |

> **UPDATED 2026-08-23 — the Schnorr row is now stale and the update is
> recorded here rather than overwritten.** `PERF_SCOPE.md` §13 rewrote
> `secp256k1_schnorr.asm` onto the same fixed-base comb and GLV+wNAF ladder
> ECDSA already used, made the `x(R) == r` test projective, and replaced
> `fe_inv`'s naive binary exponentiation with an addition chain. Measured by
> **alternating the baseline commit's binary and the branch's binary on the
> same core in the same window** (three passes, min-of-15 CPU time each):
> **60.65 µs → 25.45 µs, 2.38×**, with `ecdsa_verify` as an untouched control
> moving 21.20 → 21.23 µs. Against the 21.40 µs libsecp256k1 figure above
> that is **3.35× → ~1.19×**, but the two columns come from different
> sittings on a much busier box, so treat 1.19× as an estimate and re-run
> `scripts/bench_vs_core.sh` on a quiet machine for a same-sitting ratio.

Two things to say about this table.

**The ECDSA gap has essentially closed, and this is the first measurement that
shows it.** `PERF_SCOPE.md` §1 measured the same pair on this same box on
2026-08-21 at **21.8 µs vs 120.9 µs — a 5.5× gap**. The field-kernel rewrite
(§5.2) and the work in §10 have taken it to **1.12×**. The number in §1 should
now be read as historical.

**The Schnorr gap had never been measured and was the largest remaining crypto
gap.** It is not the ECDSA ratio: BIP340 verification does carry a tagged-hash
challenge, and our implementation did not share what the ECDSA path had
gained — it called plain `point_scalar_mul` twice where ECDSA used the
fixed-base comb and the GLV ladder, and it did **two** field inversions where
one was needed and neither was needed for the x compare. All three are fixed
as of 2026-08-23 (`PERF_SCOPE.md` §13). The sentence below about "the verify
that dominates the part of the chain the replay has not reached yet" is why
that mattered, and it still stands. This matters more than it looks, because taproot key-path spends pay it
on every input from height 709,632 onward, and `FEATURE_GAPS.md` notes taproot
usage goes script-path-heavy from roughly 775,000 — i.e. **this is the verify
that dominates the part of the chain the replay has not reached yet.**
`asm/tests/bench_schnorr` exists so the next change to that path can be measured
rather than assumed.

The BIP340 fixture is read at runtime from `asm/tests/bip340_test_vectors.csv`
(the official bitcoin/bips vectors that `tests/test_schnorr` already validates
against), and the harness verifies it once before timing — a benchmark of the
reject path would be meaningless.

### Hashes

Both sides use **Core's own benchmark shapes**, byte for byte
(`src/bench/crypto_hash.cpp`: 1,000,000-byte buffers, a 32-byte buffer, and 1024
double-hashes of 64 bytes). `asm/tests/bench_hash_core` exists specifically so
this row is comparable; the pre-existing `asm/tests/bench_hash` compares against
OpenSSL instead and is left alone.

| shape | Core benchmark | Core | ours | ratio |
|---|---|---|---|---|
| SHA-256, 1,000,000 B | `SHA256_SHANI` | 0.3654 ns/B (2.74 GB/s) | 0.4206 ns/B (2.38 GB/s) | 1.15× slower |
| **SHA-256, 32 B** | `SHA256_32b_SHANI` | 37.63 ns | **35.55 ns** | **0.94× — we are 1.06× faster** |
| SHA-256d, 64 B × 1024 | `SHA256D64_1024_SHANI` | 0.7104 ns/B (45.47 ns/pair) | ~~1.5901~~ → **0.8084 ns/B** (51.7 ns/pair) | ~~2.24×~~ → **1.14×** |
| SHA-1, 1,000,000 B | `SHA1` | 0.6472 ns/B | 1.7318 ns/B | 2.68× slower |
| SHA-512, 1,000,000 B | `SHA512` | 0.9783 ns/B | 1.7513 ns/B | 1.79× slower |
| RIPEMD-160, 1,000,000 B | `BenchRIPEMD160` | 1.1371 ns/B | 3.5877 ns/B | 3.16× slower |
| Merkle root, 9,001 leaves | `MerkleRoot` | 45.97 ns/leaf | ~~103.14~~ → **53.89 ns/leaf** | ~~2.24×~~ → **1.17×** |

Notes, in order of how much they change the reading:

- **The SHA-256d and merkle rows were the same finding, and the diagnosis was
  right.** Core's `ComputeMerkleRoot` and its `SHA256D64` share a **2-way
  interleaved SHA-NI kernel**; this repo called `sha256d` sequentially. The two
  rows agreed to within 0.3 % on the ratio (2.238 and 2.243), which is what you
  would expect if a 2-way batch were the whole difference.

  **2026-08-23: confirmed by direct measurement and fixed.** Alternating N
  independent `sha256_block_shani` chains on this CPU costs 26.88 ns per
  compression at N=1 and **16.91 ns at N=2** — and 16.72/16.75/16.78/16.67 at
  N=3/4/5/6, so **two is the right width here and more buys nothing**. A new
  `sha256d64(out, in, pairs)` (`bitcoin_hash.asm`) runs two chains interleaved
  through the *existing* `sha256_block` — no new cryptographic kernel — and
  hoists the constant padding blocks into `.rodata`; `merkle_root` stages 16
  pairs per call. Both rows above are the branch's re-measured numbers, taken
  by alternating baseline and branch binaries on one core.

  **Read the end-to-end value before quoting the ratio.** `merkle_root` has
  exactly one caller in the node (`cons_verify`), and counted over three real
  mainnet blocks (heights 772,000 / 850,000 / 963,000) it is 6.7 % / 11.6 % /
  10.2 % of that block's SHA-256 compressions. Against `PERF_SCOPE.md` §11's
  5.14 % for *all* of `sha256_block_shani`, merkle is 0.34–0.60 % of replay
  cycles: the 1.86× is worth about **1.002× end to end**, and an infinitely
  fast `merkle_root` would be worth 1.006×. It was built because it needed no
  new kernel, not because the ratio was large.
- **Single-block SHA-256 is at parity, and slightly ahead on the small shape.**
  Both sides are SHA-NI. The 32-byte win is the interesting one: it is the shape
  Bitcoin actually hashes most often, and it says our one-shot path has less
  per-call overhead than `CSHA256().Write().Finalize()`.
- **The RIPEMD-160 row carries an asterisk.** `ripemd160` in this repo does not
  preserve the caller's `r14`/`r15` (see
  [Bugs found](#bugs-found-while-building-this-suite)), so the harness calls it
  through a register-saving trampoline, `asm/tests/bench_abi_guard.S`. That costs
  six push/pop pairs per call, which against a 3.5 ms call is under one part in
  a million. The number is honest; the bug is real.
- **The Merkle row uses Core's `MerkleRootWithMutation` minimum**, because
  nanobench's CSV writer emits only the last result when a benchmark function
  registers two names. Core's console output for the same run put plain
  `MerkleRoot` at 45.91 ns/leaf and `MerkleRootWithMutation` at 46.29 — within
  1 %, so the substitution does not move the ratio. It is worth noting which
  direction the substitution errs in: our `merkle_root` has **no
  mutation-detection mode at all** (the CVE-2012-2459 duplicate-subtree guard),
  so the correct Core comparator is the *cheaper* of the two, and we are still
  2.24× slower than it.
- Leaf *content* differs between the two merkle benchmarks (Core seeds from its
  own `FastRandomContext`; ours from a splitmix64). SHA-256 has no
  data-dependent branches, so this does not affect timing, but it does mean our
  harness cannot cross-check against Core's expected-root constant.

---

## Tier 2 — components, comparable with stated caveats

### Block-level consensus check — we are 2× slower, and Core is doing more

Both sides read **the same bytes**: mainnet block 413,567 (999,887 bytes, 1,557
transactions) straight out of Core's own
`src/bench/data/block413567.raw`. `asm/tests/bench_checkblock` takes the path as
an argument rather than vendoring the blob, so the input is provably identical.

| | Core | ours | ratio |
|---|---|---|---|
| block-level consensus check | `CheckBlockTest` **371.07 µs** | `cons_verify` **739.73 µs** (475.10 ns/tx) | **1.99× slower** |

**And the ratio understates it, because Core's `CheckBlock` does strictly more.**
In addition to PoW and the merkle root, Core checks: merkle **mutation**
detection (CVE-2012-2459), block weight and serialized-size limits,
`CheckTransaction` on every transaction (empty vin/vout, output value range and
total-value overflow, duplicate inputs within a transaction, null prevout on
non-coinbase, coinbase scriptSig length bounds), and the legacy sigop limit.
`cons_verify` (`bitcoin_cons.asm`) checks PoW, that every transaction parses
in-bounds, that the first transaction has `n_in == 1`, and that the merkle root
of the collected txids matches the header. Several of the missing checks do
exist in this codebase, on other paths (`bitcoin_sigops.asm`, the `tx_verify`
block-connect path) — they are simply not inside the function being timed. A
"faster CheckBlock" claim would be measuring a smaller function.

Given that `merkle_root` alone is 2.24× slower (tier 1) and block 413,567 has
1,557 leaves, the merkle half plausibly accounts for much of this. That is a
hypothesis this suite does not test; it is written down as a hypothesis.

### Transaction walk vs block deserialization — not like-for-like

| | Core | ours |
|---|---|---|
| walk every tx in block 413,567 | `DeserializeBlockTest` 920.99 µs | `tx_parse` × 1,557 → **20.24 µs** (13.00 ns/tx) |

**Do not read 45× off this row.** Core *deserializes* into `CBlock` /
`CTransaction` objects — a heap allocation per transaction, per input and per
output, producing a structure it then uses. This repo does not deserialize at
all: `tx_parse` walks the wire bytes in place and records offsets. These are
different operations with different outputs. The row is here because Core
publishes the number and someone will otherwise compare them badly; the honest
statement is that **a zero-copy design avoids work an object-graph design does**,
which is an architectural observation, not a speed measurement.

### Per-input script verification — no equivalent harness on our side

Core's `VerifyScript*` benchmarks run one complete input verification: script
interpreter, sighash and signature check, with `STANDARD_SCRIPT_VERIFY_FLAGS`.

| input type | Core | ours |
|---|---|---|
| P2WPKH (segwit v0, ECDSA) | `VerifyScriptP2WPKH` **20.44 µs** | no single harness |
| P2TR key path (Schnorr) | `VerifyScriptP2TR_KeyPath` **20.66 µs** | no single harness |
| P2TR script path (tapscript) | `VerifyScriptP2TR_ScriptPath` **36.39 µs** | no single harness |

This node **has** the equivalent code path (`script_eval`, `bitcoin_witness_v0.c`,
`bitcoin_taproot_sighash.c`, `daemon/tx_verify.c`) — what it does not have is a
benchmark harness that drives one input end to end. Building one was out of
scope for this session and is the single most valuable addition to this suite.

What can be said meanwhile is a **lower bound**, by adding the two components we
do measure. These are lower bounds on *our* time because they omit the script
interpreter, the flags dispatch, and the witness classification:

| input type | our sighash | our sig verify | **our lower bound** | Core | ≥ ratio |
|---|---|---|---|---|---|
| P2WPKH | 0.3799 µs (BIP143, 1-in/2-out) | 23.70 µs | **24.08 µs** | 20.44 µs | **≥ 1.18× slower** |
| P2TR key path | 0.3815 µs (BIP341, ext_flag=0) | ~~71.66~~ → 25.45 µs | ~~72.04~~ → **25.83 µs** | 20.66 µs | ~~≥ 3.49×~~ → **≥ 1.25×** |
| P2TR script path | 0.4112 µs (BIP341, ext_flag=1) | ~~71.66~~ → 25.45 µs | ~~72.07~~ → **25.86 µs** | 36.39 µs | ~~≥ 1.98×~~ → **≥ 0.71×** |

The two taproot rows are updated for the 2026-08-23 Schnorr work
(`PERF_SCOPE.md` §13). The script-path row now reads **below 1.0**, which does
**not** mean we are faster than Core there: it means the *lower bound* has
stopped being informative, because tapscript execution — which the bound omits
entirely and Core's 36.39 µs includes — is now a larger share of that number
than the signature is. The right response is the harness this document already
lists as its highest-value missing piece, not a speed claim.

`PERF_SCOPE.md` §9 warns "do not compose the component factors", and that warning
is about composing *speedup ratios* — which is invalid, because each component
speedup applies only to its own share. Composing *absolute times of disjoint
components into a lower bound* is a different operation and is sound: the sum of
parts of the work cannot exceed the whole. The ratios in the last column are
therefore floors, not estimates.

### Whole-block connect — no equivalent harness

Core's `ConnectBlock*` benchmarks build a 1,000-transaction block where each
transaction has 5 inputs and 5 outputs — 5,000 input verifications per block —
and run `Chainstate::ConnectBlock` over it.

| | Core (single core, as pinned) | our lower bound, from the table above |
|---|---|---|
| `ConnectBlockAllEcdsa` | **113.29 ms** (22.66 µs/input) | ≥ 120.4 ms (**≥ 1.06×**) |
| `ConnectBlockMixedEcdsaSchnorr` (1:4 schnorr:ecdsa) | **114.01 ms** | ~~≥ 168.4 ms (≥ 1.48×)~~ → **≥ 124.2 ms (≥ 1.09×)** |
| `ConnectBlockAllSchnorr` | **113.82 ms** | ~~≥ 360.2 ms (≥ 3.16×)~~ → **≥ 129.2 ms (≥ 1.13×)** |

The mixed case is the one to watch: Core's own comment says blocks between
848,000 and 868,000 run roughly 20 % Schnorr to 80 % ECDSA, so that row is the
closest thing in this document to a projection of the modern chain. It said we
would be **at least ~1.5× slower per block there, driven almost entirely by the
Schnorr gap**; after 2026-08-23 the same composition says **≥ 1.09×**, and the
all-Schnorr row moves from ≥ 3.16× to ≥ 1.13×. Again, no harness on our side; these are floors composed from
tier-1 and tier-2 measurements, and they exclude UTXO lookups, undo-log writes,
block-level checks and coinbase handling that `ConnectBlock` also performs.

### UTXO lookup — NOT comparable, and the row exists to say so

| | value |
|---|---|
| Core `CCoinsCaching` | 161.63 ns per op |
| our `bench_lsm_get` | ~398 ns per lookup (2,513,229 lookups/s) |

**These measure different objects and the ratio is meaningless.** Core's
benchmark validates three inputs against an in-memory `CCoinsViewCache` backed by
an empty view — it is a hash-map hit, not a database read. Ours builds a real
on-disk LSM with 10 run files and 4,000 keys and does 200,000 `utxo_lsm_get`
calls against it. Two further reasons not to compare them: `bench_lsm_get` uses
`CLOCK_MONOTONIC` (wall clock) and a single run, so it does not meet this
document's own standard; and a 4,000-key LSM is a toy next to the ~77 M-entry
production set. The live profile is the number to trust for the storage layer —
`PERF_SCOPE.md` §11 puts `lsm_run_lookup_mm` at **1.45 % of all replay cycles**,
i.e. the UTXO store is not currently a bottleneck for us at all.

Bringing `bench_lsm_get` up to CPU-time min-of-N and a realistic key count is
listed under [what could not be measured](#what-could-not-be-measured-and-why).

### Block read from disk — NOT comparable

| | value |
|---|---|
| Core `ReadRawBlockBench` | 33.70 µs for block 413,567 (~1 MB) |
| Core `ReadBlockBench` | 952.22 µs (read **and** deserialize the same block) |
| our `store_read_at` | 4.39 µs per block, 23.2 GB/s (synthetic ~102 KB blocks) |

Different block sizes, different stores, and Core additionally de-obfuscates
every byte on read (its blk files are XORed with a per-datadir key). The one
comparison that *is* clean here is Core's own pair: `ReadBlockBench` minus
`ReadRawBlockBench` shows that **deserializing block 413,567 costs Core ~918 µs
against ~34 µs to read it** — which is the same architectural point the
transaction-walk row makes, from Core's own numbers.

### Sighash — no Core equivalent exists

Core publishes no BIP143 or BIP341 sighash microbenchmark, so there is nothing to
compare against. These are recorded as our own baseline; they are the harnesses
`PERF_SCOPE.md` §8 and §10 were built around.

BIP143 (segwit v0), CPU time per `segwit_v0_sighash()` call, min-of-15:

| shape | tx size | min | median | max |
|---|---|---|---|---|
| 1 in / 2 out | 189 B | 0.3799 µs | 0.3807 | 0.3840 |
| 2 in / 2 out | 304 B | 0.4124 µs | 0.4127 | 0.4187 |
| 100 in / 5 out | 11,667 B | 2.6358 µs | 2.6847 | 2.7234 |
| 1,372 in / 100 out | 160,894 B | 33.0689 µs | 33.3069 | 33.8868 |
| 2 in / 3,000 out | 93,244 B | 46.1036 µs | 46.5217 | 46.7667 |

BIP341 (taproot), CPU time per `taproot_sighash()` call, min-of-15:

| shape | key path (ext_flag=0) | script path (ext_flag=1) |
|---|---|---|
| 1 in / 2 out | 0.3815 µs | 0.4112 µs |
| 2 in / 2 out | 0.4404 µs | 0.4701 µs |
| 100 in / 5 out | 4.1321 µs | 4.1498 µs |
| 1,372 in / 100 out | 53.1443 µs | 53.1938 µs |
| 2 in / 3,000 out | 42.2379 µs | 42.4428 µs |

Both are linear in transaction size, which is the property `PERF_SCOPE.md` §8 and
§10 set out to establish — the O(n²) walks are gone.

---

## Tier 3 — end-to-end full-verification replay

**This is the number that actually matters, and it has not been run.**

### What was built

`scripts/bench_tier3.sh` is a complete, tested harness with four subcommands:

```
scripts/bench_tier3.sh prepare-ours --height H --dest DIR
scripts/bench_tier3.sh prepare-core --height H --dest DIR
scripts/bench_tier3.sh run-ours     --height H --dest DIR --cpus LIST
scripts/bench_tier3.sh run-core     --height H --dest DIR --cpus LIST --par N --dbcache MB
scripts/bench_tier3.sh check        # is the box quiet enough to measure?
```

Both halves were validated end to end at H=1000 (see
[harness validation](#harness-validation-not-a-result) below).

### Why the range must start at genesis

You cannot validate block H without the UTXO set as of H−1, and neither side can
be handed the other's. A band starting at, say, 400,000 would require both sides
to already hold a chainstate at 399,999 built the same way — which means
replaying from genesis anyway. So the range is always [0, H] and **H is the only
knob**.

H also decides how *representative* the answer is. Blocks below ~200,000 carry a
handful of transactions each; a run bounded there mostly measures block-file
reading and database setup, and it flatters whichever side has cheaper fixed
costs. **H < 300,000 is a smoke test of the harness, not a result.**

### The fairness controls

| control | how it is enforced |
|---|---|
| same height range | both sides bounded to [0, H] |
| same block source class | both read blocks from **local disk**, no network on either side |
| same starting state | both start from an empty UTXO set / chainstate |
| `-assumevalid=0` on Core | passed explicitly by `run-core`; without it the comparison is meaningless |
| core pinning | both sides `taskset -c $CPUS`, stated in the output |
| Core's `-par` and `-dbcache` | explicit flags, printed in the log's `Command-line arg:` lines |
| our thread count | `dbcache` in the generated `bitcoin.conf`; the replay's verify path is one download worker |
| no production contact | `--dest` is refused if it points at `/storage/bitcoin`, the live datadir, the oracle, or the Core source tree |
| the archive is copied, never linked | a symlinked `blk*.dat` would let an appending writer reach the real archive |

**Bounding mechanism, ours.** There is no `-stopatheight` equivalent on the UTXO
side: `node_config`'s `stopatheight` clamps the *download* span
(`daemon/main.c` `dlc_span`), not `utxo_live_catchup`, which always runs to the
store's tip. `prepare-ours` therefore truncates the copied `index.dat` to
(H+1) × 48 bytes, which moves the tip — the bound that actually takes effect.

**Bounding mechanism, Core.** `-reindex -stopatheight=H` over a copied,
truncated set of `blk*.dat`.

**Post-conditions are asserted, not suggested.** `run-ours` polls
`utxo_applied_height.dat` (the checkpoint `utxo_live.c` rewrites after every
block — the post-condition the replay exists to produce, not a log message about
it), and **refuses to print a rate** if `index.dat` grew during the run, because
that would mean blocks came off the network and the range was not bounded.
`run-core` reads the tip back out of Core's own `UpdateTip` line and refuses to
print a rate if it did not reach H.

### What each side is actually doing — enumerate, do not hand-wave

Neither side is a superset of the other.

**Core does, and we do not:** maintain a mempool; maintain a leveldb block index
and compute chainwork; maintain an addrman and peers.dat; run an RPC/HTTP server
(16 worker threads, even with `-connect=0`); write `rev*.dat` undo files in its
own format; obfuscate every byte written to and read from a block file with a
per-datadir XOR key; maintain a full chainstate in leveldb with its own caching,
flushing and compaction; run the full `CheckBlock` suite enumerated in tier 2;
detect merkle mutation; enforce block weight and sigop limits.

**We do, and Core does not:** store **~22.2 M provably-unspendable outputs** that
Core never writes to its chainstate (see
[what this node does not do](#what-this-node-does-not-do)) — tens of millions of
dead entries plus the write and compaction amplification they cause, all for the
same chain; maintain our own LSM with its own WAL, manifest and compaction;
write a per-block undo log; verify **every** historical script unconditionally,
with no `assumevalid` to turn off because there never was one.

**Both do:** read every block from local disk, parse it, verify proof of work and
the merkle root, verify every input's script and signature under the correct
per-height consensus flags, and apply the result to a persistent UTXO set.

### Why it was not run

The box is not quiet, and it will not be quiet for the duration this needs.
`scripts/bench_tier3.sh check` at the time of writing:

```
loadavg(1m) = 7.60 ; approx busy cores = 7 of 32
     514       09:47 bitcoind          <- the live full-chain replay
    99.7       02:09 test_ecdsa_inve   <- another agent
    48.5    16:38:04 bitcoind          <- the Core oracle
    11.9  1-08:18:07 VLLM::EngineCor
```

Pinning does not rescue a multi-hour run the way it rescues a 40 ms
microbenchmark: the replay's I/O, page-cache pressure and memory bandwidth are
shared no matter which cores each side is given. A representative H (≥ 300,000)
means hours per side, during which the competing load will change — and
`PERF_SCOPE.md` §9's 43 %-from-contention incident is exactly what that produces.
The script refuses to take a timed measurement when `check` fails, and requires
`--force` plus an explicit "this number is contaminated" label to override.

**A documented protocol plus honest partial data is a better deliverable than a
flattering number.** So: the protocol is above, the harness is written and
tested, and there is no tier-3 result.

### Harness validation (NOT a result)

Run at **H=1000** with `--force` on the busy box described above, purely to prove
both halves work. Heights 0–1000 are dominated by process startup, hash-index
building and leveldb initialisation; **these figures say nothing about
verification speed and must not be quoted as a tier-3 comparison.**

| | elapsed | post-condition checked |
|---|---|---|
| ours (`serve`, cpus 26-27) | 12.14 s | applied height reached 1000; `index.dat` unchanged at 48,048 B |
| Core (`-reindex -assumevalid=0 -stopatheight=1000`, cpus 26-27, `-par=2 -dbcache=512`) | 8.02 s | `UpdateTip … height=1000` |

Of our 12.14 s, roughly 8 s was boot (archive reload, integrity check,
hash-index build, chainwork backfill) before the first block was applied. That
proportion is exactly why H must be large.

### To run it properly

1. Wait for a genuinely quiet machine — `scripts/bench_tier3.sh check` must pass
   with no `--force`. Stop the live replay first if that is authorised; if it is
   not, do not run tier 3.
2. Choose H ≥ 300,000. Check disk: `prepare-ours` copies whole `blk*.dat` files.
3. `prepare-ours --height H` then `prepare-core --height H`.
4. `run-ours --height H --cpus <set>` and `run-core --height H --cpus <same set>
   --par <n> --dbcache <mb>`, one after the other, never concurrently.
5. Record everything `check` printed, both `Command-line arg:` blocks, and the
   asserted post-conditions. Publish the differences list above alongside the
   ratio, or the ratio means nothing.

---

## Where we are slower

Collected in one place, because a suite that buries these is not a benchmark
suite. All single-core, ours ÷ theirs.

| | factor | where |
|---|---|---|
| **RIPEMD-160 throughput** | **3.16×** | tier 1 — **now the largest gap**, and see the note below |
| **SHA-1 throughput** | **2.68×** | tier 1 |
| **Block-level consensus check** | **1.99×** | tier 2 — *and Core is doing strictly more work*; the merkle half of it improved 2026-08-23, not re-measured |
| **SHA-512 throughput** | **1.79×** | tier 1 |
| **SHA-256 over 1 MB** | **1.15×** | tier 1 |
| **Merkle root** | ~~2.24×~~ → **1.17×** | tier 1 — 2026-08-23, 2-way batch |
| **SHA-256d over 64-byte pairs** | ~~2.24×~~ → **1.14×** | tier 1 — same change |
| **Schnorr / BIP340 verify** | ~~3.35×~~ → **~1.19×** | tier 1 — 2026-08-23, `PERF_SCOPE.md` §13 |
| **ECDSA verify** | **1.12×** | tier 1 — down from 5.5× on 2026-08-21 |
| P2TR key-path input verify | ~~≥ 3.49×~~ → **≥ 1.25×** | tier 2, composed lower bound |
| P2WPKH input verify | **≥ 1.18×** | tier 2, composed lower bound |
| Whole block, Schnorr-heavy | ~~≥ 3.16×~~ → **≥ 1.13×** | tier 2, composed lower bound |
| Whole block, realistic 1:4 mix | ~~≥ 1.48×~~ → **≥ 1.09×** | tier 2, composed lower bound |
| P2TR script-path input verify | ~~≥ 1.98×~~ → **≥ 0.71×** | tier 2 — the bound has stopped being informative, see tier 2 |

**On RIPEMD-160 and SHA-1, now the two worst rows: neither is worth fixing,
and that is a measurement, not an opinion.** Neither appears in
`PERF_SCOPE.md` §11's live-profile top 22, so each is under ~0.5 % of replay
cycles. SHA-1 is reachable only through `OP_SHA1`. RIPEMD-160 is reached once
per P2PKH/P2SH/P2WPKH input through `hash160` — real, but the profile says it
is not where the time goes. A 3× on 0.5 % is 0.3 %.

**Where we are faster:** exactly one measured row — SHA-256 over a 32-byte input,
**1.06×**. Plus the transaction-walk row, which is an architectural difference
rather than a speed win and is not counted.

That is the honest summary: **on every operation this suite could compare
directly, this project is at or behind Bitcoin Core.** As of 2026-08-23 the
signature and hash rows are all inside ~1.2×, and the two worst remaining rows
(RIPEMD-160 and SHA-1) are the two the live profile says do not matter. What
is left that *does* matter is not in this table at all: the tier-2 and tier-3
harnesses this document lists as missing.

---

## What could not be measured, and why

1. **A tier-3 end-to-end result.** Covered above: the box is shared with a live
   replay and other agents, and no amount of pinning makes a multi-hour
   comparison fair under that. Harness written and validated; result absent by
   choice.
2. **A single-harness per-input script verification** on our side, to sit against
   Core's `VerifyScriptP2WPKH` / `VerifyScriptP2TR_*`. The code path exists; the
   harness does not. Only lower bounds are published. **This is the highest-value
   addition to the suite.**
3. **A whole-block connect harness**, against Core's `ConnectBlock*`. Same
   situation, one level up.
4. **A meaningful UTXO-store comparison.** Core's `CCoinsCaching` is an in-memory
   cache hit; our `bench_lsm_get` is a disk LSM with a 4,000-key toy dataset and
   wall-clock timing. Neither is a proxy for the other, and ours does not meet
   this document's own methodology bar. A real comparison needs Core's leveldb
   chainstate read path against our LSM at production scale, which needs both
   datasets — i.e. it is a tier-3 by-product, not a microbenchmark.
5. **Core's parallel throughput.** Everything here is pinned to one core, so
   Core's `-par` script threads never ran in parallel. This suite says nothing
   about how fast Core is on 16 cores, and nothing here should be quoted as if it
   did.
6. **Anything with frequency scaling controlled.** `pyperf system tune` needs
   root. Min-of-N is the mitigation.
7. **`WriteBlockBench` / write-path comparison.** Core has one; our
   `bench_store_read` covers reads only, and its writes are synthetic. Not
   attempted.
8. **Whether the tier-2 `CheckBlock` gap is really the merkle kernel.** Stated as
   a hypothesis in tier 2; not tested.

---

## Bugs found while building this suite

None of these are fixed here — this branch is measurement infrastructure, and
repairing a consensus-path primitive belongs in its own change with its own
tests. `asm/tests/bench_abi_audit` is the standing, reproducible check;
`scripts/bench_vs_core.sh` runs it before any timing and prints the result next
to the numbers.

### 1. Six functions return with callee-saved registers destroyed

The System V AMD64 ABI requires `rbx`, `rbp`, `r12`, `r13`, `r14` and `r15` to
survive a call. `asm/tests/bench_abi_audit` loads six distinct sentinels into
them, calls each function with real arguments, and reports what came back
changed:

```
hash primitives:
  sha256_full    clean
  sha256d        clean
  sha1_full      clean
  sha512_full    clean
  ripemd160      CLOBBERS r14 r15
  hash160        CLOBBERS r13 r14 r15
block/merkle primitives:
  merkle_root    clean
  block_hash     clean
  pow_check      CLOBBERS r13
  tx_parse       clean
  cons_verify    CLOBBERS r13          (inherited from pow_check)
script interpreter:
  script_eval    CLOBBERS rbx r12 r13 r14 r15
  p2sh_hash      CLOBBERS r13 r14 r15
```

**They are all the same mistake:** the prologue is `push rbp; mov rbp, rsp;
push <callee-saved>...`, which puts the saved registers at `rbp-0x08 … rbp-0x28`,
and then stack locals are placed at offsets that overlap them. The epilogue's
`pop` instructions restore digest bytes and interpreter state instead of the
caller's values.

- `ripemd160` (`ripemd160.asm`): state words h2/h3 land on saved `r15`, h4 on the
  low half of saved `r14`. On return `r15 == (h3<<32)|h2`. Reproduced at input
  lengths 0, 20, 64 and 1,000,000.
- `hash160` (`bitcoin_addr.asm`): a 32-byte SHA-256 buffer at `rbp-0x30` covers
  saved `r13` and `r14`; `r15` is never saved, so `ripemd160`'s damage passes
  through.
- `pow_check` (`bitcoin_hash.asm`): `block_hash`'s 32-byte output buffer at
  `rbp-0x30` covers saved `r13`. `cons_verify`'s own frame is correct — it saves
  only `rbx`, at `rbp-8` — and inherits the damage by calling `pow_check`.
- **`script_eval` (`bitcoin_interp.asm:288-301`) is the worst of them and the one
  to fix first.** It pushes all five and then documents and uses locals at
  exactly those five offsets: `-0x08 fExec, -0x10 pc, -0x18 pend,
  -0x20 pbegincodehash, -0x28 nOpCount`. All five registers come back holding
  interpreter state. It is entered for every input of every transaction in every
  block.

**Is it live today? On the consensus path, no — and the only thing preventing it
is `-O0`.** `asm/Makefile:1309` builds `daemon/bitcoind` with `-no-pie -O0`, and
at `-O0` GCC keeps everything `rbp`-relative and reloads across calls, so no live
value sits in a clobbered register. At `-O1`/`-O2` it is an immediate hit — e.g.
`bitcoin_witness_v0.c` at `-O2` keeps the scriptPubKey pointer in `r13` across
`call hash160` and dereferences it four instructions later. The Makefile's own
folklore about C files "misbehaving under aggressive optimisation"
(`asm/Makefile:266`, `asm/Makefile:1296`) is very likely this bug class
misattributed to a compiler quirk. **The `-O0` pin is load-bearing, and nobody
recorded that it was.**

**One live instance does exist, in a shipping binary.** `daemon/pverify` is built
at `-O1` (`asm/Makefile:1317`), where GCC sinks a `cur_fno = fno` store past both
the `pow_check` and `cons_verify` calls, so `cur_fno` is poisoned every
iteration. The consequence is a performance bug, not a wrong answer: the
`if (fno != cur_fno)` test always fires and pverify re-opens the block file for
every block, but it opens the *correct* file, so verification results are
unaffected.

**`make abi-check` passes on all of this.** `scripts/abi_stack_audit.py` and
`asm/tests/test_abi_stack_align.c` audit RSP 16-alignment at call sites, which is
a different (and also useful) property. This class of bug is invisible to them.
`asm/tests/bench_abi_audit` is deliberately **not** wired into `make test` yet,
because it currently fails by design; wiring it in is the natural second half of
fixing these.

A static scan for the same pattern also flagged, unverified dynamically:
`sha512_block`, `bitcoind.asm` `node_drain` and `node_serve_block`,
`bitcoin_mempool.asm` `mpool_put`, `bip32_fingerprint`, and all four
`bitcoin_bip39.asm` entry points.

### 2. `connect=` does not stop the download worker from dialling DNS seeds

Found the first time `bench_tier3.sh run-ours` was executed. With
`listen=0 dnsseed=0 maxconnections=0` the daemon logged
`[boot] dnsseed=0 -- not querying the DNS seeds`, then
`[dl] no discovered peers; temporary seed fallback`, dialled
`seed.bitcoin.sipa.be`, `dnsseed.bluematt.me` and two more, and **downloaded 350
blocks past the truncated tip within three minutes** — silently un-bounding the
range the harness had just set up.

Adding `connect=192.0.2.1` fixed the block download (the boot path honours it:
`[boot] connect= set -- skipping all peer discovery`, `daemon/main.c:1020`), but
**the worker's fallback at `daemon/main.c:2066` still fires under `connect_only`**
and still dialled a DNS seed as a feeler. The code at `daemon/main.c:1017` states
the intent plainly — "Core `-connect`: these are the ONLY peers. No DNS, no
seednode getaddr, no book growth" — and the degraded fallback consults none of
`dnsseed`, `maxconnections` or `connect_only`.

Beyond breaking a bounded benchmark, this means an operator who sets
`dnsseed=0` or `connect=` for privacy reasons still leaks to the DNS seeds
whenever peer discovery comes up empty.

Unprivileged network namespaces are unavailable on this box (`unshare -rn` →
`write failed /proc/self/uid_map: Operation not permitted`), so the harness
cannot enforce isolation. It asserts the post-condition instead: if `index.dat`
grew during a run, `run-ours` refuses to report a rate.

### 3. Core's `blocks/xor.dat` is easy to lose, and losing it fails silently

Not our bug — an operational trap worth writing down, because it cost an hour.
Since Core v28 every byte in a `blk*.dat` is XORed with a per-datadir key stored
in `blocks/xor.dat`. Copying block files without it produced a `-reindex` that
read all 15 files, printed "Reindexing block file blk00014.dat (93 % complete)"
and "Reindexing finished", reported `Loaded 0 blocks from external file` for every
one, and settled at height 0 — **with no error of any kind**. Worse, because
`-reindex` opens block files for writing, that first bad run rewrote the head of
`blk00000.dat` under its own freshly generated key, so the directory could not
be repaired by copying `xor.dat` in afterwards. `prepare-core` now copies the key
with the data and refuses to reuse a non-empty destination.

---

## Reproducing

**2026-08-23 note on re-running this on a busy box.** `scripts/bench_vs_core.sh`
was re-run after the §13 work and its output was discarded, because the
machine was at load 42: Core's nanobench and libsecp256k1's `bench` both time
with a WALL clock, while our harnesses use `CLOCK_THREAD_CPUTIME_ID`, so
contention inflates their side more than ours and the ratio flatters us. The
refreshed figures in this document were taken instead by **alternating Core's
binary and ours back to back on one core, three passes, minimum of each** —
and validated by a control: `bench_hash_core` still carries the OLD
one-at-a-time `sha256d` shape, which in that same window measured 2.22× Core,
reproducing the 2.24× on this page to within 1 %. `PERF_SCOPE.md` §13.3b has
the full table and the CPU/wall ratio.

```bash
# everything, default settings (pins to cpu 25, 3 process reps, min-of-15 rounds)
scripts/bench_vs_core.sh

# one tier, more repetitions, a different core
scripts/bench_vs_core.sh --tier 1 --reps 5 --cpu 30

# what it would run
scripts/bench_vs_core.sh --list
```

The driver builds what it needs and never touches the oracle:

- Our harnesses: `cd asm && make bench-vs-core`.
- libsecp256k1's own `bench`: configured from Core's vendored source with Core's
  shipped options, into `bench-results/secp-bench/`.
- Core's `bench_bitcoin`: configured **out of tree** into `/storage/core-bench-build`
  with `-DBUILD_BENCH=ON`. It is never built in `/storage/bitcoin-core-source/build`,
  because a Core oracle daemon runs from there and other work depends on it
  staying up. (Out of tree rather than the in-tree `build-bench` a writable
  checkout would use, because `/storage/bitcoin-core-source` is root-owned.)

Raw output from every command — including `environment.txt`, the Core CSVs and
the CPU/wall ratios — is kept under `bench-results/<timestamp>/`, so a surprising
row can be traced back to the text it came from. That directory is gitignored;
this document carries the numbers.

New harnesses added by this branch:

| file | what it measures | Core opposite number |
|---|---|---|
| `asm/tests/bench_schnorr.c` | BIP340 verify | libsecp256k1 `bench schnorrsig_verify` |
| `asm/tests/bench_hash_core.c` | SHA-256/1/512, RIPEMD-160 in Core's exact buffer shapes | `crypto_hash.cpp` |
| `asm/tests/bench_merkle.c` | merkle root, 9,001 leaves | `MerkleRoot` |
| `asm/tests/bench_checkblock.c` | `cons_verify` + tx walk on block 413,567 | `CheckBlockTest`, `DeserializeBlockTest` |
| `asm/tests/bench_abi_audit.c` | callee-saved register preservation | none — this is ours to worry about |
| `asm/tests/bench_abi_guard.S` | the trampoline and probe the above two use | — |

Changed by the 2026-08-23 work (`PERF_SCOPE.md` §13):

| file | what changed |
|---|---|
| `asm/tests/bench_hash_core.c` | the `SHA256D64` row now drives `sha256d64`, which is Core's actual opposite number; the old one-at-a-time `sha256d` shape is kept as a second row so the change is visible in the same table |
