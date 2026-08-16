# CUDA Acceleration for bitcoinmachinecode — Working Analysis

Status: **PoC complete and verified on this host (RTX 5090 / CUDA 13.3, SM 12.0).**
This directory contains a working proof-of-concept plus the roadmap, and includes an
**auto-detecting, fallback-safe dispatcher** (`cuda_autodetect.c`): it probes at
runtime for a usable CUDA device and uses the GPU only when present AND the batch is
large enough to amortize launch/copy, otherwise falls back bit-exact to the proven
assembly crypto. It is NOT yet wired into the assembly node binary — see
"Integration plan" for the seam.

`cuda_verify` PASSES against the repo's own assembly oracle (same FIPS vectors +
10,000 random cases, bit-for-bit). `cuda_bench` reports real measured numbers.
`cuda_autodetect_test` verifies routing + digest correctness in every mode (default →
CUDA; disabled / small-batch / no-GPU → CPU fallback).

---

## 1. TL;DR (should we / can we do CUDA?)

**Yes, conditionally.** The GPU is not a universal win for this product. It wins
only for *batched, independent* crypto work. Concretely on the RTX 5090 here:

| Workload                      | CPU (asm SHA-NI) | GPU (scalar CUDA, unoptimized) | Result   |
|-------------------------------|------------------|-------------------------------|----------|
| 1,000,000 independent sha256d | 8.57 Mh/s        | 151.4 Mh/s                    | **17.7x** |
| 1,000            sha256d      | 8.86 Mh/s        | 29.7 Mh/s                     | 3.35x    |
| 100              sha256d      | 8.32 Mh/s        | 5.01 Mh/s                     | 0.60x    |

The crossover is around a few hundred independent hashes. Above ~1k hashes the GPU
pulls ahead and the gap widens almost linearly. The numbers above are for a
**deliberately naive 1-thread-per-message scalar kernel** — the honest
correctness-first baseline. A proper SHA pipeline kernel would widen the gap
substantially (see §6).

**Why the CPU path is already fast:** the assembly `sha256_block` already has a
CPUID-gated SHA-NI accelerator (see `sha256.asm` `:sha256_block_shani:`). One hash
at a time, SHA-NI is the right tool and a GPU cannot beat it (a single 64-round
block finishes in microseconds on the GPU — far slower than CPU per hash once you
add launch + copy). The GPU's entire value is **throughput on batches**, not
latency on singles.

---

## 2. What crypto work exists in the product (the CUDA candidates)

From `asm/*.asm`, the crypto surface is:

- **SHA-256** (`sha256.asm`, `bitcoin_hash.asm`)
  - `sha256_full`, `sha256_block`, plus node layer `sha256d`, `block_hash`,
    `merkle_root`, `pow_check`, `diff_target`. Embarrassingly parallel. **Best fit.**
- **RIPEMD-160** (`ripemd160.asm`) — hash160 (addresses). Batchable.
- **SHA-512** (`sha512.asm`) — used by BIP39/HMAC chains (BIP32/39 seeds).
  Batchable; also benefits from SHA-512 SHA intrinsics on the CPU side.
- **HMAC-SHA256/SHA512** (`bitcoin_hmac.asm`) — BIP32/39, deterministic derivation.
  Sequential internally, but many independent derivations = batchable.
- **secp256k1** (`secp256k1_fe.asm`, `_scalar`, `_point`, `_ecdsa`, `_schnorr`,
  `_taproot`) — EC multiplication is the consensus-critical hot path for
  script signature verification (ECDSA/Schnorr). **Hard but very high value**, and
  the natural fit for CUDA's 32-bit modular-multiply strengths *if* you write the
  field arithmetic in CUDA (see §6 — this is a big project, distinct from hashing).

---

## 3. Where GPU hashing actually fits the product (honest scoring)

| Product activity                                   | Batchable? | GPU value | Notes                                     |
|----------------------------------------------------|-----------|-----------|-------------------------------------------|
| PoW check on one header (`pow_check`)              | no        | none      | keep asm/SHA-NI                           |
| IBD: validating many blocks/txs                    | **yes**   | **high**  | batch tx/block hashes per page            |
| Mempool accept / tx relay (one tx)                 | no*       | low       | *batch the whole mempool accept queue*    |
| Wallet: derive many addresses / many BIP32 paths   | **yes**   | med/high  | hash160 + HMAC batches                    |
| Re-index / utxo rebuild / verify-txid analytics    | **yes**   | **high**  | bulk sha256d                              |
| Mining-style nonce scanning (batch of headers)     | **yes**   | **high**  | the `cuda_bench` workload A               |
| Intermittent GUI / CLI "show one hash"             | no        | none      | keep CPU                                  |

**Design principle:** the node keeps its proven assembly crypto as the always-on,
zero-setup, single-hash path (it is the correctness anchor and works on any CPU
with no driver). CUDA is an *optional accelerator tier* enabled only when (a) a
GPU+runtime is present, and (b) the caller supplies a batch of independent hashes
large enough to amortize launch/copy. This is the same philosophy as the existing
SHA-NI dispatch: CPUID-gate, fall back to scalar. CUDA gating just falls back to
the CPU (SHA-NI or scalar) instead of failing.

---

## 4. What is implemented in this directory (working PoC)

- **`cuda_sha256.cu`** — batched SHA-256 / SHA-256d kernel (1 thread per message,
  FIPS 180-4) + host launchers with a clean opaque `void*` ABI
  (`cuda_sha256_batch_init/launch/sync/free`) + shared ABI header `cuda_sha256.h`.
- **`cuda_verify.cu`** — the correctness gate. Compares CUDA output against the
  repo's **own assembly `sha256_full`/`sha256d` oracle** (linked from
  `../sha256.o ../bitcoin_hash.o`) over:
  - FIPS 180-4 vectors (empty, "abc"),
  - the Bitcoin-critical padding edges the node actually hits: len 55, 56, 57, 63,
    64, 65 (single-block boundary + length-spill cases),
  - a 200-byte message, a 1000-byte message,
  - **10,000 random messages** of varied length (sha256d).
  Result: **all pass, 0 failures** — CUDA digests are bit-for-bit identical to the
  assembly oracle.
- **`cuda_bench.cu`** — honest wall-clock comparison of the *whole batch*
  (host upload + launch + device→host copy + sync) for workload A (N independent
  80-byte headers, sha256d each) vs. the identical N hashes through the asm
  `sha256d` on CPU. Cross-checks a sample against CPU for correctness.
- **`cuda_autodetect.c`** — the auto-detect + fallback dispatcher. The single
  entrypoint `bmc_sha256d_batch(out, msgs, idx, count)` decides at runtime:
  - probes once (cached) by dlopen'ing `libbmc_cuda.so` and calling
    `cudaGetDeviceCount` for a real "any usable device" check;
  - uses CUDA only when a device is present AND `count >= 512` (the measured
    amortization threshold) AND not disabled by `BMC_CUDA=0`;
  - on ANY CUDA error, or no device, or small batch, falls through to the proven
    assembly `sha256d` loop — bit-exact, no driver required.
  Introspection for tests/AI audits: `bmc_cuda_detected()` and
  `bmc_cuda_was_used()`.
- **`cuda_autodetect_test.c`** — verifies routing + digest correctness in EVERY
  mode via a fresh process per mode (probe state is cached, so each mode must run
  in its own process): default → CUDA (digests OK), `BMC_CUDA=0` → CPU, batch 100
  (< threshold) → CPU, `BMC_CUDA_LIB=/nonexistent/...` (simulated no GPU) → CPU.
  All modes produce byte-exact digests vs the assembly oracle.
- **`libbmc_cuda.so`** — CUDA kernels + host launchers compiled as a shared object
  that the dispatcher dlopens at runtime (build target in the Makefile).

### Auto-detect guarantee (respects the repo's audit stance)
The CPU (assembly) path is and remains the correctness anchor. CUDA is a
performance tier that is activated only when all of: (device present, batch large
enough, not disabled). Any failure to load or run CUDA degrades to the identical
CPU behavior — never to wrong output. A production integration must keep the
`cuda_autodetect_test` matrix in CI before the CUDA tier may ever serve consensus
data.
- **`Makefile`** — `make all` = verify + bench + autodetect; `make poc` runs the
  txid-offload PoC below. Building the CUDA kernel/.so requires nvcc + CUDA GPU;
  but the auto-detect dispatcher (plain C + assembly oracle) links and runs with
  zero CUDA installed and simply falls back to CPU at runtime.

### cons_verify txid-offload PoC — CORRECT but NOT worth it per-block (findings)

`cuda_txid_poc.py` (`make poc`) prototypes offloading cons_verify's dominant
per-block crypto — computing tx_txid (= SHA-256d of the unwitnessed tx) for every
tx — to the CUDA sha256d batch, verified against the trusted assembly `tx_txid`
oracle via consensus_shim on a REAL mainnet block.

**Correctness: PROVEN.** CUDA sha256d reproduced the asm tx_txid byte-for-byte on
every tx of blk 200000 (0 / 388 mismatches) — including the SegWit-era unwitnessed
form. The mechanism is sound.

**Performance: NEGATIVE for per-block offload.** On a single block's ~388 txs:
  - CUDA batch (incl. host upload + launch + device→host copy): 172.7 ms
  - ASM oracle serial (per-tx via shim): 107.5 ms
  - => CUDA is ~0.6x the speed (slower)

Root cause: per-block launch + H2D/D2H transfer overhead (~170ms) dwarfs the
actual crypto on a few-hundred-tx batch — far below the ~1k+ crossover we measured
in `cuda_bench`, and the per-tx CPU path through the shim is already fast.

**Conclusion for the roadmap (tier-defining):** Do NOT wire CUDA into per-block
`cons_verify` — it would slow the node down. CUDA only pays off for txid hashing
if we batch ACROSS many blocks (thousands of txids per GPU call), i.e. a harness/API
that collects unwitnessed txs from a whole header-page / IBD page and hash them in
one launch — then the ~18x raw batch win applies. This is exactly the deferred
direction already noted in §12 of PLAN.md; this PoC confirms the "batch across
blocks, not per-block" shape is required.

### Config note
This host has `nvcc` (CUDA 13.3) and one RTX 5090 (SM 12.0). Builds use
`-arch=sm_120`. The GPU is shared with a vLLM engine (31.3 of 32.6 GiB in use), so
the launch/copy numbers reflect a busy device. Change `ARCH` in the Makefile for a
different target.

---

## 5. Correctness / audit stance (aligns with the repo's security contract)

The README stresses this code is untrusted/experimental until independently
audited, and that crypto must be bit-exact. GPU hashing must honour the same rule:
**a CUDA SHA-256 either produces the identical digest to FIPS 180-4 or it is
wrong.** There is no "GPU-approximate hash." Our gate enforces exactly this by
comparing against the assembly oracle over random + edge vectors. Any future
integration MUST keep a permanent CI harness of the same shape before the CUDA
path is ever allowed to serve consensus data.

---

## 6. Roadmap / ways to take this further (ranked)

### Tier 1 — finish & land SHA-256 acceleration (small, high confidence)
1. **Optimize the SHA kernel.** Replace the 1-thread-per-message scalar body with
   the standard NVIDIA-style 5-way message-schedule pipeline (process 5 hashes per
   thread with interleaved schedule/compress), load schedule words via wider loads,
   keep round constants in registers/`__constant__`, and size the grid to saturate
   all 170 SMs. Expect large gains over the already-17x baseline. Re-verify with
   the *same* gate (the oracle comparison does not care about speed).
2. **Add SHA-256d-native + RIPEMD-160 (hash160) batch kernels** for address / utxo
   index building.
3. **Use unified/pinned memory + async streams** so the node can overlap the
   device-to-host copy of batch i with launch of batch i+1, hiding most of the
   copy cost (the dominant overhead at small N).
4. **Wire an optional runtime gate** into the node's hash dispatch mirroring the
   SHA-NI seam: `sha256_block_shani` is chosen by CPUID; a batch entrypoint would
   be chosen by "CUDA runtime loaded AND batch size > threshold AND a batch API
   caller". Keep single-hash call sites (pow_check, per-tx in mempool) on CPU.

### Tier 2 — secp256k1 ECDSA/Schnorr verify acceleration (very high value, big effort)
5. **Port secp256k1 field/point arithmetic to CUDA as a batch verifier.** This is
   the consensus-critical hot path during IBD (each input's signature verify).
   Design:
   - Reuse the *verified* `secp256k1_fe.asm`/`_point.asm` algorithms as the spec;
     translate to CUDA keeping the same 256-bit-limb layout.
   - One *warp* (32 lanes) or one *thread* per input, batching many signature
     verifications across blocks.
   - Do NOT hand-roll; validate every kernel against the existing
     `test_ecdsa`/`test_schnorr` oracle and the repo corpus
     (`validation/corpus_diff.py`), exactly like the hashing gate above.
   - Note: ECDSA verify has inherently irregular per-input branches (some fail
     early on pubkey parse or low-S), so coalesce by *junk* verification results
     (each lane verifies a distinct input and writes a pass/fail bit) — never let
     one slow/garbage input stall a whole warp.
6. **Batch validation at the block level.** Group all signature checks in a
   downloaded block (or across a headers page worth of blocks) into one kernel
   launch rather than one call per input. This is where the real node speedup
   lives during IBD.

### Tier 3 — HMAC / BIP32 / BIP39 (medium value, easy)
7. Batch key-derivation: many independent HMAC-SHA512 (BIP32) steps, many BIP39
   seed derivations, many hash160 address generations in one launch. These are
   perfect-fire-and-forget batches for a wallet that generates addresses on
   demand / sweeps many keys.

### Tier 4 — long shots / not worth it
8. **SHA-512 CPU intrinsics first.** Before any GPU work on BIP39, the cheap win
   is SHA-512 SHA intrinsics on the CPU scalar path (like the SHA-NI 256 work).
9. **Merkle-root / merkle branch** — inherently tiny and serialized (log-depth);
   leave on CPU.
10. **Verifying a single tx / one RPC "getblockhash"** — always leave on CPU.

---

## 7. Integration seam into the assembly node (concrete)

The node is pure assembly; CUDA is a C++/device-language runtime. You do not
rewrite the assembly. You add a **small C host shim** (compiled with nvcc or as a
`libcudart`-linked `.so`) that the asm binary can `dlsym`+call via the existing
ABI, exactly the way `daemon/bitcoind` already shells out to C for
RPC/wallet/policy. Suggested shape:

- Provide `cuda_sha256_batch_*` (already written) compiled behind a runtime probe:
  `dlopen("libcudart")` and check for a device; NULL implies CPU fallback.
- Add a tiny asm trampoline in `bitcoin_hash.asm` that, given
  `(count, msgs, lengths, out)` for a known batch shape, attempts the CUDA path
  once the runtime is present and count > threshold, else falls through to the
  scalar `sha256d` loop that exists today.
- Guard it behind an env flag (e.g. `BMC_CUDA=1`) so behavior is never silently
  different from a pure-CPU build — respecting the "untrusted until audited"
  stance. Ship the CPU path as default-off until the CUDA path has matched a
  full mainnet IBD hash-for-hash in a CI differential test.

---

## 8. Files

- `cuda_sha256.cu` — batch SHA-256/SHA-256d kernel + host API
- `cuda_sha256.h`  — opaque ABI header
- `cuda_verify.cu` — correctness gate vs. the assembly oracle (PASSES)
- `cuda_bench.cu`  — throughput comparison vs. asm (17-18x at 1M batch)
- `cuda_autodetect.c` — auto-detect + fallback dispatcher (bmc_sha256d_batch)
- `cuda_autodetect_test.c` — routing/digest matrix (all modes pass)
- `libbmc_cuda.so` — runtime-loaded CUDA backend (build target)
- `Makefile`       — `make verify` / `make bench` / `make detect` / `make all`

Rebuild/run from this directory:

    cd /storage/bitcoinmachinecode/asm/cuda
    make all          # verify then bench then autodetect
    make detect       # just the auto-detect routing/digest matrix

Note: `make all` needs the assembly oracle objects; they are produced by
`make asm` in `/storage/bitcoinmachinecode/asm`.
