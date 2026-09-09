# OSX PORT STATE — durable snapshot

Updated whenever status materially changes. Newest section top.
(Companion to `OSX_PORT.md` (branch model), `OSX_ROADMAP.md` (per-module
status) and `OSX_STRATEGY.md` (phased plan-of-record, PR #130).)

## 2026-09-09 — bitcoin_hash native: first full 6-op module, x86-diff byte-identical

- `port/osx/bitcoin_hash.S` (7 public symbols) gated three ways: upstream
  test_pow_check 13/13 native, 6,485-vector Python-oracle differential 0
  failures, and byte-identical results vs the x86 bitcoin_hash.o/sha256.o run
  on the 9950X3D (192.168.5.242). Driver pair committed (dvh.c /
  gen_bhash_vecs.py) — batched file-based oracles, no popen.
- Driver bug caught by cross-arch diff: sha256d64 out stride is 32B per 64B
  input (Core SHA256D64 shape); assuming 64B out stride silently compared
  stale memory on BOTH arches and "agreed". Cross-arch diffing only proves
  what the driver actually measures.
- x86-vs-osx benchmarking now possible on shared shapes: bench_hash_core +
  bench_fe build on both. x86 reference numbers captured (9950X3D, cores
  16-19): sha256_1MB 2.40 GB/s, fe_mul THRU 5.54ns, ECDSA verify 47.1k/s/core,
  Schnorr 38.4k/s/core.
- IBD status: x86 full mainnet IBD COMPLETE on .242 (tip 961639, progress 1.0,
  760G, /mnt/2tbssd/bmc-bench deployment). OSX native daemon (p3) still
  blocked on p1/p2 module waves.

## 2026-09-09 — p1 progressing: sha512 + ripemd160 + sha1 landed

- sha1 joined ripemd160 as a C twin (gate 10/10 after fixing a LE length
  field the gate caught). Committed straight to bmc_osx (3ee6c5a5).

- sha512.S native, upstream test 4/4. ripemd160 shipped as C twin after
  two failed asm translations (see OSX_ROADMAP pitfalls); 23/23 + 2.08M
  digest thread-stress green. bitcoin_hash done earlier (PR #134).
- Committed straight to bmc_osx (docs+module batch); next modules:
  sha1, bech32, base32, then the secp256k1 family.

## 2026-09-09 — p0 landed: sha256 is the first native module

- `port/osx/sha256.S` (Mach-O AArch64, 7 public symbols) + native gate
  `port/osx/tests/test_sha256_osx.c` (16 checks, 0 failures) + upstream
  `test_cry6_sha_paths.c` linked unchanged against the Mach-O object (7/7).
  Upstream C compiled untouched; only the x86-only CPUID section of
  test_sha256.c needed replacing (Darwin has no CPUID) — the osx gate
  replaces it with a sysctl cross-check. Full evidence in OSX_ROADMAP.md.
- Recurring-pitfall list started in OSX_ROADMAP.md (sp alignment at bl
  sites, x18/x28 reserved, @PAGEOFF, sysctl probes, python -c limits).
- Next: bitcoin_hash (sha256d/block_hash/diff_target/pow_check) on top of
  the proven sha256, then sha1/sha512/ripemd160.

## 2026-09-09 — strategy locked: native port, phased, PR-per-layer

- `port/OSX_STRATEGY.md` merged via PR #130: port-don't-emulate decision,
  measured surface (238 raw syscalls; C layer POSIX-clean except 2 prctl
  uses; no futex/epoll/eventfd), 5 phases (p0 build bridge → p1 pure-compute
  → p2 syscall I/O → p3 daemon → p4 parity), PR branches `osx/pN-*` merged
  --no-ff into bmc_osx with green gates.
- First working PR target: p0 sha256 proof module (Mach-O build + native
  harness + differential fuzz vs hashlib/Python).

## 2026-09-09 — round 0: fresh start on `bmc_osx`

- Branch `bmc_osx` forked from `main` @1dac38ae (upstream through PR #127,
  addnode dials), pushed to origin, local clone at `~/bmc_osx/bitcoinmachinecode`.
- `main` is declared the x86-64 development tree; `bmc_osx` merges from it,
  never develops into it.
- Toolchain verified: Apple clang 21.0.0, macOS 26.6.2, M1 Max (arm64).
- Reuse strategy: arm-port branch (origin) is the algorithm reference — all
  63 modules were ported and differential-verified there — but its syscall
  layer is Linux-only (`svc #0`, nr in x8). Darwin needs `svc #0x80`,
  nr in x16, Mach-O sections/symbols (`_` prefix), no x28 use, PIC via
  adrp/add. Rough rework weight per module (svc counts from arm-port .S):
  utxo_lsm 66, store 42, utxo_store 30, idxscan 19, undo 18, store_fast 17.
- Docs created: `port/OSX_PORT.md`, `port/OSX_ROADMAP.md`, this file.
- Next: pick the first module (pure-compute, no syscalls — e.g. sha256 or
  bitcoin_hash) to prove the Mach-O build+verify loop end to end.
