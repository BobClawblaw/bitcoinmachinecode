# bmc_osx cross-arch benchmarks (x86 bare metal vs Apple Silicon native)

Purpose: measure the macOS AArch64 port against the x86-64 original on the
same repo harnesses, same shapes, same measurement discipline
(CLOCK_THREAD_CPUTIME_ID, min-of-N). No emulation anywhere:
- x86 side: bare metal AMD Ryzen 9 9950X3D (192.168.5.242, Ubuntu 24.04,
  gcc 13.3, NASM 2.16.01), benches pinned with `taskset -c 16-19`.
- osx side: Apple M1 Max (this Mac, macOS 26.6.2, Apple clang 21, arm64).
- METHODOLOGY NOTE: the M1 Max also hosts parallel compile/agent workloads.
  Contention inflates wall-sensitive benches (merkle_root measured 164 ns/leaf
  under load, 71 quiet). Numbers below were re-verified quiet; re-measure the
  same way before trusting any future delta.

## Hash primitives — bench_hash_core (Core's own benchmark shapes)

| shape              | x86 9950X3D      | osx M1 Max       | osx/x86 |
|--------------------|------------------|------------------|---------|
| sha256_1MB         | 416 us, 2.40 GB/s| 445 us, 2.25 GB/s| 0.94x   |
| sha256_32b         | 35.4 ns          | 34.6 ns          | 1.02x   |
| sha256d64 64Bx1024 | 53.5 us, 1.22 GB/s | 64.7 us, 1.01 GB/s | 0.83x |
| sha256d_seq x1024  | 103.3 us, 0.64 GB/s | 98.8 us, 0.66 GB/s | 1.05x |
| sha1_1MB           | 1639 us, 0.61 GB/s | 4557 us, 0.22 GB/s | 0.36x |
| sha512_1MB         | 1651 us, 0.61 GB/s | 2970 us, 0.34 GB/s | 0.56x |
| ripemd160_1MB      | 1192 us, 0.84 GB/s | 3407 us, 0.29 GB/s | 0.35x |

Notes:
- sha256 (native asm, FEAT_SHA256 accelerator path) is nearly at parity and
  WINS on 32-byte messages; x86's SHA-NI edge shows only on long streams.
- sha1/ripemd160 are C twins on osx (escape hatch) — their 3x gap is
  un-tuned C vs tuned x86 asm; prime candidates for asm optimization later.
- sha512 asm exists on osx but is 1.8x behind; likely scheduling, worth a
  pass before p3.

## Field arithmetic — bench_fe

| op         | x86 (ADcx/ADox/MULX asm) | osx (C twin) | osx/x86 |
|------------|--------------------------|--------------|---------|
| fe_mul LAT | 8.65 ns                  | 22.67 ns     | 0.38x   |
| fe_mul THRU| 5.74 ns                  | 12.73 ns     | 0.45x   |
| fe_sqr LAT | 7.62 ns                  | 21.98 ns     | 0.35x   |
| fe_sqr THRU| 4.65 ns                  | 12.33 ns     | 0.38x   |
| fe_add LAT | 2.19 ns                  | 8.20 ns      | 0.27x   |
| fe_sub LAT | 1.27 ns                  | 7.15 ns      | 0.18x   |

The x86 carry schedule has no AArch64 equivalent (documented in fe_twin.c);
closing this gap needs a hand-written limb implementation using
adcs/sbc/mul+umulh. fe_add/fe_sub at 7-8 ns are absurd for what they do —
likely call overhead dominates; inline candidates.

## AEAD / stream C + sha256 reference — bench_ckeys

| op           | x86         | osx         | osx/x86 |
|--------------|-------------|-------------|---------|
| chacha20     | 846 MB/s    | 632 MB/s    | 0.75x   |
| poly1305     | 3666 MB/s   | 1497 MB/s   | 0.41x   |
| aead 1KB     | 628 MB/s    | 439 MB/s    | 0.70x   |
| sha3-256     | 128 MB/s    | 331 MB/s    | 2.59x   |
| sha256 (asm) | 2387 MB/s   | 2224 MB/s   | 0.93x   |

osx WINS sha3-256 2.6x (C on both sides; x86 number likely hurt by
-no-pie/hardening flags). poly1305 is the weakest — vectorizable on ARM.

## Merkle — bench_merkle (9001 leaves, Core fixture)

| op                | x86         | osx        | osx/x86 |
|-------------------|-------------|------------|---------|
| merkle_root 9001  | 53.7 ns/leaf| 71.2 ns/leaf | 0.75x |

osx sha256d64 in isolation: 63.2 ns/pair (x86: two interleaved lanes at
53.5 us/1024 = 52.3 ns/pair). The 2-way interleave strategy is correct on
both; the residual gap is the compression kernel itself.

## Full-block verify — bench_checkblock (block 413567, Core fixture, 1557 txs)

| op        | x86            | osx   |
|-----------|----------------|-------|
| tx walk   | 12.92 ns/tx    | TBD (needs bitcoin_tx port) |
| cons_verify | 410.41 ns/tx | TBD (needs interp/scriptcodec/cons ports) |

## IBD throughput (x86 reference, full mainnet)

Deployment: /mnt/2tbssd/bmc-bench on .242, bmcbitcoind @ 75a1f21e, 3 outbound
peers, dbcache=8192, bulk_slots=2^25.
- Bulk phase disk growth: 100G -> 629G in 13.4 h = **39.6 GB/h sustained**.
- Tip 961639 first seen 2026-09-09 04:28 UTC, 17.2 h into the monitored
  epoch (epoch.start 2026-09-08 11:18 UTC; the run resumed from ~100G of
  prior headers/blocks, so genesis-to-tip is not directly derivable).
- Final chain size: 760G (verificationprogress 1.0, initialblockdownload
  still true at check time), 165,810,611 txouts in the live UTXO set.
- osx equivalent: pending the p3 daemon link (this is the reason p1/p2 are
  being ported); the Darwin daemon will run this same IBD natively on the
  M1 Max for the real cross-arch IBD comparison.

## 2026-09-09 — ECDSA/Schnorr (first cross-arch crypto-verify numbers)
First native ECDSA + BIP340 Schnorr verification benchmarks on the M1 Max
(port/osx/ecdsa_twin.c + pubkey_schnorr_twin.c, quiet machine, min-of-5
thread-CPU rounds — same discipline as the x86 side):

| benchmark | x86 9950X3D (taskset -c 16-19) | M1 Max (this port) | ratio |
|---|---|---|---|
| ecdsa_verify  | 21.46 us/verify (46,606/s per core) | 140.14 us/verify (7,136/s per core) | 6.5x |
| schnorr_verify| 26.07 us/verify (38,353/s per core) | 273.11 us/verify (3,661/s per core) | 10.5x |
| schnorr_verify (2026-09-10 CORRECTED) | 26.07 us/verify | 79.92 us/verify (12,513/s per core) | 3.1x |

Context: 1e9 sigs at these rates = 6.0 core-hours (x86) vs 38.9 core-hours
(M1 Max) for ECDSA.

2026-09-10 CORRECTION: the 273.11 us schnorr number was measured with
leftover bring-up debug inside schnorr_verify (two fe_inv + several
fprintf per call) -- removed in the bip143 session; re-measured 79.92 us
(3.4x faster, and the ratio to x86 drops from 10.5x to 3.1x).  The
ecdsa_verify number was never affected (ecdsa_twin.c carried no debug).  The gap is dominated by the C twins running the same
algorithms the x86 has as hand-scheduled asm (fe_mul chains, comb/GLV
multiplies); AArch64 native asm for fe_mul/scalar_mul is future work and
should close much of it.  Both implementations produce byte-identical
results (1740-vector point/CT differential + BIP340 csv row 0 fixture).
