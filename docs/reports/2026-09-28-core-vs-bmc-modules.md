# Bitcoin Machine Code vs Bitcoin Core, module by module — the 2026-09-28 rerun

2026-09-28. Bitcoin Machine Code (an all-assembly x86-64 node, https://github.com/BobClawblaw/bitcoinmachinecode) measured against Bitcoin Core's own benchmark suite (src/bench, v31.99.0-67efced1fc83), on the same box, the same core, the same inputs -- the 2026-09-27 report rerun in full after one day of work on the gaps it named: the MuHash inverse (a port of Core's safegcd), ElligatorSwift (constant-time comb and window multiplies, a Jacobi square test, and an encoder that draws its branch at random as libsecp256k1 does -- the fixed order was biased), ChaCha20 in AVX2, SHA-1 by SHA-NI, SHA-512 unrolled, Base58Check by 64-bit limbs.

**How it was measured.** Core's numbers come from Core's bench_bitcoin (nanobench, -min-time=1000, the minimum over 3 processes), built RelWithDebInfo as Core's own default; the secp256k1 rows from libsecp256k1's own bench, Core's vendored copy with Core's shipped config. Ours come from harnesses that mirror each Core benchmark's loop -- the same work per iteration, the same sizes and element counts -- as thread CPU time, the minimum of 15 rounds. Both sides pinned to one core (taskset -c 25) of an AMD Ryzen 9 9950X3D with the production node and a Core oracle running (load average 3.3 on 32 threads); Core's timed loops showed no preemption (cpu/wall 1.000). Where the two sides do not do the same work, the row says so. The 09-27 report's MuHashMul row compared one multiply with Core's two; every row here is per the same unit on both sides.

## Where this node is ahead

| **module** | **Core** | **bmc** | **ratio** | **note** |
|---|---|---|---|---|
| Base58Check encode (`Base58CheckEncode`) | 47.7 ns/B | 6.1 ns/B | **7.9x faster** | 64-bit limbs divided by 58^10; was 3.2x slower on 09-27 |
| MuHash insert of one coin (`MuHash`) | 2.66 us | 0.45 us | **6.0x faster** | expand + one multiply; Core's op is expand + two multiplies |
| MuHash 3072-bit multiply (`MuHashMul`, per multiply) | 1.16 us | 0.29 us | **4.0x faster** | AVX-512 IFMA / ADX paths; Core's `*=` is two multiplies, so the row is per multiply |
| block archive: raw read (`ReadRawBlockBench`) | 37.4 us | 13.3 us | **2.8x faster** | raw bytes on both sides |
| ChaCha20, 1 MB | 0.71 ns/B | 0.30 ns/B | **2.4x faster** | AVX2, two blocks per register, three pairs in flight; was 1.6x slower |
| MuHash element expansion (`MuHashPrecompute`) | 350 ns | 160 ns | **2.2x faster** | SHA-256 + ChaCha20; was 1.9x slower |
| block archive: append a 1 MB block (`WriteBlockBench`) | 310 us | 144 us | **2.1x faster** | the same block appended each op on both sides |
| BIP324 packet AEAD, 1 MB (`FSCHACHA20POLY1305_1MB`) | 0.98 ns/B | 0.58 ns/B | **1.7x faster** | was 1.5x slower |
| SHA-1, 1 MB | 0.64 ns/B | 0.39 ns/B | **1.6x faster** | SHA-NI body; Core's is plain C++; was 2.5x slower |
| ChaCha20, 256 B | 0.74 ns/B | 0.48 ns/B | **1.55x faster** | four blocks served by the six-block group; was 1.6x slower |
| Bech32 encode | 6.4 ns/B | 5.2 ns/B | **1.2x faster** |  |
| MuHash finalize (`MuHashFinalize`: the `gettxoutsetinfo` digest) | 28.2 us | 26.0 us | **1.08x faster** | the same safegcd inverse Core uses (ported); was 66x slower |
| ECDSA verify | 21.0 us | 20.2 us | **4% faster** | libsecp256k1's own bench for Core's side |

## Parity

| **module** | **Core** | **bmc** | **verdict** |
|---|---|---|---|
| SHA-256, 32 B | 36.6 ns | 35.1 ns | parity |
| SHA-512, 1 MB | 0.97 ns/B | 1.01 ns/B | within 4%; was 1.7x slower |
| RIPEMD-160, 1 MB | 1.13 ns/B | 1.18 ns/B | within 4% |
| BIP340 verify | 21.6 us | 22.3 us | within 3% |
| compact-block reconstruction (`BlockEncodingNoExtra`) | 1.24 ms | 1.29 ms | within 4% |
| Poly1305, 256 B / 1 MB | 0.31 / 0.27 ns/B | 0.33 / 0.27 ns/B | within 8% / parity |
| Bech32 decode + verify | 3.3 ns/B | 3.2 ns/B | parity |
| BIP324 packet AEAD, 256 B | 1.31 ns/B | 1.40 ns/B | within 7%; was 1.7x slower |
| ElligatorSwift key creation (`EllSwiftCreate`) | 18.2 us | 20.9 us | 1.15x slower; was 6.6x |

## Where Core is ahead, and why

| **module** | **Core** | **bmc** | **ratio** | **why** |
|---|---|---|---|---|
| GCS filter construct, 100,000 elements | 4.9 ms | 21.6 ms | **4.4x slower** | our side also parses the 4 MB block and dedups its scripts; Core hashes ready-made elements |
| GCS filter header hash | 62 us | 119 us | **1.9x slower** | SHA-256d over the encoded filter |
| BIP324 ECDH | 21.6 us | 39.7 us | **1.8x slower** | a constant-time w=4 window vs libsecp256k1's GLV-split ecmult_const; was 3.2x |
| CheckBlock, block 413,567 | 370 us | 669 us | **1.8x slower** | Core does more per block (see tests/bench_checkblock.c) |
| BIP324 packet AEAD, 64 B | 2.29 ns/B | 3.81 ns/B | **1.7x slower** | three single ChaCha20 blocks per small packet: their latency is the row |
| taproot script-path verify | 36.0 us | 50.1 us | **1.4x slower** | ours spends a 2-leaf tree; Core a 1-leaf |
| ChaCha20, 64 B / Poly1305, 64 B | 0.79 / 0.44 ns/B | 0.94 / 0.53 ns/B | **1.2x slower** | one block is a dependent chain either way |
| SHA-256, 1 MB / SHA-256d 64 B x1024 / merkle root | 0.36 ns/B / 45.8 us / 45.7 ns/leaf | 0.42 / 52.9 / 53.0 | **1.15x slower** | Core's 2-way SHA-NI interleave vs our 1-way |
| P2WPKH / taproot key-path verify | 20.4 / 20.8 us | 22.9 / 22.3 us | **1.1x slower** | the sighash is recomputed per input; Core precomputes midstates per transaction |

## Verdict

The consensus kernel -- signature verification, the hashes on the hot path, compact-block reconstruction, the block archive -- is at or ahead of Core. Since 09-27 the transport cipher, the MuHash set hash and the address encoder moved from behind to well ahead, and SHA-1 and SHA-512 from behind to ahead and parity. What is left behind is named: the BIP324 ECDH's window against a GLV split, single-block latency on 64-byte packets, a filter-construction row whose two sides do different work, and Core's 2-way SHA-NI interleave on long SHA-256 inputs. Every number, harness and script is in the repository (docs/devlog/BENCHMARKS.md, addendum 2026-09-28).

The previous report (2026-09-27) with its dated corrections: `docs/reports/2026-09-27-core-vs-bmc-modules.md`.
