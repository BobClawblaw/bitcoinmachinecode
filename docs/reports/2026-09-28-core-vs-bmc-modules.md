# Bitcoin Machine Code vs Bitcoin Core, module by module — the 2026-09-28 rerun

2026-09-28, 04:08Z. Bitcoin Machine Code (an all-assembly x86-64 node, https://github.com/BobClawblaw/bitcoinmachinecode) measured against Bitcoin Core's own benchmark suite (src/bench, v31.99.0-67efced1fc83), on the same box, the same core, the same inputs -- the 2026-09-27 report rerun in full after one day of work on every gap it named: the MuHash inverse (Core's safegcd ported), ElligatorSwift (constant-time comb, window and GLV multiplies, a Jacobi square test, an encoder that draws its branch at random as libsecp256k1 does -- the fixed order was biased), ChaCha20 in AVX2, SHA-1 by SHA-NI, SHA-512 unrolled, Base58Check by 64-bit limbs, SHA-256 hashed in place with a multi-block SHA-NI run, the block filter builder rebuilt, every private-key multiply on a cmov-scanned comb.

**How it was measured.** Core's numbers come from Core's bench_bitcoin (nanobench, -min-time=1000, the minimum over 3 processes), built RelWithDebInfo as Core's own default; the secp256k1 rows from libsecp256k1's own bench, Core's vendored copy with Core's shipped config. Ours come from harnesses that mirror each Core benchmark's loop -- the same work per iteration, the same sizes and element counts -- as thread CPU time, the minimum of 15 rounds. Both sides pinned to one core (taskset -c 25) of an AMD Ryzen 9 9950X3D with the production node and a Core oracle running (load average 3.4 on 32 threads); Core's timed loops showed no preemption (cpu/wall 0.986-1.000). Where the two sides do not do the same work, the row says so; every row here is per the same unit on both sides.

## Where this node is ahead

| **module** | **Core** | **bmc** | **ratio** | **note** |
|---|---|---|---|---|
| Base58Check encode (`Base58CheckEncode`) | 47.2 ns/B | 6.0 ns/B | **7.9x faster** | 64-bit limbs divided by 58^10; 3.2x slower on 09-27 |
| MuHash insert of one coin (`MuHash`) | 2.65 us | 0.45 us | **5.9x faster** | expand + one multiply; Core's op is expand + two multiplies |
| MuHash 3072-bit multiply (`MuHashMul`, per multiply) | 1.15 us | 0.29 us | **4.0x faster** | AVX-512 IFMA / ADX; Core's `*=` is two multiplies, so the row is per multiply |
| block archive: append a 1 MB block (`WriteBlockBench`) | 418 us | 146 us | **2.9x faster** | the same block appended each op on both sides |
| block archive: raw read (`ReadRawBlockBench`) | 36.5 us | 13.3 us | **2.7x faster** | raw bytes on both sides |
| ChaCha20, 1 MB | 0.71 ns/B | 0.30 ns/B | **2.4x faster** | AVX2, two blocks per register, three pairs in flight; 1.6x slower on 09-27 |
| MuHash element expansion (`MuHashPrecompute`) | 344 ns | 160 ns | **2.1x faster** | SHA-256 + ChaCha20; 1.9x slower on 09-27 |
| SHA-1, 1 MB | 0.64 ns/B | 0.37 ns/B | **1.7x faster** | SHA-NI body; Core's is plain C++; 2.5x slower on 09-27 |
| BIP324 packet AEAD, 1 MB (`FSCHACHA20POLY1305_1MB`) | 0.97 ns/B | 0.58 ns/B | **1.7x faster** | 1.5x slower on 09-27 |
| Bech32 encode / decode+verify | 6.4 / 3.3 ns/B | 4.2 / 2.6 ns/B | **1.5x / 1.3x faster** |  |
| ChaCha20, 256 B | 0.72 ns/B | 0.47 ns/B | **1.5x faster** | four blocks served by the six-block group |
| GCS filter construct, 100,000 elements (`GCSFilterConstruct`) | 4.86 ms | 3.76 ms | **1.3x faster** | the element-list builder on both sides; 4.4x slower in the morning's row, which had included our block parse |
| MuHash finalize (`MuHashFinalize`: the `gettxoutsetinfo` digest) | 28.1 us | 25.5 us | **1.10x faster** | the same safegcd inverse Core uses (ported); 66x slower on 09-27 |
| ECDSA verify | 21.1 us | 20.4 us | **4% faster** | libsecp256k1's own bench for Core's side |
| SHA-256, 32 B | 36.4 ns | 34.7 ns | **5% faster** |  |

## Parity

| **module** | **Core** | **bmc** | **verdict** |
|---|---|---|---|
| SHA-256, 1 MB | 0.357 ns/B | 0.361 ns/B | parity; 1.25x slower on 09-27 |
| SHA-512, 1 MB | 0.96 ns/B | 0.99 ns/B | within 4%; 1.7x slower on 09-27 |
| BIP340 verify | 21.4 us | 22.2 us | within 4% |
| RIPEMD-160, 1 MB | 1.12 ns/B | 1.17 ns/B | within 5% |
| compact-block reconstruction (`BlockEncodingNoExtra`) | 1.23 ms | 1.27 ms | within 3% |
| Poly1305, 1 MB | 0.26 ns/B | 0.27 ns/B | parity |
| BIP324 packet AEAD, 256 B | 1.31 ns/B | 1.36 ns/B | parity; 1.7x slower on 09-27 |
| ChaCha20, 64 B | 0.78 ns/B | 0.83 ns/B | within 7%; a single block is a dependent chain either way |
| script verify, P2TR key path / P2WPKH | 20.4 / 20.1 us | 22.2 / 22.7 us | 1.09x / 1.13x: the compressed-pubkey square root |
| ElligatorSwift key creation (`EllSwiftCreate`) | 18.0 us | 20.8 us | 1.16x; 6.6x slower on 09-27 |

## Where Core is ahead, and why

| **module** | **Core** | **bmc** | **ratio** | **why** |
|---|---|---|---|---|
| BIP324 ECDH | 21.0 us | 30.9 us | **1.5x slower** | a constant-time GLV window over complete formulas (84 ns a double, 117 an add) vs libsecp256k1's ecmult_const; 3.2x on 09-27 |
| BIP324 packet AEAD, 64 B | 2.26 ns/B | 3.65 ns/B | **1.6x slower** | three single ChaCha20 blocks per small packet: their latency is the row |
| CheckBlock, block 413,567 | 367 us | 585 us | **1.6x slower** | Core does more per block (see tests/bench_checkblock.c); 1.8x in the morning |
| GCS filter header hash | 62 us | 95 us | **1.5x slower** | SHA-256d over the 263 KB encoded filter plus the header link |
| taproot script-path verify | 36.0 us | 49.3 us | **1.4x slower** | ours spends a 2-leaf tree; Core a 1-leaf |
| Poly1305, 64 B | 0.44 ns/B | 0.54 ns/B | **1.2x slower** | per-packet setup |
| SHA-256d 64 B x1024 / merkle root | 45.6 us / 45.1 ns/leaf | 52.5 us / 52.9 ns/leaf | **1.15x slower** | Core's schedule ordering; a two-lane SHA-NI body was exact and no faster than two calls |

## Verdict

The consensus kernel -- signature verification, the hashes on the hot path, compact-block reconstruction, the block archive -- is at or ahead of Core, and since 09-27 the transport cipher, the MuHash set hash, the address codecs, the block filter builder, SHA-1 and SHA-256 over long input moved from behind to ahead or parity. What is left is named with its cause: the ECDH's complete-formula point arithmetic against libsecp256k1's, single-block latency on 64-byte packets, the compressed-pubkey square root under the script rows, and Core's schedule ordering on SHA-256d and the merkle root. Every number, harness and script is in the repository (docs/devlog/BENCHMARKS.md, addendum 2026-09-28, second rerun).

The previous report (2026-09-27), with its dated corrections: `docs/reports/2026-09-27-core-vs-bmc-modules.md`. The morning-of-09-28 rerun that preceded this one is the first 2026-09-28 addendum in `docs/devlog/BENCHMARKS.md`.
