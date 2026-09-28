# Bitcoin Machine Code vs Bitcoin Core, module by module: 31 of Core's own benchmarks, side by side

2026-09-27. Bitcoin Machine Code (an all-assembly x86-64 node, <https://github.com/BobClawblaw/bitcoinmachinecode>) measured against Bitcoin Core's own benchmark suite (`src/bench`, v31.99.0-67efced1fc83), on the same box, the same core, the same inputs.

**How it was measured.** Core's numbers come from Core's `bench_bitcoin` (nanobench, `-min-time=1000`, the minimum over 3 processes), built RelWithDebInfo as Core's own default; the secp256k1 rows from libsecp256k1's own `bench`, Core's vendored copy with Core's shipped config. Our numbers come from harnesses that mirror the shape of each Core benchmark -- the same work per iteration, the same buffer sizes, the same element counts -- as thread CPU time, the minimum of 15 rounds. Both sides pinned to one core (`taskset -c 25`) of an AMD Ryzen 9 9950X3D. The production node and a Core oracle were running on the box at the time (load average 3.95 on 32 threads); Core's timed loops showed no preemption (cpu/wall 1.000 in every group). Where the two sides do not do the same work, the row says so.

## Where this node is ahead

| **module** | **Core** | **bmc** | **ratio** | **note** |
|---|---|---|---|---|
| MuHash 3072-bit modular multiply (`MuHashMul`) | 2.30 us | 0.30 us | **7.7x faster** | AVX-512 IFMA / ADX paths in `bitcoin_muhash.asm` |
| block archive: append a 1 MB block (`WriteBlockBench`) | 422 us | 143 us | **3.0x faster** | block 413,567, the same block appended each op on both sides |
| block archive: raw read of that block (`ReadRawBlockBench`) | 36.2 us | 13.1 us | **2.8x faster** | raw bytes on both sides |
| MuHash insert of one coin (`MuHash`) | 2.65 us | 0.94 us | **2.8x faster** | SHA-256 + ChaCha20 expansion + one multiply |
| Bech32 encode / decode+verify | 6.3 / 3.3 ns/byte | 4.3 / 2.8 ns/byte | **1.5x / 1.2x faster** | Core's decode bench never checks its result; ours decodes a valid address and verifies |
| ECDSA verify (`ecdsa_verify`) | 20.80 us | 20.02 us | **4% faster** | was 1.12x slower a month ago (safegcd scalar inverse, 2026-09-27) |
| SHA-256, 32 bytes | 36.5 ns | 34.3 ns | **6% faster** | Core: SHA-NI |

## Parity (within 5%)

| **module** | **Core** | **bmc** | **note** |
|---|---|---|---|
| compact-block reconstruction (`BlockEncodingNoExtra`) | 1.243 ms | 1.252 ms | a 3,000-short-id block against a 50,000-tx mempool holding none of them; short ids of every pool tx computed and matched |
| BIP340 Schnorr verify (`schnorrsig_verify`) | 21.10 us | 22.09 us | was 3.35x slower a month ago |
| RIPEMD-160, 1 MB | 1.118 ns/byte | 1.170 ns/byte |  |
| Poly1305, 256 B / 1 MB | 0.31 / 0.26 ns/byte | 0.33 / 0.26 ns/byte | 1.2x slower at 64 bytes |

## Where this node is behind

| **module** | **Core** | **bmc** | **ratio** | **why** |
|---|---|---|---|---|
| MuHash finalize (`MuHashFinalize`: the `gettxoutsetinfo` digest) | 28.0 us | 1,861 us | **66x slower** | our 3072-bit inverse is a Fermat exponentiation, 6,142 modular multiplies; Core's is a safegcd. Paid once per RPC call, never per block. |
| ElligatorSwift key creation (`EllSwiftCreate`) | 18.0 us | 119.8 us | **6.6x slower** | plain C over the asm field arithmetic; once per BIP324 connection |
| BIP324 ECDH | 21.0 us | 66.6 us | **3.2x slower** | same |
| GCS block filter construction, 100,000 elements (`GCSFilterConstruct`) | 5.14 ms | 21.07 ms | **4.1x slower** | same 100,000 unique 32-byte elements; ours arrive as the outputs of a 4 MB block that is parsed first, Core starts from the element set |
| Base58Check encode, 32 bytes | 47 ns/byte | 146 ns/byte | **3.1x slower** | address display only |
| SHA-1, 1 MB | 0.637 ns/byte | 1.581 ns/byte | **2.5x slower** | not on any hot path |
| CheckBlock, block 413,567 (1,557 tx) vs our `cons_verify` | 370 us | 647 us | **1.75x slower** | Core's CheckBlock does more per block (the harness header lists what) |
| hash of the encoded 100,000-element filter (`GCSBlockFilterGetHash`) | 61.6 us | 106.5 us | **1.7x slower** | Core's figure is 0.23 ns/byte over ~263 KB, faster than its own 1 MB SHA-256 row; not understood, reported as measured |
| SHA-512, 1 MB | 0.955 ns/byte | 1.627 ns/byte | **1.7x slower** |  |
| ChaCha20, 64 B / 256 B / 1 MB | 0.77 / 0.72 / 0.71 ns/byte | 1.18 / 1.18 / 1.15 ns/byte | **1.5-1.6x slower** | plain C; Core's is a 2-way SIMD implementation. Per byte on the v2 transport. |
| BIP324 AEAD packet (`FSCHACHA20POLY1305`), 64 B / 256 B / 1 MB | 2.24 / 1.30 / 0.97 ns/byte | 4.39 / 2.19 / 1.43 ns/byte | **1.5-2x slower** | the whole packet: length cipher + ChaCha20-Poly1305 with rekeying |
| script verification, P2TR script path (`VerifyScriptP2TR_ScriptPath`) | 35.8 us | 49.3 us | **1.38x slower** | our fixture spends a 2-leaf tree (one more merkle step) against Core's 1-leaf; plus the sighash point below |
| merkle root, 9,001 leaves | 45.0 ns/leaf | 53.0 ns/leaf | **1.18x slower** |  |
| SHA-256d, 64 B x 1024 (the merkle inner node) | 45.5 us | 52.4 us | **1.15x slower** |  |
| SHA-256, 1 MB | 0.359 ns/byte | 0.410 ns/byte | **1.14x slower** | Core: SHA-NI |
| script verification, P2WPKH / P2TR key path | 20.06 / 20.28 us | 22.52 / 22.26 us | **1.12x / 1.10x slower** | the signature verifications are level (above); Core precomputes the sighash midstates once per transaction, we hash per input |

## What is not in these tables, and why

Core's `src/bench` has 59 files. 31 benchmark names across 14 of them are paired above. The rest, with the reason:

- **No counterpart by design:** `addrman` (a different address-book structure), `ccoins_caching` (Core's coins cache is a different object from our memtable/LSM), `checkqueue` (our parallel verify is measured whole-block), `connectblock` (Core connects a synthetic block through its chainstate; ours is measured end to end by the IBD comparisons), `rollingbloom`, `txgraph`, `txorphanage`, `disconnected_transactions`, `checkblockindex`, `load_external`, `index_blockfilter`.
- **Measured at the RPC level instead** (the project's PERFORMANCE.md): `block_assemble` (`getblocktemplate`), `rpc_blockchain`, `rpc_mempool`.
- **C++ runtime and utility micro-benchmarks with no equivalent module:** `prevector`, `pool`, `lockedpool`, `random`, `logging`, `streams_findbyte`, `strencodings`, `parse_hex`, `util_time`, `hashpadding`, `obfuscation`, the harness itself.
- **Different wallet:** the seven `wallet_*` benches (Core's descriptor wallet vs a journal-backed seed wallet).
- **Candidates a day's harness each would pair:** `cluster_linearize`, `coin_selection`, `descriptors`, the three `mempool_*` eviction/stress benches, `peer_eviction`, `sign_transaction`.
- **Partly paired:** `blockencodings` (we keep no extra-transaction pool, so only the NoExtra variant), `gcs_filter` (construct and hash; we neither decode nor match filters), `base58` (Base58Check encode only), `readwriteblock` (raw read and write; Core's ReadBlock deserialises and checks too), `verify_script` (3 of 4; VerifyNestedIfScript is interpreter-only).


## What this says

The consensus kernel -- signature verification, the hashes on the hot path, block reconstruction from a compact block, the block archive, the UTXO set's MuHash -- is level with Core or ahead. The gaps are in the parts still written in C on this side (ElligatorSwift, ChaCha20, the AEAD), in code that runs once per RPC call (the MuHash finalize inverse), in the two hashes nothing hot uses (SHA-1, SHA-512), and in per-input sighash recomputation that Core amortises per transaction. Each gap is named with its cause so the next piece of assembly can be chosen by the number, not by guesswork.

## Reproducing

```
git clone https://github.com/BobClawblaw/bitcoinmachinecode
cd bitcoinmachinecode && scripts/bench_vs_core.sh          # tiers 1-2, including 2b
```

The script builds Core's `bench_bitcoin` out of tree on first use, builds our harnesses (`make bench-vs-core`), runs both sides pinned, and writes the raw CSVs, our harness output and the joined table into `bench-results/<timestamp>/`. The harness is `asm/tests/bench_core_modules.c`; every difference between a pair is stated in its file header and in the table's note column. The full write-up, including the classification above and the earlier tiers, is `docs/devlog/BENCHMARKS.md`, addendum 2026-09-27.
