# The module benchmark's gaps closed: MuHash, ElligatorSwift, ChaCha20, SHA-1, SHA-512, Base58 (2026-09-28)

**What changed for an operator:** nothing in behaviour, and a good deal in
speed on paths that run per connection, per packet and per RPC call. The
`gettxoutsetinfo` digest's 3072-bit inverse takes 23 µs instead of 1.8 ms.
A BIP324 v2 handshake's key creation takes 21 µs instead of 108 and its ECDH
40 instead of 65, both still constant time; the encoder now draws its
ElligatorSwift branch at random, as libsecp256k1 does, so the 64 bytes on
the wire are uniform over the valid encodings (the fixed order was not).
Every v2 packet's ChaCha20 runs in AVX2 from two blocks up (a megabyte at
0.30 ns/byte against Core's 0.71), and the same routine expands MuHash
elements (a UTXO insert into the set hash 992 → 444 ns). SHA-1 (`OP_SHA1`)
runs on the SHA extensions, SHA-512 (BIP32/BIP39 derivation) at Core's
speed, and a Base58Check address encodes in 194 ns instead of 4.8 µs. Five
PRs, #329–#332 and #334, each gated and deployed as `deploy-20260928a`…`e`,
each confirmed on the next block against Core.

## The numbers, on the whole suite rerun (`bench-results/20260928T040807Z`, after #334)

| row | Core | this project | 09-27 → 09-28 |
|---|---:|---:|---|
| MuHash finalize | 28.2 µs | 26.0 µs | 66× behind → 1.08× ahead |
| MuHash insert | 2.66 µs | 0.45 µs | 2.8× → 6.0× ahead |
| EllSwift create | 18.2 µs | 20.9 µs | 6.6× behind → 1.15× |
| BIP324 ECDH | 21.0 µs | 30.9 µs | 3.2× behind → 1.47× |
| ChaCha20 1 MB / 256 B / 64 B | 0.71 / 0.72 / 0.78 ns/B | 0.30 / 0.47 / 0.83 | 1.6× behind → 2.4× / 1.5× ahead / within 7% |
| packet AEAD 1 MB / 256 B / 64 B | 0.97 / 1.31 / 2.26 ns/B | 0.58 / 1.36 / 3.65 | 1.5–2× behind → 1.7× ahead / parity / 1.6× |
| SHA-1 1 MB | 0.64 ns/B | 0.39 ns/B | 2.5× behind → 1.6× ahead |
| SHA-512 1 MB | 0.97 ns/B | 1.01 ns/B | 1.7× behind → within 4% |
| Base58Check | 47.2 ns/B | 6.0 ns/B | 3.2× behind → 7.9× ahead |
| SHA-256 1 MB | 0.357 ns/B | 0.361 ns/B | 1.25× behind → parity |
| GCS filter construct (100,000 elements) | 4.86 ms | 3.76 ms | 4.4× behind → 1.3× ahead (like-for-like row) |

Signature verification, the SHA-256 rows, RIPEMD-160, the merkle root,
compact-block reconstruction and the block archive are as on 09-27 (ECDSA
4% ahead of libsecp256k1, BIP340 within 3%, the archive 2–3× ahead).

## How (one line each; the commits say the rest)

- **#329** `daemon/num3072_inv.c`: Core's `Num3072::GetInverse` (safegcd) step for step. The inverse is level with Core's; the row's shape had said "ahead" and was corrected.
- **#330** `secp256k1_point_ct.asm`: a cmov-scanned comb for k·G (9 µs) and a w=4 window for k·P (33 µs) over the complete formulas; `fe_is_square_var` (Jacobi by safegcd); `fe_inv_var` and a constant ½ in the map; the encoder's branch from a hash pool.
- **#331** `chacha20_avx2.asm`: two blocks per ymm register, three pairs in flight, one ~112 ns group for three to six blocks; the C block, unrolled, keeps single blocks; the MuHash keystream dispatches to it.
- **#332** `sha1_block_shani` (sha1rnds4/nexte/msg1/msg2); SHA-512's 80 rounds written out with the state in registers; Base58Check by 64-bit limbs ÷ 58¹⁰.
- **#334** `point_scalar_mul_glv_ct` (the GLV endomorphism, constant time) for the ECDH; the comb at every private-key k·G (signing, key derivation, address generation: 52 → 9 µs); the ChaCha20 block inlined and XORed in place; `sha256_full` in place with `sha256_blocks_shani`; the block filter builder split into `bf_build_hashed` with a hash-table dedup, a radix sort and a word-buffered Golomb-Rice writer; the script rows in a sighash session.

## Proof

Each batch: a test that fails with the change reverted (two to four
mutations per routine, on scratch assemblies), the existing vector suites
on fresh binaries, the full gate (`MAKE_EXIT=0`, 401–402 pass markers),
`make link-check` clean; the deploy watched on the next block; the MuHash
digest checked live against Core after #329 and #331; v2 handshakes
observed completing after #330 and #331. New tests: `test_num3072_inv`
(2,536 checks), `test_pointmul_ct_variants` (2,646), `test_fe_sqrt`'s
Jacobi section (40,073), `test_chacha20`'s AVX2 section (3,000 cases),
`test_muhash` down both keystream bodies, `test_sha1` (both bodies),
`test_addr`'s 321 Python-generated Base58Check vectors.

## Also today, from the Mac branch (#336, #337)

Three shared fixes the Mac's testnet4 node found on 09-24 and that had never
reached main — the reorg apply never moving past the gap, a hole below the
archive tip re-fetched whatever `bmc.bootcatchup` says, the archive frame
check accepting the chain's magic — landed as #336 (`deploy-20260928f`); and
the Mac's PR for issues #294 (memtable sizing on the store's shape) and #304
(a cluster's false claim no longer runs the parallel downloader) as #337
(`deploy-20260928g`). Each cherry-picked, revert-checked on x86, `-Werror`,
gated; both issues closed.

## The IBD benchmark on the repaired link

Run 30 (main `1370d041`) synced to the tip in **4 h 54 m 30 s** with the
MuHash identical to Core's at 968,987 — on a link whose bad backhaul the
operator had just repaired, so the number compares to nothing measured
before it. Core v31.1 is being rerun on the same drive and link; the pair is
`docs/reports/2026-09-28-run30-vs-core.md` (the Core run was later cut short at 924,616 by a fault outside both nodes; the report says so).

## What is still behind

The ECDH's point arithmetic (complete formulas at 84/117 ns against
libsecp256k1's Jacobian complete addition), single-block latency on
64-byte packets, the compressed-pubkey square root under the script rows,
and Core's schedule ordering on SHA-256d and the merkle root. All listed
with sizes in `worklog/2026-09-28.md`.
