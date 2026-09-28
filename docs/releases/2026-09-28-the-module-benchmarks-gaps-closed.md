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
speed, and a Base58Check address encodes in 194 ns instead of 4.8 µs. Four
PRs, #329–#332, each gated and deployed as `deploy-20260928a`…`d`, each
confirmed on the next block against Core.

## The numbers, on the whole suite rerun (`bench-results/20260928T023002Z`)

| row | Core | this project | 09-27 → 09-28 |
|---|---:|---:|---|
| MuHash finalize | 28.2 µs | 26.0 µs | 66× behind → 1.08× ahead |
| MuHash insert | 2.66 µs | 0.45 µs | 2.8× → 6.0× ahead |
| EllSwift create | 18.2 µs | 20.9 µs | 6.6× behind → 1.15× |
| BIP324 ECDH | 21.6 µs | 39.7 µs | 3.2× behind → 1.84× |
| ChaCha20 1 MB / 256 B / 64 B | 0.71 / 0.74 / 0.79 ns/B | 0.30 / 0.48 / 0.94 | 1.6× behind → 2.4× / 1.55× ahead / 1.19× behind |
| packet AEAD 1 MB / 256 B / 64 B | 0.98 / 1.31 / 2.29 ns/B | 0.58 / 1.40 / 3.81 | 1.5–2× behind → 1.7× ahead / parity / 1.67× |
| SHA-1 1 MB | 0.64 ns/B | 0.39 ns/B | 2.5× behind → 1.6× ahead |
| SHA-512 1 MB | 0.97 ns/B | 1.01 ns/B | 1.7× behind → within 4% |
| Base58Check | 47.7 ns/B | 6.1 ns/B | 3.2× behind → 7.9× ahead |

Signature verification, the SHA-256 rows, RIPEMD-160, the merkle root,
compact-block reconstruction and the block archive are as on 09-27 (ECDSA
4% ahead of libsecp256k1, BIP340 within 3%, the archive 2–3× ahead).

## How (one line each; the commits say the rest)

- **#329** `daemon/num3072_inv.c`: Core's `Num3072::GetInverse` (safegcd) step for step. The inverse is level with Core's; the row's shape had said "ahead" and was corrected.
- **#330** `secp256k1_point_ct.asm`: a cmov-scanned comb for k·G (9 µs) and a w=4 window for k·P (33 µs) over the complete formulas; `fe_is_square_var` (Jacobi by safegcd); `fe_inv_var` and a constant ½ in the map; the encoder's branch from a hash pool.
- **#331** `chacha20_avx2.asm`: two blocks per ymm register, three pairs in flight, one ~112 ns group for three to six blocks; the C block, unrolled, keeps single blocks; the MuHash keystream dispatches to it.
- **#332** `sha1_block_shani` (sha1rnds4/nexte/msg1/msg2); SHA-512's 80 rounds written out with the state in registers; Base58Check by 64-bit limbs ÷ 58¹⁰.

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

## What is still behind

The ECDH window against libsecp256k1's GLV split (a constant-time lambda
split is the next piece), single-block latency on 64-byte packets, the
filter-construction row (different work on the two sides), Core's 2-way
SHA-NI on long SHA-256 inputs, and the per-input sighash (Core precomputes
midstates per transaction). All listed with sizes in `worklog/2026-09-28.md`.
