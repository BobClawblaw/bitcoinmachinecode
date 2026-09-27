# Signature verification at libsecp256k1's speed, the full-verification sync, and a byte order (2026-09-27)

**What changed for an operator:** a mainnet sync with `assumevalid=0` — every
script of every block evaluated — has now been completed on this node: 8 h 0 m
to the tip at nice 10 on the benchmark box, with the UTXO set's per-height
digests equal to Bitcoin Core's at every height checked. Signature
verification runs at the speed of Core's own library: ECDSA 20.7 µs and BIP340
22.4 µs per verification on one core, against libsecp256k1's 21.0 and 22.0 on
the same core. The no-height `gettxoutsetinfo muhash` prints its digest in
Core's byte order again (it had been reversed on any node with the coinstats
index since 2026-09-25), the parity harness pins both sides to a height, and a
compact block whose bytes are not the block its header names is fetched in
full instead of marking the real block invalid. Seven PRs, #319–#325, all
landed as `--no-ff` merges and deployed as `deploy-20260927a`…`f`.

## The verification kernel (#319, #320)

The profile of the full-verification run put three quarters of the apply
process's CPU in the secp256k1 field and point arithmetic, which was already
level with libsecp256k1 (`fe_mul` 8.7 ns vs 9.3, mixed point add 96 ns vs
105). The two pieces that were not:

- **`sc_inv_var`**, ECDSA's `s^{-1}`, was a binary extended GCD at 3.55 µs
  per call, 16% of a verify. It is now the variable-time Bernstein–Yang
  safegcd (62 divsteps at a time on the low words, then the 2×2 transition
  applied to the full-width values), written from the paper as a C prototype
  checked against the Fermat inverse on a million inputs and then transcribed
  to `asm/safegcd_var.inc`, a macro instantiated for n and for p. 0.67 µs.
- **`lift_x`'s square root** in `pubkey_parse` was a bit-by-bit power over
  `(p+1)/4`, an exponent that is almost all ones: ~254 squarings and ~250
  multiplies, 4.1 µs. `fe_pow_sqrt` is `fe_inv`'s addition chain with a
  different tail, 253 squarings and 13 multiplies: 2.1 µs. Every compressed
  ECDSA key and every BIP340 key goes through it.
- BIP340's even-Y test needed one field inversion of a public value; it uses
  `fe_inv_var` (safegcd mod p, 0.7 µs) instead of the constant-time chain
  (2.1 µs). Secret-scalar paths keep the constant-time `sc_inv`/`fe_inv`.

| one core, min of rounds | before | after | libsecp256k1 |
|---|---|---|---|
| `sc_inv_var` | 3.55 µs | 0.67 µs | 0.68 µs |
| ECDSA verify | 21.9 µs | 20.7 µs | 21.0 µs |
| BIP340 verify | 25.9 µs | 22.4 µs | 22.0 µs |

Proof: `test_ecdsa_inverse` (1,001,023 inverses byte-identical to the Fermat
inverse, 113,315 verifies against a frozen reference), `test_fe_pow_sqrt`
(250,270 roots against the old power function), `test_fe_inv_var` (3,020,828
checks), each revert-checked by breaking a constant, a sign fix-up or a
reduction and watching it fail. A latent NASM trap was found on the way:
`%assign cl` in a macro shadowed the `cl` register for the rest of the file,
and the first build shifted by a constant instead of by `cl`.

## The full-verification sync, and its false FAIL (#321)

The run reached the tip at 08:25Z after 8 h 0 m with `bad=0`, then the harness
wrote `FAIL first-divergent-height=968807`. The set was never divergent:
recomputing H(num · den⁻¹) from `coinstats.dat`'s two accumulators gives one
SHA256 whose forward hex was our no-height answer and whose reversed hex was
Core's. The coinstats-index RPC adapter had reversed the digest "for
presentation" since 2026-08-26; when the walk path's forward printing was
fixed at the RPC layer on 2026-09-25, that line served the adapter too, and
every indexed node — production included — printed the no-height digest
backwards. `gettxoutsetinfo muhash <height|hash>` was right throughout. The
adapter now hands over the raw bytes like the other two readers; two tests
that had pinned the reversal now pin the raw order; and the harness's capstone
compares our per-height row with the oracle's and checks the live answer
against that row first, so a presentation defect is named as one.

## The rest

- **#322** — the Mac side's shared fixes, landed after x86 revert-checks:
  `addr_hist` was not thread-safe (real here: a thread per Esplora connection;
  ThreadSanitizer reports 22 races with the old file and none with the new),
  and the wallet CLI's passphrase prompt flushed an answer that arrived before
  echo was turned off (reproduced with strace's ioctl delay injection).
- **#323** — the block-mapping cache's magic word sat on read-fd cache slot 7,
  so a fill of that slot leaked every mapping the next map call held; a dword
  at `st+52` now.
- **#324** — the store CLI rejected uppercase hex (its uppercase branch was
  unreachable and fell through) and read blocks into 384-byte stack buffers;
  `multisig_verify` read past a malformed push.
- **#325** — from the Mac: a compact-block reconstruction is checked against
  the witness commitment before a caller sees it, and a witness mismatch at
  apply is MUTATED (dropped and re-fetched, no mark), never a rejection.
  Before this, a peer's witness-stripped coinbase could put the real block's
  hash in `invalid.dat`. Production was not hit; the Mac was, at 968,824.

Every code fix above was gated (`make -j8 test`, `MAKE_EXIT=0`), landed as a
`--no-ff` merge, and each deploy was confirmed on the next new block against
Core (0.0–2.8 s behind, hash equal). The Mac tree took main #316–#323 with a
note (`worklog/2026-09-27-note-for-osx.md` on `bmc_osx`).
