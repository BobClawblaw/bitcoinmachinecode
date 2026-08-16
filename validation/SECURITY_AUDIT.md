# Independent Security Audit — Bitcoin Machine Code ASM Crypto + Consensus Core

**Auditor scope:** sha256.asm, secp256k1_fe/point/scalar/ecdsa/schnorr/taproot.asm,
bitcoin_cons.asm, bitcoin_interp.asm, legacy/BIP143/BIP341 sighash, concurrent
store/UTXO/prune writers, and the P2P framer length-field handling.

**Date:** 2026-08-15
**Baseline:** `make test` green (62 binaries pass) before changes; green after fixes.
**Method:** line-by-line review of the AI-authored x86-64 assembly + the C
verification/signing layers, plus an in-engine reproduction of the top finding.

---

## Summary

The code is significantly *better* than typical AI-generated assembly on the
parsing hot path: `tx_parse`, `cons_verify`, the P2P framer, and the C sighash
builders all show careful absolute-pointer bounds discipline, and the field
arithmetic (carry chains, two-fold reduction, canonicalization) is correct and
validated against big-integer oracles. However, an independent audit confirms
the README's standing warning for **at least one concrete reason of the highest
severity**: the ECDSA **signing** path is not constant-time and will leak the
private key to any timing-observing attacker. A second, reproduced
memory-safety bug (a source out-of-bounds read in the legacy sighash builder)
is fixed in this pass.

Severity scale: CRITICAL / HIGH / MEDIUM / LOW / INFO.

---

## FINDING 1 — CRITICAL — Non-constant-time scalar multiplication in the signing path (private-key leak via timing)

**Files:** `asm/secp256k1_point.asm`, `asm/secp256k1_scalar.asm`, `asm/wallet_core.c`

### Description

Three assembly primitives execute a **branch per scalar bit**, and the signing
path feeds them secret values:

1. `point_scalar_mul` (`secp256k1_point.asm`) is an MSB→LSB **double-and-add**
   with `bt rax, rdx / jnc .loop` (branch on each bit of the scalar `k`) and a
   loop bound derived from the scalar's **highest set bit** (`bsr`). Both the
   number of loop iterations and the per-bit add/only-double selection depend on
   the scalar.

2. `sc_mul` (`secp256k1_scalar.asm`) is also double-and-add over 256 bits with a
   per-bit `bt / jnc` branch on the multiplicand.

3. `sc_add`/`sc_sub` branch on carry/borrow derived from the operand values
   (used inside `sc_mul`).

`wallet_core.c` calls these with **secret** data during `wallet_ecdsa_sign`:

```c
point_scalar_mul(R, G_AFF, k);   /* k = deterministic nonce (SECRET) */
sc_mul(rd, r, d);                /* d = private key (SECRET) */
sc_inv(k, k);
sc_mul(out_s, zrd, k);           /* k = nonce (SECRET) */
```

### Impact

A timing-observing attacker (local process, or remote across the signing RPC)
can recover the ECDSA nonce `k` from the `k*G` multiply, then trivially derive
the private key `d = (s*k - z)/r`. This is a total loss of the signing key. It
is the canonical "why the warning is justified" finding.

### Why verification alone is not the fix's excuse

`ecdsa_verify`/`schnorr_verify` only multiply **public** values, so the
non-constant-time code is epistemically safe on the *verify* path. The exposure
is specifically the wallet signing path, which is a stated feature of this node
(`wallet_sign_all_inputs`, `wallet_signrawtx_withkeys`, RPC sign, wallet_cli).

### Repro / proof

Static only (timing measurement not run here), but the branch-per-bit structure
is unambiguous in the assembly (see `point_scalar_mul` `.loop` and `sc_mul`
`.dbl_loop`).

### Fix

Land a constant-time scalar ladder / fixed window in both `point_scalar_mul`
and `sc_mul`, and make loop bounds data-independent (always iterate all 256
bits, or a fixed `ceil(256/w)` window count). Because this is a high-risk
rewrite of primitives that are already validated bit-exact, it is flagged for a
**dedicated follow-up task** rather than patched blind in this audit pass (see
"Remediation plan" below).

### Status — FIXED (scalar half 2026-08-15, point half 2026-08-16)

**Scalar half — FIXED.** Commit `6162ad8` made `sc_add`, `sc_sub`, `sc_mul`,
`sc_sqr`, `sc_inv` fully constant-time (no data-dependent branches): the carry
fold in `sc_add` and the borrow re-add in `sc_sub` use mask-selected arithmetic
instead of `jnc`, and the per-bit conditional add in `sc_mul` is now an
unconditional add + `bt`/`cmovnc` revert (fixed 256-iteration loop, branch-free).
This covers the secret scalar multiplications on the signing path:
`sc_mul(rd, r, d)` and `sc_mul(out_s, zrd, k)`.
Verified: `test_scalar` KAT (13 vectors) + `tests/stress_scalar.py` differential
vs a Python big-int oracle (20,000 iters, 0 failures) + signing suites
(`test_ecdsa`, `test_wallet`, `test_keys`, `test_scalarmul`, `test_taproot`).

**Point half — FIXED (2026-08-16).** Landed as a new companion module
`asm/secp256k1_point_ct.asm` exporting `point_scalar_mul_ct` (same ABI and same
12-limb Jacobian output as `point_scalar_mul`). The two **secret**-scalar call
sites now use it:

| call site | secret scalar | now calls |
|---|---|---|
| `wallet_core.c` `wallet_ecdsa_sign` | nonce `k` | `point_scalar_mul_ct` |
| `bitcoin_keys.asm` `scalar_to_pubkey` | private key | `point_scalar_mul_ct` |

`point_scalar_mul` itself is **deliberately left unchanged**. Its remaining
callers — `ecdsa_verify` (`u2*Q`), `schnorr_verify` (`s*G`, `e*P`) and the
taproot tweak (`t*G`) — multiply only **public** values, where variable-time is
both safe and roughly 4x faster. Since these sit on the consensus-hot block
validation path, converting them would cost throughput to protect nothing.
Leaving the function untouched also keeps its existing differential proof
(`tests/run_pointmul_diff.py`) valid byte-for-byte as a regression guard.

*Implementation.* Rather than retrofit cmov around the special cases of the
Jacobian adds, the CT module uses the **Renes–Costello–Batina complete addition
formulas for a=0** (eprint 2015/1060, Alg. 7 add / Alg. 9 double) in
homogeneous projective coordinates. These are exception-free by construction —
a single straight-line sequence is correct for the identity, for `P == Q` and
for `P == -Q` — so there is no special case to enumerate and therefore nothing
to branch on. This sidesteps the blocker recorded above (that
`point_add_mixed`/`point_add` mishandle an infinity operand) instead of
patching it. Conversion back to Jacobian happens once at the end via
`(X*Z, Y*Z^2, Z)`; both conventions send `Z=0` to `Z=0`, so infinity
round-trips and the canonical `(1,1,0)` is selected by cmov.

*Constant-time properties.* Exactly 256 iterations regardless of `k` (no `bsr`,
no bit-length dependence); one complete double plus one complete add every
iteration (double-and-add-always), committed or discarded by 12 `cmov`s rather
than a jump; and **no precomputed table**, hence no secret-indexed load and no
cache-timing channel. The underlying `fe_*` primitives are already branch-free
(see FINDING 3).

*Validation.* KATs (1G/2G/3G/kbig, `nG` → canonical infinity, `0G`); differential
vs the Python oracle via `tests/run_pointmul_ct_diff.py` (2,513 samples, 0
failures); cross-check against `point_scalar_mul` in affine over 2,000 random
scalars, 300 random non-`G` base points and `k = 1..512`, all exact; plus
`test_ecdsa`, `test_keys`, `test_add`, `test_addm`, `test_scalarmul` green, and
`point_scalar_mul`'s own differential re-run at 1,513 samples / 0 failures.
Measured timing (`tests/test_scalarmul_ct`), minimal vs full-width dense scalar:

```
variable-time : tiny 0.01 ms   dense 0.12 ms   ratio 15.9x
constant-time : tiny 0.23 ms   dense 0.23 ms   ratio  1.00x
```

> CORRECTION TO THE DESCRIPTION ABOVE: the "Description" section of this finding
> describes an MSB→LSB `bt`/`jnc` double-and-add. That code was already
> superseded by a w=4 windowed ladder before this fix. The finding was still
> valid, but the actual leaks at the time of the fix were (a) the `bsr`-derived
> loop bound, (b) `jz .wskip` skipping zero window digits, and (c) the
> secret-indexed `TAB[digit]` address — a cache channel the original write-up
> did not identify.

> NOTE: this finding does **not** affect consensus-correctness of the node
> (verification is functionally correct and differentially tested).

---

## FINDING 2 — HIGH — Legacy sighash builder: out-of-bounds **source** read (reproduced SIGSEGV) — **FIXED**

**File:** `asm/bitcoin_sighash.asm`

### Description

In the input walk, after reading the raw scriptSig length with `parse_varint`,
the source cursor is advanced past the script bytes **without a bounds check**:

```asm
call  parse_varint    ; rax = len
mov   rcx, rax
add   rdi, rcx        ; <-- no check that rdi <= txend
mov   [rbp-0x60], rdi
```

The subsequent raw reads (prevout+index, sequence) via the *unchecked*
`copy_bytes` then read past the end of the tx buffer. `sighash_all` is reached
with **untrusted network tx bytes** from `verify_p2pkh` / multisig verification
*before* the tx is run through the bounds-checked `tx_parse`, so a hostile
scriptSig length field that overruns the tx is reachable.

### Repro (reproduced)

Crafted a 1-in tx whose `scriptSig` length varint claims 200 bytes while the tx
is only ~44 bytes. Pre-fix: `sighash_all` **SEGFAULTED** (exit 139). After the
fix it returns 0 (rejects).

### Fix (landed)

Added a source-cursor bounds check after the scriptSig skip:

```asm
add   rdi, rcx
cmp   rdi, [rbp-0x68]   ; txend
ja    .fail
```

Regression test `tests/test_sighash_oob.c` added to the suite; `make test`
green.

---

## FINDING 2b — MEDIUM — Legacy sighash builder: preimage **write** cap on the signing-script copy is caller-dependent — **FIXED**

**File:** `asm/bitcoin_sighash.asm` (`.write_script` path)

The preimage write path for the supplied signing script does
`write_varint` + `copy_bytes(script_len)` with **no check against the preimage
cap** (`[rbp-0x58]` = preimg+cap). The fixed 4-byte version/hashtype writes are
checked, but the script copy is not. In the current callers the `script` is the
prevout scriptPubKey (≤ consensus 10 kB) and the preimage buffer is 4 kB
(wallet) or an interpreter-provided `work` buffer — so a buffer overflow needs
`script_len` near/above `cap`, which the current call graph does not obviously
produce. Still an internal invariant violation; a defensive cap check should be
added (cheap, recommended as a follow-up with #2).

### Fix (landed)

A defensive cap check was added immediately after the script `copy_bytes`, so a
script copy that would push the preimage cursor past the supplied end
(`[rbp-0x58]`) is rejected with `.fail` exactly like the hashtype write:

```asm
cmp   rdi, [rbp-0x58]   ; reject if the resulting cursor passes the preimage end
ja    .fail
```

This closes the invariant without altering valid-input behavior (current
preimage buffers are far larger than any reachable script). Verified:
`sighash` / `sighash_oob` / `p2pkh` / `script` / `multisig` suites green.

---

## FINDING 3 — MEDIUM (design / hardening) — `fe_sub` branches on borrow; point double-and-add branches on coordinate equality

**Files:** `asm/secp256k1_fe.asm` (`fe_sub`), `asm/secp256k1_point.asm`
(`point_add*` equal/opposite branches)

`fe_sub` uses a timing-dependent `jnc` on the borrow, and `point_add_mixed` /
`point_add` branch on `U2==X1` / `S2==Y1` to select double-vs-add-vs-infinity.
These are acceptable for **verification** (all values public). They are only a
concern if a future coding path runs secret scalars through them — which is
already foreclosed by FINDING 1's remediation (constant-time ladder). No action
beyond noting the hygiene (prefer `cmov` in any future secret path).

### Status — FIXED (field ops 2026-08-15; point-add branches resolved by avoidance 2026-08-16)

**Field arithmetic — FIXED.** Commit `6e19041` made `fe_add` and `fe_sub`
branch-free (constant-time): the `fe_sub` borrow re-add of `p` and the `fe_add`
257th-carry fold now use mask-selected arithmetic instead of `jnc`. `fe_mul`
was already branch-free (its only `jnz` is a fixed 8-iteration zeroing loop,
data-independent; the reduction uses `cmovnc`). No data-dependent branches
remain in the field layer; `fe_inv` still branches only on the fixed Fermat
exponent (constant-time w.r.t. the input). Verified: `test_fe` KAT (40) +
`tests/run_fe_diff.py` differential vs a Python big-int oracle (8,000 samples,
0 failures) + all dependent point/ecdsa/wallet/key/taproot/sighash suites green
+ `point_scalar_mul` differential (1,213 samples, 0 failures).

**Point-addition branches — RESOLVED BY AVOIDANCE (2026-08-16).** The
equal/opposite/infinity branches in `point_add` / `point_add_mixed` still exist
and are **not** being removed. They are now reachable only from
`point_scalar_mul`, which after the FINDING 1 fix is called exclusively with
**public** scalars (`ecdsa_verify`, `schnorr_verify`, taproot tweak), so the
branches leak nothing secret and the variable-time speed is wanted on the
consensus-hot path.

Secret-scalar work no longer goes through them at all: `point_scalar_mul_ct`
(`asm/secp256k1_point_ct.asm`) uses complete, exception-free RCB formulas that
have no special cases to branch on. See FINDING 1 status.

Residual risk accepted: if a **new** caller ever passes a secret scalar to
`point_scalar_mul`, this becomes live again. Guard: any new secret-scalar call
site must use `point_scalar_mul_ct`.

---

## Areas reviewed and found sound

**Field/scalar reduction (`secp256k1_fe.asm`, `secp256k1_scalar.asm`).**
`fe_add`/`fe_sub` canonicalize with a single conditional subtract after a
correct carry fold (`2^256 ≡ C mod p`); `fe_mul` does a standard schoolbook
product + two-fold reduction + one conditional subtract, as validated against a
big-integer oracle. `fe_inv`/`sc_inv` branch only on the **fixed** Fermat
exponent (constant-time w.r.t. the input). No carry/branch bug found.

**`sha256.asm`.** Round schedule, state fold, and FIPS-180-4 padding (0x80,
zero-fill, 64-bit BE bit-length, extra-block path for `len ≥ 56`) are correct;
digest emitted big-endian. Non-executable stack marker present.

**`bitcoin_cons.asm`.** Tx-count CompactSize (all four widths) bounds-checked
against the *absolute* end pointer; each tx re-parsed in bounds; walked count
must equal the wire count; merkle root verified against the header. Solid.

**P2P framer (`bitcoin_net.asm`).** `p2p_read` reads at most `min(announced,
cap)` payload bytes into the caller buffer, reports the announced length,
drains excess through a fixed 64-byte scratch, and returns `-2` on truncation.
Header fixed 24 bytes with magic check; command fixed 12 bytes; `p2p_frame`
caps command at 12. No length-field overflow.

**BIP143 / BIP341 sighash (`bitcoin_segwit.c`, `bitcoin_taproot_sighash.c`).**
Every preimage append is bounds-checked against `pend`/`cap` before `memcpy`.

**Concurrent store writers (`bitcoin_store.asm`).** `store_append_shared`
serializes appends under `flock(LOCK_EX)`, seeks to true end under the lock,
writes frame+payload+48-byte index at its own slot. Pruner uses `ftruncate`
after compaction. No obvious data-race in the shared append path.

**`bitcoin_tx.asm` (`tx_parse`, `tx_txid`).** Every field advance (varints of
all widths, input/output/witness walk, locktime) is bounds-checked
(`ja .fail`) against the absolute end; segwit marker/flag detected; witness
correctly skipped for unwitnessed txid. No overflow found.

---

## Remediation plan (recommended follow-up cards)

1. **Constant-time `point_scalar_mul`** (FINDING 1, point half) — **DONE**
   (`asm/secp256k1_point_ct.asm`, `point_scalar_mul_ct`; card `t_08b49753`).
   Shipped as a separate CT routine on the two secret-scalar call sites rather
   than a rewrite of `point_scalar_mul`, which stays variable-time for the
   public-scalar verification path. NOTE for future cards: the acceptance gate
   is **affine** equality against the Python oracle — `tests/stress_pointmul.c`
   calls `toaff()` before printing, so Jacobian/projective `Z` is never
   compared and any mathematically correct implementation passes. The earlier
   framing of this card as requiring *bit-exact Jacobian* output was wrong and
   describes an unsatisfiable constraint.
2. **Defensive cap check on the sighash script copy** (findings 2b) — **DONE**
   (commit `83f2019`, documented in FINDING 2b above).
3. Re-run the full differential-consensus harness + `make test` after any
   crypto rewrite.

## Changes landed in this pass

- `asm/bitcoin_sighash.asm` — source-cursor bounds check after scriptSig skip
  (FINDING 2); preimage-write cap check (FINDING 2b).
- `asm/secp256k1_scalar.asm` — constant-time `sc_add`/`sc_sub`/`sc_mul`/`sc_sqr`/
  `sc_inv` (FINDING 1, scalar half; commit `6162ad8`).
- `asm/secp256k1_point_ct.asm` (NEW) — constant-time `point_scalar_mul_ct` via
  Renes-Costello-Batina complete formulas + fixed 256-iteration
  double-and-add-always ladder (FINDING 1, point half). Callers repointed:
  `wallet_core.c` (`wallet_ecdsa_sign`), `bitcoin_keys.asm` (`scalar_to_pubkey`).
  Harnesses: `tests/test_scalarmul_ct.c`, `tests/stress_pointmul_ct.c`,
  `tests/run_pointmul_ct_diff.py`.
- `asm/secp256k1_fe.asm` — constant-time (branch-free) `fe_add`/`fe_sub`
  (FINDING 3, field-op half; commit `6e19041`); `fe_mul` verified branch-free.
- `asm/tests/test_sighash_oob.c` — regression repro (new).
- `asm/tests/stress_pointmul.py` + `.c`, `run_pointmul_diff.py` — differential
  harness for `point_scalar_mul` (validates the pending point-half ladder).
- `asm/tests/run_fe_diff.py` + `stress_fe.c` — differential harness for
  `fe_add`/`fe_sub`/`fe_mul` (locks FINDING 3 bit-exactness).
- `asm/Makefile` — wire `tests/test_sighash_oob` into build/test/clean.

`make test` green for the crypto/signing suites; the only outstanding build
gap is the in-progress P2SH card's `tests/test_verify_p2sh.c` (worker WIP).

**Bottom line:** the node's *verification & consensus* core is functionally
sound and has been hardened substantially. The **signing** crypto is now
constant-time on the scalar half (key/nonce low-level mults) and the field layer
is branch-free, but the `k*G` point multiply (`point_scalar_mul`) and the
point-addition disagree/infinity branches are still not — so it must not be used
with real private keys until the point half of FINDING 1 lands. The README
warning should remain until then.
