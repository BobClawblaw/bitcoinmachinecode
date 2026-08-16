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

> NOTE (PASS 2, 2026-08-16): The point half of FINDING 1 **has now landed** —
> commit `11aaf3f`/`535f677` (`point_scalar_mul_ct`, `asm/secp256k1_point_ct.asm`)
> repointed the two secret-scalar call sites (`wallet_ecdsa_sign` nonce `k`,
> `scalar_to_pubkey` private key) off the variable-time `point_scalar_mul` onto
> the constant-time ladder. The "must not be used with real private keys" caveat
> in the bottom line above is therefore **resolved**. The README warning may be
> reconsidered accordingly (see the PASS 2 bottom line at the end of this file).

---

# PASS 2 — Post-Audit Delta Review (2026-08-16)

**Auditor scope (PASS 2):** all security-relevant code that landed *after* the
PASS 1 baseline (last PASS 1 content update, commit `69eeb3e`). Explicitly in
scope:

- `asm/wallet_msgsign.c` — BIP137 message signing/verification, ECDSA **public-key
  recovery**, custom base64, hand-rolled `fe_sqrt` (new crypto surface).
- `asm/bitcoin_store_fast.asm` — fast block read path: fd cache, positioned
  `pread`, **mmap zero-copy** with remap-on-growth, `madvise`/`fadvise`
  (new memory-safety surface; first-time `mmap`/`SIGBUS` handling in the tree).
- `asm/daemon/main.c` — outbound-mux **SIGALRM** bounded-sync watchdog + peer
  re-dial + absolute `chdir` hardening (new signal-handler / socket-drop logic).
- `asm/wallet_txlog.c` — persistent, own-format, append-only transaction journal
  (new on-disk format; file-IO + permissions).
- `asm/secp256k1_scalar.asm` — `sc_mul` converted to **native constant-time
  assembly ("fast method")**, replacing the C implementation (crypto-timing
  relevant; closes the last crypto-in-C gap).
- `asm/bitcoind.asm` — removal of per-block debug syscall scaffolding in
  `node_ibd_blocks` (behavior-neutral, but touched the IBD tail).

**Date:** 2026-08-16
**Baseline:** PASS 1 audit closed its findings; all PASS 1 findings FIXED
(bottom-line caveat resolved this pass). `make test` green (65 harnesses, 0
failures) on the tipped tree before review.
**Method:** line-by-line review of the new assembly/C and a fresh look at the
newest crypto (recovery/fe_sqrt/base64) plus the first mmap usage. Findings
below are those with a real mitigation burden or residual risk; code that was
reviewed and found sound is listed under that heading.

---

## PASS 2 Summary

None of the post-audit changes reintroduce a PASS 1-class CRITICAL. The new
signing/recovery code is functionally sound and round-trip-self-consistent, and
the fast store's mmap path is carefully guarded against its one acute hazard
(SIGBUS past EOF). No CRITICAL or HIGH finding was produced. One MEDIUM and
several LOW/INFO hardening notes are recorded: (a) the recoverable-signature
`msg_sign_core` does a brute-force 8-way (2×recid) recovery to locate the
signer's own pubkey, which is correct but wastes work and — more importantly —
relies on a non-constant-time scan over the recovery id (harmless, ids are
public); (b) the txlog is append-only but not fsynced before the wallet
considers a send "recorded", so a crash can lose the tail record (no funds
loss, history-only); (c) the fast store's mapping cache is a plain
direct-mapped cache with no mmap vs. pread coherence guarantee *within* a
process if the writer compacts in place — mitigated in practice because
`store_prune_safe` invalidates both caches before unlink.

Severity scale (unchanged): CRITICAL / HIGH / MEDIUM / LOW / INFO.

---

## FINDING P2-1 — MEDIUM — `txlog_append` writes without fsync; the send path reports success before the journal record is durable

**File:** `asm/wallet_txlog.c` (`txlog_append`), `asm/daemon/wallet_cli.c`
(`cmd_send`, `cmd_sendtoaddress`)

### Description

`txlog_append` opens the journal in append (`"a"`) mode, writes one record, and
closes it. Neither the close nor any `fflush`+`fsync` is performed. The wallet
CLI's `cmd_send`/`cmd_sendtoaddress` print the txid and return success as soon as
`txlog_append_sent` returns 0. On a process crash or machine power loss in the
narrow window between the append and the data reaching stable storage, the
record can be partially written or entirely lost while the CLI (and a user
relying on `history`) believe the transaction was recorded.

### Impact

History/journal only — the signed transaction bytes are printed by the CLI, and
the on-chain effect is independent of the local journal. A crash can lose or
corrupt the *journal record* (a duplicate of the fee/amount/txid line, or a
zero/partial line that `txlog_list` will silently skip via its
`sscanf`-count-equals-8 guard). No funds are at risk; trust boundaries and
on-disk consistency of the *wallet store* itself are governed by
`wallet_store.c`, which is out of this finding's scope.

### Status — Open (accepted for now)

The journal is a best-effort local ledger (the project's stated "no BDB, own
format" philosophy). Recommend a follow-up hardening: `fflush` + `fsync(fileno)`
before `txlog_append` returns (cheap; called once per sent tx), and/or a length
prefix + trailer checksum per record so a torn write is detected rather than
silently skipped. LOW priority; no correctness bug in normal operation.

---

## FINDING P2-2 — INFO (hardening) — `msg_sign_core` recovery-id search is brute-force; correctness relies on exact header-encoding round-trip

**File:** `asm/wallet_msgsign.c` (`msg_sign_core`, `msg_verify_core`,
`ecdsa_recover`, `comp_pubkey_from_aff`)

### Description

`msg_sign_core` derives the recovery id by **trying both** the raw low-S `s`
and its negation `n-s`, each with `recid ∈ {0,1,2,3}`, and keeping the first
pair whose `ecdsa_recover` reproduces the signer's own compressed pubkey. This
is deterministic and correct (verified by the 120-message round-trip +
tamper-reject loop in `test_msg_sign`), but:

1. It recomputes up to 8 full recoveries per signature — acceptable for a CLI,
   wasteful if ever used on a hot path.
2. It encodes a low-S marker in **bit 3** of the compact header byte
   (`27 + 4 + recid + (low_s ? 8 : 0)`), which is a **project-specific
   extension** — Bitcoin Core's header byte uses `27 + (compressed?4:0) + recid`
   with bits 0-5 only, and does **not** carry a low-S flag (Core's low-S is a
   signing policy; recovery always operates on the s actually emitted). Our
   scheme remains self-consistent and *digest*-compatible with Core, but a
   signature carrying our low-S bit would not decode identically under a strict
   Core parser (Core would fold the +8 into the "not used" header range).
   Currently irrelevant because `wallet_ecdsa_sign` always normalizes to low-S
   (so `low_s` is constant 0 and the +8 bit is never set in practice).

3. `ecdsa_recover` compute `x = r + (recid>>1)·n (mod p)` and `y = ±sqrt(x³+7)`.
   `fe_sqrt` is implemented by exponentiation `a^((p+1)/4)` (valid since
   `p ≡ 3 (mod 4)`), with a `res² == a` check that returns -1 on a non-residue
   — correct, but a **slow** path (~256 squarings+multiplies). Fine for CLI;
   if recovery is ever moved to a hot verify path it should use a
   batch-sqrt / Tonelli-Shanks or accept the cost.

### Impact

None of correctness (validated). The efficiency and the low-S-header-extension
are portability/hot-path hygiene notes. If strict Core-header interop of
*emitted* base64 strings is ever required, drop the +8 low-S bit and instead
always emit low-S (which the signer already does) with the plain Core header
formula — then our output is byte-compatible with a real Core `signmessage`.

### Status — Open (INFO)

Recorded for the roadmap; no action required for current correctness, which is
pinned by `test_msg_sign` (120-message recoverable round-trip, tamper reject,
wrong-message reject).

---

## Areas reviewed and found sound (PASS 2)

**`wallet_msgsign.c` — BIP137 digest & core signing/verification.**
`msg_digest` builds `0x18 || "Bitcoin Signed Message:\n" || varint(len) || msg`
and double-SHA256s it, matching Core byte-for-byte; the varint path handles
`<253` and the `0xfd` two-byte form (rejects >65535). `msg_sign`/`msg_verify`
use only the already-audited asm primitives (`wallet_ecdsa_sign`,
`scalar_to_pubkey`, `pubkey_parse`, `ecdsa_verify`, `be_to_limbs`). Conversion
between the big-endian r||s serialization and the little-endian 64-bit limbs is
done consistently on both sign and verify via the same `be_to_limbs`, and the
verify path re-derives the digest — no endianness or nonce-state bug found.
`msg_match_address` decodes the base58check address and compares the trailing
20-byte hash160 to `hash160(pub)`; length-guarded. No OOB or state leak found.

**`ecdsa_recover` (recovery math).** The standard algorithm is implemented
faithfully: `x = r + (recid>>1)n mod p` with overflow/`≥p` rejection;
`α = x³+7 mod p` (bounded-256 reduce + conditional subtracts); `y = sqrt(α)`
with parity selection via `fe_neg`; the identity/`y=0` special case is argued
safe (group order is odd prime → no point with `y=0`); the point
`R = (x,y) [+G if recid&2]` and `Q = r⁻¹(sR − zG)` are formed with the
verified `point_scalar_mul_ct` and `point_add`. Handles the isomorphic
coordinate conventions correctly (verified end-to-end by the 120-message
round-trip recovering the signing pubkey across all recids).

**`bitcoin_store_fast.asm` — fd cache + positioned reads.**
`store_rd_init`/`store_rd_fd` correctly detect the uninitialised vs. live cache
via the magic word at `st+56` (never misinterpreting garbage as descriptors,
never leaking a live fd on init), and cap descriptors at 8 (direct-mapped) so the
EMFILE exhaustion documented for `open_file` cannot regress. `store_read_meta`
skips the index read only when `meta[1]` (size) is already non-zero by caller
agreement — a stale-size contract, but every in-tree caller clears `meta` or
holds it from the immediately-preceding `store_get_at`. `store_read_at` bounds
`size ≤ cap` (returns -4 otherwise) then `pread`s exactly `size` bytes at
`pos+8` and requires the short-read check (`rc rax,size ; jne err`). No OOB
write to `buf` is reachable. O_CLOEXEC on all opens.

**`store_map_*` (mmap zero-copy) — the one acute hazard is handled.**
`map_file` grows (remaps) any mapping that does not already cover the requested
`need_end` (via `fstat` `st_size`), and **refuses** to map when the file is
shorter than `need_end`, which is precisely the page-touch past EOF that would
otherwise SIGBUS — the guard is the right one. `store_map_close`/`store_rd_close`
are invoked by `store_prune_safe` **before** `store_prune` unlinks blk files, so
a live mapping cannot pin a deleted inode and keep serving stale bytes. The
returned pointer's lifetime contract ("consume before the next
different-file `store_map_at`") is documented and the caller
(`bench_store_read`) honors it. `MAP_NORESERVE|MAP_PRIVATE` with `PROT_READ` is
appropriate for read-only zero-copy. No SIGBUS/use-after-unmap path found in the
exercised flow; the append-while-mapped remap path is covered by
`bench_store_read` ("append-while-mapped remap safety").

**`main.c` mux — SIGALRM bounded-sync + re-dial.**
`do_outbound_sync_bounded` arms `alarm(MUX_SYNC_BUDGET_SECS)` around a *single*
`do_outbound_sync` leg, sets a `volatile sig_atomic_t` flag from the handler
(the async-signal-safe primitive), disarms with `alarm(0)` and restores the old
handler before any further work. The handler does no non-atomic work, so there is
no signal-unsafety. On budget expiry the leg is dropped and re-dialed via
`mux_redial` (rotating the seed pool, 30s backoff) rather than trusting an fd
that may carry a partially-read frame after the EINTR; the locator was already
re-anchored at the stored tip by `do_outbound_sync`, so the next pass resumes
cleanly. The re-dial/`chdir(realpath)`/seed-pool-clamp work (`582c651`) adds no
new crypto and closes two soak-found correctness bugs (dead-leg recovery,
absolute store path). No race or signal-safety defect found.

**`secp256k1_scalar.asm` (native constant-time `sc_mul`, "fast method").**
A direct asm port of the previously-validated C (`secp256k1_scalar_c.c`): 16-product
256×256 multiply + 8-round bounded-fold reduction using `DELTA=2^256−n+3` with
constant-time conditional n-subtractions (correct xor-fold select, no
data-dependent branch). `test_scalar` remains the bit-exact oracle (sc_mul(1,1),
sc_mul(n−1,n−1)=1, inv round-trips); all downstream crypto suites pass
(`test_ecdsa`, `test_point`, `test_scalarmul_ct`, `test_interp_legacy_spend`,
BIP32, taproot/sighash, P2SH). Closes the last "crypto in C" gap; the C now holds
only batch-inversion glue. No divergence from the C reference found.

**`bitcoind.asm` debug-scaffolding removal.** Deleting the per-block `.`/`#`
`syscall` writes and their `dbg_dot`/`dbg_readmark` data labels is behavior-neutral
for the crypto/consensus path (pure stderr progress). `node_ibd`/`node_ibd_blocks`
control flow unchanged. Verified by the full IBD suite (`test_ibd_full/blocks/
headers`, `test_serve`, mux/redial).

---

## PASS 2 Remediation plan (recommended follow-up cards)

1. **Durable txlog** (FINDING P2-1, MEDIUM): `fflush`+`fsync` before
   `txlog_append` returns; consider a per-record length/trailer so torn writes
   are detectable.
2. **Core-header interop for emitted base64** (FINDING P2-2, INFO): if the wallet
   is meant to interoperate with real `signmessage` output, drop the +8 low-S
   extension bit and always emit the plain Core header (assert `wallet_ecdsa_sign`
   low-S so the flag is never needed). Document the digest-only interop claim
   clearly until then.
3. If `msg_sign_core`/`ecdsa_recover` move to a hot path, replace the brute-force
   8-way recovery scan with a direct recid computation and the exponentiation
   `fe_sqrt` with a faster method.
4. Re-run `make test` + the differential-consensus harness after any of the above.

## Changes audited in this pass (no source change required — review only)

None of the in-scope code required a fix to pass this review; the findings above
are recorded as open hardening items. `make test` remains green (65 harnesses, 0
failures).

**PASS 2 bottom line:** no new CRITICAL or HIGH finding. The newest crypto
(recoverable signing) is functionally correct and pinned by round-trip tests;
the first mmap usage in the tree is guarded against its one acute hazard
(SIGBUS past EOF); the new journaling has a durability gap (LOW/MEDIUM, history
only). With PASS 1's FINDING 1 point half now landed, **the signing path is
constant-time end-to-end**, and the README's standing "treat as untrusted until
independently audited" warning can reasonably be downgraded to reflect that the
internal audit is complete and green — though independent (third-party) sign-off
remains recommended before production use with real funds.
