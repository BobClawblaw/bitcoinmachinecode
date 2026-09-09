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

## 2026-09-09 — bitcoin_tx native: bounds fuzz 55M calls + x86-diff byte-identical

- port/osx/bitcoin_tx.S (tx_parse + tx_txid): test_tx 20/20, test_txtxid,
  test_tx_bounds_fuzz 55,232,133 guarded calls 0 faults, 501-vector
  differential byte-identical vs x86 objects on .242 (dtx.c/gen_tx_vecs.py).
- NEW DARWIN PITFALL: `ldp x27,x27,[sp],#16` (Rt==Rt2) is CONSTRAINED
  UNPREDICTABLE — SIGILL on Apple Silicon. Never pair-restore the same
  register twice; pop odd slots with ldr + explicit sp adjust.
- Delegation note: parallel subagent waves time out on this provider (5-12
  API calls in 600s). Porting proceeds serially, coordinator-owned.

## 2026-09-09 — secp256k1_scalar native: 2,306-vector x86-diff byte-identical
port/osx/secp256k1_scalar.S: sc_add/sc_sub/sc_sqr/sc_inv/sc_inv_var/
sc_mul_512/sc_split_lambda native AArch64. sc_mul + sc_mul_512 currently
route to proven C twins (port/osx/sc_mul_c.c, sc_mul_512_c.c) — the AArch64
asm fold drops a DELTA on dense products; root-cause later, C twins are the
correctness baseline. Gates: test_scalar 12/12, test_glv_split 3 campaigns
(1,001,018 + 1,000,000) 0 failures, cross-arch dsl diff vs .242 byte-identical
(800 mul_512/split + 1500 mul/add/sub vectors). Three port bugs the gates
caught: (1) add/adc vs adds/adcs — AArch64 add/adc do NOT write NZCV, every
carry chain needs adds/adcs; (2) sc_mul_512/split frames were aliased over
active locals until a real `sub sp, sp, #N` was added (same class as the
tx epilogue leak); (3) my MULACC expansion dropped the hi term into the
carry chain (cur[k+1] += hi + c, then propagate) — the x86 macro did the
same math but the ARM rewrite skipped it. Commit 131e5171 on osx/p1-scalar,
merged to bmc_osx (2e7b1f07).

## 2026-09-09 — bitcoin_hmac native + sha512.S caller-frame corruption fix
port/osx/bitcoin_hmac.S: hmac_sha512 native (CRY-4 frame-local buffers,
WAL-3 zeroise).  The 400-vector differential vs .242 exposed a REAL bug in
port/osx/sha512.S: the 128-bit BE length field zero loop ran with x13 =
carrier+120 and offsets 112..127, writing carrier[232..247] — outside the
sha512_full frame.  When rem>=112 (two-block pad path) the carrier is pad1
at its_sp+0xc0, so the stray writes hit the CALLER's frame at caller_sp+8..
+23, zeroing hmac's kpad[8..23] and corrupting any HMAC with keylen>=16 and
msglen in 112..127/255 (symptom: only some vectors fail, key-length
dependent).  Fix: offsets -8..7 from x13.  sha512_NIST 4/4 re-verified;
400/400 byte-identical after the fix.  Commit da3f4b6d.

## 2026-09-09 — bitcoin_bip39 native; bitcoin_aes already pure C
port/osx/bitcoin_bip39.S: all four ABI functions native + wordlist_gnu.inc
(the 2048x9 table in __TEXT,__const — __cstring gets tail-merged by the
Darwin linker and silently shifts fixed-width records).  Two port bugs the
gate caught: (1) find_word_index clobbered x22/x23 (unsaved callee-saved in
that helper) destroying the caller's token pointer after the first word —
every mnemonic invalid; (2) the parse tail (entropy extract + checksum
compare) initially fell through to the epilogue returning garbage.  Gate:
test_bip39 24-vector oracle round + WAL-11 canary + negatives, ALL PASS,
same harness green on x86.  bitcoin_aes: pure C upstream, test_aes passes
natively unchanged.  Commits 0c259e99.
