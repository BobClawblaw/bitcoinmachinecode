# OSX Port Roadmap — per-module status

Companion to `OSX_STRATEGY.md` (phases) and `OSX_PORT.md` (branch model).
A module is DONE only when its gate runs natively on this Mac: build +
repo-harness-equivalent run + differential verification (fuzz vs C twin /
Python oracle), with both code paths exercised where a dispatcher exists.

## Phase 0 — build bridge
- [x] Toolchain proof: Mach-O AArch64 object assembles under Apple clang
      21 (`cc -arch arm64`), links with repo C, runs natively. (2026-09-09)
- [x] Darwin-ism inventory for the .S layer: `_`-prefixed globals,
      `adrp+@PAGEOFF` (no GOT for same-file data), no `.type/.size/
      .note.GNU-stack`, x18/x28 forbidden (platform regs), sp 16-aligned
      at every `bl`, sysctl instead of EL0-trapping MRS probes. (2026-09-09)

## Phase 1 — pure-compute modules
- [x] sha256   -> port/osx/sha256.S   DONE 2026-09-09. Evidence:
      16-check osx gate 0 failures (KATs; boundary lens 55/56/57/63/64/119/120
      vs hashlib; 2x2000 random-length fuzz vs hashlib through BOTH bodies;
      5000 random state/block pairs scalar-vs-accelerator bit-identical;
      dispatcher/probe contract) + upstream CRY-6 harness 7/7 ok. Two Darwin
      bugs caught and fixed by the gate: (1) 8-byte x30 push in the probe
      left sp misaligned at a call site -> stp x29,x30; (2) test's own
      oracle first deadlocked on popen stdin (pipe never hit EOF) ->
      file-based batched oracle, and second: python -c cannot run a
      compound `while` statement on one line -> newline-separated helper.
- [x] bitcoin_hash -> port/osx/bitcoin_hash.S  DONE 2026-09-09. Evidence:
      upstream test_pow_check 13/13 native (guard-page clamp, VAL-11 range
      checks, powLimit arming) + 6,485-vector differential: Python oracle
      0 failures AND byte-identical output stream vs the x86 objects run on
      the 9950X3D reference (drivers: port/osx/tests/dvh.c +
      gen_bhash_vecs.py; ops sha256d/block_hash/diff_target/pow_check/
      sha256d64/merkle_root incl. odd counts + CVE-2012-2459 mutation flag).
      Contract notes: sha256d64 writes 32B per 64B input (in stride 64,
      out stride 32); diff_target stores BE with e3<0 or e3>31 -> all-zero
      target; merkle_root returns mutation flag 0/1 in w0.
- [x] sha512   -> port/osx/sha512.S      DONE 2026-09-09. Upstream
      test_sha512 unchanged: 4/4 FIPS vectors (incl. 1M-'a').
- [x] ripemd160 -> port/osx/ripemd160_twin.c  DONE 2026-09-09 as a C TWIN
      (clang -O2 AArch64, identical symbol/semantics; in-file doc records
      why: two asm translations diverged unlocatably). Gates: upstream
      test_ripemd160 23/23 + thread-stress 2.08M digests/8 threads, 0
      mismatches.
- [x] sha1    -> port/osx/sha1_twin.c   DONE 2026-09-09 as C twin.
      Gate 10/10 (FIPS KATs, padding edges vs hashlib, 1500-case fuzz).
      The C twin's own first cut had the length field memcpy'd LE -- the
      gate caught it; fixed to BE. (asm translations deferred.)
- [x] secp256k1_fe -> port/osx/fe_twin.c  DONE 2026-09-09 as C twin
      (constant-time; the x86 ADcx/ADox/MULX carry schedule has no AArch64
      equivalent, so the algorithm was reimplemented and differential-
      verified). Gates: upstream test_fe 40/40 (incl. algebraic identities
      a*inv(a)==1 over all vectors), test_fe_sqrt via crypto_fe_sqrt.c:
      ALL PASS. Two real bugs the gate caught in my first reduce: a
      2^32-vs-2^64 weight typo on acc[5] and a mis-weighted oh*C fold.
      NOTE: test_fe_repr/test_fe_inline need the x86-only fe_ref/fe_inline
      differential objects -- not portable; superseded by the vectors in
      test_fe plus the python big-int differential used during bring-up.
- [ ] secp256k1_point / _point_ct / _scalar / _scalar_c / _glv_c / _ecdsa
      (+ _taproot/_schnorr when upstream main carries them)
- [ ] bitcoin_hmac, aes (wallet_crypter deps), bip39
- [ ] bitcoin_tx (parser), bitcoin_p2p (codec), bitcoin_pubkey, bitcoin_keys
- [ ] bitcoin_sighash, bitcoin_bip143, bitcoin_bip341, bitcoin_bip342
- [ ] bitcoin_interp, bitcoin_scriptcodec, bitcoin_script_flags,
      bitcoin_script, bitcoin_multisig, bitcoin_cons
- [ ] bitcoin_chainwork, bitcoin_muhash (compute parts), bip32 family

## Phase 2 — syscall-carrying modules (Darwin syscall rework)
Heavy svc counts from the x86 .asm (measured 2026-09-09):
- [ ] bitcoin_utxo_lsm (65), bitcoin_store (51), bitcoin_utxo_store (31)
- [ ] bitcoin_idxscan (19), bitcoin_undo (17), bitcoin_store_fast (15)
- [ ] bitcoin_net (9: raw-socket syscalls, x86 arg4-in-R10 -> Darwin x3),
      bitcoin_headers (6), bitcoin_addrmgr (6), bitcoin_idx (5)
- [ ] bitcoin_cli (2), bitcoind (2), node_log (1), bitcoin_serve (1)
Darwin syscall deltas to apply per site: `svc #0x80`, nr in x16, args x0-x7,
error = negative errno in x0 with carry set (b.cs); fdatasync sites that
mean durability -> F_FULLFSYNC via fcntl; C shims (_bmcshim_*) only where no
Darwin twin exists, each shim noted here with its justification.

## Phase 3 — daemon
- [ ] link all port/osx objects + daemon C into bmcbitcoind (macOS)
- [ ] darwin_compat.h: prctl(PR_SET_PDEATHSIG)->fork-getppid poll,
      prctl(PR_GET_NAME)->pthread_getname_np (coinstats_index.c, log_ts.h)
- [ ] regtest IBD green, then signet/testnet4

## Phase 4 — parity
- [ ] differential run vs x86 reference (Linux container on this Mac)
- [ ] parity sweep summary "pass N" rows verified actually-run
      (ENGINEERING_RULES: link-check once ran 0 tests silently)

## Recurring Darwin .S pitfalls (found during p0, in this tree)
- sp must be 16-byte aligned AT EVERY bl SITE: an 8-byte lone x30 push
  misaligns it (the arm-port did this; guardmalloc kills it on macOS).
  Use `stp x29, x30, [sp,#-16]!` / `ldp x29, x30, [sp], #16`.
- x18 and x28 are platform-reserved on macOS — never temps (arm-port used
  w27/w28 freely; all temps moved to x9-x15/w4-w8 here).
- adrp+@PAGEOFF for same-file data; `:got:` relocs are ELF-only.
- MRS of ID_AA64ISAR0_EL1 traps at EL0 on macOS; feature probes go through
  sysctlbyname ("hw.optional.arm.FEAT_SHA256" etc.).
- Mach-O: every exported symbol is `_name`; no .type/.size/.note.GNU-stack;
  sections __TEXT,__text / __DATA,__data / __TEXT,__cstring.
- python -c one-liners can't carry a compound while-statement on a single
  line (syntax error at the second simple statement) — newline-join or
  ship a helper .py file next to the harness.
- FRAME-BASE ORDER: `sub sp, #locals` MUST come BEFORE `mov x20, sp`.
  The wrong order points the frame base at the save area and every
  +offset store lands in saved regs / the caller's frame -- the bug
  class behind the ripemd160 crash saga (silent main-frame corruption,
  process died at exit, pc=0 reports).
- CALLEE-SAVED REGS ARE OFF-LIMITS inside .L helpers called from a
  wrapper that parked pointers there (x25/x26/x27 as table bases
  clobbered the wrapper's out/in/len). Use dead arg regs (x3-x7).
- W-REGISTER TEMPS ZERO THE PARKED X-REG: writing w19 destroys x19's
  upper half. Never park a live pointer in a register whose w-half is a
  body temp (w19 was the X-load temp; out pointer moved to x6).
- C-symbol naming: C `___dumphere` becomes `____dumphere` at link time
  (extra `_`); asm `___dumphere` stays 3. When a debug symbol mismatches,
  count the underscores first.
- ESCAPE HATCH (used for ripemd160): a module may ship as a clang -O2 C
  twin with the identical symbol when asm translation resists localization
  -- rule #2 (prove the outcome) outranks assembly purity. Document
  in-file and revisit after the daemon runs.
