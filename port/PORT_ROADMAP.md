# AArch64 Native Port Roadmap — bitcoinmachinecode

Goal: run this project NATIVELY on an ARM64 host (this DGX Spark / GB10 box), by
rewriting the 63 x86-64 assembly modules (~45k LOC) in AArch64 assembly, one at
a time, each validated against the repo's own C oracles / test vectors /
differential fuzz. The daemon/ C is portable and links these modules, so once
the set of symbols the daemon uses exist as AArch64 objects, `bitcoind` links
and runs natively.

## Method (proven with sha256, this box)
1. Read the upstream `asm/<name>.asm` to capture the EXACT public ABI +
   semantics (SysV amd64 (rdi,rsi,rdx) -> AAPCS64 (x0,x1,x2); native
   little-endian words, `bswap` -> `rev` on byte-reverse points).
2. Write `port/arm64/<name>.S` exposing the identical symbols so the existing
   C harnesses / daemon link UNCHANGED.
3. Build native: `gcc -c <name>.S`, link the repo harness, run it natively.
4. Differential-fuzz against the C twin oracle (`*_c.c`) or Python (hashlib,
   big-int) over thousands of random vectors.
5. Only mark DONE when the repo's own suite + differential fuzz pass natively.

## Status
- [x] sha256  -> port/arm64/sha256.S      FIPS-180-4 harness PASS native; 882-case
      differential fuzz vs hashlib: 0 fail.   (2026-08-24)
- [x] sha1    -> port/arm64/sha1.S        FIPS vectors + 270-case fuzz vs hashlib: 0.
      (found + fixed halfword-swapped round constants via fuzz)
- [x] sha512  -> port/arm64/sha512.S      repo harness ALL PASS + 301-case fuzz: 0.
- [x] ripemd160-> port/arm64/ripemd160.S  repo harness ALL PASS (22 vectors incl.
      len-boundaries + 1M-a) + 440-case fuzz vs hashlib: 0. Step tables parsed
      programmatically from Bosselaers' canonical rmd160.c (left/right message
      order, rotations as 32-s, f-selectors, K constants); fixed the tuple-rotation
      bug (E,tt,B,C',D) verified in a Python model before the asm.
- [x] bitcoin_hash -> port/arm64/bitcoin_hash.S  sha256d fuzz vs hashlib; genesis
      block hash byte-exact; pow_check(genesis) PASS; merkle_root n=1..1000 vs
      Python reference: 0 fail. Built on ported sha256 (single source of truth).
- [x] secp256k1_fe (prime field)      -> port/arm64/secp256k1_fe.S   repo
      test_fe PASS native; 6400+ diff cases vs Python big-int (add/sub/mul/sqr/
      inv, incl. non-canonical/full-range for mul) 0 fail. Fixed 6 real bugs
      (see worklog): SUB-borrow flag, C-value-vs-address, carry-in-feedback in
      columns+fold, multi-bit column carries, T*slot operand swap in fe_inv,
      128Bit-overlap fold. (2026-08-24)
- [x] secp256k1_scalar (arith mod n)  -> port/arm64/secp256k1_scalar.S repo
      test_scalar PASS native; 900+ diff-fuzz vs Python big-int mod n: 0 fail.
      sc_add/sub/mul/sqr/inv. Fixed SCA_ADD carry-propagation bug (must
      `ldr; adcs x,x,xzr; str` -- `adcs x,xzr,xzr` overwrote limbs). (2026-08-24)
- [x] secp256k1_point (core group ops)   -> port/arm64/secp256k1_point.S
      repo test_point (2G) PASS native; ~83k-vector differential fuzz vs a
      fresh pure-Python Jacobian secp256k1 oracle over 7 seeds (point_double,
      point_add, point_add_mixed, +_zr incl. z-ratio, w=4 windowed
      point_scalar_mul; out-of-place AND in-place; degenerate shapes
      q==p/double-branch, opposite->inf, x==0/(0,0)): 0 failures.
      Fixed 3 real bugs: (1) scalar_mul held loop state in x19/x20/x22 which
      point_add/add_mixed/double CLOBBER (their own r/p/q/zr ptrs) -> heal in
      x23..x28 (never touched by leaf point_*/fe_*); (2) top-of-file
      `.note.GNU-stack` swallowed all code into the note section (moved to EOF);
      (3) interval branches `sub x28,#1; b.mi/b.pl` used plain `sub` (no NZCV)
      so they read STALE flags and over-ran the window loop -> `subs`. (2026-08-25)
    - [x] point_scalar_mul_fixed (k*G comb) -> same file; G_COMB_TABLE (converted
          dq->.quad) in .rodata; verified vs Python k*G across 7 seeds, 0 fail.
          R held in memory, only calls point_add_mixed -> no register-clobber
          hazard. (2026-08-25)
    - [x] secp256k1_scalar.S += sc_inv_var (binary xgcd, variable-time): 20k
          diff-fuzz vs Python pow(a,-1,n), 0 fail. Fixed u/v==1 check OR-ing the
          low limb (==1) so cbz never fired -> infinite loop; OR only upper 3.
    - [x] secp256k1_ecdsa.S (ecdsa_verify + ecdsa_x_eq_mod_n): ~34k-vector
          diff-fuzz vs an INDEPENDENT pure-Python ECDSA signer+verifier
          (valid sigs, corrupted z/r/s/Q, out-of-range r/s, r=0/s=0)
          8 seeds, 0 failures. GLV deferred: u2*Q via the verified
          point_scalar_mul (== the kill-switch fallback). (2026-08-25)
    - [ ] secp256k1_point_ct  (constant-time, for signing only -- NOT needed
          for IBD/verify; skip for now)
    - [ ] point_scalar_mul_glv / sc_split_lambda  (perf; deferred)
    - [x] secp256k1_schnorr (BIP340 verify) + bitcoin_pubkey (fe_pow+parse)
          -> port/arm64/secp256k1_schnorr.S + bitcoin_pubkey.S: pubkey_parse
          8005 vecs (comp+uncomp+non-QR reject) 0 fail; schnorr vs independent
          pure-Python BIP340 across seeds 0 fail + OFFICIAL test vector PASS.
          (2026-08-25)
==> secp verification core COMPLETE: ECDSA + BIP340 both native+verified. Next:
- [x] bitcoin_cons (cons_verify)      -> port/arm64/bitcoin_cons.S: block-level
      checks (pow_check, tx walk via tx_parse, coinbase n_in==1, txids via
      tx_txid, merkle_root == header root) using ONLY ported deps. Verified on
      genesis (1) + corrupt-root/wrong-count/bad-tx negatives (0); C
      reimplementation of the identical logic returns VALID too. Contains the
      real 1 MiB tx_txid rebuild buffer on the stack (subs-flags bug fixed).
      (2026-08-25)
- [x] legacy_sighash (SIGHASH legacy signature hash, core of checksig)
      -> port/arm64/bitcoin_sighash.S (copy_bytes/parse_varint/write_varint/
      script_op_len/script_push_encode/script_find_and_delete/legacy_locate_nout
      + legacy_sighash). 30k-vector differential fuzz vs independent Python Core-
      equivalent oracle (ALL/NONE/SINGLE x ANYONECANPAY, SINGLE out-of-range
      uint256(1) quirk, codeseparator stripping, malformed/truncated rejection):
      0 fail across 10 seeds. Fixed in-module bugs: 0xffff/0xffffffff out-of-range
      compare immediates; `cmp reg,[mem]` is invalid AArch64 (-> CMd load macro);
      `legacy_locate_nout` over-popped its frame; parse_varint failure propagated
      newptr=0 (-> sentinel -1 so downstream bounds checks fail); script_find_and_delete
      looped .fad_copy_unit->.fad_decode so post-first OP_CODESEPARATOR units were never
      stripped (-> .fad_mc); locate_nout now fully walks outputs+locktime so SINGLE
      quirk only fires on fully-valid txs. (2026-08-25)
- [x] bech32 / bech32m (BIP173/BIP350 codec) -> port/arm64/bech32.S (bech32_init/
      create_checksum/verify_checksum/convert_bits/encode/decode). Official
      BIP173+BIP350 test vectors PASS native (valid, cross-spec reject, invalid,
      real bc1q/bc1p encodes, convert_bits); 30k-vector differential fuzz across
      12 seeds vs independent Python reference (polymod, convertbits, encode,
      verify incl. cross-spec, decode round-trips + corruptions): 0 fail. Fixed:
      un-saved x23 clobbered the caller in verify_checksum (O2-only crash);
      convert_bits error return now full 64-bit -1. (2026-08-25)
- [x] bitcoin_script.S (be_to_limbs + der_parse_sig) -- sig pre-processing
- [x] bitcoin_bip143.S (BIP143 segwit v0 sighash: swtx_parse_asm + segwit_v0_sighash_asm) -- 20k-vector diff-fuzz vs independent Python BIP143 (segwit+legacy tx, ALL/NONE/SINGLE x ACP, truncation): 0 fail
- [x] bitcoin_checksig.S (sv_checksig_asm BSASE + sv_checksig_witness_v0_asm) --
      exported script_find_and_delete/script_push_encode from bitcoin_sighash.S.
      ~6k-vector diff-fuzz vs independent Python pipeline (DER->sighash->pub->ECDSA,
      legacy+BIP143, valid+corrupt, compressed+uncompressed pub): 0 fail.
- [ ] script/consensus layer: bitcoin_interp / bitcoin_script VM /
      mempool -- NEXT: the interpreter VM (~5000 lines), then UTXO, then daemon.
      checksig / segwit + taproot script paths, mempool  <- NEXT (large: a
      full stack VM, ~5000 lines of x86-64 across interp/sighash/checksig)
- [x] bitcoin_tx (tx parse/txid)        -> port/arm64/bitcoin_tx.S  repo harnesses
      test_tx + test_txtxid PASS native; ~8.5k-case differential fuzz vs Python
      oracle (legacy+segwit txids, tx_parse fields, malformed rejection): 0 fail.
      (2026-08-24)
- [x] bitcoin_net / bitcoin_p2p           (raw-syscall sockets + framers) and
      bitcoin_headers (persistent header chain) -> port/arm64/bitcoin_{net,p2p,headers}.S
      test_net / test_p2p / test_p2p_inv / test_headers PASS native
- [x] bitcoin_store (multi-file blk + index)  -> port/arm64/bitcoin_store.S
      test_store 41 PASS native + t_roll rollover verified (caught MAX_FILE
      0x80000000->0x08000000 bug). (2026-08-24)
- [x] bitcoin_store.S += store_append_shared/_nolock + open_idx_close
      (concurrent-safe shared append; ends idxscan deferral). (2026-08-26)
- [x] bitcoin_store.S += store_prune / store_set_prune / unlink_blk /
      read_idx_rec / write_idx_rec (AArch64 PRUNING: persist gate to prune.dat,
      delete fully-pruned blk files, in-place boundary-file compaction w/ 64KB
      chunk copy + ftruncate). VERIFIED natively by t_prune.c (behavioral store
      built by hand to store_append's exact on-disk format): Case A prune@80
      (delete f0,f1 + compact f2), B prune@60 (mid-file compaction), C prune@0
      (persist_only), D prune@100 (prune_all), E prune@-1 (clamp->persist),
      F prune@200 (clamp->prune_all), G empty store: ALL PASS; plus existing
      test_store 41 still PASS. Unlocks bitcoin_store_fast. (2026-08-26)
- [x] bitcoin_store_fast  -> port/arm64/bitcoin_store_fast.S (commit d824396):
      read-path fd cache (pread64, 8 slots @st+64, magic RDFC@+56) + mmap-backed
      ZERO-COPY map cache (4 slots @st+128, magic MAP@+120). 11 exports:
      store_rd_init/_close/_fd, store_read_meta/_at, store_rd_advise,
      store_map_init/_close/_at/_advise, store_prune_safe. AArch64 syscalls:
      openat=56 pread64=67 fstat=80 fadvise64=223 mmap=222 munmap=215 madvise=233.
      VERIFIED by differential driver tfast.c: read_at/meta bytes == appended raw
      for 12 blocks; prefill-meta (skip-lookup) path; cap->-4; map_at zero-copy
      == raw; fd-cache; prune_safe(0) cache-invalidate + reads still correct;
      70MB blocks forcing file-2 rollover with cross-file read_at + map grow +
      map eviction; prune_all + prune.dat persisted. ALL PASS. (2026-08-26)
- [x] LIVE FULL-BLOCK DOWNLOAD MILESTONE  live_blocks.c: 30 real mainnet blocks
      (segwit, >=1.8MB) fetched via getdata BLOCK, header-hash verified vs the
      verified 963k header chain, prev-links checked, coinbase parsed by the
      ported bitcoin_tx, persisted via bitcoin_store + read back: 0 failures
      natively. Blk/index now in data/ (blk00000.dat + index.dat).
- [ ] bitcoin_cons (cons_verify)          [in DAEMONOBJS]
- [x] bitcoin_strip_witness (void witness stripping; canonical read_cs + minimal
      re-encode; consumed by modern txval + BIP341 stripped-commitment)
      -> port/arm64/bitcoin_strip_witness.S (+hash160). Differential vs C twin
      (bitcoin_segwit.c): synthetic 2183 cases + 3 real mainnet blocks (481824/413567/700000
      = 4699 txs) + independent Python fuzz (~65k) + 1200 large-script (70KB scriptSig) ->
      0 fail everywhere. (2026-08-25)
- [ ] bitcoin_interp / scriptcodec / sighash / checksig / script / segwit /
      taproot_verify / strip_witness / tapagg / multisig / sigops ...
- [ ] bitcoind.asm                        (daemon entry; links everything above)
- [ ] Remaining leaf modules (bip32/bip39/bip143/bip341, keys, addr*,
      idx, idxscan, muhash, mempool, serve, cli, chainwork, cmpct, headers,
      net addrmgr, node_log, txv_, witness_v0, ...)

## Notes
- Port is scalar-first (correct by construction). ARMv8 SHA2/crypto-extension
  (SHA256SU0/SHA256H/AESE etc.) fast paths can be added per-module later,
  mirroring how the x86 file's SHA-NI path complements its scalar body.
- Assembly is hand-written x86-64 with no automated translator; each module is
  a fresh AArch64 implementation matching the C-visible ABI.
- SECURITY: this is untrusted, experiment-unaudited consensus code (see
  README top). Keep it offline/testnet, no real funds, no internet exposure.

## Strategic update (2026-08-25): script VERIFICATION is unblocked
The daemon's script validation path is C-orchestrated: bitcoin_scriptverify.c
sv_run_v is a THIN WRAPPER over asm script_eval. Every crypto extern it needs
(legacy_sighash, script_find_and_delete, script_push_encode, der_parse_sig,
pubkey_parse, ecdsa_verify, be_to_limbs, segwit_v0_sighash) is now ported to
port/arm64/* and differential-fuzz verified (30k/60k/20k/~6k vectors, 0 fail).
So the crypto hooks for VerifyScript are complete. The single remaining
consensus-critical asm module is `script_eval` in bitcoin_interp.asm (~3165
lines + bitcoin_scriptcodec.asm). Port it and the C wrapper links unchanged.

## interpreter foundation (2026-08-25): bitcoin_scriptcodec.S PURE primitives
Ported + verified (150k vectors, 10 seeds, 0 fail): scriptnum_decode, scriptnum_serialize,
cast_to_bool, der_sig_strict (BIP66), check_minimal_push. NEXT in this module: get_op,
scriptnum elem boundary, then the element-stack engine (stack_push/pop/copy/dup/erase/insert), then vfExec, then script_eval (bitcoin_interp.asm).

## interpreter foundation -- COMPLETE (2026-08-25)
bitcoin_scriptcodec.asm is FULLY ported to port/arm64/bitcoin_scriptcodec.S and verified:
- part 1: scriptnum_decode/serialize, cast_to_bool, der_sig_strict, check_minimal_push (150k vec, 10 seeds, 0 fail)
- part 2: elem_tmp*_addr, snum_overflow_addr, stack depth/top/second/third/elem_ptr, stack_pop,
  stack_push(_copy), stack_dup/erase/insert_index, stack_swap_two, elem_move, get_op,
  vfexec_sp_reset/push/pop/depth/toggle_top/all_true (10 seeds x 500 scripted cases, 0 fail).
NEXT: bitcoin_interp.asm -- script_eval, the opcode-dispatch VM (the last consensus module).

## bitcoin_interp.S port started (2026-08-25)
Ported+verified: is_opsuccess (BIP342 OP_SUCCESSx, exhaustive 0..255), is_opsuccess_c,
interp_memeq. Files/globals created (interp_tmp, bool_buf, interp_err, interp_slice,
cms_* buffers). REMAINING (the project's last & biggest consensus module):
script_eval (~2000-line opcode-dispatch VM) + interp_push_num/interp_push_bool +
interp_swap_recs + checksig/checkmultisig subroutines. These are intertwined with
script_eval's frame (rbp-relative slots, r13/r14 = stack-top/alt-top), so they are
being written together; the interp helpers (interp_swap_recs etc.) are internal to
script_eval's call graph, not standalone.

## script_eval TRANSCRIBED + LINKS (2026-08-25) -- semantic verification still TODO
bitcoin_interp.S now contains the complete AArch64 port of asm/bitcoin_interp.asm:
script_eval (full ~2000-line opcode-dispatch VM: pre-scan, controls, stack, mono/bin/
within, crypto, CODESEPARATOR, CHECKSIG(ADD/verify), CHECKMULTISIG(verify), CLTV/CSV
with real tx context, cleanstack/tapscript) + interp_push_num/_bool/_require_depth/
_swap_recs/_sig_encoding_ok/_checksig/_checksig_add/_checkmultisig + is_opsuccess(_c)/
interp_memeq. It ASSEMBLES and LINKS clean against codec+sighash+crypto objects.
IMPORTANT: this is a faithful transcription, NOT yet semantically verified. Next step:
build the whole-VM differential harness (pure-Python EvalScript over ~90 opcodes +
CLTV/CSV with tx context) driving a C script_state provider, + real Core/block vectors.

## script_eval MAIN VM -- DIFFERENTIAL-VERIFIED (2026-08-25)
The full opcode-dispatch VM (all non-CHECKSIG opcodes) is verified against an independent
pure-Python EvalScript mirror (eval_oracle.py) with EXACT rc + err_out + final-stack equality:
32 seeds x 400 = 12,800 scripted cases, 0 fails. Ops covered: controls IF/NOTIF/ELSE/ENDIF,
VERIFY/RETURN, TOALT/FROMALT, 2DROP/2DUP/3DUP/2OVER/2ROT/2SWAP/IFDUP/DEPTH/DROP/DUP/NIP/
OVER/PICK/ROLL/ROT/SWAP/TUCK/SIZE, EQUAL(VERIFY), mono(1ADD..0NOTEQUAL), bin(ADD..MAX),
WITHIN, crypto(RIPEMD160/SHA1/SHA256/HASH160/HASH256), CODESEPARATOR, CLTV/CSV (real tx
context), pushnum, tapscript prescan/cleanstack/minimal-if, empty-script end-of-loop.
Real asm bugs found+fixed via this harness: get_op lacked its 2nd return (pushlen); missing
pc>=pend .loop_done check; minimal-if cbz-vs-cbnz; helper x1-then-CSTK idx clobber; 2ROT
bottom-2 (fix: index depth-6/depth-5); ROT loop indices; leaf helpers not preserving x19-x24
and x30 (tail-ret trap); x24 never set to frame base (interp helpers read garbage slots);
element len read as 64-bit instead of u32 (OP_SIZE pitfall) at 19 sites.
REMAINING slice: interp_checksig/_checksig_add/_checkmultisig (CHECKSIG/CHECKMULTISIG paths
+ C checksig_fn callback interop) still crash under the stub-plumbing test -- next debug item.

## 2026-08-25 — s5 script/consensus COMPLETE (interpreter done)
script_eval (bitcoin_interp.S) is now FULLY differential-verified, including the
whole CHECKSIG/CHECKMULTISIG plumbing, two fixes:
- script_find_and_delete saved-reg/local (x19/x20) overlap in bitcoin_sighash.S
- interp_checkmultisig NULLDUMMY missing x1-elems reload in bitcoin_interp.S
24,000 targeted cms/checksig cases + 1,200 VM regressions: 0 fail. Full harness pass.
Next: s6 daemon link (UTXO store + bitcoind + mempool) then s7 full IBD + UTXO build.

## 2026-08-25 — bitcoin_utxo.S ported + verified (UTXO core, s6 building block)
In-memory UTXO set: open-addressing hash table + bump-blob, backward-shift (Knuth R)
deletion, utxo_walk_live visitor. AArch64 port in port/arm64/bitcoin_utxo.S, same
exports+ABI. Differential-fuzzed vs independent Python dict oracle over a C driver:
  - 24 seeds x 1500 = 36,000 mixed put/get/del/walk ops with full sorted-set dump
    equality at EVERY step (keys/36B, value, height/is_coinbase code, slen, script): 0 fail
  - 8 seeds x 4000 = 32,000 high-load ops (slots=32, live 22-30, heavy 4-byte-prefix
    collisions -> long probe chains + near-full, frequent backward-shift deletes): 0 fail
Pitfalls hit: (1) un-saved x23/x24/x25 in utxo_init clobbered the C caller (crash
after init) -> loop must use caller-saved x9-x17 only; (2) utxo_walk_live loaded the
index into x10 then reloaded x10 with the callback -> re-load index right before the
key store; (3) empty-script put silently skipped by sscanf (empty trailing field,
the strtok-style empty-token pitfall again) -> '-' sentinel. t_utxo.c + fuzz_utxo.py.
s6/UTXO core underway: bitcoin_utxo done; bitcoin_utxo_store IN PROGRESS (a
concurrent session); bitcoin_sigops DONE (2026-08-25 this session):
- [x] bitcoin_sigops.S (sigop accounting) -> script_sigops / script_sigops_accurate /
      tx_legacy_sigops, built on the already-ported get_op. Differential fuzz vs an
      independent Python Core-equivalent oracle (multisig=20 inaccurate / DecodeOP_N
      accurate; segwit marker+flag skip): 47k script (acc+inacc) + 23.5k tx + 1.2k
      large-script (0xfd/0xfe/0xff slen) + 32 big-count (n_in/n_out up to 300k) cases,
      0 fail across 6 seeds. (port/arm64/bitcoin_sigops.S, fuzz_sigops.py, fz_sigops.c)

## 2026-08-25 — bitcoin_utxo_store.S ported + verified (persistent UTXO store, s6 core #2)
AArch64 port of the WAL+checkpoint persistent UTXO store (utxo.dat append log,
utxo.idx snapshot, crash-safe reload = checkpoint + WAL-tail replay; same on-disk
framing as x86). Exports: init, init_ro, put, del, count, get, clear, sync, reload,
close over raw syscalls (openat/read/write/lseek/fsync/close; arm64 fsync=82).
Differential-fuzzed vs a Python dict oracle over a C driver t_ustore that does
random put/del/get + periodic sync/reload in a scratch dir; the oracle REQUIRES
reload to reproduce the exact live set (keys/36B, value, height/is_coinbase code,
slen, script). 10 seeds x 600 ops = 6,000 ops + 60+ reload reconstructions: 0 fail,
exact asm==exp line-for-line (restart-resume validated both via checkpoint and,
when the checkpoint is removed, pure WAL replay).
PITFALL defeated: the root cause of hours of 'reload returns empty set' was
AArch64 `svc` NOT setting NZCV, so `bl/ge/lt` right after a syscall branches on
STALE flags from before the call -- a successful positive read() x0>0 could still
take `b.lt .rbad` and report failure. Fix: `tbnz x0,#63,.rbad` (tests the sign
bit, no flags). Also honored: mac_read_exact must NOT use callee-saved x21 as its
internal counter (reload holds its idx fd in x21 across calls) -- used x9 instead;
and the reload idr-header check disconfirmed-sized fields need 8-multiple ldr
immediates, so unaligned packed fields are read via register-offset (add xN,base,#off;
ldr xD,[xN]).
s6/UTXO core: bitcoin_utxo (in-memory) + bitcoin_utxo_store (persistent) both done.
Next: bitcoin_sigops, bitcoin_undo, then the IBD driver for full download->verify->UTXO.

## 2026-08-25 — bitcoin_undo.S ported+verified (UTXO reorg layer complete)
Per-block undo store (append/load/replay[+tolerant]/discard/prune/prune_from), same
on-disk "undo_<h>.dat" format as x86. Differential-fuzzed against the C oracle
(asm/daemon/undo_log.c) directly: 16 seeds x 800 = 12,800 ops across all functions
incl. absent files, negative heights, empty & large scripts, prune windows; 0 fail,
byte-for-byte asm==C. AArch64: openat/unlinkat replace x86 open/unlink; raw syscalls.
Pitfall: a 40MB static test array (u8 (*)[UMS]) faulted on this aarch64 build in the
driver's ld-walk even in-bounds; switching to a heap buffer fixed it (static-array
addressing quirk, unrelated to the port). undo_capture_and_del deferred (needs the
not-yet-ported bitcoin_utxo_lsm get/del). s6 UTXO layer now: utxo (mem) + utxo_store
(persist) + sigops + undo all native+verified. NEXT: the IBD driver (download ->
cons_verify -> per-tx script verify -> UTXO apply) for full-chained download+verify.
