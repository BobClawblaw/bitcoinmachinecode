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
- [ ] secp256k1_scalar / point / point_ct / ecdsa / schnorr / taproot
                                          (the security-critical core; validate
                                           against *_{fe,scalar,glv,scalar}_c.c
                                           oracles + Python int oracle)
    - [x] secp256k1_scalar  -> port/arm64/secp256k1_scalar.S   test_scalar PASS
          native (12/12 incl. sc_inv and 3*inv(3)==1); ~13.5k-case differential
          fuzz vs Python big-int mod n (add/sub/mul/sqr/inv, full-range operands)
          0 failures. Fixed 2 real bugs: (1) sc_mul clobbered callee-saved x22
          (AAPCS violation -> main's live x22 corrupt -> SIGSEGV); (2) sc_mul fold
          carry-propagation loop `cmp`-clobbered the C flag between `adcs` steps,
          silently dropping each column carry at tmp[k+2] -> result off by DELTA.
          (2026-08-25)
    - [ ] secp256k1_point / point_ct / ecdsa / schnorr / glv  <- NEXT
          (sc_inv_var binary-xgcd still needs porting for ecdsa_verify s^{-1})
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
- [x] LIVE FULL-BLOCK DOWNLOAD MILESTONE  live_blocks.c: 30 real mainnet blocks
      (segwit, >=1.8MB) fetched via getdata BLOCK, header-hash verified vs the
      verified 963k header chain, prev-links checked, coinbase parsed by the
      ported bitcoin_tx, persisted via bitcoin_store + read back: 0 failures
      natively. Blk/index now in data/ (blk00000.dat + index.dat).
- [ ] bitcoin_cons (cons_verify)          [in DAEMONOBJS]
- [ ] bitcoin_interp / scriptcodec / sighash / checksig / script / segwit /
      taproot_verify / strip_witness / tapagg / multisig / sigops ...
- [ ] bitcoind.asm                        (daemon entry; links everything above)
- [ ] Remaining leaf modules (bech32, bip32/bip39/bip143/bip341, keys, addr*,
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
