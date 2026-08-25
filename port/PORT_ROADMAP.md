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
- [ ] secp256k1_fe / scalar / point / point_ct / ecdsa / schnorr / taproot
                                          (the security-critical core; validate
                                           against *_{fe,scalar,glv,scalar}_c.c
                                           oracles + Python int oracle)
- [ ] bitcoin_tx (tx parse/txid)          [in DAEMONOBJS]
- [ ] bitcoin_net / bitcoin_p2p           (raw-syscall sockets + framers)
- [ ] bitcoin_cons (cons_verify)          [in DAEMONOBJS]
- [ ] bitcoin_store / store_fast / utxo*  (UTXO mmap/LSM stores)
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
