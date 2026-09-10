# OSX PORT STATE — durable snapshot

Updated whenever status materially changes. Newest section top.
(Companion to `OSX_PORT.md` (branch model), `OSX_ROADMAP.md` (per-module
status) and `OSX_STRATEGY.md` (phased plan-of-record, PR #130).)

## 2026-09-10 — MAINNET IBD RUNNING on Apple Silicon

- The native bmcbitcoind (M1 Max, macOS 26.6) is doing a real mainnet IBD
  right now: 966,400 headers stored (headers.dat 108,236,800 B, ~29 min),
  then blocks from genesis via the boot catch-up against the x86 reference
  node (`connect=192.168.5.242:8332`, which is itself mid-IBD -- the osx
  node follows its tail live). 115,401/966,400 stored (11.9%) at elapsed
  5:01, ~460 blk/s, zero consensus failures. No debugger was usable on
  this machine (lldb attach/launch permission-gated); the crash backtraces
  came from macOS DiagnosticReports .ips files plus an in-worker
  siginfo+backtrace handler.
- Enabling commits: bc38f9e8 (the p2/p3 wave: syscall .S ports + C shims +
  native build + the fixes below) and the diagnostics commit. Regtest IBD
  end-to-end green first: fresh node B pulled 113 blocks from node A over
  the wire (3 chunks, ~10s), UTXO applied 113/113, tip hashes identical.
- Four port bugs the IBD path caught (details in worklog/2026-09-10.md):
  three raw-svc sites still using the Linux nr-in-x8 convention
  (idxscan flock x2, node_log openat -- SIGSYS/SIGSEGV roulette in the
  worker), node_make_version's double-deref of _node_services (SIGSEGV at
  0x809 in the probe handshake), and cons_twin txid_of_span's legacy-tx
  strip offset + cap-semantics confusion (caught by test_cons).

## 2026-09-09 — secp256k1_taproot twin landed; bip341 gate scoped

- **secp256k1_taproot -> taproot_twin.c** (C twin): tagged_hash256,
  tap_branch_hash, tap_leaf_hash, taproot_tweak_pubkey (1 even / 2 odd,
  parity captured before even-normalising), tap_merkle_root.  Gates:
  upstream test_taproot ALL PASS native + 227-record cross-arch
  differential byte-identical vs .242 (tags/msgs to 200 KB, leaf
  compactsize boundaries, tweak rejections x>=p/t>=n, merkle depth 0..8).
- bitcoin_taproot_sighash.c (the bip341/bip342 production C) is
  arch-neutral and needs this twin at link time; its harness
  test_taproot_sighash pulls bitcoin_interp/scriptcodec/sha1, so the
  bip341/342 gate lands with the script VM wave -- the same deferral
  pattern as test_ir10 (script) and test_segwit_sighash (witness_v0).
- Session total so far: bitcoin_keys.S, bitcoin_addr.S, bitcoin_bip32.S
  native; sighash/script/taproot twins; bip143 no-port gate; hmac x25 ABI
  fix; harness UB fix; schnorr bench corrected 273 -> 80 us.  24 commits
  pending push (origin publickey still blocked from this Mac).

## 2026-09-09 — bip143 (no port needed) + bitcoin_script twin; schnorr bench was 3.4x inflated

- **bitcoin_bip143: NO PORT NEEDED.** Production calls bitcoin_segwit.c
  (arch-neutral) directly; the asm module is only the differential harness's
  perf twin.  Gate: native test (BIP143 published example + real block-481824
  tx 562 with the actual witness signature verified through ecdsa_twin under
  the C's sighash + swtx_parse contract) and a 1,635-vector corpus dump
  byte-identical three ways: osx-C == x86-C == x86-ASM.
- **bitcoin_script -> script_twin.c** (C twin): test_script + test_p2pkh
  green native; 18.7 KB cross-arch diff byte-identical; the differential
  caught der_long_len re-masking the first length byte as the count (the
  upstream short-form-only harnesses could not see long-form INTEGERs).
- **pubkey_schnorr_twin.c carried committed bring-up debug inside
  schnorr_verify** (two fe_inv + fprintf per call).  Removed; BIP340
  19/19 re-verified; bench CORRECTED 273.11 -> 79.92 us/verify (3.4x;
  BENCHMARKS_OSX.md updated).  Two process lessons recorded: (1) the first
  removal pass dropped the real point_scalar_mul_fixed(SG,sL) call with the
  debug block -- caught only because bench_schnorr refuses to time a
  fixture that does not verify; (2) hand-transcribed fixture hex carried
  two silent copy errors -- regenerate fixtures programmatically.
- segwit-v0 sighash is now fully Darwin-covered.  Next: secp256k1_taproot
  (tagged_hash256/tweaked_pubkey) to unlock the bip341 gate, then the
  script VM wave.

## 2026-09-09 — keys/addr/bip32 native + sighash twin: wallet derivation covered

- Four modules landed, three as native AArch64 asm (details in
  OSX_ROADMAP.md; commits 3db7bd97, 1092ebee, 5cfccf4d, 404f968b):
  **bitcoin_keys.S** (test_keys 6/6 + 647-record diff), **bitcoin_addr.S**
  (test_addr 5/5 + 56-record diff; the x11-cursor pitfall again),
  **bitcoin_bip32.S** (all four upstream bip32 harnesses + 990-record diff;
  frame-overrun, byte-0-skipping carry loops, and the AAPCS64
  eight-register-arg extkey contract all caught by the gates), and
  **sighash_twin.c** (test_legacy_sighash 500/500 Core vectors +
  test_find_and_delete 23/23 + test_sighash_oob + 143 KB diff).
- REAL PRE-EXISTING PORT BUG fixed: bitcoin_hmac.S used x25 without saving
  it (callee-saved; main's GOT anchor) -- latent until the dbip32 driver,
  which parks x25 across bip32_master -> hmac_sha512. Prologue/epilogue
  now save/restore x25,x26; test_hmac re-verified green. First port bug
  found by a caller's register pressure rather than a gate's value check
  -- the differential drivers earn their keep as ABI stress.
- UPSTREAM HARNESS UB fixed: test_bip32_master.c's sscanf %2x into
  (unsigned*)&kg[i] spills 3 bytes into adjacent frame vars (zeroed
  kg[0..2] and the caller's c[0..2] under clang's layout; the k/c outputs
  were correct all along). Fixed to the unsigned-temp pattern; verified
  green on BOTH arches (.242 re-run).
- With this wave the wallet key-derivation path (seed -> master -> path ->
  xprv/xpub/address) and the legacy sighash preimage builders are fully
  Darwin-covered. Remaining p1: bip143/bip341/bip342, taproot, and the
  script VM (interp/scriptcodec/script/multisig/script_flags).
- Session housekeeping: removed a stale utxo_lsm_twin-*.o.tmp; push still
  blocked from this Mac (origin publickey), 20 commits pending on bmc_osx.

## 2026-09-09 — docs backfill: the point→cons wave (8b341e41..5b7f679f)

- Ten modules landed in a fast wave without per-module state/roadmap
  entries (the worklog jumped from fe_twin to net_twin). Durable record
  now in OSX_ROADMAP.md, evidence from the commits + in-file headers:
  - **secp256k1_point/point_ct** (point_twin.c, point_ct_twin.c,
    g_comb_table_data.c): test_point + test_point_inf native, 1200 +
    1740-record cross-arch diffs byte-identical (8b341e41, 93a4d015).
  - **secp256k1_ecdsa + bitcoin_pubkey/secp256k1_schnorr**
    (ecdsa_twin.c, pubkey_schnorr_twin.c): BIP340 verify native + first
    cross-arch verify benches (BENCHMARKS_OSX.md); fixed sc_inv_var
    `ldp x25,x25` SIGILL (b25968b9).
  - **bitcoin_chainwork/muhash/utxo_stats** (chainwork_twin.c,
    muhash_twin.c, utxo_stats_twin.c): test_chainwork 0F + test_muhash
    green on Core-oracle vectors; test_tmpdir.h Darwin shim (50526b34).
  - **bitcoin_utxo + bitcoin_store_fast** (utxo_twin.c,
    store_fast_twin.c): test_utxo 0F, test_store 0F, bench_store_read
    byte-exact (b611922b; store_twin born here, completed a253ef93).
  - **bitcoin_cons** (cons_twin.c) and **bitcoin_headers**
    (headers_twin.c): test_cons / test_headers green (5b7f679f,
    9f112d91); cons + headers gates re-run green in this session.
- Session housekeeping: removed a stale utxo_lsm_twin-*.o.tmp; push still
  blocked from this Mac (origin publickey), 15 commits pending on bmc_osx.

## 2026-09-09 — bitcoin_net twin: first p2 syscall module landed (C twin)

- `port/osx/net_twin.c`: BIP314 v1 framing + fd plumbing + v2 dispatch +
  upload-pacer hook, all 12 public symbols of asm/bitcoin_net.asm. Gates:
  upstream test_net 19/19, test_p2p_msgsize 14/14 (oversize -3 + no-drain +
  NET-11 checksum), hook-arg smoke, live tcp_connect_ip vs .242:8332, and
  a 240-frame p2p_frame cross-arch differential byte-identical vs the x86
  objects (dnet.c + gen_dnet_vecs.py; includes two 4MB P2P_MAX_MSG frames).
  Commit 45fe22bb.
- Twin bug the upstream-equivalent gates caught: a half-finished edit left a
  DUPLICATED drain loop and checksum-before-drain ordering; x86 order is
  checksum (only when announced<=cap) THEN drain, and *plen_out is written
  AFTER the drain (test_net's post-drain-alignment check pins this).
- headers_twin landed just before this (9f112d91, test_headers all green,
  hst_append returns new count). IBD-path assembly pair bitcoin_net +
  bitcoin_headers is now Darwin-covered. Next: bitcoin_p2p message builders
  (p2p_getheaders etc. -- pure compute) then addrmgr/idx, keeping the
  one-module-one-gate rhythm.

## 2026-09-09 — bitcoin_p2p twin: IBD message layer complete (C twin)

- `port/osx/p2p_twin.c`: p2p_getheaders (Stage A multi-hash locator,
  count 1..252), p2p_getdata_block (MSG_WITNESS_BLOCK 0x40000002), p2p_ping,
  p2p_headers_count, p2p_inv_count, p2p_inv_get. Gates: upstream test_p2p
  18/18 + test_p2p_inv 12/12 native, 130-record cross-arch differential
  byte-identical vs x86 (dp2p.c + gen_dp2p_vecs.py). Commit 57588bdb.
- With net_twin + headers_twin the whole IBD wire path (framing, message
  builders, header store) is Darwin-covered. Next: addrmgr/idx, then the
  big store modules, keeping one-module-one-gate.

## 2026-09-09 — bitcoin_addrmgr twin landed (C twin)

- `port/osx/addrmgr_twin.c`: peers.dat book (init/count/add/get_i/lookup)
  + addr v1/v2 codecs + addr_count. Gates: upstream test_addrmgr 28/28
  (Core-reference codec bytes), 73-record cross-arch differential
  byte-identical vs x86 -- result stream AND the resulting peers.dat file.
  Commit 2725d14b.

## 2026-09-09 — bitcoin_idx twin landed (C twin) + REAL x86 BUG found

- `port/osx/idx_twin.c`: hash->height open-addressing index (init/put/get/
  count/build_from_file), layout-compatible 48B slots. Gates: upstream
  test_idx 12/12, 868-record cross-arch differential byte-identical.
  Commit 6fed3a71.
- THE DIFFERENTIAL FOUND A REAL X86 BUG: 100%-full table -> x86 idx_put
  spins forever. memcmp_exact clobbers r8b; idx_put keeps the probe budget
  in r8 across the call, so after one non-matching memcmp the budget is
  garbage and `dec r8; jz .full` never fires. Production never fills its
  1M-slot table so it was latent. Vectors regenerated to keep <100% load;
  x86 asm fix goes on main (TODO.md).

## 2026-09-09 — bitcoin_store twin landed (C twin); p2 store layer open

- `port/osx/store_twin.c`: the full block store (init/reload/append/get_at/
  get_tip/get_file_fd/prune family/append_shared family/reorg primitives/
  truncate family), 19 public symbols. Gates: upstream test_store 42/42,
  test_truncate 54/54, 69-record differential byte-identical (retval stream
  AND the full cwd file set via tarball compare). Commit a253ef93.
- Note: prune/truncate run against files by bare relative name -- differential
  harness must start in a scratch cwd (stale prune.dat from a previous run
  poisons store_init's gate restore).
- GitHub push still blocked from this Mac (no gh auth, SSH key unregistered);
  9 commits pending on bmc_osx.

## 2026-09-09 — bitcoin_utxo_store twin landed (C twin)

- `port/osx/utxo_store_twin.c`: WAL + checkpoint UTXO persistence (buffered
  WAL, atomic checkpoint publish, torn-tail truncate, init_ro). Gates:
  test_utxo_store + test_utxo_wal_buffer + test_utxo_torn_tail green,
  124-record differential byte-identical (retvals + utxo.dat/utxo.idx).
  Commit 55c76deb. utxo_struct_size added to utxo_twin.c.

## 2026-09-09 — bitcoin_utxo_lsm twin landed (C twin) -- the whale is done

- `port/osx/utxo_lsm_twin.c` (+ vendored utxo_lsm_mm.c): the LSM UTXO store
  -- flush/sorted-runs/bloom/sparse-index/manifest, multi-run get,
  recount/compact/walk k-way merge, tombstone hash. Gates: 6 upstream LSM
  harnesses green native; 229-record differential byte-identical (retvals +
  WAL/runs/manifest file set). Commit b65c12e1. macOS note: the upstream
  mmap fast path is byte-identical but fails CONCURRENT gets under
  clang-21/arm64 -- defaulted off on __APPLE__, twin path is the anchor
  (documented in utxo_lsm_mm.c).

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
