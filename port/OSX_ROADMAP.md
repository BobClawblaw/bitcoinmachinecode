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
- [x] secp256k1_point -> port/osx/point_twin.c  DONE 2026-09-09 as a C TWIN
      (point_double/add/add_mixed/add_mixed_zr/scalar_mul w=4 windowed/
      scalar_mul_fixed over the 64x15 comb table (g_comb_table_data.c,
      converted from the NASM .inc)/scalar_mul_glv GLV+wNAF with fallback;
      same formulas, same 4x64-limb convention, same 12-limb Jacobian and
      Z=0-with-X=Y=1 infinity repr as the x86 asm; fe ops from fe_twin,
      scalar split from secp256k1_scalar.S, wNAF from upstream-pure-C
      secp256k1_glv_c.c). Gates: tests/test_point 2/2 + test_point_inf ALL
      PASS native; 1200-record cross-arch differential byte-identical vs
      x86 on .242 (random + Z=0 canonical/non-canonical + q==p +
      mixed-equal-x + Y1=0 + affine(0,0) shapes; drivers port/osx/tests/
      dpt.c + gen_dpt_vecs.py). C twin because the x86 inline-macro
      structure (r8-r11 accumulator, cmov/sbb tails) has no faithful
      AArch64 mapping at this scope; revisit asm for perf after p3.
      Commit 8b341e41.
- [x] secp256k1_point_ct -> port/osx/point_ct_twin.c  DONE 2026-09-09 as a
      C TWIN (pointh_add RCB Algorithm 7 complete branch-free, pointh_double
      complete a=0 doubling, point_scalar_mul_ct fixed 256-round cmov ladder
      with the x86's exact emit mapping out.x=X*Z/out.y=Y*Z^2/out.z=Z
      non-affine -- the contract callers bip32_ckdpub/bip340_sign consume).
      Gate: 1740-record cross-arch differential byte-identical vs x86 (dpt.c
      ops 7-9 added). Commit 93a4d015.
- [x] secp256k1_ecdsa -> port/osx/ecdsa_twin.c  DONE 2026-09-09 as a C TWIN
      (ecdsa_verify + ecdsa_x_eq_mod_n transcribed instruction-for-
      instruction from the x86 listing so the slot flow matches).
- [x] bitcoin_pubkey + secp256k1_schnorr -> port/osx/pubkey_schnorr_twin.c
      DONE 2026-09-09 as a C TWIN (pubkey_parse compressed/hybrid, BIP340
      schnorr_verify with the repo's message-length cap, fe_pow
      square-and-multiply). Both gated by the first cross-arch crypto-verify
      benchmarks (bench_ecdsa/bench_schnorr, quiet machine, min-of-5
      thread-CPU rounds; BIP340 csv row 0 fixture on both sides; numbers in
      BENCHMARKS_OSX.md: ecdsa 140.14 us/verify M1 Max vs 21.46 us x86,
      schnorr 273.11 vs 26.07 -- the gap is C twins vs hand-scheduled asm,
      both byte-identical on the shared fixtures). The wave also fixed a
      real port bug: sc_inv_var's `ldp x25,x25` (Rt==Rt2 SIGILL class).
      Commit b25968b9. secp256k1_taproot stays open.
- [x] secp256k1_scalar -> port/osx/secp256k1_scalar.S  DONE 2026-09-09.
      Native: sc_add/sc_sub/sc_sqr/sc_inv/sc_inv_var/sc_mul_512/
      sc_split_lambda; sc_mul -> sc_mul_c (C twin) + sc_mul_512 wrapped
      over sc_mul_512_c until the AArch64 asm fold bug is root-caused.
      Evidence: test_scalar 12/12, test_glv_split 3 campaigns (1,001,018
      + 1,000,000 cases) 0 failures; cross-arch differential vs x86
      objects on the 9950X3D: 2,306 vectors byte-identical (mul_512 800,
      split 6, sc_mul/sc_add/sc_sub 1500; drivers port/osx/tests/dsl.c +
      gen_dsl_vecs*.py).  Commit 131e5171 (branch osx/p1-scalar).
      Pitfalls recorded: AArch64 `add`/`adc` set no flags (use
      adds/adcs); ldp Rt==Rt2 SIGILL; frame aliases need real `sub sp`.
- [x] bitcoin_aes -> NO PORT NEEDED: asm/bitcoin_aes.c is pure C; test_aes
      passes natively on AArch64 unchanged.  Verified 2026-09-09.
- [x] bitcoin_bip39 -> port/osx/bitcoin_bip39.S  DONE 2026-09-09. Evidence:
      tests/test_bip39 native: 24-vector oracle round (generate+validate+
      entropy+seed; empty and TREZOR passphrases) + WAL-11 400-word
      rejection + m39_guard canary + negative cases ALL PASS; the same
      harness is green on x86 .242.  Commit 0c259e99.
      MACH-O PITFALL: fixed-width data tables must go in __TEXT,__const —
      __cstring entries get tail-merged by the Darwin linker, silently
      shifting 9-byte wordlist records.  Helper-scratch pitfall:
      find_word_index must use x8-x17 only (first draft trashed the
      caller's x22/x23 after word one).
      test_hmac RFC 4231 3/3 native + 400-vector cross-arch differential
      (RFC shapes, BIP32/BIP39 inputs, 127/128/129 key boundaries,
      two-block pads) byte-identical vs .242 (drivers port/osx/tests/dsv.c
      + gen_dsv_vecs.py).  C twin bitcoin_hmac_c.c kept as reference.
      Commit da3f4b6d.  FIXED A REAL sha512.S BUG found by the differential:
      the carrier[112..127] zero loop was aimed at carrier+232..247 (base
      x13 already +120) -- for the two-block pad path (rem>=112) it wrote
      16 zero bytes INTO THE CALLER'S FRAME (hmac kpad[8..23]).  Gate
      caught it: any keylen>=16 + msglen 112..127/255 failed vs x86.
- [x] bitcoin_hmac -> port/osx/bitcoin_hmac.S  DONE 2026-09-09.  (Evidence
      block follows the bip39/aes entries above.)
- [x] bitcoin_tx -> port/osx/bitcoin_tx.S  DONE 2026-09-09. Evidence:
      upstream test_tx 20/20 + test_txtxid + test_tx_bounds_fuzz
      55,232,133 guarded calls 0 faults (all native) + 501-tx differential
      (tx_parse+tx_txid, valid/truncated/poisoned) byte-identical vs the x86
      objects on the 9950X3D (drivers: port/osx/tests/dtx.c + gen_tx_vecs.py).
      Port bugs the gates caught: (1) stp/ldp x27,x27 -- ldp with Rt==Rt2 is
      CONSTRAINED UNPREDICTABLE and SIGILLs on Apple Silicon (pop odd slot
      with ldr + add sp,#8); (2) locktime path stored the ADDRESS register as
      the new cursor (tx_len corruption); (3) witness walk must reload n_in
      from info after x23 is reused for n_out.
- [x] bitcoin_net -> port/osx/net_twin.c  DONE 2026-09-09 as a C TWIN
      (the 9 socket syscalls go through Darwin libc; x86 arg4-in-R10 is moot).
      Surface: net_magic, g_v2_active[4096], g_p2p_write_hook, g_v2_hook_write,
      g_v2_hook_read, fd_write_all, fd_read_full, fd_close, tcp_connect_ip,
      p2p_frame, p2p_write, p2p_read. Gates: upstream test_net 19/19 +
      test_p2p_msgsize 14/14 native (oversize -3 refusal, no drain, checksum
      incl. empty-payload NET-11) + v2/pacer hook smoke (hook arg order:
      read hook gets plen_out POINTER as 5th arg) + live tcp_connect_ip to
      .242:8332 and refused-port -errno passthrough + 240-frame p2p_frame
      cross-arch differential byte-identical vs x86 (drivers:
      port/osx/tests/dnet.c + gen_dnet_vecs.py; cmd lens 0..16 straddling
      the 12-byte field, payload lens 0/55/56/63/64/65/127/128/129/... and
      two P2P_MAX_MSG 4,000,000 frames).  Commit 45fe22bb.  TWIN BUGS THE
      GATES CAUGHT: first cut duplicated the drain loop after a botched edit
      and had checksum-before-drain ordering wrong (checksum runs FIRST,
      only when announced<=cap; plen_out is written AFTER the drain).
- [x] bitcoin_p2p -> port/osx/p2p_twin.c  DONE 2026-09-09 as a C TWIN
      (6 pure-compute payload builders/parsers; NODE_PROTOCOL_VER pinned to
      asm/version.inc's 70016 with a pointer comment -- a bump shows as a
      cross-arch diff failure, not silent drift). Gates: upstream test_p2p
      18/18 (incl. the p2p_write pacer-hook block via net_twin) +
      test_p2p_inv 12/12 (1-byte/0xfd varints, 0xfe reject, round-trip) +
      130-record differential byte-identical vs x86 bitcoin_p2p.o
      (drivers port/osx/tests/dp2p.c + gen_dp2p_vecs.py: getheaders counts
      1..252 + negatives 0/253/300/0xFFFFFFFF, getdata MSG_WITNESS_BLOCK,
      ping nonces, headers_count/inv_count incl. 0xfc/0xfd/0xfe/0xff and
      count*81/count*36 plen boundaries, inv_get round-trips).
      Commit 57588bdb.
- [x] bitcoin_addrmgr -> port/osx/addrmgr_twin.c  DONE 2026-09-09 as a C
      TWIN (peers.dat book ops via Darwin libc; the x86 raw open/lseek/read/
      write collapse to open/lseek/read/write -- semantics kept exactly:
      count=filesize/18 no partial-tail error, add=seek-end+write(18),
      get_i short read -> -1). Gates: upstream test_addrmgr 28/28 native
      (Core msg_addr/msg_addrv2 reference bytes incl. services CompactSize
      edges fd/fe and 300-record fd 2c 01 count) + 73-record differential
      byte-identical vs x86 bitcoin_addrmgr.o on .242 -- BOTH the result
      stream AND the resulting peers.dat file (damr.c + gen_damr_vecs.py:
      add new/dup, get_i in+out of range, lookup hit/miss, v1/v2 codecs
      1..300 records, addr_count fd/fe/ff/truncated shapes).
      Commit 2725d14b.
- [x] bitcoin_idx -> port/osx/idx_twin.c  DONE 2026-09-09 as a C TWIN
      (FNV-1a full-32-byte hash + XOR-fold, linear probing, 48B stride slot
      layout identical to x86; buffered-pread build_from_file, wire-order
      hashes, holes skipped). Gates: upstream test_idx 12/12 native (incl.
      the 500k pow-prefix clustering regression guard, 0.84s total) +
      868-record differential byte-identical vs x86 bitcoin_idx.o on .242
      (didx.c + gen_didx_vecs.py: put/get/dup/negative/heavy-collision,
      build_from_file over hole-rich files with dups, raw table dumps at
      64/1024/4096 slots).
      CROSS-ARCH FIND (real x86 bug, masked in production): a 100%-full table
      makes x86 idx_put SPIN FOREVER. memcmp_exact clobbers r8b (its own
      header says it may), but idx_put/idx_get keep the probe budget in r8
      across the call -- after one memcmp the budget becomes garbage
      (0x400 | last hash byte) and `dec r8; jz .full` never fires. The
      differential vectors hit this by accident (800 puts + 224 build
      inserts == 1024 slots exactly); production masks it (1M slots, 962k
      records, never full). Twin implements the DOCUMENTED contract (ret 2
      full); vectors keep <100% load (700-put phase B) so the differential
      exercises defined behavior. x86 fix belongs on main (move the budget
      to a stack local or a non-clobbered reg) -- TODO.md item added.
      Commit 6fed3a71.
- [x] bitcoin_store -> port/osx/store_twin.c  DONE 2026-09-09 as a C TWIN
      (rolling 128MB blk%05u.dat files + positional index.dat, state struct
      offsets identical; fmt_blkname, init/reload w/ prune.dat restore,
      append w/ STO-11 fdatasync ordering + rollover, get_at with prune
      gate + 0xFFFFFFFF sparse-prune marker, get_tip, get_file_fd, set/get
      sync, append_shared(+nolock) w/ flock self-healing position, tip_hash,
      validates_prevhash, layout_monotonic, truncate_to w/ the
      monotonic-safety gate, truncate_index_only, set_prune/prune with
      boundary-file compaction). Gates: upstream test_store 42/42 +
      test_truncate 54/54 native + 69-record differential byte-identical vs
      x86 bitcoin_store.o on .242 -- retval stream AND the full resulting
      file set (index.dat, blk*.dat, prune.dat) compared via tarball
      (dstore.c + gen_dstore_vecs.py: append/get/tip/tip_hash/
      prevhash/monotonic/reload/re-append/prune persist+physical/
      truncate_to mid + wipe/idx-only/sync toggles). Commit a253ef93.
- [x] bitcoin_utxo_store -> port/osx/utxo_store_twin.c  DONE 2026-09-09 as
      a C TWIN (WAL utxo.dat w/ 1MB process-wide shared buffer keyed by fd +
      atomic utxo.idx checkpoint publish via .tmp+rename; put/del write the
      record then apply via the memtable twin; reload = clear + snapshot +
      WAL-tail replay with UTX-4 torn-tail truncate; init_ro for read-only
      datadirs; log_len is the LOGICAL length). Also added
      utxo_struct_size to utxo_twin.c (was missing). Gates: upstream
      test_utxo_store + test_utxo_wal_buffer (42503-record self-drain) +
      test_utxo_torn_tail ALL GREEN native; 124-record differential
      byte-identical vs x86 on .242 -- retval stream AND utxo.dat/utxo.idx
      files (duxst.c + gen_duxst_vecs.py: 40 puts w/ script lens
      0/1/24/255/320/1690, dels, gets, count, full-WAL reload,
      checkpoint+tail reload, second sync+tail, closes).
      TWIN BUGS THE GATE CAUGHT: (1) torn-tail gate must fire on the
      FAILING-RECORD START (a `torn` flag + rec_start vs log_end), else an
      unknown-op record is skipped (consumed already advanced) and a clean
      WAL's last record gets truncated -- both caught by test_utxo_torn_tail;
      (2) utxo_get's out pointers are 8-byte unsigned long (asm ABI) -- a
      4-byte out got its neighbor smashed (test_utxo_store's height checks).
      DRIVER NOTE: x86-side duxst needs static get-outs (gcc -O2 stack-local
      outs corrupted the value slot with the upstream asm; osx twin + statics
      agree byte-for-byte). Commits 55c76deb (+ utxo_struct_size in utxo_twin).
- [x] bitcoin_utxo_lsm -> port/osx/utxo_lsm_twin.c  DONE 2026-09-09 as a
      C TWIN (memtable flush -> sorted MAGIC_RUN3 runs w/ 3-seed bloom +
      64-record sparse index; UMAN/UMN2 manifest w/ tmp+fsync+rename+dirsync;
      multi-run get newest-index-first bloom-gated sparse-accelerated;
      k-way merge recount/compact/compact_range/walk; tombstone O(1) hash;
      radix or merge sort via set_sort_mode; WAL tier delegated to
      utxo_store_twin -- lst layout is utxo_store's exactly). The upstream
      asm/utxo_lsm_mm.c mmap fast path is vendored byte-identical, DEFAULTED
      OFF on macOS: byte-identical file, but 8-thread concurrent gets fail
      under clang-21/arm64 while single-threaded mm lookups are byte-correct
      and the twin fallback passes everything including concurrently
      (documented in the file; root cause unpinned, correctness anchor is
      the twin path). Gates: upstream test_utxo_lsm + test_lsm_flush_sparse
      + test_lsm_mmap_diff + test_lsm_sparse_diff + test_lsm_bloomsat +
      test_lsm_lost_tombstones ALL GREEN native; 229-record differential
      byte-identical vs x86 bitcoin_utxo_lsm.o -- retval stream AND the
      full file set (utxo.dat, utxo.idx, utxo_manifest.dat, every
      utxo_run_*.dat) (dlsm.c + gen_dlsm_vecs.py: 120 puts w/ script lens
      0/12/33/255/20, dels w/ older-run shadowing, reload, explicit flush,
      compact, post-compact reload+gets). test_lsm_count_drift deferred to
      p3 (needs the full REORGOBJS module set). Commit b65c12e1.
- [x] bitcoin_bip143 -> NO PORT NEEDED  DONE 2026-09-09.  The x86 asm module
      is only the differential harness's perf twin; production
      (bitcoin_witness_v0.c, bitcoin_scriptverify.c) calls bitcoin_segwit.c
      directly -- arch-neutral C, compiles unchanged on Darwin.  Gate (all
      native): port/osx/tests/test_bip143_osx.c (BIP143 published example
      digest c37af311..; real block-481824 tx 562 fixture sighash 32f2913c..
      with the actual witness signature verified through ecdsa_twin under
      that sighash; swtx_parse contract) + 1,635-vector corpus
      (gen_b143_corpus.py) dumped via validation/bip143_corpus_dump.c:
      osx-C == x86-C == x86-ASM byte-for-byte on .242.  ABI note: the C
      takes the BARE scriptCode and writes the compactsize itself; the
      prefixed 1976a914.. form is the Python oracle's convention.  Hand-
      transcribed fixture hex had TWO silent copy errors -- fixtures must
      be generated programmatically.  Commit 93b6cfca.
- [x] bitcoin_script -> port/osx/script_twin.c  DONE 2026-09-09 as a C TWIN
      (der_parse_sig with Core's ecdsa_signature_parse_der_lax shape --
      long-form SEQUENCE length skipped unchecked, long-form INTEGER length
      bytes leading-zero-skipped + >=4 rejected + BE accumulated, any number
      of redundant 0x00s stripped to <=32; be_to_limbs; verify_p2pkh with
      the IR-10 bounded walk, IR-2 hashtype-pop, direct pushes only).
      Gates: test_script + test_p2pkh green native (test_ir10 deferred to
      the interp wave: needs bitcoin_interp/scriptcodec); 18.7 KB cross-arch
      differential byte-identical vs .242 (dscript.c + gen_dscript_vecs.py).
      The differential caught a REAL twin bug the short-form-only upstream
      harnesses missed: der_long_len re-masked the first length BYTE as the
      count instead of the header's low 7 bits.  Commit 93b6cfca.
- [x] secp256k1_taproot -> port/osx/taproot_twin.c  DONE 2026-09-09 as a C
      TWIN (tagged_hash256, tap_branch_hash with cmpsb ordering, tap_leaf_hash
      with the TAP_PREIMG_CAP-70 bound, taproot_tweak_pubkey returning 1 even
      / 2 odd with the parity captured before even-normalising, tap_merkle_root
      over control siblings innermost-first, count ignored as on x86; lazy
      __thread 4 MiB tap_preimg replaces the .tbss).  Gates: upstream
      test_taproot ALL PASS native; 227-record cross-arch differential
      byte-identical vs x86 on .242 (dtap.c + gen_dtap_vecs.py: tags/msgs to
      200 KB, leaf compactsize boundaries 0xfd/0x10000, tweak rejections
      x>=p/t>=n, merkle paths depth 0..8 mixed orderings).  Commit 871200f3.
- [ ] bitcoin_bip341, bitcoin_bip342 (bitcoin_taproot_sighash.c is
      production arch-neutral C like bitcoin_segwit.c and needs this twin
      at link time; its harness test_taproot_sighash pulls
      bitcoin_interp/scriptcodec/sha1 -- gate lands with the script VM wave)
- [x] bitcoin_sighash -> port/osx/sighash_twin.c  DONE 2026-09-09 as a C
      TWIN (sighash_all, legacy_sighash with every legacy hashtype x
      ANYONECANPAY incl. the SIGHASH_SINGLE out-of-range uint256(1) quirk
      and OP_CODESEPARATOR stripping via script_find_and_delete(0xab),
      script_op_len/script_push_encode/script_find_and_delete,
      legacy_sighash_scfbuf as __thread[20000] replacing the x86 .tbss TLS;
      every bound check / unchecked raw copy of the x86 transcribed as-is).
      Gates: test_sighash green, test_legacy_sighash 500/500 Core
      sighash.json vectors, test_find_and_delete 23/23, test_sighash_oob
      rejection -- all native; 143 KB cross-arch differential byte-identical
      vs x86 (120 random txs x both builders x 11 hashtype classes,
      per-stage truncations, SINGLE quirk, ACP shapes, zero-output tx,
      PUSHDATA1/2/4 forms incl. truncated headers, all push length classes,
      needle present/absent/repeated/malformed; drivers port/osx/tests/
      dsighash.c + gen_dsighash_vecs.py). Commit 404f968b.
- [ ] bitcoin_interp, bitcoin_scriptcodec, bitcoin_script_flags,
      bitcoin_script, bitcoin_multisig
- [x] bip32 family -> port/osx/bitcoin_keys.S + bitcoin_addr.S +
      bitcoin_bip32.S  DONE 2026-09-09 as native AArch64 asm (all three).
      - bitcoin_keys.S: scalar_small_nonzero (byte-wise n compare; the x86's
        k==n falls-through-to-1 quirk transcribed verbatim and noted in-file)
        + scalar_to_pubkey (BE->4 LE limbs, CT ladder via point_scalar_mul_ct,
        affinize z2/z3/inv2/inv3, compressed serialize). Gates: test_keys
        6/6 native + 647-record cross-arch differential byte-identical
        (compare-lattice edges: first-differing-byte walks, n-1/n/n+1,
        600 random + curve-edge to_pubkey scalars incl. 0/n/n+1; dkeys.c +
        gen_dkeys_vecs.py). Commit 3db7bd97.
      - bitcoin_addr.S: hash160 (sha256_full + ripemd160) + base58check_encode
        (zcount '1's, div-58 digit loop with udiv/msub, paylen 0..78 with the
        >78 and unsigned-negative refusal writing out[0]=0 only). First cut
        parked the out cursor in x11 and the digit-emit temps zeroed it
        (w-write destroys the parked x -- the recurring pitfall); cursor
        moved to callee-saved x22. Gates: test_addr 5/5 native + 56-record
        cross-arch differential byte-identical (hash160 lengths 0..1000,
        base58check paylen edges 0/1/4/5/20/21/25/64/78 x zero/random/
        end-nonzero payloads, 78-byte extended-key shape, refusal shapes;
        daddr.c + gen_daddr_vecs.py; driver's 64-byte out window raised to
        the callers' real 128). Commit 1092ebee.
      - bitcoin_bip32.S: bip32_master (HMAC-SHA512 "Bitcoin seed"),
        bip32_ckd_priv (hardened 0x00||k vs ser256(K_par) data, IL range
        gate, (IL+kpar) mod n byte-wise carry/borrow chains),
        bip32_derive_path (in-place walk of native-endian u32 indexes),
        bip32_fingerprint (HASH160[0..3]), bip32_extkey_serialize (xprv/xpub
        payload; key/keylen arrive in x6/x7 -- AAPCS64 passes eight args in
        registers where x86 SysV spills 7/8 to the stack). Port bugs the
        gates caught: the 33-byte pub temp overran ckd_priv's local
        reservation into the save area (the x86 module's own documented
        FINDING class); the add/sub loops skipped byte 0 (post-decrement
        cbnz bound), leaving the carry INTO byte 0 in w9 -- a phantom 257th
        bit -- plus a stale sum[0]; both rewritten countdown-from-32.
        Gates: test_bip32_master, test_bip32_chain (full vector-1 chain m
        .. m/0'/1/2'/2/1e9), test_bip32_extkey (BIP44/BIP84 receive paths,
        xprv/xpub/address), test_bip32_ckdpub (12 checks through the
        wallet_core link) ALL GREEN native; 990-record cross-arch
        differential byte-identical (masters over seed-length classes,
        ckd_priv over edge scalars x index classes incl. zero/all-ff kpar,
        60 random paths, fingerprints, extkey serializations; dbip32.c +
        gen_dbip32_vecs.py). Commit 5cfccf4d.
      - FOUND BY THE BIP32 DIFFERENTIAL DRIVER, FIXED IN PLACE:
        bitcoin_hmac.S used x25 as its concat-buffer base WITHOUT saving it
        (x24 was saved; x25 is callee-saved) -- main's GOT anchor died at
        the next ldr [x25] after any hmac_sha512 call. Latent until dbip32
        (no earlier caller parked x25 across the call). Prologue/epilogue
        now save/restore x25,x26; test_hmac re-verified green. Same commit.
      - test_bip32_master.c itself had UB: sscanf %2x into
        (unsigned*)&kg[i] writes 4 bytes into a 1-byte slot, spilling 3
        bytes into adjacent frame vars -- under clang's arm64 layout those
        zeroed kg[0..2] and the caller's c[0..2] AFTER the fill (the k/c
        outputs were correct all along; x86 gcc layout hid it). Fixed to
        the unsigned-temp pattern test_bip32_chain.c already uses;
        verified green natively AND on .242.
- [x] bitcoin_chainwork -> port/osx/chainwork_twin.c  DONE 2026-09-09 as a
      C TWIN (compact_to_target_le, u256_div, block_work, chainwork_add/cmp,
      store_chainwork_init/append/get_at -- the chainwork.dat layer).
- [x] bitcoin_muhash -> port/osx/muhash_twin.c  DONE 2026-09-09 as a C TWIN
      (num3072 p=2^3072-1103717 48xu64 LE limbs, muhash_to_num3072 via
      SHA256+ChaCha20 keystream, insert/combine/finalize, the generic and
      stat layers on top).
- [x] bitcoin_utxo_stats -> port/osx/utxo_stats_twin.c  DONE 2026-09-09 as
      a C TWIN (struct layout offsets identical to x86 -- tests poke them
      directly: TXOUTS/AMOUNT/BOGOSIZE/UNSP_*/RAW_N/ZEROH/WANT_MUHASH/
      EXCL_GENESIS/GENESIS_N/ACC/MUHASH). Gates for the three: upstream
      test_chainwork 0 failures + test_muhash ALL GREEN native (Core-oracle
      vectors); asm/tests/test_tmpdir.h added as the Darwin test-harness
      shim (mkdtemp vs the x86 fixed tmp paths) + bench_muhash guards.
      Commit 50526b34.
- [x] bitcoin_utxo -> port/osx/utxo_twin.c  DONE 2026-09-09 as a C TWIN
      (in-memory UTXO set, 48B slots, FNV-1a over the first 8 txid bytes
      xor index, blob arena; struct offsets from the x86 listing).
- [x] bitcoin_store_fast -> port/osx/store_fast_twin.c  DONE 2026-09-09 as
      a C TWIN (read-cache layer on the store struct: FDC magic +8-slot
      fd cache LRU-by-slot + mmap layer). bitcoin_store's own twin was born
      in this commit and completed in a253ef93. Gates: test_utxo 0 failures
      + test_store 0 failures native, bench_store_read byte-exact through
      the fd-cache and mmap layers. Commit b611922b.
- [x] bitcoin_cons -> port/osx/cons_twin.c  DONE 2026-09-09 as a C TWIN
      (cons_verify: pow_check + compact-size tx count + every tx parses and
      txids (cap 1 MiB) + tx[0] coinbase n_in==1 + exact txid-list fill +
      merkle root match + no duplicate-txid mutation flag). Gate: upstream
      test_cons ALL GREEN native (re-verified 2026-09-09 in this session).
      Commit 5b7f679f.
- [x] bitcoin_headers -> port/osx/headers_twin.c  DONE 2026-09-09 as a C
      TWIN (hst_init/reload/append/get_at/count over the 112-byte-record
      headers.dat; hst_append returns the new count). Gate: upstream
      test_headers ALL GREEN native -- each stored entry's block_hash links
      to the next entry's prevhash (re-verified 2026-09-09 in this
      session). Commit 9f112d91. Full IBD-path pairing with net_twin
      completed 2026-09-09 (see OSX_STATE).

## Phase 2 — syscall-carrying modules (Darwin syscall rework)
Heavy svc counts from the x86 .asm (measured 2026-09-09):
- [x] bitcoin_store (51), bitcoin_utxo_store (31), bitcoin_utxo_lsm (65)
      (store/utxo_store/utxo_lsm landed as C twins through Darwin libc;
      the raw-svc tiers are subsumed -- the twins own these modules now)
- [ ] bitcoin_idxscan (19), bitcoin_undo (17), bitcoin_store_fast (15)
- [x] bitcoin_net (9: raw-socket syscalls, x86 arg4-in-R10 -> Darwin x3),
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
