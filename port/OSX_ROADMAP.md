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
- [ ] secp256k1_point / _point_ct / _glv_c / _ecdsa
      (+ _taproot/_schnorr when upstream main carries them)
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
- [ ] bitcoin_sighash, bitcoin_bip143, bitcoin_bip341, bitcoin_bip342
- [ ] bitcoin_interp, bitcoin_scriptcodec, bitcoin_script_flags,
      bitcoin_script, bitcoin_multisig, bitcoin_cons
- [ ] bitcoin_chainwork, bitcoin_muhash (compute parts), bip32 family

## Phase 2 — syscall-carrying modules (Darwin syscall rework)
Heavy svc counts from the x86 .asm (measured 2026-09-09):
- [ ] bitcoin_utxo_lsm (65), bitcoin_store (51), bitcoin_utxo_store (31)
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
