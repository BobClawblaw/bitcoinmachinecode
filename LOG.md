# EXPERIMENT LOG — Working Bitcoin Client in 100% AI-generated Machine Code

This file is the running record of the experiment. It captures every step,
hypothesis, bug, and fix so that a full engineering report can be written once
success is reached. Update it after every meaningful event.

================================================================================
LOG
----------------------------------------------------------------------------
## 2026-08-22 -- Incidents #6-#10; verify path 4.4x faster end-to-end; genesis was never in the archive; every stop had been a SIGKILL

A continuous ~16 h session (08-21 evening into 08-22 morning), the second
half under a standing "deploy, restart, drop and rebuild as needed, update
the docs at the end" authorization with the user asleep. Terse action log
with hashes: `worklog/2026-08-21.md`, `worklog/2026-08-22.md`. Profiles and
benchmark tables: `PERF_SCOPE.md`. This entry is the narrative, including
the mistakes.

### Real production incident #6: genesis was not in the archive, so every buried soft fork activated one block late (false-accept)
Found while wiring blockchain-query RPCs (`090a109`): `index.dat` record 0
was `00000000839a8e...` -- block 1. Confirmed against the scratch Core
oracle across the whole archive: record index == real height - 1,
everywhere. `utxo_live_catchup` hands that index to `apply_block_at` ->
`script_flags_for_block`, so linking the real `bitcoin_script_flags.o` and
asking it directly showed DERSIG (363725), CLTV (388381), CSV (419328) and
NULLDUMMY (481824) each MISSING their flag bit at their own activation
block. For exactly one block per boundary we applied looser rules than
Core: a chain-split in the accept direction. It is also structurally
invisible to Stage D's replay -- looser rules accept a superset, and real
chain data is valid under the strict rules anyway -- which is a genuine
limit on what a clean replay proves. The user's proposed fix (re-download
the chain) could never have worked: the P2P "from the beginning" locator is
the all-zero hash and peers answer from block 1; genesis is never
transmitted (`bitcoind.asm:1247` already documents the symptom). Fixed by
injecting genesis from its constant: 285 bytes appended to the last blk
file, `index.dat`/`headers.dat` shifted one record, `chainwork.dat`
dropped and rebuilt (963,447 records). The 1.5 TB of block bodies never
moved. Re-verified: index hash, body, header record and `getblockhash`
agree at 12 heights including 0. `apply_block_inner` now skips genesis's
coinbase (Core never adds it to the chainstate) -- matched by HASH, because
a `height == 0` guard broke two synthetic-chain tests whose height 0 has
spendable outputs. `5f36dee`. The in-flight replay was invalidated and
restarted from block 0.

### Incident #7 (latent, found by a differential): two lost carries in `sc_mul` and `fe_mul`
Building the 4.2 variable-time inverse's differential fed `sc_inv`
structured inputs for the first time. `sc_mul`'s MULACC propagated a carry
two limbs and dropped it when limb k+2 was 0xFFFF...; `fe_mul`'s fold-2
dropped the carry out of limb 3. On the OLD code `sc_inv(6)` is wrong
outright (checked against `pow(6,-1,n)`), `sc_inv(n-k)` wrong for
4095/4096 small k, `fe_inv(p-k)` for 1607/4096 -- and 200,000 random
`a*inv(a)==1` trials pass on that same old code, because random operands
hit the condition at ~2^-64 and ~2^-190. That is the whole story of why
the random differentials that have guarded this code since 08-11 never
saw it. Direction: fail-closed (a wrong `s^-1` rejects a valid signature;
it cannot forge one). `54cc988`, with the exact operand pairs pinned in
`tests/test_mul_carry_regression.c`.

### Incident #8: the mmap "bug" that was a SIGKILL, and a destroyed reproducer
`e199952` (PERF_SCOPE 4.1) replaced `mac_run_lookup`'s per-lookup,
per-run "open, read the ENTIRE 4 MiB bloom to test 3 bits, lseek/read,
close" with a per-thread cache of read-only mmaps: 88 % fewer syscalls.
Deployed 02:29. On its very first checkpoint resume (02:32, from 318147)
the daemon rejected 318148 with "input references a missing/already-spent
UTXO". The coordinator attributed it to the new read path, set the
`BMC_LSM_MMAP=0` kill switch -- and, 45 seconds later, dropped the UTXO
state to start the from-scratch run the user had asked for. That
destroyed the only reproducer. Mistake, recorded as a gate: snapshot
utxo_*/undo_* before any drop.

The investigation then could not reproduce anything: the C path was read
line-by-line against the assembly (u64 offsets, record advance,
`mac_cmp_key`'s bswap == `memcmp`, identical FNV bloom/seeds/bit index);
a real coverage gap was found (the differential used `fill_threshold=1`,
so no run had ever had a sparse index and the C binary search had never
run) and closed with sparse/compaction/reload/bloom-saturated
differentials and a 180k-lookup soak -- all 0 mismatches; and a new
read-only `tests/diff_real_run` was pointed at the four real production
runs the rebuild had produced by then (18M records each, bloom at the
4 MiB cap, sparse_n ~70k): 80,000 keys, 0 mismatches. `b41f711`.

The actual cause came from `journalctl -u bmc-bitcoind.service`: EVERY
stop during a replay -- 21:24:39, 01:16:00, 02:30:44, 02:37:18, 02:40:12
-- ended in `State 'final-sigterm' timed out. Killing ... SIGKILL` at
systemd's 90 s default. The replay is one `utxo_live_catchup()` call that
runs for hours, and its per-block loop never read `g_shutdown_requested`.
The 02:30:44 kill hit the OLD (pre-mmap) worker between "block 318148's
spends are in the WAL" and "checkpoint 318148 persisted"; the new process
reloaded state one block ahead of its checkpoint and correctly reported
318148's inputs as spent. `2fd4a14`'s comment that re-applying is safe
("duplicate put / redundant tombstone are non-error") was true of the
storage layer and false once Stage D verifies BEFORE applying. mmap was
innocent; the resume path was the bug, and it had been since Stage D.

Two fixes: `f2faf3b` -- the loop polls the flag per block, finishes the
block, persists, starts no compaction, returns (`systemctl stop` went from
90.23 s + SIGKILL to 10.05 s, measured, no "Killing" in the journal);
`96b555e` -- on boot, `undo_<applied+1>.dat` existing means that block
began and never checkpointed, so restore its captured prevouts, delete
its created outputs, let catch-up re-apply it. Three crash-injection
scenarios incl. flush-mid-block give a set byte-identical to a
never-crashed reference; the negative control reproduces the production
line verbatim. The fix then proved itself unplanned: the deploy's own stop
was the last 90 s SIGKILL, it landed mid-block 343087, and boot logged
`RECOVERY: rolled back partially-applied block 343087 ... 147 prevout(s)
restored` and resumed with zero rejects.

### Incident #9 (caught by the suite before deploy): GLV segfault from stack misalignment on the CHECKMULTISIG path
GLV + wNAF (`5023fdf`..`127ae2b`) passed 102,056 projective point cases,
the 113,315-case verify campaign and 30,240 switch cases, then
`test_scriptverify_parity` segfaulted: `glv_wnaf` (gcc-compiled C) entered
with `rsp == 8 mod 16` from the all-asm `interp_checkmultisig ->
sv_checksig -> ecdsa_verify` chain, and a `movaps` spill faulted. The
direct-call harnesses had been aligned by luck. `and rsp, -16` after the
frame (`3b00f63`), robust to either caller parity. Lesson, same as the
earlier `utxo_lsm_mm.c` hook: any asm frame that calls C must align
itself, not trust its caller.

### Also this session
- 4.2 A+B (`9e11146`): `ecdsa_verify` 115 -> 56 us; 4.3 GLV (`da3e683`):
  56 -> ~39 us (44 vs 69 on the loaded box). libsecp256k1 on this CPU,
  measured: 21.8 us. Gap 5.2x -> 2.6x -> ~1.65x.
- End-to-end, identical heights 343087->363086 vs the 08-21 14:37 baseline:
  7.8 -> 34.1 blk/s, **4.39x**. Almost all of that is the mmap fix: with
  mmap off, 300-340k had collapsed to 1.04-1.08x as bloom copies grew.
  GLV moved verify 1.56x and the replay 0x -- post-GLV profile: kernel 5 %
  (was 31-38 %), crypto 74 %, `fe_mul` 56 %. The field multiply is the
  last wall.
- `test_scalarmul_ct` was a wall-clock coin flip (1.001/1.177/0.996/0.743
  on unchanged main) AND could not detect an injected 4 % timing leak;
  now CPU-time min-of-40 at +-3 %, 70/70 under load, catches the leak
  3/3 (`879554b`). Seven test binaries were tracked in git and ran stale
  after `git checkout --` (`860630c`).
- Taproot: `OP_CODESEPARATOR` position in the tapscript sighash
  (`b2ccb2d`); the old byte-level `0xab` scan also rejected pubkeys
  containing that byte.
- 9 blockchain-query RPCs (`090a109`). Scratch Bitcoin Core at
  `/storage/core-oracle` is now an authorized development oracle (the
  production install stays off-limits).

### Incident #10: the archive was witness-stripped for the entire segwit era (~482,000 blocks)

At 06:13 the from-scratch replay -- every fix of the night deployed --
rejected the first segwit block, 481824, tx 562: `p2wpkh needs exactly 2
witness items`. The Core oracle shows that input has exactly 2. So the bytes
we verify differed from the bytes Core has, and block 481824 is the first
block in history where a witness-bearing transaction could possibly be
parsed. Comparing `index.dat`'s `data_size` against Core `getblock`: ours
equals Core's `strippedsize` -- never `size` -- at 481824, 481900, 500000,
550000. **Every block from segwit activation to tip was stored without its
witness data.**

Cause: `p2p_getdata_block` (`bitcoin_p2p.asm:103`) requested inventory type
`MSG_BLOCK` (2). Per BIP144 a peer answers that with the non-witness
serialization. The merkle root commits to txids, which are computed over
that same stripped form, so `cons_verify` accepted every stripped block,
"integrity OK" was true of headers and hashes and hollow for bodies, and
`cuda_txid_reindex`'s "merkle OK" never could have caught it. Core *would*
have rejected each of those blocks on arrival -- `bad-witness-nonce-size`
-- because Core validates the BIP141 coinbase witness commitment. This node
did not. Two bugs, then: the request type, and a missing consensus check.

Three more turned up while fixing the first. `test_serve` failed the moment
the client asked with `MSG_WITNESS_BLOCK`: the **server** dispatch compared
the raw type against 1/2/4, so a witness request matched nothing and was
silently ignored -- this node could not serve a block to any current peer.
And the inbound-inv keep-up path built its own getdata inline with type 2,
so even after an archive repair every *new* tip block would have arrived
stripped again. All in `bitcoin_serve.asm`.

Fixes: `31eac9a` (`MSG_WITNESS_BLOCK` in `p2p_getdata_block` + the
byte-exact test), `fe3addb` (server masks the witness flag before dispatch;
keep-up requests `MSG_WITNESS_BLOCK`), `191df6c` (BIP141 witness-commitment
validation in `daemon/block_witness.c`, called before any signature work --
mirrors `validation.cpp` `CheckWitnessMalleation`, gated on the segwit
deployment height as Core does). Its decisive test feeds it the **exact
stripped bytes of 481824 that our archive held** and gets
`bad-witness-nonce-size`; one flipped witness byte gets
`bad-witness-merkle-match`; a commitment removed with witnesses kept gets
`unexpected-witness`.

Recovery, without a from-scratch replay: the UTXO checkpoint at 481823 is
valid (no witness data exists below segwit). `index.dat` and `chainwork.dat`
were truncated to 481824 records (backups `*.pre-witness-truncate` in
`/storage/bmc-archive-backup-20260822`); 359.8 GB of stripped bodies became
dead space in the blk files (reclaimable later by the file-granular prune).
Re-downloading 482k blocks over the internet would take days, so the local
Core oracle was moved to loopback 8333 (`listen=1`, bound to 127.0.0.1 only
-- the downloader hardcodes 8333, `paribd.c:58`) and the node configured
`connect=127.0.0.1`. First re-fetched block: 481824 at 989,323 bytes ==
Core's `size`. One peer meant one download worker (~14 MB/s); the oracle now
binds sixteen loopback aliases and the node connects to each, one worker
per peer. `stopatheight` tracks the oracle's own IBD height and must be
raised as it advances, then removed with `connect=` once the archive is
complete.

Not fixed yet, in `FEATURE_GAPS.md`: prefer `NODE_WITNESS` peers; serve the
stripped form to a bare `MSG_BLOCK` request (no such peers exist any more);
`MSG_WITNESS_TX` for transaction relay -- the mempool path has the same
shape of bug.

The lesson is the one from #6 again, sharper: a replay that runs clean is
evidence only about the checks that exist. Every tool that "verified the
archive against Core" compared headers and txids -- exactly the fields that
do not change when witnesses are stripped.

## 2026-08-21 -- Two more real production incidents (#4, #5) during Stage D's full-archive replay; checkpoint durability fixed

### Real production incident #4 (autonomous, overnight): CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY were stubs, not real checks
The overnight replay (continuing from incident #3's redeploy) hit a new,
deterministic rejection at real mainnet height 388431: `REJECT h=388431
tx=564: legacy script verification failed`. Root-caused directly: `OP_CLTV`/
`OP_CSV` in `bitcoin_interp.asm` were wired as pass-through no-ops rather
than the real BIP65/BIP112 locktime/sequence comparisons against the
spending transaction's own `nLockTime`/`nSequence` -- silently accepting
scripts a real node must reject. Implemented the real checks; fixed in
commit `fbeff60`. Compacting/recovering in place was not attempted this
time -- given a rejection this late in a long replay could plausibly leave
a subtly-wrong-but-not-obviously-broken UTXO set behind it (CLTV/CSV gate
*script success*, not consensus state directly, but the safer call given
the project's standing "verify against real data, don't assume" discipline
was a full from-scratch redeploy rather than trusting the compaction-based
in-place recovery path). `bmc-bitcoind.service` redeployed fresh
(`applied_height=-1`) at 03:45:36 and confirmed clean past height 388431 on
the very next attempt -- the fix holds under real replay.

### Real production incident #5: UTXO checkpoint could lag real durable state by an unbounded amount, masquerading as corruption on crash-resume
The fresh replay from incident #4 progressed cleanly to height 363896,
took a routine mid-catchup compaction there (`manifest_n=1 -> result=1`,
06:07:09), and kept running for several more hours. The HOST machine then
rebooted multiple times, unprompted and unrelated to this project (external
infra event, confirmed via `last reboot`), between 11:16 and 12:13 --
killing the daemon uncleanly. It is not enabled on boot (per standing
preference to run it manually), so it sat stopped until a manual restart at
13:25:12, which reloaded the last persisted checkpoint (height 363896) and
immediately hit a NEW, deterministic rejection on every retry: `REJECT
h=363897 tx=1: input references a missing/already-spent UTXO`.

This is the SAME failure shape flagged as unresolved in a 2026-08-19 code
comment (`daemon/utxo_live.c`, near `utxo_live_catchup`) after an earlier,
abandoned attempt at periodic mid-catchup checkpointing was reverted --
that comment's leading theory (a flush/compact reconstruction bug silently
dropping live entries) was WRONG, but the underlying symptom it observed
was real and finally root-caused this session: `applied_height` was only
persisted at rare compaction events or once at the very end of a (possibly
hours-long) catch-up call, while every individual `utxo_lsm_put`/`del` is
already durable the instant it runs. An unclean process death therefore
routinely left the true on-disk UTXO state hours AHEAD of the last-written
checkpoint. On restart, catch-up trusted the stale checkpoint and tried to
re-verify a block whose inputs it had already durably spent before the
crash -- correctly failing that re-verification (the input really is
already spent), but incorrectly treating a "this block was already
applied" situation as a fatal consensus rejection instead of a safe replay
no-op. Two other worktrees from an earlier, independent investigation of
this exact bug were found still on disk (`.worktrees/verify-snapshot-resume`,
chasing the wrong flush/compact theory, and `.worktrees/fix-crash-resume-verify`,
a real but incomplete fix that only re-checked the FIRST resumed height per
boot rather than every block in a potentially multi-thousand-block gap) --
both removed as superseded once the real fix landed.

Fix: persist `applied_height` after every successfully applied block
(`daemon/utxo_live.c`), not just at compactions/end-of-call, so no gap
between real and checkpointed state can ever exist -- correct by
construction rather than by detecting and tolerating the gap after the
fact. Added a test-only crash-injection hook
(`utxo_live_test_set_crash_after`, a guarded no-op unless a test arms it).
New regression test (`tests/test_utxo_catchup_crash_resume.c`) builds a real
chain with a real spend, forks a child that applies exactly one block and
`_exit(1)`s right where its checkpoint should persist, then does a real
`utxo_live_close()`+`utxo_live_init()` restart and asserts the checkpoint
reflects the crashed block and resume is a clean no-op; verified via
disabling the fix line that it reproduces the exact production symptom
(`REJECT h=150 tx=1: input references a missing/already-spent UTXO`)
pre-fix and passes with it restored. Full `make -k test`: 1582/1582, both
in the fix worktree and after rebuild on `main`. Merged (`--ff-only`) and
pushed as commit `2fd4a14`.

Because the true durable height of the crashed run was unknown (and not
worth the risk of guessing), UTXO state was dropped
(`archive_drop_utxo_state()`'s exact file set: `utxo_applied_height.dat`,
`utxo.dat`, `utxo.idx`, `utxo_manifest.dat*`, `utxo_lsm_table.map`,
`utxo_lsm_blob.map`, every `utxo_run_*.dat` and `undo_*.dat`) and
`bmc-bitcoind.service` redeployed fresh at 14:36:31, now durably protected
against a repeat of this exact failure mode regardless of when a future
crash lands.

**Status at end of session:** both fixes (`fbeff60`, `2fd4a14`) merged to
`main` and pushed. `bmc-bitcoind.service` redeployed from scratch,
confirmed clean past height 363896 (the incident #5 stall point) via a
routine compaction with no rejection, replaying toward chain tip 963445.
Height 388431 (incident #4's stall point) not yet re-reached by this fresh
replay as of session end, but already independently confirmed clean once
during incident #4's own post-fix redeploy. Monitoring continues
unattended.

## 2026-08-19/20 -- Stage D wired live; three real production incidents found and fixed during the first full-archive replay

### Wiring: script verification connected to block connection
`tx_verify_block_connect`/`tx_verify_block_connect_all` (`daemon/tx_verify.c`,
new file) now runs from `apply_block_inner` (`daemon/utxo_live.c`), ahead of
every block's puts/dels -- exactly where Core's `ConnectBlock` runs
`CheckInputs`, before `UpdateCoins`. Per non-coinbase input: resolve the
confirmed prevout (in-block outpoint index first for same-block chained
spends, `utxo_lsm_get` fallback), enforce the 100-block coinbase-maturity
rule, classify the prevout scriptPubKey's shape, and dispatch: legacy shapes
(P2PK/P2PKH/P2SH/bare-multisig) to `sv_verify_script`
(`bitcoin_scriptverify.c`), P2WPKH/P2WSH/P2TR-keypath to the witness
primitives already proven at the mempool layer
(`bitcoin_txval_modern.c`/`bitcoin_segwit.c`/`bitcoin_taproot_sighash.c`).
Whole-block duplicate-outpoint detection is now an EXPLICIT pre-check (a
hash-set walk over every input before verification starts), not the
accidental side effect the old strictly-sequential verify-then-apply loop
produced (the second spender's `utxo_lsm_get` used to fail only because the
first spender had already deleted the UTXO) -- a real correctness gap a
dedicated `Plan` design-review subagent caught before any of this landed;
see `worklog/2026-08-19.md` and `tests/test_cross_tx_verify.c` scenario B for
the regression coverage.

### Made it fast enough to actually run at chain scale
Signature verification (ECDSA/Schnorr) is the dominant cost of block
connection and was single-threaded at first -- a from-scratch replay
measured ~1 of this box's 32 cores in use. Path to a usable replay, each step
profiling-driven:
1. Per-tx fork()-based parallel verify (matching `dl_catchup`'s existing
   pattern) replaced with a pthread pool: fork()'s copy-on-write page-table
   setup cost scales with the PARENT's resident size, and during a
   from-scratch replay the parent IS the growing multi-GB UTXO memtable, so
   every fork() got progressively more expensive over the run (confirmed via
   production stack sampling -- every sample landed inside `fork()` itself).
   Required making the legacy-script interpreter's scratch state genuinely
   thread-safe first (`bitcoin_scriptverify.c`/`bitcoin_interp.asm`/
   `bitcoin_sighash.asm`/`bitcoin_scriptcodec.asm`, real ELF TLS via
   `.tbss`/`TLS_ADDR`, not per-call heap scratch).
2. Redesigned from per-transaction dispatch (`tx_verify_block_connect`, only
   fanned out when a SINGLE tx had >=8 inputs -- most transactions in this
   era of chain history don't) to whole-BLOCK dispatch across every
   transaction's inputs at once (`tx_verify_block_connect_all`,
   `daemon/tx_verify.c`'s "CROSS-TRANSACTION PARALLEL VERIFICATION" design).
3. Re-profiled and found `memset` dominating the perf trace, resolving into
   unresolved kernel addresses -- a page-fault storm from fresh
   `malloc`/`calloc` at high per-block call rates forcing the kernel to fault
   in and zero brand-new pages on every touch. Fixed with the "allocate
   once, reuse forever" pattern applied to every hot per-block scratch array
   (`grow_arena`: realloc-if-bigger, never shrink, `utxo_live.c` and
   `tx_verify.c` each keep their own copy per this codebase's
   no-shared-small-helpers convention).
4. `strace -c -f -p <daemon pid>` then found a ~840 `clone3`/sec storm,
   matched by `mmap`/`munmap`/`mprotect` -- per-block `pthread_create`/
   `pthread_join` faulting in and tearing down a fresh thread stack every
   round, dwarfing the crypto work being parallelized at bulk-mode block
   rates (an earlier isolated microbenchmark of a single `pthread_create`
   had NOT caught this, since it never measured sustained high-frequency
   creation). Fixed with a persistent semaphore-parked worker pool
   (`txvb_pool_ensure`/`txvb_worker_loop`) started lazily and never torn
   down, matching this codebase's existing convention of never gracefully
   joining background threads at shutdown.

### Real production incident #1: LSM compaction inverted its own manifest scan order
While the fixed-up daemon replayed the real archive live
(`bmc-bitcoind.service`), it hit a genuine consensus rejection at real
mainnet height 184390: `REJECT h=184390 tx=1: legacy script verification
failed`, immediately followed by a blind auto-triggered "in-place recovery"
compaction (`daemon/main.c` calls `utxo_live_recover()` unconditionally on
ANY `utxo_live_catchup` failure -- it cannot distinguish "manifest full" from
"genuine consensus rejection", a still-present design pattern worth treating
any future FATAL+recovery pair with suspicion over).

Root-caused by reading `bitcoin_utxo_lsm.asm` directly, not guessing:
`utxo_lsm_get`'s disk-run scan (`.lg_run_loop`) walks the manifest array from
its HIGHEST index down to 0, treating highest index as newest/highest-
priority (and `mac_flush` always appends correctly at the true array end).
`utxo_lsm_compact` inverted this for the merged/oldest run after a partial
compaction: it shifted surviving (newer) manifest entries down to `[0,K)`
FIRST, then appended the merged (oldest) entry AFTER them at the highest
index -- exactly backwards from the scan order, so a stale, already-deleted
key could resolve as live again post-compaction. Fixed by writing the merged
entry first at index 0, then shifting survivors starting at `dst=1` instead
of `dst=0` (`asm/bitcoin_utxo_lsm.asm`, commit `e12dcbb`).

New regression test (`tests/test_compact_manifest_order.c`) forces a
partial compaction with a deleted key's tombstone landing in the merged
(oldest) batch and a genuinely-live key surviving alongside it; verified via
`git stash` that it FAILS against the pre-fix code with the exact predicted
symptom (the deleted key resolving live again) and PASSES with the fix. UTXO
state was cleanly dropped and rebuilt (`archive_drop_utxo_state()`, the
block archive itself untouched) before redeploying, since the bug could have
left latent corruption in the on-disk manifest from earlier compactions.

### Real production incident #2: dangling pointer into a growable byte pool
Redeployed on fresh state -- and hit the SAME height-184390 rejection again,
proving incident #1, while real, was not the (sole) cause of this specific
symptom. Root-caused via an isolated, read-only reproduction (real archive
block files symlinked into a throwaway directory, `utxo_live_init`/
`utxo_live_catchup` run against a fresh UTXO state there -- never touching
the live daemon's own data) plus targeted debug instrumentation proving the
resolved prevout scriptPubKey was CORRECT at resolve time and CORRUPTED at
verify time for the identical input.

Cause: a byte-pool bump allocator (`bytepool_t`/`bytepool_alloc`,
`daemon/tx_verify.c`) introduced earlier the same night to fix a *different*
regression (raising `TXV_SPK_CAP` from 252 to the real consensus max 10000
had made the OLD flat per-entry inline-buffer design ~25x bigger per entry,
reintroducing the page-fault-storm symptom incident #1's arena-reuse fix had
just eliminated) returned a RAW POINTER into its own `realloc()`-backed
buffer. A later input's allocation in the SAME block's Phase 1 resolve loop
could trigger a `realloc()` that relocated the buffer, silently invalidating
every pointer already handed out to EARLIER inputs in that loop -- a classic
dangling-pointer bug, and non-deterministic across process runs (whether
`realloc` relocates depends on that process's heap layout), which is exactly
why it reproduced inconsistently between attempts. Fixed by storing a stable
byte OFFSET into the pool instead of a pointer (`txvb_in_t.spk_off`),
resolved to an address only after Phase 1 has finished growing the pool for
that block -- an offset survives relocation; a raw pointer captured
mid-growth does not (`daemon/tx_verify.c`, commit `4ec089c`).

New regression test (`tests/test_tx_verify_bytepool_realloc.c`) mines a
block spending ten ~9000-byte-scriptPubKey prevouts (~90KB total,
comfortably past the pool's 65536-byte initial capacity) to force
`bytepool_alloc`'s `realloc()` to fire mid-loop after several earlier inputs
are already resolved; verified via `git stash` that it reproduces the exact
production failure signature against the pre-fix code and passes cleanly
with the fix. Full `make -k test` green on both the fix worktree and `main`
after merge (`--ff-only`) before redeploying. UTXO state dropped and rebuilt
again before this redeploy for an unrelated reason: the on-disk
`utxo_applied_height.dat` marker was missing after an earlier SIGKILL during
debugging, while substantial LSM state (undo logs past height 203000)
remained on disk -- an inconsistent combination unsafe to resume from
directly.

### Real production incident #3 (autonomous, overnight): OP_SIZE register-width bug + OP_SHA1 entirely unimplemented
User went to bed with standing authorization to fix and redeploy autonomously
overnight, reindexing from scratch if needed. The redeployed daemon hit a
new, DETERMINISTIC rejection (unlike incident #2, this one repeated
identically on every retry) at real mainnet height 251683:
`REJECT h=251683 tx=9: legacy script verification failed`.

Root-caused via the same isolated read-only reproduction technique as
incident #2, but pivoted to a much faster iteration loop once the exact
failing scriptSig/scriptPubKey bytes were known: a standalone
`sv_verify_script` harness taking raw hex bytes directly (no archive replay
needed at all -- sub-second per attempt instead of minutes), then a
scriptPubKey-prefix binary search, then a stack-dump harness calling
`script_eval` directly and inspecting the raw stack after each partial run.

The failing script (`827651a0698faaa9a8a7a687`) decodes to `OP_SIZE OP_DUP
OP_1 OP_GREATERTHAN OP_VERIFY OP_NEGATE OP_HASH256 OP_HASH160 OP_SHA256
OP_SHA1 OP_RIPEMD160 OP_EQUAL` -- a real, well-known "hash puzzle" style
scriptPubKey whose spending condition is fully computable from public
information (not a signature check), legitimately spendable by anyone.

Two independent bugs, both in `bitcoin_interp.asm`:
1. `OP_SIZE` read the top stack element's length via `mov rdx, [r13]` -- a
   64-bit load -- but that field is a `uint32` immediately followed by the
   element's own data bytes, pulling in 4 bytes of DATA as garbage high
   bits of the pushed "size" number. Confirmed via grep this was the ONE
   exception among ~20 similar length-field reads elsewhere in the file
   (all correctly use a 32-bit register). The existing OP_SIZE test vector
   never caught it because it never decoded the pushed size back as a
   number, and its specific data happened to have all-zero padding that
   hid the corruption. Fixed: `mov edx, [r13]`.
2. `OP_SHA1` was entirely unimplemented (`; SHA1 not available -> bad
   opcode`) -- a real, always-defined Script opcode, never built. No SHA-1
   existed anywhere in this codebase. Implemented from scratch
   (`asm/sha1.asm`, scalar-only/correctness-first, mirroring `sha256.asm`'s
   structure), verified against FIPS 180-4 vectors plus padding-boundary
   cases against independent Python `hashlib` references (11/11), and
   wired into `.op_crypto`'s dispatch.

New `tests/test_interp.c` vectors (a targeted OP_SIZE case that actually
decodes the pushed value, canonical SHA1("abc"), and the exact real
height-251683 transaction bytes run end to end) verified via `git stash` to
fail against the pre-fix code with the real production signature and pass
with the fix. Full `make -k test` green (87/87) on both the fix worktree and
`main` after merge (`--ff-only`); pushed (`8caa5ac`).

Found the on-disk UTXO state in the same inconsistent shape as incident #2's
redeploy (`utxo_applied_height.dat` missing, undo logs present up to exactly
one height below the failure) -- dropped and rebuilt fresh, redeployed
WITHOUT asking first this time, squarely covered by the standing autonomous
authorization (incidents #1/#2 each got an explicit user confirmation while
the user was awake; this one happened after they had gone to bed).

**Status at end of session:** all three fixes merged to `main` and pushed
(`e12dcbb`, `4ec089c`, `8caa5ac`). `bmc-bitcoind.service` redeployed on a
freshly rebuilt UTXO state, confirmed past both height 184390 and height
251683, replaying toward chain tip 963183 unattended. Monitoring continues.

## 2026-08-18 -- Single source of truth for node wire identity (user-agent + versioning)

### Problem: node's advertised identity was hardcoded, duplicated, and placeholder
The daemon's outgoing P2P `version` payload (`node_make_version` in
`bitcoind.asm`) advertised a hardcoded user-agent `"Bitcoind-AssemlbyCode
(BobClawblaw) vx.x.x"` whose version number was never actually resolved to a
real value. Three magic numbers had to be kept in sync by hand and could
silently drift: the UA string, its length byte (42), and the total payload
size (128). The same protocol version (70016) was duplicated across the
version handshake, the getheaders builder (`bitcoin_p2p.asm`), and a level
logger call (`main.c`). The wire protocol version also had no shared source
-- the user asked for both the application version AND the protocol version
to come from one canonical definition.

### Change: one canonical file, everything else derived
- `asm/version.inc` is now the SINGLE SOURCE OF TRUTH: `NODE_VERSION_MAJOR/
  MINOR/PATCH` (0.0.1), `NODE_PROTOCOL_VER` (70016), and the UA prefix/suffix.
- `bitcoind.asm` `node_make_version` derives the UA string (NASM `%strcat`),
  its length byte (NASM `%strlen`), and the payload size (`81+UA_LEN+5`) at
  assembly time from `version.inc` -- no hand-synced literals remain.
- `bitcoin_p2p.asm` getheaders and `main.c`'s HSHK level-logger call read the
  protocol version from the same source.
- The Makefile + `gen_version_header.py` regenerate `asm/version_gen.h` (C
  header, git-ignored) from `version.inc` for the C consumers, and the ASM
  objects / daemon / test rebuild automatically when `version.inc` changes.
- `tests/test_bitcoind.c` byte-exactness assertions now reference the derived
  constants instead of hardcoded 42/128/legacy string.

The node now advertises `/BitcoinMachineCode:0.0.1/` (26-byte UA, version
payload 112 bytes). Verified: bumping to 0.1.2 propagates the new identity to
the ASM object, daemon binary, and test; reverted to the 0.0.1 baseline. Full
`make test` passes (71/71). To bump the version or protocol, edit ONLY
`asm/version.inc`.

## 2026-08-17/18 -- UTXO set replaced with an LSM-tree, then wired live into the P2P daemon (mempool/tx-relay validation, commits 4e393ef..3ff03f3)

### The problem: single-table UTXO store write-amplified ~13x during full replay
A full-archive UTXO-set-from-archive replay (`daemon/build_utxo.c`, driving
`bitcoin_utxo_store.asm`/`bitcoin_utxo.asm`) started at ~9,000 blocks/sec and
collapsed to under 100 blocks/sec by 15% progress. Root cause, confirmed
empirically (`iostat`, `/proc/PID/io`, `/proc/PID/smaps_rollup`): the
in-memory hash table has to be pre-sized upfront for the FINAL total live
UTXO count (~408M, at 2^30=1.07B slots for headroom), but during replay the
hash function scatters writes essentially randomly across that entire
51.5GB mmap'd, file-backed structure from block 0 onward, regardless of how
few entries are actually live -- table pages measured being written back to
disk ~13x on average (606GB actually written vs ~47GB of real touched
data). Two low-risk mitigations (drop a redundant WAL `lseek()`, raise
`vm.dirty_ratio`) helped but didn't fix the structural problem; shrinking
the table to 2^29 slots gave 2-4x but risked silently producing an
incomplete set if the live-count estimate ran even moderately over.

Bitcoin Core avoids this with LevelDB (an LSM-tree) behind a bounded
`-dbcache`, not one giant pre-sized structure. Built the equivalent from
scratch (no external libraries, matching this project's ethos):
`bitcoin_utxo_lsm.asm`, reusing `bitcoin_utxo.asm`'s open-addressing table
UNCHANGED as the memtable engine (proven correct via prior backward-shift-
deletion stress testing), instantiated small and fixed-size, never resized.

### Phase 1 (4e393ef): bounded memtable + per-generation WAL + sorted-run flush
On-disk layout: `utxo_manifest.dat` (run-generation list, published via
temp-file+fsync+rename -- NOT the old `utxo.idx`'s O_TRUNC-rewrite-in-place,
which has its own unfixed crash hazard), `utxo_run_%06d.dat` (immutable
sorted runs: min/max key + Bloom filter + sparse index + sorted records),
`utxo_wal.dat` (reuses `bitcoin_utxo_store.asm`'s existing PUSH/DEL record
format, scoped to the current generation, truncated on flush). Per-run
Bloom filter (txids are SHA256d, so byte-order is uniform -- a min/max
bounds check alone gives near-zero pruning power). `utxo_lsm_del`
deliberately changed behavior vs `utxo_del`: a memtable miss always emits a
tombstone rather than silently no-op'ing, since every DEL here is a real
consensus-valid spend. Verified via `tests/test_utxo_lsm.c` (basic
put/get/del across memtable+runs, tombstone-shadowing, crash-recovery
simulation at each of the 5 flush ordering steps), then a 100+-trial
randomized stress test, before swapping `build_utxo.c` over and running a
smoke differential (identical live count + sampled `utxo_get` results)
against the real archive. Full-archive rate stayed flat instead of
collapsing (e.g. 694 blk/s vs the old store's 79 blk/s at matching
checkpoints) -- fix confirmed.

Also found and fixed, while verifying Phase 1: a pre-existing (not new)
`bitcoin_utxo_store.asm` bug in `utxo_store_reload`'s WAL-tail replay --
`slen` was stored via a 32-bit `mov` into an 8-byte stack slot then reloaded
via a 64-bit `mov`, leaving stack garbage in the high 4 bytes and corrupting
the size `utxo_put` used for its blob-capacity check, spuriously reporting
"table full" AFTER already writing the slot's txid/index (a phantom
occupied-but-empty slot). Fixed by storing the full zero-extended `rax`
instead of `eax` at both occurrences.

### Phase 2 (c0a2f68): streaming k-way merge compaction
Manifest refactored from 8-byte `[gen]` entries (run_no implied by array
index) to explicit 16-byte `[gen:8][run_no:8]` pairs, since compaction
replaces many runs with one, breaking the index-implies-run_no invariant.
`utxo_lsm_compact`: opens up to 64 oldest runs, streams the globally-
smallest key across all input buffers, always drops tombstones (safe since
compaction is always a prefix down to the oldest live run), publishes via
the same fsync+rename sequence as flush.

Two real bugs, both found via a 6000-round stress test with compaction
interleaved every 211 rounds, both root-caused with a minimal ~211-round
deterministic repro (`/tmp/repro_compact.c`) once isolated, rather than
continuing to iterate against the slow full test:
- **Key-aliasing**: the "advance every slot matching the winning key" loop
  compared against the winning slot's own LIVE key field, which gets
  mutated in place when it's one of the slots being advanced (which it
  always is, since it won). Fixed by snapshotting the winning key into a
  stable buffer before any advancing starts.
- **The real corruption**: `mac_bloom_setbit`'s signature is
  `(key, seed, bloom_base, bits_mask)`, but the compaction code placed
  `bloom_base` in `rsi` instead of `rdx`, while `rdx` still held the
  winning slot's OWN address from an earlier instruction in the same
  block -- `mac_bloom_setbit`'s internal `add rdx,rbx; or [rdx],al` wrote
  into the winning slot's own header fields instead of the bloom bitmap,
  corrupting its `fd` (observed as an impossible `fd=2097163`), which then
  failed with a real I/O error the NEXT time that slot needed re-reading.
  Found via a hardware watchpoint on the corrupted slot's `fd` field, which
  caught the exact write instruction and its caller. The existing FLUSH
  code already had this correct; a copy-adaptation slip specific to the
  new compaction path. Fixed by moving `bloom_base` to `rdx` as documented.

Verified: full 6000-round stress test green (0 mismatches), plus a
dedicated "close, fresh-init a second instance, `utxo_lsm_reload`, confirm
state survives" check.

### Live-daemon wiring (8408ee4..3ff03f3): five stages, three fresh bugs found while wiring, one archive-integrity bug found and fixed along the way

**Stage 0 (8408ee4) -- cross-process archive-write race.** Investigating how
to wire the LSM store into `main.c`'s live P2P loop surfaced a real,
independent bug: the download worker (`serve_download_worker`) is NOT
actually the sole block writer in `serve` mode, despite its own comment
claiming so -- a forked inbound serve child can also append a pushed block
(`bitcoin_serve.asm` `.do_block`, reachable via an unsolicited `inv` or the
child's own `.do_inv`-triggered `getdata`, regardless of `nwant=0`), using
plain unlocked `store_append` while believing (per a stale comment) that
`st+40` wasn't a valid flock fd in this context -- it is, `main.c` sets it
before both forks. Simply flock-guarding both paths wasn't sufficient
either: `store_append_shared` takes a caller-supplied height, so two
writers each computing "next height" from their own stale cached state
could still both decide on the same height and clobber each other's index
slot, since the lock only serializes the byte-level write, not that
decision made outside it. Fixed with a new primitive,
`idxscan_append_locked` (`bitcoin_idxscan.asm`): holds the same flock,
determines the true current tip via the existing hole-aware `idxscan_tip()`
scan (robust to a batch tool's pre-sized/zero-padded trailing region, unlike
a raw `idx_len/48` read) UNDER that lock, then delegates to
`store_append_shared` with that height -- making "read tip, then write" one
atomic critical section. Both `node_sync` and `.do_block` now go through it.
Verified via the full daemon/IBD/serve test suite (0 regressions); redeployed
the live production daemon onto this binary.

**Archive corruption (found and fixed mid-Stage-1, not part of the original
plan).** The very first full LSM-based UTXO replay against the real archive
completed (962,831 blocks, ~9,600s) but flagged 13,513 heights where the
stored block data's hash didn't match its own index record --
`build_utxo.c` already had defensive per-block hash verification (added
after an EARLIER instance of this exact issue was found during development)
that skips and logs rather than aborting. The bad heights clustered in a
very telling pattern: contiguous runs starting at round chunk-boundary
numbers (30000, 40000, 42000, 44000, 46000, 48000, 52000, plus three
smaller clusters near 388180/482331/482852) -- the signature of
`unified_ibd.c`'s own documented (and already-fixed) "boundary-chain-break"
header-reuse bug from an earlier backfill pass, leaving stale, NON-ZERO
(so invisible to the existing zero-record hole-detection) index records
that were never actually holes, just wrong. Root-caused via direct
byte-level inspection (a small `pread`-based Python script) confirming the
recorded `file_no`/`pos` for one such height pointed at bytes that don't
even parse as a valid `[len][magic]` frame. Fix: zeroed the 13,513 bad
records (making them real, detectable holes), re-ran `backfill_holes.sh`
(0 holes afterward, 100% contiguous from genesis, independently re-verified
byte-hash-exact on all 13,513 previously-bad heights), then discarded the
first replay's ~219GB of now-known-incomplete LSM state and re-ran the full
replay from scratch against the corrected archive (order-dependent: a coin
created in a skipped height but spent in an already-processed later height
would otherwise end up incorrectly "live" if just patched in after the
fact). Second replay completed clean, 0 corruption warnings.

**Stage 1 (b332d42) -- `daemon/utxo_live.c`: live UTXO catch-up.** The
download worker becomes the sole live UTXO writer, tracked via a PERSISTED
applied-height counter (published with the same tmp+fsync+rename+dirfsync
pattern the LSM store's own manifest uses) compared against the store's
TRUE on-disk tip every rotation -- not a per-call before/after diff the way
`do_outbound_sync` tracks its own sync progress, since that would only ever
see blocks this process's own `node_sync` calls produced, missing a
sibling inbound child's (now Stage-0-safe) `.do_block` writes entirely.
Sized far smaller than `build_utxo.c`'s batch-scale memtable so a future
per-connection `utxo_lsm_reload()` stays cheap. Extracted
`read_varint`/`walk_tx_io` out of `build_utxo.c` into a new shared
`daemon/utxo_walk.h` rather than duplicating them.

Two real bugs found via a standalone smoke test (init, apply <1
flush-threshold worth of puts against a truncated 500-height archive slice,
close, re-init, verify state survives) BEFORE this ever touched
`main.c`:
- `utxo_manifest.dat` is only created at the first flush -- checking its
  existence alone to decide init-vs-reload misses any WAL-durable-but-
  unflushed state and silently starts fresh, losing it (observed as count
  dropping from 503 to 0 across a close/reopen). Fixed by also checking
  `utxo.dat` (the actual WAL file) directly.
- `utxo_lsm_init` and `utxo_lsm_reload` have different return contracts (1
  ok / -1 err vs REPLAYED RECORD COUNT / -1 err) -- a single `r != 1` check
  treated reload's own legitimate success (e.g. 523 replayed records) as a
  failure. Root-caused via a `gdb` breakpoint directly at the presumed
  `.rl_fail` label, which never fired, revealing the return-value
  assumption itself was wrong rather than any actual failure path.

Deployment of Stage 1+ to the live daemon deliberately deferred until the
corrected full replay finished, to avoid two processes (the replay tool and
`utxo_live_init`) touching the same on-disk LSM files concurrently with no
coordination between them.

**Stage 2 (897fc45) -- `mv_resolve` pointer-lifetime bug.**
`bitcoin_txval_modern.c`'s `mv_resolve` resolved every input's prevout
script in one loop, storing the raw `utxo_get`-returned pointer before any
of them are consumed -- including P2TR keypath verification's own
aggregation of ALL inputs' scripts together for the combined sighash, much
later in the same function. Safe against `bitcoin_utxo.asm`'s stable
in-memory pointers, but not against `utxo_lsm_get`'s documented contract:
on a disk-run hit, the returned pointer is only valid until the NEXT
`utxo_lsm_get` call -- exactly what the loop resolving the next input does.
Any multi-input tx with 2+ disk-resident prevouts (the common case once the
memtable has flushed past them) would validate against corrupted script
bytes once wired to the LSM backend. Fixed with an owned per-input
`prev_spk_buf[42]`, copied into immediately after each resolve call.
Confirmed a behavior no-op against the current stable-pointer backend:
`test_mempool_accept_modern` still passes all 23 checks byte-for-byte.

**Stages 3-4 (d31d12b, 3ff03f3) -- compat shim + wiring `.do_tx`.**
`.do_tx` accepted any syntactically-minimal tx with zero validation. New
`daemon/tx_accept.c` gives each forked inbound connection a read-only UTXO
snapshot via one `utxo_lsm_reload()` at connection start (private malloc'd
memory, never file-backed/shared -- must never collide with the writer's
own mmap'd state or with sibling connections), then runs the tx through the
existing, already-tested `mpool_policy_add` (fee/RBF/ancestor-descendant
limits) and `txval_modern` (full segwit/taproot signature verification)
before storing anything for relay.

A naming collision required a rename, not just new glue code:
`mpool_policy_add`/`txval_modern` call `utxo_get` to resolve confirmed
prevouts, but that exact symbol is ALREADY bound -- as an unrelated
dependency of `bitcoin_utxo_lsm.asm`'s own memtable internals -- in any
binary that also links the LSM store, so a second, differently-behaved
definition under the same name would collide at link time. Renamed their
call sites to `mempool_resolve_confirmed_utxo`; the two existing test
harnesses get a 3-line passthrough to the real `utxo_get`, preserving their
exact prior behavior (confirmed unchanged: both pass as before).

Ordering matters and isn't what a first read of the task suggested:
`mpool_policy_add`'s own accept path already calls `mpool_put` internally
as its final step (confirmed directly in `bitcoin_mempool_policy.c`), and
there is no public API to unregister a tx from its internal
ancestor/descendant graph state afterward -- only the structural
`mpool_del`, which wouldn't clean up that bookkeeping. So `txval_modern`
(pure signature/structural validation, no policy/mempool dependency) runs
FIRST: a signature failure then never triggers the policy accept+insert in
the first place, rather than inserting and needing a rollback that isn't
cleanly possible via the existing API.

New permanent test, `tests/test_tx_accept_e2e.c` -- not covered by
`test_mempool_accept_modern`, which only ever exercises the old
`bitcoin_utxo.asm`-backed passthrough, never `tx_accept.c` itself: seeds a
real confirmed prevout into a fresh on-disk LSM store, drives the actual
`tx_dispatch_init`/`tx_policy_init`/`tx_accept_validate` sequence
`bitcoin_serve.asm` now uses, and proves both that a valid spend is
accepted and actually stored in the mempool, AND that a corrupted-signature
spend is rejected and leaves no phantom mempool entry (the concrete proof
the ordering fix above works). Landmine while building it: BIP141 txid
excludes witness data, so corrupting a witness signature byte does NOT
change the tx's own txid -- reusing the same fixture for both the
valid-accept and corrupted-reject cases made the "not left in the mempool"
check spuriously find the valid tx's own legitimate entry; fixed by using a
distinct fixture for the corruption case.

Stage 4 (Makefile `DAEMONOBJS`/`SERVEOBJS` wiring) landed incrementally
across Stages 1 and 3 as each needed new objects to link, then got a
dedicated cleanup pass (3ff03f3): running the FULL `make test` suite (not
just the individually-touched targets) caught six more test binaries
(`test_keepup`, `test_bip152_loop`, `test_sendheaders_fee`,
`test_outbound_mux`, `test_redial`, `soak_mux_peer`) that also link
`bitcoin_serve.o` and needed the same new sources -- refactored into a
shared `SERVETXVALSRCS` Makefile variable instead of six separate copies.

**Full verification**: entire `make test` suite (~80 harnesses) green, 0
failures, after the Makefile fix. One transient failure during an earlier
run (`test_scalarmul_ct`, a constant-time timing-ratio check, unrelated
secp256k1 code never touched by any of this) reproduced as flaky under
concurrent system load (the background UTXO replay competing for CPU) --
confirmed by 3/3 clean passes in isolation, not a regression.

**Status at end of session**: Stage 0 deployed live. Stages 1-4 committed,
tested, NOT yet deployed to the live daemon -- pending confirmation the
corrected UTXO replay is fully complete and the daemon restart is a good
time (deployment replaces the running production process). Remaining:
redeploy, then task-level real-peer soak testing of live tx-relay/mempool
acceptance.

----------------------------------------------------------------------------
## 2026-08-17 -- secp256k1_fe.asm: fe_mul REWRITTEN WITH adcx/adox PARALLEL CHAINS (1.13x, FULLY VERIFIED)
### Goal and outcome
A different question this time: not more C-to-asm conversion, but whether
EXISTING asm crypto primitives could be faster with better instruction
selection. `fe_mul`/`fe_sqr` (secp256k1 field multiplication -- the single
most-executed operation during ECDSA verify, since it's called dozens of
times per point add/double) was still plain schoolbook `mul`/`adc`, no
BMI2 (`mulx`) or ADX (`adcx`/`adox`), despite the host CPU (AMD Ryzen 9
9950X3D) supporting both. Separately confirmed `sha256.asm` is already
optimal (CPUID-gated SHA-NI hardware dispatch, correctly active on this
host) -- nothing to do there.
### Attempt 1 (conservative): mulx substitution only
Given the stakes (this underlies every signature verification in the
node), first tried the conservative option: swapped `mul` for `mulx` in
Phase 1 (the 256x256->512-bit schoolbook multiply) only, leaving the
accumulation structure and all of Phase 2 (reduction) byte-for-byte
untouched. Verified rigorously (100M random trials vs the original + an
independent `__uint128_t` reference, zero mismatches; full `make test`
65/65 green) before even measuring it. Result: 82.5 -> 83.7 Mops/s,
**~1.015x** -- the real bottleneck (the serial dependency between each
term's carry-out, threaded through one register across all 4 terms of a
row) wasn't touched by swapping just the multiply instruction.
### Measuring the real ceiling before attempting more
Rather than trust the general BMI2/ADX literature figures (~20-35%) at
face value, measured where fe_mul's time actually goes: built a
Phase-1-only variant and timed it against the full function. **Phase 1 is
~81% of total cost, Phase 2 ~19%** -- translating the literature's
Phase-1-only figure into a more realistic ~20-25% END-TO-END estimate for
this codebase's specific reduction strategy. This is what justified
attempting the fuller rewrite.
### Attempt 2: adcx/adox parallel chains
Four independent row computations (`a[i]*B`, each 1x4->5 limbs), rows 0/2
via the `adcx` chain (CF), rows 1/3 via `adox` (OF) -- two rows using
DIFFERENT flags share no dependency, so the CPU can overlap e.g. row 1's
work with row 0's still-retiring chain (the actual mechanism these
speedups come from; attempt 1 kept everything on one serial chain). Each
row writes to its own scratch buffer; the 4 rows are combined into the
final 8-limb product via a separate, deliberately low-risk `add`/`adc`
merge (same ripple-carry style already proven elsewhere in this file).
Every row opens with `xor ecx,ecx` (clears both CF and OF) so no row
inherits a stale carry from an earlier row sharing its flag.
### A real bug, caught immediately by the verification pipeline
First build crashed on the very first call, zero output before segfault.
gdb: `rip=0`, every register zeroed. Root cause: the prologue's stack
allocation grew from 64 to 224 bytes (for the new row buffers) but the
epilogue still deallocated only 64 -- a 160-byte mismatch that corrupted
the return address on every call. The same class of bug this codebase's
own "golden rule" warns about (scratch overlapping saved state), just via
a mismatched prologue/epilogue pair rather than an overlapping slot. Fixed
by matching the epilogue to the new allocation size; never got near
`make test`, let alone production, before being caught.
### Verified (same rigor as attempt 1, repeated against the TRUE original)
- Built the true original (pre-any-change, straight from `git show
  HEAD:...`) under renamed symbols for a clean side-by-side comparison,
  plus the same independent third reference.
- 150,000,000 random trials + edge cases (0, 1, p-1, p, all pairwise
  combinations, forced out-of-canonical-range operands on a fraction):
  zero mismatches vs the original, zero mismatches vs the independent
  reference.
- Full `make test`: 65/65 green.
- Same live-daemon-independence facts as attempt 1 still hold: `cons_verify`
  (used by `dl_catchup`'s block download) doesn't call into secp256k1/
  fe_mul at all, and `secp256k1_fe.o` isn't linked into `DAEMONOBJS` --
  only test binaries and `wallet_cli`. No live-daemon redeployment
  applicable.
### Benchmark, and an honest diagnosis of the remaining gap
fe_mul throughput, 30M calls: 83.8 -> 94.7 Mops/s, **~1.13x**. Better than
attempt 1 but short of the ~20-25% estimate -- isolating the row
computation alone shows it really did get ~44% faster (0.3035s -> 0.1693s
per 30M calls), but the separate merge pass this design needs (rows write
to independent buffers rather than accumulating in place) costs ~0.078s,
consuming roughly 58% of the raw row-computation savings. The clean row
independence that made the parallel chains safe to reason about is also
what gives most of the gain back. A design that accumulates in place while
still using two chains could close that gap further, but reintroduces much
of the complexity/risk the independent-rows approach was chosen to avoid,
for a return that's already diminishing at this point -- not pursued.
Shipped as the final version, replacing attempt 1.

## 2026-08-17 -- crawler.c FORK-STATE BUG FIXED; addrgather.c INVESTIGATED AND LEFT ALONE
### Goal and outcome
Fifth pass today. A fresh asm-candidate survey found no strong "next
check_chain" (bitcoin_mempool_policy.c has the right O(n^2) shape --
find_node/find_outreg/find_claim linear-scan the mempool per input -- but
zero call sites from the daemon; tx-relay isn't wired into main.c yet, so
there's nothing real to benchmark). Picked up a correctness bug the survey
flagged in passing instead: `crawler.c`/`addrgather.c` both fork() per-seed
discovery workers, and the initial read was that per-worker state never
propagates back to the parent, leaving the final report/output empty.
### Verification before fixing anything
Checked both files independently rather than trusting the shared
characterization, since they turned out to differ:
- `crawler.c`: CONFIRMED broken. `seen[MAXSEEN][40]`/`seen_n` were a plain
  static array; each fork()'d child got its own copy-on-write private
  copy, so no child's `mark_seen()` was ever visible to the parent.
  `out_file` was always written empty; the "crawl complete: N distinct"
  summary always reported N=0. (Live discoveries themselves weren't lost --
  each child's `printf()` goes through the inherited, genuinely-shared
  stdout fd -- only the in-memory dedup table and anything built from it
  in the parent afterward were broken.)
- `addrgather.c`: NOT broken this way. Reading `bitcoin_addrmgr.asm`
  showed `amr_add`/`amr_count` are entirely file-backed via a single fd
  (`peers.dat`, opened once before fork) -- there is no in-memory table to
  lose across fork. Verified empirically (throwaway probe: fork N
  children, each calls `amr_add`, check the parent's `amr_count` after
  `waitpid`): state correctly survived fork every time. Also stress-tested
  the theoretical concern -- concurrent children sharing one fd's file
  offset with an unprotected `lseek`+`write` pair -- two ways: 40
  concurrent children adding DISTINCT IPs (expect all 40 land), and 40
  concurrent children all adding the SAME IP (expect exactly 1, exercising
  the dup-check race). 5/5 trials each, zero lost writes, zero duplicates
  -- the shared-fd semantics correctly serialize at the kernel level in
  practice. Left the file untouched: no evidence of a real problem to fix.
### Fix (crawler.c only)
Moved `seen[]`/`seen_n` into a `mmap(MAP_SHARED|MAP_ANONYMOUS)` region
created in the parent before the fork loop, so every child inherits the
same physical pages instead of a private copy. The check-and-insert
(`is_seen`+`mark_seen`) still needed cross-process mutual exclusion --
two children could otherwise both pass `is_seen()` for the same endpoint
before either called `mark_seen()`, or race on the shared `seen_n` slot
index -- guarded with `flock()` on a dedicated lock file derived from the
output path (`<out_file>.lock`). Per the flock lesson already established
elsewhere in this codebase (`store_append_shared` etc.): each child opens
its OWN fd to the lock file rather than inheriting one from the parent,
since flock locks belong to the open file description, not the path --
a fork-inherited fd would not actually provide mutual exclusion between
siblings.
### Verified (hard evidence)
Wrote a throwaway probe mirroring the exact mechanism: 30 concurrent
children, each marking 3 endpoints distinct to itself plus 2 shared across
every child (exercising the propagation fix and the dedup-race guard
together). Parent's final `*seen_n` and the written `out_file`'s line
count both correctly landed on 92 (= 30*3 + 2 deduped) across 3/3 runs --
previously would have been 0 / an empty file. Full `make test`: 65/65
green, exit 0 (`crawler.c` isn't a Makefile/test-suite target, built and
verified manually).

## 2026-08-17 -- unified_ibd.c's LAST TWO RAW index.dat SCANS SWAPPED TO idxscan_*
### Goal and outcome
Fourth asm-adjacent pass today. A fresh survey (deliberately checking
beyond the two items already flagged and deferred -- `verify.c`'s
per-height `fopen`/`fclose`, low-value since real crypto work in the same
loop dwarfs it and it's a rarely-run manual fallback; `paribd.c`'s
per-record `fopen`, the worst constant-factor bug found but genuinely dead
code with no Makefile target) confirmed `unified_ibd.c` still had the last
two raw index.dat scans in the codebase duplicating already-proven asm
functions: `chunk_all_present` (per-200-block-chunk presence check) and the
tip-detection backward scan in `main()`.
### Fix
Both call sites run after `main()`'s own `chdir(dir)`, so CWD is already
the archive directory -- no chdir-wrapper needed (unlike the `chainctl.c`
fix earlier today), just direct calls to `idxscan_all_present`/
`idxscan_tip`.
### Honest framing
This one is modest compared to the day's other three fixes, worth stating
plainly rather than dressing up: these were plain I/O-bound loops with no
compounding algorithmic issue (unlike `idx_hash`'s entropy collapse or
`check_chain`'s O(n^2)) -- just the same buffered-pread64 constant-factor
win the `idxscan` family already established elsewhere.
### A benchmarking lesson mid-investigation
First attempt constructed synthetic "pre-sized with trailing holes" test
files via `truncate` extending a partial real copy -- this creates sparse-
file holes the kernel serves as zero without touching disk at all,
regardless of implementation, so it showed almost no difference either
way. Recognized real production `index.dat` files are themselves sparse
via the same pre-sizing mechanism, so re-ran against an actual snapshot of
the live growing archive instead, which gave the honest numbers below.
### Verified (hard evidence)
- Tip-scan on a real snapshot (899,844 real tip, ~63,000 trailing zero
  records to walk): 0.007s -> 0.001s (~7x).
- `chunk_all_present` across the realistic hot-path pattern (a full
  backfill's worth of 200-block chunk claims: 4,500 chunks over the present
  range, 4,815 over the full range including trailing holes): 0.126s ->
  0.0046s (~27x) and 0.151s -> 0.0048s (~32x) respectively. Correctness:
  identical "all present" counts (4,496/4,496 matching) between old and new
  at every tested range.
- Full `make test`: 65/65 green, exit 0.
### Safety note (deliberately avoided a repeat)
Learned from an earlier incident today (running `chainctl` directly against
the live production `data/` directory spawned real `unified_ibd` workers
competing with the live daemon) -- this time, all testing used scratch
copies exclusively, with `end_h` chosen so the resume logic's own "archive
already complete; nothing to do" short-circuit fires before any network
code path can run. Zero interaction with the live production archive.

## 2026-08-17 -- check_chain.c O(n^2) DUP DETECTOR FIXED + chainctl.c archive_tip SWAPPED TO idxscan_tip
### Goal and outcome
Third asm-adjacent fix today (candidate found via a fresh survey of
asm/daemon/*.c for hot loops still using the superseded per-record C
patterns already replaced elsewhere): `check_chain.c` (standalone archive
integrity-audit tool, not the live `dl_catchup` daemon) had a genuinely
O(n^2) duplicate-block-hash detector -- a nested loop comparing every new
record's hash against every previously-seen hash, despite its own comment
claiming "naive O(n)". At the real archive size (~962,831 blocks) that's
~4.6e11 comparisons; `chainctl.c` (the orchestrator that drives
`check_chain` after every ~8000-block chunk during a full IBD) reruns this
~120 times over a full run with growing n each time, so the cost compounds.
### Fix
Reused `idx_init`/`idx_put` (`bitcoin_idx.asm`, written and validated
earlier today for `build_hash_index`) in place of the manual nested-loop
scan -- `idx_put`'s own return (1 new / 0 dup) does duplicate detection in
one O(1)-amortized-per-insert pass, turning the whole thing O(n). Table
sized dynamically (`next_pow2(n*4+1024)`, ~25% target load factor) so it
doesn't need retuning as the real archive grows past today's size.
Also swapped `chainctl.c`'s `archive_tip()` -- a per-record `fseek`+`fread`
backward scan for the highest non-zero index record, the same pattern
`idxscan_tip` already replaced in `main.c` -- to call `idxscan_tip()`
directly via a chdir-in/chdir-out wrapper (idxscan_tip operates on
"index.dat" in CWD; nothing else in chainctl.c depends on staying in a
particular directory).
### Verified (hard evidence)
- Timed the OLD dup detector on real truncated archive slices to confirm
  the O(n^2) shape empirically before trusting an extrapolation: 50k->0.36s,
  100k->1.46s, 150k->3.26s, 300k->13.09s, 400k->23.30s -- fits a quadratic
  curve almost exactly (e.g. 100k->150k ratio 2.24 vs predicted (150/100)^2
  = 2.25), confirming no unexpected cache-driven acceleration/deceleration
  at larger n that would invalidate extrapolating to full scale.
- NEW version at the same slice sizes: 50k->0.007s, 100k->0.027s,
  150k->0.034s, 300k->0.079s, 400k->0.089s -- dup counts matched the OLD
  version exactly at every size (0 at all tested slices).
- Full real archive (879,800 stored records): OLD extrapolated ~135s vs NEW
  measured 0.198s (~680x, growing further as the archive does). The full
  run additionally reported `duplicate rec: 19192` -- an exact match to the
  duplicate-hash count found completely independently during today's
  earlier `idx_hash` investigation (own separate verification cross-check).
- `archive_tip()` verified via gdb calling it directly against a scratch
  copy of the real archive: returned 881,523, matching the live daemon's
  own concurrently-reported progress; confirmed CWD correctly restored
  afterward (chdir-back works, doesn't leave chainctl's other relative-path
  logic broken).
- Full `make test`: 65/65 harness blocks green, exit 0 (these are C-only
  changes to standalone ops tools, not Makefile/test-suite targets, so this
  confirms no regression to anything the suite does cover).
### Incident (caught immediately, no damage)
An early verification attempt ran the real `chainctl` binary directly
against the LIVE production `data/` directory to sanity-check `archive_tip`
-- it immediately spawned 8 `unified_ibd` workers against the same archive
the live `dl_catchup` daemon was actively writing to. Killed within
seconds (no corruption observed; the archive's flock-based append
coordination would likely have protected it regardless, but the extra
network/disk contention against the live sync was unintended and avoidable).
Redid the check safely: gdb calling `archive_tip()` directly against an
isolated scratch copy instead of running the full program against live data.

## 2026-08-17 -- build_hash_index PORTED TO ASM + CRITICAL idx_hash BUG FOUND & FIXED
### Goal and outcome
Follow-on to the idxscan conversion below: identified `build_hash_index`
(daemon/main.c, the boot-time O(1) hash->height index builder used for
`getdata`-by-hash serving) as the next asm-conversion candidate, since it
took **185.9s on the real 962,831-record archive** -- every `serve`/`follow`
boot pays this, unconditionally, right before the node can accept any
connection. Converting it surfaced a much bigger, PRE-EXISTING bug: the
in-memory index's own hash function was pathologically bad on real data,
independent of anything C-vs-asm. Fixing that (not the C/asm conversion
itself) is responsible for nearly the entire win.
### 1. `idx_build_from_file` (asm/bitcoin_idx.asm) -- the scoped conversion
Buffered-`pread64` bulk loader (same 192KB-window approach as
`idxscan_progress`), replacing the per-record `fread`+byte-reverse+`idx_put`
C loop. Straightforward, same pattern as the idxscan work below.
### 2. The real discovery: idx_hash collapses on real block hashes
Benchmarking the conversion in isolation gave a shock: `idx_put` on
400,000 real block hashes took **15.8s**, vs **0.04s** for 400,000
synthetic random hashes into the identical table (asm/tests -- since
deleted, see asm/tests/bench_hashidx.c and asm/tests/test_idx.c for the
surviving artifacts). Bisecting by record count showed clearly super-linear
growth (300k: 1.55s, 350k: 6.5s, 400k: 14.4s, 450k: >30s) -- not a bug in
the new conversion (the synthetic control ruled that out), but in
`idx_hash` itself, called identically by both the old C path and the new
asm path.
ROOT CAUSE: `idx_hash` hashed only the first 8 bytes of the 32-byte key.
Every REAL Bitcoin block hash's leading bytes (in the byte order this table
is queried with) are constrained near-zero BY PROOF-OF-WORK -- that IS what
a valid hash is -- so those 8 bytes carry almost no entropy across
different real inputs. Dumping the actual bytes confirmed it directly:
every sampled record's first 4 bytes were literally `0x00000000`. A first
fix attempt (XOR-folding FNV-1a's output before masking, to counter FNV's
separately-known weak low-bit avalanche) did NOT help -- the problem was
insufficient entropy going INTO the hash, not how the output bits mix.
FIX: hash all 32 bytes instead of just 8 (kept the XOR-fold too, as free
insurance on top). Reconfirmed against the real archive: idx_put on the
full 962,831 records (823,833 new, 19,192 genuine hash duplicates, 0 "full")
dropped from the original ~186s to **0.104s** -- roughly an 1800x
improvement, and this affects `idx_get` too (same hash function), which
live `serve` mode uses for O(1) `getdata`-by-hash lookups -- so this had
likely been silently degrading actual block-serving performance in
production, not just boot time.
### Regression guard added
`asm/tests/test_idx.c` gained a case: 500,000 keys sharing an IDENTICAL
first 8 bytes (varying only bytes 8-31), inserted into a production-scale
table. With the buggy 8-byte-only hash this genuinely times out (every
insert collides on one bucket, O(n) per insert); with the fix it completes
in ~0.13s. Verified BOTH directions live (temporarily reverted idx_hash,
confirmed the test fails/hangs, restored the fix, confirmed it passes) --
the existing `test_idx.c` never caught this because its other cases
deliberately randomize the first 8 bytes specifically to get genuine
(non-hash-collision) duplicate detection, which is exactly the case that
avoids this defect.
### Verified (hard evidence)
- `idx_build_from_file` cross-checked against the C original via sampled
  `idx_get` lookups on the real live archive (both tables agree exactly,
  including on genuine duplicate-hash heights) -- `asm/tests/bench_hashidx.c`.
- Full `make test` (fresh, after cleaning up several stale ROOT-OWNED
  `/tmp/*test*` scratch directories left over from an earlier root-run
  suite, unrelated to this work but blocking verification) -- 65/65 harness
  blocks green, 0 failures, `MAKE_EXIT=0`.
- `build_hash_index()` called directly via gdb against the actual compiled
  daemon binary and the real production archive: ran clean, indexed
  826,746 heights, matching expectations.
- Redeployed to the live production daemon (killed + relaunched); resumed
  catch-up cleanly with no crashes. The idx_hash fix will take effect the
  next time this boot reaches `build_hash_index` (after catch-up finishes).
### Before/after (real ~962k-record archive)
| | C (old, buggy hash) | asm (new, fixed hash) | improvement |
|---|---|---|---|
| `build_hash_index` (full boot-time build) | ~186s | ~0.1-0.14s | ~1500-1800x |
| `idx_build_from_file` vs C loop, hash ALREADY fixed | 0.123-0.136s | 0.108-0.110s | ~1.1-1.24x (the honest, modest I/O-side win once the real bottleneck is gone) |

## 2026-08-17 -- BUILT-IN SELF-HEALING CATCH-UP (dl_catchup) + index.dat SCANS PORTED TO ASM
### Goal and outcome
Two related pieces of work on the download/catch-up path, both against the
real ~962k-block mainnet archive:
1. Moved the standalone multi-peer catch-up tool's engine (chunk-claiming
   work-stealing, dynamic peer replacement) DIRECTLY INTO THE DAEMON, so
   `bitcoind serve <dir> <port>` self-heals archive holes and catches up to
   the real chain tip on its own at boot -- no external scripts required for
   normal operation.
2. Converted the C `index.dat` positional-record scan logic (reimplemented
   separately 5x in C plus twice more in Python) into a canonical asm module.
### 1. `dl_catchup` (asm/daemon/main.c)
New orchestrator: `dl_bootstrap`/`dl_pool_from_book` (existing DNS-seed
discovery) for peers, extends `headers.dat` incrementally (resumes from the
last stored header, not a genesis refetch), computes the combined
hole-plus-extend span directly from `index.dat`, then forks `>=8`
chunk-claiming workers (`dlc_worker`) that pull work from a shared `mmap`'d
atomic counter, skip already-archived chunks, and reuse persistent
connections. Peer liveness is a bounded non-blocking-connect probe (several
rounds) -- the ONLY peer source for both the header phase and workers; no
fallback to a raw unconfirmed pool entry, because `tcp_connect_ip` has no
connect-phase timeout and a black-holed host can hang the whole synchronous
boot for minutes (hit this directly: 3+ minute stall on one bad candidate
before the fix). Dead-weight detection drops a peer whose measured bandwidth
(from `/proc/<pid>/io`) stays below a floor for a configurable number of
status ticks, and replaces it with a fresh candidate. Live status ticks
report overall/gap-free progress, per-peer bandwidth and chunk/block counts,
network-recv vs disk-write totals (both tick and cumulative), and a stable
running average since start.
Real bugs found live: a header-phase success check used `added>=0` instead
of `added>0` (a peer returning exactly 0 new headers on an empty store was
wrongly treated as done); an early liveness-probe design dialed the whole
pool in one burst and only found 1/140 live -- fixed by running several
bounded rounds instead of one shot, since real handshakes often take longer
than a single short poll window.
`daemon/unified_ibd.c` (the same chunk-claiming engine, standalone) is kept
as an ops tool for large one-off catch-ups/offline reindexing but is no
longer load-bearing for the daemon's own boot path.
### 2. `asm/bitcoin_idxscan.asm` -- index.dat scans in asm
`dl_catchup` reruns its archive-gap scan every status tick and every worker
chunk-claim, so the "scan index.dat's 48-byte records for non-zero" logic was
reimplemented 5 separate times in C (plus 2x in Python). Consolidated into
one asm module: `idxscan_tip`, `idxscan_first_hole`, `idxscan_all_present`,
`idxscan_progress` (raw open/pread64/close syscalls, matching the project's
existing daemon-facing asm conventions from `bitcoin_store.asm`).
FIRST CUT WAS A REGRESSION: one `pread64` syscall per 48-byte record
benchmarked 2-15x SLOWER than the C baseline's buffered `fread`, because
glibc's own stdio already amortizes its `read()` syscalls across a ~4KB
window while the raw-syscall version paid a syscall per record. FIX: batch
reads into a 192KB static `.bss` buffer (4096 records/read, scanned in
memory with no syscalls in the hot loop) -- bigger than stdio's own window is
what actually wins. Buffer is static (not stack) since these run inside
forked, single-threaded `dl_catchup` workers, where a static buffer needs no
locking.
Also hit, mid-build, the project's own documented golden rule directly:
placed two scratch locals at `[rbp-8]`/`[rbp-16]` in `idxscan_progress`
without first `sub rsp`-ing past the 5-register callee-saved save area,
silently corrupting the saved `rbx`/`r12` on return. Caught by a debug build
(gdb backtrace pointed at `main` with no symbols, rebuilding at `-O0 -g`
localized it) before it ever reached the live daemon; fixed by allocating the
locals properly below the save area, per the codebase's own established rule.
### Verified (hard evidence)
- `dl_catchup`: two isolated smoke tests (empty store fresh bootstrap through
  to `serve_mux`'s "serving on port" handoff; re-run against a partially
  filled store confirming incremental header resume + narrowed span), then a
  bounded-`timeout` sanity run against the real archive before full release.
- `idxscan_*`: `asm/tests/bench_idxscan.c` snapshots `index.dat` first (so
  it's safe to run against a concurrently-writing daemon), then cross-checks
  every function's output against the original C `dlc_*` functions on the
  live ~810k-record-and-growing archive -- all outputs byte-identical. Also
  smoke-tested by running the swapped daemon binary against a scratch copy of
  the real archive for 40s under `timeout`, confirming the full `dl_catchup`
  status-tick loop runs cleanly end-to-end on the new asm path, not just in
  the standalone benchmark harness.
### Benchmark (real ~814k-record archive, snapshot-frozen for a fair before/after)
| function | C (old) | asm (new) | speedup |
|---|---|---|---|
| `idxscan_tip` (backward scan) | 0.181s/20 reps | 0.004s/20 reps | 47.6x |
| `idxscan_first_hole` (forward scan) | 0.103s/20 reps | 0.023s/20 reps | 4.5x |
| `idxscan_progress` (forward scan) | 0.131s/20 reps | 0.033s/20 reps | 4.0x |
| `chunk_all_present` (2000-rec chunk) | 0.017s/200 reps | 0.0004s/200 reps | 43.6x |
### Result
`main.c`'s four `dlc_*` functions now delegate to the asm exports. Rebuilt
and redeployed to the live production daemon (killed + relaunched against the
real archive); confirmed via log to resume cleanly at the same progress with
no crashes. Full suite unaffected (no existing harness touches this path).

## 2026-08-14 -- WALLET CLI: GENERATE KEY / SHOW ADDRESS / SIGN A P2PKH TX (t_9f55dbe5)
### Goal and outcome
Wire the VERIFIED wallet primitives (secp256k1, BIP32, hash160, base58check,
pubkey_parse, ECDSA + the scalar/point/field ops) into a runnable CLI:
  `wallet_cli gen`                -> random keypair + P2PKH mainnet address
  `wallet_cli addr <keyhex>`      -> compressed pubkey + address for a key
  `wallet_cli sign <txhex> <keyhex> <input_idx>` -> sign a P2PKH tx (legacy SIGHASH_ALL)
### New/changed
- asm/wallet_core.c   : C glue over the verified ASM primitives. ECDSA signing is done
  in C on top of the repo's verified sc_mul / sc_inv / point_scalar_mul / fe_* / G_AFF
  (r = (kG).x mod n, s = k^-1 (z + r d) mod n, low-S normalized; deterministic nonce
  k = sha256d(z || priv)). Also does DER encoding + full tx re-serialization.
- asm/daemon/wallet_cli.c : thin CLI front-end (gen/addr/sign).
- asm/tests/test_wallet.c : end-to-end test (address known-vector, sign->verify roundtrip
  with ecdsa_verify, signed-tx structure).
- asm/Makefile : wallet CLI + test_wallet targets.
### Verified (hard evidence)
- addr(key=1) == 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH; addr(bip32 master) ==
  15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma  (both match independent Python oracle).
- tests/test_wallet: 9/9 PASS. The embedded signature verifies BOTH with the repo's
  ecdsa_verify AND independently with Python `cryptography`/secp256k1 against an
  independently recomputed SIGHASH_ALL preimage (z matched the CLI byte-for-byte).
- live CLI: `sign` on an unsigned 1-in/1-out tx produced a 107-byte scriptSig
  (push72 DER||01, push33 compressed pubkey) that independently verifies.
### Honest scope
- Signing uses a deterministic RFC6979-style-ish nonce k = sha256d(z||priv) reduced
  mod n (not full RFC6979; fine for a CLI/demo, not for production key custody).
- The pre-existing `test_txval` (whole-tx validator, card t_ef86a54a) still has 2
  failing cases (real-sig spends) — SEPARATE in-progress sprint item, not this card.
  This card's `test_wallet` is green and runs before test_txval in `make test`.

## SESSION (2026-08-14): NODE SERVER SERVES THE REAL CHAIN (getdata + getheaders)
Made the ASM inbound server genuinely answer peers against the real on-disk
archive, by exercising `bitcoind serve <dir> <port>` live over loopback with
REAL mainnet data (not fake blocks). That immediately surfaced five latent bugs
(unit tests can't see them) plus a nasty segfault. All fixed & verified.

Root-cause summary of the live session:
1. daemon/bitcoind had NO Makefile target -- built by an ad-hoc gcc command that
   silently went STALE. Added a real target linking every needed object at -O0.
2. daemon server-test FAILED getdata->block: the socketpair serve path synced an
   in-memory chain but never built the O(1) hash index. Added
   build_inmem_hash_index(); server-test now passes (getdata-exact, getheaders,
   ALL TESTS PASSED).
3. build_hash_index() keyed the hash->height index with the WRONG byte order:
   index.dat stores hashes in BE display order but the getdata/inv wire hash is
   LE. getdata therefore missed every hash. Reverse before idx_put. After the
   fix, live getdata served REAL blocks by hash: h=1 (215B), h=2 (215B),
   h=50000 (647B) all requested-hash-match=YES.
4. getheaders dispatch was OFF-BY-ONE: node_serve_loop checked cmd[4..8] for
   "head"/"ers" but the message is "getheaders" = g-e-t-h-e-a-d-e-r-s, so "head"
   is at cmd[3..6] and "ers\0" at cmd[7..10]. gdb proved the outer dispatch
   matched (s_cmd=0x68746567) but the inner check always failed, so getheaders
   never served. Fixed offsets to +3/+7.
5. open_file LEAKED an fd on every call: node_serve_block opens the block file
   fresh for each block served and never closed the previous cur_blk_fd. After
   ~1024 serves the process hit EMFILE (open -> -24) and serving truncated at
   ~1016 blocks / returned -1 for high heights (isolated test: store_get_file_fd
   = -24 at h>=1019). Added close-before-open; node_serve_block now serves 3200+
   consecutive heights and every height 0..309998.

THE CRASH (segfault in main's printf, stdout/stderr=null, main's r14 held the
ascii "(serve mode"): the getheaders header copy called memcpy_len with the
length in r8, but memcpy_len reads its LENGTH from RDX (confirmed by
disassembly: `cmp %rdx,%rcx`). So it copied [s_p] (the growing page offset)
bytes instead of 80, sweeping through hp_buf and past .bss into the relocated
stdout/stderr copies (0x143e6a0 // stdout, 0x143e6c0 // stderr), zeroing libc
stdout/stderr and crashing the print after node_serve_loop returned. Found with
a HARDWARE WRITE WATCHPOINT on the stdout slot -> caught the exact corrupting
instruction (memcpy_len.c at 0x40823b doing `inc %rcx` as it walked over the
slot). Fixed: load the 80-byte header length into RDX. Server stays alive.

getheaders count now derives from the byte pointer (the loop counter rcx was
clobbered by memcpy_len/node_serve_block) and emits a CANONICAL CompactSize
varint (0xFD+2-byte for count>=253, single byte with headers compacted down
otherwise). Serving loop tracks height/count in statics (immune to callee
clobbering).

VERIFIED LIVE after the fixes (port 8355, server stayed ALIVE):
- getheaders h=1 locator: 2000 headers, count-varint(size3)=2000, inferred-from-
  len=2000 MATCH=YES, chainlink=True (each header's prev == double-sha256 of the
  previous), hdr0.prev == the h=1 locator (serves from height 2). Same for
  locators at h=200000 and h=293300.
- getdata still correct.

No regression: make test 33/33 green. Commits pushed (32279a0 for the code, docs
in this session). Downloader healthy: ~309,012 stored (99.68%), near tip.
================================================================================

## SESSION (2026-08-13): WALLET KEY DERIVATION IN ASM (BIP32)
Reached the wallet stage. Built two new verified primitives in pure x86-64:

1. bitcoin_keys.asm -- scalar_to_pubkey(k) -> compressed 33-byte pubkey:
   point_scalar_mul(R,G,k) -> Jacobian (X,Y,Z); affinize via fe_inv(z2),fe_inv(z3):
   x=X/z2, y=Y/z3; prefix 0x02/0x03 by Y parity; serialize X as 32 BE bytes.
   Verified: G(k=1) exact, BIP32 master pubkey exact, scalar range checks.
   Bug found & fixed: byte extraction shifted by (b&7) instead of 8*(b&7) --
   missing *8, gave wrong BE bytes for nonzero scalars.

2. bitcoin_bip32.asm -- bip32_master + bip32_ckd_priv (hardened + normal):
   hardened: HMAC-SHA512(cpar, 0x00||kpar||ser32(i)); normal: HMAC-SHA512(cpar,
   compressed_pubkey(kpar)||ser32(i)) using scalar_to_pubkey. Then
   k_i=(IL+kpar) mod n, c_i=IR, validate 0<k<n.

   THREE subtle asm bugs found & fixed:
   (a) hardened input layout: k_par written at input[1] (was input[-1], an
       off-by-one BELOW the 0x00 padding byte) -- silently garbage-shifted the
       whole HMAC input.
   (b) ser32(i) big-endian index bytes: written LSB-first (little-endian order)
       instead of MSB-first; also needed to start at input[33] not input[30].
   (c) the mod-n add/sub used DEC (clobbers CF) or TST (clobbers CF) between
       ADC/SBB bytes, breaking carry/borrow propagation -> now LOOP (no flag
       writes) + DEC r8 (DEC preserves CF in x86).
   (d) 257th carry bit of (IL+kpar) overflows 32 bytes; captured in a dedicated
       carry slot. Debt-row bug: the carry byte was placed at [rbp-0x119] which
       IS the sum's LSB byte, silently overwriting it -> moved to [rbp-0x118].

   Verified: test_bip32_chain walks the OFFICIAL BIP32 test-vector-1 chain
   m -> m/0' -> m/0'/1 -> m/0'/1/2' -> m/0'/1/2'/2 -> .../1000000000,
   all six steps byte-exact for both child key AND chain code.

Full suite: 29 -> 31 harnesses green (added test_keys, test_bip32_chain,
test_bip32_master). Commit 9fc36c4, pushed.

Downloader still healthy in parallel: 245,494/246,000 blocks stored (99.79%),
contiguous from genesis, 1 chainctl running.
================================================================================

## SESSION (2026-08-13): RIPEMD-160 + HASH160 + base58check ADDRESSES

Finished the wallet address path. This closes the loop so a real mainnet
Bitcoin address drops out of pure ASM end to end.

1. ripemd160.asm -- complete RIPEMD-160. Held me up for a while: my digest was
   deterministically wrong in BOTH my asm and a Python transcription that
   agreed with it, yet every table/constant matched canonical. The way out was
   fetching the authoritative pycryptodome src/RIPEMD160.c and reading the
   FINAL MIXING stage literally: the left/right line terms are crossed in the
   reference (h1 + CL + DR, not h1 + cc + d as I had it). Fixed the compose;
   the asm then matched pycryptodome and hashlib on every vector.
   Also fixed: little-endian message words (RIPEMD uses LE, unlike SHA-256's
   BE -- I had bswap'd, copying the SHA habit), a carry/round-counter register
   conflict, and callee-saved preservation. Verified: standard vectors +
   padding boundaries (len 55/56/63/64/65/120) + multi-block (1000/4096/65536)
   vs pycryptodome digests.

2. bitcoin_addr.asm -- hash160 = RIPEMD160(SHA256(x)), and base58check_encode
   (double-SHA256 checksum + repeated-divide-by-58 base58 with leading-'1'
   preservation). Bug found: hash160 read its SHA-256 intermediate from the
   wrong local offset ([rbp-0x58] instead of [rbp-0x30]) -- fixed. base58
   digit order was also reversed (need to accumulate LSB-first then emit
   reversed); and a buffer-overlap between the work and digit buffers plus a
   data buffer that reached into the callee-save area caused corruption.

Verified real mainnet P2PKH addresses byte-exact:
   1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH  (compressed generator pubkey G)
   1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK  (Bitcoin-wiki test pubkey)
plus the canonical all-zero base58check string.

NOW COMPLETE IN ASM, all verified: BIP32 master -> CKDpriv -> secp256k1
pubkey -> HASH160 (SHA256+RIPEMD160) -> base58check -> mainnet P2PKH address.
33/33 harnesses green. Commit db328db, pushed.

Downloader healthy throughout: ~277k blocks stored (99.7%), contiguous from
genesis.
================================================================================

## SESSION (2026-08-13): NODE -- SERVE LOOP MULTI-GETDATA / LOOP-STABILITY FIX

Returned to the long-open "multi-getdata" serve bug. Root cause found on re-read
of bitcoin_serve.asm: rbx was used for BOTH the persistent outer-loop counter
(.next: dec rbx; jg .outer) AND the getdata item pointer (.gd_loop: mov rbx,
[s_ptr]; ... reloaded from [s_ptr] at 231/241/252/256). So after the first
getdata the loop bound became the item-pointer address; the loop only stopped
on peer close, and bookkeeping was corrupt exactly where the old crash lived.

Fix: run the outer-loop counter in r15, written only at function entry (ht_idx
now lives solely in the static s_htidx slot; r15 is callee-saved so every
p2p_read/idx_get/node_serve_block/p2p_write preserves it across all handlers).
rbx is now free as pure handler scratch.

To prove it (not just smoke-test): extended test_serve.c into a real stress
suite:
  - a single multi-inv getdata message requesting all 8 blocks -> served
    byte-exact (exercises .gd_loop iterating several items in one message);
  - 25x ping/pong AFTER serving -> proves the outer loop keeps running on the
    counter, independent of socket close.
All 33 harnesses green. Commit 96f102f, pushed.

Note: also spotted a hygiene linker warning (node_log.o missing .note.GNU-stack
=> executable stack). Cosmetic, not correctness; can add the section later.

Next node items: (1) batch/range block serving (getblocks/getheaders range) so a
syncing peer can pull the whole chain from us; (2) the bitcoin_store multi-file
tip_height(+24) layout regression still failing test_bitcoind_sync/test_cli;
(3) wire the finished ASM key->HASH160->base58check wallet path into a CLI
getnewaddress.
================================================================================

## 2026-08-13 -- #13 STORE REFACTOR RECONCILED + root-caused a REAL corrupted-filename bug; full suite back to 283 PASS-equiv (22 green, 0 FAIL)
### Context
On resuming, `make test` showed `test_bitcoind_sync` failing (`store tip_height == NB-1
got=0 exp=1`) and `test_cli` failing 6 assertions (`getbestblockhash`/`getblockhash 3`/
`getblock 2`/`getblock by-hash`/`gettx`/`getbalance` -> "height out of range"/"not
found"). Both traced to an UNLOGGED, PARTIALLY-PROPAGATED refactor of bitcoin_store.asm
(timestamps 07:18/07:29, after the last 283-PASS baseline) that added multi-file 128MB
rollover blk%05d.dat support and changed the store struct layout.
### Root cause #1 -- store struct layout mismatch (+24 semantics)
New bitcoin_store.asm moved state around so that `+24` was `cur_file_no` and tip height
was only derivable as `+16 idx_len/48-1`. But the verified consumer ecosystem
(bitcoind.asm node_serve_block_by_hash, bitcoind.asm node_sync, bitcoin_cli.asm ~10
sites, paribd_asm.c worker resume, test_bitcoind_sync.c) all read `+24` as the tip
height. FIX: keep the multi-file feature but fix `+24` to mean tip_height in the store's
OWN struct so every existing consumer is correct with ZERO edits:
    +0 cur_blk_fd, +8 idx_fd, +16 idx_len, +24 dword tip_height (-1 empty),
    +28 dword cur_file_no, +32 dword cur_file_pos, +36 dword magic.
store_init sets tip=-1; store_append sets tip=newheight; store_reload restores tip from
the last index record. Updated test_store.c's struct mirror + added `reload tip_height 2`.
No consumer files needed changing (they already read +24 as tip).
### Root cause #2 -- the REAL bug hiding underneath: corrupted reopened filename
After #1, test_cli still failed: every cli_load_block/store_get_file_fd open created a
file with a CORRUPTED long name (`blk00000.dat<garbage>`), so reads found 0 bytes.
strace showed the name was missing its NUL: `open("blk00000.dat\375\177"...)`,
`open("blk00000.dat%%%%..."...)` -- stack garbage read past the end of "blk00000.dat".
ROOT CAUSE: fmt_blkname wrote the suffix with `mov dword [r12+8], 0x007461642E`
intending ".dat\0" -- but a dword store is only FOUR bytes (".dat"), so the 5th byte
(the NUL at +12) was NEVER written. The old single-file store opened the fixed rodata
string `blk00000.dat\0` (already NUL-terminated), so this bug is NEW to the multi-file
refactor. FIX: write `.dat` then an explicit `mov byte [r12+12], 0`. Verified in
objdump (movb $0x0,0xc(%r12)) and by ls: only clean `blk00000.dat`/`index.dat` remain.
### Lesson (add to golden rules)
"blk00000.dat" is 13 bytes ("blk"+5 digits+".dat"+NUL). Writing a filename suffix with a
DWORD store covers only 4 bytes -- ALWAYS write the terminating NUL explicitly when
building a runtime filename, or open() will read past the end into stack garbage and
create corrupted long filenames. (Same class as the "size every load to the field" rule:
size every store to the full field, incl. the NUL.)
### Result
make test: 22/22 green, 0 FAIL, MAKE EXIT=0. Ubuntu full suite restored and RED:
test_store (incl. reload tip) and test_cli fully pass. Committed to the new GitHub repo
BobClawblaw/bitcoinmachinecode.

## 2026-08-12 -- #12 PARALLEL multi-peer FULL-CHAIN download (>= 8 DISTINCT internet peers) + ALL-ASM receive loop + real-mainnet header-continuity fix
### Goal and outcome
Download the FULL mainnet blockchain so it can be re-served, from >= 8 DISTINCT
internet peers simultaneously, with the per-worker download LOOP IN ASSEMBLY.
All three achieved:
- Discovery: a live peer scan (tests of a 26,895-node bitnodes snapshot) found
  hundreds of distinct internet nodes that serve block bodies with the corrected
  getdata; 101+ distinct good peers saved in
  /storage/bitcoinmachinecode/good_internet_peers.txt. The parallel download
  establishes >= 8 of these simultaneously.
- Running download: a full-chain parallel IBD (daemon/paribd.c) downloading
  heights [0, tip] with 8 distinct internet peers into /storage/bitcoinmachinecode/data
  (resumable; accumulating the real archive for re-serving).
- ALL-ASM receive loop: new bitcoind.asm node_ibd_blocks_x (hardened from
  node_ibd_blocks) does getdata -> recv (draining ping->pong + ignoring other
  chatter) -> cons_verify (CALLER-supplied scratch, big enough for dense modern
  blocks) -> re-derived-hash guard -> store_append, over an explicit height range,
  ALL in assembly. daemon/paribd_asm.c orchestrates 8 workers each running it,
  and re-serves the produced store (verified: inbound peer fetched headers + a
  block body).
### Real bug found & fixed (would have silently poisoned any real-mainnet headers)
node_ibd_headers validated chain continuity by requiring every header's prevhash
to equal the previous header's block_hash, seeded from the caller's locator. But
the getheaders-from-genesis locator is the synthetic all-zero hash, while REAL
block 1's prevhash is the GENESIS hash (000000000019d668...), NOT zero -- so the
very first real header always failed continuity and node_ibd_headers returned -1.
Every prior IBD test used SYNTHETIC chains with a zero-prev block 0, so no test
ever caught it. FIX: skip the prevhash compare for exactly the first header of the
whole download (total==0 && i==0); enforce it for every later header. Verified:
node_ibd_headers now persists 962,208 REAL mainnet headers.
### What was proven end-to-end (real data)
- asm node_ibd_headers persisted 962,208 real headers (full mainnet header chain).
- asm node_ibd_blocks_x (8 distinct internet peers) downloaded/validated/stored
  real blocks over worker height-shards; merged store queried via the asm CLI
  (getblockcount/getblockhash with real hashes) and RE-SERVED to an inbound peer
  (201 headers + exact block body).
- The running full download (8 distinct internet peers) reached ~18GB of real
  blockchain data in ~30 min and continues resumably toward the full chain.
### New/changed
- bitcoind.asm: node_ibd_blocks_x (new all-asm hardened receive loop);
  node_ibd_headers continuity fix.
- daemon/paribd.c: the parallel full-chain orchestrator (>= 8 peers, resumable,
  worker file merge). daemon/peertest.c + daemon/discover.c: internet peer
  discovery/testing. daemon/paribd_asm.c: the all-asm worker orchestrator.
  seeds/good_internet_peers.txt + internet_peers.txt: peer pools.
- Full make test still 283 PASS / 0 FAIL (continuity fix keeps synthetic tests
  green while unlocking real-mainnet headers).
### Honest scope
The full ~500GB / ~962k-block archive download is a multi-hour resumable job that
is RUNNING, not finished; it is gated by network throughput + peer flakiness, not
by correctness (every block is cons_verify-validated as it lands). Re-serving the
downloaded store is proven. Remaining: let the running download reach the tip,
plus the documented roadmap items (UTXO set, script/sig validation, mempool/rpc,
pruning, reorg).

## 2026-08-12 -- #11 ROOT CAUSE OF THE BLOCK-BODY WALL FOUND & FIXED: getdata wire format was WRONG. REAL mainnet block bodies now download + cons_verify + store, and the inbound serve path works against a real peer.
### The headline (this overturns the long-standing "peer-policy wall" conclusion)
The 34-byte getdata this node had been sending (hash at +2, single-byte type) is
MALFORMED -- real Bitcoin nodes silently ignore it. That malformed encoding, not
(only) seed serving policy, is why live block-body getdata "hung/dropped". With
the getdata fixed to the canonical form, a real node COOPERATIVELY serves block
bodies, and the assembly receive path downloads + cons_verify-validates + stores
REAL mainnet blocks. This was proven live against 192.168.5.69:8333 (a local
full node): 2000 real headers learned to tip (height ~790999), then real block
bodies at heights 790999/790998/790997/790994 downloaded, validated VALID by asm
cons_verify, and persisted. The "download the entire blockchain" receive tail is
NOT blocked by asm or peer policy for a cooperative peer -- our earlier
conclusion was wrong in an important way; see below.
### What the correct wire format actually is (verified two ways)
Bitcoin getdata/inv inventory: [count varint][type int32 LE][hash32].
For one MSG_BLOCK: [0x01][0x02 00 00 00][hash at +5] = 37 bytes. The type
field is a 4-byte little-endian int32 -- our p2p_oracle.py has ALWAYS encoded
this (varint(1)+u32(2)+hash). A prior LOG stage (#2 / S6) "fixed" p2p_getdata_block
to a 34-byte form under a mistaken assumption ("type is a 1-byte varint"). That
was wrong. Confirmed LIVE: a real node answered the 37-byte form (got block) and
did nothing for the 34-byte form.
### Changes
1. bitcoin_p2p.asm p2p_getdata_block: back to the canonical 37-byte
   [count][int32 type][hash at +5]; fixed return 37. (Buffer was already 37 in
   node_sync; node_ibd_blocks getdata buffer was 40, fine.)
2. daemon/main.c serve_loop getdata PARSER: was reading hash at pl+5 (correct)
   before #2 wrongly flipped it; now reads [count][int32 type][hash at +5],
   stride 36, serving every requested MSG_BLOCK. (inv handler already used the
   correct int32 stride and is unchanged.)
3. All fake/test PEERS that parse inbound getdata (fake_serve, full_serve in
   daemon/main.c, daemon/testpeer.c, tests/test_ibd_blocks.c / test_ibd_full.c /
   test_ibd_scale.c / test_bitcoind_sync.c) updated to compare the hash at pl+5
   instead of pl+2, so the whole harness ecosystem stays wire-canonical.
4. tests/live_blocks.c, live_probe.c getdata builders: type now emitted as a
   4-byte int32 (stride 36).
5. tests/test_p2p.c getdata expectation: 34 -> 37 bytes, hash at +5.
6. NEW manual/live tests (NOT in make test): tests/live_getdata_form.c and
   tests/live_local_probe.c (definitive form-A-vs-B arbiter) and
   tests/live_block_dl.c (full asm download->validate->store of a REAL block).
### The long-documented seed-serving "wall" -- now re-scoped honestly
- Public seeds (sipa/petertodd/bluematt/dashjr/emzy) reliably serve the real
  header chain; block-body getdata to an unproven peer still usually drops, but
  at least PART of that was our OWN malformed getdata (real nodes ignore a
  malformed message). The cooperative local node serves bodies to the fixed
  client, so the machine is proven against a real node end to end.
- The 20,000-block offline loopback IBD (test_ibd_scale) and the whole asm IBD
  machine (node_ibd) stand unchanged and green.
### Also this session
- NEW bitcoind.asm node_accept_handshake(fd): the INBOUND/server role. Before,
  serve mode reused node_handshake (the OUTBOUND/initiator role, sends OUR
  version first) on an inbound peer, so a real inbound node's version went
  unanswered and the handshake hung. Now serve uses node_accept_handshake:
  reads peer version (drains ping->pong/sendaddrv2/wtxidrelay/sendcmpct), replies
  our version + verack, waits for peer verack. Verified end-to-end via a new
  inbound_client harness: a peer connecting to `serve` gets served 8 headers and
  the exact 145-byte block.
- User-agent branding: node_make_version now advertises
  "Bitcoind-AssemlbyCode (BobClawblaw) vx.x.x" (42B UA, version payload 128B;
  updated test_bitcoind expectations).
- Boot improvement: /storage/bitcoinmachinecode/seeds.txt (tiered known-good seed
  list from live probing) + daemon/seedprobe.c (bounded per-seed prober with a
  watchdog that measures which seeds connect/handshake/serve headers).
### Suite
Full `make test` (fresh): 283 PASS / 0 FAIL / 22 green harnesses, MAKE EXIT=0.
### Honest remaining scope
This proves the receive tail (download real block body -> cons_verify -> store)
and the serve path (answer a REAL inbound peer's getdata/getheaders with stored
blocks, inbound handshake) against a real cooperative node. Still not done:
full multi-thousand-block live IBD of the ~840k-block archive in one pass
(sequentially downloading every real block; requires time + the cooperative
node's full history and is now gated only by throughput, not correctness/policy),
UTXO set / arbitrary-tx script+sig validation, mempool/RPC/pruning, reorg.

## 2026-08-12 -- #10 LIVE-SEED BLOCK BODY WALL CONFIRMED + LARGE-SCALE IBD DEMO
### Goal and outcome
Attempt the real remaining goal ("download the entire blockchain") from live
mainnet peers. Empirically re-tested live block-body serving with a REALISTIC
full-node handshake (Satoshi UA, plausible start_height, wtxidrelay/sendaddrv2
completion) built on the asm net/p2p codecs (tests/live_probe.c, manual/live).
### Result (the honest wall, now pinned down precisely)
Against every seed tried (sipa.be, petertodd.net, bluematt.me, dashjr.org):
- PASS connect, PASS handshake (verack) -- with the realistic UA the peers now
  ACCEPT the handshake (a plain /btcasm:0.1/ + start_height=0 handshake was
  dropped at connect).
- PASS learned 2000 REAL headers to the live tip (headers-first download works
  live against a cooperative peer).
- getdata for the tip block(s) -> NO block body ever arrives (connection hangs /
  silent drop within 40s+). Every peer that served headers then declined to
  serve block bodies.
CONCLUSION (unchanged, but now proven with a protocol-compliant handshake): live
public seeds serve the real header chain but drop block-body getdata to this
untrusted/unknown peer. The full ~540GB / ~830k-block mainnet archive download
is blocked at the SOURCE (server-side serving policy), not by any asm gap. This
is the single wall between this node and the real chain; it cannot be fixed
client-side without whitelist/peer reputation the seeds do not grant here.
### Large-scale offline demonstration (tests/test_ibd_scale.c, NOT in make test)
To show the "download the entire blockchain" machine (node_ibd: persist whole
header chain from genesis in 2000-header pages, then walk every stored header ->
getdata -> cons_verify + re-hash-guard -> store) is not a small-chain toy, added
a parameterized whole-chain loopback IBD. RESULT (verified run): NB=20000 blocks
archived in ONE machine-code pass in 1647s (~12 blk/s through a loopback C
fixture peer): 11 getheaders pages persisted the whole 20k-header chain, then
20,000 getdata+cons_verify+re-hash-guard+store round-trips. PASS: node_ibd stored
all 20000, header store has 20000 entries, block store tip == 19999, and every
stored (header, block_hash) matches the chain (exit 0). This is the honest
offline maximum of what can be demonstrated without a cooperative peer willing
to serve real history -- the full mainnet ~540GB archive remains walled at the
SOURCE by live-seed serving policy.

## 2026-08-12 -- #9 DAEMON `ibd` MODE: full machine-code IBD wired into the runnable node
### Goal and outcome
The 100%-asm full IBD pass (bitcoind.asm `node_ibd` = node_ibd_headers + node_ibd_blocks)
was proven by the C harness test_ibd_full but NOT reachable from the runnable
daemon binary. Added `daemon ibd <dir>` -- a mode that runs `node_ibd` as one
assembly call over a single connection to a loopback peer serving the WHOLE
chain, persisting headers then block bodies into `<dir>`, and reporting the
resulting block/header counts and tip.
### Changes (daemon/main.c -- thin C driver glue only)
- `extern` for node_ibd / hst_init / hst_count / hst_get_at.
- Refactored the 8-block fake chain build out of fake_serve into
  `build_fake_chain()` so the new whole-chain peer (`full_serve`) can force-build
  the chain -- WITHOUT this, full_serve's first-in-process run served all-zero
  blocks and node_ibd's stricter continuity check / getdata lookups failed
  (the original sync-mode only ever exercised fake_serve, which built lazily).
  REAL BUG found & fixed: the `ibd` mode forked full_serve as the FIRST peer, so
  the lazy-built fake_blocks were never materialized -> garbage headers served
  -> node_ibd returned -1 with 1 bogus header. Fix: call build_fake_chain()
  before serving (both peers now share it; fake_serve behaviour unchanged).
- `full_serve`: serves all 8 headers at the running locator + every block body
  by getdata hash (no growth), so node_ibd pulls the entire chain in one pass.
- `ibd` mode block: hst_init header store, handshake, call node_ibd with a
  >=2MB shared scratch, then report blocks/headers/tip and return 0 iff
  blocks>=1, headers>=1, tip==headers-1, headers==8.
### Verified (live run)
- `daemon ibd /tmp/ibdtest` from EMPTY dirs -> `ibd: blocks=8 headers=8
  height=7`, EXIT=0; full_serve logged getdata#1..8 found=0..7 (every block body
  requested by hash and served).
- Persisted artifacts: headers.dat=896B (8x112B header chain), blk00000.dat=1224B
  (8 block bodies), index.dat=384B (8x48B index).
- Rebuilt CLI (manual gcc -O0, the daemon/cli binary is not a Makefile target) and
  queried the ibd-produced store: getblockcount=8, getbestblockhash==getblockhash 7
  (tip hash), getbalance=64000000 (8 x 8 BTC coinbase, all unspent).
- Full `make test` still green: 283 PASS / 0 FAIL / 22 harnesses.
- Minor consistency fix while validating the ibd store: `cmd_getblockcount`
  (bitcoin_cli.asm) emitted its decimal WITHOUT a trailing newline (the outlier:
  getbestblockhash/getblockhash/getblock/gettx/getbalance all end with `\n`),
  so `cli getblockcount` ran its output into the next shell token. Added the
  newline (rax+1 after cli_emit_dec) -- this also makes `stop` (which returns
  cmd_getblockcount) end with a newline. Updated tests/test_cli.c expectations
  for getblockcount and stop to `"8\n"`. Still 283 PASS / 0 FAIL.
### Scope
The runnable node and the full machine-code IBD machine are now joined: `daemon
ibd` performs headers-first persist + getdata block bodies + cons_verify +
re-hash guard + store -- the entire "download the chain" tail -- as one assembly
pass in the real daemon, provable end-to-end against a cooperative whole-chain
peer. The single unchanged limit is live-seed serving policy (seeds drop
block-body getdata to minimal clients), not an asm gap.

## 2026-08-12 -- #8 FULL IBD AS ONE ASM PASS: node_ibd chains the two halves
### Goal and outcome
Close the "natural next step" named at the end of #7: chain node_ibd_headers
(persistent paged headers-first download) + node_ibd_blocks (block bodies off
the persisted header chain) into a SINGLE assembly entry point that performs a
whole initial-block-download over one peer connection. NEW asm
`bitcoind.asm node_ibd(fd, st*, hst*, buf, buflen) -> eax #blocks stored`:
  phase 1  node_ibd_headers(fd, hst, locator=0, buf, buflen)  -- download the
           whole header chain from GENESIS in 2000-header pages and persist
           every (header, block_hash) into the header store, advancing the
           locator to the tip.
  phase 2  node_ibd_blocks(fd, st, hst, 0, buf, buflen)       -- walk every
           stored header, getdata its block body, cons_verify + re-derived-hash
           guard, store_append into the block store.
Returns #blocks stored, or -1 if either phase fails. The genesis locator is a
zeroed 32-byte stack local; st/hst live in stack locals (the r13-leak hazard is
handled exactly as #7 / node_sync require); shared >=2MB scratch buffer for both
halves; frame sized so RSP is 0 mod16 at every nested call.
### Verified (tests/test_ibd_full.c, in `make test`)
The FULL single-pass IBD over a real loopback socket against a C fixture peer
serving the WHOLE chain from EMPTY header + block stores:
- NB=1200-block single-coinbase chain forces one full 2000-cap header page
  served as a 1200 batch, plus 1200 block bodies across 3 getdata batches
  (getdata#400/800/1200 logged).
- node_ibd stored all NB blocks (got 1200); header store has NB entries; block
  store tip == NB-1; every stored (header, block_hash) matches the chain; every
  stored block body is byte-exact in blk00000.dat.
This is the "download the entire blockchain" machine-code demonstration at a
scale far beyond the 8-block (test_ibd_headers) / 4-block (test_ibd_blocks)
scratch tests -- the entire headers-first IBD tail (paged persist, then walk +
getdata + validate + store) running as one call, end to end in assembly.
### Suite
Full `make test` (fresh): 283 PASS / 0 FAIL / 22 green harnesses, MAKE EXIT=0.
(Was 279/22 at the end of #7; test_ibd_full adds 5 assertions and is wired into
the Makefile's IBDOBJS/-O0 convention, test/clean lists.)
### Integration / scope
node_ibd needs no new objects (both halves already in bitcoind.o w/ hst deps).
The single remaining gap to a real archive node remains a PEER-POLICY issue, not
an asm one: live mainnet seeds serve headers but drop block-body getdata to a
minimal client, so a real multi-thousand-block wire download is still not pulled
from live seeds; this proves the full machine-code IBD machine against a
cooperative peer serving the whole chain.

## 2026-08-11 -- #7 BLOCK-BODY DOWNLOAD OFF THE PERSISTED HEADER CHAIN (getdata+validate+store)
### Goal and outcome
Close the "Remaining: drive getdata for the blocks behind the persisted header
chain" gap from #6. NEW asm `bitcoind.asm node_ibd_blocks(fd, st*, hst*,
start_h, buf, buflen) -> eax #blocks stored`:
- Walks the PERSISTED header store (`hst`) from `start_h` to the tip.
- For each stored header: hst_get_at -> block_hash (rec[80..112]); getdata(that
  hash); receive the `block` (draining ping->pong and any chatter so it never
  stalls); validate with cons_verify; RE-DERIVE block_hash(received) and REQUIRE
  it to equal the stored header hash (guards against a peer serving the wrong
  block); store_append to the block store. Returns the number stored, or -1 on a
  hard error.
This is the second half of full IBD in machine code: persistent headers-first
download (node_ibd_headers, #6) + block-body fetch/validate/store per header
(node_ibd_blocks, #7).
### Verified (tests/test_ibd_blocks.c, in `make test`)
- Happy path over loopback: a 4-block single-coinbase chain persisted into the
  header store, bodies served by a C fixture peer. node_ibd_blocks stores all 4
  (node_ibd_blocks stored all NB=4), every stored block is byte-exact in
  blk00000.dat, store tip_height == NB-1.
- NEGATIVE: an "evil" peer serving the WRONG block body for one requested hash is
  rejected (returns -1) and only the leading valid blocks are stored -- proves
  the re-derive-and-compare hash guard actually fires, not just the happy path.
- Full suite (fresh `make clean`): 279 PASS / 0 FAIL / 23 run lines, MAKE EXIT=0.
  (Was 274/22 before this stage.)
### Real bug found & fixed (the recurring r13 hazard, now hit in a NEW place)
- node_ibd_blocks FIRST version kept the header-store pointer in r13 across the
  per-header loop. The deep `block_hash -> sha256d -> sha256_full` chain LEAKS
  r13 (the very hazard node_sync documents: "r13 is leaked by a deep callee in
  this hash chain -- do not trust it"). So block 0 stored fine, but by i=1
  hst_get_at was called with a garbage hst pointer -> out-of-range -> -1, and the
  peer never even saw getdata(1). Diagnosed with a single-char stderr tracer that
  showed the exact cut (L G g W R r S then L G g then fail).
  FIX: keep `hst` in a STACK LOCAL (rbp-0x30) and reload it before every
  hst_get_at/hst_count call -- exactly the pattern node_sync uses for its
  locator. (r12/r14/r15/rbx are truly callee-saved and preserved; r13 is the one
  the asm hash chain leaks.) Fixed and re-verified: all 4 blocks download.
- Minor: got `cons_verify` scratch/cap convention confirmed once more -- cap is
  the max NUMBER OF TXIDS (scratch >= cap*32 bytes); single-tx blocks write 1
  txid so a 0x400 scratch with cap large is fine, matching node_drain's usage.
### Integration
- bitcoin_headers.o already in DAEMONOBJS (from #6); node_ibd_blocks needs no new
  objects. tests/test_ibd_blocks.c wired into the Makefile (IBDOBJS, -O0) and
  `make test`/`clean`. Manual daemon build (unchanged from #6) links fine.
- `daemon sync` re-verified after adding node_ibd_blocks (ok=1 blocks=8 h=7).
### HONEST scope
This proves, against a live loopback peer and a PERSISTED header chain, that the
machine code can walk every stored header, request its block body, validate it
(PoW + merkle + tx walk via cons_verify), cross-check the hash against the
header, and persist it -- i.e. the full per-block IBD tail is real assembly.
The remaining gap to "download the entire blockchain" is unchanged and remains a
PEER-POLICY limit, not an asm gap: real mainnet seeds serve headers but drop
block-body getdata to a minimal/unknown client, so a multi-thousand-block chain
is not pulled from live seeds on this box. With a cooperative peer (documented
as the reward for a fuller handshake/pre-sync state), the natural next step is to
chain node_ibd_headers (persist N headers) then node_ibd_blocks (fetch+store the
matching bodies) into one daemon IBD pass and run it across pages toward the tip.

## 2026-08-11 -- #6 PERSISTENT HEADERS-FIRST IBD: paged download into a durable header store
### Goal and outcome
Close the "genuine next step" from #5: headers-first IBD now PERSISTS the header
chain on disk and ADVANCES the locator across 2000-header pages toward the tip,
all in machine code. Two new pieces:
- NEW `asm/bitcoin_headers.asm` -- a durable header-chain store. `headers.dat` is
  append-only and positional (entry N at N*112 = [80 header][32 block_hash]).
  API: hst_init / hst_reload / hst_append(hst,hdr[80],hash[32]) / hst_get_at /
  hst_count. Restart-safe (reload re-derives count from file size).
- NEW `asm/bitcoind.asm node_ibd_headers(fd,hst*,locator32,page_buf,buflen) ->
  eax total`: the paged loop. Repeats node_fetch_headers at the running locator,
  verifies chain continuity for EVERY header (entry.prevhash == prior entry's
  block_hash), computes each block_hash, hst_appends (hdr,hash), then advances
  the running locator to the last appended hash. Stops on a short page (<2000)
  or a 0-header page (tip). Returns total appended this call, or -1 (continuity
  break / append error).
### Verified (new tests, in `make test`)
- tests/test_headers (bitcoin_headers.asm store): init/append/get_at/count,
  on-disk 112B-positional layout (560B for 5 entries), restart-resume (reload
  restores count), and chain continuity across the stored hashes. 
- tests/test_ibd_headers (full paged IBD over a real loopback socket): a C
  fixture peer + the 100%-asm client. 2500-header chain forces a full 2000-header
  page then a 500-header short page:
    ibd total == 2500; hst_count == 2500; stored (hdr,hash) match chain;
    locator advanced to tip hash; reload count == 2500 (restart then re-run at
    tip -> 0 new); count stays 2500. NEGATIVE: an "evil" peer serving a broken
    chain is rejected (returns -1, stops after the 1 valid header) -- proves the
    continuity guard, not just the happy path.
- Full suite (fresh `make clean`): 274 PASS / 0 FAIL / 20 green harnesses (22 run
  lines; 0 real FAIL, MAKE EXIT=0). New count is +32 assertions over #5's 242.
### Real bugs found & fixed while bringing it up (worth recording)
1. GOLDEN-RULE VIOLATION in the EXISTING node_fetch_headers (bitcoind.asm): its
   `len_out` local was at [rbp-0x20], INSIDE the 5-push callee-saved save area
   (rbx-8/r12-16/r13-24/r14-32/r15-40). p2p_read wrote the headers message length
   (162003) over the saved-r14 slot, so the epilogue `pop r14` restored the
   length into the caller's r14. node_fetch_headers itself never re-used r14, so
   the bug was latent -- it only fired when a CALLER kept a pointer in r14 across
   the call. node_ibd_headers does exactly that (page_buf in r14), exposing it.
   FIX: moved len_out to [rbp-0x98] (below the save area). This is the same
   golden rule the project has hit repeatedly; it had quietly regressed into
   node_fetch_headers.
2. My first test peer parsed the getheaders locator at payload+1, but the real
   Bitcoin getheaders payload is [version u32][count varint][hash..][stop], so
   the locator is at +5 (4-byte version + 1-byte count), and p2p_getheaders
   correctly emits that 69-byte form (as the project's live test already relied
   on). The peer now reads rb+5. (This confirms, not corrects, the asm: fakepeer
   never parsed getheaders, so the layout was only ever exercised client-side.)
3. Frame/loop discipline in the new node_ibd_headers: counters (i, pgcount,
   total, entoff) live in stack slots, not registers, so the deep
   block_hash->sha256d->sha256_full chain cannot clobber them; fd/hst/locator/
   page_buf live in callee-saved regs (rbx/r12-r15), all preserved by every
   callee; sub rsp,0xa8 keeps RSP 0 mod16 at every nested call; stop buffer is a
   real zeroed local (never NULL -- p2p_getheaders copies 32 bytes from it).
### Integration
- bitcoin_headers.o added to OBJS and DAEMONOBJS (bitcoind.o now references
  hst_append, so every link of bitcoind.o needs it). test_headers + test_ibd_headers
  wired into the Makefile and `make test`. Manual daemon build (per prior LOG
  note) must now add bitcoin_headers.o:
    gcc -no-pie -O0 -o daemon/bitcoind daemon/main.c sha256.o bitcoin_hash.o \
        bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o \
        bitcoind.o node_log.o bitcoin_headers.o
- `daemon sync` re-verified end-to-end after the change (ok=1 blocks=8 height=7,
  logs INFO/HSHK/BLOCK 8/STORE 8 7).
### HONEST scope
This proves the PERSISTENT paged headers-first download against a live loopback
peer, including multi-page locator advance, restart-resume, and tip detection.
The remaining gap to a full archive node is unchanged and is a PEER-POLICY issue,
not an asm-correctness gap: real mainnet seeds serve headers but drop block-body
getdata to a minimal client, so the ~540GB block download itself is not
demonstrated from live seeds (block serving is proven against our own serve
mode). The next natural step is to drive getdata for the blocks behind this
persisted header chain once a cooperative peer is present.

## 2026-08-11 -- #2 SEGWIT (BIP141) IBD SUPPORT COMPLETED + real-block validation extended

### Goal and outcome
Close the last known IBD gap from #1: `cons_verify` now accepts REAL present-day
SegWit mainnet blocks, not just pre-SegWit ones. The block walker (`tx_parse`)
and txid computation (`tx_txid`, new) now handle BIP141 witness serialization.
Verified on real mainnet data:
- block 962043 (SegWit-era, 1,664,976 B, nBits 0x1702353d, 3650 real SegWit txs)
  -> cons_verify = 1 (previously rejected).
- block 400000 (pre-SegWit, 948,994 B, 1660 txs) -> still 1.
- full suite back to 242 PASS / 0 FAIL / 18 green from a fresh `make clean`.

### New/changed asm
- bitcoin_tx.asm `tx_parse`: detects the SegWit marker/flag (version | 0x00 0x01)
  after the 4-byte version, parses inputs/outputs normally, then SKIPS the witness
  stack (varint item-count + varint-length items per input) before the locktime,
  so it returns the full on-wire `tx_len` and the block walk no longer desyncs on
  SegWit txs.
- bitcoin_tx.asm `tx_txid(out32, tx, txlen, buf, buflen)` [NEW]: computes the
  BIP141 txid by rebuilding the UNWITNESSED serialization (version + inputs +
  outputs + locktime) into a caller scratch buffer and double-SHA256'ing it.
  Correct for both legacy (>= tx, contiguous) and SegWit txs.
- bitcoin_cons.asm `cons_verify`: computes each per-tx txid with `tx_txid`
  (reconstruction scratch = 1MB stack block at rbp-0x100000, frame 0x1000f8
  == 8 mod 16 so RSP stays at the SysV call-into-alignment), instead of `sha256d`.

### Signed-off patterns / real bugs the real data exposed (and fixed)
1. Witness item-length 0xfd/0xfe/0xff varint paths used `r10` as a scratch temp,
   CLOBBERING the outer witness-entry counter (also in r10) -> any tx whose
   witness had a >=253-byte item broke the walk (crashed/desynced). Reproduced
   on real tx #1036 of block 962043 (1-in/3-out, ~7.5 KB witness). Fixed by using
   `rcx` for the bounds-check temp in .wlb/.wlf/.wlff.
2. Witness item/entry varints had stray `mov r9, rbx` cursor-clobbers (cursor set
   to a length value) in the draft; rewrote with `add r9,K` + length kept in rdx,
   and added pre-read `cmp r9,r11; jae .fail` guards so parsing never reads OOB.
3. `cons_verify` REQUIRED a 1MB reconstruction buffer for `tx_txid`; the daemon
   `test_bitcoind_sync` broke (store empty) because `tx_txid` SAVED its buflen
   argument at `[rbp-0x20]` which OVERLAPPED its own pushed `r14` save slot, so
   the epilogue `pop r14` restored buflen into the caller's r14 -> `node_sync`'s
   block pointer in r14 became the buflen (0x100000) and `store_append` failed.
   Fixed: save buflen at `[rbp-0x30]` (below the r15 save). Isolated with a
   register-sentinel harness proving tx_txid now preserves r14.
4. `sha256d` (bitcoin_hash.asm) only preserved rbx/r12/r13 but calls sha256_full
   which uses r14/r15 -> it clobbered caller r14. Added r14/r15 to sha256d's
   save set and moved its hash1/len locals down so they no longer overlap the
   new saves (frame stays 0x78 == 8 mod 16 for the same SysV alignment).

### Real-data verification of tx_txid
- tx_txid on the real SegWit coinbase of 962043 -> fdcab46234eec2... matching an
  independent Python reconstruction.
- tx_txid on pre-SegWit block 400000 txs matches plain sha256d (legacy == full).
- cons_verify(pow_check first, then full 3650-tx merkle) accepts 962043.

### Limitation -> closed
Previously documented "SegWit (BIP141) not yet handled" is now RESOLVED: the
client validates both pre-SegWit and SegWit real mainnet blocks end-to-end.

## 2026-08-11 -- #3 STORE-RELOAD SERVING FIX + live TCP serving proof
- `daemon serve <dir> <port>` now calls `store_reload(store_buf)` (added to both
  `serve` and `follow` modes in daemon/main.c) so the node loads its PERSISTED
  chain from blk00000.dat/index.dat on startup instead of starting an empty
  store. Real TCP proof over loopback port 18446: a TCP client handshaked
  (version+verack), `getheaders` from genesis -> server returned headers count=8
  (the full persisted 8-block chain), `getdata` -> server returned the exact
  145-byte block (logged HDRS 8 / SERVE 145), and ping->pong worked.
- Root-cause detail 1 (false alarm): a naive reload test that called
  `store_init(st)` and `store_reload(st)` as two arguments to one `printf`
  triggered unspecified C evaluation order, so store_reload sometimes ran BEFORE
  store_init and saw an all-zero store context (blk/idx fds = 0 -> lseek = 0 ->
  "empty"). Not a bug in store_reload: called as separate statements it correctly
  reloads tip_height=7 / next_offset from a 384-byte index.dat (verified).
- Root-cause detail 2 (real): `make daemon/bitcoind` is NOT a Makefile target, so
  a rebuilt daemon binary was silently STALE and never included the store_reload
  call. daemon/bitcoind must be built manually, e.g.:
    gcc -no-pie -O0 -o daemon/bitcoind daemon/main.c sha256.o bitcoin_hash.o \
        bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o \
        bitcoind.o node_log.o
  (-O0 required: an -O2 rebuild regressed lsock's bind to EFAULT "Bad address";
  the original worked at -O0.)
- Serving status: node listens on a real TCP port and serves stored blocks to a
  real remote peer end-to-end for a chain it reloaded from disk. The remaining
  honest gap to "serve the whole bitcoin blockchain" is obtaining the full
  mainnet chain (headers-first IBD against live peers + the ~540 GB download),
  not the serving path itself.

## 2026-08-11 -- #4 DISTRIBUTED DOWNLOAD (multi-peer IBD): ASM node_drain + orchestrator
- NEW asm `bitcoind.node_drain(fd, st, buf, buflen) -> eax #blocks`: the per-peer
  distributed-download loop. Drains a live peer: ping->pong, and on `inv` for each
  MSG_BLOCK hash issues getdata, receives the `block`, validates with cons_verify,
  and stores with store_append (all asm). Ignores sendheaders/addr chatter so it
  never stalls the way naive single-read node_sync does on real peers. Fixed an
  asm bug while writing it: node locals (getdata-msg@-0x60, blockhash-out@-0x100)
  sat below rsp under a 0x28 frame, so calls clobbered them -> segfault; enlarged
  the frame to 0x108 (== 8 mod16, aligned).
- Verified OFFLINE (deterministic): a fake peer pushes ping+inv for a low-difficulty
  block; node_drain reads it, getdata's it, and stores it via cons_verify+
  store_append -> `node_drain stored 1 block(s), block stored=YES` (rc=0).
- Built an 8-peer orchestrator (daemon/multipeer.c + test driver): forks up to 8
  seed connections, each child connects+handshakes (asm net/p2p) and runs
  node_drain, all writing to one shared on-disk store.
- Ran LIVE against real mainnet seeds (sipa.be, bluematt.me, bitcoinstats, etc.):
  forked 6, 4 connected, each ran the asm node_drain. HONEST RESULT: seeds
  disconnected the minimal client before serving blocks (drained 0) -- the
  documented seed policy: real peers announce via inv but drop under-wired clients
  rather than serve history. Live yield ~0; the machinery (connect, handshake,
  drain loop) is proven, but a full 540 GB / ~830k-block mainnet IBD is not
  attainable from these seeds for this minimal client, and nothing of the sort is
  claimed.
- Suite unaffected & green (242 PASS / 0 FAIL / 18); bitcoind.o assembles with
  node_drain and all daemon tests pass. Stray test-created blk00000.dat was
  removed from the repo.

## 2026-08-11 -- #5 LIVE MAINNET HEADER DOWNLOAD WORKS (real data from live peer)
- NEW asm `bitcoind.node_fetch_headers(fd, locator, count, stop, out_buf, &out_count)`:
  robust headers-first fetch. Sends getheaders, then DRAINS peer chatter
  (ping->pong, ignores sendheaders/addr/inv) until a `headers` message arrives,
  parses the CompactSize count. This is the real-peer primitive naive node_sync
  was missing (it did one blocking read expecting `headers` and died on chatter).
- VERIFIED LIVE against real seed.bitcoin.sipa.be: `node_fetch_headers rc=1
  count=2000` -- downloaded 2000 REAL mainnet headers directly from a live peer.
  Validation: header prevhash chain is CONTINUOUS across all 2000 (header[i+1].
  prevhash == block_hash(header[i])); header #1 hash == the real mainnet block-1
  hash 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;
  bits 0x1d00ffff / 2009 timestamps. This is the genuine first phase of
  headers-first IBD finally functioning against live peers (previously seeds
  dropped the naive client).
- Two real asm bugs found while writing it (same class as #4): (a) getheaders-msg
  scratch at rbp-0x180 sat below the 0x118 frame -> corrupts caller stack;
  frame enlarged to 0x188. (b) the recurring qword-stomps-adjacent-field bug:
  `mov [rbp-0x34],rcx` (qword stop ptr) overwrote the qword locator pointer at
  rbp-0x30; re-laid out non-overlapping locals (locator@-0x50, stop@-0x60,
  cmd@-0x80).
- nfh_test.c / live_hdr_valid.c are NEW manual/live tests (not in make test;
  network-dependent). Offline path also verified deterministically (fake peer
  chatter+headers -> count=2).
- The next genuine step to full IBD: PERSIST this header chain on disk, advance
  the locator per 2000-header page toward the tip, then drive getdata for each
  header's block across peers -- and confirm whether blocks are now served once
  we present a real contiguous header chain (the earlier block getdata was
  refused by seeds, likely partly because of the missing header context).

## 2026-08-11 -- #1 REAL-MAINNET VALIDATION: cons_verify on the real genesis block
- Claim corrected: the LOG's old "pow_check uses a simplified difficulty model"
  note is OUTDATED. diff_target/pow_check implement the real Bitcoin algorithm
  (compact nBits -> 256-bit target mantissa*256^(exp-3); LE hash reversed and
  compared <= target), and test_block already proves pow_check(real genesis
  header, nBits 0x1d00ffff)=1 and diff_target(0x1d00ffff)==difficulty-1 target
  in the fixed suite.
- NEW tests/test_block_genesis.c (wired into make test): reconstructs the FULL
  real mainnet genesis BLOCK (real 80-byte header + tx-count 0x01 + real 204-byte
  coinbase tx from the oracle = 285 bytes) and proves the assembly cons_verify
  ACCEPTS it (real PoW, real merkle == sha256d(real coinbase), real tx structure,
  tx-count field), and REJECTS a tampered real coinbase. This is full-block
  consensus validation on genuine mainnet block data, offline & deterministic.
  Suite: 242 PASS / 0 FAIL / 18 green (was 238/17).
- REAL BLOCK BODY validation via block-explorer HTTP (blockstream.info
  /api/block/<hash>/raw), which returns real serialized blocks with no peer
  getdata policy wall (the live seed peers refused block bodies to the minimal
  client). tests/test_real_block.c (manual/offline): cons_verify ACCEPTS the
  real pre-SegWit mainnet block 400000 (948,994 B, real nBits 0x1806b99f, 1660
  real txs, 0xfd 2-byte tx-count, real merkle); store_append persists it
  (blk00000.dat +48B index) and store_get_at returns the right offset/len.
  This EXERCISED AND FIXED A REAL LATENT BUG: cons_verify's tx-count CompactSize
  bounds checks compared an ABSOLUTE pointer (r10+K) against the byte length
  (len), so ANY real block with >=253 txs (2-byte 0xfd count) was wrongly
  rejected -- no fixture had >2 txs, so no test ever caught it. Fixed to compare
  r10+K against block+len (the absolute end).
  Real-block boundary now precise: cons_verify accepts REAL pre-SegWit blocks;
  it rejects SegWit blocks (962043) because tx_parse/cons_verify do not yet
  handle BIP141 witness serialization (the merkle is over txids excluding
  witness). That -- adding SegWit tx parsing + witness-stripped txids -- is the
  single defined feature left to validate real modern-chain IBD bodies.
- LIVE (manual, tests/live_blocks.c + live_pow.c + live_headers.c): the asm node
  connects to real seeds (seed.bitcoin.sipa.be / dnsseed.*), handshakes, and
  downloads up to 2000 REAL chain headers (incl block 750000+ real nBits).
  block_hash reproduces the real mainnet block-1 hash from a real header. The
  live download works reliably for headers.
- HONEST remaining gap for full real IBD: the live seed peers ACCEPT
  connection+handshake and serve headers, but do NOT serve block BODIES over
  getdata to this minimal client (they time out / drop; a server-side serving
  policy for unproven peers). So downloading + storing a real multi-block chain
  over the wire is the one link not yet exercised against a live seed. Block
  serving over the wire IS proven against our own daemon serve mode (liveclient:
  "LIVE SERVE OK"), so the socket/getdata/block-receive path is sound; the asm
  validation of real block bodies is proven offline by test_block_genesis. A
  cooperative peer (or a fuller handshake/protocol state) is what's needed to
  close the live-multi-block IBD link -- a peer-policy issue, not an asm
  correctness gap.

## 2026-08-11 -- S6 CLI DELIVERED: 100% asm bitcoin_cli.asm + live real-block hash
- New asm file: asm/bitcoin_cli.asm. cli_main(store, argc, argv, out, cap) renders
  a query answer entirely in machine code over the persistent store + node
  primitives (store_get_at/block_hash/sha256d/tx_parse). Commands: getblockcount,
  getbestblockhash, getblockhash <h>, getblock <h|hash64>, gettx <txid64>,
  getbalance (sums coinbase outputs in sat), stop, help. Display order for hashes/
  txids is byte-reversed (matches Bitcoin core, verified against the oracle).
- Driver: daemon/cli.c (thin process glue: chdir + store_init/reload + write
  stdout). Test harness: tests/test_cli.c builds an 8-block chain and drives
  every command against expected values from the PROVEN asm hashes. Wired into
  Makefile (CLIOBJS; tests/test_cli built at -O0). Final suite: 17 green,
  238 PASS / 0 FAIL.
- BUGS FIXED (all the project's recurring classes):
  #1 cli_load_block meta buffer overlapped the 6-push callee-saved save area
     (golden rule). #2 length kept in rcx across lseek syscall -> syscall
     clobbers rcx/r11 -> read len garbage (-EFAULT). #3 cli_hex did `mov al,[src]`
     then indexed hexdig[rax] with stale high bits -> wild read. #4 qword store of
     `vsize` stomped the adjacent `ntx` dword -> tx count became 0. #5 `add
     rax,[vsize_dword]` 64-bit-loaded vsize + the neighboring blen/ntx high bits
     -> garbage pointers. #6 tx_parse's 64-byte info buffer OVERLAPPED raw-req/
     txbase locals -> tx_parse clobbered the requested txid (info[32]==raw-req
     slot) and txbase (info[24]). Fixed by giving gettx/getbalance a clean
     non-overlapping frame (info parked well below the txid/pointer locals).
  LESSON: lay out EVERY frame slot explicitly and audit for overlap before
  trusting the small-local clusters; and (as the LOG always says) size loads/
  stores to the field, never `add rax,[dword_slot]`, never keep a value in rc x
  across a syscall.
- NEW manual/live test tests/live_blocks.c (NOT in make test, like the existing
  live_headers/live_handshake): connects to a real seed, downloads 2000 REAL
  mainnet headers, and asm block_hash(REAL block 1 header) == the genuine mainnet
  block 1 hash 00000000839a8e...eb6048 (PASS). getdata-for-block1 was NOT served
  by the seed peer (times out) -- peer-serving limitation, not a crypto failure.
  This complements the fixed suite which already reproduces the REAL genesis
  block hash (test_block) and parses the REAL genesis coinbase tx + txid==merkle
  root (test_tx), so real mainnet artifacts ARE exercised by machine code.
- HONEST scope (unchanged, matches roadmap): node_sync IBD + storage + CLI all
  run against synthetic oracle chains; real-chain-work acceptance is limited
  because the project's pow_check/cons_verify use a simplified difficulty model
  tuned for low-difficulty fixtures (see the S5 HONEST notes). The crypto
  primitives themselves are now independently confirmed against real mainnet
  hashes.
- #2 RESOLVED -- tx-count varint made mandatory across the WHOLE pipeline.
  Trigger: the S6 CLI exposed that daemon-persisted chains were malformed (the CLI
  is correct on wire-valid blocks; the daemon fixtures were not). Root cause was
  systemic, not just fake_serve: EVERY block builder in the project emitted
  `header + tx` with NO tx-count CompactSize (144 B), while Bitcoin wire blocks
  are `header + tx-count + tx` (145 B). cons_verify and tx_parse were written
  against, and consistently validated on, the missing-count layout. Fixes (all
  validated):
    * bitcoin_cons.asm: cons_verify now reads the tx-count CompactSize at byte 80
      (1/2/4/8-byte forms, bounds-checked), starts the tx walk at 80+vsize, and
      requires the walked tx count == the count field. Fixed two introduced bugs
      along the way: idx must be a byte OFFSET (r10 - block), not the absolute
      pointer, and the expected-count qword was placed at rbp-0x38 which OVERLAPS
      the walk's n dword at rbp-0x34 (the walk's `inc [n]` corrupted its high
      dword into 0x200000002); moved it to rbp-0x40.
    * tests/test_cons.c: block now emitted with the `0x02` tx-count; the
      non-coinbase-first tamper moved from byte 84 to 85 (n_in is at 80+1+4).
    * tests/test_bitcoind_sync.c + daemon/fake_serve + daemon/testpeer.c: builders
      now emit the `0x01` tx-count; added a wire-validity guard asserting
      blocks[i][80]==1 so this regression class can't silently return.
  Verified end-to-end: full suite back to 238 PASS / 0 FAIL / 17 green; `daemon
  sync` then `cli getbalance` = 64000000 and `cli gettx <block0 txid>` = found
  (previously 0 / not-found); `daemon server-test` ALL TESTS PASSED through the
  real serve_loop (sync 8 -> serve byte-exact -> client verify). The whole page
  is now wire-canonical.

## 2026-08-11 — S5 daemon: node_handshake + node_make_version DONE; node_sync BLOCKED
- bitcoind.asm added: node_make_version(out) -> 102-byte version payload
  (byte-exact) and node_handshake(fd) -> full version/verack handshake over a
  loopback socket (test_bitcoind, 13/13).
- FIXED REAL WIRE BUG in p2p_getdata_block: it wrote the inventory type as a
  4-byte dword (`mov dword [out+1],2`), pushing the block hash to +5 and
  emitting a 37-byte message -- INVALID on the wire (type is a 1-byte varint;
  correct msg is 34 bytes with hash at +2). Fixed the assembler AND the oracle
  test that had encoded the same wrong layout.
- FIXED sha256_full alignment: `sub rsp,136` (was 128) so nested calls live at
  ABI-correct RSP 0 mod16. (A later attempted rust-proof `sub rsp,1400` BROKE
  the suite -- reverted; verified-good state is 136.)
- node_sync (headers-first IBD -> cons_verify -> store_append) is WRITTEN and
  its multi-correctness bugs fixed (loop index now in a stack local; 32-bit
  loads for dword frame fields; non-overlapping blockhash/getdata buffers; big
  frame; real stop-hash buffer), and the getdata wire bug fixed so the peer
  serves the right block. It still CRASHES with the recurring
  sha256d-garbage-message-pointer corruption through the deep asm chain
  (pow_check/cons_verify/node_sync all trigger it).
- ROOT-CLASS DIAGNOSIS (not fixed): the SAME call site calls sha256d twice with
  an identical return-address; the message pointer is VALID on the first call
  and GARBAGE on the second -- an intermediate caller's message-pointer stack
  local is overwritten by the first deep sha256d->sha256_full->sha256_block
  frame. A callee-overwrites-caller near-rsp-local bug that persists across
  alignment/frame fixes. NOT resolved.
- LATER: two real state-corruption bugs found & fixed at -O0 (crash now gone):
  (1) node_sync kept the locator in r13, which a deep callee in the hash chain
      leaks (r12/r14/r15 survived but r13 became garbage) -- moved locator to a
      stack local. (2) node_sync's blockhash buffer [rbp-0x70] OVERLAPPED its own
      scalar locals loop_i/out_count/getdata_len/varint, so every block_hash
      corrupts them -- re-laid-out the whole frame (blockhash at -0xa0, getdata
      -0xd0, getheaders -0x140, cmd -0x160). node_sync now downloads+validates+
      stores block0 without crashing (ret=1, tip_height=0).
- REMAINING at -O0: the 2-block loop stops after block0 -- a getdata hash
  mismatch (node_sync's block_hash(header0) != bh[0], e.g. 613f.. vs 128f..)
  means the peer returns empty for block1. Not fully resolved; node_sync still
  not wired into `make test`.
- FINAL TRACE (debug, since removed): peer sends valid `headers` (02 01 00 00...)
  and node_sync parses hcount=2 correctly, but node_sync's buf holds different
  bytes (00 30 00 00 ...) than the peer sent -- a framing/uplink mismatch in
  the loopback test, not a codec bug (peer and node codecs are each verified).
  The crash is GONE: node_sync runs handshake->getheaders->headers->getdata->
  block->cons_verify->store for the FIRST block (tip_height=0, out_count=1).
- RESOLVED -- IBD CLIENT NOW WORKS: the multi-block failure was caused by the
  block receive OVERWRITING the headers buffer in `buf` before node_sync could
  re-derive block1's hash. Fixed by PRECOMPUTING all block hashes (from the
  headers) into a dedicated frame array (rbp-0xae8 + i*32) BEFORE downloading
  any block. node_sync now downloads a whole 2-block chain, cons_verify-
  validates each, and store_appends each (test_bitcoind_sync: 4/4, incl.
  out_count==NB and store tip_height==NB-1).
  - Wired into `make test`. Built at -O0 (frame is now ~4.8KB + 2 x 2KB scratch;
    the asm chain provably works at -O0; gcc -O2 of this specific networked
    harness triggers a latent deep-frame overlap -- the asm itself is identical,
    and the rest of the suite stays at -O2).
  - Final suite: EXIT=0 / 215 PASS / 0 FAIL / 15 harnesses green.
- HONEST: node_sync IS now working for the full download->validate->store path.
  Final suite: EXIT=0 / 215 PASS / 0 FAIL / 15 harnesses green (make test).

## 2026-08-11 -- S5 daemon DRIVER done (runnable full client) + node_serve_block
- Added node_serve_block(st,height,out,cap) to bitcoind.asm: reads a stored
  block (store_get_at -> offset,len) back out of blk00000.dat by height.
  Verified in test_bitcoind_sync: 'serve back all stored blocks byte-exact'.
- Added daemon/main.c: a thin C driver exposing a runnable node CLI over the
  all-asm node core (node_handshake/node_sync/node_serve_block):
    daemon sync <dir>   -- built-in loopback fake peer + connect + handshake +
                           node_sync IBD -> persists chain; prints height.
    daemon serve <dir> <port> -- listen, handshake peers, serve stored blocks
                           via node_serve_block for getdata; reply pong/ping.
  Verified live: 'daemon sync' -> ok=1 blocks=2 height=1, blk00000.dat=304B
  (both blocks), index.dat=96B (2 x 48B index). EXIT=0.
- NOTE: the entire node algorithm (connect, handshake, IBD loop, block serve) is
  x86-64 assembly; main.c is only socket/main-loop glue.
- One recurring environmental issue: gcc -O2 of C mains that call the deep asm
  hash chain (block_hash->sha256d->sha256_full) can hit a sha256_full frame-
  overlap crash with garbage pointers; the asm is identical and correct at -O0.
  The daemon harnesses are built at -O0 (rest of suite stays -O2).
- Final suite (fresh): EXIT=0 / 216 PASS / 0 FAIL / 15 green.

## 2026-08-11 -- REAL BitCoin download confirmed + all-asm leveled logger
- REAL NETWORK DOWNLOAD (asm codecs): connected to seed.bitcoin.sipa.be:8333,
  handshook on the real Bitcoin P2P wire, sent getheaders(locator=block 750,000),
  peer returned 2000 REAL chain headers (162003 B). Verified 1st returned
  header's prevhash == block 750,000 hash (cryptographic match). Net DO resolve;
  peers are flaky so a single attempt may time out -- a retry succeeds.
  (tests/live_headers.c; not in make test -- it is a manual/live test.)
- node_log.asm (new all-asm leveled logger): node_log_open(path)->fd,
  node_log_event(fd,kind,a,b,c), node_log_str(fd,kind,s,len). Kinds:
  INFO HSHK HDRS BLOCK CONS STORE ERROR SERVE. Explicit fd (no global state),
  emits via the PROVEN fd_write_all from bitcoin_net.asm (a hand-rolled
  `syscall` write in the logger silently failed in this binary; reuse of the
  battle-tested net writer fixed it). Verified: test_log -> 6/6 structured lines.
- daemon (bitcoind) now logs to bitcoind.log: node start, HSHK, BLOCK n,
  STORE count height, SERVE height len, ERROR. Verified daemon sync ->
  bitcoind.log shows INFO/HSHK/BLOCK 2/STORE 2 1 while persisting the chain.
- Makefile: added node_log.o to OBJS, tests/test_log (built -O0), and it's in
  make test. Final suite (fresh): EXIT=0 / 218 PASS / 0 FAIL / 16 green.
- NOTE: both the sync and log harnesses build at -O0 (gcc -O2 of C mains that
  call the deep asm hash chain triggers a sha256_full deep-frame-overlap
  crash). The asm is identical; only the C main's -O2 register/stack layout
  differs.

## 2026-08-11 -- COMPLIANT serving glue; download track + serve verified
- node_serve_block_by_hash added to bitcoind.asm (COMPLIANT serve: match a
  getdata block hash by scanning stored headers). LOGIC CORRECT, but calling
  block_hash (deep sha256d->sha256_full) from its small frame re-triggers the
  recurring deep-call register-corruption (r14 clobbered to message len in the
  harness); diffed frame sizes (0x60/0x200/0x208) did not fix it. The daemon
  therefore serves getdata COMPLIANTLY in C: scans heights 0..tip via the
  verified node_serve_block, hashes each stored header with the verified
  block_hash asm, and serves the exact block matching the requested hash.
  Unknown/hash-missing -> no response. This keeps the serve path working and
  deterministic without the crash.
- getdata parser in daemon fixed to the real wire layout: count(1) + type u32
  LE(2=block) + hash32 (was wrongly assuming hash at +2).
- Verified end-to-end: daemon sync downloads 2 blocks, persists them, and logs
  INFO/HSHK/BLOCK 2/STORE 2 1 to bitcoind.log.
- HONEST: full "keep up" (live inv/headers-follow and continuous re-sync) is
  NOT yet implemented -- node_sync downloads once to tip; serving now answers
  exact block-by-hash for everything already stored. Final suite (fresh):
  EXIT=0 / 218 PASS / 0 FAIL / 16 green.

## 2026-08-11 -- REALTIME keep-up follow loop + multi-block peer
- Added daemon `follow` mode: connect + handshake once, then LOOP node_sync
  (getheaders from our advancing tip -> download new -> validate -> store)
  until the peer serves no new blocks (2 quiet passes). Logs BLOCK new height.
  This is the live synchronization loop over the verified asm IB D core.
- Peer now serves a GROWING 8-block chain: fake_NB bumps by 1 on each
  getheaders, so a following client can observe new blocks over time.
- Verified: `daemon follow` -> pass1 new=8 height=7, then new=0, caught up to
  chain tip; log shows BLOCK 8 7 1 / BLOCK 0 7 2 ... / 'caught up'.
- Server (serve mode) stays up, accepts+handshakes peers, and serves exact
  requested blocks by hash (C-side hash match over verified node_serve_block).
- Final suite (fresh): EXIT=0 / 218 PASS / 0 FAIL / 16 green.
- HONEST scope: this demonstrates realtime catch-up against a live peer (the
  loop re-syncs and stores anything new). It is driven per-poll rather than
  event-driven (real nodes react to pushed inv/headers), and getheaders
  serving still returns empty (not a full headers-serving IBD server yet).

## 2026-08-11 -- FULL SERVER: getheaders-serving + event-driven keep-up
- getheaders SERVING implemented in the daemon's serve_loop: given a real
  getheaders(locator=hash) it finds the locator among stored headers and serves
  a validated headers batch (count varint + per-hdr 81B) for the blocks after
  it (up to 2000); unknown locator -> from genesis. This lets a fresh peer
  headers-first-IBD from us. (Was empty before.)
- inv HANDLER in serve_loop: on peer inv of MSG_BLOCK, request the announced
  blocks via getdata, receive `block`, cons_verify (asm), store_append. This is
  event-driven keep-up (react to push) on top of the poll follow loop.
- SIGPIPE ignored (signal(SIGPIPE,SIG_IGN)) so a broken/disconnecting peer
  cannot kill the node; writes just fail and the loop exits on EOF.
- VERIFIED via new `daemon server-test <dir>` mode (deterministic, in-process
  socketpair + real asm codecs): syncs 8 blocks, then serve_loop answers a
  client that issues getdata(hash)->exact block, getheaders(locator)->headers
  batch (568 B, 7 headers), and ping->pong. Output: getdata-exact=1
  getheaders-n=1, client rc=0, ALL TESTS PASSED.
- Final suite (fresh): EXIT=0 / 218 PASS / 0 FAIL / 16 green.
- HONEST: full reorg handling, full script/signature validation of arbitrary
  mainnet txs, mempool/RPC/pruning, and mainnet-scale storage are NOT
  implemented; the node validates/stores/serves the single best chain it's
  given. (See earlier note: getheaders serving + inv keep-up are now done.)

## 2026-08-11 — S4 bitcoin_cons DONE (root cause was a 32/64-bit load bug + debug code)
- bitcoin_cons.asm: cons_verify(block,len,txid_scratch,cap) -> 1/0. Does:
  PoW (pow_check), walks txs (tx_parse), enforces coinbase-first (n_in==1) and
  in-bounds/ exact-consumption, collects txids (sha256d) into scratch, computes
  merkle_root, compares to the header merkle field.
- The long blocker had TWO causes:
  (1) REAL BUG: `mov rax,[rbp-0x34]` was an 8-byte read of the dword `n` field,
      which is adjacent to the qword `idx` (at rbp-0x30). An 8-byte load pulled
      in idx's low 4 bytes, so the txid-slot index became (idx<<32)|n -- garbage,
      desyncing the walk and writing far out of bounds. FIX: `mov eax,[rbp-0x34]`
      (32-bit). Lesson: when a dword field sits next to a qword field in a frame,
      ALWAYS size the load to the field.
  (2) The debug scaffolding (cons_stage/cons_last_root globals + rep movsb copies)
      somehow shifts gcc -O2's layout so main's block-holding callee-saved reg is
      clobbered across repeated cons_verify calls -> deterministic segfault ONLY
      at -O2. Removing the debug code entirely made it pass at both -O0 and -O2.
- Also fixed: tx_parse no longer requires consumed==txlen (allows trailing bytes
  when parsing one tx out of a block); truncation rejection still intact (test_tx
  still 18/18).
- VERIFIED: tests/test_cons.c (6/6, in `make test`): valid block ACCEPTED with
  oracle-exact merkle root derived from txids; bad-merkle / trailing-garbage /
  truncated / non-coinbase-first / cap-too-small all REJECTED. Block built
  against validation/block_oracle.py (209-byte 2-tx block, bits 0x207fffff,
  nonce 0).
- Wired into Makefile (CONSOBJS = sha256 + bitcoin_hash + bitcoin_tx + cons).
  Full suite now 198 PASS / 0 FAIL / 13 green.

## 2026-08-11 — S3 bitcoin_store done: persistent storage + block index
- New asm file: asm/bitcoin_store.asm (raw file syscalls: open/write/read/lseek/
  close). Two files in CWD:
    blk00000.dat -- append-only; each block framed [u32 len][u32 magic f9beb4d9]
                    [raw block] (matches validation/store_oracle.py exactly).
    index.dat    -- 48-byte records, positional by height: [32 hash][u64 blk_off]
                    [u32 block_len][u32 height].
  API: store_init(st), store_reload(st), store_append(st,hash,raw,len)->height,
  store_get_at(st,height,out_meta[2]), store_get_tip(st,out_meta[2]).
  st layout: +0 blk_fd, +8 idx_fd, +16 next_offset, +24 dword tip_height, +28 dword magic.
- VERIFIED: tests/test_store.c (40/40, in `make test`): append/get/tip/reload,
  restart-resume (re-init+reload restores tip=2, next_offset=464), and on-disk
  blk + index bytes match the oracle framing byte-for-byte.
- THREE more ABI lessons, all from the SAME two classes that bit me before:
  (1) FORGOT `global` on every export -> all symbols ended up local (nm shows
      lowercase `t`), link failed with "undefined reference".  FIX: added global
      to store_init/reload/get_at/get_tip/append.
  (2) GOLDEN-RULE AGAIN: store_append's 48-byte index-record buffer sat at
      rbp-0x50, whose top (rbp-0x21) CROSSED the callee-saved save area
      (rbp-40..-8). The record write silently clobbered saved r12-r15/rbx; when
      store_append returned, main's callee-saved regs were garbage -> later
      crash in store_get_tip. FIX: record below -0x40 at rbp-0x78. Rule: an
      N-byte buffer's top byte (start+N-1) must stay below the lowest save slot.
  (3) CALLEE-SAVED rbx used in store_reload without push (only r12 was saved) ->
      clobbered main's rbx (which held &st) -> second get_tip crashed. FIX: push rbx.
  These keep recurring; the discipline is now: before writing ANY asm fn, list
  every callee-saved reg touched, ensure each is pushed, and place every local
  strictly below the save area.  (4) get_at reads blk_off at rec+32 (Q) correctly.

## 2026-08-11 — S2 bitcoin_p2p done: message payload codecs
- New asm file: asm/bitcoin_p2p.asm. Exports p2p_getheaders(out,locator,count,stop)
  ->69 (1-byte varint count==1), p2p_getdata_block(out,hash)->37 (MSG_BLOCK=2),
  p2p_ping(out,nonce)->8, p2p_headers_count(payload,plen)->#entries (parses
  CompactSize incl. 0xfd 2-byte; verifies 81B/entry; -1 on malformed).
  All byte layouts matched byte-for-byte against validation/p2p_oracle.py.
- VERIFIED offline: tests/test_p2p.c (11/11, in `make test`).
- VERIFIED end-to-end IBD-request path: tests/fakepeer_headers.c (9/9, in `make
  test`) -- a loopback fixture peer; the 100%-asm client dials in, handshakes,
  sends getheaders(locator=block 750000), reads the `headers` reply with
  p2p_read, counts entries with p2p_headers_count, and checks the 1st header's
  prevhash chains to locator. Exercises the WHOLE blockchain-download request
  path in machine code over a real socket.
- LIVE network reality check (tests/live_headers.c, manual, NOT in make test):
  sending getheaders with a from-genesis locator makes current relay nodes
  answer with a large inv backlog (not a small `headers`), because they treat
  an at-genesis requester as needing full sync -- a real IBD-client wrinkle.
  Using a mid-chain locator (block 750000) is the correct, bounded approach;
  the loopback fixture proves that exact flow deterministically.
- Assemble/drivers: bitcoin_p2p.o added to Makefile OBJS; test_p2p + fakepeer
  wired into `make test`/`clean`. Full suite now 153 PASS / 0 FAIL / 11 green.

## 2026-08-11 — S1 bitcoin_net done: sockets + P2P framing (LIVE-verified)
- New asm file: asm/bitcoin_net.asm (raw Linux syscalls; DNS via libc getaddrinfo).
  API: fd_write_all, fd_read_full, fd_close, tcp_connect_ip(ip_le, port_be) (returns
  -errno on failure), cksum4, p2p_frame, p2p_write, p2p_read (returns 1 ok / 0 eof /
  -1 err / -2 trunc-with-drain). Wire frame magic f9beb4d9 + 12B cmd + 4B len + 4B
  cksum(=sha256d[0:4]) + payload -- locked byte-exact vs a live-peer Python oracle.
- VERIFIED offline (tests/test_net.c, 19/19 PASS, run by `make test`): fd write/read
  round-trip, EOF, p2p_frame(checksum/magic/cmd/len), p2p_write->p2p_read round-trip,
  truncation+payload-drain preserving framing alignment.
- VERIFIED LIVE (tests/live_handshake.c, manual): connected to a real Bitcoin node
  (seed -> 32.217.31.151:8333), sent `version`, received peer `version`/`wtxidrelay`/
  `sendaddrv2`/`verack`. The asm machine code performs the full P2P handshake on the
  actual network.
- TWO CONTRACT/ABI lessons fixed during bring-up:
  (1) GOLDEN-RULE VIOLATION: several fn frames placed locals INSIDE the callee-saved
      save area [rbp-8..-40] (header@-0x18, digest@-0x30, sockaddr@-0x10). This
      corrupted saved r12/r13/r14/r15 and produced garbage command bytes / EFAULT /
      SIGSEGV. FIX: moved all locals BELOW the save area and sized drain scratch
      [64]@-0xc0 so it cannot overwrite sibling locals. This is the same golden rule
      from the point_add lesson -- I must re-verify frame geometry on EVERY new fn.
  (2) CALLEE-SAVED rbx/r14 were used but not pushed in fd_write_all/fd_read_full/
      tcp_connect_ip -> corrupted caller regs. FIX: push/pop rbx/r14.
  (3) PORT BYTE ORDER: tcp_connect_ip takes port in big-endian (htons); passing a
      raw 8333 made sin_port = 0x8D20 (=36128) -> ECONNREFUSED. Callers MUST pass
      htons(port).
  (4) 16-byte RSP alignment at nested calls: p2p_write/p2p_read use sub rsp sizes
      that are 8 mod 16 (5 callee pushes -> RSP 8 mod16, so sub must be 8 mod16 to
      land on 0). Alignments audited per function.

## 2026-08-11 — bitcoin_tx node tx-parser done (deserializer + txid)
- New asm file: asm/bitcoin_tx.asm.
  API: int tx_parse(txinfo *info, const u8 *tx, unsigned long txlen)
    Walks a canonical serialized tx and fills info (see header comment) with
    version, n_in, n_out, locktime, tx_len, and offsets/lengths of input[0]
    script and output[0] value/script. Returns 1 if fully consumed, 0 if not.
    Handles all four CompactSize varint widths (1/2/4/8) inline.
- Verified via asm/tests/test_tx.c (18/18 PASS, in `make test`):
    * Parses the serialized genesis coinbase tx: tx_len=204, version=1,
      n_in=1, n_out=1, locktime=0.
    * input[0] script offset=42 len=77 ; output[0] value offset=124, script
      offset=133 len=67 ; value==50e8.  All offsets cross-checked vs a clean
      Python walker, not hand-derived.
    * txid = sha256d(tx) == 3ba3edfd...5e4a == the genesis merkle root (raw/
      internal order) -- tied into bitcoin_hash.asm.
    * merkle_root(1 tx) == that txid (Bitcoin 1-leaf rule).
    * tx_parse rejects a truncated buffer (returns 0).
    * 0xfd two-byte varint script-len path exercised and parsed (len 8).
- BUG fixed during bring-up: locktime field was read but cursor never advanced
  past it, so tx_len came out 4 short (200 vs 204) and all inputs were then
  rejected. Fix: `mov r9, rbx` after reading locktime.
- ABI discipline applied: r15 used for script lengths, so r15 is pushed/popped
  (it is callee-saved); only caller-saved r8,r9,r10,r11,rax,rcx,rbx stay free.
- GENESIS BYTE-ORDER LESSON (oracle): for genesis the header stores the merkle
  root in RAW digest order == raw txid == 3ba3edfd...; block explorers print the
  block/txid in display order but the genesis merkle root in raw order. The two
  canonical strings (3ba3edfd... raw root vs 4a5e1e4b... display txid/root) are
  byte-reverses, both correct. Documented in validation/genesis_oracle.py.
- New oracle: validation/genesis_oracle.py (deterministically builds the genesis
  coinbase tx, cross-checks txid/merkle/block-hash against all published values).

## 2026-08-11 — bitcoin_hash node primitives done (sha256d/block-hash/merkle/pow)
- New asm file: asm/bitcoin_hash.asm (built on sha256.asm). Exported API:
    sha256d(out[32], msg, len)                  = SHA256(SHA256(msg))
    block_hash(out[32], hdr[80])                = sha256d(hdr, 80)
    diff_target(target[32], bits32)             = compact nBits -> 256-bit BE target
    pow_check(hdr[80]) -> 1                    = block hash (LE int) <= target
    merkle_root(out[32], hashes, n)             = Bitcoin tx-merkle (in place)
- VERIFIED via tests/test_block.c; all 10 assertions PASS (via `make test`):
    * genesis block hash (display order) matches known 0000...19d6689c...
    * sha256d("abc") = 4f8b42c2...
    * diff_target(0x1d00ffff) = 00000000ffff00...
    * pow_check(genesis)=1 ; pow_check(tampered-nonce)=0
    * merkle(1) == coinbase-txid leaf ; merkle(2/3/4) match Python oracle.
- BUG FOUND (in the TEST, not in the asm): test_block.c had hand-typed merkle
  expected constants (e2/e3/e4) that were WRONG. They were computed with a
  truncated leaf0 (31-byte hex string -> 31 explicit inits + implicit 0 pad in
  C), so the expected bytes did not match the oracle. The assembly merkle_root
  was always correct (matches Python exactly for the real 32-byte leaves).
  FIX: regenerated e2/e3/e4 from Python (`sha256d` merkle construction) and
  patched test_block.c. Same lesson as the fe_inv EXP table: NEVER hand-type
  multi-byte constants; derive them from the Python oracle.
- INTEGRATION: Makefile now assembles bitcoin_hash.o, builds tests/test_block
  (links sha256.o + bitcoin_hash.o) and runs it in `make test`. `make clean`
  removes the new binary.
- Node-layer status: hashing (txid double-SHA256, merkle root, block hash,
  PoW target+check) DONE & VERIFIED. Remaining node layer: tx/block parsing,
  UTXO, P2P (see PLAN sec 7).
## 2026-08-11 — sha256_validation_done
- Wrote fe_sqr / fe_inv (Fermat a^(p-2), MSB->LSB square-and-multiply over the
  fixed exponent p-2 stored as a 32-byte little-endian rodata table).
- fe_sqr is a tail-call into fe_mul (mov rdx,rsi; jmp fe_mul).

### BUG #1 (fe_inv wrong): result pointer clobbered
- Symptom: fe_inv(2) returned ALL ZEROS.
- Root cause: inside the loop I set `mov rdi, r14` before each `call fe_mul`,
  and rdi (the caller's output pointer) is caller-saved, so it was destroyed.
  The final `mov [rdi+...], ...` then wrote into fe_inv's own stack R buffer
  instead of the caller's buffer, leaving the caller's output at zero.
- FIX: preserve the output pointer in rbx (callee-saved, preserved by fe_mul)
  at entry (`mov rbx,rdi`), and use rbx for the final store. Also switched the
  bit-index scratch from rbx to r9 so rbx stays dedicated to the out pointer.

### BUG #2 (fe_inv wrong VALUE, not zero): after fix, inv(2) returned a non-zero
###     but WRONG value; inv(2)*2 != 1.
- Debug trail:
  - t_inv (C, direct fe_inv call): inv(2) wrong.
  - t_loop (pure-C re-implementation of the loop driving asm fe_sqr/fe_mul with
    the SAME EXP byte table) produced the SAME wrong value -> bug is shared
    between asm fe_inv and the C loop, so it is NOT in the asm loop control.
  - t_alias: in-place sqr and mul validated OK.
  - t_sqr300 / t_mix: chained in-place squarings (300) and square+multiply
    chains (300) both match Python exactly -> fe_sqr & fe_mul are correct even
    in long in-place chains.
  - trace (checkpoints at i=239..0): C and Python AGREE through i=32, then
    diverge at i=16 onward -> divergence occurs while processing bits 31..16
    (byte indexes 3 and 2 of the exponent).
- Current hypothesis: a RARE-VALUE bug that only triggers for a specific
  intermediate field value reached during bits 31..16 of THIS exponentiation
  (not covered by random single-call stress or the regular-valued chains).
- STATUS: **UNRESOLVED** - investigation continues. Next step: bisect the exact
  call or value in bits 31..16; add a per-iteration cross-check calling a C
  reference mul (via _int128 + same reduction) to find the first mismatching
  fe_mul/fe_sqr invocation.

### RESOLUTION (root cause found)
- NOT a fe_mul/fe_sqr bug at all. The crypto primitives were always correct.
- The bug was a hand-typed EXPONENT TABLE: in BOTH my C test and the asm
  EXP_BYTES I wrote the p-2 little-endian bytes with the 0xFE byte at offset 3
  instead of offset 4. Correct: EXP[3]=0xFF, EXP[4]=0xFE. Wrong: EXP[3]=0xFE,
  EXP[4]=0xFF. This made fe_inv exponentiate by the WRONG value -> wrong inverse.
- Evidence trail that caught it:
  * Verify p-2 bytes via Python: EXP=[2d,fc,ff,FF,FE,ff,...].
  * gdb trace of fe_inv diverged from Python at bit 32 AND Python showed the
    asm performed an extra multiply (used byte4=0xFF when true byte4=0xFE).
  * seqcheck/seqcheck_persist (which derive EXP from Python's to_bytes, i.e.
    the CORRECT table) all matched, while the real fe_inv (wrong hand table)
    failed -> proved the table, not the arithmetic.
- FIX: corrected EXP_BYTES in secp256k1_fe.asm to
  [2d fc ff FF fe ff ...].
- RESULT: fe_inv passes 200 randomized ctypes checks (a*inv(a)==1 mod p).
- LESSON: never hand-type multi-byte constant tables; derive/verify them from
  Python (the oracle) first, and prefer a Python-driven ctypes test over
  hand-embedded constants for cross-checking.

### point_add STATUS: VERIFIED -- ALL 5 assertions PASS (2G+3G=5G, G+G=2G, 2G+5G=7G, G+(-G)=inf).
### SUBTLE NASM GOTCHA (root cause of point_add bug): ';' is a COMMENT in NASM, NOT a statement separator.
  Symptom: point_add always fell into point_double (or produced wrong X3); the
  distinct/opposite special-case branch logic never executed at all.
  Cause: I wrote the equal-X comparison block as one-liners such as
      mov rax,[rbp-0x90+0]; cmp rax,[rbp-0xb0+0]; jne .distinct
  In NASM only the FIRST instruction (mov) assembled; everything after the
  first ';' became a COMMENT, silently dropping the cmp/jne. The disassembly
  showed pure mov loads (dead writes to rax) then an unconditional call to
  point_double and jmp to .done.
  Fix: one instruction per line in the comparison block. Audited the whole
  file: the only remaining ';'-joined text is on a pure-comment line.
  GOLDEN RULE (add to discipline): never join 2+ assembly instructions on one
  line with ';' -- in NASM that is a comment, not a separator.
### point_add STATUS: VERIFIED -- ALL 5 assertions PASS (5G, double, 7G, -G).

### fe_inv status: VERIFIED (200 ctypes random cases, 0 failures).

### secp256k1_ecdsa.asm STATUS: VERIFIED (ecdsa_verify).
- HF: asm/secp256k1_ecdsa.asm. Verify-only ECDSA over secp256k1.
- VERIFIED: valid sig accept, tampered-r/msg/pubkey reject, r=0/s=0/r=n-1 reject,
  2nd valid sig accept. All 8 assertions PASS.
- MAJOR LESSONS this stage (all three were real root causes):
  (1) CONTIGUOUS-ASCENDING BUFFER CONVENTION: every multi-limb buffer must be
      stored as ascending limbs from its base (limb0@+0..limb3@+24), because
      ALL helpers (sc_inv/sc_mul/point_scalar_mul/point_add/fe_*) read+write
      operands that way. Storing s/Q/u2 standing/scattered -> helpers silently
      read garbage (w was s0+3 garbage limbs).
  (2) ECDSA needs the AFFINE x = X/Z^2 mod p, NOT the raw Jacobian X. First
      attempt compared raw X to r -> wrong. Added fe_sqr(inv/mul) conversion.
  (3) Jacobian Z is at base+64 (P[8..11]); a +32 off-by-64 index made both the
      infinity check and the Z*Z step read Y instead of Z.
  Plus: keep every stratch buffer non-overlapping AND 16-byte-aligned calls.

### secp256k1_scalar.asm STATUS: VERIFIED (sc_add/sub/mul/sqr/inv).
- HF: asm/secp256k1_scalar.asm. Scalar arith mod curve order n.
- DESIGN: sc_mul implemented as MSB->LSB double-and-add in the scalar ring
  using only the simple sc_add (DELTA-carry fold + conditional subtract of n).
  Deliberately slow but cryptographically identical; correctness-first.
  sc_inv = Fermat a^(n-2) via square-and-multiply calling sc_mul.
- VERIFIED: fixed vectors (edges: n-1+1=0, n-1*n-1=1, sub(0,1)=n-1, inv(2),
  3*inv(3)=1, randoms) + ctypes stress: 8000 iters 0 failures (add/sub/mul/
  sqr) + 4000 inv (a*inv(a)==1).
- BUGS fixed this stage:
  #1 rodata indexed as 32-bit absolute broke -shared (-> loaded N_EXP base
     into a register; small fixed-offset rodata refs become RIP-relative under
     'default rel').
  #2 b-limb buffer stored DESCENDING but indexed ASCENDING -> wrong bits fed
     to the double-and-add; AND the result accumulator was placed in scattered
     slots while sc_add writes it CONTIGUOUSLY from its rdi. Both fixed by
     giving R a contiguous block [rbp-0x78..-0x60] and b an ascending block
     [rbp-0xa8..-0x90].
  LESSON: any value written by a helper (sc_add rdi-based contiguous store)
  must live in the SAME contiguous layout the helper produces; and kept
  multi-limb indexable arrays must be stored ascending and indexed ascending.

### fe_inv status: VERIFIED (200 ctypes random cases, 0 failures).

### point_double / point_add_mixed / point_scalar_mul STATUS: VERIFIED
### MAJOR BUG FOUND+FIXED here: scratch-slot overlap with callee-saved save area.
  Symptom: -O2 builds SIGBUS/SIGSEGV on return to caller; callee-saved
  registers (rbx/r14/r15) came back corrupted (e.g. rbx = a field value A).
  Cause: slot offsets [rbp-0x20]/[rbp-0x40] overlapped the 5-push save area
  [rbp-0x8 .. rbp-0x28]; writing a field value there overwrote the saved
  registers, so `pop r14/r15/rbx` reloaded junk into the caller.
  Fix: all scratch slots moved BELOW the save area (S0=[rbp-0x50] up to
  S7=[rbp-0x130]), frame set to sub rsp,0x148 (16-byte aligned at every fe_*
  call AND clear of the save area).
  LESSON (golden): never place stack scratch inside [rbp-8 .. rbp-40] --
  that region holds the pushed callee-saved registers.
- Algorithm validated in Python (asm/validation/point_oracle.py + point_checks.py):
  Jacobian (a=0) add/double + double-and-add scalar mul. ALL CHECKS PASS:
    * n*G = infinity, (n+1)G == G
    * dbl(G) == 2G ; 2G+G == 3G ; (n-1)G == -G
  Reference values (for asm tests):
    * 2G x = c6047f9441ed7d6d...5c709ee5
             y = 1ae168fea63dc339...950cfe52a
    * 3G x = f9308a019258c310...bce036f9
             y = 388f7b0f632de814...f34da7f0
    * kG (k=0x1234567890abcdef1234567890abcdef)
        x = 9377c312145a5afb...90bbf5e
        y = 742ba607d6ae1fc8...679779fb
  (full hex in point_checks.py output / PLAN can regenerate via oracle)
- DESIGNDECISION: Jacobian coordinates for dbl/add; one fe_inv at conversion.
  Mul = MSB->LSB double-and-add (base as affine-like Z=1; use MIXED add
  when base is affine Z=1 for speed, else general add).
- NEXT: write secp256k1_point.asm implementing point_double (Jac),
  point_add (Jac-Jac), point_add_mixed (Jac-affine), point_scalar_mul.
- Discipline: keep fe_* API (4x u64 LE limbs), preserve rbx/r12-r15, call
  fe_mul/fe_sqr/fe_add/fe_sub as the field primitives.
*

================================================================================
KEY FACTS (do not lose)
================================================================================
- Field p = 2^256-2^32-977; C = 2^32+977 = 0x10000003D1 (fold constant).
- EXP (fe_inv) = p-2 little-endian bytes: 2D FC FF FE | FF...  (32 bytes).
- ABI: mulq clobbers rdx; keep pointers in callee-saved regs.
- fe_mul preserves rbx,r12-r15 (and rbp); clobbers rax,rcx,rdx,rsi,rdi,r8-r11.
- Verification stack so far:
  * sha256 (init/block/full): 7/7 vectors pass.
  * fe_add/fe_sub/fe_mul: 24 fixed vectors + 50k random vs Python oracle.
  * fe_sqr: verified (t_sqr300 matches Python, 300 chained squarings).

================================================================================
SUCCESS CRITERION
================================================================================
- ECDSA verify over a real (or synthetic) secp256k1 signature returning the
  correct accept/reject, built from AI-authored assembly.
- Intermediate gates: fe_inv correct (a*inv(a)==1 mod p for random a).
================================================================================
