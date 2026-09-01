; ============================================================================
; bitcoin_utxo_lsm.asm -- LSM-tree-style persistent UTXO store, Phase 1.
;
; Replaces bitcoin_utxo_store.asm's giant-pre-sized-table approach (which
; write-amplified ~13x during full-archive replay because the table had to
; be sized for the FINAL live-UTXO count and scattered writes across the
; whole 51.5GB structure from block 0 onward) with a bounded, FIXED-SIZE
; in-memory "memtable" that periodically flushes to sorted, immutable
; on-disk "runs" -- the same structural idea as Bitcoin Core's real
; LevelDB-backed chainstate (a bounded -dbcache in front of an LSM tree).
;
; The memtable+WAL tier is NOT reimplemented here: bitcoin_utxo.asm's
; open-addressing table and bitcoin_utxo_store.asm's utxo_store_init/put/
; del/reload/close ALREADY implement exactly "WAL-logged put/del against a
; hash table, replay-recoverable on crash" -- proven correct by this
; project's own stress tests. This module's state struct starts with the
; IDENTICAL 40-byte layout utxo_store_* expects (log_fd/idx_fd/log_len/
; ckpt_log_off/ckpt_n) so `lst` can be passed directly as utxo_store_*'s
; `st` argument with zero translation.
;
; What THIS module adds on top:
;   - a flush trigger (memtable live-count OR op-count threshold) that,
;     once crossed, sorts the memtable's live entries plus this
;     generation's delete-tombstones into a new immutable run file and
;     resets the memtable/WAL for the next generation;
;   - a per-run Bloom filter (uniform SHA256d-derived keys make min/max
;     range bounds useless for pruning, so a real Bloom filter is the
;     actual fast-reject);
;   - a crash-safe manifest (temp-file + fsync + rename) tracking which
;     runs exist, instead of the O_TRUNC-rewrite-in-place utxo_store_sync
;     uses for its checkpoint (that pattern has a real, separate crash
;     hazard: a crash mid-rewrite loses the checkpoint with no WAL replay
;     covering the gap -- not fixed here, just not repeated);
;   - multi-run point lookup (utxo_lsm_get), newest generation first,
;     Bloom-gated, stopping at the first tombstone or hit.
;
; CONTRACT CHANGE from utxo_del/utxo_store_del: utxo_lsm_del(key) returns 1
; (recorded) for BOTH a memtable hit and a memtable MISS -- a miss is
; assumed to reference a key flushed into an older run (this workload's
; every DEL is a real consensus-valid spend) and is recorded as a
; tombstone so it correctly shadows that older run's PUSH at merge time.
; This assumption is NOT safe for a general-purpose store; it is safe here
; specifically because callers only ever delete real spends (see
; daemon/build_utxo.c). utxo_lsm_del returns -1 only on a genuine I/O error.
;
; PHASE 2: utxo_lsm_compact(lst) merges ALL current runs into one via a
; single-pass streaming k-way merge (bounded memory -- one small read-ahead
; buffer per input run, in a scratch region this function mmaps itself,
; not the caller's flush-oriented scratch_buf). Since it always compacts
; every run down to the oldest one, every tombstone it encounters is safe
; to drop outright (no older run could still need it). It's EXPLICIT /
; caller-invoked, not auto-triggered by a garbage-ratio estimate -- that's
; a documented future refinement, not implemented here. This is what makes
; the run count bounded for a long-running process; Phase 1 alone (flush
; with no compaction) is only safe for a one-shot, non-resumable replay
; like build_utxo.c, where the run count is naturally bounded by archive
; size / memtable capacity and the process never runs "forever."
;
; Run files are SORTED (ascending 36-byte key) so a lookup can early-exit
; and so a future compaction can do a straight streaming k-way merge
; without re-sorting. A sparse index is NOT implemented in Phase 1 (a
; known, deliberate simplification: utxo_lsm_get is never on build_utxo.c's
; hot path, so a full linear scan per candidate run is an acceptable cost;
; only the WAL-backed memtable path is hot, and that is untouched
; utxo_store_* code already proven fast).
;
; ---- state struct `lst` (caller allocates, zeroes, then fills the
;      caller-owned config fields below BEFORE calling utxo_lsm_init or
;      utxo_lsm_reload) ----
;   +0   qword log_fd         \
;   +8   qword idx_fd          \  IDENTICAL layout to bitcoin_utxo_store.asm's
;   +16  qword log_len          > state struct -- owned by utxo_store_*,
;   +24  qword ckpt_log_off    /   never touched directly by this module.
;   +32  qword ckpt_n         /
;   +40  qword op_count        -- puts+dels since the last flush
;   +48  qword op_threshold    -- CALLER SETS: flush when op_count reaches this
;   +56  qword fill_threshold  -- CALLER SETS: flush when memtable live-count
;                                  reaches this (utxo_count(u), i.e. u->n)
;   +64  qword tomb_buf        -- CALLER SETS: buffer of 36-byte (txid+index)
;                                  entries, capacity >= op_threshold
;   +72  qword tomb_cap        -- CALLER SETS: capacity of tomb_buf (entries)
;   +80  qword tomb_n          -- current tombstone-list count this generation
;   +88  qword total_live      -- best-effort live-count estimate (put-hit
;                                  increments, every del decrements; NOT
;                                  reconciled against older-run contents --
;                                  informational/telemetry only, mirrors how
;                                  build_utxo.c already treats del_miss as
;                                  approximate, never correctness-critical)
;   +96  qword next_gen        -- next generation number to assign on flush
;                                  or compaction (compaction's merged run
;                                  adopts a FRESH gen here, not the max of
;                                  its inputs -- see utxo_lsm_compact)
;   +104 qword manifest_buf    -- CALLER SETS: array of 16-byte entries,
;                                  one per run: [gen:8][run_no:8]. A run's
;                                  file is "utxo_run_%06u.dat" for its OWN
;                                  run_no field -- NOT its manifest index.
;                                  (Phase 1 alone could imply run_no from
;                                  the index since runs were never removed;
;                                  compaction replaces many runs with one,
;                                  so the index no longer determines the
;                                  file number and both fields are stored
;                                  explicitly.)
;   +112 qword manifest_cap    -- CALLER SETS: capacity of manifest_buf
;                                  (runs, i.e. manifest_buf must be >=
;                                  manifest_cap*16 bytes)
;   +120 qword manifest_n      -- current run count
;   +128 qword scratch_buf     -- CALLER SETS: big scratch arena, layout:
;                                  [0 .. desc_cap*64)         merge-sort ping
;                                  [desc_cap*64 .. *128)      merge-sort pong
;                                  [desc_cap*128 .. +BLOOM_MAX_BYTES) bloom
;                                  [+BLOOM_MAX_BYTES .. +SCRIPT_MAX_BYTES) script
;                                  where desc_cap = (scratch_cap -
;                                  BLOOM_MAX_BYTES - SCRIPT_MAX_BYTES) / 128.
;                                  Required: desc_cap >= fill_threshold +
;                                  tomb_cap (worst case every live memtable
;                                  entry AND every tombstone need a
;                                  descriptor in the same flush). Used only
;                                  by flush/get, NOT by compaction (which
;                                  mmaps its own small scratch -- see below).
;   +136 qword scratch_cap     -- CALLER SETS: byte size of scratch_buf
;   +144 qword next_run_no     -- next run file number to assign (decoupled
;                                  from manifest_n/next_gen since compaction
;                                  can shrink the manifest while file
;                                  numbers must stay globally unique)
;   +152 qword tomb_hash_buf   -- LSM-OWNED, do NOT set: lazily mmap'd by
;                                  mac_tomb_hash_reset (called from
;                                  utxo_lsm_init/reload/mac_flush's post-
;                                  flush reset). Array of 8-byte slots, each
;                                  either -1 (empty) or a 0-based index into
;                                  tomb_buf. Open-addressed hash set that
;                                  makes utxo_lsm_get's tombstone-membership
;                                  check O(1) instead of an O(tomb_n) linear
;                                  scan of tomb_buf via mac_cmp_key -- caller
;                                  still just zero-inits this field like
;                                  every other struct field.
;   +160 qword tomb_hash_mask  -- LSM-OWNED: (capacity-1) of tomb_hash_buf,
;                                  capacity = next_pow2(max(tomb_cap,1)*2).
;   (total struct size: 168 bytes)
;
; Exports (System V AMD64):
;   long utxo_lsm_init(void* lst)                              -> 1 / -1
;   long utxo_lsm_put(void* lst, void* u, const u8 txid[32],
;                      u32 index, u64 value, const u8* script, u32 slen)
;                                                                -> 1/0/2/-1
;   long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index)
;                                                                -> 1 / -1
;   long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
;                      u64* value, unsigned long* height, unsigned long*
;                      is_coinbase, u8** script, unsigned long* slen) -> 1/0/-1
;                      (slen is a FULL 8-byte store -- incident #49: it was
;                      a 4-byte store while every daemon caller declared
;                      unsigned long*, leaving stale stack garbage in the
;                      upper half and nondeterministically failing mempool
;                      prevout resolution. All callers now declare 64-bit.)
;                      (on a disk-run hit, *script points into lst's
;                      internal scratch buffer -- valid only until the next
;                      utxo_lsm_get call, unlike a memtable hit's stable
;                      blob pointer; documented divergence from utxo_get.)
;   long utxo_lsm_count(void* lst)                              -> total_live
;   long utxo_lsm_reload(void* lst, void* u)          -> replayed count / -1
;   long utxo_lsm_reload_ro(void* lst, void* u)       -> replayed count / -1
;                      (identical, except the WAL is opened READ-ONLY and
;                      utxo.idx is never created -- for tools that inspect a
;                      datadir they must not modify; see its own comment)
;   long utxo_lsm_walk(void* lst, void* u, cb, ctx)   -> live count / -1
;                      (visits the whole live set exactly once each through
;                      cb(ctx, key36, value, (height<<1)|coinbase, script,
;                      slen) -- the read side of `gettxoutsetinfo`, built on
;                      the SAME k-way merge mac_lsm_recount already uses)
;   long utxo_lsm_compact(void* lst)      -> 1 ok / 0 nothing-to-do / -1 err
;   void utxo_lsm_close(void* lst)
;
; FRAME RULE: same as bitcoin_utxo_store.asm -- locals live strictly below
; the push-save area; `syscall` clobbers rcx/r11, never held live across one.
; ============================================================================
default rel
section .text

MAGIC_RUN        equ 0x4E555255      ; "URUN" little-endian dword -- OLD format, no sparse index
MAGIC_RUN2       equ 0x32555255      ; "URU2" little-endian dword -- adds sparse_off/sparse_n
; MAGIC_RUN3 (2026-08-19, Stage D): the PER-RECORD shape changes (a PUSH
; record's value-portion grows from 10 to 15 bytes: value(8)+slen(2) ->
; value(8)+slen(2)+height(4)+is_coinbase(1)), not just the header -- unlike
; the RUN->RUN2 change, which only added header fields and left every
; record byte-compatible. A header-only version bump would let new code
; silently misparse an old-shape run file (wrong height/is_coinbase, and
; slen read from the wrong offset entirely, corrupting the subsequent
; script-length-gated read) with no error at all. mac_read_run_header
; reports which record shape a file uses (out+56, see below); old files
; (MAGIC_RUN/MAGIC_RUN2) are still fully readable, just report
; height=0/is_coinbase=0 for every record (that data was never captured).
MAGIC_RUN3       equ 0x33555255      ; "URU3" little-endian dword -- new PUSH record shape
MAGIC_MANIFEST   equ 0x4E414D55      ; "UMAN" little-endian dword -- OLD format, no persisted live-count
; MAGIC_MANIFEST2 (2026-08-22): the manifest header grows by ONE trailing
; qword, total_live, written after manifest_n. This is the persisted,
; ACCURATE live-UTXO count that utxo_lsm_reload restores instead of the old
; WAL-tail-only seed (which counted only the current unflushed generation
; and came back tens of millions too low, driving live_utxo negative). The
; value persisted is the RUNS-ONLY count (WAL/memtable excluded), so reload
; adds the current WAL tail's net (pushes - dels) on top without double-
; counting -- see utxo_lsm_reload. An OLD-format (MAGIC_MANIFEST) manifest
; carries no such field; reload detects the old magic and falls back to a
; one-time full dedup recount (mac_lsm_recount) to establish the baseline,
; mirroring the MAGIC_RUN -> MAGIC_RUN2 discipline for run files above.
MAGIC_MANIFEST2  equ 0x324E4D55      ; "UMN2" little-endian dword -- adds trailing total_live qword
BLOOM_MAX_BYTES  equ 4*1024*1024     ; 4MB bloom scratch (~3.35M entries @10 bits/entry)
SCRIPT_MAX_BYTES equ 65536           ; get-time script-read scratch

; mac_run_lookup (utxo_lsm_get's disk-run-hit path) used to stage its bloom
; read + returned script bytes in lst->scratch_buf -- fine when get() only
; ever ran from one thread, unsafe now that cross-transaction block
; verification calls utxo_lsm_get concurrently from multiple worker threads
; (mac_flush, the WRITER, keeps using lst->scratch_buf unchanged below --
; it is exclusively single-writer by this module's own architecture, and
; get()/flush() never run concurrently with each other by construction).
; Fixed-size (not lst->scratch_cap-dependent, since get() never touches the
; much larger merge-sort ping/pong region that makes scratch_cap so large)
; and per-thread, same TLS pattern as bitcoin_sighash.asm's legacy_sighash_
; scfbuf: Initial-Exec model via ..gottpoff (this NASM build has no ..tpoff).
%macro TLS_ADDR 2
    mov  %1, [rel %2 wrt ..gottpoff]
    add  %1, qword [fs:0]
%endmacro
section .tbss alloc noexec nowrite tls align=16
global lsm_get_scratch
lsm_get_scratch: resb BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES
section .text

; ---- sparse index (added after Phase 2 shipped without one -- see
; mac_read_run_header's header comment for the full backward-compat story) ----
SPARSE_STRIDE    equ 64              ; sample every Nth sorted record (index 0 always sampled)
                                      ; 256 -> 64 on 2026-09-01: the forward scan after the sparse
                                      ; search was 10% of the live replay (lsm_run_lookup_mm); 44 B
                                      ; per 64 records is ~0.7 B/record of index. Readers use the
                                      ; header's sparse_n, so old runs keep working unchanged.
SPARSE_ENT_SIZE  equ 44              ; key(36) + file_offset(8) per sparse entry

; ---- compaction (Phase 2) constants ----
; utxo_lsm_compact merges the OLDEST min(manifest_n, COMPACT_MAX_RUNS) runs
; into one via a streaming k-way merge, using its OWN small mmap'd scratch
; (not the caller's flush-oriented scratch_buf): one read-ahead "current
; record" slot per input run, bounded regardless of how large those runs
; are. Always a contiguous PREFIX starting at the oldest run, so every
; tombstone encountered is provably safe to drop (no older run could still
; need it) -- this holds for a partial (< manifest_n) batch too, not just a
; full compaction, since "oldest" only ever grows from index 0 upward.
COMPACT_MAX_RUNS   equ 64
; per-run slot: fd(8) gen(8) run_no(8) remaining(8) active(8) key(36)
; type(1)+pad(3) value(8) slen(2) height(4) is_coinbase(1)+pad(1) rec_v2(8)
; script(up to SCRIPT_MAX_BYTES) -- see mac_compact_read_rec's own header
; comment for the exact byte offsets (grown 2026-08-19, Stage D: was 96).
; READ-AHEAD BUFFER, inline in the slot (2026-08-31). mac_compact_read_rec used
; to pull every record with THREE read(2) syscalls -- key+type (37), value
; block (15 or 10), script -- so a merge over a 5 GB set ran at ~50 MB/s on an
; HDD and on NVMe alike: it was syscall-bound, not disk-bound. Production paid
; 163-326 s of apply stall per compaction of its 13 GB set; a signet bulk
; catch-up spent 44% of wall-clock in it. Each slot now owns COMPACT_RDBUF
; bytes and refills with one read(2) per 256 KB. The slots are compaction's
; (and the recount's) own fresh anonymous mmap, so the extra bytes cost the
; caller nothing and start zeroed: fill = pos = 0 means "empty".
COMPACT_RDBUF      equ 262144
SLOT_RD_FILL       equ 104 + SCRIPT_MAX_BYTES        ; bytes valid in the buffer
SLOT_RD_POS        equ SLOT_RD_FILL + 8              ; bytes consumed
SLOT_RD_BUF        equ SLOT_RD_FILL + 16             ; the buffer itself
COMPACT_SLOT_SIZE  equ SLOT_RD_BUF + COMPACT_RDBUF
COMPACT_SLOTS_BYTES equ COMPACT_MAX_RUNS * COMPACT_SLOT_SIZE
COMPACT_SCRATCH_BYTES equ COMPACT_SLOTS_BYTES + BLOOM_MAX_BYTES

manifest_name:     db "utxo_manifest.dat", 0
manifest_tmp_name:  db "utxo_manifest.tmp", 0
manifest_child_name: db "utxo_manifest.child", 0   ; background child's deferred publish
dot_name:           db ".", 0
wal_name:            db "utxo.dat", 0

; PERF_SCOPE.md 4.1: mmap-cached fast path for the disk-run lookup below.
; Returns 1/0/2/-1 exactly as mac_run_lookup does, or -2 ("fall back") when
; it declines -- open/mmap failure, a malformed run, any out-of-bounds
; offset. See asm/utxo_lsm_mm.c for the cache and its staleness rules.
extern lsm_run_lookup_mm
extern lsm_mm_invalidate_all
extern utxo_put
extern utxo_get
extern utxo_del
extern utxo_walk_live
extern utxo_store_init
extern utxo_store_init_ro
extern utxo_store_put
extern utxo_store_del
extern utxo_store_reload
extern utxo_store_wal_drain
extern utxo_store_close

; ============================================================================
; small local helpers

; ============================================================================
; mac_fl_write(fd=rdi, src=rsi, len=rdx) -> rax 0 ok / nonzero error
;   Same contract as mac_write_exact, but appends to mac_fl_buf and only
;   writes when the buffer would overflow (a record larger than the buffer
;   goes straight out after a drain). Single-threaded: mac_flush runs in the
;   writer alone.
; mac_fl_drain(fd=rdi) -> rax 0 ok / nonzero error: write out what is buffered.
; ============================================================================
mac_fl_write:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rbx, rdx
    mov  rax, [rel mac_fl_fill]
    add  rax, rbx
    cmp  rax, MAC_FLBUF
    jbe  .flw_append
    mov  rdi, r12
    call mac_fl_drain
    test rax, rax
    jnz  .flw_done
    cmp  rbx, MAC_FLBUF
    jbe  .flw_append
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rbx
    call mac_write_exact
    jmp  .flw_done
.flw_append:
    lea  rdi, [rel mac_fl_buf]
    add  rdi, [rel mac_fl_fill]
    mov  rsi, r13
    mov  rdx, rbx
    call mac_memcpy
    add  [rel mac_fl_fill], rbx
    xor  eax, eax
.flw_done:
    pop  r13
    pop  r12
    pop  rbx
    ret
mac_fl_drain:
    push rbx
    mov  rbx, [rel mac_fl_fill]
    test rbx, rbx
    jz   .fld_empty
    lea  rsi, [rel mac_fl_buf]
    mov  rdx, rbx
    call mac_write_exact            ; rdi = fd (unchanged)
    mov  qword [rel mac_fl_fill], 0
    pop  rbx
    ret
.fld_empty:
    xor  eax, eax
    pop  rbx
    ret

; ============================================================================

; mac_memcpy(dst=rdi, src=rsi, n=rdx) -- preserves nothing special, trivial
mac_memcpy:
    push rcx
    xor  ecx, ecx
.ml:
    cmp  rcx, rdx
    jae  .md
    mov  al, [rsi+rcx]
    mov  [rdi+rcx], al
    inc  rcx
    jmp  .ml
.md:
    pop  rcx
    ret

; mac_read_exact2(fd=rdi, buf=rsi, len=rdx) -> rax 0 ok / -1
mac_read_exact2:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rbx, rdx
.re:
    test rbx, rbx
    jz   .ok
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rbx
    xor  eax, eax
    syscall
    test rax, rax
    jz   .bad
    js   .bad
    add  r13, rax
    sub  rbx, rax
    jmp  .re
.bad:
    mov  rax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret
.ok:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret

; mac_write_exact(fd=rdi, buf=rsi, len=rdx) -> rax 0 ok / -1
mac_write_exact:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rbx, rdx
.we:
    test rbx, rbx
    jz   .ok
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rbx
    mov  eax, 1
    syscall
    test rax, rax
    jle  .bad
    add  r13, rax
    sub  rbx, rax
    jmp  .we
.bad:
    mov  rax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret
.ok:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret

; mac_fsync2(fd=rdi) -> rax
mac_fsync2:
    mov  eax, 74
    syscall
    ret

; mac_cmp_key(p=rdi, q=rsi) -> eax: 0 = p<q, 1 = p==q, 2 = p>q (36-byte unsigned)
; Clobbers rax, rdx. Does NOT preserve rdi/rsi/rcx/rdx -- checked all 6 call
; sites, none rely on that (each reloads rdi/rsi fresh before calling, and the
; two that need rdx/rcx live across the call already push/pop it themselves).
; Compares as 4 big-endian qword chunks + 1 dword chunk instead of 36 individual
; bytes, since this is the hottest function in the UTXO-lookup path (profiled
; ~34% of total CPU during bulk catch-up) and the old per-byte loop plus its
; save/restore prologue/epilogue dominated that cost.
mac_cmp_key:
    mov  rax, [rdi]
    mov  rdx, [rsi]
    bswap rax
    bswap rdx
    cmp  rax, rdx
    jne  .diff

    mov  rax, [rdi+8]
    mov  rdx, [rsi+8]
    bswap rax
    bswap rdx
    cmp  rax, rdx
    jne  .diff

    mov  rax, [rdi+16]
    mov  rdx, [rsi+16]
    bswap rax
    bswap rdx
    cmp  rax, rdx
    jne  .diff

    mov  rax, [rdi+24]
    mov  rdx, [rsi+24]
    bswap rax
    bswap rdx
    cmp  rax, rdx
    jne  .diff

    mov  eax, [rdi+32]
    mov  edx, [rsi+32]
    bswap eax
    bswap edx
    cmp  eax, edx
    jne  .diff

    mov  eax, 1
    ret
.diff:
    jb   .lt
    mov  eax, 2
    ret
.lt:
    xor  eax, eax
    ret

; mac_tomb_hash_reset(lst=rdi) -> rax: 1 ok / -1 err
;   (Re)initializes the O(1) tombstone-membership hash set (tomb_hash_buf/
;   tomb_hash_mask) for a fresh generation. mmaps ONCE per lst instance
;   (capacity = next_pow2(max(tomb_cap,1)*2) 8-byte slots -- anonymous pages
;   are lazily zero-cost until touched, so this is cheap even at BULK-mode
;   scale) and just memsets the existing mapping back to the -1 empty
;   sentinel on every later call for the SAME lst -- avoids leaking a
;   mapping on every flush/compact generation reset in a long-running
;   process. Called from utxo_lsm_init, utxo_lsm_reload, and mac_flush's
;   post-flush reset, everywhere tomb_n gets zeroed for a new generation.
mac_tomb_hash_reset:
    push rbx
    push r12
    mov  r12, rdi
    cmp  qword [r12+152], 0
    jne  .thr_fill
    mov  rax, [r12+72]           ; tomb_cap
    cmp  rax, 1
    jae  .thr_min_ok
    mov  rax, 1
.thr_min_ok:
    shl  rax, 1                   ; *2 for a <=50% max load factor
    dec  rax
    mov  rcx, rax
    shr  rcx, 1
    or   rax, rcx
    mov  rcx, rax
    shr  rcx, 2
    or   rax, rcx
    mov  rcx, rax
    shr  rcx, 4
    or   rax, rcx
    mov  rcx, rax
    shr  rcx, 8
    or   rax, rcx
    mov  rcx, rax
    shr  rcx, 16
    or   rax, rcx
    mov  rcx, rax
    shr  rcx, 32
    or   rax, rcx
    inc  rax                       ; rax = cap_pow2 (>= tomb_cap*2)
    mov  rbx, rax
    shl  rax, 3                     ; *8 bytes/slot
    xor  edi, edi
    mov  rsi, rax
    mov  edx, 3                      ; PROT_READ|PROT_WRITE
    mov  r10d, 0x22                   ; MAP_PRIVATE|MAP_ANONYMOUS
    mov  r8, -1
    xor  r9d, r9d
    mov  eax, 9                        ; mmap
    syscall
    cmp  rax, -1
    je   .thr_err
    mov  [r12+152], rax               ; tomb_hash_buf
    dec  rbx
    mov  [r12+160], rbx                ; tomb_hash_mask = cap_pow2-1
.thr_fill:
    mov  rdi, [r12+152]
    mov  rcx, [r12+160]
    inc  rcx                            ; slot count = mask+1
    mov  rax, -1
    rep  stosq
    mov  rax, 1
    jmp  .thr_done
.thr_err:
    mov  rax, -1
.thr_done:
    pop  r12
    pop  rbx
    ret

; mac_tomb_hash_probe(lst=rdi, key=rsi) -> rax = &slot (in tomb_hash_buf)
;   Finds either the slot already holding this key's tomb_buf index, or the
;   first empty (-1) slot -- a combined find-or-insert-point, standard
;   open-addressing linear probe. Always terminates: tomb_buf's own
;   capacity check (tomb_n < tomb_cap, enforced at every append site)
;   guarantees this table can never exceed 50% load, so an empty slot is
;   always reachable.
;   Caller decides what the result means: utxo_lsm_get checks whether
;   *slot == -1 (not found) or otherwise found (this only returns early on
;   an empty slot or a genuine key match, never anything in between);
;   an appender just overwrites *slot with the new tomb_buf index.
; Clobbers rax,rcx,rdx,r8,r9,r10. Preserves rbx/r12/r13 (pushed/popped, even
; though used internally) and rdi/rsi (values, not contents pointed-to,
; since neither mac_cmp_key nor this function ever assigns to them).
mac_tomb_hash_probe:
    push rbx
    push r12
    push r13
    mov  r8, 0x811c9dc5
    xor  ecx, ecx
.hp_hl:
    cmp  ecx, 8
    jae  .hp_hdone
    movzx eax, byte [rsi+rcx]
    xor  r8d, eax
    imul r8d, r8d, 16777619
    inc  ecx
    jmp  .hp_hl
.hp_hdone:
    mov  eax, [rsi+32]              ; vout index
    xor  r8, rax
    and  r8, [rdi+160]               ; tomb_hash_mask -> starting probe index
    mov  r9, [rdi+152]                ; tomb_hash_buf base
    mov  r10, [rdi+64]                 ; tomb_buf base
    mov  r12, [rdi+160]                 ; mask (kept for wraparound)
    mov  r13, rdi                        ; save lst -- rdi gets repurposed below
.hp_probe:
    lea  rbx, [r9 + r8*8]                  ; &slot
    mov  rcx, [rbx]                         ; slot value (tomb_buf index or -1)
    cmp  rcx, -1
    je   .hp_ret
    imul rax, rcx, 36
    add  rax, r10                            ; &tomb_buf[slot_value]
    mov  rdi, rax
    call mac_cmp_key                          ; rsi (key) untouched by it
    cmp  eax, 1
    je   .hp_ret
    inc  r8
    and  r8, r12
    jmp  .hp_probe
.hp_ret:
    mov  rax, rbx
    mov  rdi, r13
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; mac_read_run_header(fd=rdi, out=rsi) -> rax: 0 ok / -1 err
;   Reads a run file's header, transparently handling BOTH the original
;   28-byte MAGIC_RUN format (no sparse index -- every run written before
;   this fix) and the new 44-byte MAGIC_RUN2 format (adds sparse_off/
;   sparse_n). No migration tool needed: an old-format run keeps working
;   via the caller's own unchanged full-scan fallback (sparse_n=0 signals
;   this), and gets rewritten in the new format automatically the next
;   time it's touched by a flush or compaction (both write through the
;   same updated writer). Leaves the fd positioned immediately after
;   the header either way (ready for the caller to read the bloom bytes
;   next, exactly as before this helper existed).
;
;   out (64-byte caller-allocated buffer):
;     +0  gen(8)  +8 nrec(8)  +16 bloom_bytes(8)  +24 bits_mask(8)
;     +32 header_size(8, 28 or 44)  +40 sparse_off(8)  +48 sparse_n(8)
;     +56 rec_v2(8, 0/1 -- see MAGIC_RUN3 above: 1 means PUSH records in
;     this file carry height/is_coinbase (15-byte value-portion), 0 means
;     they don't (10-byte value-portion, height/is_coinbase unavailable --
;     callers must default them to 0/0, not read 5 bytes that were never
;     written). Added alongside MAGIC_RUN3, independent of header_size:
;     MAGIC_RUN2 and MAGIC_RUN3 share the same 44-byte header shape.)
;     (sparse_off/sparse_n are 0 for an old-format run, or for a new-
;     format run whose sparse index build could find nothing -- either
;     way the caller's contract is "0 means fall back to the original
;     start-of-records scan," so both cases are handled identically.)
; ============================================================================
mac_read_run_header:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    sub  rsp, 0x30
    mov  r12, rdi           ; fd
    mov  r13, rsi            ; out

    mov  rdi, r12
    lea  rsi, [rbp-0x38]
    mov  rdx, 4
    call mac_read_exact2
    test rax, rax
    jnz  .rh_err

    mov  eax, [rbp-0x38]
    cmp  eax, MAGIC_RUN3
    je   .rh_new3
    cmp  eax, MAGIC_RUN2
    je   .rh_new2
    cmp  eax, MAGIC_RUN
    jne  .rh_err             ; unrecognized magic -- treat as corrupt

    ; ---- old format (MAGIC_RUN): remaining 24 bytes are gen+nrec+bloom_bits ----
    mov  rdi, r12
    lea  rsi, [rbp-0x38]
    mov  rdx, 24
    call mac_read_exact2
    test rax, rax
    jnz  .rh_err
    mov  rax, [rbp-0x38]
    mov  [r13+0], rax         ; gen
    mov  rax, [rbp-0x38+8]
    mov  [r13+8], rax          ; nrec
    mov  rax, [rbp-0x38+16]
    mov  rcx, rax
    dec  rcx
    mov  [r13+24], rcx           ; bits_mask
    shr  rax, 3
    mov  [r13+16], rax             ; bloom_bytes
    mov  qword [r13+32], 28         ; header_size
    mov  qword [r13+40], 0           ; sparse_off
    mov  qword [r13+48], 0            ; sparse_n
    mov  qword [r13+56], 0             ; rec_v2 = 0 (old PUSH record shape)
    xor  eax, eax
    jmp  .rh_ret

.rh_new2:
    mov  qword [rbp-0x40], 0    ; rec_v2 = 0 -- MAGIC_RUN2 grew the HEADER
                                  ; only; its PUSH records are still old-shape
    jmp  .rh_new_common
.rh_new3:
    mov  qword [rbp-0x40], 1    ; rec_v2 = 1 -- MAGIC_RUN3's PUSH records
                                  ; carry height/is_coinbase
.rh_new_common:
    ; ---- MAGIC_RUN2/RUN3 share this header shape: remaining 40 bytes are
    ; gen+nrec+bloom_bits+sparse_off+sparse_n ----
    mov  rdi, r12
    lea  rsi, [rbp-0x38]
    mov  rdx, 40
    call mac_read_exact2
    test rax, rax
    jnz  .rh_err
    mov  rax, [rbp-0x38]
    mov  [r13+0], rax          ; gen
    mov  rax, [rbp-0x38+8]
    mov  [r13+8], rax           ; nrec
    mov  rax, [rbp-0x38+16]
    mov  rcx, rax
    dec  rcx
    mov  [r13+24], rcx            ; bits_mask
    shr  rax, 3
    mov  [r13+16], rax              ; bloom_bytes
    mov  rax, [rbp-0x38+24]
    mov  [r13+40], rax                ; sparse_off
    mov  rax, [rbp-0x38+32]
    mov  [r13+48], rax                  ; sparse_n
    mov  qword [r13+32], 44              ; header_size
    mov  rax, [rbp-0x40]
    mov  [r13+56], rax                    ; rec_v2
    xor  eax, eax
    jmp  .rh_ret
.rh_err:
    mov  rax, -1
.rh_ret:
    add  rsp, 0x30
    pop  r13
    pop  r12
    pop  rbp
    ret

; mac_copy_rec(dst=rdi, src=rsi) -- copies a fixed 64-byte descriptor.
; Preserves rdi,rsi,rcx.
; Clobbers rax only. Eight qword moves: the byte loop this replaced was 70%
; of the flush's CPU (2026-09-01 perf on the live replay -- the merge sort
; calls this O(n log n) times per flush).
mac_copy_rec:
%assign _cr 0
%rep 8
    mov  rax, [rsi+_cr]
    mov  [rdi+_cr], rax
%assign _cr _cr+8
%endrep
    ret

; mac_bloom_h(key=rdi(36B), seed=esi) -> eax = FNV-1a-style 32-bit hash.
; Preserves rdi,rdx,rcx,rbx (esi untouched throughout).
; Fully unrolled (36 fixed bytes; the loop was 12% of the flush's CPU).
mac_bloom_h:
    push rbx
    push rdx
    mov  ebx, esi
%assign _bh 0
%rep 36
    movzx edx, byte [rdi+_bh]
    xor  ebx, edx
    imul ebx, ebx, 16777619
%assign _bh _bh+1
%endrep
    mov  eax, ebx
    pop  rdx
    pop  rbx
    ret

; mac_bloom_setbit(key=rdi, seed=esi, bloom_base=rdx, bits_mask=ecx) -- sets
; the one bit this (key,seed) hashes to, mod bits_mask+1. Clobbers rax/rbx/
; rdx/rcx (does NOT preserve rdx/rcx across return -- caller must re-load
; bloom_base/bits_mask before the next call if it needs them again).
mac_bloom_setbit:
    push rbx
    call mac_bloom_h
    and  eax, ecx
    mov  ebx, eax
    shr  ebx, 3
    and  eax, 7
    mov  cl, al
    mov  al, 1
    shl  al, cl
    add  rdx, rbx
    or   [rdx], al
    pop  rbx
    ret

; mac_bloom_testbit(key=rdi, seed=esi, bloom_base=rdx, bits_mask=ecx) -> eax
; 1 if the bit is set, 0 if not. Same clobber contract as mac_bloom_setbit.
mac_bloom_testbit:
    push rbx
    call mac_bloom_h
    and  eax, ecx
    mov  ebx, eax
    shr  ebx, 3
    and  eax, 7
    mov  cl, al
    mov  al, 1
    shl  al, cl
    add  rdx, rbx
    test byte [rdx], al
    jz   .bt0
    mov  eax, 1
    jmp  .btr
.bt0:
    xor  eax, eax
.btr:
    pop  rbx
    ret

; mac_clear_memtable(u=rdi) -- reset the in-memory table to empty, reusing
; its mask/blob/blob_cap pointers (local re-implementation of
; bitcoin_utxo_store.asm's utxo_store_clear, which isn't exported).
mac_clear_memtable:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    mov  r12, rdi
    mov  qword [r12], 0
    mov  qword [r12+32], 0
    mov  r13, [r12+8]
    inc  r13
    lea  rdi, [r12+40]
.cm:
    test r13, r13
    jz   .cmd
    mov  dword [rdi+40], 0xFFFFFFFF
    add  rdi, 48
    dec  r13
    jmp  .cm
.cmd:
    pop  r13
    pop  r12
    pop  rbp
    ret

; mac_calc_desc_cap(lst=rdi) -> rax = (scratch_cap - BLOOM_MAX_BYTES -
;   SCRIPT_MAX_BYTES) / 128. Leaf function, no frame needed.
mac_calc_desc_cap:
    mov  rax, [rdi+136]
    sub  rax, BLOOM_MAX_BYTES
    sub  rax, SCRIPT_MAX_BYTES
    xor  edx, edx
    mov  rcx, 128
    div  rcx
    ret

; fmt_runname(buf20=rdi, run_no=esi) -- writes "utxo_run_%06u.dat\0" (20B)
fmt_runname:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    sub  rsp, 0x10
    mov  r12, rdi
    mov  byte [r12+0], 'u'
    mov  byte [r12+1], 't'
    mov  byte [r12+2], 'x'
    mov  byte [r12+3], 'o'
    mov  byte [r12+4], '_'
    mov  byte [r12+5], 'r'
    mov  byte [r12+6], 'u'
    mov  byte [r12+7], 'n'
    mov  byte [r12+8], '_'
    mov  eax, esi
    xor  edx, edx
    mov  ebx, 100000
    div  ebx
    add  al, '0'
    mov  [r12+9], al
    mov  eax, edx
    xor  edx, edx
    mov  ebx, 10000
    div  ebx
    add  al, '0'
    mov  [r12+10], al
    mov  eax, edx
    xor  edx, edx
    mov  ebx, 1000
    div  ebx
    add  al, '0'
    mov  [r12+11], al
    mov  eax, edx
    xor  edx, edx
    mov  ebx, 100
    div  ebx
    add  al, '0'
    mov  [r12+12], al
    mov  eax, edx
    xor  edx, edx
    mov  ebx, 10
    div  ebx
    add  al, '0'
    mov  [r12+13], al
    mov  eax, edx
    add  al, '0'
    mov  [r12+14], al
    mov  dword [r12+15], 0x7461642E   ; ".dat"
    mov  byte  [r12+19], 0
    add  rsp, 0x10
    pop  r12
    pop  rbx
    pop  rbp
    ret

; mac_sort_desc(a=rdi, b=rsi, n=rdx) -- bottom-up iterative merge sort of n
; fixed-64-byte records in a, comparing the first 36 bytes (mac_cmp_key), b
; is scratch of equal size. Final sorted result always ends up in a.
mac_sort_desc:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x80
    mov  r12, rdi          ; a
    mov  r13, rsi          ; b
    mov  r14, rdx          ; n
    cmp  r14, 1
    jbe  .sd_done
    mov  rbx, 1             ; width
    mov  r15, 1             ; cur_src_is_a
.sd_pass:
    cmp  rbx, r14
    jae  .sd_maybe_copy
    cmp  r15, 1
    je   .sd_src_a
    mov  qword [rbp-0x30], r13
    mov  qword [rbp-0x38], r12
    jmp  .sd_bases_set
.sd_src_a:
    mov  qword [rbp-0x30], r12
    mov  qword [rbp-0x38], r13
.sd_bases_set:
    mov  qword [rbp-0x40], 0
.sd_outer:
    mov  rax, [rbp-0x40]
    cmp  rax, r14
    jae  .sd_pass_done
    mov  [rbp-0x48], rax
    mov  rcx, rax
    add  rcx, rbx
    cmp  rcx, r14
    jbe  .sd_mid_ok
    mov  rcx, r14
.sd_mid_ok:
    mov  [rbp-0x50], rcx
    mov  rdx, rbx
    shl  rdx, 1
    add  rdx, rax
    cmp  rdx, r14
    jbe  .sd_hi_ok
    mov  rdx, r14
.sd_hi_ok:
    mov  [rbp-0x58], rdx
    mov  rax, [rbp-0x48]
    mov  [rbp-0x60], rax
    mov  rax, [rbp-0x50]
    mov  [rbp-0x68], rax
    mov  rax, [rbp-0x48]
    mov  [rbp-0x70], rax
.sd_inner:
    mov  rax, [rbp-0x60]
    mov  rcx, [rbp-0x50]
    cmp  rax, rcx
    jae  .sd_drain_q
    mov  rax, [rbp-0x68]
    mov  rcx, [rbp-0x58]
    cmp  rax, rcx
    jae  .sd_drain_p
    mov  rax, [rbp-0x60]
    shl  rax, 6
    add  rax, [rbp-0x30]
    mov  rdi, rax
    mov  rax, [rbp-0x68]
    shl  rax, 6
    add  rax, [rbp-0x30]
    mov  rsi, rax
    call mac_cmp_key
    cmp  eax, 2
    je   .sd_take_q
    mov  rax, [rbp-0x60]
    shl  rax, 6
    add  rax, [rbp-0x30]
    mov  rsi, rax
    mov  rax, [rbp-0x70]
    shl  rax, 6
    add  rax, [rbp-0x38]
    mov  rdi, rax
    call mac_copy_rec
    inc  qword [rbp-0x60]
    inc  qword [rbp-0x70]
    jmp  .sd_inner
.sd_take_q:
    mov  rax, [rbp-0x68]
    shl  rax, 6
    add  rax, [rbp-0x30]
    mov  rsi, rax
    mov  rax, [rbp-0x70]
    shl  rax, 6
    add  rax, [rbp-0x38]
    mov  rdi, rax
    call mac_copy_rec
    inc  qword [rbp-0x68]
    inc  qword [rbp-0x70]
    jmp  .sd_inner
.sd_drain_p:
    mov  rax, [rbp-0x60]
    mov  rcx, [rbp-0x50]
    cmp  rax, rcx
    jae  .sd_drain_done
    mov  rax, [rbp-0x60]
    shl  rax, 6
    add  rax, [rbp-0x30]
    mov  rsi, rax
    mov  rax, [rbp-0x70]
    shl  rax, 6
    add  rax, [rbp-0x38]
    mov  rdi, rax
    call mac_copy_rec
    inc  qword [rbp-0x60]
    inc  qword [rbp-0x70]
    jmp  .sd_drain_p
.sd_drain_q:
    mov  rax, [rbp-0x68]
    mov  rcx, [rbp-0x58]
    cmp  rax, rcx
    jae  .sd_drain_done
    mov  rax, [rbp-0x68]
    shl  rax, 6
    add  rax, [rbp-0x30]
    mov  rsi, rax
    mov  rax, [rbp-0x70]
    shl  rax, 6
    add  rax, [rbp-0x38]
    mov  rdi, rax
    call mac_copy_rec
    inc  qword [rbp-0x68]
    inc  qword [rbp-0x70]
    jmp  .sd_drain_q
.sd_drain_done:
    mov  rax, [rbp-0x40]
    mov  rcx, rbx
    shl  rcx, 1
    add  rax, rcx
    mov  [rbp-0x40], rax
    jmp  .sd_outer
.sd_pass_done:
    shl  rbx, 1
    xor  r15, 1
    jmp  .sd_pass
.sd_maybe_copy:
    cmp  r15, 1
    je   .sd_done
    xor  ecx, ecx
.sd_copyall:
    cmp  rcx, r14
    jae  .sd_done
    push rcx
    mov  rax, rcx
    shl  rax, 6
    lea  rdi, [r12+rax]
    lea  rsi, [r13+rax]
    call mac_copy_rec
    pop  rcx
    inc  rcx
    jmp  .sd_copyall
.sd_done:
    add  rsp, 0x80
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_lsm_init(lst) -> 1 ok / -1 err
;   Opens the WAL (utxo_store_init) and resets THIS module's own fields.
;   Caller must already have set op_threshold/fill_threshold/tomb_buf/
;   tomb_cap/manifest_buf/manifest_cap/scratch_buf/scratch_cap.
; ============================================================================
global utxo_lsm_init
utxo_lsm_init:
    push rbp
    mov  rbp, rsp
    push r12
    sub  rsp, 0x10
    mov  r12, rdi
    ; SysV alignment bracket around the ONE C callee on this path.
    ;   Entry RSP == 8 mod16; `push rbp` -> 0, `push r12` -> 8, `sub 0x10`
    ;   (0 mod16) -> still 8. Every `call` in this function therefore runs at
    ;   8 mod16, which violates the ABI. Rather than resize the frame -- which
    ;   would flip the entry parity delivered to utxo_store_init and
    ;   mac_tomb_hash_reset and every asm function below them -- correct it for
    ;   exactly the call that leaves assembly, the way mac_run_lookup already
    ;   brackets its own C call. lsm_mm_invalidate_all is currently a 5-insn
    ;   leaf (two rip-relative movs, an add, ret: no frame, no SSE) so this is
    ;   latent today, but it is one `fprintf` away from incident #18's
    ;   `movaps %xmm0,-0xc0(%rbp)` -> SIGSEGV(si_addr==NULL). (2026-08-22)
    sub  rsp, 8
    call lsm_mm_invalidate_all   ; PERF_SCOPE 4.1: a fresh instance restarts
                                  ; run_no/gen at 0, so every cached mapping
                                  ; from a previous instance is now stale
    add  rsp, 8
    mov  rdi, r12
    call utxo_store_init
    cmp  rax, 1
    jne  .li_fail
    mov  qword [r12+40], 0
    mov  qword [r12+80], 0
    mov  qword [r12+88], 0
    mov  qword [r12+96], 0
    mov  qword [r12+120], 0
    mov  qword [r12+144], 0
    mov  rdi, r12
    call mac_tomb_hash_reset
    cmp  rax, 1
    jne  .li_fail
    jmp  .li_done
.li_fail:
    mov  rax, -1
.li_done:
    add  rsp, 0x10
    pop  r12
    pop  rbp
    ret

; ============================================================================
; utxo_lsm_put(lst, u, txid, index, value, height, is_coinbase, script, slen)
;                                                                -> 1/0/2/-1
; ============================================================================
global utxo_lsm_put
utxo_lsm_put:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x40
    mov  r12, rdi          ; lst
    mov  r13, rsi          ; u
    mov  [rbp-0x30], rdx   ; txid
    mov  [rbp-0x38], rcx   ; index
    mov  [rbp-0x40], r8    ; value
    mov  [rbp-0x48], r9    ; height
    ; is_coinbase/script/slen are our OWN 7th/8th/9th args, at [rbp+16/24/32]
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, [rbp-0x30]
    mov  rcx, [rbp-0x38]
    mov  r8,  [rbp-0x40]
    mov  r9,  [rbp-0x48]
    mov  rax, [rbp+16]      ; is_coinbase
    mov  r10, [rbp+24]      ; script (r10: scratch, not an arg register)
    mov  r11, [rbp+32]      ; slen
    sub  rsp, 0x18
    mov  [rsp], rax
    mov  [rsp+8], r10
    mov  [rsp+16], r11
    call utxo_store_put
    add  rsp, 0x18
    mov  r14d, eax
    cmp  r14d, 1
    jne  .lp_no_live_inc
    inc  qword [r12+88]
.lp_no_live_inc:
    inc  qword [r12+40]
    xor  r15d, r15d
    mov  rax, [r12+40]
    cmp  rax, [r12+48]
    jae  .lp_do_flush
    mov  rax, [r13]
    cmp  rax, [r12+56]
    jb   .lp_skip_flush
.lp_do_flush:
    mov  rdi, r12
    mov  rsi, r13
    call mac_flush
    cmp  rax, -1
    jne  .lp_skip_flush
    mov  r15d, 1
.lp_skip_flush:
    cmp  r15d, 1
    je   .lp_err
    mov  eax, r14d
    jmp  .lp_done
.lp_err:
    mov  rax, -1
.lp_done:
    add  rsp, 0x40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_lsm_del(lst, u, txid, index) -> 1 recorded / -1 err
;   See CONTRACT CHANGE note at top of file: memtable-miss still returns 1
;   and still records a tombstone.
; ============================================================================
global utxo_lsm_del
utxo_lsm_del:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x40
    mov  r12, rdi           ; lst
    mov  r13, rsi            ; u
    mov  rbx, rdx             ; txid
    mov  r14d, ecx              ; index
    call utxo_store_del          ; rdi..rcx unchanged since our entry
    cmp  rax, -1
    je   .ld_err
    ; append to tombstone list unconditionally (hit or miss)
    mov  rax, [r12+80]
    cmp  rax, [r12+72]
    jae  .ld_err
    mov  rdi, [r12+64]
    mov  rcx, rax
    imul rcx, rcx, 36
    add  rdi, rcx
    mov  rsi, rbx
    push rdi
    mov  rdx, 32
    call mac_memcpy
    pop  rdi
    mov  eax, r14d
    mov  [rdi+32], eax
    mov  rsi, rdi                 ; key = &tomb_buf[old_index] (just-written)
    mov  rdi, r12                  ; lst
    call mac_tomb_hash_probe
    mov  rdx, [r12+80]              ; old_index (tomb_n, still pre-increment)
    mov  [rax], rdx
    inc  qword [r12+80]
    inc  qword [r12+40]
    dec  qword [r12+88]
    xor  r15d, r15d
    mov  rax, [r12+40]
    cmp  rax, [r12+48]
    jae  .ld_do_flush
    mov  rax, [r13]
    cmp  rax, [r12+56]
    jb   .ld_skip_flush
.ld_do_flush:
    mov  rdi, r12
    mov  rsi, r13
    call mac_flush
    cmp  rax, -1
    jne  .ld_skip_flush
    mov  r15d, 1
.ld_skip_flush:
    cmp  r15d, 1
    je   .ld_err
    mov  eax, 1
    jmp  .ld_done
.ld_err:
    mov  rax, -1
.ld_done:
    add  rsp, 0x40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_lsm_count(lst) -> total_live
; ============================================================================
global utxo_lsm_count
utxo_lsm_count:
    mov  rax, [rdi+88]
    ret

; ============================================================================
; utxo_lsm_close(lst) -- tail call, same struct layout utxo_store_close needs
; ============================================================================
global utxo_lsm_close
utxo_lsm_close:
    jmp  utxo_store_close

; ============================================================================
; mac_run_lookup(lst, run_no, txid, index, &value, &height, &is_coinbase,
;                &script, &slen) ->
;   1 found-push / 0 absent-in-this-run / 2 tombstone-hit(=miss) / -1 err
; ============================================================================
mac_run_lookup:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x300
    mov  r12, rdi
    mov  r13d, esi
    mov  [rbp-0x30], rdx
    mov  [rbp-0x38], ecx
    mov  [rbp-0x40], r8     ; &value
    mov  [rbp-0x48], r9     ; &height
    mov  rax, [rbp+16]
    mov  [rbp-0x50], rax    ; &is_coinbase
    mov  rax, [rbp+24]
    mov  [rbp-0x78], rax    ; &script
    mov  rax, [rbp+32]
    mov  [rbp-0x80], rax    ; &slen

    ; off_bloom is always 0 now: bloom/script live in the dedicated
    ; lsm_get_scratch TLS buffer (see its header comment above), not in
    ; lst->scratch_buf's ping/pong-prefixed layout mac_flush still uses.
    mov  qword [rbp-0x60], 0    ; off_bloom

    ; ---- PERF_SCOPE.md 4.1 fast path ----------------------------------
    ; Try the mmap-cached lookup first. It answers from a mapping already
    ; held by this thread -- no open, no 4 MiB bloom copy, no lseek/read
    ; per record. -2 means it declined (see the extern's comment); every
    ; other value is a final answer and returns straight out, so the code
    ; below is reached ONLY as the fallback and is otherwise untouched.
    ; gen comes from the manifest entry the caller is iterating and is what
    ; makes a reused run_no impossible to serve from a stale mapping.
    ; rsp is 8 (mod 16) here (6 pushes + 0x300); 0x28 brings the call site
    ; to 0 (mod 16) as the SysV ABI requires, leaving the four stack args
    ; at [rsp .. rsp+24] and 8 bytes of pad above them.
    mov  rdi, r12               ; lst
    mov  esi, r13d              ; run_no
    mov  rdx, [rbp+40]          ; gen
    mov  rcx, [rbp-0x30]        ; txid
    mov  r8d, [rbp-0x38]        ; index
    mov  r9, [rbp-0x40]         ; &value
    sub  rsp, 0x28
    mov  rax, [rbp-0x48]
    mov  [rsp], rax             ; &height
    mov  rax, [rbp-0x50]
    mov  [rsp+8], rax           ; &is_coinbase
    mov  rax, [rbp-0x78]
    mov  [rsp+16], rax          ; &script
    mov  rax, [rbp-0x80]
    mov  [rsp+24], rax          ; &slen
    call lsm_run_lookup_mm
    add  rsp, 0x28
    cmp  eax, -2
    jne  .ml_ret

    lea  rdi, [rbp-0x180]
    mov  esi, r13d
    call fmt_runname
    lea  rdi, [rbp-0x180]
    xor  esi, esi
    mov  eax, 2
    syscall
    test rax, rax
    jl   .ml_err
    mov  [rbp-0x68], rax

    ; format-aware header read (old MAGIC_RUN or new MAGIC_RUN2, see
    ; mac_read_run_header's own header comment) -- out struct at [rbp-0x200]
    mov  rdi, [rbp-0x68]
    lea  rsi, [rbp-0x200]
    call mac_read_run_header
    test rax, rax
    jnz  .ml_err_close

    mov  rcx, [rbp-0x200+24]
    mov  [rbp-0x58], rcx        ; bits_mask
    mov  rax, [rbp-0x200+16]    ; bloom_bytes

    mov  rdi, [rbp-0x68]
    TLS_ADDR rsi, lsm_get_scratch
    add  rsi, [rbp-0x60]
    mov  rdx, rax
    call mac_read_exact2
    test rax, rax
    jnz  .ml_err_close

    lea  rdi, [rbp-0x100]
    mov  rsi, [rbp-0x30]
    mov  rdx, 32
    call mac_memcpy
    mov  eax, [rbp-0x38]
    mov  [rbp-0x100+32], eax

    TLS_ADDR rdx, lsm_get_scratch
    add  rdx, [rbp-0x60]
    mov  ecx, [rbp-0x58]
    lea  rdi, [rbp-0x100]
    mov  esi, 0x811c9dc5
    push rdx
    push rcx
    call mac_bloom_testbit
    pop  rcx
    pop  rdx
    test eax, eax
    jz   .ml_absent_close
    lea  rdi, [rbp-0x100]
    mov  esi, 0xa1b2c3d4
    push rdx
    push rcx
    call mac_bloom_testbit
    pop  rcx
    pop  rdx
    test eax, eax
    jz   .ml_absent_close
    lea  rdi, [rbp-0x100]
    mov  esi, 0x5bd1e995
    call mac_bloom_testbit
    test eax, eax
    jz   .ml_absent_close

    ; ---- sparse index acceleration ----
    ; records_start = header_size + bloom_bytes: the position the file is
    ; ALREADY sitting at (untouched since the bloom-bytes read above) --
    ; captured explicitly here because the binary search below performs its
    ; own lseeks to read individual sparse entries, so "don't seek, rely on
    ; the current position" stops being valid once any entries have been
    ; read. Every path from here to .ml_scan_loop seeks explicitly instead.
    mov  rax, [rbp-0x200+32]         ; header_size
    add  rax, [rbp-0x200+16]          ; + bloom_bytes
    mov  [rbp-0x220], rax               ; records_start

    mov  rax, [rbp-0x200+48]         ; sparse_n
    test rax, rax
    jnz  .ml_sp_search
    mov  r15, [rbp-0x220]             ; old format or empty run -- no sparse index
    jmp  .ml_sp_seek

.ml_sp_search:
    xor  rbx, rbx                      ; lo = 0
    mov  r14, rax
    dec  r14                            ; hi = sparse_n - 1
    mov  r15, [rbp-0x220]                ; best_offset defaults to records_start;
                                           ; index 0 is always sampled (see the
                                           ; write side), so a well-formed search
                                           ; always improves on this default.
.ml_sp_loop:
    cmp  rbx, r14
    jg   .ml_sp_seek
    mov  rax, rbx
    add  rax, r14
    shr  rax, 1                           ; mid
    mov  rcx, [rbp-0x200+40]               ; sparse_off
    mov  rdx, rax
    imul rdx, rdx, SPARSE_ENT_SIZE
    add  rcx, rdx                           ; this entry's file offset
    push rax
    push rbx
    push r14
    push r15
    mov  rdi, [rbp-0x68]
    mov  rsi, rcx
    xor  edx, edx
    mov  eax, 8                              ; lseek SEEK_SET
    syscall
    test rax, rax
    js   .ml_sp_err_pop
    mov  rdi, [rbp-0x68]
    lea  rsi, [rbp-0x260]
    mov  rdx, SPARSE_ENT_SIZE
    call mac_read_exact2
    test rax, rax
    jnz  .ml_sp_err_pop
    pop  r15
    pop  r14
    pop  rbx
    pop  r13                                  ; mid -- NOT popped into rax: mac_cmp_key
                                                 ; returns its result in eax, which would
                                                 ; clobber mid before lo/hi get updated
                                                 ; from it below (this was a real infinite-
                                                 ; loop bug: lo/hi kept "shrinking" toward
                                                 ; the cmp result 0-2 instead of toward mid,
                                                 ; so the range stopped converging).
    lea  rdi, [rbp-0x260]                       ; sampled key
    lea  rsi, [rbp-0x100]                        ; target key
    call mac_cmp_key                              ; 0=sampled<target 1=eq 2=sampled>target
    cmp  eax, 2
    je   .ml_sp_hi
    mov  rcx, [rbp-0x260+36]                        ; this entry's own file_offset
    mov  r15, rcx
    lea  rbx, [r13+1]                                 ; lo = mid + 1
    jmp  .ml_sp_loop
.ml_sp_hi:
    test r13, r13
    jz   .ml_sp_seek                                    ; mid==0: no smaller candidate exists
    lea  r14, [r13-1]                                     ; hi = mid - 1
    jmp  .ml_sp_loop
.ml_sp_err_pop:
    add  rsp, 32
    jmp  .ml_err_close
.ml_sp_seek:
    mov  rdi, [rbp-0x68]
    mov  rsi, r15
    xor  edx, edx
    mov  eax, 8                                           ; lseek SEEK_SET
    syscall
    test rax, rax
    js   .ml_err_close

.ml_scan_loop:
    mov  rdi, [rbp-0x68]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 37
    call mac_read_exact2
    test rax, rax
    jnz  .ml_absent_close
    lea  rdi, [rbp-0x1C0]
    lea  rsi, [rbp-0x100]
    call mac_cmp_key
    cmp  eax, 1
    je   .ml_key_match
    cmp  eax, 2
    je   .ml_absent_close
    movzx eax, byte [rbp-0x1C0+36]
    cmp  eax, 1
    jne  .ml_scan_loop
    ; Skip past a NON-matching PUSH record to examine the next one. Format-
    ; aware for the SAME reason .ml_key_match is: reading the wrong byte
    ; count here desyncs the scan position for every record after this one
    ; (a real bug this fixed: it stayed hardcoded at 10 bytes/old slen
    ; offset even after .ml_key_match was updated, so any scan that had to
    ; skip past even one new-shape record silently corrupted every lookup
    ; after it -- caught by the sparse-index test's spot-checks, which
    ; started reporting false misses partway through a large run).
    mov  rax, [rbp-0x200+56]      ; rec_v2
    test rax, rax
    jz   .ml_skip_old
    mov  rdi, [rbp-0x68]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 15                    ; value(8)+slen(2)+height(4)+is_coinbase(1)
    call mac_read_exact2
    test rax, rax
    jnz  .ml_absent_close
    movzx eax, word [rbp-0x1C0+8]     ; slen (new-shape offset)
    jmp  .ml_skip_have_slen
.ml_skip_old:
    mov  rdi, [rbp-0x68]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 10
    call mac_read_exact2
    test rax, rax
    jnz  .ml_absent_close
    movzx eax, word [rbp-0x1C0+8]     ; slen (old-shape offset, same position)
.ml_skip_have_slen:
    test eax, eax
    jz   .ml_scan_loop
    mov  rdi, [rbp-0x68]
    mov  rsi, rax
    mov  edx, 1
    mov  eax, 8
    syscall
    test rax, rax
    jl   .ml_err_close
    jmp  .ml_scan_loop
.ml_key_match:
    movzx eax, byte [rbp-0x1C0+36]
    cmp  eax, 2
    je   .ml_tombstone_close
    ; format-aware value-portion read: an old-shape run (rec_v2==0, see
    ; MAGIC_RUN3's header comment) never captured height/is_coinbase at
    ; all, so those two paths write the caller's output pointers
    ; DIRECTLY from their own respective buffer layouts (rather than
    ; sharing one extraction after the fact) to avoid any aliasing
    ; confusion between where slen sits in each shape.
    mov  rax, [rbp-0x200+56]      ; rec_v2
    test rax, rax
    jz   .ml_read_old_rec

    ; ---- new shape: value(8)+slen(2)+height(4)+is_coinbase(1) = 15, SAME
    ; order mac_flush actually writes (see its descriptor-build comment:
    ; height/is_coinbase reuse the pad gap right AFTER slen, not before
    ; it) -- this function originally assumed value,height,is_coinbase,slen
    ; instead, a real bug: every new-format height/is_coinbase/slen came
    ; back wrong (slen's own bytes reinterpreted as height), caught by the
    ; flush-then-read-back assertions in tests/test_utxo_lsm.c. ----
    mov  rdi, [rbp-0x68]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 15
    call mac_read_exact2
    test rax, rax
    jnz  .ml_err_close
    movzx r14d, word [rbp-0x1C0+8]    ; slen
    mov  rax, [rbp-0x1C0]
    mov  rcx, [rbp-0x40]
    mov  [rcx], rax                    ; *value
    mov  eax, [rbp-0x1C0+10]
    mov  rcx, [rbp-0x48]
    mov  [rcx], rax                     ; *height (zero-extended)
    movzx eax, byte [rbp-0x1C0+14]
    mov  rcx, [rbp-0x50]
    mov  [rcx], rax                      ; *is_coinbase (zero-extended)
    jmp  .ml_have_value_fields

.ml_read_old_rec:
    ; ---- old shape: value(8)+slen(2) = 10; height/is_coinbase were never
    ; captured for this run -- caller gets 0/0, not garbage. ----
    mov  rdi, [rbp-0x68]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 10
    call mac_read_exact2
    test rax, rax
    jnz  .ml_err_close
    movzx r14d, word [rbp-0x1C0+8]    ; slen (old offset)
    mov  rax, [rbp-0x1C0]
    mov  rcx, [rbp-0x40]
    mov  [rcx], rax                    ; *value
    mov  rcx, [rbp-0x48]
    mov  qword [rcx], 0                 ; *height = 0
    mov  rcx, [rbp-0x50]
    mov  qword [rcx], 0                  ; *is_coinbase = 0
.ml_have_value_fields:
    test r14d, r14d
    jz   .ml_push_noscript
    mov  rdi, [rbp-0x68]
    TLS_ADDR rsi, lsm_get_scratch
    add  rsi, [rbp-0x60]
    add  rsi, BLOOM_MAX_BYTES
    mov  rdx, r14
    call mac_read_exact2
    test rax, rax
    jnz  .ml_err_close
.ml_push_noscript:
    mov  rdi, [rbp-0x68]
    mov  eax, 3
    syscall
    ; script ptr
    mov  rcx, [rbp-0x78]
    TLS_ADDR rax, lsm_get_scratch
    add  rax, [rbp-0x60]
    add  rax, BLOOM_MAX_BYTES
    mov  [rcx], rax
    ; slen
    mov  rcx, [rbp-0x80]
    mov  [rcx], r14d
    mov  eax, 1
    jmp  .ml_ret
.ml_tombstone_close:
    mov  rdi, [rbp-0x68]
    mov  eax, 3
    syscall
    mov  eax, 2
    jmp  .ml_ret
.ml_absent_close:
    mov  rdi, [rbp-0x68]
    mov  eax, 3
    syscall
    xor  eax, eax
    jmp  .ml_ret
.ml_err_close:
    mov  rdi, [rbp-0x68]
    mov  eax, 3
    syscall
.ml_err:
    mov  rax, -1
.ml_ret:
    add  rsp, 0x300
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_lsm_get(lst, u, txid, index, &value, &height, &is_coinbase, &script,
;              &slen) -> 1/0/-1
; height/is_coinbase are u64* (unnarrowed, matching &value's treatment) --
; NOT the narrow u32* convention &slen uses at this layer, to avoid needing
; the same scratch+narrow-copy dance twice more for no real benefit (a block
; height is an unbounded-growing counter in spirit, like value, not a small
; bounded count like a script length).
; ============================================================================
global utxo_lsm_get
utxo_lsm_get:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x120
    mov  r12, rdi
    mov  r13, rsi
    mov  rbx, rdx
    mov  [rbp-0x30], ecx
    mov  [rbp-0x38], r8     ; &value
    mov  [rbp-0x40], r9     ; &height
    mov  rax, [rbp+16]
    mov  [rbp-0x68], rax    ; &is_coinbase
    mov  rax, [rbp+24]
    mov  [rbp-0x48], rax    ; &script
    mov  rax, [rbp+32]
    mov  [rbp-0x70], rax    ; &slen

    mov  rdi, r13
    mov  rsi, rbx
    mov  edx, [rbp-0x30]
    mov  rcx, [rbp-0x38]    ; &value
    mov  r8, [rbp-0x40]     ; &height
    mov  r9, [rbp-0x68]     ; &is_coinbase
    ; utxo_get's REAL contract writes a full 8-byte "unsigned long* slen"
    ; (see bitcoin_utxo.asm) even though this module's own contract is
    ; u32* slen throughout -- forwarding the caller's 4-byte u32* directly
    ; here would be a genuine 4-byte stack overflow on every memtable hit.
    ; Give it an 8-byte scratch slot instead and narrow-copy below.
    sub  rsp, 0x10
    mov  rax, [rbp-0x48]
    mov  [rsp], rax          ; &script (utxo_get's 7th arg)
    lea  rax, [rbp-0x110]
    mov  [rsp+8], rax        ; scratch &slen (utxo_get's 8th arg)
    call utxo_get
    add  rsp, 0x10
    cmp  eax, 1
    jne  .lg_no_memtable_hit
    jmp  .lg_found          ; slen already in the scratch slot; published below
.lg_no_memtable_hit:

    ; Check THIS generation's unflushed tombstone list before falling
    ; through to disk runs. Without this, a del that missed the memtable
    ; (assumed to shadow an older run, per the documented contract change)
    ; would stay invisible to get() until the NEXT flush actually writes
    ; its tombstone record to a run file -- a real staleness window, since
    ; tomb_buf is otherwise only consulted at flush time.
    lea  rdi, [rbp-0x100]
    mov  rsi, rbx
    push rdi
    mov  rdx, 32
    call mac_memcpy
    pop  rdi
    mov  eax, [rbp-0x30]
    mov  [rdi+32], eax
    lea  rsi, [rbp-0x100]
    mov  rdi, r12
    call mac_tomb_hash_probe
    cmp  qword [rax], -1
    je   .lg_tomb_done
    jmp  .lg_not_found
.lg_tomb_done:

    mov  rax, [r12+120]
    mov  [rbp-0x50], rax
.lg_run_loop:
    mov  rax, [rbp-0x50]
    test rax, rax
    jz   .lg_not_found
    dec  rax
    mov  [rbp-0x50], rax
    ; run_no comes from the manifest ENTRY, not the array index -- once
    ; compaction can replace many runs with one, the index no longer
    ; determines the file number.
    mov  rcx, rax
    shl  rcx, 4                 ; *16 (entry size)
    mov  rdx, [r12+104]          ; manifest_buf
    add  rdx, rcx
    mov  r14, [rdx]               ; gen (PERF_SCOPE 4.1: validates the
                                   ; mmap cache -- see mac_run_lookup)
    mov  esi, [rdx+8]             ; run_no
    mov  rdi, r12
    mov  rdx, rbx
    mov  ecx, [rbp-0x30]
    mov  r8, [rbp-0x38]      ; &value
    mov  r9, [rbp-0x40]      ; &height
    mov  rax, [rbp-0x68]     ; &is_coinbase
    mov  r10, [rbp-0x48]     ; &script (r10: scratch, not an arg register)
    lea  r11, [rbp-0x110]    ; &slen -> OWN scratch slot: the run lookups
                              ; store 4 bytes (u32 internally); the caller's
                              ; unsigned long* gets one full-width store at
                              ; .lg_found instead of a torn half-write here
    sub  rsp, 0x28           ; 0x28 == 0x18 (mod 16): same call-site
                              ; alignment as before, one more arg slot
    mov  [rsp], rax
    mov  [rsp+8], r10
    mov  [rsp+16], r11
    mov  [rsp+24], r14       ; gen -> mac_run_lookup's [rbp+40]
    call mac_run_lookup
    add  rsp, 0x28
    cmp  eax, 1
    je   .lg_found
    cmp  eax, 2
    je   .lg_not_found
    cmp  eax, -1
    je   .lg_err
    jmp  .lg_run_loop
.lg_found:
    ; publish slen to the caller ONCE, full width. Every internal path
    ; (utxo_get writes 8 bytes, the run lookups write 4) delivered it into
    ; this function's own scratch slot; the 32-bit load below zero-extends,
    ; so the 8-byte store cannot carry stale high bits. THE BUG THIS FIXES
    ; (incident #49): the run paths previously stored 4 bytes straight
    ; through the caller's pointer while every daemon caller declares
    ; "unsigned long* slen" -- the upper half of the caller's variable kept
    ; whatever the stack last held, and mempool validation nondeterministically
    ; rejected real transactions with "prevout script too large" whenever
    ; that garbage was nonzero. The public contract is now explicitly
    ; 64-bit; the 11 callers that had matched the old 4-byte behaviour were
    ; migrated in the same commit.
    mov  eax, dword [rbp-0x110]
    mov  rcx, [rbp-0x70]
    mov  [rcx], rax
    mov  eax, 1
    jmp  .lg_done
.lg_not_found:
    xor  eax, eax
    jmp  .lg_done
.lg_err:
    mov  rax, -1
.lg_done:
    add  rsp, 0x120
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_lsm_flush(lst=rdi, u=rsi) -> 1 ok / -1 err
;   mac_flush by its public name, for the ONE caller that needs a flush
;   without an accompanying put/del: daemon/utxo_live.c, at the moment
;   catch-up completes and the flush thresholds downshift to steady state.
;
;   Until 2026-08-23 that caller had no way to ask. The downshift comment
;   said "the next put/del simply sees live-count over the new, lower
;   threshold and flushes naturally" -- true only if another block arrives.
;   Caught up on a quiet chain there is no next put/del, so the current WAL
;   generation stays BULK-sized indefinitely, and any restart in that window
;   reloads it into a steady-state 2^16-slot memtable. daemon/flush_wal_tail.c
;   documents where that ends up; it was hit for real after the 963,000-block
;   replay finished, spinning in utxo_del's probe loop at 100% CPU.
;
;   A tail jump, so the ABI and return contract are mac_flush's exactly.
; ============================================================================
global utxo_lsm_flush
utxo_lsm_flush:
    jmp  mac_flush

; ============================================================================
; mac_flush(lst=rdi, u=rsi) -> 1 ok / -1 err
;   See header comment for full algorithm. Called by utxo_lsm_put/del once
;   op_count or memtable fill crosses its threshold.
; ============================================================================
mac_flush:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x300
    mov  r12, rdi           ; lst
    mov  r13, rsi            ; u
    ; background-compaction gate: see mac_flush_hook. r12/r13 are callee-saved
    ; in the C hook. mac_flush is entered from asm callers with rsp%16 == 0
    ; (abi-check: "entry 0"), so the frame is aligned here by accident of the
    ; prologue; align explicitly and restore from rbp so a future caller with
    ; the other parity cannot break the one call that leaves assembly.
    mov  rax, [rel mac_flush_hook]
    test rax, rax
    jz   .mf_nohook
    and  rsp, -16
    call rax
    lea  rsp, [rbp-0x328]                    ; 5 pushes + 0x300 frame
.mf_nohook:
    ; the flush ends by truncating the WAL: every buffered byte must be in the file before
    ; anything here can fail and leave the WAL as the only copy of the memtable
    mov  rdi, r12
    call utxo_store_wal_drain
    cmp  rax, -1
    je   .fl_err

    mov  rdi, r12
    call mac_calc_desc_cap
    mov  [rbp-0x30], rax     ; desc_cap
    shl  rax, 6
    mov  [rbp-0x40], rax     ; off_desc_b
    shl  rax, 1
    mov  [rbp-0x48], rax     ; off_bloom
    mov  qword [rbp-0x38], 0 ; n_desc

    ; ---- walk memtable live slots -> PUSH descriptors ----
    mov  rax, [r13+8]
    mov  [rbp-0x58], rax      ; mask
    mov  qword [rbp-0x50], 0  ; slot cursor i
.fl_slot_loop:
    mov  rax, [rbp-0x50]
    cmp  rax, [rbp-0x58]
    ja   .fl_slots_done
    mov  rax, [rbp-0x50]
    imul rax, rax, 48
    lea  rax, [r13+rax+40]     ; slot base
    mov  ecx, [rax+40]
    cmp  ecx, 0xFFFFFFFF
    je   .fl_slot_next
    mov  rdx, [rbp-0x38]
    cmp  rdx, [rbp-0x30]
    jae  .fl_err
    mov  rdi, [r12+128]
    mov  rsi, rdx
    shl  rsi, 6
    add  rdi, rsi               ; dest descriptor
    push rax                     ; slot base
    push rdi                      ; dest
    lea  rsi, [rax+8]
    mov  rdx, 32
    call mac_memcpy
    pop  rdi
    pop  rax
    mov  ecx, [rax+40]
    mov  [rdi+32], ecx
    mov  byte [rdi+36], 1         ; type = PUSH
    mov  rdx, [rax]                ; blob_off
    mov  rcx, [r13+16]              ; blob base
    add  rdx, rcx                    ; record = blob+blob_off (bitcoin_utxo.asm
                                       ; Stage D layout: value@0 height/cb@8
                                       ; (packed) slen@16 script@24)
    mov  rcx, [rdx]                   ; value
    mov  [rdi+40], rcx
    ; height/is_coinbase reuse the sort descriptor's existing pad gap
    ; between slen(+48,2B) and script_ptr(+56) -- was 6 bytes of pure
    ; padding, now height(4B)@+50 + is_coinbase(1B)@+54 + 1 pad byte@+55,
    ; so the descriptor's overall 64-byte size and script_ptr's offset are
    ; both unchanged (mac_sort_desc/mac_copy_rec copy the struct wholesale
    ; via `shl rax,6`, oblivious to individual field positions).
    mov  rcx, [rdx+8]                  ; height(low32)/is_coinbase(byte32) packed
    mov  [rdi+50], ecx                  ; height
    mov  rax, rcx
    shr  rax, 32
    and  eax, 0xFF
    mov  [rdi+54], al                    ; is_coinbase
    mov  cx, [rdx+16]                     ; slen (moved from +8 to +16)
    mov  [rdi+48], cx
    lea  rcx, [rdx+24]                     ; script_ptr (moved from +16 to +24)
    mov  [rdi+56], rcx
    inc  qword [rbp-0x38]
.fl_slot_next:
    inc  qword [rbp-0x50]
    jmp  .fl_slot_loop
.fl_slots_done:

    ; ---- walk tombstone list -> DEL descriptors where not currently live ----
    mov  qword [rbp-0x60], 0     ; tomb cursor
.fl_tomb_loop:
    mov  rax, [rbp-0x60]
    cmp  rax, [r12+80]
    jae  .fl_tomb_done
    mov  rbx, [r12+64]
    mov  rcx, rax
    imul rcx, rcx, 36
    add  rbx, rcx                  ; tomb entry ptr
    mov  rdi, r13
    mov  rsi, rbx
    mov  edx, [rbx+32]
    ; This call only cares whether the key is CURRENTLY live (eax==1); every
    ; output is discarded, so all 5 just need valid scratch, no narrowing.
    lea  rcx, [rbp-0x180]     ; &value (discarded)
    lea  r8, [rbp-0x188]      ; &height (discarded)
    lea  r9, [rbp-0x190]      ; &is_coinbase (discarded)
    sub  rsp, 0x10
    lea  rax, [rbp-0x198]
    mov  [rsp], rax           ; &script (discarded)
    lea  rax, [rbp-0x1A0]
    mov  [rsp+8], rax         ; &slen (discarded)
    call utxo_get
    add  rsp, 0x10
    cmp  eax, 1
    je   .fl_tomb_skip
    mov  rdx, [rbp-0x38]
    cmp  rdx, [rbp-0x30]
    jae  .fl_err
    mov  rdi, [r12+128]
    mov  rsi, rdx
    shl  rsi, 6
    add  rdi, rsi
    push rdi
    mov  rsi, rbx
    mov  rdx, 36
    call mac_memcpy
    pop  rdi
    mov  byte [rdi+36], 2          ; type = DEL
    inc  qword [rbp-0x38]
.fl_tomb_skip:
    inc  qword [rbp-0x60]
    jmp  .fl_tomb_loop
.fl_tomb_done:

    mov  rax, [rbp-0x38]
    test rax, rax
    jz   .fl_finish_reset

    ; Check manifest capacity BEFORE doing any sort/bloom/run-file work --
    ; catching this after writing the run file (as the later manifest-
    ; append check does, kept as a defensive backstop) would leave an
    ; orphaned run file on disk that's never referenced by the manifest,
    ; silently losing whatever it would have shadowed (fatal for a
    ; tombstone: an older run's stale PUSH stays visible to get()).
    mov  rax, [r12+120]
    cmp  rax, [r12+112]
    jae  .fl_err

    ; ---- sort descriptors ----
    mov  rdi, [r12+128]
    mov  rsi, [r12+128]
    add  rsi, [rbp-0x40]
    mov  rdx, [rbp-0x38]
    call mac_sort_desc

    ; ---- compute bloom_bits/bits_mask ----
    mov  rax, [rbp-0x38]
    imul rax, rax, 10
    cmp  rax, 64
    jae  .fl_bb1
    mov  rax, 64
.fl_bb1:
    mov  rcx, 1
.fl_bb_loop:
    cmp  rcx, rax
    jae  .fl_bb2
    shl  rcx, 1
    jmp  .fl_bb_loop
.fl_bb2:
    mov  rdx, BLOOM_MAX_BYTES*8
    cmp  rcx, rdx
    jbe  .fl_bb3
    mov  rcx, rdx
.fl_bb3:
    mov  [rbp-0x70], rcx           ; bloom_bits
    mov  rax, rcx
    shr  rax, 3
    mov  [rbp-0x68], rax           ; bloom_bytes
    dec  rcx
    mov  [rbp-0x78], rcx           ; bits_mask

    ; ---- zero bloom region ----
    mov  rdi, [r12+128]
    add  rdi, [rbp-0x48]
    mov  rcx, [rbp-0x68]
.fl_bz:
    test rcx, rcx
    jz   .fl_bz_done
    mov  byte [rdi], 0
    inc  rdi
    dec  rcx
    jmp  .fl_bz
.fl_bz_done:

    ; ---- set 3 bloom bits per descriptor ----
    mov  qword [rbp-0x80], 0
.fl_bloom_loop:
    mov  rax, [rbp-0x80]
    cmp  rax, [rbp-0x38]
    jae  .fl_bloom_done
    mov  rdi, [r12+128]
    mov  rsi, rax
    shl  rsi, 6
    add  rdi, rsi                   ; key ptr
    mov  rdx, [r12+128]
    add  rdx, [rbp-0x48]              ; bloom base
    mov  ecx, [rbp-0x78]                ; bits_mask
    push rdi
    push rdx
    push rcx
    mov  esi, 0x811c9dc5
    call mac_bloom_setbit
    pop  rcx
    pop  rdx
    pop  rdi
    push rdi
    push rdx
    push rcx
    mov  esi, 0xa1b2c3d4
    call mac_bloom_setbit
    pop  rcx
    pop  rdx
    pop  rdi
    mov  esi, 0x5bd1e995
    call mac_bloom_setbit
    inc  qword [rbp-0x80]
    jmp  .fl_bloom_loop
.fl_bloom_done:

    ; ---- write run file ----
    lea  rdi, [rbp-0x140]
    mov  esi, [r12+144]              ; this run's file number = next_run_no
    call fmt_runname
    lea  rdi, [rbp-0x140]
    mov  esi, 1 | 0x40 | 0x200
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .fl_err
    mov  [rbp-0x88], rax             ; fd
    mov  qword [rel mac_fl_fill], 0  ; fresh record buffer for this run

    mov  dword [rbp-0x100], MAGIC_RUN3     ; new PUSH record shape (Stage D)
    mov  rax, [r12+96]                ; next_gen
    mov  [rbp-0x100+4], rax
    mov  rax, [rbp-0x38]
    mov  [rbp-0x100+12], rax
    mov  rax, [rbp-0x70]
    mov  [rbp-0x100+20], rax
    mov  qword [rbp-0x100+28], 0        ; sparse_off placeholder (patched below)
    mov  qword [rbp-0x100+36], 0         ; sparse_n placeholder (patched below)
    mov  rdi, [rbp-0x88]
    lea  rsi, [rbp-0x100]
    mov  rdx, 44
    call mac_write_exact
    test rax, rax
    jnz  .fl_err_close

    mov  rdi, [rbp-0x88]
    mov  rsi, [r12+128]
    add  rsi, [rbp-0x48]
    mov  rdx, [rbp-0x68]
    call mac_write_exact
    test rax, rax
    jnz  .fl_err_close

    mov  qword [rbp-0x80], 0
    mov  qword [rbp-0x1A0], 0    ; sparse_n (entries sampled so far)
.fl_wr_loop:
    mov  rax, [rbp-0x80]
    cmp  rax, [rbp-0x38]
    jae  .fl_wr_done
    mov  rsi, [r12+128]
    mov  rcx, rax
    shl  rcx, 6
    add  rsi, rcx
    mov  rdi, [rbp-0x88]

    ; ---- sparse index sampling: every SPARSE_STRIDEth record (by sorted
    ; order -- index 0 always included), record (key, file_offset) BEFORE
    ; writing this record, so the captured offset is exactly where its
    ; bytes are about to start. mac_memcpy preserves rdi/rsi/rdx/rcx (only
    ; clobbers rax), so no need to save them across that call; rdi=fd DOES
    ; get repurposed as mac_memcpy's dest pointer, restored explicitly
    ; before falling through to the caller's own upcoming write below. ----
    test rax, (SPARSE_STRIDE-1)
    jnz  .fl_wr_nosample
    push rsi
    xor  esi, esi
    mov  edx, 1                  ; SEEK_CUR
    mov  eax, 8
    syscall
    pop  rsi
    test rax, rax
    js   .fl_err_close
    add  rax, [rel mac_fl_fill]    ; + the records still in the write buffer: the LOGICAL offset
    mov  rbx, rax                  ; this record's file offset
    mov  rdx, [rbp-0x1A0]            ; sparse_n
    mov  rdi, [r12+128]
    add  rdi, [rbp-0x40]               ; sparse_buf base (off_desc_b slack region)
    imul rax, rdx, SPARSE_ENT_SIZE
    add  rdi, rax                        ; dest = sparse_buf + sparse_n*44
    push rdi
    mov  rdx, 36
    call mac_memcpy                        ; copy the 36-byte key (rsi) -> dest (rdi)
    pop  rdi
    mov  [rdi+36], rbx                       ; append file_offset right after the key
    inc  qword [rbp-0x1A0]                     ; sparse_n++
    mov  rdi, [rbp-0x88]                         ; restore fd
.fl_wr_nosample:
    push rsi
    mov  rdx, 37
    call mac_fl_write
    pop  rsi
    test rax, rax
    jnz  .fl_err_close
    movzx eax, byte [rsi+36]
    cmp  eax, 1
    jne  .fl_wr_next
    ; value(8)+slen(2)+height(4)+is_coinbase(1) = 15 contiguous bytes at
    ; descriptor+40, in exactly this order -- see the descriptor-build
    ; comment above (height/is_coinbase reuse the existing pad gap right
    ; after slen, so this is still ONE write, just 15 bytes instead of 10).
    mov  rdi, [rbp-0x88]
    lea  rax, [rsi+40]
    push rsi
    mov  rsi, rax
    mov  rdx, 15
    call mac_fl_write
    pop  rsi
    test rax, rax
    jnz  .fl_err_close
    movzx r14d, word [rsi+48]
    test r14d, r14d
    jz   .fl_wr_next
    mov  rdi, [rbp-0x88]
    mov  r9, [rsi+56]
    push rsi
    mov  rsi, r9
    mov  rdx, r14
    call mac_fl_write
    pop  rsi
    test rax, rax
    jnz  .fl_err_close
.fl_wr_next:
    inc  qword [rbp-0x80]
    jmp  .fl_wr_loop
.fl_wr_done:
    ; drain the buffered records BEFORE the SEEK_CUR below reads the offset
    mov  rdi, [rbp-0x88]
    call mac_fl_drain
    test rax, rax
    jnz  .fl_err_close
    ; ---- write the sparse index right after the last record, then seek
    ; back to patch sparse_off/sparse_n into the header -- the same seek-
    ; back-and-patch shape this file's own compaction write path already
    ; uses for its nrec/bloom fields. ----
    mov  rdi, [rbp-0x88]
    xor  esi, esi
    mov  edx, 1                    ; SEEK_CUR -- this is where the sparse index starts
    mov  eax, 8
    syscall
    test rax, rax
    js   .fl_err_close
    mov  [rbp-0x1A8], rax             ; sparse_off

    mov  rax, [rbp-0x1A0]               ; sparse_n
    test rax, rax
    jz   .fl_sp_written
    imul rdx, rax, SPARSE_ENT_SIZE
    mov  rdi, [rbp-0x88]
    mov  rsi, [r12+128]
    add  rsi, [rbp-0x40]
    call mac_write_exact
    test rax, rax
    jnz  .fl_err_close
.fl_sp_written:
    mov  rdi, [rbp-0x88]
    mov  esi, 28
    xor  edx, edx
    mov  eax, 8                        ; lseek SEEK_SET to the sparse_off/sparse_n slot
    syscall
    test rax, rax
    jl   .fl_err_close
    mov  rax, [rbp-0x1A8]
    mov  [rbp-0x100], rax
    mov  rax, [rbp-0x1A0]
    mov  [rbp-0x100+8], rax
    mov  rdi, [rbp-0x88]
    lea  rsi, [rbp-0x100]
    mov  rdx, 16
    call mac_write_exact
    test rax, rax
    jnz  .fl_err_close

    mov  rdi, [rbp-0x88]
    call mac_fsync2
    mov  rdi, [rbp-0x88]
    mov  eax, 3
    syscall

    ; ---- append to in-memory manifest, advance next_gen/next_run_no ----
    mov  rax, [r12+120]
    cmp  rax, [r12+112]
    jae  .fl_err
    mov  rdi, [r12+104]
    mov  rcx, rax
    shl  rcx, 4                 ; *16 (entry size: gen8+run_no8)
    add  rdi, rcx
    mov  rdx, [r12+96]           ; gen
    mov  [rdi], rdx
    mov  rdx, [r12+144]           ; run_no
    mov  [rdi+8], rdx
    inc  qword [r12+120]          ; manifest_n++
    inc  qword [r12+96]            ; next_gen++
    inc  qword [r12+144]            ; next_run_no++

    ; ---- publish manifest: tmp file + fsync + rename + dir fsync ----
    lea  rdi, [rel manifest_tmp_name]
    mov  esi, 1 | 0x40 | 0x200
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .fl_err
    mov  rbx, rax
    ; New-format (MAGIC_MANIFEST2) header: magic(4) manifest_n(8)
    ; total_live(8) = 20 bytes. At THIS point total_live ([r12+88]) is the
    ; RUNS-ONLY live count: the memtable's live entries were just folded into
    ; the run written above, and the WAL is truncated a few lines below at
    ; .fl_finish_reset -- so the running counter equals "all runs, WAL empty."
    ; Persisting it here means reload restores an exact base and only has to
    ; add the (then-empty, or since-appended) WAL tail's net on top.
    mov  dword [rbp-0x100], MAGIC_MANIFEST2
    mov  rax, [r12+120]
    mov  [rbp-0x100+4], rax
    mov  rax, [r12+88]                 ; total_live (runs-only at this point)
    mov  [rbp-0x100+12], rax
    mov  rdi, rbx
    lea  rsi, [rbp-0x100]
    mov  rdx, 20
    call mac_write_exact
    test rax, rax
    jnz  .fl_merr_close
    mov  rdi, rbx
    mov  rsi, [r12+104]
    mov  rdx, [r12+120]
    shl  rdx, 4                 ; *16 (entry size)
    call mac_write_exact
    test rax, rax
    jnz  .fl_merr_close
    mov  rdi, rbx
    call mac_fsync2
    mov  rdi, rbx
    mov  eax, 3
    syscall

    lea  rdi, [rel manifest_tmp_name]
    lea  rsi, [rel manifest_name]
    mov  eax, 82                        ; rename
    syscall
    test rax, rax
    jl   .fl_err

    lea  rdi, [rel dot_name]
    xor  esi, esi
    mov  eax, 2
    syscall
    test rax, rax
    jl   .fl_finish_reset
    mov  rbx, rax
    mov  rdi, rbx
    call mac_fsync2
    mov  rdi, rbx
    mov  eax, 3
    syscall

.fl_finish_reset:
    mov  rdi, [r12+0]
    xor  esi, esi
    mov  eax, 77                         ; ftruncate
    syscall
    mov  rdi, [r12+0]
    xor  esi, esi
    xor  edx, edx
    mov  eax, 8                           ; lseek SEEK_SET 0
    syscall
    mov  qword [r12+16], 0
    mov  rdi, r13
    call mac_clear_memtable
    mov  qword [r12+40], 0
    mov  qword [r12+80], 0
    mov  rdi, r12
    call mac_tomb_hash_reset
    cmp  rax, 1
    jne  .fl_err
    mov  rax, 1
    jmp  .fl_ret

.fl_merr_close:
    mov  rdi, rbx
    mov  eax, 3
    syscall
    jmp  .fl_err
.fl_err_close:
    mov  rdi, [rbp-0x88]
    mov  eax, 3
    syscall
.fl_err:
    mov  rax, -1
.fl_ret:
    add  rsp, 0x300
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_lsm_reload(lst, u) -> replayed count / -1
;   (1) reads utxo_manifest.dat if present -> manifest_buf/manifest_n/
;       next_gen; (2) utxo_store_reload rebuilds the memtable from the WAL
;       (no checkpoint file is ever written in this design, so it always
;       replays the whole WAL from offset 0 -- exactly this generation's
;       unflushed history); (3) a second read-only pass over the same WAL
;       reconstructs the tombstone list and op_count (lost across a crash
;       since they only ever lived in memory) by re-deriving them from the
;       WAL's own DEL records.
; ============================================================================
; utxo_lsm_reload_ro(lst=rdi, u=rsi) -- identical to utxo_lsm_reload except
; that the WAL is opened READ-ONLY (utxo_store_init_ro) and utxo.idx is never
; created. Everything else in the reload chain -- the manifest read, the run
; opens, utxo_store_reload's replay, the WAL tombstone rescan, mac_lsm_recount
; -- is already read-only, so this one substitution is the entire difference.
; It exists so a set-hash/`gettxoutsetinfo` tool can inspect a datadir it is
; forbidden to modify (the live replay's `data/`) and still be certain it has
; changed nothing. A store opened this way is NOT usable for puts or dels:
; idx_fd is -1 and log_fd is not writable, so any mutation fails loudly rather
; than silently corrupting a datadir someone else owns.
global utxo_lsm_reload_ro
utxo_lsm_reload_ro:
    mov  edx, 1
    jmp  mac_lsm_reload_impl

global utxo_lsm_reload
utxo_lsm_reload:
    xor  edx, edx
mac_lsm_reload_impl:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x200
    ; Stash both args in CALLEE-saved regs before the C call below: rdi/rsi
    ; are caller-saved, and [rbp-0x08] is the saved rbx (the five pushes
    ; above occupy rbp-0x08..rbp-0x28), so neither survives a call.
    mov  r12, rdi           ; lst
    mov  r13, rsi            ; u
    mov  [rbp-0x128], rdx    ; read-only flag (see utxo_lsm_reload_ro above).
                              ; Stashed FIRST: lsm_mm_invalidate_all below is a
                              ; call, and rdx is caller-saved.
    ; live-count restore locals (see the persist/restore design at
    ; MAGIC_MANIFEST2): [rbp-0x108] has_count (1 if the manifest carried a
    ; persisted total_live), [rbp-0x110] the persisted runs-only base,
    ; [rbp-0x118]/[rbp-0x120] the WAL tail's PUSH/DEL counts (net applied on
    ; top of the base). Default has_count=0 so any manifest-absent/-bad/old
    ; path takes the recount branch below.
    mov  qword [rbp-0x108], 0
    mov  qword [rbp-0x110], 0
    mov  qword [rbp-0x118], 0
    mov  qword [rbp-0x120], 0
    ; SysV alignment bracket -- see the identical note in utxo_lsm_init above.
    ; This function's 6 pushes + `sub rsp,0x200` leave RSP at 8 mod16 at every
    ; call; correct it for the one call that leaves assembly, so no asm callee's
    ; entry parity changes.
    sub  rsp, 8
    call lsm_mm_invalidate_all   ; PERF_SCOPE 4.1: reload re-derives
                                  ; next_run_no/next_gen from the manifest,
                                  ; so cached mappings may no longer match
    add  rsp, 8
    mov  rdi, r12

    ; open (or reopen) the WAL fds -- utxo_store_reload below assumes
    ; st->log_fd/idx_fd are already valid open fds (it never opens them
    ; itself, mirroring bitcoin_utxo_store.asm's own store_init-then-
    ; store_reload calling convention). Safe to call unconditionally: it
    ; reopens the existing utxo.dat/utxo.idx (O_CREAT|O_RDWR, no truncate).
    mov  rdi, r12
    cmp  qword [rbp-0x128], 0
    jne  .rl_init_ro
    call utxo_store_init
    jmp  .rl_init_done
.rl_init_ro:
    call utxo_store_init_ro
.rl_init_done:
    cmp  rax, 1
    jne  .rl_fail

    lea  rdi, [rel manifest_name]
    xor  esi, esi
    mov  eax, 2
    syscall
    test rax, rax
    jl   .rl_no_manifest
    mov  r14, rax
    lea  rsi, [rbp-0x80]
    mov  rdi, r14
    mov  rdx, 12
    call mac_read_exact2
    test rax, rax
    jnz  .rl_manifest_bad
    mov  eax, [rbp-0x80]
    cmp  eax, MAGIC_MANIFEST2
    je   .rl_manifest_v2
    cmp  eax, MAGIC_MANIFEST
    jne  .rl_manifest_bad
    jmp  .rl_manifest_haveN         ; old format: has_count stays 0 -> recount
.rl_manifest_v2:
    ; new format: read the trailing total_live qword that follows the
    ; 12-byte magic+manifest_n prefix, BEFORE the entry array.
    mov  rdi, r14
    lea  rsi, [rbp-0x110]
    mov  rdx, 8
    call mac_read_exact2
    test rax, rax
    jnz  .rl_manifest_bad
    mov  qword [rbp-0x108], 1        ; has_count = 1
.rl_manifest_haveN:
    mov  rax, [rbp-0x80+4]
    cmp  rax, [r12+112]
    ja   .rl_manifest_bad
    mov  [r12+120], rax
    test rax, rax
    jz   .rl_manifest_close
    mov  rdi, r14
    mov  rsi, [r12+104]
    mov  rdx, rax
    shl  rdx, 4                 ; *16 (entry size: gen8+run_no8)
    call mac_read_exact2
    test rax, rax
    jnz  .rl_manifest_bad
.rl_manifest_close:
    mov  rdi, r14
    mov  eax, 3
    syscall
    ; next_gen/next_run_no = 1 + the max gen/run_no seen across all
    ; entries -- can no longer assume manifest_n itself (compaction can
    ; shrink the manifest while gens/run_nos keep climbing globally).
    mov  qword [r12+96], 0        ; max_gen so far (next_gen slot doubles as accumulator)
    mov  qword [r12+144], 0       ; max_run_no so far
    mov  qword [rbp-0x90], 0      ; scan cursor
.rl_mscan:
    mov  rax, [rbp-0x90]
    cmp  rax, [r12+120]
    jae  .rl_mscan_done
    mov  rcx, rax
    shl  rcx, 4
    mov  rdx, [r12+104]
    add  rdx, rcx
    mov  rax, [rdx]              ; this entry's gen
    cmp  rax, [r12+96]
    jbe  .rl_mscan_g
    mov  [r12+96], rax
.rl_mscan_g:
    mov  rax, [rdx+8]            ; this entry's run_no
    cmp  rax, [r12+144]
    jbe  .rl_mscan_r
    mov  [r12+144], rax
.rl_mscan_r:
    inc  qword [rbp-0x90]
    jmp  .rl_mscan
.rl_mscan_done:
    cmp  qword [r12+120], 0
    je   .rl_manifest_done         ; empty manifest -> next_gen/next_run_no stay 0
    inc  qword [r12+96]
    inc  qword [r12+144]
    jmp  .rl_manifest_done
.rl_manifest_bad:
    mov  rdi, r14
    mov  eax, 3
    syscall
    mov  qword [r12+120], 0
    mov  qword [r12+96], 0
    mov  qword [r12+144], 0
    jmp  .rl_manifest_done
.rl_no_manifest:
    mov  qword [r12+120], 0
    mov  qword [r12+96], 0
    mov  qword [r12+144], 0
.rl_manifest_done:

    mov  rdi, r12
    mov  rsi, r13
    call utxo_store_reload
    cmp  rax, -1
    je   .rl_fail
    mov  r15, rax

    mov  qword [r12+80], 0
    mov  qword [r12+40], 0
    mov  rdi, r12
    call mac_tomb_hash_reset
    cmp  rax, 1
    jne  .rl_fail
    lea  rdi, [rel wal_name]
    xor  esi, esi
    mov  eax, 2
    syscall
    test rax, rax
    jl   .rl_fail
    mov  rbx, rax
    mov  qword [rbp-0x90], 0
.rl_wal_loop:
    mov  rax, [rbp-0x90]
    cmp  rax, [r12+16]
    jae  .rl_wal_close
    mov  rdi, rbx
    lea  rsi, [rbp-0x100]
    mov  rdx, 8
    call mac_read_exact2
    test rax, rax
    jnz  .rl_wal_close
    add  qword [rbp-0x90], 8
    inc  qword [r12+40]
    mov  al, [rbp-0x100+4]
    cmp  al, 1
    je   .rl_wal_push
    cmp  al, 2
    je   .rl_wal_del
    jmp  .rl_wal_close
.rl_wal_push:
    inc  qword [rbp-0x118]           ; WAL tail PUSH count (live-count delta)
    ; This is a SEPARATE rescan of the WAL from utxo_store_reload's own
    ; replay above (which already rebuilt the memtable) -- it exists only
    ; to rebuild the LSM layer's own per-generation tombstone list/op_count
    ; from DEL records, so a PUSH record is just skipped over here, never
    ; applied. Body size grew from 46 to 51 with height/is_coinbase
    ; (2026-08-19, Stage D; matches bitcoin_utxo_store.asm's own CKPT_REC,
    ; the same fixed shape, just not a shared symbol across files) -- a
    ; THIRD independent copy of this
    ; same "WAL PUSH body size" fact (alongside utxo_store_put's write and
    ; utxo_store_reload's own replay, both already fixed) that was missed
    ; on the first pass and stayed at 46/its old slen offset, corrupting
    ; every WAL-tail rescan's byte position from the first PUSH record
    ; onward -- caught by test_utxo_lsm.c's crash-recovery and stress
    ; tests (a DEL right after an unflushed PUSH lost its tombstone).
    mov  rdi, rbx
    lea  rsi, [rbp-0x100]
    mov  rdx, 51            ; txid(32)+index(4)+value(8)+height(4)+is_coinbase(1)+slen(2)
    call mac_read_exact2
    test rax, rax
    jnz  .rl_wal_close
    add  qword [rbp-0x90], 51
    movzx eax, word [rbp-0x100+49]    ; slen (txid32+index4+value8+height4+is_coinbase1=49)
    add  qword [rbp-0x90], rax
    test eax, eax
    jz   .rl_wal_loop
    mov  rdi, rbx
    mov  rsi, rax
    mov  edx, 1                         ; SEEK_CUR
    mov  eax, 8
    syscall
    test rax, rax
    jl   .rl_wal_close
    jmp  .rl_wal_loop
.rl_wal_del:
    inc  qword [rbp-0x120]           ; WAL tail DEL count (live-count delta)
    mov  rdi, rbx
    lea  rsi, [rbp-0x100]
    mov  rdx, 36
    call mac_read_exact2
    test rax, rax
    jnz  .rl_wal_close
    add  qword [rbp-0x90], 36
    mov  rax, [r12+80]
    cmp  rax, [r12+72]
    jae  .rl_wal_close
    mov  rdi, [r12+64]
    mov  rcx, rax
    imul rcx, rcx, 36
    add  rdi, rcx
    lea  rsi, [rbp-0x100]
    push rdi
    mov  rdx, 36
    call mac_memcpy
    pop  rdi
    mov  rsi, rdi                 ; key = &tomb_buf[old_index] (just-written)
    mov  rdi, r12                  ; lst
    call mac_tomb_hash_probe
    mov  rdx, [r12+80]              ; old_index (tomb_n, still pre-increment)
    mov  [rax], rdx
    inc  qword [r12+80]
    jmp  .rl_wal_loop
.rl_wal_close:
    mov  rdi, rbx
    mov  eax, 3
    syscall

    ; ---- restore an ACCURATE total_live (was: total_live = u->n, which
    ; counted ONLY the current unflushed generation and ignored every
    ; flushed/compacted run -- tens of millions too low, and every del of an
    ; older-run key then drove it negative). ----
    cmp  qword [rbp-0x108], 0
    je   .rl_recount
    ; new-format manifest with an EMPTY WAL tail (the clean-shutdown case):
    ; the persisted RUNS-ONLY base is exact as-is.
    ;
    ; INCIDENT #45 (2026-08-25): the old arithmetic here -- base + tail
    ; PUSHes - tail DELs -- assumed "the base was persisted with the WAL
    ; empty, so the tail is exactly the ops not yet folded". A kill landing
    ; BETWEEN the flush's manifest write and its WAL truncate breaks that
    ; assumption undetectably: the manifest's base already CONTAINS the
    ; tail's ops, and base+tail then double-counts the tail's net. That is
    ; exactly how the ghost-heal rebuild's counter drifted +7,890,418 while
    ; the walk (and the set itself -- muhash-proven) stayed correct
    ; (tests/test_lsm_count_drift.c reproduces the window byte-for-byte).
    ; The v2 manifest cannot distinguish a folded tail from an unfolded one,
    ; so a NON-EMPTY tail now always takes the exact recount below --
    ; O(total run records), paid only on unclean-shutdown boots (a clean
    ; close flushes, leaving the tail empty and this fast path intact).
    mov  rax, [rbp-0x118]            ; WAL tail PUSHes
    or   rax, [rbp-0x120]            ; | WAL tail DELs
    jnz  .rl_recount                  ; any tail at all -> exact recount
    mov  rax, [rbp-0x110]            ; persisted base (runs-only, tail empty)
    mov  [r12+88], rax
    mov  rax, r15
    jmp  .rl_ret
.rl_recount:
    ; old-format / absent / bad manifest: no persisted count. Establish the
    ; baseline with a one-time full dedup recount over all runs + the
    ; (already WAL-replayed) memtable + this generation's rebuilt tombstones.
    ; Its result is the exact current live count and ALREADY reflects the WAL
    ; tail (the memtable is that tail replayed), so no delta is added.
    mov  rdi, r12
    mov  rsi, r13
    xor  edx, edx                 ; cb = NULL -- count only, unchanged behaviour
    xor  ecx, ecx                  ; ctx
    call mac_lsm_recount
    cmp  rax, -1
    je   .rl_fail
    mov  [r12+88], rax
    mov  rax, r15
    jmp  .rl_ret
.rl_fail:
    mov  rax, -1
.rl_ret:
    add  rsp, 0x200
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; mac_compact_read_rec(slot=rdi) -> eax: 1 ok / -1 err
;   Reads ONE record from slot.fd at the slot's current file position into
;   the slot's record fields, sets slot.active=1, decrements slot.remaining.
;   CALLER must have already verified slot.remaining > 0 before calling (a
;   slot whose header-reported record count is exhausted is never read
;   again -- this function trusts that count rather than inferring EOF from
;   a short read, so a genuinely truncated/corrupt run file surfaces as a
;   mac_read_exact2 failure here, -1, same as any other I/O error).
;   Slot layout (grown 2026-08-19, Stage D): +0 fd +8 gen +16 run_no
;   +24 remaining +32 active +40 key(36) +76 type +80 value(8) +88 slen(2)
;   +90 height(4) +94 is_coinbase(1) +96 rec_v2(8, CALLER sets once when
;   opening/priming this run, from mac_read_run_header's out+56 -- see
;   MAGIC_RUN3's header comment; this function only READS it) +104 script
;   (up to SCRIPT_MAX_BYTES). value/slen/height/is_coinbase are laid out in
;   the SAME order the run-file's on-disk PUSH record uses (see mac_flush's
;   descriptor-build comment), so both the new-shape and old-shape reads
;   below land directly in their final slot position with no extra copy --
;   and so the merge-write in utxo_lsm_compact can still emit them as one
;   contiguous range, matching the file format exactly.
; ============================================================================
; ----------------------------------------------------------------------------
; mac_slot_read(slot=rdi, dst=rsi, len=rdx) -> rax 0 ok / -1
;   Exactly mac_read_exact2's contract (a short or zero read is an error),
;   served from the slot's inline read-ahead buffer, refilled 256 KB at a
;   time from the slot's fd. Only ever advances the fd sequentially, which is
;   the only way the record stream is read; the run header and the bloom skip
;   happen BEFORE the first record and go straight to the fd, so the buffer
;   is empty when they run. Reading ahead past the last record (into the
;   sparse-index trailer) is harmless: nothing reads an input fd after the
;   merge. Clobbers rax, rcx, rdx, rsi, r8-r11; preserves rdi and the
;   callee-saved set.
; ----------------------------------------------------------------------------
mac_slot_read:
    push rdi
.sr_loop:
    test rdx, rdx
    jz   .sr_ok
    mov  r8, [rdi+SLOT_RD_FILL]
    mov  r9, [rdi+SLOT_RD_POS]
    sub  r8, r9                          ; avail
    jnz  .sr_have
    ; refill
    push rsi
    push rdx
    mov  r10, rdi
    mov  rdi, [r10]                      ; fd
    lea  rsi, [r10+SLOT_RD_BUF]
    mov  rdx, COMPACT_RDBUF
    xor  eax, eax                        ; read
    syscall
    mov  rdi, r10
    pop  rdx
    pop  rsi
    test rax, rax
    jle  .sr_bad
    mov  [rdi+SLOT_RD_FILL], rax
    mov  qword [rdi+SLOT_RD_POS], 0
    jmp  .sr_loop
.sr_have:
    mov  rcx, r8
    cmp  rcx, rdx
    jbe  .sr_n
    mov  rcx, rdx
.sr_n:
    add  [rdi+SLOT_RD_POS], rcx
    sub  rdx, rcx
    lea  r10, [rdi+SLOT_RD_BUF]
    add  r10, r9                         ; src = buf + pos
    mov  r11, rdi                        ; keep slot
    mov  rdi, rsi                        ; dst
    mov  rsi, r10                        ; src
    rep  movsb                           ; rdi = dst+n, rsi = src+n
    mov  rsi, rdi                        ; next dst
    mov  rdi, r11                        ; slot
    jmp  .sr_loop
.sr_ok:
    xor  eax, eax
    pop  rdi
    ret
.sr_bad:
    mov  rax, -1
    pop  rdi
    ret

; ----------------------------------------------------------------------------
; Buffered writer for the compaction's OUTPUT run (2026-08-31). The merge
; loop used to issue three write(2) calls per record; they now land in a 1 MB
; buffer that is written with one syscall when full. Everything AFTER the
; merge loop -- the header patches at fixed offsets and the sparse-index
; append -- goes straight through mac_write_exact as before, and the loop's
; exit flushes this buffer FIRST, so those writes see a complete file.
;
; One writer at a time: compaction runs in the download worker, and no other
; code path in that process opens a run for writing while it runs. The state
; is process-global on purpose; a per-connection child never compacts.
;   mac_out_begin(fd=rdi)                       arm for this output fd
;   mac_out_write(rsi=src, rdx=len) -> 0/-1     rdi ignored (call-compatible
;                                               with mac_write_exact's args)
;   mac_out_flush() -> 0/-1                     write out whatever is held
; ----------------------------------------------------------------------------
MAC_OWBUF equ 1048576
section .bss
mac_ow_fd:   resq 1
mac_ow_fill: resq 1
mac_ow_buf:  resb MAC_OWBUF
; ---- mac_flush's buffered record writer (2026-09-01) --------------------
; mac_flush wrote every record with three tiny write()s (37-byte key +
; offset, 15-byte value/height/slen, script): ~90M syscalls per 30M-record
; flush, a 100 s stall in the replay. Records now accumulate here and go
; out 1 MB at a time; the buffer is drained before anything positional
; (the SEEK_CUR that locates the sparse index, the header patch, fsync).
MAC_FLBUF equ 1048576
mac_fl_fill: resq 1
mac_fl_buf:  resb MAC_FLBUF
; ---- background compaction support (2026-08-31) --------------------------
; mac_compact_defer_unlink: when non-zero, utxo_lsm_compact publishes the new
;   manifest as usual but leaves its INPUT run files on disk. A forked child
;   compacting on the parent's behalf sets this: the parent still holds the
;   old manifest in memory and may open those runs by name until it adopts
;   the new one, and unlinking under it would turn a lookup into a false
;   miss. The parent unlinks them itself after adopting. Orphaned runs are
;   already tolerated by design (a crash between publish and unlink).
; mac_flush_hook: called by mac_flush BEFORE it touches anything. mac_flush is
;   the only other manifest writer, and it is triggered from inside
;   utxo_lsm_put, where C cannot intercept it; the parent's hook waits for a
;   running compaction child so two writers never race on the manifest.
; mac_compact_defer_publish: when non-zero, utxo_lsm_compact writes the new
;   manifest bytes to utxo_manifest.child instead of publishing them -- no
;   rename over utxo_manifest.dat, no dir fsync. The forked child sets this
;   too: the parent keeps flushing (and publishing) while the child merges,
;   then merges the child's manifest with the runs it flushed meanwhile and
;   publishes the union itself (daemon/lsm_manifest.c, adopt_child). The
;   child's in-memory lsm_state is discarded with the child.
mac_compact_defer_unlink:  resq 1
mac_compact_defer_publish: resq 1
mac_flush_hook:            resq 1
; utxo_lsm_compact_range's arguments, parked here so the range entry can share
; utxo_lsm_compact's body: lo = first manifest index of the batch, k = run
; count (0 = the classic "oldest min(n,64)" batch). See .cc_bs_default.
mac_cr_lo:                 resq 1
mac_cr_k:                  resq 1
section .text

global utxo_lsm_set_defer_unlink
utxo_lsm_set_defer_unlink:
    mov  [rel mac_compact_defer_unlink], rdi
    ret
global utxo_lsm_set_defer_publish
utxo_lsm_set_defer_publish:
    mov  [rel mac_compact_defer_publish], rdi
    ret
global utxo_lsm_set_flush_hook
utxo_lsm_set_flush_hook:
    mov  [rel mac_flush_hook], rdi
    ret


mac_out_begin:
    mov  [rel mac_ow_fd], rdi
    mov  qword [rel mac_ow_fill], 0
    ret

mac_out_flush:
    mov  rdx, [rel mac_ow_fill]
    test rdx, rdx
    jz   .of_ok
    mov  rdi, [rel mac_ow_fd]
    lea  rsi, [rel mac_ow_buf]
    mov  qword [rel mac_ow_fill], 0
    jmp  mac_write_exact                 ; tail call: its rax is our rax
.of_ok:
    xor  eax, eax
    ret

; mac_out_tell() -> rax = logical write position (fd offset + buffered bytes), or -1
mac_out_tell:
    mov  rdi, [rel mac_ow_fd]
    xor  esi, esi
    mov  edx, 1                          ; SEEK_CUR
    mov  eax, 8                          ; lseek
    syscall
    test rax, rax
    js   .ot_ret
    add  rax, [rel mac_ow_fill]
.ot_ret:
    ret

mac_out_write:
    mov  r8, [rel mac_ow_fill]
    lea  r9, [r8+rdx]
    cmp  r9, MAC_OWBUF
    ja   .ow_spill
.ow_copy:
    lea  rdi, [rel mac_ow_buf]
    add  rdi, r8
    mov  rcx, rdx
    rep  movsb
    mov  [rel mac_ow_fill], r9
    xor  eax, eax
    ret
.ow_spill:
    push rsi
    push rdx
    call mac_out_flush
    pop  rdx
    pop  rsi
    test rax, rax
    jnz  .ow_bad
    cmp  rdx, MAC_OWBUF
    jae  .ow_direct                      ; larger than the buffer: write through
    xor  r8d, r8d                        ; buffer is empty now
    mov  r9, rdx
    jmp  .ow_copy
.ow_direct:
    mov  rdi, [rel mac_ow_fd]
    jmp  mac_write_exact
.ow_bad:
    ret

mac_compact_read_rec:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x10
    mov  r12, rdi                  ; slot base
    mov  rbx, [r12]                 ; fd
    mov  rdi, r12                    ; slot: buffered read (see mac_slot_read)
    lea  rsi, [r12+40]
    mov  rdx, 37                     ; key(36)+type(1)
    call mac_slot_read
    test rax, rax
    jnz  .cr_err
    movzx eax, byte [r12+76]           ; type
    cmp  eax, 1
    jne  .cr_dec
    mov  rax, [r12+96]                    ; rec_v2 (set by the caller at open time)
    test rax, rax
    jz   .cr_read_old

    ; ---- new shape: value(8)+slen(2)+height(4)+is_coinbase(1) = 15 ----
    mov  rdi, r12
    lea  rsi, [r12+80]
    mov  rdx, 15
    call mac_slot_read
    test rax, rax
    jnz  .cr_err
    movzx eax, word [r12+88]              ; slen
    jmp  .cr_have_slen

.cr_read_old:
    ; ---- old shape: value(8)+slen(2) = 10; height/is_coinbase unavailable,
    ; explicitly zeroed (they land at the SAME slot offsets the new shape
    ; uses, just never populated by this read). ----
    mov  rdi, r12
    lea  rsi, [r12+80]
    mov  rdx, 10
    call mac_slot_read
    test rax, rax
    jnz  .cr_err
    movzx eax, word [r12+88]              ; slen
    mov  dword [r12+90], 0                  ; height = 0
    mov  byte [r12+94], 0                    ; is_coinbase = 0
.cr_have_slen:
    test eax, eax
    jz   .cr_dec
    mov  rdi, r12
    lea  rsi, [r12+104]
    mov  rdx, rax
    call mac_slot_read
    test rax, rax
    jnz  .cr_err
.cr_dec:
    mov  qword [r12+32], 1              ; active = 1
    dec  qword [r12+24]                  ; remaining--
    mov  eax, 1
    jmp  .cr_ret
.cr_err:
    mov  rax, -1
.cr_ret:
    add  rsp, 0x10
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; mac_lsm_recount(lst=rdi, u=rsi, cb=rdx, ctx=rcx) -> rax = exact live UTXO
;                                                     count / -1 err
;   ONE-TIME baseline recount used by utxo_lsm_reload when the manifest is
;   OLD-format (or absent/corrupt) and so carries no persisted total_live.
;   Read-only: opens every run, k-way merges them (newest generation wins on
;   a key tie -- exactly like utxo_lsm_compact's merge) and counts a key live
;   iff its newest RUN record is a PUSH (type==1) AND the key is not shadowed
;   by the newer memtable generation -- i.e. it is not currently live in the
;   memtable (utxo_get miss; if it IS live there it is already counted in
;   u->n) and not tombstoned this generation (tomb_hash miss). The memtable's
;   own live entries are added up front as u->n. Runs, memtable and
;   tombstones here are the fully-reloaded state (utxo_store_reload + the WAL
;   tombstone rescan both ran before this), so the result already reflects
;   the WAL tail -- reload adds no separate delta on this branch. Bounded
;   O(total run records) one-time cost, never on the hot per-op path.
;   Reuses the compaction per-run SLOT layout (COMPACT_SLOT_SIZE) and its
;   record reader / header reader / key comparator.
;
;   OPTIONAL VISITOR (added 2026-08-23 for the UTXO set hash). `cb` may be
;   NULL, in which case this behaves exactly as it always has and the count is
;   the only output. When non-NULL it is invoked ONCE PER LIVE RUN-RESIDENT
;   ENTRY, at precisely the point the counter increments -- so the visited set
;   and the counted set cannot drift apart:
;
;       void cb(void* ctx, const u8 key36[36], u64 value,
;               u64 code, const u8* script, u64 slen)
;
;   with `code` = (height << 1) | is_coinbase, which is the exact uint32 Core
;   serializes for a coin (kernel/coinstats.cpp TxOutSer). Packing the two
;   fields into one argument is what keeps the callback inside six registers,
;   so no stack argument is needed here or in any implementation of it.
;
;   This does NOT visit the memtable's own live entries: those are added to
;   the count up front as u->n and never enter the merge (that is the whole
;   shadowing rule below). A caller that needs every live entry must walk the
;   memtable too -- utxo_lsm_walk does exactly that, and is the only intended
;   caller of this function with a non-NULL cb.
;
;   The callback is invoked through a `sub rsp,8` / `add rsp,8` bracket
;   because this function's own prologue leaves RSP at 8 mod 16 and the
;   callee may be C (ENGINEERING_RULES.md 6: bracket the one call that leaves
;   assembly rather than resizing the frame, which would change the entry
;   parity every asm callee below already relies on).
;
;   Frame locals (all below the push-save area): -0x30 live  -0x38 mmap_size
;   -0x40 loop-i  -0x48 best_idx / slot-base stash  -0x50 winner_slot
;   -0xA0..-0x60 run-header out(64)  -0xC0 fmtbuf(20)  -0xF0 winning-key
;   snapshot(36)  -0x100 &value -0x108 &height -0x110 &is_coinbase
;   -0x118 &script -0x120 &slen (utxo_get out-args, values discarded)
;   -0x128 cb  -0x130 ctx.
; ============================================================================
mac_lsm_recount:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x140
    mov  r12, rdi                  ; lst
    mov  r13, rsi                  ; u
    mov  [rbp-0x128], rdx          ; cb (may be 0)
    mov  [rbp-0x130], rcx          ; ctx
    mov  rax, [r13]                ; u->n = memtable live entries
    mov  [rbp-0x30], rax           ; live = u->n
    mov  r14, [r12+120]            ; manifest_n (run count)
    mov  qword [rbp-0x38], 0       ; mmap_size (0 => nothing mapped yet)
    xor  r15d, r15d                ; slots base = 0 until mmap'd
    test r14, r14
    jz   .rc_ret_live              ; no runs -> live is just u->n

    ; ---- mmap n slots (n * COMPACT_SLOT_SIZE), one read-ahead record each --
    mov  rax, r14
    imul rax, rax, COMPACT_SLOT_SIZE
    mov  [rbp-0x38], rax
    xor  edi, edi
    mov  rsi, rax
    mov  edx, 3                    ; PROT_READ|PROT_WRITE
    mov  r10d, 0x22                ; MAP_PRIVATE|MAP_ANONYMOUS
    mov  r8, -1
    xor  r9d, r9d
    mov  eax, 9
    syscall
    cmp  rax, -1
    je   .rc_err_nomap
    mov  r15, rax                  ; slots base

    ; ---- init every slot fd=-1 / active=0 so cleanup is uniform ----
    mov  qword [rbp-0x40], 0
.rc_init_loop:
    mov  rax, [rbp-0x40]
    cmp  rax, r14
    jae  .rc_init_done
    imul rax, rax, COMPACT_SLOT_SIZE
    add  rax, r15
    mov  qword [rax], -1           ; slot.fd = -1
    mov  qword [rax+32], 0         ; slot.active = 0
    inc  qword [rbp-0x40]
    jmp  .rc_init_loop
.rc_init_done:

    ; ---- open + prime each run (mirrors utxo_lsm_compact's open loop) ----
    mov  qword [rbp-0x40], 0
.rc_open_loop:
    mov  rax, [rbp-0x40]
    cmp  rax, r14
    jae  .rc_open_done
    mov  rcx, rax
    shl  rcx, 4
    mov  rdx, [r12+104]            ; manifest_buf
    add  rdx, rcx
    mov  rcx, [rdx]               ; gen
    mov  rdx, [rdx+8]             ; run_no
    mov  rax, [rbp-0x40]
    imul rax, rax, COMPACT_SLOT_SIZE
    add  rax, r15                  ; slot base
    mov  [rax+8], rcx             ; slot.gen
    mov  [rax+16], rdx            ; slot.run_no
    mov  [rbp-0x48], rax           ; stash slot base (fmt_runname clobbers regs)
    lea  rdi, [rbp-0xC0]
    mov  esi, edx                  ; run_no (low 32)
    call fmt_runname
    lea  rdi, [rbp-0xC0]
    xor  esi, esi                  ; O_RDONLY
    mov  eax, 2
    syscall
    test rax, rax
    js   .rc_err_cleanup
    mov  rdx, [rbp-0x48]           ; slot base
    mov  [rdx], rax               ; slot.fd
    mov  rdi, rax
    lea  rsi, [rbp-0xA0]
    call mac_read_run_header
    test rax, rax
    jnz  .rc_err_cleanup
    mov  rdx, [rbp-0x48]
    mov  rax, [rbp-0xA0+8]         ; nrec
    mov  [rdx+24], rax            ; slot.remaining
    mov  rax, [rbp-0xA0+56]        ; rec_v2
    mov  [rdx+96], rax           ; slot.rec_v2
    mov  rdi, [rdx]               ; fd
    mov  rsi, [rbp-0xA0+16]        ; bloom_bytes -> skip to records
    mov  edx, 1                    ; SEEK_CUR
    mov  eax, 8
    syscall
    test rax, rax
    js   .rc_err_cleanup
    mov  rdx, [rbp-0x48]
    cmp  qword [rdx+24], 0         ; remaining == 0 (empty run)?
    je   .rc_open_next
    mov  rdi, rdx
    call mac_compact_read_rec
    cmp  eax, -1
    je   .rc_err_cleanup
.rc_open_next:
    inc  qword [rbp-0x40]
    jmp  .rc_open_loop
.rc_open_done:

    ; ================= streaming k-way merge, count only =================
.rc_merge:
    mov  qword [rbp-0x48], -1      ; best_idx
    mov  qword [rbp-0x40], 0       ; i
.rc_find:
    mov  rax, [rbp-0x40]
    cmp  rax, r14
    jae  .rc_find_done
    mov  rdx, rax
    imul rdx, rdx, COMPACT_SLOT_SIZE
    add  rdx, r15                  ; this slot
    cmp  qword [rdx+32], 0         ; active?
    je   .rc_find_next
    cmp  qword [rbp-0x48], -1
    je   .rc_find_setbest
    mov  rcx, [rbp-0x48]
    imul rcx, rcx, COMPACT_SLOT_SIZE
    add  rcx, r15                  ; best slot
    lea  rdi, [rdx+40]
    lea  rsi, [rcx+40]
    push rdx
    call mac_cmp_key               ; 0 this<best / 1 eq / 2 this>best
    pop  rdx
    cmp  eax, 0
    je   .rc_find_setbest
    cmp  eax, 1
    jne  .rc_find_next
    ; equal keys: this wins the tie only on a strictly higher generation
    mov  rax, [rdx+8]             ; this.gen
    mov  rcx, [rbp-0x48]
    imul rcx, rcx, COMPACT_SLOT_SIZE
    add  rcx, r15
    mov  rcx, [rcx+8]            ; best.gen
    cmp  rax, rcx
    jbe  .rc_find_next
.rc_find_setbest:
    mov  rax, [rbp-0x40]
    mov  [rbp-0x48], rax
.rc_find_next:
    inc  qword [rbp-0x40]
    jmp  .rc_find
.rc_find_done:
    cmp  qword [rbp-0x48], -1
    je   .rc_merge_done           ; no active slots -> done

    mov  rax, [rbp-0x48]
    imul rax, rax, COMPACT_SLOT_SIZE
    add  rax, r15
    mov  [rbp-0x50], rax           ; winner slot
    lea  rdi, [rbp-0xF0]           ; stable snapshot of the winning key
    lea  rsi, [rax+40]
    mov  rdx, 36
    call mac_memcpy

    mov  rax, [rbp-0x50]
    movzx ecx, byte [rax+76]       ; winner type
    cmp  ecx, 1
    jne  .rc_advance              ; DEL/tombstone winner -> key is dead

    ; PUSH winner: is this key shadowed by the newer memtable generation?
    lea  rax, [rbp-0xF0]          ; key: txid(32)+index(4)
    mov  rdi, r13                 ; u
    mov  rsi, rax                 ; txid
    mov  edx, [rax+32]           ; index
    lea  rcx, [rbp-0x100]         ; &value
    lea  r8,  [rbp-0x108]         ; &height
    lea  r9,  [rbp-0x110]         ; &is_coinbase
    sub  rsp, 0x10
    lea  rax, [rbp-0x118]
    mov  [rsp], rax              ; &script
    lea  rax, [rbp-0x120]
    mov  [rsp+8], rax            ; &slen
    call utxo_get
    add  rsp, 0x10
    cmp  rax, 1
    je   .rc_advance             ; live in memtable -> already in u->n

    mov  rdi, r12                 ; lst
    lea  rsi, [rbp-0xF0]          ; key
    call mac_tomb_hash_probe
    mov  rax, [rax]              ; tomb slot value (-1 == not present)
    cmp  rax, -1
    jne  .rc_advance             ; tombstoned this generation -> dead

    inc  qword [rbp-0x30]         ; live++

    ; ---- optional visitor, at exactly the point the counter moves ----
    cmp  qword [rbp-0x128], 0
    je   .rc_advance
    mov  rax, [rbp-0x50]           ; winner slot
    mov  rdi, [rbp-0x130]          ; ctx
    lea  rsi, [rbp-0xF0]           ; key36 snapshot (stable across the call)
    mov  rdx, [rax+80]             ; value
    mov  ecx, [rax+90]             ; height
    shl  rcx, 1
    movzx r10d, byte [rax+94]      ; is_coinbase
    or   rcx, r10                   ; code = (height<<1) | is_coinbase
    lea  r8, [rax+104]              ; script
    movzx r9d, word [rax+88]         ; slen
    ; RSP is 8 mod 16 here (see the header comment); correct it for this one
    ; call, which may leave assembly.
    sub  rsp, 8
    call qword [rbp-0x128]
    add  rsp, 8

.rc_advance:
    ; advance every active slot whose current key equals the winning key
    mov  qword [rbp-0x40], 0
.rc_adv_loop:
    mov  rax, [rbp-0x40]
    cmp  rax, r14
    jae  .rc_adv_done
    mov  rcx, rax
    imul rcx, rcx, COMPACT_SLOT_SIZE
    add  rcx, r15                  ; this slot
    cmp  qword [rcx+32], 0         ; active?
    je   .rc_adv_next
    lea  rdi, [rcx+40]
    lea  rsi, [rbp-0xF0]          ; snapshot key
    push rcx
    call mac_cmp_key
    pop  rcx
    cmp  eax, 1
    jne  .rc_adv_next             ; different key -> leave it
    cmp  qword [rcx+24], 0         ; remaining
    jne  .rc_adv_reread
    mov  qword [rcx+32], 0         ; exhausted -> active=0
    jmp  .rc_adv_next
.rc_adv_reread:
    mov  rdi, rcx
    call mac_compact_read_rec
    cmp  eax, -1
    je   .rc_err_cleanup
.rc_adv_next:
    inc  qword [rbp-0x40]
    jmp  .rc_adv_loop
.rc_adv_done:
    jmp  .rc_merge
.rc_merge_done:

    ; ---- close all run fds, munmap slots ----
    mov  qword [rbp-0x40], 0
.rc_close_loop:
    mov  rax, [rbp-0x40]
    cmp  rax, r14
    jae  .rc_close_done
    imul rax, rax, COMPACT_SLOT_SIZE
    add  rax, r15
    mov  rdi, [rax]
    cmp  rdi, -1
    je   .rc_close_next
    mov  eax, 3
    syscall
.rc_close_next:
    inc  qword [rbp-0x40]
    jmp  .rc_close_loop
.rc_close_done:
    mov  rdi, r15
    mov  rsi, [rbp-0x38]
    mov  eax, 11                   ; munmap
    syscall
.rc_ret_live:
    mov  rax, [rbp-0x30]
    jmp  .rc_ret
.rc_err_cleanup:
    mov  qword [rbp-0x40], 0
.rc_errc_loop:
    mov  rax, [rbp-0x40]
    cmp  rax, r14
    jae  .rc_errc_done
    imul rax, rax, COMPACT_SLOT_SIZE
    add  rax, r15
    mov  rdi, [rax]
    cmp  rdi, -1
    je   .rc_errc_next
    mov  eax, 3
    syscall
.rc_errc_next:
    inc  qword [rbp-0x40]
    jmp  .rc_errc_loop
.rc_errc_done:
    mov  rdi, r15
    mov  rsi, [rbp-0x38]
    mov  eax, 11                   ; munmap
    syscall
.rc_err_nomap:
    mov  rax, -1
.rc_ret:
    add  rsp, 0x140
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_lsm_walk(lst=rdi, u=rsi, cb=rdx, ctx=rcx) -> rax = live entries
;                                                    visited / -1 err
;   The whole live set, exactly once each, through one visitor -- the read
;   side of `gettxoutsetinfo`.
;
;   There is deliberately no second iteration written for this. The k-way
;   merge in mac_lsm_recount already visits precisely the live run-resident
;   set (newest generation wins; a key is live iff its newest run record is a
;   PUSH, it is not currently live in the newer memtable, and it is not
;   tombstoned this generation), and it has been running in production since
;   2026-08-22. This function is that merge with its visitor hooked up, plus
;   utxo_walk_live over the memtable for the entries the merge deliberately
;   skips -- the ones recount folds in as the up-front u->n. Together those
;   two are the live set with no overlap:
;     - a key live in the memtable is emitted by utxo_walk_live, and the merge
;       skips it (its utxo_get probe hits);
;     - a key live only in a run is emitted by the merge, and the memtable
;       does not hold it;
;     - a key deleted this generation is in tomb_hash, so the merge skips it,
;       and utxo_del already removed it from the memtable.
;
;   The return value is mac_lsm_recount's exact live count, which INCLUDES the
;   memtable's u->n. As a self-check the memtable walk's own count is compared
;   against u->n and a disagreement returns -1 rather than a plausible number:
;   the caller of this function is an acceptance test, and an acceptance test
;   that can be quietly wrong is worse than one that refuses.
;
;   Frame (ENGINEERING_RULES.md 6b prologue: callee-saved pushed BEFORE rbp,
;   so the save area is at [rbp+8..] and no local can alias it): entry RSP is
;   8 mod 16, six pushes leave it at 8 mod 16, sub rsp, 0x18 (8 mod 16) brings
;   it to 0 mod 16 at every call. Locals: [rbp-0x08] cb, [rbp-0x10] ctx.
; ============================================================================
global utxo_lsm_walk
utxo_lsm_walk:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x18
    mov  r12, rdi                  ; lst
    mov  r13, rsi                  ; u
    mov  [rbp-0x08], rdx           ; cb
    mov  [rbp-0x10], rcx           ; ctx

    ; ---- runs: the existing merge, with the visitor hooked up -------------
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, [rbp-0x08]
    mov  rcx, [rbp-0x10]
    call mac_lsm_recount
    cmp  rax, -1
    je   .w_err
    mov  rbx, rax                  ; total live (runs + memtable)

    ; ---- memtable: the entries the merge deliberately does not emit -------
    mov  rdi, r13
    mov  rsi, [rbp-0x08]
    mov  rdx, [rbp-0x10]
    call utxo_walk_live
    cmp  rax, [r13]                ; must equal u->n, the count recount used
    jne  .w_err
    mov  rax, rbx
    jmp  .w_ret
.w_err:
    mov  rax, -1
.w_ret:
    add  rsp, 0x18
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; utxo_lsm_compact(lst=rdi) -> 1 ok / 0 nothing-to-do / -1 err
;   Merges the oldest min(manifest_n, COMPACT_MAX_RUNS) runs into one new
;   run via a streaming k-way merge (see header comment + COMPACT_* consts
;   above). Drops every tombstone it sees (always safe: this batch always
;   starts at the globally oldest run). On a same-key tie across inputs,
;   the copy with the HIGHEST generation wins; every input holding that key
;   still advances past its own copy so it isn't reprocessed. Bloom sized
;   from the sum of input nrecs (a safe upper bound, since merging can only
;   drop records via dedup/tombstones, never add any) computed up front so
;   the whole write is one pass; nrec and the bloom bytes are the only
;   things patched via seek-back at the end. Publishes via the same
;   tmp+fsync+rename+dirsync manifest pattern as flush, then unlinks the
;   old run files -- a crash between publish and unlink just orphans those
;   files (harmless, never referenced by the new manifest); a crash before
;   publish leaves the old manifest+old runs fully intact and correct.
; ============================================================================
global utxo_lsm_compact
; utxo_lsm_compact_range(lst, lo, k): merge manifest entries [lo, lo+k) into
; one run that takes index lo. Leveled compaction's entry (daemon/utxo_live.c
; picks lo/k by size ratio): lo == 0 is the classic base merge; lo > 0 must
; end at the newest run, and then tombstones are KEPT in the output -- they
; still cancel puts in the runs below. Returns like utxo_lsm_compact; a bad
; range (k < 2, k > COMPACT_MAX_RUNS, past the end, or in the middle) is a
; no-op returning 0.
global utxo_lsm_compact_range
utxo_lsm_compact_range:
    mov  [rel mac_cr_lo], rsi
    mov  [rel mac_cr_k], rdx
    jmp  utxo_lsm_compact.cc_entry

utxo_lsm_compact:
    mov  qword [rel mac_cr_lo], 0
    mov  qword [rel mac_cr_k], 0
.cc_entry:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x400
    mov  r12, rdi                   ; lst
    mov  rax, [r12+120]              ; manifest_n
    cmp  rax, 2
    jb   .cc_noop                     ; 0 or 1 runs -> nothing to compact
    mov  [rbp-0x210], rax             ; original manifest_n (for the full-merge test)
    mov  qword [rbp-0x240], 0         ; lo: first manifest index of the batch
    mov  qword [rbp-0x248], 0         ; keep_dels: 1 iff older runs exist below the batch
    mov  rcx, [rel mac_cr_k]
    test rcx, rcx
    jz   .cc_bs_default
    ; explicit range: 2 <= k <= COMPACT_MAX_RUNS, inside the manifest, and
    ; anchored at the oldest run (lo == 0) or ending at the newest (lo+k == n).
    ; A merge in the middle would put a fresh-gen run below older survivors
    ; and break the manifest's gen-ascending order that get() relies on.
    cmp  rcx, 2
    jb   .cc_noop
    cmp  rcx, COMPACT_MAX_RUNS
    ja   .cc_noop
    mov  rdx, [rel mac_cr_lo]
    add  rdx, rcx
    cmp  rdx, rax
    ja   .cc_noop
    cmp  qword [rel mac_cr_lo], 0
    je   .cc_bs_range_ok
    cmp  rdx, rax
    jne  .cc_noop
    mov  qword [rbp-0x248], 1         ; runs below the batch: tombstones must survive
.cc_bs_range_ok:
    mov  rdx, [rel mac_cr_lo]
    mov  [rbp-0x240], rdx
    mov  rax, rcx
    jmp  .cc_bs_ok
.cc_bs_default:
    mov  rcx, COMPACT_MAX_RUNS
    cmp  rax, rcx
    jbe  .cc_bs_ok
    mov  rax, rcx
.cc_bs_ok:
    mov  r14, rax                     ; batch_size (stable for the whole function)

    ; ---- mmap our own scratch (NOT lst->scratch_buf) ----
    xor  edi, edi
    mov  esi, COMPACT_SCRATCH_BYTES
    mov  edx, 3                        ; PROT_READ|PROT_WRITE
    mov  r10d, 0x22                     ; MAP_PRIVATE|MAP_ANONYMOUS
    mov  r8, -1
    xor  r9d, r9d
    mov  eax, 9                          ; mmap
    syscall
    cmp  rax, -1
    je   .cc_err_noscratch
    mov  r13, rax                        ; scratch base (stable for the whole function)

    mov  qword [rbp-0x38], 0             ; upper_bound accumulator

    ; ---- open + prime each of the batch_size (oldest) runs ----
    mov  qword [rbp-0x78], 0             ; i
.cc_open_loop:
    mov  rax, [rbp-0x78]
    cmp  rax, r14
    jae  .cc_open_done

    ; manifest entry lo+i -> gen, run_no
    mov  rcx, rax
    add  rcx, [rbp-0x240]
    shl  rcx, 4
    mov  rdx, [r12+104]
    add  rdx, rcx
    mov  rcx, [rdx]              ; gen
    mov  rdx, [rdx+8]             ; run_no
    mov  [rbp-0x90], rcx           ; stash gen
    mov  [rbp-0x98], rdx            ; stash run_no

    ; slot base for i
    mov  rax, [rbp-0x78]
    imul rax, rax, COMPACT_SLOT_SIZE
    add  rax, r13
    mov  rcx, [rbp-0x90]
    mov  [rax+8], rcx              ; slot.gen
    mov  rcx, [rbp-0x98]
    mov  [rax+16], rcx              ; slot.run_no
    mov  qword [rax+32], 0           ; slot.active = 0 (until primed below)

    ; format filename from run_no, open read-only
    lea  rdi, [rbp-0x140]
    mov  esi, [rbp-0x98]
    call fmt_runname
    lea  rdi, [rbp-0x140]
    xor  esi, esi
    mov  eax, 2
    syscall
    test rax, rax
    jl   .cc_err

    mov  rdx, [rbp-0x78]
    imul rdx, rdx, COMPACT_SLOT_SIZE
    add  rdx, r13
    mov  [rdx], rax                 ; slot.fd

    ; format-aware header read (MAGIC_RUN/RUN2/RUN3 -- an input run being
    ; compacted may be ANY of them, since not every run has necessarily
    ; been rewritten by the fixed writer yet; see mac_read_run_header's own
    ; header comment). [rbp-0x1C0] holds its 64-byte output struct here;
    ; its TAIL ([rbp-0x188] onward) gets reused for unrelated staging
    ; (sparse_scratch/sparse_n) just a few instructions below in this same
    ; iteration -- safe only because rec_v2 (the struct's last field) is
    ; extracted immediately after this call, before that reuse happens (see
    ; the comment at that extraction). Further reuse of [rbp-0x1C0] itself
    ; later in this function (the OUTPUT run's own header, then manifest
    ; staging) is fine as before -- those happen in strictly later,
    ; non-overlapping phases, well after every input run has been opened.
    mov  rdi, rax
    lea  rsi, [rbp-0x1C0]
    call mac_read_run_header
    test rax, rax
    jnz  .cc_err

    mov  rax, [rbp-0x1C0+8]          ; this run's nrec
    mov  rdx, [rbp-0x78]
    imul rdx, rdx, COMPACT_SLOT_SIZE
    add  rdx, r13
    mov  [rdx+24], rax                ; slot.remaining = nrec
    add  qword [rbp-0x38], rax          ; upper_bound += nrec
    ; rec_v2 (out+56) MUST be extracted here, before this same scratch
    ; region ([rbp-0x1C0]'s tail, at [rbp-0x188]) gets reused below for
    ; sparse_scratch/sparse_n -- an input run being compacted may be ANY of
    ; MAGIC_RUN/RUN2/RUN3, so each slot needs its OWN rec_v2, not a shared
    ; assumption (see MAGIC_RUN3's header comment).
    mov  rax, [rbp-0x1C0+56]
    mov  [rdx+96], rax                  ; slot.rec_v2

    ; skip this run's own bloom bytes to reach its records section
    mov  rax, [rbp-0x1C0+16]           ; this run's bloom_bytes (already shifted)
    mov  rdx, [rbp-0x78]
    imul rdx, rdx, COMPACT_SLOT_SIZE
    add  rdx, r13
    mov  rdi, [rdx]                       ; fd
    mov  rsi, rax
    mov  edx, 1                             ; SEEK_CUR
    mov  eax, 8
    syscall
    test rax, rax
    jl   .cc_err

    ; prime the first record, unless this run is (degenerately) empty
    mov  rdx, [rbp-0x78]
    imul rdx, rdx, COMPACT_SLOT_SIZE
    add  rdx, r13
    cmp  qword [rdx+24], 0
    je   .cc_open_next
    mov  rdi, rdx
    call mac_compact_read_rec
    cmp  eax, -1
    je   .cc_err

.cc_open_next:
    inc  qword [rbp-0x78]
    jmp  .cc_open_loop
.cc_open_done:

    ; ---- bloom sizing from the upper-bound record count ----
    mov  rax, [rbp-0x38]
    imul rax, rax, 10
    cmp  rax, 64
    jae  .cc_bb1
    mov  rax, 64
.cc_bb1:
    mov  rcx, 1
.cc_bb_loop:
    cmp  rcx, rax
    jae  .cc_bb2
    shl  rcx, 1
    jmp  .cc_bb_loop
.cc_bb2:
    mov  rdx, BLOOM_MAX_BYTES*8
    cmp  rcx, rdx
    jbe  .cc_bb3
    mov  rcx, rdx
.cc_bb3:
    mov  [rbp-0x40], rcx           ; bloom_bits
    mov  rax, rcx
    shr  rax, 3
    mov  [rbp-0x50], rax            ; bloom_bytes
    dec  rcx
    mov  [rbp-0x48], rcx             ; bits_mask

    ; zero the bloom region in OUR scratch
    mov  rdi, r13
    add  rdi, COMPACT_SLOTS_BYTES
    mov  rcx, [rbp-0x50]
.cc_bz:
    test rcx, rcx
    jz   .cc_bz_done
    mov  byte [rdi], 0
    inc  rdi
    dec  rcx
    jmp  .cc_bz
.cc_bz_done:

    ; ---- second, separate mmap for the sparse-index build buffer ----
    ; Sized from upper_bound (the sum of input runs' own nrec, already known
    ; from .cc_open_loop -- a safe over-estimate of the merged run's true
    ; record count, same upper-bound-not-exact-count reasoning the bloom
    ; sizing above already relies on). Kept as ITS OWN mmap, separate from
    ; the fixed-size COMPACT_SCRATCH_BYTES region above, since its size is
    ; only known now, not at compile time.
    mov  rax, [rbp-0x38]              ; upper_bound
    xor  edx, edx
    mov  rcx, SPARSE_STRIDE
    div  rcx
    add  rax, 2                         ; +2 margin
    imul rax, rax, SPARSE_ENT_SIZE
    mov  [rbp-0x178], rax                 ; sparse_scratch_bytes
    xor  edi, edi
    mov  esi, eax
    mov  edx, 3                            ; PROT_READ|PROT_WRITE
    mov  r10d, 0x22                          ; MAP_PRIVATE|MAP_ANONYMOUS
    mov  r8, -1
    xor  r9d, r9d
    mov  eax, 9                                ; mmap
    syscall
    cmp  rax, -1
    je   .cc_err
    ; NOTE: 0x188/0x180/0x178 -- deliberately NOT 0x200/0x208/0x210, which
    ; collide with the pre-existing winning-key snapshot buffer at
    ; [rbp-0x200] (36 bytes, written/read every .cc_merge_loop iteration --
    ; see the "stable buffer" comment above .cc_wr_skip). This is the one
    ; genuinely free gap in this frame: below the fmt_runname buffer at
    ; [rbp-0x140] (max offset 0x140) and above the mac_read_run_header
    ; output struct at [rbp-0x1C0] (occupies offsets 0x189-0x1C0).
    mov  [rbp-0x188], rax                        ; sparse_scratch base
    mov  qword [rbp-0x180], 0                      ; sparse_n

    ; ---- open the output run, write a placeholder header+bloom ----
    mov  rax, [r12+96]                  ; next_gen -- the merged run's FRESH gen
    mov  [rbp-0x68], rax                  ; out_gen
    mov  rax, [r12+144]                    ; next_run_no
    mov  [rbp-0x60], rax                     ; out_run_no

    lea  rdi, [rbp-0x140]
    mov  esi, [rbp-0x60]
    call fmt_runname
    lea  rdi, [rbp-0x140]
    mov  esi, 1 | 0x40 | 0x200
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .cc_err
    mov  [rbp-0x58], rax                    ; out_fd

    mov  dword [rbp-0x1C0], MAGIC_RUN3     ; new PUSH record shape (Stage D)
    mov  rax, [rbp-0x68]
    mov  [rbp-0x1C0+4], rax
    mov  qword [rbp-0x1C0+12], 0             ; nrec placeholder
    mov  rax, [rbp-0x40]
    mov  [rbp-0x1C0+20], rax
    mov  qword [rbp-0x1C0+28], 0               ; sparse_off placeholder (patched below)
    mov  qword [rbp-0x1C0+36], 0                ; sparse_n placeholder (patched below)
    mov  rdi, [rbp-0x58]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 44
    call mac_write_exact
    test rax, rax
    jnz  .cc_err_close

    mov  rdi, [rbp-0x58]
    mov  rsi, r13
    add  rsi, COMPACT_SLOTS_BYTES
    mov  rdx, [rbp-0x50]
    call mac_write_exact
    test rax, rax
    jnz  .cc_err_close

    mov  rdi, [rbp-0x58]
    call mac_out_begin                        ; per-record writes below are buffered
    mov  qword [rbp-0x70], 0                  ; true_nrec

    ; ================= streaming k-way merge =================
.cc_merge_loop:
    ; find the active slot with the smallest key; ties broken by highest gen
    mov  qword [rbp-0xA0], -1        ; best_idx
    mov  qword [rbp-0x78], 0          ; i
.cc_find_loop:
    mov  rax, [rbp-0x78]
    cmp  rax, r14
    jae  .cc_find_done
    mov  rdx, rax
    imul rdx, rdx, COMPACT_SLOT_SIZE
    add  rdx, r13                     ; this slot base
    cmp  qword [rdx+32], 0             ; active?
    je   .cc_find_next
    cmp  qword [rbp-0xA0], -1
    je   .cc_find_setbest
    mov  rcx, [rbp-0xA0]
    imul rcx, rcx, COMPACT_SLOT_SIZE
    add  rcx, r13                       ; best slot base
    lea  rdi, [rdx+40]
    lea  rsi, [rcx+40]
    push rdx
    call mac_cmp_key                       ; 0=this<best 1=eq 2=this>best
    pop  rdx
    cmp  eax, 0
    je   .cc_find_setbest
    cmp  eax, 1
    jne  .cc_find_next
    ; equal keys -- this wins the tie only if its gen is strictly higher
    mov  rax, [rdx+8]                         ; this.gen
    mov  rcx, [rbp-0xA0]
    imul rcx, rcx, COMPACT_SLOT_SIZE
    add  rcx, r13
    mov  rcx, [rcx+8]                           ; best.gen
    cmp  rax, rcx
    jbe  .cc_find_next
.cc_find_setbest:
    mov  rax, [rbp-0x78]
    mov  [rbp-0xA0], rax
.cc_find_next:
    inc  qword [rbp-0x78]
    jmp  .cc_find_loop
.cc_find_done:
    cmp  qword [rbp-0xA0], -1
    je   .cc_merge_done                    ; no active slots left -> done

    mov  rax, [rbp-0xA0]
    imul rax, rax, COMPACT_SLOT_SIZE
    add  rax, r13
    mov  [rbp-0xB0], rax                    ; winning slot base
    ; Snapshot the winning key into a STABLE buffer now. The advance loop
    ; below re-reads the winning slot's OWN fields in place (it's one of
    ; the slots that matches the winning key, so it gets advanced too) --
    ; comparing later iterations against the winning slot's now-mutated
    ; live fields instead of this snapshot was a real bug (rereads landed
    ; past a run's true EOF because slots that should have matched the
    ; ORIGINAL winning key no longer did once it changed mid-loop).
    lea  rdi, [rbp-0x200]
    lea  rsi, [rax+40]
    push rax
    mov  rdx, 36
    call mac_memcpy
    pop  rax

    ; ---- emit the winner: a PUSH always; a DEL only when older runs exist
    ; below the batch (keep_dels), where it still cancels their puts. A batch
    ; anchored at the oldest run has nothing below it, so DEL is dropped. ----
    movzx eax, byte [rax+76]                  ; type
    cmp  eax, 1
    je   .cc_wr_emit
    cmp  qword [rbp-0x248], 0
    je   .cc_wr_skip
    cmp  eax, 2
    jne  .cc_wr_skip
.cc_wr_emit:

    ; ---- sparse index sampling: sample every SPARSE_STRIDEth EMITTED
    ; record's (key, file_offset), checked BEFORE true_nrec's increment
    ; below (so [rbp-0x70] here is the 0-indexed ordinal of THIS emission
    ; -- index 0 is always sampled) -- offset captured before writing any
    ; of this record's bytes, so it points exactly at this record's start,
    ; mirroring mac_flush's identical sampling technique. ----
    mov  rax, [rbp-0x70]                ; true_nrec (pre-increment)
    test rax, (SPARSE_STRIDE-1)
    jnz  .cc_sp_nosample
    ; The offset MUST come through the buffered writer. lseek(SEEK_CUR) here
    ; reports what has reached the file, which with a write buffer lags the
    ; records already emitted by up to a megabyte -- every sparse entry would
    ; point up to 1 MB too early. Found by byte-comparing old vs new output
    ; (35,675 differing bytes, all in the sparse index), not by any test; the
    ; sparse-offset invariant test exists because of it.
    call mac_out_tell                    ; = file position + bytes buffered
    test rax, rax
    js   .cc_err_close
    mov  rbx, rax                              ; this record's file offset
    mov  rax, [rbp-0x180]                        ; sparse_n
    imul rax, rax, SPARSE_ENT_SIZE
    add  rax, [rbp-0x188]                          ; dest = sparse base + n*44
    mov  rdi, rax
    mov  rdx, [rbp-0xB0]
    lea  rsi, [rdx+40]                                ; winning slot's key ptr
    mov  rdx, 36
    call mac_memcpy
    mov  [rdi+36], rbx                                  ; file_offset (rdi preserved by mac_memcpy)
    inc  qword [rbp-0x180]                                ; sparse_n++
.cc_sp_nosample:

    mov  rdx, [rbp-0xB0]
    mov  rdi, [rbp-0x58]
    lea  rsi, [rdx+40]                          ; key+type, 37 bytes
    mov  rdx, 37
    call mac_out_write
    test rax, rax
    jnz  .cc_err_close
    mov  rdx, [rbp-0xB0]
    cmp  byte [rdx+76], 1
    jne  .cc_wr_bloom                            ; DEL: key+type only, exactly as mac_flush writes it
    mov  rdi, [rbp-0x58]
    ; value(8)+slen(2)+height(4)+is_coinbase(1) = 15 contiguous bytes, same
    ; order as the on-disk PUSH record (see mac_compact_read_rec's header
    ; comment) -- height/is_coinbase are 0 for a record that came from an
    ; old-shape input run (mac_compact_read_rec zeroed them at read time),
    ; so compacting a mix of old- and new-shape runs is safe: it just
    ; can't manufacture height/coinbase data that was never captured.
    lea  rsi, [rdx+80]                            ; value+slen+height+is_coinbase, 15 bytes
    mov  rdx, 15
    call mac_out_write
    test rax, rax
    jnz  .cc_err_close
    mov  rdx, [rbp-0xB0]
    movzx r15d, word [rdx+88]                       ; slen
    test r15d, r15d
    jz   .cc_wr_bloom
    mov  rdi, [rbp-0x58]
    lea  rsi, [rdx+104]                            ; script (moved from +96)
    mov  rdx, r15
    call mac_out_write
    test rax, rax
    jnz  .cc_err_close
.cc_wr_bloom:
    ; mac_bloom_setbit's real signature is (key=rdi, seed=esi,
    ; bloom_base=rdx, bits_mask=ecx) -- bloom_base MUST go in rdx, not
    ; rsi (rsi is the seed slot, overwritten by each call below anyway).
    ; Putting it in rsi here left rdx holding whatever this block's first
    ; line put there (the WINNING SLOT's own address), so the "set bit"
    ; write landed inside that slot's own header fields (fd/gen/run_no/
    ; remaining/active) instead of the bloom bitmap -- confirmed via a
    ; hardware watchpoint on the corrupted fd field, which caught the
    ; write happening right here.
    mov  rdx, [rbp-0xB0]
    lea  rdi, [rdx+40]                                ; key ptr
    mov  rdx, r13
    add  rdx, COMPACT_SLOTS_BYTES                        ; bloom base
    mov  ecx, [rbp-0x48]                                    ; bits_mask
    push rdi
    push rdx
    push rcx
    mov  esi, 0x811c9dc5
    call mac_bloom_setbit
    pop  rcx
    pop  rdx
    pop  rdi
    push rdi
    push rdx
    push rcx
    mov  esi, 0xa1b2c3d4
    call mac_bloom_setbit
    pop  rcx
    pop  rdx
    pop  rdi
    mov  esi, 0x5bd1e995
    call mac_bloom_setbit
    inc  qword [rbp-0x70]                                     ; true_nrec++
.cc_wr_skip:

    ; ---- advance every slot whose current key equals the winning key ----
    mov  qword [rbp-0x78], 0
.cc_adv_loop:
    mov  rax, [rbp-0x78]
    cmp  rax, r14
    jae  .cc_adv_done
    mov  rcx, rax
    imul rcx, rcx, COMPACT_SLOT_SIZE
    add  rcx, r13                          ; this slot base
    cmp  qword [rcx+32], 0                   ; active?
    je   .cc_adv_next
    lea  rdi, [rcx+40]
    lea  rsi, [rbp-0x200]                       ; stable snapshot of the winning key
    push rcx
    call mac_cmp_key
    pop  rcx
    cmp  eax, 1
    jne  .cc_adv_next                             ; not the same key -> leave it
    cmp  qword [rcx+24], 0                          ; remaining
    jne  .cc_adv_reread
    mov  qword [rcx+32], 0                            ; exhausted -> active=0
    jmp  .cc_adv_next
.cc_adv_reread:
    mov  rdi, rcx
    call mac_compact_read_rec
    cmp  eax, -1
    je   .cc_err_close
.cc_adv_next:
    inc  qword [rbp-0x78]
    jmp  .cc_adv_loop
.cc_adv_done:
    jmp  .cc_merge_loop
.cc_merge_done:
    ; ================= end streaming k-way merge =================

    ; ---- patch bloom bytes (file offset 44 -- MAGIC_RUN2's header is 44
    ; bytes, not the old format's 28, since sparse_off/sparse_n now sit
    ; between bloom_bits and the bloom bytes themselves) and nrec (offset
    ; 12, unchanged -- still inside the common MAGIC/gen/nrec prefix) ----
    call mac_out_flush                   ; every buffered record hits the file
    test rax, rax                        ; BEFORE the header is patched
    jnz  .cc_err_close
    mov  rdi, [rbp-0x58]
    mov  esi, 44
    xor  edx, edx
    mov  eax, 8                          ; lseek SEEK_SET
    syscall
    test rax, rax
    jl   .cc_err_close
    mov  rdi, [rbp-0x58]
    mov  rsi, r13
    add  rsi, COMPACT_SLOTS_BYTES
    mov  rdx, [rbp-0x50]
    call mac_write_exact
    test rax, rax
    jnz  .cc_err_close

    mov  rdi, [rbp-0x58]
    mov  esi, 12
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .cc_err_close
    mov  rax, [rbp-0x70]
    mov  [rbp-0x1C0], rax
    mov  rdi, [rbp-0x58]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 8
    call mac_write_exact
    test rax, rax
    jnz  .cc_err_close

    ; ---- append the sparse index after all records (SEEK_END lands there
    ; exactly: the two patches above overwrote existing bytes in place,
    ; they never changed the file's length), then patch sparse_off/sparse_n
    ; into the header at offset 28 -- same placeholder-then-patch pattern
    ; as nrec/bloom above, mirroring mac_flush's identical technique. ----
    mov  rdi, [rbp-0x58]
    xor  esi, esi
    mov  edx, 2                          ; SEEK_END
    mov  eax, 8
    syscall
    test rax, rax
    jl   .cc_err_close
    mov  r15, rax                         ; sparse_off
    mov  rax, [rbp-0x180]                   ; sparse_n
    test rax, rax
    jz   .cc_sp_wr_done
    mov  rdi, [rbp-0x58]
    mov  rsi, [rbp-0x188]                     ; sparse scratch base
    mov  rdx, [rbp-0x180]
    imul rdx, rdx, SPARSE_ENT_SIZE
    call mac_write_exact
    test rax, rax
    jnz  .cc_err_close
.cc_sp_wr_done:
    mov  rdi, [rbp-0x58]
    mov  esi, 28
    xor  edx, edx
    mov  eax, 8                          ; lseek SEEK_SET
    syscall
    test rax, rax
    jl   .cc_err_close
    mov  [rbp-0x1C0], r15                    ; sparse_off
    mov  rax, [rbp-0x180]                      ; sparse_n
    mov  [rbp-0x1C0+8], rax
    mov  rdi, [rbp-0x58]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 16
    call mac_write_exact
    test rax, rax
    jnz  .cc_err_close

    mov  rdi, [rbp-0x58]
    call mac_fsync2
    mov  rdi, [rbp-0x58]
    mov  eax, 3
    syscall

    ; ---- write the merged (OLDEST surviving generation) entry FIRST, at
    ;      index 0, then shift the surviving (newer, un-merged) entries
    ;      down to start right after it -- the array must stay strictly
    ;      gen-ascending (lowest index = oldest) because utxo_lsm_get's own
    ;      scan (.lg_run_loop) walks it from its HIGHEST index down to 0,
    ;      treating the highest index as "newest, check first."
    ;
    ;      BUG (2026-08-20, found root-causing a real production incident:
    ;      a genuinely-live, later-legitimately-spent UTXO resolved to its
    ;      stale pre-spend value after a partial compaction, causing a
    ;      real historical block's signature check to fail against wrong
    ;      data): this used to shift survivors down to indices [0,K) FIRST
    ;      and append the merged entry AFTER them at index K -- the
    ;      HIGHEST index, which get()'s scan treats as newest. Any
    ;      compaction that doesn't merge every existing run (batch_size <
    ;      manifest_n, i.e. manifest_n was already > COMPACT_MAX_RUNS) put
    ;      the OLDEST generation's data at the FRONT of get()'s scan order
    ;      and the genuinely-newest surviving runs -- including whichever
    ;      one held the correct, up-to-date tombstone or value for a given
    ;      key -- BEHIND it. No existing test caught this because every
    ;      test's manifest_n stays under COMPACT_MAX_RUNS(64), so every
    ;      test compaction merges everything, leaving zero survivors and
    ;      thus no ordering to get wrong. ----
    mov  rdi, [r12+104]                    ; manifest_buf
    mov  rcx, [rbp-0x240]                  ; the merged entry takes the batch's first index (lo)
    shl  rcx, 4
    add  rdi, rcx
    mov  rax, [rbp-0x68]                    ; out_gen
    mov  [rdi], rax
    mov  rax, [rbp-0x60]                     ; out_run_no
    mov  [rdi+8], rax

    mov  rax, [r12+120]                   ; manifest_n
    mov  rdx, r14
    add  rdx, [rbp-0x240]
    mov  [rbp-0x78], rdx                    ; src index, starts at lo + batch_size
    mov  rdx, [rbp-0x240]
    inc  rdx
    mov  [rbp-0x90], rdx                    ; dst index, starts at lo + 1 (lo is the merged entry)
.cc_shift_loop:
    mov  rdx, [rbp-0x78]
    cmp  rdx, rax
    jae  .cc_shift_done
    mov  rsi, [r12+104]
    mov  rcx, rdx
    shl  rcx, 4
    add  rsi, rcx                            ; src ptr
    mov  rdi, [r12+104]
    mov  rcx, [rbp-0x90]
    shl  rcx, 4
    add  rdi, rcx                             ; dst ptr
    mov  rcx, [rsi]
    mov  [rdi], rcx
    mov  rcx, [rsi+8]
    mov  [rdi+8], rcx
    inc  qword [rbp-0x78]
    inc  qword [rbp-0x90]
    jmp  .cc_shift_loop
.cc_shift_done:
    mov  rax, [rbp-0x90]
    mov  [r12+120], rax                           ; manifest_n = new count
    inc  qword [r12+96]                             ; next_gen++
    inc  qword [r12+144]                              ; next_run_no++

    ; ---- decide the live-count field for the new manifest (see the
    ; MAGIC_MANIFEST2 design note). The persisted value must be RUNS-ONLY
    ; (WAL/memtable excluded) so reload can add the WAL tail on top without
    ; double-counting. First recover the previously persisted base from the
    ; CURRENT on-disk manifest (still intact -- the rename is below). ----
    mov  qword [rbp-0x218], 0        ; has_count = 0
    lea  rdi, [rel manifest_name]
    xor  esi, esi
    mov  eax, 2
    syscall
    test rax, rax
    js   .cc_pl_decide               ; unreadable -> has_count stays 0
    mov  [rbp-0x228], rax            ; read fd
    mov  rdi, rax
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 12
    call mac_read_exact2
    test rax, rax
    jnz  .cc_pl_close
    mov  eax, [rbp-0x1C0]
    cmp  eax, MAGIC_MANIFEST2
    jne  .cc_pl_close
    mov  rdi, [rbp-0x228]
    lea  rsi, [rbp-0x220]            ; P_old (previously persisted runs-only base)
    mov  rdx, 8
    call mac_read_exact2
    test rax, rax
    jnz  .cc_pl_close
    mov  qword [rbp-0x218], 1        ; has_count = 1
.cc_pl_close:
    mov  rdi, [rbp-0x228]
    mov  eax, 3
    syscall
.cc_pl_decide:
    ; is_full == (batch_size == original manifest_n)?  A full merge collapses
    ; ALL runs into one, so true_nrec ([rbp-0x70]) IS the exact runs-only
    ; live count -- authoritative, independent of any prior drift.
    mov  rax, r14
    cmp  rax, [rbp-0x210]
    jne  .cc_pl_partial
    mov  rax, [rbp-0x70]             ; true_nrec
    mov  [rbp-0x230], rax            ; persist_count
    mov  qword [rbp-0x238], 1        ; write v2
    ; heal the in-memory running counter to ground truth while preserving the
    ; WAL tail's contribution: new = true_nrec + (running - old_base). Only
    ; when we recovered old_base; otherwise the running value already came
    ; from a fresh recount/init and is left untouched.
    cmp  qword [rbp-0x218], 0
    je   .cc_pl_have
    mov  rax, [r12+88]
    sub  rax, [rbp-0x220]
    add  rax, [rbp-0x70]
    mov  [r12+88], rax
    jmp  .cc_pl_have
.cc_pl_partial:
    ; partial merge: count-neutral, and true_nrec covers only the merged
    ; subset. Carry the previously persisted base through unchanged; if there
    ; is none, write an OLD-format header so reload recomputes via recount.
    cmp  qword [rbp-0x218], 0
    je   .cc_pl_v1
    mov  rax, [rbp-0x220]            ; P_old
    mov  [rbp-0x230], rax
    mov  qword [rbp-0x238], 1        ; write v2
    jmp  .cc_pl_have
.cc_pl_v1:
    mov  qword [rbp-0x238], 0        ; write v1 (no count field)
.cc_pl_have:

    ; ---- publish manifest: tmp file + fsync + rename + dir fsync ----
    ; (deferred publish: same bytes to utxo_manifest.child, then stop before
    ; the rename -- see mac_compact_defer_publish)
    lea  rdi, [rel manifest_tmp_name]
    cmp  qword [rel mac_compact_defer_publish], 0
    je   .cc_pub_name
    lea  rdi, [rel manifest_child_name]
.cc_pub_name:
    mov  esi, 1 | 0x40 | 0x200
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .cc_err_close
    mov  rbx, rax
    mov  rax, [r12+120]
    mov  [rbp-0x1C0+4], rax          ; manifest_n
    cmp  qword [rbp-0x238], 0
    je   .cc_hdr_v1
    mov  dword [rbp-0x1C0], MAGIC_MANIFEST2
    mov  rax, [rbp-0x230]
    mov  [rbp-0x1C0+12], rax         ; total_live
    mov  edx, 20
    jmp  .cc_hdr_wr
.cc_hdr_v1:
    mov  dword [rbp-0x1C0], MAGIC_MANIFEST
    mov  edx, 12
.cc_hdr_wr:
    mov  rdi, rbx
    lea  rsi, [rbp-0x1C0]
    call mac_write_exact
    test rax, rax
    jnz  .cc_merr_close
    mov  rdi, rbx
    mov  rsi, [r12+104]
    mov  rdx, [r12+120]
    shl  rdx, 4
    call mac_write_exact
    test rax, rax
    jnz  .cc_merr_close
    mov  rdi, rbx
    call mac_fsync2
    mov  rdi, rbx
    mov  eax, 3
    syscall
    cmp  qword [rel mac_compact_defer_publish], 0
    jne  .cc_dirsync_skip                   ; deferred: the parent publishes

    lea  rdi, [rel manifest_tmp_name]
    lea  rsi, [rel manifest_name]
    mov  eax, 82                            ; rename
    syscall
    test rax, rax
    jl   .cc_err_close

    lea  rdi, [rel dot_name]
    xor  esi, esi
    mov  eax, 2
    syscall
    test rax, rax
    jl   .cc_dirsync_skip
    mov  rbx, rax
    mov  rdi, rbx
    call mac_fsync2
    mov  rdi, rbx
    mov  eax, 3
    syscall
.cc_dirsync_skip:

    ; ---- close output fd, close+unlink old input runs, free scratch ----
    mov  rdi, [rbp-0x58]
    mov  eax, 3
    syscall

    mov  qword [rbp-0x78], 0
.cc_unlink_loop:
    mov  rax, [rbp-0x78]
    cmp  rax, r14
    jae  .cc_unlink_done
    mov  rdx, rax
    imul rdx, rdx, COMPACT_SLOT_SIZE
    add  rdx, r13
    mov  rdi, [rdx]                          ; input fd
    mov  eax, 3
    syscall
    cmp  qword [rel mac_compact_defer_unlink], 0
    jne  .cc_unlink_next                     ; deferred: the adopting parent unlinks
    lea  rdi, [rbp-0x140]
    mov  rdx, [rbp-0x78]
    imul rdx, rdx, COMPACT_SLOT_SIZE
    add  rdx, r13
    mov  esi, [rdx+16]                          ; run_no
    call fmt_runname
    lea  rdi, [rbp-0x140]
    mov  eax, 87                                  ; unlink
    syscall
.cc_unlink_next:
    inc  qword [rbp-0x78]
    jmp  .cc_unlink_loop
.cc_unlink_done:

    mov  rdi, r13
    mov  esi, COMPACT_SCRATCH_BYTES
    mov  eax, 11                             ; munmap
    syscall

    mov  rdi, [rbp-0x188]                    ; sparse scratch base
    mov  esi, [rbp-0x178]                      ; sparse_scratch_bytes
    mov  eax, 11                                 ; munmap
    syscall

    mov  rax, 1
    jmp  .cc_ret

.cc_noop:
    xor  eax, eax
    jmp  .cc_ret_noscratch
.cc_merr_close:
    mov  rdi, rbx
    mov  eax, 3
    syscall
    jmp  .cc_err_close
.cc_err_close:
    mov  rdi, [rbp-0x58]
    mov  eax, 3
    syscall
.cc_err:
    ; best-effort only: input fds / mmap'd scratch are left for the
    ; process to reclaim on exit rather than unwound perfectly here -- -1
    ; is meant to be treated as fatal by the caller, same as elsewhere in
    ; this module (utxo_lsm_put/del's own -1 contract).
    mov  rax, -1
    jmp  .cc_ret
.cc_err_noscratch:
    mov  rax, -1
.cc_ret_noscratch:
    add  rsp, 0x400
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.cc_ret:
    add  rsp, 0x400
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
