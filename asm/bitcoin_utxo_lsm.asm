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
;   (total struct size: 152 bytes)
;
; Exports (System V AMD64):
;   long utxo_lsm_init(void* lst)                              -> 1 / -1
;   long utxo_lsm_put(void* lst, void* u, const u8 txid[32],
;                      u32 index, u64 value, const u8* script, u32 slen)
;                                                                -> 1/0/2/-1
;   long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index)
;                                                                -> 1 / -1
;   long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
;                      u64* value, u8** script, u32* slen)      -> 1/0/-1
;                      (on a disk-run hit, *script points into lst's
;                      internal scratch buffer -- valid only until the next
;                      utxo_lsm_get call, unlike a memtable hit's stable
;                      blob pointer; documented divergence from utxo_get.)
;   long utxo_lsm_count(void* lst)                              -> total_live
;   long utxo_lsm_reload(void* lst, void* u)          -> replayed count / -1
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
MAGIC_MANIFEST   equ 0x4E414D55      ; "UMAN" little-endian dword
BLOOM_MAX_BYTES  equ 4*1024*1024     ; 4MB bloom scratch (~3.35M entries @10 bits/entry)
SCRIPT_MAX_BYTES equ 65536           ; get-time script-read scratch

; ---- sparse index (added after Phase 2 shipped without one -- see
; mac_read_run_header's header comment for the full backward-compat story) ----
SPARSE_STRIDE    equ 256             ; sample every Nth sorted record (index 0 always sampled)
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
; type(1)+pad(3) value(8) slen(2)+pad(6) script(up to SCRIPT_MAX_BYTES)
COMPACT_SLOT_SIZE  equ 96 + SCRIPT_MAX_BYTES
COMPACT_SLOTS_BYTES equ COMPACT_MAX_RUNS * COMPACT_SLOT_SIZE
COMPACT_SCRATCH_BYTES equ COMPACT_SLOTS_BYTES + BLOOM_MAX_BYTES

manifest_name:     db "utxo_manifest.dat", 0
manifest_tmp_name:  db "utxo_manifest.tmp", 0
dot_name:           db ".", 0
wal_name:            db "utxo.dat", 0

extern utxo_put
extern utxo_get
extern utxo_del
extern utxo_store_init
extern utxo_store_put
extern utxo_store_del
extern utxo_store_reload
extern utxo_store_close

; ============================================================================
; small local helpers
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
; Preserves rdi,rsi,rcx,rdx.
mac_cmp_key:
    push rdi
    push rsi
    push rcx
    push rdx
    xor  ecx, ecx
.kl:
    cmp  ecx, 36
    jae  .keq
    movzx eax, byte [rdi+rcx]
    movzx edx, byte [rsi+rcx]
    cmp  eax, edx
    jb   .klt
    ja   .kgt
    inc  ecx
    jmp  .kl
.keq:
    mov  eax, 1
    jmp  .kret
.klt:
    mov  eax, 0
    jmp  .kret
.kgt:
    mov  eax, 2
.kret:
    pop  rdx
    pop  rcx
    pop  rsi
    pop  rdi
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
;   out (56-byte caller-allocated buffer):
;     +0  gen(8)  +8 nrec(8)  +16 bloom_bytes(8)  +24 bits_mask(8)
;     +32 header_size(8, 28 or 44)  +40 sparse_off(8)  +48 sparse_n(8)
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
    cmp  eax, MAGIC_RUN2
    je   .rh_new
    cmp  eax, MAGIC_RUN
    jne  .rh_err             ; unrecognized magic -- treat as corrupt

    ; ---- old format: remaining 24 bytes are gen+nrec+bloom_bits ----
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
    xor  eax, eax
    jmp  .rh_ret

.rh_new:
    ; ---- new format: remaining 40 bytes are gen+nrec+bloom_bits+sparse_off+sparse_n ----
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
mac_copy_rec:
    push rdi
    push rsi
    push rcx
    xor  ecx, ecx
.cl:
    cmp  ecx, 64
    jae  .cd
    mov  al, [rsi+rcx]
    mov  [rdi+rcx], al
    inc  ecx
    jmp  .cl
.cd:
    pop  rcx
    pop  rsi
    pop  rdi
    ret

; mac_bloom_h(key=rdi(36B), seed=esi) -> eax = FNV-1a-style 32-bit hash.
; Preserves rdi,rdx,rcx,rbx (esi untouched throughout).
mac_bloom_h:
    push rbx
    push rcx
    push rdx
    push rdi
    mov  ebx, esi
    xor  ecx, ecx
.bh:
    cmp  ecx, 36
    jae  .bhd
    movzx edx, byte [rdi+rcx]
    xor  ebx, edx
    imul ebx, ebx, 16777619
    inc  ecx
    jmp  .bh
.bhd:
    mov  eax, ebx
    pop  rdi
    pop  rdx
    pop  rcx
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
    call utxo_store_init
    cmp  rax, 1
    jne  .li_fail
    mov  qword [r12+40], 0
    mov  qword [r12+80], 0
    mov  qword [r12+88], 0
    mov  qword [r12+96], 0
    mov  qword [r12+120], 0
    mov  qword [r12+144], 0
    mov  rax, 1
    jmp  .li_done
.li_fail:
    mov  rax, -1
.li_done:
    add  rsp, 0x10
    pop  r12
    pop  rbp
    ret

; ============================================================================
; utxo_lsm_put(lst, u, txid, index, value, script, slen) -> 1/0/2/-1
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
    mov  rax, [rbp+16]      ; slen (my 7th arg)
    push rax                 ; forward as utxo_store_put's 7th arg
    call utxo_store_put       ; rdi..r9 untouched since our own entry
    add  rsp, 8
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
; mac_run_lookup(lst, run_no, txid, index, &value, &script, &slen) ->
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
    mov  [rbp-0x40], r8
    mov  [rbp-0x48], r9
    mov  rax, [rbp+16]
    mov  [rbp-0x50], rax

    mov  rdi, r12
    call mac_calc_desc_cap
    shl  rax, 7
    mov  [rbp-0x60], rax        ; off_bloom

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
    mov  rsi, [r12+128]
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

    mov  rdx, [r12+128]
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
    mov  rdi, [rbp-0x68]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 10
    call mac_read_exact2
    test rax, rax
    jnz  .ml_absent_close
    movzx eax, word [rbp-0x1C0+8]
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
    mov  rdi, [rbp-0x68]
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 10
    call mac_read_exact2
    test rax, rax
    jnz  .ml_err_close
    movzx r14d, word [rbp-0x1C0+8]
    test r14d, r14d
    jz   .ml_push_noscript
    mov  rdi, [rbp-0x68]
    mov  rsi, [r12+128]
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
    mov  rax, [rbp-0x1C0]
    mov  rcx, [rbp-0x40]
    mov  [rcx], rax
    mov  rcx, [rbp-0x48]
    mov  rax, [r12+128]
    add  rax, [rbp-0x60]
    add  rax, BLOOM_MAX_BYTES
    mov  [rcx], rax
    mov  rcx, [rbp-0x50]
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
; utxo_lsm_get(lst, u, txid, index, &value, &script, &slen) -> 1/0/-1
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
    mov  [rbp-0x38], r8
    mov  [rbp-0x40], r9
    mov  rax, [rbp+16]
    mov  [rbp-0x48], rax

    mov  rdi, r13
    mov  rsi, rbx
    mov  edx, [rbp-0x30]
    mov  rcx, [rbp-0x38]
    mov  r8, [rbp-0x40]
    ; utxo_get's REAL contract writes a full 8-byte "unsigned long* slen"
    ; (see bitcoin_utxo.asm) even though this module's own contract is
    ; u32* slen throughout -- forwarding the caller's 4-byte u32* directly
    ; here would be a genuine 4-byte stack overflow on every memtable hit.
    ; Give it an 8-byte scratch slot instead and narrow-copy below.
    lea  r9, [rbp-0x110]
    call utxo_get
    cmp  eax, 1
    jne  .lg_no_memtable_hit
    mov  eax, [rbp-0x110]
    mov  rcx, [rbp-0x48]
    mov  [rcx], eax
    jmp  .lg_found
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
    mov  rax, [r12+80]        ; tomb_n
    mov  [rbp-0x58], rax
    mov  qword [rbp-0x60], 0
.lg_tomb_loop:
    mov  rax, [rbp-0x60]
    cmp  rax, [rbp-0x58]
    jae  .lg_tomb_done
    mov  rdi, [r12+64]
    mov  rcx, rax
    imul rcx, rcx, 36
    add  rdi, rcx
    lea  rsi, [rbp-0x100]
    call mac_cmp_key
    cmp  eax, 1
    je   .lg_not_found
    inc  qword [rbp-0x60]
    jmp  .lg_tomb_loop
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
    mov  esi, [rdx+8]             ; run_no
    mov  rdi, r12
    mov  rdx, rbx
    mov  ecx, [rbp-0x30]
    mov  r8, [rbp-0x38]
    mov  r9, [rbp-0x40]
    mov  rax, [rbp-0x48]
    push rax
    call mac_run_lookup
    add  rsp, 8
    cmp  eax, 1
    je   .lg_found
    cmp  eax, 2
    je   .lg_not_found
    cmp  eax, -1
    je   .lg_err
    jmp  .lg_run_loop
.lg_found:
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
    add  rdx, rcx
    mov  rcx, [rdx]                  ; value
    mov  [rdi+40], rcx
    mov  cx, [rdx+8]                  ; slen (low u16)
    mov  [rdi+48], cx
    lea  rcx, [rdx+16]                 ; script_ptr
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
    lea  rcx, [rbp-0x180]
    lea  r8, [rbp-0x188]
    lea  r9, [rbp-0x190]
    call utxo_get
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

    mov  dword [rbp-0x100], MAGIC_RUN2
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
    call mac_write_exact
    pop  rsi
    test rax, rax
    jnz  .fl_err_close
    movzx eax, byte [rsi+36]
    cmp  eax, 1
    jne  .fl_wr_next
    mov  rdi, [rbp-0x88]
    lea  rax, [rsi+40]
    push rsi
    mov  rsi, rax
    mov  rdx, 10
    call mac_write_exact
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
    call mac_write_exact
    pop  rsi
    test rax, rax
    jnz  .fl_err_close
.fl_wr_next:
    inc  qword [rbp-0x80]
    jmp  .fl_wr_loop
.fl_wr_done:
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
    mov  dword [rbp-0x100], MAGIC_MANIFEST
    mov  rax, [r12+120]
    mov  [rbp-0x100+4], rax
    mov  rdi, rbx
    lea  rsi, [rbp-0x100]
    mov  rdx, 12
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
global utxo_lsm_reload
utxo_lsm_reload:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x200
    mov  r12, rdi           ; lst
    mov  r13, rsi            ; u

    ; open (or reopen) the WAL fds -- utxo_store_reload below assumes
    ; st->log_fd/idx_fd are already valid open fds (it never opens them
    ; itself, mirroring bitcoin_utxo_store.asm's own store_init-then-
    ; store_reload calling convention). Safe to call unconditionally: it
    ; reopens the existing utxo.dat/utxo.idx (O_CREAT|O_RDWR, no truncate).
    mov  rdi, r12
    call utxo_store_init
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
    cmp  eax, MAGIC_MANIFEST
    jne  .rl_manifest_bad
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
    mov  rdi, rbx
    lea  rsi, [rbp-0x100]
    mov  rdx, 46
    call mac_read_exact2
    test rax, rax
    jnz  .rl_wal_close
    add  qword [rbp-0x90], 46
    movzx eax, word [rbp-0x100+44]
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
    inc  qword [r12+80]
    jmp  .rl_wal_loop
.rl_wal_close:
    mov  rdi, rbx
    mov  eax, 3
    syscall

    mov  rax, [r13]
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
;   Slot layout: +0 fd +8 gen +16 run_no +24 remaining +32 active +40 key(36)
;   +76 type +80 value(8) +88 slen(2) +96 script(up to SCRIPT_MAX_BYTES).
; ============================================================================
mac_compact_read_rec:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x10
    mov  r12, rdi                  ; slot base
    mov  rbx, [r12]                 ; fd
    mov  rdi, rbx
    lea  rsi, [r12+40]
    mov  rdx, 37                     ; key(36)+type(1)
    call mac_read_exact2
    test rax, rax
    jnz  .cr_err
    movzx eax, byte [r12+76]           ; type
    cmp  eax, 1
    jne  .cr_dec
    mov  rdi, rbx
    lea  rsi, [r12+80]
    mov  rdx, 10                          ; value(8)+slen(2)
    call mac_read_exact2
    test rax, rax
    jnz  .cr_err
    movzx eax, word [r12+88]                ; slen
    test eax, eax
    jz   .cr_dec
    mov  rdi, rbx
    lea  rsi, [r12+96]
    mov  rdx, rax
    call mac_read_exact2
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
utxo_lsm_compact:
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

    ; manifest entry i -> gen, run_no
    mov  rcx, rax
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

    ; format-aware header read (old MAGIC_RUN or new MAGIC_RUN2 -- an input
    ; run being compacted may be EITHER, since not every run has necessarily
    ; been rewritten by the fixed writer yet; see mac_read_run_header's own
    ; header comment). [rbp-0x1C0] holds its 56-byte output struct here;
    ; this slot gets reused for unrelated staging later in this same
    ; function (the OUTPUT run's own header, then manifest staging) -- safe,
    ; since those uses happen in strictly later, non-overlapping phases.
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

    mov  dword [rbp-0x1C0], MAGIC_RUN2
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

    ; ---- emit the winner if it's a PUSH (DEL is always safe to drop) ----
    movzx eax, byte [rax+76]                  ; type
    cmp  eax, 1
    jne  .cc_wr_skip

    ; ---- sparse index sampling: sample every SPARSE_STRIDEth EMITTED
    ; record's (key, file_offset), checked BEFORE true_nrec's increment
    ; below (so [rbp-0x70] here is the 0-indexed ordinal of THIS emission
    ; -- index 0 is always sampled) -- offset captured before writing any
    ; of this record's bytes, so it points exactly at this record's start,
    ; mirroring mac_flush's identical sampling technique. ----
    mov  rax, [rbp-0x70]                ; true_nrec (pre-increment)
    test rax, (SPARSE_STRIDE-1)
    jnz  .cc_sp_nosample
    mov  rdi, [rbp-0x58]                 ; out_fd
    xor  esi, esi
    mov  edx, 1                            ; SEEK_CUR
    mov  eax, 8                              ; lseek
    syscall
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
    call mac_write_exact
    test rax, rax
    jnz  .cc_err_close
    mov  rdx, [rbp-0xB0]
    mov  rdi, [rbp-0x58]
    lea  rsi, [rdx+80]                            ; value+slen, 10 bytes
    mov  rdx, 10
    call mac_write_exact
    test rax, rax
    jnz  .cc_err_close
    mov  rdx, [rbp-0xB0]
    movzx r15d, word [rdx+88]                       ; slen
    test r15d, r15d
    jz   .cc_wr_bloom
    mov  rdi, [rbp-0x58]
    lea  rsi, [rdx+96]
    mov  rdx, r15
    call mac_write_exact
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

    ; ---- shift surviving (newer) manifest entries down, append the merged
    ;      entry after them so the array stays strictly gen-ascending ----
    mov  rax, [r12+120]                   ; manifest_n
    mov  [rbp-0x78], r14                    ; src index, starts at batch_size
    mov  qword [rbp-0x90], 0                  ; dst index, starts at 0
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
    mov  rdi, [r12+104]
    mov  rcx, [rbp-0x90]
    shl  rcx, 4
    add  rdi, rcx
    mov  rax, [rbp-0x68]                       ; out_gen
    mov  [rdi], rax
    mov  rax, [rbp-0x60]                        ; out_run_no
    mov  [rdi+8], rax
    inc  qword [rbp-0x90]
    mov  rax, [rbp-0x90]
    mov  [r12+120], rax                           ; manifest_n = new count
    inc  qword [r12+96]                             ; next_gen++
    inc  qword [r12+144]                              ; next_run_no++

    ; ---- publish manifest: tmp file + fsync + rename + dir fsync ----
    lea  rdi, [rel manifest_tmp_name]
    mov  esi, 1 | 0x40 | 0x200
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .cc_err_close
    mov  rbx, rax
    mov  dword [rbp-0x1C0], MAGIC_MANIFEST
    mov  rax, [r12+120]
    mov  [rbp-0x1C0+4], rax
    mov  rdi, rbx
    lea  rsi, [rbp-0x1C0]
    mov  rdx, 12
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
    lea  rdi, [rbp-0x140]
    mov  rdx, [rbp-0x78]
    imul rdx, rdx, COMPACT_SLOT_SIZE
    add  rdx, r13
    mov  esi, [rdx+16]                          ; run_no
    call fmt_runname
    lea  rdi, [rbp-0x140]
    mov  eax, 87                                  ; unlink
    syscall
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
