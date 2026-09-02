; ============================================================================
; bitcoin_idxscan.asm -- on-disk index.dat positional-record scans.
;
; Canonical asm home for the "scan index.dat's 48-byte records for the first
; 4 bytes non-zero" family of checks that dl_catchup (asm/daemon/main.c)
; needs every status tick and every worker chunk-claim. This logic used to
; be reimplemented separately for each of the 4 call sites in C (and twice
; more in hole_ranges.py) -- straight ports of dlc_chunk_all_present,
; dlc_index_tip, dlc_first_hole and dlc_scan_progress, byte-for-byte same
; semantics (first 4 bytes of the 48-byte record are the presence check),
; operating on "index.dat" in the current working directory exactly like the
; C originals did via fopen("index.dat","rb").
;
; Reads are BUFFERED: one pread64 per IDXSCAN_BUFRECS (4096) records into a
; static scratch buffer, scanned in memory with no syscalls in the hot loop.
; A naive first cut here (one pread64 syscall per single 48-byte record)
; benchmarked 2-15x SLOWER than the C baseline's stdio fread, because
; glibc's own buffered stdio already amortizes its read() syscalls across a
; ~4KB (BUFSIZ) window while the raw-syscall version paid a syscall per
; record; going bigger than stdio's window (192KB vs ~4KB) is what actually
; wins. Buffer lives in .bss, not on the stack: these functions run inside
; forked dl_catchup workers, which are separate single-threaded processes
; (see main.c dlc_worker), so a static buffer is safe without locking, and
; 192KB is too large to want on the stack next to this file's small,
; save-area-safe frames.
;
; Raw syscalls only (open=2, close=3, lseek=8, pread64=17), matching the
; rest of the tree's daemon-facing asm (see bitcoin_store.asm). Linux
; preserves rdi/rsi/rdx/r10/r8/r9 (and all callee-saved regs) across a bare
; `syscall` instruction -- only rax/rcx/r11 are clobbered -- so values
; staged into those registers before a syscall are still valid right after
; it, no reload needed.
;
; Stack frame: push rbp; mov rbp,rsp; push callee-saved; sub rsp for locals
; placed BELOW the register-save area -- this codebase has a documented
; past bug where a scratch slot overlapping the save area corrupted
; callee-saved registers on return (SIGBUS/SIGSEGV), so every function here
; follows that layout (none of these need stack locals, since the scan
; buffer is static, but the convention is kept for consistency).
; ============================================================================

default rel

%define IDXSCAN_BUFRECS 4096
%define IDXSCAN_BUFBYTES (IDXSCAN_BUFRECS*48)

extern store_append_shared
extern store_append_shared_nolock

section .text

; ----------------------------------------------------------------------------
; idxscan_all_present(long lo, long hi)   (rdi, rsi)  -> rax: 1 if every
;   height in [lo,hi] has a non-zero index.dat record, else 0 (including
;   "index.dat missing/short"). lo>hi (empty range) is vacuously true,
;   matching the C loop's "for(k=lo;k<=hi;k++)" never executing.
; ----------------------------------------------------------------------------
global idxscan_all_present
idxscan_all_present:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14, rdi              ; lo
    mov  r15, rsi               ; hi
    cmp  r14, r15
    jg   .trivial_true
    lea  rdi, [rel idxscan_name]
    xor  esi, esi                ; O_RDONLY
    xor  edx, edx
    mov  eax, 2                  ; open
    syscall
    test rax, rax
    js   .absent
    mov  r12, rax                 ; fd
    mov  rax, r15
    sub  rax, r14
    inc  rax                      ; total records in range
    mov  rbx, rax                 ; remaining
    mov  r13, r14                 ; pos (absolute height)
.loop:
    cmp  rbx, 0
    jle  .allpresent
    mov  rax, IDXSCAN_BUFRECS
    cmp  rbx, rax
    cmovl rax, rbx                 ; take = min(remaining, BUFRECS)
    mov  r8, rax                   ; take
    mov  rdx, r8
    imul rdx, 48                    ; count = take*48
    mov  rax, r13
    imul rax, 48                    ; offset = pos*48
    mov  r10, rax
    mov  rdi, r12
    lea  rsi, [rel idxscan_buf]
    mov  eax, 17                     ; pread64
    syscall
    cmp  rax, rdx
    jne  .close_absent               ; short read -> not all present
    xor  r9, r9                       ; i = 0
.scanrec:
    cmp  r9, r8
    jge  .advance
    mov  rax, r9
    imul rax, 48
    lea  rax, [idxscan_buf + rax]        ; absolute base+index (no RIP form exists with an index register; this is what nasm emitted for the old `rel` spelling, byte-identical)
    mov  eax, [rax]
    test eax, eax
    jz   .close_absent
    inc  r9
    jmp  .scanrec
.advance:
    add  r13, r8
    sub  rbx, r8
    jmp  .loop
.allpresent:
    mov  rbx, 1
    jmp  .close_ret
.close_absent:
    xor  ebx, ebx
.close_ret:
    mov  rdi, r12
    mov  eax, 3                       ; close
    syscall
    mov  rax, rbx
    jmp  .ret
.absent:
    xor  eax, eax
    jmp  .ret
.trivial_true:
    mov  rax, 1
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; idxscan_tip(void)  -> rax: highest height with a non-zero record, or -1 if
;   none/empty/missing.
; ----------------------------------------------------------------------------
global idxscan_tip
idxscan_tip:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    lea  rdi, [rel idxscan_name]
    xor  esi, esi
    xor  edx, edx
    mov  eax, 2
    syscall
    test rax, rax
    js   .none
    mov  r12, rax                     ; fd
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 2                        ; SEEK_END
    mov  eax, 8
    syscall
    test rax, rax
    js   .close_none
    xor  edx, edx
    mov  rcx, 48
    div  rcx                            ; rax = n records
    mov  r13, rax                       ; end (exclusive)
.loop:
    cmp  r13, 0
    jle  .close_none
    mov  rax, IDXSCAN_BUFRECS
    cmp  r13, rax
    cmovl rax, r13
    mov  r8, rax                        ; take
    mov  r14, r13
    sub  r14, r8                        ; start = end - take
    mov  rdx, r8
    imul rdx, 48                         ; count
    mov  rax, r14
    imul rax, 48                         ; offset
    mov  r10, rax
    mov  rdi, r12
    lea  rsi, [rel idxscan_buf]
    mov  eax, 17
    syscall
    cmp  rax, rdx
    jne  .close_none                     ; short read within known size -- stop
    mov  r9, r8
    dec  r9                              ; i = take-1
.scanrec:
    cmp  r9, 0
    jl   .advance
    mov  rax, r9
    imul rax, 48
    lea  rax, [idxscan_buf + rax]        ; absolute base+index (no RIP form exists with an index register; this is what nasm emitted for the old `rel` spelling, byte-identical)
    mov  eax, [rax]
    test eax, eax
    jnz  .found
    dec  r9
    jmp  .scanrec
.advance:
    mov  r13, r14                        ; end = start; try the previous block
    jmp  .loop
.found:
    mov  rbx, r14
    add  rbx, r9                          ; tip = start + i
    mov  rdi, r12
    mov  eax, 3
    syscall
    mov  rax, rbx
    jmp  .ret
.close_none:
    mov  rdi, r12
    mov  eax, 3
    syscall
.none:
    mov  rax, -1
.ret:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; idxscan_append_locked(st, hash[32], raw, len)   (rdi,rsi,rdx,rcx)
;   -> rax: height on success, -1 on error, -2 refused: the block's prev
;      field does not link to the current tip (incident #46's stale-duplicate
;      race; see the linkage gate below).
;
;   CONCURRENT-SAFE "append the next sequential block" for opportunistic
;   multi-process writers that do NOT pre-partition disjoint heights among
;   themselves (unlike dl_catchup's worker pool, which allocates disjoint
;   chunks via a shared atomic cursor and can safely call store_append_shared
;   with a caller-computed height). Two independent processes -- e.g. the
;   serve daemon's download worker and an inbound peer's forked serve child --
;   each occasionally appending "whatever the next block is" cannot safely
;   pre-compute a height outside the lock: two callers that both read a stale
;   view of the true tip could both decide on the SAME "next" height, and
;   store_append_shared's lock only serializes the byte-level write, not that
;   decision. This function closes that gap by making "read true tip, then
;   write" one atomic critical section: acquire the SAME flock
;   store_append_shared uses (st+40), determine the true current tip via
;   idxscan_tip() (robust to any pre-sized/zero-padded trailing region a
;   batch tool like dl_catchup may have left -- unlike a raw idx_len/48
;   read), then delegate the actual write to store_append_shared with that
;   height. flock(LOCK_EX) taken twice in a row by the same fd (once here,
;   again inside store_append_shared) is a harmless idempotent re-assertion;
;   store_append_shared's own LOCK_UN at the end is what actually releases
;   it, so the whole read-then-write sequence stays locked throughout.
;
;   On success, refreshes st's cached idx_len/tip_height (st+16/st+24)
;   directly from the height just written, rather than via store_reload
;   (whose idx_len/48-1 tip computation is NOT hole-aware and would be wrong
;   under the same pre-sized-region scenario this function exists to handle
;   correctly at write time).
; ----------------------------------------------------------------------------
global idxscan_append_locked
idxscan_append_locked:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x48           ; 32B tip-hash scratch at [rbp-0x48] (+ alignment)
    mov  r12, rdi            ; st
    mov  r13, rsi            ; hash
    mov  r14, rdx            ; raw
    mov  r15, rcx            ; len
    ; ---- acquire shared append lock (mirrors store_append_shared's own) ----
    mov  rdi, [r12+40]
    test rdi, rdi
    js   .noflock
    mov  eax, 73              ; flock
    mov  esi, 2               ; LOCK_EX
    syscall
.noflock:
    ; ---- true current tip under lock, hole-aware ----
    call idxscan_tip           ; -> rax = tip (-1 if empty)
    lea  rbx, [rax+1]          ; height = tip + 1 (callee-saved across the call below)
    ; ---- INCIDENT #46 linkage gate (2026-08-25): the block about to land at
    ; tip+1 must actually LINK to the tip. Without this, a keep-up leg whose
    ; sync pass started before a sibling stored the same block would append
    ; that block AGAIN at tip+1 -- prev not even linking -- which is exactly
    ; what happened live at height 964032: heights are assigned HERE at
    ; append time, while the leg's validation used its pass-start chain view.
    ; The check lives INSIDE this critical section (atomic with the height
    ; decision, both writers covered); store_append_shared itself stays
    ; check-free because parallel IBD legitimately writes disjoint,
    ; non-sequential heights with caller-computed positions.
    ;   rax = -2: refused, not-tip-linked (stale duplicate / competing block;
    ;             duplicates die here, competing branches stay the reorg
    ;             path's job -- reorg reconnects through the nolocked variant
    ;             under its own outer lock, unaffected).
    cmp  rax, -1
    je   .linked               ; empty store: genesis bootstrap, nothing to link
    imul rax, 48               ; index record offset = tip*48
    mov  rdi, [r12+8]           ; idx_fd
    lea  rsi, [rbp-0x48]         ; tip-hash scratch
    mov  edx, 32
    mov  r10, rax
    mov  eax, 17                  ; pread64: record starts with the 32B hash
    syscall
    cmp  rax, 32
    jne  .refuse                  ; unreadable tip record: refuse, never guess
    lea  rsi, [rbp-0x48]
    lea  rdi, [r14+4]              ; new block's prev field (header bytes 4..36)
    mov  ecx, 32
    repe cmpsb
    jne  .refuse
.linked:
    ; ---- delegate the actual write: store_append_shared(st, height, hash, raw, len) ----
    mov  rdi, r12
    mov  rsi, rbx
    mov  rdx, r13
    mov  rcx, r14
    mov  r8,  r15
    call store_append_shared
    cmp  rax, -1
    je   .ret                  ; error: lock already released by store_append_shared
    mov  dword [r12+24], eax   ; tip_height = height
    lea  rcx, [rax+1]
    imul rcx, 48
    mov  [r12+16], rcx         ; idx_len = (height+1)*48
    jmp  .ret
.refuse:
    ; not-tip-linked: release the lock we took (the success path's unlock
    ; happens inside store_append_shared, which we are not calling) and
    ; report -2. The store is untouched.
    mov  rdi, [r12+40]
    test rdi, rdi
    js   .refuse_done
    mov  eax, 73              ; flock
    mov  esi, 8               ; LOCK_UN
    syscall
.refuse_done:
    mov  rax, -2
.ret:
    add  rsp, 0x48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; idxscan_append_nolocked(st, hash[32], raw, len)   (rdi,rsi,rdx,rcx)
;   -> rax: height on success, -1 on error.   STAGE B.
;
;   idxscan_append_locked, MINUS all locking. For a caller that is ALREADY
;   holding the st+40 append flock across a longer critical section and must
;   not have it dropped underneath it.
;
;   The bug this exists to fix: idxscan_append_locked takes LOCK_EX itself and
;   delegates to store_append_shared, which unconditionally does LOCK_UN on the
;   way out of EVERY call. daemon/reorg.c needs the lock held across
;   pre-flight + disconnect + truncate + the entire reconnect loop; with the
;   plain function, the very first reconnected block's LOCK_UN would silently
;   release the reorg's own outer hold, leaving every remaining reconnect
;   append -- and the window between them -- unprotected against an inbound
;   serve child appending onto a half-rebuilt chain. Re-acquiring is a no-op
;   on Linux (flock is per-open-file-description, not counting), so only the
;   release had to be removed.
;
;   The read-true-tip-then-write sequence is still atomic FOR THIS CALLER,
;   because the caller holds the same lock the whole time -- which is a
;   stronger guarantee than idxscan_append_locked's own per-call critical
;   section, not a weaker one. Calling this WITHOUT already holding that lock
;   is a bug; there is no way for it to check.
;
;   Register/stack layout, tip computation and st+16/st+24 refresh are
;   otherwise identical to idxscan_append_locked -- see that function's header
;   for the rationale behind each.
; ----------------------------------------------------------------------------
global idxscan_append_nolocked
idxscan_append_nolocked:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi            ; st
    mov  r13, rsi            ; hash
    mov  r14, rdx            ; raw
    mov  r15, rcx            ; len
    ; ---- true current tip, hole-aware (caller's lock is already held) ----
    call idxscan_tip           ; -> rax = tip (-1 if empty)
    lea  rbx, [rax+1]          ; height = tip + 1 (callee-saved across the call below)
    mov  rdi, r12
    mov  rsi, rbx
    mov  rdx, r13
    mov  rcx, r14
    mov  r8,  r15
    call store_append_shared_nolock
    cmp  rax, -1
    je   .nlret
    mov  dword [r12+24], eax   ; tip_height = height
    lea  rcx, [rax+1]
    imul rcx, 48
    mov  [r12+16], rcx         ; idx_len = (height+1)*48
.nlret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; idxscan_first_hole(long tip)   (rdi)  -> rax: first zero-record height in
;   [0,tip], or -1 if tip<0, file missing, or no hole (contiguous).
; ----------------------------------------------------------------------------
global idxscan_first_hole
idxscan_first_hole:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdi                        ; tip
    cmp  r15, 0
    jl   .none
    lea  rdi, [rel idxscan_name]
    xor  esi, esi
    xor  edx, edx
    mov  eax, 2
    syscall
    test rax, rax
    js   .none
    mov  r12, rax                         ; fd
    xor  r13, r13                          ; pos = 0
    mov  r14, r15
    inc  r14                               ; remaining = tip+1
.loop:
    cmp  r14, 0
    jle  .close_none                        ; scanned through tip, no hole -> contiguous
    mov  rax, IDXSCAN_BUFRECS
    cmp  r14, rax
    cmovl rax, r14
    mov  r8, rax                            ; take
    mov  rdx, r8
    imul rdx, 48                             ; count
    mov  rax, r13
    imul rax, 48                             ; offset
    mov  r10, rax
    mov  rdi, r12
    lea  rsi, [rel idxscan_buf]
    mov  eax, 17
    syscall
    cmp  rax, 0
    jl   .found_at_pos                       ; read error -> treat pos as the hole
    xor  edx, edx
    mov  ecx, 48
    div  ecx                                  ; eax = full records actually read (rax was byte count)
    mov  r11, rax                             ; full
    xor  r9, r9                                ; i = 0
.scanrec:
    cmp  r9, r11
    jge  .checkshort
    mov  rax, r9
    imul rax, 48
    lea  rax, [idxscan_buf + rax]        ; absolute base+index (no RIP form exists with an index register; this is what nasm emitted for the old `rel` spelling, byte-identical)
    mov  eax, [rax]
    test eax, eax
    jz   .found_at_i
    inc  r9
    jmp  .scanrec
.checkshort:
    cmp  r11, r8
    jl   .found_at_i                          ; short read -> first missing record is the hole
    add  r13, r8
    sub  r14, r8
    jmp  .loop
.found_at_i:
    mov  rbx, r13
    add  rbx, r9
    jmp  .close_found
.found_at_pos:
    mov  rbx, r13
.close_found:
    mov  rdi, r12
    mov  eax, 3
    syscall
    mov  rax, rbx
    jmp  .ret
.close_none:
    mov  rdi, r12
    mov  eax, 3
    syscall
.none:
    mov  rax, -1
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; idxscan_progress(long* out_tip, long* out_present)   (rdi, rsi)
;   Single forward pass: *out_tip = highest non-zero height seen (-1 if
;   none), *out_present = count of non-zero records. Matches
;   dlc_scan_progress exactly, including stopping at the first short/partial
;   read instead of treating a truncated trailing record as data.
; ----------------------------------------------------------------------------
global idxscan_progress
idxscan_progress:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x10          ; running_tip@[rbp-0x30], running_present@[rbp-0x38]
                             ; -- BELOW the 5-push (40-byte) save area, per the
                             ; documented convention (a slot overlapping the
                             ; save area corrupts callee-saved regs on return)
    mov  r12, rdi                           ; out_tip
    mov  r13, rsi                            ; out_present
    mov  qword [r12], -1
    mov  qword [r13], 0
    lea  rdi, [rel idxscan_name]
    xor  esi, esi
    xor  edx, edx
    mov  eax, 2
    syscall
    test rax, rax
    js   .ret
    mov  r14, rax                             ; fd
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 2                                ; SEEK_END
    mov  eax, 8
    syscall
    test rax, rax
    js   .close
    xor  edx, edx
    mov  rcx, 48
    div  rcx
    mov  r15, rax                               ; n = total records
    xor  rbx, rbx                               ; pos = 0
    mov  qword [rbp-0x30], -1                    ; running_tip
    mov  qword [rbp-0x38], 0                     ; running_present
.loop:
    cmp  rbx, r15
    jge  .flush
    mov  rax, r15
    sub  rax, rbx                                ; remaining
    mov  r9, IDXSCAN_BUFRECS
    cmp  rax, r9
    cmovg rax, r9                                 ; take = min(remaining, BUFRECS)
    mov  r8, rax                                   ; take
    mov  rdx, r8
    imul rdx, 48                                    ; count
    mov  rax, rbx
    imul rax, 48                                     ; offset
    mov  r10, rax
    mov  rdi, r14
    lea  rsi, [rel idxscan_buf]
    mov  eax, 17
    syscall
    cmp  rax, 0
    jle  .flush                                       ; nothing read -> stop
    mov  r11, rax                                      ; bytes read
    xor  edx, edx
    mov  rax, r11
    mov  ecx, 48
    div  ecx                                            ; eax = full records read
    mov  r9, rax                                         ; full (reuse r9, done with BUFRECS const)
    xor  rcx, rcx                                         ; i = 0
.scanrec:
    cmp  rcx, r9
    jge  .afterscan
    mov  rax, rcx
    imul rax, 48
    lea  rax, [idxscan_buf + rax]        ; absolute base+index (no RIP form exists with an index register; this is what nasm emitted for the old `rel` spelling, byte-identical)
    mov  eax, [rax]
    test eax, eax
    jz   .nextrec
    mov  rax, rbx
    add  rax, rcx
    mov  [rbp-0x30], rax                                  ; running tip
    mov  rax, [rbp-0x38]
    inc  rax
    mov  [rbp-0x38], rax                                  ; running present
.nextrec:
    inc  rcx
    jmp  .scanrec
.afterscan:
    add  rbx, r9                                          ; advance pos by full records read
    cmp  r9, r8
    jl   .flush                                           ; read fewer than requested -> EOF/short -> stop
    jmp  .loop
.flush:
    mov  rax, [rbp-0x30]
    mov  [r12], rax
    mov  rax, [rbp-0x38]
    mov  [r13], rax
.close:
    mov  rdi, r14
    mov  eax, 3
    syscall
.ret:
    add  rsp, 0x10
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .bss
align 16
idxscan_buf: resb IDXSCAN_BUFBYTES

section .rodata
idxscan_name: db "index.dat", 0

section .note.GNU-stack noalloc noexec nowrite progbits
