; ============================================================================
; bitcoin_utxo_store.asm -- PERSISTENT Unspent Transaction Output (UTXO) store.
;
; Extends the in-memory UTXO set (bitcoin_utxo.asm) with a crash-safe, reloadable
; on-disk layer, mirroring the proven append-only store/index pattern already
; used by bitcoin_store.asm (blk%05d.dat + positional index.dat + restart-resume):
;
;   utxo.dat  -- append-only OPERATION LOG (the ".dat" payload). Every mutation
;                is a framed record appended at the current log length:
;                  PUSH : [u32 magic][u8 op=1][3 pad][txid 32][u32 index]
;                         [u64 value][u16 slen][script slen]   (add an output)
;                  DEL  : [u32 magic][u8 op=2][3 pad][txid 32][u32 index]
;                         (spend/delete an output)
;                Replaying PUSH/DEL records in order reconstructs the exact
;                current UTXO set -- this is the durable source of truth.
;
;   utxo.idx  -- POSITIONAL INDEX / CHECKPOINT (the "index.dat" analog). A
;                serialized snapshot of every LIVE (unspent) record plus the
;                utxo.dat byte offset it covers and the live count:
;                  [u32 magic][u64 log_off][u64 n]
;                  then n records: [txid 32][u32 index][u64 value][u16 slen]
;                                  [script slen]
;                Written by utxo_store_sync() (a checkpoint). On reload the
;                snapshot is restored O(n) and only the log TAIL past log_off
;                is replayed -- so a crash between checkpoints is recovered by
;                replaying the remaining log records (restart-resume), exactly
;                like store_reload restoring tip/cur_file_pos from index.dat.
;
; The in-memory hash table is UNCHANGED (bitcoin_utxo.asm owns it); this module
; is a thin durable wrapper: every put/del writes the log first (WAL), then
; applies the same op in memory. Sync checkpoints the index; reload rebuilds.
;
; State struct (caller supplies, zeroed), offsets:
;   +0    qword log_fd        (utxo.dat fd, or -1)
;   +8    qword idx_fd        (utxo.idx fd, or -1; write fd for append)
;   +16   qword log_len       (bytes in utxo.dat)
;   +24   qword ckpt_log_off  (utxo.dat offset the current checkpoint covers)
;   +32   qword ckpt_n        (live records captured in the current checkpoint)
;
; Exports (System V AMD64):
;   long utxo_store_init(void* st)                          -> 1 ok / -1 err
;   long utxo_store_sync(void* st, void* u)                 -> 1 ok / -1 err
;   long utxo_store_reload(void* st, void* u)               -> records replayed, -1 err
;   long utxo_store_put(void* st, void* u, const u8 txid[32],
;                       u32 index, u64 value, const u8* script, u32 slen)
;                                                           -> utxo_put result (1/0/2) or -1
;   long utxo_store_del(void* st, void* u, const u8 txid[32], u32 index)
;                                                           -> utxo_del result (1/0) or -1
;   long utxo_store_count(void* st, void* u)                -> utxo_count(u)
;   long utxo_store_get(void* st, void* u, const u8 txid[32], u32 index,
;                       u64* value, u8** script, u32* slen) -> utxo_get result (1/0)
;   void utxo_store_close(void* st)                         -> fsync + close fds
;
; The in-memory table layout (bitcoin_utxo.asm) that this module reads/writes:
;   +0 qword n ; +8 qword mask ; +16 qword blob ; +24 qword blob_cap ;
;   +32 qword fill ; +40 slots (48B): [+0 qword blob_off][+8 u8 txid[32]]
;                                    [+40 u32 index][+44 qword _pad]
;   empty slot: index field == 0xFFFFFFFF
;   blob record at blob+off: [+0 u64 value][+8 u64 slen][+16 u8 script[slen]]
;
; FRAME RULE (as bitcoin_store.asm): for a function that pushes N callee-saved
; registers the save area occupies [rbp-8 .. -(8*N)]. ALL stack locals live
; strictly BELOW it, at [rbp-(8*N+8)] and lower -- never inside the save area,
; or the saved registers (callee-saved! restored on return) get clobbered.
; Also: the `syscall` instruction clobbers rcx and r11 -- never hold a live
; value in rcx/r11 across a syscall; keep long-lived values in callee-saved
; regs (rbx,r12-r15) or the stack frame.
; ============================================================================

default rel
section .text

MAGIC_LOG equ 0x5554584F      ; "UTXO" little-endian in a dword
OP_PUSH   equ 1
OP_DEL    equ 2
MAGIC_IDX equ 0x55545849      ; "UTXI"
PUSH_HDR  equ 54              ; header bytes before script for a PUSH record
DEL_SIZE  equ 44              ; DEL record fully fixed size
IDX_HDR   equ 20              ; utxo.idx header: magic(4)+log_off(8)+n(8)

logname: db "utxo.dat",0
idxname: db "utxo.idx",0

; external in-memory UTXO primitives (bitcoin_utxo.asm)
extern utxo_put
extern utxo_del
extern utxo_get

; ============================================================================
; mac_memcpy(dst=rdi, src=rsi, n=rdx) -- trivial byte copy (local)
; ============================================================================
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

; ============================================================================
; mac_read_exact(fd=rdi, buf=rsi, len=rdx) -> rax 0 ok / -1 (EOF or short read)
;   Loops until 'len' bytes are read; uses and advances the fd position.
; ============================================================================
mac_read_exact:
    push rbx
    push r12
    push r13
    mov  r12, rdi          ; fd
    mov  r13, rsi          ; buf
    mov  rbx, rdx          ; remaining len
.re:
    test rbx, rbx
    jz   .ok
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rbx
    xor  eax, eax          ; read
    syscall
    test rax, rax
    jz   .bad              ; EOF -> failure
    js   .bad              ; error -> failure
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

; ============================================================================
; mac_wr_log(st=r12, buf=r13, len=r14) -> rax 0 ok / -1
;   Appends 'len' bytes at st->log_len to the log fd, advancing st->log_len.
;   Internal: passes args in callee-saved regs (non-ABI). Preserves r12/r13/r14.
;
;   PERFORMANCE: no longer lseek()s before every write(). This fd is written
;   ONLY here, append-only, single-writer -- a successful write() already
;   advances the kernel's file offset by exactly the bytes just written,
;   which is precisely where log_len (just incremented by the same amount)
;   says the next write belongs. The seek was therefore redundant on every
;   call after the first. The one place that matters is utxo_store_reload:
;   it measures the log's size via lseek(log_fd, 0, SEEK_END) on this SAME
;   fd, which as a side effect parks the fd exactly at log_len before any
;   post-reload mac_wr_log call -- and reload's own replay of the WAL tail
;   reads through a SEPARATE fd it opens for itself, so it never disturbs
;   this one. Removing the lseek cuts the syscall count for the WAL append
;   path roughly in half (this was a measured bottleneck: ~2 syscalls per
;   utxo_store_put, up to 3.78B times across a full-archive replay).
; ============================================================================
mac_wr_log:
    mov  rdi, [r12]        ; log_fd
    mov  rsi, r13
    mov  rdx, r14
    mov  eax, 1            ; write
    syscall
    cmp  rax, r14
    jne  .wf
    add  qword [r12+16], r14
    xor  eax, eax
    ret
.wf:
    mov  rax, -1
    ret

; ============================================================================
; mac_fsync(fd=rdi) -> rax 0 / -1
; ============================================================================
mac_fsync:
    mov  eax, 74          ; fsync
    syscall
    ret

; ============================================================================
; utxo_store_init(st) -> 1 ok / -1
;   Opens (creates) utxo.dat and utxo.idx read/write; resets store state.
;   Does NOT touch the caller's in-memory table (call utxo_init separately).
; ============================================================================
global utxo_store_init
utxo_store_init:
    push rbp
    mov  rbp, rsp
    push r12                ; 1 push -> save area [rbp-8..-0x10] (r12@-8)
    mov  r12, rdi
    lea  rdi, [rel logname]
    mov  esi, 2 | 0x40
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .fail
    mov  [r12+0], rax        ; log_fd
    lea  rdi, [rel idxname]
    mov  esi, 2 | 0x40
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .fail2
    mov  [r12+8], rax        ; idx_fd
    mov  qword [r12+16], 0   ; log_len = 0
    mov  qword [r12+24], 0   ; ckpt_log_off = 0
    mov  qword [r12+32], 0   ; ckpt_n = 0
    mov  rax, 1
    pop  r12
    pop  rbp
    ret
.fail2:
    mov  rdi, [r12]
    mov  eax, 3
    syscall
.fail:
    mov  rax, -1
    pop  r12
    pop  rbp
    ret

; ============================================================================
; utxo_store_put(st, u, txid, index, value, script, slen)
;   rdi=st rsi=u rdx=txid rcx=index(dword) r8=value r9=script [rbp+16]=slen(dword)
;   5 pushes -> save area [rbp-8 .. -0x40]; locals at <= -0x48.
;   r12=st r15=u (stable) rbx=txid; r13/r14 transient for mac_wr_log.
; ============================================================================
global utxo_store_put
utxo_store_put:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x100
    mov  r12, rdi           ; st
    mov  r15, rsi           ; u
    mov  rbx, rdx           ; txid
    mov  [rbp-0x48], ecx    ; index
    mov  [rbp-0x50], r8     ; value
    mov  [rbp-0x58], r9     ; script
    mov  rax, [rbp+16]
    mov  [rbp-0x60], rax    ; slen
    ; ---- build PUSH header (54 bytes) at rbp-0xB0 ----
    mov  dword [rbp-0xB0], MAGIC_LOG
    mov  byte  [rbp-0xB0+4], OP_PUSH
    mov  byte  [rbp-0xB0+5], 0
    mov  byte  [rbp-0xB0+6], 0
    mov  byte  [rbp-0xB0+7], 0
    lea  rdi, [rbp-0xB0+8]
    mov  rsi, rbx
    mov  rdx, 32
    call mac_memcpy
    mov  eax, [rbp-0x48]
    mov  [rbp-0xB0+40], eax
    mov  rax, [rbp-0x50]
    mov  [rbp-0xB0+44], rax
    mov  ax, [rbp-0x60]
    mov  [rbp-0xB0+52], ax
    ; ---- append header to log ----
    lea  r13, [rbp-0xB0]
    mov  r14, PUSH_HDR
    call mac_wr_log
    test rax, rax
    jnz  .fail
    ; ---- append script if any ----
    mov  rax, [rbp-0x60]
    test rax, rax
    jz   .no_script
    mov  r13, [rbp-0x58]
    mov  r14, rax
    call mac_wr_log
    test rax, rax
    jnz  .fail
.no_script:
    ; ---- apply in memory (utxo_put(u, txid, index, value, script, slen)) ----
    mov  rdi, r15           ; u
    mov  rsi, rbx           ; txid
    mov  edx, [rbp-0x48]
    mov  rcx, [rbp-0x50]
    mov  r8,  [rbp-0x58]
    mov  r9,  [rbp-0x60]
    call utxo_put
    jmp  .done
.fail:
    mov  rax, -1
.done:
    add  rsp, 0x100
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_store_del(st, u, txid, index) -> 1 deleted / 0 miss / -1 err
;   rdi=st rsi=u rdx=txid rcx=index (dword)
;   5 pushes -> save area [rbp-8 .. -0x40]; locals at <= -0x48.
; ============================================================================
global utxo_store_del
utxo_store_del:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x100
    mov  r12, rdi           ; st
    mov  r15, rsi           ; u
    mov  rbx, rdx           ; txid
    mov  [rbp-0x48], ecx    ; index
    ; ---- build DEL record (44 bytes) at rbp-0xB0 ----
    mov  dword [rbp-0xB0], MAGIC_LOG
    mov  byte  [rbp-0xB0+4], OP_DEL
    mov  byte  [rbp-0xB0+5], 0
    mov  byte  [rbp-0xB0+6], 0
    mov  byte  [rbp-0xB0+7], 0
    lea  rdi, [rbp-0xB0+8]
    mov  rsi, rbx
    mov  rdx, 32
    call mac_memcpy
    mov  eax, [rbp-0x48]
    mov  [rbp-0xB0+40], eax
    ; ---- append to log ----
    lea  r13, [rbp-0xB0]
    mov  r14, DEL_SIZE
    call mac_wr_log
    test rax, rax
    jnz  .fail
    ; ---- apply in memory (utxo_del(u, txid, index)) ----
    mov  rdi, r15           ; u
    mov  rsi, rbx           ; txid
    mov  edx, [rbp-0x48]
    call utxo_del
    jmp  .done
.fail:
    mov  rax, -1
.done:
    add  rsp, 0x100
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_store_count(st, u) -> utxo_count(u)
; ============================================================================
global utxo_store_count
utxo_store_count:
    mov  rax, [rsi]
    ret

; ============================================================================
; utxo_store_get(st, u, txid, index, &value, &script, &slen) -> utxo_get result
;   rdi=st rsi=u rdx=txid rcx=index(dword) r8=&value r9=&script [rsp+8]=&slen
;   Clean tail-call into utxo_get (no frame locals at all). st is unused.
; ============================================================================
global utxo_store_get
utxo_store_get:
    mov  r10, [rsp+8]     ; &slen (7th arg; return addr is at [rsp])
    mov  rdi, rsi         ; u
    mov  rsi, rdx         ; txid
    mov  rdx, rcx         ; index
    mov  rcx, r8          ; &value
    mov  r8,  r9          ; &script
    mov  r9,  r10         ; &slen
    jmp  utxo_get         ; tail call (utxo_get returns to our caller)
    ; (no ret here -- utxo_get's ret returns to the original caller)

; ============================================================================
; utxo_store_clear(u=rdi) -- reset the in-memory table to empty, reusing its
;   existing mask/blob/blob_cap pointers (mirrors utxo_init's empty scan).
;   2 pushes -> save area [rbp-8..-0x20]; no stack locals used.
; ============================================================================
utxo_store_clear:
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
.cl:
    test r13, r13
    jz   .cd
    mov  dword [rdi+40], 0xFFFFFFFF
    add  rdi, 48
    dec  r13
    jmp  .cl
.cd:
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; utxo_store_sync(st, u) -> 1 ok / -1
;   Checkpoints the current live UTXO set into utxo.idx (truncate + rewrite),
;   records st->ckpt_log_off = log_len and st->ckpt_n = live count, then
;   fsyncs BOTH utxo.idx and utxo.dat so the checkpoint + WAL are durable.
;
;   5 pushes -> save area [rbp-8..-0x40]; locals at <= -0x48.
;   r12=st r13=u r14=idx fd r15=slot index, rbx=scratch.
;   Slot base is RECOMPUTED from r15 before every syscall (syscall clobbers
;   rcx/r11), never cached in a caller-saved reg across writes.
; ============================================================================
global utxo_store_sync
utxo_store_sync:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x100
    mov  r12, rdi
    mov  r13, rsi
    ; open utxo.idx O_WRONLY|O_CREAT|O_TRUNC 0644
    lea  rdi, [rel idxname]
    mov  esi, 1 | 0x40 | 0x200
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .fail
    mov  r14, rax           ; idx fd
    ; header @ rbp-0x60: magic(4) log_off(8) n(8) = 20 bytes
    mov  dword [rbp-0x60], MAGIC_IDX
    mov  rax, [r12+16]
    mov  [rbp-0x5c], rax
    mov  rax, [r13]
    mov  [rbp-0x54], rax
    mov  rdi, r14
    lea  rsi, [rbp-0x60]
    mov  rdx, IDX_HDR
    mov  eax, 1
    syscall
    cmp  rax, IDX_HDR
    jne  .fclose
    ; walk slots: for each live slot write [txid32][index4][value8][slen2][script]
    mov  r15, 0
.slot_loop:
    mov  rax, [r13+8]       ; mask
    cmp  r15, rax
    ja   .done_slots
    ; slot base = u + 40 + r15*48
    mov  rax, r15
    imul rax, rax, 48
    lea  r10, [r13+40]
    add  r10, rax           ; r10 = slot base (r10 preserved by syscall)
    mov  edx, [r10+40]      ; index field
    cmp  edx, 0xFFFFFFFF
    je   .slot_next
    ; write txid[32] from slot+8
    mov  rdi, r14
    lea  rsi, [r10+8]
    mov  rdx, 32
    mov  eax, 1
    syscall
    cmp  rax, 32
    jne  .fclose
    ; outpoint index u32 @ slot+40
    mov  eax, r15d
    imul eax, eax, 48
    lea  r10, [r13+40]
    add  r10, rax
    mov  edx, [r10+40]
    mov  [rbp-0x48], edx
    mov  rdi, r14
    lea  rsi, [rbp-0x48]
    mov  rdx, 4
    mov  eax, 1
    syscall
    cmp  rax, 4
    jne  .fclose
    ; blob record = blob + slot->blob_off
    mov  eax, r15d
    imul eax, eax, 48
    lea  r10, [r13+40]
    add  r10, rax
    mov  rax, [r10]         ; blob_off (qword)
    mov  rdx, [r13+16]      ; blob base
    add  rax, rdx           ; record
    mov  rbx, [rax]         ; value
    mov  [rbp-0x50], rbx
    mov  rbx, [rax+8]       ; slen (u64; only low u16 persisted)
    mov  [rbp-0x58], rbx
    ; write value (8 bytes)
    mov  rdi, r14
    lea  rsi, [rbp-0x50]
    mov  rdx, 8
    mov  eax, 1
    syscall
    cmp  rax, 8
    jne  .fclose
    ; write slen (2 bytes, low u16)
    mov  rdi, r14
    lea  rsi, [rbp-0x58]
    mov  rdx, 2
    mov  eax, 1
    syscall
    cmp  rax, 2
    jne  .fclose
    ; write script slen bytes from record+16
    mov  rbx, [rbp-0x58]
    test rbx, rbx
    jz   .slot_next
    mov  eax, r15d
    imul eax, eax, 48
    lea  r10, [r13+40]
    add  r10, rax
    mov  rax, [r10]         ; blob_off
    mov  rdx, [r13+16]
    add  rax, rdx
    add  rax, 16            ; script ptr
    mov  rdi, r14
    mov  rsi, rax
    mov  rdx, rbx
    mov  eax, 1
    syscall
    cmp  rax, rbx
    jne  .fclose
.slot_next:
    inc  r15
    jmp  .slot_loop
.done_slots:
    ; record checkpoint in state
    mov  rax, [r12+16]
    mov  [r12+24], rax      ; ckpt_log_off = log_len
    mov  rax, [r13]
    mov  [r12+32], rax      ; ckpt_n = n
    ; fsync idx then log
    mov  rdi, r14
    call mac_fsync
    mov  rdi, [r12]
    call mac_fsync
    mov  rdi, r14
    mov  eax, 3
    syscall
    mov  rax, 1
    add  rsp, 0x100
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.fclose:
    mov  rdi, r14
    mov  eax, 3
    syscall
.fail:
    mov  rax, -1
    add  rsp, 0x100
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_store_reload(st, u) -> records replayed / -1 err
;   (1) resets the in-memory table empty; (2) measures utxo.dat size and sets
;       st->log_len; (3) if utxo.idx is a valid checkpoint, loads the snapshot
;       (O(n)); otherwise starts from log offset 0; (4) replays the WAL tail
;       from st->ckpt_log_off to end, applying PUSH/DEL in order (restart-resume).
;
;   5 pushes -> save area [rbp-8..-0x40]; locals at <= -0x48.
;   Buffer layout (all safely in the 0x160+65536 frame, non-overlapping):
;     [rbp-0x100]    46-byte fixed record buffer: txid@-0x100 idx@-0xE0
;                    value@-0xDC slen(u16)@-0xD4
;     [rbp-0x10158]  script scratch (65536+ bytes of room, growing UP toward
;                    rbp -- must stay far from rbp so a max-size script can
;                    never reach it; see the frame-size comment below)
;     [rbp-0x150]    consumed-offset counter
;     [rbp-0x48]     slen local (qword)
;   r12=st r13=u r14=read fd r15=replayed counter rbx=log end offset.
; ============================================================================
global utxo_store_reload
utxo_store_reload:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; frame enlarged from the original 0x160. The script scratch buffer used
    ; to live at [rbp-0x140], a mere 0x140 (320) bytes from rbp -- but a
    ; script's slen can be up to 65535 (SCRIPT_MAX_BYTES-1), and the buffer
    ; is filled by copying FORWARD (increasing addresses, i.e. TOWARD rbp).
    ; Any script over ~320 bytes -- routine for real Bitcoin scripts -- wrote
    ; straight through the saved rbp and the return address into the
    ; CALLER's frame. Merely growing the frame downward (the first attempted
    ; fix) did nothing, since that only adds room on the far side of the
    ; buffer, away from the direction it actually overflows. The real fix:
    ; the buffer was RELOCATED to [rbp-0x10158], near the bottom of this
    ; enlarged frame, so a max-size copy (ending at [rbp-0x159]) still lands
    ; nowhere near rbp. This never showed up in testing because every test
    ; fixture used tiny (<320-byte) scripts; the real replay's WAL has at
    ; least one script with slen=1690, which crashes it reliably.
    sub  rsp, 0x160+65536
    mov  r12, rdi
    mov  r13, rsi
    ; ---- (1) reset table ----
    mov  rdi, r13
    call utxo_store_clear
    ; ---- (2) measure log size ----
    mov  rdi, [r12]
    xor  esi, esi
    mov  edx, 2
    mov  eax, 8
    syscall
    test rax, rax
    jl   .fail
    mov  [r12+16], rax
    mov  rbx, rax           ; log end offset
    ; ---- (3) try to load checkpoint ----
    mov  qword [r12+24], 0
    mov  qword [r12+32], 0
    lea  rdi, [rel idxname]
    xor  esi, esi
    mov  eax, 2
    syscall
    test rax, rax
    jl   .no_ckpt
    mov  r14, rax
    ; checkpoint header @ [rbp-0xB0]: magic@-0xB0 log_off@-0xac n@-0xa4
    mov  rdi, r14
    lea  rsi, [rbp-0xB0]
    mov  rdx, IDX_HDR
    call mac_read_exact
    test rax, rax
    jnz  .ckpt_bad
    mov  eax, [rbp-0xB0]
    cmp  eax, MAGIC_IDX
    jne  .ckpt_bad
    mov  rax, [rbp-0xac]
    mov  [r12+24], rax      ; ckpt_log_off
    mov  rax, [rbp-0xa4]
    mov  [r12+32], rax      ; ckpt_n
    test rax, rax
    jz   .ckpt_done
    ; load 'n' snapshot records: [txid32][idx4][value8][slen2][script]
    mov  r15, 0
.ckpt_loop:
    mov  rax, [r12+32]
    cmp  r15, rax
    jae  .ckpt_done
    ; read 46 fixed bytes into [rbp-0x100..]
    mov  rdi, r14
    lea  rsi, [rbp-0x100]   ; txid@-0x100 idx@-0xE0 value@-0xDC slen@-0xD4
    mov  rdx, 46
    call mac_read_exact
    test rax, rax
    jnz  .ckpt_done         ; truncated snapshot -> stop gracefully
    movzx eax, word [rbp-0xD4]
    ; store the FULL 64-bit rax (not eax) -- movzx already zero-extends the
    ; u16 into all of rax, but a 32-bit `mov [.],eax` only overwrites the
    ; low 4 bytes of this 8-byte slot, leaving stale stack garbage in the
    ; high 4 bytes; utxo_put's slen arg is loaded back as a 64-bit qword
    ; below (r9), so that garbage corrupted the value it saw -- confirmed
    ; via a real replay where it made utxo_put's blob-capacity check see a
    ; huge garbage size and spuriously report "table full" (2) after
    ; already writing the slot's txid/index, leaving a phantom "occupied"
    ; slot with no value/script -- a real UTXO-lookup correctness bug.
    mov  [rbp-0x48], rax    ; slen
    mov  rdx, rax
    test rdx, rdx
    jz   .ckpt_put
    ; read script into [rbp-0x10158] scratch
    mov  rdi, r14
    lea  rsi, [rbp-0x10158]
    call mac_read_exact
    test rax, rax
    jnz  .ckpt_done
.ckpt_put:
    mov  rdi, r13
    lea  rsi, [rbp-0x100]   ; txid
    mov  edx, [rbp-0xE0]    ; index
    mov  rcx, [rbp-0xDC]    ; value
    lea  r8,  [rbp-0x10158]   ; script
    mov  r9,  [rbp-0x48]    ; slen
    call utxo_put
    inc  r15
    jmp  .ckpt_loop
.ckpt_done:
    mov  rdi, r14
    mov  eax, 3
    syscall
    jmp  .replay
.ckpt_bad:
    mov  rdi, r14
    mov  eax, 3
    syscall
    mov  qword [r12+24], 0
    mov  qword [r12+32], 0
    jmp  .replay
.no_ckpt:
    mov  qword [r12+24], 0
    mov  qword [r12+32], 0
.replay:
    ; ---- (4) replay WAL tail from ckpt_log_off to log_len ----
    mov  rax, [r12+24]
    mov  [rbp-0x150], rax   ; consumed-offset counter
    lea  rdi, [rel logname]
    xor  esi, esi
    mov  eax, 2
    syscall
    test rax, rax
    jl   .fail
    mov  r14, rax
    mov  rdi, r14
    mov  rsi, [r12+24]
    xor  edx, edx
    mov  eax, 8
    syscall
    mov  r15, 0            ; replayed count
.rep_loop:
    mov  rax, [rbp-0x150]  ; consumed
    cmp  rax, rbx          ; vs log end
    jae  .rep_done
    ; read 8-byte prefix [magic u32][op u8][pad3] into [rbp-0x100]
    mov  rdi, r14
    lea  rsi, [rbp-0x100]
    mov  rdx, 8
    call mac_read_exact
    test rax, rax
    jnz  .rep_close
    add  qword [rbp-0x150], 8
    mov  al, [rbp-0x100+4] ; op
    cmp  al, OP_PUSH
    je   .rep_push
    cmp  al, OP_DEL
    je   .rep_del
    jmp  .rep_close        ; unknown op -> stop replaying
.rep_push:
    ; read txid[32]+idx4+value8+slen2 = 46 bytes into [rbp-0x100..]
    mov  rdi, r14
    lea  rsi, [rbp-0x100]  ; txid@-0x100 idx@-0xE0 value@-0xDC slen@-0xD4
    mov  rdx, 46
    call mac_read_exact
    test rax, rax
    jnz  .rep_close
    add  qword [rbp-0x150], 46
    movzx eax, word [rbp-0xD4]
    ; see the identical fix + explanation in .ckpt_loop above -- same bug,
    ; same fix (store rax, not eax, so the slot's high 4 bytes are zeroed).
    mov  [rbp-0x48], rax   ; slen
    mov  rdx, rax
    test rdx, rdx
    jz   .rep_push_apply
    ; read script into [rbp-0x10158] scratch
    mov  rdi, r14
    lea  rsi, [rbp-0x10158]
    call mac_read_exact
    test rax, rax
    jnz  .rep_close
.rep_push_apply:
    mov  rdi, r13
    lea  rsi, [rbp-0x100]  ; txid
    mov  edx, [rbp-0xE0]   ; index
    mov  rcx, [rbp-0xDC]   ; value
    lea  r8,  [rbp-0x10158]  ; script
    mov  r9,  [rbp-0x48]   ; slen
    call utxo_put
    mov  rax, [rbp-0x48]
    add  qword [rbp-0x150], rax   ; consume script bytes
    inc  r15
    jmp  .rep_loop
.rep_del:
    ; read txid[32]+idx4 = 36 bytes into [rbp-0x100..]
    mov  rdi, r14
    lea  rsi, [rbp-0x100]
    mov  rdx, 36
    call mac_read_exact
    test rax, rax
    jnz  .rep_close
    add  qword [rbp-0x150], 36
    mov  rdi, r13
    lea  rsi, [rbp-0x100]
    mov  edx, [rbp-0xE0]   ; index @ -0x100+32 = -0xE0
    call utxo_del
    inc  r15
    jmp  .rep_loop
.rep_close:
    mov  rdi, r14
    mov  eax, 3
    syscall
    mov  rax, r15
    add  rsp, 0x160+65536
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.rep_done:
    jmp  .rep_close
.fail:
    mov  rax, -1
    add  rsp, 0x160+65536
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; utxo_store_close(st) -> void (fsync both then close)
; ============================================================================
global utxo_store_close
utxo_store_close:
    push rbp
    mov  rbp, rsp
    push r12
    mov  r12, rdi
    mov  rdi, [r12]
    cmp  rdi, -1
    je   .skip_log
    call mac_fsync
    mov  rdi, [r12]
    mov  eax, 3
    syscall
.skip_log:
    mov  rdi, [r12+8]
    cmp  rdi, -1
    je   .skip_idx
    call mac_fsync
    mov  rdi, [r12+8]
    mov  eax, 3
    syscall
.skip_idx:
    pop  r12
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
