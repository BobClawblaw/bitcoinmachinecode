; ============================================================================
; bitcoin_undo.asm -- per-block undo-data structure, 100% AI-generated x86-64
; assembly (NASM, ELF64). Port of daemon/undo_log.c (2026-08-24, phase 1 of
; the C->asm conversion); undo_log.c stays in-tree as the differential oracle
; (tests/test_undo_asm_diff.c compares the two function by function, byte by
; byte, on the same op streams).
;
; CONTRACT (identical to the C -- daemon/undo_log.c's header has the whys):
;   Record, appended to per-height file "undo_<height>.dat":
;     txid[32] | index(u32 LE) | value(u64 LE) | utxo_height(u32 LE) |
;     is_coinbase(u8) | script_len(u16 LE) | script[script_len]
;   51-byte header + script, back to back, no file-level framing.
;   `height` in the FILE NAME is the consuming block's height; the `height`
;   FIELD is the spent UTXO's own creation height. Do not conflate (the
;   100-block maturity rule depends on the distinction).
;
;   undo_rec_t (undo_load's out array) -- offsets pinned by offsetof() on the
;   C struct, NOT re-derived by hand:
;     txid @0, index @32, value @40, height @48, is_coinbase @52, slen @54,
;     script @56, stride 10056.
;
; Exports (System V AMD64; every function returns long in rax):
;   undo_append_record(height, txid, index, value, utxo_height, is_coinbase,
;                      script, slen)                          -> 1 / -1
;   undo_load(height, out, max_recs)                          -> n / -1
;   undo_replay(height, cb, ctx)                              -> n / -1
;   undo_replay_tolerant(height, cb, ctx, &torn)              -> n / -1
;   undo_discard(height)                                      -> 1 / 0
;   undo_prune_from(from_height, tip_height, window, max_scan)-> cursor
;   undo_prune(tip_height, window)                            -> removed
;
;   cb(ctx, txid, index, value, height, is_coinbase, script, slen) -> int;
;   a cb returning 0 aborts the replay with -1 (a half-restored UTXO set
;   must surface as an error, never as a silently short success). cb == NULL
;   is allowed and just counts records, exactly like the C.
;
; DISCIPLINE NOTE (written after this file's first two drafts): every export
; here receives `height` in rdi, and every export builds a path, which needs
; rdi as the out pointer -- so the FIRST body instruction of every function
; moves height out of rdi (into rbx or another callee-saved). Both aborted
; drafts clobbered rdi before saving it. If you edit an argument order here,
; re-check that rule first.
;
; THREAD SAFETY: undo_replay_impl streams through ONE process-global script
; buffer (.bss), exactly like the C's `static u8 script[...]` -- the replay
; paths are boot recovery and reorg disconnect, both single-threaded. Same
; contract, same caveat, now written down where the buffer lives.
;
; Raw syscalls (open 2, read 0, write 1, close 3, unlink 87), matching
; bitcoin_store.asm's no-libc style. A failed open returns -errno in rax, so
; every "fd < 0" check is a sign test. The kernel clobbers only rcx and r11;
; anything that must survive a syscall sits in a callee-saved reg or the
; frame.
; ============================================================================

BITS 64
DEFAULT REL

%define SYS_read    0
%define SYS_write   1
%define SYS_open    2
%define SYS_close   3
%define SYS_unlink  87

%define O_APPEND_CREAT_WRONLY 0x441      ; O_WRONLY|O_CREAT|O_APPEND
%define O_RDONLY    0
%define MODE_0644   420                  ; 0o644

%define UNDO_MAX_SCRIPT 10000
%define HDR_BYTES   51

%define REC_INDEX   32
%define REC_VALUE   40
%define REC_HEIGHT  48
%define REC_CB      52
%define REC_SLEN    54
%define REC_SCRIPT  56
%define REC_STRIDE  10056

section .bss
align 16
replay_script: resb UNDO_MAX_SCRIPT      ; the streaming reader's one record buffer

section .text

; ----------------------------------------------------------------------------
; undo_path_build: rdi = out (>= 64 bytes), rsi = height (signed long)
; Writes "undo_<decimal>.dat\0" -- byte-identical to the oracle's
; snprintf("undo_%ld.dat"), including the '-' of a negative height (callers
; never pass one, but the differential covers it, so the twin must match).
; Preserves rdi and every callee-saved register; clobbers rax,rcx,rdx,r8,r9,
; r10 and rsi. Makes no calls.
; ----------------------------------------------------------------------------
undo_path_build:
    mov  dword [rdi], 0x6f646e75         ; "undo"
    mov  byte  [rdi+4], 0x5f             ; "_"
    lea  r8, [rdi+5]                     ; write cursor
    mov  rax, rsi
    test rax, rax
    jns  .abs
    mov  byte [r8], '-'
    inc  r8
    neg  rax
.abs:
    sub  rsp, 32                         ; digit scratch; no calls below
    lea  r9, [rsp]
    xor  ecx, ecx
    mov  r10, 10
.dig:
    xor  edx, edx
    div  r10                             ; rax /= 10, rdx = next digit
    add  dl, '0'
    mov  [r9+rcx], dl
    inc  ecx
    test rax, rax
    jnz  .dig
.emit:                                   ; digits were generated reversed
    dec  ecx
    mov  dl, [r9+rcx]
    mov  [r8], dl
    inc  r8
    test ecx, ecx
    jnz  .emit
    add  rsp, 32
    mov  dword [r8], 0x7461642e          ; ".dat"
    mov  byte  [r8+4], 0
    ret

; ----------------------------------------------------------------------------
; undo_append_record(height, txid, index, value, utxo_height, is_coinbase,
;                    script, slen) -> 1 ok / -1 err
;   rdi=height rsi=txid edx=index rcx=value r8d=utxo_height r9b=is_coinbase
;   [rbp+16]=script [rbp+24]=slen (u16 in a 64-bit arg slot)
; Frame: push rbp + 3 pushes (saves at [rbp-0x08..-0x18]), sub rsp,0xa8 ->
; rsp = rbp-0xc0 and 0 mod 16 at every call. Locals: scalars at
; [rbp-0x20..-0x31], path[64] at [rbp-0x80..-0x40), hdr[51] at
; [rbp-0xc0..-0x8d) -- strictly below the path buffer and the save area.
; ----------------------------------------------------------------------------
global undo_append_record
undo_append_record:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0xa8
    mov  rbx, rdi                        ; height OUT of rdi first (see header)
    mov  [rbp-0x28], rsi                 ; txid
    mov  dword [rbp-0x2c], edx           ; index
    mov  [rbp-0x20], rcx                 ; value
    mov  dword [rbp-0x30], r8d           ; utxo_height
    mov  byte  [rbp-0x31], r9b           ; is_coinbase

    lea  rdi, [rbp-0x80]
    mov  rsi, rbx
    call undo_path_build

    lea  rdi, [rbp-0x80]
    mov  esi, O_APPEND_CREAT_WRONLY
    mov  edx, MODE_0644
    mov  eax, SYS_open
    syscall
    test rax, rax
    js   .fail                           ; C: fd < 0 -> return -1
    mov  r12, rax                        ; fd

    ; build hdr[51] at [rbp-0xc0]
    mov  rsi, [rbp-0x28]
    mov  rax, [rsi]
    mov  [rbp-0xc0], rax
    mov  rax, [rsi+8]
    mov  [rbp-0xb8], rax
    mov  rax, [rsi+16]
    mov  [rbp-0xb0], rax
    mov  rax, [rsi+24]
    mov  [rbp-0xa8], rax
    mov  eax, [rbp-0x2c]
    mov  [rbp-0xc0+32], eax              ; index
    mov  rax, [rbp-0x20]
    mov  [rbp-0xc0+36], rax              ; value (unaligned store, fine)
    mov  eax, [rbp-0x30]
    mov  [rbp-0xc0+44], eax              ; utxo_height
    mov  al,  [rbp-0x31]
    mov  [rbp-0xc0+48], al               ; is_coinbase
    mov  rax, [rbp+24]
    mov  [rbp-0xc0+49], ax               ; slen (low 16 bits of the arg slot)

    mov  r13, 1                          ; ok = 1
    mov  rdi, r12
    lea  rsi, [rbp-0xc0]
    mov  edx, HDR_BYTES
    mov  eax, SYS_write
    syscall
    cmp  rax, HDR_BYTES
    je   .hdr_ok
    mov  r13, -1
.hdr_ok:
    cmp  r13, 1
    jne  .close
    movzx edx, word [rbp+24]             ; slen
    test edx, edx
    jz   .close
    mov  rdi, r12
    mov  rsi, [rbp+16]                   ; script
    mov  eax, SYS_write
    syscall                              ; rdx (slen) survives the syscall
    movzx ecx, word [rbp+24]
    cmp  rax, rcx
    je   .close
    mov  r13, -1
.close:
    mov  rdi, r12
    mov  eax, SYS_close
    syscall
    mov  rax, r13
    jmp  .out
.fail:
    mov  rax, -1
.out:
    add  rsp, 0xa8
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; undo_load(height, out, max_recs) -> records read (>=0) / -1 malformed
;   rdi=height rsi=out rdx=max_recs
; Missing file -> 0 (absent == empty). A record with slen > UNDO_MAX_SCRIPT
; or any short read is malformed -> -1, file closed.
; Frame: push rbp + 5 pushes (saves at [rbp-0x08..-0x28]), sub rsp,0x98 ->
; rsp = rbp-0xc0, 0 mod 16 at the call. path[64] at [rbp-0x70..-0x30),
; hdr[51] at [rbp-0xc0..-0x8d) -- below path, below the save area.
; ----------------------------------------------------------------------------
global undo_load
undo_load:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x98
    mov  rbx, rdi                        ; height OUT of rdi first
    mov  r15, rsi                        ; out cursor (advances by REC_STRIDE)
    mov  r12, rdx                        ; max_recs
    xor  r14d, r14d                      ; n = 0

    lea  rdi, [rbp-0x70]
    mov  rsi, rbx
    call undo_path_build

    lea  rdi, [rbp-0x70]
    mov  esi, O_RDONLY
    xor  edx, edx
    mov  eax, SYS_open
    syscall
    test rax, rax
    js   .absent                         ; missing file -> 0 records
    mov  r13, rax                        ; fd

.loop:
    cmp  r14, r12                        ; n < max_recs ?
    jge  .done
    mov  rdi, r13
    lea  rsi, [rbp-0xc0]
    mov  edx, HDR_BYTES
    mov  eax, SYS_read
    syscall
    test rax, rax
    jz   .done                           ; clean EOF between records
    cmp  rax, HDR_BYTES
    jne  .bad

    ; copy hdr fields into out[n] (offsets pinned from C offsetof)
    mov  rax, [rbp-0xc0]
    mov  [r15], rax
    mov  rax, [rbp-0xb8]
    mov  [r15+8], rax
    mov  rax, [rbp-0xb0]
    mov  [r15+16], rax
    mov  rax, [rbp-0xa8]
    mov  [r15+24], rax
    mov  eax, [rbp-0xc0+32]
    mov  [r15+REC_INDEX], eax
    mov  rax, [rbp-0xc0+36]
    mov  [r15+REC_VALUE], rax
    mov  eax, [rbp-0xc0+44]
    mov  [r15+REC_HEIGHT], eax
    mov  al,  [rbp-0xc0+48]
    mov  [r15+REC_CB], al
    movzx eax, word [rbp-0xc0+49]
    mov  [r15+REC_SLEN], ax
    cmp  eax, UNDO_MAX_SCRIPT
    ja   .bad
    test eax, eax
    jz   .next
    mov  rdi, r13
    lea  rsi, [r15+REC_SCRIPT]
    mov  edx, eax                        ; slen
    mov  eax, SYS_read
    syscall
    movzx ecx, word [r15+REC_SLEN]
    cmp  rax, rcx
    jne  .bad
.next:
    inc  r14
    add  r15, REC_STRIDE
    jmp  .loop

.bad:
    mov  rdi, r13
    mov  eax, SYS_close
    syscall
    mov  rax, -1
    jmp  .out
.done:
    mov  rdi, r13
    mov  eax, SYS_close
    syscall
.absent:
    mov  rax, r14
    ; fall through: r14 is 0 on the absent path (set before open)
.out:
    add  rsp, 0x98
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; undo_replay_impl(height, cb, ctx, tolerant, torn) -> n / -1   (internal)
;   rdi=height rsi=cb rdx=ctx ecx=tolerant r8=torn(int*)
; Streaming reader; one record at a time through replay_script (.bss).
; Tolerant mode: a SHORT header or short script at the tail (a torn trailing
; append) ends the replay and sets *torn=1 instead of failing -- an append
; that never completed is an append whose delete never ran. An OVERSIZED
; slen is corruption in both modes.
; Frame: push rbp + 5 pushes, sub rsp,0x98 -> rsp = rbp-0xc0, 0 mod 16 at
; the path-build call; the cb call site pushes 2 stack args (16 bytes), so
; it is also 0 mod 16 there. path[64] at [rbp-0x70], hdr[51] at [rbp-0xc0],
; tolerant flag at [rbp-0x74] dword.
; ----------------------------------------------------------------------------
undo_replay_impl:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x98
    mov  rax, rdi                        ; height (moved before path build)
    mov  rbx, rsi                        ; cb
    mov  r12, rdx                        ; ctx
    mov  dword [rbp-0x74], ecx           ; tolerant
    mov  r15, r8                         ; torn (int*)
    xor  r14d, r14d                      ; n = 0

    lea  rdi, [rbp-0x70]
    mov  rsi, rax
    call undo_path_build

    lea  rdi, [rbp-0x70]
    mov  esi, O_RDONLY
    xor  edx, edx
    mov  eax, SYS_open
    syscall
    test rax, rax
    js   .absent                         ; absent == empty, same as undo_load
    mov  r13, rax                        ; fd

.loop:
    mov  rdi, r13
    lea  rsi, [rbp-0xc0]
    mov  edx, HDR_BYTES
    mov  eax, SYS_read
    syscall
    test rax, rax
    jz   .done                           ; clean EOF
    cmp  rax, HDR_BYTES
    je   .have_hdr
    ; short header: torn tail in tolerant mode (r > 0), corruption otherwise
    cmp  dword [rbp-0x74], 0
    je   .bad
    test rax, rax
    jle  .bad                            ; r < 0 is a read error even tolerant
    call .mark_torn
    jmp  .done
.have_hdr:
    movzx eax, word [rbp-0xc0+49]        ; slen
    cmp  eax, UNDO_MAX_SCRIPT
    ja   .bad                            ; oversized: corruption in BOTH modes
    test eax, eax
    jz   .invoke
    mov  rdi, r13
    lea  rsi, [replay_script]
    mov  edx, eax
    mov  eax, SYS_read
    syscall
    movzx ecx, word [rbp-0xc0+49]
    cmp  rax, rcx
    je   .invoke
    ; short script: torn tail in tolerant mode (r >= 0), corruption otherwise
    cmp  dword [rbp-0x74], 0
    je   .bad
    test rax, rax
    js   .bad
    call .mark_torn
    jmp  .done
.invoke:
    test rbx, rbx
    jz   .count                          ; cb == NULL: just count, like the C
    mov  rdi, r12                        ; ctx
    lea  rsi, [rbp-0xc0]                 ; txid = hdr[0..32)
    mov  edx, [rbp-0xc0+32]              ; index
    mov  rcx, [rbp-0xc0+36]              ; value
    mov  r8d, [rbp-0xc0+44]              ; utxo height
    movzx r9d, byte [rbp-0xc0+48]        ; is_coinbase
    movzx eax, word [rbp-0xc0+49]        ; slen
    push rax                             ; arg 8: slen
    lea  rax, [replay_script]
    push rax                             ; arg 7: script
    call rbx                             ; rsp was 0 mod 16 before the pushes;
    add  rsp, 16                         ;   2 pushes keep it 0 mod 16 at call
    test eax, eax
    jz   .bad                            ; cb said stop -> error, like the C
.count:
    inc  r14
    jmp  .loop

.mark_torn:                              ; tiny helper; near call, no frame
    test r15, r15
    jz   .mt_done
    mov  dword [r15], 1
.mt_done:
    ret

.bad:
    mov  rdi, r13
    mov  eax, SYS_close
    syscall
    mov  rax, -1
    jmp  .out
.done:
    mov  rdi, r13
    mov  eax, SYS_close
    syscall
.absent:
    mov  rax, r14
.out:
    add  rsp, 0x98
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; undo_replay(height, cb, ctx) -> n / -1        (strict: any tear is -1)
; ----------------------------------------------------------------------------
global undo_replay
undo_replay:
    xor  ecx, ecx                        ; tolerant = 0
    xor  r8d, r8d                        ; torn = NULL
    jmp  undo_replay_impl

; ----------------------------------------------------------------------------
; undo_replay_tolerant(height, cb, ctx, torn) -> n / -1
; C: if (torn) *torn = 0; then impl(..., tolerant=1, torn)
; ----------------------------------------------------------------------------
global undo_replay_tolerant
undo_replay_tolerant:
    test rcx, rcx
    jz   .go
    mov  dword [rcx], 0
.go:
    mov  r8, rcx                         ; torn
    mov  ecx, 1                          ; tolerant
    jmp  undo_replay_impl

; ----------------------------------------------------------------------------
; undo_discard(height) -> 1 removed / 0 nothing there
; Frame: push rbp only, sub rsp,0x50 -> 0 mod 16 at the call. path at
; [rbp-0x50..-0x10).
; ----------------------------------------------------------------------------
global undo_discard
undo_discard:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x50
    mov  rax, rdi                        ; height out of rdi first
    lea  rdi, [rbp-0x50]
    mov  rsi, rax
    call undo_path_build
    lea  rdi, [rbp-0x50]
    mov  eax, SYS_unlink
    syscall
    xor  ecx, ecx
    test rax, rax
    setz cl                              ; 1 iff unlink returned 0
    mov  eax, ecx                        ; full-width result (SETcc lesson, #28)
    add  rsp, 0x50
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; undo_prune_from(from_height, tip_height, window, max_scan) -> cursor
;   rdi=from rsi=tip rdx=window rcx=max_scan
; Bounded resumable sweep; exact C semantics including every early return.
; Frame: push rbp + 3 pushes, sub rsp,0x58 -> 0 mod 16 at the calls. path at
; [rbp-0x70..-0x30).
; ----------------------------------------------------------------------------
global undo_prune_from
undo_prune_from:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x58
    mov  r13, rdi                        ; from_height (also the fallback result)
    ; if (tip < 0 || window <= 0 || max_scan <= 0) return from;
    test rsi, rsi
    js   .ret_from
    test rdx, rdx
    jle  .ret_from
    test rcx, rcx
    jle  .ret_from
    ; if (from < 0) from = 0;
    mov  rbx, r13
    test rbx, rbx
    jns  .kf
    xor  ebx, ebx
.kf:
    ; keep_from = tip - window + 1; if (< 0) keep_from = 0;
    mov  rax, rsi
    sub  rax, rdx
    inc  rax
    test rax, rax
    jns  .kf2
    xor  eax, eax
.kf2:
    ; end = from + max_scan; if (end > keep_from) end = keep_from;
    mov  r12, rbx
    add  r12, rcx
    cmp  r12, rax
    jle  .sweep
    mov  r12, rax
.sweep:
    ; for (h = from(clamped); h < end; h++) unlink(path(h));
    ; NOTE the C compares from the CLAMPED from (rbx) but returns end vs the
    ; ORIGINAL from (r13) -- mirrored exactly.
.loop:
    cmp  rbx, r12
    jge  .fin
    lea  rdi, [rbp-0x70]
    mov  rsi, rbx
    call undo_path_build
    lea  rdi, [rbp-0x70]
    mov  eax, SYS_unlink
    syscall                              ; result ignored, like the C
    inc  rbx
    jmp  .loop
.fin:
    ; return end > from_original ? end : from_original;
    mov  rax, r12
    cmp  r12, r13
    jg   .out
.ret_from:
    mov  rax, r13
.out:
    add  rsp, 0x58
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; undo_prune(tip_height, window) -> number of files removed
;   rdi=tip rsi=window
; Frame: push rbp + 3 pushes, sub rsp,0x58 -> 0 mod 16 at the calls.
; ----------------------------------------------------------------------------
global undo_prune
undo_prune:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x58
    ; if (tip < 0 || window <= 0) return 0;
    xor  r13d, r13d                      ; removed = 0
    test rdi, rdi
    js   .fin
    test rsi, rsi
    jle  .fin
    ; keep_from = tip - window + 1; if (< 0) keep_from = 0;
    mov  r12, rdi
    sub  r12, rsi
    inc  r12
    test r12, r12
    jns  .go
    xor  r12d, r12d
.go:
    xor  ebx, ebx                        ; h = 0
.loop:
    cmp  rbx, r12
    jge  .fin
    lea  rdi, [rbp-0x70]
    mov  rsi, rbx
    call undo_path_build
    lea  rdi, [rbp-0x70]
    mov  eax, SYS_unlink
    syscall
    test rax, rax
    jnz  .skip
    inc  r13                             ; removed++
.skip:
    inc  rbx
    jmp  .loop
.fin:
    mov  rax, r13
    add  rsp, 0x58
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; undo_capture_and_del(lst, u, height, txid, index) -> 1 / 0 / -1
;   rdi=lst rsi=u rdx=height rcx=txid r8d=index
; Composition, exactly the C: utxo_lsm_get (1 -> captured fields), then
; undo_append_record (must return 1), then utxo_lsm_del (its result IS the
; return). get's 0/-1 pass through unchanged; a failed append is -1.
; `height` is the CONSUMING block (file name); the record's height field is
; the spent UTXO's own creation height from the get. See the file header.
; Frame: push rbp + 5 pushes, sub rsp,0x48 -> rsp = rbp-0x70, 0 mod 16; the
; lsm_get call site adds sub 8 + 3 pushes (32 bytes) and the append call
; site 2 pushes (16), both landing back on 0 mod 16 at their calls.
; Out-params live at [rbp-0x30..-0x50], strictly below the save area.
; ----------------------------------------------------------------------------
extern utxo_lsm_get
extern utxo_lsm_del

global undo_capture_and_del
undo_capture_and_del:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x48
    mov  rbx, rdi                        ; lst
    mov  r12, rsi                        ; u
    mov  r13, rdx                        ; height (consuming block)
    mov  r14, rcx                        ; txid
    mov  r15d, r8d                       ; index (u32)

    ; zero the out-params, like the C's initializers
    xor  eax, eax
    mov  [rbp-0x30], rax                 ; value
    mov  [rbp-0x38], rax                 ; utxo_height
    mov  [rbp-0x40], rax                 ; is_coinbase
    mov  [rbp-0x48], rax                 ; script
    mov  [rbp-0x50], rax                 ; slen

    ; utxo_lsm_get(lst, u, txid, index, &value, &height, &cb, &script, &slen)
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r14
    mov  ecx, r15d
    lea  r8,  [rbp-0x30]
    lea  r9,  [rbp-0x38]
    sub  rsp, 8                          ; 3 stack args below need realignment
    lea  rax, [rbp-0x50]
    push rax                             ; arg 9: &slen
    lea  rax, [rbp-0x48]
    push rax                             ; arg 8: &script
    lea  rax, [rbp-0x40]
    push rax                             ; arg 7: &is_coinbase
    call utxo_lsm_get
    add  rsp, 32
    cmp  rax, 1
    jne  .out                            ; 0 / -1 pass through unchanged

    ; undo_append_record(height, txid, index, value, utxo_height,
    ;                    is_coinbase, script, slen)
    mov  rdi, r13
    mov  rsi, r14
    mov  edx, r15d
    mov  rcx, [rbp-0x30]                 ; value
    mov  r8d, [rbp-0x38]                 ; utxo_height (low 32 of the u64 out)
    movzx r9d, byte [rbp-0x40]           ; is_coinbase (low byte)
    push qword [rbp-0x50]                ; arg 8: slen (low 16 used by callee)
    push qword [rbp-0x48]                ; arg 7: script
    call undo_append_record
    add  rsp, 16
    cmp  rax, 1
    je   .del
    mov  rax, -1
    jmp  .out
.del:
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r14
    mov  ecx, r15d
    call utxo_lsm_del                    ; its result is the return value
.out:
    add  rsp, 0x48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; SECURITY (audit 2026-08-29 finding 9): without this note the linker
; conservatively marks the whole program's stack EXECUTABLE (PT_GNU_STACK
; RWE). Nothing here needs a runnable stack; a single object missing the
; note is enough to turn it on for the entire binary, which is why every
; .asm file carries it.
section .note.GNU-stack noalloc noexec nowrite progbits
