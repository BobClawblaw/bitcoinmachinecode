; ============================================================================
; bitcoin_strip_witness.asm -- canonical witness stripping, 100% AI-generated
; x86-64 assembly (NASM, ELF64). Phase 2 slice 6 of the C->asm conversion
; (2026-08-24). Twin of bitcoin_segwit.c's strip_witness; differential:
; tests/test_strip_witness_diff.c.
;
;   long strip_witness_asm(const u8* tx, i64 txlen, u8* out, long cap)
;     -> stripped length (> 0) or 0 on malformed / cap exceeded
;
; Core: SERIALIZE_TRANSACTION_NO_WITNESS -- version || inputs || outputs ||
; locktime. Consumers: legacy sighash on mixed (segwit-carrying) txs and
; BIP341's stripped-tx commitment, so a byte of divergence here is a wrong
; sighash, which is silent.
;
; FIDELITY NOTES (all mirrored exactly):
;   - the compactsize reader here is bitcoin_segwit.c's read_cs, which
;     REJECTS non-canonical encodings (v < min for its width) -- stricter
;     than tx_verify's txv_rd_cs. RDCSC below implements that contract.
;   - the walk-phase scriptSig bound was `avail < sl + 4` (wrap); FIXED to the
;     split form (incident #38) matching the C. The header note below
;     64-bit wrap for sl within 4 of 2^64 as the C (and as txv_parse; see
;     LOG.md 2026-08-24 -- the Core-differential for that class is filed).
;   - the emit-phase per-input bound is the C's own documented
;     unsigned-compare shape: `cap < 0 || (u64)(cap - dsz) < cs_size(sl)
;     + sl + 4`, everything else a signed `dsz + k > cap`.
;   - the nin/scriptSig varints are RE-ENCODED minimally on output (put_cs)
;     while the outputs section is copied verbatim -- exactly the C's
;     asymmetry. On failure, partial bytes already written to `out` are
;     left behind, same as the C; the differential compares those too.
; ============================================================================

BITS 64
DEFAULT REL

section .text

; RDCSC <fail>: canonical compact-size at rbx (end = r12) -> rax, rbx
; advanced; jumps to <fail> on truncation OR non-canonical encoding.
; Clobbers rax, rcx.
%macro RDCSC 1
    cmp  rbx, r12
    jae  %1
    movzx eax, byte [rbx]
    inc  rbx
    cmp  al, 0xfd
    jb   %%done
    je   %%two
    cmp  al, 0xfe
    je   %%four
    mov  rcx, r12                        ; 0xff: 8 bytes
    sub  rcx, rbx
    cmp  rcx, 8
    jb   %1
    mov  rax, [rbx]
    add  rbx, 8
    mov  rcx, 0x100000000
    cmp  rax, rcx
    jb   %1                              ; non-canonical
    jmp  %%done
%%four:
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, 4
    jb   %1
    mov  eax, [rbx]
    add  rbx, 4
    cmp  rax, 0x10000
    jb   %1
    jmp  %%done
%%two:
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, 2
    jb   %1
    movzx eax, word [rbx]
    add  rbx, 2
    cmp  eax, 0xfd
    jb   %1
%%done:
%endmacro

; PUTCS: write rax as a minimal compactsize at r13, advance r13 and add the
; width to r14 (dsz). Clobbers rcx, rdx. (Caller has already bounds-checked.)
%macro PUTCS 0
    cmp  rax, 0xfd
    jae  %%big
    mov  [r13], al
    inc  r13
    inc  r14
    jmp  %%done
%%big:
    cmp  rax, 0xffff
    ja   %%big4
    mov  byte [r13], 0xfd
    mov  [r13+1], ax
    add  r13, 3
    add  r14, 3
    jmp  %%done
%%big4:
    mov  rcx, 0xffffffff
    cmp  rax, rcx
    ja   %%big8
    mov  byte [r13], 0xfe
    mov  [r13+1], eax
    add  r13, 5
    add  r14, 5
    jmp  %%done
%%big8:
    mov  byte [r13], 0xff
    mov  [r13+1], rax
    add  r13, 9
    add  r14, 9
%%done:
%endmacro

; CSSIZE: rcx = cs_size(rax). Clobbers rdx.
%macro CSSIZE 0
    mov  ecx, 1
    cmp  rax, 0xfd
    jb   %%done
    mov  ecx, 3
    cmp  rax, 0xffff
    jbe  %%done
    mov  ecx, 5
    mov  rdx, 0xffffffff
    cmp  rax, rdx
    jbe  %%done
    mov  ecx, 9
%%done:
%endmacro

; ----------------------------------------------------------------------------
; strip_witness_asm(tx=rdi, txlen=rsi, out=rdx, cap=rcx) -> rax dsz / 0
; Frame: push rbp + 5 pushes, sub rsp,0x58 -> rsp = rbp-0x80, 0 mod 16 (no
; calls are made; kept for uniformity). Locals below the save area:
;   [rbp-0x30] tx      [rbp-0x38] nin     [rbp-0x40] segwit
;   [rbp-0x48] outs_start [rbp-0x50] outs_end [rbp-0x58] lock
;   [rbp-0x60] i       [rbp-0x68] in0 (input section, post-nin-varint)
;   [rbp-0x70] nitems  [rbp-0x78] sl scratch
; Registers: rbx = read cursor (RDCSC contract), r12 = end, r13 = write
; cursor d, r14 = dsz, r15 = cap.
; ----------------------------------------------------------------------------
global strip_witness_asm
strip_witness_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x58
    mov  [rbp-0x30], rdi                 ; tx
    mov  r13, rdx                        ; d = out
    mov  r15, rcx                        ; cap (long)
    xor  r14d, r14d                      ; dsz = 0
    cmp  rsi, 10
    jl   .fail
    lea  r12, [rdi+rsi]                  ; end
    lea  rbx, [rdi+4]                    ; p = tx + 4
    ; segwit = (p[0]==0x00 && p[1]==0x01) -- txlen >= 10 covers the reads
    xor  eax, eax
    cmp  byte [rbx], 0x00
    jne  .segdone
    cmp  byte [rbx+1], 0x01
    jne  .segdone
    mov  eax, 1
    add  rbx, 2
.segdone:
    mov  [rbp-0x40], rax                 ; segwit

    RDCSC .fail                          ; nin
    test rax, rax
    jz   .fail                           ; nin == 0
    mov  [rbp-0x38], rax
    mov  [rbp-0x68], rbx                 ; in0: input section start (post varint)

    ; ---- walk 1: inputs ----
    xor  ecx, ecx
    mov  [rbp-0x60], rcx
.w_in:
    mov  rax, [rbp-0x60]
    cmp  rax, [rbp-0x38]
    jae  .w_in_done
    mov  rax, r12
    sub  rax, rbx
    cmp  rax, 36                         ; avail < 36 ?
    jb   .fail
    add  rbx, 36
    RDCSC .fail                          ; sl
    mov  rdx, r12
    sub  rdx, rbx                        ; avail
    cmp  rdx, rax                        ; avail < sl ? (split bound, incident #38 --
    jb   .fail                           ;   the C strip_witness fixed the same wrap)
    sub  rdx, rax                        ; avail - sl
    cmp  rdx, 4
    jb   .fail
    lea  rbx, [rbx+rax+4]
    inc  qword [rbp-0x60]
    jmp  .w_in
.w_in_done:

    mov  [rbp-0x48], rbx                 ; outs_start (nout varint included)
    RDCSC .fail                          ; nout
    mov  rdx, rax                        ; nout countdown in rdx? RDCSC clobbers rcx only besides rax
.w_out:
    test rdx, rdx
    jz   .w_out_done
    mov  rax, r12
    sub  rax, rbx
    cmp  rax, 8
    jb   .fail
    add  rbx, 8
    push rdx                             ; RDCSC clobbers rcx/rax only, but keep
    RDCSC .fail_pop                      ;   the countdown safe across the macro
    pop  rdx
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, rax                        ; avail < sl ?
    jb   .fail
    add  rbx, rax
    dec  rdx
    jmp  .w_out
.w_out_done:

    mov  [rbp-0x50], rbx                 ; outs_end
    mov  [rbp-0x58], rbx                 ; lock (legacy default)
    cmp  qword [rbp-0x40], 0
    je   .w_lock
    ; ---- walk 2: witness stacks (segwit only) ----
    xor  ecx, ecx
    mov  [rbp-0x60], rcx
.w_wit:
    mov  rax, [rbp-0x60]
    cmp  rax, [rbp-0x38]
    jae  .w_wit_done
    RDCSC .fail                          ; nitems
    mov  [rbp-0x70], rax
.w_item:
    cmp  qword [rbp-0x70], 0
    je   .w_item_done
    RDCSC .fail                          ; il
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, rax
    jb   .fail
    add  rbx, rax
    dec  qword [rbp-0x70]
    jmp  .w_item
.w_item_done:
    inc  qword [rbp-0x60]
    jmp  .w_wit
.w_wit_done:
    mov  [rbp-0x58], rbx                 ; lock = q
.w_lock:
    mov  rax, r12
    sub  rax, [rbp-0x58]
    cmp  rax, 4                          ; avail(lock) < 4 ?
    jb   .fail

    ; ================= emit =================
    ; version: dsz + 4 > cap ? (signed, like the C)
    lea  rax, [r14+4]
    cmp  rax, r15
    jg   .fail
    mov  rdi, [rbp-0x30]
    mov  eax, [rdi]
    mov  [r13], eax
    add  r13, 4
    add  r14, 4
    ; nin varint, re-encoded minimally
    mov  rax, [rbp-0x38]
    CSSIZE                               ; rcx = width
    lea  rdx, [r14+rcx]
    cmp  rdx, r15                        ; dsz + csn > cap ? (signed)
    jg   .fail
    PUTCS
    ; ---- inputs: copy outpoint+sequence, re-encode scriptSig varint ----
    mov  rbx, [rbp-0x68]                 ; it = input section start
    xor  ecx, ecx
    mov  [rbp-0x60], rcx
.e_in:
    mov  rax, [rbp-0x60]
    cmp  rax, [rbp-0x38]
    jae  .e_in_done
    lea  rax, [r14+36]
    cmp  rax, r15                        ; dsz + 36 > cap ? (signed)
    jg   .fail
    mov  rsi, rbx                        ; outpoint: 36 bytes
    mov  rdi, r13
    mov  ecx, 36
    rep  movsb
    add  rbx, 36
    add  r13, 36
    add  r14, 36
    RDCSC .fail                          ; sl (re-read; walk 1 validated it)
    mov  [rbp-0x78], rax                 ; sl
    ; the C's documented unsigned bound: cap < 0 || (u64)(cap - dsz) <
    ; cs_size(sl) + sl + 4
    test r15, r15
    js   .fail
    CSSIZE                               ; rcx = cs_size(sl)
    lea  rcx, [rcx+rax+4]                ; cs_size + sl + 4 (u64, may wrap: fidelity)
    mov  rdx, r15
    sub  rdx, r14                        ; cap - dsz
    cmp  rdx, rcx
    jb   .fail
    PUTCS                                ; scriptSig varint (rax = sl)
    mov  rcx, [rbp-0x78]                 ; copy scriptSig bytes
    mov  rsi, rbx
    mov  rdi, r13
    add  rbx, rcx
    add  r13, rcx
    add  r14, rcx
    rep  movsb
    mov  eax, [rbx]                      ; sequence
    mov  [r13], eax
    add  rbx, 4
    add  r13, 4
    add  r14, 4
    inc  qword [rbp-0x60]
    jmp  .e_in
.e_in_done:
    ; ---- outputs section, verbatim ----
    mov  rax, [rbp-0x50]
    sub  rax, [rbp-0x48]                 ; olen
    cmp  rax, 1
    jl   .fail                           ; olen < 1
    lea  rdx, [r14+rax]
    cmp  rdx, r15                        ; dsz + olen > cap ? (signed)
    jg   .fail
    mov  rcx, rax
    mov  rsi, [rbp-0x48]
    mov  rdi, r13
    add  r13, rax
    add  r14, rax
    rep  movsb
    ; ---- locktime ----
    lea  rax, [r14+4]
    cmp  rax, r15
    jg   .fail
    mov  rsi, [rbp-0x58]
    mov  eax, [rsi]
    mov  [r13], eax
    add  r14, 4
    mov  rax, r14                        ; return dsz
    jmp  .out

.fail_pop:
    pop  rdx
.fail:
    xor  eax, eax
.out:
    add  rsp, 0x58
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
