; ============================================================================
; bitcoin_tapagg.asm -- BIP341 aggregate-sighash arena build/verify, 100%
; AI-generated x86-64 assembly (NASM, ELF64). Phase 2 slice 7 of the C->asm
; conversion (2026-08-24). Twin of tx_verify.c's tapagg_build/tapagg_verify;
; differential: tests/test_tapagg_diff.c.
;
;   long tapagg_build_asm(bytepool_t* pool, tapagg_t* d, tapin_fn get,
;                         void* ctx, u64 nin, const u8* tx,
;                         /*stack*/ u64 txlen, const char** reason) -> 1/0
;   long tapagg_verify_asm(const bytepool_t* pool, const tapagg_t* d,
;                          const u8* spk, const u8* const* wit,
;                          const u32* witlen, u32 nwit,
;                          /*stack*/ u64 local_idx, const char** reason)
;
; The build's dependency chain is all-asm: txv_bytepool_reserve_asm (slice
; 5) and strip_witness_asm (slice 6) -- both differential-proven twins of
; the functions the C calls, so calling them preserves bug-for-bug
; equivalence by transitivity. The `get` adapter is a caller-supplied
; function pointer (SysV, 6 args); taproot_verify_input stays a C extern
; (its own later slice).
;
; The C's two invariant checks inside the write pass are reproduced: the
; arena must not move between the single reserve and the writes, and the
; write cursor must stay within the sizing pass's splen -- both guard
; against a `get` adapter whose two calls disagree, which would corrupt
; OTHER transactions' descriptors silently (see the C's comment).
;
; tapagg_t (all u64): po_off@0 am_off@8 sp_off@16 ns_off@24 nslen@32 nin@40.
; bytepool_t: buf@0 cap@8 used@16.
; ============================================================================

BITS 64
DEFAULT REL

extern txv_bytepool_reserve_asm       ; slice 5 twin
extern strip_witness_asm              ; slice 6 twin
extern taproot_verify_input           ; C (bitcoin_taproot_sighash.c) -- later slice

%define TA_PO    0
%define TA_AM    8
%define TA_SP    16
%define TA_NS    24
%define TA_NSLEN 32
%define TA_NIN   40

%define BP_BUF   0

section .rodata
t_spkbig: db "prevout script too large for taproot aggregate sighash",0
t_oom:    db "out of memory",0
t_moved:  db "internal: taproot arena moved during build",0
t_sizing: db "internal: taproot arena sizing pass disagreed",0
t_strip:  db "malformed witness (strip failed)",0
t_p2tr:   db "p2tr verify failed",0

section .text

; ----------------------------------------------------------------------------
; tapagg_build_asm(pool=rdi, d=rsi, get=rdx, ctx=rcx, nin=r8, tx=r9,
;                  txlen=[rbp+16], reason=[rbp+24]) -> 1 / 0
; Frame: push rbp + 5 pushes, sub rsp,0x68 -> rsp = rbp-0x90, 0 mod 16 at
; every call site (the get() calls included). Locals below the save area:
;   [rbp-0x30] pool   [rbp-0x38] d      [rbp-0x40] get    [rbp-0x48] ctx
;   [rbp-0x50] nin    [rbp-0x58] tx     [rbp-0x60] splen  [rbp-0x68] k
;   [rbp-0x70] &op    [rbp-0x78] &v     [rbp-0x80] &spk   [rbp-0x88] &sl(u32)
;   [rbp-0x90] w / base scratch
; The out-params for get() live in the frame and are re-read after each
; call, exactly like the C's locals.
; ----------------------------------------------------------------------------
global tapagg_build_asm
tapagg_build_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x68
    mov  [rbp-0x30], rdi                 ; pool
    mov  [rbp-0x38], rsi                 ; d
    mov  [rbp-0x40], rdx                 ; get
    mov  [rbp-0x48], rcx                 ; ctx
    mov  [rbp-0x50], r8                  ; nin
    mov  [rbp-0x58], r9                  ; tx

    ; ---- sizing pass: splen = sum(1 + sl), reject sl >= 0xfd ----
    xor  eax, eax
    mov  [rbp-0x60], rax                 ; splen = 0
    mov  [rbp-0x68], rax                 ; k = 0
.size_loop:
    mov  rax, [rbp-0x68]
    cmp  rax, [rbp-0x50]
    jae  .size_done
    mov  rdi, [rbp-0x48]                 ; ctx
    mov  rsi, rax                        ; k
    lea  rdx, [rbp-0x70]                 ; &op
    lea  rcx, [rbp-0x78]                 ; &v
    lea  r8,  [rbp-0x80]                 ; &spk
    lea  r9,  [rbp-0x88]                 ; &sl
    call qword [rbp-0x40]
    mov  eax, [rbp-0x88]                 ; sl (u32)
    cmp  eax, 0xfd
    jae  .r_spkbig
    inc  eax                             ; 1 + sl
    add  [rbp-0x60], rax
    inc  qword [rbp-0x68]
    jmp  .size_loop
.size_done:

    ; need = nin*36 + nin*8 + splen + txlen ; off = reserve(pool, need)
    mov  rax, [rbp-0x50]
    imul rax, rax, 44                    ; nin*36 + nin*8
    add  rax, [rbp-0x60]
    add  rax, [rbp+16]                   ; + txlen
    mov  rdi, [rbp-0x30]
    mov  rsi, rax
    call txv_bytepool_reserve_asm
    cmp  rax, -1
    je   .r_oom

    ; fill the descriptor offsets
    mov  rbx, [rbp-0x38]                 ; d
    mov  [rbx+TA_PO], rax
    mov  rcx, [rbp-0x50]
    imul rdx, rcx, 36
    add  rdx, rax
    mov  [rbx+TA_AM], rdx                ; po + nin*36
    lea  r8, [rdx+rcx*8]
    mov  [rbx+TA_SP], r8                 ; am + nin*8
    mov  r9, r8
    add  r9, [rbp-0x60]
    mov  [rbx+TA_NS], r9                 ; sp + splen
    mov  [rbx+TA_NIN], rcx

    ; base = pool->buf (only NOW -- the reserve above was the last relocation)
    mov  rax, [rbp-0x30]
    mov  r12, [rax+BP_BUF]               ; base
    mov  r13, [rbx+TA_PO]
    add  r13, r12                        ; po
    mov  r14, [rbx+TA_AM]
    add  r14, r12                        ; am
    mov  r15, [rbx+TA_SP]
    add  r15, r12                        ; sp
    xor  eax, eax
    mov  [rbp-0x90], rax                 ; w = 0
    mov  [rbp-0x68], rax                 ; k = 0

.write_loop:
    mov  rax, [rbp-0x68]
    cmp  rax, [rbp-0x50]
    jae  .write_done
    mov  rdi, [rbp-0x48]
    mov  rsi, rax
    lea  rdx, [rbp-0x70]
    lea  rcx, [rbp-0x78]
    lea  r8,  [rbp-0x80]
    lea  r9,  [rbp-0x88]
    call qword [rbp-0x40]
    ; invariant 1: the arena must not have moved
    mov  rax, [rbp-0x30]
    cmp  r12, [rax+BP_BUF]
    jne  .r_moved
    ; invariant 2: sl < 0xfd and w + 1 + sl <= splen
    mov  eax, [rbp-0x88]                 ; sl
    cmp  eax, 0xfd
    jae  .r_sizing
    mov  rcx, [rbp-0x90]                 ; w
    lea  rdx, [rcx+rax+1]                ; w + 1 + sl
    cmp  rdx, [rbp-0x60]
    ja   .r_sizing
    ; po[k*36] = op (36 bytes)
    mov  rax, [rbp-0x68]
    imul rdi, rax, 36
    add  rdi, r13
    mov  rsi, [rbp-0x70]                 ; op
    mov  ecx, 36
    rep  movsb
    ; am[k*8] = v, LE64 (an unaligned store IS the C's byte loop)
    mov  rax, [rbp-0x68]
    mov  rcx, [rbp-0x78]                 ; v
    mov  [r14+rax*8], rcx
    ; sp[w++] = sl; memcpy(sp+w, spk, sl); w += sl
    mov  rcx, [rbp-0x90]                 ; w
    mov  eax, [rbp-0x88]                 ; sl
    mov  [r15+rcx], al
    inc  rcx
    lea  rdi, [r15+rcx]
    mov  rsi, [rbp-0x80]                 ; spk
    add  rcx, rax                        ; w' = w + 1 + sl
    mov  [rbp-0x90], rcx
    mov  ecx, eax
    rep  movsb
    inc  qword [rbp-0x68]
    jmp  .write_loop
.write_done:

    ; nslen = strip_witness(tx, txlen, ns, txlen); <= 0 -> fail
    mov  rdi, [rbp-0x58]                 ; tx
    mov  rsi, [rbp+16]                   ; txlen
    mov  rbx, [rbp-0x38]
    mov  rdx, [rbx+TA_NS]
    add  rdx, r12                        ; ns = base + ns_off
    mov  rcx, [rbp+16]                   ; cap = txlen
    call strip_witness_asm
    test rax, rax
    jle  .r_strip
    mov  [rbx+TA_NSLEN], rax
    mov  eax, 1
    jmp  .out

.r_spkbig: lea rsi, [t_spkbig]
           jmp .reject
.r_oom:    lea rsi, [t_oom]
           jmp .reject
.r_moved:  lea rsi, [t_moved]
           jmp .reject
.r_sizing: lea rsi, [t_sizing]
           jmp .reject
.r_strip:  lea rsi, [t_strip]
.reject:
    mov  rax, [rbp+24]
    mov  [rax], rsi
    xor  eax, eax
.out:
    add  rsp, 0x68
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; tapagg_verify_asm(pool=rdi, d=rsi, spk=rdx, wit=rcx, witlen=r8, nwit=r9d,
;                   local_idx=[rbp+16], reason=[rbp+24]) -> 1 / 0
; Marshals to taproot_verify_input's 12-arg C signature (6 stack args). r
; defaults to "p2tr verify failed" exactly like the C local.
; Frame: push rbp + 1 push (rbx), sub rsp,0x18 -> rsp = rbp-0x28; the call
; site pushes 6 stack args (48 bytes) landing back on 0 mod 16.
; Locals: [rbp-0x10] r (the reason slot passed by address), [rbp-0x18] pool
; buf base scratch.
; ----------------------------------------------------------------------------
global tapagg_verify_asm
tapagg_verify_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    sub  rsp, 0x18
    mov  rbx, rsi                        ; d
    lea  rax, [t_p2tr]
    mov  [rbp-0x10], rax                 ; const char* r = "p2tr verify failed"
    mov  rax, [rdi+BP_BUF]               ; A = pool->buf
    mov  [rbp-0x18], rax

    ; args 1..6: spk, wit, witlen, nwit, tx(=A+ns_off), txlen(=nslen)
    mov  rdi, rdx                        ; spk
    mov  rsi, rcx                        ; wit
    mov  rdx, r8                         ; witlen
    mov  ecx, r9d                        ; nwit
    mov  r8,  [rbp-0x18]
    add  r8,  [rbx+TA_NS]                ; tx = A + ns_off
    mov  r9,  [rbx+TA_NSLEN]             ; txlen
    ; args 7..12 pushed in reverse: n_in, prevouts, amounts, spks,
    ; num_inputs, &r
    lea  rax, [rbp-0x10]
    push rax                             ; arg 12: &r
    push qword [rbx+TA_NIN]              ; arg 11: num_inputs
    mov  rax, [rbp-0x18]
    add  rax, [rbx+TA_SP]
    push rax                             ; arg 10: spks
    mov  rax, [rbp-0x18]
    add  rax, [rbx+TA_AM]
    push rax                             ; arg  9: amounts
    mov  rax, [rbp-0x18]
    add  rax, [rbx+TA_PO]
    push rax                             ; arg  8: prevouts
    push qword [rbp+16]                  ; arg  7: n_in = local_idx
    call taproot_verify_input
    add  rsp, 48
    test eax, eax
    jz   .bad
    mov  eax, 1
    jmp  .out
.bad:
    mov  rax, [rbp+24]                   ; *reason = r
    mov  rcx, [rbp-0x10]
    mov  [rax], rcx
    xor  eax, eax
.out:
    add  rsp, 0x18
    pop  rbx
    pop  rbp
    ret
