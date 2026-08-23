; ============================================================================
; RIPEMD-160 -- 100% AI-generated x86-64 assembly (NASM, ELF64 ABI)
;
; PURPOSE
;   RIPEMD-160 is one half of Bitcoin's HASH160 = RIPEMD-160(SHA-256(x)).
;   HASH160 is what every P2PKH address commits to (HASH160 of the public
;   key), so a self-contained Bitcoin implementation needs RIPEMD-160 to
;   generate and check receiving addresses.
;
; ALGORITHM (RIPEMD-160)
;   Padded to 64-byte blocks (0x80 + zeros + 64-bit LE bit-length). Each block
;   -> 16 LE message words X. 5-word state h0..h4; 80 rounds in two parallel
;   lines; cross-mix at the end.
;
;   Left line  round j:  T = ROL(A+f_j(B,C,D)+X[r[j]]+Kl[j], s[j]) + E
;   Right line round j:  T = ROL(A2+g_j(B2,C2,D2)+X[rp[j]]+Kr[j], sp[j])+E2
;   Round functions (both lines, standard RIPEMD-160):
;      f1= B^C^D ; f2=(B&C)|(~B&D) ; f3=(B|~C)^D ; f4=(B&D)|(C&~D) ; f5=B^(C|~D)
;   Left uses f1..f5 then cycles; right line uses them MIRRORED (round1..5 of
;   the right line use f5,f4,f3,f2,f1 respectively).
;   Round constants: left K= {0,5a827999,6ed9eba1,8f1bbcdc,a953fd4e};
;   right K'= {50a28be6,5c4dd124,6d703ef3,7a6d76e9,0}.
;   Per round the two lines rotate their own 5-word registers A..E / A2..E2 by
;   the same shift a->E,a... pattern; C and C2 are rotated <<<10 each round.
;
; PUBLIC ABI (System V AMD64)
;   void ripemd160(u8 out[20], const void *in, i64 len) -> rdi, rsi, rdx
; ============================================================================

BITS 64
DEFAULT REL

section .rodata
align 16
KCON:
    dd 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e
    dd 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000
ISTATE:
    dd 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
align 16
RL:  db 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
     db 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8
     db 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12
     db 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2
     db 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
RP:  db 5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12
     db 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2
     db 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13
     db 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14
     db 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
SL:  db 11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8
     db 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12
     db 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5
     db 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12
     db 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
SPROT: db 8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6
     db 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11
     db 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5
     db 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8
     db 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11

section .text
global ripemd160

; ============================================================================
; Compress one 64-byte block. Message words X[0..15] (LE dwords) must already
; be at [rbp-0x90..-0x50]; state h0..h4 at [rbp-0x30,-0x2c,-0x28,-0x24,-0x20].
; Register map (persistent across all 80 rounds):
;   LEFT : A=esi B=r8d C=r9d D=r10d E=r11d
;   RIGHT: A2=edi B2=r12d C2=r13d D2=r14d E2=ebx
; Clobbers eax,ecx,edx. State is updated in place at the end.
; ============================================================================
rmd160_compress:
    ; Preserve every callee-saved register we free-use (A2..E2 live in
    ; r12..r14, rbx; round counter in r15) because the calling ripemd160
    ; keeps its persistent out/in/len/offset in these same registers.
    push r15
    push r14
    push r13
    push r12
    push rbx
    mov  esi,  [rbp-0x30]      ; A
    mov  r8d,  [rbp-0x2c]      ; B
    mov  r9d,  [rbp-0x28]      ; C
    mov  r10d, [rbp-0x24]      ; D
    mov  r11d, [rbp-0x20]      ; E
    mov  edi,  esi             ; A2
    mov  r12d, r8d             ; B2
    mov  r13d, r9d             ; C2
    mov  r14d, r10d            ; D2
    mov  ebx,  r11d            ; E2

    xor  r15d, r15d            ; round counter 0..79 (r15 = callee-saved, pushed)
.round:
    ; ---------- left line ----------
    lea  rax, [RL]
    movzx edx, byte [rax+r15]
    mov  [rbp-0x3c], edx       ; idx_l
    lea  rax, [SL]
    movzx edx, byte [rax+r15]
    mov  [rbp-0x38], edx       ; rotl_l
    mov  edx, r15d
    shr  edx, 4
    mov  eax, [KCON + rdx*4]
    mov  [rbp-0x44], eax       ; Kl
    call rmd_f_left             ; eax = f(B,C,D), preserves r15
    add  eax, esi               ; + A
    add  eax, [rbp-0x44]        ; + Kl
    mov  edx, [rbp-0x3c]
    add  eax, [rbp-0x90 + rdx*4]; + X[idx_l]
    mov  ecx, [rbp-0x38]
    rol  eax, cl                ; ROL by s[j]
    add  eax, r11d              ; + E
    ; shift left line
    mov  esi,  r11d             ; A  = E
    mov  r11d, r10d             ; E  = D
    mov  edx, r9d
    rol  edx, 10                ; D  = ROL(C,10)
    mov  r10d, edx
    mov  r9d,  r8d              ; C  = B
    mov  r8d,  eax              ; B  = T

    ; ---------- right line ----------
    lea  rax, [RP]
    movzx edx, byte [rax+r15]
    mov  [rbp-0x3c], edx       ; idx_r
    lea  rax, [SPROT]
    movzx edx, byte [rax+r15]
    mov  [rbp-0x38], edx       ; rotl_r
    mov  edx, r15d
    shr  edx, 4
    mov  eax, [KCON + (5+rdx)*4]
    mov  [rbp-0x44], eax       ; Kr
    ; right line function selector: group' = 5 - group (1..5)
    mov  eax, 5
    mov  edx, r15d
    shr  edx, 4
    sub  eax, edx
    mov  [rbp-0x48], eax
    call rmd_f_right            ; eax = g(B2,C2,D2)
    add  eax, edi               ; + A2
    add  eax, [rbp-0x44]        ; + Kr
    mov  edx, [rbp-0x3c]
    add  eax, [rbp-0x90 + rdx*4]; + X[idx_r]
    mov  ecx, [rbp-0x38]
    rol  eax, cl                ; ROL by sp[j]
    add  eax, ebx               ; + E2
    ; shift right line
    mov  edi,  ebx              ; A2 = E2
    mov  ebx,  r14d             ; E2 = D2
    mov  edx, r13d
    rol  edx, 10                ; D2 = ROL(C2,10)
    mov  r14d, edx
    mov  r13d, r12d             ; C2 = B2
    mov  r12d, eax              ; B2 = T

    inc  r15d
    cmp  r15d, 80
    jb   .round

    ; ---------- cross-mix into state and add ----------
    ; Reference (pycryptodome src/RIPEMD160.c final mixing), where the left
    ; line A..E (=esi,r8d,r9d,r10d,r11d) and right line A2..E2 (=edi,r12d,
    ; r13d,r14d,ebx):
    ;   T   = h1 + CL + DR   ;  h1'= h2 + DL + ER
    ;   h2' = h3 + EL + AR   ;  h3'= h4 + AL + BR ;  h4'= h0 + BL + CR
    mov  eax, [rbp-0x2c]       ; h1
    add  eax, r9d              ; + CL (left C)
    add  eax, r14d             ; + DR (right D2)
    mov  [rbp-0x40], eax       ; T
    mov  eax, [rbp-0x28]       ; h2
    add  eax, r10d             ; + DL (left D)
    add  eax, ebx              ; + ER (right E2)
    mov  [rbp-0x2c], eax       ; h1'
    mov  eax, [rbp-0x24]       ; h3
    add  eax, r11d             ; + EL (left E)
    add  eax, edi              ; + AR (right A2)
    mov  [rbp-0x28], eax       ; h2'
    mov  eax, [rbp-0x20]       ; h4
    add  eax, esi              ; + AL (left A)
    add  eax, r12d             ; + BR (right B2)
    mov  [rbp-0x24], eax       ; h3'
    mov  eax, [rbp-0x30]       ; h0
    add  eax, r8d              ; + BL (left B)
    add  eax, r13d             ; + CR (right C2)
    mov  [rbp-0x20], eax       ; h4'
    mov  eax, [rbp-0x40]
    mov  [rbp-0x30], eax       ; h0'
    pop  rbx
    pop  r12
    pop  r13
    pop  r14
    pop  r15
    ret

; ----------------------------------------------------------------------------
; rmd_f_left: eax = f(B,C,D) for the LEFT line: round group (ecx>>4) selects
;   f1..f5. Registers unchanged except eax. B=r8d C=r9d D=r10d.
; ----------------------------------------------------------------------------
rmd_f_left:
    ; group = round>>4 ; round counter lives in r15d (not ecx, which is the
    ; rotate scratch). B=r8d C=r9d D=r10d.
    mov  eax, r15d
    shr  eax, 4
    and  eax, 7                 ; group 0..4
    cmp  eax, 0
    je   .fl1
    cmp  eax, 1
    je   .fl2
    cmp  eax, 2
    je   .fl3
    cmp  eax, 3
    je   .fl4
.fl5:
    ; f5 = B ^ (C | ~D)
    mov  eax, r10d
    not  eax
    or   eax, r9d
    xor  eax, r8d
    ret
.fl1:
    ; f1 = B ^ C ^ D
    mov  eax, r8d
    xor  eax, r9d
    xor  eax, r10d
    ret
.fl2:
    ; f2 = (B & C) | (~B & D)
    mov  eax, r8d
    and  eax, r9d
    mov  edx, r8d
    not  edx
    and  edx, r10d
    or   eax, edx
    ret
.fl3:
    ; f3 = (B | ~C) ^ D
    mov  eax, r9d
    not  eax
    or   eax, r8d
    xor  eax, r10d
    ret
.fl4:
    ; f4 = (B & D) | (C & ~D)
    mov  eax, r8d
    and  eax, r10d
    mov  edx, r10d
    not  edx
    and  edx, r9d
    or   eax, edx
    ret

; ----------------------------------------------------------------------------
; rmd_f_right: eax = g(B2,C2,D2) for the RIGHT line. On entry the function
;   selector is a scalar group' (0..4) passed via a convention -- see caller,
;   which sets [rbp-0x48] to the desired f-number. B2=r12d C2=r13d D2=r14d.
; ----------------------------------------------------------------------------
rmd_f_right:
    mov  eax, [rbp-0x48]        ; which f (1..5)
    cmp  eax, 1
    je   .fr1
    cmp  eax, 2
    je   .fr2
    cmp  eax, 3
    je   .fr3
    cmp  eax, 4
    je   .fr4
.fr5:
    ; f5 = B2 ^ (C2 | ~D2)
    mov  eax, r14d
    not  eax
    or   eax, r13d
    xor  eax, r12d
    ret
.fr1:
    mov  eax, r12d
    xor  eax, r13d
    xor  eax, r14d
    ret
.fr2:
    mov  eax, r12d
    and  eax, r13d
    mov  edx, r12d
    not  edx
    and  edx, r14d
    or   eax, edx
    ret
.fr3:
    mov  eax, r13d
    not  eax
    or   eax, r12d
    xor  eax, r14d
    ret
.fr4:
    mov  eax, r12d
    and  eax, r14d
    mov  edx, r14d
    not  edx
    and  edx, r13d
    or   eax, edx
    ret

; ----------------------------------------------------------------------------
; rmd_rol helper removed -- rotations now done inline with `rol eax, cl` where
; rcx is loaded with the per-round rotation amount (round counter lives in r15).
; ----------------------------------------------------------------------------

; ============================================================================
; ripemd160(u8 out[20], const void *in, i64 len)  -> rdi, rsi, rdx
; One-shot hashing with the standard RIPEMD-160 padding.
;   out : 20-byte digest
;   in  : message (len bytes)
;
; LOCAL FRAME (all at [rbp-...], inside this function's own reservation):
;   state h0..h4   [rbp-0x30,-0x2c,-0x28,-0x24,-0x20]  (5 dwords, updated)
;   working        [rbp-0x40] (T), [rbp-0x44] (K), [rbp-0x48] (f-select)
;   idx/rot        [rbp-0x3c] (idx), [rbp-0x38] (rot)
;   X[16] LE dwords [rbp-0x90..-0x50]
;   pad scratch    [rbp-0x118..-0x99] (128 bytes)
;
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP, NOT BELOW IT.
;   The pushes come before `push rbp`, so rbx/r12/r13/r14/r15 are preserved at
;   [rbp+0x08 .. rbp+0x28] and every [rbp-N] local above is inside the 0x120
;   reservation and cannot alias them.
;   The previous order (`push rbp` / `mov rbp,rsp` / five pushes) put saved r15
;   at rbp-0x28 and saved r14 at rbp-0x20, exactly where state words h2/h3/h4
;   live -- so the epilogue popped digest bytes into the CALLER's r14 and r15.
;   Confirmed by tests/bench_abi_audit before this change.
;   ALIGNMENT IS UNCHANGED: still six pushes then `sub rsp,0x120`, merely
;   reordered, so RSP has the same parity at every instruction after the
;   prologue as it did before (entry 8 -> 5 pushes -> 0 -> push rbp -> 8 ->
;   sub 0x120 -> 8; previously 8 -> push rbp -> 0 -> 5 pushes -> 8 -> 8).
; ============================================================================
ripemd160:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x120           ; locals down to rbp-0x120; X at -0x90, pad at -0x118

    mov  r12, rdi             ; out
    mov  r13, rsi             ; in
    mov  r14, rdx             ; len

    ; ---- init state ----
    lea  rax, [ISTATE]
    mov  ecx, [rax+0]
    mov  [rbp-0x30], ecx
    mov  ecx, [rax+4]
    mov  [rbp-0x2c], ecx
    mov  ecx, [rax+8]
    mov  [rbp-0x28], ecx
    mov  ecx, [rax+12]
    mov  [rbp-0x24], ecx
    mov  ecx, [rax+16]
    mov  [rbp-0x20], ecx

    ; ---- process full 64-byte blocks of the input directly ----
    mov  r15, r14
    shr  r15, 6               ; number of full 64-byte blocks
    xor  rbx, rbx             ; offset in bytes
.block:
    test r15, r15
    jz   .nofull
    ; load 16 LE words from in+offset into [rbp-0x90..]
    lea  rdi, [rbp-0x90]
    mov  rsi, r13
    add  rsi, rbx
    xor  rcx, rcx
.wl:
    mov  eax, [rsi + rcx*4]

    mov  [rdi + rcx*4], eax
    inc  rcx
    cmp  rcx, 16
    jb   .wl
    call rmd160_compress
    add  rbx, 64
    dec  r15
    jmp  .block
.nofull:
    ; ---- build padded tail block(s) in scratch [rbp-0x118] ----
    ; rem = len & 63; copy rem bytes, then 0x80, zeros, then bit-length.
    lea  rdi, [rbp-0x118]     ; scratch
    mov  rcx, r14
    and  rcx, 63              ; rem
    mov  r15, rcx             ; r15 = rem (free now)
    lea  rsi, [rbp-0x118]
    mov  r9, r13
    add  r9, rbx              ; in+offset (end of full blocks)
    xor  r10, r10
.cp:
    cmp  r10, r15
    jae  .cp_done
    mov  al, [r9 + r10]
    mov  [rsi + r10], al
    inc  r10
    jmp  .cp
.cp_done:
    mov  byte [rsi + r15], 0x80
    ; zero from rem+1 up to byte 127 (both blocks' second halves get zeroed)
    lea  r10, [r15 + 1]
.zz:
    cmp  r10, 128
    jae  .zz_done
    mov  byte [rsi + r10], 0
    inc  r10
    jmp  .zz
.zz_done:
    ; bit length (64-bit LE) goes at the end of the FINAL block.
    ; final block is block 0 (if rem<56) or block 1 (if rem>=56).
    mov  rax, r14
    shl  rax, 3               ; bit length
    ; determine final block start: padding (0x80 + 8-byte length) fits in one
    ; block iff rem + 1 + 8 <= 64  <=>  rem <= 55. Otherwise two blocks.
    mov  rcx, r15
    cmp  rcx, 56               ; rem < 56 => single block
    jb   .len_in_block0
    ; two blocks: final is block1 at scratch+64
    mov  qword [rbp-0x118 + 64 + 56], rax
    mov  qword [rbp-0x118 + 64 + 56 - 8], 0  ; (not needed; writable)
    ; pad zeros already set; process BOTH blocks
    ; block0 = scratch+0, block1 = scratch+64
    lea  rdi, [rbp-0x118]
    call rmd_load_compress
    lea  rdi, [rbp-0x118 + 64]
    call rmd_load_compress
    jmp  .out
.len_in_block0:
    mov  qword [rbp-0x118 + 56], rax
    lea  rdi, [rbp-0x118]
    call rmd_load_compress
    jmp  .out

.out:
    ; ---- write 20-byte digest (LE words) as big-endian bytes ----
    mov  eax, [rbp-0x30]

    mov  [r12+0], eax
    mov  eax, [rbp-0x2c]

    mov  [r12+4], eax
    mov  eax, [rbp-0x28]

    mov  [r12+8], eax
    mov  eax, [rbp-0x24]

    mov  [r12+12], eax
    mov  eax, [rbp-0x20]

    mov  [r12+16], eax
    add  rsp, 0x120
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ----------------------------------------------------------------------------
; rmd_load_compress(rdi = 64-byte block). Loads 16 LE words from rdi into
; X[] and runs rmd160_compress. Clobbers rdi,rsi,eax,ecx (and compress regs).
; ----------------------------------------------------------------------------
rmd_load_compress:
    lea  rsi, [rbp-0x90]
    xor  rcx, rcx
.lc:
    mov  eax, [rdi + rcx*4]

    mov  [rsi + rcx*4], eax
    inc  rcx
    cmp  rcx, 16
    jb   .lc
    jmp  rmd160_compress

section .note.GNU-stack noalloc noexec nowrite progbits

