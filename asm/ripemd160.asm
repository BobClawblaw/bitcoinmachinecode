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

    ; ---------- 80 rounds x 2 lines, FULLY UNROLLED (2026-08-23) ----------
    ; The loop version was a per-round interpreter: table loads for idx/shift/K
    ; spilled through the stack plus a CALL into a branch-tree f-selector, for
    ; BOTH lines, every round -- measured 3.16x slower than Core (3.59 vs
    ; 1.14 ns/B, BENCHMARKS.md tier 1). Everything below is generated from the
    ; SAME schedule tables kept in .rodata above (RL/RP/SL/SPROT/KCON, now
    ; reference-only): constants are immediates, round functions are inlined,
    ; state never leaves registers. Register renaming replaces the 5-register
    ; shuffle: each round writes only A and rotates C, and the NEXT round's
    ; macro-expansion uses the rotated name list -- (E,A,B,C,D) -- so the
    ; per-round "mov" chain of the loop version disappears entirely. Left and
    ; right rounds are interleaved L0,R0,L1,R1,... so the two independent
    ; dependency chains sit adjacent in program order and overlap in the OoO
    ; window. eax/edx stay the only scratch, exactly as the header promises.
    ; L0  f1 X[0] s=11
    mov  eax, r8d
    xor  eax, r9d
    xor  eax, r10d
    add  esi, [rbp-0x90+0*4]
    add  esi, eax
    rol  esi, 11
    add  esi, r11d
    rol  r9d, 10
    ; R0  f5 X[5] s=8 K=0x50a28be6
    mov  eax, r14d
    not  eax
    or   eax, r13d
    xor  eax, r12d
    add  edi, [rbp-0x90+5*4]
    add  edi, 0x50a28be6
    add  edi, eax
    rol  edi, 8
    add  edi, ebx
    rol  r13d, 10
    ; L1  f1 X[1] s=14
    mov  eax, esi
    xor  eax, r8d
    xor  eax, r9d
    add  r11d, [rbp-0x90+1*4]
    add  r11d, eax
    rol  r11d, 14
    add  r11d, r10d
    rol  r8d, 10
    ; R1  f5 X[14] s=9 K=0x50a28be6
    mov  eax, r13d
    not  eax
    or   eax, r12d
    xor  eax, edi
    add  ebx, [rbp-0x90+14*4]
    add  ebx, 0x50a28be6
    add  ebx, eax
    rol  ebx, 9
    add  ebx, r14d
    rol  r12d, 10
    ; L2  f1 X[2] s=15
    mov  eax, r11d
    xor  eax, esi
    xor  eax, r8d
    add  r10d, [rbp-0x90+2*4]
    add  r10d, eax
    rol  r10d, 15
    add  r10d, r9d
    rol  esi, 10
    ; R2  f5 X[7] s=9 K=0x50a28be6
    mov  eax, r12d
    not  eax
    or   eax, edi
    xor  eax, ebx
    add  r14d, [rbp-0x90+7*4]
    add  r14d, 0x50a28be6
    add  r14d, eax
    rol  r14d, 9
    add  r14d, r13d
    rol  edi, 10
    ; L3  f1 X[3] s=12
    mov  eax, r10d
    xor  eax, r11d
    xor  eax, esi
    add  r9d, [rbp-0x90+3*4]
    add  r9d, eax
    rol  r9d, 12
    add  r9d, r8d
    rol  r11d, 10
    ; R3  f5 X[0] s=11 K=0x50a28be6
    mov  eax, edi
    not  eax
    or   eax, ebx
    xor  eax, r14d
    add  r13d, [rbp-0x90+0*4]
    add  r13d, 0x50a28be6
    add  r13d, eax
    rol  r13d, 11
    add  r13d, r12d
    rol  ebx, 10
    ; L4  f1 X[4] s=5
    mov  eax, r9d
    xor  eax, r10d
    xor  eax, r11d
    add  r8d, [rbp-0x90+4*4]
    add  r8d, eax
    rol  r8d, 5
    add  r8d, esi
    rol  r10d, 10
    ; R4  f5 X[9] s=13 K=0x50a28be6
    mov  eax, ebx
    not  eax
    or   eax, r14d
    xor  eax, r13d
    add  r12d, [rbp-0x90+9*4]
    add  r12d, 0x50a28be6
    add  r12d, eax
    rol  r12d, 13
    add  r12d, edi
    rol  r14d, 10
    ; L5  f1 X[5] s=8
    mov  eax, r8d
    xor  eax, r9d
    xor  eax, r10d
    add  esi, [rbp-0x90+5*4]
    add  esi, eax
    rol  esi, 8
    add  esi, r11d
    rol  r9d, 10
    ; R5  f5 X[2] s=15 K=0x50a28be6
    mov  eax, r14d
    not  eax
    or   eax, r13d
    xor  eax, r12d
    add  edi, [rbp-0x90+2*4]
    add  edi, 0x50a28be6
    add  edi, eax
    rol  edi, 15
    add  edi, ebx
    rol  r13d, 10
    ; L6  f1 X[6] s=7
    mov  eax, esi
    xor  eax, r8d
    xor  eax, r9d
    add  r11d, [rbp-0x90+6*4]
    add  r11d, eax
    rol  r11d, 7
    add  r11d, r10d
    rol  r8d, 10
    ; R6  f5 X[11] s=15 K=0x50a28be6
    mov  eax, r13d
    not  eax
    or   eax, r12d
    xor  eax, edi
    add  ebx, [rbp-0x90+11*4]
    add  ebx, 0x50a28be6
    add  ebx, eax
    rol  ebx, 15
    add  ebx, r14d
    rol  r12d, 10
    ; L7  f1 X[7] s=9
    mov  eax, r11d
    xor  eax, esi
    xor  eax, r8d
    add  r10d, [rbp-0x90+7*4]
    add  r10d, eax
    rol  r10d, 9
    add  r10d, r9d
    rol  esi, 10
    ; R7  f5 X[4] s=5 K=0x50a28be6
    mov  eax, r12d
    not  eax
    or   eax, edi
    xor  eax, ebx
    add  r14d, [rbp-0x90+4*4]
    add  r14d, 0x50a28be6
    add  r14d, eax
    rol  r14d, 5
    add  r14d, r13d
    rol  edi, 10
    ; L8  f1 X[8] s=11
    mov  eax, r10d
    xor  eax, r11d
    xor  eax, esi
    add  r9d, [rbp-0x90+8*4]
    add  r9d, eax
    rol  r9d, 11
    add  r9d, r8d
    rol  r11d, 10
    ; R8  f5 X[13] s=7 K=0x50a28be6
    mov  eax, edi
    not  eax
    or   eax, ebx
    xor  eax, r14d
    add  r13d, [rbp-0x90+13*4]
    add  r13d, 0x50a28be6
    add  r13d, eax
    rol  r13d, 7
    add  r13d, r12d
    rol  ebx, 10
    ; L9  f1 X[9] s=13
    mov  eax, r9d
    xor  eax, r10d
    xor  eax, r11d
    add  r8d, [rbp-0x90+9*4]
    add  r8d, eax
    rol  r8d, 13
    add  r8d, esi
    rol  r10d, 10
    ; R9  f5 X[6] s=7 K=0x50a28be6
    mov  eax, ebx
    not  eax
    or   eax, r14d
    xor  eax, r13d
    add  r12d, [rbp-0x90+6*4]
    add  r12d, 0x50a28be6
    add  r12d, eax
    rol  r12d, 7
    add  r12d, edi
    rol  r14d, 10
    ; L10  f1 X[10] s=14
    mov  eax, r8d
    xor  eax, r9d
    xor  eax, r10d
    add  esi, [rbp-0x90+10*4]
    add  esi, eax
    rol  esi, 14
    add  esi, r11d
    rol  r9d, 10
    ; R10  f5 X[15] s=8 K=0x50a28be6
    mov  eax, r14d
    not  eax
    or   eax, r13d
    xor  eax, r12d
    add  edi, [rbp-0x90+15*4]
    add  edi, 0x50a28be6
    add  edi, eax
    rol  edi, 8
    add  edi, ebx
    rol  r13d, 10
    ; L11  f1 X[11] s=15
    mov  eax, esi
    xor  eax, r8d
    xor  eax, r9d
    add  r11d, [rbp-0x90+11*4]
    add  r11d, eax
    rol  r11d, 15
    add  r11d, r10d
    rol  r8d, 10
    ; R11  f5 X[8] s=11 K=0x50a28be6
    mov  eax, r13d
    not  eax
    or   eax, r12d
    xor  eax, edi
    add  ebx, [rbp-0x90+8*4]
    add  ebx, 0x50a28be6
    add  ebx, eax
    rol  ebx, 11
    add  ebx, r14d
    rol  r12d, 10
    ; L12  f1 X[12] s=6
    mov  eax, r11d
    xor  eax, esi
    xor  eax, r8d
    add  r10d, [rbp-0x90+12*4]
    add  r10d, eax
    rol  r10d, 6
    add  r10d, r9d
    rol  esi, 10
    ; R12  f5 X[1] s=14 K=0x50a28be6
    mov  eax, r12d
    not  eax
    or   eax, edi
    xor  eax, ebx
    add  r14d, [rbp-0x90+1*4]
    add  r14d, 0x50a28be6
    add  r14d, eax
    rol  r14d, 14
    add  r14d, r13d
    rol  edi, 10
    ; L13  f1 X[13] s=7
    mov  eax, r10d
    xor  eax, r11d
    xor  eax, esi
    add  r9d, [rbp-0x90+13*4]
    add  r9d, eax
    rol  r9d, 7
    add  r9d, r8d
    rol  r11d, 10
    ; R13  f5 X[10] s=14 K=0x50a28be6
    mov  eax, edi
    not  eax
    or   eax, ebx
    xor  eax, r14d
    add  r13d, [rbp-0x90+10*4]
    add  r13d, 0x50a28be6
    add  r13d, eax
    rol  r13d, 14
    add  r13d, r12d
    rol  ebx, 10
    ; L14  f1 X[14] s=9
    mov  eax, r9d
    xor  eax, r10d
    xor  eax, r11d
    add  r8d, [rbp-0x90+14*4]
    add  r8d, eax
    rol  r8d, 9
    add  r8d, esi
    rol  r10d, 10
    ; R14  f5 X[3] s=12 K=0x50a28be6
    mov  eax, ebx
    not  eax
    or   eax, r14d
    xor  eax, r13d
    add  r12d, [rbp-0x90+3*4]
    add  r12d, 0x50a28be6
    add  r12d, eax
    rol  r12d, 12
    add  r12d, edi
    rol  r14d, 10
    ; L15  f1 X[15] s=8
    mov  eax, r8d
    xor  eax, r9d
    xor  eax, r10d
    add  esi, [rbp-0x90+15*4]
    add  esi, eax
    rol  esi, 8
    add  esi, r11d
    rol  r9d, 10
    ; R15  f5 X[12] s=6 K=0x50a28be6
    mov  eax, r14d
    not  eax
    or   eax, r13d
    xor  eax, r12d
    add  edi, [rbp-0x90+12*4]
    add  edi, 0x50a28be6
    add  edi, eax
    rol  edi, 6
    add  edi, ebx
    rol  r13d, 10
    ; L16  f2 X[7] s=7 K=0x5a827999
    mov  eax, r8d
    xor  eax, r9d
    and  eax, esi
    xor  eax, r9d
    add  r11d, [rbp-0x90+7*4]
    add  r11d, 0x5a827999
    add  r11d, eax
    rol  r11d, 7
    add  r11d, r10d
    rol  r8d, 10
    ; R16  f4 X[6] s=9 K=0x5c4dd124
    mov  eax, edi
    xor  eax, r12d
    and  eax, r13d
    xor  eax, r12d
    add  ebx, [rbp-0x90+6*4]
    add  ebx, 0x5c4dd124
    add  ebx, eax
    rol  ebx, 9
    add  ebx, r14d
    rol  r12d, 10
    ; L17  f2 X[4] s=6 K=0x5a827999
    mov  eax, esi
    xor  eax, r8d
    and  eax, r11d
    xor  eax, r8d
    add  r10d, [rbp-0x90+4*4]
    add  r10d, 0x5a827999
    add  r10d, eax
    rol  r10d, 6
    add  r10d, r9d
    rol  esi, 10
    ; R17  f4 X[11] s=13 K=0x5c4dd124
    mov  eax, ebx
    xor  eax, edi
    and  eax, r12d
    xor  eax, edi
    add  r14d, [rbp-0x90+11*4]
    add  r14d, 0x5c4dd124
    add  r14d, eax
    rol  r14d, 13
    add  r14d, r13d
    rol  edi, 10
    ; L18  f2 X[13] s=8 K=0x5a827999
    mov  eax, r11d
    xor  eax, esi
    and  eax, r10d
    xor  eax, esi
    add  r9d, [rbp-0x90+13*4]
    add  r9d, 0x5a827999
    add  r9d, eax
    rol  r9d, 8
    add  r9d, r8d
    rol  r11d, 10
    ; R18  f4 X[3] s=15 K=0x5c4dd124
    mov  eax, r14d
    xor  eax, ebx
    and  eax, edi
    xor  eax, ebx
    add  r13d, [rbp-0x90+3*4]
    add  r13d, 0x5c4dd124
    add  r13d, eax
    rol  r13d, 15
    add  r13d, r12d
    rol  ebx, 10
    ; L19  f2 X[1] s=13 K=0x5a827999
    mov  eax, r10d
    xor  eax, r11d
    and  eax, r9d
    xor  eax, r11d
    add  r8d, [rbp-0x90+1*4]
    add  r8d, 0x5a827999
    add  r8d, eax
    rol  r8d, 13
    add  r8d, esi
    rol  r10d, 10
    ; R19  f4 X[7] s=7 K=0x5c4dd124
    mov  eax, r13d
    xor  eax, r14d
    and  eax, ebx
    xor  eax, r14d
    add  r12d, [rbp-0x90+7*4]
    add  r12d, 0x5c4dd124
    add  r12d, eax
    rol  r12d, 7
    add  r12d, edi
    rol  r14d, 10
    ; L20  f2 X[10] s=11 K=0x5a827999
    mov  eax, r9d
    xor  eax, r10d
    and  eax, r8d
    xor  eax, r10d
    add  esi, [rbp-0x90+10*4]
    add  esi, 0x5a827999
    add  esi, eax
    rol  esi, 11
    add  esi, r11d
    rol  r9d, 10
    ; R20  f4 X[0] s=12 K=0x5c4dd124
    mov  eax, r12d
    xor  eax, r13d
    and  eax, r14d
    xor  eax, r13d
    add  edi, [rbp-0x90+0*4]
    add  edi, 0x5c4dd124
    add  edi, eax
    rol  edi, 12
    add  edi, ebx
    rol  r13d, 10
    ; L21  f2 X[6] s=9 K=0x5a827999
    mov  eax, r8d
    xor  eax, r9d
    and  eax, esi
    xor  eax, r9d
    add  r11d, [rbp-0x90+6*4]
    add  r11d, 0x5a827999
    add  r11d, eax
    rol  r11d, 9
    add  r11d, r10d
    rol  r8d, 10
    ; R21  f4 X[13] s=8 K=0x5c4dd124
    mov  eax, edi
    xor  eax, r12d
    and  eax, r13d
    xor  eax, r12d
    add  ebx, [rbp-0x90+13*4]
    add  ebx, 0x5c4dd124
    add  ebx, eax
    rol  ebx, 8
    add  ebx, r14d
    rol  r12d, 10
    ; L22  f2 X[15] s=7 K=0x5a827999
    mov  eax, esi
    xor  eax, r8d
    and  eax, r11d
    xor  eax, r8d
    add  r10d, [rbp-0x90+15*4]
    add  r10d, 0x5a827999
    add  r10d, eax
    rol  r10d, 7
    add  r10d, r9d
    rol  esi, 10
    ; R22  f4 X[5] s=9 K=0x5c4dd124
    mov  eax, ebx
    xor  eax, edi
    and  eax, r12d
    xor  eax, edi
    add  r14d, [rbp-0x90+5*4]
    add  r14d, 0x5c4dd124
    add  r14d, eax
    rol  r14d, 9
    add  r14d, r13d
    rol  edi, 10
    ; L23  f2 X[3] s=15 K=0x5a827999
    mov  eax, r11d
    xor  eax, esi
    and  eax, r10d
    xor  eax, esi
    add  r9d, [rbp-0x90+3*4]
    add  r9d, 0x5a827999
    add  r9d, eax
    rol  r9d, 15
    add  r9d, r8d
    rol  r11d, 10
    ; R23  f4 X[10] s=11 K=0x5c4dd124
    mov  eax, r14d
    xor  eax, ebx
    and  eax, edi
    xor  eax, ebx
    add  r13d, [rbp-0x90+10*4]
    add  r13d, 0x5c4dd124
    add  r13d, eax
    rol  r13d, 11
    add  r13d, r12d
    rol  ebx, 10
    ; L24  f2 X[12] s=7 K=0x5a827999
    mov  eax, r10d
    xor  eax, r11d
    and  eax, r9d
    xor  eax, r11d
    add  r8d, [rbp-0x90+12*4]
    add  r8d, 0x5a827999
    add  r8d, eax
    rol  r8d, 7
    add  r8d, esi
    rol  r10d, 10
    ; R24  f4 X[14] s=7 K=0x5c4dd124
    mov  eax, r13d
    xor  eax, r14d
    and  eax, ebx
    xor  eax, r14d
    add  r12d, [rbp-0x90+14*4]
    add  r12d, 0x5c4dd124
    add  r12d, eax
    rol  r12d, 7
    add  r12d, edi
    rol  r14d, 10
    ; L25  f2 X[0] s=12 K=0x5a827999
    mov  eax, r9d
    xor  eax, r10d
    and  eax, r8d
    xor  eax, r10d
    add  esi, [rbp-0x90+0*4]
    add  esi, 0x5a827999
    add  esi, eax
    rol  esi, 12
    add  esi, r11d
    rol  r9d, 10
    ; R25  f4 X[15] s=7 K=0x5c4dd124
    mov  eax, r12d
    xor  eax, r13d
    and  eax, r14d
    xor  eax, r13d
    add  edi, [rbp-0x90+15*4]
    add  edi, 0x5c4dd124
    add  edi, eax
    rol  edi, 7
    add  edi, ebx
    rol  r13d, 10
    ; L26  f2 X[9] s=15 K=0x5a827999
    mov  eax, r8d
    xor  eax, r9d
    and  eax, esi
    xor  eax, r9d
    add  r11d, [rbp-0x90+9*4]
    add  r11d, 0x5a827999
    add  r11d, eax
    rol  r11d, 15
    add  r11d, r10d
    rol  r8d, 10
    ; R26  f4 X[8] s=12 K=0x5c4dd124
    mov  eax, edi
    xor  eax, r12d
    and  eax, r13d
    xor  eax, r12d
    add  ebx, [rbp-0x90+8*4]
    add  ebx, 0x5c4dd124
    add  ebx, eax
    rol  ebx, 12
    add  ebx, r14d
    rol  r12d, 10
    ; L27  f2 X[5] s=9 K=0x5a827999
    mov  eax, esi
    xor  eax, r8d
    and  eax, r11d
    xor  eax, r8d
    add  r10d, [rbp-0x90+5*4]
    add  r10d, 0x5a827999
    add  r10d, eax
    rol  r10d, 9
    add  r10d, r9d
    rol  esi, 10
    ; R27  f4 X[12] s=7 K=0x5c4dd124
    mov  eax, ebx
    xor  eax, edi
    and  eax, r12d
    xor  eax, edi
    add  r14d, [rbp-0x90+12*4]
    add  r14d, 0x5c4dd124
    add  r14d, eax
    rol  r14d, 7
    add  r14d, r13d
    rol  edi, 10
    ; L28  f2 X[2] s=11 K=0x5a827999
    mov  eax, r11d
    xor  eax, esi
    and  eax, r10d
    xor  eax, esi
    add  r9d, [rbp-0x90+2*4]
    add  r9d, 0x5a827999
    add  r9d, eax
    rol  r9d, 11
    add  r9d, r8d
    rol  r11d, 10
    ; R28  f4 X[4] s=6 K=0x5c4dd124
    mov  eax, r14d
    xor  eax, ebx
    and  eax, edi
    xor  eax, ebx
    add  r13d, [rbp-0x90+4*4]
    add  r13d, 0x5c4dd124
    add  r13d, eax
    rol  r13d, 6
    add  r13d, r12d
    rol  ebx, 10
    ; L29  f2 X[14] s=7 K=0x5a827999
    mov  eax, r10d
    xor  eax, r11d
    and  eax, r9d
    xor  eax, r11d
    add  r8d, [rbp-0x90+14*4]
    add  r8d, 0x5a827999
    add  r8d, eax
    rol  r8d, 7
    add  r8d, esi
    rol  r10d, 10
    ; R29  f4 X[9] s=15 K=0x5c4dd124
    mov  eax, r13d
    xor  eax, r14d
    and  eax, ebx
    xor  eax, r14d
    add  r12d, [rbp-0x90+9*4]
    add  r12d, 0x5c4dd124
    add  r12d, eax
    rol  r12d, 15
    add  r12d, edi
    rol  r14d, 10
    ; L30  f2 X[11] s=13 K=0x5a827999
    mov  eax, r9d
    xor  eax, r10d
    and  eax, r8d
    xor  eax, r10d
    add  esi, [rbp-0x90+11*4]
    add  esi, 0x5a827999
    add  esi, eax
    rol  esi, 13
    add  esi, r11d
    rol  r9d, 10
    ; R30  f4 X[1] s=13 K=0x5c4dd124
    mov  eax, r12d
    xor  eax, r13d
    and  eax, r14d
    xor  eax, r13d
    add  edi, [rbp-0x90+1*4]
    add  edi, 0x5c4dd124
    add  edi, eax
    rol  edi, 13
    add  edi, ebx
    rol  r13d, 10
    ; L31  f2 X[8] s=12 K=0x5a827999
    mov  eax, r8d
    xor  eax, r9d
    and  eax, esi
    xor  eax, r9d
    add  r11d, [rbp-0x90+8*4]
    add  r11d, 0x5a827999
    add  r11d, eax
    rol  r11d, 12
    add  r11d, r10d
    rol  r8d, 10
    ; R31  f4 X[2] s=11 K=0x5c4dd124
    mov  eax, edi
    xor  eax, r12d
    and  eax, r13d
    xor  eax, r12d
    add  ebx, [rbp-0x90+2*4]
    add  ebx, 0x5c4dd124
    add  ebx, eax
    rol  ebx, 11
    add  ebx, r14d
    rol  r12d, 10
    ; L32  f3 X[3] s=11 K=0x6ed9eba1
    mov  eax, esi
    not  eax
    or   eax, r11d
    xor  eax, r8d
    add  r10d, [rbp-0x90+3*4]
    add  r10d, 0x6ed9eba1
    add  r10d, eax
    rol  r10d, 11
    add  r10d, r9d
    rol  esi, 10
    ; R32  f3 X[15] s=9 K=0x6d703ef3
    mov  eax, edi
    not  eax
    or   eax, ebx
    xor  eax, r12d
    add  r14d, [rbp-0x90+15*4]
    add  r14d, 0x6d703ef3
    add  r14d, eax
    rol  r14d, 9
    add  r14d, r13d
    rol  edi, 10
    ; L33  f3 X[10] s=13 K=0x6ed9eba1
    mov  eax, r11d
    not  eax
    or   eax, r10d
    xor  eax, esi
    add  r9d, [rbp-0x90+10*4]
    add  r9d, 0x6ed9eba1
    add  r9d, eax
    rol  r9d, 13
    add  r9d, r8d
    rol  r11d, 10
    ; R33  f3 X[5] s=7 K=0x6d703ef3
    mov  eax, ebx
    not  eax
    or   eax, r14d
    xor  eax, edi
    add  r13d, [rbp-0x90+5*4]
    add  r13d, 0x6d703ef3
    add  r13d, eax
    rol  r13d, 7
    add  r13d, r12d
    rol  ebx, 10
    ; L34  f3 X[14] s=6 K=0x6ed9eba1
    mov  eax, r10d
    not  eax
    or   eax, r9d
    xor  eax, r11d
    add  r8d, [rbp-0x90+14*4]
    add  r8d, 0x6ed9eba1
    add  r8d, eax
    rol  r8d, 6
    add  r8d, esi
    rol  r10d, 10
    ; R34  f3 X[1] s=15 K=0x6d703ef3
    mov  eax, r14d
    not  eax
    or   eax, r13d
    xor  eax, ebx
    add  r12d, [rbp-0x90+1*4]
    add  r12d, 0x6d703ef3
    add  r12d, eax
    rol  r12d, 15
    add  r12d, edi
    rol  r14d, 10
    ; L35  f3 X[4] s=7 K=0x6ed9eba1
    mov  eax, r9d
    not  eax
    or   eax, r8d
    xor  eax, r10d
    add  esi, [rbp-0x90+4*4]
    add  esi, 0x6ed9eba1
    add  esi, eax
    rol  esi, 7
    add  esi, r11d
    rol  r9d, 10
    ; R35  f3 X[3] s=11 K=0x6d703ef3
    mov  eax, r13d
    not  eax
    or   eax, r12d
    xor  eax, r14d
    add  edi, [rbp-0x90+3*4]
    add  edi, 0x6d703ef3
    add  edi, eax
    rol  edi, 11
    add  edi, ebx
    rol  r13d, 10
    ; L36  f3 X[9] s=14 K=0x6ed9eba1
    mov  eax, r8d
    not  eax
    or   eax, esi
    xor  eax, r9d
    add  r11d, [rbp-0x90+9*4]
    add  r11d, 0x6ed9eba1
    add  r11d, eax
    rol  r11d, 14
    add  r11d, r10d
    rol  r8d, 10
    ; R36  f3 X[7] s=8 K=0x6d703ef3
    mov  eax, r12d
    not  eax
    or   eax, edi
    xor  eax, r13d
    add  ebx, [rbp-0x90+7*4]
    add  ebx, 0x6d703ef3
    add  ebx, eax
    rol  ebx, 8
    add  ebx, r14d
    rol  r12d, 10
    ; L37  f3 X[15] s=9 K=0x6ed9eba1
    mov  eax, esi
    not  eax
    or   eax, r11d
    xor  eax, r8d
    add  r10d, [rbp-0x90+15*4]
    add  r10d, 0x6ed9eba1
    add  r10d, eax
    rol  r10d, 9
    add  r10d, r9d
    rol  esi, 10
    ; R37  f3 X[14] s=6 K=0x6d703ef3
    mov  eax, edi
    not  eax
    or   eax, ebx
    xor  eax, r12d
    add  r14d, [rbp-0x90+14*4]
    add  r14d, 0x6d703ef3
    add  r14d, eax
    rol  r14d, 6
    add  r14d, r13d
    rol  edi, 10
    ; L38  f3 X[8] s=13 K=0x6ed9eba1
    mov  eax, r11d
    not  eax
    or   eax, r10d
    xor  eax, esi
    add  r9d, [rbp-0x90+8*4]
    add  r9d, 0x6ed9eba1
    add  r9d, eax
    rol  r9d, 13
    add  r9d, r8d
    rol  r11d, 10
    ; R38  f3 X[6] s=6 K=0x6d703ef3
    mov  eax, ebx
    not  eax
    or   eax, r14d
    xor  eax, edi
    add  r13d, [rbp-0x90+6*4]
    add  r13d, 0x6d703ef3
    add  r13d, eax
    rol  r13d, 6
    add  r13d, r12d
    rol  ebx, 10
    ; L39  f3 X[1] s=15 K=0x6ed9eba1
    mov  eax, r10d
    not  eax
    or   eax, r9d
    xor  eax, r11d
    add  r8d, [rbp-0x90+1*4]
    add  r8d, 0x6ed9eba1
    add  r8d, eax
    rol  r8d, 15
    add  r8d, esi
    rol  r10d, 10
    ; R39  f3 X[9] s=14 K=0x6d703ef3
    mov  eax, r14d
    not  eax
    or   eax, r13d
    xor  eax, ebx
    add  r12d, [rbp-0x90+9*4]
    add  r12d, 0x6d703ef3
    add  r12d, eax
    rol  r12d, 14
    add  r12d, edi
    rol  r14d, 10
    ; L40  f3 X[2] s=14 K=0x6ed9eba1
    mov  eax, r9d
    not  eax
    or   eax, r8d
    xor  eax, r10d
    add  esi, [rbp-0x90+2*4]
    add  esi, 0x6ed9eba1
    add  esi, eax
    rol  esi, 14
    add  esi, r11d
    rol  r9d, 10
    ; R40  f3 X[11] s=12 K=0x6d703ef3
    mov  eax, r13d
    not  eax
    or   eax, r12d
    xor  eax, r14d
    add  edi, [rbp-0x90+11*4]
    add  edi, 0x6d703ef3
    add  edi, eax
    rol  edi, 12
    add  edi, ebx
    rol  r13d, 10
    ; L41  f3 X[7] s=8 K=0x6ed9eba1
    mov  eax, r8d
    not  eax
    or   eax, esi
    xor  eax, r9d
    add  r11d, [rbp-0x90+7*4]
    add  r11d, 0x6ed9eba1
    add  r11d, eax
    rol  r11d, 8
    add  r11d, r10d
    rol  r8d, 10
    ; R41  f3 X[8] s=13 K=0x6d703ef3
    mov  eax, r12d
    not  eax
    or   eax, edi
    xor  eax, r13d
    add  ebx, [rbp-0x90+8*4]
    add  ebx, 0x6d703ef3
    add  ebx, eax
    rol  ebx, 13
    add  ebx, r14d
    rol  r12d, 10
    ; L42  f3 X[0] s=13 K=0x6ed9eba1
    mov  eax, esi
    not  eax
    or   eax, r11d
    xor  eax, r8d
    add  r10d, [rbp-0x90+0*4]
    add  r10d, 0x6ed9eba1
    add  r10d, eax
    rol  r10d, 13
    add  r10d, r9d
    rol  esi, 10
    ; R42  f3 X[12] s=5 K=0x6d703ef3
    mov  eax, edi
    not  eax
    or   eax, ebx
    xor  eax, r12d
    add  r14d, [rbp-0x90+12*4]
    add  r14d, 0x6d703ef3
    add  r14d, eax
    rol  r14d, 5
    add  r14d, r13d
    rol  edi, 10
    ; L43  f3 X[6] s=6 K=0x6ed9eba1
    mov  eax, r11d
    not  eax
    or   eax, r10d
    xor  eax, esi
    add  r9d, [rbp-0x90+6*4]
    add  r9d, 0x6ed9eba1
    add  r9d, eax
    rol  r9d, 6
    add  r9d, r8d
    rol  r11d, 10
    ; R43  f3 X[2] s=14 K=0x6d703ef3
    mov  eax, ebx
    not  eax
    or   eax, r14d
    xor  eax, edi
    add  r13d, [rbp-0x90+2*4]
    add  r13d, 0x6d703ef3
    add  r13d, eax
    rol  r13d, 14
    add  r13d, r12d
    rol  ebx, 10
    ; L44  f3 X[13] s=5 K=0x6ed9eba1
    mov  eax, r10d
    not  eax
    or   eax, r9d
    xor  eax, r11d
    add  r8d, [rbp-0x90+13*4]
    add  r8d, 0x6ed9eba1
    add  r8d, eax
    rol  r8d, 5
    add  r8d, esi
    rol  r10d, 10
    ; R44  f3 X[10] s=13 K=0x6d703ef3
    mov  eax, r14d
    not  eax
    or   eax, r13d
    xor  eax, ebx
    add  r12d, [rbp-0x90+10*4]
    add  r12d, 0x6d703ef3
    add  r12d, eax
    rol  r12d, 13
    add  r12d, edi
    rol  r14d, 10
    ; L45  f3 X[11] s=12 K=0x6ed9eba1
    mov  eax, r9d
    not  eax
    or   eax, r8d
    xor  eax, r10d
    add  esi, [rbp-0x90+11*4]
    add  esi, 0x6ed9eba1
    add  esi, eax
    rol  esi, 12
    add  esi, r11d
    rol  r9d, 10
    ; R45  f3 X[0] s=13 K=0x6d703ef3
    mov  eax, r13d
    not  eax
    or   eax, r12d
    xor  eax, r14d
    add  edi, [rbp-0x90+0*4]
    add  edi, 0x6d703ef3
    add  edi, eax
    rol  edi, 13
    add  edi, ebx
    rol  r13d, 10
    ; L46  f3 X[5] s=7 K=0x6ed9eba1
    mov  eax, r8d
    not  eax
    or   eax, esi
    xor  eax, r9d
    add  r11d, [rbp-0x90+5*4]
    add  r11d, 0x6ed9eba1
    add  r11d, eax
    rol  r11d, 7
    add  r11d, r10d
    rol  r8d, 10
    ; R46  f3 X[4] s=7 K=0x6d703ef3
    mov  eax, r12d
    not  eax
    or   eax, edi
    xor  eax, r13d
    add  ebx, [rbp-0x90+4*4]
    add  ebx, 0x6d703ef3
    add  ebx, eax
    rol  ebx, 7
    add  ebx, r14d
    rol  r12d, 10
    ; L47  f3 X[12] s=5 K=0x6ed9eba1
    mov  eax, esi
    not  eax
    or   eax, r11d
    xor  eax, r8d
    add  r10d, [rbp-0x90+12*4]
    add  r10d, 0x6ed9eba1
    add  r10d, eax
    rol  r10d, 5
    add  r10d, r9d
    rol  esi, 10
    ; R47  f3 X[13] s=5 K=0x6d703ef3
    mov  eax, edi
    not  eax
    or   eax, ebx
    xor  eax, r12d
    add  r14d, [rbp-0x90+13*4]
    add  r14d, 0x6d703ef3
    add  r14d, eax
    rol  r14d, 5
    add  r14d, r13d
    rol  edi, 10
    ; L48  f4 X[1] s=11 K=0x8f1bbcdc
    mov  eax, r10d
    xor  eax, r11d
    and  eax, esi
    xor  eax, r11d
    add  r9d, [rbp-0x90+1*4]
    add  r9d, 0x8f1bbcdc
    add  r9d, eax
    rol  r9d, 11
    add  r9d, r8d
    rol  r11d, 10
    ; R48  f2 X[8] s=15 K=0x7a6d76e9
    mov  eax, ebx
    xor  eax, edi
    and  eax, r14d
    xor  eax, edi
    add  r13d, [rbp-0x90+8*4]
    add  r13d, 0x7a6d76e9
    add  r13d, eax
    rol  r13d, 15
    add  r13d, r12d
    rol  ebx, 10
    ; L49  f4 X[9] s=12 K=0x8f1bbcdc
    mov  eax, r9d
    xor  eax, r10d
    and  eax, r11d
    xor  eax, r10d
    add  r8d, [rbp-0x90+9*4]
    add  r8d, 0x8f1bbcdc
    add  r8d, eax
    rol  r8d, 12
    add  r8d, esi
    rol  r10d, 10
    ; R49  f2 X[6] s=5 K=0x7a6d76e9
    mov  eax, r14d
    xor  eax, ebx
    and  eax, r13d
    xor  eax, ebx
    add  r12d, [rbp-0x90+6*4]
    add  r12d, 0x7a6d76e9
    add  r12d, eax
    rol  r12d, 5
    add  r12d, edi
    rol  r14d, 10
    ; L50  f4 X[11] s=14 K=0x8f1bbcdc
    mov  eax, r8d
    xor  eax, r9d
    and  eax, r10d
    xor  eax, r9d
    add  esi, [rbp-0x90+11*4]
    add  esi, 0x8f1bbcdc
    add  esi, eax
    rol  esi, 14
    add  esi, r11d
    rol  r9d, 10
    ; R50  f2 X[4] s=8 K=0x7a6d76e9
    mov  eax, r13d
    xor  eax, r14d
    and  eax, r12d
    xor  eax, r14d
    add  edi, [rbp-0x90+4*4]
    add  edi, 0x7a6d76e9
    add  edi, eax
    rol  edi, 8
    add  edi, ebx
    rol  r13d, 10
    ; L51  f4 X[10] s=15 K=0x8f1bbcdc
    mov  eax, esi
    xor  eax, r8d
    and  eax, r9d
    xor  eax, r8d
    add  r11d, [rbp-0x90+10*4]
    add  r11d, 0x8f1bbcdc
    add  r11d, eax
    rol  r11d, 15
    add  r11d, r10d
    rol  r8d, 10
    ; R51  f2 X[1] s=11 K=0x7a6d76e9
    mov  eax, r12d
    xor  eax, r13d
    and  eax, edi
    xor  eax, r13d
    add  ebx, [rbp-0x90+1*4]
    add  ebx, 0x7a6d76e9
    add  ebx, eax
    rol  ebx, 11
    add  ebx, r14d
    rol  r12d, 10
    ; L52  f4 X[0] s=14 K=0x8f1bbcdc
    mov  eax, r11d
    xor  eax, esi
    and  eax, r8d
    xor  eax, esi
    add  r10d, [rbp-0x90+0*4]
    add  r10d, 0x8f1bbcdc
    add  r10d, eax
    rol  r10d, 14
    add  r10d, r9d
    rol  esi, 10
    ; R52  f2 X[3] s=14 K=0x7a6d76e9
    mov  eax, edi
    xor  eax, r12d
    and  eax, ebx
    xor  eax, r12d
    add  r14d, [rbp-0x90+3*4]
    add  r14d, 0x7a6d76e9
    add  r14d, eax
    rol  r14d, 14
    add  r14d, r13d
    rol  edi, 10
    ; L53  f4 X[8] s=15 K=0x8f1bbcdc
    mov  eax, r10d
    xor  eax, r11d
    and  eax, esi
    xor  eax, r11d
    add  r9d, [rbp-0x90+8*4]
    add  r9d, 0x8f1bbcdc
    add  r9d, eax
    rol  r9d, 15
    add  r9d, r8d
    rol  r11d, 10
    ; R53  f2 X[11] s=14 K=0x7a6d76e9
    mov  eax, ebx
    xor  eax, edi
    and  eax, r14d
    xor  eax, edi
    add  r13d, [rbp-0x90+11*4]
    add  r13d, 0x7a6d76e9
    add  r13d, eax
    rol  r13d, 14
    add  r13d, r12d
    rol  ebx, 10
    ; L54  f4 X[12] s=9 K=0x8f1bbcdc
    mov  eax, r9d
    xor  eax, r10d
    and  eax, r11d
    xor  eax, r10d
    add  r8d, [rbp-0x90+12*4]
    add  r8d, 0x8f1bbcdc
    add  r8d, eax
    rol  r8d, 9
    add  r8d, esi
    rol  r10d, 10
    ; R54  f2 X[15] s=6 K=0x7a6d76e9
    mov  eax, r14d
    xor  eax, ebx
    and  eax, r13d
    xor  eax, ebx
    add  r12d, [rbp-0x90+15*4]
    add  r12d, 0x7a6d76e9
    add  r12d, eax
    rol  r12d, 6
    add  r12d, edi
    rol  r14d, 10
    ; L55  f4 X[4] s=8 K=0x8f1bbcdc
    mov  eax, r8d
    xor  eax, r9d
    and  eax, r10d
    xor  eax, r9d
    add  esi, [rbp-0x90+4*4]
    add  esi, 0x8f1bbcdc
    add  esi, eax
    rol  esi, 8
    add  esi, r11d
    rol  r9d, 10
    ; R55  f2 X[0] s=14 K=0x7a6d76e9
    mov  eax, r13d
    xor  eax, r14d
    and  eax, r12d
    xor  eax, r14d
    add  edi, [rbp-0x90+0*4]
    add  edi, 0x7a6d76e9
    add  edi, eax
    rol  edi, 14
    add  edi, ebx
    rol  r13d, 10
    ; L56  f4 X[13] s=9 K=0x8f1bbcdc
    mov  eax, esi
    xor  eax, r8d
    and  eax, r9d
    xor  eax, r8d
    add  r11d, [rbp-0x90+13*4]
    add  r11d, 0x8f1bbcdc
    add  r11d, eax
    rol  r11d, 9
    add  r11d, r10d
    rol  r8d, 10
    ; R56  f2 X[5] s=6 K=0x7a6d76e9
    mov  eax, r12d
    xor  eax, r13d
    and  eax, edi
    xor  eax, r13d
    add  ebx, [rbp-0x90+5*4]
    add  ebx, 0x7a6d76e9
    add  ebx, eax
    rol  ebx, 6
    add  ebx, r14d
    rol  r12d, 10
    ; L57  f4 X[3] s=14 K=0x8f1bbcdc
    mov  eax, r11d
    xor  eax, esi
    and  eax, r8d
    xor  eax, esi
    add  r10d, [rbp-0x90+3*4]
    add  r10d, 0x8f1bbcdc
    add  r10d, eax
    rol  r10d, 14
    add  r10d, r9d
    rol  esi, 10
    ; R57  f2 X[12] s=9 K=0x7a6d76e9
    mov  eax, edi
    xor  eax, r12d
    and  eax, ebx
    xor  eax, r12d
    add  r14d, [rbp-0x90+12*4]
    add  r14d, 0x7a6d76e9
    add  r14d, eax
    rol  r14d, 9
    add  r14d, r13d
    rol  edi, 10
    ; L58  f4 X[7] s=5 K=0x8f1bbcdc
    mov  eax, r10d
    xor  eax, r11d
    and  eax, esi
    xor  eax, r11d
    add  r9d, [rbp-0x90+7*4]
    add  r9d, 0x8f1bbcdc
    add  r9d, eax
    rol  r9d, 5
    add  r9d, r8d
    rol  r11d, 10
    ; R58  f2 X[2] s=12 K=0x7a6d76e9
    mov  eax, ebx
    xor  eax, edi
    and  eax, r14d
    xor  eax, edi
    add  r13d, [rbp-0x90+2*4]
    add  r13d, 0x7a6d76e9
    add  r13d, eax
    rol  r13d, 12
    add  r13d, r12d
    rol  ebx, 10
    ; L59  f4 X[15] s=6 K=0x8f1bbcdc
    mov  eax, r9d
    xor  eax, r10d
    and  eax, r11d
    xor  eax, r10d
    add  r8d, [rbp-0x90+15*4]
    add  r8d, 0x8f1bbcdc
    add  r8d, eax
    rol  r8d, 6
    add  r8d, esi
    rol  r10d, 10
    ; R59  f2 X[13] s=9 K=0x7a6d76e9
    mov  eax, r14d
    xor  eax, ebx
    and  eax, r13d
    xor  eax, ebx
    add  r12d, [rbp-0x90+13*4]
    add  r12d, 0x7a6d76e9
    add  r12d, eax
    rol  r12d, 9
    add  r12d, edi
    rol  r14d, 10
    ; L60  f4 X[14] s=8 K=0x8f1bbcdc
    mov  eax, r8d
    xor  eax, r9d
    and  eax, r10d
    xor  eax, r9d
    add  esi, [rbp-0x90+14*4]
    add  esi, 0x8f1bbcdc
    add  esi, eax
    rol  esi, 8
    add  esi, r11d
    rol  r9d, 10
    ; R60  f2 X[9] s=12 K=0x7a6d76e9
    mov  eax, r13d
    xor  eax, r14d
    and  eax, r12d
    xor  eax, r14d
    add  edi, [rbp-0x90+9*4]
    add  edi, 0x7a6d76e9
    add  edi, eax
    rol  edi, 12
    add  edi, ebx
    rol  r13d, 10
    ; L61  f4 X[5] s=6 K=0x8f1bbcdc
    mov  eax, esi
    xor  eax, r8d
    and  eax, r9d
    xor  eax, r8d
    add  r11d, [rbp-0x90+5*4]
    add  r11d, 0x8f1bbcdc
    add  r11d, eax
    rol  r11d, 6
    add  r11d, r10d
    rol  r8d, 10
    ; R61  f2 X[7] s=5 K=0x7a6d76e9
    mov  eax, r12d
    xor  eax, r13d
    and  eax, edi
    xor  eax, r13d
    add  ebx, [rbp-0x90+7*4]
    add  ebx, 0x7a6d76e9
    add  ebx, eax
    rol  ebx, 5
    add  ebx, r14d
    rol  r12d, 10
    ; L62  f4 X[6] s=5 K=0x8f1bbcdc
    mov  eax, r11d
    xor  eax, esi
    and  eax, r8d
    xor  eax, esi
    add  r10d, [rbp-0x90+6*4]
    add  r10d, 0x8f1bbcdc
    add  r10d, eax
    rol  r10d, 5
    add  r10d, r9d
    rol  esi, 10
    ; R62  f2 X[10] s=15 K=0x7a6d76e9
    mov  eax, edi
    xor  eax, r12d
    and  eax, ebx
    xor  eax, r12d
    add  r14d, [rbp-0x90+10*4]
    add  r14d, 0x7a6d76e9
    add  r14d, eax
    rol  r14d, 15
    add  r14d, r13d
    rol  edi, 10
    ; L63  f4 X[2] s=12 K=0x8f1bbcdc
    mov  eax, r10d
    xor  eax, r11d
    and  eax, esi
    xor  eax, r11d
    add  r9d, [rbp-0x90+2*4]
    add  r9d, 0x8f1bbcdc
    add  r9d, eax
    rol  r9d, 12
    add  r9d, r8d
    rol  r11d, 10
    ; R63  f2 X[14] s=8 K=0x7a6d76e9
    mov  eax, ebx
    xor  eax, edi
    and  eax, r14d
    xor  eax, edi
    add  r13d, [rbp-0x90+14*4]
    add  r13d, 0x7a6d76e9
    add  r13d, eax
    rol  r13d, 8
    add  r13d, r12d
    rol  ebx, 10
    ; L64  f5 X[4] s=9 K=0xa953fd4e
    mov  eax, r11d
    not  eax
    or   eax, r10d
    xor  eax, r9d
    add  r8d, [rbp-0x90+4*4]
    add  r8d, 0xa953fd4e
    add  r8d, eax
    rol  r8d, 9
    add  r8d, esi
    rol  r10d, 10
    ; R64  f1 X[12] s=8
    mov  eax, r13d
    xor  eax, r14d
    xor  eax, ebx
    add  r12d, [rbp-0x90+12*4]
    add  r12d, eax
    rol  r12d, 8
    add  r12d, edi
    rol  r14d, 10
    ; L65  f5 X[0] s=15 K=0xa953fd4e
    mov  eax, r10d
    not  eax
    or   eax, r9d
    xor  eax, r8d
    add  esi, [rbp-0x90+0*4]
    add  esi, 0xa953fd4e
    add  esi, eax
    rol  esi, 15
    add  esi, r11d
    rol  r9d, 10
    ; R65  f1 X[15] s=5
    mov  eax, r12d
    xor  eax, r13d
    xor  eax, r14d
    add  edi, [rbp-0x90+15*4]
    add  edi, eax
    rol  edi, 5
    add  edi, ebx
    rol  r13d, 10
    ; L66  f5 X[5] s=5 K=0xa953fd4e
    mov  eax, r9d
    not  eax
    or   eax, r8d
    xor  eax, esi
    add  r11d, [rbp-0x90+5*4]
    add  r11d, 0xa953fd4e
    add  r11d, eax
    rol  r11d, 5
    add  r11d, r10d
    rol  r8d, 10
    ; R66  f1 X[10] s=12
    mov  eax, edi
    xor  eax, r12d
    xor  eax, r13d
    add  ebx, [rbp-0x90+10*4]
    add  ebx, eax
    rol  ebx, 12
    add  ebx, r14d
    rol  r12d, 10
    ; L67  f5 X[9] s=11 K=0xa953fd4e
    mov  eax, r8d
    not  eax
    or   eax, esi
    xor  eax, r11d
    add  r10d, [rbp-0x90+9*4]
    add  r10d, 0xa953fd4e
    add  r10d, eax
    rol  r10d, 11
    add  r10d, r9d
    rol  esi, 10
    ; R67  f1 X[4] s=9
    mov  eax, ebx
    xor  eax, edi
    xor  eax, r12d
    add  r14d, [rbp-0x90+4*4]
    add  r14d, eax
    rol  r14d, 9
    add  r14d, r13d
    rol  edi, 10
    ; L68  f5 X[7] s=6 K=0xa953fd4e
    mov  eax, esi
    not  eax
    or   eax, r11d
    xor  eax, r10d
    add  r9d, [rbp-0x90+7*4]
    add  r9d, 0xa953fd4e
    add  r9d, eax
    rol  r9d, 6
    add  r9d, r8d
    rol  r11d, 10
    ; R68  f1 X[1] s=12
    mov  eax, r14d
    xor  eax, ebx
    xor  eax, edi
    add  r13d, [rbp-0x90+1*4]
    add  r13d, eax
    rol  r13d, 12
    add  r13d, r12d
    rol  ebx, 10
    ; L69  f5 X[12] s=8 K=0xa953fd4e
    mov  eax, r11d
    not  eax
    or   eax, r10d
    xor  eax, r9d
    add  r8d, [rbp-0x90+12*4]
    add  r8d, 0xa953fd4e
    add  r8d, eax
    rol  r8d, 8
    add  r8d, esi
    rol  r10d, 10
    ; R69  f1 X[5] s=5
    mov  eax, r13d
    xor  eax, r14d
    xor  eax, ebx
    add  r12d, [rbp-0x90+5*4]
    add  r12d, eax
    rol  r12d, 5
    add  r12d, edi
    rol  r14d, 10
    ; L70  f5 X[2] s=13 K=0xa953fd4e
    mov  eax, r10d
    not  eax
    or   eax, r9d
    xor  eax, r8d
    add  esi, [rbp-0x90+2*4]
    add  esi, 0xa953fd4e
    add  esi, eax
    rol  esi, 13
    add  esi, r11d
    rol  r9d, 10
    ; R70  f1 X[8] s=14
    mov  eax, r12d
    xor  eax, r13d
    xor  eax, r14d
    add  edi, [rbp-0x90+8*4]
    add  edi, eax
    rol  edi, 14
    add  edi, ebx
    rol  r13d, 10
    ; L71  f5 X[10] s=12 K=0xa953fd4e
    mov  eax, r9d
    not  eax
    or   eax, r8d
    xor  eax, esi
    add  r11d, [rbp-0x90+10*4]
    add  r11d, 0xa953fd4e
    add  r11d, eax
    rol  r11d, 12
    add  r11d, r10d
    rol  r8d, 10
    ; R71  f1 X[7] s=6
    mov  eax, edi
    xor  eax, r12d
    xor  eax, r13d
    add  ebx, [rbp-0x90+7*4]
    add  ebx, eax
    rol  ebx, 6
    add  ebx, r14d
    rol  r12d, 10
    ; L72  f5 X[14] s=5 K=0xa953fd4e
    mov  eax, r8d
    not  eax
    or   eax, esi
    xor  eax, r11d
    add  r10d, [rbp-0x90+14*4]
    add  r10d, 0xa953fd4e
    add  r10d, eax
    rol  r10d, 5
    add  r10d, r9d
    rol  esi, 10
    ; R72  f1 X[6] s=8
    mov  eax, ebx
    xor  eax, edi
    xor  eax, r12d
    add  r14d, [rbp-0x90+6*4]
    add  r14d, eax
    rol  r14d, 8
    add  r14d, r13d
    rol  edi, 10
    ; L73  f5 X[1] s=12 K=0xa953fd4e
    mov  eax, esi
    not  eax
    or   eax, r11d
    xor  eax, r10d
    add  r9d, [rbp-0x90+1*4]
    add  r9d, 0xa953fd4e
    add  r9d, eax
    rol  r9d, 12
    add  r9d, r8d
    rol  r11d, 10
    ; R73  f1 X[2] s=13
    mov  eax, r14d
    xor  eax, ebx
    xor  eax, edi
    add  r13d, [rbp-0x90+2*4]
    add  r13d, eax
    rol  r13d, 13
    add  r13d, r12d
    rol  ebx, 10
    ; L74  f5 X[3] s=13 K=0xa953fd4e
    mov  eax, r11d
    not  eax
    or   eax, r10d
    xor  eax, r9d
    add  r8d, [rbp-0x90+3*4]
    add  r8d, 0xa953fd4e
    add  r8d, eax
    rol  r8d, 13
    add  r8d, esi
    rol  r10d, 10
    ; R74  f1 X[13] s=6
    mov  eax, r13d
    xor  eax, r14d
    xor  eax, ebx
    add  r12d, [rbp-0x90+13*4]
    add  r12d, eax
    rol  r12d, 6
    add  r12d, edi
    rol  r14d, 10
    ; L75  f5 X[8] s=14 K=0xa953fd4e
    mov  eax, r10d
    not  eax
    or   eax, r9d
    xor  eax, r8d
    add  esi, [rbp-0x90+8*4]
    add  esi, 0xa953fd4e
    add  esi, eax
    rol  esi, 14
    add  esi, r11d
    rol  r9d, 10
    ; R75  f1 X[14] s=5
    mov  eax, r12d
    xor  eax, r13d
    xor  eax, r14d
    add  edi, [rbp-0x90+14*4]
    add  edi, eax
    rol  edi, 5
    add  edi, ebx
    rol  r13d, 10
    ; L76  f5 X[11] s=11 K=0xa953fd4e
    mov  eax, r9d
    not  eax
    or   eax, r8d
    xor  eax, esi
    add  r11d, [rbp-0x90+11*4]
    add  r11d, 0xa953fd4e
    add  r11d, eax
    rol  r11d, 11
    add  r11d, r10d
    rol  r8d, 10
    ; R76  f1 X[0] s=15
    mov  eax, edi
    xor  eax, r12d
    xor  eax, r13d
    add  ebx, [rbp-0x90+0*4]
    add  ebx, eax
    rol  ebx, 15
    add  ebx, r14d
    rol  r12d, 10
    ; L77  f5 X[6] s=8 K=0xa953fd4e
    mov  eax, r8d
    not  eax
    or   eax, esi
    xor  eax, r11d
    add  r10d, [rbp-0x90+6*4]
    add  r10d, 0xa953fd4e
    add  r10d, eax
    rol  r10d, 8
    add  r10d, r9d
    rol  esi, 10
    ; R77  f1 X[3] s=13
    mov  eax, ebx
    xor  eax, edi
    xor  eax, r12d
    add  r14d, [rbp-0x90+3*4]
    add  r14d, eax
    rol  r14d, 13
    add  r14d, r13d
    rol  edi, 10
    ; L78  f5 X[15] s=5 K=0xa953fd4e
    mov  eax, esi
    not  eax
    or   eax, r11d
    xor  eax, r10d
    add  r9d, [rbp-0x90+15*4]
    add  r9d, 0xa953fd4e
    add  r9d, eax
    rol  r9d, 5
    add  r9d, r8d
    rol  r11d, 10
    ; R78  f1 X[9] s=11
    mov  eax, r14d
    xor  eax, ebx
    xor  eax, edi
    add  r13d, [rbp-0x90+9*4]
    add  r13d, eax
    rol  r13d, 11
    add  r13d, r12d
    rol  ebx, 10
    ; L79  f5 X[13] s=6 K=0xa953fd4e
    mov  eax, r11d
    not  eax
    or   eax, r10d
    xor  eax, r9d
    add  r8d, [rbp-0x90+13*4]
    add  r8d, 0xa953fd4e
    add  r8d, eax
    rol  r8d, 6
    add  r8d, esi
    rol  r10d, 10
    ; R79  f1 X[11] s=11
    mov  eax, r13d
    xor  eax, r14d
    xor  eax, ebx
    add  r12d, [rbp-0x90+11*4]
    add  r12d, eax
    rol  r12d, 11
    add  r12d, edi
    rol  r14d, 10
    ; after 80 rounds the renaming cycle (80 mod 5 == 0) restores the
    ; original register assignment: left A..E = esi,r8d,r9d,r10d,r11d,
    ; right A2..E2 = edi,r12d,r13d,r14d,ebx -- the cross-mix below is
    ; unchanged from the loop version.

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
; rmd_f_left / rmd_f_right removed 2026-08-23: the unrolled rounds inline all
; five round functions with immediate constants (see the compress body above).
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

