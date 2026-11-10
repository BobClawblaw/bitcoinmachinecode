; setjmp.asm -- setjmp/longjmp/sigsetjmp for the SysV side (bmc_win).
; musl's x86_64 versions are ELF-directive assembly; these keep its jmp_buf
; layout: rbx rbp r12 r13 r14 r15 rsp rip, then (sigjmp_buf) the __fl word.
; No signal masks exist on bmc_win, so sigsetjmp never saves one.
section .text
global setjmp
global _setjmp
global __setjmp
setjmp:
_setjmp:
__setjmp:
    mov  [rdi],    rbx
    mov  [rdi+8],  rbp
    mov  [rdi+16], r12
    mov  [rdi+24], r13
    mov  [rdi+32], r14
    mov  [rdi+40], r15
    lea  rdx, [rsp+8]           ; rsp after this function returns
    mov  [rdi+48], rdx
    mov  rdx, [rsp]             ; return address
    mov  [rdi+56], rdx
    xor  eax, eax
    ret

global longjmp
global _longjmp
longjmp:
_longjmp:
    xor  eax, eax
    cmp  esi, 1                 ; CF = (val == 0)
    adc  eax, esi               ; val ? val : 1
    mov  rbx, [rdi]
    mov  rbp, [rdi+8]
    mov  r12, [rdi+16]
    mov  r13, [rdi+24]
    mov  r14, [rdi+32]
    mov  r15, [rdi+40]
    mov  rsp, [rdi+48]
    jmp  [rdi+56]

global sigsetjmp
global __sigsetjmp
sigsetjmp:
__sigsetjmp:
    mov  qword [rdi+64], 0      ; __fl: no mask saved
    jmp  setjmp
