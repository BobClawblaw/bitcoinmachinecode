; fe_inline_wrap.asm -- thin callable wrappers around the REAL macros of
; asm/secp256k1_fe_inline.inc, so the lifter and the differential driver can
; exercise exactly the instruction sequences point_*.asm inlines. The macro
; bodies are included verbatim; only the load/store framing is ours.
BITS 64
DEFAULT REL
%include "secp256k1_fe_inline.inc"
section .text
; void w_fe_addm(u64 r[4], const u64 a[4], const u64 b[4])   V=a; FE_ADDM b
global w_fe_addm
w_fe_addm:
    push rbx
    push r12
    mov  r12, rdi
    FE_C_INIT
    FE_LD rsi
    FE_ADDM rdx
    FE_ST r12
    pop  r12
    pop  rbx
    ret
; void w_fe_dbl(u64 r[4], const u64 a[4])                    V=a; FE_DBL
global w_fe_dbl
w_fe_dbl:
    push rbx
    push r12
    mov  r12, rdi
    FE_C_INIT
    FE_LD rsi
    FE_DBL
    FE_ST r12
    pop  r12
    pop  rbx
    ret
; void w_fe_subm(u64 r[4], const u64 a[4], const u64 b[4])   V=a; FE_SUBM b
global w_fe_subm
w_fe_subm:
    push rbx
    FE_C_INIT
    FE_LD rsi
    FE_SUBM rdx
    FE_ST rdi
    pop  rbx
    ret
section .note.GNU-stack noalloc noexec nowrite progbits
