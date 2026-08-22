; ============================================================================
; tests/fe_inline_probe.asm -- TEST-ONLY thin wrappers that expose the inline
; field macros of secp256k1_fe_inline.inc as ordinary SysV functions, so
; tests/test_fe_inline.c can drive them directly against fe_add / fe_sub and
; against a big-integer oracle.
;
; Nothing in the node links this file. It exists because the macros are
; consensus arithmetic that would otherwise only ever be tested THROUGH
; point_double / point_add, where the operand distribution is whatever the EC
; formulas happen to produce -- which never includes the carry boundaries that
; separate the merged reduction in FE_ADD_TAIL from fe_add's two-step form.
;
; The wrappers deliberately use the SAME register convention the EC routines
; do (accumulator in r8..r11, C in rbx, pointers in callee-saved registers),
; so what is measured here is exactly the code the EC routines execute.
; ============================================================================

BITS 64
DEFAULT REL

%include "secp256k1_fe_inline.inc"

section .text

; void fe_add_inl(u64 r[4], const u64 a[4], const u64 b[4])
global fe_add_inl
fe_add_inl:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rdx
    FE_C_INIT
    FE_LD rsi
    FE_ADDM r13
    FE_ST r12
    pop  r13
    pop  r12
    pop  rbx
    ret

; void fe_sub_inl(u64 r[4], const u64 a[4], const u64 b[4])
global fe_sub_inl
fe_sub_inl:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rdx
    FE_C_INIT
    FE_LD rsi
    FE_SUBM r13
    FE_ST r12
    pop  r13
    pop  r12
    pop  rbx
    ret

; void fe_dbl_inl(u64 r[4], const u64 a[4])
global fe_dbl_inl
fe_dbl_inl:
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

section .note.GNU-stack noalloc noexec nowrite progbits
