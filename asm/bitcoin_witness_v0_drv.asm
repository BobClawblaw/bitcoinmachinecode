; ============================================================================
; bitcoin_witness_v0_drv.asm -- the witness-v0 verification driver, 100%
; AI-generated x86-64 assembly (NASM, ELF64). Phase 2 slice 9 of the C->asm
; conversion (2026-08-24). Twin of bitcoin_witness_v0.c's
; sv_verify_witness_v0; differential: tests/test_wv0_drv_diff.c.
;
;   long sv_verify_witness_v0_asm(const u8* prog, u32 proglen,
;                                 const u8* const* wit, const u32* witlen,
;                                 u32 nwit, u64 amount,
;                                 /*stack*/ u64 flags, u64 nIn,
;                                 const u8* tx, u64 txlen,
;                                 u8* work, u64 workcap) -> SCRIPT_ERR_*
;
; Core: VerifyWitnessProgram (version-0 arm) + ExecuteWitnessScript.
;   32-byte program (P2WSH): witness non-empty; last item is the
;     witnessScript, sha256 of it must equal the program; the rest is the
;     initial stack.
;   20-byte program (P2WPKH): witness exactly 2 items; the script is the
;     implied P2PKH: OP_DUP OP_HASH160 <prog> OP_EQUALVERIFY OP_CHECKSIG.
;   other lengths: WITNESS_PROGRAM_WRONG_LENGTH.
; ExecuteWitnessScript: every initial stack element <= 520 (PUSH_SIZE),
; then sv_run_v under SIGVERSION_WITNESS_V0 with the BIP143 checksig hook,
; then exactly one stack element (CLEANSTACK) that casts to true
; (EVAL_FALSE).
;
; The interpreter itself (sv_run_v) and its checksig hook stay C for this
; slice -- the twin drives the SAME sv_run_v with the SAME hook (via the
; exported alias), so the differential isolates exactly this driver's
; work: shape selection, the sha256 program check, the implied-script
; build, stack fill, ctx fill, and the post-run cleanstack/truth checks.
;
; Per-thread state mirrors the C exactly: main_e is a lazily-malloc'd
; MAX_STACK*ELEM_SIZE (528,000B) buffer behind a .tbss pointer (BMC_TLS_BUF
; shape, abort on OOM); the 25-byte implied-P2WPKH script is a .tbss array
; (the C's __thread array is exactly that).
;
; sv_ctx (offset-pinned from the C struct): tx@0 txlen@8 nIn@16 work@24
; workcap@32 tx_locktime@40 in_sequence@44 tx_version@48 amount@56, size 64.
; sv_get_locktime_context is called with (&ver, &lt, &seq) = (@48, @40, @44)
; -- the C's own argument order, not the struct order.
; Stack record: u32 len @0, data @4, stride 528 (ELEM_SIZE); MAX_STACK 1000;
; MAX_SCRIPT_ELEMENT_SIZE 520; SIGVERSION_WITNESS_V0 = 1.
; ============================================================================

BITS 64
DEFAULT REL

extern malloc
extern abort
extern sha256_full                    ; asm
extern sv_run_v                       ; C (bitcoin_scriptverify.c) -- later slice
extern sv_true                        ; C helper (exported)
extern sv_get_locktime_context        ; C
extern sv_checksig_witness_v0_export  ; C seam: alias of the static hook

%define ELEM_SIZE     528
%define ELEM_DATA_OFF 4
%define MAX_STACK     1000
%define MAX_ELEM      520
%define SIGV_WV0      1

%define ERR_OK        0
%define ERR_EVAL_FALSE 2
%define ERR_PUSH_SIZE 6
%define ERR_STACK_SIZE 8
%define ERR_CLEANSTACK 30
%define ERR_WP_WRONG_LENGTH 38
%define ERR_WP_WITNESS_EMPTY 39
%define ERR_WP_MISMATCH 40

%define CTX_TX        0
%define CTX_TXLEN     8
%define CTX_NIN       16
%define CTX_WORK      24
%define CTX_WORKCAP   32
%define CTX_LOCKTIME  40
%define CTX_SEQUENCE  44
%define CTX_VERSION   48
%define CTX_AMOUNT    56

section .tbss alloc noexec nowrite tls align=8
global wv0_main_e
wv0_main_e:  resq 1                   ; __thread u8* main stack arena (lazy)
global wv0_p2wpkh
wv0_p2wpkh:  resb 25                  ; __thread implied-P2PKH script

section .text

%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

; ----------------------------------------------------------------------------
; sv_verify_witness_v0_asm -- see header.
;   rdi=prog esi=proglen rdx=wit rcx=witlen r8d=nwit r9=amount
;   [rbp+16]=flags [rbp+24]=nIn [rbp+32]=tx [rbp+40]=txlen
;   [rbp+48]=work [rbp+56]=workcap
; Frame: push rbp + 5 pushes, sub rsp,0xa8 -> rsp = rbp-0xd0, 0 mod 16 at
; every call (sv_run_v's 2 stack args keep it 16-aligned too). Locals:
;   [rbp-0x30] script  [rbp-0x38] slen    [rbp-0x40] nstack
;   [rbp-0x58] st.e  [rbp-0x50] st.sp     (sv_stack, contiguous)
;   [rbp-0xa0..-0x60) ctx (64B)           [rbp-0xa8] main_e
;   [rbp-0xb0] err (dword)                [rbp-0xd0..-0xb0) h[32]
; Registers: rbx = wit, r12 = witlen, r13d = nwit, r14 = prog, r15 = i.
; ----------------------------------------------------------------------------
global sv_verify_witness_v0_asm
sv_verify_witness_v0_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xa8
    mov  rbx, rdx                        ; wit
    mov  r12, rcx                        ; witlen
    mov  r13d, r8d                       ; nwit
    mov  r14, rdi                        ; prog
    mov  [rbp-0x68], r9                  ; ctx.amount (@ -0xa0 + 56)
    mov  eax, esi                        ; proglen

    ; ---- this thread's stack arena, lazily malloc'd ----
    TLS_ADDR rcx, wv0_main_e
    mov  rdx, [rcx]
    test rdx, rdx
    jnz  .have_arena
    push rax                             ; live: proglen (rax)
    push rcx                             ;   and the TLS slot
    mov  edi, MAX_STACK*ELEM_SIZE
    call malloc
    test rax, rax
    jnz  .arena_ok
    call abort
.arena_ok:
    mov  rdx, rax
    pop  rcx
    pop  rax
    mov  [rcx], rdx
.have_arena:
    mov  [rbp-0xa8], rdx                 ; main_e

    ; ---- shape selection ----
    cmp  eax, 32
    je   .p2wsh
    cmp  eax, 20
    je   .p2wpkh
    mov  eax, ERR_WP_WRONG_LENGTH
    jmp  .out

.p2wsh:
    test r13d, r13d
    jz   .r_empty
    ; script = wit[nwit-1], slen = witlen[nwit-1]
    mov  ecx, r13d
    dec  ecx
    mov  rax, [rbx+rcx*8]
    mov  [rbp-0x30], rax                 ; script
    mov  ecx, [r12+rcx*4]
    mov  [rbp-0x38], rcx                 ; slen
    ; sha256(script) must equal the program
    lea  rdi, [rbp-0xd0]                 ; h[32]
    mov  rsi, rax
    mov  rdx, rcx
    call sha256_full
    mov  rax, [rbp-0xd0]
    xor  rax, [r14]
    mov  rcx, [rbp-0xc8]
    xor  rcx, [r14+8]
    or   rax, rcx
    mov  rcx, [rbp-0xc0]
    xor  rcx, [r14+16]
    or   rax, rcx
    mov  rcx, [rbp-0xb8]
    xor  rcx, [r14+24]
    or   rax, rcx
    jnz  .r_mismatch
    mov  eax, r13d
    dec  eax
    mov  [rbp-0x40], rax                 ; nstack = nwit - 1 (zero-extended)
    jmp  .fill

.p2wpkh:
    cmp  r13d, 2
    jne  .r_mismatch
    TLS_ADDR rdi, wv0_p2wpkh
    mov  byte [rdi],    0x76             ; OP_DUP
    mov  byte [rdi+1],  0xa9             ; OP_HASH160
    mov  byte [rdi+2],  0x14             ; push 20
    mov  rax, [r14]
    mov  [rdi+3], rax
    mov  rax, [r14+8]
    mov  [rdi+11], rax
    mov  eax, [r14+16]
    mov  [rdi+19], eax
    mov  byte [rdi+23], 0x88             ; OP_EQUALVERIFY
    mov  byte [rdi+24], 0xac             ; OP_CHECKSIG
    mov  [rbp-0x30], rdi                 ; script
    mov  qword [rbp-0x38], 25            ; slen
    mov  qword [rbp-0x40], 2             ; nstack
    jmp  .fill

.fill:
    ; nstack > MAX_STACK -> STACK_SIZE
    mov  rax, [rbp-0x40]
    cmp  rax, MAX_STACK
    ja   .r_stacksize
    ; st = { main_e, 0 }, then push every initial item
    mov  rax, [rbp-0xa8]
    mov  [rbp-0x58], rax                 ; st.e
    xor  ecx, ecx
    mov  [rbp-0x50], rcx                 ; st.sp = 0
    xor  r15d, r15d                      ; i = 0
.fill_loop:
    cmp  r15, [rbp-0x40]
    jae  .run
    mov  ecx, [r12+r15*4]                ; witlen[i]
    cmp  ecx, MAX_ELEM
    ja   .r_pushsize
    ; rec = main_e + i*ELEM_SIZE ; *(u32*)rec = len ; copy the data
    imul rdi, r15, ELEM_SIZE
    add  rdi, [rbp-0xa8]
    mov  [rdi], ecx
    add  rdi, ELEM_DATA_OFF
    mov  rsi, [rbx+r15*8]                ; wit[i]
    rep  movsb                           ; rcx = len already
    inc  qword [rbp-0x50]                ; st.sp++
    inc  r15
    jmp  .fill_loop

.run:
    ; ctx = { tx, txlen, nIn, work, workcap, 0, 0, 0, amount } (amount set
    ; at entry); then the locktime context fills ver/lt/seq
    mov  rax, [rbp+32]
    mov  [rbp-0xa0+CTX_TX], rax
    mov  rax, [rbp+40]
    mov  [rbp-0xa0+CTX_TXLEN], rax
    mov  rax, [rbp+24]
    mov  [rbp-0xa0+CTX_NIN], rax
    mov  rax, [rbp+48]
    mov  [rbp-0xa0+CTX_WORK], rax
    mov  rax, [rbp+56]
    mov  [rbp-0xa0+CTX_WORKCAP], rax
    xor  eax, eax
    mov  [rbp-0xa0+CTX_LOCKTIME], eax
    mov  [rbp-0xa0+CTX_SEQUENCE], eax
    mov  [rbp-0xa0+CTX_VERSION], eax
    mov  rdi, [rbp+32]                   ; tx
    mov  rsi, [rbp+40]                   ; txlen
    mov  rdx, [rbp+24]                   ; nIn
    lea  rcx, [rbp-0xa0+CTX_VERSION]     ; &ver
    lea  r8,  [rbp-0xa0+CTX_LOCKTIME]    ; &lt
    lea  r9,  [rbp-0xa0+CTX_SEQUENCE]    ; &seq
    call sv_get_locktime_context
    ; err = OK; sv_run_v(script, slen, &st, flags, &ctx, &err, WV0, cs)
    mov  dword [rbp-0xb0], ERR_OK
    mov  rdi, [rbp-0x30]
    mov  rsi, [rbp-0x38]
    lea  rdx, [rbp-0x58]                 ; &st
    mov  rcx, [rbp+16]                   ; flags
    lea  r8,  [rbp-0xa0]                 ; &ctx
    lea  r9,  [rbp-0xb0]                 ; &err
    lea  rax, [sv_checksig_witness_v0_export]
    push rax                             ; arg 8: cs
    push SIGV_WV0                        ; arg 7: sigversion
    call sv_run_v
    add  rsp, 16
    test eax, eax
    jz   .run_failed
    ; cleanstack: exactly one element left
    cmp  qword [rbp-0x50], 1
    jne  .r_cleanstack
    ; ... and it must cast to true
    lea  rdi, [rbp-0x58]
    xor  esi, esi
    call sv_true
    test eax, eax
    jz   .r_evalfalse
    xor  eax, eax                        ; SCRIPT_ERR_OK
    jmp  .out
.run_failed:
    mov  eax, [rbp-0xb0]                 ; the interpreter's err code
    jmp  .out

.r_empty:      mov eax, ERR_WP_WITNESS_EMPTY
               jmp .out
.r_mismatch:   mov eax, ERR_WP_MISMATCH
               jmp .out
.r_stacksize:  mov eax, ERR_STACK_SIZE
               jmp .out
.r_pushsize:   mov eax, ERR_PUSH_SIZE
               jmp .out
.r_cleanstack: mov eax, ERR_CLEANSTACK
               jmp .out
.r_evalfalse:  mov eax, ERR_EVAL_FALSE
.out:
    add  rsp, 0xa8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
