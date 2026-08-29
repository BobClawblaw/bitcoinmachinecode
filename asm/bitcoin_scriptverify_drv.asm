; ============================================================================
; bitcoin_scriptverify_drv.asm -- the legacy/P2SH verification driver, 100%
; AI-generated x86-64 assembly (NASM, ELF64). Phase 2 slice 10 of the C->asm
; conversion (2026-08-24). Twin of bitcoin_scriptverify.c's sv_verify_script
; (with sv_push_only ported inline); differential:
; tests/test_svs_drv_diff.c.
;
;   long sv_verify_script_asm(const u8* scriptSig, u64 ssl,
;                             const u8* scriptPubKey, u64 spl,
;                             u64 flags, u64 nIn,
;                             /*stack*/ const u8* tx, u64 txlen,
;                             u8* work, u64 workcap) -> SCRIPT_ERR_*
;
; Core: VerifyScript's legacy arm -- scriptSig eval, (P2SH) stack snapshot,
; scriptPubKey eval, truth check, the BIP16 redeem re-run from the
; snapshot, CLEANSTACK under its flag. Drives the SAME sv_run_v with the
; SAME legacy checksig hook (exported alias seam), so the differential
; isolates the driver: push-only enforcement, the two/three eval sequence,
; the 528,000-byte snapshot/restore, redeem extraction, and every
; structural error code.
;
; Per-thread state mirrors the C exactly: main_e / copy_e (528,000B each)
; and redeem (20,000B), all lazily malloc'd behind .tbss pointers. The
; per-call memset of main_e and the full-arena snapshot memcpys are the
; C's own behavior, reproduced (they are the documented cost of the
; snapshot discipline, not this port's invention).
;
; Flags: SV_P2SH 1<<0, SV_SIGPUSHONLY 1<<5, SV_CLEANSTACK 1<<8.
; Errors: OK 0, EVAL_FALSE 2, PUSH_SIZE 6, INVALID_STACK_OPERATION 18,
; SIG_PUSHONLY 26, CLEANSTACK 30. SIGV_BASE = 0.
; sv_ctx as in slice 9's header; amount stays 0 on the legacy path.
; ============================================================================

BITS 64
DEFAULT REL

extern malloc
extern abort
extern sv_run_v                       ; C -- later slice
extern sv_true                        ; C helper (exported)
extern sv_get_locktime_context        ; C
extern sv_checksig_export             ; C seam: alias of the static legacy hook

%define ELEM_SIZE     528
%define ELEM_DATA_OFF 4
%define MAX_STACK     1000
%define ARENA_BYTES   (MAX_STACK*ELEM_SIZE)
%define REDEEM_CAP    20000
%define SIGV_BASE     0

%define SV_P2SH        (1 << 0)
%define SV_SIGPUSHONLY (1 << 5)
%define SV_CLEANSTACK  (1 << 8)

%define ERR_OK          0
%define ERR_EVAL_FALSE  2
%define ERR_PUSH_SIZE   6
%define ERR_INVALID_STACK_OP 18
%define ERR_SIG_PUSHONLY 26
%define ERR_CLEANSTACK  30

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
global svs_main_e
svs_main_e: resq 1
global svs_copy_e
svs_copy_e: resq 1
global svs_redeem
svs_redeem: resq 1

section .text

%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

; TLS_LAZY dst, slot, size -- dst = this thread's lazily-malloc'd buffer.
; Clobbers rax, rcx, rdi (and whatever malloc does on the cold path).
; Call sites sit at rsp == 0 mod 16.
%macro TLS_LAZY 3
    TLS_ADDR rcx, %2
    mov  %1, [rcx]
    test %1, %1
    jnz  %%have
    push rcx
    push rcx                             ; keep 16-alignment across malloc
    mov  edi, %3
    call malloc
    test rax, rax
    jnz  %%ok
    call abort
%%ok:
    pop  rcx
    pop  rcx
    mov  [rcx], rax
    mov  %1, rax
%%have:
%endmacro

; ----------------------------------------------------------------------------
; push_only: rdi = script, rsi = n -> rax 1/0. Inline port of the C's
; sv_push_only (the walker differs from bitcoin_segwit_classify.asm's
; last_push: this one only VALIDATES, and its PUSHDATA2/4 length adds are
; the C's own size_t arithmetic). Fully SysV; clobbers rax, rcx, rdx, r8.
; ----------------------------------------------------------------------------
push_only:
    xor  ecx, ecx                        ; i = 0
.loop:
    cmp  rcx, rsi
    jae  .done
    movzx eax, byte [rdi+rcx]
    cmp  eax, 0x4f                       ; OP_1NEGATE
    je   .one
    cmp  eax, 0x51
    jb   .not_small
    cmp  eax, 0x60
    ja   .no
.one:
    inc  rcx
    jmp  .loop
.not_small:
    cmp  eax, 0x4e
    ja   .no
    cmp  eax, 0x4b
    ja   .pushdata
    lea  rcx, [rcx+rax+1]                ; i += 1 + op
    jmp  .loop
.pushdata:
    cmp  eax, 0x4c
    je   .pd1
    cmp  eax, 0x4d
    je   .pd2
    lea  rdx, [rcx+5]                    ; PUSHDATA4: i+5 > n ?
    cmp  rdx, rsi
    ja   .no
    mov  edx, [rdi+rcx+1]                ; 4-byte LE len
    lea  rcx, [rcx+5]
    add  rcx, rdx
    jmp  .loop
.pd1:
    lea  rdx, [rcx+2]
    cmp  rdx, rsi
    ja   .no
    movzx edx, byte [rdi+rcx+1]
    lea  rcx, [rcx+2]
    add  rcx, rdx
    jmp  .loop
.pd2:
    lea  rdx, [rcx+3]
    cmp  rdx, rsi
    ja   .no
    movzx edx, word [rdi+rcx+1]
    lea  rcx, [rcx+3]
    add  rcx, rdx
    jmp  .loop
.done:
    xor  eax, eax
    cmp  rcx, rsi                        ; return i == n
    sete al
    ret
.no:
    xor  eax, eax
    ret

; ----------------------------------------------------------------------------
; sv_verify_script_asm -- see header.
;   rdi=scriptSig rsi=ssl rdx=scriptPubKey rcx=spl r8=flags r9=nIn
;   [rbp+16]=tx [rbp+24]=txlen [rbp+32]=work [rbp+40]=workcap
; Frame: push rbp + 5 pushes, sub rsp,0xa8 -> rsp = rbp-0xd0, 0 mod 16 at
; every call. Locals:
;   [rbp-0x30] scriptSig [rbp-0x38] ssl  [rbp-0x40] spk  [rbp-0x48] spl
;   [rbp-0x58] st.e  [rbp-0x50] st.sp    [rbp-0x68] cp.e [rbp-0x60] cp.sp
;   [rbp-0xa8..-0x68) ctx (64B)          [rbp-0xb0] err (dword)
;   [rbp-0xb8] main_e  [rbp-0xc0] copy_e [rbp-0xc8] redeem [rbp-0xd0] rl
; Registers: r14 = flags (held), others scratch per phase.
; ----------------------------------------------------------------------------
global sv_verify_script_asm
sv_verify_script_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xa8
    mov  [rbp-0x30], rdi                 ; scriptSig
    mov  [rbp-0x38], rsi                 ; ssl
    mov  [rbp-0x40], rdx                 ; scriptPubKey
    mov  [rbp-0x48], rcx                 ; spl
    mov  r14, r8                         ; flags
    mov  [rbp-0xa8+CTX_NIN], r9

    TLS_LAZY rbx, svs_main_e, ARENA_BYTES
    mov  [rbp-0xb8], rbx
    TLS_LAZY rbx, svs_copy_e, ARENA_BYTES
    mov  [rbp-0xc0], rbx

    ; st = { main_e, 0 } ; cp = { copy_e, 0 }
    mov  rax, [rbp-0xb8]
    mov  [rbp-0x58], rax
    xor  ecx, ecx
    mov  [rbp-0x50], rcx
    mov  rax, [rbp-0xc0]
    mov  [rbp-0x68], rax
    mov  [rbp-0x60], rcx
    ; ctx = { tx, txlen, nIn(set), work, workcap, 0,0,0, 0 }
    mov  rax, [rbp+16]
    mov  [rbp-0xa8+CTX_TX], rax
    mov  rax, [rbp+24]
    mov  [rbp-0xa8+CTX_TXLEN], rax
    mov  rax, [rbp+32]
    mov  [rbp-0xa8+CTX_WORK], rax
    mov  rax, [rbp+40]
    mov  [rbp-0xa8+CTX_WORKCAP], rax
    xor  eax, eax
    mov  [rbp-0xa8+CTX_LOCKTIME], eax
    mov  [rbp-0xa8+CTX_SEQUENCE], eax
    mov  [rbp-0xa8+CTX_VERSION], eax
    mov  [rbp-0xa8+CTX_AMOUNT], rax
    mov  rdi, [rbp+16]
    mov  rsi, [rbp+24]
    mov  rdx, [rbp-0xa8+CTX_NIN]
    lea  rcx, [rbp-0xa8+CTX_VERSION]
    lea  r8,  [rbp-0xa8+CTX_LOCKTIME]
    lea  r9,  [rbp-0xa8+CTX_SEQUENCE]
    call sv_get_locktime_context

    ; memset(main_e, 0, ARENA_BYTES) -- the C's per-call zeroing
    mov  rdi, [rbp-0xb8]
    xor  eax, eax
    mov  ecx, ARENA_BYTES
    rep  stosb

    ; SIGPUSHONLY gate
    test r14, SV_SIGPUSHONLY
    jz   .run_sig
    mov  rdi, [rbp-0x30]
    mov  rsi, [rbp-0x38]
    call push_only
    test eax, eax
    jz   .r_pushonly

.run_sig:
    ; sv_run(scriptSig): sv_run_v(..., SIGV_BASE, legacy hook)
    mov  dword [rbp-0xb0], ERR_OK
    mov  rdi, [rbp-0x30]
    mov  rsi, [rbp-0x38]
    call .run_one
    test eax, eax
    jz   .r_err

    ; P2SH: snapshot the post-scriptSig stack
    test r14, SV_P2SH
    jz   .run_spk
    mov  rdi, [rbp-0xc0]                 ; copy_e
    mov  rsi, [rbp-0xb8]                 ; main_e
    mov  ecx, ARENA_BYTES
    rep  movsb
    mov  rax, [rbp-0x50]
    mov  [rbp-0x60], rax                 ; cp.sp = st.sp

.run_spk:
    mov  rdi, [rbp-0x40]
    mov  rsi, [rbp-0x48]
    call .run_one
    test eax, eax
    jz   .r_err
    ; st.sp == 0 -> EVAL_FALSE ; !sv_true(&st, sp-1) -> EVAL_FALSE
    mov  rax, [rbp-0x50]
    test rax, rax
    jz   .r_evalfalse
    lea  rdi, [rbp-0x58]
    lea  rsi, [rax-1]
    call sv_true
    test eax, eax
    jz   .r_evalfalse

    ; ---- BIP16 ----
    test r14, SV_P2SH
    jz   .cleanstack
    ; sv_is_p2sh(spk, spl): 23 bytes, a9 14 .. 87
    mov  rax, [rbp-0x40]
    cmp  qword [rbp-0x48], 23
    jne  .cleanstack
    cmp  byte [rax], 0xa9
    jne  .cleanstack
    cmp  byte [rax+1], 0x14
    jne  .cleanstack
    cmp  byte [rax+22], 0x87
    jne  .cleanstack
    ; scriptSig must be push-only (checked HERE too, matching the C)
    mov  rdi, [rbp-0x30]
    mov  rsi, [rbp-0x38]
    call push_only
    test eax, eax
    jz   .r_pushonly
    mov  rax, [rbp-0x60]                 ; cp.sp
    test rax, rax
    jz   .r_invstack
    TLS_LAZY rbx, svs_redeem, REDEEM_CAP
    mov  [rbp-0xc8], rbx
    ; rl = sv_len(&cp, cp.sp-1) = *(u32*)(copy_e + (sp-1)*528)
    mov  rax, [rbp-0x60]
    dec  rax
    imul rax, rax, ELEM_SIZE
    add  rax, [rbp-0xc0]                 ; rec
    mov  ecx, [rax]                      ; rl
    mov  [rbp-0xd0], rcx
    cmp  ecx, REDEEM_CAP
    ja   .r_pushsize
    ; memcpy(redeem, rec+4, rl)
    lea  rsi, [rax+ELEM_DATA_OFF]
    mov  rdi, [rbp-0xc8]
    rep  movsb
    ; cp.sp-- ; restore main from the snapshot ; st.sp = cp.sp
    dec  qword [rbp-0x60]
    mov  rdi, [rbp-0xb8]
    mov  rsi, [rbp-0xc0]
    mov  ecx, ARENA_BYTES
    rep  movsb
    mov  rax, [rbp-0x60]
    mov  [rbp-0x50], rax
    ; run the redeem script
    mov  rdi, [rbp-0xc8]
    mov  rsi, [rbp-0xd0]
    call .run_one
    test eax, eax
    jz   .r_err
    mov  rax, [rbp-0x50]
    test rax, rax
    jz   .r_evalfalse
    lea  rdi, [rbp-0x58]
    lea  rsi, [rax-1]
    call sv_true
    test eax, eax
    jz   .r_evalfalse

.cleanstack:
    test r14, SV_CLEANSTACK
    jz   .ok
    cmp  qword [rbp-0x50], 1
    jne  .r_cleanstack
.ok:
    xor  eax, eax                        ; SCRIPT_ERR_OK
    jmp  .out

; local call: run one script through sv_run_v with the legacy hook.
; rdi = script, rsi = slen; returns sv_run_v's 1/0 (err already in the
; frame's err slot on 0). Entered by CALL at rsp == 0 mod 16, so inside
; rsp == 8 mod 16; one alignment sub before the 2-push call site restores
; 0 mod 16 at the sv_run_v call.
.run_one:
    sub  rsp, 8
    lea  rdx, [rbp-0x58]                 ; &st
    mov  rcx, r14                        ; flags
    lea  r8,  [rbp-0xa8]                 ; &ctx
    lea  r9,  [rbp-0xb0]                 ; &err
    lea  rax, [sv_checksig_export]
    push rax                             ; arg 8: cs
    push SIGV_BASE                       ; arg 7: sigversion
    call sv_run_v
    add  rsp, 24
    ret

.r_pushonly:   mov eax, ERR_SIG_PUSHONLY
               jmp .out
.r_evalfalse:  mov eax, ERR_EVAL_FALSE
               jmp .out
.r_invstack:   mov eax, ERR_INVALID_STACK_OP
               jmp .out
.r_pushsize:   mov eax, ERR_PUSH_SIZE
               jmp .out
.r_cleanstack: mov eax, ERR_CLEANSTACK
               jmp .out
.r_err:
    mov  eax, [rbp-0xb0]                 ; the interpreter's err code
.out:
    add  rsp, 0xa8
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
