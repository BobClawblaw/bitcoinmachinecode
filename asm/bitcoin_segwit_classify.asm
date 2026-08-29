; ============================================================================
; bitcoin_segwit_classify.asm -- BIP141 witness-program classification,
; 100% AI-generated x86-64 assembly (NASM, ELF64). Phase 2 slice 3 of the
; C->asm conversion (2026-08-24). Twin of bitcoin_witness_v0.c's
; sv_classify_segwit + sv_witness_program + sv_last_push (and the inlined
; sv_is_p2sh check); differential: tests/test_segwit_classify_diff.c.
;
; Core equivalents: CScript::IsWitnessProgram, CScript::IsPayToScriptHash,
; and the P2SH-wrapped branch of VerifyScript ("scriptSig must be exactly
; CScript() << redeemScript" -- one MINIMAL DIRECT push, opcode == length,
; hash160(redeem) == the P2SH hash).
;
;   long sv_witness_program_asm(const u8* s, u64 n, u32* version,
;                               const u8** prog, u32* proglen) -> 1 / 0
;   long sv_classify_segwit_asm(const u8* spk, u64 spl, const u8* ss,
;                               u64 ssl, u32* version, const u8** prog,
;                               u32* proglen, /*stack*/ int* wrapped)
;     -> 1 native / 2 wrapped / -1 malleated-or-hash-mismatch / 0 legacy
;
; hash160 is already assembly (bitcoin_addr.asm); the wrapped branch calls
; it directly -- the first consensus slice with an asm->asm dependency.
;
; sv_last_push's opcode classes, mirrored exactly:
;   0x01..0x4b direct push; 0x4c/0x4d/0x4e PUSHDATA1/2/4;
;   0x00, 0x4f, 0x51..0x60 small-int pushes (count as pushes, payload len 0);
;   anything else -> not push-only -> 0.
; The PUSHDATA4 bound uses the C's own 64-bit widening ((u64)p + 5 + dl)
; so a dl near 2^32 cannot wrap the check.
; ============================================================================

BITS 64
DEFAULT REL

extern hash160                        ; void (u8 out[20], const void*, i64) -- bitcoin_addr.asm

section .text

; ----------------------------------------------------------------------------
; sv_witness_program_asm(s=rdi, n=rsi, version=rdx, prog=rcx, proglen=r8)
;   -> rax 1 / 0.  4..42 bytes, OP_0 or OP_1..OP_16, s[1] == n-2.
; No calls, no callee-saved use.
; ----------------------------------------------------------------------------
global sv_witness_program_asm
sv_witness_program_asm:
    cmp  rsi, 4
    jb   .no
    cmp  rsi, 42
    ja   .no
    movzx eax, byte [rdi]
    test eax, eax                        ; OP_0
    jz   .ver_ok
    cmp  eax, 0x51
    jb   .no
    cmp  eax, 0x60
    ja   .no
.ver_ok:
    lea  r9, [rsi-2]
    movzx r10d, byte [rdi+1]
    cmp  r10, r9                         ; s[1] == n - 2 ?
    jne  .no
    ; *version = s[0] ? s[0]-0x50 : 0
    test eax, eax
    jz   .v0
    sub  eax, 0x50
.v0:
    mov  [rdx], eax
    lea  rax, [rdi+2]
    mov  [rcx], rax                      ; *prog = s + 2
    mov  eax, r9d
    mov  [r8], eax                       ; *proglen = n - 2
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ----------------------------------------------------------------------------
; last_push: rdi=ss rsi=ssl -> CF clear: rax=last push data ptr, rdx=len,
; rcx=push count (>=1).  CF set: not push-only / malformed / empty.
; Internal helper, fully SysV (clobbers caller-saved only).
; Cursor p in r8, all bounds vs rsi.
; ----------------------------------------------------------------------------
last_push:
    xor  r8d, r8d                        ; p = 0
    xor  ecx, ecx                        ; npush = 0
    xor  eax, eax                        ; data = 0
    xor  edx, edx                        ; len = 0
.loop:
    cmp  r8, rsi
    jae  .done
    movzx r9d, byte [rdi+r8]
    cmp  r9d, 0x4b
    ja   .not_direct
    ; direct push 0x00..0x4b -- NOTE 0x00 lands HERE in the C too (its
    ; `op <= 0x4b` test runs first, so its small-int arm is dead for OP_0):
    ; a zero-byte "push" whose data pointer aims AFTER the opcode. The first
    ; draft routed 0x00 to the small-int arm (data pointer AT the opcode);
    ; unobservable through sv_classify_segwit's outputs, but bug-for-bug
    ; means matching the dead-code shape too. p+1+op > ssl ?
    lea  r10, [r8+1]
    add  r10, r9
    cmp  r10, rsi
    ja   .bad
    lea  rax, [rdi+r8+1]                 ; data
    mov  edx, r9d                        ; len
    mov  r8, r10
    jmp  .counted
.not_direct:
    cmp  r9d, 0x4c
    je   .pd1
    cmp  r9d, 0x4d
    je   .pd2
    cmp  r9d, 0x4e
    je   .pd4
    cmp  r9d, 0x4f                       ; OP_1NEGATE
    je   .smallint
    cmp  r9d, 0x51
    jb   .bad
    cmp  r9d, 0x60
    ja   .bad
.smallint:                               ; OP_1NEGATE / OP_1..OP_16 (never OP_0)
    lea  rax, [rdi+r8]                   ; data = ss + p
    xor  edx, edx                        ; len = 0
    inc  r8
    jmp  .counted
.pd1:                                    ; 0x4c: len byte follows
    lea  r10, [r8+2]
    cmp  r10, rsi
    ja   .bad
    movzx edx, byte [rdi+r8+1]
    lea  r10, [r8+2]
    add  r10, rdx
    cmp  r10, rsi
    ja   .bad
    lea  rax, [rdi+r8+2]
    mov  r8, r10
    jmp  .counted
.pd2:                                    ; 0x4d: 2-byte LE len
    lea  r10, [r8+3]
    cmp  r10, rsi
    ja   .bad
    movzx edx, word [rdi+r8+1]
    lea  r10, [r8+3]
    add  r10, rdx
    cmp  r10, rsi
    ja   .bad
    lea  rax, [rdi+r8+3]
    mov  r8, r10
    jmp  .counted
.pd4:                                    ; 0x4e: 4-byte LE len, 64-bit-safe bound
    lea  r10, [r8+5]
    cmp  r10, rsi
    ja   .bad
    mov  edx, [rdi+r8+1]                 ; dl (u32, zero-extended)
    lea  r10, [r8+5]
    add  r10, rdx                        ; (u64)p + 5 + dl -- cannot wrap
    cmp  r10, rsi
    ja   .bad
    lea  rax, [rdi+r8+5]
    mov  r8, r10
.counted:
    inc  ecx
    jmp  .loop
.done:
    test ecx, ecx
    jz   .bad                            ; empty scriptSig: no push
    clc
    ret
.bad:
    stc
    ret

; ----------------------------------------------------------------------------
; sv_classify_segwit_asm(spk=rdi, spl=rsi, ss=rdx, ssl=rcx,
;                        version=r8, prog=r9, proglen=[rbp+16],
;                        wrapped=[rbp+24]) -> 1 / 2 / -1 / 0
; Frame: push rbp + 5 pushes (saves at [rbp-0x08..-0x28]), sub rsp,0x48 ->
; rsp = rbp-0x70, 0 mod 16 at both call sites. Locals below the save area:
;   [rbp-0x30] version out  [rbp-0x38] prog out  [rbp-0x40] ss
;   [rbp-0x48] ssl          [rbp-0x60..-0x4c] h[20] (hash160 scratch)
; Registers: rbx = spk, r12 = redeem data, r13 = redeem len, r14 = npush,
; r15 = spl.
; ----------------------------------------------------------------------------
global sv_classify_segwit_asm
sv_classify_segwit_asm:
    ; ---- FRAMELESS FAST PATH (2026-08-24, second rev) ----
    ; The two overwhelmingly common outcomes -- native program, and
    ; plain-legacy spk -- need no calls, so they pay no prologue. The C wins
    ; these paths because gcc inlines sv_witness_program and keeps the leaf
    ; lean; this recovers that. Stack args while frameless:
    ;   [rsp+8] = proglen out, [rsp+16] = wrapped out.
    mov  rax, [rsp+16]
    mov  dword [rax], 0                  ; *wrapped = 0 (always, like the C)
    ; inline witness-program test on the spk
    cmp  rsi, 4
    jb   .not_native
    cmp  rsi, 42
    ja   .not_native
    movzx eax, byte [rdi]
    test eax, eax                        ; OP_0
    jz   .nv_ok
    cmp  eax, 0x51
    jb   .not_native
    cmp  eax, 0x60
    ja   .not_native
.nv_ok:
    lea  r10, [rsi-2]
    movzx r11d, byte [rdi+1]
    cmp  r11, r10                        ; s[1] == n - 2 ?
    jne  .not_native
    test eax, eax                        ; *version = s[0] ? s[0]-0x50 : 0
    jz   .nv_v0
    sub  eax, 0x50
.nv_v0:
    mov  [r8], eax
    lea  rax, [rdi+2]
    mov  [r9], rax                       ; *prog = spk + 2
    mov  rax, [rsp+8]
    mov  [rax], r10d                     ; *proglen = n - 2
    mov  eax, 1
    ret
.not_native:
    ; not-P2SH -> legacy, still frameless
    cmp  rsi, 23
    jne  .fast_legacy
    cmp  byte [rdi], 0xa9
    jne  .fast_legacy
    cmp  byte [rdi+1], 0x14
    jne  .fast_legacy
    cmp  byte [rdi+22], 0x87
    je   .p2sh_slow                      ; real P2SH: take the framed path
.fast_legacy:
    xor  eax, eax
    ret

    ; ---- FRAMED SLOW PATH: P2SH-wrapped analysis (calls last_push,
    ; sv_witness_program_asm, hash160) -- args still intact in registers
    ; and at their original stack slots, which the frame re-addresses as
    ; [rbp+16]/[rbp+24] exactly as before. ----
.p2sh_slow:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x48
    mov  rbx, rdi                        ; spk
    mov  r15, rsi                        ; spl
    mov  [rbp-0x40], rdx                 ; ss
    mov  [rbp-0x48], rcx                 ; ssl
    mov  [rbp-0x30], r8                  ; version out
    mov  [rbp-0x38], r9                  ; prog out
    ; last push of the scriptSig
    mov  rdi, [rbp-0x40]
    mov  rsi, [rbp-0x48]
    call last_push
    jc   .legacy                         ; not push-only / empty -> legacy
    mov  r12, rax                        ; redeem data
    mov  r13, rdx                        ; redeem len
    mov  r14, rcx                        ; npush
    ; is the redeem a witness program?
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, [rbp-0x30]
    mov  rcx, [rbp-0x38]
    mov  r8,  [rbp+16]
    call sv_witness_program_asm
    test rax, rax
    jz   .legacy
    ; exactly one MINIMAL DIRECT push: np==1 && ssl==1+rl && ss[0]==rl
    cmp  r14, 1
    jne  .malleated
    lea  rax, [r13+1]
    cmp  [rbp-0x48], rax                 ; ssl == 1 + rl ?
    jne  .malleated
    mov  rax, [rbp-0x40]
    movzx eax, byte [rax]
    cmp  rax, r13                        ; ss[0] == rl ?
    jne  .malleated
    ; hash160(redeem) must equal the P2SH hash (spk+2)
    lea  rdi, [rbp-0x60]                 ; h[20]
    mov  rsi, r12
    mov  rdx, r13
    call hash160
    ; memcmp(h, spk+2, 20)
    mov  rax, [rbp-0x60]
    xor  rax, [rbx+2]
    mov  rcx, [rbp-0x58]
    xor  rcx, [rbx+10]
    or   rax, rcx
    mov  ecx, [rbp-0x50]
    xor  ecx, [rbx+18]
    or   rax, rcx
    jnz  .malleated
    mov  rax, [rbp+24]
    mov  dword [rax], 1                  ; *wrapped = 1
    mov  eax, 2
    jmp  .out
.malleated:
    mov  rax, -1
    jmp  .out
.legacy:
    xor  eax, eax
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
