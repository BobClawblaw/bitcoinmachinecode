; ============================================================================
; bitcoin_checksig.asm -- the two script-interpreter checksig hooks, 100%
; AI-generated x86-64 assembly (NASM, ELF64). Phase 2 slice 11 of the C->asm
; conversion (2026-08-24). Twins of bitcoin_scriptverify.c's sv_checksig
; (SigVersion::BASE) and bitcoin_witness_v0.c's sv_checksig_witness_v0
; (SigVersion::WITNESS_V0); differential: tests/test_checksig_diff.c.
;
;   u64 sv_checksig_asm(void* ctx, const u8* sig, u64 siglen,
;                       const u8* pub, u64 publen, const void* slice)
;   u64 sv_checksig_witness_v0_asm(... same signature ...)
;
; These have the sv_checksig_fn pointer type, so both entry points ARE the
; hooks -- callable by the C sv_run_v exactly like the C hooks. Every leaf
; is already assembly (der_parse_sig, legacy_sighash / segwit_v0_sighash,
; the script codec, be_to_limbs, pubkey_parse, ecdsa_verify), so this is a
; marshaling twin: return 0 for an empty sig, take the hashtype from the
; signature's LAST byte (the 2026-08-19 raw-hashtype fix, not der_parse's
; recognized dht), and thread the ctx / scriptCode-slice fields through.
;
; sv_checksig (BASE) additionally does Core's FindAndDelete: encode the
; signature as a script push (script_push_encode) and delete every
; occurrence from the scriptCode slice (script_find_and_delete) BEFORE
; legacy_sighash. sv_checksig_witness_v0 does NOT (Core applies FindAndDelete
; only for BASE) and uses the slice verbatim.
;
; sv_ctx offsets: tx@0 txlen@8 nIn@16 work@24 workcap@32 amount@56.
; scriptCode slice { const u8* p @0; size_t n @8 }.
; Per-thread scratch mirrors the C's __thread buffers: needle[600] +
; scF[20000] for BASE, pre[65536] for WITNESS_V0, lazy .tbss+malloc.
; ============================================================================

BITS 64
DEFAULT REL

extern malloc
extern abort
extern der_parse_sig                  ; asm
extern script_push_encode             ; asm
extern script_find_and_delete         ; asm
extern legacy_sighash                 ; asm
extern segwit_v0_sighash              ; asm
extern be_to_limbs                    ; asm
extern pubkey_parse                   ; asm
extern ecdsa_verify                   ; asm

%define CTX_TX      0
%define CTX_TXLEN   8
%define CTX_NIN     16
%define CTX_WORK    24
%define CTX_WORKCAP 32
%define CTX_AMOUNT  56

%define SLICE_P     0
%define SLICE_N     8

%define NEEDLE_CAP  600
%define SCF_CAP     20000
%define PRE_CAP     65536

section .tbss alloc noexec nowrite tls align=8
global cks_needle
cks_needle: resq 1                    ; __thread u8* needle[600]
global cks_scf
cks_scf:    resq 1                    ; __thread u8* scF[20000]
global cks_pre
cks_pre:    resq 1                    ; __thread u8* pre[65536]

section .text

%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

%macro TLS_LAZY 3
    TLS_ADDR rcx, %2
    mov  %1, [rcx]
    test %1, %1
    jnz  %%have
    push rcx
    push rcx
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
; sv_checksig_asm (SigVersion::BASE)
;   rdi=ctx rsi=sig rdx=siglen rcx=pub r8=publen r9=slice
; Frame: push rbp + 5 pushes, sub rsp,0x138 -> rsp 0 mod 16
; in the body (each call site re-aligns for its own stack args).
; Locals: [rbp-0x30] ctx [rbp-0x38] sig [rbp-0x40] siglen [rbp-0x48] pub
;   [rbp-0x50] publen [rbp-0x58] slice [rbp-0x60] scF [rbp-0x68] scflen
;   [rbp-0x70] ht (dword)   [rbp-0x134] dht (dword)
;   Each of these is 32 BYTES and they must not overlap -- the first draft
;   put qy at -0xf8 and zl at -0xf0, so pubkey_parse's qy write clobbered
;   the message-hash limbs and ecdsa_verify rejected every VALID signature
;   (caught by this slice's differential; same bug class as incident #31):
;     r[4]  @ -0x90 .. -0x70     s[4]  @ -0xb0 .. -0x90
;     z[32] @ -0xd0 .. -0xb0     zl[4] @ -0xf0 .. -0xd0
;     qx[4] @ -0x110 .. -0xf0    qy[4] @ -0x130 .. -0x110
;   The frame reserves 0x138 (keeps rsp 0 mod 16) and all of it sits
;   strictly below the 5-push save area at [rbp-0x08..-0x28].
; ----------------------------------------------------------------------------
global sv_checksig_asm
sv_checksig_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x138
    mov  [rbp-0x30], rdi
    mov  [rbp-0x38], rsi
    mov  [rbp-0x40], rdx
    mov  [rbp-0x48], rcx
    mov  [rbp-0x50], r8
    mov  [rbp-0x58], r9
    test rdx, rdx                        ; empty sig -> 0
    jz   .zero
    ; ht = sig[siglen-1]
    mov  rax, rsi
    add  rax, rdx
    movzx eax, byte [rax-1]
    mov  [rbp-0x70], eax
    ; der_parse_sig(sig, siglen, r, s, &dht)
    mov  rdi, rsi
    mov  rsi, rdx
    lea  rdx, [rbp-0x90]                 ; r[4]
    lea  rcx, [rbp-0xb0]                 ; s[4]
    lea  r8,  [rbp-0x134]                ; &dht (dword)
    call der_parse_sig
    test eax, eax
    jz   .zero
    ; needle = script_push_encode(needle, 600, sig, siglen)
    TLS_LAZY rbx, cks_needle, NEEDLE_CAP
    mov  rdi, rbx
    mov  esi, NEEDLE_CAP
    mov  rdx, [rbp-0x38]
    mov  rcx, [rbp-0x40]
    call script_push_encode
    test rax, rax
    js   .zero                           ; nlen < 0
    mov  r14, rax                        ; nlen
    ; scflen = script_find_and_delete(scF, 20000, slice.p, slice.n, needle, nlen)
    TLS_LAZY r12, cks_scf, SCF_CAP
    mov  [rbp-0x60], r12
    mov  rdi, r12
    mov  esi, SCF_CAP
    mov  rax, [rbp-0x58]
    mov  rdx, [rax+SLICE_P]
    mov  rcx, [rax+SLICE_N]
    mov  r8,  rbx                        ; needle
    mov  r9,  r14                        ; nlen
    call script_find_and_delete
    test rax, rax
    js   .zero                           ; scflen < 0
    mov  [rbp-0x68], rax
    ; legacy_sighash(z, tx, txlen, nIn, scF, scflen, ht, work, workcap)
    mov  r15, [rbp-0x30]                 ; ctx
    lea  rdi, [rbp-0xd0]                 ; z[32]
    mov  rsi, [r15+CTX_TX]
    mov  rdx, [r15+CTX_TXLEN]
    mov  rcx, [r15+CTX_NIN]
    mov  r8,  [rbp-0x60]                 ; scF
    mov  r9,  [rbp-0x68]                 ; scflen
    mov  eax, [rbp-0x70]                 ; ht
    sub  rsp, 8                          ; 3 stack args would leave rsp 8 mod
                                         ; 16 at the call; realign first
    push qword [r15+CTX_WORKCAP]         ; arg 9: cap
    push qword [r15+CTX_WORK]            ; arg 8: preimg
    push rax                             ; arg 7: hashtype
    call legacy_sighash
    add  rsp, 32
    test eax, eax
    jz   .zero
    ; zl = be_to_limbs(z, 32) ; pubkey_parse ; ecdsa_verify
    lea  rdi, [rbp-0xf0]                 ; zl[4]
    lea  rsi, [rbp-0xd0]                 ; z
    mov  edx, 32
    call be_to_limbs
    mov  rdi, [rbp-0x48]                 ; pub
    mov  rsi, [rbp-0x50]                 ; publen
    lea  rdx, [rbp-0x110]                ; qx[4]
    lea  rcx, [rbp-0x130]                ; qy[4]
    call pubkey_parse
    test eax, eax
    jz   .zero
    lea  rdi, [rbp-0xf0]                 ; z limbs
    lea  rsi, [rbp-0x90]                 ; r
    lea  rdx, [rbp-0xb0]                 ; s
    lea  rcx, [rbp-0x110]                ; qx
    lea  r8,  [rbp-0x130]                ; qy
    call ecdsa_verify
    movsx rax, eax
    jmp  .out
.zero:
    xor  eax, eax
.out:
    add  rsp, 0x138
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; sv_checksig_witness_v0_asm (SigVersion::WITNESS_V0) -- no FindAndDelete,
; BIP143 sighash over the slice verbatim.
;   rdi=ctx rsi=sig rdx=siglen rcx=pub r8=publen r9=slice
; ----------------------------------------------------------------------------
global sv_checksig_witness_v0_asm
sv_checksig_witness_v0_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x138
    mov  [rbp-0x30], rdi
    mov  [rbp-0x38], rsi
    mov  [rbp-0x40], rdx
    mov  [rbp-0x48], rcx
    mov  [rbp-0x50], r8
    mov  [rbp-0x58], r9
    test rdx, rdx
    jz   .zero
    mov  rax, rsi
    add  rax, rdx
    movzx eax, byte [rax-1]
    mov  [rbp-0x70], eax                 ; ht
    mov  rdi, rsi
    mov  rsi, rdx
    lea  rdx, [rbp-0x90]
    lea  rcx, [rbp-0xb0]
    lea  r8,  [rbp-0x134]
    call der_parse_sig
    test eax, eax
    jz   .zero
    ; segwit_v0_sighash(z, tx, txlen, nIn, ht, amount, slice.p, slice.n, pre, 1<<16)
    TLS_LAZY rbx, cks_pre, PRE_CAP
    mov  r15, [rbp-0x30]                 ; ctx
    lea  rdi, [rbp-0xd0]                 ; z
    mov  rsi, [r15+CTX_TX]
    mov  rdx, [r15+CTX_TXLEN]
    mov  rcx, [r15+CTX_NIN]
    mov  r8d, [rbp-0x70]                 ; ht (u32)
    mov  r9,  [r15+CTX_AMOUNT]
    mov  rax, [rbp-0x58]                 ; slice
    mov  r10, [rax+SLICE_P]
    mov  r11, [rax+SLICE_N]
    ; push the 4 stack args in reverse: cap, pre, scLen, scriptCode
    push PRE_CAP
    push rbx                             ; pre
    push r11                             ; scriptcode_len
    push r10                             ; scriptCode
    call segwit_v0_sighash
    add  rsp, 32
    test rax, rax
    jle  .zero
    lea  rdi, [rbp-0xf0]
    lea  rsi, [rbp-0xd0]
    mov  edx, 32
    call be_to_limbs
    mov  rdi, [rbp-0x48]
    mov  rsi, [rbp-0x50]
    lea  rdx, [rbp-0x110]                ; qx
    lea  rcx, [rbp-0x130]                ; qy
    call pubkey_parse
    test eax, eax
    jz   .zero
    lea  rdi, [rbp-0xf0]
    lea  rsi, [rbp-0x90]
    lea  rdx, [rbp-0xb0]
    lea  rcx, [rbp-0x110]                ; qx
    lea  r8,  [rbp-0x130]                ; qy
    call ecdsa_verify
    movsx rax, eax
    jmp  .out
.zero:
    xor  eax, eax
.out:
    add  rsp, 0x138
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
