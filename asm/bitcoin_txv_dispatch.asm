; ============================================================================
; bitcoin_txv_dispatch.asm -- the per-input verification dispatch and the
; legacy transaction view, 100% AI-generated x86-64 assembly (NASM, ELF64).
; Phase 2 slice 8 of the C->asm conversion (2026-08-24). Twins of
; tx_verify.c's txvb_verify_one (refactored to explicit-state the same day)
; and legacy_tx_view; differential: tests/test_txv_dispatch_diff.c.
;
;   const u8* legacy_tx_view_asm(const u8* tx, u64 txlen, u64* out_len)
;   long txvb_verify_one_asm(const u8* tx, u64 txlen, txvb_in_t* in,
;                            u64 flags, u8* sv_work, u64 sv_workcap,
;                            /*stack*/ const bytepool_t* spk_pool,
;                            const bytepool_t* tap_pool,
;                            const tapagg_t* tapdesc,
;                            const char** reason) -> 1 / 0
;
; legacy_tx_view: legacy (pre-segwit sigversion) sighash serializes the tx
; WITHOUT witness data; a tx mixing legacy and segwit inputs is
; segwit-serialized, so the legacy input's sighash would otherwise commit
; to marker/flag/witness bytes and fail (first real case: block 481825).
; The C keeps one lazily-malloc'd 1MB buffer per thread (__thread pointer +
; BMC_TLS_BUF); the twin mirrors that exactly -- a .tbss pointer slot
; (Initial-Exec model, same TLS_ADDR idiom as bitcoin_interp.asm) and a
; lazy malloc, abort() on OOM like the C's macro. Strip failure falls back
; to the unstripped tx, "sv will reject on a bad hash" -- the C's comment
; and behavior, reproduced.
;
; The dispatch calls tapagg_verify_asm (slice 7 twin) for P2TR and the C
; sv_verify_witness_v0 / sv_verify_script leaves for WV0/LEGACY (the
; interpreter driver layer is its own campaign). Reason strings byte-match
; the C's. TXV_SHAPE_*: LEGACY 0, P2TR 3, WV0 4, everything else passes
; (WPASS: unknown witness version, anyone-can-spend under consensus flags).
;
; txvb_in_t offsets (offsetof-pinned, same table as bitcoin_txv_parse.asm):
;   local_idx@8 scriptSig@40 scriptSiglen@48 wit@56 witlen@64 nwit@72
;   wprog@80 wproglen@88 wprog_off@96 value@104 spk_off@112 spklen@120
;   tap_desc@128 shape@136
; ============================================================================

BITS 64
DEFAULT REL

extern malloc
extern abort
extern strip_witness_asm              ; slice 6 twin
extern tapagg_verify_asm              ; slice 7 twin
extern sv_verify_witness_v0           ; C (bitcoin_witness_v0.c) -- later slice
extern sv_verify_script               ; C (bitcoin_scriptverify.c) -- later slice
extern g_txv_script_checks            ; VAL-16: assumevalid short-circuit (daemon/tx_verify.c)

%define LTV_CAP       (1 << 20)

%define SHAPE_LEGACY  0
%define SHAPE_P2TR    3
%define SHAPE_WV0     4

%define IN_LOCAL      8
%define IN_SCRIPTSIG  40
%define IN_SSLEN      48
%define IN_WIT        56
%define IN_WITLEN     64
%define IN_NWIT       72
%define IN_WPROG      80
%define IN_WPROGLEN   88
%define IN_WPROGOFF   96
%define IN_VALUE      104
%define IN_SPKOFF     112
%define IN_SPKLEN     120
%define IN_TAPDESC    128
%define IN_SHAPE      136

%define TAPAGG_SIZE   48

%define BP_BUF        0

section .tbss alloc noexec nowrite tls align=8
global ltv_buf                        ; global: ..gottpoff needs a visible symbol
                                      ; (same as bitcoin_interp.asm's tbss slots)
ltv_buf: resq 1                       ; __thread u8* stripped (lazy malloc)

section .rodata
d_notbuilt: db "internal: taproot aggregate not built",0
d_wpkh:     db "p2wpkh signature invalid",0
d_wsh:      db "p2wsh script verification failed",0
d_legacy:   db "legacy script verification failed",0

section .text

%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

; ----------------------------------------------------------------------------
; legacy_tx_view_asm(tx=rdi, txlen=rsi, out_len=rdx) -> rax = view ptr
; Exact C: not segwit-marked (or < 6 bytes) -> the tx itself, len unchanged;
; else strip into this thread's lazy buffer; strip failure -> unstripped
; fallback.
; Frame: push rbp + 3 pushes, sub rsp,0x18 -> 0 mod 16 at the calls.
; rbx = tx, r12 = txlen, r13 = out_len.
; ----------------------------------------------------------------------------
global legacy_tx_view_asm
legacy_tx_view_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x18
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    ; if (txlen < 6 || !(tx[4]==0x00 && tx[5]==0x01)) return tx unchanged
    cmp  rsi, 6
    jb   .plain
    cmp  byte [rdi+4], 0x00
    jne  .plain
    cmp  byte [rdi+5], 0x01
    jne  .plain
    ; this thread's buffer, lazily malloc'd (BMC_TLS_BUF shape: abort on OOM)
    TLS_ADDR rax, ltv_buf
    mov  [rbp-0x28], rax                 ; &stripped (this thread's slot)
    mov  rdi, [rax]
    test rdi, rdi
    jnz  .have_buf
    mov  edi, LTV_CAP
    call malloc
    test rax, rax
    jnz  .store_buf
    call abort
.store_buf:
    mov  rcx, [rbp-0x28]
    mov  [rcx], rax
    mov  rdi, rax
.have_buf:
    mov  [rbp-0x20], rdi                 ; stripped
    ; n = strip_witness(tx, txlen, stripped, 1<<20)
    mov  rdx, rdi
    mov  rdi, rbx
    mov  rsi, r12
    mov  ecx, LTV_CAP
    call strip_witness_asm
    test rax, rax
    jle  .plain                          ; fall back; sv rejects on a bad hash
    mov  [r13], rax                      ; *out_len = n
    mov  rax, [rbp-0x20]                 ; return stripped
    jmp  .out
.plain:
    mov  [r13], r12                      ; *out_len = txlen
    mov  rax, rbx                        ; return tx
.out:
    add  rsp, 0x18
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; txvb_verify_one_asm -- see header for the signature.
;   rdi=tx rsi=txlen rdx=in rcx=flags r8=sv_work r9=sv_workcap
;   [rbp+16]=spk_pool [rbp+24]=tap_pool [rbp+32]=tapdesc [rbp+48... no:
;   [rbp+40]=reason
; Frame: push rbp + 5 pushes, sub rsp,0x38 -> rsp = rbp-0x60, 0 mod 16; the
; two big C calls push their own stack args in multiples of 16.
; Locals: [rbp-0x30] ltxlen (legacy view out-param).
; Registers: rbx = in, r12 = tx, r13 = txlen, r14 = flags, r15 = spk.
; ----------------------------------------------------------------------------
global txvb_verify_one_asm
txvb_verify_one_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x38
    mov  rbx, rdx                        ; in
    mov  r12, rdi                        ; tx
    mov  r13, rsi                        ; txlen
    mov  r14, rcx                        ; flags
    mov  [rbp-0x38], r8                  ; sv_work
    mov  [rbp-0x40], r9                  ; sv_workcap
    ; spk = spk_pool->buf + in->spk_off
    mov  rax, [rbp+16]
    mov  r15, [rax+BP_BUF]
    add  r15, [rbx+IN_SPKOFF]

    ; ---- VAL-16 (audit 2026-09-03): the assumevalid short-circuit ----------
    ; daemon/tx_verify.c:607 opens the equivalent C function with
    ;     if (!g_txv_script_checks) return 1;
    ; and this twin did not have it. Nothing in production drives this file
    ; today -- tests/test_txv_dispatch_diff is its only caller -- so there was
    ; no behavioural difference to observe. But the whole POINT of a
    ; differential twin is that it answers identically to the original, and
    ; the first differential run with assumevalid ON would have diverged on
    ; every input: the C side returning 1 without evaluating, this side
    ; evaluating. A twin that disagrees with its original under a documented
    ; configuration is worse than no twin, because the diff is trusted.
    cmp  dword [rel g_txv_script_checks], 0
    jne  .checks_on
    mov  eax, 1                          ; assumevalid: accept without evaluating
    jmp  .out
.checks_on:
    movzx eax, byte [rbx+IN_SHAPE]
    cmp  eax, SHAPE_P2TR
    je   .p2tr
    cmp  eax, SHAPE_WV0
    je   .wv0
    cmp  eax, SHAPE_LEGACY
    je   .legacy
    mov  eax, 1                          ; WPASS and anything else: valid
    jmp  .out

.p2tr:
    mov  rax, [rbx+IN_TAPDESC]
    cmp  rax, -1
    je   .r_notbuilt
    ; tapagg_verify_asm(tap_pool, &tapdesc[tap_desc], spk, wit, witlen,
    ;                   nwit, local_idx, reason)
    imul rax, rax, TAPAGG_SIZE
    add  rax, [rbp+32]                   ; &tapdesc[tap_desc]
    mov  rdi, [rbp+24]                   ; tap_pool
    mov  rsi, rax
    mov  rdx, r15                        ; spk
    mov  rcx, [rbx+IN_WIT]
    mov  r8,  [rbx+IN_WITLEN]
    mov  r9d, [rbx+IN_NWIT]
    push qword [rbp+40]                  ; arg 8: reason
    mov  eax, [rbx+IN_LOCAL]
    push rax                             ; arg 7: local_idx
    call tapagg_verify_asm
    add  rsp, 16
    ; its return IS ours; on fail it already set *reason
    jmp  .out

.wv0:
    ; wprog = in->wprog ? in->wprog : spk + in->wprog_off
    mov  rdi, [rbx+IN_WPROG]
    test rdi, rdi
    jnz  .have_wprog
    mov  edi, [rbx+IN_WPROGOFF]
    add  rdi, r15
.have_wprog:
    ; sv_verify_witness_v0(wprog, wproglen, wit, witlen, nwit, value, flags,
    ;                      local_idx, tx, txlen, work, workcap) -- 12 args
    mov  esi, [rbx+IN_WPROGLEN]
    mov  rdx, [rbx+IN_WIT]
    mov  rcx, [rbx+IN_WITLEN]
    mov  r8d, [rbx+IN_NWIT]
    mov  r9,  [rbx+IN_VALUE]
    push qword [rbp-0x40]                ; arg 12: workcap
    push qword [rbp-0x38]                ; arg 11: work
    push r13                             ; arg 10: txlen
    push r12                             ; arg  9: tx
    mov  eax, [rbx+IN_LOCAL]
    push rax                             ; arg  8: local_idx
    push r14                             ; arg  7: flags
    call sv_verify_witness_v0
    add  rsp, 48
    test eax, eax
    jz   .ok
    cmp  dword [rbx+IN_WPROGLEN], 20
    jne  .r_wsh
    lea  rsi, [d_wpkh]
    jmp  .reject
.r_wsh:
    lea  rsi, [d_wsh]
    jmp  .reject

.legacy:
    ; ltx = legacy_tx_view(tx, txlen, &ltxlen)
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbp-0x30]
    call legacy_tx_view_asm
    ; sv_verify_script(scriptSig, ssl, spk, spklen, flags, local_idx,
    ;                  ltx, ltxlen, work, workcap) -- 10 args
    mov  rdi, [rbx+IN_SCRIPTSIG]
    mov  esi, [rbx+IN_SSLEN]
    mov  rdx, r15                        ; spk
    mov  ecx, [rbx+IN_SPKLEN]
    mov  r8,  r14                        ; flags
    mov  r9d, [rbx+IN_LOCAL]
    push qword [rbp-0x40]                ; arg 10: workcap
    push qword [rbp-0x38]                ; arg  9: work
    push qword [rbp-0x30]                ; arg  8: ltxlen
    push rax                             ; arg  7: ltx
    call sv_verify_script
    add  rsp, 32
    test eax, eax
    jz   .ok
    lea  rsi, [d_legacy]
    jmp  .reject

.r_notbuilt:
    lea  rsi, [d_notbuilt]
.reject:
    mov  rax, [rbp+40]
    mov  [rax], rsi                      ; *reason = string
    xor  eax, eax
    jmp  .out
.ok:
    mov  eax, 1
.out:
    add  rsp, 0x38
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
