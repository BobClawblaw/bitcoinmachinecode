; ============================================================================
; bitcoin_txv_classify.asm -- per-input consensus classification of
; daemon/tx_verify.c's block path, 100% AI-generated x86-64 assembly (NASM,
; ELF64). Phase 2 slice 2 of the C->asm conversion (2026-08-24).
;
; Twin of txvb_classify (extracted verbatim from Phase 1's loop the same
; day): coinbase maturity, prevout spk copy-out (offset discipline into the
; caller's bytepool), the taproot gate, segwit classification including the
; wrapped/native wprog split, the unexpected-witness rule, and the legacy
; fallthrough. Segwit shape DETECTION stays in C (sv_classify_segwit,
; bitcoin_scriptverify.c) -- that whole layer is its own later slice; pool
; growth likewise stays behind txv_bytepool_alloc, phase 3's boundary.
;
;   long txvb_classify_asm(txvb_in_t* in, long height, u64 flags, u64 value,
;                          u64 uheight, u64 ucb,
;                          /*stack*/ const u8* spk, u64 spklen,
;                          bytepool_t* spk_pool, int* has_taproot,
;                          const char** reason)
;     -> 1 ok / 0 reject (*reason = .rodata literal, byte-identical to the
;        C's; the differential strcmp()s them)
;
; STRUCT ABI (offsetof-pinned, not hand-derived):
;   txvb_in_t: tx_index@0 local_idx@8 tx_ptr@16 tx_len@24 outpoint@32
;              scriptSig@40 scriptSiglen@48 wit@56 witlen@64 nwit@72
;              wit_off@76 wprog@80 wproglen@88 wrapped@92 wprog_off@96
;              value@104 spk_off@112 spklen@120 tap_desc@128 shape@136,
;              sizeof 144
;
; The wprog split is the consensus-critical subtlety (incident 482566):
; wrapped programs point into the TX bytes (stable); native programs are
; stored as an OFFSET into the spk copy because sv_classify_segwit's pointer
; aims into the caller's transient prevout buffer. Reproduced exactly.
; ============================================================================

BITS 64
DEFAULT REL

extern sv_classify_segwit             ; int (spk, u32 spl, ss, u32 ssl,
                                      ;      u32* wver, const u8** wprog,
                                      ;      u32* wplen, int* wrapped) -- C
extern txv_bytepool_alloc             ; u64 (bytepool_t*, const u8*, u64) -- C

%define TXV_SPK_CAP       10000
%define COINBASE_MATURITY 100
%define FLAG_WITNESS      (1 << 11)
%define FLAG_TAPROOT      (1 << 17)

%define SHAPE_LEGACY 0
%define SHAPE_P2TR   3
%define SHAPE_WV0    4
%define SHAPE_WPASS  5

%define IN_SCRIPTSIG  40
%define IN_SSLEN      48
%define IN_NWIT       72
%define IN_WPROG      80
%define IN_WPROGLEN   88
%define IN_WRAPPED    92
%define IN_WPROGOFF   96
%define IN_VALUE      104
%define IN_SPKOFF     112
%define IN_SPKLEN     120
%define IN_SHAPE      136

section .rodata
c_immature: db "immature coinbase spend (100-block rule)",0
c_spkbig:   db "prevout script too large",0
c_oom:      db "out of memory",0
c_tapss:    db "p2tr scriptSig must be empty",0
c_tapwit:   db "p2tr empty witness",0
c_wrapss:   db "p2sh-wrapped witness program: scriptSig must be exactly one push of the redeemScript",0
c_wpss:     db "witness program scriptSig must be empty",0
c_wpkh2:    db "p2wpkh needs exactly 2 witness items",0
c_wsh1:     db "p2wsh needs a witnessScript",0
c_unexwit:  db "unexpected witness on a non-witness script",0

section .text

; ----------------------------------------------------------------------------
; txvb_classify_asm -- see header for the full signature.
;   rdi=in rsi=height rdx=flags rcx=value r8=uheight r9=ucb
;   [rbp+16]=spk [rbp+24]=spklen [rbp+32]=spk_pool [rbp+40]=has_taproot
;   [rbp+48]=reason
; Frame: push rbp + 5 pushes (saves at [rbp-0x08..-0x28]), sub rsp,0x38 ->
; rsp = rbp-0x60, 0 mod 16 at both C call sites (each pushes 0 or 2 stack
; args; 2 pushes keep 0 mod 16). Locals, below the save area:
;   [rbp-0x30] wver(dword)  [rbp-0x34] wplen(dword)  [rbp-0x38] wrapped(dword)
;   [rbp-0x40] wprog(qword) [rbp-0x48] height
; Registers: rbx = in, r12 = spk, r13 = spklen, r14 = flags.
; ----------------------------------------------------------------------------
global txvb_classify_asm
txvb_classify_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x38
    mov  rbx, rdi                        ; in
    mov  r14, rdx                        ; flags
    mov  r12, [rbp+16]                   ; spk
    mov  r13, [rbp+24]                   ; spklen
    mov  [rbp-0x48], rsi                 ; height

    ; ---- coinbase maturity ----
    test r9, r9                          ; ucb
    jz   .not_cb
    mov  rax, rsi                        ; height
    sub  rax, r8                         ; - (long)uheight
    cmp  rax, COINBASE_MATURITY
    jge  .not_cb
    lea  rsi, [c_immature]
    jmp  .reject
.not_cb:
    mov  [rbx+IN_VALUE], rcx             ; in->value = value

    cmp  r13, TXV_SPK_CAP                ; spklen > TXV_SPK_CAP ?
    ja   .r_spkbig

    ; ---- spk copy-out: offset into the caller's pool ----
    mov  rdi, [rbp+32]                   ; spk_pool
    mov  rsi, r12
    mov  rdx, r13
    call txv_bytepool_alloc
    cmp  rax, -1
    je   .r_oom
    mov  [rbx+IN_SPKOFF], rax
    mov  [rbx+IN_SPKLEN], r13d           ; (u32)spklen

    ; ---- taproot gate: is_p2tr(spk, spklen) && (flags & TAPROOT) ----
    cmp  r13, 34
    jne  .not_tap
    cmp  byte [r12], 0x51
    jne  .not_tap
    cmp  byte [r12+1], 0x20
    jne  .not_tap
    test r14, FLAG_TAPROOT
    jz   .not_tap
    mov  rax, [rbp+40]                   ; *has_taproot = 1
    mov  dword [rax], 1
    mov  byte [rbx+IN_SHAPE], SHAPE_P2TR
    cmp  dword [rbx+IN_SSLEN], 0
    jne  .r_tapss
    cmp  dword [rbx+IN_NWIT], 0
    je   .r_tapwit
    jmp  .accept
.not_tap:

    test r14, FLAG_WITNESS
    jz   .legacy
    ; ---- segwit classification (detection stays in C for this slice) ----
    mov  rdi, r12                        ; spk
    mov  esi, r13d                       ; (u32)spklen
    mov  rdx, [rbx+IN_SCRIPTSIG]
    mov  ecx, [rbx+IN_SSLEN]
    lea  r8,  [rbp-0x30]                 ; &wver
    lea  r9,  [rbp-0x40]                 ; &wprog
    lea  rax, [rbp-0x38]
    push rax                             ; arg 8: &wrapped
    lea  rax, [rbp-0x34]
    push rax                             ; arg 7: &wplen
    call sv_classify_segwit
    add  rsp, 16
    test eax, eax
    js   .r_wrapss                       ; cls < 0
    jz   .not_witprog                    ; cls == 0
    ; cls > 0: a witness program
    cmp  dword [rbp-0x38], 0             ; wrapped?
    jne  .have_wrap
    cmp  dword [rbx+IN_SSLEN], 0         ; native: scriptSig must be empty
    jne  .r_wpss
.have_wrap:
    cmp  dword [rbp-0x30], 0             ; wver == 0 ?
    jne  .wpass
    mov  byte [rbx+IN_SHAPE], SHAPE_WV0
    mov  eax, [rbp-0x34]                 ; wplen
    mov  [rbx+IN_WPROGLEN], eax
    mov  ecx, [rbp-0x38]                 ; wrapped (int)
    mov  [rbx+IN_WRAPPED], cl            ; (u8)wrapped
    test ecx, ecx
    jz   .native
    mov  rdx, [rbp-0x40]                 ; wrapped: wprog = raw ptr (tx bytes)
    mov  [rbx+IN_WPROG], rdx
    mov  dword [rbx+IN_WPROGOFF], 0
    jmp  .wv0_rules
.native:
    mov  qword [rbx+IN_WPROG], 0         ; native: offset into the spk copy
    mov  rdx, [rbp-0x40]
    sub  rdx, r12                        ; wprog - spk
    mov  [rbx+IN_WPROGOFF], edx
.wv0_rules:
    mov  eax, [rbp-0x34]                 ; wplen
    cmp  eax, 20
    jne  .chk32
    cmp  dword [rbx+IN_NWIT], 2
    jne  .r_wpkh2
    jmp  .accept
.chk32:
    cmp  eax, 32
    jne  .accept
    cmp  dword [rbx+IN_NWIT], 1
    jb   .r_wsh1
    jmp  .accept
.wpass:
    mov  byte [rbx+IN_SHAPE], SHAPE_WPASS
    jmp  .accept
.not_witprog:
    cmp  dword [rbx+IN_NWIT], 0          ; witness on a non-witness script?
    jne  .r_unexwit
.legacy:
    mov  byte [rbx+IN_SHAPE], SHAPE_LEGACY
.accept:
    mov  eax, 1
    jmp  .out

.r_spkbig:  lea rsi, [c_spkbig]
            jmp .reject
.r_oom:     lea rsi, [c_oom]
            jmp .reject
.r_tapss:   lea rsi, [c_tapss]
            jmp .reject
.r_tapwit:  lea rsi, [c_tapwit]
            jmp .reject
.r_wrapss:  lea rsi, [c_wrapss]
            jmp .reject
.r_wpss:    lea rsi, [c_wpss]
            jmp .reject
.r_wpkh2:   lea rsi, [c_wpkh2]
            jmp .reject
.r_wsh1:    lea rsi, [c_wsh1]
            jmp .reject
.r_unexwit: lea rsi, [c_unexwit]
.reject:
    mov  rax, [rbp+48]
    mov  [rax], rsi                      ; *reason = string
    xor  eax, eax
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
