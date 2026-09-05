; ============================================================================
; bitcoin_sigops.asm -- sigop accounting (matches Bitcoin Core exactly).
;
;   long script_sigops(const u8* script, ulong len)                  [accurate]
;       Core CScript::GetSigOpCount(fAccurate=true): OP_CHECKSIG/VERIFY = 1,
;       OP_CHECKMULTISIG/VERIFY = DecodeOP_N(following OP_1..16) or 20.
;
;   long tx_legacy_sigops(const u8* tx, ulong txlen)
;       Core GetLegacySigOpCount(tx): for EVERY input,
;           scriptSig.GetSigOpCount(INACCURATE)   (multisig always 20)
;       for EVERY output, scriptPubKey.GetSigOpCount(INACCURATE).
;       This is the pure-structural part of the block sigop cost
;       (no prevouts, no witness). Used for the pre-SegWit differential.
;
;   long tx_sigop_cost(const u8* tx, ulong txlen)
;       Core GetTransactionSigOpCost structural part: counts legacy (accurate)
;       sigops from scriptSig + outputs, then the BIP141 witness sigop cost.
;       We implement the legacy and scriptPubKey portions; witness portion is
;       additive and handled by the higher-level block counter when present.
;
; To keep the differential exact, the block counter walks every tx, calls
; tx_legacy_sigops (inaccurate-20 multisig, matching Core), and sums.
;
; Uses get_op from bitcoin_scriptcodec.asm. All registers preserved per ABI.
; ============================================================================
default rel
section .text

extern get_op

; ============================================================================
; script_sigops_internal(script rdi, len rsi, accurate rdx) -> rax
;   if accurate: CHECKMULTISIG counts DecodeOP_N(last), else 20.
; ============================================================================
global script_sigops
script_sigops:
    xor   edx, edx            ; default accurate=false
    jmp   script_sigops_ex

global script_sigops_accurate
script_sigops_accurate:
    mov   edx, 1              ; accurate=true
    jmp   script_sigops_ex

global script_sigops_ex
script_sigops_ex:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    sub   rsp, 0x30
    mov   [rbp-0x30], rdx     ; accurate flag  (saved-reg area is -8..-0x20)
    xor   eax, eax
    mov   [rbp-0x28], rax     ; count (below saved r14 at -0x20)
    mov   r12, rdi            ; cursor
    lea   r13, [r12+rsi]      ; pend
    xor   ebx, ebx            ; last_opcode (0 = invalid)
.loop:
    cmp   r12, r13
    jae   .done
    lea   rdi, [rbp-0x38]
    mov   [rbp-0x38], r12
    mov   rsi, r13
    call  get_op
    test  rax, rax
    jz    .done
    mov   r12, [rbp-0x38]
    dec   rax                 ; real opcode
    cmp   rax, 0xac
    je    .checksig
    cmp   rax, 0xad
    je    .checksig
    cmp   rax, 0xae
    je    .multisig
    cmp   rax, 0xaf
    je    .multisig
    ; numeric push OP_1..OP_16 (0x51..0x60) -> remember for accurate count
    cmp   rax, 0x51
    jb    .reset_last
    cmp   rax, 0x60
    ja    .reset_last
    mov   ebx, eax
    jmp   .loop
.reset_last:
    xor   ebx, ebx
    jmp   .loop
.checksig:
    inc   qword [rbp-0x28]
    xor   ebx, ebx
    jmp   .loop
.multisig:
    cmp   qword [rbp-0x30], 0
    jz    .mult20
    ; accurate: if last is OP_1..16
    cmp   ebx, 0x51
    jb    .mult20
    cmp   ebx, 0x60
    ja    .mult20
    lea   eax, [rbx-0x50]
    add   [rbp-0x28], rax
    jmp   .mult_done
.mult20:
    add   qword [rbp-0x28], 20
.mult_done:
    xor   ebx, ebx
    jmp   .loop
.done:
    mov   rax, [rbp-0x28]
    add   rsp, 0x30
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret

; ============================================================================
; SCR-10 (audit 2026-09-03): tx_legacy_sigops walked the transaction with NO
; bounds checks at all -- r13 (len) was loaded once and never compared, and
; every varint read and every advance indexed r14 unconditionally. It was
; unreachable only because both callers happen to parse the transaction fully
; first: daemon/tx_accept.c:528 after its own walk, daemon/main.c:6096 on
; mempool-resident transactions. That is the "a distant function already
; checked this" pattern this tree's own comments warn about, one refactor away
; from being an out-of-bounds read on peer-supplied bytes.
;
; SO_NEED n -- require n more bytes at r14 within [r12, r12+r13), else bail.
;   Checks the ADDITION for carry too, so a varint claiming a huge length
;   cannot wrap the cursor past the end and land back inside the buffer.
;   Clobbers rax and rbx (both dead in this function; rbx is saved on entry).
; ============================================================================
%macro SO_NEED 1
    mov   rbx, r14
    add   rbx, %1
    jc    .oob                 ; cursor + n overflowed: malformed by construction
    lea   rax, [r12+r13]       ; end
    cmp   rbx, rax
    ja    .oob
%endmacro

; SO_VARINT dst -- read a CompactSize at r14 into [dst], advancing r14, with
;   every read bounded. Mirrors the four arms the hand-written code had.
%macro SO_VARINT 1
    SO_NEED 1
    movzx eax, byte [r14]
    cmp   eax, 0xfd
    jb    %%v1
    cmp   eax, 0xfd
    je    %%v2
    cmp   eax, 0xfe
    je    %%v4
    SO_NEED 9
    mov   rax, [r14+1]
    mov   %1, rax
    add   r14, 9
    jmp   %%vdone
%%v4:
    SO_NEED 5
    mov   eax, [r14+1]
    mov   %1, rax
    add   r14, 5
    jmp   %%vdone
%%v2:
    SO_NEED 3
    movzx rax, word [r14+1]
    mov   %1, rax
    add   r14, 3
    jmp   %%vdone
%%v1:
    movzx rax, byte [r14]
    mov   %1, rax
    inc   r14
%%vdone:
%endmacro

; ============================================================================
; tx_legacy_sigops(tx rdi, txlen rsi) -> rax
; ============================================================================
global tx_legacy_sigops
tx_legacy_sigops:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x40
    ; locals (all below saved r15@-0x28, within -0x28..-0x68):
    ;   [rbp-0x30] = total
    ;   [rbp-0x38] = n_in
    ;   [rbp-0x40] = n_out
    ;   [rbp-0x48] = script len (scratch)
    ;   [rbp-0x50] = cursor (scratch)
    ;   [rbp-0x58] = safe call arg (prevout skip)
    xor   eax, eax
    mov   [rbp-0x30], rax     ; total = 0
    mov   r12, rdi            ; base
    mov   r13, rsi            ; len
    lea   r14, [r12+4]        ; cursor after version
    ; ---- skip SegWit marker+flag (0x00 0x01 after version) ----
    ; A segwit tx serializes: version, 0x00, 0x01, n_in, ...  The marker 0x00
    ; would otherwise be misread as n_in=0. Detect: [r14]==0x00 && [r14+1]==0x01.
    SO_NEED 2
    movzx eax, byte [r14]
    test  eax, eax
    jnz   .have_flags
    cmp   byte [r14+1], 1
    jne   .have_flags
    add   r14, 2              ; skip marker 0x00 + flag 0x01
.have_flags:
    ; ---- n_in varint ----
    SO_VARINT [rbp-0x38]
.havein:
    ; ---- walk inputs ----
.in_loop:
    mov   rax, [rbp-0x38]
    test  rax, rax
    jz    .in_done
    SO_NEED 36
    lea   r14, [r14+36]              ; skip prevout (36)
    SO_VARINT [rbp-0x48]
    ; the scriptSig bytes themselves must be inside the buffer before
    ; script_sigops is handed a pointer and a length
    SO_NEED [rbp-0x48]
    ; count scriptSig (inaccurate): rdi=r14 (script), rsi=slen
    mov   rdi, r14
    mov   rsi, [rbp-0x48]
    xor   edx, edx
    call  script_sigops
    add   [rbp-0x30], rax
    ; advance past scriptSig + seq(4), decrement n_in
    mov   rax, [rbp-0x48]
    add   r14, rax
    SO_NEED 4                        ; sequence
    add   r14, 4
    mov   rax, [rbp-0x38]
    dec   rax
    mov   [rbp-0x38], rax
    jmp   .in_loop
.in_done:
    ; ---- n_out varint ----
    SO_VARINT [rbp-0x40]
.haveout:
.out_loop:
    mov   rax, [rbp-0x40]
    test  rax, rax
    jz    .done
    SO_NEED 8
    lea   r14, [r14+8]               ; skip value
    SO_VARINT [rbp-0x48]
    SO_NEED [rbp-0x48]
    mov   rdi, r14
    mov   rsi, [rbp-0x48]
    xor   edx, edx
    call  script_sigops
    add   [rbp-0x30], rax
    mov   rax, [rbp-0x48]
    add   r14, rax
    mov   rax, [rbp-0x40]
    dec   rax
    mov   [rbp-0x40], rax
    jmp   .out_loop
.oob:
    ; SCR-10: malformed / truncated. -1 rather than 0, because 0 is a
    ; LEGITIMATE count and both callers add the result to a cost compared
    ; against a limit -- returning 0 here would say "no sigops" and pass the
    ; check, which is fail-open on exactly the input that earned the refusal.
    mov   qword [rbp-0x30], -1
.done:
    mov   rax, [rbp-0x30]
    add   rsp, 0x40
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
