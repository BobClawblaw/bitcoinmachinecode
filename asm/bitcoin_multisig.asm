; ============================================================================
; bitcoin_multisig.asm -- P2SH / multisig (OP_CHECKMULTISIG) script evaluation.
;
;   int p2sh_hash(const u8 *script, ulong script_len, u8 out20[20])
;       Compute P2SH address hash = RIPEMD160(SHA256(script)).
;       Returns 1 on success, 0 if script is empty.
;
;   int multisig_verify(const u8 *scriptSig, ulong sigLen,
;                        const u8 *pubKey, ulong pubLen,
;                        const u8 *tx, ulong txLen, ulong inputIndex,
;                        u8 *work, ulong workCap,
;                        const u8 *prevOutScript, ulong prevOutScriptLen)
;       OP_CHECKMULTISIG evaluation for one signer.
;       Walk scriptSig pushes, find the target pubKey, and treat the
;       immediately-preceding push as that signer's DER signature; verify it
;       against the SIGHASH_ALL preimage (prevOutScript as the signing script).
;       scriptSig layout: [dummy] <len> <DERsig+hashtype> <len> <pubKey>.
;       Returns 1 if valid, 0 otherwise.
;
;   ABI: SysV AMD64. Callee-saved rbx, r12-r15 preserved. rsp stays 8mod16.
; ============================================================================
    default rel
    global p2sh_hash
    global multisig_verify
    extern sha256_full
    extern ripemd160
    extern der_parse_sig
    extern be_to_limbs
    extern sighash_all
    extern pubkey_parse
    extern ecdsa_verify

section .text

; ============================================================================
; p2sh_hash(script, script_len, out20[20])
;
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP. This function keeps script/script_len/
; out20 in r12/r13/r14 across two calls, but previously pushed only rbx and r12
; -- r13 and r14 were used as scratch and never saved at all, so the caller lost
; them outright (and lost r15 to the nested ripemd160). r13/r14 are now saved.
; They must go ABOVE rbp: pushed below it they would land at rbp-0x18/-0x20,
; directly underneath the 32-byte sha_buf at [rbp-0x30..rbp-0x11], which is the
; same aliasing bug this commit removes elsewhere.
; ALIGNMENT IS UNCHANGED at the two nested calls: two extra pushes is +0x10,
; a multiple of 16. Entry 8 -> 4 pushes -> 8 -> push rbp -> 0 -> sub 0x50 -> 0;
; previously 8 -> push rbp -> 0 -> 2 pushes -> 0 -> sub 0x50 -> 0.
; ============================================================================
p2sh_hash:
    push  rbx
    push  r12
    push  r13
    push  r14
    push  rbp
    mov   rbp, rsp
    sub   rsp, 0x50          ; sha_buf at [rbp-0x30], inside this reservation
    mov   r12, rdi           ; script
    mov   r13, rsi           ; script_len
    mov   r14, rdx           ; out20
    test  r13, r13
    jz    .fail
    ; sha_buf at [rbp-0x30] (32 bytes)
    lea   rdi, [rbp-0x30]
    mov   rsi, r12
    mov   rdx, r13
    call  sha256_full
    mov   rdi, r14
    lea   rsi, [rbp-0x30]
    mov   rdx, 32
    call  ripemd160
    mov   eax, 1
.done:
    add   rsp, 0x50
    pop   rbp
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    ret
.fail:
    xor   eax, eax
    jmp   .done

; ============================================================================
; multisig_verify(scriptSig, sigLen, pubKey, pubLen, tx, txLen, inputIndex,
;                  work, workCap, prevOutScript, prevOutScriptLen)
;   SysV args: rdi=scriptSig, rsi=sigLen, rdx=pubKey, rcx=pubLen
;                r8=tx, r9=txLen
;                [rbp+16]=inputIndex, [rbp+24]=work, [rbp+32]=workCap
;                [rbp+40]=prevOutScript, [rbp+48]=prevOutScriptLen
;   Frame: 6 pushes(0x30) + 0x200 = 0x230 (rsp 8mod16); locals down to -0x1c0
;   sit within the reserved 0x200 shadow so nested calls can't clobber them.
;   Locals (below callee-saved area):
;     sigLen:     -0x30
;     sigStart:   -0x38
;     tx:         -0x40
;     txLen:      -0x48
;     inputIndex: -0x50
;     work:       -0x58
;     workCap:    -0x60
;     prevOut:    -0x68
;     prevOutLen: -0x70
;     r_out:      -0x140 (32)
;     s_out:      -0x180 (32)
;     Qx:         -0x120 (32)
;     Qy:         -0x0e0 (32)
;     z_limbs:    -0x100 (32)
;     sighash_out:-0x1c0 (32)
;     hashtype:   -0x160
; ============================================================================
multisig_verify:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x200         ; 6 pushes(0x30)+0x200=0x230 (==8 mod16) rsp 8mod16
                             ; locals used down to [rbp-0x1c0] must fit below rsp
                             ; (they sit in the reserved shadow, not the red zone).

    ; Store arguments (SysV: 6 in regs rdi..r9, rest on stack [rbp+16..])
    mov   r12, rdi           ; scriptSig
    mov   r13, rsi           ; sigLen
    mov   r14, rdx           ; pubKey
    mov   r15, rcx           ; pubLen
    mov   [rbp-0x40], r8    ; tx
    mov   [rbp-0x48], r9    ; txLen
    mov   rax, [rbp+16]
    mov   [rbp-0x50], rax   ; inputIndex   (7th arg)
    mov   rax, [rbp+24]
    mov   [rbp-0x58], rax   ; work         (8th arg)
    mov   rax, [rbp+32]
    mov   [rbp-0x60], rax   ; workCap      (9th arg)
    mov   rax, [rbp+40]
    mov   [rbp-0x68], rax   ; prevOutScript (10th arg)
    mov   rax, [rbp+48]
    mov   [rbp-0x70], rax   ; prevOutScriptLen (11th arg)

    ; ---- Step 1: scan scriptSig for pubKey, capture preceding sigLen ----
    ; Each push is <len> <data>. We remember the immediately-preceding push
    ; (prevLen, prevData) so that when the current push equals the pubKey we
    ; can use the previous push as its signature.
    ;   r10 = prevLen (0 initially -> no prev)
    ;   r11 = prevData
    mov   rdi, r12        ; cursor
    lea   rsi, [r12+r13]  ; end
    xor   r10d, r10d
    xor   r11d, r11d
.scan_loop:
    cmp   rdi, rsi
    jae   .not_found
    ; Read push length
    movzx eax, byte [rdi]
    lea   r8, [rdi+1]
    cmp   r8, rsi
    ja    .not_found
    mov   r9, rax          ; pushLen (current)
    lea   rdi, [rdi+1]     ; current data start
    mov   [rbp-0x78], rdi  ; save data start (for .advance recompute)
    ; Check if this push equals pubKey
    cmp   r9, r15
    jne   .advance         ; length differs -> not the pubkey
    ; candidate: compare data with pub
    mov   r8, r14
    mov   rcx, r15
.cmp_loop:
    mov   al, [rdi]
    cmp   al, [r8]
    jne   .advance         ; content differs -> not the pubkey
    inc   rdi
    inc   r8
    dec   rcx
    jnz   .cmp_loop
    ; Found: current push == pubKey. Its signature is the PREVIOUS push.
    ; prevData/prevLen are the DER sig; store them.
    mov   [rbp-0x30], r10  ; sigLen = prevLen
    mov   [rbp-0x38], r11  ; sig start = prevData
    jmp   .sig_found
.advance:
    ; skip current push; make it the new previous
    mov   rdi, [rbp-0x78]  ; back to data start
    mov   r10d, r9d        ; prevLen = current len
    mov   r11, rdi         ; prevData = current data start
    add   rdi, r9          ; cursor = end of current push
    jmp   .scan_loop
.sig_found:
    ; ---- Step 2: sighash_all ----
    lea   rdi, [rbp-0x1c0]
    mov   rsi, [rbp-0x40]   ; tx
    mov   rdx, [rbp-0x48]   ; txLen
    mov   rcx, [rbp-0x50]   ; inputIndex
    mov   r8,  [rbp-0x68]   ; prevOutScript
    mov   r9,  [rbp-0x70]   ; prevOutScriptLen
    ; 7th/8th args (work, workCap) go to [rsp]/[rsp+8] for the callee.
    mov   r11, rsp
    mov   rax, [rbp-0x58]
    mov   [r11+0], rax     ; work
    mov   rax, [rbp-0x60]
    mov   [r11+8], rax     ; workCap
    call  sighash_all
    test  eax, eax
    jz    .fail

    ; ---- Step 3: der_parse_sig ----
    mov   rdi, [rbp-0x38]   ; sig start
    mov   rsi, [rbp-0x30]   ; sigLen
    test  rsi, rsi
    jz    .fail             ; empty sig
    dec   rsi               ; IR-2: hashtype popped first (read above), parser sees siglen-1 -- as Core
    lea   rdx, [rbp-0x140]  ; r_out
    lea   rcx, [rbp-0x180]  ; s_out
    lea   r8,  [rbp-0x160]  ; (parser's optional-hashtype slot, overwritten below)
    call  der_parse_sig
    test  eax, eax
    jz    .fail
    mov   rax, [rbp-0x38]
    add   rax, [rbp-0x30]
    movzx eax, byte [rax-1] ; hashtype = sig[sigLen-1], read by the caller as Core does
    mov   [rbp-0x160], eax
    mov   eax, [rbp-0x160]
    cmp   eax, 1
    jne   .fail

    ; ---- Step 4: z = be_to_limbs(sighash) ----
    lea   rdi, [rbp-0x100]
    lea   rsi, [rbp-0x1c0]
    mov   rdx, 32
    call  be_to_limbs

    ; ---- Step 5: pubkey_parse ----
    mov   rdi, r14          ; pubKey
    mov   rsi, r15          ; pubLen
    lea   rdx, [rbp-0x120] ; Qx
    lea   rcx, [rbp-0x0e0] ; Qy
    call  pubkey_parse
    test  eax, eax
    jz    .fail

    ; ---- Step 6: ecdsa_verify ----
    lea   rdi, [rbp-0x100]  ; z
    lea   rsi, [rbp-0x140]  ; r
    lea   rdx, [rbp-0x180]  ; s
    lea   rcx, [rbp-0x120]  ; Qx
    lea   r8,  [rbp-0x0e0]  ; Qy
    call  ecdsa_verify
    test  eax, eax
    jz    .fail
    mov   eax, 1
    jmp   .done
.not_found:
.fail:
    xor   eax, eax
.done:
    add   rsp, 0x200
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret

; SECURITY (audit 2026-08-29 finding 9): without this note the linker
; conservatively marks the whole program's stack EXECUTABLE (PT_GNU_STACK
; RWE). Nothing here needs a runnable stack; a single object missing the
; note is enough to turn it on for the entire binary, which is why every
; .asm file carries it.
section .note.GNU-stack noalloc noexec nowrite progbits
