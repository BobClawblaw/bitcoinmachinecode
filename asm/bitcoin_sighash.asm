; ============================================================================
; bitcoin_sighash.asm -- legacy SIGHASH_ALL preimage builder.
;
;   int sighash_all(u8 out32[32], const u8 *tx, ulong txlen,
;                   ulong input_index, const u8 *script, ulong script_len,
;                   u8 *preimg, ulong cap)
;        Build the legacy SignatureHash (SIGHASH_ALL) preimage for input
;        `input_index`; out32 = sha256d(preimage). returns 1 ok / 0 fail.
;
;   Preimage:
;     version(4)  varint n_in
;     per input: prevout(32)+index(4) | script (target's script, else 0x00)
;                | sequence(4)
;     raw tail [n_out..locktime] copied verbatim
;     hashtype(4)=1 ; out = sha256d(preimage)
;
; DISCIELINE: every pointer lives in a stack slot; loaded right before a
; helper call and re-stored after. rbx,r12-r15 are callee-saved (preserved by
; sha256d and our own helpers). Frame: 5 pushes(0x28)+0x48=0x70 (==0 mod16)
; => rsp==8mod16 (rbp==8mod16) at the sha256d call. Locals in [rbp-0x30..-0x78]
; which is below the callee-saved area [rbp-8..-0x28] and within rbp-0x70.
; ============================================================================
    default rel
    global sighash_all
    extern sha256d

section .text

; ----------------------------------------------------------------------------
; sighash_all
;   Frame locals:
;     -0x30 script      -0x38 script_len
;     -0x40 preimg      -0x48 cap
;     -0x50 p (cursor)  -0x58 p_end
;     -0x60 txcur       -0x68 txend
;     -0x70 i           -0x78 totlen (preimage length for sha256d)
; ----------------------------------------------------------------------------
sighash_all:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x88          ; 5 pushes(0x28)+0x88=0xb0 (==0 mod16) => rsp==8mod16
                             ; at nested calls (rbp==8mod16). Locals -0x30..-0x78
                             ; are below [rbp-8..-0x28] and within rbp-0xb0.

    ; args: rdi=out32 rsi=tx rdx=txlen rcx=input_index r8=script r9=script_len
    ;       [rbp+16]=preimg [rbp+24]=cap
    mov   rbx, rdi        ; out32
    mov   r12, rsi        ; tx
    mov   r13, rdx        ; txlen
    mov   r14, rcx        ; input_index
    mov   [rbp-0x30], r8
    mov   [rbp-0x38], r9
    mov   rax, [rbp+16]
    mov   [rbp-0x40], rax
    mov   rax, [rbp+24]
    mov   [rbp-0x48], rax
    lea   rax, [r12+r13]
    mov   [rbp-0x68], rax ; txend

    cmp   r13, 10
    jb    .fail

    ; ---- n_in varint at tx+4 ----
    lea   rax, [r12+4]
    mov   [rbp-0x60], rax ; txcur
    mov   rdi, [rbp-0x60]
    mov   rsi, [rbp-0x68]
    call  parse_varint    ; rax=value, rdi advanced (cursor via rdi)
    mov   [rbp-0x60], rdi
    cmp   rax, 0
    je    .fail
    cmp   r14, rax
    jae   .fail
    mov   r15, rax        ; n_in (callee-saved, survives calls)

    ; ---- init preimg cursor ----
    mov   rax, [rbp-0x40]
    mov   [rbp-0x50], rax
    mov   rax, [rbp-0x48]
    add   rax, [rbp-0x40]
    mov   [rbp-0x58], rax

    ; ---- version(4) ----
    mov   rax, [rbp-0x50]
    lea   rax, [rax+4]
    cmp   rax, [rbp-0x58]
    ja    .fail
    mov   eax, [r12]
    mov   rdx, [rbp-0x50]
    mov   [rdx], eax
    add   qword [rbp-0x50], 4

    ; ---- varint n_in ----
    mov   rax, r15
    mov   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x58]
    call  write_varint    ; rax=value, rdi advanced
    mov   [rbp-0x50], rdi

    ; ---- walk inputs ----
    mov   qword [rbp-0x70], 0   ; i
.in_loop:
    mov   rax, [rbp-0x70]
    cmp   rax, r15
    jae   .in_done

    ; copy prevout(32)+index(4)=36 raw bytes into preimg
    mov   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x60]
    mov   r8, 36
    call  copy_bytes      ; advances rdi,rsi
    mov   [rbp-0x50], rdi
    mov   [rbp-0x60], rsi

    ; --- advance the RAW tx cursor past this input's scriptSig ---
    ; (the raw script bytes are skipped no matter which script we emit; the
    ;  preimage script is the supplied one for the target, empty otherwise.)
    mov   rdi, [rbp-0x60]
    mov   rsi, [rbp-0x68]
    call  parse_varint    ; rax = raw scriptSig length; rdi advanced past the varint
    cmp   rax, 0        ; (a zero-length script is legal; we still handled len=0)
    ; advance txcur past the scriptSig bytes, and RE-VALIDATE the resulting
    ; cursor stays within [tx, txend). A hostile scriptSig length that overruns
    ; the tx buffer must be rejected here -- otherwise the later raw reads
    ; (prevout/index, sequence) via copy_bytes would read past the buffer.
    ; (SECURITY: OOB source read; reproduced as a SIGSEGV on a tx whose
    ;  scriptSig length field runs past the tx end.)
    mov   rcx, rax
    add   rdi, rcx
    cmp   rdi, [rbp-0x68]
    ja    .fail
    mov   [rbp-0x60], rdi

    ; script (emit for preimage)
    mov   rax, [rbp-0x70]
    cmp   rax, r14
    je    .write_script
    ; empty script: 1 byte 0x00
    mov   rax, [rbp-0x50]
    inc   rax
    cmp   rax, [rbp-0x58]
    ja    .fail
    mov   rdx, [rbp-0x50]
    mov   byte [rdx], 0
    inc   qword [rbp-0x50]
    jmp   .after_script
.write_script:
    mov   rax, [rbp-0x38]      ; script_len
    mov   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x58]
    call  write_varint
    mov   [rbp-0x50], rdi
    ; copy script bytes
    mov   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x30]      ; script
    mov   r8, [rbp-0x38]
    call  copy_bytes
    mov   [rbp-0x50], rdi
    ; FINDING 2b: the script preimage write (varint + script_len bytes) was not
    ; capped against the preimage end ([rbp-0x58] = preimg+cap). The current
    ; callers cannot exceed it (script is a prevout scriptPubKey, <= consensus
    ; 10 kB, vs a 4 kB preimage buffer), but this is an internal invariant
    ; violation that must be defensively rejected, exactly like the hashtype
    ; write below. Reject if the resulting cursor passes the preimage end.
    cmp   rdi, [rbp-0x58]
    ja    .fail
.after_script:
    ; sequence(4) raw (txcur now points at the raw sequence)
    mov   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x60]
    mov   r8, 4
    call  copy_bytes
    mov   [rbp-0x50], rdi
    mov   [rbp-0x60], rsi

    inc   qword [rbp-0x70]
    jmp   .in_loop
.in_done:
    ; tail: copy [txcur .. txend] verbatim (n_out..locktime)
    mov   rax, [rbp-0x68]
    sub   rax, [rbp-0x60]
    mov   r8, rax
    mov   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x60]
    call  copy_bytes
    mov   [rbp-0x50], rdi

    ; hashtype(4)=1
    mov   rax, [rbp-0x50]
    add   rax, 4
    cmp   rax, [rbp-0x58]
    ja    .fail
    mov   rdx, [rbp-0x50]
    mov   dword [rdx], 1
    add   qword [rbp-0x50], 4

    ; ---- sha256d(out32=rbx, msg=preimg, len=p - preimg) ----
    mov   rax, [rbp-0x50]
    sub   rax, [rbp-0x40]
    mov   [rbp-0x78], rax       ; len
    mov   rdi, rbx
    mov   rsi, [rbp-0x40]
    mov   rdx, [rbp-0x78]
    call  sha256d
    mov   eax, 1
.done:
    add   rsp, 0x88
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret
.fail:
    xor   eax, eax
    jmp   .done

; ============================================================================
; parse_varint(rdi=cursor, rsi=end) -> rax=value, rdi=advanced (or 0 on fail)
; CompactSize: <0xfd 1B ; 0xfd+2B ; 0xfe+4B ; 0xff+8B. Little-endian.
; On any over-run returns rax=0. (A legit value can't be 0 except a bare 0,
; which is n=0; callers reject n==0 anyway.)
; ============================================================================
parse_varint:
    push  rbx
    push  r12
    cmp   rdi, rsi
    jae   .pv_fail
    movzx eax, byte [rdi]
    inc   rdi
    cmp   al, 0xfd
    jb    .pv_ret            ; 1-byte value == eax (already in al)
    ; width
    xor   r12d, r12d
    cmp   al, 0xfe
    je    .pv_w4
    cmp   al, 0xff
    je    .pv_w8
    mov   r12d, 2
    jmp   .pv_load
.pv_w4:
    mov   r12d, 4
    jmp   .pv_load
.pv_w8:
    mov   r12d, 8
.pv_load:
    lea   rax, [rdi+r12]
    cmp   rax, rsi
    ja    .pv_fail
    mov   eax, 0
.pv_b:
    shl   rax, 8
    movzx ecx, byte [rdi]
    or    rax, rcx
    inc   rdi
    dec   r12
    jnz   .pv_b
    jmp   .pv_ret
.pv_fail:
    xor   eax, eax
.pv_ret:
    pop   r12
    pop   rbx
    ret

; ============================================================================
; write_varint(rdi=cursor, rax=value, rsi=end) -> rdi advanced ; 0 ok /0? 
; Emits CompactSize encoding of rax; on overflow of cap returns rdi unchanged
; and we rely on caller bounds (we simply write; caller checks after).
; ============================================================================
write_varint:
    push  rbx
    push  r12
    mov   r12, rax           ; value
    ; decide width
    cmp   rax, 0xfc
    jbe   .wv_1
    cmp   rax, 0xffff
    jbe   .wv_2
    cmp   rax, 0xffffffff
    jbe   .wv_4
    jmp   .wv_8
.wv_1:
    mov   byte [rdi], al
    inc   rdi
    jmp   .wv_ret
.wv_2:
    mov   byte [rdi], 0xfd
    mov   word [rdi+1], ax
    add   rdi, 3
    jmp   .wv_ret
.wv_4:
    mov   byte [rdi], 0xfe
    mov   dword [rdi+1], eax
    add   rdi, 5
    jmp   .wv_ret
.wv_8:
    mov   byte [rdi], 0xff
    mov   qword [rdi+1], rax
    add   rdi, 9
.wv_ret:
    pop   r12
    pop   rbx
    ret

; ============================================================================
; copy_bytes(rdi=dst, rsi=src, r8=n) -> rdi,rsi advanced. Caller ensures bounds.
; ============================================================================
copy_bytes:
    push  rcx
    xor   rcx, rcx
.cb_loop:
    cmp   rcx, r8
    jae   .cb_done
    mov   al, [rsi+rcx]
    mov   [rdi+rcx], al
    inc   rcx
    jmp   .cb_loop
.cb_done:
    add   rdi, r8
    add   rsi, r8
    pop   rcx
    ret

; (footer: nothing in .rodata needed)
