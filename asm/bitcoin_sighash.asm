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
    global legacy_sighash
    global script_find_and_delete
    global script_op_len
    global script_push_encode
    extern sha256d

section .text

; TLS_ADDR dst, sym -- dst = this thread's address of `sym` (ELF x86-64
; Initial-Exec model: a GOT-style offset loaded from a fixed, link-time
; location, added to the thread pointer at %fs:0). Clobbers only `dst`.
; Mirrors bitcoin_interp.asm's identical macro (kept per-file since NASM
; macros aren't visible across separately-assembled files).
%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

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
    xor   eax, eax
    xor   ebx, ebx            ; shift amount (bits) -- little-endian accumulation.
                              ; BUG FIX (2026-08-19): this loop used to do
                              ; `shl rax,8; or rax,byte; inc rdi`, which walks
                              ; bytes low-address-first (correct for reading
                              ; the wire's little-endian byte order) but then
                              ; accumulates them MSB-first via the left-shift
                              ; -- a big-endian read of a little-endian field.
                              ; A value like 320 (wire bytes 0x40,0x01) came
                              ; back as (0x40<<8)|0x01=16385 instead of
                              ; (0x01<<8)|0x40=320. Found via the Stage D
                              ; archive replay: a real 320-input mainnet tx at
                              ; height 29663 had its own n_in corrupted this
                              ; way, desyncing legacy_sighash's whole input
                              ; walk and producing a wrong SignatureHash for a
                              ; genuinely valid signature. Only ever bites a
                              ; CompactSize field >= 253 (the point the wire
                              ; format needs more than one byte), which is why
                              ; Core's own 500-vector sighash.json fixture
                              ; never tripped it -- none of those vectors
                              ; happen to have that many inputs/outputs.
.pv_b:
    movzx edx, byte [rdi]
    mov   cl, bl
    shl   rdx, cl
    or    rax, rdx
    inc   rdi
    add   ebx, 8
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

; ============================================================================
; script_op_len(rdi=pos, rsi=end) -> rax = byte length of the ONE script unit
; (opcode + any immediate push data) starting at pos, or 0 if pos>=end or the
; unit is malformed / would overrun end.
;
; Mirrors Core's GetScriptOp (script.cpp): opcode < OP_PUSHDATA1(0x4c) is a
; direct-length push (unit = 1+opcode); OP_PUSHDATA1/2/4 (0x4c/0x4d/0x4e) read
; a 1/2/4-byte LE length; anything else is a bare 1-byte opcode.
; ============================================================================
script_op_len:
    cmp   rdi, rsi
    jae   .zero
    movzx eax, byte [rdi]
    cmp   al, 0x4c
    jb    .direct
    je    .pd1
    cmp   al, 0x4d
    je    .pd2
    cmp   al, 0x4e
    je    .pd4
    mov   rax, 1
    jmp   .checked
.direct:
    inc   rax                 ; rax already = opcode (0..0x4b) from movzx; unit=1+opcode
    jmp   .checked
.pd1:
    lea   rax, [rdi+2]
    cmp   rax, rsi
    ja    .zero
    movzx ecx, byte [rdi+1]
    lea   rax, [rcx+2]
    jmp   .checked
.pd2:
    lea   rax, [rdi+3]
    cmp   rax, rsi
    ja    .zero
    movzx ecx, word [rdi+1]
    lea   rax, [rcx+3]
    jmp   .checked
.pd4:
    lea   rax, [rdi+5]
    cmp   rax, rsi
    ja    .zero
    mov   ecx, dword [rdi+1]  ; zero-extends into rcx
    lea   rax, [rcx+5]
.checked:
    lea   rcx, [rdi+rax]
    cmp   rcx, rsi
    ja    .zero
    ret
.zero:
    xor   eax, eax
    ret

; ============================================================================
; script_find_and_delete(rdi=dst, rsi=dstcap, rdx=src, rcx=srclen,
;                        r8=needle, r9=needlelen) -> rax = outlen, or
;                        0xFFFFFFFFFFFFFFFF (sentinel) if dstcap is exceeded.
;
; Mirrors Core's FindAndDelete (script/interpreter.cpp): walk `src` one
; decoded op-unit at a time (script_op_len); at every unit boundary, first
; try to consume one-or-more CONSECUTIVE raw needlelen-byte matches (deleted,
; not copied), then decode+copy exactly one unit. A malformed trailing unit
; (script_op_len==0, pos<end) copies the raw remainder verbatim, matching
; Core's do-while termination on a failed GetOp. needlelen==0 is a no-op
; (never matches), matching Core's `if (b.empty()) return 0`.
;
; Used BOTH for real signature removal (needle = the sig as a script push,
; built by script_push_encode) and, internally by legacy_sighash, for
; OP_CODESEPARATOR stripping (needle = the single byte 0xab) -- Core's own
; SerializeScriptCode is exactly FindAndDelete with that needle.
; ============================================================================
script_find_and_delete:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x88

    ; args: rdi=dst rsi=dstcap rdx=src rcx=srclen r8=needle r9=needlelen
    mov   [rbp-0x30], rdi         ; dst
    mov   [rbp-0x38], rsi         ; dstcap
    mov   [rbp-0x40], r8          ; needle
    mov   [rbp-0x48], r9          ; needlelen
    lea   rax, [rdx+rcx]
    mov   [rbp-0x58], rax         ; end
    mov   [rbp-0x50], rdx         ; pc
    mov   rax, [rbp-0x30]
    mov   [rbp-0x60], rax         ; out
    add   rax, [rbp-0x38]
    mov   [rbp-0x68], rax         ; outend

.fad_loop:
.fad_match_check:
    mov   r8, [rbp-0x48]
    test  r8, r8
    jz    .fad_decode
    mov   rax, [rbp-0x58]
    sub   rax, [rbp-0x50]
    cmp   rax, r8
    jb    .fad_decode
    mov   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x40]
    xor   rcx, rcx
.fad_cmp:
    cmp   rcx, r8
    jae   .fad_matched
    mov   al, [rdi+rcx]
    cmp   al, [rsi+rcx]
    jne   .fad_decode
    inc   rcx
    jmp   .fad_cmp
.fad_matched:
    add   qword [rbp-0x50], r8    ; pc += needlelen (deleted)
    jmp   .fad_match_check
.fad_decode:
    mov   rax, [rbp-0x50]
    cmp   rax, [rbp-0x58]
    je    .fad_done
    mov   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x58]
    call  script_op_len
    test  rax, rax
    jnz   .fad_copy_unit
    ; malformed trailing bytes: copy the raw remainder verbatim
    mov   rax, [rbp-0x58]
    sub   rax, [rbp-0x50]
    mov   r8, rax
    mov   rax, [rbp-0x60]
    add   rax, r8
    cmp   rax, [rbp-0x68]
    ja    .fad_overflow
    mov   rdi, [rbp-0x60]
    mov   rsi, [rbp-0x50]
    call  copy_bytes
    mov   [rbp-0x60], rdi
    mov   [rbp-0x50], rsi
    jmp   .fad_done
.fad_copy_unit:
    mov   r8, rax
    mov   rax, [rbp-0x60]
    add   rax, r8
    cmp   rax, [rbp-0x68]
    ja    .fad_overflow
    mov   rdi, [rbp-0x60]
    mov   rsi, [rbp-0x50]
    call  copy_bytes
    mov   [rbp-0x60], rdi
    mov   [rbp-0x50], rsi
    jmp   .fad_loop
.fad_done:
    mov   rax, [rbp-0x60]
    sub   rax, [rbp-0x30]
    jmp   .fad_ret
.fad_overflow:
    mov   rax, -1
.fad_ret:
    add   rsp, 0x88
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret

; ============================================================================
; script_push_encode(rdi=dst, rsi=dstcap, rdx=data, rcx=datalen) -> rax=outlen
; or 0xFFFFFFFFFFFFFFFF if dstcap exceeded. Minimal CScript::operator<<(bytes)
; push encoding: len<0x4c -> 1-byte opcode=len; len<=0xff -> PUSHDATA1;
; len<=0xffff -> PUSHDATA2; else PUSHDATA4 (all LE lengths).
; ============================================================================
script_push_encode:
    cmp   rcx, 0x4c
    jae   .pe_pd1
    ; header = 1 byte (opcode == len)
    lea   rax, [rcx+1]
    cmp   rax, rsi
    ja    .pe_overflow
    mov   [rdi], cl
    lea   rax, [rdi+1]
    jmp   .pe_copy
.pe_pd1:
    cmp   rcx, 0xff
    ja    .pe_pd2
    lea   rax, [rcx+2]
    cmp   rax, rsi
    ja    .pe_overflow
    mov   byte [rdi], 0x4c
    mov   byte [rdi+1], cl
    lea   rax, [rdi+2]
    jmp   .pe_copy
.pe_pd2:
    cmp   rcx, 0xffff
    ja    .pe_pd4
    lea   rax, [rcx+3]
    cmp   rax, rsi
    ja    .pe_overflow
    mov   byte [rdi], 0x4d
    mov   word [rdi+1], cx
    lea   rax, [rdi+3]
    jmp   .pe_copy
.pe_pd4:
    lea   rax, [rcx+5]
    cmp   rax, rsi
    ja    .pe_overflow
    mov   byte [rdi], 0x4e
    mov   dword [rdi+1], ecx
    lea   rax, [rdi+5]
.pe_copy:
    ; copy rcx bytes from rdx to rax (header end), byte loop (rcx may be
    ; large-ish for scripts but never for signatures; simple loop is fine)
    push  r8
    xor   r8, r8
.pe_cploop:
    cmp   r8, rcx
    jae   .pe_cpdone
    mov   r9b, [rdx+r8]
    mov   [rax+r8], r9b
    inc   r8
    jmp   .pe_cploop
.pe_cpdone:
    add   rax, rcx
    sub   rax, rdi             ; outlen = (header_end + datalen) - dst
    pop   r8
    ret
.pe_overflow:
    mov   rax, -1
    ret

; ============================================================================
; legacy_locate_nout (internal) -- walk version+n_in+all-inputs of a raw tx
; to find nOut without writing anything. Used only for the SIGHASH_SINGLE
; out-of-range pre-check (Core evaluates that BEFORE building any preimage).
;   rdi=tx, rsi=txend -> rax=nOut, rdx=1 ok/0 fail (also rejects nIn>=n_in
;   for a passed-in nIn via rcx on entry)
; ============================================================================
legacy_locate_nout:
    push  rbx
    push  r12
    push  r13
    mov   rbx, rdi              ; tx
    mov   r12, rsi              ; txend
    mov   r13, rcx              ; nIn (to validate against n_in)
    lea   rax, [rbx+4]
    mov   rdi, rax
    mov   rsi, r12
    call  parse_varint
    test  rax, rax
    jz    .lln_fail
    cmp   r13, rax
    jae   .lln_fail
    mov   rcx, rax              ; n_in
    mov   rdx, rdi              ; cursor (post n_in-varint)
    xor   r8, r8                ; i
.lln_loop:
    cmp   r8, rcx
    jae   .lln_outvarint
    add   rdx, 36
    cmp   rdx, r12
    ja    .lln_fail
    mov   rdi, rdx
    mov   rsi, r12
    push  rcx
    push  r8
    call  parse_varint
    pop   r8
    pop   rcx
    mov   rdx, rdi              ; advanced past scriptSig varint
    add   rdx, rax              ; += scriptSig length
    cmp   rdx, r12
    ja    .lln_fail
    add   rdx, 4                ; sequence
    cmp   rdx, r12
    ja    .lln_fail
    inc   r8
    jmp   .lln_loop
.lln_outvarint:
    ; parse_varint's rax==0 return is ambiguous between "genuine value 0" and
    ; "malformed/truncated" -- ambiguity this call site cannot tolerate,
    ; since it drives the SIGHASH_SINGLE out-of-range branch. Pre-validate
    ; enough bytes exist for whatever encoding the prefix byte claims, so the
    ; call below is guaranteed to succeed and rax==0 can only mean value 0.
    cmp   rdx, r12
    jae   .lln_fail
    movzx eax, byte [rdx]
    cmp   al, 0xfd
    jb    .lln_ov_call
    cmp   al, 0xfe
    je    .lln_ov_w4
    cmp   al, 0xff
    je    .lln_ov_w8
    lea   rax, [rdx+3]           ; 0xfd: 1 prefix + 2 value bytes
    jmp   .lln_ov_check
.lln_ov_w4:
    lea   rax, [rdx+5]
    jmp   .lln_ov_check
.lln_ov_w8:
    lea   rax, [rdx+9]
.lln_ov_check:
    cmp   rax, r12
    ja    .lln_fail
.lln_ov_call:
    mov   rdi, rdx
    mov   rsi, r12
    call  parse_varint
    mov   rdx, 1
    pop   r13
    pop   r12
    pop   rbx
    ret
.lln_fail:
    xor   eax, eax
    xor   edx, edx
    pop   r13
    pop   r12
    pop   rbx
    ret

; ============================================================================
; legacy_sighash -- full legacy SignatureHash (Core: SignatureHash() for
; SigVersion::BASE). Generalizes sighash_all (SIGHASH_ALL only, unchanged,
; still used by its existing callers) to every legacy hashtype: ALL/NONE/
; SINGLE x ANYONECANPAY, including the SIGHASH_SINGLE-out-of-range
; uint256(1) quirk. Internally strips OP_CODESEPARATOR from scriptCode
; (Core's SerializeScriptCode) via script_find_and_delete(needle=0xab) --
; this is NOT the signature-removal FindAndDelete, which the CALLER must do
; first (see bitcoin_scriptverify.c's sv_checksig): scriptCode here is
; whatever the caller passes, used as-is modulo codeseparator stripping.
;
;   int legacy_sighash(u8 out32[32], const u8* tx, u64 txlen, u64 nIn,
;                      const u8* scriptCode, u64 scLen, int32_t hashtype,
;                      u8* preimg, u64 cap)
; Returns 1 ok / 0 fail (malformed tx, nIn out of range, or buffer too small
; -- never a silent wrong hash).
;
; Frame locals (rbp-relative, all below the callee-saved save area):
;   -0x30 out32     -0x38 tx        -0x40 txlen     -0x48 nIn
;   -0x50 scriptCode -0x58 scLen    -0x60 hashtype  -0x68 preimg   -0x70 cap
;   -0x78 fACP      -0x80 fSingle   -0x88 fNone     -0x90 txend
;   -0x98 n_in      -0xA0 n_out     -0xA8 pcur      -0xB0 pend
;   -0xB8 txcur     -0xC0 i         -0xC8 j
;   -0xD0 prevout_ptr -0xD8 seq_ptr -0xE0 val_ptr -0xE8 spk_ptr -0xF0 spk_len
;   -0xF8 scF_len
; ============================================================================
legacy_sighash:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x158

    mov   [rbp-0x30], rdi
    mov   [rbp-0x38], rsi
    mov   [rbp-0x40], rdx
    mov   [rbp-0x48], rcx
    mov   [rbp-0x50], r8
    mov   [rbp-0x58], r9
    mov   eax, dword [rbp+16]
    mov   [rbp-0x60], rax
    mov   rax, [rbp+24]
    mov   [rbp-0x68], rax
    mov   rax, [rbp+32]
    mov   [rbp-0x70], rax

    ; ---- hashtype flags ----
    mov   eax, dword [rbp-0x60]
    mov   ecx, eax
    and   ecx, 0x1f
    xor   edx, edx
    cmp   ecx, 3
    sete  dl
    mov   [rbp-0x80], rdx              ; fSingle
    xor   edx, edx
    cmp   ecx, 2
    sete  dl
    mov   [rbp-0x88], rdx              ; fNone
    mov   ecx, eax
    and   ecx, 0x80
    xor   edx, edx
    test  ecx, ecx
    setnz dl
    mov   [rbp-0x78], rdx              ; fACP

    ; ---- version/n_in ----
    mov   rax, [rbp-0x38]
    add   rax, [rbp-0x40]
    mov   [rbp-0x90], rax              ; txend
    cmp   qword [rbp-0x40], 10
    jb    .ls_fail

    mov   rax, [rbp-0x38]
    lea   rdi, [rax+4]
    mov   rsi, [rbp-0x90]
    call  parse_varint
    test  rax, rax
    jz    .ls_fail
    mov   [rbp-0x98], rax              ; n_in
    mov   rax, [rbp-0x48]
    cmp   rax, [rbp-0x98]
    jae   .ls_fail
    mov   [rbp-0xB8], rdi              ; txcur (post n_in-varint)

    ; ---- SIGHASH_SINGLE out-of-range pre-check ----
    cmp   qword [rbp-0x80], 0
    je    .ls_no_single_check
    mov   rdi, [rbp-0x38]
    mov   rsi, [rbp-0x90]
    mov   rcx, [rbp-0x48]
    call  legacy_locate_nout
    test  rdx, rdx
    jz    .ls_fail
    mov   rcx, [rbp-0x48]
    cmp   rcx, rax
    jb    .ls_no_single_check
    mov   rdi, [rbp-0x30]
    mov   byte [rdi], 1
    mov   rcx, 1
.ls_quirk_zero:
    cmp   rcx, 32
    jae   .ls_quirk_done
    mov   byte [rdi+rcx], 0
    inc   rcx
    jmp   .ls_quirk_zero
.ls_quirk_done:
    mov   eax, 1
    jmp   .ls_done
.ls_no_single_check:

    ; ---- codeseparator-strip scriptCode into the per-thread scratch buffer ----
    TLS_ADDR rdi, legacy_sighash_scfbuf
    mov   [rbp-0x100], rdi     ; also needed again below, past intervening calls
    mov   rsi, 20000
    mov   rdx, [rbp-0x50]
    mov   rcx, [rbp-0x58]
    lea   r8, [rel cs_needle]
    mov   r9, 1
    call  script_find_and_delete
    cmp   rax, -1
    je    .ls_fail
    mov   [rbp-0xF8], rax              ; scF_len

    ; ---- preimg cursor init ----
    mov   rax, [rbp-0x68]
    mov   [rbp-0xA8], rax              ; pcur
    add   rax, [rbp-0x70]
    mov   [rbp-0xB0], rax              ; pend

    ; ---- version(4) raw ----
    mov   rax, [rbp-0xA8]
    lea   rax, [rax+4]
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rax, [rbp-0x38]
    mov   eax, [rax]
    mov   rdx, [rbp-0xA8]
    mov   [rdx], eax
    add   qword [rbp-0xA8], 4

    ; ---- nInputs varint: fACP?1:n_in ----
    mov   rax, [rbp-0x98]
    cmp   qword [rbp-0x78], 0
    je    .ls_ninputs_have
    mov   rax, 1
.ls_ninputs_have:
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xB0]
    call  write_varint
    mov   [rbp-0xA8], rdi
    cmp   rdi, [rbp-0xB0]
    ja    .ls_fail

    ; ---- input loop: i=0..n_in-1, ALWAYS walk raw tx forward ----
    mov   qword [rbp-0xC0], 0
.ls_in_loop:
    mov   rax, [rbp-0xC0]
    cmp   rax, [rbp-0x98]
    jae   .ls_in_done

    mov   rax, [rbp-0xB8]
    mov   [rbp-0xD0], rax              ; prevout_ptr
    add   qword [rbp-0xB8], 36
    mov   rax, [rbp-0xB8]
    cmp   rax, [rbp-0x90]
    ja    .ls_fail

    mov   rdi, [rbp-0xB8]
    mov   rsi, [rbp-0x90]
    call  parse_varint
    mov   [rbp-0xB8], rdi
    mov   rcx, rax
    add   rdi, rcx
    cmp   rdi, [rbp-0x90]
    ja    .ls_fail
    mov   [rbp-0xB8], rdi

    mov   rax, [rbp-0xB8]
    mov   [rbp-0xD8], rax              ; seq_ptr
    add   qword [rbp-0xB8], 4
    mov   rax, [rbp-0xB8]
    cmp   rax, [rbp-0x90]
    ja    .ls_fail

    mov   rax, [rbp-0xC0]
    cmp   rax, [rbp-0x48]
    jne   .ls_in_other

    ; ---- the signed input: ALWAYS emitted ----
    mov   rax, [rbp-0xA8]
    add   rax, 36
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xD0]
    mov   r8, 36
    call  copy_bytes
    mov   [rbp-0xA8], rdi
    mov   rax, [rbp-0xF8]
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xB0]
    call  write_varint
    mov   [rbp-0xA8], rdi
    cmp   rdi, [rbp-0xB0]
    ja    .ls_fail
    mov   rax, [rbp-0xA8]
    add   rax, [rbp-0xF8]
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0x100]     ; this thread's legacy_sighash_scfbuf address,
                                ; computed once above
    mov   r8, [rbp-0xF8]
    call  copy_bytes
    mov   [rbp-0xA8], rdi
    mov   rax, [rbp-0xA8]
    add   rax, 4
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xD8]
    mov   r8, 4
    call  copy_bytes
    mov   [rbp-0xA8], rdi
    jmp   .ls_in_next

.ls_in_other:
    cmp   qword [rbp-0x78], 0
    jne   .ls_in_next              ; fACP: other inputs are not emitted at all

    mov   rax, [rbp-0xA8]
    add   rax, 36
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xD0]
    mov   r8, 36
    call  copy_bytes
    mov   [rbp-0xA8], rdi
    mov   rax, [rbp-0xA8]
    inc   rax
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rdx, [rbp-0xA8]
    mov   byte [rdx], 0
    inc   qword [rbp-0xA8]
    mov   rax, [rbp-0xA8]
    add   rax, 4
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rax, [rbp-0x80]
    or    rax, [rbp-0x88]
    test  rax, rax
    jz    .ls_in_other_realseq
    mov   rdx, [rbp-0xA8]
    mov   dword [rdx], 0
    add   qword [rbp-0xA8], 4
    jmp   .ls_in_next
.ls_in_other_realseq:
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xD8]
    mov   r8, 4
    call  copy_bytes
    mov   [rbp-0xA8], rdi

.ls_in_next:
    inc   qword [rbp-0xC0]
    jmp   .ls_in_loop
.ls_in_done:

    ; ---- n_out (raw side) ----
    mov   rdi, [rbp-0xB8]
    mov   rsi, [rbp-0x90]
    call  parse_varint
    mov   [rbp-0xB8], rdi
    mov   [rbp-0xA0], rax              ; n_out

    ; ---- nOutputs varint to emit ----
    cmp   qword [rbp-0x88], 0
    jne   .ls_nout_none
    cmp   qword [rbp-0x80], 0
    jne   .ls_nout_single
    mov   rax, [rbp-0xA0]
    jmp   .ls_nout_have
.ls_nout_none:
    xor   eax, eax
    jmp   .ls_nout_have
.ls_nout_single:
    mov   rax, [rbp-0x48]
    inc   rax
.ls_nout_have:
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xB0]
    call  write_varint
    mov   [rbp-0xA8], rdi
    cmp   rdi, [rbp-0xB0]
    ja    .ls_fail

    ; ---- output loop: j=0..n_out-1, ALWAYS walk raw side ----
    mov   qword [rbp-0xC8], 0
.ls_out_loop:
    mov   rax, [rbp-0xC8]
    cmp   rax, [rbp-0xA0]
    jae   .ls_out_done

    mov   rax, [rbp-0xB8]
    mov   [rbp-0xE0], rax              ; val_ptr
    add   qword [rbp-0xB8], 8
    mov   rax, [rbp-0xB8]
    cmp   rax, [rbp-0x90]
    ja    .ls_fail

    mov   rdi, [rbp-0xB8]
    mov   rsi, [rbp-0x90]
    call  parse_varint
    mov   [rbp-0xB8], rdi
    mov   [rbp-0xF0], rax              ; spk_len
    mov   rax, [rbp-0xB8]
    mov   [rbp-0xE8], rax              ; spk_ptr
    mov   rax, [rbp-0xB8]
    add   rax, [rbp-0xF0]
    cmp   rax, [rbp-0x90]
    ja    .ls_fail
    mov   [rbp-0xB8], rax

    cmp   qword [rbp-0x88], 0
    jne   .ls_out_next

    cmp   qword [rbp-0x80], 0
    je    .ls_out_real

    mov   rax, [rbp-0xC8]
    cmp   rax, [rbp-0x48]
    jae   .ls_out_maybe_real
    mov   rax, [rbp-0xA8]
    add   rax, 9
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rdx, [rbp-0xA8]
    mov   qword [rdx], -1
    mov   byte [rdx+8], 0
    add   qword [rbp-0xA8], 9
    jmp   .ls_out_next
.ls_out_maybe_real:
    mov   rax, [rbp-0xC8]
    cmp   rax, [rbp-0x48]
    jne   .ls_out_next

.ls_out_real:
    mov   rax, [rbp-0xA8]
    add   rax, 8
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xE0]
    mov   r8, 8
    call  copy_bytes
    mov   [rbp-0xA8], rdi
    mov   rax, [rbp-0xF0]
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xB0]
    call  write_varint
    mov   [rbp-0xA8], rdi
    cmp   rdi, [rbp-0xB0]
    ja    .ls_fail
    mov   rax, [rbp-0xA8]
    add   rax, [rbp-0xF0]
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xE8]
    mov   r8, [rbp-0xF0]
    call  copy_bytes
    mov   [rbp-0xA8], rdi

.ls_out_next:
    inc   qword [rbp-0xC8]
    jmp   .ls_out_loop
.ls_out_done:

    ; ---- locktime(4 raw) ----
    mov   rax, [rbp-0xB8]
    add   rax, 4
    cmp   rax, [rbp-0x90]
    ja    .ls_fail
    mov   rax, [rbp-0xA8]
    add   rax, 4
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   rdi, [rbp-0xA8]
    mov   rsi, [rbp-0xB8]
    mov   r8, 4
    call  copy_bytes
    mov   [rbp-0xA8], rdi

    ; ---- hashtype(4) raw LE, the full passed-in bit pattern ----
    mov   rax, [rbp-0xA8]
    add   rax, 4
    cmp   rax, [rbp-0xB0]
    ja    .ls_fail
    mov   eax, dword [rbp-0x60]
    mov   rdx, [rbp-0xA8]
    mov   [rdx], eax
    add   qword [rbp-0xA8], 4

    ; ---- sha256d(out32, preimg, pcur-preimg) ----
    mov   rax, [rbp-0xA8]
    sub   rax, [rbp-0x68]
    mov   rdi, [rbp-0x30]
    mov   rsi, [rbp-0x68]
    mov   rdx, rax
    call  sha256d
    mov   eax, 1
    jmp   .ls_done

.ls_fail:
    xor   eax, eax
.ls_done:
    add   rsp, 0x158
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret

section .rodata
cs_needle: db 0xab

; Thread-local (2026-08-19, parallel per-input verification): was a plain
; .bss global (one shared instance for the whole process), unsafe once
; legacy_sighash can be called concurrently from multiple worker threads --
; see bitcoin_interp.asm's matching header note for the full rationale.
section .tbss alloc noexec nowrite tls align=8
global legacy_sighash_scfbuf
legacy_sighash_scfbuf: resb 20000

section .text

; (footer: nothing else needed)

; SECURITY (audit 2026-08-29 finding 9): without this note the linker
; conservatively marks the whole program's stack EXECUTABLE (PT_GNU_STACK
; RWE). Nothing here needs a runnable stack; a single object missing the
; note is enough to turn it on for the entire binary, which is why every
; .asm file carries it.
section .note.GNU-stack noalloc noexec nowrite progbits
