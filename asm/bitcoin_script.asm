; ============================================================================
; bitcoin_script.asm -- P2PKH spend validation (wallet / tx-validation layer).
;
;   int der_parse_sig(const u8* sig, ulong slen, u64 r[4], u64 s[4],
;                     u32 *hashtype)
;        Parse a DER ECDSA signature, TOLERANT of non-minimal INTEGER
;        encoding (real pre-BIP66/DERSIG mainnet history has these):
;           0x30 len 0x02 rlen r-bytes 0x02 slen s-bytes [0x01 htype]
;        r-bytes/s-bytes may carry any number of redundant leading 0x00
;        padding bytes, stripped down to <=32 significant bytes before
;        conversion; a value that still doesn't fit in 32 bytes after
;        stripping is rejected (genuinely out of range for secp256k1).
;        Into r,s as 4-LE-limb arrays (big-endian integer bytes converted by
;        be_to_limbs) and the trailing SIGHASH-type byte (0 if absent).
;        Returns 1 ok / 0 malformed.
;
; ABI: SysV AMD64. callee-saved rbx,r12-r15. Frame: 5 pushes(0x28)+0x60=0x88
; (==8 mod16) => rsp==8mod16 at nested calls. Locals in [rbp-0x30..-0x40].
; ============================================================================
    default rel
    global der_parse_sig
    global verify_p2pkh
    global be_to_limbs
    extern sighash_all
    extern pubkey_parse
    extern ecdsa_verify

section .text

der_parse_sig:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x70          ; 5 pushes(0x28)+0x70=0x98 (==8 mod16) => rsp==8mod16.

    mov   r12, rdi        ; sig
    mov   r13, rsi        ; slen
    mov   [rbp-0x30], rdx ; r_out
    mov   [rbp-0x38], rcx ; s_out
    mov   [rbp-0x40], r8  ; hashtype*

    ; need at least: 0x30 len 0x02 rlen (+1 rbyte) 0x02 slen (+1 sbyte) = 8
    cmp   r13, 8
    jb    .fail
    cmp   byte [r12], 0x30
    jne   .fail
    ; len byte (r12+1): sequence length; must satisfy 2+seq_len <= slen
    ; (best-effort; we still rely on explicit 0x02 markers)
    ; ---- r: expect 0x02 rlen ----
    cmp   byte [r12+2], 0x02
    jne   .fail
    movzx ecx, byte [r12+3]    ; rlen
    test  ecx, ecx
    jz    .fail
    lea   rdx, [r12+4]         ; r value base
    mov   r14, rdx             ; r base
    mov   r15, rcx             ; r len
    ; ensure within slen
    lea   rax, [r12+r13]
    lea   rbx, [r14+r15]
    cmp   rbx, rax
    ja    .fail
    ; BUG FIX (2026-08-19): strip ANY number of redundant leading 0x00
    ; padding bytes down to <=32 significant bytes, not just exactly one
    ; (the old 33->32 special case). Non-minimal DER INTEGER encodings
    ; (multiple redundant leading zero bytes) were routinely produced/
    ; accepted by Bitcoin's original OpenSSL-based signature parser before
    ; BIP66/DERSIG activates (height 363725) -- a real mainnet spend at
    ; height 124275 has a 34-byte r AND s, each with a double leading zero,
    ; that the old single-byte-strip logic rejected outright as malformed.
    ; base+len stays invariant across the loop (inc/dec pair), so the later
    ; `lea rbx,[r14+r15]` (locating the s-marker) is unaffected by how much
    ; got stripped. A genuinely-nonzero byte short of 32 significant bytes
    ; means the value doesn't fit in 32 bytes -- correctly invalid either way.
.r_strip:
    cmp   r15, 32
    jbe   .r_norm
    cmp   byte [r14], 0x00
    jne   .fail
    inc   r14
    dec   r15
    jmp   .r_strip
.r_norm:
    ; convert r -> limbs
    mov   rdi, [rbp-0x30]
    mov   rsi, r14
    mov   rdx, r15
    call  be_to_limbs          ; (out=rdi, bytes=rsi, len=rdx); preserves rbx,r12-r15
    ; ---- s: 0x02 slen at [r14+r15] ----
    lea   rbx, [r14+r15]       ; s marker
    cmp   byte [rbx], 0x02
    jne   .fail
    movzx ecx, byte [rbx+1]    ; slen
    test  ecx, ecx
    jz    .fail
    lea   rdx, [rbx+2]         ; s value base
    lea   rax, [rdx+rcx]       ; end of s (ORIGINAL, unstripped -- the later
                               ; hashtype lookup needs this exact position)
    ; ensure within slen
    lea   r8,  [r12+r13]
    cmp   rax, r8
    ja    .fail
    ; BUG FIX (2026-08-19): see the matching r-value fix above -- strip ANY
    ; number of redundant leading 0x00 bytes down to <=32 significant bytes.
    ; Only rdx/rcx (s base/len) are touched; rax (end-of-s) stays untouched
    ; for the hashtype-byte lookup right after the be_to_limbs call below.
.s_strip:
    cmp   rcx, 32
    jbe   .s_norm
    cmp   byte [rdx], 0x00
    jne   .fail
    inc   rdx
    dec   rcx
    jmp   .s_strip
.s_norm:
    push  rcx
    push  rax
    mov   rdi, [rbp-0x38]
    mov   rsi, rdx
    mov   rdx, rcx
    call  be_to_limbs
    pop   rax                  ; end of s
    pop   rcx
    ; ---- hashtype: optional 0x01 byte right after s ----
    mov   r9d, 0
    ; rax = end-of-s ; sig end = r12+r13
    lea   r8, [r12+r13]
    cmp   rax, r8
    jae   .ht_done
    cmp   byte [rax], 1
    jne   .ht_done
    movzx r9d, byte [rax]
.ht_done:
    mov   rdx, [rbp-0x40]
    mov   [rdx], r9d
    mov   eax, 1
.done:
    add   rsp, 0x70
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
; be_to_limbs(out u64[4], bytes, len) -- big-endian integer bytes -> 4 LE limbs.
;   1..32 bytes. Zero-pads on the left to 32 bytes, then limb j = bswap of the
;   j-th 8-byte group (so out[0] holds the low 64 bits of the integer).
;   Clobbers rax,rcx,rdx,rsi,rdi,r8. Uses local [rbp-0x60..-0x40] (32 bytes).
;   Preserves rbx,r12-r15.
; ============================================================================
be_to_limbs:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x70          ; 5 pushes(0x28)+0x70=0x98(==8 mod16) => rsp 8mod16.
    mov   r12, rdi           ; out
    mov   r13, rsi           ; bytes
    ; zero 32-byte local at [rbp-0x80 .. -0x60]
    xor   eax, eax
    mov   [rbp-0x80], rax
    mov   [rbp-0x78], rax
    mov   [rbp-0x70], rax
    mov   [rbp-0x68], rax
    ; copy `len` bytes (big-endian b[0..len-1]) into [rbp-0x80 + (32-len) ..]
    mov   rcx, rdx           ; len
    lea   rdi, [rbp-0x80+32]
    sub   rdi, rcx           ; destination start (right-justified)
    mov   rsi, r13
    rep movsb
    ; limb j = bswap(tmp[8*(3-j) .. 8*(3-j)+7])  ; tmp[0] is MSB
    xor   ecx, ecx           ; j
.bl_loop:
    cmp   ecx, 4
    jae   .bl_done
    mov   eax, 3
    sub   eax, ecx
    shl   eax, 3
    movsxd rdx, eax
    lea   rsi, [rbp-0x80+rdx]
    mov   rax, [rsi]
    bswap rax
    mov   [r12+rcx*8], rax
    inc   ecx
    jmp   .bl_loop
.bl_done:
    add   rsp, 0x70
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret

; ============================================================================
; parse_varint(rdi=cursor, rsi=end) -> rax=value, rdi=advanced past varint.
; CompactSize: <0xfd 1B; 0xfd+2B; 0xfe+4B; 0xff+8B (little-endian).
; Returns rax=0 on over-run (callers treat 0 as an error where n must be >0).
; Clobbers rcx,rdx. Preserves rbx,r12-r15.
; ============================================================================
parse_varint:
    push  r12
    push  r13
    cmp   rdi, rsi
    jae   .pv_fail
    movzx eax, byte [rdi]
    inc   rdi
    cmp   al, 0xfd
    jb    .pv_ret
    xor   r12d, r12d
    cmp   al, 0xfe
    je    .pv_w4
    cmp   al, 0xff
    je    .pv_w8
    mov   r12d, 2
    jmp   .pv_read
.pv_w4:
    mov   r12d, 4
    jmp   .pv_read
.pv_w8:
    mov   r12d, 8
.pv_read:
    lea   rax, [rdi+r12]
    cmp   rax, rsi
    ja    .pv_fail
    xor   eax, eax
    xor   r13d, r13d          ; shift amount (bits) -- little-endian accumulation.
                              ; BUG FIX (2026-08-19): see bitcoin_sighash.asm's
                              ; own parse_varint fix -- this was an independent
                              ; duplicate of the same big-endian-read-of-a-
                              ; little-endian-field bug (`shl rax,8` accumulation
                              ; over low-address-first bytes).
.pv_b:
    movzx edx, byte [rdi]
    mov   cl, r13b
    shl   rdx, cl
    or    rax, rdx
    inc   rdi
    add   r13d, 8
    dec   r12
    jnz   .pv_b
    jmp   .pv_ret
.pv_fail:
    xor   eax, eax
.pv_ret:
    pop   r13
    pop   r12
    ret

; ============================================================================
; verify_p2pkh(tx, txlen, input_index, prevout_script, prevout_len, work, cap)
;   Evaluate a P2PKH input spend. scriptSig = <sig_der+hashtype> <pubkey>.
;   Returns 1 if the signature verifies, 0 otherwise.
;   Steps:
;     1. sighash_all(out32, ...) with prevout_script as the signing script.
;     2. walk the raw tx to input_index, locate its scriptSig, parse two
;        pushes: sig and pubkey.
;     3. der_parse_sig(sig) -> r,s,htype  (require htype==1).
;     4. sighash(32 BE) -> z limbs (be_to_limbs/bswap).
;     5. pubkey_parse(pubkey) -> Qx,Qy.
;     6. ecdsa_verify(z,r,s,Qx,Qy).
; Frame: 5 pushes(0x28)+0x78=0xa0(==0 mod16) => rsp==8mod16 (rbp==0). Locals
;   below [rbp-0x28], within [rbp-0x90].
; Register/slot map:
;   -0x30 tx      -0x38 txlen  -0x40 idx   -0x48 pvscript -0x50 pvlen
;   -0x58 work    -0x60 cap     -0x68 out32[4] (32B)     -0x98 sighash
;   -0xb0 workcursor
; ============================================================================
verify_p2pkh:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x200          ; (0x28+0x200=0x228, ==8 mod16) => rsp==8mod16.
                             ; Covers locals down to [rbp-0x1f0].

    ; ---- args: tx, txlen, idx, pv, pvlen, work, cap(=[rbp+16]) ----
    mov   [rbp-0x30], rdi
    mov   [rbp-0x38], rsi
    mov   [rbp-0x40], rdx
    mov   [rbp-0x48], rcx
    mov   [rbp-0x50], r8
    mov   [rbp-0x58], r9
    mov   rax, [rbp+16]
    mov   [rbp-0x60], rax

    ; ---- step 1: sighash_all(out@-0x1f0(32), tx, txlen, idx, pv, pvlen, work, cap)
    lea   rdi, [rbp-0x1f0]
    mov   rsi, [rbp-0x30]
    mov   rdx, [rbp-0x38]
    mov   rcx, [rbp-0x40]
    mov   r8,  [rbp-0x48]
    mov   r9,  [rbp-0x50]
    ; stack args 7,8: [rsp+0]=work, [rsp+8]=cap  (I am the caller; write above rsp)
    ; use r11 (caller-saved) as the stack-pointer snapshot -- NEVER clobber rbx
    mov   r11, rsp
    mov   rax, [rbp-0x58]
    mov   [r11+0], rax
    mov   rax, [rbp-0x60]
    mov   [r11+8], rax
    call  sighash_all
    test  eax, eax
    jz    .fail

    ; ---- step 2: locate input_index's scriptSig in raw tx ----
    mov   r12, [rbp-0x30]    ; tx
    mov   r13, [rbp-0x38]    ; txlen
    lea   r14, [r12+r13]     ; end
    lea   rdi, [r12+4]
    mov   rsi, r14
    call  parse_varint       ; n_in
    cmp   rax, 0
    je    .fail
    cmp   [rbp-0x40], rax
    jae   .fail
    ; rdi = cursor at first input's prevout
    xor   ecx, ecx
.walk:
    mov   r11, [rbp-0x40]
    cmp   rcx, r11
    jae   .found
    add   rdi, 36            ; prevout+index
    mov   rsi, r14
    call  parse_varint       ; scriptSig len (rdi advanced past varint)
    add   rdi, rax           ; skip scriptSig bytes
    add   rdi, 4             ; sequence
    inc   rcx
    jmp   .walk
.found:
    ; rdi = cursor at target input's prevout
    add   rdi, 36            ; -> scriptSig varint
    mov   rsi, r14
    call  parse_varint       ; scriptSig len, rdi at script bytes
    mov   [rbp-0x78], rdi    ; script bytes start
    mov   [rbp-0x80], rax    ; scriptSig len
    ; parse push0 (sig): <len> sig
    movzx ecx, byte [rdi]
    mov   [rbp-0x88], rcx     ; sig len
    lea   rax, [rdi+1]
    mov   [rbp-0x90], rax     ; sig bytes
    add   rdi, rcx
    add   rdi, 1
    ; push1 (pubkey): <len> pubkey ; we only need pub key bytes+len
    movzx ecx, byte [rdi]
    mov   [rbp-0x98], rcx     ; pub len
    lea   rax, [rdi+1]
    mov   [rbp-0xa0], rax     ; pub bytes

    ; ---- step 3: der_parse_sig(sig, slen, &r@-0x1c0, &s@-0x180, &htype@-0x68)
    mov   rdi, [rbp-0x90]
    mov   rsi, [rbp-0x88]
    lea   rdx, [rbp-0x1c0]
    lea   rcx, [rbp-0x180]
    lea   r8,  [rbp-0x68]
    call  der_parse_sig
    test  eax, eax
    jz    .fail
    mov   eax, [rbp-0x68]
    cmp   eax, 1
    jne   .fail

    ; ---- step 4: z = be_to_limbs(sighash bytes @-0x1f0) ----
    lea   rdi, [rbp-0x140]
    lea   rsi, [rbp-0x1f0]
    mov   rdx, 32
    call  be_to_limbs

    ; ---- step 5: pubkey_parse(pub, publen, &Qx@-0x100, &Qy@-0xc0) ----
    mov   rdi, [rbp-0xa0]
    mov   rsi, [rbp-0x98]
    lea   rdx, [rbp-0x100]
    lea   rcx, [rbp-0xc0]
    call  pubkey_parse
    test  eax, eax
    jz    .fail

    ; ---- step 6: ecdsa_verify(z@-0x140, r@-0x1c0, s@-0x180, Qx@-0x100, Qy@-0xc0)
    lea   rdi, [rbp-0x140]
    lea   rsi, [rbp-0x1c0]
    lea   rdx, [rbp-0x180]
    lea   rcx, [rbp-0x100]
    lea   r8,  [rbp-0xc0]
    call  ecdsa_verify
    test  eax, eax
    jz    .fail
    mov   eax, 1
    jmp   .done
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

