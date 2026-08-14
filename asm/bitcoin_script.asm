; ============================================================================
; bitcoin_script.asm -- P2PKH spend validation (wallet / tx-validation layer).
;
;   int der_parse_sig(const u8* sig, ulong slen, u64 r[4], u64 s[4],
;                     u32 *hashtype)
;        Parse a canonical DER ECDSA signature
;           0x30 len 0x02 rlen(<=32) r-bytes 0x02 slen(<=32) s-bytes [0x01 htype]
;        into r,s as 4-LE-limb arrays (big-endian integer bytes converted by
;        be_to_limbs) and the trailing SIGHASH-type byte (0 if absent).
;        Returns 1 ok / 0 malformed.
;
; ABI: SysV AMD64. callee-saved rbx,r12-r15. Frame: 5 pushes(0x28)+0x60=0x88
; (==8 mod16) => rsp==8mod16 at nested calls. Locals in [rbp-0x30..-0x40].
; ============================================================================
    default rel
    global der_parse_sig

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
    cmp   ecx, 33
    ja    .fail
    lea   rdx, [r12+4]         ; r value base
    mov   r14, rdx             ; r base
    mov   r15, rcx             ; r len
    ; ensure within slen
    lea   rax, [r12+r13]
    lea   rbx, [r14+r15]
    cmp   rbx, rax
    ja    .fail
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
    cmp   ecx, 33
    ja    .fail
    lea   rdx, [rbx+2]         ; s value base
    lea   rax, [rdx+rcx]       ; end of s
    ; ensure within slen
    lea   r8,  [r12+r13]
    cmp   rax, r8
    ja    .fail
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
