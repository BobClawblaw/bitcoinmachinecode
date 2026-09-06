; ============================================================================
; bech32.asm -- bech32 (BIP173) and bech32m (BIP350) address codec.
;
; Implements the full BIP173/BIP350 checksum algorithm in pure x86-64:
;   polymod = 30-bit LFSR CRC (BIP173 reference) over the HRP-expanded values
;   followed by the 5-bit data values, XORed with 1 (bech32) or 0x2bc830a3
;   (bech32m). The 5-bit data values come from 8-bit bytes via convert_bits.
;
; PUBLIC ABI (System V AMD64)
;   void bech32_init(void)
;       Builds the charset lookup tables. Call once at startup.
;
;   void bech32_create_checksum(u8 out6[6], const char *hrp, i64 hrplen,
;                               const u8 *data5, i64 datalen, i64 spec)
;       data5 = 5-bit values (0..31) WITHOUT the checksum.
;       spec  = 0 -> bech32, 1 -> bech32m.
;       Writes the 6 trailing 5-bit checksum values into out6.
;
;   i64 bech32_verify_checksum(const char *hrp, i64 hrplen,
;                              const u8 *data5, i64 datalen, i64 spec)
;       data5 = 5-bit values INCLUDING the 6 trailing checksum values.
;       spec  = 0 -> bech32, 1 -> bech32m.
;       Returns 1 if the checksum validates for that spec, else 0.
;
;   i64 bech32_convert_bits(u8 *out, const u8 *in, i64 inlen,
;                           i64 frombits, i64 tobits, i64 pad)
;       BIP173 convertbits. Returns output count, or -1 if pad==0 and
;       non-zero padding bits remain.
;
;   i64 bech32_encode(char *out, const char *hrp, i64 hrplen,
;                     const u8 *data5, i64 datalen, i64 spec)
;       Writes "hrp" + '1' + data chars + checksum chars + NUL.
;       Returns the string length (excluding NUL).
;
;   i64 bech32_decode(u8 *out5, char *out_hrp, i64 hrp_cap, const char *in)
;       Parses a full string. out5 receives the 5-bit data values INCLUDING
;       the 6 checksum values (caller verifies separately). out_hrp receives
;       the human readable part. Returns data count or -1 on syntax error.
; ============================================================================

BITS 64
DEFAULT REL

section .rodata
align 16
CHARSET:
    db "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

; BIP173 generator constants (30-bit).
BECH32_GEN:
    dd 0x3b6a57b2
    dd 0x26508e6d
    dd 0x1ea119fa
    dd 0x3d4233dd
    dd 0x2a1462b3

section .bss
align 16
CHAR2IDX:
    resb 256
IDX2CHAR:
    resb 32
; scratch workspace (module is used single-threaded by the tests)
WS:
    resb 512

section .text
global bech32_init
global bech32_create_checksum
global bech32_verify_checksum
global bech32_convert_bits
global bech32_encode
global bech32_decode

; ============================================================================
; bech32_init
; ============================================================================
bech32_init:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    sub  rsp, 0x10

    lea  rdi, [CHAR2IDX]
    mov  ecx, 256
    mov  al, 0xFF
    rep  stosb

    lea  r12, [CHARSET]
    lea  rbx, [IDX2CHAR]
    xor  rcx, rcx
.fill_id:
    cmp  rcx, 32
    jae  .fill_char
    movzx eax, byte [r12 + rcx]
    mov  byte [rbx + rcx], al
    inc  rcx
    jmp  .fill_id
.fill_char:
    lea  rbx, [CHAR2IDX]
    xor  rcx, rcx
.fill_char2:
    cmp  rcx, 32
    jae  .fill_up
    movzx eax, byte [r12 + rcx]
    mov  byte [rbx + rax], cl
    inc  rcx
    jmp  .fill_char2
.fill_up:
    ; decoders accept both cases; map uppercase letters to the same value.
    xor  rcx, rcx
.fill_up2:
    cmp  rcx, 32
    jae  .done
    movzx eax, byte [r12 + rcx]
    cmp  al, 'a'
    jb   .upnext
    cmp  al, 'z'
    ja   .upnext
    sub  eax, 32
    mov  byte [rbx + rax], cl
.upnext:
    inc  rcx
    jmp  .fill_up2
.done:
    add  rsp, 0x10
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; bech32_polymod (internal) -- i64 polymod(const u8 *values, i64 count)
;   eax = 1
;   for each v (byte):
;       b   = eax >> 25
;       eax = ((eax & 0x1ffffff) << 5) ^ v
;       for i in 0..4: if (b>>i)&1: eax ^= GEN[i]
;   Clobbers: rax, rcx, rdx, r8-r11, r12.
; ============================================================================
bech32_polymod:
    push rbp
    mov  rbp, rsp
    push r12
    sub  rsp, 0x10

    mov  r12, rsi          ; count
    xor  r8,  r8           ; index
    mov  eax, 1            ; chk
.loop:
    cmp  r8,  r12
    jge  .done
    mov  ecx, eax
    shr  ecx, 25           ; b
    mov  edx, eax
    and  edx, 0x1ffffff
    shl  edx, 5
    movzx r9d, byte [rdi + r8]
    xor  edx, r9d
    mov  eax, edx
    xor  r10d, r10d        ; gen index
.genloop:
    cmp  r10d, 5
    jge  .gennext
    bt   ecx, r10d
    jnc  .genskip
    mov  r11d, dword [BECH32_GEN + r10*4]
    xor  eax, r11d
.genskip:
    inc  r10d
    jmp  .genloop
.gennext:
    inc  r8
    jmp  .loop
.done:
    add  rsp, 0x10
    pop  r12
    pop  rbp
    ret

; ============================================================================
; bech32_hrp_expand (internal) -- i64 expand(u8 *out, const char *hrp, i64 len)
;   out = [hrp[i]>>5 for i] + [0] + [hrp[i]&31 for i]; returns 2*len+1.
; ============================================================================
bech32_hrp_expand:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x10

    mov  r12, rdi          ; out
    mov  rbx, rsi          ; hrp
    mov  r13, rdx          ; len
    xor  rcx, rcx
.upper:
    cmp  rcx, r13
    jae  .sep
    movzx eax, byte [rbx + rcx]
    shr  eax, 5
    mov  byte [r12 + rcx], al
    inc  rcx
    jmp  .upper
.sep:
    mov  byte [r12 + r13], 0
    lea  rdx, [r12 + r13 + 1]
    xor  rcx, rcx
.lower:
    cmp  rcx, r13
    jae  .done
    movzx eax, byte [rbx + rcx]
    and  eax, 31
    mov  byte [rdx + rcx], al
    inc  rcx
    jmp  .lower
.done:
    lea  rax, [r13 + r13 + 1]
    add  rsp, 0x10
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; bech32_create_checksum
;   args: rdi=out6, rsi=hrp, rdx=hrplen, rcx=data5, r8=datalen, r9=spec
; ============================================================================
bech32_create_checksum:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18

    mov  rbx, rdi          ; out6
    mov  r12, rsi          ; hrp
    mov  r13, rdx          ; hrplen
    mov  r14, rcx          ; data5
    mov  r15, r8           ; datalen
    mov  [rbp-0x38], r9    ; spec (stack slot below the 5 saved regs)

    ; values = hrp_expand + data5 + [0;6]  at WS
    lea  rdi, [WS]
    mov  rsi, r12
    mov  rdx, r13
    call bech32_hrp_expand
    mov  r12, rax          ; expand_len

    lea  rdi, [WS + r12]
    mov  rsi, r14
    mov  rcx, r15
    rep  movsb

    lea  rdi, [WS + r12 + r15]
    xor  eax, eax
    mov  ecx, 6
    rep  stosb

    ; chk = polymod(values, expand_len + datalen + 6)
    lea  rdi, [WS]
    lea  rsi, [r12 + r15]
    add  rsi, 6
    call bech32_polymod

    ; chk ^= (spec ? BECH32M_CONST : 1)
    mov  ecx, 1
    cmp  qword [rbp-0x38], 0
    jz   .haveconst
    mov  ecx, 0x2bc830a3
.haveconst:
    xor  eax, ecx

    ; out6[i] = (chk >> (5*(5-i))) & 31
    xor  rcx, rcx          ; i
.outloop:
    cmp  rcx, 6
    jae  .done
    mov  r9d, 5
    sub  r9d, ecx
    imul r9d, r9d, 5       ; shift
    mov  r8d, eax
    push rcx
    mov  cl, r9b
    shr  r8d, cl
    pop  rcx
    and  r8d, 31
    mov  byte [rbx + rcx], r8b
    inc  rcx
    jmp  .outloop
.done:
    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; bech32_verify_checksum
;   args: rdi=hrp, rsi=hrplen, rdx=data5, rcx=datalen, r8=spec
; ============================================================================
bech32_verify_checksum:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18

    mov  rbx, rdi          ; hrp
    mov  r12, rsi          ; hrplen
    mov  r13, rdx          ; data5
    mov  r14, rcx          ; datalen
    mov  r15, r8           ; spec

    lea  rdi, [WS]
    mov  rsi, rbx
    mov  rdx, r12
    call bech32_hrp_expand
    mov  rbx, rax          ; expand_len

    lea  rdi, [WS + rbx]
    mov  rsi, r13
    mov  rcx, r14
    rep  movsb

    lea  rdi, [WS]
    lea  rsi, [rbx + r14]
    call bech32_polymod

    ; expected const = spec ? 0x2bc830a3 : 1
    mov  ecx, 1
    test r15, r15
    jz   .haveexpect
    mov  ecx, 0x2bc830a3
.haveexpect:
    cmp  eax, ecx
    sete al
    movzx eax, al
.done:
    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; bech32_convert_bits
;   args: rdi=out, rsi=in, rdx=inlen, rcx=frombits, r8=tobits, r9=pad
; ============================================================================
bech32_convert_bits:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x10

    mov  rbx, rdi          ; out
    mov  r12, rsi          ; in
    mov  r13, rdx          ; inlen
    mov  r14, rcx          ; frombits
    mov  r15, r8           ; tobits
    mov  [rbp-0x38], r9    ; pad (kept in a stack slot; no calls in this fn)

    ; max_acc = (1 << (frombits+tobits-1)) - 1  (keeps acc bounded)
    mov  ecx, r14d
    add  ecx, r15d
    dec  ecx
    mov  edx, 1
    mov  cl, cl
    shl  edx, cl
    dec  edx
    mov  r11d, edx         ; r11d = max_acc

    xor  eax, eax          ; acc
    xor  r8d, r8d          ; bits
    xor  r9d, r9d          ; ret count
    xor  r10d, r10d        ; input index
.inloop:
    cmp  r10, r13
    jge  .pad
    movzx edx, byte [r12 + r10]
    mov  cl, r14b
    shl  eax, cl           ; acc <<= frombits
    or   eax, edx          ; acc |= in[i]
    and  eax, r11d         ; acc &= max_acc
    add  r8d, r14d         ; bits += frombits
.bitloop:
    cmp  r8d, r15d
    jl   .inloop_cont
    mov  ecx, r8d
    sub  ecx, r15d         ; ecx = bits - tobits (shift count)
    mov  edx, eax
    shr  edx, cl           ; edx = acc >> shift
    xor  ecx, ecx
    bts  ecx, r15d         ; ecx = 1 << tobits
    dec  ecx               ; ecx = mask = (1<<tobits)-1
    and  edx, ecx
    mov  byte [rbx + r9], dl
    inc  r9d
    sub  r8d, r15d         ; bits -= tobits
    jmp  .bitloop
.inloop_cont:
    inc  r10
    jmp  .inloop
.pad:
    test r8d, r8d
    jz   .done
    mov  ecx, r15d
    sub  ecx, r8d          ; ecx = tobits - bits
    mov  edx, eax
    shl  edx, cl           ; edx = acc << (tobits-bits)
    xor  ecx, ecx
    bts  ecx, r15d         ; ecx = 1 << tobits
    dec  ecx               ; mask
    and  edx, ecx
    cmp  qword [rbp-0x38], 0
    jz   .nopad
    mov  byte [rbx + r9], dl
    inc  r9d
    jmp  .done
.nopad:
    test edx, edx
    jnz  .err
    jmp  .done
.err:
    mov  eax, -1
    jmp  .out
.done:
    mov  eax, r9d
.out:
    add  rsp, 0x10
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; bech32_encode
;   args: rdi=out, rsi=hrp, rdx=hrplen, rcx=data5, r8=datalen, r9=spec
; ============================================================================
bech32_encode:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18

    mov  rbx, rdi          ; out
    mov  r12, rsi          ; hrp
    mov  r13, rdx          ; hrplen
    mov  r14, rcx          ; data5
    mov  r15, r8           ; datalen
    mov  r10, r9           ; spec

    ; hrp + '1'
    lea  rdi, [rbx]
    mov  rsi, r12
    mov  rcx, r13
    rep  movsb
    mov  byte [rbx + r13], '1'

    ; compute checksum into WS
    lea  rdi, [WS]
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    mov  r8,  r15
    mov  r9,  r10
    call bech32_create_checksum

    ; data chars
    lea  r11, [IDX2CHAR]
    lea  r8,  [rbx + r13 + 1]
    xor  r9,  r9
.data_chars:
    cmp  r9, r15
    jae  .ck_chars
    movzx eax, byte [r14 + r9]
    mov  al, byte [r11 + rax]
    mov  byte [r8 + r9], al
    inc  r9
    jmp  .data_chars
.ck_chars:
    lea  rax, [r8 + r15]
    xor  r9, r9
.ck_loop:
    cmp  r9, 6
    jae  .finish
    movzx edx, byte [WS + r9]
    mov  dl, byte [r11 + rdx]
    mov  byte [rax + r9], dl
    inc  r9
    jmp  .ck_loop
.finish:
    ; length = hrplen + 1 + datalen + 6 ; NUL at out+length
    lea  rdx, [r13 + r15]
    add  rdx, 7
    mov  byte [rbx + rdx], 0
    mov  rax, rdx
    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; bech32_decode
;   args: rdi=out5, rsi=out_hrp, rdx=hrp_cap, rcx=in
;   Returns data5 count (incl checksum) or -1.
; ============================================================================
bech32_decode:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x20

    mov  rbx, rdi          ; out5
    mov  r12, rsi          ; out_hrp
    mov  r13, rdx          ; hrp_cap
    mov  r14, rcx          ; in

    ; find the LAST '1' (the separator). HRP chars precede it; all data chars
    ; after it are from the charset (never '1'), so the last '1' is the split.
    xor  r15, r15          ; running string length
    xor  r8,  r8           ; position of last '1' (0 = none yet)
    xor  r9,  r9           ; SER-5: case bitmap -- 1 = saw lower, 2 = saw upper
.sep_scan:
    ; BIP173: a bech32(/bech32m) string is at most 90 characters. Reject the
    ; over-length form HERE, before the data loop below: that loop converts
    ; every character after the separator into WS+300, whose data region runs
    ; WS+300..WS+389 (90 bytes max). The checksum path then uses WS+0 for
    ; hrp_expand (2*hrp_len+1 <= 35 at hrp_cap<=17) + data5 + 6 zeros --
    ; 35 + 90 + 6 fits WS (512) with room to spare. Without this cap a
    ; ~300-char address argument (any address-taking RPC, e.g. validateaddress
    ; via wallet_validate_address) overflowed WS into the following .bss --
    ; audit SER-1/WAL-1 (2026-09-03). The scan bounds the input read too.
    movzx eax, byte [r14 + r15]
    test al, al
    jz   .sep_scan_done
    cmp  r15, 90
    jae  .err             ; >= 90 with no NUL yet -> over-length
    ; ---- SER-5 / WAL-9 (audit 2026-09-03): reject MIXED case ----
    ; bech32_init maps upper-case letters to the same values as lower, so the
    ; decoder folded case and accepted a string BIP173 forbids: "the string
    ; must be either all lowercase or all uppercase". validateaddress on
    ; bc1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4 answered isvalid:true where
    ; Core's bech32::Decode answers false. All-upper and all-lower both stay
    ; valid, which BIP173 also requires -- only the mixture is refused.
    cmp  al, 'a'
    jb   .cs_upper
    cmp  al, 'z'
    ja   .cs_upper
    or   r9, 1
    jmp  .cs_done
.cs_upper:
    cmp  al, 'A'
    jb   .cs_done
    cmp  al, 'Z'
    ja   .cs_done
    or   r9, 2
.cs_done:
    cmp  al, '1'
    jne  .not_sep
    mov  r8, r15
.not_sep:
    inc  r15
    jmp  .sep_scan
.sep_scan_done:
    cmp  r9, 3             ; SER-5: both cases present -> not a bech32 string
    je   .err
    ; r8 = separator index. Must exist and be < total len.
    test r8, r8
    jz   .err             ; no separator, or separator at position 0 (empty HRP)
    mov  r15, r8          ; hrp_len = separator index (>= 1 non-empty)
    ; HRP must fit the caller buffer.
    cmp  r15, r13
    jae  .err
    ; NOTE: no separate hrp_cap bound is needed here. The total scan above
    ; caps the whole string at 90, and the data region is strictly shorter,
    ; so .data_conv writes at most 89 bytes into WS+300 (capacity 212). The
    ; HRP's own bound is the caller's hrp_cap (checked just above); the
    ; checksum helpers size their workspace from the caller's hrp argument,
    ; not from hrp_cap, so no decode-time cap is correct for hrp length.
    ; validate every HRP char is printable US-ASCII (0x21..0x7e)
    xor  rcx, rcx
.hrp_check:
    cmp  rcx, r15
    jae  .hrp_ok
    movzx eax, byte [r14 + rcx]
    cmp  al, 0x21
    jb   .err
    cmp  al, 0x7e
    ja   .err
    inc  rcx
    jmp  .hrp_check
.hrp_ok:
    mov  rdi, r12
    lea  rsi, [r14]
    mov  rcx, r15
    rep  movsb
    mov  byte [r12 + r15], 0

    mov  qword [rbp-0x38], rbx     ; stash out5
    lea  rdi, [WS + 300]
    lea  rsi, [r14 + r15 + 1]
    xor  r9, r9
.data_conv:
    movzx eax, byte [rsi + r9]
    test al, al
    jz   .data_done
    ; the total-length cap above makes this bound unreachable for any
    ; NUL-terminated input; kept as a hard belt so .data_conv can never
    ; write past its 212-byte WS region even if a caller hands a
    ; non-NUL-terminated buffer (it would read OOB, but never write OOB).
    cmp  r9, 90
    jae  .err
    movzx ecx, byte [CHAR2IDX + rax]
    cmp  cl, 0xFF
    je   .err
    mov  byte [rdi + r9], cl
    inc  r9
    jmp  .data_conv
.data_done:
    cmp  r9, 6
    jl   .err
    mov  rdi, [rbp-0x38]
    lea  rsi, [WS + 300]
    mov  rcx, r9
    rep  movsb
    mov  rax, r9
    jmp  .out
.err:
    mov  rax, -1
.out:
    add  rsp, 0x20
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
