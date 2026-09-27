;============================================================================
; safegcd_var.inc -- variable-time modular inverse by Bernstein-Yang
; "safegcd" (Fast constant-time gcd computation and modular inversion, 2019),
; as one macro instantiated per modulus:
;
;   SAFEGCD_INV_VAR name, M62, MINV62, M4
;     int name(r[4], a[4]) : r = a^-1 mod m
;     M62    : label of m as 5 signed 62-bit limbs (5 dq)
;     MINV62 : label of one dq, m^{-1} mod 2^62
;     M4     : label of m as 4 little-endian u64 limbs
;   m must be odd and in (2^255, 2^256), so one subtraction reduces any
;   256-bit input. Both users qualify: n (secp256k1_scalar.asm: sc_inv_var,
;   ecdsa_verify's s^{-1}) and p (secp256k1_fe.asm: fe_inv_var, the even-Y
;   test's Z^{-1} in schnorr_verify).
;
;   Written for sc_inv_var on 2026-09-27 (binary GCD 3.6 us -> 0.67 us) and
;   moved here unchanged when fe_inv_var needed the same algorithm mod p; the
;   only addition is the entry reduction (a >= m -> a - m), which the scalar
;   version documented as unsupported.
;
;   VARIABLE TIME: public inputs only. Secrets (signing nonces, private keys,
;   anything a wallet derives) go through the constant-time Fermat sc_inv /
;   fe_inv. Policy (secp256k1_point_ct.asm header): variable time "is FINE
;   and FAST for verification, where the scalar is public ... It is FATAL for
;   signing, where the scalar is the secret nonce k".
;
;   REPRESENTATION. f, g, d, e are 5 signed 62-bit limbs: value =
;   sum limb[k] * 2^(62k). Limbs 0..3 are in [0, 2^62) and limb 4 carries the
;   sign (the updates below always leave them that way). f and g shrink, so
;   they have a live length LEN (5 down to 1); a top limb that is 0 or -1 in
;   both is folded into the one below.
;
;   ONE OUTER ITERATION.
;   1. divsteps (on f0 = f mod 2^64, g0 = g mod 2^64, eta), 62 of them:
;        z = ctz(g0), capped at the steps left: g0 >>= z, u,v <<= z,
;        eta -= z. If eta < 0: eta = -eta, (f0,g0) = (g0,-f0),
;        (u,v,q,r) = (q,r,-u,-v). Then clear up to min(eta+1, steps left, 6)
;        low bits of g0 in one step: g0 += w*f0 with w = -g0/f0 mod 2^limit,
;        using f0*(f0*f0-2) == -f0^{-1} (mod 64) for odd f0; q += w*u,
;        r += w*v. Invariant: 2^62 * (f',g') = [u v; q r] (f,g).
;   2. d, e = [u v; q r] (d, e) / 2^62 mod m. The division is exact after
;        adding md*m (resp. me*m), md = -(u*d0+v*e0) * m^{-1} mod 2^62, with
;        m added up front for each negative input. Keeps d, e in (-2m, m).
;   3. f, g = [u v; q r] (f, g) / 2^62 (exact: the divsteps cleared 62 bits).
;   4. g == 0 -> done: f == +-1 and a^{-1} == d * f (mod m).
;   Start: f = m, g = a, d = 0, e = 1, eta = -1. At most 10 outer
;   iterations were seen over 1e6 random inputs mod n (the C prototype this
;   was transcribed from, validated against sc_inv before a line of asm).
;
;   Every accumulation is a signed 128-bit sum of products of a matrix entry
;   (|x| <= 2^62) and a limb (< 2^62 in magnitude), at most three plus a
;   carry, so it cannot overflow.
;
;   Returns eax=1 and writes r. Returns eax=0 and leaves r untouched if
;   a == 0 (mod m): no inverse.
;   ABI: rdi=out, rsi=a. Leaf. Preserves rbx, rbp, r12-r15.
;   Frame (rsp-relative, 5-limb blocks): F @0, G @40, D @80, E @120,
;                                        ETA @160, LEN @168, OUT @176.
;
;   NASM NOTE: never `%assign cl` (or any register name) in a file that
;   includes this. secp256k1_scalar.asm's sc_mul macros did, which shadowed
;   the cl register for every later line and turned each `shl reg, cl` here
;   into a shift by a constant (renamed to mcl, 2026-09-27).
;============================================================================
%ifndef SAFEGCD_VAR_INC
%define SAFEGCD_VAR_INC

%define SIV_F    0
%define SIV_G    40
%define SIV_D    80
%define SIV_E    120
%define SIV_ETA  160
%define SIV_LEN  168
%define SIV_OUT  176
%define SIV_FRAME 192           ; 5 pushes + ret = 48; 48 + 192 keeps rsp 16-aligned

; x &= 2^62 - 1
%macro MASK62 1
    shl  %1, 2
    shr  %1, 2
%endmacro
; (hi:lo) >>= 62, arithmetic
%macro SAR62 2
    shrd %1, %2, 62
    sar  %2, 62
%endmacro
; (hi:lo) += reg * [mem], signed 64x64 -> 128. Clobbers rax, rdx.
%macro SMACC 4
    mov  rax, %3
    imul qword %4
    add  %1, rax
    adc  %2, rdx
%endmacro

%macro SAFEGCD_INV_VAR 4
global %1
%1:
    ; a >= m -> a - m (m > 2^255, so once is enough); then a == 0 -> fail,
    ; before anything is written
    mov  r8,  [rsi+0]
    mov  r9,  [rsi+8]
    mov  r10, [rsi+16]
    mov  r11, [rsi+24]
    mov  rax, r8
    sub  rax, [%4+0]
    mov  rcx, r9
    sbb  rcx, [%4+8]
    mov  rdx, r10
    sbb  rdx, [%4+16]
    mov  rsi, r11
    sbb  rsi, [%4+24]
    jb   .reduced
    mov  r8,  rax
    mov  r9,  rcx
    mov  r10, rdx
    mov  r11, rsi
.reduced:
    mov  rax, r8
    or   rax, r9
    or   rax, r10
    or   rax, r11
    jz   .fail_early

    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, SIV_FRAME
    mov  [rsp+SIV_OUT], rdi

    ; f = m
    mov  rax, [%2+0]
    mov  [rsp+SIV_F+0], rax
    mov  rax, [%2+8]
    mov  [rsp+SIV_F+8], rax
    mov  rax, [%2+16]
    mov  [rsp+SIV_F+16], rax
    mov  rax, [%2+24]
    mov  [rsp+SIV_F+24], rax
    mov  rax, [%2+32]
    mov  [rsp+SIV_F+32], rax

    ; g = a (reduced, in r8..r11), 4x64 -> 5x62
    mov  rax, r8
    MASK62 rax
    mov  [rsp+SIV_G+0], rax
    mov  rax, r9
    shld rax, r8, 2             ; a1<<2 | a0>>62
    MASK62 rax
    mov  [rsp+SIV_G+8], rax
    mov  rax, r10
    shld rax, r9, 4             ; a2<<4 | a1>>60
    MASK62 rax
    mov  [rsp+SIV_G+16], rax
    mov  rax, r11
    shld rax, r10, 6            ; a3<<6 | a2>>58
    MASK62 rax
    mov  [rsp+SIV_G+24], rax
    mov  rax, r11
    shr  rax, 56
    mov  [rsp+SIV_G+32], rax

    ; d = 0, e = 1, eta = -1, len = 5
    xor  eax, eax
    mov  [rsp+SIV_D+0], rax
    mov  [rsp+SIV_D+8], rax
    mov  [rsp+SIV_D+16], rax
    mov  [rsp+SIV_D+24], rax
    mov  [rsp+SIV_D+32], rax
    mov  [rsp+SIV_E+8], rax
    mov  [rsp+SIV_E+16], rax
    mov  [rsp+SIV_E+24], rax
    mov  [rsp+SIV_E+32], rax
    mov  qword [rsp+SIV_E+0], 1
    mov  qword [rsp+SIV_ETA], -1
    mov  qword [rsp+SIV_LEN], 5

.outer:
    ; ---- 1. 62 divsteps on the low words. rdi=f0 rsi=g0 r12=eta r14=steps
    ;         left, (u,v,q,r) = (r8,r9,r10,r11).
    mov  rdi, [rsp+SIV_F]
    mov  rsi, [rsp+SIV_G]
    mov  r12, [rsp+SIV_ETA]
    mov  r8d, 1
    xor  r9d, r9d
    xor  r10d, r10d
    mov  r11d, 1
    mov  r14d, 62
.ds_loop:
    mov  rax, -1
    mov  ecx, r14d
    shl  rax, cl                ; bits >= steps-left set: caps the count
    or   rax, rsi
    bsf  rcx, rax               ; z (rax != 0)
    shr  rsi, cl
    shl  r8, cl
    shl  r9, cl
    sub  r12, rcx
    sub  r14, rcx
    jz   .ds_done
    test r12, r12
    jns  .ds_noswap
    neg  r12                    ; eta = -eta
    mov  rax, rdi               ; (f,g) = (g,-f)
    mov  rdi, rsi
    neg  rax
    mov  rsi, rax
    mov  rax, r8                ; (u,v,q,r) = (q,r,-u,-v)
    mov  r8, r10
    neg  rax
    mov  r10, rax
    mov  rax, r9
    mov  r9, r11
    neg  rax
    mov  r11, rax
.ds_noswap:
    lea  rcx, [r12+1]           ; limit = min(eta+1, steps left); eta >= 0 here
    cmp  rcx, r14
    cmova rcx, r14
    neg  rcx
    add  rcx, 64                ; cl = 64 - limit
    mov  rdx, -1
    shr  rdx, cl
    and  edx, 63                ; m = 2^min(limit,6) - 1
    mov  rax, rdi
    imul rax, rdi
    sub  rax, 2
    imul rax, rdi               ; f*(f*f-2) == -1/f mod 64
    imul rax, rsi
    and  rax, rdx               ; w
    mov  rcx, rdi
    imul rcx, rax
    add  rsi, rcx               ; g += w*f
    mov  rcx, r8
    imul rcx, rax
    add  r10, rcx               ; q += w*u
    mov  rcx, r9
    imul rcx, rax
    add  r11, rcx               ; r += w*v
    jmp  .ds_loop
.ds_done:
    mov  [rsp+SIV_ETA], r12

    ; ---- 2. (d,e) = [u v; q r](d,e) / 2^62 mod n.
    ;         md=r12 me=r13, cd=r15:r14, ce=rcx:rbx.
    mov  rax, [rsp+SIV_D+32]
    sar  rax, 63                ; sd
    mov  rdx, [rsp+SIV_E+32]
    sar  rdx, 63                ; se
    mov  r12, r8
    and  r12, rax
    mov  rsi, r9
    and  rsi, rdx
    add  r12, rsi               ; md = (u & sd) + (v & se)
    mov  r13, r10
    and  r13, rax
    mov  rsi, r11
    and  rsi, rdx
    add  r13, rsi               ; me = (q & sd) + (r & se)
    xor  r14d, r14d
    xor  r15d, r15d
    xor  ebx, ebx
    xor  ecx, ecx
    SMACC r14, r15, r8,  [rsp+SIV_D]
    SMACC r14, r15, r9,  [rsp+SIV_E]
    SMACC rbx, rcx, r10, [rsp+SIV_D]
    SMACC rbx, rcx, r11, [rsp+SIV_E]
    mov  rax, [%3]
    imul rax, r14
    add  rax, r12
    MASK62 rax
    sub  r12, rax               ; md -= (ninv*cd + md) mod 2^62
    mov  rax, [%3]
    imul rax, rbx
    add  rax, r13
    MASK62 rax
    sub  r13, rax               ; me -= (ninv*ce + me) mod 2^62
    SMACC r14, r15, r12, [%2+0]
    SMACC rbx, rcx, r13, [%2+0]
    SAR62 r14, r15              ; low 62 bits are zero by construction
    SAR62 rbx, rcx
%assign k 1
%rep 4
    SMACC r14, r15, r8,  [rsp+SIV_D+8*k]
    SMACC r14, r15, r9,  [rsp+SIV_E+8*k]
    SMACC r14, r15, r12, [%2+8*k]
    SMACC rbx, rcx, r10, [rsp+SIV_D+8*k]
    SMACC rbx, rcx, r11, [rsp+SIV_E+8*k]
    SMACC rbx, rcx, r13, [%2+8*k]
    mov  rax, r14
    MASK62 rax
    mov  [rsp+SIV_D+8*(k-1)], rax
    mov  rax, rbx
    MASK62 rax
    mov  [rsp+SIV_E+8*(k-1)], rax
    SAR62 r14, r15
    SAR62 rbx, rcx
%assign k k+1
%endrep
    mov  [rsp+SIV_D+32], r14
    mov  [rsp+SIV_E+32], rbx

    ; ---- 3. (f,g) = [u v; q r](f,g) / 2^62 over the live length.
    ;         cf=r15:r14, cg=rcx:rbx, rsi=k, rdi=len.
    xor  r14d, r14d
    xor  r15d, r15d
    xor  ebx, ebx
    xor  ecx, ecx
    SMACC r14, r15, r8,  [rsp+SIV_F]
    SMACC r14, r15, r9,  [rsp+SIV_G]
    SMACC rbx, rcx, r10, [rsp+SIV_F]
    SMACC rbx, rcx, r11, [rsp+SIV_G]
    SAR62 r14, r15
    SAR62 rbx, rcx
    mov  rdi, [rsp+SIV_LEN]
    mov  esi, 1
.fg_loop:
    cmp  rsi, rdi
    jae  .fg_end
    SMACC r14, r15, r8,  [rsp+SIV_F+rsi*8]
    SMACC r14, r15, r9,  [rsp+SIV_G+rsi*8]
    SMACC rbx, rcx, r10, [rsp+SIV_F+rsi*8]
    SMACC rbx, rcx, r11, [rsp+SIV_G+rsi*8]
    mov  rax, r14
    MASK62 rax
    mov  [rsp+SIV_F-8+rsi*8], rax
    mov  rax, rbx
    MASK62 rax
    mov  [rsp+SIV_G-8+rsi*8], rax
    SAR62 r14, r15
    SAR62 rbx, rcx
    inc  rsi
    jmp  .fg_loop
.fg_end:
    mov  [rsp+SIV_F-8+rdi*8], r14
    mov  [rsp+SIV_G-8+rdi*8], rbx

    ; ---- 4. g == 0 -> done; else fold a 0/-1 top limb pair and go again.
    mov  rax, [rsp+SIV_G]
    test rax, rax
    jnz  .shrink
    mov  esi, 1
.or_loop:
    cmp  rsi, rdi
    jae  .or_end
    or   rax, [rsp+SIV_G+rsi*8]
    inc  rsi
    jmp  .or_loop
.or_end:
    test rax, rax
    jz   .done
.shrink:
    cmp  rdi, 2
    jb   .outer
    mov  rax, [rsp+SIV_F-8+rdi*8]   ; fn
    mov  rdx, [rsp+SIV_G-8+rdi*8]   ; gn
    mov  rsi, rax
    sar  rsi, 63
    xor  rsi, rax
    mov  rcx, rdx
    sar  rcx, 63
    xor  rcx, rdx
    or   rsi, rcx
    jnz  .outer
    shl  rax, 62
    or   [rsp+SIV_F-16+rdi*8], rax
    shl  rdx, 62
    or   [rsp+SIV_G-16+rdi*8], rdx
    dec  rdi
    mov  [rsp+SIV_LEN], rdi
    jmp  .outer

.done:
    ; ---- result = d * sign(f), reduced into [0, n). d as 320-bit two's
    ;      complement in r12:r11:r10:r9:r8 (limbs 0..3 are in [0,2^62)).
    mov  rax, [rsp+SIV_D+8]
    mov  r8, rax
    shl  r8, 62
    or   r8, [rsp+SIV_D+0]          ; w0 = l0 | l1<<62
    shr  rax, 2
    mov  r9, [rsp+SIV_D+16]
    mov  rdx, r9
    shl  r9, 60
    or   r9, rax                    ; w1 = l1>>2 | l2<<60
    shr  rdx, 4
    mov  r10, [rsp+SIV_D+24]
    mov  rax, r10
    shl  r10, 58
    or   r10, rdx                   ; w2 = l2>>4 | l3<<58
    shr  rax, 6
    mov  r12, [rsp+SIV_D+32]
    mov  r11, r12
    shl  r11, 56
    or   r11, rax                   ; w3 = l3>>6 | l4<<56
    sar  r12, 8                     ; w4 = l4 >> 8, sign-extended
    mov  rax, [rsp+SIV_F-8+rdi*8]   ; f's top live limb carries its sign
    test rax, rax
    jns  .addn
    not  r8                         ; d = -d
    not  r9
    not  r10
    not  r11
    not  r12
    add  r8, 1
    adc  r9, 0
    adc  r10, 0
    adc  r11, 0
    adc  r12, 0
.addn:
    test r12, r12
    jns  .subn
    add  r8,  [%4+0]
    adc  r9,  [%4+8]
    adc  r10, [%4+16]
    adc  r11, [%4+24]
    adc  r12, 0
    jmp  .addn
.subn:
    mov  rax, r8                    ; t = x - n; keep it while t >= 0
    sub  rax, [%4+0]
    mov  rcx, r9
    sbb  rcx, [%4+8]
    mov  rdx, r10
    sbb  rdx, [%4+16]
    mov  rsi, r11
    sbb  rsi, [%4+24]
    mov  rdi, r12
    sbb  rdi, 0
    js   .store
    mov  r8, rax
    mov  r9, rcx
    mov  r10, rdx
    mov  r11, rsi
    mov  r12, rdi
    jmp  .subn
.store:
    mov  rax, [rsp+SIV_OUT]
    mov  [rax+0],  r8
    mov  [rax+8],  r9
    mov  [rax+16], r10
    mov  [rax+24], r11
    add  rsp, SIV_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.fail_early:
    xor  eax, eax
    ret
%endmacro

%endif
