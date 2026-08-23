; ============================================================================
; secp256k1_schnorr.asm -- BIP340 Schnorr signature verification (verify-only)
;   for the secp256k1 curve, hand-written x86-64 assembly (100% AI-authored,
;   validated against the official BIP340 test-vectors.csv).
;
;   int schnorr_verify(const u8 sig[64], const u8 pub_xonly[32], const u8 *msg, int msglen)
;     sig = r(32) || s(32) big-endian ; pub_xonly = x-coord (big-endian)
;     msg = message of msglen bytes (the taproot sighash for taproot spends)
;     returns 1 if valid BIP340 signature, else 0.
;
;   BIP340 Verify (section 5.2):
;     P = lift_x(int(pk)); fail if x^3+7 is not a QR.
;     r = int(sig[0:32]); fail if r >= p.
;     s = int(sig[32:64]); fail if s >= n.
;     e = int(tagged_hash("BIP0340/challenge", bytes(r)||bytes(P.x)||m)) mod n.
;     R = s*G - e*P.
;     fail if y(R) odd or x(R) != r.
;
;   PERF: the two scalar multiplies are the same pair ecdsa_verify uses --
;   point_scalar_mul_fixed for the constant-base s*G and point_scalar_mul_glv
;   (GLV endomorphism + width-5 wNAF) for the variable-base e*P. The x(R)==r
;   test is decided projectively (r*Z^2 == X mod p) so it costs no inversion
;   and rejects before the single remaining fe_inv, which exists only because
;   the even-Y test needs the real affine y. See PERF_SCOPE.md section 13.
;
;   Buffer table (offsets from rbp; each box is [off-N+1, off] inclusive):
;     s_limbs   -0x40  (32)   r_limbs    -0x70  (32)
;     e         -0xa0  (32)   P_aff      -0x120 (64: qx,qy)
;     sG        -0x180 (96)   eP         -0x1e0 (96)
;     R         -0x240 (96)   z3         -0x280 (32)
;     zi        -0x2a0 (32)   yr         -0x2e0 (32)
;     taghash   -0x340 (32)   digest     -0x320 (32)
;     keyscratch -0x362 (34)  preimg     -0x372 .. -0x4b2 (320, ASCENDING)
;   (the z2, xr and xBE boxes retired with the projective x compare, which now
;    lives in schnorr_x_eq_r and keeps its own two scratch slots)
;   Frame = sub rsp, 0x368 (==8 mod16 -> rsp 0 mod16 at calls after 6 pushes).
;   Every box sits AT/ABOVE rsp (= rbp-0x368) so nested calls cannot clobber it.
;
;   lift_x via pubkey_parse on 33-byte [0x02||pk] (even-Y root).
;
;   System V ABI. Preserve rbx,r12-r15.
;
;   THREAD SAFETY (fixed 2026-08-23, and it was a live false-reject bug)
;   The tagged-hash preimage used to be a process-global `.data` buffer
;   (`schnorr_preimg`). daemon/tx_verify.c verifies a block's inputs on
;   several worker threads, so two taproot key-path inputs verified at the
;   same time interleaved their writes into it and computed each other's
;   challenge e. The result is a WRONG e, hence a wrong R, hence a REJECTED
;   valid signature -- and a rejected valid signature in a block is a rejected
;   valid block. Reproduced at 1,982 false rejects in 160,000 verifications of
;   KNOWN-GOOD signatures across 8 threads; tests/test_schnorr_thread_stress.c
;   is that reproducer. The buffer now lives in this function's own frame, so
;   every call has its own.
;
;   The 2026-08-19 TLS conversion (bitcoin_scriptverify.c, bitcoin_interp.asm,
;   bitcoin_sighash.asm) covered the interpreter's scratch and missed this one.
;   It also missed secp256k1_taproot.asm's `tagh_buf` and `tap_preimg`, which
;   are still process-global and still on the taproot verify path -- SAME BUG,
;   not fixed here, see that file.
; ============================================================================
default rel

extern pubkey_parse
extern point_scalar_mul
extern point_scalar_mul_fixed     ; fixed-base G comb, secp256k1_point.asm
extern point_scalar_mul_glv       ; GLV + wNAF, secp256k1_point.asm
extern bmc_ecdsa_glv_enabled      ; BMC_ECDSA_GLV kill switch, secp256k1_glv_c.c
extern point_add
extern fe_mul
extern fe_sqr
extern fe_inv
extern sha256_full

%define S_SLIMS    -0x50
%define R_SLIMS    -0x80
%define E_SLIMS    -0xb0
%define P_AFF      -0x130
%define SG         -0x190
%define EP         -0x1f0
%define RPT        -0x250
%define Z3         -0x290
%define ZI         -0x2b0
%define YR         -0x2f0
%define DIGEST     -0x330
%define TAGHASH    -0x350
%define KEYSCR     -0x372
%define PREIMG     -0x4b2          ; 320 bytes: tagh||tagh||r||pk||msg
%define PREIMG_CAP 320
%define MSG_CAP    (PREIMG_CAP - 128)
%define FRAME      0x4c8

section .rodata
align 16
P_LIMBS:
    dq 0xFFFFFFFEFFFFFC2F,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF
align 16
N_LIMBS:
    dq 0xBFD25E8CD0364141,0xBAAEDCE6AF48A03B,0xFFFFFFFFFFFFFFFE,0xFFFFFFFFFFFFFFFF
align 16
CHALLENGE_TAG:
    db "BIP0340/challenge"
CHALLENGE_TAG_LEN equ $ - CHALLENGE_TAG

section .text

; ----------------------------------------------------------------------------
; int schnorr_x_eq_r(const u64 r[4], const u64 X[4], const u64 Z[4])
;   1 iff X / Z^2 == r (mod p) -- BIP340's "x(R) == r" test, decided WITHOUT a
;   field inversion:  x(R) = X/Z^2, so x(R) == r  <=>  r * Z^2 == X (mod p).
;
;   Unlike ecdsa_x_eq_mod_n (secp256k1_ecdsa.asm) there is no second candidate:
;   that function's r is a scalar mod n and 2n > p forces an r+n retry, whereas
;   BIP340's r IS a field element and the caller has already rejected r >= p.
;
;   PRECONDITIONS: r canonical in [0,p) (the caller's r < p check), X canonical
;   (fe_mul / the inlined FE_ macros both guarantee it -- see
;   secp256k1_fe_inline.inc "CANONICALITY"), Z != 0 (the caller's infinity
;   check). With Z == 0 this returns 1 for r == X == 0, which is exactly why
;   schnorr_verify's explicit infinity test is load-bearing and not decoration.
;
;   EXPORTED, not static, ONLY so tests/test_schnorr_diff.c can drive it with
;   constructed (r, X, Z) that differ in ONE limb. No signature can produce
;   such a pair -- it would need x(R) to agree with r in three limbs out of
;   four, a ~2^-192 event -- so a mutation that drops a limb from this compare
;   is invisible to any corpus of real signatures and visible here. Same
;   reason, and the same precedent, as ecdsa_x_eq_mod_n.
;
;   rdi=r, rsi=X, rdx=Z. Preserves rbx, r12-r15.
;   Frame: z2 @ rbp-0x40, t @ rbp-0x60 (ascending 4-limb boxes).
; ----------------------------------------------------------------------------
global schnorr_x_eq_r
schnorr_x_eq_r:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 0x60          ; entry rsp==8 mod16; +5 pushes -> 0; -0x60 -> 0
    mov  r12, rdi           ; r
    mov  r13, rsi           ; X
    mov  r14, rdx           ; Z

    lea  rdi, [rbp-0x40]
    mov  rsi, r14
    call fe_sqr             ; z2 = Z^2
    lea  rdi, [rbp-0x60]
    mov  rsi, r12
    lea  rdx, [rbp-0x40]
    call fe_mul             ; t = r * Z^2, canonical

    mov  rax, [rbp-0x60+0]
    cmp  rax, [r13+0]
    jne  .no
    mov  rax, [rbp-0x60+8]
    cmp  rax, [r13+8]
    jne  .no
    mov  rax, [rbp-0x60+16]
    cmp  rax, [r13+16]
    jne  .no
    mov  rax, [rbp-0x60+24]
    cmp  rax, [r13+24]
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 0x60
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .text
global schnorr_verify
schnorr_verify:
    push rbp
    mov  rbp, rsp
    and  rsp, -16          ; snap to 16-byte alignment regardless of entry
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, FRAME        ; FRAME==8 mod16 -> rsp 0 mod16 at nested calls

    ; r12=sig  r13=pub  r14=msg  r15=msglen
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    movsxd r15, ecx           ; msglen is an int; sign-extend before using it
                              ; as a rep-movsb count

    ; ---- msglen bound (2026-08-23) --------------------------------------
    ; The challenge preimage is 128 fixed bytes plus the message, and it now
    ; lives in this frame rather than in a process-global buffer (see below),
    ; so an unchecked length would smash the stack instead of quietly
    ; corrupting .data. Consensus only ever passes 32 (the taproot sighash);
    ; BIP340 itself allows any length and the official vectors go up to 100.
    ; Anything that does not fit is REJECTED, loudly and without hashing --
    ; the same "clean rejection rather than silent truncation" rule
    ; secp256k1_taproot.asm's tap_leaf_hash already follows.
    cmp r15, 0
    jl  .invalid
    cmp r15, MSG_CAP
    ja  .invalid

    ; ---- P = lift_x(pk) via pubkey_parse([0x02||pk],33,P_aff) ----
    mov byte [rbp+KEYSCR], 0x02
    lea rdi, [rbp+KEYSCR+1]
    mov rsi, r13
    mov rcx, 32
    rep movsb
    lea rdi, [rbp+KEYSCR]
    mov rsi, 33
    lea rdx, [rbp+P_AFF]
    lea rcx, [rbp+P_AFF+32]
    call pubkey_parse
    test rax, rax
    jz   .invalid

    ; ---- r = sig[0:32] BE -> LE limbs at R_SLIMS ; fail if r >= p ----
    ; limb[j] = bswap( r_BE bytes[(3-j)*8 .. +7] )  (limb0 = least significant)
    mov rax, [r12+24]
    bswap rax
    mov [rbp+R_SLIMS], rax
    mov rax, [r12+16]
    bswap rax
    mov [rbp+R_SLIMS+8], rax
    mov rax, [r12+8]
    bswap rax
    mov [rbp+R_SLIMS+16], rax
    mov rax, [r12+0]
    bswap rax
    mov [rbp+R_SLIMS+24], rax
    mov rax, [rbp+R_SLIMS+24]
    cmp rax, [P_LIMBS+24]
    ja  .invalid
    jb  .r_ok
    mov rax, [rbp+R_SLIMS+16]
    cmp rax, [P_LIMBS+16]
    ja  .invalid
    jb  .r_ok
    mov rax, [rbp+R_SLIMS+8]
    cmp rax, [P_LIMBS+8]
    ja  .invalid
    jb  .r_ok
    mov rax, [rbp+R_SLIMS]
    cmp rax, [P_LIMBS]
    jae .invalid
.r_ok:

    ; ---- s = sig[32:64] BE -> LE limbs at S_SLIMS ; fail if s >= n ----
    ; limb[j] = bswap( s_BE bytes[(3-j)*8 .. +7] ) ; s_BE byte0 = sig[32]
    mov rax, [r12+56]
    bswap rax
    mov [rbp+S_SLIMS], rax
    mov rax, [r12+48]
    bswap rax
    mov [rbp+S_SLIMS+8], rax
    mov rax, [r12+40]
    bswap rax
    mov [rbp+S_SLIMS+16], rax
    mov rax, [r12+32]
    bswap rax
    mov [rbp+S_SLIMS+24], rax
    mov rax, [rbp+S_SLIMS+24]
    cmp rax, [N_LIMBS+24]
    ja  .invalid
    jb  .s_ok
    mov rax, [rbp+S_SLIMS+16]
    cmp rax, [N_LIMBS+16]
    ja  .invalid
    jb  .s_ok
    mov rax, [rbp+S_SLIMS+8]
    cmp rax, [N_LIMBS+8]
    ja  .invalid
    jb  .s_ok
    mov rax, [rbp+S_SLIMS]
    cmp rax, [N_LIMBS]
    jae .invalid
.s_ok:
    ; ---- e = tagged_hash("BIP0340/challenge", r||pk||m) mod n ----
    ;   tagh = SHA256("BIP0340/challenge") -> TAGHASH
    lea rdi, [rbp+TAGHASH]
    lea rsi, [rel CHALLENGE_TAG]
    mov rdx, CHALLENGE_TAG_LEN
    call sha256_full
    ; preimg = tagh||tagh||r_BE||pk||m  in the STACK frame (see PREIMG)
    lea rdi, [rbp+PREIMG]
    lea rsi, [rbp+TAGHASH]
    mov rcx, 32
    rep movsb
    lea rdi, [rbp+PREIMG+32]
    lea rsi, [rbp+TAGHASH]
    mov rcx, 32
    rep movsb
    lea rdi, [rbp+PREIMG+64]
    mov rsi, r12              ; r big-endian bytes = sig[0:32]
    mov rcx, 32
    rep movsb
    lea rdi, [rbp+PREIMG+96]
    mov rsi, r13              ; pk
    mov rcx, 32
    rep movsb
    lea rdi, [rbp+PREIMG+128]
    mov rsi, r14              ; msg
    mov rcx, r15              ; msglen
    rep movsb
    ; digest = SHA256(preimg[0 .. 128+msglen]) -> DIGEST ; e limbs at E_SLIMS
    lea rdi, [rbp+DIGEST]
    lea rsi, [rbp+PREIMG]
    mov rdx, r15
    add rdx, 128
    call sha256_full
    ; e limbs: limb[j] = bswap( digest bytes[(3-j)*8 .. +7] )
    mov rax, [rbp+DIGEST+24]
    bswap rax
    mov [rbp+E_SLIMS], rax
    mov rax, [rbp+DIGEST+16]
    bswap rax
    mov [rbp+E_SLIMS+8], rax
    mov rax, [rbp+DIGEST+8]
    bswap rax
    mov [rbp+E_SLIMS+16], rax
    mov rax, [rbp+DIGEST]
    bswap rax
    mov [rbp+E_SLIMS+24], rax
    ; e = digest mod n (single conditional subtract; digest < 2n)
    mov rax, [rbp+E_SLIMS+24]
    cmp rax, [N_LIMBS+24]
    jb  .e_ok
    ja  .e_sub
    mov rax, [rbp+E_SLIMS+16]
    cmp rax, [N_LIMBS+16]
    jb  .e_ok
    ja  .e_sub
    mov rax, [rbp+E_SLIMS+8]
    cmp rax, [N_LIMBS+8]
    jb  .e_ok
    ja  .e_sub
    mov rax, [rbp+E_SLIMS]
    cmp rax, [N_LIMBS]
    jb  .e_ok
.e_sub:
    mov rax, [rbp+E_SLIMS]
    sub rax, [N_LIMBS]
    mov [rbp+E_SLIMS], rax
    mov rax, [rbp+E_SLIMS+8]
    sbb rax, [N_LIMBS+8]
    mov [rbp+E_SLIMS+8], rax
    mov rax, [rbp+E_SLIMS+16]
    sbb rax, [N_LIMBS+16]
    mov [rbp+E_SLIMS+16], rax
    mov rax, [rbp+E_SLIMS+24]
    sbb rax, [N_LIMBS+24]
    mov [rbp+E_SLIMS+24], rax
.e_ok:
    ; ---- sG = s*G (Jacobian) at SG  [FIXED-BASE G comb, zero doublings] ----
    ; G is a compile-time constant, so this is the same fixed-base multiply
    ; ecdsa_verify uses for its u1*G term (secp256k1_point.asm,
    ; point_scalar_mul_fixed). s == 0 -> Jacobian infinity, which point_add
    ; below handles through its Z==0 operand guard.
    lea rdi, [rbp+SG]
    lea rsi, [rbp+S_SLIMS]
    call point_scalar_mul_fixed

    ; ---- eP = e*P (Jacobian) at EP  [GLV endomorphism + width-5 wNAF] ----
    ; P is variable, so this is the same shape as ecdsa_verify's u2*Q term.
    ; e is PUBLIC (it is a hash of public data), so a variable-time multiply
    ; is within the policy that already covers point_scalar_mul
    ; (secp256k1_point_ct.asm header). BMC_ECDSA_GLV=0 forces the plain
    ; ladder here exactly as it does for ECDSA -- one switch, both verifies.
    ; point_scalar_mul_glv itself falls back to point_scalar_mul internally
    ; if the lambda split or the wNAF encoder signals a problem.
    ; The C call clobbers only caller-saved registers; every operand below is
    ; re-derived from rbp, and r12-r15 are ours.
    call bmc_ecdsa_glv_enabled
    test eax, eax
    jz  .ep_plain
    lea rdi, [rbp+EP]
    lea rsi, [rbp+P_AFF]
    lea rdx, [rbp+E_SLIMS]
    call point_scalar_mul_glv
    jmp .ep_done
.ep_plain:
    lea rdi, [rbp+EP]
    lea rsi, [rbp+P_AFF]
    lea rdx, [rbp+E_SLIMS]
    call point_scalar_mul
.ep_done:

    ; ---- negate eP.Y (Jacobian) : (X,Y,Z) -> (X,-Y,Z) ; R = sG + (-eP) ----
    mov rax, [rbp+EP+32]
    or  rax, [rbp+EP+40]
    or  rax, [rbp+EP+48]
    or  rax, [rbp+EP+56]
    jz   .done_neg
    mov rax, [P_LIMBS]
    sub rax, [rbp+EP+32]
    mov [rbp+EP+32], rax
    mov rax, [P_LIMBS+8]
    sbb rax, [rbp+EP+40]
    mov [rbp+EP+40], rax
    mov rax, [P_LIMBS+16]
    sbb rax, [rbp+EP+48]
    mov [rbp+EP+48], rax
    mov rax, [P_LIMBS+24]
    sbb rax, [rbp+EP+56]
    mov [rbp+EP+56], rax
.done_neg:
    lea rdi, [rbp+RPT]
    lea rsi, [rbp+SG]
    lea rdx, [rbp+EP]
    call point_add

    ; ---- R infinite? ----
    mov rax, [rbp+RPT+64]
    or  rax, [rbp+RPT+72]
    or  rax, [rbp+RPT+80]
    or  rax, [rbp+RPT+88]
    jz  .invalid

    ; ---- x(R) == r ?  PROJECTIVELY, with no field inversion ----
    ;   x(R) = X / Z^2 (mod p), and r was already range-checked to r < p, so
    ;   both sides are canonical field elements and
    ;       x(R) == r   <=>   r * Z^2 == X   (mod p).
    ;   Unlike ecdsa_x_eq_mod_n there is NO second candidate to try: r there
    ;   is a scalar mod n and 2n > p forces the r+n case, whereas BIP340's r
    ;   IS a field element. One fe_sqr + one fe_mul replaces an fe_inv and
    ;   two fe_mul, and every rejected signature now leaves before the
    ;   inversion below is ever reached.
    ;   fe_mul's result and point_add's X are both canonical in [0,p)
    ;   (secp256k1_fe.asm:187, secp256k1_fe_inline.inc "CANONICALITY"), so
    ;   limb equality IS field equality. The compare lives in its own exported
    ;   function so a test can drive it with one-limb-apart operands, which no
    ;   signature can produce -- see schnorr_x_eq_r's header.
    lea rdi, [rbp+R_SLIMS]
    lea rsi, [rbp+RPT]
    lea rdx, [rbp+RPT+64]
    call schnorr_x_eq_r
    test eax, eax
    jz  .invalid

    ; ---- y(R) even ?  This one genuinely needs the affine y, because parity
    ;   is not a projective invariant -- but it needs ONE inversion, not two:
    ;   zi = Z^{-1} ; y = Y * zi^3.  (The old code inverted Z^2 and then
    ;   inverted Z^3 as well.)  Z != 0 was established by the infinity check.
    lea rdi, [rbp+ZI]
    lea rsi, [rbp+RPT+64]
    call fe_inv                 ; zi = Z^{-1}
    lea rdi, [rbp+Z3]
    lea rsi, [rbp+ZI]
    call fe_sqr                 ; z3 = zi^2
    lea rdi, [rbp+Z3]
    lea rsi, [rbp+Z3]
    lea rdx, [rbp+ZI]
    call fe_mul                 ; z3 = zi^3
    lea rdi, [rbp+YR]
    lea rsi, [rbp+RPT+32]
    lea rdx, [rbp+Z3]
    call fe_mul                 ; yr = Y * Z^{-3}
    test byte [rbp+YR], 1
    jnz .invalid

    mov eax, 1
    jmp .done
.invalid:
    xor eax, eax
.done:
    add rsp, FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    mov  rsp, rbp
    pop rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
