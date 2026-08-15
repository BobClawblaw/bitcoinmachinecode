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
;   Buffer table (offsets from rbp; each box is [off-N+1, off] inclusive):
;     s_limbs   -0x40  (32)   r_limbs    -0x70  (32)
;     e         -0xa0  (32)   P_aff      -0x120 (64: qx,qy)
;     sG        -0x180 (96)   eP         -0x1e0 (96)
;     R         -0x240 (96)   z2         -0x260 (32)
;     z3        -0x280 (32)   zi         -0x2a0 (32)
;     xr        -0x2c0 (32)   yr         -0x2e0 (32)
;     xBE       -0x300 (32)   taghash    -0x340 (32)
;     digest    -0x320 (32)   keyscratch -0x362 (34)
;   Frame = sub rsp, 0x368 (==8 mod16 -> rsp 0 mod16 at calls after 6 pushes).
;   Every box sits AT/ABOVE rsp (= rbp-0x368) so nested calls cannot clobber it.
;
;   lift_x via pubkey_parse on 33-byte [0x02||pk] (even-Y root).
;
;   System V ABI. Preserve rbx,r12-r15.
; ============================================================================
default rel

extern pubkey_parse
extern point_scalar_mul
extern point_add
extern fe_mul
extern fe_inv
extern sha256_full

%define S_SLIMS    -0x50
%define R_SLIMS    -0x80
%define E_SLIMS    -0xb0
%define P_AFF      -0x130
%define SG         -0x190
%define EP         -0x1f0
%define RPT        -0x250
%define Z2         -0x270
%define Z3         -0x290
%define ZI         -0x2b0
%define XR         -0x2d0
%define YR         -0x2f0
%define XBE        -0x310
%define DIGEST     -0x330
%define TAGHASH    -0x350
%define KEYSCR     -0x372
%define FRAME      0x388

section .rodata
align 16
G_AFF:
    dq 0x59F2815B16F81798,0x029BFCDB2DCE28D9,0x55A06295CE870B07,0x79BE667EF9DCBBAC
    dq 0x9C47D08FFB10D4B8,0xFD17B448A6855419,0x5DA4FBFC0E1108A8,0x483ADA7726A3C465
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

section .data
align 16
schnorr_preimg: times 320 db 0

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
    mov r15, rcx

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
    ; preimg = tagh||tagh||r_BE||pk||m  at schnorr_preimg (192 bytes)
    lea rdi, [rel schnorr_preimg]
    lea rsi, [rbp+TAGHASH]
    mov rcx, 32
    rep movsb
    lea rdi, [rel schnorr_preimg+32]
    lea rsi, [rbp+TAGHASH]
    mov rcx, 32
    rep movsb
    lea rdi, [rel schnorr_preimg+64]
    mov rsi, r12              ; r big-endian bytes = sig[0:32]
    mov rcx, 32
    rep movsb
    lea rdi, [rel schnorr_preimg+96]
    mov rsi, r13              ; pk
    mov rcx, 32
    rep movsb
    lea rdi, [rel schnorr_preimg+128]
    mov rsi, r14              ; msg
    mov rcx, r15              ; msglen
    rep movsb
    ; digest = SHA256(preimg[0 .. 128+msglen]) -> DIGEST ; e limbs at E_SLIMS
    lea rdi, [rbp+DIGEST]
    lea rsi, [rel schnorr_preimg]
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
    ; ---- sG = s*G (Jacobian) at SG ----
    lea rdi, [rbp+SG]
    lea rsi, [rel G_AFF]
    lea rdx, [rbp+S_SLIMS]
    call point_scalar_mul

    ; ---- eP = e*P (Jacobian) at EP ----
    lea rdi, [rbp+EP]
    lea rsi, [rbp+P_AFF]
    lea rdx, [rbp+E_SLIMS]
    call point_scalar_mul

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

    ; ---- affine xr = X*(1/Z^2) ; yr = Y*(1/Z^3) ----
    lea rdi, [rbp+Z2]
    lea rsi, [rbp+RPT+64]
    lea rdx, [rbp+RPT+64]
    call fe_mul                 ; z2
    lea rdi, [rbp+ZI]
    lea rsi, [rbp+Z2]
    call fe_inv                 ; zi = z2^{-1}
    lea rdi, [rbp+XR]
    lea rsi, [rbp+RPT]
    lea rdx, [rbp+ZI]
    call fe_mul                 ; xr
    lea rdi, [rbp+Z3]
    lea rsi, [rbp+Z2]
    lea rdx, [rbp+RPT+64]
    call fe_mul                 ; z3
    lea rdi, [rbp+ZI]
    lea rsi, [rbp+Z3]
    call fe_inv                 ; zi3
    lea rdi, [rbp+YR]
    lea rsi, [rbp+RPT+32]
    lea rdx, [rbp+ZI]
    call fe_mul                 ; yr

    ; ---- x(R) == r ? ; y(R) even ? ----
    ;   BE serialization = most-significant limb first: xBE[0..7]=limb3, ...
    mov rax, [rbp+XR+24]
    bswap rax
    mov [rbp+XBE], rax
    mov rax, [rbp+XR+16]
    bswap rax
    mov [rbp+XBE+8], rax
    mov rax, [rbp+XR+8]
    bswap rax
    mov [rbp+XBE+16], rax
    mov rax, [rbp+XR]
    bswap rax
    mov [rbp+XBE+24], rax
    lea rsi, [rbp+XBE]
    mov rdi, r12
    mov rcx, 32
    cld
    rep cmpsb
    jne .invalid
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
