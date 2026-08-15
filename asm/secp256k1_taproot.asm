; ============================================================================
; secp256k1_taproot.asm -- BIP341 Taproot helpers (key-path tweak + script-path
;   merkle tree) on top of the verified secp256k1 point/scalar + sha256.
;   Hand-written x86-64, 100% AI-authored, validated against Python reference
;   implementations and the BIP341 spec vector.
;
;   void tagged_hash256(u8 out[32], const char* tag, u64 taglen, const u8* msg,
;                       u64 msglen)
;       out = SHA256(SHA256(tag)||SHA256(tag)||msg)
;
;   i64 taproot_tweak_pubkey(u8 out_x[32], const u8 internal_x[32],
;                            const u8* merkle_root)   ; NULL => key-only
;       BIP341 key-path output-key derivation.
;
;   void tap_leaf_hash(u8 out[32], u8 leaf_version, const u8* script, u64 slen)
;       out = TapLeaf(leaf_version || compact_size(slen) || script)
;
;   void tap_branch_hash(u8 out[32], const u8 a[32], const u8 b[32])
;       out = TapBranch(a || b)
;
;   i64 tap_merkle_root(u8 out[32], const u8* leaf_hashes, u64 count,
;                       const u8* control, u64 clen)
;       Reconstruct the merkle root from the leaf hash + the trailing
;       control-block sibling path (innermost first). control NULL/too short
;       => single-leaf root = leaf_hashes[0]. Returns 1/0.
;
;   LEAF_VERSION_TAPSCRIPT == 0xc0.
;
;   System V ABI; preserves rbx,r12-r15. Global scratch (tagh_buf,
;   tap_preimg) used by the small helpers is single-threaded.
; ============================================================================
default rel

extern sha256_full
extern pubkey_parse
extern point_scalar_mul
extern point_add
extern fe_inv
extern fe_mul

section .rodata
align 16
P_LIMBS_TR:
    dq 0xFFFFFFFEFFFFFC2F,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF
align 16
N_LIMBS_TR:
    dq 0xBFD25E8CD0364141,0xBAAEDCE6AF48A03B,0xFFFFFFFFFFFFFFFE,0xFFFFFFFFFFFFFFFF
align 16
TAPTWEAK_TAG:
    db "TapTweak"
TAPTWEAK_TAG_LEN equ $ - TAPTWEAK_TAG
align 16
TAPLEAF_TAG:
    db "TapLeaf"
TAPLEAF_TAG_LEN equ $ - TAPLEAF_TAG
align 16
TAPBRANCH_TAG:
    db "TapBranch"
TAPBRANCH_TAG_LEN equ $ - TAPBRANCH_TAG
align 16
G_AFF_TR:
    dq 0x59F2815B16F81798,0x029BFCDB2DCE28D9,0x55A06295CE870B07,0x79BE667EF9DCBBAC
    dq 0x9C47D08FFB10D4B8,0xFD17B448A6855419,0x5DA4FBFC0E1108A8,0x483ADA7726A3C465
; p in big-endian byte order for the x < p check (BIP340 lift_x rejects x>=p)
align 16
P_BE:
    db 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    db 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F

section .data
align 16
tagh_buf:  times 32 db 0
tap_preimg: times 352 db 0

; ============================================================================
; tagged_hash256(out[32]=rdi, tag=rsi, taglen=rdx, msg=rcx, msglen=r8)
;   r12=out, r13=tag, r14=taglen, rbx=msg, r15=msglen
; ============================================================================
section .text
global tagged_hash256
tagged_hash256:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rbx, rcx
    mov  r15, r8
    lea  rdi, [rel tagh_buf]
    mov  rsi, r13
    mov  rdx, r14
    call sha256_full
    lea  rdi, [rel tap_preimg]
    lea  rsi, [rel tagh_buf]
    mov  rcx, 32
    rep movsb
    lea  rdi, [rel tap_preimg+32]
    lea  rsi, [rel tagh_buf]
    mov  rcx, 32
    rep movsb
    lea  rdi, [rel tap_preimg+64]
    mov  rsi, rbx
    mov  rcx, r15
    rep movsb
    mov  rdi, r12
    lea  rsi, [rel tap_preimg]
    mov  rdx, r15
    add  rdx, 64
    call sha256_full
    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    mov  rsp, rbp
    pop  rbp
    ret

; ============================================================================
; tap_branch_hash(out[32]=rdi, a=rsi, b=rdx)  -> TapBranch(a||b)
; ============================================================================
global tap_branch_hash
tap_branch_hash:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18
    mov  r12, rdi
    mov  r13, rsi          ; a
    mov  r14, rdx          ; b
    ; BIP341 branch hash sorts the two hashes lexicographically.
    ; compare a vs b (cmpsb flags = [rsi=b] - [rdi=a]); if a<=b -> a first.
    mov  rdi, r13
    mov  rsi, r14
    mov  rcx, 32
    repe cmpsb
    jb   .bfirst
    ; a first: msg = a||b at tap_preimg+64
    lea  rdi, [rel tap_preimg+64]
    mov  rsi, r13
    mov  rcx, 32
    rep movsb
    lea  rdi, [rel tap_preimg+96]
    mov  rsi, r14
    mov  rcx, 32
    rep movsb
    jmp  .bdo
.bfirst:
    ; b first: msg = b||a
    lea  rdi, [rel tap_preimg+64]
    mov  rsi, r14
    mov  rcx, 32
    rep movsb
    lea  rdi, [rel tap_preimg+96]
    mov  rsi, r13
    mov  rcx, 32
    rep movsb
.bdo:
    mov  rdi, r12
    lea  rsi, [rel TAPBRANCH_TAG]
    mov  rdx, TAPBRANCH_TAG_LEN
    lea  rcx, [rel tap_preimg+64]
    mov  r8, 64
    call tagged_hash256
    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    mov  rsp, rbp
    pop  rbp
    ret

; ============================================================================
; tap_leaf_hash(out[32]=rdi, leaf_version=rsi, script=rdx, slen=rcx)
; ============================================================================
global tap_leaf_hash
tap_leaf_hash:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18
    mov  r12, rdi
    mov  r13, rdx
    mov  r14, rcx
    ; msg at tap_preimg+64: ver || compact(slen) || script
    mov  byte [rel tap_preimg+64], sil
    lea  r15, [rel tap_preimg+65]
    cmp  r14, 253
    jae  .big
    mov  byte [r15], r14b
    inc  r15
    jmp  .copy
.big:
    mov  byte [r15], 0xfd
    inc  r15
    mov  word [r15], r14w
    add  r15, 2
.copy:
    mov  rdi, r15
    mov  rsi, r13
    mov  rcx, r14
    rep movsb
    lea  rax, [rel tap_preimg+64]
    sub  r15, rax
    add  r15, r14
    mov  rdi, r12
    lea  rsi, [rel TAPLEAF_TAG]
    mov  rdx, TAPLEAF_TAG_LEN
    lea  rcx, [rel tap_preimg+64]
    mov  r8, r15
    call tagged_hash256
    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    mov  rsp, rbp
    pop  rbp
    ret

; ============================================================================
; taproot_tweak_pubkey(out_x[32]=rdi, internal_x[32]=rsi, merkle_root=rdx)
;   BIP341 key-path: t=TapTweak(internal||mr) ; Q=lift(even)+t*G, even-normalize.
;   Frame (rbp-relative):
;     MSG=-0x90(64) DIGEST=-0xb0(32) T=-0xd0(32) PAFF=-0x110(64)
;     PJ=-0x170(96) TG=-0x1d0(96) Q=-0x230(96) Z2=-0x250(32)
;     Z3=-0x270(32) ZI=-0x290(32) XR=-0x2b0(32) YR=-0x2d0(32) KSCR=-0x2f2(34)
;   FRAME2=0x308
; ============================================================================
%define TW_MSG    -0x90
%define TW_DIGEST -0xb0
%define TW_T      -0xd0
%define TW_PAFF   -0x110
%define TW_PJ     -0x170
%define TW_TG     -0x1d0
%define TW_Q      -0x230
%define TW_Z2     -0x250
%define TW_Z3     -0x270
%define TW_ZI     -0x290
%define TW_XR     -0x2b0
%define TW_YR     -0x2d0
%define TW_KSCR   -0x2f2
%define TW_FRAME  0x308
global taproot_tweak_pubkey
taproot_tweak_pubkey:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, TW_FRAME
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    ; ---- MSG = internal_x || [merkle_root] ----
    lea  rdi, [rbp+TW_MSG]
    mov  rsi, r13
    mov  rcx, 32
    rep movsb
    mov  r15, 32
    test r14, r14
    jz   .nomr
    lea  rdi, [rbp+TW_MSG+32]
    mov  rsi, r14
    mov  rcx, 32
    rep movsb
    mov  r15, 64
.nomr:
    ; ---- digest = TapTweak(MSG) ----
    lea  rdi, [rbp+TW_DIGEST]
    lea  rsi, [rel TAPTWEAK_TAG]
    mov  rdx, TAPTWEAK_TAG_LEN
    lea  rcx, [rbp+TW_MSG]
    mov  r8, r15
    call tagged_hash256
    ; ---- t limbs, reject t >= n ----
    mov  rax, [rbp+TW_DIGEST+24]
    bswap rax
    mov  [rbp+TW_T], rax
    mov  rax, [rbp+TW_DIGEST+16]
    bswap rax
    mov  [rbp+TW_T+8], rax
    mov  rax, [rbp+TW_DIGEST+8]
    bswap rax
    mov  [rbp+TW_T+16], rax
    mov  rax, [rbp+TW_DIGEST]
    bswap rax
    mov  [rbp+TW_T+24], rax
    mov  rax, [rbp+TW_T+24]
    cmp  rax, [N_LIMBS_TR+24]
    ja   .fail
    jb   .tok
    mov  rax, [rbp+TW_T+16]
    cmp  rax, [N_LIMBS_TR+16]
    ja   .fail
    jb   .tok
    mov  rax, [rbp+TW_T+8]
    cmp  rax, [N_LIMBS_TR+8]
    ja   .fail
    jb   .tok
    mov  rax, [rbp+TW_T]
    cmp  rax, [N_LIMBS_TR]
    jae  .fail
.tok:
    ; ---- reject internal_x >= p (BIP340 lift_x / BIP341 internal key range) ----
    ; compare 32 BE bytes internal_x (r13) vs P_BE; if x >= p -> fail.
    lea  rax, [rel P_BE]
    xor  rcx, rcx
.xloop:
    cmp  rcx, 32
    jae  .x_in_range
    mov  dl, [r13+rcx]
    cmp  dl, [rax+rcx]
    jb   .x_in_range          ; byte lower -> x < p
    ja   .fail                ; byte higher -> x > p
    inc  rcx
    jmp  .xloop
.x_in_range:
    ; ---- P = lift_x(internal) via pubkey_parse([0x02||internal],33) ----
    mov  byte [rbp+TW_KSCR], 0x02
    lea  rdi, [rbp+TW_KSCR+1]
    mov  rsi, r13
    mov  rcx, 32
    rep movsb
    lea  rdi, [rbp+TW_KSCR]
    mov  rsi, 33
    lea  rdx, [rbp+TW_PAFF]
    lea  rcx, [rbp+TW_PAFF+32]
    call pubkey_parse
    test rax, rax
    jz   .fail
    ; ---- PJ = (P.x, P.y, 1) ----
    lea  rdi, [rbp+TW_PJ]
    lea  rsi, [rbp+TW_PAFF]
    mov  rcx, 64
    rep movsb
    mov  qword [rbp+TW_PJ+64], 1
    mov  qword [rbp+TW_PJ+72], 0
    mov  qword [rbp+TW_PJ+80], 0
    mov  qword [rbp+TW_PJ+88], 0
    ; ---- TG = t*G ----
    lea  rdi, [rbp+TW_TG]
    lea  rsi, [rel G_AFF_TR]
    lea  rdx, [rbp+TW_T]
    call point_scalar_mul
    ; ---- Q = PJ + TG ----
    lea  rdi, [rbp+TW_Q]
    lea  rsi, [rbp+TW_PJ]
    lea  rdx, [rbp+TW_TG]
    call point_add
    ; Q infinite?
    mov  rax, [rbp+TW_Q+64]
    or   rax, [rbp+TW_Q+72]
    or   rax, [rbp+TW_Q+80]
    or   rax, [rbp+TW_Q+88]
    jz   .fail
    ; ---- affine ----
    lea  rdi, [rbp+TW_Z2]
    lea  rsi, [rbp+TW_Q+64]
    lea  rdx, [rbp+TW_Q+64]
    call fe_mul
    lea  rdi, [rbp+TW_ZI]
    lea  rsi, [rbp+TW_Z2]
    call fe_inv
    lea  rdi, [rbp+TW_XR]
    lea  rsi, [rbp+TW_Q]
    lea  rdx, [rbp+TW_ZI]
    call fe_mul
    lea  rdi, [rbp+TW_Z3]
    lea  rsi, [rbp+TW_Z2]
    lea  rdx, [rbp+TW_Q+64]
    call fe_mul
    lea  rdi, [rbp+TW_ZI]
    lea  rsi, [rbp+TW_Z3]
    call fe_inv
    lea  rdi, [rbp+TW_YR]
    lea  rsi, [rbp+TW_Q+32]
    lea  rdx, [rbp+TW_ZI]
    call fe_mul
    ; ---- even-normalize yr ----
    test byte [rbp+TW_YR], 1
    jz   .even
    mov  rax, [P_LIMBS_TR]
    sub  rax, [rbp+TW_YR]
    mov  [rbp+TW_YR], rax
    mov  rax, [P_LIMBS_TR+8]
    sbb  rax, [rbp+TW_YR+8]
    mov  [rbp+TW_YR+8], rax
    mov  rax, [P_LIMBS_TR+16]
    sbb  rax, [rbp+TW_YR+16]
    mov  [rbp+TW_YR+16], rax
    mov  rax, [P_LIMBS_TR+24]
    sbb  rax, [rbp+TW_YR+24]
    mov  [rbp+TW_YR+24], rax
.even:
    ; ---- out_x = BE bytes of xr ----
    mov  rax, [rbp+TW_XR+24]
    bswap rax
    mov  [r12+0], rax
    mov  rax, [rbp+TW_XR+16]
    bswap rax
    mov  [r12+8], rax
    mov  rax, [rbp+TW_XR+8]
    bswap rax
    mov  [r12+16], rax
    mov  rax, [rbp+TW_XR]
    bswap rax
    mov  [r12+24], rax
    mov  eax, 1
    jmp  .twdone
.fail:
    xor  eax, eax
.twdone:
    add  rsp, TW_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    mov  rsp, rbp
    pop  rbp
    ret

; ============================================================================
; tap_merkle_root(out[32]=rdi, leaf_hashes=rsi, count=rdx, control=rcx, clen=r8)
;   Reconstruct merkle root: node = leaf_hashes[0]; then for each sibling in the
;   control path (innermost first, control[33+i*32]) do
;     node = TapBranch(min(node,sib)||max(node,sib)).
;   Workspace layout in tap_preimg (single-threaded global):
;     node   at +192 (32)     ordered msg at +128 (64)   out temp at +224 (32)
;   tagged_hash256 builds its own preimg at [0..191] and copies msg from +64, so
;   our node (+192) and ordered-msg (+128) live clear of that.
;   r12=out, r13=leaf_hashes, r14=count, rbx=control, r15=depth, r9=i
; ============================================================================
global tap_merkle_root
tap_merkle_root:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x28
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rbx, rcx
    mov  r15, 0
    test rbx, rbx
    jz   .justleaf
    cmp  r8, 33
    jb   .justleaf
    mov  rax, r8
    sub  rax, 33
    shr  rax, 5
    mov  r15, rax
.justleaf:
    ; node = leaf_hashes[0] at tap_preimg+192
    lea  rdi, [rel tap_preimg+192]
    mov  rsi, r13
    mov  rcx, 32
    rep movsb
    ; i lives on the stack at rbp-0x10 (survives nested calls)
    mov  qword [rbp-0x10], 0
.mloop:
    mov  r9, [rbp-0x10]
    cmp  r9, r15
    jae  .mdone
    ; sibling = control + 33 + i*32
    mov  rax, r9
    shl  rax, 5
    add  rax, 33
    lea  r11, [rbx+rax]
    ; compare node (+192) vs sibling: cmpsb flags = [rsi=sibling] - [rdi=node],
    ; so CF set here means sibling < node -> sibling goes FIRST.
    lea  rdi, [rel tap_preimg+192]
    mov  rsi, r11
    mov  rcx, 32
    repe cmpsb
    jb   .sib_first
    ; node first: msg = node||sibling  (node <= sibling)
    lea  rdi, [rel tap_preimg+128]
    lea  rsi, [rel tap_preimg+192]
    mov  rcx, 32
    rep movsb
    lea  rdi, [rel tap_preimg+160]
    mov  rsi, r11
    mov  rcx, 32
    rep movsb
    jmp  .do_hash
.sib_first:
    ; sibling first: msg = sibling||node  (sibling < node)
    lea  rdi, [rel tap_preimg+128]
    mov  rsi, r11
    mov  rcx, 32
    rep movsb
    lea  rdi, [rel tap_preimg+160]
    lea  rsi, [rel tap_preimg+192]
    mov  rcx, 32
    rep movsb
    jmp  .do_hash
.do_hash:
    ; node = TapBranch(msg at +128) -> write into +224 then copy to +192
    lea  rdi, [rel tap_preimg+224]
    lea  rsi, [rel TAPBRANCH_TAG]
    mov  rdx, TAPBRANCH_TAG_LEN
    lea  rcx, [rel tap_preimg+128]
    mov  r8, 64
    call tagged_hash256
    lea  rdi, [rel tap_preimg+192]
    lea  rsi, [rel tap_preimg+224]
    mov  rcx, 32
    rep movsb
    mov  rax, [rbp-0x10]
    inc  rax
    mov  [rbp-0x10], rax
    jmp  .mloop
.mdone:
    mov  rdi, r12
    lea  rsi, [rel tap_preimg+192]
    mov  rcx, 32
    rep movsb
    mov  eax, 1
    add  rsp, 0x28
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    mov  rsp, rbp
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
