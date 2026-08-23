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
;   System V ABI; preserves rbx,r12-r15. The scratch the small helpers use
;   (tagh_buf, tap_preimg) is THREAD-LOCAL as of 2026-08-23; it was
;   process-global, and that one fact is why daemon/tx_verify.c verified every
;   taproot input in a sequential pass while every other shape fanned out
;   across the worker pool. These functions are safe to call concurrently.
;   If you add scratch here, put it in .tbss too -- a plain .data/.bss buffer
;   silently re-serializes the whole taproot path.
; ============================================================================
default rel

extern sha256_full
extern pubkey_parse
extern point_scalar_mul
extern point_add
extern fe_inv
extern fe_mul
extern fe_sqr

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


; tap_preimg: shared scratch for tagged_hash256/tap_branch_hash/tap_leaf_hash/
; tap_merkle_root (single-threaded global, see this file's header comment).
; Sized generously for tap_leaf_hash's variable-length script copy at +64:
; BIP342 deliberately has NO fixed tapscript-size cap (bitcoin_interp.asm's
; own MAX_SCRIPT_SIZE check is skipped entirely for SIGVERSION_TAPSCRIPT),
; so this must hold any realistic real-world tapscript, not just the small
; fixed-size hashes (32/64 bytes) the other three functions ever write here.
; tap_leaf_hash checks its actual write length against (TAP_PREIMG_CAP-64)
; and fails cleanly (returns 0, writes nothing) rather than overflow if that
; capacity is ever exceeded -- found and fixed 2026-08-21 after a genuinely
; large synthetic tapscript (~1.4KB, a validation-weight-budget test script)
; silently overflowed the original 352-byte buffer and corrupted adjacent
; global state (manifested as an unrelated-looking commitment mismatch in
; LATER, otherwise-correct calls, and a crash under a different memory
; layout) -- this is exactly the "produce a clean, loud rejection rather
; than silent truncation" philosophy already established elsewhere in this
; project (see e.g. TXV_SPK_CAP's own header comment in daemon/tx_verify.c).
TAP_PREIMG_CAP equ 4*1024*1024
; Thread-local (2026-08-23). Both were process-global scratch, which is
; why daemon/tx_verify.c had to verify every taproot input in a SEQUENTIAL
; pass while every other input shape fanned out across the worker pool --
; see PERF_SCOPE.md section 14 for the profile that measured the cost.
; .tbss is demand-paged, so TAP_PREIMG_CAP is 4 MiB of address space per
; thread but only the touched pages are ever resident.
section .tbss alloc noexec nowrite tls align=16
global tagh_buf
tagh_buf:   resb 32
global tap_preimg
tap_preimg: resb TAP_PREIMG_CAP

; ============================================================================
; tagged_hash256(out[32]=rdi, tag=rsi, taglen=rdx, msg=rcx, msglen=r8)
;   r12=out, r13=tag, r14=taglen, rbx=msg, r15=msglen
; ============================================================================
; TLS_ADDR dst, sym -- dst = this thread's address of `sym` (ELF x86-64
; Initial-Exec model). Clobbers only `dst`, so it is a drop-in for the
; `lea dst, [rel sym]` it replaced. Mirrors the identical macro in
; bitcoin_interp.asm / bitcoin_sighash.asm (NASM macros are per-file).
%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

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
    TLS_ADDR rdi, tagh_buf
    mov  rsi, r13
    mov  rdx, r14
    call sha256_full
    TLS_ADDR rdi, tap_preimg
    TLS_ADDR rsi, tagh_buf
    mov  rcx, 32
    rep movsb
    TLS_ADDR rdi, tap_preimg
    add  rdi, 32
    TLS_ADDR rsi, tagh_buf
    mov  rcx, 32
    rep movsb
    TLS_ADDR rdi, tap_preimg
    add  rdi, 64
    mov  rsi, rbx
    mov  rcx, r15
    rep movsb
    mov  rdi, r12
    TLS_ADDR rsi, tap_preimg
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
    TLS_ADDR rdi, tap_preimg
    add  rdi, 64
    mov  rsi, r13
    mov  rcx, 32
    rep movsb
    TLS_ADDR rdi, tap_preimg
    add  rdi, 96
    mov  rsi, r14
    mov  rcx, 32
    rep movsb
    jmp  .bdo
.bfirst:
    ; b first: msg = b||a
    TLS_ADDR rdi, tap_preimg
    add  rdi, 64
    mov  rsi, r14
    mov  rcx, 32
    rep movsb
    TLS_ADDR rdi, tap_preimg
    add  rdi, 96
    mov  rsi, r13
    mov  rcx, 32
    rep movsb
.bdo:
    mov  rdi, r12
    lea  rsi, [rel TAPBRANCH_TAG]
    mov  rdx, TAPBRANCH_TAG_LEN
    TLS_ADDR rcx, tap_preimg
    add  rcx, 64
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
;   -> rax = 1 ok / 0 slen too large for TAP_PREIMG_CAP (out untouched on 0,
;   nothing written past the buffer either way -- see TAP_PREIMG_CAP's own
;   comment above tap_preimg for why this bound and check exist).
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
    ; Bound slen against the buffer's real usable capacity BEFORE writing
    ; anything: 64 (tag-hash-doubled prefix) + 1 (ver) + up to 5 (compact-
    ; size) + slen must fit in TAP_PREIMG_CAP. Clean, loud failure instead
    ; of ever overflowing -- see this function's own header comment.
    mov  rax, TAP_PREIMG_CAP - 70
    cmp  r14, rax
    ja   .too_large
    ; msg at tap_preimg+64: ver || compact(slen) || script
    TLS_ADDR r15, tap_preimg
    add  r15, 64
    mov  byte [r15], sil
    inc  r15                       ; r15 = tap_preimg+65, as before
    cmp  r14, 0xfd
    jb   .small
    cmp  r14, 0x10000
    jb   .mid
    ; 5-byte compact-size (0xfe + 4-byte LE): slen already bounded well
    ; under 4G by the TAP_PREIMG_CAP check above, so r14d truncation here
    ; is exact, not lossy.
    mov  byte [r15], 0xfe
    inc  r15
    mov  dword [r15], r14d
    add  r15, 4
    jmp  .copy
.mid:
    mov  byte [r15], 0xfd
    inc  r15
    mov  word [r15], r14w
    add  r15, 2
    jmp  .copy
.small:
    mov  byte [r15], r14b
    inc  r15
.copy:
    mov  rdi, r15
    mov  rsi, r13
    mov  rcx, r14
    rep movsb
    TLS_ADDR rax, tap_preimg
    add  rax, 64
    sub  r15, rax
    add  r15, r14
    mov  rdi, r12
    lea  rsi, [rel TAPLEAF_TAG]
    mov  rdx, TAPLEAF_TAG_LEN
    TLS_ADDR rcx, tap_preimg
    add  rcx, 64
    mov  r8, r15
    call tagged_hash256
    mov  eax, 1
    jmp  .ret
.too_large:
    xor  eax, eax
.ret:
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
    call fe_sqr
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
    TLS_ADDR rdi, tap_preimg
    add  rdi, 192
    mov  rsi, r13
    mov  rcx, 32
    rep movsb
    ; i lives on the stack, in the frame's own reserved area at rsp+0x18
    ; (survives nested calls; rsp is not touched between the prologue's
    ; `sub rsp,0x28` and the epilogue's `add rsp,0x28`).
    ;
    ; It was at rbp-0x10 until 2026-08-23, which ALIASED SAVED r12. The
    ; prologue is `push rbp / mov rbp,rsp / and rsp,-16 / push rbx /
    ; push r12 / ...`: because the callee-saved pushes happen AFTER
    ; `and rsp,-16`, the distance from rbp down to them depends on the
    ; CALLER's alignment. With no padding, saved rbx landed at rbp-0x08
    ; and saved r12 at exactly rbp-0x10 -- so writing the loop counter
    ; here overwrote it and `pop r12` returned the counter. Measured: a
    ; caller got r12 = 0/1/2/3 for control blocks with 0/1/2/3 siblings.
    ; Pinned by tests/test_abi_coverage.
    mov  qword [rsp+0x18], 0
.mloop:
    mov  r9, [rsp+0x18]
    cmp  r9, r15
    jae  .mdone
    ; sibling = control + 33 + i*32
    mov  rax, r9
    shl  rax, 5
    add  rax, 33
    lea  r11, [rbx+rax]
    ; compare node (+192) vs sibling: cmpsb flags = [rsi=sibling] - [rdi=node],
    ; so CF set here means sibling < node -> sibling goes FIRST.
    TLS_ADDR rdi, tap_preimg
    add  rdi, 192
    mov  rsi, r11
    mov  rcx, 32
    repe cmpsb
    jb   .sib_first
    ; node first: msg = node||sibling  (node <= sibling)
    TLS_ADDR rdi, tap_preimg
    add  rdi, 128
    TLS_ADDR rsi, tap_preimg
    add  rsi, 192
    mov  rcx, 32
    rep movsb
    TLS_ADDR rdi, tap_preimg
    add  rdi, 160
    mov  rsi, r11
    mov  rcx, 32
    rep movsb
    jmp  .do_hash
.sib_first:
    ; sibling first: msg = sibling||node  (sibling < node)
    TLS_ADDR rdi, tap_preimg
    add  rdi, 128
    mov  rsi, r11
    mov  rcx, 32
    rep movsb
    TLS_ADDR rdi, tap_preimg
    add  rdi, 160
    TLS_ADDR rsi, tap_preimg
    add  rsi, 192
    mov  rcx, 32
    rep movsb
    jmp  .do_hash
.do_hash:
    ; node = TapBranch(msg at +128) -> write into +224 then copy to +192
    TLS_ADDR rdi, tap_preimg
    add  rdi, 224
    lea  rsi, [rel TAPBRANCH_TAG]
    mov  rdx, TAPBRANCH_TAG_LEN
    TLS_ADDR rcx, tap_preimg
    add  rcx, 128
    mov  r8, 64
    call tagged_hash256
    TLS_ADDR rdi, tap_preimg
    add  rdi, 192
    TLS_ADDR rsi, tap_preimg
    add  rsi, 224
    mov  rcx, 32
    rep movsb
    mov  rax, [rsp+0x18]
    inc  rax
    mov  [rsp+0x18], rax
    jmp  .mloop
.mdone:
    mov  rdi, r12
    TLS_ADDR rsi, tap_preimg
    add  rsi, 192
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
