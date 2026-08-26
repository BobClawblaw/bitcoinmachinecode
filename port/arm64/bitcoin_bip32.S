/* bitcoin_bip32.S -- AArch64 port of asm/bitcoin_bip32.asm (AAPCS64).
 * BIP32 HD key derivation on the verified secp256k1/HMAC/SHA-512 core.
 * Exports:
 *   int bip32_master(k[32], c[32], seed, seedlen)            -> 1/0
 *   int bip32_ckd_priv(k[32], c[32], k_par[32], c_par[32], index) -> 1/0
 *   int bip32_derive_path(k[32], c[32], seed, seedlen, indexes[4n], n) -> 1/0
 *   void bip32_fingerprint(fp[4], pub[33])
 *   int  bip32_extkey_serialize(ser[78], is_priv, depth, parent_fp[4],
 *                               child, c[32], key, keylen)      -> 78
 * child index is a u32 in w4 (top bit = hardened). All keys are
 * big-endian 256-bit scalars. Curve order n (NBYTES) for mod-reduction. */
    .section .rodata
    .p2align 4
bip32_seed_key:
    .asciz "Bitcoin seed"
    .p2align 4
NBYTES:
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE
    .byte 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B
    .byte 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41

    .text

/* ================= bip32_master(k=x0, c=x1, seed=x2, seedlen=x3) -> 1/0 ================= */
    .global bip32_master
    .type bip32_master,%function
bip32_master:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    sub  sp,sp,#0x50           /* digest[64] @sp+0x10 */
    mov  x29,sp
    mov  x19,x0                /* k */
    mov  x20,x1                /* c */
    mov  x21,x2                /* seed */
    mov  x22,x3                /* seedlen */
    /* hmac_sha512(digest, "Bitcoin seed", 12, seed, seedlen) */
    add  x0,sp,#0x10
    adrp x9,bip32_seed_key
    add  x1,x9,:lo12:bip32_seed_key
    mov  x2,#12
    mov  x3,x21
    mov  x4,x22
    bl   hmac_sha512
    /* k = digest[0..31] */
    mov  x0,x19
    add  x1,sp,#0x10
    mov  x2,#32
    bl   __b32_copy
    /* c = digest[32..63] */
    mov  x0,x20
    add  x1,sp,#0x10
    add  x1,x1,#32
    mov  x2,#32
    bl   __b32_copy
    /* return 1 iff k != 0 */
    mov  x0,x19
    bl   __b32_nonzero
    add  sp,sp,#0x50
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size bip32_master,.-bip32_master

/* ================= bip32_ckd_priv(k_out=x0, c_out=x1, k_par=x2, c_par=x3, index=w4) ================= */
    .global bip32_ckd_priv
    .type bip32_ckd_priv,%function
bip32_ckd_priv:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    sub  sp,sp,#0x100
    mov  x29,sp
    mov  x19,x0                /* k_out */
    mov  x20,x1                /* c_out */
    mov  x21,x2                /* k_par */
    mov  x22,x3                /* c_par */
    mov  w23,w4                /* index */
    /* snapshot k_par -> sp+0xC0, c_par -> sp+0xE0 (in-place safe) */
    mov  x0,sp
    add  x0,x0,#0xC0
    mov  x1,x21
    mov  x2,#32
    bl   __b32_copy
    mov  x0,sp
    add  x0,x0,#0xE0
    mov  x1,x22
    mov  x2,#32
    bl   __b32_copy
    /* build HMAC input @ sp+0x40 (37 bytes) */
    tbz  w23,#31,.b32_normal
    /* hardened: inp[0]=0, inp[1..32]=ser256(k_par) */
    strb wzr,[sp,#0x40]
    add  x0,sp,#0x40
    add  x0,x0,#1
    mov  x1,x21
    mov  x2,#32
    bl   __b32_copy
    b    .b32_inp_ready
.b32_normal:
    /* normal: inp[0..32] = compressed pubkey of k_par (33B) */
    add  x0,sp,#0x00           /* pub temp */
    mov  x1,x21
    bl   scalar_to_pubkey
    add  x0,sp,#0x40           /* inp */
    add  x1,sp,#0x00           /* pub */
    mov  x2,#33
    bl   __b32_copy
.b32_inp_ready:
    /* append ser32(index) big-endian at inp[33..36] */
    mov  w9,w23
    add  x8,sp,#0x40
    strb w9,[x8,#36]
    lsr  w9,w9,#8
    strb w9,[x8,#35]
    lsr  w9,w9,#8
    strb w9,[x8,#34]
    lsr  w9,w9,#8
    strb w9,[x8,#33]
    /* hmac_sha512(I=sp+0x80, c_par=sp+0xE0, 32, inp=sp+0x40, 37) */
    add  x0,sp,#0x80
    add  x1,sp,#0xE0
    mov  x2,#32
    add  x3,sp,#0x40
    mov  x4,#37
    bl   hmac_sha512
    /* validate IL = I[0..31]: scalar_small_nonzero(I) */
    add  x0,sp,#0x80
    bl   scalar_small_nonzero
    cbz  w0,.b32_invalid
    /* c_i = IR = I[32..63] -> c_out */
    mov  x0,x20
    add  x1,sp,#0x80
    add  x1,x1,#32
    mov  x2,#32
    bl   __b32_copy
    /* k_i = (IL + k_par) mod n.
     * Load each 8-byte BE limb and REV it to its true arithmetic value
     * (a plain LE ldr byte-swaps the chunk, so carries would misalign).
     * x8..x11 = IL limbs (x11 = LSB limb), x12..x15 = k_par limbs. */
    ldr  x8,[sp,#0x80];  rev x8,x8
    ldr  x9,[sp,#0x88];  rev x9,x9
    ldr  x10,[sp,#0x90]; rev x10,x10
    ldr  x11,[sp,#0x98]; rev x11,x11
    ldr  x12,[sp,#0xC0]; rev x12,x12
    ldr  x13,[sp,#0xC8]; rev x13,x13
    ldr  x14,[sp,#0xD0]; rev x14,x14
    ldr  x15,[sp,#0xD8]; rev x15,x15
    adds x3,x11,x15            /* sum3 (LSB limb) */
    adcs x2,x10,x14
    adcs x1,x9,x13
    adcs x0,x8,x12
    adc  x16,xzr,xzr           /* carry (257th bit) */
    /* load n limbs (rev to true values) into x5..x7,x18 */
    adrp x4,NBYTES
    add  x4,x4,:lo12:NBYTES
    ldr  x5,[x4];  rev x5,x5            /* n0 */
    ldr  x6,[x4,#8]; rev x6,x6           /* n1 */
    ldr  x7,[x4,#16]; rev x7,x7          /* n2 */
    ldr  x18,[x4,#24]; rev x18,x18       /* n3 */
    cbnz x16,.b32_subn
    /* compare sum vs n (MSB-limb-first) */
    cmp  x0,x5
    b.hi .b32_subn
    b.lo .b32_store
    cmp  x1,x6
    b.hi .b32_subn
    b.lo .b32_store
    cmp  x2,x7
    b.hi .b32_subn
    b.lo .b32_store
    cmp  x3,x18
    b.lo .b32_store             /* sum < n -> keep */
.b32_subn:
    subs x3,x3,x18
    sbcs x2,x2,x7
    sbcs x1,x1,x6
    sbcs x0,x0,x5
.b32_store:
    rev  x0,x0
    str  x0,[x19]
    rev  x1,x1
    str  x1,[x19,#8]
    rev  x2,x2
    str  x2,[x19,#16]
    rev  x3,x3
    str  x3,[x19,#24]
    /* validate child key: 0 < k_i < n */
    mov  x0,x19
    bl   scalar_small_nonzero
    cbz  w0,.b32_invalid
    mov  w0,#1
    b    .b32_done
.b32_invalid:
    mov  w0,#0
.b32_done:
    add  sp,sp,#0x100
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size bip32_ckd_priv,.-bip32_ckd_priv

/* ============ bip32_derive_path(k=x0, c=x1, seed=x2, seedlen=x3, idx=x4, n=x5) ============ */
    .global bip32_derive_path
    .type bip32_derive_path,%function
bip32_derive_path:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    sub  sp,sp,#0x10
    mov  x29,sp
    mov  x19,x0                /* k */
    mov  x20,x1                /* c */
    mov  x21,x2                /* seed */
    mov  x22,x3                /* seedlen */
    mov  x23,x4                /* indexes */
    mov  x24,x5                /* n */
    /* master */
    mov  x0,x19
    mov  x1,x20
    mov  x2,x21
    mov  x3,x22
    bl   bip32_master
    cbz  w0,.b32d_fail
    mov  x25,#0                /* cur */
.b32d_loop:
    cmp  x25,x24
    b.hs .b32d_ok
    ldr  w8,[x23,x25,lsl#2]    /* index (native LE u32) */
    mov  x0,x19                /* k out */
    mov  x1,x20                /* c out */
    mov  x2,x19                /* k_par */
    mov  x3,x20                /* c_par */
    mov  w4,w8                 /* index */
    bl   bip32_ckd_priv
    cbz  w0,.b32d_fail
    add  x25,x25,#1
    b    .b32d_loop
.b32d_ok:
    mov  w0,#1
    b    .b32d_done
.b32d_fail:
    mov  w0,#0
.b32d_done:
    add  sp,sp,#0x10
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size bip32_derive_path,.-bip32_derive_path

/* ================= bip32_fingerprint(fp=x0, pub=x1) ================= */
    .global bip32_fingerprint
    .type bip32_fingerprint,%function
bip32_fingerprint:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    sub  sp,sp,#0x30
    mov  x29,sp
    mov  x19,x0                /* fp kept in CALLEE-SAVED reg (hash160 clobbers x9) */
    add  x0,sp,#0x10           /* h160 */
    mov  x1,x1
    mov  x2,#33
    bl   hash160
    ldr  w8,[sp,#0x10]
    str  w8,[x19]
    add  sp,sp,#0x30
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size bip32_fingerprint,.-bip32_fingerprint

/* ========= bip32_extkey_serialize(ser=x0, is_priv=w1, depth=x2, fp=x3, child=w4, c=x5, key=x6, keylen=x7) ========= */
    .global bip32_extkey_serialize
    .type bip32_extkey_serialize,%function
bip32_extkey_serialize:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                /* ser */
    mov  x20,x1                /* is_priv */
    /* version */
    tbz  w20,#0,.v_pub
    b    .v_pub
    /* version bytes written one at a time in BE order (a plain 32-bit st to
     * LE memory would emit them reversed). */
.v_pub:
    mov  w8,#0x04
    strb w8,[x19,#0]
    tbz  w20,#0,.v2_pub
    mov  w8,#0x88
    strb w8,[x19,#1]
    mov  w8,#0xAD
    strb w8,[x19,#2]
    mov  w8,#0xE4
    strb w8,[x19,#3]
    b    .v3_done
.v2_pub:
    mov  w8,#0x88
    strb w8,[x19,#1]
    mov  w8,#0xB2
    strb w8,[x19,#2]
    mov  w8,#0x1E
    strb w8,[x19,#3]
.v3_done:
    strb w2,[x19,#4]           /* depth */
    ldr  w8,[x3]               /* parent fp (4 bytes verbatim) */
    str  w8,[x19,#5]
    /* child, big-endian at ser[9..12] */
    mov  w8,w4
    strb w8,[x19,#12]
    lsr  w8,w8,#8
    strb w8,[x19,#11]
    lsr  w8,w8,#8
    strb w8,[x19,#10]
    lsr  w8,w8,#8
    strb w8,[x19,#9]
    /* chain code c -> ser[13..44] */
    add  x0,x19,#13
    mov  x1,x5
    mov  x2,#32
    bl   __b32_copy
    /* key data */
    tbz  w20,#0,.k_pub
    strb wzr,[x19,#45]         /* 0x00 pad */
    add  x0,x19,#46
    mov  x1,x6
    mov  x2,x7
    bl   __b32_copy
    b    .done
.k_pub:
    add  x0,x19,#45
    mov  x1,x6
    mov  x2,x7
    bl   __b32_copy
.done:
    mov  w0,#78
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size bip32_extkey_serialize,.-bip32_extkey_serialize

/* ---------- internal helpers ----------
 * __b32_copy(dst=x0, src=x1, n=x2): byte copy.
 * __b32_nonzero(x0=buf) -> w0 (1 if any byte non-zero). */
    .type __b32_copy,%function
__b32_copy:
    mov  x3,#0
.bc_l:
    cmp  x3,x2
    b.hs .bc_d
    ldrb w4,[x1,x3]
    strb w4,[x0,x3]
    add  x3,x3,#1
    b    .bc_l
.bc_d:
    ret
    .size __b32_copy,.-__b32_copy

    .type __b32_nonzero,%function
__b32_nonzero:
    mov  x1,#0
    mov  w2,#0
.bz_l:
    cmp  x1,#32
    b.hs .bz_d
    ldrb w3,[x0,x1]
    orr  w2,w2,w3
    add  x1,x1,#1
    b    .bz_l
.bz_d:
    cmp  w2,#0
    cset w0,ne
    ret
    .size __b32_nonzero,.-__b32_nonzero

    .section .note.GNU-stack,"",@progbits
