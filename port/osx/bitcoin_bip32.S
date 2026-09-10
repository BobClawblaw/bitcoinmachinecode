/* ============================================================================
 * bitcoin_bip32.S -- BIP32 hierarchical-deterministic key management
 * (Mach-O AArch64).  Functional twin of asm/bitcoin_bip32.asm (x86-64).
 *
 *   int  bip32_master(u8 k[32], u8 c[32], const u8* seed, i64 seedlen);
 *   int  bip32_ckd_priv(u8 k[32], u8 c[32], const u8 k_par[32],
 *                       const u8 c_par[32], u32 index);
 *   int  bip32_derive_path(u8 k[32], u8 c[32], const u8* seed, i64 seedlen,
 *                          const u32* indexes, i64 n);
 *   void bip32_fingerprint(u8 fp[4], const u8 pub[33]);
 *   int  bip32_extkey_serialize(u8 ser[78], int is_priv, u8 depth,
 *                               const u8 parent_fp[4], u32 child,
 *                               const u8 c[32], const u8* key, i64 keylen);
 *
 * master = HMAC-SHA512("Bitcoin seed", seed): k = I[0..31], c = I[32..63];
 * returns k != 0.  ckd_priv: hardened (index bit31) data = 0x00 || k_par,
 * normal data = ser256(K_par); I = HMAC-SHA512(c_par, data||ser32(index));
 * invalid unless 0 < IL < n; k_i = (IL + k_par) mod n (byte-wise carry /
 * borrow chains -- the low 32 bytes are correct even for the 257-bit carry
 * case, as in the x86); c_i = IR; returns 0 if k_i is 0 or >= n.
 * derive_path: master, then in-place ckd_priv per u32 index (the array is
 * native-endian u32s; hardened indexes arrive OR'd with 0x80000000).
 * fingerprint = HASH160(pub)[0..3].  extkey_serialize builds the 78-byte
 * xprv/xpub payload; key/keylen arrive in x6/x7 -- AAPCS64 passes up to
 * eight args in registers, where the x86 SysV ABI (six registers) spilled
 * them to stack slots [rbp+16]/[rbp+24].
 *
 * Calls (all proven on this port): hmac_sha512 (bitcoin_hmac.S),
 * scalar_to_pubkey + scalar_small_nonzero (bitcoin_keys.S), hash160
 * (bitcoin_addr.S), sha256d/sha256_full (bitcoin_hash.S/sha256.S).
 *
 * Darwin pitfalls honoured: sp 16-aligned at every bl (save areas 48/64B +
 * locals multiples of 16); no x18/x28; w-temps never touch parked x19-x23
 * halves; fixed-width rodata in __TEXT,__const.
 * ==========================================================================*/

.section __TEXT,__text

/* ------------------------------------------------------------------ master */
.globl _bip32_master
_bip32_master:
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x19, x0                     // k out (parked)
    mov     x20, x1                     // c out (parked)
    mov     x21, x2                     // seed
    mov     x22, x3                     // seedlen
    sub     sp, sp, #64                 // I (64B) at sp+0
    mov     x0, sp
    adrp    x1, .bc_seedkey@PAGE
    add     x1, x1, .bc_seedkey@PAGEOFF
    mov     x2, #12
    mov     x3, x21
    mov     x4, x22
    bl      _hmac_sha512
    // k = I[0..31]
    mov     x9, #0
.m_kcp:
    cmp     x9, #32
    b.hs    .m_kcp_done
    ldrb    w10, [sp, x9]
    strb    w10, [x19, x9]
    add     x9, x9, #1
    b       .m_kcp
.m_kcp_done:
    // c = I[32..63]
    add     x11, sp, #32
    mov     x9, #0
.m_ccp:
    cmp     x9, #32
    b.hs    .m_ccp_done
    ldrb    w10, [x11, x9]
    strb    w10, [x20, x9]
    add     x9, x9, #1
    b       .m_ccp
.m_ccp_done:
    // return k != 0
    mov     w9, #0
    mov     w10, #0
.m_zk:
    cmp     w10, #32
    b.hs    .m_zk_done
    ldrb    w11, [x19, x10]
    orr     w9, w9, w11
    add     w10, w10, #1
    b       .m_zk
.m_zk_done:
    cmp     w9, #0
    cset    w0, ne
    add     sp, sp, #64
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    ret

/* --------------------------------------------------------------- ckd_priv */
.globl _bip32_ckd_priv
_bip32_ckd_priv:
    // save area 64B: x29,x30 @0/8, x19,x20 @16/24, x21,x22 @32/40,
    //                x23,x24 @48/56
    stp     x29, x30, [sp, #-64]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    mov     x19, x0                     // k out
    mov     x20, x1                     // c out
    mov     x21, x2                     // k_par
    mov     x22, x3                     // c_par
    mov     w23, w4                     // index
    sub     sp, sp, #0xe0
    //   inp sp+0x000 (40, 37 used)   I sp+0x030 (64)
    //   kpar sp+0x070 (32)           sum sp+0x090 (32)
    //   pub sp+0x0b0 (40, 33 used -> ends 0xd1, inside the 0xe0 local
    //   reservation; the save area starts at 0xe0)
    tbz     w23, #31, .ck_normal
    // ---- hardened: 0x00 || ser256(k_par) ----
    strb    wzr, [sp]
    add     x11, sp, #1
    mov     x9, #0
.ck_h:
    cmp     x9, #32
    b.hs    .ck_inp
    ldrb    w10, [x21, x9]
    strb    w10, [x11, x9]
    add     x9, x9, #1
    b       .ck_h
.ck_normal:
    // ---- normal: ser256(K_par) via scalar_to_pubkey ----
    add     x0, sp, #0xb0
    mov     x1, x21
    bl      _scalar_to_pubkey
    mov     x9, #0
.ck_n:
    cmp     x9, #33
    b.hs    .ck_inp
    add     x11, sp, #0xb0
    ldrb    w10, [x11, x9]
    strb    w10, [sp, x9]
    add     x9, x9, #1
    b       .ck_n
.ck_inp:
    // ---- append ser32(index), big-endian, at inp[33..36] ----
    add     x11, sp, #33
    mov     w9, w23
    strb    w9, [x11, #3]               // LSB
    lsr     w9, w9, #8
    strb    w9, [x11, #2]
    lsr     w9, w9, #8
    strb    w9, [x11, #1]
    lsr     w9, w9, #8
    strb    w9, [x11]                   // MSB
    // ---- I = HMAC-SHA512(c_par, inp, 37) ----
    add     x0, sp, #0x30
    mov     x1, x22
    mov     x2, #32
    mov     x3, sp
    mov     x4, #37
    bl      _hmac_sha512
    // ---- IL must be nonzero ----
    add     x0, sp, #0x30
    bl      _scalar_small_nonzero
    cbz     w0, .ck_invalid
    // ---- snapshot k_par (kpar local) ----
    mov     x9, #0
.ck_kp:
    cmp     x9, #32
    b.hs    .ck_kp_done
    ldrb    w10, [x21, x9]
    add     x11, sp, #0x70
    strb    w10, [x11, x9]
    add     x9, x9, #1
    b       .ck_kp
.ck_kp_done:
    // ---- c_out = IR (I[32..63]) ----
    add     x11, sp, #0x30
    add     x11, x11, #32
    mov     x9, #0
.ck_ic:
    cmp     x9, #32
    b.hs    .ck_ic_done
    ldrb    w10, [x11, x9]
    strb    w10, [x20, x9]
    add     x9, x9, #1
    b       .ck_ic
.ck_ic_done:
    // ---- sum = IL + k_par, byte-wise LSB-first with carry ----
    // countdown-from-32: the body runs for x11 = 31..0 inclusive (a
    // `mov x11,#31` + post-decrement cbnz shape skips byte 0, which leaves
    // the carry INTO byte 0 in w9 -- a phantom 257th bit -- and a stale
    // sum[0]; both downstream bugs at once).
    mov     w9, #0                      // carry
    mov     x11, #32
.ck_add:
    sub     x11, x11, #1                // x11 = 31..0
    add     x12, sp, #0x30
    ldrb    w13, [x12, x11]             // IL byte
    add     x12, sp, #0x70
    ldrb    w14, [x12, x11]             // kpar byte
    add     w13, w13, w14
    add     w13, w13, w9
    lsr     w9, w13, #8                 // new carry
    and     w13, w13, #0xff
    add     x12, sp, #0x90
    strb    w13, [x12, x11]
    cbnz    x11, .ck_add
    // carry set -> sum >= 2^256 > n -> subtract; else compare against n
    cbz     x9, .ck_cmpn
    b       .ck_subn
.ck_cmpn:
    adrp    x10, .bc_nbytes@PAGE
    add     x10, x10, .bc_nbytes@PAGEOFF
    add     x12, sp, #0x90
    mov     x11, #0
.ck_cmp:
    cmp     x11, #32
    b.hs    .ck_subn                    // all equal (sum == n) -> subtract
    ldrb    w13, [x12, x11]
    ldrb    w14, [x10, x11]
    cmp     w13, w14
    b.lo    .ck_store                   // sum < n -> keep
    b.hi    .ck_subn                    // sum > n -> subtract
    add     x11, x11, #1
    b       .ck_cmp
.ck_subn:
    // ---- sum -= n: byte-wise borrow chain from the LSB (x11 = 31..0, same
    //      countdown shape as the add).  For the 257-bit carry case the low
    //      32 bytes of (sum - n) are (w - n) mod 2^256, which is exactly
    //      what this chain computes. ----
    adrp    x10, .bc_nbytes@PAGE
    add     x10, x10, .bc_nbytes@PAGEOFF
    mov     w9, #0                      // borrow
    mov     x11, #32
.ck_sub:
    sub     x11, x11, #1
    add     x12, sp, #0x90
    ldrb    w13, [x12, x11]
    ldrb    w14, [x10, x11]
    sub     w13, w13, w14
    sub     w13, w13, w9
    cmp     w13, #0
    cset    w9, lt                      // borrow out
    and     w13, w13, #0xff
    strb    w13, [x12, x11]
    cbnz    x11, .ck_sub
.ck_store:
    // ---- copy sum -> k_out, then validate 0 < k_i < n ----
    mov     x9, #0
.ck_oc:
    cmp     x9, #32
    b.hs    .ck_oc_done
    add     x12, sp, #0x90
    ldrb    w10, [x12, x9]
    strb    w10, [x19, x9]
    add     x9, x9, #1
    b       .ck_oc
.ck_oc_done:
    mov     x0, x19
    bl      _scalar_small_nonzero
    cbz     w0, .ck_invalid
    mov     w0, #1
    b       .ck_done
.ck_invalid:
    mov     w0, #0
.ck_done:
    add     sp, sp, #0xe0
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #64
    ret

/* ------------------------------------------------------------ derive_path */
.globl _bip32_derive_path
_bip32_derive_path:
    stp     x29, x30, [sp, #-64]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    mov     x19, x0                     // k (in/out)
    mov     x20, x1                     // c (in/out)
    mov     x21, x4                     // indexes
    mov     x22, x5                     // n
    // master: x2/x3 (seed, seedlen) already in place
    mov     x0, x19
    mov     x1, x20
    bl      _bip32_master
    cbz     w0, .dp_fail
    mov     x23, #0
.dp_loop:
    cmp     x23, x22
    b.hs    .dp_ok
    // indexes[cur]: u32, native-endian, hardened already OR'd
    ldr     w24, [x21, x23, lsl #2]
    // in-place child derivation (ckd_priv snapshots its inputs first)
    mov     x0, x19
    mov     x1, x20
    mov     x2, x19
    mov     x3, x20
    mov     w4, w24
    bl      _bip32_ckd_priv
    cbz     w0, .dp_fail
    add     x23, x23, #1
    b       .dp_loop
.dp_ok:
    mov     w0, #1
    b       .dp_done
.dp_fail:
    mov     w0, #0
.dp_done:
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #64
    ret

/* ------------------------------------------------------------ fingerprint */
.globl _bip32_fingerprint
_bip32_fingerprint:
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x19, x0                     // fp out
    mov     x20, x1                     // pub
    sub     sp, sp, #32                 // h160 (20 of 32 used) at sp+0
    mov     x0, sp
    mov     x1, x20
    mov     x2, #33
    bl      _hash160
    ldr     w9, [sp]
    str     w9, [x19]
    add     sp, sp, #32
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    ret

/* ----------------------------------------------------- extkey_serialize */
.globl _bip32_extkey_serialize
_bip32_extkey_serialize:
    // key/keylen arrive in x6/x7 (register args 7/8 under AAPCS64; no bl
    // in this body so they survive from entry)
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x19, x0                     // ser out
    mov     w20, w1                     // is_priv
    mov     w21, w2                     // depth
    mov     x22, x3                     // parent_fp
    // x4 = child, x5 = c -- no bl in this body, caller-saved regs stay put
    // ---- version: 0x0488ADE4 xprv / 0x0488B21E xpub ----
    cbz     w20, .es_vpub
    mov     w9, #0x04
    strb    w9, [x19]
    mov     w9, #0x88
    strb    w9, [x19, #1]
    mov     w9, #0xAD
    strb    w9, [x19, #2]
    mov     w9, #0xE4
    strb    w9, [x19, #3]
    b       .es_vdone
.es_vpub:
    mov     w9, #0x04
    strb    w9, [x19]
    mov     w9, #0x88
    strb    w9, [x19, #1]
    mov     w9, #0xB2
    strb    w9, [x19, #2]
    mov     w9, #0x1E
    strb    w9, [x19, #3]
.es_vdone:
    strb    w21, [x19, #4]              // depth
    ldr     w9, [x22]                   // parent fingerprint, verbatim
    str     w9, [x19, #5]
    // ---- child number, big-endian ----
    mov     w9, w4
    strb    w9, [x19, #12]              // LSB
    lsr     w9, w9, #8
    strb    w9, [x19, #11]
    lsr     w9, w9, #8
    strb    w9, [x19, #10]
    lsr     w9, w9, #8
    strb    w9, [x19, #9]               // MSB
    // ---- chain code (32 bytes) ----
    mov     x9, #0
.es_cc:
    cmp     x9, #32
    b.hs    .es_cc_done
    ldrb    w10, [x5, x9]
    add     x11, x19, #13
    strb    w10, [x11, x9]
    add     x9, x9, #1
    b       .es_cc
.es_cc_done:
    // ---- key data ----
    cbz     w20, .es_kpub
    // priv: ser[45] = 0x00, key at 46..77
    strb    wzr, [x19, #45]
    mov     x9, #0
.es_kp:
    cmp     x9, x7
    b.hs    .es_done
    ldrb    w10, [x6, x9]
    add     x11, x19, #46
    strb    w10, [x11, x9]
    add     x9, x9, #1
    b       .es_kp
.es_kpub:
    // pub: 33-byte compressed pubkey at 45..77
    mov     x9, #0
.es_kq:
    cmp     x9, x7
    b.hs    .es_done
    ldrb    w10, [x6, x9]
    add     x11, x19, #45
    strb    w10, [x11, x9]
    add     x9, x9, #1
    b       .es_kq
.es_done:
    mov     w0, #78
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    ret

.section __TEXT,__const
.bc_seedkey:
    .ascii "Bitcoin seed"
.bc_nbytes:
    /* secp256k1 n, big-endian byte order */
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE
    .byte 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B
    .byte 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
