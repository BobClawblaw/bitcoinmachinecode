/* ============================================================================
 * bitcoin_keys.S -- secp256k1 key derivation helper (Mach-O AArch64).
 * Functional twin of asm/bitcoin_keys.asm (x86-64), branch bmc_osx.
 *
 *   int  scalar_small_nonzero(const u8 k[32]);       w0
 *   void scalar_to_pubkey(u8 pub[33], const u8 k[32]);   x0, x1
 *
 * scalar_small_nonzero: OR of all 32 bytes nonzero, then byte-wise compare
 * against big-endian n.  NOTE (transcribed x86 behavior, kept verbatim):
 * when every byte of k equals n's bytes (k == n) the x86 compare loop
 * falls through to .ok and returns 1 -- the "< n" half of the range check
 * is really "<= n" for that single input.  Production callers parse
 * scalars < n out of signatures/derivation, so it is latent there too;
 * this twin matches the x86 exactly.  An x86 fix, if wanted, belongs on
 * main first.
 *
 * scalar_to_pubkey: pub = compressed secp256k1 pubkey of secret scalar k:
 *   limbs[j] = bswap64(load64(k + (3-j)*8))      BE bytes -> 4 LE limbs
 *   point = point_scalar_mul_ct(G, k)            (CT ladder: k is SECRET)
 *   z2 = Z^2, z3 = Z*z2, inv2 = 1/z2, inv3 = 1/z3
 *   ax = X*inv2, ay = Y*inv3
 *   pub[0] = 0x02 | (ay limb0 & 1); pub[1..32] = ax bytes reversed to BE.
 *
 * Calls (AAPCS64, all proven on this port):
 *   point_scalar_mul_ct (point_ct_twin.c), fe_mul/fe_sqr/fe_inv (fe_twin.c).
 *
 * Darwin pitfalls honoured here: sp 16-aligned at every bl (stp x29,x30
 * prologue); no x18/x28; w-regs never touch parked x19/x20 halves; data
 * tables in __TEXT,__const (not __cstring -- tail merging).
 * ==========================================================================*/

.section __TEXT,__text

.globl _scalar_small_nonzero
_scalar_small_nonzero:
    // OR all 32 bytes; zero -> 0
    mov     w9, #0
    mov     w10, #0
.Lnz_or:
    ldrb    w11, [x0, x10]
    orr     w9, w9, w11
    add     w10, w10, #1
    cmp     w10, #32
    b.lt    .Lnz_or
    cbz     x9, .Lnz_bad                // all-zero scalar
    // byte-wise compare against N_BE
    adrp    x1, _N_BE@PAGE
    add     x1, x1, _N_BE@PAGEOFF
    mov     w10, #0
.Lnz_cmp:
    ldrb    w11, [x0, x10]
    ldrb    w12, [x1, x10]
    cmp     w11, w12
    b.lo    .Lnz_ok                     // first differing byte < n -> k < n
    b.hi    .Lnz_bad                    // first differing byte > n -> k > n
    add     w10, w10, #1
    cmp     w10, #32
    b.lt    .Lnz_cmp
    // all 32 equal (k == n): the x86 loop exits via `jae .ok` -> 1.
.Lnz_ok:
    mov     w0, #1
    ret
.Lnz_bad:
    mov     w0, #0
    ret

.globl _scalar_to_pubkey
_scalar_to_pubkey:
    // save area 48B: x29,x30 @0/8, x19,x20 @16/24, x21,x22 @32/40
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x19, x0                     // pub (parked; w19 never used)
    mov     x20, x1                     // k   (parked; w20 never used)
    sub     sp, sp, #0x140              // locals (16-aligned: 48+320=368)
    //   limbs sp+0x000 (32)   point sp+0x020 (96)
    //   z2    sp+0x080 (32)   z3    sp+0x0a0 (32)
    //   inv2  sp+0x0c0 (32)   inv3  sp+0x0e0 (32)
    //   ax    sp+0x100 (32)   ay    sp+0x120 (32)

    // ---- k (32 BE bytes) -> 4 LE limbs: limb j = bswap(load64(k+(3-j)*8)) ----
    ldr     x9, [x20, #24]
    rev     x9, x9
    str     x9, [sp, #0]
    ldr     x9, [x20, #16]
    rev     x9, x9
    str     x9, [sp, #8]
    ldr     x9, [x20, #8]
    rev     x9, x9
    str     x9, [sp, #16]
    ldr     x9, [x20, #0]
    rev     x9, x9
    str     x9, [sp, #24]

    // ---- point = k * G (constant-time ladder; k is secret) ----
    add     x0, sp, #0x20               // r (12-limb Jacobian)
    adrp    x1, _G_AFF@PAGE
    add     x1, x1, _G_AFF@PAGEOFF      // affine (X,Y) 8 limbs
    mov     x2, sp                      // k limbs
    bl      _point_scalar_mul_ct

    // ---- affinize: z2 = Z^2 (Z at point+64) ----
    add     x0, sp, #0x80
    add     x1, sp, #0x20
    add     x1, x1, #64
    bl      _fe_sqr
    // z3 = Z * z2
    add     x0, sp, #0xa0
    add     x1, sp, #0x20
    add     x1, x1, #64
    add     x2, sp, #0x80
    bl      _fe_mul
    // inv2 = 1/z2, inv3 = 1/z3
    add     x0, sp, #0xc0
    add     x1, sp, #0x80
    bl      _fe_inv
    add     x0, sp, #0xe0
    add     x1, sp, #0xa0
    bl      _fe_inv
    // ax = X * inv2 (X at point+0), ay = Y * inv3 (Y at point+32)
    add     x0, sp, #0x100
    add     x1, sp, #0x20
    add     x2, sp, #0xc0
    bl      _fe_mul
    add     x0, sp, #0x120
    add     x1, sp, #0x20
    add     x1, x1, #32
    add     x2, sp, #0xe0
    bl      _fe_mul

    // ---- serialize ax to big-endian pub[1..32] ----
    // limb j little-endian bytes extracted LSB-first; byte i (LE order,
    // i = j*8+b) lands at pub[1 + (31-i)] = pub[32-i].  Countdown t=32..1.
    add     x10, sp, #0x100
    mov     x16, #32                    // target index t (x16, never w16)
    mov     w22, #0                     // limb counter (x21/x22 saved above)
.Lser_limb:
    ldr     x13, [x10], #8
    mov     w14, #8
.Lser_byte:
    and     w15, w13, #0xff
    strb    w15, [x19, x16]
    lsr     x13, x13, #8
    sub     x16, x16, #1
    subs    w14, w14, #1
    b.ne    .Lser_byte
    add     w22, w22, #1                // limb counter (w22 spare: x21/x22 saved)
    cmp     w22, #4
    b.lt    .Lser_limb

    // ---- prefix: 0x02 if ay even else 0x03; written last like the x86 ----
    ldr     x9, [sp, #0x120]            // ay limb 0
    tbz     x9, #0, .Lpre_even
    mov     w10, #3
    b       .Lpre_store
.Lpre_even:
    mov     w10, #2
.Lpre_store:
    strb    w10, [x19]

    add     sp, sp, #0x140
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    ret

.section __TEXT,__const
.align 8
_G_AFF:
    /* X: 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 */
    .quad 0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC
    /* Y: 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8 */
    .quad 0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465
.align 8
_N_BE:
    /* secp256k1 n, big-endian byte order (same bytes as the x86 N_BE) */
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE
    .byte 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B
    .byte 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
