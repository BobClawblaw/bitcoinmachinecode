/* ============================================================================
 * bitcoin_addr.S -- wallet address generation (Mach-O AArch64).
 * Functional twin of asm/bitcoin_addr.asm (x86-64), branch bmc_osx.
 *
 *   void hash160(u8 out[20], const void *in, i64 len);
 *   void base58check_encode(char *out, const u8 *payload, i64 paylen);
 *
 * hash160 = RIPEMD-160(SHA-256(in)); base58check = the standard
 * double-SHA256-checksum base58 encoding with leading-zero '1' preservation.
 *
 * base58check contract (kept exactly):
 *   - paylen 0..78; paylen > 78 (unsigned compare, so negatives included)
 *     writes out[0] = 0 and returns without touching anything else.
 *   - an all-zero payload yields (paylen+4) '1's and no digits, exactly like
 *     the x86 divide loop (the zero-count path covers it; ndigits stays 0).
 *
 * Frame notes carried over from the x86 module's FINDING: buffers are sized
 * for the 78-byte extended key (data 82 bytes -> ~112 base58 digits) and
 * every buffer is disjoint here by construction (separate sp offsets), so
 * the x86's saved-register-overrun history cannot recur.
 *
 * Calls: sha256d (bitcoin_hash.S), sha256_full (sha256.S), ripemd160
 * (ripemd160_twin.c) -- all proven on this port.  Locals are sp-relative;
 * sp stays 16-aligned at every bl (48B save area + 0x180 locals = 432).
 * ==========================================================================*/

.section __TEXT,__text

.globl _hash160
_hash160:
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x19, x0                     // out (parked)
    mov     x20, x1                     // in
    mov     x21, x2                     // len
    sub     sp, sp, #48                 // sha256 digest at sp+0 (32 of 48 used)
    mov     x0, sp
    mov     x1, x20
    mov     x2, x21
    bl      _sha256_full
    mov     x0, x19
    mov     x1, sp
    mov     x2, #32
    bl      _ripemd160
    add     sp, sp, #48
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    ret

.globl _base58check_encode
_base58check_encode:
    // refuse a payload that would not fit data (unsigned: negatives caught)
    cmp     x2, #78
    b.ls    .bc_len_ok
    strb    wzr, [x0]
    ret
.bc_len_ok:
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x19, x0                     // out (parked; w19 never a temp)
    mov     x20, x1                     // payload (parked)
    mov     x21, x2                     // paylen (parked until +4)
    sub     sp, sp, #0x180
    //   data     sp+0x000 (96)   checksum sp+0x060 (32)
    //   work     sp+0x080 (96)   digitRev sp+0x0e0 (160)

    // ---- data[0..paylen) = payload ----
    mov     x9, #0
.bc_cp1:
    cmp     x9, x21
    b.hs    .bc_cp1_done
    ldrb    w10, [x20, x9]
    strb    w10, [sp, x9]
    add     x9, x9, #1
    b       .bc_cp1
.bc_cp1_done:
    // ---- checksum = sha256d(payload); data[paylen..+4] = its first 4 bytes ----
    add     x0, sp, #0x60
    mov     x1, x20
    mov     x2, x21
    bl      _sha256d
    add     x9, sp, #0x60
    ldr     w10, [x9]
    add     x14, sp, x21
    str     w10, [x14]
    add     x21, x21, #4                // total length (paylen + 4)

    // ---- count leading zero bytes of data ----
    mov     x10, #0                     // zcount
.bc_czl:
    cmp     x10, x21
    b.hs    .bc_czl_done
    ldrb    w9, [sp, x10]
    cbnz    w9, .bc_czl_done
    add     x10, x10, #1
    b       .bc_czl
.bc_czl_done:
    // ---- emit zcount leading '1's; x22 = out cursor (callee-saved park:
    //      w-temps below must not clobber it, the x11-cursor draft died to
    //      exactly that) ----
    mov     x22, #0
    mov     x9, #0
.bc_ez:
    cmp     x9, x10
    b.hs    .bc_ez_done
    mov     w12, #'1'
    strb    w12, [x19, x22]
    add     x22, x22, #1
    add     x9, x9, #1
    b       .bc_ez
.bc_ez_done:
    // ---- copy data -> work ----
    mov     x9, #0
.bc_bcopy:
    cmp     x9, x21
    b.hs    .bc_bcopy_done
    ldrb    w10, [sp, x9]
    add     x14, sp, #0x80
    strb    w10, [x14, x9]
    add     x9, x9, #1
    b       .bc_bcopy
.bc_bcopy_done:
    mov     x12, x21                    // work length
    mov     x13, #0                     // ndigits
.bc_divloop:
    // is work[0..len) all zero?
    add     x15, sp, #0x80
    mov     x9, #0
    mov     w14, #0                     // found-nonzero flag
.bc_iszero:
    cmp     x9, x12
    b.hs    .bc_iszero_done
    ldrb    w10, [x15, x9]
    cbz     w10, .bc_iszero_next
    mov     w14, #1
.bc_iszero_next:
    add     x9, x9, #1
    b       .bc_iszero
.bc_iszero_done:
    cbz     x14, .bc_divide_done
    // one division pass: MSB->LSB, cur = rem*256 + work[i];
    // work[i] = cur/58; rem = cur%58 (cur <= 57*256+255 fits w).
    mov     w9, #0                      // rem
    mov     x10, #0
    mov     w8, #58
.bc_dv:
    cmp     x10, x12
    b.hs    .bc_dv_done
    ldrb    w11, [x15, x10]             // b
    lsl     w14, w9, #8                 // rem * 256
    add     w11, w14, w11               // cur = rem*256 + b
    udiv    w14, w11, w8                // q = cur / 58
    msub    w9, w14, w8, w11            // rem = cur - q*58
    strb    w14, [x15, x10]             // work[i] = q
    add     x10, x10, #1
    b       .bc_dv
.bc_dv_done:
    // emit ALPHABET[rem] into digitRev[ndigits++]
    adrp    x10, .bc_alphabet@PAGE
    add     x10, x10, .bc_alphabet@PAGEOFF
    ldrb    w11, [x10, x9]              // x9 = rem (w9 write zeroed x9)
    add     x15, sp, #0xe0
    add     x15, x15, x13
    strb    w11, [x15]
    add     x13, x13, #1
    b       .bc_divloop
.bc_divide_done:
    // ---- reverse-copy ndigits chars into out after the '1's, then NUL ----
    add     x9, x19, x22
    add     x10, sp, #0xe0
    add     x10, x10, x13
.bc_rv:
    cbz     x13, .bc_rv_done
    sub     x13, x13, #1
    sub     x10, x10, #1
    ldrb    w11, [x10]
    strb    w11, [x9], #1
    b       .bc_rv
.bc_rv_done:
    strb    wzr, [x9]
    add     sp, sp, #0x180
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    ret

.section __TEXT,__const
.bc_alphabet:
    .ascii "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
