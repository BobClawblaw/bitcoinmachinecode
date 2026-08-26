/* bitcoin_addr.S -- AArch64 port of asm/bitcoin_addr.asm (AAPCS64).
 *
 * Exported (identical to x86 original):
 *   void hash160(u8 out[20], const void* in, u64 len)
 *        = RIPEMD-160( SHA-256(in) )
 *   void base58check_encode(char* out, const u8* payload, u64 paylen)
 *        = Bitcoin base58check string (version||hash160, paylen 0..78)
 *
 * Deps (all verified ports): sha256_full (sha256.S), sha256d (bitcoin_hash.S),
 * ripemd160 (ripemd160.S).
 */
    .text

/* ---------- hash160 ---------- */
    .global hash160
    .type hash160,%function
hash160:
    /* frame 0x50. x29/x30@0, x19/x20@16, x21@32, h[32]@40..71 (NO overlap). */
    sub  sp,sp,#0x50
    stp  x29,x30,[sp,#0x00]
    stp  x19,x20,[sp,#0x10]
    str  x21,[sp,#0x20]
    mov  x29,sp
    mov  x19,x0               /* out   */
    mov  x20,x1               /* in    */
    mov  x21,x2               /* len   */
    add  x0,sp,#40            /* h out */
    mov  x1,x20
    mov  x2,x21
    bl   sha256_full
    mov  x0,x19               /* out   */
    add  x1,sp,#40            /* h     */
    mov  x2,#32
    bl   ripemd160
    ldr  x21,[sp,#0x20]
    ldp  x19,x20,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x50
    ret
    .size hash160,.-hash160

/* ---------- base58check_encode ---------- */
    .section .rodata
    .p2align 4
ALPHABET:
    .ascii "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    .text

    .global base58check_encode
    .type base58check_encode,%function
base58check_encode:
    /* frame 0x240. saved regs at [sp,#0x00..0x3F]; locals below:
     *   data     = sp+#0x40  (96)
     *   checksum = sp+#0xA0  (32)
     *   work     = sp+#0xC0  (96)
     *   digitRev = sp+#0x130 (160)
     * Persistent: x19=out x20=payload x21=len(then total) x22=ndigits
     *             x23=leading-''1'' count  x24=out-cursor-after-''1''s
     */
    sub  sp,sp,#0x240
    stp  x29,x30,[sp,#0x00]
    stp  x19,x20,[sp,#0x10]
    stp  x21,x22,[sp,#0x20]
    stp  x23,x24,[sp,#0x30]
    mov  x29,sp

    /* ---- refuse a payload that won't fit `data` (unsigned cmp => neg caught) */
    cmp  x2,#78
    b.hi .adr_len_bad
    mov  x19,x0               /* out    */
    mov  x20,x1               /* payload */
    mov  x21,x2               /* paylen */

    /* ---- data[0..paylen) = payload ---- */
    add  x12,sp,#0x40         /* data */
    mov  x13,x21
    mov  x8,#0
.adr_cp1:
    cmp  x8,x13
    b.hs .adr_cp1_done
    ldrb w9,[x20,x8]
    strb w9,[x12,x8]
    add  x8,x8,#1
    b    .adr_cp1
.adr_cp1_done:
    /* ---- checksum = sha256d(checksum, payload, paylen) ---- */
    add  x0,sp,#0xA0
    mov  x1,x20
    mov  x2,x21
    bl   sha256d
    /* ---- append first 4 checksum bytes at data+paylen ---- */
    add  x8,sp,#0xA0
    ldr  x9,[x8]
    add  x10,sp,#0x40
    add  x10,x10,x21
    str  w9,[x10]
    /* ---- total length = paylen + 4 ---- */
    add  x21,x21,#4

    /* ---- count leading zero bytes of data -> x9 ---- */
    add  x8,sp,#0x40
    mov  x9,#0
.adr_czl:
    cmp  x9,x21
    b.hs .adr_czl_done
    ldrb w10,[x8,x9]
    cbnz w10,.adr_czl_done
    add  x9,x9,#1
    b    .adr_czl
.adr_czl_done:
    mov  x23,x9               /* leading ''1''s = first zero bytes */

    /* ---- emit x23 leading ''1''s; x24 = out cursor ---- */
    mov  x10,#0
    mov  x11,#0
.adr_ez:
    cmp  x11,x23
    b.hs .adr_ez_done
    mov  w12,#'1'
    strb w12,[x19,x10]
    add  x10,x10,#1
    add  x11,x11,#1
    b    .adr_ez
.adr_ez_done:
    mov  x24,x10 

    /* ---- copy data(tot len x21) -> work ---- */
    add  x8,sp,#0xC0          /* work  */
    add  x9,sp,#0x40          /* data  */
    mov  x11,#0
.adr_bcopy:
    cmp  x11,x21
    b.hs .adr_bcopy_done
    ldrb w12,[x9,x11]
    strb w12,[x8,x11]
    add  x11,x11,#1
    b    .adr_bcopy
.adr_bcopy_done:
    mov  x22,#0               /* ndigits */
    /* x14 = length of work number (= total) */
    mov  x14,x21
.adr_divloop:
    add  x8,sp,#0xC0          /* work */
    mov  x11,#0
    mov  x12,#0               /* nonzero flag */
.adr_iszero:
    cmp  x11,x14
    b.hs .adr_iszero_done
    ldrb w13,[x8,x11]
    cbnz w13,.adr_one
    add  x11,x11,#1
    b    .adr_iszero
.adr_one:
    mov  x12,#1
.adr_iszero_done:
    cbz  x12,.adr_divide_done
    /* ---- divide work by 58 MSB->LSB; remainder -> base58 digit ---- */
    add  x8,sp,#0xC0          /* work */
    mov  x9,#0                /* rem  */
    mov  x11,#0
.adr_dv:
    cmp  x11,x14
    b.hs .adr_dv_done
    ldrb w10,[x8,x11]         /* b   */
    mov  x15,#256
    mul  x9,x9,x15
    add  x9,x9,x10
    mov  x15,#58
    udiv x16,x9,x15           /* quotient */
    msub x10,x16,x15,x9       /* remainder = x9 - q*58 */
    strb w16,[x8,x11]         /* store quotient byte back */
    mov  x9,x10
    add  x11,x11,#1
    b    .adr_dv
.adr_dv_done:
    /* x9 = remainder = index into ALPHABET */
    adrp x8, ALPHABET
    add  x8,x8,:lo12:ALPHABET
    ldrb w10,[x8,x9]          /* base58 char */
    add  x11,sp,#0x130        /* digitRev */
    strb w10,[x11,x22]        /* digitRev[ndigits] (LSB-first) */
    add  x22,x22,#1
    b    .adr_divloop
.adr_divide_done:
    /* ---- reverse-copy x22 chars from digitRev into out after the ''1''s ---- */
    add  x0,x19,x24           /* out + leading-''1'' cursor */
    add  x1,sp,#0x130         /* digitRev */
    mov  x8,x22               /* count */
.adr_rv:
    cbz  x8,.adr_rv_done
    sub  x8,x8,#1
    ldrb w9,[x1,x8]
    strb w9,[x0]
    add  x0,x0,#1
    b    .adr_rv
.adr_rv_done:
    mov  w9,#0
    strb w9,[x0]              /* NUL terminate */

    /* ---- epilogue ---- */
    ldp  x23,x24,[sp,#0x30]
    ldp  x21,x22,[sp,#0x20]
    ldp  x19,x20,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x240
    ret

.adr_len_bad:
    mov  w9,#0
    strb w9,[x0]              /* out[0]=0, len too big */
    ldp  x23,x24,[sp,#0x30]
    ldp  x21,x22,[sp,#0x20]
    ldp  x19,x20,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x240
    ret
    .size base58check_encode,.-base58check_encode

    .section .note.GNU-stack,"",@progbits
