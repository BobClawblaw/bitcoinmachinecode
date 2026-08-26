/* bitcoin_hmac.S -- AArch64 port of asm/bitcoin_hmac.asm (AAPCS64).
 *   void hmac_sha512(u8 out[64], const u8* key, i64 keylen,
 *                    const u8* msg, i64 msglen)
 * Uses global .bss scratch (kpad[128], tmp[1160]) exactly like the x86.
 * Dep: sha512_full (sha512.S).
 */
    .bss
    .p2align 4
kpad:
    .space 128
    .p2align 4
tmp:
    .space 1160
    .text

    .global hmac_sha512
    .type hmac_sha512,%function
hmac_sha512:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                 /* out   */
    mov  x20,x1                 /* key   */
    mov  x21,x2                 /* keylen (later effective) */
    mov  x22,x3                 /* msg   */
    mov  x23,x4                 /* msglen */

    /* ---- effective key: if keylen > 128, K = SHA512(key) (64 B) ---- */
    cmp  x21,#128
    b.le .keyok
    adrp x7,tmp
    add  x7,x7,:lo12:tmp
    mov  x0,x7                  /* out = tmp */
    mov  x1,x20
    mov  x2,x21
    bl   sha512_full
    mov  x21,#64                /* effective keylen = 64 */
    adrp x7,tmp
    add  x7,x7,:lo12:tmp
    mov  x20,x7                 /* effective key = tmp digest */
.keyok:

    adrp x24,kpad
    add  x24,x24,:lo12:kpad      /* x24 = kpad base */
    adrp x25,tmp
    add  x25,x25,:lo12:tmp       /* x25 = tmp base */

    /* ---- K' = effective key right-padded to 128 into kpad ---- */
    mov  x10,#0
.hkcp:
    cmp  x10,x21
    b.hs .hkcp_done
    ldrb w11,[x20,x10]
    strb w11,[x24,x10]
    add  x10,x10,#1
    b    .hkcp
.hkcp_done:
.hkz:
    cmp  x10,#128
    b.hs .hkz_done
    strb wzr,[x24,x10]
    add  x10,x10,#1
    b    .hkz
.hkz_done:

    /* ---- INNER: tmp[0..127] = K' XOR ipad(0x36); tmp[128..] = msg ---- */
    mov  x10,#0
.hxip:
    cmp  x10,#128
    b.hs .hxip_done
    ldrb w11,[x24,x10]
    mov  w12,#0x36
    eor  w11,w11,w12
    strb w11,[x25,x10]
    add  x10,x10,#1
    b    .hxip
.hxip_done:
    mov  x10,#0
.hmcp:
    cmp  x10,x23
    b.hs .hmcp_done
    ldrb w11,[x22,x10]
    add  x12,x25,#128
    strb w11,[x12,x10]
    add  x10,x10,#1
    b    .hmcp
.hmcp_done:
    /* inner_len = 128 + msglen ; inner digest = sha512_full(tmp, tmp, inner_len) */
    add  x2,x23,#128
    mov  x0,x25
    mov  x1,x25
    bl   sha512_full
    /* stash inner digest tmp[0..63] -> tmp[192..255] */
    mov  x10,#0
.hstash:
    cmp  x10,#64
    b.hs .hstash_done
    ldrb w11,[x25,x10]
    add  x13,x25,#192
    strb w11,[x13,x10]
    add  x10,x10,#1
    b    .hstash
.hstash_done:
    /* ---- OUTER: tmp[0..127] = K' XOR opad(0x5c) ---- */
    mov  x10,#0
.hxop:
    cmp  x10,#128
    b.hs .hxop_done
    ldrb w11,[x24,x10]
    mov  w12,#0x5c
    eor  w11,w11,w12
    strb w11,[x25,x10]
    add  x10,x10,#1
    b    .hxop
.hxop_done:
    /* copy tmp[192..255] -> tmp[128..191] */
    mov  x10,#0
.hicp:
    cmp  x10,#64
    b.hs .hicp_done
    add  x13,x25,#192
    ldrb w11,[x13,x10]
    add  x14,x25,#128
    strb w11,[x14,x10]
    add  x10,x10,#1
    b    .hicp
.hicp_done:
    /* out = sha512_full(out, tmp, 192) */
    mov  x0,x19
    mov  x1,x25
    mov  x2,#192
    bl   sha512_full

    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size hmac_sha512,.-hmac_sha512

    .section .note.GNU-stack,"",@progbits
