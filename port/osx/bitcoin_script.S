/* ============================================================================
 * bitcoin_script.S -- P2PKH spend validation and DER signature parsing in
 * AArch64 assembly (Apple silicon), the counterpart of asm/bitcoin_script.asm.
 * Replaces script_twin.c on the Mac (2026-09-26); the twin stays in
 * port/osx/test_support as the oracle.
 *
 *   int  der_parse_sig(const u8* sig, u64 slen, u64 r[4], u64 s[4],
 *                      u32* hashtype);
 *   void be_to_limbs(u64 out[4], const u8* bytes, u64 len);     len 0..32
 *   int  verify_p2pkh(const u8* tx, u64 txlen, u64 input_index,
 *                     const u8* prevout_script, u64 prevout_len,
 *                     u8* work, u64 cap);
 *
 * der_parse_sig is TOLERANT on purpose (pre-BIP66 history), as Core's
 * ecdsa_signature_parse_der_lax: a long-form SEQUENCE length is skipped
 * unread; a long-form INTEGER length skips leading zero length bytes, is
 * rejected at >= 4 significant length bytes, then accumulates big-endian;
 * any number of redundant leading 0x00 value bytes is stripped down to 32;
 * a zero length is rejected; the s marker is looked for at the stripped r
 * base + stripped r length (the same address as unstripped); *hashtype = 1
 * when a 0x01 follows the ORIGINAL end of s, else 0. (BIP66's strict shape
 * is der_sig_strict in bitcoin_scriptcodec, a separate predicate.)
 *
 * verify_p2pkh: sighash_all over the prevout script, then a walk to the
 * input whose every advance is bounded (IR-10: an empty scriptSig, an
 * overrunning push, a push that is not a 1..75 direct push -- all refused);
 * the hashtype byte is popped before the DER parse (IR-2) and must be
 * SIGHASH_ALL; z = be_to_limbs(sighash); pubkey_parse; ecdsa_verify.
 * ========================================================================== */
    .text

/* be_to_limbs(out=x0, bytes=x1, len=x2) ; leaf, a 32-byte right-justified
 * copy on the stack, then one byte-reversed load per limb */
    .p2align 2
    .globl _be_to_limbs
_be_to_limbs:
    sub   sp, sp, #32
    stp   xzr, xzr, [sp]
    stp   xzr, xzr, [sp, #16]
    mov   x9, #32
    sub   x9, x9, x2
    add   x9, sp, x9                      /* tmp + (32 - len) */
    mov   x10, #0
1:  cmp   x10, x2
    b.hs  2f
    ldrb  w11, [x1, x10]
    strb  w11, [x9, x10]
    add   x10, x10, #1
    b     1b
2:  ldp   x9, x10, [sp]                   /* BE groups 0..3 = limbs 3..0 */
    ldp   x11, x12, [sp, #16]
    rev   x9, x9
    rev   x10, x10
    rev   x11, x11
    rev   x12, x12
    stp   x12, x11, [x0]
    stp   x10, x9, [x0, #16]
    add   sp, sp, #32
    ret

/* Ldll(cur=x0, end=x1, n=x2) -> x0 value (0 = malformed), x1 new cursor ;
 * leaf. Core: skip zero length bytes, >= 4 significant -> reject, BE. */
    .p2align 2
Ldll:
    sub   x9, x1, x0
    cmp   x9, x2
    b.lo  9f                              /* more length bytes than remain */
1:  cbz   x2, 2f
    ldrb  w9, [x0]
    cbnz  w9, 2f
    add   x0, x0, #1
    sub   x2, x2, #1
    b     1b
2:  cmp   x2, #4
    b.hs  9f
    mov   x10, #0
3:  cbz   x2, 4f
    ldrb  w9, [x0], #1
    orr   x10, x9, x10, lsl #8
    sub   x2, x2, #1
    b     3b
4:  mov   x1, x0
    mov   x0, x10
    ret
9:  mov   x0, #0
    ret

/* ============================================================================
 * der_parse_sig(sig=x0, slen=x1, r=x2, s=x3, hashtype=x4)
 * end x19, p x20, r x21, s x22, ht ptr x23, len x24, send x25
 * ========================================================================== */
    .p2align 2
    .globl _der_parse_sig
_der_parse_sig:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    mov   x29, sp
    str   x25, [sp, #-16]!
    cmp   x1, #8
    b.lo  Ldp_no
    ldrb  w9, [x0]
    cmp   w9, #0x30
    b.ne  Ldp_no
    add   x19, x0, x1
    mov   x21, x2
    mov   x22, x3
    mov   x23, x4
    add   x20, x0, #1
    ldrb  w9, [x20], #1                   /* SEQUENCE length */
    tbz   w9, #7, 1f
    and   x9, x9, #0x7f                   /* long form: skipped, not read */
    sub   x10, x19, x20
    cmp   x10, x9
    b.lo  Ldp_no
    add   x20, x20, x9
1:  /* r */
    cmp   x20, x19
    b.hs  Ldp_no
    ldrb  w9, [x20], #1
    cmp   w9, #0x02
    b.ne  Ldp_no
    cmp   x20, x19
    b.hs  Ldp_no
    ldrb  w9, [x20], #1
    mov   x24, x9
    tbz   w9, #7, 2f
    mov   x0, x20
    mov   x1, x19
    and   x2, x9, #0x7f
    bl    Ldll
    mov   x20, x1
    mov   x24, x0
2:  cbz   x24, Ldp_no
    sub   x10, x19, x20
    cmp   x10, x24
    b.lo  Ldp_no
3:  cmp   x24, #32                        /* strip redundant leading zeros */
    b.ls  4f
    ldrb  w9, [x20]
    cbnz  w9, Ldp_no
    add   x20, x20, #1
    sub   x24, x24, #1
    b     3b
4:  mov   x0, x21
    mov   x1, x20
    mov   x2, x24
    bl    _be_to_limbs
    add   x20, x20, x24                   /* s marker: base + len */
    cmp   x20, x19
    b.hs  Ldp_no
    ldrb  w9, [x20], #1
    cmp   w9, #0x02
    b.ne  Ldp_no
    cmp   x20, x19
    b.hs  Ldp_no
    ldrb  w9, [x20], #1
    mov   x24, x9
    tbz   w9, #7, 5f
    mov   x0, x20
    mov   x1, x19
    and   x2, x9, #0x7f
    bl    Ldll
    mov   x20, x1
    mov   x24, x0
5:  cbz   x24, Ldp_no
    add   x25, x20, x24                   /* the ORIGINAL end of s */
    cmp   x25, x19
    b.hi  Ldp_no
6:  cmp   x24, #32
    b.ls  7f
    ldrb  w9, [x20]
    cbnz  w9, Ldp_no
    add   x20, x20, #1
    sub   x24, x24, #1
    b     6b
7:  mov   x0, x22
    mov   x1, x20
    mov   x2, x24
    bl    _be_to_limbs
    mov   w9, #0                          /* hashtype: a 0x01 right after s */
    cmp   x25, x19
    b.hs  8f
    ldrb  w10, [x25]
    cmp   w10, #1
    cset  w9, eq
8:  str   w9, [x23]
    mov   w0, #1
    b     Ldp_ret
Ldp_no:
    mov   w0, #0
Ldp_ret:
    ldr   x25, [sp], #16
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* Lrd(cur=x0, end=x1) -> x0 value, x1 new cursor ; leaf, x9..x11 --
 * CompactSize: 0 with the cursor unmoved at/after end; 0 with the prefix
 * consumed when the value bytes overrun */
    .p2align 2
Lrd:
    cmp   x0, x1
    b.hs  8f
    ldrb  w9, [x0], #1
    cmp   w9, #0xfd
    b.lo  7f
    mov   x10, #2
    mov   x11, #4
    cmp   w9, #0xfe
    csel  x10, x11, x10, eq
    mov   x11, #8
    cmp   w9, #0xff
    csel  x10, x11, x10, eq
    sub   x11, x1, x0
    cmp   x11, x10
    b.lo  6f
    cmp   x10, #4
    b.eq  4f
    b.hi  5f
    ldrh  w9, [x0]
    b     3f
4:  ldr   w9, [x0]
    b     3f
5:  ldr   x9, [x0]
3:  add   x1, x0, x10
    mov   x0, x9
    ret
6:  mov   x1, x0
    mov   x0, #0
    ret
7:  mov   x1, x0
    mov   x0, x9
    ret
8:  mov   x1, x0
    mov   x0, #0
    ret

/* ============================================================================
 * verify_p2pkh(tx=x0, txlen=x1, idx=x2, prev=x3, plen=x4, work=x5, cap=x6)
 * tx x19, end x20, idx x21, p x22, ssend x23, sig x24, siglen x25, pub x26,
 * publen x27, i x28 ; frame: out32 0, r 32, s 64, qx 96, qy 128, z 160,
 * ht 192 -> 208
 * ========================================================================== */
    .p2align 2
    .globl _verify_p2pkh
_verify_p2pkh:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #208
    mov   x19, x0
    add   x20, x0, x1
    mov   x21, x2
    mov   x7, x6                          /* sighash_all(out32, tx, txlen, idx, */
    mov   x6, x5                          /*   prev, plen, work, cap) */
    mov   x5, x4
    mov   x4, x3
    mov   x3, x2
    mov   x2, x1
    mov   x1, x0
    mov   x0, sp
    bl    _sighash_all
    cbz   w0, Lvp_no
    add   x0, x19, #4                     /* walk to the input, bounded */
    mov   x1, x20
    bl    Lrd
    mov   x22, x1
    cbz   x0, Lvp_no
    cmp   x21, x0
    b.hs  Lvp_no
    mov   x28, #0
1:  cmp   x28, x21
    b.hs  2f
    sub   x9, x20, x22
    cmp   x9, #36
    b.lt  Lvp_no
    add   x0, x22, #36
    mov   x1, x20
    bl    Lrd
    mov   x22, x1
    sub   x9, x20, x22
    cmp   x9, x0
    b.lo  Lvp_no
    add   x22, x22, x0
    sub   x9, x20, x22
    cmp   x9, #4
    b.lt  Lvp_no
    add   x22, x22, #4
    add   x28, x28, #1
    b     1b
2:  sub   x9, x20, x22                    /* the target input */
    cmp   x9, #36
    b.lt  Lvp_no
    add   x0, x22, #36
    mov   x1, x20
    bl    Lrd
    mov   x22, x1
    sub   x9, x20, x22
    cmp   x9, x0
    b.lo  Lvp_no
    add   x23, x22, x0                    /* scriptSig end */
    /* push 0 (sig), push 1 (pubkey): direct pushes 1..75 only */
    cmp   x22, x23
    b.hs  Lvp_no
    ldrb  w9, [x22]
    sub   w10, w9, #1
    cmp   w10, #74
    b.hi  Lvp_no
    sub   x10, x23, x22
    add   x11, x9, #1
    cmp   x10, x11
    b.lo  Lvp_no
    add   x24, x22, #1
    mov   x25, x9
    add   x22, x22, x11
    cmp   x22, x23
    b.hs  Lvp_no
    ldrb  w9, [x22]
    sub   w10, w9, #1
    cmp   w10, #74
    b.hi  Lvp_no
    sub   x10, x23, x22
    add   x11, x9, #1
    cmp   x10, x11
    b.lo  Lvp_no
    add   x26, x22, #1
    mov   x27, x9
    /* IR-2: the hashtype byte is popped first and must be SIGHASH_ALL */
    mov   x0, x24
    sub   x1, x25, #1
    add   x2, sp, #32
    add   x3, sp, #64
    add   x4, sp, #192
    bl    _der_parse_sig
    cbz   w0, Lvp_no
    sub   x9, x25, #1
    ldrb  w9, [x24, x9]
    cmp   w9, #1
    b.ne  Lvp_no
    add   x0, sp, #160
    mov   x1, sp
    mov   x2, #32
    bl    _be_to_limbs
    mov   x0, x26
    mov   x1, x27
    add   x2, sp, #96
    add   x3, sp, #128
    bl    _pubkey_parse
    cbz   w0, Lvp_no
    add   x0, sp, #160
    add   x1, sp, #32
    add   x2, sp, #64
    add   x3, sp, #96
    add   x4, sp, #128
    bl    _ecdsa_verify
    cbz   w0, Lvp_no
    mov   w0, #1
    b     Lvp_ret
Lvp_no:
    mov   w0, #0
Lvp_ret:
    add   sp, sp, #208
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret
