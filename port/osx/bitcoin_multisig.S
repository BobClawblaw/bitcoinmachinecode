/* ============================================================================
 * bitcoin_multisig.S -- the standalone one-signer CHECKMULTISIG helper in
 * AArch64 assembly (Apple silicon), the counterpart of
 * asm/bitcoin_multisig.asm. Replaces multisig_twin.c on the Mac
 * (2026-09-26); the twin stays in port/osx/test_support as the oracle.
 *
 *   int p2sh_hash(const u8* script, ulong len, u8 out20[20]);
 *       RIPEMD160(SHA256(script)); 1, or 0 for an empty script.
 *   int multisig_verify(const u8* scriptSig, ulong sigLen,
 *                       const u8* pubKey, ulong pubLen,
 *                       const u8* tx, ulong txLen, ulong inputIndex,
 *                       u8* work, ulong workCap,
 *                       const u8* prevOutScript, ulong prevOutScriptLen);
 *       Walk the scriptSig's pushes (<len byte><data>); the push equal to
 *       pubKey names the signer and the push BEFORE it is its DER signature
 *       + hashtype; verify it over the legacy SIGHASH_ALL digest with
 *       prevOutScript as the signing script. 1 valid / 0 otherwise; the
 *       hashtype byte must be exactly 1.
 *
 * Only tests/test_multisig and the ABI bench call this; consensus multisig
 * is the interpreter's OP_CHECKMULTISIG. As the twin (and unlike the x86,
 * which reads past the scriptSig when a length byte overruns it), a push
 * must fit inside the scriptSig -- malformed input only; every well-formed
 * scriptSig answers the same. The sighash is computed before the empty-
 * signature check, in the twin's order (it fills the caller's work buffer).
 *
 * work, the 8th argument, arrives in x7; the 9th..11th (workCap,
 * prevOutScript, prevOutScriptLen) on the stack at [sp], [sp+8], [sp+16]
 * (8-byte slots: Darwin packs stack arguments by natural size, and these
 * are all 8 bytes).
 * ========================================================================== */
    .text

/* p2sh_hash(script=x0, len=x1, out=x2) ; frame h 0 (32) */
    .p2align 2
    .globl _p2sh_hash
_p2sh_hash:
    cbz   x1, 1f
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x2
    mov   x2, x1
    mov   x1, x0
    mov   x0, sp
    bl    _sha256_full
    mov   x0, x19
    mov   x1, sp
    mov   x2, #32
    bl    _ripemd160
    mov   w0, #1
    add   sp, sp, #32
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret
1:  mov   w0, #0
    ret

/* ============================================================================
 * multisig_verify
 * frame: digest 0, r 32, s 64, z 96, qx 128, qy 160, ht 192 (16) -> 208
 * x19 sig ptr, x20 sig len, x21 pub, x22 pub len, x23 tx, x24 txlen,
 * x25 input index, x26 incoming stack args base, x27 work
 * ========================================================================== */
#define M_DIG  0
#define M_R    32
#define M_S    64
#define M_Z    96
#define M_QX   128
#define M_QY   160
#define M_HT   192
#define M_SIZE 208

    .p2align 2
    .globl _multisig_verify
_multisig_verify:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    str   x27, [sp, #80]
    mov   x29, sp
    add   x26, sp, #96                    /* caller's outgoing args */
    sub   sp, sp, #M_SIZE
    mov   x21, x2
    mov   x22, x3
    mov   x23, x4
    mov   x24, x5
    mov   x25, x6
    mov   x27, x7
    /* step 1: p = scriptSig walk; x9 = p, x10 = end, x19/x20 = prev push */
    mov   x9, x0
    add   x10, x0, x1
    mov   x19, xzr
    mov   x20, xzr
1:  cmp   x9, x10
    b.hs  Lms_no                          /* ran out: pubKey not found */
    ldrb  w11, [x9], #1                   /* n */
    sub   x12, x10, x9
    cmp   x11, x12
    b.hi  Lms_no                          /* the push must fit */
    cmp   x11, x22
    b.ne  3f
    mov   x13, #0                         /* compare n bytes with pubKey */
2:  cmp   x13, x11
    b.hs  4f                              /* equal: found */
    ldrb  w14, [x9, x13]
    ldrb  w15, [x21, x13]
    cmp   w14, w15
    b.ne  3f
    add   x13, x13, #1
    b     2b
3:  mov   x19, x9                         /* prev = p, prev_len = n */
    mov   x20, x11
    add   x9, x9, x11
    b     1b
4:  /* step 2: SIGHASH_ALL digest over prevOutScript */
    mov   x0, sp
    mov   x1, x23
    mov   x2, x24
    mov   x3, x25
    ldr   x4, [x26, #8]                   /* prevOutScript */
    ldr   x5, [x26, #16]                  /* prevOutScriptLen */
    mov   x6, x27                         /* work */
    ldr   x7, [x26]                       /* workCap */
    bl    _sighash_all
    cbz   w0, Lms_no
    /* step 3: DER without the hashtype byte, which must be 1 */
    cbz   x20, Lms_no
    str   wzr, [sp, #M_HT]
    mov   x0, x19
    sub   x1, x20, #1
    add   x2, sp, #M_R
    add   x3, sp, #M_S
    add   x4, sp, #M_HT
    bl    _der_parse_sig
    cbz   w0, Lms_no
    sub   x9, x20, #1
    ldrb  w9, [x19, x9]
    cmp   w9, #1
    b.ne  Lms_no
    /* steps 4-6: z, Q, verify */
    add   x0, sp, #M_Z
    mov   x1, sp
    mov   x2, #32
    bl    _be_to_limbs
    mov   x0, x21
    mov   x1, x22
    add   x2, sp, #M_QX
    add   x3, sp, #M_QY
    bl    _pubkey_parse
    cbz   w0, Lms_no
    add   x0, sp, #M_Z
    add   x1, sp, #M_R
    add   x2, sp, #M_S
    add   x3, sp, #M_QX
    add   x4, sp, #M_QY
    bl    _ecdsa_verify
    cmp   w0, #0
    cset  w0, ne
    b     Lms_ret
Lms_no:
    mov   w0, #0
Lms_ret:
    add   sp, sp, #M_SIZE
    ldr   x27, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret
