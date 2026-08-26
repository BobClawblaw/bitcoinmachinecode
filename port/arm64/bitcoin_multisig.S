/* bitcoin_multisig.S -- AArch64 port of asm/bitcoin_multisig.asm (AAPCS64).
 * Exports:
 *   int p2sh_hash(const u8* script, ulong script_len, u8 out20[20]) -> 1/0
 *   int multisig_verify(const u8* scriptSig, ulong sigLen, const u8* pubKey,
 *                       ulong pubLen, const u8* tx, ulong txLen, ulong inputIndex,
 *                       u8* work, ulong workCap, const u8* prevOutScript,
 *                       ulong prevOutScriptLen) -> 1/0
 * Deps: sha256_full, ripemd160, der_parse_sig, be_to_limbs, pubkey_parse,
 *       ecdsa_verify (all ported). Uses ported legacy_sighash (hashtype=1 =
 *       SIGHASH_ALL) in place of the x86's sighash_all -- same digest.
 */
    .text

/* ---------- p2sh_hash(script=x0, script_len=x1, out20=x2) -> 1/0 ---------- */
    .global p2sh_hash
    .type p2sh_hash,%function
p2sh_hash:
    sub  sp,sp,#0x40
    stp  x29,x30,[sp,#0x00]
    stp  x19,x20,[sp,#0x10]
    str  x21,[sp,#0x20]
    mov  x29,sp
    mov  x19,x0
    mov  x20,x1
    mov  x21,x2
    cbz  x20,.ph_fail
    add  x0,sp,#0x28              /* sha_buf[32] */
    mov  x1,x19
    mov  x2,x20
    bl   sha256_full
    mov  x0,x21
    add  x1,sp,#0x28
    mov  x2,#32
    bl   ripemd160
    mov  w0,#1
    b    .ph_ret
.ph_fail:
    mov  w0,#0
.ph_ret:
    ldr  x21,[sp,#0x20]
    ldp  x19,x20,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x40
    ret
    .size p2sh_hash,.-p2sh_hash

/* ---------- multisig_verify (11 args) ----------
 * x0..x7 = scriptSig,sigLen,pubKey,pubLen,tx,txLen,inputIndex,work
 * [sp+0]=workCap [sp+8]=prevOutScript [sp+16]=prevOutScriptLen
 * frame 0x2E0; persistents x19..x28 saved at [0x10..0x5F]; locals 0x60+.
 * Calls legacy_sighash (9 args) via a 16-byte call frame for its 9th arg. */
    .global multisig_verify
    .type multisig_verify,%function
multisig_verify:
    sub  sp,sp,#0x2E0
    stp  x29,x30,[sp,#0x00]
    stp  x19,x20,[sp,#0x10]
    stp  x21,x22,[sp,#0x20]
    stp  x23,x24,[sp,#0x30]
    stp  x25,x26,[sp,#0x40]
    stp  x27,x28,[sp,#0x50]
    add  x29,sp,#0x2E0            /* x29 = entry sp */
    mov  x19,x0                   /* scriptSig */
    mov  x20,x1                   /* sigLen */
    mov  x21,x2                   /* pubKey */
    mov  x22,x3                   /* pubLen */
    mov  x23,x4                   /* tx */
    mov  x24,x5                   /* txLen */
    mov  x25,x6                   /* inputIndex */
    mov  x26,x7                   /* work */
    ldr  x27,[x29,#8]             /* prevOutScript */
    ldr  x28,[x29,#16]            /* prevOutScriptLen */
    ldr  x9,[x29,#0]              /* workCap */
    str  x9,[sp,#0x60]

    /* ---- Step 1: scan scriptSig for pubKey; remember preceding push ----- */
    mov  x9,x19                   /* cursor */
    add  x12,x19,x20              /* end */
    mov  x10,#0                   /* prevLen */
    mov  x11,#0                   /* prevData */
.ms_scan:
    cmp  x9,x12
    b.hs .ms_notfound
    ldrb w8,[x9]                  /* pushLen */
    add  x13,x9,#1                /* current data start */
    cmp  x13,x12
    b.hi .ms_notfound
    mov  x14,x8                   /* pushLen(current) */
    cmp  x14,x22                  /* == pubLen ? */
    b.ne .ms_advance
    mov  x8,#0
.ms_cmp:
    cmp  x8,x22
    b.hs .ms_found
    ldrb w16,[x13,x8]
    ldrb w17,[x21,x8]
    cmp  w16,w17
    b.ne .ms_advance
    add  x8,x8,#1
    b    .ms_cmp
.ms_found:
    str  x11,[sp,#0x68]           /* sigStart = prevData */
    str  x10,[sp,#0x70]           /* sigLen_local = prevLen */
    b    .ms_sig_found
.ms_advance:
    mov  x10,x14                  /* prevLen = curLen */
    mov  x11,x13                  /* prevData = cur data start */
    add  x9,x13,x14               /* cursor = end of cur push */
    b    .ms_scan
.ms_notfound:
    mov  w0,#0
    b    .ms_ret

    /* ---- Step 2: sighash (SIGHASH_ALL) ---- */
.ms_sig_found:
    add  x0,sp,#0x80              /* sighash_out[32] */
    mov  x1,x23                   /* tx */
    mov  x2,x24                   /* txLen */
    mov  x3,x25                   /* inputIndex */
    mov  x4,x27                   /* prevOutScript */
    mov  x5,x28                   /* prevOutScriptLen */
    mov  x6,#1                    /* SIGHASH_ALL */
    mov  x7,x26                   /* work / preimg */
    ldr  x9,[sp,#0x60]            /* workCap */
    sub  sp,sp,#16                /* call frame for 9th arg */
    str  x9,[sp]
    bl   legacy_sighash
    add  sp,sp,#16
    cbz  x0,.ms_fail

    /* ---- Step 3: der_parse_sig ---- */
    ldr  x0,[sp,#0x68]            /* sigStart */
    ldr  x1,[sp,#0x70]            /* sigLen */
    add  x2,sp,#0xA0              /* r_out */
    add  x3,sp,#0xC0              /* s_out */
    add  x4,sp,#0x140             /* hashtype */
    bl   der_parse_sig
    cbz  x0,.ms_fail
    ldr  w8,[sp,#0x140]
    cmp  w8,#1
    b.ne .ms_fail

    /* ---- Step 4: z = be_to_limbs(sighash_out) ---- */
    add  x0,sp,#0x120             /* z */
    add  x1,sp,#0x80              /* sighash_out */
    mov  x2,#32
    bl   be_to_limbs

    /* ---- Step 5: pubkey_parse ---- */
    mov  x0,x21                   /* pubKey */
    mov  x1,x22                   /* pubLen */
    add  x2,sp,#0xE0              /* Qx */
    add  x3,sp,#0x100             /* Qy */
    bl   pubkey_parse
    cbz  x0,.ms_fail

    /* ---- Step 6: ecdsa_verify ---- */
    add  x0,sp,#0x120             /* z */
    add  x1,sp,#0xA0              /* r */
    add  x2,sp,#0xC0              /* s */
    add  x3,sp,#0xE0              /* Qx */
    add  x4,sp,#0x100             /* Qy */
    bl   ecdsa_verify
    cbz  x0,.ms_fail
    mov  w0,#1
    b    .ms_ret
.ms_fail:
    mov  w0,#0
.ms_ret:
    ldp  x27,x28,[sp,#0x50]
    ldp  x25,x26,[sp,#0x40]
    ldp  x23,x24,[sp,#0x30]
    ldp  x21,x22,[sp,#0x20]
    ldp  x19,x20,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x2E0
    ret
    .size multisig_verify,.-multisig_verify

    .section .note.GNU-stack,"",@progbits
