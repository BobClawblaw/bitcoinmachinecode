/* ============================================================================
 * bitcoin_tapagg.S -- AArch64 (GNU as) port of asm/bitcoin_tapagg.asm:
 * BIP341 aggregate-sighash arena build/verify (tapagg_build / tapagg_verify),
 * twin of asm/daemon/tx_verify.c. Differential: test_tapagg_diff.c.
 *
 *   long tapagg_build_asm (bytepool_t* pool, tapagg_t* d, tapin_fn get,
 *                          void* ctx, u64 nin, const u8* tx,
 *                          u64 txlen, const char** reason) -> 1/0
 *   long tapagg_verify_asm (const bytepool_t* pool, const tapagg_t* d,
 *                           const u8* spk, const u8* const* wit,
 *                           const u32* witlen, u32 nwit,
 *                           u64 local_idx, const char** reason) -> 1/0
 *
 * Both are 8-arg functions, so on AAPCS64 ALL args arrive in x0..x7 (the x86
 * SysV original had args 7/8 on the stack).
 *
 * tapagg_t (u64): po_off@0 am_off@8 sp_off@16 ns_off@24 nslen@32 nin@40.
 * bytepool_t: buf@0 cap@8 used@16.
 *
 * Deps (all native): txv_bytepool_reserve_asm (bitcoin_txv_pools.S),
 * strip_witness_asm (bitcoin_strip_witness.S), taproot_verify_input_asm
 * (bitcoin_taproot_verify.S, itself verified == C taproot_verify_input).
 * ==========================================================================*/
    .section .text
    .global tapagg_build_asm
    .type   tapagg_build_asm,%function
    .global tapagg_verify_asm
    .type   tapagg_verify_asm,%function

    .extern txv_bytepool_reserve_asm
    .extern strip_witness_asm
    .extern taproot_verify_input_asm

.set TA_PO, 0
.set TA_AM, 8
.set TA_SP, 16
.set TA_NS, 24
.set TA_NSLEN, 32
.set TA_NIN, 40
.set BP_BUF, 0

    .section .rodata
t_spkbig: .string "prevout script too large for taproot aggregate sighash"
t_oom:    .string "out of memory"
t_moved:  .string "internal: taproot arena moved during build"
t_sizing: .string "internal: taproot arena sizing pass disagreed"
t_strip:  .string "malformed witness (strip failed)"
t_p2tr:   .string "p2tr verify failed"

/* ---- build frame locals (offset from sp after sub) ---- */
.set L_OP, 0
.set L_V, 8
.set L_SPK, 16
.set L_SL, 24
.set L_SPLEN, 32
.set L_BASE, 40
.set L_PO, 48
.set L_AM, 56
.set L_SP, 64
.set L_W, 72
.set L_K, 80
.set L_OFF, 88
.set FRAME_B, 0x60

    .text

/* ---- callee-saved across build: x19 pool x20 d x21 get x22 ctx
 *      x23 nin x24 tx x25 txlen x26 reason ---- */
tapagg_build_asm:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    sub  sp, sp, #FRAME_B
    mov  x19, x0      /* pool */
    mov  x20, x1      /* d */
    mov  x21, x2      /* get */
    mov  x22, x3      /* ctx */
    mov  x23, x4      /* nin */
    mov  x24, x5      /* tx */
    mov  x25, x6      /* txlen */
    mov  x26, x7      /* reason */

    /* ---- sizing pass: splen = sum(1 + sl); reject sl >= 0xfd ---- */
    str  xzr, [sp, #L_SPLEN]
    str  xzr, [sp, #L_K]
.size_loop:
    ldr  x9, [sp, #L_K]
    cmp  x9, x23
    b.hs .size_done
    mov  x0, x22
    mov  x1, x9
    add  x2, sp, #L_OP
    add  x3, sp, #L_V
    add  x4, sp, #L_SPK
    add  x5, sp, #L_SL
    blr  x21
    ldr  w9, [sp, #L_SL]
    cmp  w9, #0xfd
    b.hs .r_spkbig
    add  x9, x9, #1
    ldr  x10, [sp, #L_SPLEN]
    add  x10, x10, x9
    str  x10, [sp, #L_SPLEN]
    ldr  x9, [sp, #L_K]
    add  x9, x9, #1
    str  x9, [sp, #L_K]
    b    .size_loop
.size_done:

    /* need = nin*44 + splen + txlen ; off = reserve(pool, need) */
    mov  x9, x23
    mov  x10, #44
    mul  x9, x9, x10
    ldr  x10, [sp, #L_SPLEN]
    add  x9, x9, x10
    add  x9, x9, x25
    mov  x0, x19
    mov  x1, x9
    bl   txv_bytepool_reserve_asm
    mov  x10, #-1
    cmp  x0, x10
    b.eq .r_oom
    str  x0, [sp, #L_OFF]

    /* fill descriptor offsets */
    str  x0, [x20, #TA_PO]
    mov  x11, x23
    mov  x12, #36
    mul  x11, x11, x12
    add  x11, x0, x11                  /* po + nin*36 */
    str  x11, [x20, #TA_AM]
    mov  x12, x23
    lsl  x12, x12, #3
    add  x12, x11, x12                 /* am + nin*8 */
    str  x12, [x20, #TA_SP]
    ldr  x13, [sp, #L_SPLEN]
    add  x13, x12, x13                 /* sp + splen */
    str  x13, [x20, #TA_NS]
    str  x23, [x20, #TA_NIN]

    /* base = pool->buf ; po/am/sp = base + *_off (only NOW, after reserve) */
    ldr  x9, [x19, #BP_BUF]
    str  x9, [sp, #L_BASE]
    ldr  x10, [x20, #TA_PO]
    add  x10, x9, x10
    str  x10, [sp, #L_PO]
    ldr  x11, [x20, #TA_AM]
    add  x11, x9, x11
    str  x11, [sp, #L_AM]
    ldr  x12, [x20, #TA_SP]
    add  x12, x9, x12
    str  x12, [sp, #L_SP]

    /* ---- write pass ---- */
    str  xzr, [sp, #L_W]
    str  xzr, [sp, #L_K]
.write_loop:
    ldr  x9, [sp, #L_K]
    cmp  x9, x23
    b.hs .write_done
    mov  x0, x22
    mov  x1, x9
    add  x2, sp, #L_OP
    add  x3, sp, #L_V
    add  x4, sp, #L_SPK
    add  x5, sp, #L_SL
    blr  x21
    /* invariant 1: arena must not have moved */
    ldr  x9, [x19, #BP_BUF]
    ldr  x10, [sp, #L_BASE]
    cmp  x9, x10
    b.ne .r_moved
    /* invariant 2: sl < 0xfd && w + 1 + sl <= splen */
    ldr  w9, [sp, #L_SL]
    cmp  w9, #0xfd
    b.hs .r_sizing
    ldr  x10, [sp, #L_W]
    add  x10, x10, x9
    add  x10, x10, #1
    ldr  x11, [sp, #L_SPLEN]
    cmp  x10, x11
    b.hi .r_sizing
    /* po[k*36] = op (36 bytes) */
    ldr  x10, [sp, #L_K]
    mov  x11, #36
    mul  x11, x10, x11
    ldr  x12, [sp, #L_PO]
    add  x12, x12, x11
    ldr  x13, [sp, #L_OP]
    ldr  x14, [x13]
    str  x14, [x12]
    ldr  x14, [x13, #8]
    str  x14, [x12, #8]
    ldr  x14, [x13, #16]
    str  x14, [x12, #16]
    ldr  x14, [x13, #24]
    str  x14, [x12, #24]
    ldr  w15, [x13, #32]
    str  w15, [x12, #32]
    /* am[k*8] = v, LE64  (v is a u64 VALUE, not a pointer!) */
    ldr  x12, [sp, #L_AM]
    ldr  x13, [sp, #L_V]
    str  x13, [x12, x10, lsl #3]
    /* sp[w++] = sl ; memcpy(sp+w, spk, sl) ; w += sl */
    ldr  x12, [sp, #L_SP]
    ldr  w13, [sp, #L_SL]
    ldr  x10, [sp, #L_W]
    strb w13, [x12, x10]
    add  x10, x10, #1
    ldr  x14, [sp, #L_SPK]
    mov  x16, #0
.spk_loop:
    cmp  x16, x13
    b.hs .spk_done
    ldrb w15, [x14, x16]
    strb w15, [x12, x10]
    add  x16, x16, #1
    add  x10, x10, #1
    b    .spk_loop
.spk_done:
    str  x10, [sp, #L_W]
    ldr  x9, [sp, #L_K]
    add  x9, x9, #1
    str  x9, [sp, #L_K]
    b    .write_loop
.write_done:

    /* nslen = strip_witness_asm(tx, txlen, ns, txlen) */
    ldr  x9, [sp, #L_BASE]
    ldr  x10, [x20, #TA_NS]
    add  x10, x9, x10                  /* ns = base + ns_off */
    mov  x0, x24                       /* tx */
    mov  x1, x25                       /* txlen */
    mov  x2, x10                       /* out */
    mov  x3, x25                       /* cap = txlen */
    bl   strip_witness_asm
    cmp  x0, #0
    b.le .r_strip
    str  x0, [x20, #TA_NSLEN]
    mov  w0, #1
    b    .out

.r_spkbig: adr x2, t_spkbig
           b   .reject
.r_oom:    adr x2, t_oom
           b   .reject
.r_moved:  adr x2, t_moved
           b   .reject
.r_sizing: adr x2, t_sizing
           b   .reject
.r_strip:  adr x2, t_strip
.reject:
    str  x2, [x26]                     /* *reason = ... */
    mov  w0, #0
.out:
    add  sp, sp, #FRAME_B
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

/* ---- verify frame: L_VR at sp+32 (above [sp+0..24] outgoing zone) ---- */
.set L_VR, 32
.set FRAME_V, 0x30
/* ---- callee-saved across verify: x19 d x20 A(base) x21 reason x22 spk ---- */
tapagg_verify_asm:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    sub  sp, sp, #FRAME_V
    mov  x19, x1                   /* d */
    ldr  x20, [x0]                 /* A = pool->buf */
    mov  x21, x7                   /* reason */
    mov  x22, x2                   /* spk */
    adr  x9, t_p2tr
    str  x9, [sp, #L_VR]           /* const char* r = "p2tr verify failed" */

    /* taproot_verify_input_asm(spk, wit, witlen, nwit, tx=A+ns_off,
     *   txlen=nslen, n_in=local_idx, prevouts=A+po_off, amounts=A+am_off,
     *   spks=A+sp_off, num_inputs=nin, &r)  -- 12 args: arg9..12 on stack */
    mov  x0, x22                   /* spk */
    mov  x1, x3                    /* wit */
    mov  x2, x4                    /* witlen */
    mov  x3, x5                    /* nwit */
    ldr  x4, [x19, #TA_NS]
    add  x4, x20, x4               /* tx */
    ldr  x5, [x19, #TA_NSLEN]      /* txlen */
                                   /* x6 = local_idx already */
    ldr  x7, [x19, #TA_PO]
    add  x7, x20, x7               /* prevouts */
    ldr  x9, [x19, #TA_AM]
    add  x9, x20, x9
    str  x9, [sp, #0]              /* amounts (arg9) */
    ldr  x9, [x19, #TA_SP]
    add  x9, x20, x9
    str  x9, [sp, #8]              /* spks (arg10) */
    ldr  x9, [x19, #TA_NIN]
    str  x9, [sp, #16]             /* num_inputs (arg11) */
    add  x9, sp, #L_VR
    str  x9, [sp, #24]             /* &r (arg12) */
    bl   taproot_verify_input_asm
    cbz  w0, .vbad
    mov  w0, #1
    b    .vout
.vbad:
    ldr  x9, [sp, #L_VR]
    str  x9, [x21]                 /* *reason = r */
    mov  w0, #0
.vout:
    add  sp, sp, #FRAME_V
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

    .section .note.GNU-stack,"",@progbits
