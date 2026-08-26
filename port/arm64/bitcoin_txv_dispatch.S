/* ============================================================================
 * bitcoin_txv_dispatch.S -- AArch64 (GNU as) port of asm/bitcoin_txv_dispatch.asm:
 * the per-input verification dispatch (txvb_verify_one) and the legacy tx view
 * (legacy_tx_view), twin of tx_verify.c. Differential: test_txv_dispatch_diff.c.
 *
 *   const u8* legacy_tx_view_asm(const u8* tx, u64 txlen, u64* out_len)
 *   long txvb_verify_one_asm (const u8* tx, u64 txlen, txvb_in_t* in,
 *                             u64 flags, u8* sv_work, u64 sv_workcap,
 *                             const bytepool_t* spk_pool,
 *                             const bytepool_t* tap_pool,
 *                             const tapagg_t* tapdesc,
 *                             const char** reason) -> 1 / 0
 *
 * legacy_tx_view_asm has 3 args (all registers). txvb_verify_one_asm has 10:
 * AAPCS64 puts args 1-8 in x0..x7 and args 9,10 (tapdesc, reason) on the stack
 * at [SP+0] / [SP+8] of the CALLER -- i.e. my entry [SP+0]/[SP+8] after the
 * push of outgoing args by the C test caller.
 *
 * txvb_in_t offsets (offsetof-pinned): local_idx@8 scriptSig@40 scriptSiglen@48
 *   wit@56 witlen@64 nwit@72 wprog@80 wproglen@88 wprog_off@96 value@104
 *   spk_off@112 spklen@120 tap_desc@128 shape@136.
 * tapagg_t is 48 bytes.
 *
 * Deps: strip_witness_asm (bitcoin_strip_witness.S), tapagg_verify_asm
 * (bitcoin_tapagg.S, native), and the C interpreter leaves
 * sv_verify_witness_v0 (bitcoin_witness_v0.c) / sv_verify_script
 * (bitcoin_scriptverify.c). The verifier leaves are the interpreter-driver
 * layer, C on the x86 tree too.
 * ==========================================================================*/
    .section .text

    .extern malloc
    .extern abort
    .extern strip_witness_asm
    .extern tapagg_verify_asm
    .extern sv_verify_witness_v0
    .extern sv_verify_script

.set LTV_CAP, (1 << 20)
.set SHAPE_LEGACY, 0
.set SHAPE_P2TR, 3
.set SHAPE_WV0, 4

.set IN_LOCAL, 8
.set IN_SCRIPTSIG, 40
.set IN_SSLEN, 48
.set IN_WIT, 56
.set IN_WITLEN, 64
.set IN_NWIT, 72
.set IN_WPROG, 80
.set IN_WPROGLEN, 88
.set IN_WPROGOFF, 96
.set IN_VALUE, 104
.set IN_SPKOFF, 112
.set IN_SPKLEN, 120
.set IN_TAPDESC, 128
.set IN_SHAPE, 136
.set TAPAGG_SIZE, 48
.set BP_BUF, 0

/* TLS lazy stripped-tx buffer (shared, one per thread) */
    .section .tbss,"awT",@nobits
    .global ltv_buf
ltv_buf: .space 8

    .section .rodata
d_notbuilt: .string "internal: taproot aggregate not built"
d_wpkh:     .string "p2wpkh signature invalid"
d_wsh:      .string "p2wsh script verification failed"
d_legacy:   .string "legacy script verification failed"

    .section .text

/* TLS Initial-Exec address of a .tbss symbol into d (clobbers x10) */
.macro TLS_ADDR d, sym
    adrp \d, :gottprel:\sym
    ldr  \d, [\d, #:gottprel_lo12:\sym]
    mrs  x10, tpidr_el0
    add  \d, \d, x10
.endm

/* ---- legacy_tx_view_asm(tx=x0, txlen=x1, out_len=x2) -> x0 ----
 * Persistent: x19 tx, x20 txlen, x21 out_len, x22 stripped buffer. */
    .global legacy_tx_view_asm
    .type   legacy_tx_view_asm,%function
legacy_tx_view_asm:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    sub  sp, sp, #0x20
    mov  x19, x0           /* tx */
    mov  x20, x1           /* txlen */
    mov  x21, x2           /* out_len */
    /* if (txlen < 6 || tx[4]!=0 || tx[5]!=1) return tx unchanged */
    cmp  x1, #6
    b.lo .ltv_plain
    ldrb w9, [x0, #4]
    cbnz w9, .ltv_plain
    ldrb w9, [x0, #5]
    cmp  w9, #1
    b.ne .ltv_plain
    /* this thread's lazy stripped buffer */
    TLS_ADDR x12, ltv_buf
    ldr  x22, [x12]
    cbnz x22, .ltv_have
    mov  x0, #0
    movk x0, #1, lsl #16           /* LTV_CAP */
    mov  x13, x12                  /* keep slot addr (x12 caller-saved) */
    bl   malloc
    cbz  x0, .ltv_abort
    mov  x22, x0
    str  x22, [x13]
.ltv_have:
    /* n = strip_witness_asm(tx, txlen, stripped, LTV_CAP) */
    mov  x0, x19
    mov  x1, x20
    mov  x2, x22
    mov  x3, #0
    movk x3, #1, lsl #16
    bl   strip_witness_asm
    cmp  x0, #0
    b.le .ltv_plain                 /* fall back; sv rejects on bad hash */
    str  x0, [x21]                  /* *out_len = n */
    mov  x0, x22                    /* return stripped */
    b    .ltv_out
.ltv_plain:
    str  x20, [x21]
    mov  x0, x19
.ltv_out:
    add  sp, sp, #0x20
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret
.ltv_abort:
    bl   abort
    b    .ltv_abort

/* ---- txvb_verify_one_asm frame ----
 * Entry regs: x0 tx x1 txlen x2 in x3 flags x4 sv_work x5 sv_workcap
 *             x6 spk_pool x7 tap_pool ; [SP+0]=tapdesc [SP+8]=reason
 * Persistent callee-saved: x19 in x20 tx x21 txlen x22 flags x23 spk.
 * Outgoing stack-arg scratch zone [SP+0..31] (sv_verify_witness_v0 12 args,
 * sv_verify_script 10 args); persistent locals live ABOVE it. */
.set L_OUT, 0            /* 32 B outgoing scratch -> 0..31 */
.set L_WORK, 32
.set L_WORKCAP, 40
.set L_LTXLEN, 48
.set L_TAPPOOL, 56
.set L_TAPDESC, 64
.set L_REASON, 72
.set FRAME, 0x60

    .global txvb_verify_one_asm
    .type   txvb_verify_one_asm,%function
txvb_verify_one_asm:
    /* capture incoming stack args (tapdesc, reason) before moving sp */
    ldr  x9,  [sp, #0]             /* tapdesc (arg9) */
    ldr  x10, [sp, #8]             /* reason (arg10) */
    mov  x11, x7                   /* tap_pool (arg8) */
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    sub  sp, sp, #FRAME
    mov  x19, x2          /* in */
    mov  x20, x0          /* tx */
    mov  x21, x1          /* txlen */
    mov  x22, x3          /* flags */
    str  x4, [sp, #L_WORK]
    str  x5, [sp, #L_WORKCAP]
    str  x11, [sp, #L_TAPPOOL]
    str  x9, [sp, #L_TAPDESC]
    str  x10, [sp, #L_REASON]
    /* spk = spk_pool->buf + in->spk_off  (x6 = spk_pool still valid) */
    ldr  x23, [x6, #BP_BUF]
    ldr  x9, [x19, #IN_SPKOFF]
    add  x23, x23, x9

    /* shape dispatch */
    ldrb w9, [x19, #IN_SHAPE]
    cmp  w9, #SHAPE_P2TR
    b.eq .p2tr
    cmp  w9, #SHAPE_WV0
    b.eq .wv0
    cmp  w9, #SHAPE_LEGACY
    b.eq .legacy
    mov  w0, #1                      /* WPASS / unknown: valid */
    b    .out

.p2tr:
    ldr  x9, [x19, #IN_TAPDESC]
    mov  x10, #-1
    cmp  x9, x10
    b.eq .r_notbuilt
    /* &tapdesc[tap_desc] = tapdesc + desc*48 */
    mov  x10, #TAPAGG_SIZE
    mul  x9, x9, x10
    ldr  x11, [sp, #L_TAPDESC]
    add  x9, x11, x9
    /* tapagg_verify_asm(tap_pool, &tapdesc[d], spk, wit, witlen, nwit,
     *                   local_idx, reason) -- 8 args, all registers */
    ldr  x0, [sp, #L_TAPPOOL]
    mov  x1, x9
    mov  x2, x23
    ldr  x3, [x19, #IN_WIT]
    ldr  x4, [x19, #IN_WITLEN]
    ldr  x5, [x19, #IN_NWIT]
    ldr  w6, [x19, #IN_LOCAL]
    ldr  x7, [sp, #L_REASON]
    bl   tapagg_verify_asm
    b    .out                        /* its return is ours; reason set on fail */

.wv0:
    /* wprog = in->wprog ? in->wprog : spk + in->wprog_off */
    ldr  x0, [x19, #IN_WPROG]
    cbnz x0, .have_wprog
    ldr  w0, [x19, #IN_WPROGOFF]
    add  x0, x23, x0
.have_wprog:
    /* sv_verify_witness_v0(wprog, wproglen, wit, witlen, nwit, value,
     *   flags, local_idx, tx, txlen, work, workcap) -- 12 args */
    ldr  w1, [x19, #IN_WPROGLEN]
    ldr  x2, [x19, #IN_WIT]
    ldr  x3, [x19, #IN_WITLEN]
    ldr  w4, [x19, #IN_NWIT]
    ldr  x5, [x19, #IN_VALUE]
    mov  x6, x22                     /* flags */
    ldr  w7, [x19, #IN_LOCAL]
    str  x20, [sp, #(L_OUT+0)]       /* tx   (arg9) */
    str  x21, [sp, #(L_OUT+8)]       /* txlen(arg10) */
    ldr  x9, [sp, #L_WORK]
    str  x9, [sp, #(L_OUT+16)]       /* work (arg11) */
    ldr  x9, [sp, #L_WORKCAP]
    str  x9, [sp, #(L_OUT+24)]       /* workcap(arg12) */
    bl   sv_verify_witness_v0
    cbz  w0, .ok                     /* 0 == valid */
    ldr  w9, [x19, #IN_WPROGLEN]
    cmp  w9, #20
    b.ne .r_wsh
    adr  x2, d_wpkh
    b    .reject
.r_wsh:
    adr  x2, d_wsh
    b    .reject

.legacy:
    /* ltx = legacy_tx_view_asm(tx, txlen, &ltxlen) */
    mov  x0, x20
    mov  x1, x21
    add  x2, sp, #L_LTXLEN
    bl   legacy_tx_view_asm
    mov  x8, x0                      /* ltx (before clobbering x0) */
    /* sv_verify_script(scriptSig, ssl, spk, spklen, flags, local_idx,
     *   ltx, ltxlen, work, workcap) -- 10 args */
    ldr  x0, [x19, #IN_SCRIPTSIG]
    ldr  w1, [x19, #IN_SSLEN]
    mov  x2, x23                     /* spk */
    ldr  w3, [x19, #IN_SPKLEN]
    mov  x4, x22                     /* flags */
    ldr  w5, [x19, #IN_LOCAL]
    mov  x6, x8                      /* ltx  (arg7) */
    ldr  x7, [sp, #L_LTXLEN]         /* ltxlen(arg8) */
    ldr  x9, [sp, #L_WORK]
    str  x9, [sp, #(L_OUT+0)]        /* work  (arg9) */
    ldr  x9, [sp, #L_WORKCAP]
    str  x9, [sp, #(L_OUT+8)]        /* workcap(arg10) */
    bl   sv_verify_script
    cbz  w0, .ok
    adr  x2, d_legacy
    b    .reject

.r_notbuilt:
    adr  x2, d_notbuilt
.reject:
    ldr  x9, [sp, #L_REASON]
    str  x2, [x9]
    mov  w0, #0
    b    .out
.ok:
    mov  w0, #1
.out:
    add  sp, sp, #FRAME
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

    .section .note.GNU-stack,"",@progbits
