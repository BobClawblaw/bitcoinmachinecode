/* port/osx/test_support/bench_abi_guard_twin.S -- the AArch64 (AAPCS64,
 * Apple) counterpart of tests/bench_abi_guard.S's callee-saved probe, for
 * tests/bench_abi_audit and tests/test_abi_coverage. Test-only.
 *
 *   long bench_abi_probe(void* fn, const unsigned long args[6],
 *                        unsigned long got[19])
 *
 * Loads a distinct sentinel into EVERY register AAPCS64 makes callee-saved --
 * x19..x28, x29 (the frame pointer) and the low 64 bits of v8..v15 (d8..d15)
 * -- puts args[0..5] in x0..x5, calls fn, stores what came back in got[0..18]
 * (x19..x28, x29, d8..d15, in that order) and returns how many differ.
 * Sentinel i is 0x0101010101010101 * (i+1), i = 0..18: distinct, never zero,
 * and not a value any real computation is likely to leave behind.
 *
 * The x86 probe checks six registers; this checks nineteen, because that is
 * what the Mac's hand-written AArch64 (bitcoin_interp.S, bitcoind.S, the
 * crypto .S files) must preserve. x30 (lr) and sp are the caller's to
 * restore and are covered by the probe returning at all.
 *
 * Our own callee-saved registers are saved on the stack first and restored
 * sp-relative, so the sentinel in x29 (and anything fn does to it) cannot
 * break the way back.
 */
    .text
    .p2align 2
    .globl _bench_abi_probe
_bench_abi_probe:
    stp  x29, x30, [sp, #-16]!
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    stp  x27, x28, [sp, #-16]!
    stp  d8,  d9,  [sp, #-16]!
    stp  d10, d11, [sp, #-16]!
    stp  d12, d13, [sp, #-16]!
    stp  d14, d15, [sp, #-16]!
    str  x2,  [sp, #-16]!            /* got (keeps sp 16-aligned) */

    mov  x16, x0                     /* fn */
    mov  x17, x1                     /* args */

    /* sentinels: x9 = B = 0x0101010101010101, then B*(i+1) by addition */
    movz x9, #0x0101
    movk x9, #0x0101, lsl #16
    movk x9, #0x0101, lsl #32
    movk x9, #0x0101, lsl #48
    mov  x19, x9                     /* 1B  */
    add  x20, x19, x9                /* 2B  */
    add  x21, x20, x9
    add  x22, x21, x9
    add  x23, x22, x9
    add  x24, x23, x9
    add  x25, x24, x9
    add  x26, x25, x9
    add  x27, x26, x9
    add  x28, x27, x9                /* 10B */
    add  x29, x28, x9                /* 11B */
    add  x10, x29, x9                /* 12B -> d8 */
    fmov d8,  x10
    add  x10, x10, x9
    fmov d9,  x10
    add  x10, x10, x9
    fmov d10, x10
    add  x10, x10, x9
    fmov d11, x10
    add  x10, x10, x9
    fmov d12, x10
    add  x10, x10, x9
    fmov d13, x10
    add  x10, x10, x9
    fmov d14, x10
    add  x10, x10, x9
    fmov d15, x10                    /* 19B */

    ldp  x0, x1, [x17]
    ldp  x2, x3, [x17, #16]
    ldp  x4, x5, [x17, #32]
    blr  x16

    ldr  x10, [sp], #16              /* got */
    stp  x19, x20, [x10, #0]
    stp  x21, x22, [x10, #16]
    stp  x23, x24, [x10, #32]
    stp  x25, x26, [x10, #48]
    stp  x27, x28, [x10, #64]
    str  x29,      [x10, #80]
    fmov x11, d8
    str  x11, [x10, #88]
    fmov x11, d9
    str  x11, [x10, #96]
    fmov x11, d10
    str  x11, [x10, #104]
    fmov x11, d11
    str  x11, [x10, #112]
    fmov x11, d12
    str  x11, [x10, #120]
    fmov x11, d13
    str  x11, [x10, #128]
    fmov x11, d14
    str  x11, [x10, #136]
    fmov x11, d15
    str  x11, [x10, #144]

    /* count mismatches: got[i] vs B*(i+1) */
    movz x9, #0x0101
    movk x9, #0x0101, lsl #16
    movk x9, #0x0101, lsl #32
    movk x9, #0x0101, lsl #48
    mov  x12, x9                     /* expected */
    mov  x13, #0                     /* i */
    mov  x0,  #0                     /* bad */
1:  ldr  x14, [x10, x13, lsl #3]
    cmp  x14, x12
    cinc x0, x0, ne
    add  x12, x12, x9
    add  x13, x13, #1
    cmp  x13, #19
    b.lo 1b

    ldp  d14, d15, [sp], #16
    ldp  d12, d13, [sp], #16
    ldp  d10, d11, [sp], #16
    ldp  d8,  d9,  [sp], #16
    ldp  x27, x28, [sp], #16
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret
