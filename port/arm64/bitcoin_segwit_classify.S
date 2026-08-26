/* bitcoin_segwit_classify.S -- AArch64 port of asm/bitcoin_segwit_classify.asm.
 *
 * Exported (identical to x86; NB: AA64PCS passes 8 args in registers, where
 * SysV AMD64 passes only 6, so proglen/wrapped are REGISTERS x6/x7, NOT stack):
 *   long sv_witness_program_asm(const u8* s, u64 n, u32* version,
 *                               const u8** prog, u32* proglen) -> 1/0
 *   long sv_classify_segwit_asm(const u8* spk, u64 spl, const u8* ss, u64 ssl,
 *                               u32* version, const u8** prog,
 *                               u32* proglen, int* wrapped) -> 1/2/-1/0
 *     -> 1 native / 2 wrapped / -1 malleated-or-hash-mismatch / 0 legacy
 *
 * Dep: hash160 (bitcoin_addr.S).
 */
    .text

/* ---------- sv_witness_program_asm ---------- */
    .global sv_witness_program_asm
    .type sv_witness_program_asm,%function
sv_witness_program_asm:
    /* x0=s x1=n x2=version x3=prog x4=proglen */
    cmp  x1,#4
    b.lo .wp_no
    cmp  x1,#42
    b.hi .wp_no
    ldrb w5,[x0]
    cbz  w5,.wp_ver_ok           /* OP_0 */
    cmp  w5,#0x51
    b.lo .wp_no
    cmp  w5,#0x60
    b.hi .wp_no
.wp_ver_ok:
    sub  x6,x1,#2                /* n-2 */
    ldrb w7,[x0,#1]              /* s[1] */
    cmp  x7,x6
    b.ne .wp_no
    cbz  w5,.wp_v0               /* *version = s[0] ? s[0]-0x50 : 0 */
    sub  w5,w5,#0x50
.wp_v0:
    str  w5,[x2]
    add  x6,x0,#2
    str  x6,[x3]                 /* *prog = s+2 */
    sub  x6,x1,#2
    str  w6,[x4]                 /* *proglen = n-2 */
    mov  w0,#1
    ret
.wp_no:
    mov  w0,#0
    ret
    .size sv_witness_program_asm,.-sv_witness_program_asm

/* ---------- last_push (internal) ----------
 *   in:  x0=ss, x1=ssl
 *   out: x0=dataPtr  x1=len  x2=npush  x3=1 success / 0 not-push-only-empty
 * (the x86 conveys success via CF; here via x3.)
 */
last_push:
    mov  x6,x0                   /* ss   */
    mov  x10,x1                  /* ssl  */
    mov  x8,#0                   /* p    */
    mov  x2,#0                   /* npush */
    mov  x9,#0                   /* data */
    mov  x1,#0                   /* len  */
.lp_loop:
    cmp  x8,x10
    b.hs .lp_done
    ldrb w5,[x6,x8]
    cmp  w5,#0x4b
    b.hi .lp_not_direct
    /* direct push 0x00..0x4b (0x00 lands here bug-for-bug like the x86/C) */
    add  x7,x8,#1
    add  x7,x7,x5                /* p+1+op */
    cmp  x7,x10
    b.hi .lp_bad
    add  x9,x6,x8
    add  x9,x9,#1                /* data = ss+p+1 */
    mov  x1,x5                   /* len = op */
    mov  x8,x7
    b    .lp_counted
.lp_not_direct:
    cmp  w5,#0x4c
    b.eq .lp_pd1
    cmp  w5,#0x4d
    b.eq .lp_pd2
    cmp  w5,#0x4e
    b.eq .lp_pd4
    cmp  w5,#0x4f
    b.eq .lp_smallint
    cmp  w5,#0x51
    b.lo .lp_bad
    cmp  w5,#0x60
    b.hi .lp_bad
.lp_smallint:                    /* OP_1NEGATE / OP_1..OP_16 (never OP_0) */
    add  x9,x6,x8                /* data = ss+p */
    mov  x1,#0                   /* len = 0 */
    add  x8,x8,#1
    b    .lp_counted
.lp_pd1:                         /* 0x4c: len byte follows */
    add  x12,x6,x8
    add  x7,x8,#2
    cmp  x7,x10
    b.hi .lp_bad
    ldrb w1,[x12,#1]             /* len */
    add  x7,x8,#2
    add  x7,x7,x1
    cmp  x7,x10
    b.hi .lp_bad
    add  x9,x6,x8
    add  x9,x9,#2
    mov  x8,x7
    b    .lp_counted
.lp_pd2:                         /* 0x4d: 2-byte LE len */
    add  x12,x6,x8
    add  x7,x8,#3
    cmp  x7,x10
    b.hi .lp_bad
    ldrh w1,[x12,#1]             /* len (LE) */
    add  x7,x8,#3
    add  x7,x7,x1
    cmp  x7,x10
    b.hi .lp_bad
    add  x9,x6,x8
    add  x9,x9,#3
    mov  x8,x7
    b    .lp_counted
.lp_pd4:                         /* 0x4e: 4-byte LE len, 64-bit-safe bound */
    add  x12,x6,x8
    add  x7,x8,#5
    cmp  x7,x10
    b.hi .lp_bad
    ldr  w1,[x12,#1]             /* len (zero-extends) */
    add  x7,x8,#5
    add  x7,x7,x1
    cmp  x7,x10
    b.hi .lp_bad
    add  x9,x6,x8
    add  x9,x9,#5
    mov  x8,x7
    b    .lp_counted
.lp_counted:
    add  x2,x2,#1
    b    .lp_loop
.lp_done:
    cbz  x2,.lp_bad
    mov  x0,x9                   /* return data ptr in x0 */
    mov  x3,#1
    ret
.lp_bad:
    mov  x3,#0
    ret

/* ---------- sv_classify_segwit_asm ---------- */
    .global sv_classify_segwit_asm
    .type sv_classify_segwit_asm,%function
sv_classify_segwit_asm:
    /* x0=spk x1=spl x2=ss x3=ssl x4=version x5=prog x6=proglen x7=wrapped */
    str  wzr,[x7]                /* *wrapped = 0 (always, like the C) */

    /* ---- frameless fast path: inline witness-program test on the spk ---- */
    cmp  x1,#4
    b.lo .not_native
    cmp  x1,#42
    b.hi .not_native
    ldrb w8,[x0]
    cbz  w8,.nv_ok
    cmp  w8,#0x51
    b.lo .not_native
    cmp  w8,#0x60
    b.hi .not_native
.nv_ok:
    sub  x9,x1,#2
    ldrb w10,[x0,#1]
    cmp  x10,x9                 /* s[1]==n-2 ? */
    b.ne .not_native
    cbz  w8,.nv_v0              /* *version = s[0] ? s[0]-0x50 : 0 */
    sub  w8,w8,#0x50
.nv_v0:
    str  w8,[x4]                /* *version */
    add  x8,x0,#2
    str  x8,[x5]                /* *prog = spk+2 */
    sub  x9,x1,#2
    str  w9,[x6]                /* *proglen = n-2 */
    mov  w0,#1
    ret
.not_native:
    /* not-P2SH shape -> legacy, still frameless */
    cmp  x1,#23
    b.ne .fast_legacy
    ldrb w8,[x0]
    cmp  w8,#0xa9
    b.ne .fast_legacy
    ldrb w8,[x0,#1]
    cmp  w8,#0x14
    b.ne .fast_legacy
    ldrb w8,[x0,#22]
    cmp  w8,#0x87
    b.eq .p2sh_slow
.fast_legacy:
    mov  w0,#0
    ret

    /* ---- framed slow path: P2SH-wrapped analysis ----
     * persistents x19..x28; npush on stack; h[20] at sp+112.
     */
.p2sh_slow:
    sub  sp,sp,#0x90
    stp  x29,x30,[sp,#0x00]
    stp  x19,x20,[sp,#0x10]
    stp  x21,x22,[sp,#0x20]
    stp  x23,x24,[sp,#0x30]
    stp  x25,x26,[sp,#0x40]
    str  x27,[sp,#0x50]
    str  x28,[sp,#0x58]
    mov  x29,sp
    mov  x19,x0                 /* spk */
    mov  x20,x1                 /* spl */
    mov  x21,x2                 /* ss  */
    mov  x22,x3                 /* ssl */
    mov  x23,x4                 /* version out */
    mov  x24,x5                 /* prog out */
    mov  x25,x6                 /* proglen out */
    mov  x26,x7                 /* wrapped out */

    /* last_push(ss, ssl) -> x0=data x1=len x2=npush x3=ok */
    mov  x0,x21
    mov  x1,x22
    bl   last_push
    cbz  x3,.legacy             /* not push-only / empty -> legacy */
    mov  x27,x0                 /* redeem data */
    mov  x28,x1                 /* redeem len */
    str  x2,[sp,#0x60]          /* npush */

    /* sv_witness_program_asm(redeem, rl, version, prog, proglen) */
    mov  x0,x27
    mov  x1,x28
    mov  x2,x23
    mov  x3,x24
    mov  x4,x25
    bl   sv_witness_program_asm
    cbz  x0,.legacy

    /* exactly one MINIMAL DIRECT push: npush==1 && ssl==1+rl && ss[0]==rl */
    ldr  x8,[sp,#0x60]          /* npush */
    cmp  x8,#1
    b.ne .malleated
    add  x8,x28,#1
    cmp  x22,x8                 /* ssl == 1 + rl ? */
    b.ne .malleated
    ldrb w8,[x21]               /* ss[0] */
    cmp  x8,x28                 /* ss[0] == rl ? */
    b.ne .malleated

    /* hash160(h[sp+112], redeem, rl); memcmp(h, spk+2, 20) */
    add  x0,sp,#112
    mov  x1,x27
    mov  x2,x28
    bl   hash160
    ldr  x1,[x19,#2]
    ldr  x2,[sp,#112]
    eor  x1,x1,x2
    ldr  x8,[x19,#10]
    ldr  x9,[sp,#120]
    eor  x8,x8,x9
    orr  x1,x1,x8
    ldr  w8,[x19,#18]
    ldr  w9,[sp,#128]
    eor  w8,w8,w9
    orr  x1,x1,x8
    cbnz x1,.malleated

    mov  w8,#1
    str  w8,[x26]               /* *wrapped = 1 */
    mov  w0,#2
    b    .out
.malleated:
    mov  x0,#-1                 /* full x0: -1 as a 64-bit long (not w0=zero-ext) */
    b    .out
.legacy:
    mov  w0,#0
.out:
    ldr  x28,[sp,#0x58]
    ldr  x27,[sp,#0x50]
    ldp  x25,x26,[sp,#0x40]
    ldp  x23,x24,[sp,#0x30]
    ldp  x21,x22,[sp,#0x20]
    ldp  x19,x20,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x90
    ret
    .size sv_classify_segwit_asm,.-sv_classify_segwit_asm

    .section .note.GNU-stack,"",@progbits
