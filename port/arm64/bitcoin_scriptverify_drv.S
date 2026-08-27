/* ============================================================================
 * bitcoin_scriptverify_drv.S -- AArch64 (ARMv8-A) port of asm/bitcoin_scriptverify_drv.asm
 *
 *   long sv_verify_script_asm(const u8* scriptSig, u64 ssl,
 *                             const u8* scriptPubKey, u64 spl,
 *                             u64 flags, u64 nIn,
 *                             const u8* tx, u64 txlen,
 *                             u8* work, u64 workcap) -> SCRIPT_ERR_*
 *
 * SysV amd64 -> AAPCS64: rdi,rsi,rdx,rcx,r8,r9 -> x0..x5; args 7,8 (tx,txlen)
 * -> x6,x7; args 9,10 (work,workcap) come from the stack [sp,#0],[sp,#8].
 *
 * Per-thread state mirrors the C twin exactly: main_e/copy_e (528,000B each)
 * and redeem (20,000B) are lazily malloc'd behind .tbss pointers. TLS uses
 * the Local-Exec model: address = tpidr_el0 + TP offset, via the full-range
 * :tprel_hi12: / :tprel_lo12_nc: relocation pair (the offsets can exceed 4K
 * in the differential test binaries, whose C side keeps big __thread buffers).
 *
 * AArch64 sv_run_v takes all 8 args in x0..x7 (sigversion, cs in x6,x7), so
 * no stack arguments are needed (unlike the x86 port's 2 pushed args).
 * ========================================================================== */

	.extern malloc
	.extern abort
	.extern memset
	.extern memcpy
	.extern sv_run_v
	.extern sv_true
	.extern sv_get_locktime_context
	.extern sv_checksig_export

	.text

	/* frame locals (offsets from SP after the full prologue, sp is 16-aligned) */
	.equ LOC_ST_E,   0
	.equ LOC_ST_SP,  8
	.equ LOC_CP_E,   16
	.equ LOC_CP_SP,  24
	.equ LOC_CTX,    32     /* 64 bytes */
	.equ LOC_ERR,    96     /* u32 */
	.equ LOC_MAIN,   104
	.equ LOC_COPY,   112
	.equ LOC_REDEEM, 120
	.equ LOC_RL,     128
	.equ LOC_LR,     136

	.equ ARENA_BYTES, 528000
	.equ ARENA_LO,    0x0EA0      /* 528000 = 0x8_0EA0 */
	.equ ARENA_HI,    0x8
	.equ REDEEM_CAP,  20000
	.equ REDEEM_LO,   0x4E20      /* 20000 = 0x4E20 */
	.equ ELEM_SIZE,   528
	.equ ELEM_DATA_OF,4

	.equ SVP2SH,      1
	.equ SVSPO,       32     /* 1<<5 */
	.equ SVCS,        256    /* 1<<8 */

	.equ ERR_OK,         0
	.equ ERR_EVAL_FALSE, 2
	.equ ERR_PUSH_SIZE,  6
	.equ ERR_INVSTACK,   18
	.equ ERR_SPO,        26
	.equ ERR_CLEANSTACK, 30

	.equ CTX_VERSION,   48
	.equ CTX_LOCKTIME,  40
	.equ CTX_SEQUENCE,  44

	.section .tbss,"awT",@nobits
	.global svs_main_e
	.type svs_main_e,@object
svs_main_e:
	.zero 8
	.global svs_copy_e
	.type svs_copy_e,@object
svs_copy_e:
	.zero 8
	.global svs_redeem
	.type svs_redeem,@object
svs_redeem:
	.zero 8

	.text

/* TLSLAZY rd, slot, size -- rd = this thread's lazily malloc'd buffer held by
 * the .tbss slot. Uses x9,x10 as scratch; preserves x19..x28 (callee-saved)
 * and, via str/ldr x30, the link register. sp stays 16-aligned. */
	.macro TLSLAZY rd, slot, lo, hi
	mrs  x9, tpidr_el0
	add  x9, x9, #:tprel_hi12:\slot
	add  x9, x9, #:tprel_lo12_nc:\slot
	ldr  \rd, [x9]
	cbnz \rd, 81f
	str  x30, [sp, #-16]!
	movz x0, #\lo
	movk x0, #\hi, lsl #16
	bl   malloc
	cbz  x0, 82f
	str  x0, [x9]
	mov  \rd, x0
	ldr  x30, [sp], #16
	b    81f
82:	/* malloc failed: abort */
	mov  x0, #0
	bl   abort
81:
	.endm

/* ============================================================================
 * push_only: x0=script, x1=n -> x0 1/0. Leaf (no inner bl), scratch x2..x7.
 * ========================================================================== */
	.type .Lpush_only, %function
.Lpush_only:
	mov  x2, #0                       /* i = 0 */
.Lploop:
	cmp  x2, x1
	b.hs .Lpdone
	ldrb w3, [x0, x2]
	cmp  w3, #0x4f                    /* OP_1NEGATE */
	b.eq .Lpone
	cmp  w3, #0x51
	b.lo .Lpnotsmall
	cmp  w3, #0x60
	b.hi .Lpno
.Lpone:
	add  x2, x2, #1
	b    .Lploop
.Lpnotsmall:
	cmp  w3, #0x4e
	b.hi .Lpno
	cmp  w3, #0x4b
	b.hi .Lppushdata
	add  x2, x2, x3                    /* i += 1 + op */
	add  x2, x2, #1
	b    .Lploop
.Lppushdata:
	cmp  w3, #0x4c
	b.eq .Lppd1
	cmp  w3, #0x4d
	b.eq .Lppd2
	/* PUSHDATA4: i+5 > n ? */
	add  x4, x2, #5
	cmp  x4, x1
	b.hi .Lpno
	add  x4, x0, x2
	ldr  w5, [x4, #1]                 /* 4-byte LE length */
	add  x2, x2, #5
	add  x2, x2, x5
	b    .Lploop
.Lppd1:
	add  x4, x2, #2
	cmp  x4, x1
	b.hi .Lpno
	add  x4, x0, x2
	ldrb w5, [x4, #1]
	add  x2, x2, #2
	add  x2, x2, x5
	b    .Lploop
.Lppd2:
	add  x4, x2, #3
	cmp  x4, x1
	b.hi .Lpno
	add  x4, x0, x2
	ldrh w5, [x4, #1]
	add  x2, x2, #3
	add  x2, x2, x5
	b    .Lploop
.Lpno:
	mov  w0, #0
	ret
.Lpdone:
	cmp  x2, x1
	cset w0, eq
	ret
	.size .Lpush_only, .-.Lpush_only

/* ============================================================================
 * sv_verify_script_asm -- see header.
 * ========================================================================== */
	.global sv_verify_script_asm
	.type sv_verify_script_asm, %function
sv_verify_script_asm:
	/* AAPCS: x19..x28 are CALLEE-SAVED and must be pushed BEFORE being
	 * clobbered by argument calibration. The old entry moved the args into
	 * x19..x28 (and read the stack args into x25/x26) first, then pushed,
	 * so the prologue saved the ARG values and the epilogue restored them
	 * -- clobbering whatever the caller kept in x19..x28. Same class of
	 * bug fixed in bitcoin_witness_v0_drv.S. Read the 2 stack args
	 * (work,workcap) into caller-saved x9/x10 first, push the caller's
	 * x19..x28, then calibrate. */
	/* entry: x0=ss x1=ssl x2=spk x3=spl x4=flags x5=nIn x6=tx x7=txlen,
	   [sp,#0]=work [sp,#8]=workcap */
	ldr  x9,  [sp, #0]                 /* work */
	ldr  x10, [sp, #8]                 /* workcap */
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	sub  sp, sp, #160
	mov  x19, x0                       /* scriptSig */
	mov  x20, x1                       /* ssl */
	mov  x21, x2                       /* scriptPubKey */
	mov  x22, x3                       /* spl */
	mov  x23, x4                       /* flags */
	mov  x24, x5                       /* nIn */
	mov  x27, x6                       /* tx */
	mov  x28, x7                       /* txlen */
	mov  x25, x9                       /* work */
	mov  x26, x10                      /* workcap */

	TLSLAZY x10, svs_main_e, ARENA_LO, ARENA_HI
	str  x10, [sp, #LOC_MAIN]
	TLSLAZY x11, svs_copy_e, ARENA_LO, ARENA_HI
	str  x11, [sp, #LOC_COPY]

	/* st = { main_e, 0 }; cp = { copy_e, 0 } */
	str  x10, [sp, #LOC_ST_E]
	str  xzr, [sp, #LOC_ST_SP]
	str  x11, [sp, #LOC_CP_E]
	str  xzr, [sp, #LOC_CP_SP]

	/* ctx = { tx, txlen, nIn, work, workcap, 0,0,0, amount=0 } */
	str  x27, [sp, #LOC_CTX+0]
	str  x28, [sp, #LOC_CTX+8]
	str  x24, [sp, #LOC_CTX+16]
	str  x25, [sp, #LOC_CTX+24]
	str  x26, [sp, #LOC_CTX+32]
	str  xzr, [sp, #LOC_CTX+40]        /* locktime + sequence */
	str  xzr, [sp, #LOC_CTX+48]        /* version */
	str  xzr, [sp, #LOC_CTX+56]        /* amount */

	/* sv_get_locktime_context(tx, txlen, nIn, &version, &locktime, &sequence) */
	mov  x0, x27
	mov  x1, x28
	mov  x2, x24
	add  x3, sp, #LOC_CTX+CTX_VERSION
	add  x4, sp, #LOC_CTX+CTX_LOCKTIME
	add  x5, sp, #LOC_CTX+CTX_SEQUENCE
	bl   sv_get_locktime_context

	/* memset(main_e, 0, ARENA_BYTES) -- the C's per-call zeroing */
	ldr  x0, [sp, #LOC_MAIN]
	mov  x1, #0
	movz x2, #ARENA_LO
	movk x2, #ARENA_HI, lsl #16
	bl   memset

	/* SIGPUSHONLY gate */
	tbz  x23, #5, .Lrun_sig            /* flag bit 5 = 1<<5 */
	mov  x0, x19
	mov  x1, x20
	bl   .Lpush_only
	cbz  w0, .Lr_pushonly

.Lrun_sig:
	str  wzr, [sp, #LOC_ERR]
	mov  x0, x19
	mov  x1, x20
	bl   .Lrun_one
	cbz  w0, .Lr_err

	/* P2SH: snapshot the post-scriptSig stack */
	tbz  x23, #0, .Lrun_spk            /* flag bit 0 = SV_P2SH */
	ldr  x0, [sp, #LOC_COPY]
	ldr  x1, [sp, #LOC_MAIN]
	movz x2, #ARENA_LO
	movk x2, #ARENA_HI, lsl #16
	bl   memcpy
	ldr  x9, [sp, #LOC_ST_SP]
	str  x9, [sp, #LOC_CP_SP]

.Lrun_spk:
	mov  x0, x21                       /* scriptPubKey */
	mov  x1, x22                       /* spl */
	bl   .Lrun_one
	cbz  w0, .Lr_err
	/* st.sp == 0 -> EVAL_FALSE ; !sv_true(&st, sp-1) -> EVAL_FALSE */
	ldr  x9, [sp, #LOC_ST_SP]
	cbz  x9, .Lr_evalfalse
	add  x0, sp, #LOC_ST_E
	sub  x1, x9, #1
	bl   sv_true
	cbz  w0, .Lr_evalfalse

	/* ---- BIP16 ---- */
	tbz  x23, #0, .Lcleanstack
	/* sv_is_p2sh(spk, spl): 23 bytes, a9 14 .. 87 */
	cmp  x22, #23
	b.ne .Lcleanstack
	ldrb w9, [x21, #0]
	cmp  w9, #0xa9
	b.ne .Lcleanstack
	ldrb w9, [x21, #1]
	cmp  w9, #0x14
	b.ne .Lcleanstack
	ldrb w9, [x21, #22]
	cmp  w9, #0x87
	b.ne .Lcleanstack
	/* scriptSig must be push-only (checked HERE too, matching the C) */
	mov  x0, x19
	mov  x1, x20
	bl   .Lpush_only
	cbz  w0, .Lr_pushonly

	/* TLSLAZY clobbers x9 (it uses x9 as its TLS-slot-address scratch), so
	 * cp.sp must be reloaded from the frame AFTER the lazy alloc, not held
	 * in x9 across it -- the old code loaded cp.sp into x9 first, then
	 * reused the clobbered x9 here, corrupting the top-of-stack index. */
	TLSLAZY x13, svs_redeem, REDEEM_LO, 0
	str  x13, [sp, #LOC_REDEEM]
	ldr  x9, [sp, #LOC_CP_SP]
	cbz  x9, .Lr_invstack
	/* rl = *(u32*)(copy_e + (sp-1)*ELEM_SIZE) */
	sub  x9, x9, #1
	mov  x10, #ELEM_SIZE
	mul  x9, x9, x10
	ldr  x11, [sp, #LOC_COPY]
	add  x9, x9, x11
	ldr  w12, [x9]                     /* rl */
	str  x12, [sp, #LOC_RL]
	movz x10, #REDEEM_LO               /* REDEEM_CAP */
	cmp  x12, x10
	b.hi .Lr_pushsize
	/* memcpy(redeem, rec+4, rl) */
	mov  x0, x13
	add  x1, x9, #ELEM_DATA_OF
	mov  x2, x12
	bl   memcpy
	/* cp.sp--; restore main from the snapshot; st.sp = cp.sp */
	ldr  x9, [sp, #LOC_CP_SP]
	sub  x9, x9, #1
	str  x9, [sp, #LOC_CP_SP]
	ldr  x0, [sp, #LOC_MAIN]
	ldr  x1, [sp, #LOC_COPY]
	movz x2, #ARENA_LO
	movk x2, #ARENA_HI, lsl #16
	bl   memcpy
	str  x9, [sp, #LOC_ST_SP]
	/* run the redeem script */
	ldr  x0, [sp, #LOC_REDEEM]
	ldr  x1, [sp, #LOC_RL]
	bl   .Lrun_one
	cbz  w0, .Lr_err
	ldr  x9, [sp, #LOC_ST_SP]
	cbz  x9, .Lr_evalfalse
	add  x0, sp, #LOC_ST_E
	sub  x1, x9, #1
	bl   sv_true
	cbz  w0, .Lr_evalfalse

.Lcleanstack:
	tbz  x23, #8, .Lok                 /* flag bit 8 = SV_CLEANSTACK */
	ldr  x9, [sp, #LOC_ST_SP]
	cmp  x9, #1
	b.ne .Lr_cleanstack
.Lok:
	mov  w0, #ERR_OK
	b    .Lout

.Lr_pushonly:  mov w0, #ERR_SPO;        b .Lout
.Lr_evalfalse: mov w0, #ERR_EVAL_FALSE; b .Lout
.Lr_invstack:  mov w0, #ERR_INVSTACK;   b .Lout
.Lr_pushsize:  mov w0, #ERR_PUSH_SIZE;  b .Lout
.Lr_cleanstack:mov w0, #ERR_CLEANSTACK; b .Lout
.Lr_err:
	ldr  w0, [sp, #LOC_ERR]
.Lout:
	add  sp, sp, #160
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size sv_verify_script_asm, .-sv_verify_script_asm

/* ============================================================================
 * .Lrun_one: x0=script, x1=slen -> sv_run_v's 1/0 (err already stored).
 * Local helper CALLed from sv_verify_script_asm. Saves x30 across the inner
 * bl sv_run_v (a bare ret after bl would loop forever). sv_run_v takes all 8
 * args in registers on AArch64, so no stack args are needed.
 * ========================================================================== */
	.type .Lrun_one, %function
.Lrun_one:
	str  x30, [sp, #LOC_LR]
	add  x2, sp, #LOC_ST_E             /* &st (LOC_ST_E == 0, == sp) */
	mov  x3, x23                       /* flags */
	add  x4, sp, #LOC_CTX             /* &ctx */
	add  x5, sp, #LOC_ERR             /* &err */
	mov  x6, #0                        /* SIGV_BASE */
	adrp x7, sv_checksig_export
	add  x7, x7, :lo12:sv_checksig_export
	bl   sv_run_v
	ldr  x30, [sp, #LOC_LR]
	ret
	.size .Lrun_one, .-.Lrun_one

	.section .note.GNU-stack,"",%progbits
