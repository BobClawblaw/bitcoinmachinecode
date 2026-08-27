/* ============================================================================
 * bitcoin_witness_v0_drv.S -- AArch64 (ARMv8-A) port of asm/bitcoin_witness_v0_drv.asm
 *
 *   long sv_verify_witness_v0_asm(const u8* prog, u32 proglen,
 *                                 const u8* const* wit, const u32* witlen,
 *                                 u32 nwit, u64 amount,
 *                                 u64 flags, u64 nIn,
 *                                 const u8* tx, u64 txlen,
 *                                 u8* work, u64 workcap) -> SCRIPT_ERR_*
 *
 * SysV amd64 -> AAPCS64: rdi,rsi,rdx,rcx,r8d,r9 -> x0,x1,x2,x3,w4,x5;
 * args 7,8 (flags,nIn) -> x6,x7; args 9..12 (tx,txlen,work,workcap) come
 * from the stack [sp,#0]..[sp,#24].
 *
 * Per-thread state mirrors the C twin exactly: main_e is a lazily-malloc'd
 * 528,000B arena behind a .tbss pointer; the 25-byte implied-P2WPKH script is
 * a .tbss array. TLS = Local-Exec (tpidr_el0 + :tprel_hi12:/:tprel_lo12_nc:).
 * ========================================================================== */

	.extern malloc
	.extern abort
	.extern memcpy
	.extern sha256_full
	.extern sv_run_v
	.extern sv_true
	.extern sv_get_locktime_context
	.extern sv_checksig_witness_v0_export

	.text

	/* frame locals (offsets from SP after the full prologue; sp 16-aligned) */
	.equ W_ST_E,    32
	.equ W_ST_SP,   40
	.equ W_CTX,     48     /* 64 bytes: tx@0 txlen@8 nIn@16 work@24 workcap@32 locktime@40 seq@44 ver@48 amount@56 */
	.equ W_ERR,     112    /* u32 */
	.equ W_MAIN,    120
	.equ W_SCRIPT,  128
	.equ W_SLEN,    136
	.equ W_NSTACK,  144
	.equ W_FLAGS,   152
	.equ W_LR,      160
	.equ W_H,       168     /* h[32] spans 168..199; frame is 208 */

	.equ ARENA_BYTES, 528000
	.equ ARENA_LO,    0x0EA0   /* 528000 = 0x8_0EA0 */
	.equ ARENA_HI,    0x8
	.equ MAX_ELEM,     520
	.equ MAX_STACK,    1000
	.equ ELEM_SIZE,    528
	.equ ELEM_DATA_OF, 4

	.equ ERR_OK,           0
	.equ ERR_EVAL_FALSE,   2
	.equ ERR_PUSH_SIZE,    6
	.equ ERR_STACK_SIZE,   8
	.equ ERR_CLEANSTACK,   30
	.equ ERR_WP_WRONG_LEN, 38
	.equ ERR_WP_WIT_EMPTY, 39
	.equ ERR_WP_MISMATCH,  40

	.equ CTX_LOCKTIME, 40
	.equ CTX_SEQUENCE, 44
	.equ CTX_VERSION,  48

	.section .tbss,"awT",@nobits
	.global wv0_main_e
	.type wv0_main_e,@object
wv0_main_e:
	.zero 8
	.global wv0_p2wpkh
	.type wv0_p2wpkh,@object
wv0_p2wpkh:
	.zero 25

	.text

/* TLSLAZY rd, slot, lo, hi -- rd = this thread's lazily malloc'd buffer. */
	.macro TLSLAZY rd, slot, lo, hi
	mrs  x9, tpidr_el0
	add  x9, x9, #:tprel_hi12:\slot
	add  x9, x9, #:tprel_lo12_nc:\slot
	ldr  \rd, [x9]
	cbnz \rd, 91f
	str  x30, [sp, #-16]!
	movz x0, #\lo
	movk x0, #\hi, lsl #16
	bl   malloc
	cbz  x0, 92f
	str  x0, [x9]
	mov  \rd, x0
	ldr  x30, [sp], #16
	b    91f
92:	mov  x0, #0
	bl   abort
91:
	.endm

/* ============================================================================
 * sv_verify_witness_v0_asm -- see header.
 * ========================================================================== */
	.global sv_verify_witness_v0_asm
	.type sv_verify_witness_v0_asm, %function
sv_verify_witness_v0_asm:
	/* AAPCS: x19..x28 are CALLEE-SAVED. The callee must push the CALLER's
	 * values before using them as scratch. The old entry calibrated
	 * x19/x20/x21/x22/x23/x28 from the args and read the stack args into
	 * x1..x4 BEFORE pushing, so the prologue stored the arg values in the
	 * save slots and the epilogue restored those -- silently clobbering
	 * whatever the caller kept in x19..x28 (observed: main held its result
	 * in w19 across the call and got garbage). Fix: read the 4 stack args
	 * into caller-saved x9..x12 first, push (saving the real caller's
	 * x19..x28), then calibrate from x0..x7/x9..x12. */
	/* x0=prog x1=proglen(w) x2=wit x3=witlen x4=nwit(w) x5=amount
	   x6=flags x7=nIn [sp,0]=tx [sp,8]=txlen [sp,16]=work [sp,24]=workcap */
	ldr  x9,  [sp, #0]      /* tx */
	ldr  x10, [sp, #8]      /* txlen */
	ldr  x11, [sp, #16]     /* work */
	ldr  x12, [sp, #24]     /* workcap */
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	sub  sp, sp, #208
	mov  x19, x0            /* prog */
	mov  w20, w1            /* proglen */
	mov  x21, x2            /* wit */
	mov  x22, x3            /* witlen */
	mov  w23, w4            /* nwit */
	mov  x28, x5            /* amount */

	/* ctx region = { tx, txlen, nIn, work, workcap, 0,0,0, amount } */
	str  x9,  [sp, #W_CTX+0]
	str  x10, [sp, #W_CTX+8]
	str  x7,  [sp, #W_CTX+16]
	str  x11, [sp, #W_CTX+24]
	str  x12, [sp, #W_CTX+32]
	str  xzr, [sp, #W_CTX+40]
	str  xzr, [sp, #W_CTX+48]
	str  x28, [sp, #W_CTX+56]
	str  x6,  [sp, #W_FLAGS]            /* flags (preserved for sv_run_v) */

	/* this thread's stack arena, lazily malloc'd */
	TLSLAZY x16, wv0_main_e, ARENA_LO, ARENA_HI
	str  x16, [sp, #W_MAIN]

	/* ---- shape selection ---- */
	cmp  w20, #32
	b.eq .Wp2wsh
	cmp  w20, #20
	b.eq .Wp2wpkh
	mov  w0, #ERR_WP_WRONG_LEN
	b    .Wout

.Wp2wsh:
	cbz  w23, .Wr_empty
	/* i = nwit-1 ; script = wit[i] ; slen = witlen[i] */
	sub  x1, x23, #1
	ldr  x2, [x21, x1, lsl #3]         /* wit[i] */
	add  x0, x22, x1, lsl #2
	ldr  w3, [x0]                      /* witlen[i] */
	str  x2, [sp, #W_SCRIPT]
	str  x3, [sp, #W_SLEN]
	/* sha256(script) -> h[32] at [sp,#W_H] */
	str  x30, [sp, #W_LR]
	mov  x0, x2                        /* wit[i] as msg */
	mov  x1, x2
	mov  x2, x3                        /* len */
	add  x0, sp, #W_H                  /* out */
	bl   sha256_full
	ldr  x30, [sp, #W_LR]
	/* xor against prog (x19), word by word */
	ldr  x1, [sp, #W_H+0]
	ldr  x2, [x19, #0]
	eor  x1, x1, x2
	ldr  x2, [sp, #W_H+8]
	ldr  x3, [x19, #8]
	eor  x2, x2, x3
	orr  x1, x1, x2
	ldr  x2, [sp, #W_H+16]
	ldr  x3, [x19, #16]
	eor  x2, x2, x3
	orr  x1, x1, x2
	ldr  x2, [sp, #W_H+24]
	ldr  x3, [x19, #24]
	eor  x2, x2, x3
	orr  x1, x1, x2
	cbnz x1, .Wr_mismatch
	sub  x0, x23, #1
	str  x0, [sp, #W_NSTACK]           /* nstack = nwit - 1 */
	b    .Wfill

.Wp2wpkh:
	cmp  w23, #2
	b.ne .Wr_mismatch
	/* build the implied P2PKH script into the .tbss wv0_p2wpkh array */
	mrs  x1, tpidr_el0
	add  x1, x1, #:tprel_hi12:wv0_p2wpkh
	add  x1, x1, #:tprel_lo12_nc:wv0_p2wpkh
	mov  w2, #0x76                     /* OP_DUP */
	strb w2, [x1, #0]
	mov  w2, #0xa9                     /* OP_HASH160 */
	strb w2, [x1, #1]
	mov  w2, #0x14                     /* push 20 */
	strb w2, [x1, #2]
	ldr  x2, [x19, #0]
	str  x2, [x1, #3]
	ldr  x2, [x19, #8]
	str  x2, [x1, #11]
	ldr  w2, [x19, #16]
	str  w2, [x1, #19]
	mov  w2, #0x88                     /* OP_EQUALVERIFY */
	strb w2, [x1, #23]
	mov  w2, #0xac                     /* OP_CHECKSIG */
	strb w2, [x1, #24]
	str  x1, [sp, #W_SCRIPT]
	mov  x2, #25
	str  x2, [sp, #W_SLEN]
	mov  x2, #2
	str  x2, [sp, #W_NSTACK]
	b    .Wfill

.Wfill:
	/* nstack > MAX_STACK -> STACK_SIZE */
	ldr  x0, [sp, #W_NSTACK]
	cmp  x0, #MAX_STACK
	b.hi .Wr_stacksize
	/* st = { main_e, 0 } */
	ldr  x0, [sp, #W_MAIN]
	str  x0, [sp, #W_ST_E]
	str  xzr, [sp, #W_ST_SP]
	mov  x5, #0                        /* i = 0 */
.LWfill_loop:
	ldr  x1, [sp, #W_NSTACK]
	cmp  x5, x1
	b.hs .Wrun
	add  x1, x22, x5, lsl #2
	ldr  w2, [x1]                      /* witlen[i] */
	cmp  w2, #MAX_ELEM
	b.hi .Wr_pushsize
	/* rec = main_e + i*ELEM_SIZE; *(u32*)rec = len */
	mov  x6, #ELEM_SIZE
	mul  x6, x5, x6
	ldr  x7, [sp, #W_MAIN]
	add  x6, x6, x7
	str  w2, [x6, #0]
	/* memcpy(rec+4, wit[i], len) */
	str  x30, [sp, #W_LR]
	add  x0, x6, #ELEM_DATA_OF
	add  x1, x21, x5, lsl #3
	ldr  x1, [x1]
	mov  x3, x2
	bl   memcpy
	ldr  x30, [sp, #W_LR]
	/* st.sp++ */
	ldr  x0, [sp, #W_ST_SP]
	add  x0, x0, #1
	str  x0, [sp, #W_ST_SP]
	add  x5, x5, #1
	b    .LWfill_loop

.Wrun:
	/* sv_get_locktime_context(tx, txlen, nIn, &ver, &lt, &seq) */
	mov  x0, x24                       /* scratch */
	ldr  x0, [sp, #W_CTX+0]
	ldr  x1, [sp, #W_CTX+8]
	ldr  x2, [sp, #W_CTX+16]
	add  x3, sp, #W_CTX+CTX_VERSION
	add  x4, sp, #W_CTX+CTX_LOCKTIME
	add  x5, sp, #W_CTX+CTX_SEQUENCE
	bl   sv_get_locktime_context
	/* err = OK; sv_run_v(script, slen, &st, flags, &ctx, &err, WV0, cs) */
	str  wzr, [sp, #W_ERR]
	ldr  x0, [sp, #W_SCRIPT]
	ldr  x1, [sp, #W_SLEN]
	add  x2, sp, #W_ST_E
	ldr  x3, [sp, #W_FLAGS]
	add  x4, sp, #W_CTX
	add  x5, sp, #W_ERR
	mov  x6, #1                        /* SIGVERSION_WITNESS_V0 */
	adrp x7, sv_checksig_witness_v0_export
	add  x7, x7, :lo12:sv_checksig_witness_v0_export
	bl   sv_run_v
	cbz  w0, .Wrun_failed
	/* cleanstack: exactly one element left */
	ldr  x0, [sp, #W_ST_SP]
	cmp  x0, #1
	b.ne .Wr_cleanstack
	/* ... and it must cast to true */
	add  x0, sp, #W_ST_E
	mov  x1, #0
	bl   sv_true
	cbz  w0, .Wr_evalfalse
	mov  w0, #ERR_OK
	b    .Wout
.Wrun_failed:
	ldr  w0, [sp, #W_ERR]
	b    .Wout

.Wr_empty:      mov w0, #ERR_WP_WIT_EMPTY; b .Wout
.Wr_mismatch:   mov w0, #ERR_WP_MISMATCH;  b .Wout
.Wr_stacksize:  mov w0, #ERR_STACK_SIZE;   b .Wout
.Wr_pushsize:   mov w0, #ERR_PUSH_SIZE;    b .Wout
.Wr_cleanstack: mov w0, #ERR_CLEANSTACK;   b .Wout
.Wr_evalfalse:  mov w0, #ERR_EVAL_FALSE
.Wout:
	/* Epilogue must mirror the prologue, which saves SIX pairs bottom-up:
	 * x29,x30 / x19,x20 / x21,x22 / x23,x24 / x25,x26 / x27,x28, pushed in
	 * that order so x27,x28 sit lowest (at the restored-sp start) and
	 * x29,x30 highest. The old epilogue popped only FIVE pairs starting at
	 * x25,x26 -- one pair short and shifted -- so every callee-saved
	 * register (incl. x26) was restored from the wrong slot and x30 never
	 * got its real return address (garbage `ret`). */
	add  sp, sp, #208
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size sv_verify_witness_v0_asm, .-sv_verify_witness_v0_asm

	.section .note.GNU-stack,"",%progbits
