/* ============================================================================
 * bitcoin_scriptcodec.S -- AArch64 port of asm/bitcoin_scriptcodec.asm
 * (support layer for the script interpreter). This file hosts the PURE,
 * stack-independent primitives; the element-stack engine and vfExec helpers
 * follow in the same module.
 *
 * Ported here (each verified against a Python oracle):
 *   int64 scriptnum_decode(u64 len, const u8* data, u64 maxsize)
 *        -> x0 = value (sets global snum_overflow = 1 if len > maxsize)
 *   ScriptNumOut scriptnum_serialize(int64 value)
 *        -> x0 = ptr into scriptnum_buf, x1 = byte length
 *   int cast_to_bool(u64 len, const u8* data)             -> x0 0/1
 *   int der_sig_strict(const u8* sig, u64 siglen)         -> x0 0/1 (BIP66)
 *   int check_minimal_push(u32 opcode, u64 pushlen, const u8* data) -> x0 0/1
 *
 * Element record (shared ABI, ELEM_SIZE=528): u32 len @0, data[520] @4.
 * ========================================================================== */

	.text
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

/* TLS Initial-Exec address of a .tbss symbol into d (clobbers x17 -- free at
 * every conversion site here; the only x17 use in the file, line ~567, is a
 * different local routine). Scratch buffers are PER-THREAD (x86 parity): the
 * threaded daemon verifies many inputs across worker threads concurrently. */
	.macro TLS_ADDR d, sym
	adrp \d, :gottprel:\sym
	ldr  \d, [\d, #:gottprel_lo12:\sym]
	mrs  x17, tpidr_el0
	add  \d, \d, x17
	.endm

	.section .tbss,"awT",@nobits
	.balign 16
	.global scriptnum_buf
scriptnum_buf:
	.space 16
	.global snum_overflow
snum_overflow:
	.space 8
	.global elem_tmp0, elem_tmp1, elem_tmp2, elem_tmp3
elem_tmp0: .space 528
elem_tmp1: .space 528
elem_tmp2: .space 528
elem_tmp3: .space 528
	.text

/* ============================================================================
 * scriptnum_decode(x0=len, x1=data, x2=maxsize) -> x0 = int64 value.
 * Mirrors Core CScriptNum::operator long long (signed, little-endian base-256
 * with sign in the top bit of the final byte).
 * ========================================================================== */
	.global scriptnum_decode
	.type scriptnum_decode, %function
scriptnum_decode:
	TLS_ADDR x9, snum_overflow
	str  xzr, [x9]                  /* overflow = 0 */
	cmp  x0, x2                     /* len vs maxsize */
	b.ls 1f
	mov  w3, #1
	str  x3, [x9]                   /* overflow = 1 */
1:
	mov  x4, x0                     /* len */
	mov  x5, x1                     /* data */
	mov  x6, xzr                    /* result */
	mov  x7, xzr                    /* i */
	cbz  x4, 8f
2:
	cmp  x7, x4
	b.hs 3f
	ldrb w8, [x5, x7]
	mov  x9, x7
	lsl  x9, x9, #3
	lsl  x8, x8, x9
	orr  x6, x6, x8
	add  x7, x7, #1
	b    2b
3:
	sub  x9, x4, #1                 /* len-1 */
	ldrb w8, [x5, x9]
	tst  w8, #0x80
	b.eq 8f
	lsl  x9, x9, #3                 /* (len-1)*8 */
	mov  x10, #0x80
	lsl  x10, x10, x9
	mvn  x10, x10
	and  x6, x6, x10
	neg  x6, x6
8:
	mov  x0, x6
	ret
	.size scriptnum_decode, .-scriptnum_decode

/* ============================================================================
 * scriptnum_serialize(x0=value) -> x0=ptr, x1=len (into scriptnum_buf[16]).
 * Port of CScriptNum::serialize.
 * ========================================================================== */
	.global scriptnum_serialize
	.type scriptnum_serialize, %function
scriptnum_serialize:
	TLS_ADDR x3, scriptnum_buf
	mov  x4, x0                     /* value */
	cbz  x4, .sz_zero
	mov  x5, #0                     /* neg flag */
	cmp  x4, #0
	b.ge 1f
	mov  x5, #1
	neg  x4, x4                     /* abs */
1:
	mov  x6, #0                     /* out index */
2:
	cbz  x4, 3f
	and  w7, w4, #0xff
	strb w7, [x3, x6]
	lsr  x4, x4, #8
	add  x6, x6, #1
	b    2b
3:
	sub  x7, x6, #1                 /* last index */
	ldrb w8, [x3, x7]
	tst  w8, #0x80
	b.eq 4f
	/* top byte & 0x80: append sign byte */
	mov  x9, #0x80
	cbz  x5, .sz_possign
	b    .sz_negsign
.sz_possign:
	mov  x9, #0
.sz_negsign:
	strb w9, [x3, x6]
	add  x6, x6, #1
	b    5f
4:
	cbz  x5, 5f
	/* negative, top byte < 0x80: OR 0x80 into last byte */
	ldrb w9, [x3, x7]
	orr  w9, w9, #0x80
	strb w9, [x3, x7]
5:
	mov  x0, x3
	mov  x1, x6                     /* len */
	ret
.sz_zero:
	mov  x0, x3
	mov  x1, #0
	ret
	.size scriptnum_serialize, .-scriptnum_serialize

/* ============================================================================
 * cast_to_bool(x0=len, x1=data) -> x0 0/1. Core CastToBool.
 * ========================================================================== */
	.global cast_to_bool
	.type cast_to_bool, %function
cast_to_bool:
	cbz  x0, 9f
	mov  x3, #0                     /* i */
0:
	cmp  x3, x0
	b.hs 9f
	ldrb w4, [x1, x3]
	cbz  w4, 1f
	sub  x5, x0, #1
	cmp  x3, x5
	b.ne 8f
	cmp  w4, #0x80
	b.eq 9f
8:
	mov  w0, #1
	ret
1:
	add  x3, x3, #1
	b    0b
9:
	mov  w0, #0
	ret
	.size cast_to_bool, .-cast_to_bool

/* ============================================================================
 * der_sig_strict(x0=sig, x1=siglen) -> x0 0/1. Core IsValidSignatureEncoding,
 * BIP66, checks in Core's exact order.
 * ========================================================================== */
	.global der_sig_strict
	.type der_sig_strict, %function
der_sig_strict:
	cmp  x1, #9
	b.lo .db
	cmp  x1, #73
	b.hi .db
	ldrb w2, [x0]
	cmp  w2, #0x30
	b.ne .db
	ldrb w3, [x0, #1]
	sub  x4, x1, #3
	cmp  x3, x4
	b.ne .db
	ldrb w5, [x0, #3]               /* lenR */
	add  x6, x5, #5                 /* 5+lenR */
	cmp  x6, x1
	b.hs .db
	ldrb w7, [x0, x6]               /* lenS */
	add  x8, x5, x7
	add  x8, x8, #7
	cmp  x8, x1
	b.ne .db
	ldrb w9, [x0, #2]
	cmp  w9, #0x02
	b.ne .db
	cbz  w5, .db                     /* lenR == 0 */
	ldrb w9, [x0, #4]
	tst  w9, #0x80                   /* R negative */
	b.ne .db
	cmp  w5, #1
	b.ls .roK
	ldrb w9, [x0, #4]
	cbnz w9, .roK
	ldrb w9, [x0, #5]
	tst  w9, #0x80
	b.eq .db
.roK:
	add  x10, x5, #4
	ldrb w9, [x0, x10]
	cmp  w9, #0x02
	b.ne .db
	cbz  w7, .db                     /* lenS == 0 */
	add  x10, x5, #6
	ldrb w9, [x0, x10]
	tst  w9, #0x80                   /* S negative */
	b.ne .db
	cmp  w7, #1
	b.ls .ok
	ldrb w9, [x0, x10]
	cbnz w9, .ok
	add  x11, x5, #7
	ldrb w9, [x0, x11]
	tst  w9, #0x80
	b.eq .db
.ok:
	mov  w0, #1
	ret
.db:
	mov  w0, #0
	ret
	.size der_sig_strict, .-der_sig_strict

/* ============================================================================
 * check_minimal_push(x0=opcode, x1=pushlen, x2=data) -> x0 0/1. Core's
 * CheckMinimalPush.
 * ========================================================================== */
	.global check_minimal_push
	.type check_minimal_push, %function
check_minimal_push:
	cbz  x1, .mp_empty
	cmp  x1, #1
	b.ne .mp_not1
	ldrb w3, [x2]
	cmp  w3, #1
	b.lo .mp_not1min
	cmp  w3, #16
	b.hi .mp_not1
	mov  w0, #0
	ret
.mp_not1min:
	ldrb w3, [x2]
	cmp  w3, #0x81
	b.ne .mp_not1
	mov  w0, #0
	ret
.mp_empty:
	cbz  w0, 8f
	mov  w0, #0
	ret
8:
	mov  w0, #1
	ret
.mp_not1:
	cmp  x1, #75
	b.hi .mp_255
	cmp  w0, w1
	cset w0, eq
	ret
.mp_255:
	cmp  x1, #255
	b.hi .mp_65535
	cmp  w0, #0x4c
	cset w0, eq
	ret
.mp_65535:
	movz x13, #0xffff
	cmp  x1, x13
	b.hi .mp_big
	cmp  w0, #0x4d
	cset w0, eq
	ret
.mp_big:
	mov  w0, #1
	ret
	.size check_minimal_push, .-check_minimal_push

	.section .note.GNU-stack,"",%progbits

/* ============================================================================
 * part 2: TLS-buffer getters, element-stack engine, get_op, vfexec condition
 * stack. Mirrors asm/bitcoin_scriptcodec.asm lines ~63-978.
 * Constants: ELEM_SIZE=528 (ELEM_DATA_OFF=4, len u32 @0, data[520] @4),
 * MAX_STACK_SIZE=1000.
 * ========================================================================== */

	.section .tbss,"awT",@nobits
	.align 4
vfexec:		.space 1024	/* condition stack (bytes) */
vfexec_sp:	.space 8

	.text
	.global elem_tmp0_addr
	.type elem_tmp0_addr,%function
elem_tmp0_addr:
	TLS_ADDR x0, elem_tmp0
	ret
	.size elem_tmp0_addr,.-elem_tmp0_addr

	.global elem_tmp1_addr
	.type elem_tmp1_addr,%function
elem_tmp1_addr:
	TLS_ADDR x0, elem_tmp1
	ret
	.size elem_tmp1_addr,.-elem_tmp1_addr

	.global elem_tmp2_addr
	.type elem_tmp2_addr,%function
elem_tmp2_addr:
	TLS_ADDR x0, elem_tmp2
	ret
	.size elem_tmp2_addr,.-elem_tmp2_addr

	.global elem_tmp3_addr
	.type elem_tmp3_addr,%function
elem_tmp3_addr:
	TLS_ADDR x0, elem_tmp3
	ret
	.size elem_tmp3_addr,.-elem_tmp3_addr

	.global snum_overflow_addr
	.type snum_overflow_addr,%function
snum_overflow_addr:
	TLS_ADDR x0, snum_overflow
	ret
	.size snum_overflow_addr,.-snum_overflow_addr

	.global stack_depth
	.type stack_depth,%function
stack_depth:
	ldr x0,[x0]			/* *sp */
	ret
	.size stack_depth,.-stack_depth

	.macro ELEM_PTR idxreg, elemsreg, outreg
	mov  w9, #528
	mul  \outreg, \idxreg, x9
	add  \outreg, \outreg, \elemsreg
	.endm

	.global stack_top_ptr
	.type stack_top_ptr,%function
stack_top_ptr:				/* x0=&sp, x1=elems -> A record */
	ldr x2,[x0]
	sub x2,x2,#1
	ELEM_PTR x2, x1, x0
	ret
	.size stack_top_ptr,.-stack_top_ptr

	.global stack_second_ptr
	.type stack_second_ptr,%function
stack_second_ptr:
	ldr x2,[x0]
	sub x2,x2,#2
	ELEM_PTR x2, x1, x0
	ret
	.size stack_second_ptr,.-stack_second_ptr

	.global stack_third_ptr
	.type stack_third_ptr,%function
stack_third_ptr:
	ldr x2,[x0]
	sub x2,x2,#3
	ELEM_PTR x2, x1, x0
	ret
	.size stack_third_ptr,.-stack_third_ptr

	.global stack_elem_ptr
	.type stack_elem_ptr,%function
stack_elem_ptr:				/* x1=elems, x2=idx -> ptr */
	ELEM_PTR x2, x1, x0
	ret
	.size stack_elem_ptr,.-stack_elem_ptr

	.global stack_pop
	.type stack_pop,%function
stack_pop:				/* x0=&sp */
	ldr x2,[x0]
	cbz x2, 9f
	sub x2,x2,#1
	str x2,[x0]
9:	ret
	.size stack_pop,.-stack_pop

	/* elem_move(dst_rec, src_rec) -- copies len + data. Only touches x0-x3. */
	.global elem_move
	.type elem_move,%function
elem_move:
	ldr  w2,[x1]
	str  w2,[x0]
	add  x0,x0,#4
	add  x1,x1,#4
	cbz  w2, 9f
1:	ldrb w3,[x1],#1
	strb w3,[x0],#1
	subs w2,w2,#1
	b.ne 1b
9:	ret
	.size elem_move,.-elem_move

	.global stack_push
	.type stack_push,%function
stack_push:				/* x0=&sp,x1=elems,x2=data,x3=len */
	mov  x12,x0
	mov  x13,x1
	mov  x14,x3			/* len */
	ldr  x4,[x12]
	cmp  x4,#1000
	b.hs .sp_push_fail
	ELEM_PTR x4, x13, x6
	str  w14,[x6]			/* len */
	add  x7,x6,#4
	mov  x8,x14
	cbz  x8, .sp_push_ok
1:	ldrb w9,[x2],#1
	strb w9,[x7],#1
	subs x8,x8,#1
	b.ne 1b
.sp_push_ok:
	ldr  x4,[x12]
	add  x4,x4,#1
	str  x4,[x12]
	mov  w0,#1
	ret
.sp_push_fail:
	mov  w0,#0
	ret
	.size stack_push,.-stack_push

	.global stack_push_copy
	.type stack_push_copy,%function
stack_push_copy:			/* x0=&sp,x1=elems,x2=src_rec */
	ldr  x4,[x0]
	cmp  x4,#1000
	b.hs .spc_fail
	ELEM_PTR x4, x1, x6
	ldr  w7,[x2]			/* len */
	str  w7,[x6]
	add  x8,x6,#4
	add  x9,x2,#4
	cbz  w7, .spc_ok
1:	ldrb w10,[x9],#1
	strb w10,[x8],#1
	subs w7,w7,#1
	b.ne 1b
.spc_ok:
	ldr  x4,[x0]
	add  x4,x4,#1
	str  x4,[x0]
	mov  w0,#1
	ret
.spc_fail:
	mov  w0,#0
	ret
	.size stack_push_copy,.-stack_push_copy

	.global stack_dup_index
	.type stack_dup_index,%function
stack_dup_index:			/* x0=&sp,x1=elems,x2=raw_index */
	ldr  x4,[x0]
	cmp  x4,#1000
	b.hs .sdi_fail
	ELEM_PTR x2, x1, x6		/* src */
	ELEM_PTR x4, x1, x7		/* dst */
	ldr  w8,[x6]
	str  w8,[x7]
	add  x9,x7,#4
	add  x10,x6,#4
	mov  x11,x8
	cbz  w8, .sdi_ok
1:	ldrb w12,[x10],#1
	strb w12,[x9],#1
	subs w8,w8,#1
	b.ne 1b
.sdi_ok:
	ldr  x4,[x0]
	add  x4,x4,#1
	str  x4,[x0]
	mov  w0,#1
	ret
.sdi_fail:
	mov  w0,#0
	ret
	.size stack_dup_index,.-stack_dup_index

	.global stack_erase_index
	.type stack_erase_index,%function
stack_erase_index:			/* x0=&sp,x1=elems,x2=raw_index */
	mov  x12,x0
	mov  x13,x1
	ldr  x4,[x12]			/* sp */
	mov  x5,x2
	add  x6,x5,#1			/* j = raw+1 */
1:	cmp  x6,x4
	b.hs .ser_done
	/* src = elems + j*528 ; dst = elems + (j-1)*528.
	 * NOTE: do NOT use ELEM_PTR with x9 (the macro's 528 constant reg). */
	mov  w7,#528
	mul  x8,x6,x7
	add  x8,x8,x13		/* src (j) */
	sub  x9,x6,#1
	mul  x10,x9,x7
	add  x10,x10,x13	/* dst (j-1) */
	ldr  w11,[x8]
	str  w11,[x10]
	add  x16,x8,#4		/* src data */
	add  x9,x10,#4		/* dst data */
	cbz  w11, 2f
3:	ldrb w17,[x16],#1
	strb w17,[x9],#1
	subs w11,w11,#1
	b.ne 3b
2:	add  x6,x6,#1
	b    1b
.ser_done:
	ldr  x4,[x12]
	sub  x4,x4,#1
	str  x4,[x12]
	ret
	.size stack_erase_index,.-stack_erase_index

	.global stack_insert_index
	.type stack_insert_index,%function
stack_insert_index:			/* x0=&sp,x1=elems,x2=raw,x3=data,x4=len */
	mov  x12,x0
	mov  x13,x1
	mov  x14,x2			/* raw */
	mov  x15,x3			/* data */
	mov  x16,x4			/* len */
	ldr  x4,[x12]
	cmp  x4,#1000
	b.hs .sii_fail
	sub  x5,x4,#1			/* j = sp-1 */
1:	cmp  x5,x14
	b.lo .sii_sd
	ELEM_PTR x5, x13, x7		/* src (j) */
	add  x8,x5,#1
	ELEM_PTR x8, x13, x8		/* dst (j+1) */
	ldr  w11,[x7]
	str  w11,[x8]
	add  x9,x7,#4
	add  x10,x8,#4
	cbz  w11, 2f
3:	ldrb w17,[x9],#1
	strb w17,[x10],#1
	subs w11,w11,#1
	b.ne 3b
2:	sub  x5,x5,#1
	b    1b
.sii_sd:
	ELEM_PTR x14, x13, x7		/* rec */
	str  w16,[x7]			/* len */
	add  x8,x7,#4
	mov  x17,x16
	cbz  w17, 5f
6:	ldrb w2,[x15],#1
	strb w2,[x8],#1
	subs w17,w17,#1
	b.ne 6b
5:	ldr  x4,[x12]
	add  x4,x4,#1
	str  x4,[x12]
	mov  w0,#1
	ret
.sii_fail:
	mov  w0,#0
	ret
	.size stack_insert_index,.-stack_insert_index

	.global stack_swap_two
	.type stack_swap_two,%function
stack_swap_two:				/* x0=&sp,x1=elems */
	stp  x29,x30,[sp,#-16]!		/* save our return addr; bl elem_move clobbers x30 */
	mov  x29,sp
	ldr  x2,[x0]
	sub  x2,x2,#1
	mov  w3,#528
	mul  x4,x2,x3
	add  x4,x4,x1			/* A */
	ldr  x2,[x0]
	sub  x2,x2,#2
	mul  x5,x2,x3
	add  x5,x5,x1			/* B */
	TLS_ADDR x6, elem_tmp0
	mov  x0,x6
	mov  x1,x4
	bl   elem_move			/* tmp0 = *A */
	TLS_ADDR x6, elem_tmp1
	mov  x0,x6
	mov  x1,x5
	bl   elem_move			/* tmp1 = *B */
	mov  x0,x4
	TLS_ADDR x1, elem_tmp1
	bl   elem_move			/* *A = tmp1 */
	mov  x0,x5
	TLS_ADDR x1, elem_tmp0
	bl   elem_move			/* *B = tmp0 */
	ldp  x29,x30,[sp],#16
	ret
	.size stack_swap_two,.-stack_swap_two

	/* get_op(&pc, pend) -> x0 = opcode+1 (success) / 0 (fail/end) */
	.global get_op
	.type get_op,%function
get_op:
	mov  x3,x0			/* &pc */
	ldr  x4,[x0]			/* pc */
	cmp  x4,x1
	b.hs .gop_bad
	ldrb w2,[x4]			/* opcode */
	add  x4,x4,#1
	cmp  w2,#0x4e
	b.hi .gop_plain
	cmp  w2,#0x4c
	b.lo .gop_direct
	b.eq .gop_pd1
	cmp  w2,#0x4d
	b.eq .gop_pd2
	/* OP_PUSHDATA4 */
	add  x5,x4,#4
	cmp  x5,x1
	b.hi .gop_bad
	ldr  w6,[x4]
	add  x4,x4,#4
	b    .gop_sized
.gop_plain:
	mov  w6,#0
	b    .gop_done
.gop_direct:
	mov  x6,x2
	b    .gop_sized
.gop_pd1:
	cmp  x4,x1
	b.hs .gop_bad
	ldrb w6,[x4]
	add  x4,x4,#1
	b    .gop_sized
.gop_pd2:
	add  x5,x4,#2
	cmp  x5,x1
	b.hi .gop_bad
	ldrh w6,[x4]
	add  x4,x4,#2
.gop_sized:
	add  x5,x4,x6
	cmp  x5,x1
	b.hi .gop_bad
	add  x4,x4,x6
.gop_done:
	str  x4,[x3]
	add  x0,x2,#1
	mov  x1,x6		/* return pushlen in x1 (x86 RDX) */
	ret
.gop_bad:
	mov  w0,#0
	mov  x1,#0
	ret
	.size get_op,.-get_op

	.global vfexec_sp_reset
	.type vfexec_sp_reset,%function
vfexec_sp_reset:
	TLS_ADDR x0, vfexec_sp
	str  xzr,[x0]
	ret
	.size vfexec_sp_reset,.-vfexec_sp_reset

	.global vfexec_push
	.type vfexec_push,%function
vfexec_push:				/* x0 = 0/1 */
	TLS_ADDR x2, vfexec_sp
	ldr  x3,[x2]
	TLS_ADDR x4, vfexec
	strb w0,[x4,x3]
	add  x3,x3,#1
	str  x3,[x2]
	ret
	.size vfexec_push,.-vfexec_push

	.global vfexec_pop
	.type vfexec_pop,%function
vfexec_pop:
	TLS_ADDR x1, vfexec_sp
	ldr  x2,[x1]
	cbz  x2, 9f
	sub  x2,x2,#1
	str  x2,[x1]
9:	ret
	.size vfexec_pop,.-vfexec_pop

	.global vfexec_depth
	.type vfexec_depth,%function
vfexec_depth:
	TLS_ADDR x0, vfexec_sp
	ldr  x0,[x0]
	ret
	.size vfexec_depth,.-vfexec_depth

	.global vfexec_toggle_top
	.type vfexec_toggle_top,%function
vfexec_toggle_top:
	TLS_ADDR x1, vfexec_sp
	ldr  x2,[x1]
	cbz  x2, 9f
	TLS_ADDR x3, vfexec
	sub  x2,x2,#1
	ldrb w4,[x3,x2]
	eor  w4,w4,#1
	strb w4,[x3,x2]
9:	ret
	.size vfexec_toggle_top,.-vfexec_toggle_top

	.global vfexec_all_true
	.type vfexec_all_true,%function
vfexec_all_true:
	TLS_ADDR x1, vfexec_sp
	ldr  x2,[x1]
	TLS_ADDR x3, vfexec
	mov  x4,#0
1:	cmp  x4,x2
	b.hs .vfa_yes
	ldrb w5,[x3,x4]
	cbz  w5,.vfa_no
	add  x4,x4,#1
	b    1b
.vfa_no:
	mov  w0,#0
	ret
.vfa_yes:
	mov  w0,#1
	ret
	.size vfexec_all_true,.-vfexec_all_true

	.section .note.GNU-stack,"",%progbits
