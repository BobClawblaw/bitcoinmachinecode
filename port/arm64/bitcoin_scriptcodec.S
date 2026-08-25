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

	.section .bss
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
	LAddr x9, snum_overflow
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
	LAddr x3, scriptnum_buf
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
