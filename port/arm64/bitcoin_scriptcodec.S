/* ============================================================================
 * bitcoin_scriptcodec.S -- AArch64 port of asm/bitcoin_scriptcodec.asm
 * (support layer for the script interpreter). This file hosts the PURE,
 * stack-independent primitives; the element-stack engine and vfExec helpers
 * follow in the same module.
 *
 * Ported here (each verified against a Python oracle):
 *   int64 scriptnum_decode(u64 len, const u8* data, u64 maxsize)
 *        -> x0 = value (sets global snum_overflow = 1 if len > maxsize, or --
 *           2026-09-02 -- if the ENCODING is non-minimal and bit 8 of maxsize
 *           is set: Core passes fRequireMinimal under MINIMALDATA)
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
	mov  x10, x2                    /* keep the raw word: low byte = maxsize,
	                                 * bit 8 = "require minimal encoding" (the
	                                 * caller sets it under MINIMALDATA --
	                                 * Core's fRequireMinimal). Both failures
	                                 * report through snum_overflow, i.e.
	                                 * SCRIPT_ERR_SCRIPTNUM, exactly Core's
	                                 * error for either. 2026-09-02, the
	                                 * randomized differential vs Core. */
	and  x2, x2, #0xff
	cmp  x0, x2                     /* len vs maxsize */
	b.ls .sd_size_ok
	mov  w11, #1
	str  x11, [x9]                  /* overflow = 1 */
.sd_size_ok:
	tst  x10, #0x100
	b.eq .sd_min_ok
	cbz  x0, .sd_min_ok             /* empty is minimal */
	sub  x11, x0, #1
	ldrb w11, [x1, x11]
	tst  w11, #0x7f
	b.ne .sd_min_ok                 /* top byte carries magnitude: minimal */
	cmp  x0, #1
	b.eq .sd_min_bad                /* lone 0x00 / 0x80: pad byte or a sign */
	sub  x11, x0, #2
	ldrb w11, [x1, x11]
	tst  w11, #0x80
	b.ne .sd_min_ok                 /* the pad byte IS needed for the sign */
.sd_min_bad:
	mov  w11, #1
	str  x11, [x9]
.sd_min_ok:
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
	cmp  w3, #0x81
	b.eq .mp_nonmin               /* 0x81 -> should use OP_1NEGATE. Before
	                               * 2026-09-02 this test sat behind a `b.hi
	                               * .mp_not1` that only a 0x00 byte escaped,
	                               * so a pushed 0x81 passed MINIMALDATA; the
	                               * same unreachable-branch bug main had, and
	                               * the Core differential found both. */
	cmp  w3, #1
	b.lo .mp_not1                 /* 0x00: Core falls through to the size rule */
	cmp  w3, #16
	b.hi .mp_not1
.mp_nonmin:
	mov  w0, #0                   /* 1..16 -> should use OP_1..OP_16 */
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
/* vfExec condition stack. SCR-2 (audit 2026-09-03, x86 asm/bitcoin_scriptcodec.asm)
 * was never ported here: Core has NO nesting limit under tapscript -- there is
 * no opcode limit and no script-size limit for a leaf -- so OP_IF nesting runs
 * to one conditional per script byte. This file still had the original 1024-byte
 * buffer AND an unbounded vfexec_push, so the 1025th nested OP_IF wrote past
 * vfexec into vfexec_sp and whatever else sits in the TLS block: an
 * attacker-controlled out-of-bounds write from P2P input, plus a false accept of
 * an unbalanced script. The ARM symptom was test_scr_interp_bounds' 250,000-deep
 * IF vector dying on SIGSEGV inside vfexec_push. The buffer now covers 5 MiB of
 * script bytes (more than the 4 MiB block witness limit can express) and
 * vfexec_push refuses at the cap instead of writing.
 * VFEXEC_MAX is a 12-bit<<12 cmp immediate (1280<<12), so the bound is one instruction. */
.equ VFEXEC_MAX,5*1024*1024	/* GAS needs the dot; NASM's bare `equ` is a syntax error */
vfexec:		.space VFEXEC_MAX	/* condition stack (bytes) */
vfexec_sp:	.space 8
/* IR-4 (x86 71b6de1f): Core's ConditionStack caches the position of the FIRST
 * false entry (or VFEXEC_NO_FALSE), so "is every entry true" is ONE compare.
 * vfexec_all_true used to scan the whole buffer before every opcode -- O(depth)
 * per opcode, O(N^2) per script: a 250,000-deep leaf of OP_IF/OP_ENDIF pairs is
 * ~6 x 10^10 byte loads, which is why that vector also needed the bound above. */
vfexec_ff:	.space 8
.equ VFEXEC_NO_FALSE,-1		/* stored as -1; tested as "< 0", never `cmp #-1` */

/* ---- IR-6 (INTERP_REVIEW_2026-09-05, x86 4efb0c4a): position -> slot handle
 * table. stack_erase_index shifted whole 528-byte records to close a hole, so
 * a tapscript of `<998> OP_ROLL` repeated cost O(rolls x records) in bytes
 * moved (~445 GB, ~10 s for a 3.4 MB leaf -- a denial of service by a
 * consensus-VALID block; the ARM twin measured 27.9 s for the pinning test's
 * 200,000-roll storm). Core moves a 24-byte vector header instead.
 *
 * Records now stay put and POSITIONS move: hnd_tab[p] is the SLOT holding the
 * element at position p, so a roll rotates 4-byte handles. hnd_tab is always a
 * permutation of [0, MAX_STACK_SIZE), which is what lets pop/push reuse slots
 * without a free list: pop leaves its slot at hnd_tab[sp], push takes it back.
 *
 * The table belongs to ONE arena, hnd_base -- the MAIN stack, the only one
 * that rolls. Any other arena (the alt stack, and every caller outside
 * script_eval) matches nothing, falls through to identity, and behaves exactly
 * as it did before this change.
 *
 * script_eval registers the table on entry (hnd_begin) and, ONLY IF hnd_dirty,
 * applies the permutation to the records on exit (hnd_end), so every reader
 * outside still finds element p at elems + p*ELEM_SIZE with its data inline --
 * the ABI bitcoin_scriptverify.c's sv_rec/sv_len/sv_dat and the test harnesses
 * use, unchanged. A script that never rolls leaves hnd_dirty clear and pays
 * nothing, which is what keeps IR-7's removal of the per-input arena traffic
 * intact.
 *
 * Order matters for x86 parity: hnd_base, hnd_dirty, then hnd_tab, adjacent, so
 * a (caller-bug) read of hnd_tab[-1] lands on hnd_dirty's high half on both
 * twins, exactly as in asm/bitcoin_scriptcodec.asm. */
	.global hnd_base, hnd_dirty, hnd_tab	/* TLS_ADDR's gottprel needs them global */
	.align 8
hnd_base:	.space 8
hnd_dirty:	.space 8
hnd_tab:	.space 4*1000

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

/* ---- IR-6 handle layer (x86 4efb0c4a) ------------------------------------
 * HND_ADDR elems,pos,out -- out := the RECORD address of POSITION pos in the
 * arena elems: elems + hnd_tab[pos]*528 when that arena registered a table,
 * else elems + pos*528 -- exactly the pre-IR-6 identity, so the alt stack and
 * every caller outside script_eval behave as before. Clobbers out, pos (the
 * SLOT it resolved to lands there), x10 (the u32 table load has to land in a
 * w register, so the macro owns one scratch) and x17 (TLS_ADDR's tpidr_el0).
 * HND_OF elems,out       -- out := the handle table when elems registered one,
 * else 0 (= identity). Clobbers out and x17.
 *
 * WHY MACROS WHERE x86 HAS LOCAL FUNCTIONS: on x86 these are `call`ed, the
 * position rides in rdx and the stashed args in callee-saved r12-r15.
 * AArch64 has no callee-saved scratch below x19, so a `bl hnd_addr` out of a
 * frameless primitive writes x30 with no save area -- the abi-a64 auditor's
 * UNSAVED-CLOBBER gate -- and would force a prologue onto every mutating
 * primitive, the very frame traffic IR-6 exists to remove. Inlining keeps
 * stack_push/dup/erase/insert/swap frameless and lets the position travel in
 * whatever scratch each caller can spare instead of a fixed rdx. The 528
 * multiply is (p<<9)+(p<<4), so no constant register is needed either. */
	.macro HND_ADDR elems, pos, out
	TLS_ADDR \out, hnd_base
	ldr  \out, [\out]			/* *hnd_base: the registered arena, not its address */
	cmp  \elems, \out
	b.ne .Lhnd_a\@_id
	TLS_ADDR x10, hnd_tab
	ldr  w10, [x10, \pos, lsl #2]	/* w10: hnd_tab[pos] (a u32 slot; x10 scratch) */
	mov  \pos, x10
.Lhnd_a\@_id:
	lsl  \out, \pos, #9
	add  \out, \out, \pos, lsl #4	/* slot * 528 */
	add  \out, \out, \elems
	.endm

	.macro HND_OF elems, out
	TLS_ADDR \out, hnd_base
	ldr  \out, [\out]
	cmp  \elems, \out
	b.eq .Lhnd_o\@
	mov  \out, xzr
	b    .Lhnd_oc\@
.Lhnd_o\@:
	TLS_ADDR \out, hnd_tab
.Lhnd_oc\@:
	.endm

/* hnd_begin(x0=main_elems) -> x0 = 1 if THIS call registered the table (the
 * caller must pair it with hnd_end), 0 if a table was already registered -- a
 * nested script_eval, which then simply runs on identity like the old code.
 * Clobbers x0-x4, x10, x17; touches no callee-saved register. */
	.global hnd_begin
	.type hnd_begin,%function
hnd_begin:
	TLS_ADDR x2, hnd_base
	ldr  x3, [x2]
	cbnz x3, .hb_busy
	str  x0, [x2]			/* hnd_base = main_elems */
	TLS_ADDR x2, hnd_dirty
	str  xzr, [x2]
	TLS_ADDR x2, hnd_tab
	mov  x3, xzr
.hb_init:
	str  w3, [x2, x3, lsl #2]	/* hnd_tab[p] = p (identity) */
	add  x3, x3, #1
	cmp  x3, #1000			/* MAX_STACK_SIZE */
	b.lt .hb_init
	mov  w0, #1
	ret
.hb_busy:
	mov  w0, #0
	ret
	.size hnd_begin,.-hnd_begin

/* hnd_end(x0=&sp, x1=main_elems) -- put the records back in position order
 * (only if something rolled) and unregister. Cycle-following: every record is
 * moved at most once, at most sp moves, and only for a script that rolled.
 * Saves/restores x19-x24 + x29/x30 (elem_move is a leaf on x0-x3, so nothing
 * else moves). */
	.global hnd_end
	.type hnd_end,%function
hnd_end:
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	TLS_ADDR x10, hnd_dirty
	ldr  x10, [x10]
	cbz  x10, .he_clear
	ldr  x21, [x0]			/* sp */
	mov  x20, x1			/* elems */
	TLS_ADDR x24, hnd_tab
	mov  x19, xzr			/* i */
	/* Apply the permutation in place: slot p must end up holding the record
	 * for position p, and hnd_tab[p] says where that record is NOW. Walk
	 * each cycle once, carrying one record in elem_tmp0, and mark a visited
	 * entry by setting hnd_tab[j] = j -- so every record moves at most once.
	 *
	 * (The x86 first draft swapped hnd_tab[p] with hnd_tab[q] alongside the
	 * record swap. That is wrong: exchanging the CONTENTS of slots p and q
	 * has to update whichever entries HOLD the values p and q, not the
	 * entries AT indices p and q. It produced the mirrored permutation --
	 * the IR-6 vectors caught it, which is what they were written for. The
	 * ARM twin inherits those vectors, so this loop is the corrected form.) */
.he_outer:
	cmp  x19, x21
	b.hs .he_clear
	ldr  w10, [x24, x19, lsl #2]
	cmp  x10, x19
	b.eq .he_nexti			/* already home */
	TLS_ADDR x0, elem_tmp0
	ELEM_PTR x19, x20, x1		/* x1 = &rec[i] */
	bl   elem_move			/* carry = rec[i] */
	mov  x22, x19			/* j = i */
.he_cyc:
	ldr  w10, [x24, x22, lsl #2]
	mov  x23, x10			/* k = hnd_tab[j] */
	str  w22, [x24, x22, lsl #2]	/* hnd_tab[j] = j (visited) */
	cmp  x23, x19
	b.eq .he_cycend
	ELEM_PTR x23, x20, x1		/* x1 = &rec[k] */
	ELEM_PTR x22, x20, x0		/* x0 = &rec[j] */
	bl   elem_move			/* rec[j] = rec[k] */
	mov  x22, x23			/* j = k */
	b    .he_cyc
.he_cycend:
	ELEM_PTR x22, x20, x0		/* x0 = &rec[j] */
	TLS_ADDR x1, elem_tmp0
	bl   elem_move			/* rec[j] = carry */
.he_nexti:
	add  x19, x19, #1
	b    .he_outer
.he_clear:
	TLS_ADDR x10, hnd_base
	str  xzr, [x10]
	TLS_ADDR x10, hnd_dirty
	str  xzr, [x10]
	ldp  x29,x30,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ret
	.size hnd_end,.-hnd_end

	.global stack_top_ptr
	.type stack_top_ptr,%function
stack_top_ptr:				/* x0=&sp, x1=elems -> A record */
	ldr x2,[x0]
	sub x2,x2,#1
	HND_ADDR x1, x2, x0			/* IR-6: position -> slot */
	ret					/* HND_ADDR is not a tail: it ENDS in the add,
						   so the ret the ELEM_PTR version had has to
						   stay here or this falls through into
						   stack_second_ptr and subtracts again. */
	.size stack_top_ptr,.-stack_top_ptr

	.global stack_second_ptr
	.type stack_second_ptr,%function
stack_second_ptr:
	ldr x2,[x0]
	sub x2,x2,#2
	HND_ADDR x1, x2, x0			/* IR-6 */
	ret
	.size stack_second_ptr,.-stack_second_ptr

	.global stack_third_ptr
	.type stack_third_ptr,%function
stack_third_ptr:
	ldr x2,[x0]
	sub x2,x2,#3
	HND_ADDR x1, x2, x0			/* IR-6 */
	ret
	.size stack_third_ptr,.-stack_third_ptr

	.global stack_elem_ptr
	.type stack_elem_ptr,%function
stack_elem_ptr:				/* x1=elems, x2=idx -> ptr */
	HND_ADDR x1, x2, x0			/* IR-6 */
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
	HND_ADDR x13, x4, x0		/* IR-6: the record for POSITION sp -- under a */
					/* table a SLOT, not elems+sp*528 */
	str  w14,[x0]			/* len */
	add  x7,x0,#4
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
	mov  x12,x0
	mov  x14,x2			/* IR-6: the SOURCE is already a record address; */
	ldr  x4,[x12]			/* only the destination is a position, so it is */
	cmp  x4,#1000			/* stashed out of HND_ADDR's way (x4/x0/x17). */
	b.hs .spc_fail
	HND_ADDR x1, x4, x0		/* IR-6: destination = slot of position sp */
	ldr  w7,[x14]			/* len */
	str  w7,[x0]
	add  x8,x0,#4
	add  x9,x14,#4
	cbz  w7, .spc_ok
1:	ldrb w10,[x9],#1
	strb w10,[x8],#1
	subs w7,w7,#1
	b.ne 1b
.spc_ok:
	ldr  x4,[x12]
	add  x4,x4,#1
	str  x4,[x12]
	mov  w0,#1
	ret
.spc_fail:
	mov  w0,#0
	ret
	.size stack_push_copy,.-stack_push_copy

	.global stack_dup_index
	.type stack_dup_index,%function
stack_dup_index:			/* x0=&sp,x1=elems,x2=raw_index */
	mov  x12,x0
	mov  x13,x1
	mov  x14,x2			/* raw_index */
	ldr  x4,[x12]			/* sp */
	cmp  x4,#1000
	b.hs .sdi_fail
	HND_ADDR x13, x14, x6		/* IR-6: src = slot of position raw_index */
	HND_ADDR x13, x4, x0		/* IR-6: dst = slot of position sp */
	ldr  w8,[x6]
	str  w8,[x0]
	add  x7,x0,#4
	add  x10,x6,#4
	mov  x11,x8
	cbz  w8, .sdi_ok
1:	ldrb w11,[x10],#1
	strb w11,[x7],#1
	subs w8,w8,#1
	b.ne 1b
.sdi_ok:
	ldr  x4,[x12]
	add  x4,x4,#1
	str  x4,[x12]
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
	mov  x14,x2			/* raw_index */
	HND_OF x13, x0
	cbz  x0, .ser_records
	/* IR-6: THE finding. Closing the hole used to shift every record above
	 * the index -- 528 bytes each, and OP_ROLL is erase+append with no
	 * tapscript opcode cap. With a table it shifts 4-byte handles, and the
	 * erased slot lands at handles[sp-1] where the next push picks it up
	 * (the table stays a permutation of [0, MAX_STACK_SIZE)). */
	ldr  w9, [x0, x14, lsl #2]	/* h = handles[idx] */
	ldr  x8, [x12]
	sub  x8, x8, #1			/* last = sp-1 */
	mov  x10, x14			/* j = idx */
.ser_hshift:
	cmp  x10, x8
	b.hs .ser_hdone
	add  x11, x10, #1
	ldr  w11, [x0, x11, lsl #2]	/* handles[j] = handles[j+1] */
	str  w11, [x0, x10, lsl #2]
	add  x10, x10, #1
	b    .ser_hshift
.ser_hdone:
	str  w9, [x0, x8, lsl #2]		/* handles[last] = the erased slot */
	TLS_ADDR x10, hnd_dirty
	mov  x11, #1
	str  x11, [x10]
	ldr  x4, [x12]
	sub  x4, x4, #1
	str  x4, [x12]
	ret
.ser_records:
	/* no table for this arena (the alt stack, or a caller outside
	 * script_eval): the pre-IR-6 record shift, unchanged. */
	ldr  x4,[x12]			/* sp */
	mov  x5,x14
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
	HND_OF x13, x0
	cbz  x0, .sii_records
	/* IR-6: opening the hole shifts 4-byte handles, and the new element is
	 * written into handles[sp] -- the slot the last pop/erase freed. (OP_TODEP
	 * is insert+erase; without this it moved records like OP_ROLL did.) */
	ldr  w9, [x0, x4, lsl #2]	/* h = handles[sp], the free slot */
	mov  x10, x4			/* j = sp */
.sii_ishift:
	cmp  x10, x14
	b.ls .sii_idone
	sub  x11, x10, #1
	ldr  w11, [x0, x11, lsl #2]	/* handles[j] = handles[j-1] */
	str  w11, [x0, x10, lsl #2]
	sub  x10, x10, #1
	b    .sii_ishift
.sii_idone:
	str  w9, [x0, x14, lsl #2]	/* handles[raw] = h */
	lsl  x0, x9, #9
	add  x0, x0, x9, lsl #4
	add  x0, x0, x13		/* dst = elems + h*528 (a slot, not a position) */
	str  w16,[x0]			/* len */
	add  x8,x0,#4
	mov  x0,x15
	mov  x11,x16
	cbz  x11, .sii_dirty
4:	ldrb w2,[x0],#1
	strb w2,[x8],#1
	subs x11,x11,#1
	b.ne 4b
.sii_dirty:
	TLS_ADDR x10, hnd_dirty
	mov  x11, #1
	str  x11, [x10]
	ldr  x4,[x12]
	add  x4,x4,#1
	str  x4,[x12]
	mov  w0,#1
	ret
.sii_records:
	/* no table for this arena: the pre-IR-6 record shift, unchanged. */
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
	mov  x12,x0
	mov  x13,x1
	HND_OF x13, x0
	cbz  x0, .ssw_records
	/* IR-6: with a handle table, swapping two POSITIONS is swapping two
	 * 4-byte handles; the records do not move. (OP_SWAP reaches here; on x86
	 * this is the same fast path, so a swap-heavy script costs the ARM twin
	 * the same 8 bytes of stores.) */
	ldr  x9, [x12]			/* sp */
	sub  x10, x9, #1
	sub  x11, x9, #2
	ldr  w4, [x0, x10, lsl #2]	/* h1 = handles[sp-1] */
	ldr  w5, [x0, x11, lsl #2]	/* h2 = handles[sp-2] */
	str  w5, [x0, x10, lsl #2]
	str  w4, [x0, x11, lsl #2]
	TLS_ADDR x9, hnd_dirty
	mov  x10, #1
	str  x10, [x9]
	ret
.ssw_records:
	/* no table for this arena: the pre-IR-6 record swap, unchanged. */
	mov  x0,x12
	mov  x1,x13
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
	mov  x1,#-1			/* IR-4: no entry is false (VFEXEC_NO_FALSE).
					   Clobbers x1 as well as x0 now -- the only caller
					   is script_eval's prologue, where nothing is live. */
	TLS_ADDR x0, vfexec_ff
	str  x1,[x0]
	ret
	.size vfexec_sp_reset,.-vfexec_sp_reset

	.global vfexec_push
	.type vfexec_push,%function
vfexec_push:				/* x0 = 0/1 -> x0 = 1 accepted / 0 REFUSED */
	TLS_ADDR x1, vfexec_sp
	ldr  x2,[x1]
	cmp  x2,#VFEXEC_MAX		/* SCR-2: bounded. Hitting the cap means the script
					   is malformed -- refuse and let the interpreter fail it,
					   never scribble past vfexec into vfexec_sp. */
	b.hs .vpf_full
	TLS_ADDR x3, vfexec
	strb w0,[x3,x2]
	add  x3,x2,#1
	str  x3,[x1]
	/* IR-4: the first false pushed while nothing is false yet sets the cache;
	 * its index is the depth measured BEFORE the push (x2). */
	cbnz w0,.vpf_done
	TLS_ADDR x3, vfexec_ff
	ldr  x4,[x3]
	cmp  x4,xzr
	b.ge .vpf_done			/* a first false is already cached */
	str  x2,[x3]
.vpf_done:
	mov  w0,#1
	ret
.vpf_full:
	mov  w0,#0
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
	/* IR-4: the slot just popped is the NEW depth; if it held the first false,
	 * nothing below it can be false (it was the FIRST one), so clear the cache. */
	TLS_ADDR x3, vfexec_ff
	ldr  x4,[x3]
	cmp  x4,x2
	b.ne 9f
	mov  x4,#-1
	str  x4,[x3]
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
	sub  x2,x2,#1			/* index of the top */
	TLS_ADDR x3, vfexec
	ldrb w4,[x3,x2]
	eor  w4,w4,#1
	strb w4,[x3,x2]
	/* IR-4: Core's ConditionStack::toggle_top. Flipping the top true->false
	 * makes it the first false when nothing was false; flipping false->true
	 * clears the cache only when the top WAS the first false (a false below
	 * it stays the first false). */
	TLS_ADDR x3, vfexec_ff
	ldr  x4,[x3]
	cmp  x4,xzr
	b.ge .tt_had_false
	str  x2,[x3]
	b    9f
.tt_had_false:
	cmp  x4,x2
	b.ne 9f
	mov  x4,#-1
	str  x4,[x3]
9:	ret
	.size vfexec_toggle_top,.-vfexec_toggle_top

	.global vfexec_all_true
	.type vfexec_all_true,%function
vfexec_all_true:
	/* IR-4: one compare against the cached first-false position (Core's
	 * ConditionStack::all_true). The byte scan this replaced -- and the O(depth)
	 * per opcode it cost -- is what made a deeply nested tapscript quadratic. */
	TLS_ADDR x1, vfexec_ff
	ldr  x2,[x1]
	cmp  x2,xzr
	b.lt .vfa_yes			/* == VFEXEC_NO_FALSE: nothing is false (empty too) */
	mov  w0,#0
	ret
.vfa_yes:
	mov  w0,#1
	ret
	.size vfexec_all_true,.-vfexec_all_true

	.section .note.GNU-stack,"",%progbits
