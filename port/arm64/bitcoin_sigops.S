/* ============================================================================
 * bitcoin_sigops.S -- AArch64 port of asm/bitcoin_sigops.asm
 * Sigop accounting (matches Bitcoin Core exactly).
 *
 *   long script_sigops(const u8* script, ulong len)          (accurate=false)
 *       Core CScript::GetSigOpCount(fAccurate=false): OP_CHECKSIG/VERIFY = 1,
 *       OP_CHECKMULTISIG/VERIFY = 20 (inaccurate default).
 *   long script_sigops_accurate(const u8* script, ulong len)  (accurate=true)
 *       OP_CHECKMULTISIG/VERIFY = DecodeOP_N(following OP_1..16) or 20.
 *   long script_sigops_ex(const u8* script, ulong len, long accurate)
 *       shared body.
 *   long tx_legacy_sigops(const u8* tx, ulong txlen)
 *       Core GetLegacySigOpCount: scriptSig + scriptPubKey of every input/output,
 *       counted INACCURATE (multisig always 20). Pure structural (no prevouts,
 *       no witness). Skips the SegWit marker+flag (0x00 0x01) after version.
 *
 * ABI (SysV amd64 -> AAPCS64): rdi->x0, rsi->x1, rdx->x2, rax->x0.
 * Uses get_op from bitcoin_scriptcodec.S: get_op(&pc, pend) -> x0 = opcode+1 / 0.
 * ========================================================================== */

	.text

	.global script_sigops
	.type script_sigops,%function
script_sigops:
	mov  x2,#0			/* accurate = false */
	b    script_sigops_ex
	.size script_sigops,.-script_sigops

	.global script_sigops_accurate
	.type script_sigops_accurate,%function
script_sigops_accurate:
	mov  x2,#1			/* accurate = true */
	b    script_sigops_ex
	.size script_sigops_accurate,.-script_sigops_accurate

/* ----------------------------------------------------------------------------
 * script_sigops_ex(script x0, len x1, accurate x2) -> x0 (count)
 * Frame: push x29,x30 + x19,x20 + x21,x22 + x23,x24; one 16B local below for
 * the get_op &pc slot. Registers: x19=cursor, x20=pend, x21=last_opcode,
 * x22=accurate flag, x23=count. get_op only touches x0-x17, so x19-x23 survive.
 * -------------------------------------------------------------------------- */
	.global script_sigops_ex
	.type script_sigops_ex,%function
script_sigops_ex:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	sub  sp,sp,#16			/* local: get_op pc slot at [sp] */
	mov  x19,x0			/* cursor */
	add  x20,x19,x1			/* pend */
	mov  x23,xzr			/* count = 0 */
	mov  x22,x2			/* accurate flag */
	mov  x21,xzr			/* last_opcode = 0 */

.sgo_loop:
	cmp  x19,x20
	b.hs .sgo_done
	str  x19,[sp]			/* *slot = cursor */
	mov  x0,sp			/* &slot */
	mov  x1,x20			/* pend */
	bl   get_op
	cbz  x0,.sgo_done
	ldr  x19,[sp]			/* reload cursor (get_op advanced it) */
	sub  x0,x0,#1			/* real opcode */
	cmp  x0,#0xac			/* OP_CHECKSIG */
	beq  .sgo_checksig
	cmp  x0,#0xad			/* OP_CHECKSIGVERIFY */
	beq  .sgo_checksig
	cmp  x0,#0xae			/* OP_CHECKMULTISIG */
	beq  .sgo_multisig
	cmp  x0,#0xaf			/* OP_CHECKMULTISIGVERIFY */
	beq  .sgo_multisig
	/* numeric push OP_1..OP_16 (0x51..0x60) -> remember for accurate count */
	cmp  x0,#0x51
	b.lo .sgo_reset_last
	cmp  x0,#0x60
	b.hi .sgo_reset_last
	mov  x21,x0			/* last = opcode */
	b    .sgo_loop
.sgo_reset_last:
	mov  x21,xzr
	b    .sgo_loop
.sgo_checksig:
	add  x23,x23,#1
	mov  x21,xzr
	b    .sgo_loop
.sgo_multisig:
	cbz  x22,.sgo_mult20
	/* accurate: if last is OP_1..16, count += last - 0x50 */
	cmp  x21,#0x51
	b.lo .sgo_mult20
	cmp  x21,#0x60
	b.hi .sgo_mult20
	sub  x0,x21,#0x50
	add  x23,x23,x0
	b    .sgo_mult_done
.sgo_mult20:
	add  x23,x23,#20
.sgo_mult_done:
	mov  x21,xzr
	b    .sgo_loop
.sgo_done:
	mov  x0,x23
	add  sp,sp,#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size script_sigops_ex,.-script_sigops_ex

/* ----------------------------------------------------------------------------
 * Read a CompactSize varint at [\cur] into 64-bit \dst, advance \cur.
 * Little-endian native loads. Scratch register is fixed x0 (caller-saved and
 * dead at every invocation site inside tx_legacy_sigops).
 * -------------------------------------------------------------------------- */
	.macro READ_VARINT dst, cur
	ldrb  w0,[\cur]
	cmp   w0,#0xfd
	b.lo  100f
	cmp   w0,#0xfd
	beq   102f
	cmp   w0,#0xfe
	beq   103f
	/* 0xff : 8 bytes */
	ldr   \dst,[\cur,#1]
	add   \cur,\cur,#9
	b     105f
103:
	ldr   w0,[\cur,#1]
	mov   \dst,x0
	add   \cur,\cur,#5
	b     105f
102:
	ldrh  w0,[\cur,#1]
	mov   \dst,x0
	add   \cur,\cur,#3
	b     105f
100:
	mov   \dst,x0
	add   \cur,\cur,#1
105:
	.endm

/* ----------------------------------------------------------------------------
 * tx_legacy_sigops(tx x0, txlen x1) -> x0
 * Frame: push x29,x30 + x19,x20 + x21,x22 + x23,x24 + x25,x26.
 * Registers (all survive the `bl script_sigops` because it preserves x19-x28):
 *   x19 = cursor, x21 = total, x22 = n_in, x23 = n_out, x24 = slen, x26 = scratch.
 * -------------------------------------------------------------------------- */
	.global tx_legacy_sigops
	.type tx_legacy_sigops,%function
tx_legacy_sigops:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	mov  x26,x0			/* base (for initial cursor) */
	mov  x21,xzr			/* total = 0 */
	add  x19,x26,#4			/* cursor after version */

	/* ---- skip SegWit marker+flag (0x00 0x01 after version) ---- */
	ldrb w0,[x19]
	cbnz w0,.tlo_have_flags
	ldrb w0,[x19,#1]
	cmp  w0,#1
	b.ne .tlo_have_flags
	add  x19,x19,#2
.tlo_have_flags:

	/* ---- n_in varint -> x22 ---- */
	READ_VARINT x22, x19

	/* ---- walk inputs ---- */
.tlo_in_loop:
	cbz  x22,.tlo_in_done
	add  x19,x19,#36		/* skip prevout */
	READ_VARINT x24, x19	/* scriptSig len */
	mov  x0,x19			/* script */
	mov  x1,x24			/* len */
	bl   script_sigops		/* inaccurate: multisig=20 */
	add  x21,x21,x0
	add  x19,x19,x24		/* past scriptSig */
	add  x19,x19,#4			/* seq */
	sub  x22,x22,#1
	b    .tlo_in_loop
.tlo_in_done:

	/* ---- n_out varint -> x23 ---- */
	READ_VARINT x23, x19

	/* ---- walk outputs ---- */
.tlo_out_loop:
	cbz  x23,.tlo_final
	add  x19,x19,#8			/* skip value */
	READ_VARINT x24, x19	/* scriptPubKey len */
	mov  x0,x19			/* script */
	mov  x1,x24			/* len */
	bl   script_sigops		/* inaccurate */
	add  x21,x21,x0
	add  x19,x19,x24		/* past scriptPubKey */
	sub  x23,x23,#1
	b    .tlo_out_loop
.tlo_final:
	mov  x0,x21
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size tx_legacy_sigops,.-tx_legacy_sigops

	.section .note.GNU-stack,"",@progbits
