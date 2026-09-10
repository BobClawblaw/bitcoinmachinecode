/* bitcoin_sigops.S -- adapted from the verified arm-port (origin/arm-port
 * port/arm64/bitcoin_sigops.S) to Mach-O by adapt_armport.py, then hand-gated.
 * Exports: script_sigops, script_sigops_accurate, script_sigops_ex, tx_legacy_sigops */
/* ============================================================================
 * bitcoin_sigops.S -- AArch64 port of asm/bitcoin_sigops.asm
 * Sigop accounting (matches Bitcoin Core exactly).
 *
 *   long _script_sigops(const u8* script, ulong len)          (accurate=false)
 *       Core CScript::GetSigOpCount(fAccurate=false): OP_CHECKSIG/VERIFY = 1,
 *       OP_CHECKMULTISIG/VERIFY = 20 (inaccurate default).
 *   long _script_sigops_accurate(const u8* script, ulong len)  (accurate=true)
 *       OP_CHECKMULTISIG/VERIFY = DecodeOP_N(following OP_1..16) or 20.
 *   long _script_sigops_ex(const u8* script, ulong len, long accurate)
 *       shared body.
 *   long _tx_legacy_sigops(const u8* tx, ulong txlen)
 *       Core GetLegacySigOpCount: scriptSig + scriptPubKey of every input/output,
 *       counted INACCURATE (multisig always 20). Pure structural (no prevouts,
 *       no witness). Skips the SegWit marker+flag (0x00 0x01) after version.
 *
 * ABI (SysV amd64 -> AAPCS64): rdi->x0, rsi->x1, rdx->x2, rax->x0.
 * Uses _get_op from bitcoin_scriptcodec.S: _get_op(&pc, pend) -> x0 = opcode+1 / 0.
 * ========================================================================== */

	.text

	.globl _script_sigops
_script_sigops:
	mov  x2,#0			/* accurate = false */
	b    _script_sigops_ex

	.globl _script_sigops_accurate
_script_sigops_accurate:
	mov  x2,#1			/* accurate = true */
	b    _script_sigops_ex

/* ----------------------------------------------------------------------------
 * _script_sigops_ex(script x0, len x1, accurate x2) -> x0 (count)
 * Frame: push x29,x30 + x19,x20 + x21,x22 + x23,x24; one 16B local below for
 * the _get_op &pc slot. Registers: x19=cursor, x20=pend, x21=last_opcode,
 * x22=accurate flag, x23=count. _get_op only touches x0-x17, so x19-x23 survive.
 * -------------------------------------------------------------------------- */
	.globl _script_sigops_ex
_script_sigops_ex:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	sub  sp,sp,#16			/* local: _get_op pc slot at [sp] */
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
	bl   _get_op
	cbz  x0,.sgo_done
	ldr  x19,[sp]			/* reload cursor (_get_op advanced it) */
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

/* ----------------------------------------------------------------------------
 * Read a CompactSize varint at [\cur] into 64-bit \dst, advance \cur.
 * Little-endian native loads. Scratch register is fixed x0 (caller-saved and
 * dead at every invocation site inside _tx_legacy_sigops).
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
 * _tx_legacy_sigops(tx x0, txlen x1) -> x0
 * Frame: push x29,x30 + x19,x20 + x21,x22 + x23,x24 + x25,x26.
 * Registers (all survive the `bl _script_sigops` because it preserves x19-x28):
 *   x19 = cursor, x21 = total, x22 = n_in, x23 = n_out, x24 = slen, x26 = scratch.
 * -------------------------------------------------------------------------- */
/* ----------------------------------------------------------------------------
 * SCR-10 (audit 2026-09-03): _tx_legacy_sigops walked the transaction with NO
 * bounds checks at all -- the length was loaded once and never compared, and
 * every varint read and every advance indexed unconditionally. It was
 * unreachable only because both callers parse the transaction fully first:
 * that is the "a distant function already checked this" pattern this tree's
 * own comments warn about, one refactor away from being an out-of-bounds read
 * on peer-supplied bytes. (asm/bitcoin_sigops.asm's x86 macros, register-
 * mapped: cursor x19, end x25, base x26.)
 *
 * SO_NEED n -- require n more bytes at x19 within [x26, x25), else bail.
 *   Checks the ADDITION for carry too (adds), so a varint claiming a huge
 *   length cannot wrap the cursor past the end and land back inside the
 *   buffer. Works with an immediate or a register operand.
 *
 * SO_VARINT dst -- read a CompactSize at x19 into dst, advancing x19, with
 *   every read bounded.
 * -------------------------------------------------------------------------- */
.macro SO_NEED n
	adds x6, x19, \n
	b.cs .tlo_oob
	cmp  x6, x25
	b.hi .tlo_oob
.endm

.macro SO_VARINT dst
	SO_NEED 1
	ldrb w2, [x19]
	cmp  w2, #0xfd
	b.lo .Lsv_b\@
	b.eq .Lsv_2\@
	cmp  w2, #0xfe
	b.eq .Lsv_4\@
	SO_NEED 9
	ldr  \dst, [x19, #1]
	add  x19, x19, #9
	b    .Lsv_d\@
.Lsv_b\@:	add  x19, x19, #1
	mov  \dst, x2              /* W write zero-extends */
	b    .Lsv_d\@
.Lsv_2\@:	SO_NEED 3
	ldrh w2, [x19, #1]
	add  x19, x19, #3
	mov  \dst, x2
	b    .Lsv_d\@
.Lsv_4\@:	SO_NEED 5
	ldr  w2, [x19, #1]
	add  x19, x19, #5
	mov  \dst, x2
.Lsv_d\@:
.endm

	.globl _tx_legacy_sigops
_tx_legacy_sigops:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	mov  x26,x0			/* base */
	mov  x21,xzr			/* total = 0 */
	add  x25,x26,x1			/* end = base + txlen (SCR-10: the bound that
					 * was loaded once and never compared) */
	add  x19,x26,#4			/* cursor after version */

	/* ---- skip SegWit marker+flag (0x00 0x01 after version) ---- */
	SO_NEED 2
	ldrb w0,[x19]
	cbnz w0,.tlo_have_flags
	ldrb w0,[x19,#1]
	cmp  w0,#1
	b.ne .tlo_have_flags
	add  x19,x19,#2
.tlo_have_flags:

	/* ---- n_in varint -> x22 ---- */
	SO_VARINT x22

	/* ---- walk inputs ---- */
.tlo_in_loop:
	cbz  x22,.tlo_in_done
	SO_NEED 36
	add  x19,x19,#36		/* skip prevout */
	SO_VARINT x24			/* scriptSig len */
	SO_NEED x24			/* the scriptSig bytes themselves must be in
					 * the buffer before _script_sigops is handed a
					 * pointer and a length */
	mov  x0,x19			/* script */
	mov  x1,x24			/* len */
	bl   _script_sigops		/* inaccurate: multisig=20 */
	add  x21,x21,x0
	add  x19,x19,x24		/* past scriptSig */
	SO_NEED 4			/* sequence */
	add  x19,x19,#4
	sub  x22,x22,#1
	b    .tlo_in_loop
.tlo_in_done:

	/* ---- n_out varint -> x23 ---- */
	SO_VARINT x23

	/* ---- walk outputs ---- */
.tlo_out_loop:
	cbz  x23,.tlo_final
	SO_NEED 8			/* skip value */
	add  x19,x19,#8
	SO_VARINT x24			/* scriptPubKey len */
	SO_NEED x24
	mov  x0,x19			/* script */
	mov  x1,x24			/* len */
	bl   _script_sigops		/* inaccurate */
	add  x21,x21,x0
	add  x19,x19,x24		/* past scriptPubKey */
	sub  x23,x23,#1
	b    .tlo_out_loop
.tlo_oob:
	/* SCR-10: malformed / truncated. -1 rather than 0, because 0 is a
	 * LEGITIMATE count and both callers add the result to a cost compared
	 * against a limit -- returning 0 here would say "no sigops" and pass
	 * the check, which is fail-open on exactly the input that earned the
	 * refusal. */
	mov  x21,#-1
.tlo_final:
	mov  x0,x21
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret

