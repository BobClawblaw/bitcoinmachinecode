/* ============================================================================
 * bitcoin_cons.S -- AArch64 port of asm/bitcoin_cons.asm
 *
 * int cons_verify(x0=block, x1=len, x2=scratch, x3=cap) -> w0 1/0
 *   Block-level consensus checks: PoW (pow_check); every tx parses in-bounds;
 *   first tx is coinbase (n_in==1); collect txids into scratch (<=cap); the
 *   walked tx count equals the wire CompactSize count; merkle_root(txids) ==
 *   the header's root (block+36). Uses only ported deps: sha256d,
 *   merkle_root, pow_check, tx_parse, tx_txid. tx_txid gets an internal 1 MiB
 *   unwitnessed-rebuild buffer; the caller's `scratch` holds the txid array.
 *
 * Frame (sp-relative, locals at LOW offsets, rebuild ABOVE them):
 *   txinfo@sp+0(64) txid_tmp@sp+64(32) mkout@sp+96(32); rebuild@sp+128 (1 MiB);
 *   sub sp,#0x100100.
 * PITFALL (cost real time): the loop advance `subs x9,x9,x23` MUST set flags
 * for the `b.le .Ldone` -- a plain `sub` leaves stale NZCV from an earlier
 * `cmp` and silently jumps straight to .Ldone (body never runs, n==0).
 * Registers (preserved by all leaf callees): x19=block x20=len x21=scratch
 * x22=cap x23=idx(offset) x24=expected_txcount x25=n x26=frame size.
 * ========================================================================== */
	.text
	.global cons_verify
	.type   cons_verify, %function
cons_verify:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	mov  x26, #0x0100
	movk x26, #0x0010, lsl #16   /* x26 = 0x100100 (1 MiB + 256) */
	sub  sp, sp, x26
	mov  x19, x0                 /* block */
	mov  x20, x1                 /* len */
	mov  x21, x2                 /* caller scratch (txid array) */
	mov  x22, x3                 /* cap */

	/* len < 82 -> fail */
	cmp  x20, #82
	b.lo .Lcn_fail

	/* PoW check on the 80-byte header */
	mov  x0, x19
	bl   pow_check
	cbz  w0, .Lcn_fail

	/* ---- parse tx-count CompactSize at block+80 ---- */
	ldrb w8, [x19, #80]
	cmp  w8, #0xfd
	b.lo .Lcnt1
	cmp  w8, #0xfe
	b.eq .Lcnt4
	cmp  w8, #0xff
	b.eq .Lcnt8
	/* cnt2 : u16 at block+81 */
	ldrh w9, [x19, #81]
	mov  x24, x9
	add  x23, x19, #83
	b    .Lhave
.Lcnt1:
	mov  x24, x8
	add  x23, x19, #81
	b    .Lhave
.Lcnt4:
	ldr  w9, [x19, #81]
	mov  x24, x9
	add  x23, x19, #85
	b    .Lhave
.Lcnt8:
	ldr  x9, [x19, #81]
	mov  x24, x9
	add  x23, x19, #89
.Lhave:
	/* bounds: (idx - block) <= len */
	sub  x9, x23, x19
	cmp  x9, x20
	b.hi .Lcn_fail
	/* expected_txcount == 0 -> fail */
	cbz  x24, .Lcn_fail
	/* idx as block-relative offset for the walk */
	sub  x23, x23, x19
	mov  x25, #0                 /* n */

.Lwalk:
	mov  x9, x20
	subs x9, x9, x23             /* len - idx ; SETS FLAGS for b.le below */
	b.le .Ldone
	/* tx_parse(txinfo@sp+0, block+idx, len-idx) */
	mov  x0, sp
	mov  x1, x19
	add  x1, x1, x23
	mov  x2, x9
	bl   tx_parse
	cbz  w0, .Lcn_fail
	ldr  x10, [sp]               /* tx_len */
	cbz  x10, .Lcn_fail
	mov  x9, x23
	add  x9, x9, x10             /* idx + tx_len */
	cmp  x9, x20
	b.hi .Lcn_fail
	/* n == 0 -> must be coinbase (n_in==1 at byte 12) */
	cmp  x25, #0
	b.ne .Lnotcb
	ldr  w11, [sp, #12]
	cmp  w11, #1
	b.ne .Lcn_fail
.Lnotcb:
	/* n < cap */
	cmp  x25, x22
	b.hs .Lcn_fail
	/* tx_txid(txid_tmp@sp+64, block+idx, tx_len, rebuild@sp+128, 0x100000) */
	add  x0, sp, #64             /* txid_tmp */
	mov  x1, x19
	add  x1, x1, x23
	ldr  x2, [sp]                /* tx_len */
	add  x3, sp, #128            /* 1 MiB rebuild buffer */
	mov  x4, #0x100000
	bl   tx_txid
	cbz  w0, .Lcn_fail
	/* caller_scratch + n*32 = txid_tmp */
	mov  x9, x25
	mov  x10, #32
	mul  x9, x9, x10
	add  x9, x21, x9
	add  x11, sp, #64            /* txid_tmp */
	ldp  x2, x3,  [x11]
	ldp  x4, x5,  [x11, #16]
	stp  x2, x3,  [x9]
	stp  x4, x5,  [x9, #16]
	/* idx += tx_len ; n++ */
	ldr  x10, [sp]
	add  x23, x23, x10
	add  x25, x25, #1
	b    .Lwalk

.Ldone:
	/* idx == len ? */
	cmp  x23, x20
	b.ne .Lcn_fail
	/* n > 0 */
	cmp  x25, #0
	b.le .Lcn_fail
	/* n == expected_txcount */
	cmp  x25, x24
	b.ne .Lcn_fail
	/* merkle_root(mkout@sp+96, caller_scratch, n) */
	add  x0, sp, #96
	mov  x1, x21
	mov  x2, x25
	bl   merkle_root
	/* compare mkout vs block+36 (32 bytes) */
	add  x9, sp, #96
	add  x10, x19, #36
	ldp  x2, x3,  [x9]
	ldp  x4, x5,  [x10]
	cmp  x2, x4
	b.ne .Lcn_fail
	cmp  x3, x5
	b.ne .Lcn_fail
	ldp  x2, x3,  [x9, #16]
	ldp  x4, x5,  [x10, #16]
	cmp  x2, x4
	b.ne .Lcn_fail
	cmp  x3, x5
	b.ne .Lcn_fail
	mov  w0, #1
	b    .Lcn_ret
.Lcn_fail:
	mov  w0, #0
.Lcn_ret:
	add  sp, sp, x26
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size cons_verify, .-cons_verify

	.section .note.GNU-stack,"",%progbits
