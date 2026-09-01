/* ============================================================================
 * tests/bench_abi_guard.S -- a callee-saved-register firewall for benchmark
 * harnesses, plus the probe that measures which registers a function destroys.
 * AArch64 port (the x86 original is GNU-as AT&T x86-64; the contract is
 * identical, the register set differs: x19-x28 are callee-saved on AAPCS64).
 *
 *   long bench_call_guarded(void* fn, const unsigned long args[6]);
 *       Calls fn with args[0..5] in x0..x5 and restores every callee-saved
 *       register afterwards no matter what fn did. Returns x0.
 *
 *   long bench_abi_probe(void* fn, const unsigned long args[6],
 *                        unsigned long got[6]);
 *       Loads six distinct sentinels into x19..x24, calls fn(args...), writes
 *       the observed register values to got[0..5] in that order, and returns
 *       how many came back changed.
 * ========================================================================== */
	.text
	.balign 4

	.globl bench_call_guarded
	.type  bench_call_guarded, @function
/* x0 = fn, x1 = args[6] */
bench_call_guarded:
	stp  x29,x30,[sp,#-112]!
	mov  x29, sp
	stp  x19,x20,[sp,#16]
	stp  x21,x22,[sp,#32]
	stp  x23,x24,[sp,#48]
	stp  x25,x26,[sp,#64]
	stp  x27,x28,[sp,#80]
	ldr  x10,[x1,#0]
	ldr  x11,[x1,#8]
	ldr  x12,[x1,#16]
	ldr  x13,[x1,#24]
	ldr  x14,[x1,#32]
	ldr  x15,[x1,#40]
	mov  x8, x0                     /* fn */
	mov  x0, x10
	mov  x1, x11
	mov  x2, x12
	mov  x3, x13
	mov  x4, x14
	mov  x5, x15
	blr  x8                         /* x8 is intra-call scratch on AAPCS64 */
	ldp  x27,x28,[sp,#80]
	ldp  x25,x26,[sp,#64]
	ldp  x23,x24,[sp,#48]
	ldp  x21,x22,[sp,#32]
	ldp  x19,x20,[sp,#16]
	ldp  x29,x30,[sp],#112
	ret
	.size bench_call_guarded, .-bench_call_guarded

	.globl bench_abi_probe
	.type  bench_abi_probe, @function
/* x0 = fn, x1 = args[6], x2 = got[6] -> long (count of clobbered regs) */
bench_abi_probe:
	stp  x29,x30,[sp,#-112]!
	mov  x29, sp
	stp  x19,x20,[sp,#16]
	stp  x21,x22,[sp,#32]
	stp  x23,x24,[sp,#48]
	stp  x25,x26,[sp,#64]
	stp  x27,x28,[sp,#80]
	str  x2,[sp,#96]                /* got */
	ldr  x10,[x1,#0]
	ldr  x11,[x1,#8]
	ldr  x12,[x1,#16]
	ldr  x13,[x1,#24]
	ldr  x14,[x1,#32]
	ldr  x15,[x1,#40]
	mov  x8, x0                     /* fn */
	movz x19,#0x1111
	movk x19,#0x1111,lsl #32
	movz x20,#0x2222
	movk x20,#0x2222,lsl #32
	movz x21,#0x3333
	movk x21,#0x3333,lsl #32
	movz x22,#0x4444
	movk x22,#0x4444,lsl #32
	movz x23,#0x5555
	movk x23,#0x5555,lsl #32
	movz x24,#0x6666
	movk x24,#0x6666,lsl #32
	mov  x0, x10
	mov  x1, x11
	mov  x2, x12
	mov  x3, x13
	mov  x4, x14
	mov  x5, x15
	blr  x8
	ldr  x10,[sp,#96]               /* got */
	str  x19,[x10,#0]
	str  x20,[x10,#8]
	str  x21,[x10,#16]
	str  x22,[x10,#24]
	str  x23,[x10,#32]
	str  x24,[x10,#40]
	ldp  x27,x28,[sp,#80]
	ldp  x25,x26,[sp,#64]
	ldp  x23,x24,[sp,#48]
	ldp  x21,x22,[sp,#32]
	ldp  x19,x20,[sp,#16]
	ldp  x29,x30,[sp],#112
	/* Count the mismatches here so no caller has to duplicate the sentinels. */
	movz x11,#0x1111
	movk x11,#0x1111,lsl #32
	ldr  x12,[x10,#0]
	cmp  x12,x11
	cset x0, ne
	movz x11,#0x2222
	movk x11,#0x2222,lsl #32
	ldr  x12,[x10,#8]
	cmp  x12,x11
	csinc x0, x0, xzr, eq
	movz x11,#0x3333
	movk x11,#0x3333,lsl #32
	ldr  x12,[x10,#16]
	cmp  x12,x11
	csinc x0, x0, xzr, eq
	movz x11,#0x4444
	movk x11,#0x4444,lsl #32
	ldr  x12,[x10,#24]
	cmp  x12,x11
	csinc x0, x0, xzr, eq
	movz x11,#0x5555
	movk x11,#0x5555,lsl #32
	ldr  x12,[x10,#32]
	cmp  x12,x11
	csinc x0, x0, xzr, eq
	movz x11,#0x6666
	movk x11,#0x6666,lsl #32
	ldr  x12,[x10,#40]
	cmp  x12,x11
	csinc x0, x0, xzr, eq
	ret
	.size bench_abi_probe, .-bench_abi_probe

	.section .note.GNU-stack,"",@progbits
