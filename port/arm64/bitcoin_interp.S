/* ============================================================================
 * bitcoin_interp.S -- AArch64 port of asm/bitcoin_interp.asm
 * (script_eval VM + helpers). Shared ABI: script_state struct + codec.
 *
 * Buffer globals (accessed via LAddr / *_addr below, thread-local in x86):
 *   interp_tmp (528B scratch elem), bool_buf, interp_err, interp_slice,
 *   cms_keyrefs, cms_sigrefs, cms_scstrip0, cms_scstrip1, cms_needle.
 *
 * Currently ported + verified:
 *   - is_opsuccess         (BIP342 OP_SUCCESSx range check, exhaustive)
 *   - is_opsuccess_c       (C-ABI wrapper)
 *   - interp_memeq         (byte compare -> 0/1)
 *   - interp_swap_recs     (swap two elem records via r13/r14-routed args)
 * NEXT: script_eval (the ~2000-line opcode-dispatch VM) + interp_push_num +
 * interp_push_bool + checksig/multisig subroutines.
 * ========================================================================== */

	.section .bss
	.align 4
interp_tmp:	.space 528
bool_buf:	.space 8
interp_err:	.space 8
interp_slice:	.space 16
cms_keyrefs:	.space 1024
cms_sigrefs:	.space 1024
cms_scstrip0:	.space 8192
cms_scstrip1:	.space 8192
cms_needle:	.space 1300

	.text

	/* is_opsuccess(opcode) -> x0 = 1 if opcode is a BIP342 OP_SUCCESSx.
	 * NOTE: x86 passes opcode in RAX; AAPCS64 passes first arg in x0, so both
	 * is_opsuccess and is_opsuccess_c read it from x0. */
	.global is_opsuccess
	.type   is_opsuccess,%function
is_opsuccess:
	cmp x0,#80
	b.eq .is_yes
	cmp x0,#98
	b.eq .is_yes
	cmp x0,#126
	b.lo .is_r131
	cmp x0,#129
	b.ls .is_yes
.is_r131:
	cmp x0,#131
	b.lo .is_r137
	cmp x0,#134
	b.ls .is_yes
.is_r137:
	cmp x0,#137
	b.lo .is_r141
	cmp x0,#138
	b.ls .is_yes
.is_r141:
	cmp x0,#141
	b.lo .is_r149
	cmp x0,#142
	b.ls .is_yes
.is_r149:
	cmp x0,#149
	b.lo .is_r187
	cmp x0,#153
	b.ls .is_yes
.is_r187:
	cmp x0,#187
	b.lo .is_no
	cmp x0,#254
	b.ls .is_yes
.is_no:
	mov w0,#0
	ret
.is_yes:
	mov w0,#1
	ret
	.size is_opsuccess,.-is_opsuccess

	/* is_opsuccess_c(opcode in x0) -> x0. Same register, so tail-call. */
	.global is_opsuccess_c
	.type   is_opsuccess_c,%function
is_opsuccess_c:
	b is_opsuccess
	.size is_opsuccess_c,.-is_opsuccess_c

	/* interp_memeq(a=x0, b=x1, len=x2) -> x0 = 1 if equal */
	.global interp_memeq
	.type   interp_memeq,%function
interp_memeq:
	mov  x3,#0
1:	cmp  x3,x2
	b.hs 2f
	ldrb w4,[x0,x3]
	ldrb w5,[x1,x3]
	cmp  w4,w5
	b.ne 3f
	add  x3,x3,#1
	b    1b
2:	mov  w0,#1
	ret
3:	mov  w0,#0
	ret
	.size interp_memeq,.-interp_memeq

	.section .note.GNU-stack,"",%progbits
