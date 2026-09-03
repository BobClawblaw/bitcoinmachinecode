/* bad.S -- frames that MUST be reported by SAVE-AREA-ALIAS.  A check that
 * cannot be made to fire is not a check (see worklog 2026-09-03: main's verify
 * oracle reported "ZERO DIVERGENCES" for a day while comparing nothing), so
 * these two shapes are the tool's own regression, run by --selftest. */
	.text

/* bad_tab: the prologue saves x19/x20 below the frame and a scratch store
 * lands on x20's slot -- the GLV TAB[8]-over-AUXX class. */
	.globl bad_tab
	.type bad_tab, %function
bad_tab:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	mov  x29,sp
	str  x8, [sp, #8]			/* x20's slot */
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size bad_tab,.-bad_tab

/* bad_frame: the frame is reserved with `sub sp` and the saves go into its
 * top; a scratch store at +24 lands on x20 again. */
	.globl bad_frame
	.type bad_frame, %function
bad_frame:
	sub  sp, sp, #32
	stp  x19,x20,[sp,#16]
	str  x8, [sp, #24]
	ldp  x19,x20,[sp,#16]
	add  sp, sp, #32
	ret
	.size bad_frame,.-bad_frame
