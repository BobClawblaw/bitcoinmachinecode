	.text
	.globl good_fn
good_fn:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	mov  x29,sp
	str  x8, [sp, #48]
	ldr  x9, [sp, #48]
	add  x0, x0, x9
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret

	.globl good_scratch
good_scratch:
	sub  sp, sp, #64
	stp  x19,x20,[sp,#48]
	ldr  x19,[sp,#48]
	ldr  x20,[sp,#56]
	add  sp, sp, #64
	ret
