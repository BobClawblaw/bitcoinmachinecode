/* node_log.S -- AArch64 port of asm/node_log.asm: tiny leveled text logger.
 *
 *   long node_log_open(const char* path)            -> log fd, or 0 on error
 *   void node_log_event(long fd, int kind, u32 a, u32 b, u32 c) "<KIND> a b c\n"
 *   void node_log_str  (long fd, int kind, const char* s, long len) "<KIND> s\n"
 *   kinds: 0 INFO 1 HSHK 2 HDRS 3 BLOCK 4 CONS 5 STORE 6 ERROR 7 SERVE
 * extern fd_write_all(fd, buf, len) from bitcoin_net.S
 *
 * AAPCS64: args x0.. ; callee-saved x19-x24 preserved; sp 16-aligned across bl.
 * Syscall: openat = 56 (dirfd x0, path x1, flags x2, mode x3).
 */
	.section .rodata
	.balign 4
kind_tbl:
	.ascii "INFO"	/* 0 */
	.ascii "HSHK"	/* 1 */
	.ascii "HDRS"	/* 2 */
	.ascii "BLOCK"	/* 3 */
	.ascii "CONS"	/* 4 */
	.ascii "STORE"	/* 5 */
	.ascii "ERROR"	/* 6 */
	.ascii "SERVE"	/* 7 */
kind_len:
	.byte 4,4,4,5,4,5,5,5
	.section .text
	.balign 4

/* ---- node_log_open(path) -> fd or 0 ---- */
	.global node_log_open
	.type node_log_open,%function
node_log_open:
	mov  x9, x0		/* path (AAPCS64 arg0 is x0; save before clobbering) */
	mov  w8, #56		/* openat */
	mov  x0, #-100		/* AT_FDCWD (dirfd) */
	mov  x1, x9		/* path */
	mov  x2, #0x441		/* O_WRONLY|O_APPEND|O_CREAT */
	mov  x3, #0x1b4		/* 0644 */
	svc  #0
	tbnz x0, #63, .nlo_fail
	ret
.nlo_fail:
	mov  w0, #0
	ret
	.size node_log_open,.-node_log_open

/* ---- emit_u32(buf x0, val w1) -> ptr after "VAL " in x0 ---- */
emit_u32:
	sub  sp, sp, #16	/* stack digits area [sp, sp+16) */
	mov  x2, sp
	add  x2, x2, #15	/* x2 = byte just past buffer end */
	mov  w5, w1
	cbnz w5, .lg
	sub  x2, x2, #1
	mov  w4, #'0'
	strb w4, [x2]
	b    .flip
.lg:
	mov  w6, #10
	udiv x7, x5, x6
	msub x8, x7, x6, x5	/* rem = x5 - x7*10 */
	sub  x2, x2, #1
	add  w8, w8, #'0'
	strb w8, [x2]
	mov  x5, x7
	cbnz x5, .lg
.flip:
	mov  x3, sp
	add  x3, x3, #15	/* x3 = past-end pointer */
.cp:
	ldrb w9, [x2]
	strb w9, [x0]
	add  x0, x0, #1
	add  x2, x2, #1
	cmp  x2, x3
	b.lo .cp
	mov  w10, #' '
	strb w10, [x0]
	add  x0, x0, #1
	add  sp, sp, #16
	ret

/* ---- put_kind(buf x0, kind w1) -> ptr after "<KIND> " in x0 ---- */
put_kind:
	adrp x4, kind_tbl
	add  x4, x4, :lo12:kind_tbl
	adrp x6, kind_len
	add  x6, x6, :lo12:kind_len
	mov  x5, #0
	cbz  w1, .nk
.lk:
	ldrb w7, [x6, x5]
	add  x4, x4, x7
	add  x5, x5, #1
	cmp  w5, w1
	b.lo .lk
.nk:
	ldrb w7, [x6, w1, uxtw]	/* len of this kind */
	mov  x5, #0
.w:
	ldrb w9, [x4, x5]
	strb w9, [x0, x5]
	add  x5, x5, #1
	cmp  x5, x7
	b.lo .w
	add  x0, x0, x7
	mov  w10, #' '
	strb w10, [x0]
	add  x0, x0, #1
	ret

/* ---- node_log_event(fd x0, kind w1, a w2, b w3, c w4) ---- */
	.global node_log_event
	.type node_log_event,%function
node_log_event:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	sub  sp, sp, #160	/* line buffer [sp, sp+160) */
	mov  x19, x0		/* fd */
	mov  x20, x1		/* kind */
	mov  w21, w2		/* a */
	mov  w22, w3		/* b */
	mov  w23, w4		/* c */
	mov  x0, sp
	mov  w1, w20
	bl   put_kind
	mov  w1, w21
	bl   emit_u32
	mov  w1, w22
	bl   emit_u32
	mov  w1, w23
	bl   emit_u32
	sub  x0, x0, #1		/* back over the trailing space */
	mov  w1, #10
	strb w1, [x0]		/* newline */
	add  x0, x0, #1
	mov  x3, sp
	sub  x2, x0, x3		/* len = end - buf */
	mov  x0, x19
	mov  x1, sp
	bl   fd_write_all
	add  sp, sp, #160
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size node_log_event,.-node_log_event

/* ---- node_log_str(fd x0, kind w1, s x2, len x3) ---- */
	.global node_log_str
	.type node_log_str,%function
node_log_str:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	sub  sp, sp, #160	/* line buffer */
	mov  x19, x0		/* fd */
	mov  x20, x1		/* kind (unused: production line is timestamp-first like x86 log_ts.h) */
	mov  x21, x2		/* s */
	mov  x22, x3		/* len */
	mov  x0, sp
	mov  x1, x21
	mov  x2, x22
	cbnz x2, .ap
	b    .nl
.ap:
	ldrb w9, [x1]
	strb w9, [x0]
	add  x0, x0, #1
	add  x1, x1, #1
	sub  x2, x2, #1
	cbnz x2, .ap
.nl:
	mov  w9, #10
	strb w9, [x0]
	add  x0, x0, #1
	mov  x3, sp
	sub  x2, x0, x3		/* len = end - buf */
	mov  x0, x19
	mov  x1, sp
	bl   fd_write_all
	add  sp, sp, #160
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size node_log_str,.-node_log_str

	.section .note.GNU-stack,"",@progbits
