/* ============================================================================
 * bitcoin_headers.S -- AArch64 (ARMv8-A) port of asm/bitcoin_headers.asm
 * Persistent header-chain store: append-only headers.dat with entry N at
 * byte N*112 = [80 header][32 block_hash]. Raw Linux syscalls.
 * ARM64 numbers: openat=56 lseek=62 read=63 write=64 close=57; svc #0, num in x8.
 *   hst_init (hst=x0)                 -> 1 ok / -1
 *   hst_reload(hst=x0)                -> 1 ok (count from file size)
 *   hst_append(hst=x0, hdr=x1, hash=x2) -> new count or -1
 *   hst_get_at(hst=x0, height=x1, out=x2) -> 1 / 0 oor / -1
 *   hst_count(hst=x0)                 -> count
 * State: [fd qword at +0][count qword at +8].
 * ========================================================================== */

	.section .rodata
hdrname: .string "headers.dat"

	.text

/* ============================================================================
 * hst_init(): openat(AT_FDCWD, "headers.dat", O_RDWR|O_CREAT, 0644)
 * ========================================================================== */
	.global hst_init
	.type hst_init, %function
hst_init:
	mov x9, x0                      /* hst base */
	mov x0, #-100                   /* AT_FDCWD */
	adrp x1, hdrname
	add  x1, x1, :lo12:hdrname
	mov x2, #0x42                   /* O_RDWR | O_CREAT */
	mov x3, #0644
	mov x8, #56                     /* openat */
	svc #0
	cmp x0, #0
	b.lt .HSIF
	str x0, [x9, #0]                /* fd */
	str xzr, [x9, #8]               /* count = 0 */
	mov x0, #1
	ret
.HSIF:
	mov x0, #-1
	ret
	.size hst_init, .-hst_init

/* ============================================================================
 * hst_reload(hst): count = lseek(fd, 0, SEEK_END) / 112
 * ========================================================================== */
	.global hst_reload
	.type hst_reload, %function
hst_reload:
	mov x9, x0                      /* hst (svc preserves x9) */
	ldr x0, [x9, #0]                /* fd */
	mov x1, #0
	mov x2, #2                      /* SEEK_END */
	mov x8, #62                     /* lseek */
	svc #0
	cmp x0, #0
	b.lt .HSRE
	mov x3, #112
	udiv x0, x0, x3
	str x0, [x9, #8]
	mov x0, #1
	ret
.HSRE:
	mov x0, #-1
	ret
	.size hst_reload, .-hst_reload

/* ============================================================================
 * hst_append(hst, hdr, hash): seek count*112, write [hdr 80][hash 32], advance.
 * ========================================================================== */
	.global hst_append
	.type hst_append, %function
hst_append:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	sub sp, sp, #128                /* rec[112] at sp */
	mov x19, x0                     /* hst */
	mov x20, x1                     /* hdr */
	mov x21, x2                     /* hash */
	/* lseek(fd, count*112, SEEK_SET) */
	ldr x22, [x19, #8]              /* count */
	ldr x0, [x19, #0]               /* fd */
	mov x1, x22
	mov x13, #112
	mul x1, x1, x13                 /* offset */
	mov x2, #0
	mov x8, #62
	svc #0
	cmp x0, #0
	b.lt .HSAE
	/* build rec: hdr[80] -> sp, hash[32] -> sp+80 */
	mov x3, #0
.HSACP1:
	cmp x3, #80
	b.hs .HSACP1D
	add x2, x20, x3
	ldrb w4, [x2]
	add x2, sp, x3
	strb w4, [x2]
	add x3, x3, #1
	b .HSACP1
.HSACP1D:
	mov x3, #0
.HSACP2:
	cmp x3, #32
	b.hs .HSACP2D
	add x2, x21, x3
	ldrb w4, [x2]
	add x2, sp, #80
	add x2, x2, x3
	strb w4, [x2]
	add x3, x3, #1
	b .HSACP2
.HSACP2D:
	/* write(fd, sp, 112) */
	ldr x0, [x19, #0]
	mov x1, sp
	mov x2, #112
	mov x8, #64
	svc #0
	cmp x0, #112
	b.ne .HSAE
	/* count += 1 */
	ldr x0, [x19, #8]
	add x0, x0, #1
	str x0, [x19, #8]
	add sp, sp, #128
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
.HSAE:
	mov x0, #-1
	add sp, sp, #128
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size hst_append, .-hst_append

/* ============================================================================
 * hst_get_at(hst, height, out[112]) -> 1 / 0 out-of-range / -1
 * ========================================================================== */
	.global hst_get_at
	.type hst_get_at, %function
hst_get_at:
	mov x9, x0
	mov x10, x1
	mov x11, x2
	ldr x12, [x9, #8]               /* count */
	cmp x10, x12
	b.hs .HSGOOR
	/* lseek(fd, height*112, SEEK_SET) */
	ldr x0, [x9, #0]                /* fd */
	mov x1, x10                     /* height */
	mov x13, #112
	mul x1, x1, x13                 /* offset */
	mov x2, #0
	mov x8, #62
	svc #0
	cmp x0, #0
	b.lt .HSGE
	/* read(fd, out, 112) */
	ldr x0, [x9, #0]
	mov x1, x11
	mov x2, #112
	mov x8, #63
	svc #0
	cmp x0, #112
	b.ne .HSGE
	mov x0, #1
	ret
.HSGOOR:
	mov x0, #0
	ret
.HSGE:
	mov x0, #-1
	ret
	.size hst_get_at, .-hst_get_at

/* ============================================================================
 * hst_count(hst) -> count
 * ========================================================================== */
	.global hst_count
	.type hst_count, %function
hst_count:
	ldr x0, [x0, #8]
	ret
	.size hst_count, .-hst_count

	.section .note.GNU-stack,"",%progbits
