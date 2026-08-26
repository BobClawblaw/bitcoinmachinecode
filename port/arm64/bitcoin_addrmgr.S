/* ============================================================================
 * bitcoin_addrmgr.S -- AArch64 (ARMv8-A) port of asm/bitcoin_addrmgr.asm
 *
 * Peer address book (peers.dat: fixed 18-byte records, count = size/18) +
 * the Bitcoin `addr` (v2-capable) v1 wire codec. Self-contained (raw syscalls
 * only; "no-libc" like bitcoin_store). AArch64 syscall deltas: openat=56
 * (no open), lseek=62 (offset in x1, whence x2), read=63, write=64.
 *
 * Exports (SysV x64 -> AAPCS64 x0..xn):
 *   int  amr_init   (void* ab)                 -> 1 ok / -1
 *   long amr_count  (void* ab)                 -> #records
 *   int  amr_add    (void* ab, u32 ip, u16 port, u64 services, u32 lastseen)
 *                                             -> 1 added / 0 dup / -1 err
 *   int  amr_get_i  (void* ab, long i, u8 out[18]) -> 1 / -1
 *   long amr_lookup (void* ab, u32 ip)         -> index or -1
 *   long p2p_addr_v1(u8* out, const u8 src[18], long n) -> bytes written
 *   long p2p_addr_count(const u8* pl, long plen) -> #entries or -1
 *
 * Record layout (LE unless noted): ip u32, port u16 BE, services u64,
 *   pad, last_seen u32 @14.
 * ========================================================================== */

	.text
	.global amr_init
	.type amr_init, %function
	.global amr_count
	.type amr_count, %function
	.global amr_add
	.type amr_add, %function
	.global amr_get_i
	.type amr_get_i, %function
	.global amr_lookup
	.type amr_lookup, %function
	.global p2p_addr_v1
	.type p2p_addr_v1, %function
	.global p2p_addr_count
	.type p2p_addr_count, %function

	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

	.section .rodata
peername: .asciz "peers.dat"
	.text

/* amr_init(ab) -> 1/-1 : open peers.dat O_RDWR|O_CREAT, store fd at ab[0] */
amr_init:
	stp  x19, x30, [sp, #-16]!
	mov  x19, x0                 /* ab */
	mov  x8, #56                 /* openat */
	mov  x0, #-100               /* AT_FDCWD */
	LAddr x1, peername
	mov  x2, #0x42               /* O_RDWR|O_CREAT */
	mov  x3, #420                /* 0644 */
	svc  #0
	tbnz x0, #63, .Ami_fail
	str  x0, [x19]               /* ab[0] = fd */
	mov  w0, #1
	b    .Ami_ret
.Ami_fail:
	mov  x0, #-1
.Ami_ret:
	ldp  x19, x30, [sp], #16
	ret
	.size amr_init, .-amr_init

/* amr_count(ab) -> filesize/18 (lseek to SEEK_END) */
amr_count:
	ldr  x0, [x0]                /* fd */
	mov  x1, #0
	mov  x2, #2                  /* SEEK_END */
	mov  x8, #62                 /* lseek */
	svc  #0
	tbnz x0, #63, .Amc_err
	mov  x9, #18
	udiv x0, x0, x9
	ret
.Amc_err:
	mov  x0, #-1
	ret
	.size amr_count, .-amr_count

/* amr_add(ab, ip, port, services, lastseen) -> 1/0/-1 */
amr_add:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, xzr, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #32             /* record[18] @sp */
	mov  x19, x0                 /* ab */
	mov  x20, x1                 /* ip */
	mov  x21, x2                 /* port */
	mov  x22, x3                 /* services */
	mov  x23, x4                 /* lastseen */
	/* dup check via amr_lookup */
	mov  x0, x19
	mov  x1, x20
	bl   amr_lookup
	cmp  x0, #-1
	b.ne .Ama_dup
	/* build record */
	str  w20, [sp]               /* ip u32 LE */
	strh w21, [sp, #4]           /* port u16 BE */
	str  x22, [sp, #6]           /* services u64 */
	str  w23, [sp, #14]          /* last_seen u32 */
	/* seek to end */
	ldr  x0, [x19]
	mov  x1, #0
	mov  x2, #2
	mov  x8, #62
	svc  #0
	tbnz x0, #63, .Ama_err
	/* write 18 */
	ldr  x0, [x19]
	mov  x1, sp
	mov  x2, #18
	mov  x8, #64
	svc  #0
	cmp  x0, #18
	b.ne .Ama_err
	mov  w0, #1
	b    .Ama_ret
.Ama_dup:
	mov  w0, #0
	b    .Ama_ret
.Ama_err:
	mov  x0, #-1
.Ama_ret:
	add  sp, sp, #32
	ldp  x29, x30, [sp], #16
	ldp  x23, xzr, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size amr_add, .-amr_add

/* amr_get_i(ab, i, out) -> 1/-1 : lseek(i*18) + read(18) */
amr_get_i:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x30, [sp, #-16]!
	mov  x19, x2                 /* out */
	mov  x20, x1                 /* i */
	ldr  x21, [x0]               /* fd */
	mov  x1, x20
	mov  x9, #18
	mul  x1, x1, x9
	mov  x0, x21
	mov  x2, #0
	mov  x8, #62
	svc  #0
	tbnz x0, #63, .Amg_err
	mov  x0, x21
	mov  x1, x19
	mov  x2, #18
	mov  x8, #63
	svc  #0
	cmp  x0, #18
	b.ne .Amg_err
	mov  w0, #1
	b    .Amg_ret
.Amg_err:
	mov  x0, #-1
.Amg_ret:
	ldp  x21, x30, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size amr_get_i, .-amr_get_i

/* amr_lookup(ab, ip) -> index / -1 : linear scan via amr_get_i */
amr_lookup:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x30, [sp, #-16]!
	sub  sp, sp, #32             /* rec[18] @sp */
	mov  x19, x0                 /* ab */
	mov  x20, x1                 /* ip */
	mov  x21, #0                 /* index */
.Aml_loop:
	mov  x0, x19
	mov  x1, x21
	mov  x2, sp
	bl   amr_get_i
	cmp  x0, #1
	b.lt .Aml_notfound           /* <=0 (only -1 possible) -> stop */
	ldr  w9, [sp]
	cmp  w9, w20
	b.eq .Aml_found
	add  x21, x21, #1
	b    .Aml_loop
.Aml_notfound:
	mov  x0, #-1
	b    .Aml_ret
.Aml_found:
	mov  x0, x21
.Aml_ret:
	add  sp, sp, #32
	ldp  x21, x30, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size amr_lookup, .-amr_lookup

/* p2p_addr_v1(out, src, n) -> bytes written
 *   addr v1: count varint(1B) then n x 30B [time u32][services u64]
 *   [ip16 v4-mapped at 12..15][port u16 BE] */
p2p_addr_v1:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x30, [sp, #-16]!
	mov  x19, x0                 /* out */
	mov  x20, x1                 /* src */
	mov  x21, x2                 /* n */
	strb w21, [x19]              /* count varint (1-byte, <=252 assumed) */
	mov  x22, #1                 /* cursor */
	mov  x23, #0                 /* i */
.Pav_loop:
	cmp  x23, x21
	b.ge .Pav_done
	mov  x9, #18
	mul  x9, x23, x9
	add  x11, x20, x9            /* src rec */
	add  x10, x19, x22           /* dest */
	ldr  w12, [x11, #14]         /* time = last_seen */
	str  w12, [x10]
	ldr  x12, [x11, #6]          /* services */
	str  x12, [x10, #4]
	ldr  w12, [x11]              /* ip */
	str  w12, [x10, #12]
	ldrh w12, [x11, #4]          /* port BE */
	strh w12, [x10, #28]
	str  xzr, [x10, #16]         /* zero v6 padding 16..23 */
	str  wzr, [x10, #24]         /* zero 24..27 (4B only: don't clobber port @28) */
	add  x22, x22, #30
	add  x23, x23, #1
	b    .Pav_loop
.Pav_done:
	mov  x0, x22
	ldp  x23, x30, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size p2p_addr_v1, .-p2p_addr_v1

/* p2p_addr_count(pl, plen) -> #entries / -1 : parse leading CompactSize,
 *   reject if payload can't hold count*30 records. */
p2p_addr_count:
	cmp  x1, #1
	b.lt .Pac_err
	ldrb w9, [x0]
	mov  x10, #1                 /* varint bytes */
	cmp  w9, #0xfd
	b.eq .Pac_fd
	cmp  w9, #0xfe
	b.eq .Pac_fe
	cmp  w9, #0xff
	b.eq .Pac_ff
	b    .Pac_have
.Pac_fd:
	cmp  x1, #3
	b.lt .Pac_err
	ldrh w9, [x0, #1]
	mov  x10, #3
	b    .Pac_have
.Pac_fe:
	cmp  x1, #5
	b.lt .Pac_err
	ldr  w9, [x0, #1]
	mov  x10, #5
	b    .Pac_have
.Pac_ff:
	cmp  x1, #9
	b.lt .Pac_err
	ldr  x9, [x0, #1]
	mov  x10, #9
	b    .Pac_have
.Pac_have:
	mov  x11, x9                 /* count */
	mov  x9, #30
	mul  x9, x11, x9
	add  x9, x9, x10             /* count*30 + varint */
	cmp  x9, x1
	b.hi .Pac_err
	mov  x0, x11
	ret
.Pac_err:
	mov  x0, #-1
	ret
	.size p2p_addr_count, .-p2p_addr_count

	.section .note.GNU-stack,"",%progbits
