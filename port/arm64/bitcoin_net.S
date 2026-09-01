/* ============================================================================
 * bitcoin_net.S -- AArch64 (ARMv8-A) port of asm/bitcoin_net.asm
 * POSIX sockets + Bitcoin P2P message framing via raw Linux syscalls.
 * AArch64 syscall ABI: args x0..x5, number in x8, `svc #0`, return in x0.
 * (ARM64 numbers: read=63 write=64 close=57 socket=198 connect=203
 *  setsockopt=208.) AAPCS64 arg mapping for SysV(x64):
 *   x0,x1,x2,x3,x4  ~  rdi,rsi,rdx,rcx,r8.
 * Calls sha256d (from the ported bitcoin_hash.S) for the frame checksum.
 * All labels are unique per function (GAS requirement in this tree).
 * ========================================================================== */

	.extern sha256d

	.text

/* ============================================================================
 * long fd_write_all(int fd, x0, const void *buf, x1, size_t n, x2) -> n or -1
 * ========================================================================== */
	.global fd_write_all
	.type fd_write_all, %function
fd_write_all:
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	sub sp, sp, #32                  /* pollfd@0..7, timespec@16..31 */
	mov x19, x0
	mov x20, x1
	mov x21, x2
	mov x12, #0                     /* done */
.WAL:
	cmp x12, x21
	b.hs .WADONE
	/* ---- bound the write: ppoll({fd, POLLOUT}, 1, {10s,0}, NULL) first
	 * (x86 parity; aarch64 has no plain poll -- 73 IS ppoll). A peer that
	 * stops reading otherwise holds a blocking write() for ever.
	 * NULL timeout or error: both are a failed write (-1). */
	str x19, [sp, #0]                /* pollfd.fd */
	mov w1, #4                      /* POLLOUT */
	strh w1, [sp, #4]
	strh wzr, [sp, #6]
	mov x2, #10                     /* timespec {10, 0} */
	str x2, [sp, #16]
	str xzr, [sp, #24]
	mov x0, sp                      /* fds */
	mov x1, #1                      /* nfds */
	add x2, sp, #16                 /* &timeout */
	mov x3, xzr                     /* sigmask */
	mov x8, #73                     /* ppoll */
	svc #0
	cmp x0, #1
	b.lt .WAFAIL
	mov x0, x19
	add x1, x20, x12
	sub x2, x21, x12
	mov x8, #64
	svc #0
	cmp x0, #0
	b.gt .WAOK
.WAFAIL:
	mov x0, #-1
	b .WARET
.WAOK:
	add x12, x12, x0
	b .WAL
.WADONE:
	mov x0, x12
.WARET:
	add sp, sp, #32
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ret
	.size fd_write_all, .-fd_write_all

/* ============================================================================
 * long fd_read_full(int fd, void *buf, size_t n) -> n / <n on eof / -1 on err
 * ========================================================================== */
	.global fd_read_full
	.type fd_read_full, %function
fd_read_full:
	stp x19, x20, [sp, #-16]!
	stp x21, xzr, [sp, #-16]!
	mov x19, x0
	mov x20, x1
	mov x21, x2
	mov x12, #0                     /* got */
.RAL:
	cmp x12, x21
	b.hs .RAFULL
	mov x0, x19
	add x1, x20, x12
	sub x2, x21, x12
	mov x8, #63
	svc #0
	cmp x0, #0
	b.gt .RAOK
	b.eq .RAEOF
	mov x0, #-1
	b .RARET
.RAOK:
	add x12, x12, x0
	b .RAL
.RAEOF:
	mov x0, x12
	b .RARET
.RAFULL:
	mov x0, x12
.RARET:
	ldp x21, xzr, [sp], #16
	ldp x19, x20, [sp], #16
	ret
	.size fd_read_full, .-fd_read_full

/* === int fd_close(int fd) === */
	.global fd_close
	.type fd_close, %function
fd_close:
	mov x8, #57
	svc #0
	ret
	.size fd_close, .-fd_close

/* ============================================================================
 * int tcp_connect_ip(u32 ip_le, u16 port_be) -> fd or -1
 * ========================================================================== */
	.global tcp_connect_ip
	.type tcp_connect_ip, %function
tcp_connect_ip:
	stp x19, x20, [sp, #-16]!
	stp x21, xzr, [sp, #-16]!
	mov w19, w0
	mov w20, w1
	mov x0, #2
	mov x1, #1
	mov x2, #0
	mov x8, #198
	svc #0
	cmp x0, #0
	b.lt .TCIRT
	mov x21, x0
	sub sp, sp, #32
	mov x0, #10
	str x0, [sp, #0]
	str xzr, [sp, #8]
	mov x0, x21
	mov x1, #1
	mov x2, #20
	mov x3, sp
	mov x4, #16
	mov x8, #208
	svc #0
	/* ---- and SO_SNDTIMEO (21) with the same 10s: on Linux it bounds the
	 * blocking connect() below (the x86 2026-08-31 worker-wedge fix); without
	 * it a blackholed address holds connect() for the kernel's two-minute
	 * SYN schedule. Also bounds every later write on this socket. */
	mov x0, x21
	mov x1, #1
	mov x2, #21
	mov x3, sp
	mov x4, #16
	mov x8, #208
	svc #0
	add sp, sp, #32
	sub sp, sp, #32
	str xzr, [sp, #0]
	str xzr, [sp, #8]
	mov w0, #2
	strh w0, [sp, #0]
	strh w20, [sp, #2]
	str w19, [sp, #4]
	mov x0, x21
	mov x1, sp
	mov x2, #16
	mov x8, #203
	svc #0
	add sp, sp, #32
	cmp x0, #0
	b.lt .TCICLOSE
	mov x0, x21
	b .TCIRT
.TCICLOSE:
	mov x20, x0                     /* save -errno */
	mov x0, x21
	mov x8, #57
	svc #0
	mov x0, x20
.TCIRT:
	ldp x21, xzr, [sp], #16
	ldp x19, x20, [sp], #16
	ret
	.size tcp_connect_ip, .-tcp_connect_ip

/* ============================================================================
 * cksum4(out4=x0, payload=x1, plen=x2): out[0:4] = sha256d(payload)[0:4]
 * ========================================================================== */
	.type cksum4, %function
cksum4:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, xzr, [sp, #-16]!
	sub sp, sp, #48
	mov x19, x0
	mov x20, x1
	mov x21, x2
	mov x0, sp
	mov x1, x20
	mov x2, x21
	bl sha256d
	ldr w0, [sp]
	str w0, [x19]
	add sp, sp, #48
	ldp x21, xzr, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size cksum4, .-cksum4

/* Put a u32 constant into wD (magic 0xd9b4bef9 is not a single MOV imm). */
	.macro MOVCONST wD, hi, lo
	mov \wD, #\lo
	movk \wD, #\hi, lsl #16
	.endm

/* ============================================================================
 * long p2p_frame(out=x0, cmd=x1, cmdlen=x2, payload=x3, plen=x4) -> 24+plen
 * ========================================================================== */
	.global p2p_frame
	.type p2p_frame, %function
p2p_frame:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	mov x19, x0                     /* out */
	mov x20, x1                     /* cmd */
	mov x21, x2                     /* cmdlen */
	mov x22, x3                     /* payload */
	mov x23, x4                     /* plen */
	MOVCONST w24, 0xd9b4, 0xbef9
	str w24, [x19, #0]
	add x0, x19, #4
	str xzr, [x0, #0]
	str xzr, [x0, #8]
	/* copy min(cmdlen,12) cmd bytes -> out+4 */
	mov x2, x21
	cmp x2, #12
	b.ls .PFC1
	mov x2, #12
.PFC1:
	mov x3, #0
.PFC2:
	cmp x3, x2
	b.hs .PFC3
	add x4, x19, #4
	add x5, x20, x3
	ldrb w6, [x5]
	add x7, x4, x3
	strb w6, [x7]
	add x3, x3, #1
	b .PFC2
.PFC3:
	str w23, [x19, #16]
	add x0, x19, #20
	mov x1, x22
	mov x2, x23
	bl cksum4
	/* copy plen payload bytes -> out+24 */
	mov x3, #0
.PFPL:
	cmp x3, x23
	b.hs .PFPLEND
	add x4, x19, #24
	add x5, x22, x3
	ldrb w6, [x5]
	add x7, x4, x3
	strb w6, [x7]
	add x3, x3, #1
	b .PFPL
.PFPLEND:
	add x0, x23, #24
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size p2p_frame, .-p2p_frame

/* ============================================================================
 * long p2p_write(fd=x0, cmd=x1, cmdlen=x2, payload=x3, plen=x4) -> sent/-1
 * ========================================================================== */
	.global p2p_write
	.type p2p_write, %function
p2p_write:
	/* BIP324 v2 dispatch; falls through to v1 untouched when no v2 module
	 * (see x86: one cmp + one branch on the hot v1 path). Args x0..x4 are
	 * already the hook's (fd, cmd, cmdlen, payload, plen). */
	cmp  x0, #V2_FD_MAX
	b.hs .p2p_write_v1
	adrp x9, :got:g_v2_active
	ldr  x9, [x9, :got_lo12:g_v2_active]
	ldrb w10, [x9, x0]
	cbz  w10, .p2p_write_v1
	adrp x9, :got:g_v2_hook_write
	ldr  x9, [x9, :got_lo12:g_v2_hook_write]
	ldr  x9, [x9]                    /* deref: load the fn pointer from the global */
	cbz  x9, .p2p_write_v1
	/* Real call, not a tail call: preserve the link + caller FP. sp is
	 * already 16-aligned at entry (AAPCS64), and the stp keeps it aligned,
	 * so the C callee sees the parity it expects. x0..x4 are the args. */
	stp  x29, x30, [sp, #-16]!
	blr  x9
	ldp  x29, x30, [sp], #16
	ret
.p2p_write_v1:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	sub sp, sp, #48
	mov x19, x0                     /* fd */
	mov x20, x1                     /* cmd */
	mov x21, x2                     /* cmdlen */
	mov x22, x3                     /* payload */
	mov x23, x4                     /* plen */
	MOVCONST w24, 0xd9b4, 0xbef9
	str w24, [sp, #0]
	add x0, sp, #4
	str xzr, [x0, #0]
	str xzr, [x0, #8]
	mov x2, x21
	cmp x2, #12
	b.ls .PWC1
	mov x2, #12
.PWC1:
	mov x3, #0
.PWC2:
	cmp x3, x2
	b.hs .PWC3
	add x4, sp, #4
	add x5, x20, x3
	ldrb w6, [x5]
	add x7, x4, x3
	strb w6, [x7]
	add x3, x3, #1
	b .PWC2
.PWC3:
	str w23, [sp, #16]
	add x0, sp, #20
	mov x1, x22
	mov x2, x23
	bl cksum4
	mov x0, x19
	mov x1, sp
	mov x2, #24
	bl fd_write_all
	cmp x0, #24
	b.ne .PWF
	mov x0, x19
	mov x1, x22
	mov x2, x23
	bl fd_write_all
	cmp x0, x23
	b.ne .PWF
	add x0, x23, #24
	b .PWR
.PWF:
	mov x0, #-1
.PWR:
	add sp, sp, #48
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size p2p_write, .-p2p_write

/* ============================================================================
 * int p2p_read(fd=x0, cmd_out=x1, payload=x2, cap=x3, plen_out=x4)
 *   -> 1 ok / 0 eof / -1 err / -2 trunc
 * Local frame: hdr[24]@sp+0..23, announced@24, tocopy@28, drain[64]@32..95.
 * ========================================================================== */
	.global p2p_read
	.type p2p_read, %function
p2p_read:
	/* BIP324 v2 dispatch; falls through to v1 untouched (args x0..x4 are
	 * already the hook's (fd, cmd_out, payload, cap, plen_out)). */
	cmp  x0, #V2_FD_MAX
	b.hs .p2p_read_v1
	adrp x9, :got:g_v2_active
	ldr  x9, [x9, :got_lo12:g_v2_active]
	ldrb w10, [x9, x0]
	cbz  w10, .p2p_read_v1
	adrp x9, :got:g_v2_hook_read
	ldr  x9, [x9, :got_lo12:g_v2_hook_read]
	ldr  x9, [x9]                    /* deref: load the fn pointer from the global */
	cbz  x9, .p2p_read_v1
	stp  x29, x30, [sp, #-16]!
	blr  x9
	ldp  x29, x30, [sp], #16
	ret
.p2p_read_v1:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	sub sp, sp, #96
	mov x19, x0                     /* fd */
	mov x20, x1                     /* cmd_out */
	mov x21, x2                     /* payload */
	mov x22, x3                     /* cap */
	mov x23, x4                     /* plen_out */
	mov x0, x19
	mov x1, sp
	mov x2, #24
	bl fd_read_full
	cmp x0, #24
	b.ne .PREOF
	ldr w24, [sp, #0]
	MOVCONST w18, 0xd9b4, 0xbef9   /* caller-saved scratch; never clobber x25+ */
	cmp w24, w18
	b.ne .PREOF
	/* copy command -> cmd_out */
	mov x3, #0
.PRCMD:
	cmp x3, #12
	b.hs .PRCMDEND
	add x4, sp, #4
	add x5, x4, x3
	ldrb w6, [x5]
	add x7, x20, x3
	strb w6, [x7]
	add x3, x3, #1
	b .PRCMD
.PRCMDEND:
	ldr w24, [sp, #16]
	str w24, [sp, #24]              /* announced */
	/* SECURITY (audit finding 6): reject an oversized announcement before
	 * acting on it -- Core rejects at exactly this point (net.cpp: a length
	 * over MAX_PROTOCOL_MESSAGE_LENGTH = 4,000,000). Without it a peer could
	 * announce 0xFFFFFFFF and make the drain loop below grind ~4 GB off the
	 * socket before the caller's cap saved us. */
	movz w10, #0x3D, lsl #16       /* P2P_MAX_MSG = 4,000,000 = 0x3D0900 */
	movk w10, #0x0900
	cmp  w24, w10
	b.hi .PRBADSZ
	cmp w24, w22
	b.ls .PRS1
	mov w24, w22
.PRS1:
	str w24, [sp, #28]              /* tocopy */
	cbz w24, .PRNOCPY
	mov x0, x19
	mov x1, x21
	ldr w2, [sp, #28]
	bl fd_read_full
	ldr w1, [sp, #28]
	cmp x0, x1
	b.ne .PREOF
.PRNOCPY:
	/* drain announced - tocopy */
	ldr w0, [sp, #24]
	ldr w1, [sp, #28]
	sub w2, w0, w1
	cbz w2, .PRDONE
.PRDRN:
	mov w3, w2
	cmp w3, #64
	b.ls .PRAMT
	mov w3, #64
.PRAMT:
	str w2, [sp, #92]
	mov x0, x19
	add x1, sp, #32
	mov w2, w3
	bl fd_read_full
	ldr w2, [sp, #92]
	cmp x0, #0
	b.le .PRDONE
	sub w2, w2, w0
	cbnz w2, .PRDRN
.PRDONE:
	ldr w0, [sp, #24]
	str w0, [x23]
	ldr w0, [sp, #24]
	ldr w1, [sp, #28]
	cmp w0, w1
	b.hi .PRTRUNC
	mov x0, #1
	b .PRRET
.PRTRUNC:
	mov x0, #-2
	b .PRRET
.PRBADSZ:
	mov x0, #-3                      /* oversized announcement: DISTINCT from -2
	                                  * (truncated) so the caller can score the
	                                  * peer for misbehaviour (x86 mov rax,-3;
	                                  * the serve loop's violation hook keys on
	                                  * exactly this value) */
	b .PRRET
.PREOF:
	mov x0, #0
.PRRET:
	add sp, sp, #96
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size p2p_read, .-p2p_read

	/* net_magic (mainnet P2P message magic, 0xd9b4bef9) -- x86 bitcoin_net.asm */
	.section .data
	.align 2
	.global net_magic
	.type net_magic, %object
net_magic:
	.word 0xd9b4bef9
	.size net_magic, 4

	/* ---- BIP324 v2 transport dispatch (see x86 bitcoin_net.asm) ----
	 * p2p_read/p2p_write are called from ~60 files, so v2 is keyed by fd:
	 * g_v2_active[fd] is set once a v2 handshake completes, and the hooks are
	 * filled by the v2 module. A build never linking the v2 module leaves the
	 * hooks NULL and the table zero, so v1 behaviour is untouched (one cmp +
	 * branch on the hot path). */
	V2_FD_MAX = 4096
	.section .data
	.align 3
	.global g_v2_hook_write
	.type g_v2_hook_write, %object
g_v2_hook_write:
	.quad 0                      /* long (*)(int fd, const char* cmd, u32 cmdlen, const void* payload, u32 plen) */
	.size g_v2_hook_write, 8
	.global g_v2_hook_read
	.type g_v2_hook_read, %object
g_v2_hook_read:
	.quad 0                      /* int (*)(int fd, char cmd_out[12], void* payload, u32 cap, u32* plen_out) */
	.size g_v2_hook_read, 8
	.section .bss
	.align 0
	.global g_v2_active
	.type g_v2_active, %object
g_v2_active:
	.space V2_FD_MAX             /* 1 byte per fd (0=v1, non-zero=v2) */
	.size g_v2_active, V2_FD_MAX

	.section .note.GNU-stack,"",%progbits
