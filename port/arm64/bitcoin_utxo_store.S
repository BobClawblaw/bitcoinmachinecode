/* bitcoin_utxo_store.S -- AArch64 port of asm/bitcoin_utxo_store.asm.
 * Persistent UTXO store: append-only utxo.dat WAL + utxo.idx checkpoint
 * snapshot, crash-safe via restart-resume (checkpoint + WAL-tail replay).
 * Same on-disk framing as x86 so a datadir is cross-compatible.
 *
 * st: +0 log_fd, +8 idx_fd, +16 log_len, +24 ckpt_log_off, +32 ckpt_n
 * WAL PUSH: [u32 magic][u8 op=1][3 pad][txid32][index4][value8][height4][cb1][slen2][script]  PUSH_HDR=59
 * WAL DEL : [u32 magic][u8 op=2][3 pad][txid32][index4]                                      DEL_SIZE=44
 * utxo.idx: [u32 magic][u64 log_off][u64 n] (IDX_HDR=20) then n records of CKPT_REC(51)+script
 * AArch64 syscalls: openat(dirfd=-100 AT_FDCWD)=56, read=63, write=64, lseek=62, fsync=82, close=57.
 */
	.section .text
	.balign 4

MAGIC_LOG = 0x5554584F
OP_PUSH   = 1
OP_DEL    = 2
MAGIC_IDX = 0x55545849
CKPT_REC  = 51
PUSH_HDR  = 59
DEL_SIZE  = 44
IDX_HDR   = 20
O_RDONLY  = 0
O_WRONLY  = 1
O_CREAT   = 0x40
O_TRUNC   = 0x200
AT_FDCWD  = -100
SYS_read  = 63
SYS_write = 64
SYS_lseek = 62
SYS_openat= 56
SYS_close = 57
SYS_fsync = 82

logname:
	.asciz "utxo.dat"
idxname:
	.asciz "utxo.idx"
	.balign 4

/* ---------- mac_memcpy(dst=x0, src=x1, n=x2), local ---------- */
mac_memcpy:
	mov  x3, #0
.mc:
	cmp  x3, x2
	b.hs .md
	ldrb w4, [x1, x3]
	strb w4, [x0, x3]
	add  x3, x3, #1
	b    .mc
.md:
	ret

/* ---------- mac_read_exact(fd=x0, buf=x1, len=x2) -> 0 ok / -1, local.
 * Uses only x19/x20 (pushed) and caller-saved x9 for the counter, so it
 * preserves every callee-saved register including the caller's fd in x21. */
mac_read_exact:
	stp  x19,x20,[sp,#-16]!
	mov  x19,x0
	mov  x20,x1
	mov  x9,x2
.re:
	cbz  x9, .rok
	mov  x0,x19
	mov  x1,x20
	mov  x2,x9
	mov  x8,#SYS_read
	svc  #0
	cbz  x0, .rbad
	tbnz x0, #63, .rbad      /* tax: svc doesn't set NZCV; test sign bit */
	add  x20,x20,x0
	sub  x9,x9,x0
	b    .re
.rbad:
	mov  x0,#-1
	b    .rdone
.rok:
	mov  x0,#0
.rdone:
	ldp  x19,x20,[sp],#16
	ret

/* ---------- WAL buffering (x86 2026-09-01 parity, incident replay) ----------
 * Records are appended to a 1 MB process-wide buffer (wal_buf) and land in
 * the file in one write(2) per drain -- the per-record write() was ~6% of the
 * live replay's CPU. log_len ([st+16]) is the LOGICAL length (file + buffered
 * bytes) at all times -- the lesson of the same day's sparse-offset bug.
 * Drains: utxo_store_wal_drain (exported; the apply loop calls it after every
 * block), and implicitly before a checkpoint (utxo_store_sync), a reload
 * (which measures the file), a flush (which truncates the file), a close, and
 * whenever a DIFFERENT store's fd wants the buffer. A crash can therefore
 * lose only the not-yet-drained SUFFIX of the op stream. */
	.equ WALBUF_CAP, 1048576
	.section .bss
	.align 4
wal_buf:	.zero WALBUF_CAP
	.align 3
wal_fill:	.zero 8
wal_fd:		.zero 8
	.text

/* mac_wal_drain_fd(fd=x0) -> 0 ok / -1: write every buffered byte to fd.
 * Loops over short writes; on an error the unwritten tail moves to the front
 * of the buffer so a retry writes exactly the bytes that never landed.
 * Clobbers x0-x11 only; caller-saved contract. */
mac_wal_drain_fd:
	mov  x8, x0
	adrp x9, wal_buf
	add  x9, x9, :lo12:wal_buf
	adrp x10, wal_fill
	ldr  x10, [x10, :lo12:wal_fill]
.wd_loop:
	cbz  x10, .wd_done
	mov  x0, x8
	mov  x1, x9
	mov  x2, x10
	mov  x11, x8                     /* fd across the syscall (x8 = syscall no);
	                                 * RAW syscall like the x86: mac_write_exact
	                                 * clobbers x9/x10, this loop's state */
	mov  x8, #SYS_write
	svc  #0
	mov  x8, x11
	cmp  x0, #0
	b.le .wd_err
	add  x9, x9, x0
	sub  x10, x10, x0
	b    .wd_loop
.wd_done:
	adrp x0, wal_fill
	str  xzr, [x0, :lo12:wal_fill]
	mov  x0, #0
	ret
.wd_err:
	/* dst < src: a forward overlapping copy is safe */
	adrp x0, wal_buf
	add  x0, x0, :lo12:wal_buf
	mov  x1, x9
	mov  x2, x10
3:	ldrb w3, [x1], #1
	strb w3, [x0], #1
	subs x2, x2, #1
	b.ne 3b
	adrp x0, wal_fill
	str  x10, [x0, :lo12:wal_fill]
	mov  x0, #-1
	ret
	/* clobbers x0-x11 */

mac_wal_drain_fd_pending:            /* drain to whichever fd owns the pending bytes */
	adrp x0, wal_fd
	ldr  x0, [x0, :lo12:wal_fd]
	b    mac_wal_drain_fd

/* ---------- mac_wr_log(st=x19, buf=x20, len=x21) -> 0 ok / -1, local.
 * BUFFERED (main b3d47a9 ported): records are appended to the 1 MB wal_buf and
 * land in utxo.dat one write(2) per drain; the per-record write() was ~6% of
 * the live replay's CPU. log_len ([st+16]) is the LOGICAL length -- file bytes
 * PLUS buffered bytes -- at all times.
 *   owner switch (a different store's fd owns the buffer) -> drain theirs
 *   fill + len > CAP                                        -> drain first
 *   len > CAP                                               -> drain, then
 *                                                             straight through
 * REGISTER DISCIPLINE -- this is where the first attempt died. The callers
 * (utxo_store_put/del) pass st/buf/len in x19/x20/x21 and keep x22/x23 live
 * across the call, and every temporary here is a STACK ADDRESS inside
 * utxo_store_put's frame: the last time this was buffered, the copy loop took
 * its byte register from the callee-saved set and "put's x19 came back as a
 * record byte (0x8d)" -- four gdb rounds, no answer, reverted. So: x0-x3 and
 * x8-x11 ONLY, matching mac_wal_drain_fd's documented contract, and x19-x28
 * are not touched by this routine or anything it calls. */
mac_wr_log:
	stp  x29,x30,[sp,#-16]!          /* IT CALLS NOW (the drains), so it is no
	                                  * longer a leaf: x30 must survive or the
	                                  * caller's `ret` goes nowhere. Exit only
	                                  * through .wl_ret. */
	ldr  x0,[x19]                    /* log_fd */
	adrp x9, wal_fill
	ldr  x9, [x9, :lo12:wal_fill]
	cbz  x9, .wl_owner_ok
	adrp x8, wal_fd
	ldr  x8, [x8, :lo12:wal_fd]
	subs x8, x0, x8
	b.eq .wl_owner_ok
	bl   mac_wal_drain_fd_pending    /* another store's bytes are pending: land
	                                  * them on THEIR fd first */
	cbnz x0, .wl_fail
	ldr  x0,[x19]
.wl_owner_ok:
	adrp x8, wal_fd
	str  x0, [x8, :lo12:wal_fd]
	mov  x9, #WALBUF_CAP
	cmp  x21, x9
	b.hi .wl_direct
	adrp x9, wal_fill
	ldr  x9, [x9, :lo12:wal_fill]
	add  x9, x9, x21
	mov  x10, #WALBUF_CAP
	cmp  x9, x10
	b.ls .wl_append
	bl   mac_wal_drain_fd            /* x0 = this fd: make room */
	cbnz x0, .wl_fail
.wl_append:
	adrp x0, wal_buf
	add  x0, x0, :lo12:wal_buf
	adrp x3, wal_fill
	ldr  x3, [x3, :lo12:wal_fill]
	add  x0, x0, x3                  /* dst = wal_buf + fill */
	mov  x1, x20                     /* src = the record */
	mov  x2, x21                     /* len */
.Lwl_w8:                             /* 8 at a time: plain LDR/STR allow
	                                  * unaligned addresses architecturally,
	                                  * and a WAL record is 44/59+slen bytes */
	cmp  x2, #8
	b.lt .Lwl_tail
	ldr  x3, [x1], #8
	str  x3, [x0], #8
	sub  x2, x2, #8
	b    .Lwl_w8
.Lwl_tail:
	cbz  x2, .Lwl_done
	ldrb w3, [x1], #1
	strb w3, [x0], #1
	sub  x2, x2, #1
	b    .Lwl_tail
.Lwl_done:
	adrp x0, wal_fill
	ldr  x1, [x0, :lo12:wal_fill]
	add  x1, x1, x21
	str  x1, [x0, :lo12:wal_fill]
	ldr  x2, [x19, #16]
	add  x2, x2, x21
	str  x2, [x19, #16]
	mov  x0, #0
	b    .wl_ret
.wl_direct:                          /* larger than the buffer: drain, then write it straight through */
	bl   mac_wal_drain_fd
	cbnz x0, .wl_fail
	ldr  x0,[x19]
	mov  x1,x20
	mov  x2,x21
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,x21
	b.ne .wl_fail
	ldr  x2,[x19,#16]
	add  x2,x2,x21
	str  x2,[x19,#16]
	mov  x0,#0
	b    .wl_ret
.wl_fail:
	mov  x0,#-1
.wl_ret:
	ldp  x29,x30,[sp],#16
	ret
	.size mac_wr_log,.-mac_wr_log

/* ---------- mac_fsync(fd=x0) -> 0/-1, local ---------- */
mac_fsync:
	mov  x8,#SYS_fsync
	svc  #0
	ret

/* ============================================================================
 * utxo_store_wal_drain(st) -> 0 ok / -1 write error. Lands the buffered WAL
 * bytes (whichever store they belong to) in the file. Callable from C; the
 * apply loop calls it after every block (x86 2026-09-01 parity).
 * ========================================================================== */
	.global utxo_store_wal_drain
	.type utxo_store_wal_drain,%function
utxo_store_wal_drain:
	adrp x0, wal_fill
	ldr  x0, [x0, :lo12:wal_fill]
	cbz  x0, .wdr_none
	adrp x0, wal_fd
	ldr  x0, [x0, :lo12:wal_fd]
	b    mac_wal_drain_fd
.wdr_none:
	mov  x0, #0
	ret
	.size utxo_store_wal_drain,.-utxo_store_wal_drain

/* ============================================================================
 * utxo_store_init(st=x0) -> 1/-1
 * ========================================================================== */
	.global utxo_store_init
	.type utxo_store_init,%function
utxo_store_init:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	mov  x19,x0
	mov  x0,#AT_FDCWD
	adr  x1, logname
	mov  x2,#(O_WRONLY|O_CREAT)
	mov  x3,#0644
	mov  x8,#SYS_openat
	svc  #0
	cmp  x0,#0
	b.lt 1f
	str  x0,[x19]
	mov  x0,#AT_FDCWD
	adr  x1, idxname
	mov  x2,#(O_WRONLY|O_CREAT)
	mov  x3,#0644
	mov  x8,#SYS_openat
	svc  #0
	cmp  x0,#0
	b.lt 2f
	str  x0,[x19,#8]
	str  xzr,[x19,#16]
	str  xzr,[x19,#24]
	str  xzr,[x19,#32]
	mov  x0,#1
	b    3f
2:
	ldr  x0,[x19]
	mov  x8,#SYS_close
	svc  #0
1:
	mov  x0,#-1
3:
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_store_init,.-utxo_store_init

/* ============================================================================
 * utxo_store_init_ro(st=x0) -> 1/-1
 * ========================================================================== */
	.global utxo_store_init_ro
	.type utxo_store_init_ro,%function
utxo_store_init_ro:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	mov  x19,x0
	mov  x0,#AT_FDCWD
	adr  x1, logname
	mov  x2,#O_RDONLY
	mov  x3,#0
	mov  x8,#SYS_openat
	svc  #0
	cmp  x0,#0
	b.lt 1f
	str  x0,[x19]
	mov  x0,#-1
	str  x0,[x19,#8]
	str  xzr,[x19,#16]
	str  xzr,[x19,#24]
	str  xzr,[x19,#32]
	mov  x0,#1
	b    2f
1:
	mov  x0,#-1
2:
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_store_init_ro,.-utxo_store_init_ro

/* ============================================================================
 * utxo_store_put(st,u,txid,index,value,height,cb,script,slen) -> 1/0/2/-1
 * x0=st x1=u x2=txid x3=index(w) x4=value x5=height(w) x6=cb(w) x7=script
 * [x29+16]=slen(w).  x19=st x22=u x23=txid (mac_wr_log uses x19/x20/x21).
 * ========================================================================== */
	.global utxo_store_put
	.type utxo_store_put,%function
utxo_store_put:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp,sp,#0x100
	mov  x19,x0              /* st */
	mov  x22,x1              /* u */
	mov  x23,x2              /* txid */
	uxtw x9,w3
	str  x9,[sp,#0x00]       /* index */
	str  x4,[sp,#0x08]       /* value */
	uxtw x9,w5
	str  x9,[sp,#0x10]       /* height */
	uxtw x9,w6
	str  x9,[sp,#0x18]       /* is_coinbase */
	str  x7,[sp,#0x20]       /* script */
	ldr  x9,[x29,#16]
	uxtw x9,w9
	str  x9,[sp,#0x28]       /* slen */
	/* build PUSH header (59B) at [sp,#0x50..0x8b] */
	mov  w9,#0x584f
	movk w9,#0x5554,lsl #16  /* MAGIC_LOG */
	str  w9,[sp,#0x50]
	mov  w9,#OP_PUSH
	strb w9,[sp,#0x54]
	strb wzr,[sp,#0x55]
	strb wzr,[sp,#0x56]
	strb wzr,[sp,#0x57]
	add  x0,sp,#0x58
	mov  x1,x23
	mov  x2,#32
	bl   mac_memcpy
	ldr  x9,[sp,#0x00]
	str  w9,[sp,#0x78]       /* +40 index */
	ldr  x9,[sp,#0x08]
	str  x9,[sp,#0x7c]       /* +44 value */
	ldr  x9,[sp,#0x10]
	str  w9,[sp,#0x84]       /* +52 height */
	ldr  x9,[sp,#0x18]
	strb w9,[sp,#0x88]       /* +56 is_coinbase */
	ldr  x9,[sp,#0x28]
	strh w9,[sp,#0x89]       /* +57 slen(u16) */
	/* append header */
	add  x20,sp,#0x50
	mov  x21,#PUSH_HDR
	bl   mac_wr_log
	cbnz x0,.p_fail
	/* append script if any */
	ldr  x20,[sp,#0x28]
	cbz  x20,.p_script_done
	mov  x21,x20
	ldr  x20,[sp,#0x20]
	bl   mac_wr_log
	cbnz x0,.p_fail
.p_script_done:
	/* utxo_put(u,txid,index,value,height,cb,script,slen) */
	mov  x0,x22
	mov  x1,x23
	ldr  x2,[sp,#0x00]
	ldr  x3,[sp,#0x08]
	ldr  x4,[sp,#0x10]
	ldr  x5,[sp,#0x18]
	ldr  x6,[sp,#0x20]
	ldr  x7,[sp,#0x28]
	bl   utxo_put
	b    .p_done
.p_fail:
	mov  x0,#-1
.p_done:
	add  sp,sp,#0x100
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_store_put,.-utxo_store_put

/* ============================================================================
 * utxo_store_del(st=x0,u=x1,txid=x2,index=x3) -> 1/0/-1
 * ========================================================================== */
	.global utxo_store_del
	.type utxo_store_del,%function
utxo_store_del:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp,sp,#0x100
	mov  x19,x0
	mov  x22,x1
	mov  x23,x2
	uxtw x9,w3
	str  x9,[sp,#0x00]
	mov  w9,#0x584f
	movk w9,#0x5554,lsl #16
	str  w9,[sp,#0x50]
	mov  w9,#OP_DEL
	strb w9,[sp,#0x54]
	strb wzr,[sp,#0x55]
	strb wzr,[sp,#0x56]
	strb wzr,[sp,#0x57]
	add  x0,sp,#0x58
	mov  x1,x23
	mov  x2,#32
	bl   mac_memcpy
	ldr  x9,[sp,#0x00]
	str  w9,[sp,#0x78]
	add  x20,sp,#0x50
	mov  x21,#DEL_SIZE
	bl   mac_wr_log
	cbnz x0,.d_fail
	mov  x0,x22
	mov  x1,x23
	ldr  x2,[sp,#0x00]
	bl   utxo_del
	b    .d_done
.d_fail:
	mov  x0,#-1
.d_done:
	add  sp,sp,#0x100
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_store_del,.-utxo_store_del

/* ============================================================================
 * utxo_store_count(st=x0,u=x1) -> n
 * ========================================================================== */
	.global utxo_store_count
	.type utxo_store_count,%function
utxo_store_count:
	ldr  x0,[x1]
	ret
	.size utxo_store_count,.-utxo_store_count

/* ============================================================================
 * utxo_store_get(st,u,txid,index,&value,&height,&cb,&script,&slen) -> utxo_get
 * x0=st x1=u x2=txid x3=index x4=&value x5=&height x6=&cb x7=&script [sp]=&slen
 * Tail-call utxo_get(u,txid,index,&v,&h,&cb,&script,&slen).
 * ========================================================================== */
	.global utxo_store_get
	.type utxo_store_get,%function
utxo_store_get:
	ldr  x8,[sp]
	mov  x0,x1
	mov  x1,x2
	mov  x2,x3
	mov  x3,x4
	mov  x4,x5
	mov  x5,x6
	mov  x6,x7
	mov  x7,x8
	b    utxo_get
	.size utxo_store_get,.-utxo_store_get

/* ============================================================================
 * utxo_store_clear(u=x0) -- reset in-memory table (leaf, x8-x11 only)
 * ========================================================================== */
	.global utxo_store_clear
	.type utxo_store_clear,%function
utxo_store_clear:
	mov  x8,x0
	str  xzr,[x8]
	str  xzr,[x8,#32]
	ldr  x9,[x8,#8]
	add  x9,x9,#1
	add  x10,x8,#40
.cl:
	cbz  x9, .cd
	mov  x11,#-1
	str  w11,[x10,#40]
	add  x10,x10,#48
	sub  x9,x9,#1
	b    .cl
.cd:
	ret
	.size utxo_store_clear,.-utxo_store_clear

/* ============================================================================
 * utxo_store_sync(st=x0,u=x1) -> 1/-1
 * x19=st x20=u x21=idx fd x22=slot index x23=slot base.
 * ========================================================================== */
	.global utxo_store_sync
	.type utxo_store_sync,%function
utxo_store_sync:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	sub  sp,sp,#0x100
	mov  x19,x0
	mov  x20,x1
	/* land any buffered WAL bytes first: the checkpoint records
	 * ckpt_log_off = log_len, and log_len is logical (file + buffered) */
	mov  x0,x19
	bl   utxo_store_wal_drain
	cmp  x0,#-1
	b.eq .s_fail
	mov  x0,#AT_FDCWD
	adr  x1, idxname
	mov  x2,#(O_WRONLY|O_CREAT|O_TRUNC)
	mov  x3,#0644
	mov  x8,#SYS_openat
	svc  #0
	cmp  x0,#0
	b.lt .s_fail
	mov  x21,x0
	/* header @ [sp,#0x90]: magic w, log_off q, n q */
	mov  w9,#0x5849
	movk w9,#0x5554,lsl #16   /* MAGIC_IDX */
	str  w9,[sp,#0x90]
	ldr  x9,[x19,#16]
	str  x9,[sp,#0x94]
	ldr  x9,[x20]
	str  x9,[sp,#0x9c]
	mov  x0,x21
	add  x1,sp,#0x90
	mov  x2,#IDX_HDR
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,#IDX_HDR
	b.ne .s_fclose
	mov  x22,#0
.slot_loop:
	ldr  x9,[x20,#8]
	cmp  x22,x9
	b.hi .s_done
	mov  x9,x22
	mov  x10,#48
	mul  x9,x9,x10
	add  x9,x9,#40
	add  x9,x9,x20          /* slot base */
	ldr  w10,[x9,#40]
	cmn  w10,#1
	b.eq .s_next
	mov  x23,x9
	/* txid32 */
	mov  x0,x21
	add  x1,x9,#8
	mov  x2,#32
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,#32
	b.ne .s_fclose
	/* index4 */
	mov  x0,x21
	add  x1,x23,#40
	mov  x2,#4
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,#4
	b.ne .s_fclose
	/* record = blob + [slot].blob_off */
	ldr  x9,[x23]
	ldr  x10,[x20,#16]
	add  x9,x9,x10
	mov  x24,x9
	/* value8 */
	mov  x0,x21
	mov  x1,x24
	mov  x2,#8
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,#8
	b.ne .s_fclose
	/* packed = record+8 ; write height(4) + cb(1) */
	ldr  x9,[x24,#8]
	str  x9,[sp,#0x88]
	mov  x0,x21
	add  x1,sp,#0x88
	mov  x2,#4
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,#4
	b.ne .s_fclose
	add  x1,sp,#0x88
	add  x1,x1,#4
	mov  x0,x21
	mov  x2,#1
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,#1
	b.ne .s_fclose
	/* slen2 */
	ldrh w9,[x24,#16]
	strh w9,[sp,#0x86]
	mov  x0,x21
	add  x1,sp,#0x86
	mov  x2,#2
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,#2
	b.ne .s_fclose
	/* script */
	ldrh w9,[x24,#16]
	cbz  w9,.s_next
	add  x1,x24,#24
	mov  x0,x21
	uxtw x2,w9
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,x2
	b.ne .s_fclose
.s_next:
	add  x22,x22,#1
	b    .slot_loop
.s_done:
	ldr  x9,[x19,#16]
	str  x9,[x19,#24]
	ldr  x9,[x20]
	str  x9,[x19,#32]
	mov  x0,x21
	bl   mac_fsync
	ldr  x0,[x19]
	bl   mac_fsync
	mov  x0,x21
	mov  x8,#SYS_close
	svc  #0
	mov  x0,#1
	b    .s_ret
.s_fclose:
	mov  x0,x21
	mov  x8,#SYS_close
	svc  #0
.s_fail:
	mov  x0,#-1
.s_ret:
	add  sp,sp,#0x100
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_store_sync,.-utxo_store_sync

/* ============================================================================
 * utxo_store_reload(st=x0,u=x1) -> replayed / -1 / -2(full)
 * Frame: push 5 pairs (80B), sub sp by x26 (0x10200). x25 = sp + 0x10000.
 *   script scratch @ [sp+0x10] (grows up, cap 65535; stays below x25)
 *   ckpt record @ x25+0x60 (packed 51B: txid@0 idx@32 value@36 height@44 cb@48 slen@49)
 *   idx header @ x25+0x100 (magic@0 log_off@4 n@12)
 *   consumed @ x25+0xa8
 * x19=st x20=u x21=read fd x22=replayed x23=log-end x25=high-base x26=frame-size.
 * Unaligned packed-field loads use register-offset indexing.
 * ========================================================================== */
	.global utxo_store_reload
	.type utxo_store_reload,%function
utxo_store_reload:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	movz x26,#0x0001, lsl #16
	movk x26,#0x0200        /* x26 = 0x10200 (frame size, callee-saved) */
	sub  sp,sp,x26
	add  x25,sp,#0x10000    /* x25 = high-locals base */
	mov  x19,x0
	mov  x20,x1                     /* save u BEFORE the drain (it clobbers x1) */
	/* (0) land any buffered WAL bytes: the size measured below must be the
	 * logical length (x86 parity, buffered-WAL incident) */
	mov  x0,x19
	bl   utxo_store_wal_drain
	cmp  x0,#-1
	b.eq .rl_fail
	/* (1) reset table */
	mov  x0,x20
	bl   utxo_store_clear
	/* (2) measure log size */
	ldr  x0,[x19]
	mov  x1,#0
	mov  x2,#2              /* SEEK_END */
	mov  x8,#SYS_lseek
	svc  #0
	cmp  x0,#0
	b.lt .rl_fail
	str  x0,[x19,#16]
	mov  x23,x0            /* log end */
	/* (3) try checkpoint */
	str  xzr,[x19,#24]
	str  xzr,[x19,#32]
	mov  x0,#AT_FDCWD
	adr  x1, idxname
	mov  x2,#O_RDONLY
	mov  x3,#0
	mov  x8,#SYS_openat
	svc  #0
	cmp  x0,#0
	b.lt .rl_no_ckpt
	mov  x21,x0
	mov  x0,x21
	add  x1,x25,#0x100
	mov  x2,#IDX_HDR
	bl   mac_read_exact
	cbnz x0,.rl_ckpt_bad
	ldr  w9,[x25,#0x100]
	mov  w10,#0x5849
	movk w10,#0x5554,lsl #16
	cmp  w9,w10
	b.ne .rl_ckpt_bad
	add  x16,x25,#0x104
	ldr  x9,[x16]           /* log_off */
	str  x9,[x19,#24]
	add  x16,x25,#0x10c
	ldr  x9,[x16]           /* n */
	str  x9,[x19,#32]
	cbz  x9,.rl_ckpt_done
	/* load n snapshot records */
	mov  x22,#0
.rl_ckpt_loop:
	ldr  x9,[x19,#32]
	cmp  x22,x9
	b.hs .rl_ckpt_done
	mov  x0,x21
	add  x1,x25,#0x60
	mov  x2,#CKPT_REC
	bl   mac_read_exact
	cbnz x0,.rl_ckpt_done
	add  x16,x25,#0x91      /* slen u16 (odd: register-offset) */
	ldrh w9,[x16]
	cbz  w9,.rl_ck_apply
	mov  x0,x21
	add  x1,sp,#0x10       /* script scratch */
	mov  x2,x9
	bl   mac_read_exact
	cbnz x0,.rl_ckpt_done
.rl_ck_apply:
	mov  x0,x20
	add  x1,x25,#0x60      /* txid */
	ldr  w2,[x25,#0x80]    /* index */
	add  x16,x25,#0x84
	ldr  x3,[x16]          /* value */
	add  x16,x25,#0x8c
	ldr  w4,[x16]          /* height */
	ldrb w5,[x25,#0x90]    /* cb */
	add  x6,sp,#0x10       /* script */
	add  x16,x25,#0x91
	ldrh w7,[x16]          /* slen */
	bl   utxo_put
	cmp  x0,#2
	b.eq .rl_full
	add  x22,x22,#1
	b    .rl_ckpt_loop
.rl_ckpt_done:
	mov  x0,x21
	mov  x8,#SYS_close
	svc  #0
	b    .rl_replay
.rl_ckpt_bad:
	mov  x0,x21
	mov  x8,#SYS_close
	svc  #0
	str  xzr,[x19,#24]
	str  xzr,[x19,#32]
	b    .rl_replay
.rl_no_ckpt:
	str  xzr,[x19,#24]
	str  xzr,[x19,#32]
.rl_replay:
	ldr  x9,[x19,#24]
	str  x9,[x25,#0xa8]    /* consumed = ckpt_log_off */
	mov  x0,#AT_FDCWD
	adr  x1, logname
	mov  x2,#O_RDONLY
	mov  x3,#0
	mov  x8,#SYS_openat
	svc  #0
	cmp  x0,#0
	b.lt .rl_fail
	mov  x21,x0
	mov  x0,x21
	ldr  x1,[x19,#24]      /* ckpt_log_off */
	mov  x2,#0             /* SEEK_SET */
	mov  x8,#SYS_lseek
	svc  #0
	mov  x22,#0            /* replayed */
.rl_rep_loop:
	ldr  x9,[x25,#0xa8]
	cmp  x9,x23
	b.hs .rl_rep_done
	mov  x0,x21
	add  x1,x25,#0x60
	mov  x2,#8
	bl   mac_read_exact
	cbnz x0,.rl_rep_close
	ldr  x9,[x25,#0xa8]
	add  x9,x9,#8
	str  x9,[x25,#0xa8]
	ldrb w9,[x25,#0x64]    /* op */
	cmp  w9,#OP_PUSH
	b.eq .rl_rep_push
	cmp  w9,#OP_DEL
	b.eq .rl_rep_del
	b    .rl_rep_close
.rl_rep_push:
	mov  x0,x21
	add  x1,x25,#0x60
	mov  x2,#CKPT_REC
	bl   mac_read_exact
	cbnz x0,.rl_rep_close
	ldr  x9,[x25,#0xa8]
	add  x9,x9,#CKPT_REC
	str  x9,[x25,#0xa8]
	add  x16,x25,#0x91
	ldrh w9,[x16]           /* slen */
	cbz  w9,.rl_rep_apply
	mov  x0,x21
	add  x1,sp,#0x10
	mov  x2,x9
	bl   mac_read_exact
	cbnz x0,.rl_rep_close
.rl_rep_apply:
	mov  x0,x20
	add  x1,x25,#0x60
	ldr  w2,[x25,#0x80]
	add  x16,x25,#0x84
	ldr  x3,[x16]
	add  x16,x25,#0x8c
	ldr  w4,[x16]
	ldrb w5,[x25,#0x90]
	add  x6,sp,#0x10
	add  x16,x25,#0x91
	ldrh w7,[x16]
	bl   utxo_put
	cmp  x0,#2
	b.eq .rl_full
	ldr  x9,[x25,#0xa8]
	add  x16,x25,#0x91
	ldrh w10,[x16]
	add  x9,x9,x10
	str  x9,[x25,#0xa8]
	add  x22,x22,#1
	b    .rl_rep_loop
.rl_rep_del:
	mov  x0,x21
	add  x1,x25,#0x60
	mov  x2,#36
	bl   mac_read_exact
	cbnz x0,.rl_rep_close
	ldr  x9,[x25,#0xa8]
	add  x9,x9,#36
	str  x9,[x25,#0xa8]
	mov  x0,x20
	add  x1,x25,#0x60
	ldr  w2,[x25,#0x80]
	bl   utxo_del
	add  x22,x22,#1
	b    .rl_rep_loop
.rl_rep_close:
	mov  x0,x21
	mov  x8,#SYS_close
	svc  #0
	mov  x0,x22
	b    .rl_done
.rl_rep_done:
	b    .rl_rep_close
.rl_full:
	mov  x0,#-2
	b    .rl_done
.rl_fail:
	mov  x0,#-1
.rl_done:
	add  sp,sp,x26
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_store_reload,.-utxo_store_reload

/* ============================================================================
 * utxo_store_close(st=x0) -- fsync+close both (skip -1 fds)
 * ========================================================================== */
	.global utxo_store_close
	.type utxo_store_close,%function
utxo_store_close:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	mov  x19,x0
	ldr  x0,[x19]
	cmp  x0,#-1
	b.eq 1f
	/* land buffered WAL bytes before the final fsync */
	mov  x0,x19
	bl   utxo_store_wal_drain
	ldr  x0,[x19]
	bl   mac_fsync
	ldr  x0,[x19]
	mov  x8,#SYS_close
	svc  #0
1:
	ldr  x0,[x19,#8]
	cmp  x0,#-1
	b.eq 2f
	bl   mac_fsync
	ldr  x0,[x19,#8]
	mov  x8,#SYS_close
	svc  #0
2:
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_store_close,.-utxo_store_close

	.section .note.GNU-stack,"",%progbits
