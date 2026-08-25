/* bitcoin_undo.S -- AArch64 port of asm/bitcoin_undo.asm.
 * Per-block undo-data store: "undo_<height>.dat" append-only records for
 * reorg rollback. Same on-disk format as x86. Record: txid[32]|index4|value8|
 * utxo_height4|is_coinbase1|slen2|script (51-byte hdr + script).
 * Raw syscalls (aarch64): openat(AT_FDCWD=-100)=56, unlinkat=35, read=63,
 * write=64, close=57.
 */
	.section .text
	.balign 4

O_APPEND_CREAT_WRONLY = 0x441
O_RDONLY = 0
MODE_0644 = 0644
UNDO_MAX_SCRIPT = 10000
HDR_BYTES = 51
REC_INDEX = 32
REC_VALUE = 40
REC_HEIGHT = 48
REC_CB = 52
REC_SLEN = 54
REC_SCRIPT = 56
REC_STRIDE = 10056
AT_FDCWD = -100
SYS_read = 63
SYS_write = 64
SYS_close = 57
SYS_openat = 56
SYS_unlinkat = 35

	.bss
	.balign 16
replay_script:
	.space UNDO_MAX_SCRIPT

	.section .text

/* ---------- undo_path_build(out=x0, height=x1) -- "undo_<h>.dat" internal ---------- */
undo_path_build:
	mov  w2, #0x6f64
	movk w2, #0x6e75, lsl #16   /* 0x6e756f64 = "undo" LE */
	str  w2, [x0]
	mov  w2, #0x5f
	strb w2, [x0,#4]
	add  x3, x0, #5             /* cursor */
	mov  x4, x1
	tbz  x4, #63, .pb_abs
	mov  w2, #0x2d              /* '-' */
	strb w2, [x3]
	add  x3, x3, #1
	neg  x4, x4
.pb_abs:
	sub  sp, sp, #32            /* digit scratch */
	mov  x5, sp
	mov  x2, #0
.pb_dig:
	mov  x6, #10
	udiv x7, x4, x6
	msub x8, x7, x6, x4         /* digit = x4 % 10 */
	add  w8, w8, #0x30
	strb w8, [x5, x2]
	add  x2, x2, #1
	mov  x4, x7
	cbnz x4, .pb_dig
.pb_emit:
	sub  x2, x2, #1
	ldrb w8, [x5, x2]
	strb w8, [x3]
	add  x3, x3, #1
	cbnz x2, .pb_emit
	add  sp, sp, #32
	mov  w8, #0x7461
	movk w8, #0x642e, lsl #16   /* ".dat" LE */
	str  w8, [x3]
	strb wzr, [x3,#4]
	ret

/* ============================================================================
 * undo_append_record(height, txid, index, value, utxo_height, cb, script, slen)
 * x0=height x1=txid x2=index(w) x3=value x4=utxo_height(w) x5=cb(w) x6=script
 * x7=slen(u16) -> 1/-1
 * x19=height x20=txid x21=index x22=value x23=utxo_height x24=cb x25=script
 * x26=slen x27=fd. path@[sp+0], hdr@[sp+0x70].
 * ========================================================================== */
	.global undo_append_record
	.type undo_append_record,%function
undo_append_record:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp,sp,#0xb0
	mov  x19,x0
	mov  x20,x1
	uxtw x21,w2
	mov  x22,x3
	uxtw x23,w4
	uxtw x24,w5
	mov  x25,x6
	uxtw x26,w7
	/* path build */
	mov  x0,sp
	mov  x1,x19
	bl   undo_path_build
	/* openat */
	mov  x0,#AT_FDCWD
	mov  x1,sp
	mov  x2,#O_APPEND_CREAT_WRONLY
	mov  x3,#MODE_0644
	mov  x8,#SYS_openat
	svc  #0
	cmp  x0,#0
	b.lt .ar_fail
	mov  x27,x0            /* fd */
	/* build hdr[51] at [sp,#0x70] */
	add  x1,sp,#0x70
	ldr  x2,[x20]
	str  x2,[x1]
	ldr  x2,[x20,#8]
	str  x2,[x1,#8]
	ldr  x2,[x20,#16]
	str  x2,[x1,#16]
	ldr  x2,[x20,#24]
	str  x2,[x1,#24]
	str  w21,[x1,#32]      /* index */
	str  x22,[x1,#36]      /* value */
	str  w23,[x1,#44]      /* utxo_height */
	strb w24,[x1,#48]      /* is_coinbase */
	strh w26,[x1,#49]      /* slen */
	/* write hdr(51) */
	mov  x0,x27
	add  x1,sp,#0x70
	mov  x2,#HDR_BYTES
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,#HDR_BYTES
	b.ne .ar_fail_close
	cbz  x26,.ar_close
	mov  x0,x27
	mov  x1,x25
	mov  x2,x26
	mov  x8,#SYS_write
	svc  #0
	cmp  x0,x26
	b.ne .ar_fail_close
.ar_close:
	mov  x0,x27
	mov  x8,#SYS_close
	svc  #0
	mov  x0,#1
	b    .ar_out
.ar_fail_close:
	mov  x0,x27
	mov  x8,#SYS_close
	svc  #0
.ar_fail:
	mov  x0,#-1
.ar_out:
	add  sp,sp,#0xb0
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size undo_append_record,.-undo_append_record

/* ============================================================================
 * undo_load(height=x0, out=x1, max_recs=x2) -> n / -1 (missing file -> 0)
 * x19=height x20=out x21=max_recs x22=fd x23=n. path@[sp] hdr@[sp+0x70].
 * ========================================================================== */
	.global undo_load
	.type undo_load,%function
undo_load:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	sub  sp,sp,#0xb0
	mov  x19,x0             /* height */
	mov  x20,x1             /* out cursor */
	mov  x21,x2             /* max_recs */
	mov  x23,#0             /* n */
	mov  x0,sp
	mov  x1,x19
	bl   undo_path_build
	mov  x0,#AT_FDCWD
	mov  x1,sp
	mov  x2,#O_RDONLY
	mov  x3,#0
	mov  x8,#SYS_openat
	svc  #0
	cmp  x0,#0
	b.lt .ld_absent         /* missing -> 0 */
	mov  x22,x0
.ld_loop:
	cmp  x23,x21
	b.hs .ld_done
	mov  x0,x22
	add  x1,sp,#0x70
	mov  x2,#HDR_BYTES
	mov  x8,#SYS_read
	svc  #0
	cbz  x0,.ld_done        /* clean EOF */
	mov  x2,#HDR_BYTES
	cmp  x0,x2
	b.ne .ld_bad
	/* copy hdr fields into out[n] */
	ldr  x2,[sp,#0x70]
	str  x2,[x20]
	ldr  x2,[sp,#0x78]
	str  x2,[x20,#8]
	ldr  x2,[sp,#0x80]
	str  x2,[x20,#16]
	ldr  x2,[sp,#0x88]
	str  x2,[x20,#24]
	ldr  w2,[sp,#0x90]      /* index @+32 */
	str  w2,[x20,#REC_INDEX]
	ldr  x2,[sp,#0x94]      /* value @+36 */
	str  x2,[x20,#REC_VALUE]
	ldr  w2,[sp,#0x9c]      /* height @+44 */
	str  w2,[x20,#REC_HEIGHT]
	ldrb w2,[sp,#0xa0]      /* cb @+48 */
	strb w2,[x20,#REC_CB]
	ldrh w2,[sp,#0xa1]      /* slen @+49 */
	strh w2,[x20,#REC_SLEN]
	mov  w9,#0x2710           /* UNDO_MAX_SCRIPT 10000 */
	cmp  w2,w9
	b.hi .ld_bad
	mov  x24, x2            /* slen */
	cbz  x24,.ld_next
	mov  x0,x22
	add  x1,x20,#REC_SCRIPT
	mov  x2,x24
	mov  x8,#SYS_read
	svc  #0
	cmp  x0,x24
	b.ne .ld_bad
.ld_next:
	add  x23,x23,#1
	mov  x9,#0x2748           /* REC_STRIDE 10056 */
	add  x20,x20,x9
	b    .ld_loop
.ld_bad:
	mov  x0,x22
	mov  x8,#SYS_close
	svc  #0
	mov  x0,#-1
	b    .ld_out
.ld_done:
	mov  x0,x22
	mov  x8,#SYS_close
	svc  #0
.ld_absent:
	mov  x0,x23
.ld_out:
	add  sp,sp,#0xb0
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size undo_load,.-undo_load

/* ============================================================================
 * undo_replay_impl(height=x0, cb=x1, ctx=x2, tolerant=x3, torn=x4) -> n/-1
 * x19=height x20=cb x21=ctx x22=fd x23=n x24=slen x27=tolerant x28=torn.
 * path@[sp] hdr@[sp+0x70]. script read into replay_script (.bss).
 * ========================================================================== */
undo_replay_impl:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp,sp,#0xb0
	mov  x19,x0
	mov  x20,x1
	mov  x21,x2
	uxtw x27,w3            /* tolerant */
	mov  x28,x4            /* torn */
	mov  x23,#0            /* n */
	mov  x0,sp
	mov  x1,x19
	bl   undo_path_build
	mov  x0,#AT_FDCWD
	mov  x1,sp
	mov  x2,#O_RDONLY
	mov  x3,#0
	mov  x8,#SYS_openat
	svc  #0
	cmp  x0,#0
	b.lt .rp_absent
	mov  x22,x0
.rp_loop:
	mov  x0,x22
	add  x1,sp,#0x70
	mov  x2,#HDR_BYTES
	mov  x8,#SYS_read
	svc  #0
	cbz  x0,.rp_done
	mov  x2,#HDR_BYTES
	cmp  x0,x2
	b.eq .rp_have_hdr
	/* short header: tolerant -> torn tail */
	cbz  w27,.rp_bad
	cmp  x0,#0
	b.lt .rp_bad
	bl   .rp_mark_torn
	b    .rp_done
.rp_have_hdr:
	ldrh w24,[sp,#0xa1]    /* slen @+49 */
	mov  w9,#0x2710           /* UNDO_MAX_SCRIPT 10000 */
	cmp  w24,w9
	b.hi .rp_bad
	cbz  w24,.rp_invoke
	mov  x0,x22
	adrp x1, replay_script
	add  x1,x1,:lo12:replay_script
	mov  x2,x24
	mov  x8,#SYS_read
	svc  #0
	cmp  x0,x24
	b.eq .rp_invoke
	cbz  w27,.rp_bad
	cmp  x0,#0
	b.lt .rp_bad
	bl   .rp_mark_torn
	b    .rp_done
.rp_invoke:
	cbz  x20,.rp_count
	mov  x0,x21            /* ctx */
	add  x1,sp,#0x70       /* txid */
	ldr  w2,[sp,#0x90]     /* index */
	ldr  x3,[sp,#0x94]     /* value */
	ldr  w4,[sp,#0x9c]     /* utxo_height */
	ldrb w5,[sp,#0xa0]     /* is_coinbase */
	adrp x6, replay_script
	add  x6,x6,:lo12:replay_script
	mov  x7,x24            /* slen */
	blr  x20
	cbz  x0,.rp_bad        /* cb abort -> error */
.rp_count:
	add  x23,x23,#1
	b    .rp_loop
.rp_mark_torn:
	cbz  x28,.rp_mt_done
	mov  w9,#1
	str  w9,[x28]
.rp_mt_done:
	ret
.rp_bad:
	mov  x0,x22
	mov  x8,#SYS_close
	svc  #0
	mov  x0,#-1
	b    .rp_out
.rp_done:
	mov  x0,x22
	mov  x8,#SYS_close
	svc  #0
.rp_absent:
	mov  x0,x23
.rp_out:
	add  sp,sp,#0xb0
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size undo_replay_impl,.-undo_replay_impl

/* undo_replay(height, cb, ctx) -> strict replay (torn -> -1) */
	.global undo_replay
	.type undo_replay,%function
undo_replay:
	mov  x3,#0             /* tolerant = 0 */
	mov  x4,#0             /* torn = NULL */
	b    undo_replay_impl
	.size undo_replay,.-undo_replay

/* undo_replay_tolerant(height, cb, ctx, torn) */
	.global undo_replay_tolerant
	.type undo_replay_tolerant,%function
undo_replay_tolerant:
	cbz  x3,.rp_t_go
	mov  w9,#0
	str  w9,[x3]           /* *torn = 0 */
.rp_t_go:
	mov  x4,x3             /* torn */
	mov  x3,#1             /* tolerant = 1 */
	b    undo_replay_impl
	.size undo_replay_tolerant,.-undo_replay_tolerant

/* ============================================================================
 * undo_discard(height=x0) -> 1 freed / 0 nothing  (unlinkat)
 * ========================================================================== */
	.global undo_discard
	.type undo_discard,%function
undo_discard:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	sub  sp,sp,#0x50
	mov  x9,x0
	mov  x0,sp
	mov  x1,x9
	bl   undo_path_build
	mov  x0,#AT_FDCWD
	mov  x1,sp
	mov  x2,#0
	mov  x8,#SYS_unlinkat
	svc  #0
	cmp  x0,#0
	cset x0, eq            /* 1 iff unlink returned 0 */
	add  sp,sp,#0x50
	ldp  x29,x30,[sp],#16
	ret
	.size undo_discard,.-undo_discard

/* ============================================================================
 * undo_prune_from(from=x0, tip=x1, window=x2, max_scan=x3) -> cursor
 * ========================================================================== */
	.global undo_prune_from
	.type undo_prune_from,%function
undo_prune_from:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	sub  sp,sp,#0x90
	mov  x19,x0             /* from (also fallback result) */
	/* bail: tip<0 || window<=0 || max_scan<=0 -> return from */
	tbz  x1,#63,.pf_c0
	b    .pf_ret_from
.pf_c0:
	cmp  x1,#0
	b.le .pf_ret_from
	cmp  x2,#0
	b.le .pf_ret_from
	cmp  x3,#0
	b.le .pf_ret_from
	/* from = max(from,0) */
	mov  x20,x19
	tbz  x20,#63,.pf_kf
	mov  x20,#0
.pf_kf:
	/* keep_from = max(tip - window + 1, 0) */
	mov  x9,x1
	sub  x9,x9,x2
	add  x9,x9,#1
	tbz  x9,#63,.pf_kf2
	mov  x9,#0
.pf_kf2:
	/* end = min(from+max_scan, keep_from) */
	add  x21,x20,x3
	cmp  x21,x9
	b.le .pf_sweep
	mov  x21,x9
.pf_sweep:
	cmp  x20,x21
	b.ge .pf_fin
	mov  x0,sp
	mov  x1,x20
	bl   undo_path_build
	mov  x0,#AT_FDCWD
	mov  x1,sp
	mov  x2,#0
	mov  x8,#SYS_unlinkat
	svc  #0                   /* result ignored */
	add  x20,x20,#1
	b    .pf_sweep
.pf_fin:
	/* return end > from ? end : from */
	cmp  x21,x19
	b.gt .pf_ret_end
.pf_ret_from:
	mov  x0,x19
	b    .pf_ret
.pf_ret_end:
	mov  x0,x21
.pf_ret:
	add  sp,sp,#0x90
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size undo_prune_from,.-undo_prune_from

/* ============================================================================
 * undo_prune(tip=x0, window=x1) -> removed
 * ========================================================================== */
	.global undo_prune
	.type undo_prune,%function
undo_prune:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	sub  sp,sp,#0x90
	mov  x21,#0             /* removed */
	tbz  x0,#63,.prc0
	b    .pr_fin
.prc0:
	cmp  x1,#0
	b.le .pr_fin
	/* keep_from = max(tip - window + 1, 0) */
	mov  x9,x0
	sub  x9,x9,x1
	add  x9,x9,#1
	tbz  x9,#63,.pr_go
	mov  x9,#0
.pr_go:
	mov  x20,#0             /* h */
.pr_loop:
	cmp  x20,x9
	b.ge .pr_fin
	mov  x0,sp
	mov  x1,x20
	bl   undo_path_build
	mov  x0,#AT_FDCWD
	mov  x1,sp
	mov  x2,#0
	mov  x8,#SYS_unlinkat
	svc  #0
	cbz  x0,.pr_inc
	b    .pr_next
.pr_inc:
	add  x21,x21,#1
.pr_next:
	add  x20,x20,#1
	b    .pr_loop
.pr_fin:
	mov  x0,x21
	add  sp,sp,#0x90
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size undo_prune,.-undo_prune

	.section .note.GNU-stack,"",%progbits
