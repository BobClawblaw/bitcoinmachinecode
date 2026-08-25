/* bitcoin_utxo.S -- AArch64 port of asm/bitcoin_utxo.asm (in-memory UTXO set).
 * Open-addressing hash table + bump blob. Same exported symbols + exact ABI.
 * Structure u:
 *   +0  qword n, +8 qword mask, +16 blob, +24 blob_cap, +32 fill
 *   +40 slots, 48B each: [+0 blob_off][+8 txid[32]][+40 u32 index][+44 pad]
 *      (empty slot marker: index == 0xFFFFFFFF)
 * Blob record: [+0 u64 value][+8 packed height(low32)|is_coinbase(byte32)]
 *              [+16 u64 script_len][+24 script]
 * Exports:
 *   utxo_struct_size(slots)->48*slots+48
 *   utxo_init(u,slots,blob,cap); utxo_put(u,txid,index,value,height,cb,script,slen)->1/0/2
 *   utxo_get(u,txid,index,&v,&h,&cb,&script,&slen)->1/0
 *   utxo_del(u,txid,index)->1/0 ; utxo_count(u)->n
 *   utxo_walk_live(u,cb,ctx)->emitted
 *   utxo_prefetch (hint, no-op)
 */
	.section .text
	.balign 4

/* ---------- utxo_hash(x0=txid,x1=index,x2=mask)->x0=byte offset(40+idx*48) ---------- */
	.global utxo_hash
	.type utxo_hash,%function
utxo_hash:
	mov  w9, #0x9dc5
	movk w9, #0x811c, lsl #16      /* FNV offset basis 0x811c9dc5 */
	mov  w10, #0x0193
	movk w10, #0x0100, lsl #16     /* FNV prime 16777619 = 0x01000193 */
	mov  x11, #0
.hl:
	cmp  x11, #8
	b.hs .hdone
	ldrb w12, [x0, x11]
	eor  w9, w9, w12
	mul  w9, w9, w10
	add  x11, x11, #1
	b    .hl
.hdone:
	/* fold index in */
	uxtw x13, w9
	eor  x13, x13, x1
	and  x13, x13, x2
	mov  x14, #48
	mul  x13, x13, x14
	add  x0, x13, #40
	ret
	.size utxo_hash,.-utxo_hash

/* ---------- utxo_struct_size(slots) -> 48*slots+48 ---------- */
	.global utxo_struct_size
	.type utxo_struct_size,%function
utxo_struct_size:
	mov  x9, #48
	mul  x0, x0, x9
	add  x0, x0, #48
	ret
	.size utxo_struct_size,.-utxo_struct_size

/* ---------- utxo_init(u=x0, slots=x1, blob=x2, cap=x3) ---------- */
	.global utxo_init
	.type utxo_init,%function
utxo_init:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	mov  x19,x0            /* u */
	mov  x20,x1            /* slots */
	mov  x21,x2            /* blob */
	mov  x22,x3            /* cap */
	str  xzr,[x19]         /* n=0 */
	sub  x20,x20,#1
	str  x20,[x19,#8]      /* mask = slots-1 */
	str  x21,[x19,#16]     /* blob */
	str  x22,[x19,#24]     /* cap */
	str  xzr,[x19,#32]     /* fill=0 */
	add  x9, x20, #1       /* slot count (caller-saved only) */
	add  x10, x19, #40     /* slot base */
.el:
	cbz  x9, .edone
	mov  x11, #-1
	str  w11, [x10, #40]   /* index field = 0xFFFFFFFF (empty) */
	add  x10, x10, #48
	sub  x9, x9, #1
	b    .el
.edone:
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_init,.-utxo_init

/* ---------- utxo_put(u,txid,index,value,height,cb,script,slen)->1/0/2 ---------- */
	.global utxo_put
	.type utxo_put,%function
utxo_put:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp,sp,#0x30
	mov  x19,x0            /* u */
	mov  x20,x1            /* txid */
	mov  x21,x2            /* index */
	mov  x22,x3            /* value */
	uxtw x9, w4
	str  x9,[sp,#0x00]     /* height (ze) */
	uxtw x9, w5
	str  x9,[sp,#0x08]     /* is_coinbase (ze) */
	str  x6,[sp,#0x10]     /* script */
	str  x7,[sp,#0x18]     /* slen */
	/* find home slot */
	mov  x0,x20
	mov  x1,x21
	ldr  x2,[x19,#8]
	bl   utxo_hash         /* x0 = byte offset relative to u */
	mov  x23,x0            /* slot offset */
	mov  x24,#0            /* probe count */
.probe:
	add  x9,x19,x23        /* slot base */
	ldr  w10,[x9,#40]      /* index field */
	cmn  w10,#1            /* == 0xFFFFFFFF ? */
	b.eq .found_empty
	cmp  w10,w21
	b.ne .next
	/* compare txid(32) */
	add  x0,x9,#8
	mov  x1,x20
	mov  x2,#32
	bl   memcmp_asm
	cbz  x0,.dup
.next:
	add  x24,x24,#1
	ldr  x9,[x19,#8]
	add  x9,x9,#1          /* slot count */
	cmp  x24,x9
	b.hs .full
	add  x23,x23,#48
	/* region_end_offset = 40 + slot_count*48 */
	ldr  x9,[x19,#8]
	add  x9,x9,#1
	mov  x10,#48
	mul  x9,x9,x10
	add  x9,x9,#40
	cmp  x23,x9
	b.lo .probe
	mov  x23,#40           /* wrap to first slot */
	b    .probe
.found_empty:
	/* write slot */
	add  x9,x19,x23
	str  w21,[x9,#40]      /* index */
	add  x0,x9,#8          /* txid dst */
	mov  x1,x20            /* txid src */
	mov  x2,#32
	str  x23,[sp,#0x20]
	bl   memcpy_asm
	ldr  x23,[sp,#0x20]
	/* allocate blob record */
	ldr  x8,[x19,#32]      /* fill */
	ldr  x9,[sp,#0x18]     /* slen */
	add  x9,x9,#24
	add  x10,x8,x9
	ldr  x11,[x19,#24]     /* blob_cap */
	cmp  x10,x11
	b.hi .full
	/* record base = blob + fill */
	ldr  x11,[x19,#16]
	add  x11,x11,x8
	add  x9,x19,x23
	str  x8,[x9]           /* slot.blob_off = fill */
	str  x22,[x11]         /* value */
	ldr  x9,[sp,#0x00]     /* height */
	ldr  x10,[sp,#0x08]    /* is_coinbase */
	lsl  x10,x10,#32
	orr  x9,x9,x10
	str  x9,[x11,#8]       /* packed height|is_coinbase */
	ldr  x9,[sp,#0x18]
	str  x9,[x11,#16]      /* script_len */
	add  x0,x11,#24        /* script dst */
	ldr  x1,[sp,#0x10]     /* script src */
	mov  x2,x9             /* slen */
	str  x23,[sp,#0x20]
	bl   memcpy_asm
	ldr  x23,[sp,#0x20]
	/* fill += 24+slen ; n++ */
	ldr  x8,[sp,#0x18]
	add  x8,x8,#24
	ldr  x9,[x19,#32]
	add  x9,x9,x8
	str  x9,[x19,#32]
	ldr  x9,[x19]
	add  x9,x9,#1
	str  x9,[x19]
	mov  w0,#1
	b    .done
.dup:
	mov  w0,#0
	b    .done
.full:
	mov  w0,#2
.done:
	add  sp,sp,#0x30
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_put,.-utxo_put

/* ---------- utxo_get(u,txid,index,&v,&h,&cb,&script,&slen)->1/0 ---------- */
	.global utxo_get
	.type utxo_get,%function
utxo_get:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp,sp,#0x40
	mov  x19,x0            /* u */
	mov  x20,x1            /* txid */
	mov  x21,x2            /* index */
	str  x3,[sp,#0x00]     /* &value */
	str  x4,[sp,#0x08]     /* &height */
	str  x5,[sp,#0x10]     /* &is_coinbase */
	str  x6,[sp,#0x18]     /* &script */
	str  x7,[sp,#0x20]     /* &slen */
	mov  x0,x20
	mov  x1,x21
	ldr  x2,[x19,#8]
	bl   utxo_hash
	mov  x23,x0            /* slot offset (probe) */
	mov  x24,x0            /* home slot (probe bound) */
.pr:
	add  x9,x19,x23
	ldr  w10,[x9,#40]
	cmn  w10,#1
	b.eq .miss
	cmp  w10,w21
	b.ne .pn
	add  x0,x9,#8
	mov  x1,x20
	mov  x2,#32
	bl   memcmp_asm
	cbz  x0,.hit
.pn:
	add  x23,x23,#48
	ldr  x9,[x19,#8]
	add  x9,x9,#1
	mov  x10,#48
	mul  x9,x9,x10
	add  x9,x9,#40
	cmp  x23,x9
	b.lo .pc
	mov  x23,#40
.pc:
	cmp  x23,x24
	b.eq .miss
	b    .pr
.hit:
	add  x9,x19,x23        /* slot */
	ldr  x10,[x9]          /* blob_off */
	ldr  x11,[x19,#16]     /* blob base */
	add  x11,x11,x10       /* record */
	/* *value */
	ldr  x12,[x11]
	ldr  x5,[sp,#0x00]
	str  x12,[x5]
	/* packed height/is_coinbase at +8 */
	ldr  x9,[x11,#8]
	ldr  x6,[sp,#0x08]
	uxtw x10, w9
	str  x10,[x6]          /* *height = packed low32 */
	ldr  x6,[sp,#0x10]
	lsr  x10,x9,#32
	and  x10,x10,#0xFF
	str  x10,[x6]          /* *is_coinbase */
	/* *script = record+24 */
	ldr  x6,[sp,#0x18]
	add  x12,x11,#24
	str  x12,[x6]
	/* *slen = record+16 */
	ldr  x6,[sp,#0x20]
	ldr  x12,[x11,#16]
	str  x12,[x6]
	mov  w0,#1
	b    .done2
.miss:
	mov  w0,#0
.done2:
	add  sp,sp,#0x40
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_get,.-utxo_get

/* ---------- utxo_del(u,txid,index)->1/0 (backward-shift deletion) ---------- */
	.global utxo_del
	.type utxo_del,%function
utxo_del:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp,sp,#0x20
	mov  x19,x0            /* u */
	mov  x20,x1            /* txid */
	mov  x21,x2            /* index */
	ldr  x27,[x19,#8]      /* mask (persists) */
	mov  x0,x20
	mov  x1,x21
	mov  x2,x27
	bl   utxo_hash
	mov  x23,x0            /* slot offset */
	str  x23,[sp,#0x00]    /* home slot bound */
.dprobe:
	add  x9,x19,x23
	ldr  w10,[x9,#40]
	cmn  w10,#1
	b.eq .dmiss
	cmp  w10,w21
	b.ne .dpn
	add  x0,x9,#8
	mov  x1,x20
	mov  x2,#32
	bl   memcmp_asm
	cbz  x0,.dhit
.dpn:
	add  x23,x23,#48
	ldr  x9,[x19,#8]
	add  x9,x9,#1
	mov  x10,#48
	mul  x9,x9,x10
	add  x9,x9,#40
	cmp  x23,x9
	b.lo .dpc
	mov  x23,#40
.dpc:
	ldr  x9,[sp,#0x00]
	cmp  x23,x9
	b.eq .dmiss
	b    .dprobe
.dhit:
	/* gap index i = (byte_off - 40) / 48 */
	sub  x9,x23,#40
	mov  x10,#48
	udiv x25,x9,x10        /* x25 = i */
	add  x9,x19,x23
	mov  w11,#0xFFFFFFFF
	str  w11,[x9,#40]      /* open the gap */
	ldr  x9,[x19]
	sub  x9,x9,#1
	str  x9,[x19]          /* n-- */
	mov  x26,x25           /* j := i */
.bs:
	add  x26,x26,#1
	and  x26,x26,x27       /* j = (j+1)&mask */
	mov  x9,x26
	mov  x10,#48
	mul  x9,x9,x10
	add  x9,x9,#40
	add  x22,x19,x9        /* &slot[j] */
	ldr  w10,[x22,#40]     /* slot[j].index */
	cmn  w10,#1
	b.eq .bs_done          /* empty: done */
	/* compute k = home index of slot[j] */
	add  x0,x22,#8         /* slot[j].txid */
	uxtw x1,w10            /* slot[j].index */
	mov  x2,x27            /* mask */
	/* save j/i across call in callee-saved x24, keep x26 as j and x25 as i
	 * (x26/x25 are caller-saved across bl? NO - x19-x28 are callee-saved
	 * but bl to utxo_hash clobbers x0-x17 only, so x25/x26 survive). */
	bl   utxo_hash         /* x0 = byte offset of home */
	sub  x10,x0,#40
	mov  x9,#48
	udiv x24,x10,x9        /* k */
	/* d_i = (i - k)&mask  ; d_j = (j - k)&mask */
	sub  x10,x25,x24
	and  x10,x10,x27
	sub  x11,x26,x24
	and  x11,x11,x27
	cmp  x10,x11
	b.hs .bs               /* not safe: keep scanning */
	/* move slot[j] -> slot[i] */
	mov  x9,x25
	mov  x10,#48
	mul  x9,x9,x10
	add  x9,x9,#40
	add  x9,x19,x9         /* &slot[i] */
	mov  x0,x9
	mov  x1,x22            /* &slot[j] */
	mov  x2,#48
	bl   memcpy_asm
	mov  w11,#0xFFFFFFFF
	str  w11,[x22,#40]     /* old slot[j] empty */
	mov  x25,x26           /* i := j */
	b    .bs
.bs_done:
	mov  w0,#1
	b    .ddone
.dmiss:
	mov  w0,#0
.ddone:
	add  sp,sp,#0x20
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_del,.-utxo_del

/* ---------- utxo_count(u)->n ---------- */
	.global utxo_count
	.type utxo_count,%function
utxo_count:
	ldr  x0,[x0]
	ret
	.size utxo_count,.-utxo_count

/* ---------- memcmp_asm(a,b,n)->0 equal / nonzero differ (local) ---------- */
memcmp_asm:
.ml:
	cbz  x2, .meq
	ldrb w9,[x0]
	ldrb w10,[x1]
	cmp  w9,w10
	b.ne .mne
	add  x0,x0,#1
	add  x1,x1,#1
	sub  x2,x2,#1
	b    .ml
.meq:
	mov  w0,#0
	ret
.mne:
	mov  w0,#1
	ret

/* ---------- memcpy_asm(dst,src,n) (local) ---------- */
memcpy_asm:
.yl:
	cbz  x2, .ydone
	ldrb w9,[x1]
	strb w9,[x0]
	add  x0,x0,#1
	add  x1,x1,#1
	sub  x2,x2,#1
	b    .yl
.ydone:
	ret

/* ---------- utxo_prefetch (hint only: no-op) ---------- */
	.global utxo_prefetch
	.type utxo_prefetch,%function
utxo_prefetch:
	ret
	.size utxo_prefetch,.-utxo_prefetch

/* ---------- utxo_walk_live(u=x0,cb=x1,ctx=x2)->emitted ---------- */
	.global utxo_walk_live
	.type utxo_walk_live,%function
utxo_walk_live:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp,sp,#0x40       /* key36 at [sp] (36B) + cb/ctx */
	mov  x19,x0            /* u */
	str  x1,[sp,#0x30]     /* cb */
	str  x2,[sp,#0x38]     /* ctx */
	ldr  x20,[x19,#8]      /* mask */
	add  x20,x20,#1        /* slot count */
	ldr  x21,[x19,#16]     /* blob base */
	mov  x22,#0            /* slot index */
	mov  x23,#0            /* emitted count */
.wl:
	cmp  x22,x20
	b.hs .wldone
	mov  x9,x22
	mov  x10,#48
	mul  x9,x9,x10
	add  x9,x9,#40
	add  x9,x19,x9         /* slot base */
	ldr  w10,[x9,#40]
	cmn  w10,#1
	b.eq .wln
	add  x23,x23,#1
	ldr  x10,[sp,#0x30]    /* cb */
	cbz  x10,.wln          /* counting only */
	/* key36 = txid(32) || index(4) on frame */
	add  x11,sp,#0
	ldr  x12,[x9,#8]
	str  x12,[x11]
	ldr  x12,[x9,#16]
	str  x12,[x11,#8]
	ldr  x12,[x9,#24]
	str  x12,[x11,#16]
	ldr  x12,[x9,#32]
	str  x12,[x11,#24]
	ldr  w10,[x9,#40]      /* re-load index field (x10 was clobbered by cb load) */
	str  w10,[x11,#32]
	/* blob record */
	ldr  x12,[x9]          /* blob_off */
	add  x12,x12,x21       /* record */
	ldr  x2,[x12]          /* value */
	ldr  x13,[x12,#8]      /* packed */
	lsr  x14,x13,#32
	and  x14,x14,#0xFF     /* is_coinbase */
	uxtw x13,w13           /* height low32 */
	lsl  x13,x13,#1
	orr  x13,x13,x14       /* code = (height<<1)|is_coinbase */
	ldr  x15,[x12,#16]     /* slen */
	add  x14,x12,#24       /* script */
	ldr  x0,[sp,#0x38]      /* ctx */
	add  x1, sp, #0        /* key36 */
	mov  x3, x13           /* code */
	mov  x4, x14           /* script */
	mov  x5, x15           /* slen */
	ldr  x16,[sp,#0x30]
	blr  x16
.wln:
	add  x22,x22,#1
	b    .wl
.wldone:
	mov  x0,x23
	add  sp,sp,#0x40
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_walk_live,.-utxo_walk_live

	.section .note.GNU-stack,"",%progbits
