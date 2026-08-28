/* ============================================================================
 * bitcoin_serve.S -- AArch64 (ARMv8-A) port of asm/bitcoin_serve.asm
 * The server half of the node's P2P message handling. node_serve_loop reads a
 * version/verack-acknowledged peer stream and answers each command using the
 * other assembly primitives (address book, hash index, store, mempool, BIP152).
 *
 *   long node_serve_loop(int fd, int lfd, void* st, void* ht_idx,
 *                        void* out_buf, long out_cap) -> # blocks served
 *   long node_announce_tip(int fd, void* st, void* ht_idx, long use_headers)
 *
 * All per-connection / per-command state lives in module-local .bss (as in the
 * x86 original, which keeps loop state in statics, immune to deep callees'
 * register clobbering and stack spills). AAPCS64 applies at every boundary.
 * ========================================================================== */

	.extern p2p_read
	.extern p2p_write
	.extern amr_init
	.extern amr_count
	.extern amr_get_i
	.extern p2p_addr_v1
	.extern idx_get
	.extern idx_put
	.extern store_append
	.extern idxscan_append_locked
	.extern store_validates_prevhash
	.extern cons_verify
	.extern node_serve_block
	.extern node_serve_block_by_hash
	.extern node_log_event
	.extern block_hash
	.extern mpool_init
	.extern mpool_get
	.extern tx_dispatch_init
	.extern tx_policy_init
	.extern serve_idx_topup
	.extern serve_cfilters
	.extern tx_accept_validate
	.extern log_block_stored_inbound
	.extern tx_txid
	.extern bip152_shortid
	.extern block_tx_at
	.extern block_txcount
	.extern p2p_blocktxn_build
	.extern cmpctblock_build
	.extern mp_ext_area
	.extern mp_ext_blob
	.extern mp_ext_slots
	.extern mp_ext_blobcap
	.extern mp_ext_inited

	.text

	.equ SERVE_TXID_CAP, 80000
	.equ SERVE_TXID_CAP_LO, 0x3880    /* 80000 = 0x13880 */
	.equ SERVE_TXID_CAP_HI, 0x1
	.equ MP_SLOTS, 1024

/* ---- module-local .bss state (all zero-initialised; mirrors the x86 .data/.bss) ---- */
	.bss
	.align 4
pl_buf:      .zero (8<<20)            /* receive buffer */
sb_buf:      .zero (8<<20)            /* single block buffer */
hp_buf:      .zero (2000*81+8)        /* headers page buffer */
serve_txid_scratch: .zero SERVE_TXID_CAP*32
bt_buf:      .zero (8<<20)            /* compact-block output buffer */
nf_buf:      .zero (1 + 50*36)        /* notfound payload: count byte + 36B entries */
s_cmpct_v2:  .zero 8
s_cmpct_hb:  .zero 8
s_cmpct_nonce: .zero 8
s_shdr:      .zero 8
s_peerfee:   .zero 8
s_feesent:   .zero 1
s_lasttip:   .zero 8
s_idxn:      .zero 8
s_idxbuf:    .zero (512*2)
s_diffshift: .zero 8
s_blen_spill: .zero 8
s_txptr:     .zero 8
s_txlen:     .zero 8
s_j:         .zero 8
mp_area:     .zero (40 + 1024*48 + 8)
mp_blob:     .zero (2<<20)
mp_initdone: .zero 1
mp_cur:      .zero 8
tx_dv_initdone: .zero 1
tx_dv_ok:    .zero 1
amr_ab:      .zero 64
ah_buf:      .zero (1000*30+8)
src_buf:     .zero (1000*18)
s_plen:      .zero 8
s_fh:        .zero 8
s_cmd:       .zero 16
s_cnt:       .zero 8
s_ptr:       .zero 8
s_nf:        .zero 8                    /* notfound entries accumulated for THIS getdata */
s_p:         .zero 8
s_n:         .zero 8
s_served:    .zero 8
s_tip:       .zero 8
s_from:      .zero 8
s_htidx:     .zero 8
s_txid:      .zero 32
s_st:        .zero 8
s_fd:        .zero 8
s_lfd:       .zero 8
s_lastheight: .zero 8

	.data
	.align 4
s_myfee:     .quad 1000               /* our min-relay-feerate (sat/kB) */

/* ---- command-name strings ---- */
	.section .rodata
cn_pong:   .ascii "pong\0"
cn_addr:   .ascii "addr\0"
cn_block:  .ascii "block\0"
cn_head:   .ascii "headers\0"
cn_inv:    .ascii "inv\0"
cn_tx:     .ascii "tx\0"
cn_getdata:.ascii "getdata\0"
cn_getbtxn:.ascii "getblocktxn\0"
cn_btxn:   .ascii "blocktxn\0"
cn_cmpct:  .ascii "cmpctblock\0"
cn_sendhd: .ascii "sendheaders\0"
cn_feeflt: .ascii "feefilter\0"
cn_notfnd:.ascii "notfound\0"

	.text

/* LOADADDR dst, var -- materialise the (local) address of a .bss/.data/.rodata
 * symbol into a register. */
	.macro LOADADDR dst, var
	adrp \dst, \var
	add  \dst, \dst, :lo12:\var
	.endm

/* ============================================================================
 * memcpy_len(dst=x0, src=x1, n=x2) -- byte mover. Leaf; clobbers x3,x9.
 * ========================================================================== */
	.type .Ls_memcpy_len, %function
.Ls_memcpy_len:
	mov  x9, #0
1:	cmp  x9, x2
	b.hs 2f
	ldrb w3, [x1, x9]
	strb w3, [x0, x9]
	add  x9, x9, #1
	b    1b
2:	ret
	.size .Ls_memcpy_len, .-.Ls_memcpy_len

/* ============================================================================
 * varint_put(dst=x0, val=x1) -> bytes written (x0). Leaf; clobbers x2.
 * ========================================================================== */
	.type .Ls_varint_put, %function
.Ls_varint_put:
	mov  x2, #0xfd
	cmp  x1, x2
	b.lo 1f
	movz x2, #0xffff
	cmp  x1, x2
	b.ls 2f
	movz x2, #0xffff
	movk x2, #0xffff, lsl #16         /* 0xffffffff */
	cmp  x1, x2
	b.ls 3f
	mov  w2, #0xff
	strb w2, [x0, #0]
	str  x1, [x0, #1]
	mov  x0, #9
	ret
2:	mov  w2, #0xfd
	strb w2, [x0, #0]
	strh w1, [x0, #1]
	mov  x0, #3
	ret
3:	mov  w2, #0xfe
	strb w2, [x0, #0]
	str  w1, [x0, #1]
	mov  x0, #5
	ret
1:	strb w1, [x0, #0]
	mov  x0, #1
	ret
	.size .Ls_varint_put, .-.Ls_varint_put

/* ============================================================================
 * serve_txdv_preinit() -> 1 if the tx-validation path is usable, else 0.
 *   Runs the read-only UTXO snapshot + mempool policy init ONCE, intended to
 *   be called by the parent BEFORE forking (daemon/main.c), so every inbound
 *   child inherits the snapshot copy-on-write instead of opening its own (the
 *   per-connection lazy-init below is the fallback for callers that never
 *   pre-init, e.g. the test harnesses). Idempotent: a second call is a no-op.
 * ========================================================================== */
	.global serve_txdv_preinit
	.type serve_txdv_preinit, %function
serve_txdv_preinit:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	LOADADDR x9, tx_dv_initdone
	ldrb w9, [x9]
	cmp  w9, #1
	b.eq .pre_done
	bl   tx_dispatch_init
	LOADADDR x9, tx_dv_ok
	strb w0, [x9]
	bl   tx_policy_init
	LOADADDR x9, tx_dv_ok
	ldrb w1, [x9]
	and  w0, w0, w1
	strb w0, [x9]
	LOADADDR x9, tx_dv_initdone
	mov  w1, #1
	strb w1, [x9]
.pre_done:
	LOADADDR x9, tx_dv_ok
	ldrb w0, [x9]
	ldp  x29, x30, [sp], #16
	ret
	.size serve_txdv_preinit, .-serve_txdv_preinit

/* ============================================================================
 * node_serve_loop(fd, lfd, st, ht_idx, out_buf, out_cap) -> # blocks served
 * ========================================================================== */
	.global node_serve_loop
	.type node_serve_loop, %function
node_serve_loop:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #96
	mov  x30, x0                      /* fd (temp) */
	mov  x19, x0                      /* fd */
	mov  x29, x30
	/* stable static copies (cons_verify / store_validates_prevhash clobber
	   the callee-saved regs under the x86 ABI convention; keep authoritative) */
	LOADADDR x23, s_fd
	str  x19, [x23]
	LOADADDR x23, s_lfd
	str  x1, [x23]
	LOADADDR x23, s_st
	str  x2, [x23]
	LOADADDR x23, s_htidx
	str  x3, [x23]
	LOADADDR x23, s_served
	str  xzr, [x23]
	mov  x20, x1                      /* lfd */
	mov  x21, x2                      /* st */
	mov  x22, x3                      /* ht_idx */

	/* mempool lazy init (static fallback vs C-provided -maxmempool region) */
	LOADADDR x9, mp_initdone
	ldrb w9, [x9]
	cmp  w9, #1
	b.eq .mpready
	LOADADDR x9, mp_ext_area
	ldr  x9, [x9]
	cbnz x9, .mp_external
	/* static fallback */
	LOADADDR x9, mp_area
	LOADADDR x23, mp_cur
	str  x9, [x23]
	mov  x0, x9
	mov  x1, #MP_SLOTS
	LOADADDR x2, mp_blob
	mov  x3, #(2<<20)
	bl   mpool_init
	b    .mp_inited
.mp_external:
	LOADADDR x23, mp_cur
	str  x9, [x23]                    /* mp_cur = mp_ext_area */
	LOADADDR x10, mp_ext_inited
	ldr  x10, [x10]
	cbnz x10, .mp_inited              /* shared region: init ran pre-fork */
	mov  x0, x9
	LOADADDR x9, mp_ext_slots
	ldr  x1, [x9]
	LOADADDR x9, mp_ext_blob
	ldr  x2, [x9]
	LOADADDR x9, mp_ext_blobcap
	ldr  x3, [x9]
	bl   mpool_init
.mp_inited:
	LOADADDR x9, mp_initdone
	mov  w10, #1
	strb w10, [x9]
.mpready:
	/* tx-dispatch / policy lazy init (once per process) */
	LOADADDR x9, tx_dv_initdone
	ldrb w9, [x9]
	cmp  w9, #1
	b.eq .txdvready
	bl   tx_dispatch_init
	LOADADDR x9, tx_dv_ok
	strb w0, [x9]
	bl   tx_policy_init
	LOADADDR x9, tx_dv_ok
	ldrb w1, [x9]
	and  w0, w0, w1
	strb w0, [x9]
	LOADADDR x9, tx_dv_initdone
	mov  w1, #1
	strb w1, [x9]
.txdvready:

	/* per-connection init: reset negotiation, remember tip, send our feefilter */
	LOADADDR x9, s_shdr
	str  xzr, [x9]
	LOADADDR x9, s_peerfee
	str  xzr, [x9]
	LOADADDR x9, s_feesent
	strb wzr, [x9]
	ldr  w9, [x21, #24]               /* tip height = st[24] */
	LOADADDR x10, s_lasttip
	str  x9, [x10]
	/* feefilter_send: int64 LE min-relay-feerate */
	LOADADDR x10, s_myfee
	ldr  x11, [x10]
	LOADADDR x10, hp_buf
	str  x11, [x10]
	mov  x0, x19
	LOADADDR x1, cn_feeflt
	mov  x2, #9
	mov  x3, x10
	mov  x4, #8
	bl   p2p_write
	LOADADDR x9, s_feesent
	mov  w10, #1
	strb w10, [x9]

.outer:
	LOADADDR x9, s_plen
	str  xzr, [x9]
	mov  x0, x19
	LOADADDR x1, s_cmd
	LOADADDR x2, pl_buf
	mov  x3, #(8<<20)
	LOADADDR x4, s_plen
	bl   p2p_read
	cmp  x0, #0
	b.le .done
	LOADADDR x9, s_cmd
	add  x9, x9, #11
	strb wzr, [x9]                    /* s_cmd[11]=0 */

	/* dispatch on dword0 (LE) */
	LOADADDR x9, s_cmd
	ldr  w23, [x9]
	mov  w24, #0x6970
	movk w24, #0x676e, lsl #16        /* "ping" */
	cmp  w23, w24
	b.eq .do_ping
	mov  w24, #0x6576
	movk w24, #0x6172, lsl #16        /* "vera" -> verack */
	cmp  w23, w24
	b.eq .do_verack
	mov  w24, #0x6567
	movk w24, #0x6174, lsl #16        /* "geta" (getaddr) */
	cmp  w23, w24
	b.eq .maybe_getaddr
	mov  w24, #0x6567
	movk w24, #0x6474, lsl #16        /* "getd" (getdata) */
	cmp  w23, w24
	b.eq .maybe_getdata
	mov  w24, #0x6567
	movk w24, #0x6874, lsl #16        /* "geth" (getheaders) */
	cmp  w23, w24
	b.eq .maybe_getheaders
	mov  w24, #0x6567
	movk w24, #0x6274, lsl #16        /* "getb" (getblocks / getblocktxn) */
	cmp  w23, w24
	b.eq .maybe_getb
	mov  w24, #0x6567
	movk w24, #0x6374, lsl #16        /* "getc" (getcfilters/-headers/-checkpt) */
	cmp  w23, w24
	b.eq .maybe_getcf
	mov  w24, #0x6e69
	movk w24, #0x0076, lsl #16        /* "inv" */
	cmp  w23, w24
	b.eq .do_inv
	mov  w24, #0x7874
	movk w24, #0x0000, lsl #16        /* "tx" */
	cmp  w23, w24
	b.eq .do_tx
	mov  w24, #0x6f6c
	movk w24, #0x6362, lsl #16        /* "bloc" */
	cmp  w23, w24
	b.eq .do_block
	mov  w24, #0x6e65
	movk w24, #0x6465, lsl #16        /* "send" */
	cmp  w23, w24
	b.eq .maybe_sendcmpct
	mov  w24, #0x6566
	movk w24, #0x6665, lsl #16        /* "feef" */
	cmp  w23, w24
	b.eq .maybe_feefilter
	b    .next

.do_verack:
	b    .next

.do_ping:
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #8
	b.hs 3f
	mov  x4, #0
	b    4f
3:	mov  x4, #8
4:	mov  x0, x19
	LOADADDR x1, cn_pong
	mov  x2, #4
	LOADADDR x3, pl_buf
	bl   p2p_write
	b    .next

.do_inv:
	LOADADDR x9, pl_buf
	ldrb w9, [x9]                     /* count */
	LOADADDR x10, s_cnt
	str  x9, [x10]
	cbz  x9, .next
	LOADADDR x10, s_ptr
	LOADADDR x11, pl_buf
	add  x11, x11, #1
	str  x11, [x10]                   /* s_ptr = pl_buf+1 */
.LSV_inv_loop:
	LOADADDR x9, s_cnt
	ldr  x9, [x9]
	cbz  x9, .next
	LOADADDR x9, s_ptr
	ldr  x9, [x9]                     /* item ptr */
	ldr  w10, [x9]                    /* type */
	cmp  w10, #2                      /* MSG_BLOCK */
	b.ne .LSV_inv_next
	str  x9, [sp, #0]                 /* save item ptr across idx_get */
	mov  x0, x22                      /* ht_idx */
	add  x1, x9, #4                   /* hash */
	LOADADDR x2, s_fh
	bl   idx_get
	ldr  x9, [sp, #0]
	cbnz x0, .LSV_inv_next            /* already have -> skip */
	/* build getdata: [1][type=0x40000002][hash32] */
	LOADADDR x10, src_buf
	mov  w11, #1
	strb w11, [x10]
	mov  w11, #0x0002
	movk w11, #0x4000, lsl #16        /* 0x40000002 */
	str  w11, [x10, #1]
	add  x0, x10, #5
	add  x1, x9, #4
	mov  x2, #32
	bl   .Ls_memcpy_len
	str  x9, [sp, #0]
	mov  x0, x19
	LOADADDR x1, cn_getdata
	mov  x2, #7
	LOADADDR x3, src_buf
	mov  x4, #37
	bl   p2p_write
	ldr  x9, [sp, #0]
.LSV_inv_next:
	add  x9, x9, #36
	LOADADDR x10, s_ptr
	str  x9, [x10]
	LOADADDR x10, s_cnt
	ldr  x9, [x10]
	sub  x9, x9, #1
	str  x9, [x10]
	b    .LSV_inv_loop

.do_tx:
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #10
	b.lo .next
	/* tx_txid(s_txid, pl_buf, s_plen, hp_buf, cap) */
	LOADADDR x0, s_txid
	LOADADDR x1, pl_buf
	LOADADDR x10, s_plen
	ldr  x2, [x10]
	LOADADDR x3, hp_buf
	movz x4, #0x7918                  /* 2000*81+8 = 162008 = 0x27918 */
	movk x4, #0x2, lsl #16
	bl   tx_txid
	cbz  x0, .next
	LOADADDR x9, tx_dv_ok
	ldrb w9, [x9]
	cmp  w9, #1
	b.ne .next
	LOADADDR x0, mp_cur
	ldr  x0, [x0]
	LOADADDR x1, s_txid
	LOADADDR x2, pl_buf
	LOADADDR x10, s_plen
	ldr  x3, [x10]
	bl   tx_accept_validate
	b    .next

.do_block:
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #81
	b.lo .next
	LOADADDR x0, pl_buf
	mov  x1, x9                       /* s_plen */
	LOADADDR x2, serve_txid_scratch
	movz x3, #SERVE_TXID_CAP_LO
	movk x3, #SERVE_TXID_CAP_HI, lsl #16
	bl   cons_verify
	/* restore loop regs from statics (cons_verify clobbers under x86 ABI) */
	LOADADDR x9, s_fd
	ldr  x19, [x9]
	LOADADDR x9, s_lfd
	ldr  x20, [x9]
	LOADADDR x9, s_st
	ldr  x21, [x9]
	LOADADDR x9, s_htidx
	ldr  x22, [x9]
	cbz  w0, .next
	/* block_hash(hash@sb_buf+0x200000, pl_buf) */
	LOADADDR x0, sb_buf
	add  x0, x0, #0x200000
	LOADADDR x1, pl_buf
	bl   block_hash
	/* duplicate? idx_get(ht_idx, hash, &s_fh) */
	mov  x0, x22
	LOADADDR x1, sb_buf
	add  x1, x1, #0x200000
	LOADADDR x2, s_fh
	bl   idx_get
	cbnz x0, .next
	/* chain gate: store_validates_prevhash(st, pl_buf) */
	mov  x0, x21
	LOADADDR x1, pl_buf
	bl   store_validates_prevhash
	LOADADDR x9, s_fd
	ldr  x19, [x9]
	LOADADDR x9, s_lfd
	ldr  x20, [x9]
	LOADADDR x9, s_st
	ldr  x21, [x9]
	LOADADDR x9, s_htidx
	ldr  x22, [x9]
	cbnz x0, .blk_chains
	/* does not chain: log + drop */
	mov  x0, x20
	mov  x1, #6
	mov  x2, #0
	LOADADDR x9, s_plen
	ldr  x3, [x9]
	mov  x4, #0
	bl   node_log_event
	LOADADDR x9, s_fd
	ldr  x19, [x9]
	LOADADDR x9, s_lfd
	ldr  x20, [x9]
	LOADADDR x9, s_st
	ldr  x21, [x9]
	LOADADDR x9, s_htidx
	ldr  x22, [x9]
	b    .next
.blk_chains:
	/* idxscan_append_locked(st, hash, pl_buf, s_plen) */
	mov  x0, x21
	LOADADDR x1, sb_buf
	add  x1, x1, #0x200000
	LOADADDR x2, pl_buf
	LOADADDR x9, s_plen
	ldr  x3, [x9]
	bl   idxscan_append_locked
	cmp  x0, #0
	b.le .next
	LOADADDR x9, s_lastheight
	str  x0, [x9]
	/* idx_put(ht_idx, hash, height) */
	mov  x0, x22
	LOADADDR x1, sb_buf
	add  x1, x1, #0x200000
	ldr  x2, [x9]
	bl   idx_put
	/* log_block_stored_inbound(hash, height, plen, pl_buf) */
	LOADADDR x0, sb_buf
	add  x0, x0, #0x200000
	LOADADDR x9, s_lastheight
	ldr  x1, [x9]
	LOADADDR x9, s_plen
	ldr  x2, [x9]
	LOADADDR x3, pl_buf
	bl   log_block_stored_inbound
	LOADADDR x9, s_served
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	b    .next

.maybe_getaddr:
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #4]
	mov  w10, #0x6464
	movk w10, #0x0072, lsl #16        /* "ddr\0" */
	cmp  w9, w10
	b.ne .next
	LOADADDR x0, amr_ab
	bl   amr_init
	cbz  x0, .next
	LOADADDR x0, amr_ab
	bl   amr_count
	mov  x9, x0                       /* n */
	cmp  x9, #1000
	b.ls 5f
	mov  x9, #1000
5:	mov  x10, #0                      /* have */
	mov  x11, #0                      /* i */
.LSV_aloop:
	cmp  x11, x9
	b.hs .LSV_adone
	LOADADDR x0, amr_ab
	mov  x1, x11
	/* dst = src_buf + have*18 */
	mov  x2, x10
	mov  x3, #18
	mul  x2, x2, x3
	LOADADDR x3, src_buf
	add  x2, x3, x2
	str  x10, [sp, #0]                /* save have */
	str  x11, [sp, #8]                /* save i */
	bl   amr_get_i
	ldr  x10, [sp, #0]
	ldr  x11, [sp, #8]
	cmp  x0, #1
	b.ne 6f
	add  x10, x10, #1                 /* have++ */
6:	add  x11, x11, #1
	b    .LSV_aloop
.LSV_adone:
	cbz  x10, .next
	LOADADDR x0, ah_buf
	LOADADDR x1, src_buf
	mov  x2, x10
	bl   p2p_addr_v1
	mov  x4, x0                       /* payload len */
	mov  x0, x19
	LOADADDR x1, cn_addr
	mov  x2, #4
	LOADADDR x3, ah_buf
	bl   p2p_write
	b    .next

.maybe_getdata:
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #4]
	mov  w10, #0x7461
	movk w10, #0x0061, lsl #16        /* "ata\0" */
	cmp  w9, w10
	b.ne .next
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #37
	b.lo .next
	/* Fold in any height index.dat has gained since this process last
	 * looked (the hash index was built at boot; the DOWNLOAD WORKER, a
	 * different process, appends new blocks -- without this every block we
	 * downloaded during the run is a silent miss). Cheap when nothing is
	 * new (one stat), and done here rather than per connection. */
	bl   serve_idx_topup
	LOADADDR x10, s_nf
	str  xzr, [x10]                   /* no misses yet for this getdata */
	LOADADDR x9, pl_buf
	ldrb w10, [x9]                    /* cnt */
	LOADADDR x11, s_cnt
	str  x10, [x11]
	LOADADDR x11, s_ptr
	add  x10, x9, #1
	str  x10, [x11]                   /* s_ptr = pl_buf+1 */
.LSV_gd_loop:
	LOADADDR x9, s_cnt
	ldr  x9, [x9]
	cbz  x9, .gd_done
	LOADADDR x9, s_ptr
	ldr  x9, [x9]                     /* item */
	ldr  w10, [x9]                    /* type */
	and  w10, w10, #0x3fffffff
	cmp  w10, #1
	b.eq .gd_tx
	cmp  w10, #4
	b.eq .gd_cmpct
	cmp  w10, #2
	b.eq .gd_block
	b    .gd_next

.gd_cmpct:
	LOADADDR x10, s_cmpct_v2
	ldr  x10, [x10]
	cmp  x10, #1
	b.ne .gd_miss
	str  x9, [sp, #0]
	mov  x0, x22
	add  x1, x9, #4
	LOADADDR x2, s_fh
	bl   idx_get
	ldr  x9, [sp, #0]
	cbz  x0, .gd_miss
	str  x9, [sp, #0]                 /* s_ptr */
	mov  x0, x21
	LOADADDR x1, s_fh
	ldr  x1, [x1]
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   node_serve_block
	ldr  x9, [sp, #0]
	cmp  x0, #0
	b.le .gd_miss
	LOADADDR x10, s_blen_spill
	str  x0, [x10]
	/* choose/rotate nonce */
	LOADADDR x10, s_cmpct_nonce
	ldr  x11, [x10]
	cbnz x11, 7f
	movz x11, #0x9abc
	movk x11, #0xefde, lsl #16
	movk x11, #0x4567, lsl #32
	movk x11, #0x0123, lsl #48
	str  x11, [x10]
7:	str  x9, [sp, #0]
	LOADADDR x0, bt_buf
	LOADADDR x1, sb_buf
	LOADADDR x10, s_blen_spill
	ldr  x2, [x10]
	mov  x3, x11                       /* nonce */
	bl   cmpctblock_build
	ldr  x9, [sp, #0]
	cmp  x0, #0
	b.le .gd_miss
	mov  x4, x0                       /* cmpctblock len */
	str  x9, [sp, #0]
	mov  x0, x19
	LOADADDR x1, cn_cmpct
	mov  x2, #10
	LOADADDR x3, bt_buf
	bl   p2p_write
	ldr  x9, [sp, #0]
	LOADADDR x10, s_served
	ldr  x11, [x10]
	add  x11, x11, #1
	str  x11, [x10]
	b    .gd_next

.gd_block:
	str  x9, [sp, #0]
	mov  x0, x22
	add  x1, x9, #4
	LOADADDR x2, s_fh
	bl   idx_get
	ldr  x9, [sp, #0]
	cbz  x0, .gd_miss
	str  x9, [sp, #0]
	mov  x0, x21
	LOADADDR x1, s_fh
	ldr  x1, [x1]
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   node_serve_block
	ldr  x9, [sp, #0]
	cmp  x0, #0
	b.le .gd_miss
	mov  x4, x0                        /* block len */
	str  x9, [sp, #0]
	mov  x0, x19
	LOADADDR x1, cn_block
	mov  x2, #5
	LOADADDR x3, sb_buf
	bl   p2p_write
	ldr  x9, [sp, #0]
	LOADADDR x10, s_served
	ldr  x11, [x10]
	add  x11, x11, #1
	str  x11, [x10]
	b    .gd_next

.gd_tx:
	str  x9, [sp, #0]
	LOADADDR x0, mp_cur
	ldr  x0, [x0]
	add  x1, x9, #4
	LOADADDR x2, s_n
	bl   mpool_get
	ldr  x9, [sp, #0]
	cbz  x0, .gd_miss
	mov  x3, x0                        /* tx bytes ptr (mpool blob) */
	str  x9, [sp, #0]
	mov  x0, x19
	LOADADDR x1, cn_tx
	mov  x2, #2
	LOADADDR x4, s_n
	ldr  x4, [x4]
	bl   p2p_write
	ldr  x9, [sp, #0]
	LOADADDR x10, s_served
	ldr  x11, [x10]
	add  x11, x11, #1
	str  x11, [x10]
	b    .gd_next

.gd_miss:
	/* Could not serve this entry: copy its 36 bytes (type u32 + 32B hash)
	 * into the notfound reply. x9 points at the entry -- exactly the shape
	 * notfound carries, so it is copied verbatim rather than rebuilt. */
	LOADADDR x10, s_nf
	ldr  x11, [x10]
	cmp  x11, #50
	b.hs .gd_next                     /* reply full; the rest are dropped */
	LOADADDR x12, nf_buf
	add  x12, x12, #1                 /* nf_buf[0] holds the count */
	add  x12, x12, x11, lsl #5        /* 36*n = 32n + 4n */
	add  x12, x12, x11, lsl #2
	mov  x13, #0
1:	cmp  x13, #36
	b.hs 2f
	ldrb w14, [x9, x13]
	strb w14, [x12, x13]
	add  x13, x13, #1
	b    1b
2:	add  x11, x11, #1
	LOADADDR x10, s_nf
	str  x11, [x10]
	b    .gd_next

.gd_done:
	/* every entry handled -- tell the peer about the ones we could not serve */
	LOADADDR x9, s_nf
	ldr  x9, [x9]
	cbz  x9, .next
	LOADADDR x10, nf_buf
	strb w9, [x10]                    /* count (<=50, so a single-byte varint) */
	mov  x11, x9
	add  x11, x11, x9, lsl #5
	add  x11, x11, x9, lsl #2
	add  x11, x11, #1                 /* payload len = 1 + 36*count */
	mov  x0, x19
	LOADADDR x1, cn_notfnd
	mov  x2, #8
	LOADADDR x3, nf_buf
	mov  x4, x11
	bl   p2p_write
	b    .next

.gd_next:
	LOADADDR x9, s_ptr
	ldr  x9, [x9]
	add  x9, x9, #36
	LOADADDR x10, s_ptr
	str  x9, [x10]
	LOADADDR x10, s_cnt
	ldr  x9, [x10]
	sub  x9, x9, #1
	str  x9, [x10]
	b    .LSV_gd_loop

.maybe_getcf:
	/* BIP157 compact-filter serving: getcfilters / getcfheaders / getcfcheckpt.
	 * Distinguish on cmd[4..7]: "filt" / "fhea" / "fche". */
	LOADADDR x9, s_cmd
	ldr  w10, [x9, #4]
	mov  w11, #0                      /* kind 0 = getcfilters */
	mov  w12, #0x6966
	movk w12, #0x746c, lsl #16        /* "filt" */
	cmp  w10, w12
	b.eq .gcf_go
	mov  w11, #1                      /* kind 1 = getcfheaders */
	mov  w12, #0x6866
	movk w12, #0x6165, lsl #16        /* "fhea" */
	cmp  w10, w12
	b.eq .gcf_go
	mov  w11, #2                      /* kind 2 = getcfcheckpt */
	mov  w12, #0x6366
	movk w12, #0x6568, lsl #16        /* "fche" */
	cmp  w10, w12
	b.ne .next
.gcf_go:
	/* serve_cfilters(fd, kind, pl_buf, plen) */
	mov  x0, x19
	mov  w1, w11
	LOADADDR x2, pl_buf
	LOADADDR x3, s_plen
	ldr  x3, [x3]
	bl   serve_cfilters
	b    .next

.maybe_getheaders:
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #3]
	mov  w10, #0x6561
	movk w10, #0x6468, lsl #16        /* "head" at cmd[3] */
	cmp  w9, w10
	b.ne .next
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #7]
	mov  w10, #0x7365
	movk w10, #0x0072, lsl #16        /* "ers\0" at cmd[7] */
	cmp  w9, w10
	b.ne .next
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #5
	b.lo .gh_build
	mov  x0, x22
	LOADADDR x1, pl_buf
	add  x1, x1, #5
	LOADADDR x2, s_fh
	bl   idx_get
	cbz  x0, .gh_from0
	LOADADDR x9, s_fh
	ldr  x9, [x9]
	add  x9, x9, #1                   /* from = fh+1 */
	LOADADDR x10, s_fh
	str  x9, [x10]
	b    .gh_build
.gh_from0:
	LOADADDR x9, s_fh
	str  xzr, [x9]
.gh_build:
	ldr  w9, [x21, #24]               /* tip = st[24] */
	LOADADDR x10, s_cnt
	str  x9, [x10]
	LOADADDR x9, s_fh
	ldr  x9, [x9]
	LOADADDR x10, s_cnt
	ldr  x10, [x10]
	cmp  x9, x10
	b.hi .gh_empty
	/* s_p = 3 ; s_n = 0 ; save from for log */
	LOADADDR x9, s_p
	mov  x10, #3
	str  x10, [x9]
	LOADADDR x9, s_n
	str  xzr, [x9]
	LOADADDR x9, s_fh
	ldr  x10, [x9]
	LOADADDR x11, s_plen
	str  x10, [x11]
.LSV_ghh_loop:
	/* while s_fh <= s_cnt && s_n < 2000 */
	LOADADDR x9, s_fh
	ldr  x9, [x9]
	LOADADDR x10, s_cnt
	ldr  x10, [x10]
	cmp  x9, x10
	b.hi .LSV_ghh_done
	LOADADDR x9, s_n
	ldr  x9, [x9]
	cmp  x9, #2000
	b.hs .LSV_ghh_done
	/* node_serve_block(st, h, sb_buf, cap) */
	mov  x0, x21
	LOADADDR x9, s_fh
	ldr  x1, [x9]
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   node_serve_block
	cmp  x0, #0
	b.le .LSV_ghh_done
	/* memcpy(hp_buf+p, sb_buf, 80) */
	LOADADDR x9, s_p
	ldr  x9, [x9]
	LOADADDR x10, hp_buf
	add  x0, x10, x9
	LOADADDR x1, sb_buf
	mov  x2, #80
	bl   .Ls_memcpy_len
	LOADADDR x9, s_p
	ldr  x9, [x9]
	LOADADDR x10, hp_buf
	add  x10, x10, x9
	add  x10, x10, #80
	strb wzr, [x10]                   /* tx-count byte 0 */
	LOADADDR x9, s_p
	ldr  x10, [x9]
	add  x10, x10, #81
	str  x10, [x9]                    /* s_p += 81 */
	LOADADDR x9, s_n
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	LOADADDR x9, s_fh
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	b    .LSV_ghh_loop
.LSV_ghh_done:
	/* n = (s_p - 3)/81 */
	LOADADDR x9, s_p
	ldr  x9, [x9]
	sub  x9, x9, #3
	mov  x10, #81
	udiv x9, x9, x10
	LOADADDR x10, s_n
	str  x9, [x10]
	cmp  x9, #253
	b.hs .gh_varint16
	/* compact: move n*81 bytes from hp_buf+3 to hp_buf+1, set hp_buf[0]=n */
	mov  x10, x9
	mov  x11, #81
	mul  x10, x10, x11                /* bytes = n*81 */
	mov  x12, #0
	LOADADDR x13, hp_buf
8:	cmp  x12, x10
	b.hs 9f
	add  x14, x13, #3
	ldrb w15, [x14, x12]
	add  x14, x13, #1
	strb w15, [x14, x12]
	add  x12, x12, #1
	b    8b
9:	LOADADDR x10, s_n
	ldr  w10, [x10]
	strb w10, [x13]                   /* hp_buf[0] = n */
	LOADADDR x10, s_n
	ldr  x10, [x10]
	mov  x11, #81
	mul  x10, x10, x11
	add  x10, x10, #1
	LOADADDR x11, s_p
	str  x10, [x11]                   /* s_p = 1 + n*81 */
	b    .gh_send
.gh_varint16:
	LOADADDR x9, hp_buf
	mov  w10, #0xfd
	strb w10, [x9]
	LOADADDR x10, s_n
	ldr  w11, [x10]
	strb w11, [x9, #1]
	lsr  w11, w11, #8
	strb w11, [x9, #2]
	ldr  x12, [x10]
	mov  x13, #81
	mul  x12, x12, x13
	add  x12, x12, #3
	LOADADDR x13, s_p
	str  x12, [x13]                   /* s_p = 3 + n*81 */
.gh_send:
	LOADADDR x9, s_p
	ldr  w4, [x9]
	mov  x0, x19
	LOADADDR x1, cn_head
	mov  x2, #7
	LOADADDR x3, hp_buf
	bl   p2p_write
	/* node_log_event(lfd, 6, n, from, 0) */
	mov  x0, x20
	mov  x1, #6
	LOADADDR x10, s_n
	ldr  x2, [x10]
	LOADADDR x11, s_plen
	ldr  x3, [x11]
	mov  x4, #0
	bl   node_log_event
	b    .next
.gh_empty:
	LOADADDR x9, hp_buf
	strb wzr, [x9]
	mov  x0, x19
	LOADADDR x1, cn_head
	mov  x2, #7
	LOADADDR x3, hp_buf
	mov  x4, #1
	bl   p2p_write
	b    .next

.maybe_getb:
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #8]
	mov  w10, #0x7874
	movk w10, #0x006e, lsl #16        /* "txn\0" at cmd[8] */
	cmp  w9, w10
	b.eq .do_getblocktxn
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #4]
	mov  w10, #0x636f
	movk w10, #0x6b6c, lsl #16        /* "lock" at cmd[4] */
	cmp  w9, w10
	b.ne .next
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #37
	b.lo .gb_from0
	mov  x0, x22
	LOADADDR x1, pl_buf
	add  x1, x1, #5
	LOADADDR x2, s_fh
	bl   idx_get
	cbz  x0, .gb_from0
	LOADADDR x9, s_fh
	ldr  x9, [x9]
	add  x9, x9, #1
	b    .gb_havefrom
.gb_from0:
	mov  x9, #0
.gb_havefrom:
	LOADADDR x10, s_fh
	str  x9, [x10]
	ldr  w9, [x21, #24]               /* tip */
	LOADADDR x10, s_cnt
	str  x9, [x10]
	LOADADDR x9, s_fh
	ldr  x9, [x9]
	LOADADDR x10, s_cnt
	ldr  x10, [x10]
	cmp  x9, x10
	b.hi .gb_empty
	LOADADDR x9, s_p
	mov  x10, #3
	str  x10, [x9]
	LOADADDR x9, s_n
	str  xzr, [x9]
.LSV_gbl_loop:
	LOADADDR x9, s_fh
	ldr  x9, [x9]
	LOADADDR x10, s_cnt
	ldr  x10, [x10]
	cmp  x9, x10
	b.hi .gb_done
	LOADADDR x9, s_n
	ldr  x9, [x9]
	cmp  x9, #500
	b.hs .gb_done
	mov  x0, x21
	LOADADDR x9, s_fh
	ldr  x1, [x9]
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   node_serve_block
	cmp  x0, #0
	b.le .gb_done
	/* block_hash(hash, sb_buf) */
	LOADADDR x0, sb_buf
	add  x0, x0, #0x200000
	LOADADDR x1, sb_buf
	bl   block_hash
	/* type=2 at hp_buf[p] (u32), reversed hash at hp_buf[p+4..p+35] */
	LOADADDR x9, s_p
	ldr  x9, [x9]
	LOADADDR x10, hp_buf
	add  x10, x10, x9
	mov  w11, #2
	str  w11, [x10]                   /* type u32 (will be at p..p+3) */
	add  x9, x10, #4                  /* dst base p+4 */
	LOADADDR x10, sb_buf
	add  x10, x10, #0x200000
	add  x10, x10, #31                /* src last byte */
	mov  x11, #0
.LSV_gbl_rev:
	cmp  x11, #32
	b.hs .LSV_gbl_rev_done
	sub  x12, x10, x11
	ldrb w13, [x12]
	strb w13, [x9, x11]
	add  x11, x11, #1
	b    .LSV_gbl_rev
.LSV_gbl_rev_done:
	LOADADDR x9, s_p
	ldr  x10, [x9]
	add  x10, x10, #36
	str  x10, [x9]
	LOADADDR x9, s_n
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	LOADADDR x9, s_fh
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	b    .LSV_gbl_loop
.gb_done:
	LOADADDR x9, s_n
	ldr  x9, [x9]
	cmp  x9, #253
	b.hs .gb_varint16
	mov  x10, x9
	mov  x11, #36
	mul  x10, x10, x11                /* bytes = n*36 */
	mov  x11, #0
	LOADADDR x12, hp_buf
10:	cmp  x11, x10
	b.hs 11f
	add  x13, x12, #3
	ldrb w14, [x13, x11]
	add  x13, x12, #1
	strb w14, [x13, x11]
	add  x11, x11, #1
	b    10b
11:	LOADADDR x10, s_n
	ldr  w10, [x10]
	strb w10, [x12]
	LOADADDR x10, s_n
	ldr  x10, [x10]
	mov  x11, #36
	mul  x10, x10, x11
	add  x10, x10, #1
	LOADADDR x11, s_p
	str  x10, [x11]
	b    .gb_send
.gb_varint16:
	LOADADDR x9, hp_buf
	mov  w10, #0xfd
	strb w10, [x9]
	LOADADDR x10, s_n
	ldr  w11, [x10]
	strb w11, [x9, #1]
	lsr  w11, w11, #8
	strb w11, [x9, #2]
	ldr  x12, [x10]
	mov  x13, #36
	mul  x12, x12, x13
	add  x12, x12, #3
	LOADADDR x13, s_p
	str  x12, [x13]
.gb_send:
	LOADADDR x9, s_p
	ldr  w4, [x9]
	mov  x0, x19
	LOADADDR x1, cn_inv
	mov  x2, #3
	LOADADDR x3, hp_buf
	bl   p2p_write
	LOADADDR x9, s_served
	ldr  x10, [x9]
	LOADADDR x11, s_n
	ldr  x11, [x11]
	add  x10, x10, x11
	str  x10, [x9]
	b    .next
.gb_empty:
	LOADADDR x9, hp_buf
	strb wzr, [x9]
	mov  x0, x19
	LOADADDR x1, cn_inv
	mov  x2, #3
	LOADADDR x3, hp_buf
	mov  x4, #1
	bl   p2p_write
	b    .next

.maybe_sendcmpct:
	LOADADDR x9, s_cmd
	ldrb w9, [x9, #4]
	cmp  w9, #'h'
	b.eq .do_sendheaders
	cmp  w9, #'c'
	b.ne .next
	LOADADDR x9, s_cmd
	ldrb w9, [x9, #5]
	cmp  w9, #'m'
	b.ne .next
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #9
	b.lo .next
	LOADADDR x9, pl_buf
	add  x9, x9, #1
	ldr  x10, [x9]                    /* version (u64 LE) */
	cmp  x10, #2
	b.ne .next
	LOADADDR x9, s_cmpct_v2
	mov  x10, #1
	str  x10, [x9]
	LOADADDR x9, s_cmpct_hb
	LOADADDR x10, pl_buf
	ldrb w10, [x10]                   /* announce */
	cbz  w10, 12f
	mov  x10, #1
	str  x10, [x9]
	b    .next
12:	str  xzr, [x9]
	b    .next

.do_sendheaders:
	LOADADDR x9, s_shdr
	mov  x10, #1
	str  x10, [x9]
	b    .next

.maybe_feefilter:
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #4]
	mov  w10, #0x746c
	movk w10, #0x0069, lsl #16        /* "ilt\0" */
	cmp  w9, w10
	b.ne .next
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #8
	b.lo .next
	LOADADDR x9, pl_buf
	ldr  x10, [x9]                    /* int64 LE feerate */
	LOADADDR x11, s_peerfee
	str  x10, [x11]
	b    .next

.do_getblocktxn:
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #33
	b.lo .next
	/* node_serve_block_by_hash(st, pl_buf, sb_buf, cap) */
	mov  x0, x21
	LOADADDR x1, pl_buf
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   node_serve_block_by_hash
	LOADADDR x9, s_blen_spill
	str  x0, [x9]
	cmp  x0, #0
	b.le .next
	/* parse indexes (DifferenceFormatter) from pl_buf+32 */
	LOADADDR x9, s_idxn
	str  xzr, [x9]
	LOADADDR x9, s_diffshift
	str  xzr, [x9]
	LOADADDR x10, pl_buf
	add  x10, x10, #32                /* cursor */
	ldrb w11, [x10]                   /* count varint */
	cmp  w11, #0xfd
	b.hs .gbtx_bigcnt
	add  x10, x10, #1
	mov  x12, x11                      /* rcx = count */
	b    .gbtx_cnthave
.gbtx_bigcnt:
	cmp  w11, #0xfd
	b.ne .gbkt_done
	ldrh w12, [x10, #1]
	add  x10, x10, #3
	mov  x12, x12
.gbtx_cnthave:
.LSV_gbtx_idxloop:
	cbz  x12, .gbkt_build
	ldrb w13, [x10]                   /* diff varint */
	cmp  w13, #0xfd
	b.lo .gbtx_d1
	cmp  w13, #0xfd
	b.ne .gbkt_done
	ldrh w14, [x10, #1]
	add  x10, x10, #3
	mov  w13, w14
	b    .gbtx_dhave
.gbtx_d1:
	add  x10, x10, #1
.gbtx_dhave:
	/* index = diffshift + diff */
	LOADADDR x15, s_diffshift
	ldr  x9, [x15]
	add  x9, x9, x13
	LOADADDR x14, s_idxn
	ldr  x14, [x14]
	LOADADDR x13, s_idxbuf
	strh w9, [x13, x14, lsl #1]
	LOADADDR x14, s_idxn
	ldr  x0, [x14]
	add  x0, x0, #1
	str  x0, [x14]
	add  x9, x9, #1
	str  x9, [x15]                    /* diffshift = index+1 */
	sub  x12, x12, #1
	b    .LSV_gbtx_idxloop
.gbkt_build:
	/* bt_buf = blockhash(32) + countvarint + txs */
	LOADADDR x0, bt_buf
	LOADADDR x1, pl_buf
	mov  x2, #32
	bl   .Ls_memcpy_len
	LOADADDR x0, bt_buf
	add  x0, x0, #32
	LOADADDR x1, s_idxn
	ldr  x1, [x1]
	bl   .Ls_varint_put
	add  x0, x0, #32
	LOADADDR x9, s_p
	str  x0, [x9]                     /* offset = 32 + countbytes */
	LOADADDR x9, s_cnt
	str  xzr, [x9]                    /* j = 0 */
.LSV_gbtx_txloop:
	LOADADDR x9, s_cnt
	ldr  x9, [x9]
	LOADADDR x10, s_idxn
	ldr  x10, [x10]
	cmp  x9, x10
	b.hs .gbkt_send
	/* idx = s_idxbuf[j] */
	LOADADDR x10, s_idxbuf
	add  x10, x10, x9, lsl #1
	ldrh w2, [x10]                    /* index */
	/* block_tx_at(sb_buf, blen, idx, &s_txptr, &s_txlen) */
	LOADADDR x0, sb_buf
	LOADADDR x1, s_blen_spill
	ldr  x1, [x1]
	LOADADDR x3, s_txptr
	LOADADDR x4, s_txlen
	bl   block_tx_at
	cbz  x0, .gbkt_done
	/* memcpy(bt_buf+s_p, s_txptr, s_txlen) */
	LOADADDR x9, s_p
	ldr  x9, [x9]
	LOADADDR x10, bt_buf
	add  x0, x10, x9
	LOADADDR x1, s_txptr
	ldr  x1, [x1]
	LOADADDR x2, s_txlen
	ldr  x2, [x2]
	bl   .Ls_memcpy_len
	LOADADDR x9, s_p
	ldr  x10, [x9]
	LOADADDR x11, s_txlen
	ldr  x11, [x11]
	add  x10, x10, x11
	str  x10, [x9]
	LOADADDR x9, s_cnt
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	b    .LSV_gbtx_txloop
.gbkt_send:
	LOADADDR x9, s_p
	ldr  w4, [x9]
	mov  x0, x19
	LOADADDR x1, cn_btxn
	mov  x2, #8
	LOADADDR x3, bt_buf
	bl   p2p_write
	LOADADDR x9, s_served
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	b    .next
.gbkt_done:
	b    .next

.next:
	/* tip-watch: announce a newly-advanced tip exactly once */
	ldr  w9, [x21, #24]               /* tip */
	LOADADDR x10, s_cnt
	str  x9, [x10]
	LOADADDR x10, s_lasttip
	ldr  x11, [x10]
	cmp  x11, x9
	b.ge .tw_done
	/* node_announce_tip(fd, st, ht_idx, use_headers) */
	mov  x0, x19
	mov  x1, x21
	mov  x2, x22
	LOADADDR x9, s_shdr
	ldr  x3, [x9]
	bl   node_announce_tip
	LOADADDR x10, s_lasttip
	LOADADDR x11, s_cnt
	ldr  x11, [x11]
	str  x11, [x10]
.tw_done:
	b    .outer
.done:
	LOADADDR x9, s_served
	ldr  x0, [x9]
	add  sp, sp, #96
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_serve_loop, .-node_serve_loop

/* ============================================================================
 * node_announce_tip(fd, st, ht_idx, use_headers) -> 1/0
 * ========================================================================== */
	.global node_announce_tip
	.type node_announce_tip, %function
node_announce_tip:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #32
	mov  x19, x0                     /* fd */
	mov  x20, x1                     /* st */
	str  x3, [sp, #0]                /* use_headers */
	/* tip = *(int*)(st+24) */
	ldr  w21, [x20, #24]
	cmp  w21, #0
	b.lt .at_fail
	/* node_serve_block(st, tip, sb_buf, cap) */
	mov  x0, x20
	mov  x1, x21
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   node_serve_block
	cmp  x0, #0
	b.le .at_fail
	cmp  x0, #80
	b.lo .at_fail
	/* headers or inv form depending on use_headers */
	ldr  x9, [sp, #0]
	cbz  x9, .at_inv
	/* headers: [count=1][hdr80][tx-count 0] = 82 bytes */
	LOADADDR x9, hp_buf
	mov  w10, #1
	strb w10, [x9]
	add  x0, x9, #1
	LOADADDR x1, sb_buf
	mov  x2, #80
	bl   .Ls_memcpy_len
	LOADADDR x9, hp_buf
	add  x9, x9, #81
	strb wzr, [x9]
	mov  x0, x19
	LOADADDR x1, cn_head
	mov  x2, #7
	LOADADDR x3, hp_buf
	mov  x4, #82
	bl   p2p_write
	cmp  x0, #0
	b.le .at_fail
	mov  x0, #1
	b    .at_done
.at_inv:
	/* inv: block_hash(hash, sb_buf) */
	LOADADDR x0, sb_buf
	add  x0, x0, #0x200000
	LOADADDR x1, sb_buf
	bl   block_hash
	LOADADDR x9, hp_buf
	mov  w10, #1
	strb w10, [x9]
	mov  w10, #2
	str  w10, [x9, #1]               /* type u32 LE = 2 */
	/* reverse hash -> hp_buf+5 */
	add  x9, x9, #5                   /* dst base */
	LOADADDR x10, sb_buf
	add  x10, x10, #0x200000
	add  x10, x10, #31                /* src last byte */
	mov  x11, #0
.LSV_at_rev:
	cmp  x11, #32
	b.hs .LSV_at_rev_done
	sub  x12, x10, x11
	ldrb w13, [x12]
	strb w13, [x9, x11]
	add  x11, x11, #1
	b    .LSV_at_rev
.LSV_at_rev_done:
	mov  x0, x19
	LOADADDR x1, cn_inv
	mov  x2, #3
	LOADADDR x3, hp_buf
	mov  x4, #37
	bl   p2p_write
	cmp  x0, #0
	b.le .at_fail
	mov  x0, #1
	b    .at_done
.at_fail:
	mov  x0, #0
.at_done:
	add  sp, sp, #32
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_announce_tip, .-node_announce_tip

	.section .note.GNU-stack,"",%progbits
