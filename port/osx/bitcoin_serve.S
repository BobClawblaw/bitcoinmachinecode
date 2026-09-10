/* bitcoin_serve.S -- adapted from the verified arm-port (origin/arm-port
 * port/arm64/bitcoin_serve.S) to Mach-O by adapt_armport.py, then hand-gated.
 * Exports: g_serve_inv_gate, g_serve_mempool_hook, g_serve_policy_log, g_serve_send_feefilter, g_serve_tx_gate, g_serve_violation_hook, node_announce_tip, node_serve_loop, serve_txdv_preinit */
/* ============================================================================
 * bitcoin_serve.S -- AArch64 (ARMv8-A) port of asm/bitcoin_serve.asm
 * The server half of the node's P2P message handling. _node_serve_loop reads a
 * version/verack-acknowledged peer stream and answers each command using the
 * other assembly primitives (address book, hash index, store, mempool, BIP152).
 *
 *   long _node_serve_loop(int fd, int lfd, void* st, void* ht_idx,
 *                        void* out_buf, long out_cap) -> # blocks served
 *   long _node_announce_tip(int fd, void* st, void* ht_idx, long use_headers)
 *
 * All per-connection / per-command state lives in module-local .bss (as in the
 * x86 original, which keeps loop state in statics, immune to deep callees'
 * register clobbering and stack spills). AAPCS64 applies at every boundary.
 * ========================================================================== */

	.extern _p2p_read
	.extern _p2p_write
	.extern _serve_inv_bounds
	.extern _serve_locator_from
	.extern _serve_getaddr
	.extern _g_peer_wants_addrv2
	.extern amr_init
	.extern amr_count
	.extern amr_get_i
	.extern p2p_addr_v1
	.extern _idx_get
	.extern _idx_put
	.extern _store_append
	.extern _idxscan_append_locked
	.extern _store_validates_prevhash
	.extern _cons_verify
	.extern _node_serve_block
	.extern _node_serve_block_by_hash
	.extern _node_log_event
	.extern _block_hash
	.extern _mpool_init
	.extern _mpool_get
	.extern _tx_dispatch_init
	.extern _tx_policy_init
	.extern _serve_idx_topup
	.extern _serve_cfilters
	.extern _tx_accept_validate
	.extern _log_block_stored_inbound
	.extern _tx_txid
	.extern _bip152_shortid
	.extern _node_relay_flag
	.extern _serve_reject_has          /* MEM-10: daemon/serve_rejects.c */
	.extern _serve_block_ctx_ok        /* NET-5: contextual header rules for a peer-pushed block (daemon/tx_accept.c) */
	.extern _strip_witness             /* MEM-24: the TX equivalent */
	.extern _block_tx_at
	.extern _block_txcount
	.extern _p2p_blocktxn_build
	.extern _cmpctblock_build
	.extern _mp_ext_area
	.extern _mp_ext_blob
	.extern _mp_ext_slots
	.extern _mp_ext_blobcap
	.extern _mp_ext_inited

	.text

	.equ SERVE_TXID_CAP, 80000
	.equ SERVE_TXID_CAP_LO, 0x3880    /* 80000 = 0x13880 */
	.equ SERVE_TXID_CAP_HI, 0x1
	.equ MP_SLOTS, 1024

/* ---- module-local .bss state (all zero-initialised; mirrors the x86 .data/.bss) ---- */
        .section __DATA,__bss
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
s_btend:     .zero 8                    /* NET-1: bt_buf + capacity (exclusive); the
                                         * blocktxn writer checks every append
                                         * against it (x86 80f03d4) */
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
s_ghstop:    .zero 8                    /* NET-8: hashStop height for getheaders,
                                         * -1 = absent/unknown (prologue-inited) */
s_cmd:       .zero 16
s_cnt:       .zero 8
s_ptr:       .zero 8
s_ivn:       .zero 8                    /* inv entry count (_serve_inv_bounds) */
s_ivo:       .zero 8                    /* offset of the first entry */
s_nf:        .zero 8                    /* notfound entries accumulated for THIS getdata */
s_p:         .zero 8
s_addrsent:  .zero 1        /* getaddr answered once per conn (Core: m_getaddr_recvd) */
s_abound:    .zero 8        /* getaddr loop bound in MEMORY (was clobbered in rdx) */
s_n:         .zero 8
s_served:    .zero 8
s_tip:       .zero 8
s_from:      .zero 8
s_htidx:     .zero 8
s_txid:      .zero 32                 /* inbound tx's computed BIP141 txid */
s_gdbh:      .zero 32                 /* STO-10: hash of the block getdata is about to send */
s_gdlen:     .zero 8                  /* STO-10: _node_serve_block's length across the _block_hash
                                       * call (its OWN slot, not s_n: s_n is the getheaders/cfilter
                                       * counter and aliasing it here would be a latent trap) */
s_st:        .zero 8
s_fd:        .zero 8
s_lfd:       .zero 8
s_lastheight: .zero 8

        .section __DATA,__data
	.align 4
s_myfee:     .quad 1000               /* our min-relay-feerate (sat/kB) */

/* ---- command-name strings ---- */
        .section __TEXT,__const
cn_pong:   .ascii "pong\0"
cn_addr:   .ascii "addr\0"
cn_addrv2: .ascii "addrv2\0"
cn_block:  .ascii "block\0"
cn_head:   .ascii "headers\0"
cn_inv:    .ascii "inv\0"
cn_tx:     .ascii "tx\0"
cn_getdata:.ascii "getdata\0"
viol_oversize: .ascii "oversized message announcement\0"
viol_invsz:    .ascii "inv/getdata vector above MAX_INV_SZ\0"
viol_txrelay:  .ascii "transaction sent in violation of protocol\0"
viol_invtx:    .ascii "transaction inv sent in violation of protocol\0"
viol_mempool:  .ascii "mempool request with bloom filters disabled\0"
viol_txparse:  .ascii "malformed tx payload (parse failure)\0"
viol_blkshort: .ascii "malformed block payload (shorter than a header)\0"
viol_gbtidx:   .ascii "getblocktxn with malformed or out-of-bounds tx indices\0"  /* Core: Misbehaving(100) */
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
	adrp \dst, \var@PAGE
	add  \dst, \dst, \var@PAGEOFF
	.endm

/* ============================================================================
 * memcpy_len(dst=x0, src=x1, n=x2) -- byte mover. Leaf; clobbers x3,x9.
 * ========================================================================== */
.Ls_memcpy_len:
	mov  x9, #0
1:	cmp  x9, x2
	b.hs 2f
	ldrb w3, [x1, x9]
	strb w3, [x0, x9]
	add  x9, x9, #1
	b    1b
2:	ret

/* ============================================================================
 * varint_put(dst=x0, val=x1) -> bytes written (x0). Leaf; clobbers x2.
 * ========================================================================== */
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

/* ============================================================================
 * _serve_txdv_preinit() -> 1 if the tx-validation path is usable, else 0.
 *   Runs the read-only UTXO snapshot + mempool policy init ONCE, intended to
 *   be called by the parent BEFORE forking (daemon/main.c), so every inbound
 *   child inherits the snapshot copy-on-write instead of opening its own (the
 *   per-connection lazy-init below is the fallback for callers that never
 *   pre-init, e.g. the test harnesses). Idempotent: a second call is a no-op.
 * ========================================================================== */
	.globl _serve_txdv_preinit
_serve_txdv_preinit:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	LOADADDR x9, tx_dv_initdone
	ldrb w9, [x9]
	cmp  w9, #1
	b.eq .pre_done
	bl   _tx_dispatch_init
	LOADADDR x9, tx_dv_ok
	strb w0, [x9]
	bl   _tx_policy_init
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
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

/* ============================================================================
 * _node_serve_loop(fd, lfd, st, ht_idx, out_buf, out_cap) -> # blocks served
 * ========================================================================== */
	.globl _node_serve_loop
_node_serve_loop:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #96
	mov  x30, x0                      /* fd (temp) */
	mov  x19, x0                      /* fd */
	mov  x29, x30
	/* stable static copies (_cons_verify / _store_validates_prevhash clobber
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
	/* NET-8: the hashStop sentinel: -1 = absent/unknown. */
	LOADADDR x23, s_ghstop
	mov  x9, #-1
	str  x9, [x23]
	/* NET-1: one-past-the-end of the blocktxn assembly buffer, checked by
	 * the .do_getblocktxn writer before every append. */
	LOADADDR x23, bt_buf
	add  x9, x23, #(8<<20)
	LOADADDR x23, s_btend
	str  x9, [x23]
	mov  x20, x1                      /* lfd */
	mov  x21, x2                      /* st */
	mov  x22, x3                      /* ht_idx */

	/* mempool lazy init (static fallback vs C-provided -maxmempool region) */
	LOADADDR x9, mp_initdone
	ldrb w9, [x9]
	cmp  w9, #1
	b.eq .mpready
	LOADADDR x9, _mp_ext_area
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
	bl   _mpool_init
	b    .mp_inited
.mp_external:
	LOADADDR x23, mp_cur
	str  x9, [x23]                    /* mp_cur = _mp_ext_area */
	LOADADDR x10, _mp_ext_inited
	ldr  x10, [x10]
	cbnz x10, .mp_inited              /* shared region: init ran pre-fork */
	mov  x0, x9
	LOADADDR x9, _mp_ext_slots
	ldr  x1, [x9]
	LOADADDR x9, _mp_ext_blob
	ldr  x2, [x9]
	LOADADDR x9, _mp_ext_blobcap
	ldr  x3, [x9]
	bl   _mpool_init
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
	bl   _tx_dispatch_init
	LOADADDR x9, tx_dv_ok
	strb w0, [x9]
	bl   _tx_policy_init
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
	LOADADDR x9, s_addrsent
	strb wzr, [x9]        /* getaddr answered once per conn (Core: m_getaddr_recvd) */
	ldr  w9, [x21, #24]               /* tip height = st[24] */
	LOADADDR x10, s_lasttip
	str  x9, [x10]
	/* feefilter_send: int64 LE min-relay-feerate -- gated (x86 2026-09-01):
	 * -blocksonly / forcerelay peers get no feefilter from us (Core) */
	LOADADDR x9, _g_serve_send_feefilter
	ldrb w9, [x9]
	cbz  w9, .LAH_ff_skip
	LOADADDR x10, s_myfee
	ldr  x11, [x10]
	LOADADDR x10, hp_buf
	str  x11, [x10]
	mov  x0, x19
	LOADADDR x1, cn_feeflt
	mov  x2, #9
	mov  x3, x10
	mov  x4, #8
	bl   _p2p_write
	LOADADDR x9, s_feesent
	mov  w10, #1
	strb w10, [x9]
.LAH_ff_skip:

.outer:
	LOADADDR x9, s_plen
	str  xzr, [x9]
	mov  x0, x19
	LOADADDR x1, s_cmd
	LOADADDR x2, pl_buf
	mov  x3, #(8<<20)
	LOADADDR x4, s_plen
	bl   _p2p_read
	cmp  x0, #0
	b.le .check_viol
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
	mov  w24, #0x6c62
	movk w24, #0x636f, lsl #16        /* "bloc" (0x636f6c62 LE, "block" cmd[0..3])
	                                   * -- was #0x6f6c ("oloc"): the movz half was
	                                   * byte-rotated (ASCII-immediate pitfall #2),
	                                   * so EVERY inbound block push was silently
	                                   * dropped and test_keepup's pushed block
	                                   * was never stored or served */
	cmp  w23, w24
	b.eq .do_block
	mov  w24, #0x6573
	movk w24, #0x646e, lsl #16        /* "send" (0x646e6573) */
	cmp  w23, w24
	b.eq .maybe_sendcmpct
	mov  w24, #0x6566
	movk w24, #0x6665, lsl #16        /* "feef" */
	cmp  w23, w24
	b.eq .maybe_feefilter
	mov  w24, #0x656d
	movk w24, #0x706d, lsl #16        /* "memp" (mempool) */
	cmp  w23, w24
	b.eq .maybe_mempool
	mov  w24, #0x7477
	movk w24, #0x6978, lsl #16        /* "wtxi" (wtxidrelay) -- handshake-only;
	                                     after verack Core disconnects */
	cmp  w23, w24
	b.eq .done
	b    .next

.maybe_mempool:
	/* cmd[4..7] == "ool\0"? (x86 .maybe_mempool) */
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #4]
	mov  w24, #0x6c6f
	movk w24, #0x006f, lsl #16        /* 0x006c6f6f LE */
	cmp  w9, w24
	b.ne .next
	/* _serve_mempool_msg(fd, mp): 1 handled/ignored, -1 violation (no
	 * `mempool` permission and not noban: Core disconnects) */
	LOADADDR x9, _g_serve_mempool_hook
	ldr  x9, [x9]
	cbz  x9, .next
	mov  x0, x19
	LOADADDR x1, mp_cur
	ldr  x1, [x1]
	blr  x9
	cmp  x0, #-1
	b.eq .viol_mempool_go
	b    .next

.viol_tx_malformed:
	LOADADDR x0, viol_txparse
	b    .viol_report_next
.viol_block_short:
	LOADADDR x0, viol_blkshort
.viol_report_next:
	/* audit N3: these SCORE (misbehaviour hook), unlike the policy_log
	 * disconnect path -- the test's fake hook returns 70 */
	LOADADDR x9, _g_serve_violation_hook
	ldr  x9, [x9]
	cbz  x9, .next
	blr  x9
	b    .next
.viol_mempool_go:
	LOADADDR x0, viol_mempool
	b    .viol_disconnect
.viol_invtx_go:
	LOADADDR x0, viol_invtx
	b    .viol_disconnect
.viol_txrelay_go:
	LOADADDR x0, viol_txrelay
.viol_disconnect:
	/* Core: fDisconnect, no misbehaviour score (net_processing "in violation
	 * of protocol" paths) -- log through C, then drop the connection */
	LOADADDR x9, _g_serve_policy_log
	ldr  x9, [x9]
	cbz  x9, .done
	blr  x9
	b    .done

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
	bl   _p2p_write
	b    .next

.do_inv:
	/* _serve_inv_bounds (daemon/serve_invbounds.c) parses the varint count
	 * and enforces MAX_INV_SZ (Core 50000); writing that parser in asm would
	 * only trade one subtle parser for another (x86 does the same).
	 *   w0 =  1 ok, 0 malformed/short (drop quietly),
	 *       -1 over MAX_INV_SZ: a protocol violation, score it. */
	LOADADDR x0, pl_buf
	LOADADDR x1, s_plen
	ldr  x1, [x1]
	LOADADDR x2, s_ivn
	LOADADDR x3, s_ivo
	bl   _serve_inv_bounds
	cmp  w0, #-1
	b.eq .inv_toobig
	cmp  w0, #0
	b.le .next                       /* malformed or short: drop quietly */
	/* relay policy: a tx inv from a peer that may not send us txs (-blocksonly
	 * without the relay permission) is a protocol violation (Core, x86 parity) */
	LOADADDR x9, _g_serve_inv_gate
	ldr  x9, [x9]
	cbz  x9, .inv_gate_ok
	LOADADDR x0, pl_buf
	LOADADDR x10, s_plen
	ldr  x1, [x10]
	blr  x9
	cmp  x0, #-1
	b.eq .viol_invtx_go
.inv_gate_ok:
	LOADADDR x9, s_ivn
	ldr  x9, [x9]
	LOADADDR x10, s_cnt
	str  x9, [x10]
	cbz  x9, .next
	LOADADDR x10, s_ptr
	LOADADDR x11, pl_buf
	LOADADDR x12, s_ivo
	ldr  x12, [x12]
	add  x11, x11, x12
	str  x11, [x10]                  /* s_ptr = pl_buf + s_ivo (past the varint) */
.LSV_inv_loop:
	LOADADDR x9, s_cnt
	ldr  x9, [x9]
	cbz  x9, .next
	LOADADDR x9, s_ptr
	ldr  x9, [x9]                     /* item ptr */
	ldr  w10, [x9]                    /* type */
	cmp  w10, #2                      /* MSG_BLOCK */
	b.eq .LSV_inv_block
	cmp  w10, #1                      /* MSG_TX  (2026-09-01: inbound peers' announcements are fetched
	                                  *          when relay policy allows -- _serve_inv_gate ran above) */
	b.eq .LSV_inv_txann
	cmp  w10, #5                      /* MSG_WTX (BIP339) */
	b.eq .LSV_inv_txann
	b    .LSV_inv_next
.LSV_inv_block:
	str  x9, [sp, #0]                 /* save item ptr across _idx_get */
	mov  x0, x22                      /* ht_idx */
	add  x1, x9, #4                   /* hash */
	LOADADDR x2, s_fh
	bl   _idx_get
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
	bl   _p2p_write
	ldr  x9, [sp, #0]
	b    .LSV_inv_next
.LSV_inv_txann:
	/* relay policy: we asked this peer for no relay (fRelay=0): ignore, do not fetch */
	LOADADDR x10, _node_relay_flag
	ldrb w10, [x10]
	cbz  w10, .LSV_inv_next
	ldr  x9, [sp, #0]
	/* no validation this connection: nothing to accept it into */
	LOADADDR x10, tx_dv_ok
	ldrb w10, [x10]
	cmp  w10, #1
	b.ne .LSV_inv_next
	ldr  w13, [x9]                    /* type u32 */
	cmp  w13, #1
	b.ne .LSV_inv_txann_req           /* a wtxid cannot be looked up by txid: just ask */
	/* already in the pool? _mpool_get(mp_cur, hash, &s_fh) */
	str  x9, [sp, #0]
	LOADADDR x0, mp_cur
	ldr  x0, [x0]
	add  x1, x9, #4
	LOADADDR x2, s_fh
	bl   _mpool_get
	ldr  x9, [sp, #0]
	cbnz x0, .LSV_inv_next            /* already have -> skip */
	/* ---- MEM-10 (audit 2026-09-03): have we already REFUSED this? ----
	 *
	 * Everything above answers "do we have it"; nothing answered "did we
	 * already decide no". So an inbound peer could announce the txid of a
	 * valid-signature, policy-rejected transaction once per second and every
	 * announcement was fetched and fully re-verified -- thousands of ECDSA and
	 * Schnorr checks each, in this serve child, which also takes _mp_lock for
	 * the policy pass. Core's AlreadyHaveTx consults m_recent_rejects before
	 * asking for anything.
	 *
	 * The filter holds FINAL verdicts only: a fee-only failure stays
	 * re-announceable, because a CPFP child can overturn it. It is shared
	 * across serve children, so one child's refusal spares all of them. */
	str  x9, [sp, #0]
	add  x0, x9, #4
	bl   _serve_reject_has
	ldr  x9, [sp, #0]
	cbnz x0, .LSV_inv_next            /* already refused: do not fetch it again */
.LSV_inv_txann_req:
	/* getdata: [1][type][hash]; MSG_TX is asked for as MSG_WITNESS_TX (0x40000001),
	 * MSG_WTX echoed (the getdata carries the wtxid) */
	LOADADDR x10, src_buf
	mov  w11, #1
	strb w11, [x10]
	movz w11, #0x0001
	movk w11, #0x4000, lsl #16        /* 0x40000001 */
	str  w11, [x10, #1]
	ldr  w13, [x9]                    /* type u32 */
	cmp  w13, #5
	b.eq 6f
	b    7f
6:	movz w11, #0x0005
	str  w11, [x10, #1]
7:	add  x0, x10, #5
	add  x1, x9, #4
	mov  x2, #32
	bl   .Ls_memcpy_len
	str  x9, [sp, #0]
	mov  x0, x19
	LOADADDR x1, cn_getdata
	mov  x2, #7
	LOADADDR x3, src_buf
	mov  x4, #37
	bl   _p2p_write
	ldr  x9, [sp, #0]
	b    .LSV_inv_next
.LSV_inv_next:
	add  x9, x9, #36
	LOADADDR x10, s_ptr
	str  x9, [x10]
	LOADADDR x10, s_cnt
	ldr  x9, [x10]
	sub  x9, x9, #1
	str  x9, [x10]
	b    .LSV_inv_loop
/* inv/getdata vector above MAX_INV_SZ: score it the way Core does
 * ("inv message size = %u"), then drop the message (x86 .inv_toobig). */
.inv_toobig:
	LOADADDR x9, _g_serve_violation_hook
	ldr  x9, [x9]
	cbz  x9, .next
	LOADADDR x0, viol_invsz
	blr  x9
	b    .next

.do_tx:
	/* relay policy first (x86 parity): -1 violation (disconnect), 1 drop
	 * quietly, 0 go on */
	LOADADDR x9, _g_serve_tx_gate
	ldr  x9, [x9]
	cbz  x9, .tx_gate_ok
	blr  x9
	cmp  x0, #-1
	b.eq .viol_txrelay_go
	cbnz x0, .next
.tx_gate_ok:
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #10
	b.lo .viol_tx_malformed       /* N3: too short to be a tx -> score, drop */
	/* _tx_txid(s_txid, pl_buf, s_plen, hp_buf, cap) */
	LOADADDR x0, s_txid
	LOADADDR x1, pl_buf
	LOADADDR x10, s_plen
	ldr  x2, [x10]
	LOADADDR x3, hp_buf
	movz x4, #0x7918                  /* 2000*81+8 = 162008 = 0x27918 */
	movk x4, #0x2, lsl #16
	bl   _tx_txid
	cbz  x0, .viol_tx_malformed   /* N3: does not parse -> score, drop */
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
	bl   _tx_accept_validate
	b    .next

.do_block:
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	cmp  x9, #81
	b.lo .viol_block_short        /* N3: shorter than a header -> score, drop */
	LOADADDR x0, pl_buf
	mov  x1, x9                       /* s_plen */
	LOADADDR x2, serve_txid_scratch
	movz x3, #SERVE_TXID_CAP_LO
	movk x3, #SERVE_TXID_CAP_HI, lsl #16
	bl   _cons_verify
	/* restore loop regs from statics (_cons_verify clobbers under x86 ABI) */
	LOADADDR x9, s_fd
	ldr  x19, [x9]
	LOADADDR x9, s_lfd
	ldr  x20, [x9]
	LOADADDR x9, s_st
	ldr  x21, [x9]
	LOADADDR x9, s_htidx
	ldr  x22, [x9]
	cbz  w0, .next
	/* _block_hash(hash@sb_buf+0x200000, pl_buf) */
	LOADADDR x0, sb_buf
	add  x0, x0, #0x200000
	LOADADDR x1, pl_buf
	bl   _block_hash
	/* duplicate? _idx_get(ht_idx, hash, &s_fh) */
	mov  x0, x22
	LOADADDR x1, sb_buf
	add  x1, x1, #0x200000
	LOADADDR x2, s_fh
	bl   _idx_get
	cbnz x0, .next
	/* chain gate: _store_validates_prevhash(st, pl_buf) */
	mov  x0, x21
	LOADADDR x1, pl_buf
	bl   _store_validates_prevhash
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
	bl   _node_log_event
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
	/* ---- NET-5 (audit 2026-09-03): the CONTEXTUAL header rules ----------
	 * Everything above this point is context-_free (_cons_verify: PoW against
	 * the header's own nBits, parses, coinbase, merkle root) plus "it extends
	 * our tip". Core also requires the nBits RETARGET SCHEDULE for this
	 * height, the median-time-past floor, the 2-hour future ceiling and the
	 * BIP34/66/65 version rules -- none of which were checked before the
	 * block was written to the durable archive. Consensus was not at risk
	 * (utxo_live.c re-checks the schedule at CONNECT), but the archive was: a
	 * header Core rejects became our tip at a height it can never connect at,
	 * and the node stalls behind it.
	 *
	 * Dropped, never scored -- same reasoning as the _cons_verify result
	 * above: our verifier is not the reference, so a false reject here must
	 * not ban an honest peer.
	 *
	 * _serve_block_ctx_ok(st, hdr80) -> 1 accept / 0 reject. Returns 1
	 * unchanged when the daemon has not armed the rules, so the hermetic
	 * serve suites and their synthetic chains are unaffected. */
	LOADADDR x0, s_st
	ldr  x0, [x0]
	LOADADDR x1, pl_buf
	bl   _serve_block_ctx_ok
	/* restore the loop's live registers from their stable statics, exactly as
	 * the _cons_verify and _store_validates_prevhash calls above already do */
	LOADADDR x9, s_fd
	ldr  x19, [x9]
	LOADADDR x9, s_lfd
	ldr  x20, [x9]
	LOADADDR x9, s_st
	ldr  x21, [x9]
	LOADADDR x9, s_htidx
	ldr  x22, [x9]
	cbz  w0, .next
	/* _idxscan_append_locked(st, hash, pl_buf, s_plen) */
	mov  x0, x21
	LOADADDR x1, sb_buf
	add  x1, x1, #0x200000
	LOADADDR x2, pl_buf
	LOADADDR x9, s_plen
	ldr  x3, [x9]
	bl   _idxscan_append_locked
	cmp  x0, #0
	b.le .next
	LOADADDR x9, s_lastheight
	str  x0, [x9]
	/* _idx_put(ht_idx, hash, height) */
	mov  x0, x22
	LOADADDR x1, sb_buf
	add  x1, x1, #0x200000
	ldr  x2, [x9]
	bl   _idx_put
	/* _log_block_stored_inbound(hash, height, plen, pl_buf) */
	LOADADDR x0, sb_buf
	add  x0, x0, #0x200000
	LOADADDR x9, s_lastheight
	ldr  x1, [x9]
	LOADADDR x9, s_plen
	ldr  x2, [x9]
	LOADADDR x3, pl_buf
	bl   _log_block_stored_inbound
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
	/* Core answers getaddr ONCE per connection and ignores repeats
	 * (m_getaddr_recvd: "reduce resource waste") */
	LOADADDR x9, s_addrsent
	ldrb w9, [x9]
	cbnz w9, .next
	LOADADDR x9, s_addrsent
	mov  w10, #1
	strb w10, [x9]
	/* The reply is built in C from the version-2 book (daemon/serve_addr.c,
	 * every BIP155 network) -- this loop used to read the legacy IPv4-only
	 * peers.dat book, which the negotiation tests never populate (x86
	 * parity: the asm serve.asm was rewritten the same way). */
	mov  x0, x19                      /* fd */
	adrp x1, _g_peer_wants_addrv2@PAGE
	add  x1, x1, _g_peer_wants_addrv2@PAGEOFF
	ldr  w1, [x1]
	bl   _serve_getaddr
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
	bl   _serve_idx_topup
	LOADADDR x10, s_nf
	str  xzr, [x10]                   /* no misses yet for this getdata */
	/* NET-7 (audit 2026-09-03): parse the count as a real CompactSize,
	 * bounded against the payload, exactly as .inv does via the shared
	 * _serve_inv_bounds helper. The count used to be pl_buf[0] with only
	 * plen >= 37 checked. Two consequences: Core's MAX_GETDATA_SZ is 1000,
	 * so a request for 253 or more transactions starts with 0xfd, which was
	 * read as the count 253 and left every entry misaligned by two bytes --
	 * we answered ~50 notfounds for garbage hashes and served nothing. And
	 * a 37-byte getdata with count byte 0xff walked up to 255 entries out
	 * of whatever an earlier, larger message left in the 8 MB receive
	 * buffer -- the peer-steered nonsense serve_invbounds.c was written to
	 * stop.   x0 = 1 ok, 0 malformed/short (drop), -1 over MAX_INV_SZ. */
	LOADADDR x0, pl_buf
	LOADADDR x9, s_plen
	ldr  x1, [x9]
	LOADADDR x2, s_ivn
	LOADADDR x3, s_ivo
	bl   _serve_inv_bounds
	cmp  x0, #-1
	b.eq .gd_toobig
	cmp  x0, #1
	b.lt .next			/* malformed or short: drop quietly, as inv does */
	LOADADDR x9, s_ivn
	ldr  x10, [x9]
	LOADADDR x11, s_cnt
	str  x10, [x11]			/* item counter (validated entry count) */
	LOADADDR x9, s_ivo
	ldr  x10, [x9]
	LOADADDR x11, pl_buf
	add  x10, x10, x11
	LOADADDR x11, s_ptr
	str  x10, [x11]			/* first entry (past the real CompactSize) */
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
	bl   _idx_get
	ldr  x9, [sp, #0]
	cbz  x0, .gd_miss
	str  x9, [sp, #0]                 /* s_ptr */
	mov  x0, x21
	LOADADDR x1, s_fh
	ldr  x1, [x1]
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   _node_serve_block
	ldr  x9, [sp, #0]
	cmp  x0, #0
	b.le .gd_miss
	LOADADDR x10, s_blen_spill
	str  x0, [x10]
	/* ---- NET-14 (audit 2026-09-03): a FRESH nonce per block ----
	 * This was the constant 0x0123456789abcdef, drawn once and then cached in
	 * s_cmpct_nonce for the life of the connection -- so every compact block
	 * this node ever served used the same SipHash key. Core draws a fresh
	 * nonce for every CBlockHeaderAndShortTxIDs precisely so an adversary
	 * cannot precompute transactions whose 6-byte short ids collide: with a
	 * predictable nonce they can be planted in receivers' mempools ahead of
	 * time, forcing reconstruction to fail and every peer we serve to fall
	 * back to a full block.
	 *
	 * getrandom(2) inline rather than a helper: bitcoin_net.o/bitcoin_serve.o
	 * are linked into sixty-odd targets and this file goes out of its way not
	 * to add link dependencies (see the v2 dispatch table). The syscall
	 * clobbers nothing that is live here; the loop's stable statics and sp
	 * slots are untouched.
	 *
	 * If getrandom is unavailable the fallback is CNTVCT_EL0 (the ARM generic
	 * counter; the x86 fallback is rdtsc), which is at least not a compile-
	 * time constant. `orr x0,x0,#1` keeps it nonzero: a zero nonce is what
	 * the old code used as its "unset" sentinel and test_bip152_loop still
	 * asserts the served nonce is nonzero. */
	LOADADDR x0, s_cmpct_nonce
	mov  x1, #8
	mov  x2, #0
	bl _bmcshim_getrandom          /* Darwin: arc4random_buf */
	b .gc_nonce_rdy
	mrs  x0, cntvct_el0                /* fallback: never a fixed constant */
	orr  x0, x0, #1
	LOADADDR x10, s_cmpct_nonce
	str  x0, [x10]
.gc_nonce_rdy:
	LOADADDR x10, s_cmpct_nonce
	ldr  x11, [x10]
	cbnz x11, 7f
	mov  x11, #1                       /* never hand _cmpctblock_build a zero nonce */
	str  x11, [x10]
7:	str  x9, [sp, #0]
	LOADADDR x0, bt_buf
	LOADADDR x1, sb_buf
	LOADADDR x10, s_blen_spill
	ldr  x2, [x10]
	mov  x3, x11                       /* nonce */
	bl   _cmpctblock_build
	ldr  x9, [sp, #0]
	cmp  x0, #0
	b.le .gd_miss
	mov  x4, x0                       /* cmpctblock len */
	str  x9, [sp, #0]
	mov  x0, x19
	LOADADDR x1, cn_cmpct
	mov  x2, #10
	LOADADDR x3, bt_buf
	bl   _p2p_write
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
	bl   _idx_get
	ldr  x9, [sp, #0]
	cbz  x0, .gd_miss
	str  x9, [sp, #0]
	mov  x0, x21
	LOADADDR x1, s_fh
	ldr  x1, [x1]
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   _node_serve_block
	ldr  x9, [sp, #0]
	cmp  x0, #0
	b.le .gd_miss
	/* ---- STO-10 (audit 2026-09-03): SERVE THE BLOCK THAT WAS ASKED FOR ---
	 * ht_idx maps hash -> height and was built when this process started.
	 * _serve_idx_topup only ADDS heights >= g_htidx_next, so a child forked
	 * before a reorg still maps the LOSING branch's hashes to fork+1..old_tip
	 * and never learns the replacements. The lookup above then succeeds with a
	 * stale height and _node_serve_block happily returns whatever block now
	 * occupies it -- the WRONG block for the requested hash. Core drops a
	 * block it did not request and may score the peer for it.
	 *
	 * Hashing the block we are about to send and comparing it to the requested
	 * hash makes that impossible, whatever the index believes. It is the
	 * audit's second suggestion rather than its first (a generation counter in
	 * shared status) because it is FAIL-CLOSED and self-contained: it needs no
	 * cross-process protocol, and it also catches an index/archive
	 * disagreement arising from anything other than a reorg. */
	str  x9, [sp, #0]
	LOADADDR x10, s_gdlen
	str  x0, [x10]                     /* _node_serve_block's length, across the call */
	LOADADDR x0, s_gdbh
	LOADADDR x1, sb_buf
	bl   _block_hash
	ldr  x9, [sp, #0]
	LOADADDR x10, s_gdlen
	ldr  x0, [x10]
	/* memcmp(s_gdbh, entry+4, 32) -- four qword compares, no call */
	LOADADDR x10, s_gdbh
	ldr  x11, [x10]
	ldr  x12, [x9, #4]
	cmp  x11, x12
	b.ne .gd_miss
	ldr  x11, [x10, #8]
	ldr  x12, [x9, #12]
	cmp  x11, x12
	b.ne .gd_miss
	ldr  x11, [x10, #16]
	ldr  x12, [x9, #20]
	cmp  x11, x12
	b.ne .gd_miss
	ldr  x11, [x10, #24]
	ldr  x12, [x9, #28]
	cmp  x11, x12
	b.ne .gd_miss
	mov  x4, x0                        /* block len */
	str  x9, [sp, #0]
	mov  x0, x19
	LOADADDR x1, cn_block
	mov  x2, #5
	LOADADDR x3, sb_buf
	bl   _p2p_write
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
	bl   _mpool_get
	ldr  x9, [sp, #0]
	cbz  x0, .gd_miss
	mov  x3, x0                        /* tx bytes ptr (mpool blob) */
	/* ---- MEM-24 (audit 2026-09-03): serve the FORM that was requested ------
	 * A bare MSG_TX (witness bit 0x40000000 CLEAR) asks for the non-witness
	 * serialization; Core sends TX_NO_WITNESS for it. This arm served the
	 * stored witness bytes whatever was asked, which a strict pre-segwit peer
	 * cannot parse. The BLOCK arm below has always got this right -- see
	 * .gd_block's identical witness-bit test -- so the two agree now.
	 * A strip failure serves NOTHING (never the wrong form), as the block arm
	 * also does. */
	ldr  w10, [x9]                     /* the inv entry's type u32 */
	tbnz w10, #30, .gdtx_have          /* witness requested: the stored form is right */
	str  x9, [sp, #0]
	mov  x0, x3                        /* tx */
	LOADADDR x1, s_n
	ldr  x1, [x1]                      /* txlen */
	LOADADDR x2, bt_buf                /* out (_free in this arm, as in .gd_block) */
	movz x3, #0x0000
	movk x3, #0x0080, lsl #16          /* 8<<20 */
	bl   _strip_witness
	ldr  x9, [sp, #0]
	cmp  x0, #0
	b.le .gd_miss                      /* strip failed -> notfound */
	LOADADDR x10, s_n
	str  x0, [x10]                     /* stripped length */
	LOADADDR x3, bt_buf
.gdtx_have:
	str  x9, [sp, #0]
	mov  x0, x19
	LOADADDR x1, cn_tx
	mov  x2, #2
	LOADADDR x4, s_n
	ldr  x4, [x4]
	bl   _p2p_write
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
	bl   _p2p_write
	b    .next
/* getdata vector above MAX_INV_SZ: score it the way Core does -- the same
 * violation hook and the same reason string as .inv_toobig, because it is
 * the same protocol rule on a sibling message (x86 .gd_toobig). */
.gd_toobig:
	LOADADDR x9, _g_serve_violation_hook
	ldr  x9, [x9]
	cbz  x9, .next
	LOADADDR x0, viol_invsz
	blr  x9
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
	/* _serve_cfilters(fd, kind, pl_buf, plen) */
	mov  x0, x19
	mov  w1, w11
	LOADADDR x2, pl_buf
	LOADADDR x3, s_plen
	ldr  x3, [x3]
	bl   _serve_cfilters
	b    .next

.maybe_getheaders:
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #3]
	mov  w10, #0x6568
	movk w10, #0x6461, lsl #16        /* "head" at cmd[3] (0x64616568 LE) */
	cmp  w9, w10
	b.ne .next
	LOADADDR x9, s_cmd
	ldr  w9, [x9, #7]
	mov  w10, #0x7265
	movk w10, #0x0073, lsl #16        /* "ers\0" at cmd[7] (0x00737265 LE) */
	cmp  w9, w10
	b.ne .next
	LOADADDR x9, s_plen
	ldr  x9, [x9]
	/* NET-8 (audit 2026-09-03): walk the WHOLE locator, honour hashStop.
	 * This used to look up pl+5 -- the FIRST locator hash -- and serve from
	 * height 0 on a miss, ignoring every other entry and the stop hash, with
	 * only plen >= 5 checked (so a 5-byte message read a stale hash out of
	 * the receive buffer). Every peer one block ahead of us starts its
	 * locator with a hash we do not have -- so each getheaders was answered
	 * with 2000 headers from genesis, 162 KB, that a Core peer discards as
	 * already known.
	 * _serve_locator_from does the CompactSize, the bounds and the walk
	 * (Core's FindForkInGlobalIndex), in C for the same reason
	 * _serve_inv_bounds is: hand-writing a second varint walk in assembly is
	 * how the first one went wrong.   x0 = 1 ok / 0 malformed. */
	LOADADDR x0, pl_buf
	LOADADDR x9, s_plen
	ldr  x1, [x9]
	mov  x2, x22                      /* htidx */
	LOADADDR x3, s_fh		/* out_from */
	LOADADDR x4, s_ghstop		/* out_stop (-1 = none/unknown) */
	bl   _serve_locator_from
	cbz  x0, .next			/* malformed: drop, as the inv path does */
.gh_build:
	ldr  w9, [x21, #24]               /* tip = st[24] */
	LOADADDR x10, s_cnt
	str  x9, [x10]
	/* NET-8: hashStop, when it names a height we hold, caps the range Core
	 * would send. Only ever LOWERS the bound -- a stop above our tip is not
	 * a request to invent headers. */
	LOADADDR x9, s_ghstop
	ldr  x10, [x9]
	cmp  x10, #0
	b.lt .gh_nostop
	LOADADDR x11, s_cnt
	ldr  x11, [x11]
	cmp  x10, x11
	b.hs .gh_nostop
	str  x10, [x11]
.gh_nostop:
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
	/* _node_serve_block(st, h, sb_buf, cap) */
	mov  x0, x21
	LOADADDR x9, s_fh
	ldr  x1, [x9]
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   _node_serve_block
	cmp  x0, #0
	b.le .LSV_ghh_done
	/* _memcpy(hp_buf+p, sb_buf, 80) */
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
	bl   _p2p_write
	/* _node_log_event(lfd, 6, n, from, 0) */
	mov  x0, x20
	mov  x1, #6
	LOADADDR x10, s_n
	ldr  x2, [x10]
	LOADADDR x11, s_plen
	ldr  x3, [x11]
	mov  x4, #0
	bl   _node_log_event
	b    .next
.gh_empty:
	LOADADDR x9, hp_buf
	strb wzr, [x9]
	mov  x0, x19
	LOADADDR x1, cn_head
	mov  x2, #7
	LOADADDR x3, hp_buf
	mov  x4, #1
	bl   _p2p_write
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
	mov  w10, #0x6f6c
	movk w10, #0x6b63, lsl #16        /* "lock" at cmd[4] (0x6b636f6c LE) */
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
	bl   _idx_get
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
	bl   _node_serve_block
	cmp  x0, #0
	b.le .gb_done
	/* _block_hash(hash, sb_buf) */
	LOADADDR x0, sb_buf
	add  x0, x0, #0x200000
	LOADADDR x1, sb_buf
	bl   _block_hash
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
	bl   _p2p_write
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
	bl   _p2p_write
	b    .next

.maybe_sendcmpct:
	LOADADDR x9, s_cmd
	ldrb w9, [x9, #4]
	cmp  w9, #'h'
	b.eq .do_sendheaders
	cmp  w9, #'a'
	b.eq .done            /* "sendaddrv2" after verack: handshake-only; Core disconnects */
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
	mov  w10, #0x6c69
	movk w10, #0x0074, lsl #16        /* "ilt\0" at cmd[4] (0x00746c69 LE) */
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
	/* NET-1 fix (audit 2026-09-03, x86 80f03d4): every byte this path parses
	 * is attacker-chosen. The old code read varint bytes with no bound
	 * against the payload length (a short message parsed stale bytes from
	 * earlier traffic in pl_buf) and wrote one u16 per count into s_idxbuf
	 * (512 entries) with no capacity check -- count 0xffff wrote 65535 u16 =
	 * 131 KB over .bss. Core caps each index at MAX_SIZE and
	 * Misbehaving(100)s req.indexes.size() > block.vtx.size(). Our
	 * equivalent, enforced BEFORE the block is even looked up (a peer may
	 * probe our store inventory for _free; it may not spray past it): the
	 * count must fit s_idxbuf, every varint byte must lie inside the
	 * announced payload, malformed diff forms score the peer, and any
	 * breach answers nothing. The parse bound lives in x16 across the loop
	 * (no calls happen inside the parse); the writer bound below lives in
	 * the s_btend slot because the tx loop makes calls. */
	LOADADDR x10, pl_buf
	add  x16, x10, x9                 /* payload end = pl_buf + s_plen */
	add  x10, x10, #32                /* cursor: count varint */
	add  x9, x10, #1
	cmp  x9, x16
	b.hi .gbkt_done                   /* payload ends before the count byte */
	ldrb w11, [x10]                   /* count varint */
	cmp  w11, #0xfd
	b.hs .gbtx_bigcnt
	add  x10, x10, #1
	mov  x12, x11                      /* count (1-byte form) */
	b    .gbtx_cnthave
.gbtx_bigcnt:
	cmp  w11, #0xfd
	b.ne .gbkt_done                    /* 0xfe/0xff unsupported form -> bail */
	add  x9, x10, #3
	cmp  x9, x16
	b.hi .gbkt_done                    /* 3-byte varint runs past the payload */
	ldrh w12, [x10, #1]
	add  x10, x10, #3
.gbtx_cnthave:
	/* count must fit s_idxbuf (512 entries; the same cap Core's MAX_SIZE +
	 * ProcessGetBlockTxn enforcement imposes on a real block). Oversize ->
	 * score the peer (x86 .gbkt_viol). s_idxn/s_diffshift are initialised
	 * only after this check, matching the x86 layout. */
	cmp  x12, #512
	b.hi .gbkt_viol
	LOADADDR x9, s_idxn
	str  xzr, [x9]
	LOADADDR x9, s_diffshift
	str  xzr, [x9]
.LSV_gbtx_idxloop:
	cbz  x12, .gbtx_parsed
	/* diff varint at x10 -- bounded against the payload first */
	add  x9, x10, #1
	cmp  x9, x16
	b.hi .gbkt_viol                    /* diff byte runs past the payload */
	ldrb w13, [x10]
	cmp  w13, #0xfd
	b.lo .gbtx_d1
	cmp  w13, #0xfd
	b.ne .gbkt_viol                    /* 0xfe/0xff form is malformed here */
	add  x9, x10, #3
	cmp  x9, x16
	b.hi .gbkt_viol                    /* 3-byte diff runs past the payload */
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
.gbtx_parsed:
	/* ---- vector is well-formed; NOW look the block up ----
	 * _node_serve_block_by_hash(st, pl_buf, sb_buf, cap) */
	mov  x0, x21
	LOADADDR x1, pl_buf
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   _node_serve_block_by_hash
	LOADADDR x9, s_blen_spill
	str  x0, [x9]
	cmp  x0, #0
	b.le .next                         /* not our block -> answer nothing (not scored) */
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
	/* _block_tx_at(sb_buf, blen, idx, &s_txptr, &s_txlen) */
	LOADADDR x0, sb_buf
	LOADADDR x1, s_blen_spill
	ldr  x1, [x1]
	LOADADDR x3, s_txptr
	LOADADDR x4, s_txlen
	bl   _block_tx_at
	cbz  x0, .gbkt_done
	/* _memcpy(bt_buf+s_p, s_txptr, s_txlen) */
	LOADADDR x9, s_p
	ldr  x9, [x9]
	LOADADDR x10, s_txlen
	ldr  x2, [x10]
	/* NET-1: the append must fit bt_buf -- check s_p + s_txlen against
	 * s_btend (dst >= bt_buf is automatic; s_txlen comes from _block_tx_at
	 * so it is sane) before a single byte is written. */
	add  x9, x9, x2
	LOADADDR x10, bt_buf
	add  x9, x9, x10                   /* abs one-past-write address */
	LOADADDR x10, s_btend
	ldr  x10, [x10]
	cmp  x9, x10
	b.hi .gbkt_done                    /* would overrun the assembly buffer */
	LOADADDR x9, s_p
	ldr  x9, [x9]
	LOADADDR x10, bt_buf
	add  x0, x10, x9
	LOADADDR x1, s_txptr
	ldr  x1, [x1]
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
	bl   _p2p_write
	LOADADDR x9, s_served
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	b    .next
.gbkt_done:
	b    .next
/* NET-1: a malformed or over-capacity getblocktxn index vector. Core answers
 * Misbehaving(100) ("getblocktxn with out-of-bounds tx indices") and sends
 * nothing; we score via the shared violation hook and stay silent, like the
 * other parse-failure classes. x0 = reason, tail shared with
 * .viol_report_next. */
.gbkt_viol:
	LOADADDR x0, viol_gbtidx
	b    .viol_report_next

.next:
	/* tip-watch: announce a newly-advanced tip exactly once */
	ldr  w9, [x21, #24]               /* tip */
	LOADADDR x10, s_cnt
	str  x9, [x10]
	LOADADDR x10, s_lasttip
	ldr  x11, [x10]
	cmp  x11, x9
	b.ge .tw_done
	/* _node_announce_tip(fd, st, ht_idx, use_headers) */
	mov  x0, x19
	mov  x1, x21
	mov  x2, x22
	LOADADDR x9, s_shdr
	ldr  x3, [x9]
	bl   _node_announce_tip
	LOADADDR x10, s_lasttip
	LOADADDR x11, s_cnt
	ldr  x11, [x11]
	str  x11, [x10]
.tw_done:
	b    .outer
/* A -3 from _p2p_read means the peer announced a message above P2P_MAX_MSG --
 * a protocol violation, not an ordinary disconnect. Score it before dropping
 * so a peer that does it repeatedly earns a ban (x86 .check_viol). Any other
 * <=0 just exits the loop. The hook is a C function pointer: sp is still
 * 16-aligned here (96-byte reservation on top of the 64-byte save area). */
.check_viol:
	cmp  x0, #-3
	b.ne .done
	LOADADDR x9, _g_serve_violation_hook
	ldr  x9, [x9]
	cbz  x9, .done
	LOADADDR x0, viol_oversize
	blr  x9
	b    .done
.done:
	LOADADDR x9, s_served
	ldr  x0, [x9]
	add  sp, sp, #96
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

/* ============================================================================
 * _node_announce_tip(fd, st, ht_idx, use_headers) -> 1/0
 * ========================================================================== */
	.globl _node_announce_tip
_node_announce_tip:
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
	/* _node_serve_block(st, tip, sb_buf, cap) */
	mov  x0, x20
	mov  x1, x21
	LOADADDR x2, sb_buf
	mov  x3, #(8<<20)
	bl   _node_serve_block
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
	bl   _p2p_write
	cmp  x0, #0
	b.le .at_fail
	mov  x0, #1
	b    .at_done
.at_inv:
	/* inv: _block_hash(hash, sb_buf) */
	LOADADDR x0, sb_buf
	add  x0, x0, #0x200000
	LOADADDR x1, sb_buf
	bl   _block_hash
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
	bl   _p2p_write
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

/* serve-violation hook (x86 bitcoin_serve.asm): NULL by default, filled by
        .section __DATA,__data
	.align 3
	.quad 0

/* ---- relay-policy gates (x86 2026-09-01 parity, commit e8adcca): NULL =
 * old behaviour. daemon/main.c installs the relay_policy hooks at boot. */



	.section __DATA,__data
	.globl _g_serve_violation_hook
_g_serve_violation_hook:
	.quad 0      /* void (*)(const char* reason); NULL = nobody registered */
	.globl _g_serve_tx_gate
_g_serve_tx_gate:
	.quad 0      /* int (*)(void): 0 accept, 1 drop, -1 violation */
	.globl _g_serve_inv_gate
_g_serve_inv_gate:
	.quad 0      /* int (*)(const u8* pl, long plen) */
	.globl _g_serve_mempool_hook
_g_serve_mempool_hook:
	.quad 0      /* int (*)(int fd, void* mp): 1 handled, -1 violation */
	.globl _g_serve_policy_log
_g_serve_policy_log:
	.quad 0      /* void (*)(const char* reason) */
	.globl _g_serve_send_feefilter
_g_serve_send_feefilter:
	.byte 1      /* -blocksonly / forcerelay peer: Core sends none */
