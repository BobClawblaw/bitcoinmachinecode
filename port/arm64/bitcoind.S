/* ============================================================================
 * bitcoind.S -- AArch64 (ARMv8-A) port of asm/bitcoind.asm
 * Node daemon orchestration: handshakes, headers-first sync/IBD, block serve,
 * per-peer drain loop. All network I/O via the ported bitcoin_net.S /
 * bitcoin_p2p.S / bitcoin_headers.S / bitcoin_store.S primitives and raw Linux
 * AArch64 syscalls (lseek=62 read=63).
 *
 * AAPCS64: SysV amd64 rdi..r9 -> x0..x5; extra args in x6,x7 then stack.
 *   node_make_version(out=x0)                      -> len
 *   node_handshake(fd=x0)                          -> 1/0
 *   node_accept_handshake(fd=x0)                   -> 1/0
 *   node_sync(x0..x5) -> b node_sync_multi (tail)
 *   node_sync_multi(fd,st,locator,count,buf,buflen,out_count=x6) -> 1/0
 *   node_serve_block(st,height,out_buf,cap)        -> len/-1
 *   node_serve_block_by_hash(st,hash32,out_buf,cap)-> len/-1
 *   node_drain(fd,st,buf,buflen)                   -> #blocks/-1
 *   node_fetch_headers(fd,locator,count,stop,out_buf,&cnt) -> 1/0
 *   node_ibd_headers(fd,hst,locator32,page_buf,buflen)   -> total/-1
 *   node_ibd_blocks(fd,st,hst,start_h,buf,buflen)        -> #blocks/-1
 *   node_ibd_blocks_x(fd,st,hst,start,end,buf,buflen,scratch,scratch_cap) -> #/-1
 *   node_ibd_blocks_s(fd,st,hst,lo_real,nloc,buf,buflen,scratch,scratch_cap) -> #/-1
 *   node_ibd(fd,st,hst,buf,buflen)                 -> #blocks/-1
 *
 * Wire identity mirrors version.inc (the single source of truth): protocol
 * 70016, UA "/BitcoinMachineCode:0.0.1/" (len 24). Total version payload 110B.
 * ========================================================================== */

	.extern p2p_write
	.extern p2p_read
	.extern p2p_getheaders
	.extern p2p_getdata_block
	.extern p2p_headers_count
	.extern block_hash
	.extern cons_verify
	.extern store_append
	.extern idxscan_append_locked
	.extern store_get_at
	.extern store_get_file_fd
	.extern hst_append
	.extern hst_get_at
	.extern hst_count
	.extern store_append_shared

	.text

	.equ SYNC_TXID_CAP, 80000

/* ============================================================================
 * .Lcmpeq(a=x0, b=x1, n=x2) -> x0 1/0. Leaf; clobbers x0..x5.
 * ========================================================================== */
	.type .Lcmpeq, %function
.Lcmpeq:
	mov  x3, #0
1:	cmp  x3, x2
	b.hs 2f
	ldrb w4, [x0, x3]
	ldrb w5, [x1, x3]
	cmp  w4, w5
	b.ne 3f
	add  x3, x3, #1
	b    1b
2:	mov  x0, #1
	ret
3:	mov  x0, #0
	ret
	.size .Lcmpeq, .-.Lcmpeq

/* ============================================================================
 * .Lcopy(dst=x0, src=x1, n=x2). Leaf; clobbers x3,x4.
 * ========================================================================== */
	.type .Lcopy, %function
.Lcopy:
	mov  x3, #0
1:	cmp  x3, x2
	b.hs 2f
	ldrb w4, [x1, x3]
	strb w4, [x0, x3]
	add  x3, x3, #1
	b    1b
2:	ret
	.size .Lcopy, .-.Lcopy

/* ============================================================================
 * node_make_version(out=x0) -> len
 * ========================================================================== */
	.global node_make_version
	.type node_make_version, %function
node_make_version:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	mov  x19, x0                     /* cursor base */
	/* protocol version 70016 = 0x11180 */
	movz w1, #0x1180
	movk w1, #0x1, lsl #16
	str  w1, [x19, #0]
	/* services = NODE_NETWORK(1)|NODE_WITNESS(8) = 9 */
	mov  x2, #9
	str  x2, [x19, #4]
	/* timestamp 1700000000 = 0x6553F100 */
	movz x3, #0xF100
	movk x3, #0x6553, lsl #16
	str  x3, [x19, #12]
	/* addr_recv[26] at +20: zeros then port at +44 (0x8d20 = bytes 20 8d) */
	mov  x4, x19
	add  x4, x4, #20
	mov  x5, #26
	mov  x0, x4
	mov  x1, x5
	/* zero 26 bytes */
	mov  w0, #0
1:	cmp  x5, #0
	b.eq 2f
	strb w0, [x4]
	add  x4, x4, #1
	sub  x5, x5, #1
	b    1b
2:	mov  w6, #0x8d20
	strh w6, [x19, #44]
	/* addr_from[26] at +46: zeros then port at +70 */
	mov  x4, x19
	add  x4, x4, #46
	mov  x5, #26
3:	cmp  x5, #0
	b.eq 4f
	strb w0, [x4]
	add  x4, x4, #1
	sub  x5, x5, #1
	b    3b
4:	strh w6, [x19, #70]
	/* nonce at +72 */
	movz x7, #0x7788
	movk x7, #0x5566, lsl #16
	movk x7, #0x3344, lsl #32
	movk x7, #0x1122, lsl #48
	str  x7, [x19, #72]
	/* user_agent varstr at +80: len byte + UA bytes (len 26) */
	mov  w8, #26
	strb w8, [x19, #80]
	add  x0, x19, #81                 /* dst = out+81 */
	adrp x1, ua_str
	add  x1, x1, :lo12:ua_str         /* src = ua string */
	mov  x2, #26
	bl   .Lcopy
	/* start_height u32 + relay byte at +81+26 */
	mov  x1, x19
	add  x1, x1, #107
	str  wzr, [x1, #0]
	mov  w2, #1
	strb w2, [x1, #4]
	mov  x0, #112                    /* 81 + 26 + 5 */
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_make_version, .-node_make_version

/* ============================================================================
 * node_handshake(fd=x0) -> 1/0
 * ========================================================================== */
	.global node_handshake
	.type node_handshake, %function
node_handshake:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #432
	/* locals: ver_payload@0 (128), plen@144(4), cmd@160(12), payload@192(256) */
	mov  x19, x0                     /* fd */
	/* build + send version */
	mov  x0, sp
	bl   node_make_version
	mov  x20, x0                     /* len */
	mov  x0, x19
	adrp x1, _version
	add  x1, x1, :lo12:_version
	mov  x2, #7
	mov  x3, sp
	mov  x4, x20
	bl   p2p_write
	cmp  x0, #24
	b.lt .NHfail
.LNHread:
	mov  x0, x19
	add  x1, sp, #160                /* cmd */
	add  x2, sp, #192                /* payload */
	mov  x3, #256
	add  x4, sp, #144                /* plen */
	bl   p2p_read
	cmp  x0, #0
	b.le .NHfail
	/* is it "version"? */
	add  x0, sp, #160
	adrp x1, _version
	add  x1, x1, :lo12:_version
	mov  x2, #7
	bl   .Lcmpeq
	cbz  x0, .LNH_not_version
	/* capture peer payload (side-effect only) */
	ldr  w0, [sp, #144]
	cmp  x0, #256
	b.ls 5f
	mov  x0, #256
5:	adrp x1, g_peer_version_len
	add  x1, x1, :lo12:g_peer_version_len
	str  x0, [x1]
	mov  x2, x0                        /* n = capped plen */
	adrp x1, g_peer_version_payload
	add  x1, x1, :lo12:g_peer_version_payload
	mov  x0, x1                        /* dst = payload */
	add  x1, sp, #192                  /* src */
	bl   .Lcopy
.LNH_not_version:
	/* is it "verack"? */
	add  x0, sp, #160
	adrp x1, _verack
	add  x1, x1, :lo12:_verack
	mov  x2, #6
	bl   .Lcmpeq
	cbnz x0, .LNH_send_verack
	/* is it "ping"? */
	add  x0, sp, #160
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LNHread
	/* echo pong */
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	add  x3, sp, #192
	mov  x4, #8
	bl   p2p_write
	b    .LNHread
.LNH_send_verack:
	mov  x0, x19
	adrp x1, _verack
	add  x1, x1, :lo12:_verack
	mov  x2, #6
	mov  x3, #0
	mov  x4, #0
	bl   p2p_write
	mov  w0, #1
	b    .NHret
.NHfail:
	mov  w0, #0
.NHret:
	add  sp, sp, #432
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_handshake, .-node_handshake

/* ============================================================================
 * node_accept_handshake(fd=x0) -> 1/0 (inbound/server role)
 * ========================================================================== */
	.global node_accept_handshake
	.type node_accept_handshake, %function
node_accept_handshake:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #1024
	/* cmd@0 (12), plen@16(4), ourver@32(128), recv@192(256) */
	mov  x19, x0                     /* fd */
.LAHloop:
	mov  x0, x19
	add  x1, sp, #0                  /* cmd */
	add  x2, sp, #192                /* recv */
	mov  x3, #256
	add  x4, sp, #16                 /* plen */
	bl   p2p_read
	cmp  x0, #0
	b.le .LAHfail
	add  x0, sp, #0
	adrp x1, _version
	add  x1, x1, :lo12:_version
	mov  x2, #7
	bl   .Lcmpeq
	cbnz x0, .LAH_got_version
	add  x0, sp, #0
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LAHloop
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	add  x3, sp, #192
	mov  x4, #8
	bl   p2p_write
	b    .LAHloop
.LAH_got_version:
	ldr  w0, [sp, #16]
	cmp  x0, #256
	b.ls 6f
	mov  x0, #256
6:	adrp x1, g_peer_version_len
	add  x1, x1, :lo12:g_peer_version_len
	str  x0, [x1]
	mov  x2, x0                        /* n = capped plen */
	adrp x1, g_peer_version_payload
	add  x1, x1, :lo12:g_peer_version_payload
	mov  x0, x1                        /* dst = payload */
	add  x1, sp, #192                  /* src */
	bl   .Lcopy
	/* build + send our version reply */
	add  x0, sp, #32
	bl   node_make_version
	mov  x20, x0
	mov  x0, x19
	adrp x1, _version
	add  x1, x1, :lo12:_version
	mov  x2, #7
	add  x3, sp, #32
	mov  x4, x20
	bl   p2p_write
	cmp  x0, #24
	b.lt .LAHfail
	/* send our verack */
	mov  x0, x19
	adrp x1, _verack
	add  x1, x1, :lo12:_verack
	mov  x2, #6
	mov  x3, #0
	mov  x4, #0
	bl   p2p_write
.LAHread_verack:
	mov  x0, x19
	add  x1, sp, #0
	add  x2, sp, #192
	mov  x3, #256
	add  x4, sp, #16
	bl   p2p_read
	cmp  x0, #0
	b.le .LAHfail
	add  x0, sp, #0
	adrp x1, _verack
	add  x1, x1, :lo12:_verack
	mov  x2, #6
	bl   .Lcmpeq
	cbnz x0, .LAHok
	add  x0, sp, #0
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LAHread_verack
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	add  x3, sp, #192
	mov  x4, #8
	bl   p2p_write
	b    .LAHread_verack
.LAHok:
	mov  w0, #1
	b    .LAHret
.LAHfail:
	mov  w0, #0
.LAHret:
	add  sp, sp, #1024
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_accept_handshake, .-node_accept_handshake

/* ============================================================================
 * node_sync(fd, st, locator, buf, buflen, out_count) -> tail-call node_sync_multi
 * ========================================================================== */
	.global node_sync
	.type node_sync, %function
node_sync:
	/* x0=fd x1=st x2=locator x3=buf x4=buflen x5=out_count
	   node_sync_multi: x0=fd x1=st x2=locator x3=loc_count x4=buf x5=buflen x6=out_count */
	mov  x6, x5
	mov  x5, x4
	mov  x4, x3
	mov  x3, #1
	b    node_sync_multi
	.size node_sync, .-node_sync

/* ============================================================================
 * node_sync_multi(fd, st, locator, loc_count, buf, buflen, out_count) -> 1/0
 * ========================================================================== */
	.global node_sync_multi
	.type node_sync_multi, %function
node_sync_multi:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #4096
	/* locals: buflen@8, out_count@16, hcount@24(dw), hcount_real@28,
	   plen@32(dw), varint@36(dw), getdata_len@40(dw), loop_i@44(dw),
	   loc_count@48(qw), hdr_retry@56(dw), blk_retry@60(dw),
	   stop[32]@64, cmd[12]@96, blockhash[32]@128, getdata[40]@176,
	   prehash[64*32]@224, getheaders[1061]@2304 */
	mov  x19, x0                     /* fd */
	mov  x20, x1                     /* st */
	mov  x21, x2                     /* locator */
	mov  x22, x4                     /* buf */
	str  x5, [sp, #8]                /* buflen */
	str  x6, [sp, #16]               /* out_count ptr */
	/* clamp loc_count to [1,32] */
	mov  x9, x3
	cmp  x9, #1
	b.ge 7f
	mov  x9, #1
7:	cmp  x9, #32
	b.le 8f
	mov  x9, #32
8:	str  x9, [sp, #48]               /* loc_count */
	ldr  x10, [sp, #16]
	str  xzr, [x10]                  /* *out_count = 0 */
	str  wzr, [sp, #44]              /* loop_i = 0 */
	/* zero stop[32] */
	add  x0, sp, #64
	mov  x1, #0
	mov  x2, #32
9:	cmp  x2, #0
	b.eq 10f
	strb w1, [x0]
	add  x0, x0, #1
	sub  x2, x2, #1
	b    9b
10:
.LNS_sync_loop:
	/* ---- request headers ---- */
	add  x0, sp, #2304               /* getheaders payload out */
	mov  x1, x21                     /* locator */
	ldr  w2, [sp, #48]               /* loc_count */
	add  x3, sp, #64                 /* stop */
	bl   p2p_getheaders
	cmp  x0, #0
	b.gt 11f
	mov  w1, #1
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
11:	mov  x4, x0                     /* plen */
	mov  x0, x19
	adrp x1, _getheaders
	add  x1, x1, :lo12:_getheaders
	mov  x2, #10
	add  x3, sp, #2304
	bl   p2p_write
	cmp  x0, #24
	b.ge 12f
	mov  w1, #2
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
12:	mov  w0, #0
	str  w0, [sp, #56]               /* hdr_retry = 0 */
.LNShdr_drain:
	mov  x0, x19
	add  x1, sp, #96                 /* cmd */
	mov  x2, x22                     /* buf */
	ldr  w3, [sp, #8]                /* cap = buflen */
	add  x4, sp, #32                 /* plen */
	bl   p2p_read
	cmp  x0, #-1
	b.ne .LNShdr_not_timeout
	ldr  w1, [sp, #56]
	add  w1, w1, #1
	str  w1, [sp, #56]
	cmp  w1, #8
	b.lo .LNShdr_drain
	mov  w1, #3
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
.LNShdr_not_timeout:
	cmp  x0, #0
	b.gt 13f
	mov  w1, #4
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
13:	add  x0, sp, #96
	adrp x1, _headers
	add  x1, x1, :lo12:_headers
	mov  x2, #7
	bl   .Lcmpeq
	cbnz x0, .LNS_have_headers
	/* not headers: pong if ping else re-read */
	add  x0, sp, #96
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LNShdr_drain
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	mov  x3, x22
	mov  x4, #8
	bl   p2p_write
	b    .LNShdr_drain
.LNS_have_headers:
	mov  x0, x22                     /* buf */
	ldr  w1, [sp, #32]               /* plen */
	bl   p2p_headers_count
	str  w0, [sp, #24]               /* hcount */
	str  w0, [sp, #28]               /* hcount_real */
	cbz  w0, .LNS_done
	/* varint = plen - hcount_real*81 */
	ldr  w1, [sp, #28]
	mov  w9, w1
	mov  x10, #81
	mul  x9, x9, x10
	ldr  w11, [sp, #32]
	sub  x11, x11, x9
	str  w11, [sp, #36]              /* varint */
	/* clamp hcount to 64 */
	ldr  w0, [sp, #24]
	cmp  w0, #64
	b.ls 14f
	mov  w0, #64
	str  w0, [sp, #24]
14:	str  wzr, [sp, #44]             /* loop_i = 0 */
.LNS_prehash:
	ldr  w0, [sp, #44]
	ldr  w1, [sp, #24]
	cmp  w0, w1
	b.hs .LNS_prehash_done
	/* src = buf + varint + i*81 ; block_hash(dst@prehash+i*32, src) */
	ldr  w2, [sp, #36]               /* varint */
	mov  w9, w0
	mov  x10, #81
	mul  x9, x9, x10
	add  x9, x9, x2
	add  x9, x9, x22                 /* src */
	mov  w10, w0
	mov  x11, #32
	mul  x10, x10, x11
	add  x10, x10, #224
	add  x0, sp, x10                 /* dst */
	mov  x1, x9
	bl   block_hash
	ldr  w1, [sp, #44]
	add  w1, w1, #1
	str  w1, [sp, #44]
	b    .LNS_prehash
.LNS_prehash_done:
	str  wzr, [sp, #44]
.LNS_header_loop:
	ldr  w0, [sp, #44]
	ldr  w1, [sp, #24]
	cmp  w0, w1
	b.hs .LNS_sync_loop_next
	/* copy prehash+i*32 -> blockhash@128 (32 bytes) */
	mov  w9, w0
	mov  x10, #32
	mul  x9, x9, x10
	add  x9, x9, #224
	add  x0, sp, #128
	add  x1, sp, x9
	mov  x2, #32
	bl   .Lcopy
	/* getdata build */
	add  x0, sp, #176                /* getdata */
	add  x1, sp, #128                /* blockhash */
	bl   p2p_getdata_block
	str  w0, [sp, #40]               /* getdata_len */
	mov  x4, x0
	mov  x0, x19
	adrp x1, _getdata
	add  x1, x1, :lo12:_getdata
	mov  x2, #7
	add  x3, sp, #176
	bl   p2p_write
	cmp  x0, #24
	b.ge 15f
	mov  w1, #5
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
15:	mov  w0, #0
	str  w0, [sp, #60]               /* blk_retry = 0 */
.LNSblk_drain:
	mov  x0, x19
	add  x1, sp, #96                 /* cmd */
	mov  x2, x22
	ldr  w3, [sp, #8]
	add  x4, sp, #32
	bl   p2p_read
	cmp  x0, #-1
	b.ne .LNSblk_not_timeout
	ldr  w1, [sp, #60]
	add  w1, w1, #1
	str  w1, [sp, #60]
	cmp  w1, #20
	b.lo .LNSblk_drain
	mov  w1, #6
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
.LNSblk_not_timeout:
	cmp  x0, #0
	b.gt 16f
	mov  w1, #7
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
16:	add  x0, sp, #96
	adrp x1, _block
	add  x1, x1, :lo12:_block
	mov  x2, #5
	bl   .Lcmpeq
	cbnz x0, .LNS_have_block
	add  x0, sp, #96
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LNSblk_drain
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	mov  x3, x22
	mov  x4, #8
	bl   p2p_write
	b    .LNSblk_drain
.LNS_have_block:
	/* validate */
	mov  x0, x22
	ldr  w1, [sp, #32]               /* plen */
	adrp x2, sync_txid_scratch
	add  x2, x2, :lo12:sync_txid_scratch
	movz x3, #0x3880
	movk x3, #0x1, lsl #16
	bl   cons_verify
	cbz  w0, .LNS_fail8
	/* store */
	mov  x0, x20
	add  x1, sp, #128                /* blockhash */
	mov  x2, x22
	ldr  w3, [sp, #32]
	bl   idxscan_append_locked
	cmp  x0, #-1
	b.eq .LNS_fail9
	cmp  x0, #-2
	b.eq .LNS_fail10
	/* locator = stored block hash ; loc_count = 1 ; *out_count++ */
	mov  x0, x21                     /* locator */
	add  x1, sp, #128
	mov  x2, #32
	bl   .Lcopy
	mov  x9, #1
	str  x9, [sp, #48]
	ldr  x10, [sp, #16]
	ldr  x11, [x10]
	add  x11, x11, #1
	str  x11, [x10]
	ldr  w1, [sp, #44]
	add  w1, w1, #1
	str  w1, [sp, #44]
	b    .LNS_header_loop
.LNS_fail8:
	mov  w1, #8
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
.LNS_fail9:
	mov  w1, #9
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
.LNS_fail10:
	mov  w1, #10
	adrp x2, sync_fail_code
	add  x2, x2, :lo12:sync_fail_code
	str  w1, [x2]
	b    .NSfail
.LNS_sync_loop_next:
	b    .LNS_sync_loop
.LNS_done:
	mov  w0, #1
	b    .NSret
.NSfail:
	mov  w0, #0
.NSret:
	add  sp, sp, #4096
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_sync_multi, .-node_sync_multi

/* ============================================================================
 * node_serve_block(st, height, out_buf, cap) -> len / -1
 * ========================================================================== */
	.global node_serve_block
	.type node_serve_block, %function
node_serve_block:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #80
	mov  x19, x0                     /* st */
	mov  x20, x2                     /* out_buf */
	mov  x21, x3                     /* cap */
	/* meta[24]@sp ; saved pos@48 size@56 */
	/* store_get_at(st, height, &meta) */
	mov  x4, x0
	mov  x5, x1
	mov  x0, x19
	mov  x1, x5                      /* height */
	add  x2, sp, #0                  /* meta */
	bl   store_get_at
	cmp  x0, #1
	b.ne .SBfail
	ldr  x23, [sp, #0]               /* data_pos */
	ldr  x24, [sp, #8]               /* data_size */
	ldr  w22, [sp, #16]              /* file_no */
	cmp  x24, x21                    /* size > cap ? */
	b.hi .SBfail
	/* store_get_file_fd(st, file_no) -> fd */
	mov  x0, x19
	mov  x1, x22
	bl   store_get_file_fd
	cmp  x0, #0
	b.lt .SBfail
	mov  x1, x0                      /* fd (survives svc) */
	/* lseek(fd, pos+8, SEEK_SET) */
	mov  x0, x1
	add  x1, x23, #8
	mov  x2, #0
	mov  x8, #62
	svc  #0
	tbnz x0, #63, .SBfail
	/* read(fd, out_buf, size) */
	mov  x0, x1                      /* fd (x1 preserved by svc) */
	mov  x1, x20
	mov  x2, x24
	mov  x8, #63
	svc  #0
	cmp  x0, x24
	b.ne .SBfail
	mov  x0, x24
	b    .SBret
.SBfail:
	movn x0, #0                      /* -1 */
.SBret:
	add  sp, sp, #80
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_serve_block, .-node_serve_block

/* ============================================================================
 * node_serve_block_by_hash(st, hash32, out_buf, cap) -> len / -1
 * ========================================================================== */
	.global node_serve_block_by_hash
	.type node_serve_block_by_hash, %function
node_serve_block_by_hash:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #96
	mov  x19, x0                     /* st */
	mov  x20, x1                     /* hash32 */
	mov  x21, x2                     /* out_buf */
	mov  x22, x3                     /* cap */
	/* tip = *(int*)(st+24) */
	ldr  w23, [x19, #24]
	cmp  w23, #0
	b.lt .SBHnomatch
	/* loop index i (x24) from 0..tip */
	mov  x24, #0
.LSBHloop:
	cmp  x24, x23
	b.hi .SBHnomatch
	mov  x0, x19
	mov  x1, x24
	mov  x2, x21
	mov  x3, x22
	bl   node_serve_block
	cmp  x0, #0
	b.le .LSBHnext
	/* block_hash(hashbuf@32, out_buf) */
	add  x0, sp, #32
	mov  x1, x21
	bl   block_hash
	/* compare hashbuf vs hash32 (32) */
	add  x0, sp, #32
	mov  x1, x20
	mov  x2, #32
	bl   .Lcmpeq
	cbnz x0, .LSBHmatched
.LSBHnext:
	add  x24, x24, #1
	b    .LSBHloop
.LSBHmatched:
	mov  x0, x19
	mov  x1, x24
	mov  x2, x21
	mov  x3, x22
	bl   node_serve_block
	cmp  x0, #0
	b.le .SBHnomatch
	b    .SBHret
.SBHnomatch:
	movn x0, #0
.SBHret:
	add  sp, sp, #96
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_serve_block_by_hash, .-node_serve_block_by_hash

/* ============================================================================
 * node_drain(fd, st, buf, buflen) -> #blocks stored or -1
 * ========================================================================== */
	.global node_drain
	.type node_drain, %function
node_drain:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #320
	/* buflen@0(dw), plen@4(dw), idx@8(dw), cmd@16(12), getdata@32(37),
	   blockhash@80(32) */
	mov  x19, x0                     /* fd */
	mov  x20, x1                     /* st */
	mov  x21, x2                     /* buf */
	str  w3, [sp, #0]                /* buflen */
	mov  x23, #0                     /* block count */
.LND_drain_loop:
	mov  x0, x19
	add  x1, sp, #16                 /* cmd */
	mov  x2, x21
	ldr  w3, [sp, #0]
	add  x4, sp, #4                  /* plen */
	bl   p2p_read
	cmp  x0, #0
	b.le .LND_done
	add  x0, sp, #16
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LND_not_ping
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	mov  x3, x21
	mov  x4, #8
	bl   p2p_write
	b    .LND_drain_loop
.LND_not_ping:
	add  x0, sp, #16
	adrp x1, _inv
	add  x1, x1, :lo12:_inv
	mov  x2, #3
	bl   .Lcmpeq
	cbz  x0, .LND_drain_loop
	/* inv: count = payload[0] ; items at buf+1 step 36 */
	ldr  w0, [sp, #4]                /* plen */
	cmp  w0, #5
	b.lt .LND_drain_loop
	ldrb w15, [x21]                  /* item count */
	mov  w24, w15
	cmp  w24, #1
	b.lo .LND_drain_loop
	str  wzr, [sp, #8]               /* idx = 0 */
.LND_inv_loop:
	ldr  w0, [sp, #8]
	cmp  w0, w24
	b.hs .LND_drain_loop
	/* item ptr = buf + 1 + idx*36 */
	mov  x9, x21
	add  x9, x9, #1
	mov  w10, w0
	mov  x11, #36
	mul  x10, x10, x11
	add  x9, x9, x10                  /* item */
	ldr  w1, [x9]                     /* type */
	cmp  w1, #2                       /* MSG_BLOCK */
	b.ne .LND_inv_next
	/* build getdata for hash at item+4 */
	add  x0, sp, #32
	add  x1, x9, #4
	bl   p2p_getdata_block
	mov  x4, x0
	mov  x0, x19
	adrp x1, _getdata
	add  x1, x1, :lo12:_getdata
	mov  x2, #7
	add  x3, sp, #32
	bl   p2p_write
	/* receive `block` into buf */
	mov  x0, x19
	add  x1, sp, #16
	mov  x2, x21
	ldr  w3, [sp, #0]
	add  x4, sp, #4
	bl   p2p_read
	cmp  x0, #0
	b.le .LND_inv_next
	add  x0, sp, #16
	adrp x1, _block
	add  x1, x1, :lo12:_block
	mov  x2, #5
	bl   .Lcmpeq
	cbz  x0, .LND_inv_next
	/* validate */
	mov  x0, x21
	ldr  w1, [sp, #4]
	adrp x2, drain_txid_scratch
	add  x2, x2, :lo12:drain_txid_scratch
	movz x3, #0x3880
	movk x3, #0x1, lsl #16
	bl   cons_verify
	cbz  w0, .LND_inv_next
	/* block_hash(blockhash@80, buf) */
	add  x0, sp, #80
	mov  x1, x21
	bl   block_hash
	/* store_append(st, blockhash, buf, plen) */
	mov  x0, x20
	add  x1, sp, #80
	mov  x2, x21
	ldr  w3, [sp, #4]
	bl   store_append
	cmp  x0, #-1
	b.eq .LND_inv_next
	add  x23, x23, #1                /* block stored */
.LND_inv_next:
	ldr  w1, [sp, #8]
	add  w1, w1, #1
	str  w1, [sp, #8]
	b    .LND_inv_loop
.LND_done:
	mov  x0, x23
	add  sp, sp, #320
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_drain, .-node_drain

/* ============================================================================
 * node_fetch_headers(fd, locator32, count, stop32, out_buf, &out_count) -> 1/0
 * ========================================================================== */
	.global node_fetch_headers
	.type node_fetch_headers, %function
node_fetch_headers:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #192
	/* locator@0, count@8(dw), stop@16, out_buf@24, out_count@32,
	   budget@40(qw), cmd@48(12), plen@64(4), getheaders@80(1061) */
	mov  x19, x0                     /* fd */
	str  x1, [sp, #0]                /* locator32 */
	str  w2, [sp, #8]                /* count */
	str  x3, [sp, #16]               /* stop32 */
	mov  x22, x4                     /* out_buf */
	mov  x23, x5                     /* out_count */
	/* build + send getheaders */
	add  x0, sp, #80
	ldr  x1, [sp, #0]
	ldr  w2, [sp, #8]
	ldr  x3, [sp, #16]
	bl   p2p_getheaders
	mov  x4, x0
	mov  x0, x19
	adrp x1, _getheaders
	add  x1, x1, :lo12:_getheaders
	mov  x2, #10
	add  x3, sp, #80
	bl   p2p_write
	cmp  x0, #24
	b.lt .NFHfail
	mov  x9, #64
	str  x9, [sp, #40]               /* budget */
.LNFHdo_read:
	ldr  x9, [sp, #40]
	sub  x9, x9, #1
	str  x9, [sp, #40]
	cmp  x9, #0
	b.lt .NFHfail
	mov  x0, x19
	add  x1, sp, #48                 /* cmd */
	mov  x2, x22                     /* out_buf */
	movz x3, #0x8480
	movk x3, #0x1e, lsl #16
                /* cap */
	add  x4, sp, #64                 /* plen */
	bl   p2p_read
	cmp  x0, #0
	b.le .NFHfail
	add  x0, sp, #48
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LNFH_not_ping
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	mov  x3, x22
	mov  x4, #8
	bl   p2p_write
	b    .LNFHdo_read
.LNFH_not_ping:
	add  x0, sp, #48
	adrp x1, _headers
	add  x1, x1, :lo12:_headers
	mov  x2, #7
	bl   .Lcmpeq
	cbz  x0, .LNFHdo_read
	/* got headers: report count */
	mov  x0, x22
	ldr  w1, [sp, #64]
	bl   p2p_headers_count
	cmp  x0, #0
	b.lt .NFHfail
	str  x0, [x23]
	mov  w0, #1
	b    .NFHret
.NFHfail:
	mov  w0, #0
.NFHret:
	add  sp, sp, #192
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_fetch_headers, .-node_fetch_headers

/* ============================================================================
 * node_ibd_headers(fd, hst, locator32, page_buf, buflen) -> total / -1
 * ========================================================================== */
	.global node_ibd_headers
	.type node_ibd_headers, %function
node_ibd_headers:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #192
	/* last_hash@0(32), hout@32(32), pgcount@64(qw), entoff@72(qw),
	   total@80(qw), i@88(qw), pages@96(qw), stop[32]@104 */
	mov  x19, x0                     /* fd */
	mov  x20, x1                     /* hst */
	mov  x21, x2                     /* locator32 */
	mov  x22, x3                     /* page_buf */
	mov  x23, x4                     /* buflen */
	str  xzr, [sp, #80]              /* total = 0 */
	str  xzr, [sp, #64]              /* pgcount = 0 */
	str  xzr, [sp, #96]              /* pages = 0 */
	/* zero stop[32] and last_hash seed */
	add  x0, sp, #104
	mov  x1, #0
	mov  x2, #32
17:	cmp  x2, #0
	b.eq 18f
	strb w1, [x0]
	add  x0, x0, #1
	sub  x2, x2, #1
	b    17b
18:	/* last_hash = locator (32) */
	add  x0, sp, #0
	mov  x1, x21
	mov  x2, #32
	bl   .Lcopy
.LNIH_page_loop:
	ldr  x9, [sp, #96]
	add  x9, x9, #1
	str  x9, [sp, #96]               /* pages++ */
	cmp  x9, #4096
	b.gt .LNIH_done
	/* node_fetch_headers(fd, locator, 1, stop, page_buf, &pgcount) */
	mov  x0, x19
	mov  x1, x21
	mov  w2, #1
	add  x3, sp, #104                /* stop */
	mov  x4, x22
	add  x5, sp, #64                  /* &pgcount */
	bl   node_fetch_headers
	cbz  w0, .LNIH_done
	ldr  x9, [sp, #64]
	cbz  x9, .LNIH_done
	str  xzr, [sp, #88]              /* i = 0 */
	/* entoff from count varint */
	ldrb w0, [x22]
	mov  x9, #1
	str  x9, [sp, #72]
	cmp  w0, #0xfd
	b.eq 19f
	cmp  w0, #0xfe
	b.eq 20f
	cmp  w0, #0xff
	b.eq 21f
	b    22f
19:	mov  x9, #3
	str  x9, [sp, #72]
	b    22f
20:	mov  x9, #5
	str  x9, [sp, #72]
	b    22f
21:	mov  x9, #9
	str  x9, [sp, #72]
22:
.LNIH_entry_loop:
	ldr  x0, [sp, #88]
	ldr  x1, [sp, #64]
	cmp  x0, x1
	b.hs .LNIH_page_done
	/* hdr = page_buf + entoff + i*81 */
	ldr  x1, [sp, #72]
	mov  x2, #81
	mul  x2, x0, x2
	add  x1, x1, x2
	add  x1, x1, x22                  /* hdr */
	mov  x24, x1                      /* hdr (callee-saved across block_hash) */
	/* continuity unless total==0 && i==0 */
	ldr  x3, [sp, #80]
	cbnz x3, .LNIH_do_cont
	ldr  x3, [sp, #88]
	cbz  x3, .LNIH_skip_cont
.LNIH_do_cont:
	add  x0, x24, #4
	add  x1, sp, #0                   /* last_hash */
	mov  x2, #32
	bl   .Lcmpeq
	cbz  x0, .LNIH_fail
.LNIH_skip_cont:
	/* block_hash(hout@32, hdr) */
	add  x0, sp, #32
	mov  x1, x24
	bl   block_hash
	/* hst_append(hst, hdr, hout) */
	mov  x0, x20
	mov  x1, x24
	add  x2, sp, #32
	bl   hst_append
	cmp  x0, #0
	b.lt .LNIH_fail
	ldr  x9, [sp, #80]
	add  x9, x9, #1
	str  x9, [sp, #80]               /* total++ */
	/* last_hash = hout */
	add  x0, sp, #0
	add  x1, sp, #32
	mov  x2, #32
	bl   .Lcopy
	ldr  x9, [sp, #88]
	add  x9, x9, #1
	str  x9, [sp, #88]               /* i++ */
	b    .LNIH_entry_loop
.LNIH_page_done:
	/* locator = last_hash */
	mov  x0, x21
	add  x1, sp, #0
	mov  x2, #32
	bl   .Lcopy
	/* short page (<2000) -> tip */
	ldr  x9, [sp, #64]
	cmp  x9, #2000
	b.lt .LNIH_done
	b    .LNIH_page_loop
.LNIH_done:
	ldr  x0, [sp, #80]
	b    .LNIH_ret
.LNIH_fail:
	movn x0, #0
.LNIH_ret:
	add  sp, sp, #192
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_ibd_headers, .-node_ibd_headers

/* ============================================================================
 * node_ibd_blocks(fd, st, hst, start_h, buf, buflen) -> #blocks / -1
 * ========================================================================== */
	.global node_ibd_blocks
	.type node_ibd_blocks, %function
node_ibd_blocks:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #832
	/* hst@0, i@8(qw), count@16(qw), total@24(qw), plen@32(dw),
	   cmd@36(12), getdata@48(37), blockhash@96(32), rec[112]@128 */
	mov  x19, x0                     /* fd */
	mov  x20, x1                     /* st */
	str  x2, [sp, #0]                /* hst */
	str  x3, [sp, #8]                /* i = start_h */
	mov  x22, x4                     /* buf */
	mov  x23, x5                     /* buflen */
	str  xzr, [sp, #24]              /* total = 0 */
	/* count = hst_count(hst) */
	ldr  x0, [sp, #0]
	bl   hst_count
	str  x0, [sp, #16]               /* count */
.LNIB_block_loop:
	ldr  x0, [sp, #8]
	ldr  x1, [sp, #16]
	cmp  x0, x1
	b.hs .LNIB_done
	/* hst_get_at(hst, i, rec@128) */
	ldr  x0, [sp, #0]
	mov  x1, x0                      /* reload hst */
	ldr  x1, [sp, #8]
	add  x2, sp, #128
	bl   hst_get_at
	cmp  x0, #0
	b.le .LNIB_fail
	/* getdata(block_hash = rec+80) */
	add  x0, sp, #48
	add  x1, sp, #208                /* rec+80 */
	bl   p2p_getdata_block
	mov  x4, x0
	mov  x0, x19
	adrp x1, _getdata
	add  x1, x1, :lo12:_getdata
	mov  x2, #7
	add  x3, sp, #48
	bl   p2p_write
	cmp  x0, #24
	b.lt .LNIB_fail
.LNIB_receive:
	mov  x0, x19
	add  x1, sp, #36                 /* cmd */
	mov  x2, x22
	mov  x3, x23
	add  x4, sp, #32                 /* plen */
	bl   p2p_read
	cmp  x0, #0
	b.le .LNIB_fail
	add  x0, sp, #36
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LNIB_not_ping
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	mov  x3, x22
	mov  x4, #8
	bl   p2p_write
	b    .LNIB_receive
.LNIB_not_ping:
	add  x0, sp, #36
	adrp x1, _block
	add  x1, x1, :lo12:_block
	mov  x2, #5
	bl   .Lcmpeq
	cbz  x0, .LNIB_receive
	/* validate */
	mov  x0, x22
	ldr  w1, [sp, #32]
	adrp x2, ibd_txid_scratch
	add  x2, x2, :lo12:ibd_txid_scratch
	movz x3, #0x3880
	movk x3, #0x1, lsl #16
	bl   cons_verify
	cbz  w0, .LNIB_fail
	/* block_hash(blockhash@96, buf) */
	add  x0, sp, #96
	mov  x1, x22
	bl   block_hash
	/* require == rec+80 */
	add  x0, sp, #96
	add  x1, sp, #208
	mov  x2, #32
	bl   .Lcmpeq
	cbz  x0, .LNIB_fail
	/* store_append(st, blockhash, buf, plen) */
	mov  x0, x20
	add  x1, sp, #96
	mov  x2, x22
	ldr  w3, [sp, #32]
	bl   store_append
	cmp  x0, #-1
	b.eq .LNIB_fail
	ldr  x9, [sp, #24]
	add  x9, x9, #1
	str  x9, [sp, #24]               /* total++ */
	ldr  x9, [sp, #8]
	add  x9, x9, #1
	str  x9, [sp, #8]                /* i++ */
	b    .LNIB_block_loop
.LNIB_done:
	ldr  x0, [sp, #24]
	b    .LNIB_ret
.LNIB_fail:
	movn x0, #0
.LNIB_ret:
	add  sp, sp, #832
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_ibd_blocks, .-node_ibd_blocks

/* ============================================================================
 * node_ibd_blocks_x(fd,st,hst,start_h,end_h,buf,buflen,scratch,scratch_cap) -> #/-1
 * ========================================================================== */
	.global node_ibd_blocks_x
	.type node_ibd_blocks_x, %function
node_ibd_blocks_x:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #832
	/* hst@0, start_h@8, end_h@16, i@24, total@32, scratch@40,
	   scratch_cap@48(dw), plen@52(dw), skipbudget@56(qw),
	   cmd@64(12), getdata@80(40), blockhash@128(32), rec[112]@160,
	   prevrec[112]@272 */
	mov  x19, x0                     /* fd */
	mov  x20, x1                     /* st */
	str  x2, [sp, #0]                /* hst */
	str  x3, [sp, #8]                /* start_h */
	str  x4, [sp, #16]               /* end_h */
	mov  x22, x5                     /* buf */
	str  x6, [sp, #24]               /* buflen -> i slot, will overwrite */
	str  x7, [sp, #40]               /* scratch */
	ldr  w0, [sp, #912]              /* scratch_cap (entry stack arg; =sp+912) */
	str  w0, [sp, #48]
	str  x6, [sp, #24]               /* i (reuse; overwrite scratch? no: buflen) */
	/* fix: we need buflen and i separately */
	str  xzr, [sp, #32]              /* total = 0 */
	str  xzr, [sp, #56]              /* skipbudget = 0 */
	/* i = start_h */
	ldr  x9, [sp, #8]
	str  x9, [sp, #24]
	/* buflen was x6; store it */
	str  x6, [sp, #60]
.LNIBX_block_loop:
	ldr  x0, [sp, #24]
	ldr  x1, [sp, #16]
	cmp  x0, x1
	b.hi .LNIBX_done
	ldr  x0, [sp, #0]
	mov  x1, x0
	ldr  x1, [sp, #24]
	add  x2, sp, #160
	bl   hst_get_at
	cmp  x0, #0
	b.le .LNIBX_done
	add  x0, sp, #80
	add  x1, sp, #240                /* rec+80 */
	bl   p2p_getdata_block
	mov  x4, x0
	mov  x0, x19
	adrp x1, _getdata
	add  x1, x1, :lo12:_getdata
	mov  x2, #7
	add  x3, sp, #80
	bl   p2p_write
	cmp  x0, #24
	b.lt .LNIBX_fail
.LNIBX_receive:
	mov  x0, x19
	add  x1, sp, #64                 /* cmd */
	mov  x2, x22
	ldr  w3, [sp, #60]               /* buflen */
	add  x4, sp, #52                 /* plen */
	bl   p2p_read
	cmp  x0, #0
	b.le .LNIBX_fail
	add  x0, sp, #64
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LNIBX_not_ping
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	mov  x3, x22
	mov  x4, #8
	bl   p2p_write
	b    .LNIBX_receive
.LNIBX_not_ping:
	add  x0, sp, #64
	adrp x1, _block
	add  x1, x1, :lo12:_block
	mov  x2, #5
	bl   .Lcmpeq
	cbz  x0, .LNIBX_receive
	/* validate with caller scratch */
	mov  x0, x22
	ldr  w1, [sp, #52]
	ldr  x2, [sp, #40]
	ldr  w3, [sp, #48]
	bl   cons_verify
	cbz  w0, .LNIBX_fail
	add  x0, sp, #128
	mov  x1, x22
	bl   block_hash
	add  x0, sp, #128
	add  x1, sp, #240
	mov  x2, #32
	bl   .Lcmpeq
	cbz  x0, .LNIBX_skip
	/* chain-link guard (i != start_h) */
	ldr  x0, [sp, #24]
	ldr  x1, [sp, #8]
	cmp  x0, x1
	b.eq .LNIBX_chain_ok
	ldr  x0, [sp, #0]
	sub  x1, x0, #0
	ldr  x1, [sp, #24]
	sub  x1, x1, #1
	add  x2, sp, #272                /* prevrec */
	bl   hst_get_at
	cmp  x0, #0
	b.le .LNIBX_fail
	add  x0, x22, #4
	add  x1, sp, #352                /* prevrec+80 */
	mov  x2, #32
	bl   .Lcmpeq
	cbz  x0, .LNIBX_fail
.LNIBX_chain_ok:
	mov  x0, x20
	add  x1, sp, #128
	mov  x2, x22
	ldr  w3, [sp, #52]
	bl   store_append
	cmp  x0, #-1
	b.eq .LNIBX_fail
	ldr  x9, [sp, #32]
	add  x9, x9, #1
	str  x9, [sp, #32]
	ldr  x9, [sp, #24]
	add  x9, x9, #1
	str  x9, [sp, #24]
	b    .LNIBX_block_loop
.LNIBX_skip:
	ldr  x9, [sp, #56]
	add  x9, x9, #1
	str  x9, [sp, #56]
	cmp  x9, #64
	b.hi .LNIBX_fail
	b    .LNIBX_receive
.LNIBX_done:
	ldr  x0, [sp, #32]
	b    .LNIBX_ret
.LNIBX_fail:
	movn x0, #0
.LNIBX_ret:
	add  sp, sp, #832
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_ibd_blocks_x, .-node_ibd_blocks_x

/* ============================================================================
 * node_ibd_blocks_s(fd,st,hst,lo_real,nloc,buf,buflen,scratch,scratch_cap) -> #/-1
 * ========================================================================== */
	.global node_ibd_blocks_s
	.type node_ibd_blocks_s, %function
node_ibd_blocks_s:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #832
	/* hst@0, lo_real@8, nloc@16, i@24, total@32, scratch@40,
	   scratch_cap@48(dw), plen@52(dw), skipbudget@56(qw), buflen@60,
	   cmd@64(12), getdata@80(40), blockhash@128(32), rec[112]@160,
	   prevrec[112]@272 */
	mov  x19, x0
	mov  x20, x1
	str  x2, [sp, #0]                /* hst */
	str  x3, [sp, #8]                /* lo_real */
	str  x4, [sp, #16]               /* nloc */
	mov  x22, x5                     /* buf */
	str  x6, [sp, #60]               /* buflen */
	str  x7, [sp, #40]               /* scratch */
	ldr  w0, [sp, #912]              /* scratch_cap (entry stack arg; =sp+912) */
	str  w0, [sp, #48]               /* scratch_cap */
	str  xzr, [sp, #24]              /* i = 0 */
	str  xzr, [sp, #32]              /* total = 0 */
	str  xzr, [sp, #56]              /* skipbudget = 0 */
.LNIBS_loop:
	ldr  x0, [sp, #24]
	ldr  x1, [sp, #16]
	cmp  x0, x1
	b.hs .LNIBS_done
	ldr  x0, [sp, #0]
	mov  x1, x0
	ldr  x1, [sp, #24]
	add  x2, sp, #160
	bl   hst_get_at
	cmp  x0, #0
	b.le .LNIBS_done
	add  x0, sp, #80
	add  x1, sp, #240
	bl   p2p_getdata_block
	mov  x4, x0
	mov  x0, x19
	adrp x1, _getdata
	add  x1, x1, :lo12:_getdata
	mov  x2, #7
	add  x3, sp, #80
	bl   p2p_write
	cmp  x0, #24
	b.lt .LNIBS_fail
.LNIBS_receive:
	mov  x0, x19
	add  x1, sp, #64
	mov  x2, x22
	ldr  w3, [sp, #60]
	add  x4, sp, #52
	bl   p2p_read
	cmp  x0, #0
	b.le .LNIBS_fail
	add  x0, sp, #64
	adrp x1, _ping
	add  x1, x1, :lo12:_ping
	mov  x2, #4
	bl   .Lcmpeq
	cbz  x0, .LNIBS_not_ping
	mov  x0, x19
	adrp x1, _pong
	add  x1, x1, :lo12:_pong
	mov  x2, #4
	mov  x3, x22
	mov  x4, #8
	bl   p2p_write
	b    .LNIBS_receive
.LNIBS_not_ping:
	add  x0, sp, #64
	adrp x1, _block
	add  x1, x1, :lo12:_block
	mov  x2, #5
	bl   .Lcmpeq
	cbz  x0, .LNIBS_receive
	mov  x0, x22
	ldr  w1, [sp, #52]
	ldr  x2, [sp, #40]
	ldr  w3, [sp, #48]
	bl   cons_verify
	cbz  w0, .LNIBS_fail
	add  x0, sp, #128
	mov  x1, x22
	bl   block_hash
	add  x0, sp, #128
	add  x1, sp, #240
	mov  x2, #32
	bl   .Lcmpeq
	cbz  x0, .LNIBS_skip
	/* chain-link guard if i>0 */
	ldr  x0, [sp, #24]
	cbz  x0, .LNIBS_chain_ok
	ldr  x0, [sp, #0]
	ldr  x1, [sp, #24]
	sub  x1, x1, #1
	add  x2, sp, #272
	bl   hst_get_at
	cmp  x0, #0
	b.le .LNIBS_fail
	add  x0, x22, #4
	add  x1, sp, #352
	mov  x2, #32
	bl   .Lcmpeq
	cbz  x0, .LNIBS_fail
.LNIBS_chain_ok:
	/* store_append_shared(st, lo_real+i, blockhash, buf, plen) */
	ldr  x1, [sp, #8]
	ldr  x9, [sp, #24]
	add  x1, x1, x9
	mov  x0, x20
	add  x2, sp, #128
	mov  x3, x22
	ldr  w4, [sp, #52]
	bl   store_append_shared
	cmp  x0, #-1
	b.eq .LNIBS_fail
	ldr  x9, [sp, #32]
	add  x9, x9, #1
	str  x9, [sp, #32]
	ldr  x9, [sp, #24]
	add  x9, x9, #1
	str  x9, [sp, #24]
	b    .LNIBS_loop
.LNIBS_skip:
	ldr  x9, [sp, #56]
	add  x9, x9, #1
	str  x9, [sp, #56]
	cmp  x9, #64
	b.hi .LNIBS_fail
	b    .LNIBS_receive
.LNIBS_done:
	ldr  x0, [sp, #32]
	b    .LNIBS_ret
.LNIBS_fail:
	movn x0, #0
.LNIBS_ret:
	add  sp, sp, #832
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_ibd_blocks_s, .-node_ibd_blocks_s

/* ============================================================================
 * node_ibd(fd, st, hst, buf, buflen) -> #blocks / -1
 * ========================================================================== */
	.global node_ibd
	.type node_ibd, %function
node_ibd:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #128
	/* st@0, hst@8, loc[32]@16 */
	mov  x19, x0                     /* fd */
	str  x1, [sp, #0]                /* st */
	str  x2, [sp, #8]                /* hst */
	mov  x21, x3                     /* buf */
	mov  x22, x4                     /* buflen */
	/* zero genesis locator */
	add  x0, sp, #16
	mov  x1, #0
	mov  x2, #32
45:	cmp  x2, #0
	b.eq 46f
	strb w1, [x0]
	add  x0, x0, #1
	sub  x2, x2, #1
	b    45b
46:
	/* node_ibd_headers(fd, hst, loc, buf, buflen) */
	mov  x0, x19
	ldr  x1, [sp, #8]
	add  x2, sp, #16
	mov  x3, x21
	mov  x4, x22
	bl   node_ibd_headers
	cmp  x0, #-1
	b.eq .NIBD_fail
	/* node_ibd_blocks(fd, st, hst, 0, buf, buflen) */
	mov  x0, x19
	ldr  x1, [sp, #0]
	ldr  x2, [sp, #8]
	mov  x3, #0
	mov  x4, x21
	mov  x5, x22
	bl   node_ibd_blocks
	b    .NIBD_done
.NIBD_fail:
	movn x0, #0
.NIBD_done:
	add  sp, sp, #128
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size node_ibd, .-node_ibd

/* ---- BSS: cons_verify scratch arenas + fail code ---- */
	.bss
	.align 5
	.global sync_txid_scratch
	.type sync_txid_scratch, @object
sync_txid_scratch:
	.zero SYNC_TXID_CAP*32
	.global drain_txid_scratch
	.type drain_txid_scratch, @object
drain_txid_scratch:
	.zero SYNC_TXID_CAP*32
	.global ibd_txid_scratch
	.type ibd_txid_scratch, @object
ibd_txid_scratch:
	.zero SYNC_TXID_CAP*32
	.global sync_fail_code
	.type sync_fail_code, @object
sync_fail_code:
	.zero 4

/* ---- BSS: last-seen peer version payload capture ---- */
	.global g_peer_version_payload
	.type g_peer_version_payload, @object
g_peer_version_payload:
	.zero 256
	.global g_peer_version_len
	.type g_peer_version_len, @object
g_peer_version_len:
	.zero 8

/* ---- RO data: wire command names + user-agent ---- */
	.section .rodata
_version:	.ascii "version\0"
_verack:	.ascii "verack\0"
_ping:		.ascii "ping\0"
_pong:		.ascii "pong\0"
_getheaders:	.ascii "getheaders\0"
_headers:	.ascii "headers\0"
_getdata:	.ascii "getdata\0"
_block:		.ascii "block\0"
_inv:		.ascii "inv\0"
ua_str:		.ascii "/BitcoinMachineCode:0.0.1/"

	.section .note.GNU-stack,"",%progbits
