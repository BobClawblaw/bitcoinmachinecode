/* ============================================================================
 * bech32.S -- AArch64 port of asm/bech32.asm (BIP173 bech32 / BIP350 bech32m).
 *
 * Full checksum codec (30-bit LFSR polymod over hrp_expand ++ data5 ^= const),
 * convert_bits, encode, decode. Same public ABI as the x86 original so the
 * repo C harness (asm/tests/test_bech32.c) links unchanged.
 *
 * AAPCS64: SysV (rdi,rsi,rdx,rcx,r8,r9) -> (x0,x1,x2,x3,x4,x5).
 * All 32-bit checksum/convert arithmetic uses w-registers.
 * ========================================================================== */
	.text
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

	.section .rodata
	.p2align 4
BECH32_GEN:
	.word 0x3b6a57b2
	.word 0x26508e6d
	.word 0x1ea119fa
	.word 0x3d4233dd
	.word 0x2a1462b3
CHARSET:
	.ascii "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	.balign 4
	.text

	.section .bss
	.balign 16
CHAR2IDX:
	.space 256
IDX2CHAR:
	.space 32
WS:
	.space 512
	.text

/* ============================================================================
 * bech32_init(void) -- build CHAR2IDX (0xFF init + both cases) and IDX2CHAR.
 * ========================================================================== */
	.global bech32_init
	.type bech32_init, %function
bech32_init:
	LAddr x0, CHAR2IDX
	mov  x1, #256
2:	cbz  x1, 3f
	mov  w2, #0xff
	strb w2, [x0]
	add  x0, x0, #1
	sub  x1, x1, #1
	b    2b
3:	/* IDX2CHAR[i] = charset[i] ; CHAR2IDX[charset[i]] = i (both cases) */
	LAddr x3, CHARSET
	LAddr x4, IDX2CHAR
	LAddr x5, CHAR2IDX
	mov  x6, #0
4:	cmp  x6, #32
	b.hs 7f
	ldrb w7, [x3, x6]
	strb w7, [x4, x6]          /* IDX2CHAR */
	strb w6, [x5, x7]          /* CHAR2IDX[lower] */
	/* uppercase mapping for a..z */
	cmp  w7, 'a'
	b.lo 6f
	cmp  w7, 'z'
	b.hi 6f
	sub  w7, w7, #32
	strb w6, [x5, x7]
6:	add  x6, x6, #1
	b    4b
7:	ret
	.size bech32_init, .-bech32_init

/* ============================================================================
 * bech32_polymod(x0=values, x1=count) -> w0 = chk
 * ========================================================================== */
bech32_polymod:
	LAddr x15, BECH32_GEN
	mov  w8, #1
	mov  x9, #0
.pm_loop:
	cmp  x9, x1
	b.hs .pm_done
	lsr  w10, w8, #25
	and  w11, w8, #0x1ffffff
	lsl  w11, w11, #5
	ldrb w12, [x0, x9]
	eor  w11, w11, w12
	mov  w8, w11
	mov  w13, #0
.pm_gen:
	cmp  w13, #5
	b.hs .pm_next
	lsr  w14, w10, w13
	tst  w14, #1
	b.eq .pm_gskip
	ldr  w14, [x15, x13, lsl #2]
	eor  w8, w8, w14
.pm_gskip:
	add  w13, w13, #1
	b    .pm_gen
.pm_next:
	add  x9, x9, #1
	b    .pm_loop
.pm_done:
	mov  w0, w8
	ret

/* ============================================================================
 * bech32_hrp_expand(x0=out, x1=hrp, x2=len) -> x0 = 2*len+1
 * ========================================================================== */
bech32_hrp_expand:
	mov  x3, #0
.he_upper:
	cmp  x3, x2
	b.hs .he_sep
	ldrb w4, [x1, x3]
	lsr  w4, w4, #5
	strb w4, [x0, x3]
	add  x3, x3, #1
	b    .he_upper
.he_sep:
	strb wzr, [x0, x2]
	add  x4, x0, x2
	add  x4, x4, #1
	mov  x3, #0
.he_lower:
	cmp  x3, x2
	b.hs .he_done
	ldrb w5, [x1, x3]
	and  w5, w5, #31
	strb w5, [x4, x3]
	add  x3, x3, #1
	b    .he_lower
.he_done:
	lsl  x0, x2, #1
	add  x0, x0, #1
	ret

/* ============================================================================
 * bech32_create_checksum(x0=out6, x1=hrp, x2=hrplen, x3=data5,
 *                        x4=datalen, x5=spec)
 * ========================================================================== */
	.global bech32_create_checksum
	.type bech32_create_checksum, %function
bech32_create_checksum:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	mov  x19, x0   /* out6 */
	mov  x20, x1   /* hrp */
	mov  x21, x2   /* hrplen */
	mov  x22, x3   /* data5 */
	mov  x23, x4   /* datalen */
	mov  x24, x5   /* spec */
	/* WS[0..] = hrp_expand */
	LAddr x0, WS
	mov  x1, x20
	mov  x2, x21
	bl   bech32_hrp_expand
	mov  x6, x0
	/* copy data5 -> WS+expand */
	LAddr x0, WS
	add  x0, x0, x6
	mov  x1, x22
	mov  x2, x23
5:	cbz  x2, 6f
	ldrb w3, [x1]
	strb w3, [x0]
	add  x0, x0, #1
	add  x1, x1, #1
	sub  x2, x2, #1
	b    5b
6:	/* zero 6 at WS+expand+datalen */
	LAddr x0, WS
	add  x0, x0, x6
	add  x0, x0, x23
	mov  x2, #6
7:	cbz  x2, 8f
	strb wzr, [x0]
	add  x0, x0, #1
	sub  x2, x2, #1
	b    7b
8:	/* polymod */
	LAddr x0, WS
	add  x1, x6, x23
	add  x1, x1, #6
	bl   bech32_polymod
	mov  w8, w0
	/* chk ^= spec ? 0x2bc830a3 : 1 */
	mov  w9, #1
	cbz  x24, .cc_const
	mov  w9, #0x30a3
	movk w9, #0x2bc8, lsl #16
.cc_const:
	eor  w8, w8, w9
	/* out6[i] = (chk >> (25-5*i)) & 31 */
	mov  x9, #0
.cc_out:
	cmp  x9, #6
	b.hs .cc_done
	mov  w11, #25
	mov  w12, w9
	lsl  w13, w12, #2
	add  w13, w13, w12
	sub  w11, w11, w13
	lsr  w12, w8, w11
	and  w12, w12, #31
	strb w12, [x19, x9]
	add  x9, x9, #1
	b    .cc_out
.cc_done:
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size bech32_create_checksum, .-bech32_create_checksum

/* ============================================================================
 * bech32_verify_checksum(x0=hrp, x1=hrplen, x2=data5, x3=datalen,
 *                        x4=spec) -> w0 = 1/0
 * ========================================================================== */
	.global bech32_verify_checksum
	.type bech32_verify_checksum, %function
bech32_verify_checksum:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	mov  x19, x0   /* hrp */
	mov  x20, x1   /* hrplen */
	mov  x21, x2   /* data5 */
	mov  x22, x3   /* datalen */
	mov  x23, x4   /* spec */
	/* WS[0..] = hrp_expand */
	LAddr x0, WS
	mov  x1, x19
	mov  x2, x20
	bl   bech32_hrp_expand
	mov  x6, x0
	/* copy data5 -> WS+expand */
	LAddr x0, WS
	add  x0, x0, x6
	mov  x1, x21
	mov  x2, x22
9:	cbz  x2, 10f
	ldrb w3, [x1]
	strb w3, [x0]
	add  x0, x0, #1
	add  x1, x1, #1
	sub  x2, x2, #1
	b    9b
10:	/* polymod */
	LAddr x0, WS
	add  x1, x6, x22
	bl   bech32_polymod
	mov  w8, w0
	mov  w9, #1
	cbz  x23, .vv_const
	mov  w9, #0x30a3
	movk w9, #0x2bc8, lsl #16
.vv_const:
	cmp  w8, w9
	cset w0, eq
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size bech32_verify_checksum, .-bech32_verify_checksum

/* ============================================================================
 * bech32_convert_bits(x0=out, x1=in, x2=inlen, x3=frombits, x4=tobits,
 *                     x5=pad) -> w0 = out count / -1
 * ========================================================================== */
	.global bech32_convert_bits
	.type bech32_convert_bits, %function
bech32_convert_bits:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	mov  x19, x0   /* out */
	mov  x20, x1   /* in */
	mov  x21, x2   /* inlen */
	/* max_acc = (1<<(frombits+tobits-1))-1 */
	add  w9, w3, w4
	sub  w9, w9, #1
	mov  w10, #1
	lsl  w10, w10, w9
	sub  w10, w10, #1
	mov  w11, #0   /* acc */
	mov  w12, #0   /* bits */
	mov  w13, #0   /* ret count */
	mov  x14, #0   /* in index */
.cb_in:
	cmp  x14, x21
	b.hs .cb_pad
	ldrb w15, [x20, x14]
	lsl  w11, w11, w3
	orr  w11, w11, w15
	and  w11, w11, w10
	add  w12, w12, w3
.cb_bit:
	cmp  w12, w4
	b.lo .cb_cont
	sub  w9, w12, w4
	lsr  w9, w11, w9
	mov  w16, #1
	lsl  w16, w16, w4
	sub  w16, w16, #1
	and  w9, w9, w16
	strb w9, [x19, x13]
	add  w13, w13, #1
	sub  w12, w12, w4
	b    .cb_bit
.cb_cont:
	add  x14, x14, #1
	b    .cb_in
.cb_pad:
	cbz  w12, .cb_done
	sub  w9, w4, w12
	lsl  w11, w11, w9
	mov  w16, #1
	lsl  w16, w16, w4
	sub  w16, w16, #1
	and  w11, w11, w16
	cbz  x5, .cb_nopad
	strb w11, [x19, x13]
	add  w13, w13, #1
	b    .cb_done
.cb_nopad:
	cbnz w11, .cb_err
.cb_done:
	mov  w0, w13
	b    .cb_out
.cb_err:
	mov  x0, #-1
.cb_out:
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size bech32_convert_bits, .-bech32_convert_bits

/* ============================================================================
 * bech32_encode(x0=out, x1=hrp, x2=hrplen, x3=data5, x4=datalen, x5=spec)
 *                            -> x0 = length (incl checksum, excl NUL)
 * ========================================================================== */
	.global bech32_encode
	.type bech32_encode, %function
bech32_encode:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	mov  x19, x0   /* out */
	mov  x20, x1   /* hrp */
	mov  x21, x2   /* hrplen */
	mov  x22, x3   /* data5 */
	mov  x23, x4   /* datalen */
	mov  x24, x5   /* spec */
	/* write hrp + '1' */
	mov  x10, #0
11:	cmp  x10, x21
	b.hs 12f
	ldrb w11, [x20, x10]
	strb w11, [x19, x10]
	add  x10, x10, #1
	b    11b
12:	mov  w11, #'1'
	strb w11, [x19, x21]
	/* create checksum into WS */
	LAddr x0, WS
	mov  x1, x20
	mov  x2, x21
	mov  x3, x22
	mov  x4, x23
	mov  x5, x24
	bl   bech32_create_checksum
	/* data chars at out+hrplen+1 */
	LAddr x6, IDX2CHAR
	add  x7, x19, x21            /* out + hrplen */
	mov  x8, #1 + 0
	add  x7, x7, #1              /* data base */
	mov  x9, #0
13:	cmp  x9, x23
	b.hs 14f
	ldrb w10, [x22, x9]
	ldrb w10, [x6, x10]
	strb w10, [x7, x9]
	add  x9, x9, #1
	b    13b
14:	/* checksum chars at out+hrplen+1+datalen */
	LAddr x13, WS
	mov  x10, x7
	add  x10, x10, x23
	mov  x9, #0
15:	cmp  x9, #6
	b.hs 16f
	ldrb w11, [x13, x9]
	ldrb w11, [x6, x11]
	strb w11, [x10, x9]
	add  x9, x9, #1
	b    15b
16:	/* length = hrplen+1+datalen+6 ; NUL at out+length */
	add  x0, x21, x23
	add  x0, x0, #7
	strb wzr, [x19, x0]
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size bech32_encode, .-bech32_encode

/* ============================================================================
 * bech32_decode(x0=out5, x1=out_hrp, x2=hrp_cap, x3=in) -> x0 = data count / -1
 * ========================================================================== */
	.global bech32_decode
	.type bech32_decode, %function
bech32_decode:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	mov  x19, x0   /* out5 */
	mov  x20, x1   /* out_hrp */
	mov  x21, x2   /* hrp_cap */
	mov  x22, x3   /* in */
	mov  x23, #0   /* running len */
	mov  x24, #0   /* last '1' pos */
.dc_scan:
	ldrb w10, [x22, x23]
	cbz  w10, .dc_scan_done
	cmp  w10, #'1'
	b.ne .dc_notsep
	mov  x24, x23
.dc_notsep:
	add  x23, x23, #1
	b    .dc_scan
.dc_scan_done:
	cbz  x24, .dc_err
	mov  x23, x24               /* hrp_len */
	cmp  x23, x21
	b.hs .dc_err
	mov  x25, #0
.dc_hchk:
	cmp  x25, x23
	b.hs .dc_hok
	ldrb w10, [x22, x25]
	cmp  w10, #0x21
	b.lo .dc_err
	cmp  w10, #0x7e
	b.hi .dc_err
	add  x25, x25, #1
	b    .dc_hchk
.dc_hok:
	mov  x10, #0
17:	cmp  x10, x23
	b.hs 18f
	ldrb w11, [x22, x10]
	strb w11, [x20, x10]
	add  x10, x10, #1
	b    17b
18:	strb wzr, [x20, x23]
	/* data index = in + hrp_len + 1 + x25 */
	add  x26, x22, x23
	add  x26, x26, #1          /* data base */
	LAddr x12, CHAR2IDX
	mov  x25, #0                /* data count */
.dc_data:
	ldrb w10, [x26, x25]
	cbz  w10, .dc_data_done
	ldrb w11, [x12, x10]
	cmp  w11, #0xff
	b.eq .dc_err
	strb w11, [x19, x25]
	add  x25, x25, #1
	b    .dc_data
.dc_data_done:
	cmp  x25, #6
	b.lt .dc_err
	mov  x0, x25
	b    .dc_out
.dc_err:
	mov  x0, #-1
.dc_out:
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size bech32_decode, .-bech32_decode

	.section .note.GNU-stack,"",%progbits
