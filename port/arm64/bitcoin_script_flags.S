/* bitcoin_script_flags.S -- AArch64 port of asm/bitcoin_script_flags.asm.
 *   uint64_t script_flags_for_block(uint64_t height, const uint8_t hash32[32])
 * Mirrors Core's GetBlockScriptFlags: P2SH|WITNESS|TAPROOT base (mostly)
 * + buried height-gated DERSIG/CLTV/CSV/NULLDUMMY, with two hash-identified
 * historical exceptions.
 */
    .text

    .section .rodata
    .p2align 4
SFC_EXC_BIP16_HASH:
    .byte 0x22,0x9c,0x4f,0xac,0x88,0xba,0xb1,0x94,0xeb,0x08,0xf1,0xa5,0x28,0xcc,0x30,0x8d
    .byte 0xed,0x23,0x97,0xf4,0xf4,0xeb,0x6e,0x75,0xdc,0x02,0x00,0x00,0x00,0x00,0x00,0x00
SFC_EXC_TAPROOT_HASH:
    .byte 0xad,0x95,0xe3,0xa1,0x5e,0xe5,0xff,0xd5,0x85,0xc5,0xe8,0x1d,0x44,0xb5,0x6a,0x98
    .byte 0x1e,0x84,0x2d,0x5b,0xc3,0x14,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    .text

    .global script_flags_for_block
    .type script_flags_for_block,%function
script_flags_for_block:
    /* x0=height x1=hash32 ; height kept in x2 (leaf, x9-x17 scratch noisy) */
    mov  x2,x0

    /* ---- exception 1: BIP16 hash ---- */
    adrp x4, SFC_EXC_BIP16_HASH
    add  x4,x4,:lo12:SFC_EXC_BIP16_HASH
    mov  x5,#0
.sfc_exc1:
    cmp  x5,#32
    b.hs .sfc_exc1_hit
    ldrb w6,[x1,x5]
    ldrb w7,[x4,x5]
    cmp  w6,w7
    b.ne .not_exc1
    add  x5,x5,#1
    b    .sfc_exc1
.sfc_exc1_hit:
    mov  x0,#0                 /* SFC_EXC_BIP16_FLAGS = 0x0 */
    b    .base_done

    /* ---- exception 2: Taproot hash ---- */
.not_exc1:
    adrp x4, SFC_EXC_TAPROOT_HASH
    add  x4,x4,:lo12:SFC_EXC_TAPROOT_HASH
    mov  x5,#0
.sfc_exc2:
    cmp  x5,#32
    b.hs .sfc_exc2_hit
    ldrb w6,[x1,x5]
    ldrb w7,[x4,x5]
    cmp  w6,w7
    b.ne .not_exc2
    add  x5,x5,#1
    b    .sfc_exc2
.sfc_exc2_hit:
    mov  x0,#2049              /* SFC_EXC_TAPROOT_FLAGS = 0x801 */
    b    .base_done

    /* ---- base flags: P2SH|WITNESS|TAPROOT = (1<<0)|(1<<11)|(1<<17) ---- */
.not_exc2:
    mov  x0,#1
    orr  x0,x0,#(1<<11)
    orr  x0,x0,#(1<<17)

.base_done:
    mov  x15,#0x8CCD
    movk x15,#0x5,lsl#16        /* 363725 DERSIG */
    cmp  x2,x15
    b.lo .skip_dersig
    orr  x0,x0,#(1<<2)
.skip_dersig:
    mov  x15,#0xED1D
    movk x15,#0x5,lsl#16        /* 388381 = 0x5ED1D CLTV */
    cmp  x2,x15
    b.lo .skip_cltv
    orr  x0,x0,#(1<<9)
.skip_cltv:
    mov  x15,#0x6600
    movk x15,#0x6,lsl#16        /* 419328 CSV */
    cmp  x2,x15
    b.lo .skip_csv
    orr  x0,x0,#(1<<10)
.skip_csv:
    mov  x15,#0x5A20
    movk x15,#0x7,lsl#16        /* 481824 SEGWIT -> NULLDUMMY */
    cmp  x2,x15
    b.lo .skip_segwit
    orr  x0,x0,#(1<<4)
.skip_segwit:
    ret
    .size script_flags_for_block,.-script_flags_for_block

    .section .note.GNU-stack,"",@progbits
