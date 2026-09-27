/* ============================================================================
 * bitcoin_addrmgr.S -- the peer address book and the addr / addrv2 wire
 * codecs in AArch64 assembly (Apple silicon), the counterpart of
 * asm/bitcoin_addrmgr.asm. Replaces addrmgr_twin.c on the Mac (2026-09-26);
 * the twin stays in port/osx/test_support as the oracle.
 *
 * peers.dat (cwd): 18-byte records, deduplicated by IP -- ip u32 (network
 * order, as inet_pton gives it), port u16 BE (callers pass htons), services
 * u64, last_seen u32; count = file size / 18 (a partial tail is ignored).
 *
 *   int  amr_init(void* ab);                              1 / -1
 *   long amr_count(void* ab);                             records / -1
 *   int  amr_add(void* ab, u32 ip, u16 port, u64 services, u32 lastseen);
 *                                                         1 / 0 dup / -1
 *   int  amr_get_i(void* ab, long i, u8 out[18]);         1 / -1
 *   long amr_lookup(void* ab, u32 ip);                    index / -1
 *   long p2p_addr_v1(u8* out, const u8* src, long n);     bytes
 *   long p2p_addr_v2(u8* out, const u8* src, long n);     bytes
 *   long p2p_addr_count(const u8* payload, long plen);    entries / -1
 *
 * v1 (Core's msg_addr): CompactSize count, then 30 bytes per entry: time u32,
 * services u64, ip16 ::ffff:a.b.c.d, port u16 BE. v2 (BIP155 msg_addrv2):
 * count, then time u32, services CompactSize, network id 1 (IPv4), length 4,
 * a.b.c.d, port BE. addr_count accepts all four CompactSize forms and needs
 * count * 30 + its length <= plen (the product in 64 bits, as the twin).
 *
 * The book's fd is the int at ab[0] (the twin's 32-bit store; x86 stores 64
 * bits of it). Through libc; open() is variadic: its mode on the stack.
 * ========================================================================== */
#define O_RDWR  0x0002
#define O_CREAT 0x0200

    .text

/* amr_init(ab=x0) ; ab x19 */
    .p2align 2
    .globl _amr_init
_amr_init:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    adrp  x0, Lpeername@PAGE
    add   x0, x0, Lpeername@PAGEOFF
    mov   w1, #(O_RDWR | O_CREAT)
    mov   x9, #0644
    str   x9, [sp]                        /* the variadic mode */
    bl    _open
    tbnz  w0, #31, 1f
    str   w0, [x19]
    mov   x0, #1
    b     2f
1:  mov   x0, #-1
2:  add   sp, sp, #16
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* amr_count(ab=x0) */
    .p2align 2
    .globl _amr_count
_amr_count:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    ldr   w0, [x0]
    mov   x1, #0
    mov   w2, #2                          /* SEEK_END */
    bl    _lseek
    tbnz  x0, #63, 1f
    mov   x9, #18
    sdiv  x0, x0, x9
    b     2f
1:  mov   x0, #-1
2:  ldp   x29, x30, [sp], #16
    ret

/* amr_get_i(ab=x0, i=x1, out=x2) ; fd x19, out x20 */
    .p2align 2
    .globl _amr_get_i
_amr_get_i:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    ldr   w19, [x0]
    mov   x20, x2
    mov   w0, w19
    mov   x9, #18
    mul   x1, x1, x9
    mov   w2, #0                          /* SEEK_SET */
    bl    _lseek
    tbnz  x0, #63, 1f
    mov   w0, w19
    mov   x1, x20
    mov   x2, #18
    bl    _read
    cmp   x0, #18
    b.ne  1f                              /* a short read is -1 too */
    mov   x0, #1
    b     2f
1:  mov   x0, #-1
2:  ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* amr_lookup(ab=x0, ip=w1) ; ab x19, ip x20, i x21 ; frame rec */
    .p2align 2
    .globl _amr_lookup
_amr_lookup:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x0
    mov   w20, w1
    mov   x21, #0
1:  mov   x0, x19
    mov   x1, x21
    mov   x2, sp
    bl    _amr_get_i
    cmp   x0, #1
    b.ne  3f
    ldr   w9, [sp]
    cmp   w9, w20
    b.eq  2f
    add   x21, x21, #1
    b     1b
2:  mov   x0, x21
    b     4f
3:  mov   x0, #-1
4:  add   sp, sp, #32
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* amr_add(ab=x0, ip=w1, port=w2, services=x3, lastseen=w4)
 * ab x19 ; frame rec 0 (32) */
    .p2align 2
    .globl _amr_add
_amr_add:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x0
    str   w1, [sp]                        /* the record, built first */
    strh  w2, [sp, #4]
    stur  x3, [sp, #6]
    stur  w4, [sp, #14]
    bl    _amr_lookup                     /* x0 = ab, w1 = ip still */
    cmn   x0, #1
    b.ne  2f                              /* a duplicate */
    ldr   w0, [x19]
    mov   x1, #0
    mov   w2, #2
    bl    _lseek
    tbnz  x0, #63, 1f
    ldr   w0, [x19]
    mov   x1, sp
    mov   x2, #18
    bl    _write
    cmp   x0, #18
    b.ne  1f
    mov   x0, #1
    b     3f
1:  mov   x0, #-1
    b     3f
2:  mov   x0, #0
3:  add   sp, sp, #32
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* Lcsize(dst=x0, v=x1) -> x0 bytes written ; leaf, x9 */
    .p2align 2
Lcsize:
    cmp   x1, #0xfd
    b.hs  1f
    strb  w1, [x0]
    mov   x0, #1
    ret
1:  lsr   x9, x1, #16
    cbnz  x9, 2f
    mov   w9, #0xfd
    strb  w9, [x0]
    sturh w1, [x0, #1]
    mov   x0, #3
    ret
2:  lsr   x9, x1, #32
    cbnz  x9, 3f
    mov   w9, #0xfe
    strb  w9, [x0]
    stur  w1, [x0, #1]
    mov   x0, #5
    ret
3:  mov   w9, #0xff
    strb  w9, [x0]
    stur  x1, [x0, #1]
    mov   x0, #9
    ret

/* p2p_addr_v1(out=x0, src=x1, n=x2) ; leaf apart from Lcsize (x30 in x17) */
    .p2align 2
    .globl _p2p_addr_v1
_p2p_addr_v1:
    mov   x17, x30
    mov   x15, x0                         /* out */
    mov   x16, x2                         /* n */
    mov   x14, x1                         /* src */
    mov   x1, x2
    bl    Lcsize
    mov   x30, x17
    add   x10, x15, x0                    /* write cursor */
    mov   x11, #0
1:  cmp   x11, x16
    b.ge  2f
    ldur  w12, [x14, #14]                 /* time = last_seen */
    str   w12, [x10]
    ldur  x12, [x14, #6]                  /* services */
    stur  x12, [x10, #4]
    stur  xzr, [x10, #12]                 /* ::ffff: */
    movz  w12, #0xffff, lsl #16           /* bytes 20..23 = 00 00 ff ff */
    stur  w12, [x10, #20]
    ldr   w12, [x14]                      /* a.b.c.d */
    stur  w12, [x10, #24]
    ldrh  w12, [x14, #4]                  /* port BE */
    strh  w12, [x10, #28]
    add   x10, x10, #30
    add   x14, x14, #18
    add   x11, x11, #1
    b     1b
2:  sub   x0, x10, x15
    ret

/* p2p_addr_v2(out=x0, src=x1, n=x2) ; out x19, src x20, n x21, cursor x22,
 * i x23 */
    .p2align 2
    .globl _p2p_addr_v2
_p2p_addr_v2:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    str   x23, [sp, #48]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x1, x2
    bl    Lcsize
    add   x22, x19, x0
    mov   x23, #0
1:  cmp   x23, x21
    b.ge  2f
    ldur  w9, [x20, #14]                  /* time */
    str   w9, [x22], #4
    mov   x0, x22                         /* services, as a CompactSize */
    ldur  x1, [x20, #6]
    bl    Lcsize
    add   x22, x22, x0
    mov   w9, #1                          /* network id: IPv4 */
    strb  w9, [x22]
    mov   w9, #4                          /* address length */
    strb  w9, [x22, #1]
    ldr   w9, [x20]
    stur  w9, [x22, #2]
    ldrh  w9, [x20, #4]
    sturh w9, [x22, #6]
    add   x22, x22, #8
    add   x20, x20, #18
    add   x23, x23, #1
    b     1b
2:  sub   x0, x22, x19
    ldr   x23, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* p2p_addr_count(payload=x0, plen=x1) ; leaf */
    .p2align 2
    .globl _p2p_addr_count
_p2p_addr_count:
    cmp   x1, #1
    b.lt  9f
    ldrb  w9, [x0]
    cmp   w9, #0xfd
    b.hs  1f
    mov   x10, #1
    b     5f
1:  b.ne  2f
    cmp   x1, #3
    b.lt  9f
    ldurh w9, [x0, #1]
    mov   x10, #3
    b     5f
2:  cmp   w9, #0xfe
    b.ne  3f
    cmp   x1, #5
    b.lt  9f
    ldur  w9, [x0, #1]
    mov   x10, #5
    b     5f
3:  cmp   x1, #9
    b.lt  9f
    ldur  x9, [x0, #1]
    mov   x10, #9
5:  mov   x11, #30                        /* count * 30 + len <= plen, in u64 */
    madd  x11, x9, x11, x10
    cmp   x11, x1
    b.hi  9f
    mov   x0, x9
    ret
9:  mov   x0, #-1
    ret

    .section __TEXT,__cstring
Lpeername:
    .asciz "peers.dat"
