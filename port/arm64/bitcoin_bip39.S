/* bitcoin_bip39.S -- AArch64 port of asm/bitcoin_bip39.asm (AAPCS64).
 * Exports:
 *   int bip39_generate(char* out, const u8* entropy, i64 ent_bits) -> 1/0
 *   int bip39_validate(const char* mnemonic) -> wordcount (12..24) or -1
 *   int bip39_mnemonic_to_entropy(u8 out[32], const char* mnemonic) -> bits/-1
 *   int bip39_mnemonic_to_seed(u8 seed[64], const char* mnemonic,
 *                              const char* pass, i64 passlen) -> 1
 * Deps: sha256_full (sha256.S), hmac_sha512 (bitcoin_hmac.S).
 * Wordlist: bip39_words.S.inc (2048 x 9-byte records).
 */
    .bss
    .p2align 4
m39_bits: .space 40
m39_idx:  .space 96
m39_salt: .space 512
m39_msg:  .space 520
m39_prev: .space 64
m39_cur:  .space 64
m39_acc:  .space 64
m39_nw:   .space 8
    .section .rodata
m39_seed_salt:
    .ascii "mnemonic"
    .include "bip39_words.S.inc"

/* ---- bip39_bit_at(buf=x0, bitpos=x1) -> w0 0/1 (leaf) ---- */
bip39_bit_at:
    lsr  x2,x1,#3
    and  x3,x1,#7
    mov  x4,#7
    sub  x4,x4,x3
    ldrb w5,[x0,x2]
    lsrv w5,w5,w4
    and  w0,w5,#1
    ret

/* ---- bip39_set_bit(buf=x0, bitpos=x1, val=x2) (leaf) ---- */
bip39_set_bit:
    cbz  x2,.st_zero
    lsr  x3,x1,#3
    and  x4,x1,#7
    mov  x5,#7
    sub  x5,x5,x4
    mov  w6,#1
    lslv w6,w6,w5
    ldrb w7,[x0,x3]
    orr  w7,w7,w6
    strb w7,[x0,x3]
.st_zero:
    ret

/* ---- bip39_read11(buf=x0, bitpos=x1) -> x0 (11-bit) ---- */
bip39_read11:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0
    mov  x20,x1
    mov  x21,#0
    mov  x22,#0
.r11_l:
    cmp  x22,#11
    b.hs .r11_d
    mov  x0,x19
    add  x1,x20,x22
    bl   bip39_bit_at
    lsl  x21,x21,#1
    orr  x21,x21,x0
    add  x22,x22,#1
    b    .r11_l
.r11_d:
    mov  x0,x21
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret

/* ---- find_word_index(token=x0, toklen=x1) -> x0 idx / -1 ---- */
find_word_index:
    adrp x5,bip39_words
    add  x5,x5,:lo12:bip39_words
    mov  x6,#0
.fi_l:
    cmp  x6,#2048
    b.hs .fi_nf
    mov  x11,#9
    mul  x7,x6,x11
    add  x7,x7,x5
    mov  x8,#0
.fi_cmp:
    cmp  x8,x1
    b.hs .fi_len
    ldrb w9,[x0,x8]
    ldrb w10,[x7,x8]
    cmp  w9,w10
    b.ne .fi_nxt
    add  x8,x8,#1
    b    .fi_cmp
.fi_len:
    ldrb w10,[x7,x8]
    cbnz w10,.fi_nxt
    mov  x0,x6
    ret
.fi_nxt:
    add  x6,x6,#1
    b    .fi_l
.fi_nf:
    mov  x0,#-1
    ret

/* ---- bip39_strlen(str=x0) -> x0 (leaf) ---- */
bip39_strlen:
    mov  x1,#0
.bs_l:
    ldrb w2,[x0,x1]
    cbz  w2,.bs_d
    add  x1,x1,#1
    b    .bs_l
.bs_d:
    mov  x0,x1
    ret

/* ================= bip39_generate =================
 * persistents x19=out x20=entropy x21=ent_bits x22=cs_bits x23=nwords
 * x24=m39_bits x25=out-cursor x26=m39_salt. */
    .global bip39_generate
    .type bip39_generate,%function
bip39_generate:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    cmp  x2,#128
    b.eq .bg_ok
    cmp  x2,#160
    b.eq .bg_ok
    cmp  x2,#192
    b.eq .bg_ok
    cmp  x2,#224
    b.eq .bg_ok
    cmp  x2,#256
    b.eq .bg_ok
    mov  w0,#0
    b    .bg_ret
.bg_ok:
    mov  x19,x0
    mov  x20,x1
    mov  x21,x2
    lsr  x22,x21,#5
    mov  x23,x22
    lsl  x23,x23,#1
    add  x23,x22,x23          /* nwords */
    adrp x24,m39_bits
    add  x24,x24,:lo12:m39_bits
    adrp x26,m39_salt
    add  x26,x26,:lo12:m39_salt
    str  xzr,[x24]
    str  xzr,[x24,#8]
    str  xzr,[x24,#16]
    str  xzr,[x24,#24]
    str  xzr,[x24,#32]
    lsr  x9,x21,#3            /* ent_bytes */
    mov  x10,#0
.bg_ec:
    cmp  x10,x9
    b.hs .bg_ecd
    ldrb w11,[x20,x10]
    strb w11,[x24,x10]
    add  x10,x10,#1
    b    .bg_ec
.bg_ecd:
    mov  x0,x26
    mov  x1,x20
    mov  x2,x9
    bl   sha256_full
    ldrb w13,[x26]            /* digest[0] */
    mov  x14,x21              /* bitpos */
    mov  x15,#0               /* cs idx */
.bg_ap:
    cmp  x15,x22
    b.hs .bg_apd
    mov  x8,#7
    sub  x8,x8,x15
    lsrv w8,w13,w8
    and  w8,w8,#1
    mov  x0,x24
    mov  x1,x14
    mov  x2,x8
    bl   bip39_set_bit
    add  x15,x15,#1
    add  x14,x14,#1
    b    .bg_ap
.bg_apd:
    mov  x25,x19
    mov  x14,#0               /* bitpos */
    mov  x15,#0               /* word count */
.bg_wl:
    cmp  x15,x23
    b.hs .bg_wld
    mov  x0,x24
    mov  x1,x14
    bl   bip39_read11          /* x0 = word index */
    adrp x8,bip39_words
    add  x8,x8,:lo12:bip39_words
    mov  x9,x0
    mov  x11,#9
    mul  x9,x9,x11
    add  x8,x8,x9             /* x8 = &record */
    mov  x9,#0                 /* copy offset */
.bg_cp:
    ldrb w10,[x8,x9]
    cbz  w10,.bg_cpd
    strb w10,[x25,x9]
    add  x9,x9,#1
    b    .bg_cp
.bg_cpd:
    add  x25,x25,x9            /* advance out cursor past word */
    add  x10,x15,#1
    cmp  x10,x23
    b.hs .bg_nosp
    mov  w10,#' '
    strb w10,[x25]
    add  x25,x25,#1
.bg_nosp:
    add  x14,x14,#11
    add  x15,x15,#1
    b    .bg_wl
.bg_wld:
    strb wzr,[x25]             /* NUL terminate */
    mov  w0,#1
.bg_ret:
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size bip39_generate,.-bip39_generate

/* ================= bip39_parse(mnemonic=x0) -> wordcount / -1 =================
 * persistents: x19 mnemonic, x20 nwords, x21 ent_bits, x22 cs_bits,
 * x23 m39_bits base, x24 m39_salt base. */
bip39_parse:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0
    adrp x23,m39_bits
    add  x23,x23,:lo12:m39_bits
    adrp x24,m39_salt
    add  x24,x24,:lo12:m39_salt
    mov  x20,#0
    mov  x9,x19
.bp_skipsp:
    ldrb w10,[x9]
    cmp  w10,#' '
    b.ne .bp_have_tok
    add  x9,x9,#1
    b    .bp_skipsp
.bp_have_tok:
    ldrb w10,[x9]
    cbz  w10,.bp_tok_done
    mov  x10,x9
.bp_tlok:
    ldrb w11,[x10]
    cbz  w11,.bp_tok_end
    cmp  w11,#' '
    b.eq .bp_tok_end
    add  x10,x10,#1
    b    .bp_tlok
.bp_tok_end:
    mov  x0,x9
    sub  x1,x10,x9
    stp  x9,x10,[sp,#-16]!      /* find_word_index clobbers x9/x10 (caller-saved) */
    bl   find_word_index
    ldp  x9,x10,[sp],#16
    cmp  x0,#-1
    b.eq .bp_invalid
    adrp x12,m39_idx
    add  x12,x12,:lo12:m39_idx
    str  w0,[x12,x20,lsl#2]
    add  x20,x20,#1
    mov  x9,x10
    b    .bp_skipsp
.bp_tok_done:
    cmp  x20,#12
    b.eq .bp_nok
    cmp  x20,#15
    b.eq .bp_nok
    cmp  x20,#18
    b.eq .bp_nok
    cmp  x20,#21
    b.eq .bp_nok
    cmp  x20,#24
    b.eq .bp_nok
    b    .bp_invalid
.bp_nok:
    adrp x13,m39_nw
    add  x13,x13,:lo12:m39_nw
    str  x20,[x13]
    mov  x0,x20
    lsl  x0,x0,#5
    mov  x1,#3
    udiv x21,x0,x1             /* ent_bits */
    lsr  x22,x21,#5            /* cs_bits */
    str  xzr,[x23]
    str  xzr,[x23,#8]
    str  xzr,[x23,#16]
    str  xzr,[x23,#24]
    str  xzr,[x23,#32]
    mov  x10,#0                /* word counter */
.bp_wbin:
    cmp  x10,x20
    b.hs .bp_wbin_done
    adrp x12,m39_idx
    add  x12,x12,:lo12:m39_idx
    ldr  w11,[x12,x10,lsl#2]   /* index */
    mov  x13,x10
    mov  x14,#11
    mul  x13,x13,x14           /* bitpos = i*11 */
    mov  x15,#0
.bp_bilin:
    cmp  x15,#11
    b.hs .bp_bilin_done
    mov  x8,#10
    sub  x8,x8,x15
    lsrv w8,w11,w8
    and  w8,w8,#1
    mov  x0,x23
    add  x1,x13,x15
    mov  x2,x8
    bl   bip39_set_bit
    add  x15,x15,#1
    b    .bp_bilin
.bp_bilin_done:
    add  x10,x10,#1
    b    .bp_wbin
.bp_wbin_done:
    /* extract ent_bytes from stream -> m39_salt */
    lsr  x9,x21,#3             /* ent_bytes */
    mov  x10,#0
    mov  x14,#0
.bp_entb:
    cmp  x10,x9
    b.hs .bp_entb_done
    mov  x13,#0
    mov  x15,#0
.bp_bybit:
    cmp  x15,#8
    b.hs .bp_bybit_done
    mov  x0,x23
    mov  x1,x14
    bl   bip39_bit_at
    lsl  x13,x13,#1
    orr  x13,x13,x0
    add  x14,x14,#1
    add  x15,x15,#1
    b    .bp_bybit
.bp_bybit_done:
    strb w13,[x24,x10]
    add  x10,x10,#1
    b    .bp_entb
.bp_entb_done:
    mov  x0,x24
    mov  x1,x24
    mov  x2,x9
    bl   sha256_full
    ldrb w13,[x24]             /* digest[0] */
    mov  x14,x21               /* bitpos */
    mov  x15,#0
.bp_csloop:
    cmp  x15,x22
    b.hs .bp_valid
    mov  x0,x23
    mov  x1,x14
    bl   bip39_bit_at          /* x0 = stream bit */
    mov  x16,x0
    mov  x8,#7
    sub  x8,x8,x15
    lsrv w17,w13,w8
    and  w17,w17,#1
    cmp  w17,w16
    b.ne .bp_invalid
    add  x14,x14,#1
    add  x15,x15,#1
    b    .bp_csloop
.bp_valid:
    mov  x0,x20
    b    .bp_pret
.bp_invalid:
    mov  x0,#-1
.bp_pret:
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret

/* ================= bip39_validate(mnemonic=x0) ================= */
    .global bip39_validate
    .type bip39_validate,%function
bip39_validate:
    b    bip39_parse            /* tail call: return parse result */
    .size bip39_validate,.-bip39_validate

/* ================= bip39_mnemonic_to_entropy(out=x0, mnemonic=x1) ================= */
    .global bip39_mnemonic_to_entropy
    .type bip39_mnemonic_to_entropy,%function
bip39_mnemonic_to_entropy:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                /* out */
    mov  x20,x1                /* mnemonic */
    mov  x0,x1
    bl   bip39_parse
    cmp  x0,#-1
    b.eq .bt_bad
    mov  x21,x0                /* nwords */
    mov  x0,x21
    lsl  x0,x0,#5
    mov  x1,#3
    udiv x22,x0,x1             /* ent_bits */
    adrp x23,m39_bits
    add  x23,x23,:lo12:m39_bits
    lsr  x9,x22,#3             /* ent_bytes */
    mov  x10,#0
    mov  x14,#0
.bt_eb:
    cmp  x10,x9
    b.hs .bt_eb_done
    mov  x13,#0
    mov  x15,#0
.bt_bybit:
    cmp  x15,#8
    b.hs .bt_bybit_done
    mov  x0,x23
    mov  x1,x14
    bl   bip39_bit_at
    lsl  x13,x13,#1
    orr  x13,x13,x0
    add  x14,x14,#1
    add  x15,x15,#1
    b    .bt_bybit
.bt_bybit_done:
    strb w13,[x19,x10]
    add  x10,x10,#1
    b    .bt_eb
.bt_eb_done:
    mov  x0,x22                /* ent_bits */
    b    .bt_ret
.bt_bad:
    mov  x0,#-1
.bt_ret:
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size bip39_mnemonic_to_entropy,.-bip39_mnemonic_to_entropy

/* ================= bip39_mnemonic_to_seed(seed=x0, mn=x1, pass=x2, passlen=x3) =====
 * PBKDF2-HMAC-SHA512(P=mnemonic, S="mnemonic"||pass, c=2048, dkLen=64).
 * persistents x19..x28; counter kept in a stack slot. */
    .global bip39_mnemonic_to_seed
    .type bip39_mnemonic_to_seed,%function
bip39_mnemonic_to_seed:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    stp  x27,x28,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                /* seed */
    mov  x20,x1                /* mn   */
    mov  x21,x2                /* pass */
    mov  x22,x3                /* passlen */
    mov  x0,x20
    bl   bip39_strlen
    mov  x23,x0                /* mnlen */
    adrp x9,m39_salt
    add  x9,x9,:lo12:m39_salt
    adrp x10,m39_seed_salt
    add  x10,x10,:lo12:m39_seed_salt
    ldr  x11,[x10]             /* 8 bytes "mnemonic" */
    str  x11,[x9]
    mov  x24,#8                /* saltlen */
    cbz  x21,.bm_salt_done
    mov  x12,#0
.bm_pcloop:
    cmp  x12,x22
    b.hs .bm_salt_done
    ldrb w11,[x21,x12]
    strb w11,[x9,x24]
    add  x24,x24,#1
    add  x12,x12,#1
    b    .bm_pcloop
.bm_salt_done:
    adrp x26,m39_msg
    add  x26,x26,:lo12:m39_msg
    mov  x12,#0
.bm_fm:
    cmp  x12,x24
    b.hs .bm_fm_done
    ldrb w11,[x9,x12]
    strb w11,[x26,x12]
    add  x12,x12,#1
    b    .bm_fm
.bm_fm_done:
    add  x13,x26,x24
    mov  w11,#0
    strb w11,[x13],#1
    strb w11,[x13],#1
    strb w11,[x13],#1
    mov  w11,#1
    strb w11,[x13]
    add  x25,x24,#4            /* msg1_len */
    adrp x27,m39_prev
    add  x27,x27,:lo12:m39_prev
    mov  x0,x27                /* out = prev */
    mov  x1,x20
    mov  x2,x23
    mov  x3,x26                /* msg */
    mov  x4,x25
    bl   hmac_sha512
    adrp x28,m39_acc
    add  x28,x28,:lo12:m39_acc
    mov  x12,#0
.bm_a1:
    cmp  x12,#64
    b.hs .bm_a1d
    ldrb w11,[x27,x12]
    strb w11,[x28,x12]
    add  x12,x12,#1
    b    .bm_a1
.bm_a1d:
    adrp x26,m39_cur
    add  x26,x26,:lo12:m39_cur   /* cur base (msg base no longer needed) */
    sub  sp,sp,#16
    mov  x8,#2047
    str  x8,[sp]
.bm_pbloop:
    ldr  x8,[sp]
    cbz  x8,.bm_pbdone
    mov  x0,x26                /* out = cur */
    mov  x1,x20
    mov  x2,x23
    mov  x3,x27                /* msg = prev */
    mov  x4,#64
    bl   hmac_sha512
    mov  x12,#0
.bm_xor:
    cmp  x12,#64
    b.hs .bm_xord
    ldrb w11,[x26,x12]
    ldrb w13,[x28,x12]
    eor  w13,w13,w11
    strb w13,[x28,x12]
    ldrb w11,[x26,x12]
    strb w11,[x27,x12]
    add  x12,x12,#1
    b    .bm_xor
.bm_xord:
    ldr  x8,[sp]
    sub  x8,x8,#1
    str  x8,[sp]
    b    .bm_pbloop
.bm_pbdone:
    add  sp,sp,#16
    mov  x12,#0
.bm_se:
    cmp  x12,#64
    b.hs .bm_sed
    ldrb w11,[x28,x12]
    strb w11,[x19,x12]
    add  x12,x12,#1
    b    .bm_se
.bm_sed:
    mov  w0,#1
    ldp  x27,x28,[sp],#16
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size bip39_mnemonic_to_seed,.-bip39_mnemonic_to_seed

    .section .note.GNU-stack,"",@progbits
