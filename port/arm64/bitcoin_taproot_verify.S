/* ============================================================================*/
/* bitcoin_taproot_verify.S -- AArch64 (GNU as) port of the x86-64*/
/* asm/bitcoin_taproot_verify.asm: BIP341/342 input verification orchestration.*/
/* Twin of the C taproot_verify_input in asm/bitcoin_taproot_sighash.c;*/
/* differential: tests/test_taproot_verify_diff.c.*/
/**/
/*   long taproot_verify_input_asm(const u8* spk, const u8* const* wit,*/
/*                                 const u32* witlen, u32 nwit,*/
/*                                 const u8* tx, i64 txlen,*/
/*                                 i64 n_in, const u8* prevouts,*/
/*                                 const u8* amounts, const u8* spks,*/
/*                                 i64 num_inputs, const char** reason)*/
/*     -> 1 valid / 0 rejected (*reason set byte-identical to the C's)*/
/**/
/* AAPCS64 arg mapping (x86 SysV put args 7+ on the stack; ARM puts 1-8 in x0..x7):*/
/*   x0 spk  x1 wit  x2 witlen  x3 nwit  x4 tx  x5 txlen  x6 n_in  x7 prevouts*/
/*   [sp+0]=amounts [sp+8]=spks [sp+16]=num_inputs [sp+24]=reason*/
/**/
/* Struct layouts (offsetof-pinned, same as the x86 header comment):*/
/*   taproot_checksig_ctx (96 B): tx@0 txlen@8 n_in@16 prevouts@24 amounts@32*/
/*     spks@40 num_inputs@48 tapleaf@56 codesep_pos@64 annex@72 annexlen@80*/
/*     weight_left@88*/
/*   ts_script_state (120 B, zeroed first like the C's memset): main_elems@0*/
/*     main_sp@8 alt_elems@16 alt_sp@24 script@32 script_len@40 sigversion@48*/
/*     flags@56 work@64 work_cap@72 error_out@80 checksig_ctx@88 checksig_fn@96*/
/*     tx_locktime@104 in_sequence@108 tx_version@112*/
/**/
/* Heavy lifting stays in already-ported leaf modules: tap_leaf_hash /*/
/* tap_merkle_root / taproot_tweak_pubkey (secp256k1_taproot.S), stack_push*/
/* (bitcoin_scriptcodec.S), script_eval (bitcoin_interp.S). The C seams*/
/* (taproot_keypath_verify{,_annex}, taproot_checksig_fn, ts_has_op_success_export,*/
/* tap_txctx_export) come from the C twin asm/bitcoin_taproot_sighash.c.*/
/* ============================================================================*/

    .section .text
    .global taproot_verify_input_asm
    .type   taproot_verify_input_asm,%function

/* externs ---------------------------------------------------------------*/
    .extern tap_leaf_hash
    .extern tap_merkle_root
    .extern taproot_tweak_pubkey
    .extern stack_push
    .extern script_eval
    .extern taproot_keypath_verify
    .extern taproot_keypath_verify_annex
    .extern taproot_checksig_fn
    .extern ts_has_op_success_export
    .extern tap_txctx_export
    .extern malloc
    .extern abort

/* constants -------------------------------------------------------------*/
.set ANNEX_TAG, 0x50
.set CTRL_BASE, 33
.set CTRL_NODE, 32
.set CTRL_MAX, (33 + 32*128)  /* 4129*/
.set LEAF_MASK, 0xfe
.set LEAF_TAPSCRIPT, 0xc0
.set TS_MAX_STACK, 1000
.set TS_MAX_ELEM, 520
.set TS_SIGV_TAPSCRIPT, 2
.set TS_FLAGS, ((1<<9)|(1<<10))  /* 0x600 CLTV|CSV*/
.set TS_ELEM_SIZE, 528

/* taproot_checksig_ctx offsets*/
.set C_TX, 0
.set C_TXLEN, 8
.set C_NIN, 16
.set C_PREVOUTS, 24
.set C_AMOUNTS, 32
.set C_SPKS, 40
.set C_NUMIN, 48
.set C_TAPLEAF, 56
.set C_CODESEP, 64
.set C_ANNEX, 72
.set C_ANNEXLEN, 80
.set C_WEIGHT, 88

/* ts_script_state offsets*/
.set S_MAIN, 0
.set S_MAINSP, 8
.set S_ALT, 16
.set S_ALTSP, 24
.set S_SCRIPT, 32
.set S_SCRIPTLEN, 40
.set S_SIGV, 48
.set S_FLAGS, 56
.set S_WORK, 64
.set S_WORKCAP, 72
.set S_ERROUT, 80
.set S_CSCTX, 88
.set S_CSFN, 96
.set S_LOCKTIME, 104
.set S_SEQUENCE, 108
.set S_VERSION, 112

/* frame locals (offset from locals base = sp after "sub sp,#FRAME")*/
/* callee-saved live across the whole fn: x19 spk x20 wit x21 witlen x22 nwit*/
/*   x23 tx x24 txlen x25 n_in x26 prevouts x27 amounts x28 spks*/
.set L_NUMIN, 0
.set L_REASON, 8
.set L_ANNEX, 16
.set L_ANNEXLEN, 24
.set L_EFF, 32
.set L_NINIT, 40
.set L_CONTROL, 48
.set L_CLEN, 56
.set L_SCRIPT, 64
.set L_SLEN, 72
.set L_WEIGHT, 80
.set L_SP, 88
.set L_MAIN, 96
.set L_ALT, 104
.set L_WORK, 112
.set L_LEAF, 128  /* 32 B -> 128..159*/
.set L_MERKLE, 160  /* 32 B -> 160..191*/
.set L_Q, 192  /* 32 B -> 192..223*/
.set L_ERR, 224           /* 8 B  -> 224..231*/
.set L_CTX, 240           /* 96 B -> 240..335*/
.set L_ST, 336            /* 120 B -> 336..455*/
.set L_LEAFV, 456         /* 8 B  (leaf_version, persists across bl) -> 456..463*/
.set L_X, 464             /* 40 B outgoing stack-arg area (arg9+), -> 464..503*/
.set FRAME, 0x200         /* 16-aligned, covers locals up to 503*/

/* .tbss TLS arenas (Initial-Exec; PIE + non-PIE) -------------------------*/
    .section .tbss,"awT",@nobits
    .global tv_main_e
tv_main_e:  .space 8
    .global tv_alt_e
tv_alt_e:   .space 8
    .global tv_work
tv_work:    .space 8

/* .rodata reason strings (byte-identical to the C twin) ------------------*/
    .section .rodata
e_empty:    .string "p2tr empty witness"
e_empty_ax: .string "p2tr empty witness after annex"
e_kp_ax:    .string "p2tr keypath (annex) signature invalid"
e_kp:       .string "p2tr keypath signature invalid"
e_ctrl:     .string "p2tr control block wrong size"
e_leafbig:  .string "p2tr tapscript too large"
e_merkle:   .string "p2tr merkle root reconstruction failed"
e_intpk:    .string "p2tr script-path internal pubkey invalid"
e_commit:   .string "p2tr script-path commitment mismatch"
e_parity:   .string "p2tr control block parity mismatch"
e_stackbig: .string "p2tr tapscript initial stack too large"
e_elembig:  .string "p2tr tapscript witness item exceeds 520 bytes"
e_overflow: .string "p2tr tapscript initial stack overflow"
e_exec:     .string "p2tr tapscript execution failed"

    .text

/* TLS Initial-Exec address of a .tbss symbol into d (clobbers x10)*/
.macro TLS_ADDR d, sym
    adrp \d, :gottprel:\sym
    ldr  \d, [\d, #:gottprel_lo12:\sym]
    mrs  x10, tpidr_el0
    add  \d, \d, x10
.endm

/* ---- compact-size byte count for n in x0 -> x0 (tv_cssize); clobbers x0,x9,x10*/
tv_cssize:
    mov  x9, #1
    cmp  x0, #0xfd
    b.lo .tvcs_d
    mov  x9, #3
    mov  x10, #0xffff
    cmp  x0, x10
    b.ls .tvcs_d
    mov  x9, #5
    mov  x10, #0xffff
    movk x10, #0xffff, lsl #16  /* 0xffffffff*/
    cmp  x0, x10
    b.ls .tvcs_d
    mov  x9, #9
.tvcs_d:
    mov  x0, x9
    ret

taproot_verify_input_asm:
/* --- capture incoming stack args (arg9..arg12) before adjusting sp ---*/
    ldr  x12, [sp, #0]  /* amounts*/
    ldr  x13, [sp, #8]  /* spks*/
    ldr  x14, [sp, #16]  /* num_inputs*/
    ldr  x15, [sp, #24]  /* reason*/
/* --- prologue ---*/
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    stp  x27, x28, [sp, #-16]!
    sub  sp, sp, #FRAME
/* --- stash registers that hold args ---*/
    mov  x19, x0  /* spk*/
    mov  x20, x1  /* wit*/
    mov  x21, x2  /* witlen*/
    mov  x22, x3  /* nwit*/
    mov  x23, x4  /* tx*/
    mov  x24, x5  /* txlen*/
    mov  x25, x6  /* n_in*/
    mov  x26, x7  /* prevouts*/
    mov  x27, x12  /* amounts*/
    mov  x28, x13  /* spks*/
    str  x14, [sp, #L_NUMIN]
    str  x15, [sp, #L_REASON]

/* ---- nwit == 0 -> empty witness ----*/
    cbz  x22, .r_empty

/* ---- annex detection ----*/
    str  xzr, [sp, #L_ANNEX]
    str  xzr, [sp, #L_ANNEXLEN]
    mov  x0, x22
    str  x0, [sp, #L_EFF]  /* eff = nwit*/
    cmp  x22, #2
    b.lo .eff_done
    sub  x9, x22, #1  /* idx = nwit-1*/
    ldr  w10, [x21, x9, lsl #2]  /* witlen[nwit-1]*/
    cbz  x10, .eff_done
    ldr  x11, [x20, x9, lsl #3]  /* wit[nwit-1]*/
    ldrb w10, [x11]
    cmp  w10, #ANNEX_TAG
    b.ne .eff_done
    str  x11, [sp, #L_ANNEX]
    ldr  w11, [x21, x9, lsl #2]
    str  x11, [sp, #L_ANNEXLEN]
    sub  x0, x22, #1
    str  x0, [sp, #L_EFF]  /* eff = nwit-1*/
.eff_done:
    ldr  x0, [sp, #L_EFF]
    cbz  x0, .r_empty_ax

/* ---- key path: eff == 1 ----*/
    cmp  x0, #1
    b.ne .script_path
    ldr  x1, [x20]  /* sig = wit[0]*/
    ldr  w2, [x21]  /* siglen = witlen[0]*/
    mov  x0, x19  /* spk*/
    mov  x3, x23  /* tx*/
    mov  x4, x24  /* txlen*/
    mov  x5, x25  /* n_in*/
    mov  x6, x26  /* prevouts*/
    mov  x7, x27  /* amounts*/
    str  x28, [sp, #L_X]  /* spks (arg9)*/
    ldr  x9, [sp, #L_NUMIN]
    str  x9, [sp, #(L_X+8)]  /* num_inputs (arg10)*/
    ldr  x9, [sp, #L_ANNEX]
    cbnz x9, .kp_annex
    bl   taproot_keypath_verify
    cbnz w0, .accept
    b    .r_kp
.kp_annex:
/* taproot_keypath_verify_annex(..., num_inputs, annex, annexlen, NULL)*/
    ldr  x9, [sp, #L_ANNEX]
    str  x9, [sp, #(L_X+16)]  /* arg11 annex*/
    ldr  x9, [sp, #L_ANNEXLEN]
    str  x9, [sp, #(L_X+24)]  /* arg12 annexlen*/
    str  xzr, [sp, #(L_X+32)]  /* arg13 NULL*/
    bl   taproot_keypath_verify_annex
    cbnz w0, .accept
    b    .r_kp_ax

.script_path:
/* control = wit[eff-1], script = wit[eff-2]*/
    ldr  x9, [sp, #L_EFF]
    sub  x9, x9, #1
    ldr  x10, [x20, x9, lsl #3]
    str  x10, [sp, #L_CONTROL]
    ldr  w10, [x21, x9, lsl #2]
    str  x10, [sp, #L_CLEN]
    sub  x9, x9, #1
    ldr  x10, [x20, x9, lsl #3]
    str  x10, [sp, #L_SCRIPT]
    ldr  w10, [x21, x9, lsl #2]
    str  x10, [sp, #L_SLEN]
/* control-block size rules*/
    ldr  x9, [sp, #L_CLEN]
    cmp  x9, #CTRL_BASE
    b.lo .r_ctrl
    mov  x10, #0x1021  /* CTRL_MAX = 4129*/
    cmp  x9, x10
    b.hi .r_ctrl
    sub  x9, x9, #CTRL_BASE
    and  x9, x9, #(CTRL_NODE-1)
    cbnz x9, .r_ctrl
/* leaf_version = control[0] & 0xfe*/
    ldr  x9, [sp, #L_CONTROL]
    ldrb w10, [x9]
    and  w11, w10, #LEAF_MASK
    str  w11, [sp, #L_LEAFV]  /* persist: x11 is caller-saved, clobbered by bls*/
/* tap_leaf_hash(leaf_hash, leaf_version, script, slen)*/
    add  x0, sp, #L_LEAF
    mov  w1, w11
    ldr  x2, [sp, #L_SCRIPT]
    ldr  x3, [sp, #L_SLEN]
    bl   tap_leaf_hash
    cmp  w0, #1
    b.ne .r_leafbig
/* tap_merkle_root(merkle_root, leaf_hash, 1, control, clen)*/
    add  x0, sp, #L_MERKLE
    add  x1, sp, #L_LEAF
    mov  x2, #1
    ldr  x3, [sp, #L_CONTROL]
    ldr  x4, [sp, #L_CLEN]
    bl   tap_merkle_root
    cmp  w0, #1
    b.ne .r_merkle
/* taproot_tweak_pubkey(computed_q, control+1, merkle_root)*/
    add  x0, sp, #L_Q
    ldr  x1, [sp, #L_CONTROL]
    add  x1, x1, #1
    add  x2, sp, #L_MERKLE
    bl   taproot_tweak_pubkey
    cbz  w0, .r_intpk
/* parity: (rv-1) == (control[0]&1)*/
    sub  w0, w0, #1
    ldr  x9, [sp, #L_CONTROL]
    ldrb w10, [x9]
    and  w10, w10, #1
    cmp  w0, w10
    b.ne .r_parity
/* memcmp(computed_q, spk+2, 32)  (4x8B xor/or)*/
    add  x11, sp, #L_Q
    add  x12, x19, #2
    ldr  x0, [x11]
    ldr  x1, [x12]
    eor  x0, x0, x1
    ldr  x2, [x11, #8]
    ldr  x3, [x12, #8]
    eor  x2, x2, x3
    orr  x0, x0, x2
    ldr  x2, [x11, #16]
    ldr  x3, [x12, #16]
    eor  x2, x2, x3
    orr  x0, x0, x2
    ldr  x2, [x11, #24]
    ldr  x3, [x12, #24]
    eor  x2, x2, x3
    orr  x0, x0, x2
    cbnz x0, .r_commit
/* unknown leaf version -> accept without executing*/
    ldr  w11, [sp, #L_LEAFV]  /* reload persisted leaf_version*/
    cmp  w11, #LEAF_TAPSCRIPT
    b.ne .accept
/* OP_SUCCESSx scan (Core's order: first)*/
    ldr  x0, [sp, #L_SCRIPT]
    ldr  x1, [sp, #L_SLEN]
    bl   ts_has_op_success_export
    cbnz w0, .accept
/* ninit = eff - 2 ; count limit, then per-element size limit*/
    ldr  x0, [sp, #L_EFF]
    sub  x0, x0, #2
    str  x0, [sp, #L_NINIT]
    mov  x12, #TS_MAX_STACK
    cmp  x0, x12
    b.hi .r_stackbig
/* size loop (no bl inside -> caller-saved counter ok)*/
    mov  x13, #0
.size_loop:
    ldr  x12, [sp, #L_NINIT]
    cmp  x13, x12
    b.hs .size_done
    ldr  w9, [x21, x13, lsl #2]
    mov  x11, #TS_MAX_ELEM
    cmp  x9, x11
    b.hi .r_elembig
    add  x13, x13, #1
    b    .size_loop
.size_done:

/* ---- BIP342 weight budget over the ORIGINAL full witness ----*/
    mov  x0, x22  /* nwit*/
    bl   tv_cssize
    mov  x9, x0  /* weight acc*/
    mov  x13, #0
.w_loop:
    cmp  x13, x22
    b.hs .w_done
    ldr  w10, [x21, x13, lsl #2]  /* witlen[i]*/
    mov  x0, x10
    bl   tv_cssize
    add  x9, x9, x0
    add  x9, x9, x10
    add  x13, x13, #1
    b    .w_loop
.w_done:
    add  x9, x9, #50
    str  x9, [sp, #L_WEIGHT]

/* ---- fill taproot_checksig_ctx ----*/
    add  x14, sp, #L_CTX
    str  x23, [x14, #C_TX]
    str  x24, [x14, #C_TXLEN]
    str  x25, [x14, #C_NIN]
    str  x26, [x14, #C_PREVOUTS]
    str  x27, [x14, #C_AMOUNTS]
    str  x28, [x14, #C_SPKS]
    ldr  x9, [sp, #L_NUMIN]
    str  x9, [x14, #C_NUMIN]
    add  x9, sp, #L_LEAF
    str  x9, [x14, #C_TAPLEAF]
    mov  w9, #0xffffffff
    str  w9, [x14, #C_CODESEP]
    ldr  x9, [sp, #L_ANNEX]
    str  x9, [x14, #C_ANNEX]
    ldr  x9, [sp, #L_ANNEXLEN]
    str  x9, [x14, #C_ANNEXLEN]
    ldr  x9, [sp, #L_WEIGHT]
    str  x9, [x14, #C_WEIGHT]

/* ---- per-thread arenas (lazy), then push the initial stack ----*/
    TLS_ADDR x16, tv_main_e
    ldr  x9, [x16]
    cbnz x9, .have_main
    mov  x0, #528
    movk x0, #1000, lsl #16  /* 1000*528 = 0x80E80*/
    mov  x1, x16
    bl   malloc
    cbz  x0, .abort
    str  x0, [x1]
    mov  x9, x0
.have_main:
    str  x9, [sp, #L_MAIN]

    TLS_ADDR x16, tv_alt_e
    ldr  x9, [x16]
    cbnz x9, .have_alt
    mov  x0, #528
    movk x0, #1000, lsl #16
    mov  x1, x16
    bl   malloc
    cbz  x0, .abort
    str  x0, [x1]
    mov  x9, x0
.have_alt:
    str  x9, [sp, #L_ALT]

    TLS_ADDR x16, tv_work
    ldr  x9, [x16]
    cbnz x9, .have_work
    mov  x0, #0
    movk x0, #1, lsl #16  /* 1<<16*/
    mov  x1, x16
    bl   malloc
    cbz  x0, .abort
    str  x0, [x1]
    mov  x9, x0
.have_work:
    str  x9, [sp, #L_WORK]

/* push initial stack: stack_push(&sp, main_elems, wit[i], witlen[i])*/
    str  xzr, [sp, #L_SP]
    mov  x13, #0
.push_loop:
    ldr  x12, [sp, #L_NINIT]
    cmp  x13, x12
    b.hs .push_done
    add  x0, sp, #L_SP
    ldr  x1, [sp, #L_MAIN]
    ldr  x2, [x20, x13, lsl #3]
    ldr  w3, [x21, x13, lsl #2]
    bl   stack_push
    cbz  w0, .r_overflow
    add  x13, x13, #1
    b    .push_loop
.push_done:

/* ---- fill ts_script_state (zeroed first, like the C's memset) ----*/
    add  x15, sp, #L_ST
    mov  x14, #120
    mov  x13, #0
.st_zero:
    strb wzr, [x15, x13]
    add  x13, x13, #1
    subs x14, x14, #1
    cbnz x14, .st_zero
    ldr  x9, [sp, #L_MAIN]
    str  x9, [x15, #S_MAIN]
    ldr  x9, [sp, #L_SP]
    str  x9, [x15, #S_MAINSP]
    ldr  x9, [sp, #L_ALT]
    str  x9, [x15, #S_ALT]
    str  xzr, [x15, #S_ALTSP]
    ldr  x9, [sp, #L_SCRIPT]
    str  x9, [x15, #S_SCRIPT]
    ldr  x9, [sp, #L_SLEN]
    str  x9, [x15, #S_SCRIPTLEN]
    mov  w9, #TS_SIGV_TAPSCRIPT
    str  w9, [x15, #S_SIGV]
    mov  x9, #TS_FLAGS
    str  x9, [x15, #S_FLAGS]
    ldr  x9, [sp, #L_WORK]
    str  x9, [x15, #S_WORK]
    mov  x9, #0
    movk x9, #1, lsl #16
    str  x9, [x15, #S_WORKCAP]
    str  xzr, [sp, #L_ERR]
    add  x9, sp, #L_ERR
    str  x9, [x15, #S_ERROUT]
    add  x9, sp, #L_CTX
    str  x9, [x15, #S_CSCTX]
    adrp x9, taproot_checksig_fn
    add  x9, x9, :lo12:taproot_checksig_fn
    str  x9, [x15, #S_CSFN]
/* tap_txctx_export(tx, txlen, n_in, &version, &locktime, &sequence)*/
    mov  x0, x23
    mov  x1, x24
    mov  x2, x25
    add  x3, x15, #S_VERSION
    add  x4, x15, #S_LOCKTIME
    add  x5, x15, #S_SEQUENCE
    bl   tap_txctx_export
/* run the tapscript*/
    add  x0, sp, #L_ST
    bl   script_eval
    cbz  w0, .r_exec
    b    .accept

.abort:
    bl   abort
    b    .abort

.r_empty:     adr x2, e_empty
              b   .reject
.r_empty_ax:  adr x2, e_empty_ax
              b   .reject
.r_kp_ax:     adr x2, e_kp_ax
              b   .reject
.r_kp:        adr x2, e_kp
              b   .reject
.r_ctrl:      adr x2, e_ctrl
              b   .reject
.r_leafbig:   adr x2, e_leafbig
              b   .reject
.r_merkle:    adr x2, e_merkle
              b   .reject
.r_parity:    adr x2, e_parity
              b   .reject
.r_intpk:     adr x2, e_intpk
              b   .reject
.r_commit:    adr x2, e_commit
              b   .reject
.r_stackbig:  adr x2, e_stackbig
              b   .reject
.r_elembig:   adr x2, e_elembig
              b   .reject
.r_overflow:  adr x2, e_overflow
              b   .reject
.r_exec:      adr x2, e_exec
.reject:
    ldr  x9, [sp, #L_REASON]
    str  x2, [x9]
    mov  w0, #0
    b    .out
.accept:
    mov  w0, #1
.out:
    add  sp, sp, #FRAME
    ldp  x27, x28, [sp], #16
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

    .section .note.GNU-stack,"",@progbits
