/* ============================================================================
 * bitcoin_interp.S -- AArch64 port of asm/bitcoin_interp.asm
 * (script_eval VM + helpers). Shared ABI: script_state struct + codec.
 *
 * Buffer globals (accessed via LAddr / *_addr below, thread-local in x86):
 *   interp_tmp (528B scratch elem), bool_buf, interp_err, interp_slice,
 *   cms_keyrefs, cms_sigrefs, cms_scstrip0, cms_scstrip1, cms_needle.
 *
 * Currently ported + verified:
 *   - is_opsuccess         (BIP342 OP_SUCCESSx range check, exhaustive)
 *   - is_opsuccess_c       (C-ABI wrapper)
 *   - interp_memeq         (byte compare -> 0/1)
 *   - interp_swap_recs     (swap two elem records via r13/r14-routed args)
 * NEXT: script_eval (the ~2000-line opcode-dispatch VM) + interp_push_num +
 * interp_push_bool + checksig/multisig subroutines.
 * ========================================================================== */

	.section .bss
	.align 4
interp_tmp:	.space 528
bool_buf:	.space 8
interp_err:	.space 8
interp_slice:	.space 32
cms_keyrefs:	.space 1024
cms_sigrefs:	.space 1024
cms_scstrip0:	.space 8192
cms_scstrip1:	.space 8192
cms_needle:	.space 1300

	.text

	/* is_opsuccess(opcode) -> x0 = 1 if opcode is a BIP342 OP_SUCCESSx.
	 * NOTE: x86 passes opcode in RAX; AAPCS64 passes first arg in x0, so both
	 * is_opsuccess and is_opsuccess_c read it from x0. */
	.global is_opsuccess
	.type   is_opsuccess,%function
is_opsuccess:
	cmp x0,#80
	b.eq .is_yes
	cmp x0,#98
	b.eq .is_yes
	cmp x0,#126
	b.lo .is_r131
	cmp x0,#129
	b.ls .is_yes
.is_r131:
	cmp x0,#131
	b.lo .is_r137
	cmp x0,#134
	b.ls .is_yes
.is_r137:
	cmp x0,#137
	b.lo .is_r141
	cmp x0,#138
	b.ls .is_yes
.is_r141:
	cmp x0,#141
	b.lo .is_r149
	cmp x0,#142
	b.ls .is_yes
.is_r149:
	cmp x0,#149
	b.lo .is_r187
	cmp x0,#153
	b.ls .is_yes
.is_r187:
	cmp x0,#187
	b.lo .is_no
	cmp x0,#254
	b.ls .is_yes
.is_no:
	mov w0,#0
	ret
.is_yes:
	mov w0,#1
	ret
	.size is_opsuccess,.-is_opsuccess

	/* is_opsuccess_c(opcode in x0) -> x0. Same register, so tail-call. */
	.global is_opsuccess_c
	.type   is_opsuccess_c,%function
is_opsuccess_c:
	b is_opsuccess
	.size is_opsuccess_c,.-is_opsuccess_c

	/* interp_memeq(a=x0, b=x1, len=x2) -> x0 = 1 if equal */
	.global interp_memeq
	.type   interp_memeq,%function
interp_memeq:
	mov  x3,#0
1:	cmp  x3,x2
	b.hs 2f
	ldrb w4,[x0,x3]
	ldrb w5,[x1,x3]
	cmp  w4,w5
	b.ne 3f
	add  x3,x3,#1
	b    1b
2:	mov  w0,#1
	ret
3:	mov  w0,#0
	ret
	.size interp_memeq,.-interp_memeq


/* ============================================================================
 * script_eval -- AArch64 port of asm/bitcoin_interp.asm:331-2476 (+helpers).
 * UNVERIFIED BUILD-IN-PROGRESS. Register map from x86:
 *   rbx->x19   r12(state)->x20   r13->x21   r14->x22   r15->x23
 * Frame: after stp x29,x30;stp x19,x20;stp x21,x22;stp x23,x24;sub sp,0xC0,
 * locals are sp-relative (see slot equates). All interp/codec helpers are
 * AArch64 leaves that preserve x19-x28, so live operands in x21..x23 survive
 * nested bl calls exactly as r13..r15 did on x86.
 * ========================================================================== */

	/* --- constants (SAME numeric values as the NASM %defines) --- */
	.equ SIGVERSION_BASE,0
	.equ SIGVERSION_WITNESS_V0,1
	.equ SIGVERSION_TAPSCRIPT,2
	.equ SCRIPT_VERIFY_STRICTENC,(1<<1)
	.equ SCRIPT_VERIFY_DERSIG,(1<<2)
	.equ SCRIPT_VERIFY_LOW_S,(1<<3)
	.equ SCRIPT_VERIFY_NULLDUMMY,(1<<4)
	.equ SCRIPT_VERIFY_MINIMALDATA,(1<<6)
	.equ SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,(1<<9)
	.equ SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,(1<<10)
	.equ SCRIPT_VERIFY_MINIMALIF,(1<<13)
	.equ SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,(1<<18)
	.equ SE_OK,0
	.equ SE_UNKNOWN_ERROR,1
	.equ SE_EVAL_FALSE,2
	.equ SE_OP_RETURN,3
	.equ SE_SCRIPTNUM,4
	.equ SE_SCRIPT_SIZE,5
	.equ SE_PUSH_SIZE,6
	.equ SE_OP_COUNT,7
	.equ SE_STACK_SIZE,8
	.equ SE_SIG_COUNT,9
	.equ SE_PUBKEY_COUNT,10
	.equ SE_VERIFY,11
	.equ SE_EQUALVERIFY,12
	.equ SE_CHECKMULTISIGVERIFY,13
	.equ SE_CHECKSIGVERIFY,14
	.equ SE_NUMEQUALVERIFY,15
	.equ SE_BAD_OPCODE,16
	.equ SE_DISABLED_OPCODE,17
	.equ SE_SIG_NULLDUMMY,28
	.equ SE_INVALID_STACK_OPERATION,18
	.equ SE_INVALID_ALTSTACK_OPERATION,19
	.equ SE_UNBALANCED_CONDITIONAL,20
	.equ SE_NEGATIVE_LOCKTIME,21
	.equ SE_UNSATISFIED_LOCKTIME,22
	.equ SE_SIG_DER,24
	.equ SE_MINIMALDATA,25
	.equ SE_CLEANSTACK,30
	.equ SE_MINIMALIF,31
	.equ SE_DISCOURAGE_OP_SUCCESS,36
	.equ SE_TAPSCRIPT_CHECKMULTISIG,50
	.equ SE_TAPSCRIPT_MINIMALIF,51
	.equ OP_1NEGATE,0x4f
	.equ OP_RESERVED,0x50
	.equ OP_1,0x51
	.equ OP_16,0x60
	.equ OP_PUSHDATA4,0x4e
	.equ OP_NOP,0x61
	.equ OP_VER,0x62
	.equ OP_IF,0x63
	.equ OP_NOTIF,0x64
	.equ OP_ELSE,0x67
	.equ OP_ENDIF,0x68
	.equ OP_VERIFY,0x69
	.equ OP_RETURN,0x6a
	.equ OP_TOALTSTACK,0x6b
	.equ OP_FROMALTSTACK,0x6c
	.equ OP_2DROP,0x6d
	.equ OP_2DUP,0x6e
	.equ OP_3DUP,0x6f
	.equ OP_2OVER,0x70
	.equ OP_2ROT,0x71
	.equ OP_2SWAP,0x72
	.equ OP_IFDUP,0x73
	.equ OP_DEPTH,0x74
	.equ OP_DROP,0x75
	.equ OP_DUP,0x76
	.equ OP_NIP,0x77
	.equ OP_OVER,0x78
	.equ OP_PICK,0x79
	.equ OP_ROLL,0x7a
	.equ OP_ROT,0x7b
	.equ OP_SWAP,0x7c
	.equ OP_TUCK,0x7d
	.equ OP_CAT,0x7e
	.equ OP_SUBSTR,0x7f
	.equ OP_LEFT,0x80
	.equ OP_RIGHT,0x81
	.equ OP_SIZE,0x82
	.equ OP_INVERT,0x83
	.equ OP_AND,0x84
	.equ OP_OR,0x85
	.equ OP_XOR,0x86
	.equ OP_EQUAL,0x87
	.equ OP_EQUALVERIFY,0x88
	.equ OP_1ADD,0x8b
	.equ OP_1SUB,0x8c
	.equ OP_2MUL,0x8d
	.equ OP_2DIV,0x8e
	.equ OP_NEGATE,0x8f
	.equ OP_ABS,0x90
	.equ OP_NOT,0x91
	.equ OP_0NOTEQUAL,0x92
	.equ OP_ADD,0x93
	.equ OP_SUB,0x94
	.equ OP_MUL,0x95
	.equ OP_DIV,0x96
	.equ OP_MOD,0x97
	.equ OP_LSHIFT,0x98
	.equ OP_RSHIFT,0x99
	.equ OP_BOOLAND,0x9a
	.equ OP_BOOLOR,0x9b
	.equ OP_NUMEQUAL,0x9c
	.equ OP_NUMEQUALVERIFY,0x9d
	.equ OP_NUMNOTEQUAL,0x9e
	.equ OP_LESSTHAN,0x9f
	.equ OP_GREATERTHAN,0xa0
	.equ OP_LESSTHANOREQUAL,0xa1
	.equ OP_GREATERTHANOREQUAL,0xa2
	.equ OP_MIN,0xa3
	.equ OP_MAX,0xa4
	.equ OP_WITHIN,0xa5
	.equ OP_RIPEMD160,0xa6
	.equ OP_SHA1,0xa7
	.equ OP_SHA256,0xa8
	.equ OP_HASH160,0xa9
	.equ OP_HASH256,0xaa
	.equ OP_CODESEPARATOR,0xab
	.equ OP_CHECKSIG,0xac
	.equ OP_CHECKSIGVERIFY,0xad
	.equ OP_CHECKMULTISIG,0xae
	.equ OP_CHECKMULTISIGVERIFY,0xaf
	.equ OP_NOP1,0xb0
	.equ OP_CHECKLOCKTIMEVERIFY,0xb1
	.equ OP_CHECKSEQUENCEVERIFY,0xb2
	.equ OP_NOP4,0xb3
	.equ OP_NOP5,0xb4
	.equ OP_NOP6,0xb5
	.equ OP_NOP7,0xb6
	.equ OP_NOP8,0xb7
	.equ OP_NOP9,0xb8
	.equ OP_NOP10,0xb9
	.equ OP_CHECKSIGADD,0xba
	.equ ELEM_SIZE,528
	.equ ELEM_DATA_OFF,4
	.equ MAX_STACK_SIZE,1000
	.equ MAX_SCRIPT_SIZE,10000
	.equ MAX_SCRIPT_ELEMENT_SIZE,520
	.equ MAX_OPS_PER_SCRIPT,201
	.equ LOCKTIME_THRESHOLD,500000000
	.equ SEQUENCE_FINAL,0xffffffff

	/* frame slot offsets (sp-relative) */
	.equ SL_FEXEC,0x00
	.equ SL_PC,0x08
	.equ SL_PEND,0x10
	.equ SL_BECH,0x18		/* pbegincodehash */
	.equ SL_OPCOUNT,0x20
	.equ SL_CSP,0x28		/* codeseparator position counter */
	.equ SL_OP,0x30		/* opcode */
	.equ SL_PUSHLEN,0x38
	.equ SL_CSPOS,0x40		/* BIP342 codesep_pos (0xffffffff = none) */
	.equ SL_SCANPC,0x48		/* prescan pc */
	.equ SL_SCANPEND,0x50	/* prescan pend */
	.equ SL_ITMP,0x58
	.equ SL_BOOL,0x60
	.equ SL_IERR,0x68
	.equ SL_ISLICE,0x70
	.equ SL_CSK,0x78
	.equ SL_CSS,0x80
	.equ SL_ET0,0x88
	.equ SL_ET1,0x90
	.equ SL_ET2,0x98
	.equ SL_ET3,0xa0
	.equ SL_SNUMOVF,0xa8

	/* macros */
	.macro CSTK		/* x0=&state.sp, x1=state.elems */
	add x0, x20, #8
	ldr x1, [x20]
	.endm
	.macro ALCK		/* x0=&alt.sp=state+24, x1=alt.elems=state+16 */
	add x0, x20, #24
	ldr x1, [x20, #16]
	.endm
	.macro RDLEN d, rec	/* d := u32 len of elem record @rec */
	ldr \d, [\rec]
	.endm

.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
.endm

	.global script_eval
	.type   script_eval,%function
script_eval:
	/* prologue: save x19..x24 + x29/x30; locals 0xC0 (16-aligned) */
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	sub  sp,sp,#0xC0
	mov  x24,sp			/* interp_* helper frame-slot base */
	mov  x20,x0			/* state */

	/* per-thread scratch addresses */
	LAddr x2, interp_tmp
	str  x2,[sp,#SL_ITMP]
	LAddr x2, bool_buf
	str  x2,[sp,#SL_BOOL]
	LAddr x2, interp_err
	str  x2,[sp,#SL_IERR]
	LAddr x2, interp_slice
	str  x2,[sp,#SL_ISLICE]
	LAddr x2, cms_keyrefs
	str  x2,[sp,#SL_CSK]
	LAddr x2, cms_sigrefs
	str  x2,[sp,#SL_CSS]
	LAddr x2, elem_tmp0
	str  x2,[sp,#SL_ET0]
	LAddr x2, elem_tmp1
	str  x2,[sp,#SL_ET1]
	LAddr x2, elem_tmp2
	str  x2,[sp,#SL_ET2]
	LAddr x2, elem_tmp3
	str  x2,[sp,#SL_ET3]
	LAddr x2, snum_overflow
	str  x2,[sp,#SL_SNUMOVF]

	/* script size limit (BASE/WITNESS_V0) */
	ldr  w2,[x20,#48]
	cmp  x2,#SIGVERSION_TAPSCRIPT
	b.eq .ss_ok
	ldr  x2,[x20,#40]
	mov  x9,#MAX_SCRIPT_SIZE
	cmp  x2,x9
	b.ls .ss_ok
	mov  w0,#SE_SCRIPT_SIZE
	b    .err_ret0
.ss_ok:
	/* pc=script ; pend=script+len ; pbegincodehash=script */
	ldr  x2,[x20,#32]
	str  x2,[sp,#SL_PC]
	ldr  x3,[x20,#40]
	add  x3,x2,x3
	str  x3,[sp,#SL_PEND]
	str  x2,[sp,#SL_BECH]
	str  xzr,[sp,#SL_OPCOUNT]
	str  xzr,[sp,#SL_CSP]
	mov  x2,#0xffffffff
	str  x2,[sp,#SL_CSPOS]
	bl   vfexec_sp_reset

	/* ---- tapscript OP_SUCCESSx pre-scan ---- */
	ldr  w2,[x20,#48]
	cmp  x2,#SIGVERSION_TAPSCRIPT
	b.ne .prescan_done
	ldr  x2,[x20,#32]
	str  x2,[sp,#SL_SCANPC]
	ldr  x3,[x20,#40]
	add  x3,x2,x3
	str  x3,[sp,#SL_SCANPEND]
.prescan_loop:
	add  x0,sp,#SL_SCANPC
	ldr  x1,[sp,#SL_SCANPEND]
	bl   get_op
	cbz  x0,.prescan_done
	sub  x0,x0,#1		/* opcode */
	bl   is_opsuccess
	cbz  x0,.prescan_loop
	/* found OP_SUCCESSx */
	ldr  x2,[x20,#56]
	tst  x2,#SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
	b.ne .prescan_discourage
	ldr  x2,[x20,#80]
	cbz  x2,1f
	mov  w3,#SE_OK
	str  w3,[x2]
1:	mov  w0,#1
	b    .done
.prescan_discourage:
	mov  w0,#SE_DISCOURAGE_OP_SUCCESS
	b    .err_ret0
.prescan_done:

.loop:
	/* if pc >= pend -> done (x86 cmp rbp-0x18; jae .loop_done) */
	ldr  x2,[sp,#SL_PC]
	ldr  x3,[sp,#SL_PEND]
	cmp  x2,x3
	b.hs .loop_done
	bl   vfexec_all_true
	str  x0,[sp,#SL_FEXEC]
	/* get_op */
	add  x0,sp,#SL_PC
	ldr  x1,[sp,#SL_PEND]
	bl   get_op
	cbnz x0,.op_ok
	mov  w0,#SE_BAD_OPCODE
	b    .err_ret0
.op_ok:
	sub  x0,x0,#1
	str  x0,[sp,#SL_OP]	/* opcode */
	str  x1,[sp,#SL_PUSHLEN]

	cmp  x1,#MAX_SCRIPT_ELEMENT_SIZE
	b.ls .ps_ok
	mov  w0,#SE_PUSH_SIZE
	b    .err_ret0
.ps_ok:
	/* opcount (not tapscript) */
	ldr  w2,[x20,#48]
	cmp  x2,#SIGVERSION_TAPSCRIPT
	b.eq .oc_skip
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_16
	b.ls .oc_skip
	ldr  x3,[sp,#SL_OPCOUNT]
	add  x3,x3,#1
	str  x3,[sp,#SL_OPCOUNT]
	cmp  x3,#MAX_OPS_PER_SCRIPT
	b.ls .oc_skip
	mov  w0,#SE_OP_COUNT
	b    .err_ret0
.oc_skip:
	/* disabled opcodes */
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_CAT
	b.eq .disabled
	cmp  x2,#OP_SUBSTR
	b.eq .disabled
	cmp  x2,#OP_LEFT
	b.eq .disabled
	cmp  x2,#OP_RIGHT
	b.eq .disabled
	cmp  x2,#OP_INVERT
	b.eq .disabled
	cmp  x2,#OP_AND
	b.eq .disabled
	cmp  x2,#OP_OR
	b.eq .disabled
	cmp  x2,#OP_XOR
	b.eq .disabled
	cmp  x2,#OP_2MUL
	b.eq .disabled
	cmp  x2,#OP_2DIV
	b.eq .disabled
	cmp  x2,#OP_MUL
	b.eq .disabled
	cmp  x2,#OP_DIV
	b.eq .disabled
	cmp  x2,#OP_MOD
	b.eq .disabled
	cmp  x2,#OP_LSHIFT
	b.eq .disabled
	cmp  x2,#OP_RSHIFT
	b.eq .disabled
	b    .not_disabled
.disabled:
	mov  w0,#SE_DISABLED_OPCODE
	b    .err_ret0
.not_disabled:
	/* push opcode 0..PUSHDATA4 */
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_PUSHDATA4
	b.hi .not_push
	ldr  x2,[sp,#SL_FEXEC]
	cbz  x2,.next_op
	/* minimal push */
	ldr  x2,[x20,#56]
	tst  x2,#SCRIPT_VERIFY_MINIMALDATA
	b.eq .mp_ok
	ldr  x0,[sp,#SL_OP]
	ldr  x1,[sp,#SL_PUSHLEN]
	ldr  x2,[sp,#SL_PC]
	ldr  x9,[sp,#SL_PUSHLEN]
	sub  x2,x2,x9
	bl   check_minimal_push
	cbnz x0,.mp_ok
	mov  w0,#SE_MINIMALDATA
	b    .err_ret0
.mp_ok:
	CSTK
	ldr  x2,[sp,#SL_PC]
	ldr  x9,[sp,#SL_PUSHLEN]
	sub  x2,x2,x9
	ldr  x3,[sp,#SL_PUSHLEN]
	bl   stack_push
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0
.not_push:
	/* if not executing and not IF..ENDIF, skip */
	ldr  x2,[sp,#SL_FEXEC]
	cbnz x2,.dispatch
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_IF
	b.lo .next_op
	cmp  x2,#OP_ENDIF
	b.hi .next_op

.dispatch:
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_1NEGATE
	b.eq .pushnum
	cmp  x2,#OP_1
	b.lo .bad_opcode
	cmp  x2,#OP_16
	b.ls .pushnum
	cmp  x2,#OP_NOP
	b.eq .next_op
	cmp  x2,#OP_IF
	b.eq .op_if
	cmp  x2,#OP_NOTIF
	b.eq .op_if
	cmp  x2,#OP_ELSE
	b.eq .op_else
	cmp  x2,#OP_ENDIF
	b.eq .op_endif
	cmp  x2,#OP_VERIFY
	b.eq .op_verify
	cmp  x2,#OP_RETURN
	b.eq .op_return
	cmp  x2,#OP_TOALTSTACK
	b.eq .op_toalt
	cmp  x2,#OP_FROMALTSTACK
	b.eq .op_fromalt
	cmp  x2,#OP_2DROP
	b.eq .op_2drop
	cmp  x2,#OP_2DUP
	b.eq .op_2dup
	cmp  x2,#OP_3DUP
	b.eq .op_3dup
	cmp  x2,#OP_2OVER
	b.eq .op_2over
	cmp  x2,#OP_2ROT
	b.eq .op_2rot
	cmp  x2,#OP_2SWAP
	b.eq .op_2swap
	cmp  x2,#OP_IFDUP
	b.eq .op_ifdup
	cmp  x2,#OP_DEPTH
	b.eq .op_depth
	cmp  x2,#OP_DROP
	b.eq .op_drop
	cmp  x2,#OP_DUP
	b.eq .op_dup
	cmp  x2,#OP_NIP
	b.eq .op_nip
	cmp  x2,#OP_OVER
	b.eq .op_over
	cmp  x2,#OP_PICK
	b.eq .op_pick
	cmp  x2,#OP_ROLL
	b.eq .op_pick
	cmp  x2,#OP_ROT
	b.eq .op_rot
	cmp  x2,#OP_SWAP
	b.eq .op_swap
	cmp  x2,#OP_TUCK
	b.eq .op_tuck
	cmp  x2,#OP_SIZE
	b.eq .op_size
	cmp  x2,#OP_EQUAL
	b.eq .op_equal
	cmp  x2,#OP_EQUALVERIFY
	b.eq .op_equal
	cmp  x2,#OP_1ADD
	b.eq .op_mono1
	cmp  x2,#OP_1SUB
	b.eq .op_mono2
	cmp  x2,#OP_NEGATE
	b.eq .op_mono3
	cmp  x2,#OP_ABS
	b.eq .op_mono4
	cmp  x2,#OP_NOT
	b.eq .op_mono5
	cmp  x2,#OP_0NOTEQUAL
	b.eq .op_mono6
	cmp  x2,#OP_ADD
	b.eq .op_bin1
	cmp  x2,#OP_SUB
	b.eq .op_bin2
	cmp  x2,#OP_BOOLAND
	b.eq .op_bin3
	cmp  x2,#OP_BOOLOR
	b.eq .op_bin4
	cmp  x2,#OP_NUMEQUAL
	b.eq .op_bin5
	cmp  x2,#OP_NUMEQUALVERIFY
	b.eq .op_bin5
	cmp  x2,#OP_NUMNOTEQUAL
	b.eq .op_bin7
	cmp  x2,#OP_LESSTHAN
	b.eq .op_bin8
	cmp  x2,#OP_GREATERTHAN
	b.eq .op_bin9
	cmp  x2,#OP_LESSTHANOREQUAL
	b.eq .op_bin10
	cmp  x2,#OP_GREATERTHANOREQUAL
	b.eq .op_bin11
	cmp  x2,#OP_MIN
	b.eq .op_bin12
	cmp  x2,#OP_MAX
	b.eq .op_bin13
	cmp  x2,#OP_WITHIN
	b.eq .op_within
	cmp  x2,#OP_RIPEMD160
	b.eq .op_crypto
	cmp  x2,#OP_SHA1
	b.eq .op_crypto
	cmp  x2,#OP_SHA256
	b.eq .op_crypto
	cmp  x2,#OP_HASH160
	b.eq .op_crypto
	cmp  x2,#OP_HASH256
	b.eq .op_crypto
	cmp  x2,#OP_CODESEPARATOR
	b.eq .op_cs
	cmp  x2,#OP_CHECKSIG
	b.eq .op_checksig
	cmp  x2,#OP_CHECKSIGVERIFY
	b.eq .op_checksig
	cmp  x2,#OP_CHECKSIGADD
	b.eq .op_checksigadd
	cmp  x2,#OP_CHECKMULTISIG
	b.eq .op_checkmultisig
	cmp  x2,#OP_CHECKMULTISIGVERIFY
	b.eq .op_checkmultisig
	cmp  x2,#OP_CHECKLOCKTIMEVERIFY
	b.eq .op_cltv
	cmp  x2,#OP_CHECKSEQUENCEVERIFY
	b.eq .op_csv
	cmp  x2,#OP_NOP1
	b.eq .next_op
	cmp  x2,#OP_NOP4
	b.eq .next_op
	cmp  x2,#OP_NOP5
	b.eq .next_op
	cmp  x2,#OP_NOP6
	b.eq .next_op
	cmp  x2,#OP_NOP7
	b.eq .next_op
	cmp  x2,#OP_NOP8
	b.eq .next_op
	cmp  x2,#OP_NOP9
	b.eq .next_op
	cmp  x2,#OP_NOP10
	b.eq .next_op
	b    .bad_opcode

/* --- pushnum: OP_1..OP_16 / OP_1NEGATE --- */
.pushnum:
	ldr  x2,[sp,#SL_OP]
	sub  x2,x2,#(OP_1-1)	/* value */
	CSTK
	bl   interp_push_num
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0

/* --- control flow --- */
.op_if:
	ldr  x2,[sp,#SL_FEXEC]
	cbz  x2,.if_notexec
	CSTK
	bl   stack_depth
	cmp  x0,#1
	b.hs .if_sok
	mov  w0,#SE_INVALID_STACK_OPERATION
	b    .err_ret0
.if_sok:
	CSTK
	bl   stack_top_ptr
	mov  x21,x0		/* element rec */
	/* tapscript minimal-if */
	ldr  w2,[x20,#48]
	cmp  x2,#SIGVERSION_TAPSCRIPT
	b.ne .if_tapd
	ldr  w2,[x21]
	cmp  w2,#2
	b.hs .tap_minif
	cbz  w2,.if_minif_ok		/* len==0 -> ok (false) */
	ldrb w3,[x21,#ELEM_DATA_OFF]
	cmp  w3,#1
	b.eq .if_minif_ok		/* len==1 && byte==1 -> ok */
.tap_minif:
	mov  w0,#SE_TAPSCRIPT_MINIMALIF
	b    .err_ret0
.if_tapd:
	ldr  w2,[x20,#48]
	cmp  x2,#SIGVERSION_WITNESS_V0
	b.ne .if_minif_ok
	ldr  x2,[x20,#56]
	tst  x2,#SCRIPT_VERIFY_MINIMALIF
	b.eq .if_minif_ok
	ldr  w2,[x21]
	cmp  w2,#2
	b.hs .wif_minif
	cbz  w2,.if_minif_ok
	ldrb w3,[x21,#ELEM_DATA_OFF]
	cmp  w3,#1
	b.eq .if_minif_ok
.wif_minif:
	mov  w0,#SE_MINIMALDATA
	b    .err_ret0
.if_minif_ok:
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	bl   cast_to_bool
	mov  x22,x0
	CSTK
	bl   stack_pop
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_NOTIF
	b.ne 1f
	eor  x22,x22,#1
1:	mov  x0,x22
	bl   vfexec_push
	b    .next_op
.if_notexec:
	mov  x0,#0
	bl   vfexec_push
	b    .next_op

.op_else:
	bl   vfexec_depth
	cbnz x0,.else_ok
	mov  w0,#SE_UNBALANCED_CONDITIONAL
	b    .err_ret0
.else_ok:
	bl   vfexec_toggle_top
	b    .next_op

.op_endif:
	bl   vfexec_depth
	cbnz x0,.endif_ok
	mov  w0,#SE_UNBALANCED_CONDITIONAL
	b    .err_ret0
.endif_ok:
	bl   vfexec_pop
	b    .next_op

.op_verify:
	CSTK
	bl   stack_depth
	cmp  x0,#1
	b.hs .vfy_ok
	mov  w0,#SE_INVALID_STACK_OPERATION
	b    .err_ret0
.vfy_ok:
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	bl   cast_to_bool
	cbz  x0,.vfy_fail
	CSTK
	bl   stack_pop
	b    .next_op
.vfy_fail:
	mov  w0,#SE_VERIFY
	b    .err_ret0

.op_return:
	mov  w0,#SE_OP_RETURN
	b    .err_ret0

/* --- stack ops --- */
.op_toalt:
	CSTK
	bl   stack_depth
	cmp  x0,#1
	b.hs .toalt_ok
	mov  w0,#SE_INVALID_STACK_OPERATION
	b    .err_ret0
.toalt_ok:
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  x2,[sp,#SL_ET0]
	mov  x0,x2
	mov  x1,x21
	bl   elem_move
	CSTK
	bl   stack_pop
	ALCK
	ldr  x2,[sp,#SL_ET0]
	mov  x3,x2
	ldr  w3,[x3]		/* len u32 */
	add  x2,x2,#ELEM_DATA_OFF
	bl   stack_push
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0

.op_fromalt:
	ALCK
	bl   stack_depth
	cmp  x0,#1
	b.hs .fromalt_ok
	mov  w0,#SE_INVALID_ALTSTACK_OPERATION
	b    .err_ret0
.fromalt_ok:
	ALCK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  x2,[sp,#SL_ET0]
	mov  x0,x2
	mov  x1,x21
	bl   elem_move
	ALCK
	bl   stack_pop
	CSTK
	ldr  x2,[sp,#SL_ET0]
	mov  x3,x2
	ldr  w3,[x3]
	add  x2,x2,#ELEM_DATA_OFF
	bl   stack_push
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0

.op_2drop:
	CSTK
	bl   stack_depth
	cmp  x0,#2
	b.hs .d2_ok
	mov  w0,#SE_INVALID_STACK_OPERATION
	b    .err_ret0
.d2_ok:
	CSTK
	bl   stack_pop
	CSTK
	bl   stack_pop
	b    .next_op

.op_2dup:
	mov  x0,#2
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_depth
	sub  x0,x0,#2
	mov  x2,x0
	CSTK
	bl   stack_dup_index
	CSTK
	bl   stack_depth
	sub  x0,x0,#2
	mov  x2,x0
	CSTK
	bl   stack_dup_index
	b    .next_op

.op_3dup:
	mov  x0,#3
	bl   interp_require_depth
	cbnz x0,.err_ret0
	mov  x19,#3
1:	CSTK
	bl   stack_depth
	sub  x0,x0,#3
	mov  x2,x0
	CSTK
	bl   stack_dup_index
	subs x19,x19,#1
	b.ne 1b
	b    .next_op

.op_2over:
	mov  x0,#4
	bl   interp_require_depth
	cbnz x0,.err_ret0
	mov  x19,#2
1:	CSTK
	bl   stack_depth
	sub  x0,x0,#4
	mov  x2,x0
	CSTK
	bl   stack_dup_index
	subs x19,x19,#1
	b.ne 1b
	b    .next_op

.op_2swap:
	mov  x0,#4
	bl   interp_require_depth
	cbnz x0,.err_ret0
	/* swap x1(0)<->x3(2) */
	CSTK
	bl   stack_depth
	sub  x0,x0,#4
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	mov  x21,x0
	CSTK
	bl   stack_depth
	sub  x0,x0,#2
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	mov  x22,x0
	bl   interp_swap_recs
	/* x2(1) <-> x4(3) */
	CSTK
	bl   stack_depth
	sub  x0,x0,#3
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	mov  x21,x0
	CSTK
	bl   stack_depth
	sub  x0,x0,#1
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	mov  x22,x0
	bl   interp_swap_recs
	b    .next_op

.op_2rot:
	mov  x0,#6
	bl   interp_require_depth
	cbnz x0,.err_ret0
	mov  x19,#0
	/* copy x1(0), x2(1) into et0,et1 */
	CSTK
	bl   stack_depth
	sub  x0,x0,#6
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	mov  x9,x0			/* src elem ptr (sp-6) */
	ldr  x3,[sp,#SL_ET0]
	mov  x0,x3			/* dst = et0 */
	mov  x1,x9			/* src */
	bl   elem_move
	CSTK
	bl   stack_depth
	sub  x0,x0,#5
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	ldr  x3,[sp,#SL_ET1]
	mov  x9,x0
	mov  x0,x3
	mov  x1,x9
	bl   elem_move
	/* erase idx sp-6 */
	CSTK
	bl   stack_depth
	sub  x0,x0,#6
	mov  x2,x0
	CSTK
	bl   stack_erase_index
	/* erase idx sp-5 */
	CSTK
	bl   stack_depth
	sub  x0,x0,#5
	mov  x2,x0
	CSTK
	bl   stack_erase_index
	/* push et0, et1 */
	CSTK
	ldr  x2,[sp,#SL_ET0]
	mov  x3,x2
	ldr  w3,[x3]
	add  x2,x2,#ELEM_DATA_OFF
	bl   stack_push
	CSTK
	ldr  x2,[sp,#SL_ET1]
	mov  x3,x2
	ldr  w3,[x3]
	add  x2,x2,#ELEM_DATA_OFF
	bl   stack_push
	b    .next_op

.op_ifdup:
	mov  x0,#1
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	bl   cast_to_bool
	cbz  x0,.next_op
	CSTK
	bl   stack_depth
	sub  x0,x0,#1
	mov  x2,x0
	CSTK
	bl   stack_dup_index
	b    .next_op

.op_depth:
	CSTK
	bl   stack_depth
	mov  x2,x0
	CSTK
	bl   interp_push_num
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0

.op_drop:
	mov  x0,#1
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_pop
	b    .next_op

.op_dup:
	mov  x0,#1
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_depth
	sub  x0,x0,#1
	mov  x2,x0
	CSTK
	bl   stack_dup_index
	b    .next_op

.op_nip:
	mov  x0,#2
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_depth
	sub  x0,x0,#2
	mov  x2,x0
	CSTK
	bl   stack_erase_index
	b    .next_op

.op_over:
	mov  x0,#2
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_depth
	sub  x0,x0,#2
	mov  x2,x0
	CSTK
	bl   stack_dup_index
	b    .next_op

.op_pick:			/* OP_PICK / OP_ROLL */
	mov  x0,#2
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	mov  x19,x0		/* n */
	CSTK
	bl   stack_pop
	tbnz x19,#63,.pk_fail
	CSTK
	bl   stack_depth
	cmp  x19,x0
	b.hs .pk_fail
	CSTK
	bl   stack_depth
	sub  x0,x0,#1
	sub  x0,x0,x19
	mov  x22,x0		/* idx */
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_ROLL
	b.ne .pkdup
	/* roll: copy idx, erase idx, push */
	CSTK
	mov  x2,x22
	bl   stack_elem_ptr
	ldr  x3,[sp,#SL_ET0]
	mov  x9,x0
	mov  x0,x3
	mov  x1,x9
	bl   elem_move
	CSTK
	mov  x2,x22
	bl   stack_erase_index
	CSTK
	ldr  x2,[sp,#SL_ET0]
	mov  x3,x2
	ldr  w3,[x3]
	add  x2,x2,#ELEM_DATA_OFF
	bl   stack_push
	b    .next_op
.pkdup:
	CSTK
	mov  x2,x22
	bl   stack_dup_index
	b    .next_op
.pk_fail:
	mov  w0,#SE_INVALID_STACK_OPERATION
	b    .err_ret0

.op_rot:
	mov  x0,#3
	bl   interp_require_depth
	cbnz x0,.err_ret0
	/* ROT: (x1 x2 x3) -> (x2 x3 x1). swap(sp-3,sp-2) then swap(sp-2,sp-1). */
	CSTK
	bl   stack_depth
	sub  x0,x0,#3
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	mov  x21,x0		/* a = sp-3 */
	CSTK
	bl   stack_depth
	sub  x0,x0,#2
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	mov  x22,x0		/* b = sp-2 */
	bl   interp_swap_recs
	CSTK
	bl   stack_depth
	sub  x0,x0,#2
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	mov  x21,x0		/* a = sp-2 */
	CSTK
	bl   stack_depth
	sub  x0,x0,#1
	mov  x2,x0
	CSTK
	bl   stack_elem_ptr
	mov  x22,x0		/* b = sp-1 */
	bl   interp_swap_recs
	b    .next_op

.op_swap:
	mov  x0,#2
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_swap_two
	b    .next_op

.op_tuck:
	mov  x0,#2
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  x3,[sp,#SL_ET2]
	mov  x0,x3
	mov  x1,x21
	bl   elem_move		/* et2 = x2 (top) */
	CSTK
	bl   stack_second_ptr
	mov  x21,x0
	ldr  x3,[sp,#SL_ET3]
	mov  x0,x3
	mov  x1,x21
	bl   elem_move		/* et3 = x1 (second) */
	CSTK
	bl   stack_pop
	CSTK
	bl   stack_pop
	/* push x2(top), x1, x2 */
	CSTK
	ldr  x2,[sp,#SL_ET2]
	mov  x3,x2
	ldr  w3,[x3]
	add  x2,x2,#ELEM_DATA_OFF
	bl   stack_push
	CSTK
	ldr  x2,[sp,#SL_ET3]
	mov  x3,x2
	ldr  w3,[x3]
	add  x2,x2,#ELEM_DATA_OFF
	bl   stack_push
	CSTK
	ldr  x2,[sp,#SL_ET2]
	mov  x3,x2
	ldr  w3,[x3]
	add  x2,x2,#ELEM_DATA_OFF
	bl   stack_push
	b    .next_op

.op_size:
	mov  x0,#1
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]		/* len u32 */
	CSTK
	bl   interp_push_num
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0

/* --- equality --- */
.op_equal:
	mov  x0,#2
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_top_ptr
	mov  x21,x0		/* x2 */
	CSTK
	bl   stack_second_ptr
	mov  x22,x0		/* x1 */
	ldr  w2,[x21]
	ldr  w3,[x22]
	cmp  w2,w3
	b.ne .eq_false
	add  x0,x22,#ELEM_DATA_OFF
	add  x1,x21,#ELEM_DATA_OFF
	mov  x2,x2		/* len */
	bl   interp_memeq
	cbz  x0,.eq_false
	mov  x23,#1
	b    .eq_have
.eq_false:
	mov  x23,#0
.eq_have:
	CSTK
	bl   stack_pop
	CSTK
	bl   stack_pop
	CSTK
	mov  x2,x23
	bl   interp_push_bool
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_EQUALVERIFY
	b.ne .next_op
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	bl   cast_to_bool
	cbz  x0,.eqv_fail
	CSTK
	bl   stack_pop
	b    .next_op
.eqv_fail:
	mov  w0,#SE_EQUALVERIFY
	b    .err_ret0

/* --- monadic numeric --- */
.op_mono1: mov x19,#1
	b    .mono_common
.op_mono2: mov x19,#2
	b    .mono_common
.op_mono3: mov x19,#3
	b    .mono_common
.op_mono4: mov x19,#4
	b    .mono_common
.op_mono5: mov x19,#5
	b    .mono_common
.op_mono6: mov x19,#6
	b    .mono_common
.mono_common:
	mov  x0,#1
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	ldr  x3,[sp,#SL_SNUMOVF]
	ldr  w3,[x3]
	cbnz x3,.snum_fail
	mov  x22,x0		/* bn */
	cmp  x19,#1
	b.eq .mo1
	cmp  x19,#2
	b.eq .mo2
	cmp  x19,#3
	b.eq .mo3
	cmp  x19,#4
	b.eq .mo4
	cmp  x19,#5
	b.eq .mo5
	/* mo6: 0NOTEQUAL */
	cmp  x22,#0
	cset x22,ne
	b    .mo_out
.mo1:
	add  x22,x22,#1
	b    .mo_out
.mo2:
	sub  x22,x22,#1
	b    .mo_out
.mo3:
	neg  x22,x22
	b    .mo_out
.mo4:
	cmp  x22,#0
	b.ge .mo_out
	neg  x22,x22
	b    .mo_out
.mo5:
	cmp  x22,#0
	cset x22,eq
	b    .mo_out
.mo_out:
	CSTK
	bl   stack_pop
	CSTK
	mov  x2,x22
	bl   interp_push_num
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0
.snum_fail:
	mov  w0,#SE_SCRIPTNUM
	b    .err_ret0

/* --- binary numeric --- */
.op_bin1:  mov x19,#1
	b    .bin_common
.op_bin2:  mov x19,#2
	b    .bin_common
.op_bin3:  mov x19,#3
	b    .bin_common
.op_bin4:  mov x19,#4
	b    .bin_common
.op_bin5:  mov x19,#5
	b    .bin_common
.op_bin7:  mov x19,#7
	b    .bin_common
.op_bin8:  mov x19,#8
	b    .bin_common
.op_bin9:  mov x19,#9
	b    .bin_common
.op_bin10: mov x19,#10
	b    .bin_common
.op_bin11: mov x19,#11
	b    .bin_common
.op_bin12: mov x19,#12
	b    .bin_common
.op_bin13: mov x19,#13
	b    .bin_common
.bin_common:
	mov  x0,#2
	bl   interp_require_depth
	cbnz x0,.err_ret0
	/* bn1 = second */
	CSTK
	bl   stack_second_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	ldr  x3,[sp,#SL_SNUMOVF]
	ldr  w3,[x3]
	cbnz x3,.snum_fail
	mov  x22,x0		/* bn1 */
	/* bn2 = top */
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	ldr  x3,[sp,#SL_SNUMOVF]
	ldr  w3,[x3]
	cbnz x3,.snum_fail
	mov  x23,x0		/* bn2 */
	cmp  x19,#1
	b.eq .b_add
	cmp  x19,#2
	b.eq .b_sub
	cmp  x19,#3
	b.eq .b_band
	cmp  x19,#4
	b.eq .b_bor
	cmp  x19,#5
	b.eq .b_eq
	cmp  x19,#7
	b.eq .b_ne
	cmp  x19,#8
	b.eq .b_lt
	cmp  x19,#9
	b.eq .b_gt
	cmp  x19,#10
	b.eq .b_le
	cmp  x19,#11
	b.eq .b_ge
	cmp  x19,#12
	b.eq .b_min
.b_max:
	cmp  x22,x23
	csel x22,x23,x22,lt
	b    .b_out
.b_min:
	cmp  x22,x23
	csel x22,x23,x22,gt
	b    .b_out
.b_add:
	add  x22,x22,x23
	b    .b_out
.b_sub:
	sub  x22,x22,x23
	b    .b_out
.b_band:
	cmp  x22,#0
	cset x22,ne
	cmp  x23,#0
	cset x23,ne
	and  x22,x22,x23
	b    .b_out
.b_bor:
	cmp  x22,#0
	cset x22,ne
	cmp  x23,#0
	cset x23,ne
	orr  x22,x22,x23
	b    .b_out
.b_eq:
	cmp  x22,x23
	cset x22,eq
	b    .b_out
.b_ne:
	cmp  x22,x23
	cset x22,ne
	b    .b_out
.b_lt:
	cmp  x22,x23
	cset x22,lt
	b    .b_out
.b_gt:
	cmp  x22,x23
	cset x22,gt
	b    .b_out
.b_le:
	cmp  x22,x23
	cset x22,le
	b    .b_out
.b_ge:
	cmp  x22,x23
	cset x22,ge
	b    .b_out
.b_out:
	CSTK
	bl   stack_pop
	CSTK
	bl   stack_pop
	CSTK
	mov  x2,x22
	bl   interp_push_num
	cbnz x0,.b_post
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0
.b_post:
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_NUMEQUALVERIFY
	b.ne .next_op
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	bl   cast_to_bool
	cbz  x0,.neqv_fail
	CSTK
	bl   stack_pop
	b    .next_op
.neqv_fail:
	mov  w0,#SE_NUMEQUALVERIFY
	b    .err_ret0

/* --- within --- */
.op_within:
	mov  x0,#3
	bl   interp_require_depth
	cbnz x0,.err_ret0
	/* val = third */
	CSTK
	bl   stack_third_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	mov  x23,x0		/* val */
	ldr  x3,[sp,#SL_SNUMOVF]
	ldr  w3,[x3]
	cbnz x3,.snum_fail
	/* min = second */
	CSTK
	bl   stack_second_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	mov  x22,x0		/* min */
	ldr  x3,[sp,#SL_SNUMOVF]
	ldr  w3,[x3]
	cbnz x3,.snum_fail
	/* max = top */
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	mov  x19,x0		/* max */
	ldr  x3,[sp,#SL_SNUMOVF]
	ldr  w3,[x3]
	cbnz x3,.snum_fail
	/* f = (min<=val) && (val<max) */
	cmp  x22,x23
	cset x21,le
	cmp  x23,x19
	cset x22,lt
	and  x21,x21,x22
	CSTK
	bl   stack_pop
	CSTK
	bl   stack_pop
	CSTK
	bl   stack_pop
	CSTK
	mov  x2,x21
	bl   interp_push_bool
	b    .next_op


	/* --- crypto (RIPEMD160/SHA1/SHA256/HASH160/HASH256) --- */
.op_crypto:
	mov  x0,#1
	bl   interp_require_depth
	cbnz x0,.err_ret0
	add  x0,x20,#8
	ldr  x1,[x20]
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w22,[x21]			/* len */
	add  x23,x21,#ELEM_DATA_OFF
	ldr  x19,[sp,#SL_ITMP]		/* tmp buf */
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_SHA256
	b.eq .cr_sha
	cmp  x2,#OP_RIPEMD160
	b.eq .cr_rip
	cmp  x2,#OP_HASH160
	b.eq .cr_h160
	cmp  x2,#OP_HASH256
	b.eq .cr_h256
	cmp  x2,#OP_SHA1
	b.eq .cr_sha1
	b    .bad_opcode
.cr_sha:
	mov  x0,x19
	mov  x1,x23
	mov  x2,x22
	bl   sha256_full
	mov  w22,#32
	b    .cr_out
.cr_sha1:
	mov  x0,x19
	mov  x1,x23
	mov  x2,x22
	bl   sha1_full
	mov  w22,#20
	b    .cr_out
.cr_rip:
	mov  x0,x19
	mov  x1,x23
	mov  x2,x22
	bl   ripemd160
	mov  w22,#20
	b    .cr_out
.cr_h160:
	mov  x0,x19
	mov  x1,x23
	mov  x2,x22
	bl   sha256_full
	add  x0,x19,#32
	mov  x1,x19
	mov  x2,#32
	bl   ripemd160
	mov  w22,#20
	add  x19,x19,#32		/* result at tmp+32 */
	b    .cr_out2
.cr_h256:
	mov  x0,x19
	mov  x1,x23
	mov  x2,x22
	bl   sha256d
	mov  w22,#32
	b    .cr_out
.cr_out:
	add  x0,x20,#8
	ldr  x1,[x20]
	bl   stack_pop
	add  x0,x20,#8
	ldr  x1,[x20]
	mov  x2,x19
	mov  x3,x22
	bl   stack_push
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0
.cr_out2:
	add  x0,x20,#8
	ldr  x1,[x20]
	bl   stack_pop
	add  x0,x20,#8
	ldr  x1,[x20]
	mov  x2,x19			/* tmp+32 */
	mov  x3,x22
	bl   stack_push
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0

/* --- CODE SEPARATOR (reached only when executed) --- */
.op_cs:
	ldr  x2,[sp,#SL_PC]
	str  x2,[sp,#SL_BECH]
	ldr  w2,[x20,#48]
	cmp  x2,#SIGVERSION_TAPSCRIPT
	b.ne .next_op
	ldr  x2,[sp,#SL_CSP]
	str  x2,[sp,#SL_CSPOS]
	b    .next_op

/* --- CHECKSIG family (handled below with the checksig helpers) --- */
.op_checksig:			/* CHECKSIG / CHECKSIGVERIFY */
	mov  x0,#2
	bl   interp_require_depth
	cbnz x0,.err_ret0
	bl   interp_checksig
	cmp  x0,#-1
	b.eq .err_sigder
	mov  x23,x0		/* success */
	CSTK
	bl   stack_pop
	CSTK
	bl   stack_pop
	CSTK
	mov  x2,x23
	bl   interp_push_bool
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_CHECKSIGVERIFY
	b.ne .next_op
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	bl   cast_to_bool
	cbz  x0,.csigv_fail
	CSTK
	bl   stack_pop
	b    .next_op
.csigv_fail:
	mov  w0,#SE_CHECKSIGVERIFY
	b    .err_ret0
.err_sigder:
	mov  w0,#SE_SIG_DER
	b    .err_ret0

.op_checksigadd:
	ldr  w2,[x20,#48]
	cmp  x2,#SIGVERSION_TAPSCRIPT
	b.eq .csa_go
	mov  w0,#SE_BAD_OPCODE
	b    .err_ret0
.csa_go:
	mov  x0,#3
	bl   interp_require_depth
	cbnz x0,.err_ret0
	/* num at sp-2 */
	CSTK
	bl   stack_second_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	ldr  x3,[sp,#SL_SNUMOVF]
	ldr  w3,[x3]
	cbnz x3,.snum_fail
	mov  x19,x0		/* num */
	bl   interp_checksig_add
	mov  x22,x0		/* success */
	add  x19,x19,x22
	CSTK
	bl   stack_pop
	CSTK
	bl   stack_pop
	CSTK
	bl   stack_pop
	CSTK
	mov  x2,x19
	bl   interp_push_num
	cbnz x0,.next_op
	mov  w0,#SE_STACK_SIZE
	b    .err_ret0

/* --- CHECKMULTISIG family --- */
.op_checkmultisig:
	ldr  w2,[x20,#48]
	cmp  x2,#SIGVERSION_TAPSCRIPT
	b.ne .cms_go
	mov  w0,#SE_TAPSCRIPT_CHECKMULTISIG
	b    .err_ret0
.cms_go:
	bl   interp_checkmultisig
	cbnz x0,.cms_ok
	ldr  x2,[sp,#SL_IERR]
	ldr  x3,[x2]
	cbz  x3,.bad_opcode
	mov  w0,w3
	b    .err_ret0
.cms_ok:
	ldr  x2,[sp,#SL_OP]
	cmp  x2,#OP_CHECKMULTISIGVERIFY
	b.ne .next_op
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	bl   cast_to_bool
	cbz  x0,.cmsv_fail
	CSTK
	bl   stack_pop
	b    .next_op
.cmsv_fail:
	mov  w0,#SE_CHECKMULTISIGVERIFY
	b    .err_ret0

/* --- CLTV --- */
.op_cltv:
	ldr  x2,[x20,#56]
	tst  x2,#SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
	b.ne .cltv_go
	b    .next_op
.cltv_go:
	mov  x0,#1
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#5
	bl   scriptnum_decode
	tbz  x0,#63,.cltv_nn
	mov  w0,#SE_NEGATIVE_LOCKTIME
	b    .err_ret0
.cltv_nn:
	mov  x23,x0		/* scriptTime */
	ldr  w2,[x20,#104]	/* tx_locktime */
	mov  x22,x2
	movz x9,#0x1DCD,lsl #16
	movk x9,#0x6500
	cmp  x23,x9
	b.lt .cltv_script_below
	cmp  x22,x9
	b.lt .cltv_unsatisfied
	b    .cltv_type_ok
.cltv_script_below:
	cmp  x22,x9
	b.ge .cltv_unsatisfied
.cltv_type_ok:
	cmp  x23,x22
	b.gt .cltv_unsatisfied
	ldr  w2,[x20,#108]	/* in_sequence */
	movn w3,#0		/* 0xffffffff = SEQUENCE_FINAL */
	cmp  w2,w3
	b.eq .cltv_unsatisfied
	b    .next_op
.cltv_unsatisfied:
	mov  w0,#SE_UNSATISFIED_LOCKTIME
	b    .err_ret0

/* --- CSV --- */
.op_csv:
	ldr  x2,[x20,#56]
	tst  x2,#SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
	b.ne .csv_go
	b    .next_op
.csv_go:
	mov  x0,#1
	bl   interp_require_depth
	cbnz x0,.err_ret0
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#5
	bl   scriptnum_decode
	tbz  x0,#63,.csv_nn
	mov  w0,#SE_NEGATIVE_LOCKTIME
	b    .err_ret0
.csv_nn:
	tst  x0,#0x80000000
	b.ne .next_op		/* disable flag on script operand -> NOP */
	mov  x23,x0		/* scriptSequence */
	ldr  w2,[x20,#112]	/* tx_version */
	cmp  w2,#2
	b.lt .csv_unsatisfied
	ldr  w2,[x20,#108]	/* in_sequence */
	tst  w2,#0x80000000
	b.ne .csv_unsatisfied
	mov  x22,x2		/* txToSequence */
	movz x9,#0xffff
	movk x9,#0x40,lsl #16	/* 0x0040ffff */
	and  x22,x22,x9		/* txToSequenceMasked */
	mov  x21,x23
	and  x21,x21,x9		/* nSequenceMasked */
	movz x10,#0x40,lsl #16	/* 0x00400000 */
	cmp  x21,x10
	b.lt .csv_script_below
	cmp  x22,x10
	b.lt .csv_unsatisfied
	b    .csv_type_ok
.csv_script_below:
	cmp  x22,x10
	b.ge .csv_unsatisfied
.csv_type_ok:
	cmp  x21,x22
	b.gt .csv_unsatisfied
	b    .next_op
.csv_unsatisfied:
	mov  w0,#SE_UNSATISFIED_LOCKTIME
	b    .err_ret0

.bad_opcode:
	mov  w0,#SE_BAD_OPCODE
	b    .err_ret0

.next_op:
	ldr  x2,[sp,#SL_CSP]
	add  x2,x2,#1
	str  x2,[sp,#SL_CSP]
	b    .loop

.loop_done:
	bl   vfexec_depth
	cbz  x0,.cstack
	mov  w0,#SE_UNBALANCED_CONDITIONAL
	b    .err_ret0
.cstack:
	ldr  w2,[x20,#48]
	cmp  x2,#SIGVERSION_TAPSCRIPT
	b.ne .final_ok
	CSTK
	bl   stack_depth
	cmp  x0,#1
	b.ne .cstack_fail
	CSTK
	bl   stack_top_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	bl   cast_to_bool
	cbz  x0,.evalfalse
	b    .final_ok
.cstack_fail:
	mov  w0,#SE_CLEANSTACK
	b    .err_ret0
.evalfalse:
	mov  w0,#SE_EVAL_FALSE
	b    .err_ret0
.final_ok:
	ldr  x2,[x20,#80]
	cbz  x2,1f
	mov  w3,#SE_OK
	str  w3,[x2]
1:	mov  w0,#1		/* success */
	b    .done
.err_ret0:
	/* x0 = err code */
	ldr  x2,[x20,#80]
	cbz  x2,2f
	str  w0,[x2]
2:	mov  w0,#0
.done:
	/* epilogue */
	add  sp,sp,#0xC0
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size script_eval,.-script_eval


/* ============================================================================
 * interp_* helpers. AArch64 equivalents of asm 2477-3165. x24 = script_eval
 * frame-slot base, x20 = script_state (both survive nested bl; both are
 * callee-saved, so the checksig_fn C callback preserves them too).
 * ========================================================================== */

	/* interp_require_depth(min=x0) -> x0=0 ok / SE_INVALID_STACK_OPERATION */
	/* interp_require_depth(min=x0) -> x0=0 ok / SE_INVALID_STACK_OPERATION.
	 * Inlines stack_depth (*&sp == [state+8]) -- a `bl stack_depth` here would
	 * clobber x30 and the trailing `ret` would self-loop (tail-ret trap). */
interp_require_depth:
	mov  x9,x0
	ldr  x0,[x20,#8]
	cmp  x0,x9
	b.hs 1f
	mov  w0,#SE_INVALID_STACK_OPERATION
	ret
1:	mov  w0,#0
	ret
	.size interp_require_depth,.-interp_require_depth

	/* interp_swap_recs(): swap x21 (=a) and x22 (=b) elem records via elem_tmp0 */
interp_swap_recs:
	stp  x29,x30,[sp,#-16]!
	mov  x29,sp
	LAddr x10, elem_tmp0
	mov  x0,x10
	mov  x1,x21
	bl   elem_move		/* tmp0 = *a */
	mov  x0,x21
	mov  x1,x22
	bl   elem_move		/* *a = *b */
	mov  x0,x22
	mov  x1,x10
	bl   elem_move		/* *b = tmp0 */
	ldp  x29,x30,[sp],#16
	ret
	.size interp_swap_recs,.-interp_swap_recs

interp_push_num:
	stp  x29,x30,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	mov  x25,x0		/* &sp */
	mov  x26,x1		/* elems */
	mov  x27,x2		/* value */
	mov  x0,x27
	bl   scriptnum_serialize	/* x0=ptr, x1=len */
	mov  x2,x0		/* data ptr */
	mov  x3,x1		/* len */
	mov  x0,x25
	mov  x1,x26
	bl   stack_push
	ldp  x25,x26,[sp],#16
	ldp  x27,x28,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
.size interp_push_num,.-interp_push_num

	/* interp_push_bool(&sp=x0, elems=x1, bool=x2) -> 1/0 */
interp_push_bool:
	stp  x29,x30,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	mov  x25,x0		/* &sp */
	mov  x26,x1		/* elems */
	mov  x9,x2		/* bool */
	LAddr x10, interp_tmp
	mov  w3,#0
	cbz  x9,1f
	mov  w3,#1
1:	strb w3,[x10]
	mov  x2,x10
	mov  x3,x9		/* len 0/1 */
	mov  x0,x25
	mov  x1,x26
	bl   stack_push
	ldp  x25,x26,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
.size interp_push_bool,.-interp_push_bool

	/* interp_sig_encoding_ok(sig_elem=x0) -> x0=1 ok / 0 -> SCRIPT_ERR_SIG_DER */
interp_sig_encoding_ok:
	ldr  w2,[x20,#48]
	cmp  w2,#SIGVERSION_TAPSCRIPT
	b.eq .sigenc_ok
	ldr  x2,[x20,#56]
	tst  x2,#(SCRIPT_VERIFY_DERSIG|SCRIPT_VERIFY_LOW_S|SCRIPT_VERIFY_STRICTENC)
	b.eq .sigenc_ok
	ldr  w1,[x0]		/* siglen u32 */
	cbz  w1,.sigenc_ok
	add  x0,x0,#ELEM_DATA_OFF
	b    der_sig_strict	/* tail; its 0/1 is our 0/1 */
.sigenc_ok:
	mov  w0,#1
	ret
	.size interp_sig_encoding_ok,.-interp_sig_encoding_ok

	/* interp_checksig() -> 0/1, or -1 on SCRIPT_ERR_SIG_DER.
	 * sig = sp-2, pub = sp-1 . C callback at state+96, ctx state+88. */
interp_checksig:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	add  x0,x20,#8
	ldr  x1,[x20]
	bl   stack_top_ptr
	mov  x21,x0		/* pub elem */
	ldr  w22,[x21]		/* publen */
	add  x23,x21,#ELEM_DATA_OFF	/* pub data */
	add  x0,x20,#8
	ldr  x1,[x20]
	bl   stack_second_ptr
	mov  x21,x0		/* sig elem */
	ldr  w19,[x21]		/* siglen */
	cbz  w19,.cs_false
	ldr  x0,[x20,#96]
	cbz  x0,.cs_false
	mov  x0,x21
	bl   interp_sig_encoding_ok
	cbnz x0,.cs_enc_ok
	mov  w0,#-1
	b    .cs_end
.cs_enc_ok:
	LAddr x12, interp_slice
	ldr  x11,[x24,#SL_BECH]
	str  x11,[x12]
	ldr  x13,[x24,#SL_PEND]
	sub  x13,x13,x11
	str  x13,[x12,#8]
	ldr  x14,[x24,#SL_CSPOS]
	str  x14,[x12,#16]
	ldr  x15,[x20,#88]	/* ctx */
	mov  x0,x15
	add  x1,x21,#ELEM_DATA_OFF
	mov  x2,x19
	mov  x3,x23
	mov  x4,x22
	mov  x5,x12
	ldr  x16,[x20,#96]
	blr  x16
	b    .cs_end
.cs_false:
	mov  w0,#0
.cs_end:
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size interp_checksig,.-interp_checksig

	/* interp_checksig_add() -> 0/1 ; sig = sp-3, pub = sp-1 (tapscript) */
interp_checksig_add:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	add  x0,x20,#8
	ldr  x1,[x20]
	bl   stack_top_ptr
	mov  x21,x0		/* pub elem */
	ldr  w22,[x21]
	add  x23,x21,#ELEM_DATA_OFF
	add  x0,x20,#8
	ldr  x1,[x20]
	bl   stack_third_ptr
	mov  x21,x0		/* sig elem (sp-3) */
	ldr  w19,[x21]
	cbz  w19,.csa_false
	ldr  x0,[x20,#96]
	cbz  x0,.csa_false
	LAddr x12, interp_slice
	ldr  x11,[x24,#SL_BECH]
	str  x11,[x12]
	ldr  x13,[x24,#SL_PEND]
	sub  x13,x13,x11
	str  x13,[x12,#8]
	ldr  x14,[x24,#SL_CSPOS]
	str  x14,[x12,#16]
	ldr  x15,[x20,#88]
	mov  x0,x15
	add  x1,x21,#ELEM_DATA_OFF
	mov  x2,x19
	mov  x3,x23
	mov  x4,x22
	mov  x5,x12
	ldr  x16,[x20,#96]
	blr  x16
	b    .csa_end
.csa_false:
	mov  w0,#0
.csa_end:
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size interp_checksig_add,.-interp_checksig_add

	/* interp_checkmultisig() -> x0=1 ok / 0 (error in interp_err)
	 * Stack: ... dummy sig1..sigm m pub1..pubn n . Uses cms_* globals. */
interp_checkmultisig:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp,sp,#0x50
	ldr  x2,[x24,#SL_IERR]
	str  xzr,[x2]
	/* cache sp value */
	ldr  x2,[x20,#8]
	str  x2,[sp,#0x38]	/* spval */
	/* ---- nKeys = stacktop(1) ---- */
	ldr  x2,[sp,#0x38]
	sub  x2,x2,#1
	add  x0,x20,#8
	ldr  x1,[x20]
	bl   stack_elem_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	mov  w19,w0		/* nKeys */
	tbnz w19,#31,.err_pubcount
	cmp  w19,#20
	b.gt .err_pubcount
	str  w19,[sp,#0x48]
	/* ---- nSigs = stacktop(nkeys+2) ---- */
	ldr  w2,[sp,#0x48]
	add  w2,w2,#2
	ldr  x3,[sp,#0x38]
	sub  x3,x3,x2
	add  x0,x20,#8
	ldr  x1,[x20]
	mov  x2,x3
	bl   stack_elem_ptr
	mov  x21,x0
	ldr  w2,[x21]
	add  x3,x21,#ELEM_DATA_OFF
	mov  x0,x2
	mov  x1,x3
	mov  x2,#4
	bl   scriptnum_decode
	mov  w22,w0		/* nSigs */
	tbnz w22,#31,.err_sigcount
	ldr  w9,[sp,#0x48]
	cmp  w22,w9
	b.gt .err_sigcount
	/* depth guard: sp >= nkeys+nsigs+3 */
	ldr  w2,[sp,#0x48]
	add  w2,w2,w22
	add  w2,w2,#3
	ldr  w3,[sp,#0x38]
	cmp  w3,w2
	b.lt .err_stackop
	/* ---- NULLDUMMY ---- */
	ldr  x2,[x20,#56]
	tst  x2,#SCRIPT_VERIFY_NULLDUMMY
	b.eq .cms_dummy_ok
	ldr  w2,[sp,#0x48]
	add  w2,w2,w22
	add  w2,w2,#3
	ldr  x3,[sp,#0x38]
	sub  x3,x3,x2
	mov  x2,x3
	bl   stack_elem_ptr
	ldr  w2,[x0]
	cbnz w2,.err_nulldummy
.cms_dummy_ok:
	/* ---- collect keys[] into cms_keyrefs ---- */
	mov  x25,#0
.collect_keys:
	ldr  w2,[sp,#0x48]
	cmp  w25,w2
	b.ge .ck_done
	add  w3,w25,#2
	ldr  w4,[sp,#0x38]
	sub  w4,w4,w3
	add  x0,x20,#8
	ldr  x1,[x20]
	mov  x2,x4
	bl   stack_elem_ptr
	LAddr x5, cms_keyrefs
	add  x5,x5,x25,lsl #3
	str  x0,[x5]
	add  x25,x25,#1
	b    .collect_keys
.ck_done:
	/* ---- collect sigs[] into cms_sigrefs ---- */
	mov  x25,#0
.collect_sigs:
	ldr  w2,[sp,#0x40]	/* nSigs (recompute) */
	cmp  w25,w2
	b.ge .cs_done
	ldr  w3,[sp,#0x48]
	add  w3,w3,#3
	add  w3,w3,w25
	ldr  w4,[sp,#0x38]
	sub  w4,w4,w3
	add  x0,x20,#8
	ldr  x1,[x20]
	mov  x2,x4
	bl   stack_elem_ptr
	LAddr x5, cms_sigrefs
	add  x5,x5,x25,lsl #3
	str  x0,[x5]
	add  x25,x25,#1
	b    .collect_sigs
.cs_done:
	/* ---- 2b. strip sigs from scriptCode (BASE only) ---- */
	ldr  x2,[x24,#SL_BECH]
	str  x2,[sp,#0x28]	/* cur_src ptr */
	ldr  x3,[x24,#SL_PEND]
	sub  x3,x3,x2
	str  x3,[sp,#0x20]	/* cur_src len */
	ldr  w2,[x20,#48]
	cbnz w2,.cms_strip_done
	mov  x25,#0
.cms_strip_loop:
	ldr  w2,[sp,#0x40]
	cmp  w25,w2
	b.ge .cms_strip_done
	LAddr x5, cms_sigrefs
	add  x5,x5,x25,lsl #3
	ldr  x7,[x5]		/* sigs[j] elem ptr */
	ldr  w8,[x7]		/* siglen */
	add  x9,x7,#ELEM_DATA_OFF
	LAddr x0, cms_needle
	mov  x1,#600
	mov  x2,x9
	mov  x3,x8
	bl   script_push_encode
	mov  x26,x0		/* needlelen */
	tbnz w25,#0,.strip_dst1
	LAddr x27, cms_scstrip0
	b    .strip_call
.strip_dst1:
	LAddr x27, cms_scstrip1
.strip_call:
	mov  x0,x27
	mov  x1,#10008
	ldr  x2,[sp,#0x28]
	ldr  x3,[sp,#0x20]
	LAddr x4, cms_needle
	mov  x5,x26
	bl   script_find_and_delete
	str  x27,[sp,#0x28]
	str  x0,[sp,#0x20]
	add  x25,x25,#1
	b    .cms_strip_loop
.cms_strip_done:
	LAddr x10, interp_slice
	ldr  x11,[sp,#0x28]
	str  x11,[x10]
	ldr  x12,[sp,#0x20]
	str  x12,[x10,#8]
	/* ---- 3. matching loop ---- */
	mov  x25,#0			/* isig */
	mov  x26,#0			/* ikey */
	ldr  w27,[sp,#0x40]		/* remaining */
.cms_loop:
	cmp  w27,#0
	b.le .cms_end
	ldr  w2,[sp,#0x48]
	cmp  w26,w2
	b.ge .cms_end
	LAddr x5, cms_sigrefs
	add  x5,x5,x25,lsl #3
	ldr  x21,[x5]			/* vSig elem */
	LAddr x7, cms_keyrefs
	add  x7,x7,x26,lsl #3
	ldr  x22,[x7]			/* vPub elem */
	mov  x0,x21
	bl   interp_sig_encoding_ok
	cbnz x0,.enc_ok
	mov  w0,#SE_SIG_DER
	ldr  x2,[x24,#SL_IERR]
	str  w0,[x2]
	b    .err_exit
.enc_ok:
	ldr  x23,[x20,#88]		/* ctx */
	mov  x0,x23
	add  x1,x21,#ELEM_DATA_OFF
	ldr  w2,[x21]			/* siglen */
	add  x3,x22,#ELEM_DATA_OFF
	ldr  w4,[x22]			/* publen */
	LAddr x5, interp_slice
	ldr  x6,[x20,#96]
	cbz  x6,.key_fail
	blr  x6
	cbz  x0,.key_fail
	add  x25,x25,#1
	sub  w27,w27,#1
.key_fail:
	add  x26,x26,#1
	ldr  w2,[sp,#0x48]
	sub  w2,w2,w26
	cmp  w27,w2
	b.gt .cms_fail
	b    .cms_loop
.cms_end:
	cmp  w27,#0
	b.ne .cms_fail
	mov  w26,#1
	b    .cms_finish
.cms_fail:
	mov  w26,#0
.cms_finish:
	ldr  w2,[sp,#0x48]
	add  w2,w2,w22		/* +nSigs */
	add  w2,w2,#3
	mov  x25,x2
.pop_all:
	cbz  x25,.pop_done
	add  x0,x20,#8
	ldr  x1,[x20]
	bl   stack_pop
	sub  x25,x25,#1
	b    .pop_all
.pop_done:
	add  x0,x20,#8
	ldr  x1,[x20]
	mov  x2,x26
	bl   interp_push_bool
	mov  w0,#1
	b    .cms_ret
.err_pubcount:
	mov  w0,#SE_PUBKEY_COUNT
	b    .err_set
.err_sigcount:
	mov  w0,#SE_SIG_COUNT
	b    .err_set
.err_stackop:
	mov  w0,#SE_INVALID_STACK_OPERATION
	b    .err_set
.err_nulldummy:
	mov  w0,#SE_SIG_NULLDUMMY
	b    .err_set
.err_set:
	ldr  x2,[x24,#SL_IERR]
	str  w0,[x2]
.err_exit:
	mov  w0,#0
.cms_ret:
	add  sp,sp,#0x50
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size interp_checkmultisig,.-interp_checkmultisig

	.section .note.GNU-stack,"",%progbits
