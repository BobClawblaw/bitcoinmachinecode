; ============================================================================
; bitcoin_interp.asm -- Full Bitcoin Script interpreter (all opcodes), built on
; the verified support layer bitcoin_scriptcodec.asm.
;
;   int script_eval(struct script_state* st)
;     Evaluates st->script over the initial stack in st->main_elems[0..main_sp)
;     per st->sigversion / st->flags (Core's EvalScript core semantics).
;     Returns 1 on success, 0 on failure; *st->error_out is set on failure.
;
; struct script_state {         offsets
;   uint8_t* main_elems;        +0
;   size_t   main_sp;           +8
;   uint8_t* alt_elems;         +16
;   size_t   alt_sp;            +24
;   uint8_t* script;            +32
;   size_t   script_len;        +40
;   int      sigversion;        +48
;   uint64_t flags;             +56
;   uint8_t* work;              +64
;   size_t   work_cap;          +72
;   uint64_t* error_out;        +80
;   void*    checksig_ctx;      +88
;   uint64_t (*checksig_fn)(void* ctx, const uint8_t* sig, size_t siglen,
;                           const uint8_t* pub, size_t publen,
;                           const uint8_t* sc, size_t sc_len);  +96
; }
;
; Element record: +0 len(4), +4 data[520] (ELEM_SIZE=528).
; ABI: SysV AMD64; rbx,r12-r15 preserved; rsp 8mod16 at nested calls.
; ============================================================================
    default rel
    global script_eval

    extern stack_depth
    extern stack_top_ptr
    extern stack_second_ptr
    extern stack_third_ptr
    extern stack_elem_ptr
    extern stack_pop
    extern stack_push
    extern stack_push_copy
    extern stack_swap_two
    extern stack_dup_index
    extern stack_erase_index
    extern stack_insert_index
    extern elem_move
    extern scriptnum_decode
    extern scriptnum_serialize
    extern scriptnum_buf
    extern cast_to_bool
    extern check_minimal_push
    extern get_op
    extern vfexec_push
    extern vfexec_pop
    extern vfexec_depth
    extern vfexec_toggle_top
    extern vfexec_all_true
    extern vfexec_sp_reset
    ; cross-file TLS accessors (bitcoin_scriptcodec.asm) -- see that file's
    ; header note by their definitions for why these are function calls
    ; rather than direct wrt ..gottpoff references to an extern symbol.
    extern elem_tmp0_addr
    extern elem_tmp1_addr
    extern elem_tmp2_addr
    extern elem_tmp3_addr
    extern snum_overflow_addr

    extern sha256_full
    extern ripemd160
    extern sha256d
    extern sha1_full

%define ELEM_SIZE 528
%define ELEM_DATA_OFF 4
%define OP_1NEGATE 0x4f
%define OP_1 0x51
%define OP_16 0x60
%define OP_NOP 0x61
%define OP_IF 0x63
%define OP_NOTIF 0x64
%define OP_ELSE 0x67
%define OP_ENDIF 0x68
%define OP_VERIFY 0x69
%define OP_RETURN 0x6a
%define OP_TOALTSTACK 0x6b
%define OP_FROMALTSTACK 0x6c
%define OP_2DROP 0x6d
%define OP_2DUP 0x6e
%define OP_3DUP 0x6f
%define OP_2OVER 0x70
%define OP_2ROT 0x71
%define OP_2SWAP 0x72
%define OP_IFDUP 0x73
%define OP_DEPTH 0x74
%define OP_DROP 0x75
%define OP_DUP 0x76
%define OP_NIP 0x77
%define OP_OVER 0x78
%define OP_PICK 0x79
%define OP_ROLL 0x7a
%define OP_ROT 0x7b
%define OP_SWAP 0x7c
%define OP_TUCK 0x7d
%define OP_CAT 0x7e
%define OP_SUBSTR 0x7f
%define OP_LEFT 0x80
%define OP_RIGHT 0x81
%define OP_SIZE 0x82
%define OP_INVERT 0x83
%define OP_AND 0x84
%define OP_OR 0x85
%define OP_XOR 0x86
%define OP_EQUAL 0x87
%define OP_EQUALVERIFY 0x88
%define OP_1ADD 0x8b
%define OP_1SUB 0x8c
%define OP_2MUL 0x8d
%define OP_2DIV 0x8e
%define OP_NEGATE 0x8f
%define OP_ABS 0x90
%define OP_NOT 0x91
%define OP_0NOTEQUAL 0x92
%define OP_ADD 0x93
%define OP_SUB 0x94
%define OP_MUL 0x95
%define OP_DIV 0x96
%define OP_MOD 0x97
%define OP_LSHIFT 0x98
%define OP_RSHIFT 0x99
%define OP_BOOLAND 0x9a
%define OP_BOOLOR 0x9b
%define OP_NUMEQUAL 0x9c
%define OP_NUMEQUALVERIFY 0x9d
%define OP_NUMNOTEQUAL 0x9e
%define OP_LESSTHAN 0x9f
%define OP_GREATERTHAN 0xa0
%define OP_LESSTHANOREQUAL 0xa1
%define OP_GREATERTHANOREQUAL 0xa2
%define OP_MIN 0xa3
%define OP_MAX 0xa4
%define OP_WITHIN 0xa5
%define OP_RIPEMD160 0xa6
%define OP_SHA1 0xa7
%define OP_SHA256 0xa8
%define OP_HASH160 0xa9
%define OP_HASH256 0xaa
%define OP_CODESEPARATOR 0xab
%define OP_CHECKSIG 0xac
%define OP_CHECKSIGVERIFY 0xad
%define OP_CHECKMULTISIG 0xae
%define OP_CHECKMULTISIGVERIFY 0xaf
%define OP_NOP1 0xb0
%define OP_CHECKLOCKTIMEVERIFY 0xb1
%define OP_CHECKSEQUENCEVERIFY 0xb2
%define OP_NOP4 0xb3
%define OP_NOP5 0xb4
%define OP_NOP6 0xb5
%define OP_NOP7 0xb6
%define OP_NOP8 0xb7
%define OP_NOP9 0xb8
%define OP_NOP10 0xb9
%define OP_CHECKSIGADD 0xba
%define OP_PUSHDATA4 0x4e

%define MAX_SCRIPT_ELEMENT_SIZE 520
%define MAX_OPS_PER_SCRIPT 201
%define MAX_STACK_SIZE 1000
%define MAX_SCRIPT_SIZE 10000

%define SIGVERSION_BASE 0
%define SIGVERSION_WITNESS_V0 1
%define SIGVERSION_TAPSCRIPT 2

%define SCRIPT_VERIFY_NULLDUMMY (1<<4)
%define SCRIPT_VERIFY_MINIMALDATA (1<<6)
%define SCRIPT_VERIFY_MINIMALIF (1<<13)
%define SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY (1<<9)
%define SCRIPT_VERIFY_CHECKSEQUENCEVERIFY (1<<10)
%define SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS (1<<18)

%define SCRIPT_ERR_OK                         0
%define SCRIPT_ERR_EVAL_FALSE                 2
%define SCRIPT_ERR_OP_RETURN                  3
%define SCRIPT_ERR_SCRIPT_SIZE                5
%define SCRIPT_ERR_PUSH_SIZE                  6
%define SCRIPT_ERR_OP_COUNT                   7
%define SCRIPT_ERR_STACK_SIZE                 8
%define SCRIPT_ERR_BAD_OPCODE                 16
%define SCRIPT_ERR_DISABLED_OPCODE            17
%define SCRIPT_ERR_VERIFY                     11
%define SCRIPT_ERR_EQUALVERIFY                12
%define SCRIPT_ERR_CHECKSIGVERIFY             14
%define SCRIPT_ERR_NUMEQUALVERIFY             15
%define SCRIPT_ERR_UNBALANCED_CONDITIONAL     20
%define SCRIPT_ERR_INVALID_STACK_OPERATION    18
%define SCRIPT_ERR_INVALID_ALTSTACK_OPERATION 19
%define SCRIPT_ERR_SCRIPTNUM                  4
%define SCRIPT_ERR_MINIMALDATA                25
%define SCRIPT_ERR_NEGATIVE_LOCKTIME          21
%define SCRIPT_ERR_UNSATISFIED_LOCKTIME       22
%define SCRIPT_ERR_TAPSCRIPT_MINIMALIF        51
%define SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG    50
%define SCRIPT_ERR_DISCOURAGE_OP_SUCCESS      36
%define SCRIPT_ERR_CLEANSTACK                 30
%define SCRIPT_ERR_SIG_COUNT                  9
%define SCRIPT_ERR_PUBKEY_COUNT               10
%define SCRIPT_ERR_SIG_NULLDUMMY              28

; ---- THREAD-LOCAL scratch (2026-08-19, parallel per-input verification) --
; interp_tmp/bool_buf/interp_err/interp_slice/cms_keyrefs/cms_sigrefs used
; to be plain .bss globals -- one shared instance for the whole process.
; That was fine for the original fork()-per-worker parallelism (each forked
; child gets its own COW copy of everything), but fork()'s page-table setup
; cost scales with the parent's resident size, which made it progressively
; more expensive as the UTXO memtable grew during a from-scratch replay
; (confirmed via production stack sampling: every sample landed inside
; fork() itself). Threads avoid that cost entirely -- but ONLY if nothing
; they touch is process-global mutable state, which these six buffers were.
; .tbss (NASM's thread-local BSS) + the ELF Initial-Exec TLS model gives
; each thread its own private instance with no signature/struct-layout
; changes needed anywhere that calls into this file.
;
; script_eval computes each buffer's per-thread ADDRESS once, at entry, into
; six local slots below (interp_checkmultisig shares this same frame via
; its documented "rbp = script_eval frame" convention, so it reads the same
; slots rather than re-deriving them) -- every other reference in this file
; was previously a compile-time-constant label; those become a load from
; the matching slot instead, same instruction shape, same register usage.
section .tbss alloc noexec nowrite tls align=16
global interp_tmp
global bool_buf
global interp_err
global interp_slice
interp_tmp: resb ELEM_SIZE
bool_buf: resb 1
interp_err: resq 1
interp_slice: resq 2

section .text

; TLS_ADDR dst, sym -- dst = this thread's address of `sym` (ELF x86-64
; Initial-Exec model: a GOT-style offset loaded from a fixed, link-time
; location, added to the thread pointer at %fs:0). Clobbers only `dst`.
%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

; ============================================================================
; script_eval(state*)   rdi = state
; Frame: r12=state throughout. Locals:
;   -0x08 fExec   -0x10 pc   -0x18 pend   -0x20 pbegincodehash
;   -0x28 nOpCount -0x30 opcode_pos -0x38 opcode -0x40 pushlen
;   -0x60 &interp_tmp (this thread)   -0x68 &bool_buf   -0x70 &interp_err
;   -0x78 &interp_slice   -0x80 &cms_keyrefs   -0x88 &cms_sigrefs
;   -0x90 &elem_tmp0   -0x98 &elem_tmp1   -0xA0 &elem_tmp2   -0xA8 &elem_tmp3
;   -0xB0 &snum_overflow (scriptnum_buf is only referenced from within
;   bitcoin_scriptcodec.asm's own scriptnum_serialize, already TLS-converted
;   there -- no slot needed here)
;   (computed once here; unused-but-reserved scratch space, no frame resize)
; ============================================================================
script_eval:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x100
    mov   r12, rdi            ; state

    ; per-thread scratch addresses, computed once (see file-header note
    ; above script_eval and the TLS_ADDR macro) -- unused-but-reserved
    ; frame space, no resize needed.
    TLS_ADDR rax, interp_tmp
    mov   [rbp-0x60], rax
    TLS_ADDR rax, bool_buf
    mov   [rbp-0x68], rax
    TLS_ADDR rax, interp_err
    mov   [rbp-0x70], rax
    TLS_ADDR rax, interp_slice
    mov   [rbp-0x78], rax
    TLS_ADDR rax, cms_keyrefs
    mov   [rbp-0x80], rax
    TLS_ADDR rax, cms_sigrefs
    mov   [rbp-0x88], rax
    call  elem_tmp0_addr
    mov   [rbp-0x90], rax
    call  elem_tmp1_addr
    mov   [rbp-0x98], rax
    call  elem_tmp2_addr
    mov   [rbp-0xA0], rax
    call  elem_tmp3_addr
    mov   [rbp-0xA8], rax
    call  snum_overflow_addr
    mov   [rbp-0xB0], rax

    ; script size limit for BASE/WITNESS_V0
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    je    .ss_ok
    mov   rax, [r12+40]
    cmp   rax, MAX_SCRIPT_SIZE
    jbe   .ss_ok
    mov   rax, SCRIPT_ERR_SCRIPT_SIZE
    jmp   .err_ret0
.ss_ok:
    ; pc = script, pend = script+len, pbegincodehash = script
    mov   rax, [r12+32]
    mov   [rbp-0x10], rax
    mov   rax, [r12+32]
    add   rax, [r12+40]
    mov   [rbp-0x18], rax
    mov   rax, [r12+32]
    mov   [rbp-0x20], rax
    mov   qword [rbp-0x28], 0
    mov   qword [rbp-0x30], 0
    call  vfexec_sp_reset

    ; ---- tapscript OP_SUCCESSx pre-scan (BIP342 / ExecuteWitnessScript) ----
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    jne   .prescan_done
    ; scan a temporary pc through the script; find any OP_SUCCESSx
    mov   [rbp-0x50], rax      ; (unused slot)
    mov   rax, [r12+32]
    mov   [rbp-0x50], rax      ; scan pc
    mov   rax, [r12+32]
    add   rax, [r12+40]
    mov   [rbp-0x58], rax      ; scan pend
.prescan_loop:
    lea   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x58]
    call  get_op
    test  rax, rax
    jz    .prescan_done        ; end of script or bad opcode -> no successx found
    dec   rax                   ; opcode
    call  is_opsuccess
    test  rax, rax
    jz    .prescan_loop
    ; found an OP_SUCCESSx
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
    jnz   .prescan_discourage
    ; success immediately
    mov   rax, [r12+80]
    test  rax, rax
    jz    .prescan_ret1
    mov   qword [rax], SCRIPT_ERR_OK
.prescan_ret1:
    mov   eax, 1
    jmp   .done
.prescan_discourage:
    mov   rax, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS
    jmp   .err_ret0
.prescan_done:

.loop:
    mov   rax, [rbp-0x10]
    cmp   rax, [rbp-0x18]
    jae   .loop_done

    call  vfexec_all_true
    mov   [rbp-0x08], rax      ; fExec

    ; get_op
    lea   rdi, [rbp-0x10]
    mov   rsi, [rbp-0x18]
    call  get_op
    test  rax, rax
    jnz   .op_ok
    mov   rax, SCRIPT_ERR_BAD_OPCODE
    jmp   .err_ret0
.op_ok:
    dec   rax                   ; recover opcode (get_op returns opcode+1)
    mov   [rbp-0x38], rax      ; opcode
    mov   [rbp-0x40], rdx      ; pushlen

    cmp   rdx, MAX_SCRIPT_ELEMENT_SIZE
    jbe   .ps_ok
    mov   rax, SCRIPT_ERR_PUSH_SIZE
    jmp   .err_ret0
.ps_ok:

    ; opcount
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    je    .oc_skip
    mov   rax, [rbp-0x38]
    cmp   rax, OP_16
    jbe   .oc_skip
    inc   qword [rbp-0x28]
    mov   rax, [rbp-0x28]
    cmp   rax, MAX_OPS_PER_SCRIPT
    jbe   .oc_skip
    mov   rax, SCRIPT_ERR_OP_COUNT
    jmp   .err_ret0
.oc_skip:

    ; disabled opcodes
    mov   rax, [rbp-0x38]
    cmp   rax, OP_CAT
    je    .disabled
    cmp   rax, OP_SUBSTR
    je    .disabled
    cmp   rax, OP_LEFT
    je    .disabled
    cmp   rax, OP_RIGHT
    je    .disabled
    cmp   rax, OP_INVERT
    je    .disabled
    cmp   rax, OP_AND
    je    .disabled
    cmp   rax, OP_OR
    je    .disabled
    cmp   rax, OP_XOR
    je    .disabled
    cmp   rax, OP_2MUL
    je    .disabled
    cmp   rax, OP_2DIV
    je    .disabled
    cmp   rax, OP_MUL
    je    .disabled
    cmp   rax, OP_DIV
    je    .disabled
    cmp   rax, OP_MOD
    je    .disabled
    cmp   rax, OP_LSHIFT
    je    .disabled
    cmp   rax, OP_RSHIFT
    je    .disabled
    jmp   .not_disabled
.disabled:
    mov   rax, SCRIPT_ERR_DISABLED_OPCODE
    jmp   .err_ret0
.not_disabled:

    ; push opcode 0..PUSHDATA4
    mov   rax, [rbp-0x38]
    cmp   rax, OP_PUSHDATA4
    ja    .not_push
    mov   rax, [rbp-0x08]
    test  rax, rax
    jz    .next_op
    ; minimal push
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_MINIMALDATA
    jz    .mp_ok
    mov   rdi, [rbp-0x38]
    mov   rsi, [rbp-0x40]
    mov   rdx, [rbp-0x10]
    sub   rdx, [rbp-0x40]
    call  check_minimal_push
    test  rax, rax
    jnz   .mp_ok
    mov   rax, SCRIPT_ERR_MINIMALDATA
    jmp   .err_ret0
.mp_ok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x10]
    sub   rdx, [rbp-0x40]
    mov   rcx, [rbp-0x40]
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0
.not_push:
    ; if not executing and not IF..ENDIF, skip
    mov   rax, [rbp-0x08]
    test  rax, rax
    jnz   .dispatch
    mov   rax, [rbp-0x38]
    cmp   rax, OP_IF
    jb    .next_op
    cmp   rax, OP_ENDIF
    ja    .next_op

.dispatch:
    mov   rax, [rbp-0x38]
    ; OP_RESERVED(0x50), OP_VER..., OP_RESERVED1/2 -> handled as BAD_OPCODE
    cmp   rax, OP_1NEGATE
    je    .pushnum
    cmp   rax, OP_1
    jb    .bad_opcode
    cmp   rax, OP_16
    jbe   .pushnum
    ; small dispatch
    cmp   rax, OP_NOP
    je    .next_op
    cmp   rax, OP_IF
    je    .op_if
    cmp   rax, OP_NOTIF
    je    .op_notif
    cmp   rax, OP_ELSE
    je    .op_else
    cmp   rax, OP_ENDIF
    je    .op_endif
    cmp   rax, OP_VERIFY
    je    .op_verify
    cmp   rax, OP_RETURN
    je    .op_return
    cmp   rax, OP_TOALTSTACK
    je    .op_toalt
    cmp   rax, OP_FROMALTSTACK
    je    .op_fromalt
    cmp   rax, OP_2DROP
    je    .op_2drop
    cmp   rax, OP_2DUP
    je    .op_2dup
    cmp   rax, OP_3DUP
    je    .op_3dup
    cmp   rax, OP_2OVER
    je    .op_2over
    cmp   rax, OP_2ROT
    je    .op_2rot
    cmp   rax, OP_2SWAP
    je    .op_2swap
    cmp   rax, OP_IFDUP
    je    .op_ifdup
    cmp   rax, OP_DEPTH
    je    .op_depth
    cmp   rax, OP_DROP
    je    .op_drop
    cmp   rax, OP_DUP
    je    .op_dup
    cmp   rax, OP_NIP
    je    .op_nip
    cmp   rax, OP_OVER
    je    .op_over
    cmp   rax, OP_PICK
    je    .op_pick
    cmp   rax, OP_ROLL
    je    .op_roll
    cmp   rax, OP_ROT
    je    .op_rot
    cmp   rax, OP_SWAP
    je    .op_swap
    cmp   rax, OP_TUCK
    je    .op_tuck
    cmp   rax, OP_SIZE
    je    .op_size
    cmp   rax, OP_EQUAL
    je    .op_equal
    cmp   rax, OP_EQUALVERIFY
    je    .op_equalverify
    cmp   rax, OP_1ADD
    je    .op_mono1
    cmp   rax, OP_1SUB
    je    .op_mono2
    cmp   rax, OP_NEGATE
    je    .op_mono3
    cmp   rax, OP_ABS
    je    .op_mono4
    cmp   rax, OP_NOT
    je    .op_mono5
    cmp   rax, OP_0NOTEQUAL
    je    .op_mono6
    cmp   rax, OP_ADD
    je    .op_bin1
    cmp   rax, OP_SUB
    je    .op_bin2
    cmp   rax, OP_BOOLAND
    je    .op_bin3
    cmp   rax, OP_BOOLOR
    je    .op_bin4
    cmp   rax, OP_NUMEQUAL
    je    .op_bin5
    cmp   rax, OP_NUMEQUALVERIFY
    je    .op_bin6
    cmp   rax, OP_NUMNOTEQUAL
    je    .op_bin7
    cmp   rax, OP_LESSTHAN
    je    .op_bin8
    cmp   rax, OP_GREATERTHAN
    je    .op_bin9
    cmp   rax, OP_LESSTHANOREQUAL
    je    .op_bin10
    cmp   rax, OP_GREATERTHANOREQUAL
    je    .op_bin11
    cmp   rax, OP_MIN
    je    .op_bin12
    cmp   rax, OP_MAX
    je    .op_bin13
    cmp   rax, OP_WITHIN
    je    .op_within
    cmp   rax, OP_RIPEMD160
    je    .op_crypto
    cmp   rax, OP_SHA1
    je    .op_crypto
    cmp   rax, OP_SHA256
    je    .op_crypto
    cmp   rax, OP_HASH160
    je    .op_crypto
    cmp   rax, OP_HASH256
    je    .op_crypto
    cmp   rax, OP_CODESEPARATOR
    je    .op_cs
    cmp   rax, OP_CHECKSIG
    je    .op_checksig
    cmp   rax, OP_CHECKSIGVERIFY
    je    .op_checksigverify
    cmp   rax, OP_CHECKSIGADD
    je    .op_checksigadd
    cmp   rax, OP_CHECKMULTISIG
    je    .op_checkmultisig
    cmp   rax, OP_CHECKMULTISIGVERIFY
    je    .op_checkmultisigverify
    cmp   rax, OP_CHECKLOCKTIMEVERIFY
    je    .op_cltv
    cmp   rax, OP_CHECKSEQUENCEVERIFY
    je    .op_csv
    ; OP_NOP1 (0xb0) and OP_NOP4..OP_NOP10 (0xb3..0xb9): consensus no-ops.
    ; Only OP_NOP2 (0xb1, -> CLTV/BIP65) and OP_NOP3 (0xb2, -> CSV/BIP112)
    ; were ever repurposed; the rest of the original reserved-for-upgrade
    ; NOP range must still do nothing, exactly like plain OP_NOP -- treating
    ; them as bad opcodes rejects real, historically-mined mainnet
    ; transactions that used OP_NOP1 as part of a non-standard (but
    ; consensus-valid) script (e.g. a hash-reveal script ending in
    ; OP_EQUALVERIFY OP_NOP1 instead of OP_EQUALVERIFY OP_CHECKSIG).
    ; SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS is a mempool/relay POLICY
    ; flag (like STRICTENC, removed above) that never appears in Core's
    ; consensus GetBlockScriptFlags, so it does not gate this here.
    cmp   rax, OP_NOP1
    je    .next_op
    cmp   rax, OP_NOP4
    je    .next_op
    cmp   rax, OP_NOP5
    je    .next_op
    cmp   rax, OP_NOP6
    je    .next_op
    cmp   rax, OP_NOP7
    je    .next_op
    cmp   rax, OP_NOP8
    je    .next_op
    cmp   rax, OP_NOP9
    je    .next_op
    cmp   rax, OP_NOP10
    je    .next_op
    jmp   .bad_opcode

; --- pushnum ---
.pushnum:
    mov   rax, [rbp-0x38]
    sub   rax, (OP_1 - 1)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rax
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

; ============================================================================
; Control flow
; ============================================================================
.op_if:
.op_notif:
    mov   rax, [rbp-0x08]
    test  rax, rax
    jz    .if_notexec
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 1
    jae   .if_sok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0
.if_sok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    ; tapscript minimal-if
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    jne   .if_tapd
    mov   r14d, [r13]
    cmp   r14d, 2
    jae   .tap_minif
    test  r14d, r14d
    jz    .if_minif_ok
    cmp   byte [r13+ELEM_DATA_OFF], 1
    je    .if_minif_ok
.tap_minif:
    mov   rax, SCRIPT_ERR_TAPSCRIPT_MINIMALIF
    jmp   .err_ret0
.if_tapd:
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_WITNESS_V0
    jne   .if_minif_ok
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_MINIMALIF
    jz    .if_minif_ok
    mov   r14d, [r13]
    cmp   r14d, 2
    jae   .wif_minif
    test  r14d, r14d
    jz    .if_minif_ok
    cmp   byte [r13+ELEM_DATA_OFF], 1
    je    .if_minif_ok
.wif_minif:
    mov   rax, SCRIPT_ERR_MINIMALDATA
    jmp   .err_ret0
.if_minif_ok:
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    call  cast_to_bool
    mov   r14, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    mov   rax, [rbp-0x38]
    cmp   rax, OP_NOTIF
    jne   .if_ni
    xor   r14, 1
.if_ni:
    mov   rdi, r14
    call  vfexec_push
    jmp   .next_op
.if_notexec:
    xor   edi, edi
    call  vfexec_push
    jmp   .next_op

.op_else:
    call  vfexec_depth
    test  rax, rax
    jnz   .else_ok
    mov   rax, SCRIPT_ERR_UNBALANCED_CONDITIONAL
    jmp   .err_ret0
.else_ok:
    call  vfexec_toggle_top
    jmp   .next_op

.op_endif:
    call  vfexec_depth
    test  rax, rax
    jnz   .endif_ok
    mov   rax, SCRIPT_ERR_UNBALANCED_CONDITIONAL
    jmp   .err_ret0
.endif_ok:
    call  vfexec_pop
    jmp   .next_op

.op_verify:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 1
    jae   .vfy_ok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0
.vfy_ok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    call  cast_to_bool
    test  rax, rax
    jz    .vfy_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op
.vfy_fail:
    mov   rax, SCRIPT_ERR_VERIFY
    jmp   .err_ret0

.op_return:
    mov   rax, SCRIPT_ERR_OP_RETURN
    jmp   .err_ret0

; ============================================================================
; Stack ops
; ============================================================================
.op_toalt:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 1
    jae   .toalt_ok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0
.toalt_ok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   rdi, [rbp-0x60]
    mov   rsi, r13
    call  elem_move
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+24]
    mov   rsi, [r12+16]
    mov   rdx, [rbp-0x60]
    mov   rcx, [rdx]
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_fromalt:
    lea   rdi, [r12+24]
    mov   rsi, [r12+16]
    call  stack_depth
    cmp   rax, 1
    jae   .fromalt_ok
    mov   rax, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION
    jmp   .err_ret0
.fromalt_ok:
    lea   rdi, [r12+24]
    mov   rsi, [r12+16]
    call  stack_top_ptr
    mov   r13, rax
    mov   rdi, [rbp-0x60]
    mov   rsi, r13
    call  elem_move
    lea   rdi, [r12+24]
    mov   rsi, [r12+16]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x60]
    mov   rcx, [rdx]
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_2drop:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 2
    jae   .d2_ok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0
.d2_ok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op

.op_2dup:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    jmp   .next_op

.op_3dup:
    mov   rdi, 3
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    jmp   .next_op

.op_2over:
    mov   rdi, 4
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 4
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 4
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    jmp   .next_op

.op_2rot:
    mov   rdi, 6
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; x1..x6 ; -> x3 x4 x5 x6 x1 x2
    ; copy x1(0), x2(1) ; erase them ; push x1,x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 6
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   rdi, [rbp-0x90]
    mov   rsi, rax
    call  elem_move
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 5
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   rdi, [rbp-0x98]
    mov   rsi, rax
    call  elem_move
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 6
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_erase_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 5
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_erase_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x90]
    mov   rax, [rbp-0x90]
    mov   rcx, [rax]
    call  stack_push
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x98]
    mov   rax, [rbp-0x98]
    mov   rcx, [rax]
    call  stack_push
    jmp   .next_op

.op_2swap:
    mov   rdi, 4
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; swap x1(0)<->x3(2), x2(1)<->x4(3)
    ; put each into tmp via elem ptr
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 4
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r13, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r14, rax
    call  interp_swap_recs
    ; x2(1) <-> x4(3)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r13, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r14, rax
    call  interp_swap_recs
    jmp   .next_op

.op_ifdup:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    call  cast_to_bool
    test  rax, rax
    jz    .next_op
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_dup_index
    jmp   .next_op

.op_depth:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_drop:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op

.op_dup:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_dup_index
    jmp   .next_op

.op_nip:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_erase_index
    jmp   .next_op

.op_over:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_dup_index
    jmp   .next_op

.op_pick:
.op_roll:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    mov   rdx, 4
    call  scriptnum_decode
    mov   rbx, rax            ; n
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    test  rbx, rbx
    js    .pk_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rbx, rax
    jae   .pk_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    sub   rax, rbx
    mov   r14, rax            ; idx
    mov   rax, [rbp-0x38]
    cmp   rax, OP_ROLL
    jne   .pkdup
    ; roll: copy idx, erase idx, push
    mov   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  stack_elem_ptr
    mov   rdi, [rbp-0x90]
    mov   rsi, rax
    call  elem_move
    mov   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  stack_erase_index
    mov   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x90]
    mov   rax, [rbp-0x90]
    mov   rcx, [rax]
    call  stack_push
    jmp   .next_op
.pkdup:
    mov   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  stack_dup_index
    jmp   .next_op
.pk_fail:
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0

.op_rot:
    mov   rdi, 3
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; swap top-3 <-> top-2 ; swap top-2 <-> top-1
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r13, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r14, rax
    call  interp_swap_recs
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r13, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r14, rax
    call  interp_swap_recs
    jmp   .next_op

.op_swap:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_swap_two
    jmp   .next_op

.op_tuck:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; x1 x2 -> x2 x1 x2 : copy top to tmp2; erase top&second; push x2,x1,x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   rdi, [rbp-0xA0]
    mov   rsi, r13
    call  elem_move              ; tmp2 = x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax
    mov   rdi, [rbp-0xA8]
    mov   rsi, r13
    call  elem_move              ; tmp3 = x1
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    ; push x2, x1, x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0xA0]
    mov   rax, [rbp-0xA0]
    mov   rcx, [rax]
    call  stack_push
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0xA8]
    mov   rax, [rbp-0xA8]
    mov   rcx, [rax]
    call  stack_push
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0xA0]
    mov   rax, [rbp-0xA0]
    mov   rcx, [rax]
    call  stack_push
    jmp   .next_op

.op_size:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   edx, [r13]          ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load here pulls in the element's own first
                                ; 4 DATA bytes as garbage high bits of the
                                ; pushed "size" number -- found via a real
                                ; mainnet block (height 251683) using
                                ; OP_SIZE on a 20-byte element whose first 4
                                ; data bytes were nonzero, corrupting the
                                ; result into a bogus multi-byte CScriptNum
                                ; that a later numeric op then rejected as
                                ; oversized.
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

; ============================================================================
; Equality
; ============================================================================
.op_equal:
.op_equalverify:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax          ; x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r14, rax          ; x1
    mov   eax, [r13]
    mov   ecx, [r14]
    cmp   eax, ecx
    jne   .eq_false
    mov   rdi, r14
    add   rdi, ELEM_DATA_OFF
    mov   rsi, r13
    add   rsi, ELEM_DATA_OFF
    mov   rdx, rax
    call  interp_memeq
    test  rax, rax
    jz    .eq_false
    mov   r15d, 1
    jmp   .eq_have
.eq_false:
    mov   r15d, 0
.eq_have:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r15
    call  interp_push_bool
    mov   rax, [rbp-0x38]
    cmp   rax, OP_EQUALVERIFY
    jne   .next_op
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    call  cast_to_bool
    test  rax, rax
    jz    .eqv_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op
.eqv_fail:
    mov   rax, SCRIPT_ERR_EQUALVERIFY
    jmp   .err_ret0

; ============================================================================
; Monadic numeric
; ============================================================================
.op_mono1: mov  rbx, 1
    jmp   .mono_common
.op_mono2: mov  rbx, 2
    jmp   .mono_common
.op_mono3: mov  rbx, 3
    jmp   .mono_common
.op_mono4: mov  rbx, 4
    jmp   .mono_common
.op_mono5: mov  rbx, 5
    jmp   .mono_common
.op_mono6: mov  rbx, 6
    jmp   .mono_common
.mono_common:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    mov   rdx, 4
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    mov   r14, rax          ; bn
    cmp   rbx, 1
    je    .mo1
    cmp   rbx, 2
    je    .mo2
    cmp   rbx, 3
    je    .mo3
    cmp   rbx, 4
    je    .mo4
    cmp   rbx, 5
    je    .mo5
.mo6:  test  r14, r14
    setnz r14b
    jmp   .mo_out
.mo1:  add   r14, 1
    jmp   .mo_out
.mo2:  sub   r14, 1
    jmp   .mo_out
.mo3:  neg   r14
    jmp   .mo_out
.mo4:  test  r14, r14
    jns   .mo_out
    neg   r14
    jmp   .mo_out
.mo5:  test  r14, r14
    setz  r14b
    jmp   .mo_out
.mo_out:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0
.snum_fail:
    mov   rax, SCRIPT_ERR_SCRIPTNUM
    jmp   .err_ret0

; ============================================================================
; Binary numeric
; ============================================================================
.op_bin1: mov  rbx, 1
    jmp   .bin_common
.op_bin2: mov  rbx, 2
    jmp   .bin_common
.op_bin3: mov  rbx, 3
    jmp   .bin_common
.op_bin4: mov  rbx, 4
    jmp   .bin_common
.op_bin5: mov  rbx, 5
    jmp   .bin_common
.op_bin6: mov  rbx, 6
    jmp   .bin_common
.op_bin7: mov  rbx, 7
    jmp   .bin_common
.op_bin8: mov  rbx, 8
    jmp   .bin_common
.op_bin9: mov  rbx, 9
    jmp   .bin_common
.op_bin10: mov rbx, 10
    jmp   .bin_common
.op_bin11: mov rbx, 11
    jmp   .bin_common
.op_bin12: mov rbx, 12
    jmp   .bin_common
.op_bin13: mov rbx, 13
    jmp   .bin_common
.bin_common:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    mov   rdx, 4
    call  scriptnum_decode
    mov   r14, rax          ; bn1
    mov   rcx, [rbp-0xB0]
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r15d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r15
    mov   rsi, r13
    mov   rdx, 4
    call  scriptnum_decode
    mov   r15, rax          ; bn2
    mov   rcx, [rbp-0xB0]
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    ; rbx = op id
    cmp   rbx, 1
    je    .b_add
    cmp   rbx, 2
    je    .b_sub
    cmp   rbx, 3
    je    .b_band
    cmp   rbx, 4
    je    .b_bor
    cmp   rbx, 5
    je    .b_eq
    cmp   rbx, 6
    je    .b_eq
    cmp   rbx, 7
    je    .b_ne
    cmp   rbx, 8
    je    .b_lt
    cmp   rbx, 9
    je    .b_gt
    cmp   rbx, 10
    je    .b_le
    cmp   rbx, 11
    je    .b_ge
    cmp   rbx, 12
    je    .b_min
.b_max:
    cmp   r14, r15
    cmovl r14, r15
    jmp   .b_out
.b_min:
    cmp   r14, r15
    cmovg r14, r15
    jmp   .b_out
.b_add: add   r14, r15
    jmp   .b_out
.b_sub: sub   r14, r15
    jmp   .b_out
.b_band:
    mov   r13d, 0
    test  r14, r14
    setnz r14b
    test  r15, r15
    setnz r15b
    and   r14d, r15d
    jmp   .b_out
.b_bor:
    test  r14, r14
    setnz r14b
    test  r15, r15
    setnz r15b
    or    r14d, r15d
    jmp   .b_out
.b_eq: cmp   r14, r15
    sete  r14b
    jmp   .b_out
.b_ne: cmp   r14, r15
    setne r14b
    jmp   .b_out
.b_lt: cmp   r14, r15
    setl  r14b
    jmp   .b_out
.b_gt: cmp   r14, r15
    setg  r14b
    jmp   .b_out
.b_le: cmp   r14, r15
    setle r14b
    jmp   .b_out
.b_ge: cmp   r14, r15
    setge r14b
    jmp   .b_out
.b_out:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  interp_push_num
    test  rax, rax
    jnz   .b_post
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0
.b_post:
    mov   rax, [rbp-0x38]
    cmp   rax, OP_NUMEQUALVERIFY
    jne   .next_op
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    call  cast_to_bool
    test  rax, rax
    jz    .neqv_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op
.neqv_fail:
    mov   rax, SCRIPT_ERR_NUMEQUALVERIFY
    jmp   .err_ret0

.op_within:
    mov   rdi, 3
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; x1(val) x2(min) x3(max); f=(min<=val && val<max)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_third_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    mov   rdx, 4
    call  scriptnum_decode
    mov   r15, rax          ; val
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    mov   rdx, 4
    call  scriptnum_decode
    mov   r14, rax          ; min
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    mov   rdx, 4
    call  scriptnum_decode
    mov   rbx, rax          ; max
    xor   r13d, r13d
    cmp   r14, r15
    setle r13b
    cmp   r15, rbx
    setl  r14b
    and   r13d, r14d
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    mov   rdx, r13
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_bool
    jmp   .next_op

; ============================================================================
; Crypto
; ============================================================================
.op_crypto:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rax, [rbp-0x38]
    cmp   rax, OP_SHA256
    je    .cr_sha
    cmp   rax, OP_RIPEMD160
    je    .cr_rip
    cmp   rax, OP_HASH160
    je    .cr_h160
    cmp   rax, OP_HASH256
    je    .cr_h256
    cmp   rax, OP_SHA1
    je    .cr_sha1
    jmp   .bad_opcode
.cr_sha:
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  sha256_full
    mov   r15d, 32
    jmp   .cr_out
.cr_sha1:
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  sha1_full
    mov   r15d, 20
    jmp   .cr_out
.cr_rip:
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  ripemd160
    mov   r15d, 20
    jmp   .cr_out
.cr_h160:
    ; sha256 -> ripemd160
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  sha256_full
    mov   rdi, [rbp-0x60]
    add   rdi, 32
    mov   rsi, [rbp-0x60]
    mov   rdx, 32
    call  ripemd160
    ; result in interp_tmp+32 (20 bytes)
    mov   r15d, 20
    jmp   .cr_out2
.cr_h256:
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  sha256d
    mov   r15d, 32
    jmp   .cr_out
.cr_out:
    ; pop, push (interp_tmp, r15d)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x60]
    mov   rcx, r15
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0
.cr_out2:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x60]
    add   rdx, 32
    mov   rcx, r15
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_cs:
    mov   rax, [rbp-0x10]
    mov   [rbp-0x20], rax
    jmp   .next_op

; ============================================================================
; CHECKSIG family
; ============================================================================
.op_checksig:
.op_checksigverify:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    call  interp_checksig
    mov   r13, rax          ; success
    ; pop sig, pub, push bool
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    mov   rdx, r13
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_bool
    mov   rax, [rbp-0x38]
    cmp   rax, OP_CHECKSIGVERIFY
    jne   .next_op
    ; tapscript forbids CHECKSIGVERIFY
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    je    .bad_opcode
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    call  cast_to_bool
    test  rax, rax
    jz    .csigv_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op
.csigv_fail:
    mov   rax, SCRIPT_ERR_CHECKSIGVERIFY
    jmp   .err_ret0

.op_checksigadd:
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    je    .csa_go
    mov   rax, SCRIPT_ERR_BAD_OPCODE
    jmp   .err_ret0
.csa_go:
    mov   rdi, 3
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; (sig num pubkey) -> decode num at sp-2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    mov   rdx, 4
    call  scriptnum_decode
    mov   rbx, rax          ; num (rbx preserved)
    call  interp_checksig_add
    mov   r13, rax          ; success
    add   rbx, r13
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    mov   rdx, rbx
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_checkmultisig:
.op_checkmultisigverify:
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    jne   .cms_go
    mov   rax, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG
    jmp   .err_ret0
.cms_go:
    ; full OP_CHECKMULTISIG handled by helper which returns 1 ok or sets interp_err
    call  interp_checkmultisig
    test  rax, rax
    jnz   .next_op
    mov   rax, [rbp-0x70]
    mov   rax, [rax]
    test  rax, rax
    jz    .bad_opcode
    mov   rax, [rbp-0x70]
    mov   rax, [rax]
    jmp   .err_ret0

.op_cltv:
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    jnz   .cltv_go
    jmp   .next_op
.cltv_go:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    mov   rdx, 5
    call  scriptnum_decode
    test  rax, rax
    jns   .cltv_nn
    mov   rax, SCRIPT_ERR_NEGATIVE_LOCKTIME
    jmp   .err_ret0
.cltv_nn:
    ; no tx context in pure interpreter -> unsatisfied
    mov   rax, SCRIPT_ERR_UNSATISFIED_LOCKTIME
    jmp   .err_ret0

.op_csv:
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    jnz   .csv_go
    jmp   .next_op
.csv_go:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    mov   rdx, 5
    call  scriptnum_decode
    test  rax, rax
    jns   .csv_nn
    mov   rax, SCRIPT_ERR_NEGATIVE_LOCKTIME
    jmp   .err_ret0
.csv_nn:
    ; disable flag (bit 31) -> NOP
    test  rax, 0x80000000
    jnz   .next_op
    mov   rax, SCRIPT_ERR_UNSATISFIED_LOCKTIME
    jmp   .err_ret0

.bad_opcode:
    mov   rax, SCRIPT_ERR_BAD_OPCODE
    jmp   .err_ret0

.next_op:
    inc   qword [rbp-0x30]
    jmp   .loop

.loop_done:
    call  vfexec_depth
    test  rax, rax
    jz    .cstack
    mov   rax, SCRIPT_ERR_UNBALANCED_CONDITIONAL
    jmp   .err_ret0
.cstack:
    ; Tapscript (BIP342 ExecuteWitnessScript) enforces cleanstack: the final
    ; stack must have exactly one element (else CLEANSTACK) and that element
    ; must CastToBool to true (else EVAL_FALSE). BASE/WITNESS_V0 leave
    ; cleanstack/truthiness to the outer VerifyScript, so only gate on
    ; SIGVERSION_TAPSCRIPT here. The "empty-stack treatment": a tapscript that
    ; evaluates to an empty (or multi-item / false) stack must be rejected.
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    jne   .final_ok
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 1
    jne   .cstack_fail          ; stack.size() != 1 -> CLEANSTACK
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    call  cast_to_bool
    test  rax, rax
    jz    .evalfalse           ; !CastToBool(top) -> EVAL_FALSE
    jmp   .final_ok
.cstack_fail:
    mov   rax, SCRIPT_ERR_CLEANSTACK
    jmp   .err_ret0
.evalfalse:
    mov   rax, SCRIPT_ERR_EVAL_FALSE
    jmp   .err_ret0
.final_ok:
    mov   rax, [r12+80]
    test  rax, rax
    jz    .ret1
    mov   qword [rax], SCRIPT_ERR_OK
.ret1:
    mov   eax, 1
    jmp   .done
.err_ret0:
    mov   rcx, rax
    mov   rax, [r12+80]
    test  rax, rax
    jz    .ret0
    mov   [rax], rcx
.ret0:
    xor   eax, eax
.done:
    add   rsp, 0x100
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret

; ============================================================================
; is_opsuccess(opcode in rax) -> rax = 1 if OP_SUCCESSx else 0.
;   Bitcoin Core IsOpSuccess (script.cpp:365), BIP342:
;     opcode==80(OP_RESERVED) || opcode==98(OP_VER) ||
;     (126..129)=CAT/SUBSTR/LEFT/RIGHT ||
;     (131..134)=INVERT/AND/OR/XOR || (137..138)=RESERVED1/RESERVED2 ||
;     (141..142)=2MUL/2DIV || (149..153)=MUL/DIV/MOD/LSHIFT/RSHIFT ||
;     (187..254)=undefined tapscript opcodes (starts at OP_NOP11=0xbb=187).
;   Leaf; uses only rax/rcx/rdx so callee-saved (rbx,r12-r15) stay untouched.
; ============================================================================
global is_opsuccess
is_opsuccess:
    cmp   rax, 80
    je    .yes
    cmp   rax, 98
    je    .yes
    cmp   rax, 126
    jb    .r131
    cmp   rax, 129
    jbe   .yes
.r131:
    cmp   rax, 131
    jb    .r137
    cmp   rax, 134
    jbe   .yes
.r137:
    cmp   rax, 137
    jb    .r141
    cmp   rax, 138
    jbe   .yes
.r141:
    cmp   rax, 141
    jb    .r149
    cmp   rax, 142
    jbe   .yes
.r149:
    cmp   rax, 149
    jb    .r187
    cmp   rax, 153
    jbe   .yes
.r187:
    cmp   rax, 187
    jb    .no
    cmp   rax, 254
    jbe   .yes
.no:
    xor   eax, eax
    ret
.yes:
    mov   eax, 1
    ret

; is_opsuccess_c(int opcode) : C-ABI wrapper (opcode in edi per SysV) that
; tail-calls into the rax-based is_opsuccess logic above. Used by C harnesses.
global is_opsuccess_c
is_opsuccess_c:
    mov   rax, rdi
    jmp   is_opsuccess

; ============================================================================
; interp_swap_recs(a=rdi, b=rsi)  : swap two element records pointed by r13,r14
;   -- uses the values already loaded in r13 (a) and r14 (b)
; ============================================================================
interp_swap_recs:
    push  rbx
    ; r13 = a, r14 = b. rbp is script_eval's frame here (interp_swap_recs is
    ; only ever reached via script_eval's own call graph, same convention as
    ; interp_checkmultisig/interp_push_num/interp_push_bool).
    mov   rdi, [rbp-0x90]
    mov   rsi, r13
    call  elem_move            ; tmp0 = *a
    mov   rdi, r13
    mov   rsi, r14
    call  elem_move            ; *a = *b
    mov   rdi, r14
    mov   rsi, [rbp-0x90]
    call  elem_move            ; *b = tmp0
    pop   rbx
    ret

; ============================================================================
; interp_memeq(a=rdi, b=rsi, len=rdx) -> rax 1 if equal
; ============================================================================
interp_memeq:
    xor   ecx, ecx
.loop:
    cmp   rcx, rdx
    jae   .yes
    movzx r8d, byte [rdi+rcx]
    movzx r9d, byte [rsi+rcx]
    cmp   r8b, r9b
    jne   .no
    inc   rcx
    jmp   .loop
.yes:
    mov   eax, 1
    ret
.no:
    xor   eax, eax
    ret

; ============================================================================
; interp_push_num(&sp, elems, value) -> rax 1/0
;   Serializes value (ScriptNum) and pushes; uses scriptnum_buf + rdx=len.
; ============================================================================
interp_push_num:
    ; rdi=&sp, rsi=elems, rdx=value
    push  r12
    push  r13
    push  r14
    mov   r12, rdi
    mov   r13, rsi
    mov   r14, rdx            ; value (preserved)
    mov   rdi, r14
    call  scriptnum_serialize  ; rax=ptr, rdx=len
    ; copy the serialized bytes into interp_tmp
    push  rdx
    mov   r14, rdx            ; len
    mov   rdi, rdx
    ; copy rax[0..rdx) -> interp_tmp (interp_tmp is thread-local, 528 bytes;
    ; interp_push_num is only ever reached via script_eval's own call graph,
    ; so rbp is always script_eval's frame here -- same convention as
    ; interp_checkmultisig)
    mov   rdi, [rbp-0x60]
    mov   rsi, rax
    mov   rcx, r14
    rep movsb
    pop   rdx
    ; push (interp_tmp, r14)
    mov   rdi, r12
    mov   rsi, r13
    mov   rdx, [rbp-0x60]
    mov   rcx, r14
    call  stack_push
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; interp_push_bool(&sp, elems, bool in rdx) -> rax 1/0
; ============================================================================
interp_push_bool:
    push  r12
    push  r13
    push  r14
    mov   r12, rdi
    mov   r13, rsi
    mov   r14, rdx            ; bool
    ; build the single byte
    mov   rax, [rbp-0x68]      ; this thread's bool_buf address (interp_push_bool
                                ; is only reached via script_eval's call graph,
                                ; incl. through interp_checkmultisig, which shares
                                ; script_eval's frame -- same convention as -0x60).
                                ; rax is caller-saved/volatile, safe to clobber
                                ; here and hold across .put0/.have/.pushit below
                                ; (nothing in this function relies on an incoming
                                ; rax value -- r12/r13/r14 are its only locals).
    test  r14, r14
    jz    .put0
    mov   byte [rax], 1
    jmp   .have
.put0:
    mov   byte [rax], 0
.have:
    ; push either empty (len 0) or 1 byte. For bool true push 0x01; false push empty.
    xor   ecx, ecx
    test  r14, r14
    jz    .pushit
    mov   ecx, 1
.pushit:
    mov   rdi, r12
    mov   rsi, r13
    mov   rdx, rax
    ; rcx = 0 or 1
    call  stack_push
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; interp_require_depth(min in rdi) -> rax = 0 ok / SCRIPT_ERR_INVALID_STACK_OP
;   Preserves callee-saved. Uses r14 to hold min across the stack_depth call.
; ============================================================================
interp_require_depth:
    push  r14
    mov   r14, rdi            ; min (preserved)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, r14
    jae   .ok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    pop   r14
    ret
.ok:
    xor   eax, eax
    pop   r14
    ret




; ============================================================================
; checksig helpers.
; checksig_fn (6 args, all in regs):
;   rdi=ctx, rsi=sig, rdx=siglen, rcx=pub, r8=publen, r9=&interp_slice
;   where interp_slice={sc_ptr, sc_len}; returns rax = success 0/1.
; Preserve callee-saved rbx,r12-r15. rbp = script_eval frame (for slice).
; ============================================================================

; interp_checksig() -> rax = 0/1 ; sig = sp-2, pub = sp-1
interp_checksig:
    push  r12
    push  r13
    push  r14
    push  r15
    push  rbx
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax            ; pub elem
    mov   r14d, [r13]         ; publen
    lea   r15, [r13+ELEM_DATA_OFF]
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax            ; sig elem
    mov   ebx, [r13]          ; siglen (32-bit elem length; was rbx[8])
    test  rbx, rbx
    jz    .false
    mov   rax, [r12+96]
    test  rax, rax
    jz    .false
    ; build slice
    mov   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10], rax
    mov   rax, [rbp-0x18]
    sub   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10+8], rax
    ; args
    mov   rdi, [r12+88]
    lea   rsi, [r13+ELEM_DATA_OFF]
    mov   rdx, rbx
    mov   rcx, r15
    mov   r8,  r14
    TLS_ADDR r9, interp_slice
    call  qword [r12+96]
    jmp   .end
.false:
    xor   eax, eax
.end:
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; interp_checksig_add() -> rax = 0/1 ; sig = sp-3, pub = sp-1 (tapscript CHECKSIGADD)
interp_checksig_add:
    push  r12
    push  r13
    push  r14
    push  r15
    push  rbx
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax            ; pub elem
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    ; sig = third (sp-3)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_third_ptr
    mov   r13, rax
    mov   ebx, [r13]          ; siglen (32-bit elem length; was rbx[8])
    test  rbx, rbx
    jz    .false
    mov   rax, [r12+96]
    test  rax, rax
    jz    .false
    mov   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10], rax
    mov   rax, [rbp-0x18]
    sub   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10+8], rax
    mov   rdi, [r12+88]
    lea   rsi, [r13+ELEM_DATA_OFF]
    mov   rdx, rbx
    mov   rcx, r15
    mov   r8,  r14
    TLS_ADDR r9, interp_slice
    call  qword [r12+96]
    jmp   .end
.false:
    xor   eax, eax
.end:
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; interp_checkmultisig() -> rax = 1 ok / 0 failed (error in interp_err)
;   Full OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY. Tapscript handled by caller.
;   Handles the classic (dummy) [sig...] m [pub...] n layout, signature checking
;   via checksig_fn against each key in order.
;
;   Stack (bottom..top): ... [dummy] sig1..sigm m pub1..pubn n
;   On entry r12 = script_state (checksig_ctx at +88, checksig_fn at +96),
;   rbp = script_eval frame ([rbp-0x20]..[rbp-0x18] = current scriptCode slice).
;
;   Consensus algorithm (matches Core EvalScript's CheckMultisig over the
;   functor): read nKeys=n, nSigs=m; walk the keys left-to-right, checking each
;   against the current signature via checksig_fn; consume a signature only on a
;   match. If fewer than mSigs verify, the multisig is false. Pops all operands
;   (incl. the dummy), pushes the boolean result, returns 1 (ok). On a bad
;   operand count / NULLDUMMY violation returns 0 with interp_err set.
interp_checkmultisig:
    push  r12
    push  r13
    push  r14
    push  r15
    push  rbx
    sub   rsp, 32               ; locals: [rsp+24]=nKeys, [rsp+16]=nSigs, [rsp+8]=sp, [rsp+0]=remaining
    mov   rax, [rbp-0x70]
    mov   qword [rax], 0

    ; r12 = script_state stays fixed. The stack layout (bottom..top) is:
    ;   ... dummy sig1..sigm m pub1..pubn n
    ; i.e. using stacktop(k) (1-based from top): k=1 is n, k=2..nkeys+1 are the
    ; pubkeys (pubn..pub1), k=nkeys+2 is m, k=nkeys+3..nkeys+nsigs+2 are the
    ; sigs (sigm..sig1), k=need+1 (=nkeys+nsigs+3) is the dummy.
    ; This mirrors the Core-differential bitcoin_verify.c EvalMultisig layout
    ; exactly (stacktop(nkeys+2)=m, stacktop(2+j)=keys top-first, etc).

    ; ---- helper to read stacktop(k): elem ptr = stack_elem_ptr(&sp, elems, sp-k).
    ;       We read [r12+0]=elems, [r12+8]=&sp. Local [rsp+0] caches the sp
    ;       VALUE so index arithmetic is stable across the operand reads. ----
    mov   rax, [r12+8]
    mov   [rsp+8], rax           ; sp value (cached)

    ; ---- 1. nKeys = CScriptNum(stacktop(1)), validate 1..20 ----
    mov   r15, [rsp+8]
    sub   r15, 1                 ; idx_from_bottom = sp - 1
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    mov   rdx, r15
    call  stack_elem_ptr
    mov   r15, rax               ; elem ptr
    mov   r13d, [r15]            ; len
    lea   r14, [r15+ELEM_DATA_OFF]
    mov   rdi, r13
    mov   rsi, r14
    mov   rdx, 4
    call  scriptnum_decode
    mov   r15d, eax              ; nKeys
    cmp   r15d, 1
    jl    .err_pubcount
    cmp   r15d, 20
    jg    .err_pubcount
    mov   [rsp+24], r15d         ; locals: nKeys

    ; stacktop(nkeys+2) = m
    mov   eax, [rsp+24]
    add   eax, 2
    mov   rcx, [rsp+8]
    sub   rcx, rax               ; idx = sp - (nkeys+2)
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    mov   rdx, rcx
    call  stack_elem_ptr
    mov   r15, rax
    mov   r13d, [r15]
    lea   r14, [r15+ELEM_DATA_OFF]
    mov   rdi, r13
    mov   rsi, r14
    mov   rdx, 4
    call  scriptnum_decode
    mov   r14d, eax              ; nSigs
    test  eax, eax
    js    .err_sigcount
    cmp   eax, [rsp+24]
    jg    .err_sigcount
    mov   [rsp+16], r14d         ; locals: nSigs

    ; need = nKeys + nSigs + 2 ;  dummy at stacktop(need+1)
    mov   eax, [rsp+24]
    add   eax, [rsp+16]
    add   eax, 2                 ; need
    ; ---- stack depth: need+1 elements (operands + the dummy) must exist.
    ; Without this, too few operands fell through to "multisig is false"
    ; (EVAL_FALSE) where Core reports INVALID_STACK_OPERATION.
    mov   ecx, eax               ; need
    inc   ecx                    ; need+1
    mov   edx, [rsp+8]           ; sp
    cmp   edx, ecx
    jl    .err_stackop

    ; ---- BIP147 NULLDUMMY. This MUST live here, not in the caller.
    ; The comment this replaces claimed the caller enforces it, but this
    ; function pops the dummy as part of its operand cleanup, so by the time
    ; script_eval returns there is nothing left to inspect. Core checks it
    ; inside EvalScript for the same reason. Leaving it to the caller meant
    ; the interpreter ACCEPTED a spend Core rejects.
    mov   rax, [r12+56]          ; flags
    test  rax, SCRIPT_VERIFY_NULLDUMMY
    jz    .cms_dummy_ok
    mov   ecx, [rsp+24]          ; nKeys
    add   ecx, [rsp+16]          ; + nSigs
    add   ecx, 3                 ; = need+1
    mov   edx, [rsp+8]           ; sp
    sub   edx, ecx               ; idx of the dummy, from the bottom
    movsxd rdx, edx
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   ecx, [rax]             ; dummy length
    test  ecx, ecx
    jnz   .err_nulldummy
.cms_dummy_ok:
    ; recompute need: the checks above clobbered eax.
    mov   eax, [rsp+24]
    add   eax, [rsp+16]
    add   eax, 2

    ; ---- 2. collect keys[]/sigs[] pointers into scratch (live-stack refs) --
    ; keys[j] = stacktop(2+j), j=0..nkeys-1   (pubn down to pub1)
    ; sigs[j] = stacktop(nkeys+3+j), j=0..nsigs-1  (sigm down to sig1)
    ; Store the ELEMENT POINTERS (not copies); the live stack is not modified
    ; until the final pop, exactly as bitcoin_verify.c holds Ref* operands.
    xor   r13d, r13d            ; j = 0
.collect_keys:
    mov   eax, [rsp+24]
    cmp   r13d, eax
    jge   .collect_keys_done
    ; idx = sp - (2 + j)
    mov   r15d, r13d
    add   r15d, 2
    mov   eax, [rsp+8]
    sub   eax, r15d
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    mov   edx, eax
    call  stack_elem_ptr
    ; store pointer to cms_keyrefs[j]
    mov   ecx, 8
    imul  rcx, r13
    TLS_ADDR rdx, cms_keyrefs
    add   rdx, rcx
    mov   [rdx], rax
    inc   r13d
    jmp   .collect_keys
.collect_keys_done:
    xor   r13d, r13d            ; j = 0
.collect_sigs:
    mov   eax, [rsp+16]
    cmp   r13d, eax
    jge   .collect_sigs_done
    ; idx = sp - (nkeys + 3 + j)
    mov   eax, [rsp+24]
    add   eax, 3
    add   eax, r13d
    mov   r15d, [rsp+8]
    sub   r15d, eax
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    mov   edx, r15d
    call  stack_elem_ptr
    mov   ecx, 8
    imul  rcx, r13
    TLS_ADDR rdx, cms_sigrefs
    add   rdx, rcx
    mov   [rdx], rax
    inc   r13d
    jmp   .collect_sigs
.collect_sigs_done:

    ; ---- 3. Core matching loop (bitcoin_verify.c check_multisig) ----
    ;   isig->r13d, ikey->r15d, remaining->[rsp+0].
    ;   We replicate: while(remaining>0 && ikey<nkeys):
    ;     ok=check(sigs[isig],keys[ikey]); if ok {isig++; remaining--}
    ;     ikey++; if(remaining > (nkeys-ikey)) -> fail.
    xor   r13d, r13d             ; isig
    xor   r15d, r15d             ; ikey
    mov   eax, [rsp+16]          ; orig nSigs
    mov   [rsp+0], eax           ; remaining
    ; pop count = need+1 = nkeys+nsigs+3, computed once in .cms_finish (locals
    ; nKeys/nSigs are never overwritten, so no need to pre-store it).
.cms_loop:
    mov   eax, [rsp+0]           ; remaining
    test  eax, eax
    jle   .cms_end               ; remaining<=0 -> done (success)
    mov   eax, [rsp+24]          ; nkeys
    cmp   r15d, eax
    jge   .cms_end               ; ikey>=nkeys -> done
    ; load vSig = sigs[isig], vPub = keys[ikey]
    mov   eax, r13d
    mov   rcx, 8
    imul  rcx, rax
    TLS_ADDR rbx, cms_sigrefs
    mov   rbx, [rbx+rcx]         ; vSig elem ptr
    mov   eax, r15d
    mov   rcx, 8
    imul  rcx, rax
    TLS_ADDR r14, cms_keyrefs
    mov   r14, [r14+rcx]         ; vPub elem ptr
    ; build slice (scriptCode) for the callback's sighash
    mov   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10], rax
    mov   rax, [rbp-0x18]
    sub   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10+8], rax
    ; call checksig_fn(ctx, sig, siglen, pub, publen, &slice)
    mov   rdi, [r12+88]
    mov   eax, [rbx]
    mov   rdx, rax               ; siglen
    lea   rsi, [rbx+ELEM_DATA_OFF]
    mov   eax, [r14]
    mov   r8,  rax               ; publen
    lea   rcx, [r14+ELEM_DATA_OFF]
    TLS_ADDR r9, interp_slice
    mov   rax, [r12+96]
    test  rax, rax
    jz    .cms_key_fail
    call  rax
    test  rax, rax
    jz    .cms_key_fail
    ; ok -> isig++, remaining--
    inc   r13d
    mov   eax, [rsp+0]
    dec   eax
    mov   [rsp+0], eax
.cms_key_fail:
    ; ikey++, then if remaining > (nkeys-ikey) -> fSuccess=0 (fail)
    inc   r15d
    mov   eax, [rsp+24]
    sub   eax, r15d              ; nkeys - ikey
    mov   ecx, [rsp+0]           ; remaining
    cmp   ecx, eax
    jg    .cms_fail              ; remaining > keys-left -> cannot satisfy -> fail
    jmp   .cms_loop
.cms_end:
    ; loop ended; success iff remaining==0 (all sigs matched)
    mov   eax, [rsp+0]
    test  eax, eax
    jne   .cms_fail
    ; ---- success ----
    mov   edx, 1
    jmp   .cms_finish
.cms_fail:
    mov   edx, 0
.cms_finish:
    ; pop total = need+1 = nkeys+nsigs+3 elements (locals nKeys/nSigs intact)
    mov   ecx, [rsp+24]
    add   ecx, [rsp+16]
    add   ecx, 3
    ; save bool (edx) across the pops.
    push  rdx                     ; stash bool
.pop_all:
    test  ecx, ecx
    jz    .pop_all_done
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    dec   ecx
    jmp   .pop_all
.pop_all_done:
    pop   rdx                     ; restore bool
    ; push the result bool
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_bool
    xor   eax, eax
    inc   eax                     ; return 1 (ok)
    add   rsp, 32
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

.err_stackop:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_exit
.err_nulldummy:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SIG_NULLDUMMY
    jmp   .err_exit
.err_pubcount:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_PUBKEY_COUNT
    jmp   .err_exit
.err_sigcount:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SIG_COUNT
.err_exit:
    xor   eax, eax
    add   rsp, 32
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

section .tbss alloc noexec nowrite tls align=16
global cms_keyrefs
global cms_sigrefs
cms_keyrefs: resq 20
cms_sigrefs: resq 20

