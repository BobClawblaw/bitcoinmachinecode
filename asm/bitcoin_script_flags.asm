; ============================================================================
; bitcoin_script_flags.asm -- Stage C of PLAN_SCRIPT_VERIFY.md: the
; activation-height flag schedule VerifyScript needs per block.
;
;   uint64_t script_flags_for_block(uint64_t height, const uint8_t hash32[32])
;
; Mirrors Core's GetBlockScriptFlags (src/validation.cpp) EXACTLY, including
; a detail easy to get wrong from memory (and gotten wrong once already this
; project, per PLAN_SCRIPT_VERIFY.md -- see the ScriptError-numbering note):
; P2SH/WITNESS/TAPROOT are NOT height-gated at all in current Core. They are
; unconditionally active from height 0, with exactly TWO historical blocks
; (identified by HASH, not height) where Core overrides the flags down to
; something weaker -- one pre-BIP16 block whose scriptSig happened to look
; P2SH-shaped, one pre-Taproot block with the analogous Taproot issue. DERSIG
; (BIP66) / CLTV (BIP65) / CSV (BIP112) / NULLDUMMY (BIP147, activates
; simultaneously with segwit) ARE height-gated: active at height >= a fixed
; threshold (Core's DeploymentActiveAt: index.nHeight >= DeploymentHeight).
;
; hash32 must be in this codebase's own internal byte order (block_hash's
; raw output, NOT Core's display/RPC hex order) -- verified empirically
; against the real mainnet genesis hash before this file was written; see
; the two SFC_EXC_*_HASH constants below, which are the reverse of Core's
; own display-hex strings for exactly that reason.
;
; All constants (bit positions, heights, exception hashes) are GENERATED
; from Core's own source by validation/gen_script_flags.py -- never
; hand-transcribed. Re-run it after a Core upgrade.
; ============================================================================
    default rel
    global script_flags_for_block
    global sfc_chain

%include "script_flags_consts.inc"

; ----------------------------------------------------------------------------
; sfc_chain -- runtime chain selector: 0 = mainnet (the static default, so
; every caller that never selects a chain gets exactly the old behaviour),
; 1 = regtest, 2 = testnet4. Written once by chainparams_select()
; (daemon/chainparams.c)
; before any block is verified, never again -- the unsynchronized read below
; is safe. Regtest's buried heights come from the same generator run
; (SFC_R_HEIGHT_*, CRegTestParams); the two mainnet exception hashes cannot
; occur on a regtest chain (different genesis), so the exception compares are
; skipped entirely there.
; ----------------------------------------------------------------------------
section .data
sfc_chain: dd 0

section .text

; ----------------------------------------------------------------------------
; script_flags_for_block(rdi=height, rsi=hash32) -> rax=flags
; Leaf function; only rbx is callee-saved and used to hold height across the
; two 32-byte hash comparisons.
; ----------------------------------------------------------------------------
script_flags_for_block:
    push  rbx
    mov   rbx, rdi                 ; height (survives the hash compares)

    cmp   dword [sfc_chain], 0
    je    .mainnet
    cmp   dword [sfc_chain], 2
    je    .testnet4
    jmp   .regtest
.mainnet:

    ; ---- exception 1: BIP16 ----
    lea   rax, [rel SFC_EXC_BIP16_HASH]
    mov   rcx, [rsi+0]
    cmp   rcx, [rax+0]
    jne   .not_exc1
    mov   rcx, [rsi+8]
    cmp   rcx, [rax+8]
    jne   .not_exc1
    mov   rcx, [rsi+16]
    cmp   rcx, [rax+16]
    jne   .not_exc1
    mov   rcx, [rsi+24]
    cmp   rcx, [rax+24]
    jne   .not_exc1
    mov   rax, SFC_EXC_BIP16_FLAGS
    jmp   .base_done
.not_exc1:
    ; ---- exception 2: Taproot ----
    lea   rax, [rel SFC_EXC_TAPROOT_HASH]
    mov   rcx, [rsi+0]
    cmp   rcx, [rax+0]
    jne   .not_exc2
    mov   rcx, [rsi+8]
    cmp   rcx, [rax+8]
    jne   .not_exc2
    mov   rcx, [rsi+16]
    cmp   rcx, [rax+16]
    jne   .not_exc2
    mov   rcx, [rsi+24]
    cmp   rcx, [rax+24]
    jne   .not_exc2
    mov   rax, SFC_EXC_TAPROOT_FLAGS
    jmp   .base_done
.not_exc2:
    mov   rax, (1<<SFC_BIT_P2SH) | (1<<SFC_BIT_WITNESS) | (1<<SFC_BIT_TAPROOT)
.base_done:
    ; ---- buried height deployments ----
    cmp   rbx, SFC_HEIGHT_DERSIG
    jb    .skip_dersig
    or    rax, (1<<SFC_BIT_DERSIG)
.skip_dersig:
    cmp   rbx, SFC_HEIGHT_CLTV
    jb    .skip_cltv
    or    rax, (1<<SFC_BIT_CLTV)
.skip_cltv:
    cmp   rbx, SFC_HEIGHT_CSV
    jb    .skip_csv
    or    rax, (1<<SFC_BIT_CSV)
.skip_csv:
    cmp   rbx, SFC_HEIGHT_SEGWIT
    jb    .skip_segwit
    or    rax, (1<<SFC_BIT_NULLDUMMY)
.skip_segwit:
    pop   rbx
    ret

; ---- regtest: same base flags, no exceptions, CRegTestParams heights ----
.regtest:
    mov   rax, (1<<SFC_BIT_P2SH) | (1<<SFC_BIT_WITNESS) | (1<<SFC_BIT_TAPROOT)
    cmp   rbx, SFC_R_HEIGHT_DERSIG
    jb    .r_skip_dersig
    or    rax, (1<<SFC_BIT_DERSIG)
.r_skip_dersig:
    cmp   rbx, SFC_R_HEIGHT_CLTV
    jb    .r_skip_cltv
    or    rax, (1<<SFC_BIT_CLTV)
.r_skip_cltv:
    cmp   rbx, SFC_R_HEIGHT_CSV
    jb    .r_skip_csv
    or    rax, (1<<SFC_BIT_CSV)
.r_skip_csv:
    cmp   rbx, SFC_R_HEIGHT_SEGWIT
    jb    .r_skip_segwit
    or    rax, (1<<SFC_BIT_NULLDUMMY)
.r_skip_segwit:
    pop   rbx
    ret

; ---- testnet4: same base flags, no exceptions, CTestNet4Params heights ----
.testnet4:
    mov   rax, (1<<SFC_BIT_P2SH) | (1<<SFC_BIT_WITNESS) | (1<<SFC_BIT_TAPROOT)
    cmp   rbx, SFC_T_HEIGHT_DERSIG
    jb    .t_skip_dersig
    or    rax, (1<<SFC_BIT_DERSIG)
.t_skip_dersig:
    cmp   rbx, SFC_T_HEIGHT_CLTV
    jb    .t_skip_cltv
    or    rax, (1<<SFC_BIT_CLTV)
.t_skip_cltv:
    cmp   rbx, SFC_T_HEIGHT_CSV
    jb    .t_skip_csv
    or    rax, (1<<SFC_BIT_CSV)
.t_skip_csv:
    cmp   rbx, SFC_T_HEIGHT_SEGWIT
    jb    .t_skip_segwit
    or    rax, (1<<SFC_BIT_NULLDUMMY)
.t_skip_segwit:
    pop   rbx
    ret
