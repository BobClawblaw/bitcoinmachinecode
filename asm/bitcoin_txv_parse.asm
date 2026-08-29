; ============================================================================
; bitcoin_txv_parse.asm -- transaction parse layer of daemon/tx_verify.c,
; 100% AI-generated x86-64 assembly (NASM, ELF64). Phase 2 slice 1 of the
; C->asm conversion (2026-08-24).
;
; Ports txv_rd_cs + txv_parse with an EXPLICIT-STATE ABI: no file-scope
; statics here -- the caller passes the input array and the witness pool, so
; the asm and the C can be driven side by side over the same bytes
; (tests/test_txv_parse_diff.c). Pool GROWTH stays in C for this slice
; (txv_witpool_reserve, exported from tx_verify.c): allocation is phase 3's
; boundary, parsing is this one's.
;
;   long txv_parse_asm(const u8* tx, u64 txlen, txv_rawin_t* in,
;                      witpool_t* wp, u64* out_nin, const char** reason)
;     -> 1 parsed / 0 rejected (*reason = a .rodata string literal,
;        byte-identical to the C's -- the differential strcmp()s them)
;
; STRUCT ABI -- pinned by offsetof() on the C structs, not re-derived:
;   txv_rawin_t: outpoint@0 scriptSig@8 scriptSiglen@16 wit@24 witlen@32
;                nwit@40 wit_off@44 wprog@48 wproglen@56 wrapped@60 value@64
;                spk@72 spklen@10072 shape@10076, stride 10080
;   witpool_t:   ptr@0 len@8 cap@16 used@24
;
; FIDELITY NOTE: this is a bug-for-bug twin. In particular the C's
; scriptSig bound: FIXED 2026-08-24 (incident #36) to the split form
; `avail < sl || avail - sl < 4`, matching the C and bitcoin_segwit.c's
; swtx_parse. The old `(u64)(end-p) < sl+4` wrapped for sl within 4 of 2^64 (an
; 0xff varint can encode that), which the twin reproduces EXACTLY -- the
; differential must not diverge. Whether Core's MAX_SIZE-capped compactsize
; reader makes that a real consensus difference is filed for its own
; differential; fixing it silently here would hide it from that comparison.
;
; witpool_t's ptr/len arrays can be REALLOCATED by txv_witpool_reserve, so
; they are re-read from the struct after every reserve call and only
; resolved into txv_rawin_t.wit/witlen in the final pass, after the pool
; stops growing -- the same offset-not-pointer discipline the C documents.
; ============================================================================

BITS 64
DEFAULT REL

extern txv_witpool_reserve            ; u64 (witpool_t*, u64 n) -- C, tx_verify.c

%define TXV_MAX_INPUTS    20000
%define TXV_MAX_WIT_ITEMS 4000000

%define IN_OUTPOINT   0
%define IN_SCRIPTSIG  8
%define IN_SSLEN      16
%define IN_WIT        24
%define IN_WITLEN     32
%define IN_NWIT       40
%define IN_WITOFF     44
%define IN_STRIDE     10080

%define WP_PTR        0
%define WP_LEN        8
%define WP_CAP        16
%define WP_USED       24

section .rodata
r_short:    db "tx too short",0
r_nin:      db "bad n_in varint",0
r_bounds:   db "input count out of bounds",0
r_outpt:    db "truncated outpoint",0
r_ssv:      db "bad scriptSig varint",0
r_sstrunc:  db "truncated scriptSig/sequence",0
r_nout:     db "bad n_out varint",0
r_outtr:    db "truncated output",0
r_osv:      db "bad output script varint",0
r_ostrunc:  db "truncated output script",0
r_wcv:      db "bad witness item-count varint",0
r_witmany:  db "too many witness items",0
r_oom:      db "out of memory",0
r_wlv:      db "bad witness-item-len varint",0
r_wtrunc:   db "truncated witness item",0

section .text

; ----------------------------------------------------------------------------
; RDCS <fail_label>: inline compact-size read at rbx (end = r12) -> rax,
; rbx advanced; truncation jumps straight to the fail label. Was a SysV
; helper taking &cursor (2026-08-24 first rev): fully gate-clean but ~16%
; slower than gcc's inlined txv_rd_cs on witness-heavy transactions -- the
; per-varint spill/call/reload dominated exactly where varints are densest.
; A macro expands INLINE, so the cursor lives in rbx with no call and no
; custom convention for callee-saved-check to flag: the containing function
; saves rbx once in its own prologue. Clobbers rax, rcx.
; ----------------------------------------------------------------------------
%macro RDCS 1
    cmp  rbx, r12
    jae  %1
    movzx eax, byte [rbx]
    cmp  al, 0xfd
    jb   %%one
    je   %%two
    cmp  al, 0xfe
    je   %%four
    lea  rcx, [rbx+9]                    ; 0xff: 8-byte value
    cmp  rcx, r12
    ja   %1
    mov  rax, [rbx+1]
    mov  rbx, rcx
    jmp  %%done
%%four:
    lea  rcx, [rbx+5]
    cmp  rcx, r12
    ja   %1
    mov  eax, [rbx+1]
    mov  rbx, rcx
    jmp  %%done
%%two:
    lea  rcx, [rbx+3]
    cmp  rcx, r12
    ja   %1
    movzx eax, word [rbx+1]
    mov  rbx, rcx
    jmp  %%done
%%one:
    inc  rbx
%%done:
%endmacro

; ----------------------------------------------------------------------------
; txv_parse_asm(tx, txlen, in, wp, out_nin, reason) -> 1 / 0
;   rdi=tx rsi=txlen rdx=in rcx=wp r8=out_nin r9=reason
; Frame: push rbp + 5 pushes (saves at [rbp-0x08..-0x28]), sub rsp,0x58 ->
; rsp = rbp-0x80, 0 mod 16 at every call (rd_cs is called off-alignment-
; irrelevant -- it makes no calls -- but the txv_witpool_reserve call sites
; are at 0 mod 16). Locals, all strictly below the save area:
;   [rbp-0x30] out_nin   [rbp-0x38] reason    [rbp-0x40] tx base
;   [rbp-0x48] nin       [rbp-0x50] in base   [rbp-0x58] i (input loop)
;   [rbp-0x60] segwit    [rbp-0x68] nitems    [rbp-0x70] woff
;   [rbp-0x78] j (item loop)   ([rbp-0x80] spare; the former rd_cs cursor
;   slot -- varint reads are the inline RDCS macro now, cursor stays in rbx)
; Register roles: rbx = p (parse cursor, rd_cs contract), r12 = end,
; r13 = current input record, r14 = wp, r15 = loop bounds scratch.
; ----------------------------------------------------------------------------
global txv_parse_asm
txv_parse_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x58
    mov  [rbp-0x40], rdi                 ; tx
    mov  [rbp-0x50], rdx                 ; in base
    mov  r13, rdx                        ; current record cursor
    mov  r14, rcx                        ; wp
    mov  [rbp-0x30], r8                  ; out_nin
    mov  [rbp-0x38], r9                  ; reason
    lea  r12, [rdi+rsi]                  ; end
    mov  rbx, rdi                        ; p

    cmp  rsi, 10                         ; if (txlen < 10) "tx too short"
    jb   .r_short
    mov  qword [r14+WP_USED], 0          ; wp->used = 0 (bump reset)

    add  rbx, 4                          ; skip version
    ; segwit = (p+2 <= end && p[0]==0x00 && p[1]==0x01)
    xor  eax, eax
    lea  rcx, [rbx+2]
    cmp  rcx, r12
    ja   .seg_done
    cmp  byte [rbx], 0x00
    jne  .seg_done
    cmp  byte [rbx+1], 0x01
    jne  .seg_done
    mov  eax, 1
    add  rbx, 2
.seg_done:
    mov  [rbp-0x60], rax                 ; segwit flag

    RDCS .r_nin                           ; nin
    test rax, rax                        ; nin == 0 -> bounds
    jz   .r_bounds
    cmp  rax, TXV_MAX_INPUTS
    ja   .r_bounds
    mov  [rbp-0x48], rax                 ; nin

    ; ---- input loop ----
    xor  ecx, ecx
    mov  [rbp-0x58], rcx                 ; i = 0
.in_loop:
    mov  rax, [rbp-0x58]
    cmp  rax, [rbp-0x48]
    jae  .in_done
    lea  rcx, [rbx+36]
    cmp  rcx, r12
    ja   .r_outpt
    mov  [r13+IN_OUTPOINT], rbx
    add  rbx, 36
    RDCS .r_ssv                           ; sl
    mov  r15, rax                        ; sl
    mov  rax, r12
    sub  rax, rbx                        ; avail = end - p
    cmp  rax, r15                        ; avail < sl ? (catches sl near 2^64
    jb   .r_sstrunc                      ;   without the sl+4 wrap -- incident #36)
    sub  rax, r15                        ; avail - sl (>= 0 here)
    cmp  rax, 4
    jb   .r_sstrunc
    mov  [r13+IN_SCRIPTSIG], rbx
    mov  [r13+IN_SSLEN], r15d            ; (u32)sl, the C's truncation
    lea  rbx, [rbx+r15+4]                ; p += sl + 4
    mov  dword [r13+IN_NWIT], 0
    add  r13, IN_STRIDE
    inc  qword [rbp-0x58]
    jmp  .in_loop
.in_done:

    RDCS .r_nout                           ; nout
    mov  r15, rax
.out_loop:
    test r15, r15
    jz   .out_done
    lea  rcx, [rbx+8]
    cmp  rcx, r12
    ja   .r_outtr
    add  rbx, 8
    RDCS .r_osv                           ; output script len
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, rax                        ; (end-p) < sl ?
    jb   .r_ostrunc
    add  rbx, rax
    dec  r15
    jmp  .out_loop
.out_done:

    cmp  qword [rbp-0x60], 0             ; segwit?
    je   .resolve
    mov  r13, [rbp-0x50]                 ; record cursor back to in[0]
    xor  ecx, ecx
    mov  [rbp-0x58], rcx                 ; i = 0
.wit_loop:
    mov  rax, [rbp-0x58]
    cmp  rax, [rbp-0x48]
    jae  .resolve
    RDCS .r_wcv                           ; nitems
    cmp  rax, TXV_MAX_WIT_ITEMS
    ja   .r_witmany
    mov  [rbp-0x68], rax                 ; nitems
    mov  [r13+IN_NWIT], eax              ; (u32)nitems
    mov  rdi, r14
    mov  rsi, rax
    call txv_witpool_reserve             ; may realloc wp->ptr / wp->len
    cmp  rax, -1                         ; ~0ull -> OOM
    je   .r_oom
    mov  [rbp-0x70], rax                 ; woff
    mov  [r13+IN_WITOFF], eax            ; (u32)woff
    xor  ecx, ecx
    mov  [rbp-0x78], rcx                 ; j = 0
.item_loop:
    mov  rax, [rbp-0x78]
    cmp  rax, [rbp-0x68]
    jae  .items_done
    RDCS .r_wlv                           ; il
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, rax                        ; (end-p) < il ?
    jb   .r_wtrunc
    ; wp->ptr[woff+j] = p ; wp->len[woff+j] = (u32)il
    ; (re-read the array bases from the struct: reserve may have moved them)
    mov  rcx, [rbp-0x70]
    add  rcx, [rbp-0x78]                 ; woff + j
    mov  rdx, [r14+WP_PTR]
    mov  [rdx+rcx*8], rbx
    mov  rdx, [r14+WP_LEN]
    mov  [rdx+rcx*4], eax
    add  rbx, rax                        ; p += il
    inc  qword [rbp-0x78]
    jmp  .item_loop
.items_done:
    add  r13, IN_STRIDE
    inc  qword [rbp-0x58]
    jmp  .wit_loop

.resolve:
    ; wit/witlen from wit_off, now the pool is done growing for this tx
    mov  r13, [rbp-0x50]
    mov  rcx, [rbp-0x48]                 ; nin countdown
.res_loop:
    test rcx, rcx
    jz   .ok
    mov  eax, [r13+IN_NWIT]
    test eax, eax
    jz   .res_zero
    mov  eax, [r13+IN_WITOFF]
    mov  rdx, [r14+WP_PTR]
    lea  rdx, [rdx+rax*8]
    mov  [r13+IN_WIT], rdx
    mov  rdx, [r14+WP_LEN]
    lea  rdx, [rdx+rax*4]
    mov  [r13+IN_WITLEN], rdx
    jmp  .res_next
.res_zero:
    mov  qword [r13+IN_WIT], 0
    mov  qword [r13+IN_WITLEN], 0
.res_next:
    add  r13, IN_STRIDE
    dec  rcx
    jmp  .res_loop

.ok:
    mov  rax, [rbp-0x48]
    mov  rcx, [rbp-0x30]
    mov  [rcx], rax                      ; *out_nin = nin
    mov  eax, 1
    jmp  .out

; ---- rejection tail: rsi = reason string, returns 0 ----
.r_short:   lea rsi, [r_short]
            jmp .reject
.r_nin:     lea rsi, [r_nin]
            jmp .reject
.r_bounds:  lea rsi, [r_bounds]
            jmp .reject
.r_outpt:   lea rsi, [r_outpt]
            jmp .reject
.r_ssv:     lea rsi, [r_ssv]
            jmp .reject
.r_sstrunc: lea rsi, [r_sstrunc]
            jmp .reject
.r_nout:    lea rsi, [r_nout]
            jmp .reject
.r_outtr:   lea rsi, [r_outtr]
            jmp .reject
.r_osv:     lea rsi, [r_osv]
            jmp .reject
.r_ostrunc: lea rsi, [r_ostrunc]
            jmp .reject
.r_wcv:     lea rsi, [r_wcv]
            jmp .reject
.r_witmany: lea rsi, [r_witmany]
            jmp .reject
.r_oom:     lea rsi, [r_oom]
            jmp .reject
.r_wlv:     lea rsi, [r_wlv]
            jmp .reject
.r_wtrunc:  lea rsi, [r_wtrunc]
.reject:
    mov  rcx, [rbp-0x38]
    mov  [rcx], rsi                      ; *reason = string
    xor  eax, eax
.out:
    add  rsp, 0x58
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; txvb_parse_tx_asm -- the BLOCK path's per-tx parser (phase 2 slice 4,
; 2026-08-24): twin of tx_verify.c's txvb_parse_tx, which is what the live
; daemon actually runs (txv_parse above serves the single-tx path, test-only
; since the connect-all rewrite). Same wire walk as txv_parse_asm; differs
; exactly as the C does:
;   - fills caller-supplied 144-byte txvb_in_t entries at flat[base..):
;       tx_index@0 local_idx@8 tx_ptr@16 tx_len@24 outpoint@32 scriptSig@40
;       scriptSiglen@48 nwit@72 wit_off@76 tap_desc@128 (poisoned ~0 --
;       a stale descriptor index from the previous block's flat array would
;       hand a worker the wrong tx's aggregate sighash, silently);
;   - nin bound is the caller's sizing cap (base+nin > cap), not
;     TXV_MAX_INPUTS;
;   - does NOT reset wp->used and does NOT resolve wit/witlen -- the block
;     driver owns both, before/after all txs.
;
;   long txvb_parse_tx_asm(tx, txlen, tx_index, flat, base, cap,
;                          /*stack*/ u64* out_nin, const char** reason,
;                          witpool_t* wp) -> 1 / 0
;
; Frame: push rbp + 5 pushes, sub rsp,0x58 -> rsp = rbp-0x80, 0 mod 16 at
; the txv_witpool_reserve call. Locals below the save area:
;   [rbp-0x30] tx    [rbp-0x38] txlen  [rbp-0x40] tx_index
;   [rbp-0x48] nin   [rbp-0x50] flat+base*144 (entry 0)
;   [rbp-0x58] i     [rbp-0x60] segwit [rbp-0x68] nitems
;   [rbp-0x70] woff  [rbp-0x78] j
; Registers: rbx = p (RDCS contract), r12 = end, r13 = entry cursor,
; r14 = wp, r15 = scratch.
; ----------------------------------------------------------------------------
%define BIN_TXIDX     0
%define BIN_LOCAL     8
%define BIN_TXPTR     16
%define BIN_TXLEN     24
%define BIN_OUTPOINT  32
%define BIN_SCRIPTSIG 40
%define BIN_SSLEN     48
%define BIN_NWIT      72
%define BIN_WITOFF    76
%define BIN_TAPDESC   128
%define BIN_STRIDE    144

section .rodata
r_sizing:   db "block input count exceeds sizing pass",0

section .text

global txvb_parse_tx_asm
txvb_parse_tx_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x58
    mov  [rbp-0x30], rdi                 ; tx
    mov  [rbp-0x38], rsi                 ; txlen
    mov  [rbp-0x40], rdx                 ; tx_index
    mov  r14, [rbp+32]                   ; wp
    ; entry 0 = flat + base*144  (144 = 16*9)
    mov  rax, r8
    imul rax, rax, BIN_STRIDE
    add  rax, rcx
    mov  [rbp-0x50], rax
    mov  r13, rax
    lea  r12, [rdi+rsi]                  ; end
    mov  rbx, rdi                        ; p
    mov  r15, r9                         ; cap (r8 = base survives to the check)

    cmp  rsi, 10
    jb   .b_short
    add  rbx, 4                          ; version
    xor  eax, eax
    lea  rcx, [rbx+2]
    cmp  rcx, r12
    ja   .b_segdone
    cmp  byte [rbx], 0x00
    jne  .b_segdone
    cmp  byte [rbx+1], 0x01
    jne  .b_segdone
    mov  eax, 1
    add  rbx, 2
.b_segdone:
    mov  [rbp-0x60], rax                 ; segwit

    RDCS .b_nin                          ; nin
    test rax, rax
    jz   .b_bounds                       ; nin == 0
    mov  [rbp-0x48], rax                 ; nin (saved BEFORE the sum below)
    add  rax, r8                         ; base + nin
    cmp  rax, r15                        ; > cap ?
    ja   .b_sizing

    ; ---- input loop ----
    xor  ecx, ecx
    mov  [rbp-0x58], rcx                 ; i = 0
.b_in_loop:
    mov  rax, [rbp-0x58]
    cmp  rax, [rbp-0x48]
    jae  .b_in_done
    ; entry header
    mov  rdx, [rbp-0x40]
    mov  [r13+BIN_TXIDX], rdx            ; tx_index
    mov  [r13+BIN_LOCAL], eax            ; local_idx = (u32)i
    mov  rdx, [rbp-0x30]
    mov  [r13+BIN_TXPTR], rdx
    mov  rdx, [rbp-0x38]
    mov  [r13+BIN_TXLEN], rdx
    mov  rax, -1
    mov  [r13+BIN_TAPDESC], rax          ; poison tap_desc (see header)
    lea  rcx, [rbx+36]
    cmp  rcx, r12
    ja   .b_outpt
    mov  [r13+BIN_OUTPOINT], rbx
    add  rbx, 36
    RDCS .b_ssv                          ; sl
    mov  r15, rax
    mov  rax, r12
    sub  rax, rbx                        ; avail = end - p
    cmp  rax, r15                        ; avail < sl ? (catches sl near 2^64
    jb   .b_sstrunc                   ;   without the sl+4 wrap -- incident #36)
    sub  rax, r15                        ; avail - sl (>= 0 here)
    cmp  rax, 4
    jb   .b_sstrunc
    mov  [r13+BIN_SCRIPTSIG], rbx
    mov  [r13+BIN_SSLEN], r15d
    lea  rbx, [rbx+r15+4]
    mov  dword [r13+BIN_NWIT], 0
    add  r13, BIN_STRIDE
    inc  qword [rbp-0x58]
    jmp  .b_in_loop
.b_in_done:

    RDCS .b_nout                         ; nout
    mov  r15, rax
.b_out_loop:
    test r15, r15
    jz   .b_out_done
    lea  rcx, [rbx+8]
    cmp  rcx, r12
    ja   .b_outtr
    add  rbx, 8
    RDCS .b_osv                          ; output script len
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, rax
    jb   .b_ostrunc
    add  rbx, rax
    dec  r15
    jmp  .b_out_loop
.b_out_done:

    cmp  qword [rbp-0x60], 0             ; segwit?
    je   .b_ok
    mov  r13, [rbp-0x50]                 ; entry cursor back to entry 0
    xor  ecx, ecx
    mov  [rbp-0x58], rcx                 ; i = 0
.b_wit_loop:
    mov  rax, [rbp-0x58]
    cmp  rax, [rbp-0x48]
    jae  .b_ok
    RDCS .b_wcv                          ; nitems
    cmp  rax, TXV_MAX_WIT_ITEMS
    ja   .b_witmany
    mov  [rbp-0x68], rax
    mov  [r13+BIN_NWIT], eax
    mov  rdi, r14
    mov  rsi, rax
    call txv_witpool_reserve
    cmp  rax, -1
    je   .b_oom
    mov  [rbp-0x70], rax                 ; woff
    mov  [r13+BIN_WITOFF], eax
    xor  ecx, ecx
    mov  [rbp-0x78], rcx                 ; j = 0
.b_item_loop:
    mov  rax, [rbp-0x78]
    cmp  rax, [rbp-0x68]
    jae  .b_items_done
    RDCS .b_wlv                          ; il
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, rax
    jb   .b_wtrunc
    mov  rcx, [rbp-0x70]
    add  rcx, [rbp-0x78]
    mov  rdx, [r14+WP_PTR]               ; re-read: reserve may have moved it
    mov  [rdx+rcx*8], rbx
    mov  rdx, [r14+WP_LEN]
    mov  [rdx+rcx*4], eax
    add  rbx, rax
    inc  qword [rbp-0x78]
    jmp  .b_item_loop
.b_items_done:
    add  r13, BIN_STRIDE
    inc  qword [rbp-0x58]
    jmp  .b_wit_loop

.b_ok:
    mov  rax, [rbp-0x48]
    mov  rcx, [rbp+16]
    mov  [rcx], rax                      ; *out_nin = nin
    mov  eax, 1
    jmp  .b_out

.b_short:   lea rsi, [r_short]
            jmp .b_reject
.b_nin:     lea rsi, [r_nin]
            jmp .b_reject
.b_bounds:  lea rsi, [r_bounds]
            jmp .b_reject
.b_sizing:  lea rsi, [r_sizing]
            jmp .b_reject
.b_outpt:   lea rsi, [r_outpt]
            jmp .b_reject
.b_ssv:     lea rsi, [r_ssv]
            jmp .b_reject
.b_sstrunc: lea rsi, [r_sstrunc]
            jmp .b_reject
.b_nout:    lea rsi, [r_nout]
            jmp .b_reject
.b_outtr:   lea rsi, [r_outtr]
            jmp .b_reject
.b_osv:     lea rsi, [r_osv]
            jmp .b_reject
.b_ostrunc: lea rsi, [r_ostrunc]
            jmp .b_reject
.b_wcv:     lea rsi, [r_wcv]
            jmp .b_reject
.b_witmany: lea rsi, [r_witmany]
            jmp .b_reject
.b_oom:     lea rsi, [r_oom]
            jmp .b_reject
.b_wlv:     lea rsi, [r_wlv]
            jmp .b_reject
.b_wtrunc:  lea rsi, [r_wtrunc]
.b_reject:
    mov  rcx, [rbp+24]
    mov  [rcx], rsi                      ; *reason = string
    xor  eax, eax
.b_out:
    add  rsp, 0x58
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; SECURITY (audit 2026-08-29 finding 9): without this note the linker
; conservatively marks the whole program's stack EXECUTABLE (PT_GNU_STACK
; RWE). Nothing here needs a runnable stack; a single object missing the
; note is enough to turn it on for the entire binary, which is why every
; .asm file carries it.
section .note.GNU-stack noalloc noexec nowrite progbits
