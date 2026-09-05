; ============================================================================
; bitcoin_chainwork.asm -- Stage A reorg/fork-choice primitive #1: chainwork
;   tracking. 100% AI-authored x86-64 assembly, System V AMD64 ABI.
;
;   STAGE B: this is no longer standalone. daemon/reorg.c now keeps
;   chainwork.dat in lockstep with index.dat (reorg_chainwork_sync) and uses
;   chainwork_cmp as the fork-choice predicate. tests/test_chainwork.c still
;   covers the primitives in isolation; tests/test_reorg.c covers them wired
;   into the real store.
;
;   Per-header "work" (the standard formula: work = 2^256 / (target+1),
;   computed via Bitcoin Core's GetBlockProof identity
;     work = floor((2^256-1-target) / (target+1)) + 1
;   which sidesteps representing the otherwise-unrepresentable 2^256 dividend
;   directly -- (2^256-1-target) is exactly bitwise-NOT(target) and always
;   fits in 256 bits) is computed exactly via a general 256-bit/256-bit
;   unsigned integer division (u256_div, below).
;
;   CHAINWORK PRECISION: the *accumulated* running total is kept as a plain
;   128-bit (two u64 limbs, low:high) unsigned integer with a simple
;   add/adc chain -- the simplification this stage's spec explicitly invites
;   ("simplicity favored over cleverness"). 128 bits is enormous headroom:
;   real Bitcoin mainnet's per-block work has stayed under 2^90 throughout
;   its entire history (see tests/test_chainwork.c's hand-checked vectors),
;   and the cumulative total across the whole chain is nowhere near 2^128.
;   A per-header work value is computed via the EXACT 256-bit division above
;   (not a truncated/approximate one) and then only its low 128 bits are
;   kept -- for any realistic Bitcoin nBits this is exact, not an
;   approximation, because the true work value never approaches 2^128.
;
;   Exports:
;     void u256_div(u8 q_out[32], const u8 a[32], const u8 b[32])
;         q_out = floor(a / b), unsigned 256-bit little-endian 4-limb ints.
;         b must be nonzero (guaranteed by block_work's caller-side check).
;     void block_work(u8 work[16], u32 bits)
;         work = 2^256/(target(bits)+1), truncated to its low 128 bits (LE).
;         target==0 (degenerate/invalid nBits, mirrors Core's GetBlockProof)
;         -> work=0.
;     void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16])
;         out = a+b, 128-bit unsigned add/adc (any overflow past bit 127 is
;         silently dropped -- unreachable for real chainwork totals).
;
;   Persistence. Chainwork's own per-process state -- the cached cumulative
;   work of the tip and the open descriptor for chainwork.dat -- lives in
;   THIS MODULE'S OWN storage (cw_cum / cw_fd, at the bottom of this file).
;   It is deliberately NOT stored inside the caller's store struct.
;
;   *** WHY: THE STORE STRUCT IS NOT SAFE TO EXTEND. READ BEFORE CHANGING. ***
;   Stage A put these fields at store_buf+56/+72. Stage B first moved them to
;   +128/+144. BOTH were wrong, and each was found only after the fact:
;     +0  ..+52   bitcoin_store.asm's own fields (core store state)
;     +56         bitcoin_store_fast.asm read-fd cache magic ("RDFC")
;     +64 ..+127  bitcoin_store_fast.asm read-fd cache, 8 x 8-byte slots
;     +120        bitcoin_store_fast.asm MAPPING cache magic  (overlaps +64.. )
;     +128..+255  bitcoin_store_fast.asm mapping cache, 4 x 32-byte slots
;   i.e. essentially the WHOLE +56..+255 range of a 256-byte store struct is
;   already claimed by two other caches, and the struct's documented minimum
;   size is 256 bytes -- there is no free hole left to move into. The read-fd
;   cache is live today (daemon/utxo_live.c calls store_read_at on the very
;   same store_buf); the mapping cache is defined but not yet wired to any
;   caller, so the second collision was a dormant landmine rather than an
;   active corruption -- it would have fired silently the moment anyone
;   enabled that optimisation.
;
;   Rather than hunt for a third number that merely happens to be free today,
;   chainwork now owns its state outright, the same way daemon/utxo_live.c
;   owns g_utxo_lst as a module global instead of embedding it in store_buf.
;   That removes this bug class entirely: the store struct can grow however it
;   likes and chainwork cannot be affected.
;
;   Every function below still TAKES `st` as its first argument, purely to
;   keep one calling convention across the Stage A/B primitives (and so call
;   sites read consistently) -- but `st` is now IGNORED by all of them and
;   not one byte is read from or written to it. This is honest rather than
;   lossy: chainwork.dat is opened by a FIXED name in the process's current
;   directory, so these functions were never actually per-store-struct in the
;   first place -- two structs in one process always shared one file.
;
;   Uninitialised state is a hard error, not a silent zero: cw_fd starts at -1
;   and every persistence entry point below returns -1 if store_chainwork_init
;   has not run. (store_chainwork_get_tip keeps its "always returns 1"
;   contract and yields zero work, which is the documented empty-chain value;
;   daemon/reorg.c additionally refuses to make any fork-choice decision until
;   its own open flag is set, so a zero cache can never be mistaken for a
;   real comparison.)
;
;   chainwork.dat holds one 16-byte little-endian cumulative-chainwork
;   record per stored height (positional, mirroring index.dat's own
;   height-indexed layout: record for height h at byte offset h*16).
;
;     int  store_chainwork_init(void* st)  -> 1 ok / -1
;         Opens/creates chainwork.dat, zeroes the +128 cache. Mirrors
;         store_init's shape; call once after store_init. NOTE: on an
;         EXISTING chainwork.dat this leaves the cache at zero, which would
;         make our own tip look weightless to fork choice -- always follow
;         it with store_chainwork_reload (below).
;     int  store_chainwork_append(void* st, long height, const u8 work[16])
;         -> 1 ok / -1 err
;         cumulative(height) = cumulative(height-1) [0 if height==0] + work;
;         written to chainwork.dat at height*16 and cached at st+128.
;     int  store_chainwork_get_at(void* st, long height, u8 out[16])
;         -> 1 ok / -1 (no such record)
;     int  store_chainwork_get_tip(void* st, u8 out[16]) -> 1 (always;
;         copies the st+128 cache verbatim -- 0 for a fresh/never-appended
;         store, matching an empty chain's zero cumulative work).
;
;   STAGE B ADDITIONS (fork choice + reorg rollback need these three):
;     long chainwork_cmp(const u8 a[16], const u8 b[16]) -> -1 / 0 / 1
;         Unsigned 128-bit compare (high limb first). THE fork-choice
;         predicate: "is the candidate chain heavier than ours".
;     long store_chainwork_reload(void* st) -> record count (>=0) / -1 err
;         Re-derives the st+128 cumulative-work cache from chainwork.dat's
;         CURRENT last record (0 when the file is empty). store_chainwork_init
;         zeroes that cache unconditionally, so a process that opens an
;         EXISTING chainwork.dat would otherwise believe our tip has zero
;         work and treat every candidate chain as heavier -- exactly the
;         wrong default for a destructive operation. Also used to re-sync
;         the cache after store_chainwork_truncate.
;     long store_chainwork_truncate(void* st, long target_height) -> 1 / -1
;         Rollback mirror of store_chainwork_append, and the chainwork.dat
;         counterpart of bitcoin_store.asm's store_truncate_to: drops every
;         record above target_height (ftruncate to (target_height+1)*16) and
;         refreshes the st+128 cache via store_chainwork_reload.
;         target_height==-1 empties the file. A target at/above the current
;         last record is a no-op success (ftruncate to a length >= the
;         current one would EXTEND the file with zero records, which would
;         silently manufacture bogus "zero cumulative work" heights -- so
;         that case returns early instead of calling ftruncate at all).
; ============================================================================

default rel
section .text

; ============================================================================
; compact_to_target_le(out_le[32], bits32)  -- INTERNAL (not exported).
;   out = mantissa * 256^(exponent-3), written as a 256-bit LITTLE-ENDIAN
;   4-limb integer (out[0..7] = the low 64 bits, ... out[24..31] = the high
;   64 bits). Same compact-format formula as bitcoin_hash.asm's diff_target
;   (mirrors it deliberately for identical semantics on the mantissa's
;   high-bit / "negative" edge case: we do NOT special-case it either, same
;   as diff_target's own documented behaviour), but self-contained here (no
;   cross-file dependency, no big-endian intermediate/reversal) and
;   additionally bounds-checks the mantissa's byte offset against the
;   32-byte buffer so an extreme exponent clamps to target=0 instead of
;   writing out of bounds (diff_target does not bounds-check that side;
;   real Bitcoin nBits exponents never approach it either way).
;   In: rdi=out_le, esi=bits. Clobbers rax,rcx,rdx,r8.
; ============================================================================
compact_to_target_le:
    xor  eax, eax
    mov  [rdi+0], rax
    mov  [rdi+8], rax
    mov  [rdi+16], rax
    mov  [rdi+24], rax
    mov  eax, esi
    mov  edx, esi
    shr  eax, 24              ; exponent
    and  edx, 0x00ffffff       ; mantissa
    cmp  eax, 3
    jl   .done                  ; exponent<3 -> target=0 (matches diff_target's scope)
    mov  ecx, eax
    sub  ecx, 3                  ; byte offset of the mantissa's LSB in out[]
    cmp  ecx, 29
    jg   .done                    ; would need a 3rd mantissa byte past out[31]
    mov  byte [rdi+rcx], dl
    cmp  ecx, 31
    jae  .done
    mov  r8d, edx
    shr  r8d, 8
    mov  byte [rdi+rcx+1], r8b
    cmp  ecx, 30
    jae  .done
    mov  r8d, edx
    shr  r8d, 16
    mov  byte [rdi+rcx+2], r8b
.done:
    ret

; ============================================================================
; u256_div(q_out[32], a[32], b[32]) -> q_out = floor(a/b)
;   Unsigned 256-bit / 256-bit division, both operands and the result are
;   little-endian 4x-u64-limb integers. b MUST be nonzero.
;
;   Standard bit-serial (MSB-first) restoring division: 256 iterations, one
;   dividend bit consumed per step. Not performance-critical (called at most
;   once per header) -- clarity over speed, matching this stage's stated
;   "simplicity favored over cleverness" preference. All working state lives
;   in stack memory rather than registers.
;
;   Per-iteration invariant: remainder r < divisor b BEFORE the step. After
;   shifting r left by 1 and mixing in the next dividend bit, r' = 2r+bit <
;   2b, so r' can need one bit more than b's own 256 -- that extra bit is
;   tracked via the carry flag through an rcl chain (COUT below) rather than
;   a 5th limb. Whenever COUT=1, r (the low 256 bits alone) is PROVABLY < b
;   (otherwise r'=2^256+r would be >= 2b, contradicting r'<2b) -- so the
;   plain 4-limb "r - b" (mod 2^256, via sub/sbb) always equals the true
;   r'-b in that case too, with no separate 257-bit subtract required. This
;   makes "always speculatively subtract, then decide whether to keep it by
;   COUT-OR-no-borrow" branch-free and correct in both cases.
;
;   Makes no subroutine calls -> free to use every caller-saved scratch reg;
;   only rdi (q_out) is kept live across the whole function.
; ============================================================================
global u256_div
u256_div:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0xC0
    ; ---- copy a[32] (rsi) -> A block @ rbp-0x20 ; b[32] (rdx) -> B @ rbp-0x40 ----
    mov  rax, [rsi+0]
    mov  [rbp-0x20], rax
    mov  rax, [rsi+8]
    mov  [rbp-0x18], rax
    mov  rax, [rsi+16]
    mov  [rbp-0x10], rax
    mov  rax, [rsi+24]
    mov  [rbp-0x08], rax
    mov  rax, [rdx+0]
    mov  [rbp-0x40], rax
    mov  rax, [rdx+8]
    mov  [rbp-0x38], rax
    mov  rax, [rdx+16]
    mov  [rbp-0x30], rax
    mov  rax, [rdx+24]
    mov  [rbp-0x28], rax
    ; ---- zero Q @ rbp-0x60, R @ rbp-0x80 ----
    xor  eax, eax
    mov  [rbp-0x60], rax
    mov  [rbp-0x58], rax
    mov  [rbp-0x50], rax
    mov  [rbp-0x48], rax
    mov  [rbp-0x80], rax
    mov  [rbp-0x78], rax
    mov  [rbp-0x70], rax
    mov  [rbp-0x68], rax
    ; i = 255 (loop index, authoritative copy kept in memory @ rbp-0xA8)
    mov  qword [rbp-0xA8], 255
.loop:
    ; ---- extract dividend bit i: bit = (A[i>>6] >> (i&63)) & 1 ----
    mov  rcx, [rbp-0xA8]
    mov  rax, rcx
    shr  rax, 6                 ; limb index 0..3
    mov  r8, rcx
    and  r8, 63                  ; bit position within limb
    mov  r9, [rbp+rax*8-0x20]      ; A[limb]
    mov  rcx, r8
    shr  r9, cl
    and  r9, 1                     ; r9 = bit (0/1)

    ; ---- shift R left 1 (4 limbs), capture the 257th "overflow" bit COUT ----
    clc
    mov  rax, [rbp-0x80]
    rcl  rax, 1
    mov  [rbp-0x80], rax
    mov  rax, [rbp-0x78]
    rcl  rax, 1
    mov  [rbp-0x78], rax
    mov  rax, [rbp-0x70]
    rcl  rax, 1
    mov  [rbp-0x70], rax
    mov  rax, [rbp-0x68]
    rcl  rax, 1
    mov  [rbp-0x68], rax
    setc r10b                       ; COUT (captured before anything clobbers CF)
    movzx r10, r10b

    ; ---- inject the dividend bit into R0's LSB (guaranteed 0 post-shift) ----
    or   qword [rbp-0x80], r9

    ; ---- speculative S = R - B (4 limbs); capture the borrow ----
    mov  rax, [rbp-0x80]
    sub  rax, [rbp-0x40]
    mov  [rbp-0xA0], rax
    mov  rax, [rbp-0x78]
    sbb  rax, [rbp-0x38]
    mov  [rbp-0x98], rax
    mov  rax, [rbp-0x70]
    sbb  rax, [rbp-0x30]
    mov  [rbp-0x90], rax
    mov  rax, [rbp-0x68]
    sbb  rax, [rbp-0x28]
    mov  [rbp-0x88], rax
    setc r11b                        ; CF_sub (1 = borrow, i.e. R<B)
    movzx r11, r11b

    ; ---- do_commit = COUT | !CF_sub ----
    mov  eax, r11d
    xor  eax, 1
    or   eax, r10d
    test eax, eax
    jz   .no_commit

    ; commit: R := S ; set quotient bit i
    mov  rax, [rbp-0xA0]
    mov  [rbp-0x80], rax
    mov  rax, [rbp-0x98]
    mov  [rbp-0x78], rax
    mov  rax, [rbp-0x90]
    mov  [rbp-0x70], rax
    mov  rax, [rbp-0x88]
    mov  [rbp-0x68], rax

    mov  rcx, [rbp-0xA8]
    mov  rax, rcx
    shr  rax, 6
    mov  r8, rcx
    and  r8, 63
    mov  rcx, r8
    mov  r9, 1
    shl  r9, cl
    or   qword [rbp+rax*8-0x60], r9
.no_commit:
    ; i-- ; stop after processing i==0
    mov  rax, [rbp-0xA8]
    test rax, rax
    jz   .done
    dec  rax
    mov  [rbp-0xA8], rax
    jmp  .loop
.done:
    mov  rax, [rbp-0x60]
    mov  [rdi+0], rax
    mov  rax, [rbp-0x58]
    mov  [rdi+8], rax
    mov  rax, [rbp-0x50]
    mov  [rdi+16], rax
    mov  rax, [rbp-0x48]
    mov  [rdi+24], rax
    add  rsp, 0xC0
    pop  rbp
    ret

; ============================================================================
; block_work(work[16], bits32) -> work = 2^256/(target(bits)+1), low 128 bits
;   (LE). See file header for the exact identity used and why 128 bits is
;   exact (not merely "enough") for every realistic Bitcoin difficulty.
; ============================================================================
; Frame: 2 pushes (rbp,rbx) -> sub amount must be ~=8 mod16 to keep call
; sites aligned; 0x148 (328 = 20*16+8) satisfies that with ample margin over
; the 128 bytes of locals actually used (target_le/notA/divB/q, 32B each).
;
; SAVE-AREA CLEARANCE (found the hard way -- see LOG note below): with only
; `push rbx` after `push rbp`, the saved rbx lives at [rbp-8, rbp). A local
; buffer must start at rbp-8-size or deeper to avoid writing into that slot;
; starting a 32-byte buffer at rbp-0x20 is WRONG (it reaches [rbp-0x20,
; rbp), i.e. all the way up through the saved-rbx byte) even though -0x20
; "looks" comfortably negative. All four local buffers below therefore
; start 8 bytes deeper than the naive rbp-0x20/-0x40/-0x60/-0x80 scheme.
; CONFIRMED BUG (pre-fix): the naive layout silently overwrote the saved
; rbx via compact_to_target_le's `mov [rdi+24], rax` (target_le's 4th
; qword, at rdi+24 = rbp-0x20+24 = rbp-8) -- block_work's own epilogue then
; `pop`ed that clobbered value back into rbx, corrupting the CALLER's rbx
; the moment block_work returned. It only reproduced under -O2 (where GCC
; happened to keep a live value in rbx across the call) and was invisible
; at -O0 and in trivial single-call smoke tests -- caught via a
; minimal-repro bisection (tests/test_chainwork.c crashing at -O2 but not
; -O0) down to a 2-consecutive-calls reproduction, then a stack watchpoint
; that caught `pop rbx` reading back a value nothing legitimate had written.
global block_work
block_work:
    push rbp
    mov  rbp, rsp
    push rbx
    sub  rsp, 0x148
    mov  rbx, rdi              ; work[16] out (kept live across both calls)
    lea  rdi, [rbp-0x28]        ; target_le[32] (see save-area note above)
    call compact_to_target_le
    ; target==0 -> work=0 (degenerate/invalid nBits; matches Core's
    ; GetBlockProof returning 0 for a zero/negative/overflowing target)
    mov  rax, [rbp-0x28]
    or   rax, [rbp-0x20]
    or   rax, [rbp-0x18]
    or   rax, [rbp-0x10]
    jnz  .nonzero
    xor  eax, eax
    mov  [rbx+0], rax
    mov  [rbx+8], rax
    jmp  .ret
.nonzero:
    ; notA[32] @ rbp-0x48 = ~target_le  (bitwise NOT, always fits in 256 bits)
    mov  rax, [rbp-0x28]
    not  rax
    mov  [rbp-0x48], rax
    mov  rax, [rbp-0x20]
    not  rax
    mov  [rbp-0x40], rax
    mov  rax, [rbp-0x18]
    not  rax
    mov  [rbp-0x38], rax
    mov  rax, [rbp-0x10]
    not  rax
    mov  [rbp-0x30], rax
    ; divB[32] @ rbp-0x68 = target_le + 1  (256-bit increment, add-with-carry)
    mov  rax, [rbp-0x28]
    add  rax, 1
    mov  [rbp-0x68], rax
    mov  rax, [rbp-0x20]
    adc  rax, 0
    mov  [rbp-0x60], rax
    mov  rax, [rbp-0x18]
    adc  rax, 0
    mov  [rbp-0x58], rax
    mov  rax, [rbp-0x10]
    adc  rax, 0
    mov  [rbp-0x50], rax
    jc   .overflow               ; target was 2^256-1 -> +1 wraps to 2^256
    ; q[32] @ rbp-0x88 = u256_div(notA, divB)
    lea  rdi, [rbp-0x88]
    lea  rsi, [rbp-0x48]
    lea  rdx, [rbp-0x68]
    call u256_div
    ; work = q + 1 ; keep only the low 128 bits (2 limbs)
    mov  rax, [rbp-0x88]
    add  rax, 1
    mov  [rbx+0], rax
    mov  rax, [rbp-0x80]
    adc  rax, 0
    mov  [rbx+8], rax
    jmp  .ret
.overflow:
    ; target+1 == 2^256 (target was all-ones) -> work = 2^256/2^256 = 1.
    ; Unreachable for any real compact nBits (would need mantissa=0xFFFFFF
    ; at an exponent that fills all 32 bytes) -- handled defensively only.
    mov  qword [rbx+0], 1
    mov  qword [rbx+8], 0
.ret:
    add  rsp, 0x148
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; chainwork_add(out[16], a[16], b[16]) -> out = a+b, 128-bit unsigned.
;   Plain add/adc chain (no stack frame needed -- leaf, no calls, touches no
;   callee-saved registers).
; ============================================================================
global chainwork_add
chainwork_add:
    ; STO-13 (audit 2026-09-03): SATURATE instead of wrapping.
    ;
    ; Cumulative mainnet work is ~2^97 and per-block work ~2^80, so 128 bits
    ; is not close to exhausted and overflow needs a target below 2^128 --
    ; which pow_check cannot pass at real difficulty and `bad-diffbits`
    ; rejects before work is ever summed. The audit rates this "correct as
    ; used", and that is right.
    ;
    ; It saturates anyway because of WHAT this feeds: chainwork_cmp is the
    ; fork-choice predicate. A silent wrap would not corrupt a number in a
    ; log, it would make a lighter chain compare heavier -- the node
    ; reorganising ONTO the wrong chain, with no error anywhere. Clamping to
    ; all-ones keeps the comparison monotonic in the only direction that
    ; matters, and costs two instructions on a path that runs once per header.
    mov  rax, [rsi+0]
    add  rax, [rdx+0]
    mov  [rdi+0], rax
    mov  rax, [rsi+8]
    adc  rax, [rdx+8]
    mov  [rdi+8], rax
    jnc  .no_ovf
    ; carry out of the high limb: pin to 2^128-1
    mov  qword [rdi+0], -1
    mov  qword [rdi+8], -1
.no_ovf:
    ret

; ============================================================================
; chainwork_cmp(a[16], b[16]) -> -1 (a<b) / 0 (a==b) / 1 (a>b)
;   Unsigned 128-bit compare, high limb first then low. Leaf, no frame.
;   THE fork-choice predicate: "is the candidate chain heavier than ours".
;   NOTE the -1 return uses a full 64-bit `mov rax, -1`, NOT `mov eax, -1`
;   (which zero-extends to 0x00000000FFFFFFFF and would compare unequal to
;   -1 in a C caller holding the result in a `long`) -- the exact bug
;   bitcoin_p2p.asm's p2p_getheaders documents having been caught for.
; ============================================================================
global chainwork_cmp
chainwork_cmp:
    mov  rax, [rdi+8]
    cmp  rax, [rsi+8]
    ja   .gt
    jb   .lt
    mov  rax, [rdi+0]
    cmp  rax, [rsi+0]
    ja   .gt
    jb   .lt
    xor  eax, eax
    ret
.gt:
    mov  eax, 1
    ret
.lt:
    mov  rax, -1
    ret

; ============================================================================
; store_chainwork_init(st) -> 1 ok / -1 err        (`st` ignored -- see header)
;   Opens/creates chainwork.dat and zeroes the cached cumulative work. Closes
;   any descriptor a previous init left open, so repeated calls in one process
;   (the tests do exactly this) neither leak nor keep writing through a stale
;   descriptor. NOTE: on an EXISTING chainwork.dat this leaves the cache at
;   zero, which would make our own tip look weightless to fork choice --
;   always follow it with store_chainwork_reload.
; ============================================================================
global store_chainwork_init
store_chainwork_init:
    push rbp
    mov  rbp, rsp
    mov  rax, [rel cw_fd]
    cmp  rax, 0
    jl   .noclose
    mov  rdi, rax
    mov  eax, 3                ; close
    syscall
    mov  qword [rel cw_fd], -1
.noclose:
    lea  rdi, [rel cwname]
    mov  esi, 2 | 0x40         ; O_RDWR | O_CREAT
    mov  edx, 0o644
    mov  eax, 2                 ; open
    syscall
    test rax, rax
    jl   .fail
    mov  [rel cw_fd], rax
    xor  eax, eax
    mov  [rel cw_cum+0], rax
    mov  [rel cw_cum+8], rax
    mov  rax, 1
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    pop  rbp
    ret

; ============================================================================
; store_chainwork_append(st, height, work[16]) -> 1 ok / -1 err  (`st` ignored)
;   cumulative(height) = cumulative(height-1) [0 if height==0] + work;
;   written to chainwork.dat at height*16 and cached in cw_cum. height MUST
;   be appended in order (0,1,2,...) -- same positional-append discipline
;   store_append itself relies on for index.dat.
; ============================================================================
; Frame: 4 pushes (rbp,r12,r13,r14) -> save area is [rbp-0x18, rbp) (24
; bytes: r12,r13,r14); locals must start at rbp-0x18-size or deeper (see
; block_work's save-area-clearance note -- the same class of bug was caught
; and fixed here too on re-audit: prev_cum at a naive rbp-0x20 would reach
; up into r14's saved slot). prev_cum@-0x40, new_cum@-0x60 (each 16 bytes,
; 0x20 apart, both comfortably below -0x18). sub amount must be ~=8 mod16;
; 0x68 (104 = 6*16+8) covers the deepest local (-0x60..-0x50) with margin.
global store_chainwork_append
store_chainwork_append:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    sub  rsp, 0x68
    mov  r13, rsi               ; height
    mov  r14, rdx                ; work[16]
    mov  r12, [rel cw_fd]
    cmp  r12, 0
    jl   .err                     ; never initialised -> hard error, not fd 0
    test r13, r13
    jnz  .have_prev
    xor  eax, eax
    mov  [rbp-0x40], rax
    mov  [rbp-0x38], rax
    jmp  .prevdone
.have_prev:
    mov  rax, r13
    dec  rax
    imul rax, 16
    mov  rdi, r12
    lea  rsi, [rbp-0x40]           ; prev_cum[16]
    mov  edx, 16
    mov  r10, rax
    mov  eax, 17                     ; pread64
    syscall
    cmp  rax, 16
    jne  .err
.prevdone:
    lea  rdi, [rbp-0x60]             ; new_cum[16]
    lea  rsi, [rbp-0x40]              ; prev_cum
    mov  rdx, r14                      ; work
    call chainwork_add
    mov  rax, r13
    imul rax, 16
    mov  rdi, r12
    lea  rsi, [rbp-0x60]
    mov  edx, 16
    mov  r10, rax
    mov  eax, 18                        ; pwrite64
    syscall
    cmp  rax, 16
    jne  .err
    mov  rax, [rbp-0x60]
    mov  [rel cw_cum+0], rax
    mov  rax, [rbp-0x58]
    mov  [rel cw_cum+8], rax
    mov  rax, 1
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    add  rsp, 0x68
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; store_chainwork_get_at(st, height, out[16]) -> 1 ok / -1  (`st` ignored)
;   Leaf: no calls, so pread64's r10 argument and the scratch regs are free.
;   `height` arrives in rsi, which pread64 needs for its buffer pointer, so it
;   is moved to r8 (untouched by the syscall) before rsi is overwritten.
; ============================================================================
global store_chainwork_get_at
store_chainwork_get_at:
    push rbp
    mov  rbp, rsp
    mov  rax, [rel cw_fd]
    cmp  rax, 0
    jl   .fail
    mov  r8, rsi                ; height (saved before rsi is reused)
    imul r8, r8, 16
    mov  r10, r8                 ; file offset
    mov  rdi, rax                 ; fd
    mov  rsi, rdx                  ; out[16]
    mov  edx, 16
    mov  eax, 17                    ; pread64
    syscall
    cmp  rax, 16
    jne  .fail
    mov  rax, 1
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    pop  rbp
    ret

; ============================================================================
; store_chainwork_get_tip(st, out[16]) -> 1 (always; copies the cw_cum cache)
;   (`st` ignored.) Zero for a fresh/never-appended/never-initialised store,
;   matching an empty chain's zero cumulative work.
; ============================================================================
global store_chainwork_get_tip
store_chainwork_get_tip:
    mov  rax, [rel cw_cum+0]
    mov  [rsi+0], rax
    mov  rax, [rel cw_cum+8]
    mov  [rsi+8], rax
    mov  eax, 1
    ret

; ============================================================================
; store_chainwork_reload(st) -> number of 16-byte records in chainwork.dat
;   (>=0), or -1 on error.  (`st` ignored.) Refreshes the cw_cum cache from
;   the file's last record (zeroing it when the file is empty).
;
;   Frame: 3 pushes (rbp,rbx,r12) -> save area is [rbp-0x10, rbp) (rbx,r12).
;   The 16-byte `last` local therefore has to start at rbp-0x18-16 or deeper
;   (see block_work's save-area-clearance note in this file's header for the
;   confirmed bug the naive placement caused); -0x30 spans [-0x30,-0x20),
;   comfortably clear. No calls are made (syscalls only), so the sub amount
;   is not alignment-critical; 0x30 kept anyway.
; ============================================================================
global store_chainwork_reload
store_chainwork_reload:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    sub  rsp, 0x30
    mov  r12, [rel cw_fd]
    cmp  r12, 0
    jl   .fail
    ; ---- size = lseek(cw_fd, 0, SEEK_END) ----
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 2                 ; SEEK_END
    mov  eax, 8                 ; lseek
    syscall
    test rax, rax
    js   .fail
    shr  rax, 4                  ; n = size / 16 (a partial trailing record is
    mov  rbx, rax                 ; ignored -- floor, never over-count)
    ; ---- cache := 0 (correct as-is for an empty file) ----
    xor  eax, eax
    mov  [rel cw_cum+0], rax
    mov  [rel cw_cum+8], rax
    test rbx, rbx
    jz   .done
    ; ---- cache := record (n-1) ----
    mov  rax, rbx
    dec  rax
    shl  rax, 4
    mov  r10, rax                  ; offset (n-1)*16
    mov  rdi, r12
    lea  rsi, [rbp-0x30]
    mov  edx, 16
    mov  eax, 17                     ; pread64
    syscall
    cmp  rax, 16
    jne  .fail
    mov  rax, [rbp-0x30]
    mov  [rel cw_cum+0], rax
    mov  rax, [rbp-0x28]
    mov  [rel cw_cum+8], rax
.done:
    mov  rax, rbx
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    add  rsp, 0x30
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_chainwork_truncate(st, target_height) -> 1 ok / -1 err (`st` ignored)
;   See this file's header for the contract. Frame: 3 pushes (rbp,rbx,r12);
;   entry rsp%16==8 -> after the 3 pushes rsp%16==0, so the sub amount must
;   be 0 mod 16 to keep the nested store_chainwork_reload call aligned. No
;   stack locals are used at all, so 0x10 is pure alignment padding.
; ============================================================================
global store_chainwork_truncate
store_chainwork_truncate:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    sub  rsp, 0x10
    mov  rbx, rsi                ; target_height
    cmp  rbx, -1
    jl   .fail                     ; below -1 is not a meaningful target
    mov  r12, [rel cw_fd]
    cmp  r12, 0
    jl   .fail
    ; ---- current record count (also refreshes the cache, harmlessly) ----
    xor  edi, edi                   ; `st` is ignored; pass NULL explicitly
    call store_chainwork_reload
    cmp  rax, -1
    je   .fail
    ; new_n = target_height + 1 ; no-op (success) when new_n >= current n --
    ; ftruncate to a LONGER length would zero-extend the file, manufacturing
    ; bogus zero-work records for heights that were never appended.
    lea  rdx, [rbx+1]
    cmp  rdx, rax
    jge  .noop
    shl  rdx, 4                    ; new length in bytes
    mov  rdi, r12
    mov  rsi, rdx
    mov  eax, 77                     ; ftruncate
    syscall
    test rax, rax
    js   .fail
    ; ---- re-derive the cache from the NEW last record ----
    xor  edi, edi
    call store_chainwork_reload
    cmp  rax, -1
    je   .fail
.noop:
    mov  rax, 1
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    add  rsp, 0x10
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; MODULE-OWNED STATE (see this file's header for why it is not in store_buf).
;   cw_fd  : open descriptor for chainwork.dat, or -1 when never initialised.
;            Lives in .data, NOT .bss, precisely so the "never initialised"
;            value is -1 rather than .bss's zero -- zero is a perfectly valid
;            descriptor (stdin), and every entry point above tests `< 0` to
;            refuse before it can lseek/pread/pwrite/ftruncate on it.
;   cw_cum : cumulative chainwork of the tip, 128-bit little-endian.
; ============================================================================
section .data
cw_fd:  dq -1
cw_cum: dq 0, 0

section .rodata
cwname: db "chainwork.dat", 0

section .note.GNU-stack noalloc noexec nowrite progbits
