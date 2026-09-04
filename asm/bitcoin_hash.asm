; ============================================================================
; bitcoin_hash.asm -- Bitcoin blockchain hashing + proof-of-work primitives.
;   100% AI-authored x86-64 assembly, built on sha256.asm.
;
;   Exported API (System V AMD64):
;     void sha256d(u8 out[32], const void *msg, i64 len)
;         out = SHA256( SHA256( msg[0..len) ) )
;     void block_hash(u8 out[32], const u8 hdr[80])
;         out = sha256d(hdr, 80)   (the raw block-hash digest)
;     void diff_target(u8 target[32], u32 bits)
;         convert compact nBits (bits) to a 256-bit big-endian target.
;     int  pow_check(const u8 hdr[80])  returns 1 if the header's PoW holds
;         (block hash as little-endian 256-bit int <= target from nBits).
;
;   Conventions match Bitcoin's canonical format:
;     - double-SHA256 for sha256d / txid / merkle.
;     - Hashing digests (sha256_full) are used verbatim, as a little-endian
;       integer, for the numeric PoW comparison.
;     - Compact target: mantissa * 256^(exponent-3), exponent = top byte.
;
;   All code derived from first principles + my own Python oracle; no
;   Bitcoin Core source used.
; ============================================================================

default rel

extern sha256_full
extern sha256_block

section .rodata

; ---- constants for sha256d64 (below). All three are fixed by the shape of a
; 64-byte double-SHA256 and could not be otherwise; see that function's header.
align 16
D64_IV:                     ; FIPS 180-4 H0..H7, host word order
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
align 16
D64_PAD_512:                ; block 2 of SHA-256 over a 64-byte message:
    db 0x80                 ;   0x80, then zeros, then the bit length 512 BE
    times 55 db 0
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00
align 16
D64_PAD_256:                ; bytes 32..63 of SHA-256 over a 32-byte message:
    db 0x80                 ;   0x80, then zeros, then the bit length 256 BE
    times 23 db 0
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00
align 16
D64_BSWAP32:                ; reverse the bytes WITHIN each 32-bit lane
    db 0x03,0x02,0x01,0x00, 0x07,0x06,0x05,0x04
    db 0x0b,0x0a,0x09,0x08, 0x0f,0x0e,0x0d,0x0c

section .text

; ----------------------------------------------------------------------------
; sha256d(out[32], msg, len) : SHA256(SHA256(msg))
;   Stack: hash1[32] local + saved len slot.
; ----------------------------------------------------------------------------
global sha256d
sha256d:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x48          ; hash1[32] at [-0x40..-0x21] BELOW save area
                            ; [rbp-0x08..-0x20]; len-save at -0x48. 6 pushes (0x30)
                            ; + 0x48 = 0x78 == 8 mod16 keeps rsp 0 mod16
                            ; (aligned) at the sha256_full calls.
                            ; (r14/r15 added so sha256d preserves all of
                            ; rbx/r12-r15; sha256_full clobbers r14/r15.)

    mov r12, rdi            ; out
    mov r13, rsi            ; msg
    mov [rbp-0x58], rdx     ; save len (below the r14/r15 saves at -0x20/-0x28)

    ; hash1 = sha256(msg, len)
    lea rdi, [rbp-0x50]
    mov rsi, r13
    mov rdx, [rbp-0x58]
    call sha256_full

    ; out = sha256(hash1, 32)
    mov rdi, r12
    lea rsi, [rbp-0x50]
    mov rdx, 32
    call sha256_full

    add rsp, 0x48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; block_hash(out[32], hdr[80]) : sha256d(hdr, 80)
; ----------------------------------------------------------------------------
global block_hash
block_hash:
    mov rdx, 80
    jmp sha256d

; ------------------------------------------------------------------------------
; diff_target(target[32], bits32): convert compact nBits foo0xHHMMLLLL to a
;   256-bit big-endian target = mantissa * 256^(exponent-3).
;   Layout of target[32] here: we store it big-endian so the caller can emit /
;   reason about it, but PoW compares against the hash LE. We actually only use
;   this for the numeric comparison, which we do in LE limb space below.
; ------------------------------------------------------------------------------
global diff_target
diff_target:
    push rbx
    ; rdi = target, esi = bits
    mov eax, esi
    mov edx, esi
    shr eax, 24             ; exponent (0..255)
    and edx, 0x00ffffff     ; mantissa
    ; target = mantissa * 256^(exponent-3)
    ; if mantissa has high bit set, it's negative -> 0 (invalid, but keep math)
    ; bytes of the target (big-endian, 32 bytes): exponent-3 zero bytes follow
    ; the mantissa's leading bytes.
    mov ecx, eax
    sub ecx, 3              ; exponent-3 ; if <0 -> shift right instead.
    ; We'll place mantissa as a 3-byte big-endian integer then append/prepend
    ; zero bytes to reach 32 bytes.
    ; Represent target in a 32-byte big-endian buffer:
    ;   byte[31 - i] for the mantissa's little-endian bytes, positions decided
    ;   by mantissa_len + (exponent-3). Simplest: build in big-endian scratch.
    ; We write directly:
    ;   fill target[0..31] with 0
    ;   big-endian 256-bit value = mantissa << (8*(exponent-3)). We store into
    ;   the byte array so that index0 = most significant byte.
    xor r8d, r8d
    mov rcx, 32
.z:
    mov byte [rdi+rcx-1], 0
    dec rcx
    jnz .z
    ; Now write mantissa (up to 3 bytes) at the correct offset.
    ; val = mantissa; we place its bytes (big-endian) starting at position
    ; p = 32 - mantissa_bytes - (exponent-3). Expressed low: the LSB lands at
    ; byte index (exponent-3) from the right in a 32-byte big-endian array.
    mov r8d, edx            ; mantissa
    ; mantissa occupies the low (exponent-3+mantissa_bytes)...
    ; We directly compute the byte offset of the LSB from the right = e3
    mov ecx, eax
    sub ecx, 3
    ; if ecx < 0 skip (shift right not needed for real targets)
    test ecx, ecx
    js  .done
    ; VAL-11 (audit 2026-09-03): with e3 >= 32 the LSB position rdi+31-e3
    ; lands BELOW the buffer -- the old code wrote 1-3 bytes below target_be
    ; (~220 below rbp for exponents near 0xff: a stack scribble driven by an
    ; attacker-chosen nBits, and the enabler for VAL-7/VAL-8's free bogus
    ; headers). Core's big-uint shift DISCARDS bits past 256, so the correct
    ; clamped behaviour is to write nothing: the stored target stays 0. The
    ; overflow itself is rejected by pow_check's range checks.
    cmp ecx, 31
    jg  .done
    ; LSB at target[31 - ecx]; write mantissa little-endian w/ carry up to 3
    ; bytes, provided index stays in range.
    lea r9, [rdi+31]
    sub r9, rcx
    ; r9 points at LSB position; write up to 3 bytes little-endian from
    ; mantissa.
    mov r8, rdx
    mov rcx, 3
.w:
    test r8, r8
    jz  .done
    ; VAL-11 continued: stop at the buffer's top edge. Core's 256-bit shift
    ; discards bits past bit 256 (that IS the overflow pow_check now rejects);
    ; writing them below rdi is what corrupted the frame.
    cmp r9, rdi
    jb  .done
    mov al, r8b
    mov [r9], al
    shr r8, 8
    dec r9
    dec rcx
    jnz .w
.done:
    pop rbx
    ret

; ------------------------------------------------------------------------------
; pow_check(hdr[80]) -> 1 if the block header's proof-of-work holds.
;   Computes the double-SHA256 block hash (as a little-endian 256-bit integer)
;   and ensures it is <= the target derived from the header's nBits field.
;   Returns eax = 1 (valid PoW) or 0.
;   Stack locals: hash[32]@-0x30, hash_be[32]@-0x60, target_be[32]@-0x90.
;
;   CALLEE-SAVED SAVE AREA IS *ABOVE* RBP. The pushes precede `push rbp`, so
;   rbx/r12/r13 live at [rbp+0x08..rbp+0x18] and hash[32] at
;   [rbp-0x30..rbp-0x11] is inside this function's own 0xb8 reservation.
;   Previously the pushes followed `mov rbp,rsp`, putting saved r13 at rbp-0x18
;   underneath hash[32], so block_hash's output was popped into the CALLER's
;   r13. cons_verify inherited that: its own frame is correct, but it calls
;   pow_check. Both were flagged by tests/bench_abi_audit before this change.
;   ALIGNMENT IS UNCHANGED: same four pushes and same 0xb8 reservation, merely
;   reordered. Entry 8 -> 3 pushes -> 0 -> push rbp -> 8 -> sub 0xb8 -> 0, the
;   same 0 mod 16 the nested calls saw before.
; ------------------------------------------------------------------------------
global pow_check
; VAL-11 (audit 2026-09-03): pow_pow_limit_bits -- the chain's powLimit as a
; compact nBits, ARMED by chainparams_select (daemon/chainparams.c). 0 (the
; default) means "powLimit check off": pow_check then only enforces Core's
; nBits well-formedness (negative/zero/overflow), which keeps the harnesses
; that mine against 0x207fffff without selecting a chain working. The daemon
; arms it at boot, so the live validation path can never accept a header
; whose claimed target exceeds the chain's powLimit (Core's CheckProofOfWork
; rejects exactly that).
global pow_pow_limit_bits
section .data align=16
pow_pow_limit_bits: dd 0
section .text
pow_check:
    push rbx
    push r12
    push r13
    push rbp
    mov  rbp, rsp
    sub  rsp, 0xc8         ; locals -0x30, -0x60, -0x90, and (VAL-11) the
                           ; powLimit target at -0xc0; 0xc8==8 mod16 -> aligned
                           ; (same residue as the old 0xb8: nested-call
                           ; alignment unchanged)

    mov r12, rdi           ; hdr (caller-saved clobbered by block_hash->sha256d)

    ; hash = block_hash(hdr)   (32 bytes)
    lea rdi, [rbp-0x30]
    mov rsi, r12
    call block_hash

    ; bits = *(u32 LE)(hdr+72)
    mov eax, [r12+72]

    ; ---- VAL-11 (audit 2026-09-03): Core's CheckProofOfWorkImpl range
    ; checks, mirrored from arith_uint256::SetCompact's flags. Previously the
    ; hash was compared against a target derived from WHATEVER nBits claimed,
    ; with no fNegative / ==0 / fOverflow tests -- so nBits=0x207fffff made
    ; PoW free (VAL-7's zero-cost bogus tip) and a negative or overflowing
    ; compact was "valid" math rather than invalid PoW.
    ;   nWord = bits & 0x007fffff ; nSize = bits >> 24
    ;   fNegative = nWord != 0 && (bits & 0x00800000)
    ;   fOverflow = nWord != 0 && (nSize > 34 ||
    ;               (nSize > 33 && nWord > 0xff) || (nSize > 32 && nWord > 0xffff))
    ; plus Core's bnTarget == 0 rejection.
    mov  edx, eax
    shr  edx, 24                   ; nSize
    and  eax, 0x007fffff           ; nWord
    test eax, eax
    jz   .invalid                  ; mantissa 0 -> target 0 -> badPoW
    test dword [r12+72], 0x00800000
    jnz  .invalid                  ; fNegative (nWord != 0 proven above)
    cmp  edx, 34
    jg   .invalid                  ; fOverflow: nSize > 34
    cmp  edx, 33
    jbe  .ov2
    cmp  eax, 0xff
    jg   .invalid                  ; nSize > 33 && nWord > 0xff
.ov2:
    cmp  edx, 32
    jbe  .ovdone
    cmp  eax, 0xffff
    jg   .invalid                  ; nSize > 32 && nWord > 0xffff
.ovdone:

    ; target_be[32] = diff_target(bits)
    lea rdi, [rbp-0x90]
    mov esi, [r12+72]
    call diff_target

    ; target == 0? (exponent < 3 zeroes the stored target even with a
    ; nonzero mantissa; Core rejects bnTarget == 0).
    lea  r8, [rbp-0x90]
    xor  ecx, ecx
.zt:
    cmp  qword [r8+rcx*8], 0
    jne  .zok
    inc  ecx
    cmp  ecx, 4
    jb   .zt
    jmp  .invalid
.zok:

    ; powLimit comparison, ARMED only: pow_pow_limit_bits is set by
    ; chainparams_select from the chain's pow_limit_bits and defaults to 0
    ; (off), so harnesses that mine trivial PoW without selecting a chain
    ; (test_cons, block generators) keep working; the daemon arms it at boot
    ; and the live chain can never accept a target above its powLimit
    ; (Core: bnTarget > powLimit -> invalid).
    mov  eax, [rel pow_pow_limit_bits]
    test eax, eax
    jz   .lmdone
    lea  rdi, [rbp-0xc0]
    mov  esi, eax
    call diff_target
    lea  r8, [rbp-0x90]            ; claimed target
    lea  r9, [rbp-0xc0]            ; powLimit target
    xor  ecx, ecx
.lcmp:
    movzx eax, byte [r8+rcx]
    movzx edx, byte [r9+rcx]
    cmp  eax, edx
    jb   .lmdone                   ; target < powLimit: in range
    ja   .invalid                  ; target > powLimit
    inc  ecx                       ; equal so far; keep scanning
    cmp  ecx, 32
    jne  .lcmp                     ; fully equal == in range (Core: >)
.lmdone:

    ; hash_be[32] = reverse(hash[32])
    lea r8,  [rbp-0x30+31]  ; src = hash + 31 (last byte first)
    lea r9,  [rbp-0x60]     ; dst = hash_be + 0 (first byte)
    mov ecx, 32
.rev:
    mov al, [r8]
    mov [r9], al
    dec r8
    inc r9
    dec rcx
    jnz .rev

    ; compare hash_be vs target_be as unsigned big-endian 256-bit integers.
    ; MUST compare most-significant byte (index 0) first, downward.
    ; result: 1 if hash_be <= target_be
    lea r8, [rbp-0x60]     ; hash_be
    lea r9, [rbp-0x90]     ; target_be
    xor ecx, ecx           ; byte index 0 (MSB) first
.cmp:
    movzx eax, byte [r8+rcx]
    movzx edx, byte [r9+rcx]
    cmp al, dl
    jb  .valid             ; hash byte < target byte -> hash < target
    ja  .invalid           ; hash byte > target byte -> hash > target
    inc ecx
    cmp ecx, 32
    jne .cmp
    ; all equal -> hash == target -> valid
.valid:
    mov eax, 1
    jmp .out
.invalid:
    xor eax, eax
.out:
    add rsp, 0xc8
    pop rbp
    pop r13
    pop r12
    pop rbx
    ret


; ----------------------------------------------------------------------------
; void sha256d64(u8 *out, const u8 *in, u64 pairs)
;   out[32i .. 32i+31] = SHA256(SHA256(in[64i .. 64i+63])), for i < pairs.
;   The opposite number of Core's SHA256D64 (src/crypto/sha256.h:51), and the
;   merkle tree's inner-node operation.
;
; WHY IT EXISTS (PERF_SCOPE.md 13.2)
;   `merkle_root` used to call sha256d(concat, 64) once per node. That is
;   correct and it is slow for two measured reasons, in this order:
;
;   1. THE CHAIN IS SERIAL. A 64-byte double-SHA256 is three compressions in
;      strict sequence, and sha256rnds2 is latency-bound: measured on this box
;      (Zen 5), one chained sha256_block_shani costs 26.88 ns, but TWO
;      INDEPENDENT ones alternated cost 16.91 ns each -- 1.59x, purely from
;      letting the out-of-order engine overlap two chains. Widths 3..6 were
;      measured too and buy nothing further (16.72 / 16.75 / 16.78 / 16.67),
;      so TWO is the right width on this CPU and that is a measurement, not
;      an assumption. Core's SHA256D64 is 2-way for the same reason.
;
;   2. PER-CALL OVERHEAD. sha256d -> sha256_full x2 re-runs sha256_init, does
;      a `rep movsb` of the 64 input bytes into a second buffer, and BUILDS
;      the padding block byte by byte -- every time, for a message whose
;      length is a compile-time constant. Measured at 20.07 ns of the 100.84
;      ns each pair cost, i.e. 19.9 %.
;
;   This function fixes both WITHOUT a new cryptographic kernel: it calls the
;   existing, already-validated `sha256_block` (which dispatches to SHA-NI or
;   the scalar fallback), twice per step with two independent states, and the
;   two padding blocks are .rodata constants because the two message lengths
;   are always 512 and 256 bits. Nothing here computes a hash round.
;
; LAYOUT PER PAIR OF INPUTS (lanes A and B, interleaved)
;   SA = SB = IV
;   compress(SA, inA)            compress(SB, inB)          ; the data
;   compress(SA, PAD_512)        compress(SB, PAD_512)      ; the padding
;   BA = BE(SA) || PAD_256       BB = BE(SB) || PAD_256     ; 2nd-hash block
;   SA = SB = IV
;   compress(SA, BA)             compress(SB, BB)
;   out = BE(SA) || BE(SB)
;
; ABI: rdi=out, rsi=in, rdx=pairs. Preserves rbx, r12-r15 (sha256_block does).
;   pairs == 0 returns immediately. An odd `pairs` finishes with one 1-way step.
; Frame (rbp-relative, all below the save area, all at or above rsp):
;   SA -0x50 (32)  SB -0x70 (32)  BA -0xb0 (64)  BB -0xf0 (64)
;   The save area is at rbp-0x08..-0x28 when the caller was already 16-aligned
;   and rbp-0x10..-0x30 when `and rsp,-16` had to move rsp, so NO box may sit
;   above rbp-0x30. (SA at rbp-0x40 spans up to rbp-0x21 and clobbered saved
;   rbx -- i.e. the caller's `out` pointer -- which is how this was found.)
; ----------------------------------------------------------------------------

; V := IV, at the rbp-relative base %1
%macro D64_SETIV 1
    movdqa xmm0, [rel D64_IV]
    movdqa xmm1, [rel D64_IV+16]
    movdqu [%1 + 0],  xmm0
    movdqu [%1 + 16], xmm1
%endmacro

; [%1 .. %1+31] := big-endian bytes of the 8 host words at %2.
;   pshufb with a per-dword reverse mask does all eight words in two shuffles;
;   the mask is the same permutation sha256.asm's SHA-NI body already uses to
;   byte-swap a message block, restated here so this file owns its constants.
%macro D64_STORE_BE 2
    movdqa xmm2, [rel D64_BSWAP32]
    movdqu xmm0, [%2 + 0]
    movdqu xmm1, [%2 + 16]
    pshufb xmm0, xmm2
    pshufb xmm1, xmm2
    movdqu [%1 + 0],  xmm0
    movdqu [%1 + 16], xmm1
%endmacro

; [%1 + 32 .. %1 + 63] := the 32-byte tail of a 32-byte message's padded block.
;   Hoisted OUT of the loop: the second-hash blocks are our own buffers and
;   only their first 32 bytes ever change, so this is written once per call.
%macro D64_PADTAIL 1
    movdqa xmm0, [rel D64_PAD_256]
    movdqa xmm1, [rel D64_PAD_256+16]
    movdqu [%1 + 32], xmm0
    movdqu [%1 + 48], xmm1
%endmacro

global sha256d64
sha256d64:
    push rbp
    mov  rbp, rsp
    and  rsp, -16           ; the interpreter chain does not guarantee alignment
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xf8          ; -> rsp 0 mod 16 at every nested call

    mov  rbx, rdi           ; out
    mov  r12, rsi           ; in
    mov  r13, rdx           ; pairs remaining
    test r13, r13
    jz   .out
    D64_PADTAIL rbp-0xb0    ; both second-hash blocks keep a constant tail
    D64_PADTAIL rbp-0xf0

.two:
    cmp  r13, 2
    jb   .one

    D64_SETIV rbp-0x50
    D64_SETIV rbp-0x70
    ; ---- first hash, data block, both lanes ----
    lea  rdi, [rbp-0x50]
    mov  rsi, r12
    call sha256_block
    lea  rdi, [rbp-0x70]
    lea  rsi, [r12+64]
    call sha256_block
    ; ---- first hash, padding block (constant), both lanes ----
    lea  rdi, [rbp-0x50]
    lea  rsi, [rel D64_PAD_512]
    call sha256_block
    lea  rdi, [rbp-0x70]
    lea  rsi, [rel D64_PAD_512]
    call sha256_block
    ; ---- build both second-hash blocks ----
    D64_STORE_BE rbp-0xb0, rbp-0x50
    D64_STORE_BE rbp-0xf0, rbp-0x70
    ; ---- second hash, both lanes ----
    D64_SETIV rbp-0x50
    D64_SETIV rbp-0x70
    lea  rdi, [rbp-0x50]
    lea  rsi, [rbp-0xb0]
    call sha256_block
    lea  rdi, [rbp-0x70]
    lea  rsi, [rbp-0xf0]
    call sha256_block
    ; ---- emit ----
    D64_STORE_BE rbx,    rbp-0x50
    D64_STORE_BE rbx+32, rbp-0x70

    add  rbx, 64
    add  r12, 128
    sub  r13, 2
    jmp  .two

.one:
    test r13, r13
    jz   .out
    D64_SETIV rbp-0x50
    lea  rdi, [rbp-0x50]
    mov  rsi, r12
    call sha256_block
    lea  rdi, [rbp-0x50]
    lea  rsi, [rel D64_PAD_512]
    call sha256_block
    D64_STORE_BE rbp-0xb0, rbp-0x50
    D64_SETIV rbp-0x50
    lea  rdi, [rbp-0x50]
    lea  rsi, [rbp-0xb0]
    call sha256_block
    D64_STORE_BE rbx, rbp-0x50

.out:
    add rsp, 0xf8           ; back to the 5 pushes (rsp-relative: `and rsp,-16`
    pop r15                 ; means their address is NOT a fixed rbp offset)
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
    ret

; ------------------------------------------------------------------------------
; merkle_root(out[32], hashes, n): Bitcoin merkle root of n leaf hashes (each
;   32 bytes) held contiguously in `hashes`.  Operates IN PLACE on `hashes`
;   (caller supplies a mutable buffer of n*32 bytes); writes the final root to
;   `out`.  Pairing: double-SHA256( left || right ); odd count duplicates the
;   last hash. Matches Bitcoin's tx-merkle construction (raw digest bytes).
;
;   ABI: rdi=out, rsi=hashes, rdx=n.
;   Registers (callee-saved, safe across sha256d64): rbx=hashes, r12=n,
;   r13=out, r14=nodes at this level, r15=read byte offset; the write byte
;   offset lives at [rbp-0xc8].
;
;   2026-08-23 (PERF_SCOPE.md 13.2): the inner node hash goes through
;   `sha256d64` a BATCH of nodes at a time instead of `sha256d` one at a
;   time. The double-SHA256 chains of distinct nodes are independent, and on
;   this CPU running two of them interleaved costs 16.91 ns per compression
;   against 26.88 ns for one on its own -- so the pairing is worth 1.59x on
;   the hashing itself, before the per-call padding and copying sha256d64
;   also removes.
; ------------------------------------------------------------------------------

; Stage hashes[r15] and its sibling into the 64-byte slot R9 POINTS AT.
;   Sibling = the next node, or a duplicate of this one when this is the last
;   node of an odd-sized level (Bitcoin's rule). r14 = nodes at this level.
;   Advances r15 by 64. Clobbers rax, r10, r11 (all caller-saved, all rebuilt
;   at every use); r9 is the caller's destination pointer and is left alone.
%macro MK_CONCAT 0
    mov r10, rbx
    add r10, r15
    mov rax, [r10+0]
    mov [r9+0], rax
    mov rax, [r10+8]
    mov [r9+8], rax
    mov rax, [r10+16]
    mov [r9+16], rax
    mov rax, [r10+24]
    mov [r9+24], rax
    mov r11, r15
    shr r11, 5
    inc r11
    cmp r11, r14
    jae %%dup                  ; no sibling -> duplicate the left node
    add r10, 32
    ; VAL-6 (audit 2026-09-03, CVE-2012-2459): Core's ComputeMerkleRoot sets
    ; `mutated` when a REAL sibling pair at any level is byte-identical --
    ; the duplicate-tail-fold ambiguity means such a tree can be built from a
    ; DIFFERENT tx list with the same root and the same block hash. Only the
    ; real-sibling path counts (the odd-tail duplicate below is legitimate).
    mov rax, [r10+0]
    cmp rax, [r10-32]
    jne %%nomut
    mov rax, [r10+8]
    cmp rax, [r10-24]
    jne %%nomut
    mov rax, [r10+16]
    cmp rax, [r10-16]
    jne %%nomut
    mov rax, [r10+24]
    cmp rax, [r10-8]
    jne %%nomut
    mov byte [rbp-0x480], 1
%%nomut:
%%dup:
    mov rax, [r10+0]
    mov [r9+32], rax
    mov rax, [r10+8]
    mov [r9+40], rax
    mov rax, [r10+16]
    mov [r9+48], rax
    mov rax, [r10+24]
    mov [r9+56], rax
    add r15, 64
%endmacro

; How many node pairs are staged before one sha256d64 call. Measured: 1 pair
; per call leaves the two chains unable to overlap ACROSS calls and costs
; 76.8 ns/leaf; batching amortises the call and lets consecutive pairs
; pipeline, at 16 it is 1024 bytes of stack for the staging buffer.
%define MK_STAGE 16

global merkle_root
merkle_root:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x458        ; concat[MK_STAGE*64] at [rbp-0x460..-0x61], write
                           ; offset at -0x468, staged count at -0x470, and the
                           ; VAL-6 mutation flag at -0x480; all BELOW the save
                           ; area [rbp-0x08..-0x28].
                           ; 0x458==8 mod16 -> rsp 0 mod16 at nested calls.

    mov r13, rdi           ; out
    mov rbx, rsi           ; hashes
    mov r12, rdx           ; n
    mov byte [rbp-0x480], 0    ; VAL-6 mutation flag (stack-local: thread-safe)

.next_level:
    cmp r12, 1
    jbe .finish

    ; Produce the next level, in place, into hashes[0 .. new_n) where
    ; new_n = (n+1)/2. Safe because every batch copies ALL of its inputs out
    ; of `hashes` before sha256d64 writes any of its outputs back, and the
    ; write offset is never more than half the read offset.
    mov r14, r12           ; node count THIS level (r12 stays fixed)
    xor r15, r15           ; read byte offset
    xor eax, eax
    mov [rbp-0x468], rax   ; write byte offset

.batch:
    xor eax, eax
    mov [rbp-0x470], rax   ; staged pairs = 0
.fill:
    mov rax, [rbp-0x470]
    shl rax, 6
    lea r9, [rbp-0x460]
    add r9, rax            ; r9 = &concat[staged]
    MK_CONCAT
    mov rax, [rbp-0x470]
    inc rax
    mov [rbp-0x470], rax
    mov r11, r15
    shr r11, 5
    cmp r11, r14           ; level exhausted?
    jae .flush
    cmp rax, MK_STAGE
    jb  .fill
.flush:
    mov rdi, rbx
    add rdi, [rbp-0x468]
    lea rsi, [rbp-0x460]
    mov rdx, [rbp-0x470]
    call sha256d64
    mov rax, [rbp-0x470]
    shl rax, 5             ; 32 output bytes per staged pair
    add rax, [rbp-0x468]
    mov [rbp-0x468], rax
    mov r11, r15
    shr r11, 5
    cmp r11, r14
    jb  .batch

    ; new_n = (r12 + 1) >> 1
    mov rax, r12
    add rax, 1
    shr rax, 1
    mov r12, rax
    jmp .next_level

.finish:
    mov rax, [rbx+0]
    mov [r13+0], rax
    mov rax, [rbx+8]
    mov [r13+8], rax
    mov rax, [rbx+16]
    mov [r13+16], rax
    mov rax, [rbx+24]
    mov [r13+24], rax
    ; VAL-6: return the mutation flag in eax. C callers declared `void` ignore
    ; it; cons_verify reads it to reject a CVE-2012-2459 mutated block.
    movzx eax, byte [rbp-0x480]

    add rsp, 0x458
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
