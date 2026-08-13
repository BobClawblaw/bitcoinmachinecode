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
; ------------------------------------------------------------------------------
global pow_check
pow_check:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0xb8         ; locals -0x30, -0x60, -0x90; 0xb8==8 mod16 -> aligned

    mov r12, rdi           ; hdr (caller-saved clobbered by block_hash->sha256d)

    ; hash = block_hash(hdr)   (32 bytes)
    lea rdi, [rbp-0x30]
    mov rsi, r12
    call block_hash

    ; bits = *(u32 LE)(hdr+72)
    mov eax, [r12+72]
    ; target_be[32] = diff_target(bits)
    lea rdi, [rbp-0x90]
    mov esi, eax
    call diff_target

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
    add rsp, 0xb8
    pop r13
    pop r12
    pop rbx
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
;   Registers (callee-saved, safe across sha256d): rbx=hashes, r12=n, r13=out,
;   r14=n (running).  Frame: concat[64] local; callers must keep rsp 0 mod16.
; ------------------------------------------------------------------------------
global merkle_root
merkle_root:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x98         ; concat[64] at [rbp-0x80..-0x21] BELOW save area
                          ; [rbp-0x20..-0x08]; write-offset saved at -0x88.
                          ; 0x98==8 mod16 -> rsp 0 mod16 -> sha256d calls aligned.

    mov r13, rdi           ; out
    mov rbx, rsi           ; hashes
    mov r12, rdx           ; n

    ; CALLEE-SAVED CURSORS that must survive sha256d (which clobbers rcx,r8-r11):
    ;   r15 = read byte offset ; write byte offset kept in [rbp-0x88]

.next_level:
    cmp r12, 1
    jbe .finish

    ; produce the next level, in place, into hashes[0 .. new_n)
    ; (new_n = (n+1)/2).  Each output index < its input indices, so in-place
    ; overwrite is safe once the concat buffer holds both inputs.
    mov r14, r12           ; original node count THIS level (r12 stays fixed)
    xor r15, r15           ; read offset = 0
    xor eax, eax
    mov [rbp-0x88], rax    ; write offset = 0
.pair:
    lea r9,  [rbp-0x80]    ; concat base (caller-saved, rebuilt each iter)
    ; copy left = hashes[r15 ..]  (32 bytes)
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
    ; right sibling?  left node index = r15/32 ; present if index+1 < r14
    mov r11, r15
    shr r11, 5
    inc r11
    cmp r11, r14
    jae .dup_last
    mov r10, rbx
    add r10, r15
    add r10, 32
    mov rax, [r10+0]
    mov [r9+32], rax
    mov rax, [r10+8]
    mov [r9+40], rax
    mov rax, [r10+16]
    mov [r9+48], rax
    mov rax, [r10+24]
    mov [r9+56], rax
    jmp .hash_pair
.dup_last:
    mov r10, rbx
    add r10, r15
    mov rax, [r10+0]
    mov [r9+32], rax
    mov rax, [r10+8]
    mov [r9+40], rax
    mov rax, [r10+16]
    mov [r9+48], rax
    mov rax, [r10+24]
    mov [r9+56], rax
.hash_pair:
    ; sha256d(concat,64) -> hashes[write_off ..]  ; write_off in [rbp-0x88]
    mov rdi, rbx
    mov rax, [rbp-0x88]
    add rdi, rax
    mov rsi, r9
    mov rdx, 64
    call sha256d
    ; advance one pair (both cursors are callee-saved / stack, safe)
    add r15, 64
    mov rax, [rbp-0x88]
    add rax, 32
    mov [rbp-0x88], rax
    ; continue while read_nodes (r15/32) < r14
    mov r11, r15
    shr r11, 5
    cmp r11, r14
    jb  .pair

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

    add rsp, 0x98
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
