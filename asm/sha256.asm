; ============================================================================
; SHA-256  --  100% AI-generated x86-64 assembly (NASM, ELF64 ABI)
;
; PURPOSE
;   SHA-256 is THE hash function of Bitcoin. It secures:
;     - block hashing      (the PoW target comparison / block identifiers)
;     - transaction ids    (txid, computed over the serialized transaction)
;     - Merkle tree roots  (every block header commits to its tx set)
;     - address generation (hash160 = RIPEMD160(SHA256(pubkey)))
;   A Bitcoin node therefore needs a fast, correct SHA-256 at its core. This
;   file implements the complete algorithm in raw x86-64 machine code, with
;   every line authored by an AI assistant -- no human-written instructions.
;
; ALGORITHM (FIPS 180-4 / RFC 6234)
;   SHA-256 processes the message in 512-bit (64-byte) blocks. For each block
;   it builds a 64-word message schedule W[0..63] and runs 64 compression
;   rounds over an 8-word working state a..h, then adds the working state back
;   into the running hash state H[0..7].
;
;   Each round (i = 0..63):
;     S1(e) = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25)
;     Ch(e,f,g)  = (e AND f) XOR (NOT e AND g)
;     T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i]
;     S0(a) = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)
;     Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
;     T2 = S0(a) + Maj(a,b,c)
;     h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2
;
;   W[0..15] are the 16 big-endian words of the block; W[16..63] extend via:
;     W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16]
;     s0(x) = ROTR(x,7)  ^ ROTR(x,18) ^ SHR(x,3)
;     s1(x) = ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10)
;
; PUBLIC ABI (System V AMD64: first args in rdi, rsi, rdx)
;   void sha256_init (u32 state[8])                       -> rdi = state
;   void sha256_block(u32 state[8], const u8 block[64])   -> rdi, rsi
;   void sha256_full (u8 out[32], const void *msg, i64 len) -> rdi, rsi, rdx
;
; ENDIANNESS: SHA-256 treats each 32-bit word as big-endian. The input block
; bytes are already big-endian (as Bitcoin serializes everything), so we BSWAP
; each 4-byte word on the way IN and BSWAP each digest word on the way OUT.
; ============================================================================

BITS 64
DEFAULT REL

; ----------------------------------------------------------------------------
; Read-only data: the 64 round constants K[0..63] and the 8 initial hash
; values H0..H7. These are defined in FIPS 180-4 as the fractional parts of
; the cube roots / square roots of the first 64 / 8 primes. Stored here as
; raw 4-byte constants, identical to the published table.
; ----------------------------------------------------------------------------
section .rodata
align 16
K256:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

align 16
INIT_H:
    ; H0..H7 for a fresh SHA-256 run (FIPS 180-4 initialization vector).
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

; ----------------------------------------------------------------------------
; Code section
; ----------------------------------------------------------------------------
section .text

; ============================================================================
; void sha256_init(u32 state[8])
;   Loads the SHA-256 initial hash values H0..H7 into the caller's buffer.
;
; Register usage:
;   rdi  = pointer to caller's 8-word (32-byte) state buffer
;   rsi  = pointer walking INIT_H
;   ecx  = word counter (8 iterations)
;   eax  = scratch word
; ============================================================================
global sha256_init
sha256_init:
    lea rsi, [INIT_H]   ; rsi -> first constant word
    mov ecx, 8          ; copy exactly 8 words
.loop:
    mov eax, [rsi]      ; load one constant word
    mov [rdi], eax      ; store into caller's state at the same offset
    add rdi, 4          ; advance destination pointer by one word (4 bytes)
    add rsi, 4          ; advance source pointer by one word
    dec ecx             ; decrement counter
    jnz .loop           ; loop until 8 words copied (when ecx becomes 0)
    ret

; ============================================================================
; void sha256_block(u32 state[8], const u8 block[64])
;   Runs ONE 64-byte block through the SHA-256 compression function,
;   adding the result into state[].
;
; FRAME LAYOUT (stack grows downward; rbp is the fixed frame base):
;   Before this routine returns the caller expects rbx/r12-r15 preserved, so
;   we push them. The 256-byte block for W[0..63] is carved below them.
;
;   rbp          <- caller's rbp (pushed), our fixed base
;   rbp-0x08     <- saved rbx
;   rbp-0x10     <- saved r12
;   rbp-0x18     <- saved r13
;   rbp-0x20     <- saved r14
;   rbp-0x28     <- saved r15
;   rbp-0x28-256 .. rbp-0x28-1  <- W[0..63] message schedule (256 bytes)
;        i.e. W[i] lives at [rsp + i*4]
;
; REGISTER CONTRACT THROUGHOUT THE 64 ROUNDS (the single most important
; discipline in this file): the eight SHA-256 working variables a..h are kept
; in these registers and only these registers, so the round body never has to
; reload them and the state-update step is a clean set of moves:
;   r8d = a   r9d = b   r10d = c   r11d = d
;   r12d = e  r13d = f  r14d = g  r15d = h
; Scratch (may be freely clobbered inside a round): eax, edx, rbx.
; rcx is reserved as the round index and equals the word index into K/W.
; rsi/rbp point at the block/state as noted.
;
; INPUT REGISTERS (caller-provided, System V ABI):
;   rdi = state[8]  (big-endian hash words)
;   rsi = block[64] (big-endian message bytes)
; ============================================================================
global sha256_block
sha256_block:
    ; ----- prologue: set up a fixed frame base and preserve callee-saved ----
    push rbp
    mov  rbp, rsp           ; rbp = frame base, rsp is stable from here
    push rbx                ; (order after rbp: rbx,r12,r13,r14,r15)
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 256           ; reserve 256 bytes: W[0..63] = 64 words x 4 bytes

    ; ========================================================================
    ; PHASE 1: Build W[0..15] from the raw block bytes.
    ;   Each 4-byte window of the block is the big-endian representation of a
    ;   32-bit word. SHA-256 arithmetic is defined on 32-bit host words whose
    ;   byte order is big-endian, so we BSWAP each incoming word to get the
    ;   correct numeric value in the register. BSWAP converts between the on
    ;   -wire big-endian byte order and the little-endian x86 register value.
    ; ========================================================================
    xor ecx, ecx            ; word index i = 0..15
.fill:
    mov eax, [rsi + rcx*4]  ; load raw 4 block bytes (big-endian on the wire)
    bswap eax               ; convert to host register value
    mov [rsp + rcx*4], eax  ; store into W[i]
    inc ecx
    cmp ecx, 16
    jb  .fill               ; repeat through i = 15

    ; ========================================================================
    ; PHASE 2: Extend the schedule to W[16..63].
    ;   For i in [16,64),  W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16]
    ;   where (all on 32-bit words, additions mod 2^32):
    ;     s0(x) = ROTR(x,7)  ^ ROTR(x,18) ^ SHR(x,3)
    ;     s1(x) = ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10)
    ;   Each s-function is built by rotating/shifting one stored word into two
    ;   registers -- eax and edx -- and XORing the results, re-reading the
    ;   source from memory each time so we never need a third reg. The partial
    ;   sum is accumulated in ebx and written back to W[i].
    ; ========================================================================
    mov ecx, 16
.extend:
    ; ---- compute s1(W[i-2]) = ROTR^17 ^ ROTR^19 ^ SHR^10 into eax ----
    mov eax, [rsp + (rcx-2)*4]  ; load W[i-2]
    mov edx, eax                ; 2nd copy for the 2nd rotate
    ror eax, 17                 ; ROTR(x,17)
    ror edx, 19                 ; ROTR(x,19)
    xor eax, edx                ; combine first two terms
    mov edx, [rsp + (rcx-2)*4]  ; reload W[i-2] for the shift
    shr edx, 10                 ; SHR(x,10)
    xor eax, edx                ; eax = s1(W[i-2])
    mov ebx, eax                ; ebx = s1(W[i-2])  (start of running sum)
    ; ---- add W[i-7] ----
    add ebx, [rsp + (rcx-7)*4]
    ; ---- compute s0(W[i-15]) = ROTR^7 ^ ROTR^18 ^ SHR^3 into eax ----
    mov eax, [rsp + (rcx-15)*4] ; load W[i-15]
    mov edx, eax
    ror eax, 7                  ; ROTR(x,7)
    ror edx, 18                 ; ROTR(x,18)
    xor eax, edx
    mov edx, [rsp + (rcx-15)*4] ; reload for the shift
    shr edx, 3                  ; SHR(x,3)
    xor eax, edx                ; eax = s0(W[i-15])
    add ebx, eax                ; add into running sum
    ; ---- add W[i-16] and store the result back into W[i] ----
    add ebx, [rsp + (rcx-16)*4]
    mov [rsp + rcx*4], ebx      ; W[i] = s1+s7+s0+W[i-16]
    inc ecx
    cmp ecx, 64
    jb  .extend                 ; repeat through i = 63

    ; ========================================================================
    ; PHASE 3: Initialize the working variables a..h from the hash state.
    ;   Our register contract maps a..h onto r8d..r15d as documented above.
    ; ========================================================================
    mov r8d,  [rdi + 0]    ; a = H0
    mov r9d,  [rdi + 4]    ; b = H1
    mov r10d, [rdi + 8]    ; c = H2
    mov r11d, [rdi + 12]   ; d = H3
    mov r12d, [rdi + 16]   ; e = H4
    mov r13d, [rdi + 20]   ; f = H5
    mov r14d, [rdi + 24]   ; g = H6
    mov r15d, [rdi + 28]   ; h = H7

    ; ========================================================================
    ; PHASE 4: The 64 compression rounds.
    ;
    ; Per round we produce two values: T1 and T2.
    ;   T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i]
    ;   T2 = S0(a) + Maj(a,b,c)
    ; then shift the working register window right by one position while
    ; computing the new head-and-tail:
    ;   (h,g,f,e,d,c,b,a) <- (g,f,e,d+T1,c,b,a,T1+T2)
    ;
    ; TEMP REGISTER PLAN (avoids any push/pop or stack spill inside the loop):
    ;   eax, edx : build the sigma functions by rotating a single source word
    ;              via two copies and re-reading memory. Never hold live data.
    ;   rbx      : running accumulator for T1, and later holds T1 for the final
    ;              state update. Free again once T1 is consumed.
    ;   rcX      : round counter i, also the index into K[] and W[].
    ;
    ; The state update is done ONLY at the very end of the round, using the
    ; still-unmodified old values in r8d..r15d, so ordering is safe.
    ; ========================================================================
    xor ecx, ecx            ; round index i = 0..63

.round:
    ; ------------------------------------------------------------------------
    ; Compute T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i], accumulated in eax
    ; ------------------------------------------------------------------------
    ; -- S1(e) = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25) --
    mov eax, r12d           ; copy of e for the first rotate
    mov edx, r12d           ; copy of e for the second rotate
    ror eax, 6              ; ROTR(e,6)
    ror edx, 11             ; ROTR(e,11)
    xor eax, edx
    mov edx, r12d           ; reload e for the third rotate
    ror edx, 25             ; ROTR(e,25)
    xor eax, edx            ; eax = S1(e)
    add eax, r15d           ; eax = S1(e) + h           (h is r15d)

    ; -- Ch(e,f,g) = (e AND f) XOR (NOT e AND g) --
    mov edx, r12d           ; e
    and edx, r13d           ; e AND f  (f is r13d)
    mov ebx, r12d           ; e
    not ebx                 ; NOT e   (only low bits used)
    and ebx, r14d           ; NOT e AND g  (g is r14d)
    xor edx, ebx            ; edx = Ch(e,f,g)
    add eax, edx            ; eax = ... + Ch

    ; -- add K[i] and W[i] --
    lea rdx, [K256]         ; base address of the constant table
    add eax, [rdx + rcx*4]  ; eax += K[i]
    add eax, [rsp + rcx*4]  ; eax += W[i]
    mov rbx, rax            ; rbx = T1  (move out of the way for T2 work)

    ; ------------------------------------------------------------------------
    ; Compute T2 = S0(a) + Maj(a,b,c), result in eax
    ; ------------------------------------------------------------------------
    ; -- S0(a) = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22) --
    mov eax, r8d            ; copy of a for first rotate
    mov edx, r8d            ; copy of a for second rotate
    ror eax, 2              ; ROTR(a,2)
    ror edx, 13             ; ROTR(a,13)
    xor eax, edx
    mov edx, r8d            ; reload a for third rotate
    ror edx, 22             ; ROTR(a,22)
    xor eax, edx            ; eax = S0(a)

    ; -- Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c) --
    ; T1 is still in rbx and must survive; S0(a) is in eax (the future T2
    ; accumulator). To free a scratch register we spill T1 to the stack now
    ; and pop it back afterwards, keeping rsp balanced within the round.
    push rbx                ; spill T1 (rbx holds T1) onto the stack
    mov edx, r8d            ; a
    and edx, r9d            ; a AND b   (b is r9d)
    mov ebx, r8d            ; a  (rbx now free scratch)
    and ebx, r10d           ; a AND c   (c is r10d)
    xor edx, ebx            ; (a&b) XOR (a&c)
    mov ebx, r9d            ; b
    and ebx, r10d           ; b AND c
    xor edx, ebx            ; edx = Maj(a,b,c)
    add eax, edx            ; eax = S0(a) + Maj = T2
    pop rbx                 ; rbx = T1  (restore the spilled value)

    ; ------------------------------------------------------------------------
    ; State update: slide the working window right by one and set new head/tail
    ;   (h,g,f,e,d,c,b,a) <- (g, f, e, d+T1, c, b, a, T1+T2)
    ; Current live regs: eax = T2, rbx = T1, rcx = i, r8d..r15d = old a..h.
    ; Every destination reads only values that have not been rewritten yet,
    ; so the ordering below is dependency-safe.
    ; ------------------------------------------------------------------------
    add r11d, ebx           ; r11d = d + T1        (will become new e)
    mov r15d, r14d          ; h' = old g
    mov r14d, r13d          ; g' = old f
    mov r13d, r12d          ; f' = old e
    mov r12d, r11d          ; e' = d + T1
    mov r11d, r10d          ; d' = old c
    mov r10d, r9d           ; c' = old b
    mov r9d,  r8d           ; b' = old a
    add eax, ebx            ; a' = T1 + T2
    mov r8d, eax            ; store T1+T2 into a

    inc ecx                 ; advance to the next round
    cmp ecx, 64
    jb  .round              ; continue while i < 64

    ; ========================================================================
    ; PHASE 5: Fold the working state back into the running hash state.
    ;   Per the spec, H[i] += working[i] over all 8 words. The values are
    ;   stored back into the caller's state buffer (still pointed to by rdi),
    ;   still in big-endian word form (the caller BSWAPs on digest emission).
    ; ========================================================================
    add [rdi + 0],  r8d     ; H0 += a
    add [rdi + 4],  r9d     ; H1 += b
    add [rdi + 8],  r10d    ; H2 += c
    add [rdi + 12], r11d    ; H3 += d
    add [rdi + 16], r12d    ; H4 += e
    add [rdi + 20], r13d    ; H5 += f
    add [rdi + 24], r14d    ; H6 += g
    add [rdi + 28], r15d    ; H7 += h

    ; ----- epilogue: tear down the frame in the exact reverse order -----
    add rsp, 256            ; release the W[] schedule buffer
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ============================================================================
; void sha256_full(u8 out[32], const void *msg, i64 len)
;   One-shot SHA-256 over a message of arbitrary length. Handles the required
;   padding and the 64-bit big-endian bit-length field, then produces the
;   32-byte digest in out[] (big-endian bytes, ready for Bitcoin use).
;
; PADDING RULE (FIPS 180-4):
;   Append a 0x80 byte, then zero bytes until the length is 56 mod 64, then
;   append the original message length in BITS as a 64-bit big-endian integer.
;   If the 0x80+zeros do not fit in the current final block, one extra all-
;   -zero block carrying only the length is emitted.
;
; INPUT REGISTERS (System V): rdi=out, rsi=msg, rdx=len
; ============================================================================
global sha256_full
sha256_full:
    ; ------------------------------------------------------------------------
    ; PROLOGUE / FRAME
    ;   We must survive calling sha256_init and sha256_block, which clobber
    ;   all caller-saved registers. We therefore park everything we still need
    ;   in callee-saved registers (which those calls promise to preserve):
    ;     r15 = out pointer        (caller's rdi)
    ;     rbx = current msg position
    ;     r14 = total byte length  (for the bit-length field)
    ;     r13 = bytes still unprocessed
    ;   Stack layout (rsp is 8 mod 16 after prologue, satisfying the ABI):
    ;     [rsp+0 .. rsp+31]  = running hash state H[0..7]
    ;     [rsp+32.. rsp+95]  = 64-byte work block (final padded block)
    ; ------------------------------------------------------------------------
    push rbp
    mov  rbp, rsp           ; rbp = stable frame base
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 136           ; 32B state + 64B work block + 8B pad. 6 pushes pushed
                            ; RSP to 8 mod16; sub 136 (8 mod16) -> RSP 0 mod16 so
                            ; the nested calls (sha256_init/sha256_block) happen at
                            ; ABI-correct RSP 0 mod16.

    mov r15, rdi            ; r15 = out[] (survives all calls)
    mov rbx, rsi            ; rbx = msg pointer
    mov r14, rdx            ; r14 = total length in bytes
    mov r13, rdx            ; r13 = remaining byte count

    ; initialize the running hash state to H0..H7
    mov rdi, rsp            ; state buffer lives at [rsp]
    call sha256_init

    ; ========================================================================
    ; STEP A: consume and compress every full 64-byte block of the message,
    ; advancing the message pointer until fewer than 64 bytes remain. r15, rbx,
    ; r13, r14 are all callee-saved so they survive the sha256_block calls.
    ; ========================================================================
.blocks:
    cmp r13, 64
    jb  .padrun             ; < 64 bytes remain -> build the final block(s)
    ; copy the next 64 message bytes into the work block at [rsp+32]
    lea rdi, [rsp+32]       ; destination buffer
    mov rsi, rbx            ; source = current position in msg
    mov rcx, 64
    rep movsb               ; copy 64 bytes into the work buffer
    ; compress that block into the running state
    mov rdi, rsp            ; state = [rsp]
    lea rsi, [rsp+32]       ; block = [rsp+32]
    call sha256_block
    add rbx, 64             ; advance past the block just consumed
    sub r13, 64             ; 64 fewer bytes remaining
    jmp .blocks

    ; ========================================================================
    ; STEP B: build the final padded block and compress it.
    ; Correct SHA-256 last-block layout (at least 9 bytes beyond the data):
    ;   [data... | 0x80 | 00..00 | <64-bit BE bit-length>]
    ; If data + 0x80 already reaches past byte 56, the 8-byte length does not
    ; fit; we then compress the block as-is and emit one extra all-zero block
    ; that carries only the length.
    ; ========================================================================
.padrun:
    lea rdi, [rsp+32]       ; work block buffer
    ; 1) copy the remaining r13 message bytes into the work block
    mov rsi, rbx
    mov rcx, r13
    rep movsb
    ; 2) write the 0x80 terminator byte right after the data.
    ;    NOTE: rep movsb advanced rdi past the copied bytes, so rdi now points
    ;    exactly one byte beyond the data -- the correct home for 0x80.
    mov byte [rdi], 0x80
    ; 3) zero-fill the rest of the block (bytes after the 0x80 up to 63)
    lea rdi, [rsp+32]
    mov rax, r13            ; offset of the 0x80 byte
    lea rdi, [rdi + rax + 1] ; start clearing just past the 0x80
    xor eax, eax
    mov rcx, 63
    sub rcx, r13            ; number of bytes from 0x80+1 .. byte 63 inclusive
    rep stosb

    ; if r13 >= 56 the 8-byte length field has no room in this block
    cmp r13, 56
    jb  .lastblock
    ; compress the fully-padded block that has no room for the length
    mov rdi, rsp
    lea rsi, [rsp+32]
    call sha256_block
    ; switch to a fresh all-zero block that will hold only the length
    lea rdi, [rsp+32]
    xor eax, eax
    mov rcx, 64
    rep stosb

.lastblock:
    ; write the message length in BITS as a 64-bit big-endian integer into
    ; bytes [56..63]. For any realistic message (< 2^61 bytes) the value fits,
    ; and BSWAP produces the correct big-endian 8-byte encoding of len*8.
    mov rax, r14
    shl rax, 3              ; bytes -> bits
    bswap rax               ; little-endian register -> big-endian wire bytes
    lea rdi, [rsp+32]
    mov [rdi + 56], rax     ; store the 8-byte length (bytes 56..63)
    ; compress this final block into the running state
    mov rdi, rsp
    lea rsi, [rsp+32]
    call sha256_block

    ; ========================================================================
    ; STEP C: emit the 32-byte digest. Each hash word is little-endian in the
    ; register; we BSWAP to big-endian wire bytes before storing into out[]
    ; (caller's pointer kept in r15 across all the calls above).
    ; ========================================================================
    mov rsi, rsp            ; state base
    xor ecx, ecx            ; word index 0..7
.emit:
    mov eax, [rsi + rcx*4]  ; load one hash word
    bswap eax               ; convert to big-endian
    mov [r15 + rcx*4], eax  ; store into caller's out[]
    inc ecx
    cmp ecx, 8
    jb  .emit

    ; ----- epilogue: release frame and restore callee-saved registers -----
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; Mark the stack as non-executable so the linker does not warn and the final
; binary does not carry an executable-stack flag. Security-relevant: crypto
; code must not run from data pages.
; ----------------------------------------------------------------------------
section .note.GNU-stack noalloc noexec nowrite progbits

