; ============================================================================
; bitcoin_muhash.asm -- MuHash3072, the multiset hash Bitcoin Core's
; `gettxoutsetinfo muhash` (and its `coinstatsindex`) reports over the UTXO
; set. Byte-for-byte compatible with Core's `MuHash3072` / `Num3072`
; (src/crypto/muhash.cpp) -- that compatibility is the entire point: this
; exists so our LSM UTXO set can be compared against Core's chainstate at a
; stated height with a single 32-byte value.
;
; WHY MuHash AND NOT hash_serialized_3 (recorded here because the choice is
; not obvious and the reasoning is load-bearing):
;
;   1. GROUND TRUTH AVAILABILITY. `gettxoutsetinfo hash_serialized_3 <height>`
;      is REFUSED by Core -- "hash_serialized_3 hash type cannot be queried
;      for a specific block" (rpc/blockchain.cpp). Only `muhash` is answerable
;      at an arbitrary height, because only `muhash` is what `coinstatsindex`
;      stores. Our replay is never at the oracle's tip, so hash_serialized_3
;      would have had NO ground truth to compare against.
;
;   2. ITERATION ORDER. hash_serialized_3 is order-dependent: Core hashes
;      coins grouped by txid in leveldb key order, and WITHIN a txid in
;      NUMERIC output-index order (ComputeUTXOStats buffers a
;      std::map<uint32_t, Coin>, which re-sorts numerically regardless of the
;      VARINT-encoded db key order). Our LSM's merge order is `mac_cmp_key`,
;      which compares the index field as a `bswap`ed NATIVE-ENDIAN u32 -- i.e.
;      memcmp over little-endian bytes. That agrees with numeric order only
;      for index < 256: key index 256 (00 01 00 00) sorts BEFORE index 1
;      (01 00 00 00). Any transaction with >=256 simultaneously-live outputs
;      -- routine for pool payout transactions -- would therefore have been
;      hashed in the wrong order, producing a mismatch indistinguishable from
;      a data bug. MuHash is a MULTISET hash: order-independent, so this class
;      of failure cannot occur at all.
;
;   The cost is 3072-bit modular arithmetic, which is what this file is.
;
; ---- what a MuHash is ----
; Modulus p = 2^3072 - 1103717 (the largest 3072-bit safe prime). Each set
; element is mapped to a residue by
;     ToNum3072(data) = LE-u64-limbs( ChaCha20-keystream(384 bytes,
;                                        key = SHA256(data), nonce=0, ctr=0) )
; and the set's hash is the product of all its elements' residues mod p.
; Multiplication is commutative and associative, so:
;   - insertion order does not matter (this is the property we want), and
;   - the work is shardable: hash disjoint subsets independently and combine
;     the accumulators with muhash_combine.
;
; Core's MuHash3072 carries a numerator and a denominator so it can also
; REMOVE elements. This node only ever inserts (a UTXO-set snapshot is built
; by insertion), so the denominator is permanently 1 and is not represented
; here at all. That is not a shortcut with a hidden behavioural difference:
; Core's Finalize() computes numerator/denominator, and dividing by 1 is
; `Multiply(GetInverse(1))` == `Multiply(1)`. muhash_finalize below performs
; exactly that Multiply(1) (which is NOT a no-op -- it carries Core's two
; reduction passes and the conditional FullReduce, so the canonical form is
; identical) before hashing. The consequence worth stating: this module needs
; NO modular inverse, so Core's safegcd GetInverse is not reimplemented.
;
; ---- accumulator representation (`acc`) ----
; 384 bytes = 48 little-endian u64 limbs, limb 0 least significant. This is
; byte-identical to Core's `Num3072::limbs` on x86-64 and to what
; `Num3072::ToBytes` writes, so an accumulator can be memcmp'd against Core's
; directly. The caller owns the storage; muhash_init sets it to 1.
;
; Exports (System V AMD64):
;   void muhash_init(void* acc)
;   void muhash_insert(void* acc, const void* data, unsigned long len)
;   void muhash_combine(void* acc, const void* other_acc)
;   void muhash_finalize(unsigned char out[32], const void* acc)
;   void muhash_to_num3072(void* out384, const void* data, unsigned long len)
;   void num3072_mul(void* a, const void* b)        ; a = a*b mod p
;   void num3072_set_one(void* a)
;   long num3072_is_overflow(const void* a)         ; 1 / 0
;   void num3072_full_reduce(void* a)
;   void chacha20_keystream_k0(void* out, unsigned long blocks,
;                              const unsigned char key[32])
;
; The last five are exported for the differential tests (tests/test_muhash.c
; checks each layer against vectors generated from Core's own code by
; validation/gen_muhash_vectors.py), not because any caller needs them.
;
; FRAME RULE (ENGINEERING_RULES.md 6 / 6b): callee-saved registers are pushed
; BEFORE `push rbp`, so the save area sits at [rbp+8..] where no [rbp-N] local
; can ever alias it. Entry RSP is 8 mod 16; six pushes leave it at 8 mod 16;
; every frame reservation below is therefore 8 mod 16 so RSP is 0 mod 16 at
; every `call`. Computed, not eyeballed.
; ============================================================================
default rel

extern sha256_full

; 2^3072 - MAX_PRIME_DIFF is the modulus; MAX_PRIME_DIFF fits in an imm32,
; which is why every multiply-by-modulus-difference below can use the
; three-operand `imul r64, r/m64, imm32` form.
MAX_PRIME_DIFF equ 1103717
NLIMBS         equ 48
NBYTES         equ 384

; ChaCha20 quarter-round on the 16-word working state based at rbx.
; Clobbers eax/edx only, so it composes with whatever the caller holds
; elsewhere (r12=out, r13=blocks, r14=key, r15=initial state).
%macro QROUND 4
    mov  eax, [rbx+%1*4]
    add  eax, [rbx+%2*4]
    mov  [rbx+%1*4], eax
    mov  edx, [rbx+%4*4]
    xor  edx, eax
    rol  edx, 16
    mov  [rbx+%4*4], edx

    mov  eax, [rbx+%3*4]
    add  eax, edx
    mov  [rbx+%3*4], eax
    mov  edx, [rbx+%2*4]
    xor  edx, eax
    rol  edx, 12
    mov  [rbx+%2*4], edx

    mov  eax, [rbx+%1*4]
    add  eax, edx
    mov  [rbx+%1*4], eax
    mov  edx, [rbx+%4*4]
    xor  edx, eax
    rol  edx, 8
    mov  [rbx+%4*4], edx

    mov  eax, [rbx+%3*4]
    add  eax, edx
    mov  [rbx+%3*4], eax
    mov  edx, [rbx+%2*4]
    xor  edx, eax
    rol  edx, 7
    mov  [rbx+%2*4], edx
%endmacro

section .rodata
align 16
; ChaCha20's "expand 32-byte k" constants, as four LE u32 words.
chacha_sigma:  dd 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

section .text

; ============================================================================
; num3072_set_one(a=rdi) -- a = 1. Leaf, no frame.
; ============================================================================
global num3072_set_one
num3072_set_one:
    mov  qword [rdi], 1
    xor  eax, eax
    mov  ecx, 1
.loop:
    cmp  ecx, NLIMBS
    jae  .done
    mov  [rdi+rcx*8], rax
    inc  ecx
    jmp  .loop
.done:
    ret

; ============================================================================
; muhash_init(acc=rdi) -- the empty set is the multiplicative identity.
; ============================================================================
global muhash_init
muhash_init:
    jmp  num3072_set_one

; ============================================================================
; num3072_is_overflow(a=rdi) -> rax = 1 if a >= modulus, else 0
;   Mirrors Num3072::IsOverflow(): a value is "overflown" exactly when every
;   limb above 0 is all-ones AND limb 0 is > 2^64-1-MAX_PRIME_DIFF, i.e. when
;   a >= 2^3072 - MAX_PRIME_DIFF = the modulus.
;   Leaf, no frame. Clobbers rax/rcx only -- num3072_mul relies on that.
; ============================================================================
global num3072_is_overflow
num3072_is_overflow:
    mov  rax, [rdi]
    mov  rcx, -1
    sub  rcx, MAX_PRIME_DIFF        ; rcx = MAX_LIMB - MAX_PRIME_DIFF
    cmp  rax, rcx
    jbe  .no
    mov  ecx, 1
.loop:
    cmp  ecx, NLIMBS
    jae  .yes
    mov  rax, [rdi+rcx*8]
    cmp  rax, -1
    jne  .no
    inc  ecx
    jmp  .loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ============================================================================
; num3072_full_reduce(a=rdi) -- a -= modulus, i.e. a += MAX_PRIME_DIFF taken
;   mod 2^3072 (Core's Num3072::FullReduce). Correct only where Core calls it:
;   when a is known to be >= the modulus, or when the second reduction pass of
;   Multiply carried out of the top limb.
;   Leaf, no frame. Clobbers rax(no)/rcx/r8/r9/r10.
; ============================================================================
global num3072_full_reduce
num3072_full_reduce:
    mov  r8, MAX_PRIME_DIFF         ; c0
    xor  r9d, r9d                    ; c1
    xor  ecx, ecx
.loop:
    cmp  ecx, NLIMBS
    jae  .done
    ; addnextract2(c0, c1, a[i], a[i])
    xor  r10d, r10d                  ; c2
    add  r8, [rdi+rcx*8]
    adc  r9, 0
    adc  r10, 0                       ; c2 becomes 1 only if c1 itself wrapped
    mov  [rdi+rcx*8], r8
    mov  r8, r9
    mov  r9, r10
    inc  ecx
    jmp  .loop
.done:
    ret

; ============================================================================
; num3072_mul(a=rdi, b=rsi) -- a = a*b mod (2^3072 - MAX_PRIME_DIFF)
;
;   A direct transcription of Core's Num3072::Multiply: a schoolbook 48x48
;   limb product accumulated straight into reduced form, using the identity
;   2^3072 == MAX_PRIME_DIFF (mod p) to fold the high half back down as it is
;   produced, then a second reduction pass over the 48-limb intermediate.
;   Core's helpers (muladd3, mulnadd3, extract3, muln2, addnextract2) are each
;   two to five instructions and are inlined here rather than called.
;
;   Registers: rdi=a rsi=b  c=[r8,r9,r10]  d=[r11,r12,r13]  r14=j  r15=count
;              rbx/rcx = walking limb pointers, rax/rdx = the multiplier pair.
;   Locals (frame 0x198 = 408 bytes, all at [rsp+0 .. rsp+407], strictly below
;   the save area at [rbp+8..]):
;              [rsp+0]        &tmp[0]
;              [rsp+8]        a (reloaded after the reduction helpers)
;              [rsp+16 .. +399] tmp[48]  (Core's `tmp`)
;   Frame parity: entry 8 mod 16, six pushes -> 8 mod 16, 0x198 is 8 mod 16
;   -> RSP is 0 mod 16 at the two calls below.
; ============================================================================
global num3072_mul
num3072_mul:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x198
    lea  rax, [rsp+16]
    mov  [rsp], rax                  ; &tmp[0]
    mov  [rsp+8], rdi                 ; a

    xor  r8d, r8d                    ; c0
    xor  r9d, r9d                    ; c1
    xor  r10d, r10d                  ; c2
    xor  r14d, r14d                  ; j = 0

.j_loop:
    cmp  r14, NLIMBS-1
    jae  .j_done

    ; ---- d = a[1+j] * b[47] ------------------------------------------------
    mov  rax, [rdi+r14*8+8]          ; a[1+j]
    mul  qword [rsi+(NLIMBS-1)*8]    ; b[47]
    mov  r11, rax                    ; d0
    mov  r12, rdx                    ; d1
    xor  r13d, r13d                  ; d2

    ; ---- for i = 2+j .. 47: d += a[i] * b[48+j-i] --------------------------
    ;   The b index at i = 2+j is 46 for EVERY j (48+j-(2+j)); it then walks
    ;   down to 1+j while the a index walks up to 47. Count = 46-j.
    lea  rbx, [rdi+r14*8+16]         ; &a[2+j]
    lea  rcx, [rsi+(NLIMBS-2)*8]     ; &b[46]
    mov  r15, NLIMBS-2               ; 46
    sub  r15, r14                     ; 46 - j
.d_loop:
    test r15, r15
    jz   .d_done
    mov  rax, [rbx]
    mul  qword [rcx]
    add  r11, rax
    adc  r12, rdx
    adc  r13, 0
    add  rbx, 8
    sub  rcx, 8
    dec  r15
    jmp  .d_loop
.d_done:

    ; ---- mulnadd3(c, d, MAX_PRIME_DIFF): [c0,c1,c2] = n*[d0,d1,d2] + [c0,c1]
    ;      (c2 is 0 on entry here, exactly as Core asserts) ------------------
    mov  rcx, MAX_PRIME_DIFF
    mov  rax, r11
    mul  rcx                          ; rdx:rax = d0*n
    add  rax, r8
    adc  rdx, 0
    mov  r8, rax                      ; c0
    mov  rbx, rdx                     ; carry into the next limb
    mov  rax, r12
    mul  rcx                          ; rdx:rax = d1*n
    add  rax, rbx
    adc  rdx, 0
    add  rax, r9
    adc  rdx, 0
    mov  r9, rax                      ; c1
    imul r13, r13, MAX_PRIME_DIFF     ; d2*n, low 64 -- Core truncates here too
    lea  r10, [r13+rdx]               ; c2 = d2*n + carry

    ; ---- for i = 0 .. j: c += a[i] * b[j-i] --------------------------------
    mov  rbx, rdi                     ; &a[0]
    lea  rcx, [rsi+r14*8]             ; &b[j]
    lea  r15, [r14+1]                 ; count = j+1 (always >= 1)
.c_loop:
    mov  rax, [rbx]
    mul  qword [rcx]
    add  r8, rax
    adc  r9, rdx
    adc  r10, 0
    add  rbx, 8
    sub  rcx, 8
    dec  r15
    jnz  .c_loop

    ; ---- extract3: tmp[j] = c0; shift c down one limb ---------------------
    mov  rbx, [rsp]
    mov  [rbx+r14*8], r8
    mov  r8, r9
    mov  r9, r10
    xor  r10d, r10d

    inc  r14
    jmp  .j_loop
.j_done:

    ; ---- top limb: for i = 0..47: c += a[i]*b[47-i]; tmp[47] = c0 ---------
    mov  rbx, rdi                     ; &a[0]
    lea  rcx, [rsi+(NLIMBS-1)*8]      ; &b[47]
    mov  r15, NLIMBS
.t_loop:
    mov  rax, [rbx]
    mul  qword [rcx]
    add  r8, rax
    adc  r9, rdx
    adc  r10, 0
    add  rbx, 8
    sub  rcx, 8
    dec  r15
    jnz  .t_loop
    mov  rbx, [rsp]
    mov  [rbx+(NLIMBS-1)*8], r8
    mov  r8, r9
    mov  r9, r10
    xor  r10d, r10d

    ; ---- second reduction: muln2(c0,c1,n), then fold tmp[] back into a[] ---
    mov  rcx, MAX_PRIME_DIFF
    mov  rax, r8
    mul  rcx                          ; rdx:rax = c0*n
    mov  r8, rax
    mov  rbx, rdx
    imul r9, r9, MAX_PRIME_DIFF       ; c1*n, low 64 (Core truncates)
    add  r9, rbx

    mov  r11, [rsp]                   ; &tmp[0]
    xor  ecx, ecx
.r_loop:
    cmp  ecx, NLIMBS
    jae  .r_done
    ; addnextract2(c0, c1, tmp[i], a[i])
    xor  r10d, r10d
    add  r8, [r11+rcx*8]
    adc  r9, 0
    adc  r10, 0
    mov  [rdi+rcx*8], r8
    mov  r8, r9
    mov  r9, r10
    inc  ecx
    jmp  .r_loop
.r_done:
    ; Core's post-conditions here are c1 == 0 and c0 in {0,1}; c0 is the carry
    ; out of the top limb, and means "one more modulus fits".
    mov  r14, r8                      ; stash that carry across the calls

    mov  rdi, [rsp+8]
    call num3072_is_overflow
    test rax, rax
    jz   .no_ovf
    mov  rdi, [rsp+8]
    call num3072_full_reduce
.no_ovf:
    test r14, r14
    jz   .no_carry
    mov  rdi, [rsp+8]
    call num3072_full_reduce
.no_carry:
    add  rsp, 0x198
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; chacha20_keystream_k0(out=rdi, blocks=rsi, key=rdx)
;   RFC 8439 ChaCha20 keystream, 64 bytes per block, with a 96-bit nonce of
;   zero and the block counter starting at 0 -- precisely
;   `ChaCha20Aligned{key}.Keystream(...)` in Core, which is how MuHash expands
;   a 32-byte SHA256 into a 384-byte Num3072.
;
;   State words: x0..x3 = sigma, x4..x11 = key (LE u32), x12 = counter,
;   x13..x15 = nonce (zero here). One call per set element, six blocks, so the
;   scalar form is preferred over a vectorised one for auditability against
;   the reference.
;
;   Frame 0x88 = 136 (8 mod 16 -> RSP 0 mod 16 at any call; there are none):
;     [rbp-0x88]           round counter
;     [rbp-0x80 .. -0x41]  j[16], the initial state (survives across blocks)
;     [rbp-0x40 .. -0x01]  x[16], the working state
; ============================================================================
global chacha20_keystream_k0
chacha20_keystream_k0:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x88

    mov  r12, rdi                     ; out
    mov  r13, rsi                     ; blocks
    mov  r14, rdx                     ; key

    ; ---- build the initial state j[16] ----
    lea  r15, [rbp-0x80]
    lea  rbx, [rel chacha_sigma]
    mov  ecx, [rbx]
    mov  [r15+0], ecx
    mov  ecx, [rbx+4]
    mov  [r15+4], ecx
    mov  ecx, [rbx+8]
    mov  [r15+8], ecx
    mov  ecx, [rbx+12]
    mov  [r15+12], ecx
    xor  ecx, ecx
.k_copy:
    cmp  ecx, 8
    jae  .k_copied
    mov  eax, [r14+rcx*4]
    mov  [r15+16+rcx*4], eax
    inc  ecx
    jmp  .k_copy
.k_copied:
    mov  dword [r15+48], 0            ; block counter
    mov  dword [r15+52], 0            ; nonce word 0
    mov  dword [r15+56], 0            ; nonce word 1
    mov  dword [r15+60], 0            ; nonce word 2

.block_loop:
    test r13, r13
    jz   .ks_done
    lea  rbx, [rbp-0x40]              ; x = j
    xor  ecx, ecx
.st_copy:
    cmp  ecx, 16
    jae  .st_copied
    mov  eax, [r15+rcx*4]
    mov  [rbx+rcx*4], eax
    inc  ecx
    jmp  .st_copy
.st_copied:

    mov  qword [rbp-0x88], 10
.round_loop:
    QROUND 0,4,8,12
    QROUND 1,5,9,13
    QROUND 2,6,10,14
    QROUND 3,7,11,15
    QROUND 0,5,10,15
    QROUND 1,6,11,12
    QROUND 2,7,8,13
    QROUND 3,4,9,14
    dec  qword [rbp-0x88]
    jnz  .round_loop

    ; out = x + j (LE u32 each), then advance the counter with the same
    ; 32->64-bit carry Core performs (`++j12; if (!j12) ++j13;`).
    xor  ecx, ecx
.add_out:
    cmp  ecx, 16
    jae  .add_done
    mov  eax, [rbx+rcx*4]
    add  eax, [r15+rcx*4]
    mov  [r12+rcx*4], eax
    inc  ecx
    jmp  .add_out
.add_done:
    mov  eax, [r15+48]
    inc  eax
    mov  [r15+48], eax
    test eax, eax
    jnz  .no_ctr_carry
    mov  eax, [r15+52]
    inc  eax
    mov  [r15+52], eax
.no_ctr_carry:
    add  r12, 64
    dec  r13
    jmp  .block_loop
.ks_done:
    add  rsp, 0x88
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; muhash_to_num3072(out384=rdi, data=rsi, len=rdx)
;   Core's MuHash3072::ToNum3072: SHA256 the element, use the digest as a
;   ChaCha20 key, take 384 bytes of keystream as 48 LE u64 limbs. The limbs
;   ARE those keystream bytes on a little-endian machine, so there is no
;   conversion step -- the keystream is written straight into out384.
;
;   Frame 0x38 = 56 (8 mod 16 -> RSP 0 mod 16 at both calls).
;   [rbp-0x20 .. -0x01] holds the digest; the save area is at [rbp+8..].
; ============================================================================
global muhash_to_num3072
muhash_to_num3072:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x38
    mov  rbx, rdi                     ; out384
    lea  rdi, [rbp-0x20]              ; digest out; msg/len already in rsi/rdx
    call sha256_full
    mov  rdi, rbx
    mov  esi, NBYTES/64               ; 6 blocks = 384 bytes
    lea  rdx, [rbp-0x20]
    call chacha20_keystream_k0
    add  rsp, 0x38
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; muhash_insert(acc=rdi, data=rsi, len=rdx)
;   acc *= ToNum3072(data)   -- Core's MuHash3072::Insert.
;   Frame 0x198 = 408 (8 mod 16 -> RSP 0 mod 16 at both calls); the 384-byte
;   element residue occupies [rbp-0x190 .. rbp-0x11].
; ============================================================================
global muhash_insert
muhash_insert:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x198
    mov  rbx, rdi                     ; acc
    lea  r12, [rbp-0x190]             ; element residue scratch (384 bytes)
    mov  rdi, r12                     ; data/len stay in rsi/rdx
    call muhash_to_num3072
    mov  rdi, rbx
    mov  rsi, r12
    call num3072_mul
    add  rsp, 0x198
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; muhash_combine(acc=rdi, other=rsi) -- acc *= other.
;   The union of two disjointly-hashed shards. This is what makes a sharded or
;   threaded set hash legal: MuHash's group operation IS this product, so
;   combining per-shard accumulators equals hashing the union.
; ============================================================================
global muhash_combine
muhash_combine:
    jmp  num3072_mul

; ============================================================================
; muhash_finalize(out32=rdi, acc=rsi)
;   Core's MuHash3072::Finalize with the denominator known to be 1:
;     numerator.Divide(1)  ==  { if IsOverflow FullReduce;
;                                Multiply(1);
;                                if IsOverflow FullReduce; }
;     out = SHA256(numerator.ToBytes())      <- SINGLE SHA256, not SHA256d
;   `acc` is NOT modified: the reduction runs on a local copy, so a caller can
;   finalize a running accumulator and keep inserting into it afterwards.
;
;   Frame 0x398 = 920 (8 mod 16 -> RSP 0 mod 16 at every call):
;     [rbp-0x320 .. -0x1A1]  the constant 1   (384 bytes)
;     [rbp-0x190 .. -0x011]  the working copy (384 bytes)
;   The two ranges do not overlap and both sit strictly below the save area.
; ============================================================================
global muhash_finalize
muhash_finalize:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x398
    mov  rbx, rdi                     ; out32
    lea  r12, [rbp-0x190]             ; working copy of acc
    lea  r13, [rbp-0x320]             ; the constant 1

    xor  ecx, ecx
.fc_copy:
    cmp  ecx, NLIMBS
    jae  .fc_copied
    mov  rax, [rsi+rcx*8]
    mov  [r12+rcx*8], rax
    inc  ecx
    jmp  .fc_copy
.fc_copied:

    mov  rdi, r13
    call num3072_set_one

    mov  rdi, r12
    call num3072_is_overflow
    test rax, rax
    jz   .fc_no_pre
    mov  rdi, r12
    call num3072_full_reduce
.fc_no_pre:
    mov  rdi, r12
    mov  rsi, r13
    call num3072_mul
    mov  rdi, r12
    call num3072_is_overflow
    test rax, rax
    jz   .fc_no_post
    mov  rdi, r12
    call num3072_full_reduce
.fc_no_post:
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, NBYTES
    call sha256_full

    add  rsp, 0x398
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; SECURITY (audit 2026-08-29 finding 9): without this note the linker
; conservatively marks the whole program's stack EXECUTABLE (PT_GNU_STACK
; RWE). Nothing here needs a runnable stack; a single object missing the
; note is enough to turn it on for the entire binary, which is why every
; .asm file carries it.
section .note.GNU-stack noalloc noexec nowrite progbits
