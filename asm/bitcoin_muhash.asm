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
;   void num3072_mul_ifma(void* a, const void* b)   ; the AVX-512 IFMA body
;   void num3072_mul_adx(void* a, const void* b)    ; the BMI2/ADX body
;   void num3072_mul_generic(void* a, const void* b); the mul/adc body
;   void num3072_mul_force_path(int p)              ; test seam, see below
;   int  num3072_mul_current_path(void)
;   int  num3072_cpu_has_adx(void)
;   int  num3072_cpu_has_ifma(void)
;   void num3072_set_one(void* a)
;   long num3072_is_overflow(const void* a)         ; 1 / 0
;   void num3072_full_reduce(void* a)
;   void chacha20_keystream_k0(void* out, unsigned long blocks,
;                              const unsigned char key[32])
;
; num3072_mul is a CPU dispatcher over three bit-identical bodies (see it for
; the probes and the seam). Everything from num3072_mul_ifma down is exported
; for the differential tests (tests/test_muhash.c checks each layer against
; vectors generated from Core's own code by validation/gen_muhash_vectors.py;
; tests/test_muhash_mul_diff.c holds the bodies to each other), not because
; any caller needs them.
;
; FRAME RULE (ENGINEERING_RULES.md 6 / 6b): callee-saved registers are pushed
; BEFORE `push rbp`, so the save area sits at [rbp+8..] where no [rbp-N] local
; can ever alias it. Entry RSP is 8 mod 16; six pushes leave it at 8 mod 16;
; every frame reservation below is therefore 8 mod 16 so RSP is 0 mod 16 at
; every `call`. Computed, not eyeballed. The exceptions are num3072_mul_adx
; and num3072_fold_adx, which use no callee-saved register and push only rbp
; (one push leaves RSP at 0 mod 16, so THEIR reservations are 0 mod 16), and
; num3072_mul_ifma, which pushes three (four with rbp: 8 mod 16, so its
; reservation is 8 mod 16); each states its own arithmetic.
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
;   Dispatcher. Three bodies compute this product, bit-identical to each
;   other and to Core's Num3072::Multiply (the identity argument is written
;   out at num3072_mul_adx; tests/test_muhash_mul_diff.c holds them to it):
;     num3072_mul_ifma     -- AVX-512 IFMA: 52-bit limbs, vpmadd52luq/huq
;                             column sums, then the shared fold. Taken when
;                             the CPU has AVX512F + AVX512IFMA (+ BMI2/ADX
;                             for the fold) AND the OS has enabled ZMM state.
;     num3072_mul_adx      -- BMI2/ADX: mulx with two carry chains (adcx and
;                             adox), a full 48x48 -> 96-limb product, then
;                             the modulus fold. Taken when CPUID reports BOTH
;                             BMI2 and ADX but not the IFMA set.
;     num3072_mul_generic  -- the mul/adc limb loop, Core's algorithm
;                             transcribed. The fallback, and what the daemon
;                             ran before the other bodies existed.
;   Lazy one-time CPUID probe, cached in num3072_mul_path exactly like
;   sha256.asm's shani_ready: 0 = not probed yet, 1 = ADX body, 2 = generic
;   (cached too, so an absent configuration never re-probes), 3 = IFMA body.
;   The probes are CPUID.(EAX=7,ECX=0):EBX -- bit 8 (BMI2), bit 19 (ADX),
;   bit 16 (AVX512F), bit 21 (AVX512IFMA) -- gated on the max basic leaf,
;   plus OSXSAVE and XGETBV for the IFMA body: the same leaf-7 shape
;   sha256_cpu_has_sha has had since CRY-1, where a leaf-1 probe once
;   selected SHA-NI on CPUs without it and SIGILL'd on the first hash.
;   Tail-jumps only: rdi/rsi are untouched, so the body sees the caller's
;   arguments.
; ============================================================================
global num3072_mul
num3072_mul:
    movzx eax, byte [rel num3072_mul_path]
    test al, al
    jz   .probe
    cmp  al, 3
    je   .ifma
    cmp  al, 1
    jne  .generic                     ; 2 (or any other value) -> generic
    jmp  num3072_mul_adx
.ifma:
    jmp  num3072_mul_ifma
.probe:
    push rbx                          ; CPUID clobbers EBX, a callee-saved reg
    call num3072_cpu_has_ifma
    pop  rbx
    test eax, eax
    jz   .probe_adx
    mov  byte [rel num3072_mul_path], 3
    jmp  num3072_mul_ifma
.probe_adx:
    push rbx
    call num3072_cpu_has_adx
    pop  rbx
    mov  byte [rel num3072_mul_path], 2   ; default: absent (cached)
    test eax, eax
    jz   .generic
    mov  byte [rel num3072_mul_path], 1
    jmp  num3072_mul_adx
.generic:
    jmp  num3072_mul_generic

; ============================================================================
; num3072_mul_force_path(p=edi) / num3072_mul_current_path() -> eax
;   Test-only seam, sha256_force_path's twin:
;     p = 0 -> re-probe on the next call (the normal, unprobed state)
;     p = 1 -> num3072_mul_adx
;     p = 2 -> num3072_mul_generic
;     p = 3 -> num3072_mul_ifma
;   WHY IT EXISTS. The probe runs once and every multiply in the process then
;   takes one body. On a host with IFMA -- the gate box -- the ADX and the
;   generic bodies, which every other CPU depends on, would otherwise never
;   execute under `make test`; on a host without it the IFMA body would not.
;   With the seam tests/test_muhash runs Core's vectors down every body the
;   CPU can run, and tests/test_muhash_mul_diff compares the bodies to each
;   other. Nothing in the daemon calls it; 0/unprobed is what production
;   sees.
; ============================================================================
global num3072_mul_force_path
num3072_mul_force_path:
    mov  byte [rel num3072_mul_path], dil
    ret

global num3072_mul_current_path
num3072_mul_current_path:
    movzx eax, byte [rel num3072_mul_path]
    ret

; ============================================================================
; num3072_cpu_has_adx() -> eax = 1 if BMI2 (mulx) AND ADX (adcx/adox) are
;   both present: CPUID.(EAX=7,ECX=0):EBX bit 8 and bit 19. Leaf 7 is read
;   only when the max basic leaf (CPUID.0:EAX) is >= 7. Exported so the tests
;   and the bench ask the exact question the dispatcher asks.
; ============================================================================
global num3072_cpu_has_adx
num3072_cpu_has_adx:
    push rbx
    xor  eax, eax
    cpuid
    cmp  eax, 7
    jb   .no
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    mov  eax, ebx
    shr  eax, 8                       ; bit 8:  BMI2
    and  eax, 1
    shr  ebx, 19                      ; bit 19: ADX
    and  ebx, 1
    and  eax, ebx
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; ============================================================================
; num3072_mul_generic(a=rdi, b=rsi) -- a = a*b mod (2^3072 - MAX_PRIME_DIFF)
;   The fallback body: what num3072_mul IS on a CPU without BMI2/ADX, and
;   what every CPU ran before the ADX body existed.
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
global num3072_mul_generic
num3072_mul_generic:
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

; ---- row macros for num3072_mul_adx ----------------------------------------
; Product pairs alternate (r9:r8) and (r11:r10) so each step's high half is
; still in a register when the next step wants it, with no move in between.
;
; MULX_ROW0: P[0..48] = a*b[0].   rdx = b[0], rdi = a, rax = &P[0].
;   One plain adc chain: nothing to accumulate into yet.
%macro MULX_ROW0 0
    mulx r9, r8, qword [rdi]
    mov  qword [rax], r8
    mulx r11, r10, qword [rdi+8]
    add  r10, r9
    mov  qword [rax+8], r10
%assign i 2
%rep NLIMBS-2
  %if i & 1
    mulx r11, r10, qword [rdi+i*8]
    adc  r10, r9
    mov  qword [rax+i*8], r10
  %else
    mulx r9, r8, qword [rdi+i*8]
    adc  r8, r11
    mov  qword [rax+i*8], r8
  %endif
%assign i i+1
%endrep
    adc  r11, 0                       ; limb 47 is odd: its high half is r11
    mov  qword [rax+NLIMBS*8], r11
%endmacro

; MULX_ROWADD mulbase, addbase, storebase:
;   for i in 0..47: store[i] = mul[i]*rdx + add[i] (+ carries), then
;   r11 = the 49th limb = last high half + CF + OF, with CF = OF = 0 after.
;   Two independent carry chains: adcx carries the running sum in from
;   memory, adox carries the previous step's high half along. The closing
;   limb cannot overflow: the row's whole sum is below 2^3137, so it fits.
%macro MULX_ROWADD 3
    xor  r11d, r11d                   ; CF = OF = 0 (r11 itself is dead here)
    mulx r9, r8, qword [%1]
    adcx r8, qword [%2]
    mov  qword [%3], r8
%assign i 1
%rep NLIMBS-1
  %if i & 1
    mulx r11, r10, qword [%1+i*8]
    adcx r10, qword [%2+i*8]
    adox r10, r9
    mov  qword [%3+i*8], r10
  %else
    mulx r9, r8, qword [%1+i*8]
    adcx r8, qword [%2+i*8]
    adox r8, r11
    mov  qword [%3+i*8], r8
  %endif
%assign i i+1
%endrep
    mov  r8d, 0                       ; mov leaves both chains' flags alone
    adcx r11, r8                      ; limb 47 is odd: its high half is r11
    adox r11, r8
%endmacro

; ============================================================================
; num3072_mul_adx(a=rdi, b=rsi) -- a = a*b mod p, the BMI2/ADX body.
;
;   WHY IT IS BYTE-EXACT WITH num3072_mul_generic. Core's Multiply is not
;   "the product mod p": it is a fixed chain of partial reductions whose
;   output can be a non-canonical residue, and a replacement has to reproduce
;   the chain, not merely the residue class. Written out, with P = a*b the
;   full 6144-bit product, L = P mod 2^3072, H = P >> 3072 and
;   n = MAX_PRIME_DIFF:
;     - Core's first pass computes exactly W = L + n*H. Its column sums d are
;       H's columns, folded through mulnadd3 as they are produced, so tmp is
;       W mod 2^3072 and the carry (c0,c1) left after the top limb is
;       W >> 3072, which is <= n because W < (n+1)*2^3072.
;     - muln2 then forms n*(W >> 3072) -- below 2^41, so c1 is 0 -- and the
;       addnextract2 loop adds it into tmp with carry propagation, leaving
;       c0 in {0,1}: V = (W mod 2^3072) + n*(W >> 3072).
;     - then IsOverflow -> FullReduce, and c0 -> FullReduce.
;   This body computes the same W from the fully-propagated 96-limb P (the
;   same integer, arrived at by rows instead of columns), performs the same
;   n*(W >> 3072) add and the same two conditional FullReduces through the
;   same helpers (num3072_fold_adx, below), so every value that reaches a[]
;   is the one the generic body writes. tests/test_muhash_mul_diff.c holds
;   each accelerated body to that on 100,000 random pairs, the edges around
;   the modulus, and a chained accumulator; tests/test_muhash runs Core's
;   own vectors down all of them.
;
;   Product: operand scanning by rows of b. Row 0 is a plain mulx/adc chain
;   into P[0..48]; each later row j adds a*b[j] into P[j..j+47] with mulx and
;   the two carry chains and closes both into P[j+48], which no earlier row
;   has written. The row body is unrolled (48 limbs, ~1.2 KB); the row loop
;   is not: at a row boundary both chains are closed, so the loop control's
;   flag writes are harmless.
;
;   Registers: rdi=a rsi=b rdx=b[j] rax=&P[j] rcx=j r8..r11=product pairs.
;   No callee-saved register is used, so none is pushed; rbp is pushed only
;   to give the frame a base per the file's FRAME RULE, and the frame is
;   addressed from rsp.
;   Frame 0x310 = 784 bytes: [rsp+0] a, [rsp+8] pad, [rsp+16 .. +783] P[96].
;   Parity: entry 8 mod 16, one push -> 0 mod 16, 784 is 0 mod 16 -> RSP is
;   0 mod 16 at the call to the fold. Computed, not eyeballed.
; ============================================================================
global num3072_mul_adx
num3072_mul_adx:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x310
    mov  [rsp], rdi                   ; a
    lea  rax, [rsp+16]                ; &P[0]

    ; ---- P[0..48] = a * b[0] ----------------------------------------------
    mov  rdx, [rsi]
    MULX_ROW0

    ; ---- P[j..j+48] += a * b[j], j = 1..47 ---------------------------------
    mov  ecx, 1
    add  rax, 8                       ; &P[1]
.row:
    mov  rdx, [rsi+rcx*8]
    MULX_ROWADD rdi, rax, rax
    mov  qword [rax+NLIMBS*8], r11    ; P[j+48]: first and only write
    add  rax, 8
    inc  ecx
    cmp  ecx, NLIMBS
    jb   .row

    ; ---- Core's reduction of P, shared with the IFMA body -----------------
    mov  rdi, [rsp]                   ; a
    lea  rsi, [rsp+16]                ; P
    call num3072_fold_adx
    add  rsp, 0x310
    pop  rbp
    ret

; ============================================================================
; num3072_fold_adx(a=rdi, P=rsi) -- a = Core's reduction of the 96-limb
;   product P = a*b: W = L + n*H, then V = (W mod 2^3072) + n*(W >> 3072),
;   then IsOverflow -> FullReduce and carry -> FullReduce, through the same
;   helpers the generic body calls. The tail SHARED by num3072_mul_adx and
;   num3072_mul_ifma: each builds P its own way, everything from P on is this
;   one function, so their byte-exactness with the generic body is one
;   argument (written at num3072_mul_adx), not two. Internal. Needs BMI2/ADX
;   for MULX_ROWADD, which both callers' CPU probes require.
;   Frame 16: [rsp+0] a, [rsp+8] Core's c0. Parity: entry 8 mod 16, one
;   push -> 0, 16 -> 0 mod 16 at the three calls. Computed, not eyeballed.
; ============================================================================
num3072_fold_adx:
    push rbp
    mov  rbp, rsp
    sub  rsp, 16
    mov  [rsp], rdi                   ; a

    ; ---- W = L + n*H: a[] = W mod 2^3072, r11 = W >> 3072 (<= n) ----------
    mov  rax, rsi                     ; &P[0]
    mov  edx, MAX_PRIME_DIFF
    MULX_ROWADD rax+NLIMBS*8, rax, rdi

    ; ---- V = a[] + n*(W >> 3072): Core's muln2 + addnextract2 loop --------
    ;   n*r11 < 2^41 (both factors <= n), so a single limb carried through
    ;   all 48; the carry out is Core's c0.
    imul r11, r11, MAX_PRIME_DIFF
    add  qword [rdi], r11
%assign i 1
%rep NLIMBS-1
    adc  qword [rdi+i*8], 0
%assign i i+1
%endrep
    setc cl
    movzx ecx, cl
    mov  [rsp+8], rcx                 ; c0, stashed across the calls

    ; ---- the same two conditional FullReduces, through the same helpers ---
    call num3072_is_overflow          ; rdi = a still; clobbers rax/rcx only
    test rax, rax
    jz   .no_ovf
    mov  rdi, [rsp]
    call num3072_full_reduce
.no_ovf:
    mov  rcx, [rsp+8]
    test rcx, rcx
    jz   .no_carry
    mov  rdi, [rsp]
    call num3072_full_reduce
.no_carry:
    add  rsp, 16
    pop  rbp
    ret

; ---- num3072_mul_ifma: layout of its 64-byte-aligned scratch region (rbx) --
IF_COL equ 0            ; u64 col[128]  the 52-bit-radix column sums of a*b
IF_A52 equ 1024         ; u64 a52[64]   a in 60 limbs of 52 bits, zero-padded
IF_Z   equ 1536         ; u64 z[80]     8 zero limbs, b52[0..59], 12 zero limbs
IF_S   equ 2176         ; u64 s[9][72]  s[r][k] = b52[k-r]: nine shifted copies
IF_P   equ 7360         ; u64 P[96]     the 64-bit-limb product for the fold
IF_END equ 8128
MASK52 equ 0xFFFFFFFFFFFFF

; TO52 src, dst: dst[k] = bits [52k, 52k+52) of the 48-limb number at src,
;   k = 0..59; r8 = MASK52. shrd pulls the straddling bits in from the next
;   limb; limb 47 has no next limb (k = 59 is its top four bits).
%macro TO52 2
%assign k 0
%rep 60
  %assign s (52*k) % 64
  %assign w (52*k) / 64
    mov  rax, [%1 + w*8]
  %if s != 0
    %if w+1 < NLIMBS
    mov  rdx, [%1 + (w+1)*8]
    shrd rax, rdx, s
    %else
    shr  rax, s
    %endif
  %endif
    and  rax, r8
    mov  [%2 + k*8], rax
%assign k k+1
%endrep
%endmacro

; IFMA_Q: the eight a-limbs a52[8q .. 8q+7] at r12 against all nine shifted
;   copies of b. With i = 8q+r, the low 52 bits of a_i*b_j belong to column
;   i+j and the high 52 to column i+j+1; s[r][k] = b52[k-r] places the low
;   half of a_i*s[r][k] at column 8q+k, and s[r+1] the high half at the same
;   column -- i.e. lane k-8jb of block q+jb, which is what zmm(jb) holds.
%macro IFMA_Q 0
%assign r 0
%rep 8
  %assign r1 r+1
    vpbroadcastq zmm15, qword [r12 + r*8]
  %assign jb 0
  %rep 9
    vpmadd52luq zmm%[jb], zmm15, zword [rbx + IF_S + (r*9+jb)*64]
    vpmadd52huq zmm%[jb], zmm15, zword [rbx + IF_S + (r1*9+jb)*64]
  %assign jb jb+1
  %endrep
%assign r r+1
%endrep
%endmacro

; COL2P: carry-propagate col[0..118] (r9 = carry, r11 = MASK52) and pack the
;   52-bit digits into P[0..95]. Digit k occupies bits [52k, 52k+52); r10
;   assembles the limb in progress, and a limb is stored as soon as the
;   digit that completes it arrives (s >= 12 means the digit crosses the
;   limb boundary). col[119] is the high half of a59*b59 -- two four-bit
;   limbs -- and is zero, as is every bit above 6144 (P < 2^6144).
%macro COL2P 0
%assign k 0
%rep 119
  %assign s (52*k) % 64
  %assign w (52*k) / 64
    mov  rax, [rbx + IF_COL + k*8]
    add  rax, r9
    mov  r9, rax
    shr  r9, 52                       ; carry out (< 2^8)
    and  rax, r11                     ; the digit
  %if s == 0
    mov  r10, rax
  %else
    mov  rdx, rax
    shl  rdx, s
    or   r10, rdx
    %if s >= 12
      %if w < 2*NLIMBS
    mov  [rbx + IF_P + w*8], r10
      %endif
    mov  r10, rax
    shr  r10, 64-s                    ; the digit's bits above the boundary
    %endif
  %endif
%assign k k+1
%endrep
%endmacro

; ============================================================================
; num3072_mul_ifma(a=rdi, b=rsi) -- a = a*b mod p, the AVX-512 IFMA body.
;
;   Builds the same 96-limb product P the ADX body builds, by a different
;   route, and hands it to the same num3072_fold_adx; the byte-exactness
;   argument at num3072_mul_adx therefore covers it unchanged -- P is one
;   integer, and only its construction differs.
;
;   Route: both operands are re-based to 60 limbs of 52 bits, the widest
;   limb vpmadd52 multiplies. The hardware splits each 52x52 -> 104-bit
;   product into a low and a high 52; the low half of a_i*b_j belongs to
;   column i+j and the high half to column i+j+1, and the 119 columns are
;   accumulated in 64-bit lanes with NO intermediate carries: a column has
;   at most 60 low and 60 high terms, each below 2^52, so it stays below
;   2^59 and cannot wrap. One scalar pass then propagates the carries and
;   packs the 52-bit digits back into 64-bit limbs (COL2P).
;
;   Vector layout: the columns live in nine zmm registers as blocks of
;   eight -- zmm(jb) = columns 8(q+jb) .. +7 while a52[8q .. 8q+7] is being
;   folded in. So that every product lands in an aligned lane, b is kept as
;   nine limb-shifted copies s[r][k] = b52[k-r], r = 0..8 (IFMA_Q). After
;   each q the finished block zmm0 is stored to col[8q..] (no later q can
;   reach it) and the registers rotate down by one. 8 x 8 x 9 x 2 = 1152
;   vpmadd52 in all, every memory operand aligned.
;
;   Registers: rdi=a rsi=b rbx=scratch r12=&a52[8q] r13=&col[8q] rcx=q;
;   rax/rdx/r8-r11 in the scalar passes; zmm0-8 the column blocks, zmm15 the
;   broadcast a-limb, zmm16 staging. vzeroupper once the vector work is done
;   so the scalar fold and the caller pay no SSE transition penalty.
;   Frame: rbx, r12, r13 pushed BEFORE rbp (FRAME RULE), then 0x2058 = 8280
;   bytes: [rsp+0] a, [rsp+8] pad, then up to 63 bytes of slack and the
;   8128-byte scratch region at rbx = (rsp+16+63) & -64, which ends by
;   rsp+16+63+8128 = rsp+8207 < rsp+8280. Nothing here is addressed from
;   rbp, so no local can reach the save area at [rbp+8..]. Parity: entry 8
;   mod 16, four pushes -> 8, 8280 is 8 mod 16 -> RSP 0 mod 16 at the call.
;   Computed, not eyeballed.
; ============================================================================
global num3072_mul_ifma
num3072_mul_ifma:
    push rbx
    push r12
    push r13
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x2058
    mov  [rsp], rdi                   ; a
    lea  rbx, [rsp+16+63]
    and  rbx, -64                     ; the aligned scratch region

    ; ---- a52 = a in 52-bit limbs, padded; z = 0[8], b52[60], 0[12] --------
    mov  r8, MASK52
    TO52 rdi, rbx+IF_A52
    xor  eax, eax
    mov  [rbx+IF_A52+60*8], rax
    mov  [rbx+IF_A52+61*8], rax
    mov  [rbx+IF_A52+62*8], rax
    mov  [rbx+IF_A52+63*8], rax
    vpxorq zmm16, zmm16, zmm16
    vmovdqa64 [rbx+IF_Z], zmm16              ; z[0..7]
    vmovdqa64 [rbx+IF_Z+64*8], zmm16         ; z[64..71] (b52 overwrites 64..67)
    vmovdqa64 [rbx+IF_Z+72*8], zmm16         ; z[72..79]
    TO52 rsi, rbx+IF_Z+8*8                   ; z[8..67] = b52[0..59]

    ; ---- s[r][8jb..] = z[8-r+8jb ..]: the nine shifted copies, aligned ----
%assign r 0
%rep 9
  %assign jb 0
  %rep 9
    vmovdqu64 zmm16, [rbx + IF_Z + (8-r+8*jb)*8]
    vmovdqa64 [rbx + IF_S + (r*9+jb)*64], zmm16
  %assign jb jb+1
  %endrep
%assign r r+1
%endrep

    ; ---- the column sums -------------------------------------------------
%assign jb 0
%rep 9
    vpxorq zmm%[jb], zmm%[jb], zmm%[jb]
%assign jb jb+1
%endrep
    lea  r12, [rbx+IF_A52]
    lea  r13, [rbx+IF_COL]
    mov  ecx, 8
.qloop:
    IFMA_Q
    vmovdqa64 [r13], zmm0             ; block q is complete
%assign r 0
%rep 8
  %assign r1 r+1
    vmovdqa64 zmm%[r], zmm%[r1]
%assign r r+1
%endrep
    vpxorq zmm8, zmm8, zmm8
    add  r12, 64
    add  r13, 64
    dec  ecx
    jnz  .qloop
%assign jb 0
%rep 8
    vmovdqa64 [r13 + jb*64], zmm%[jb] ; blocks 8..15: columns 64..127
%assign jb jb+1
%endrep
    vzeroupper

    ; ---- carries, and the 52-bit digits packed into P's 64-bit limbs ------
    mov  r11, MASK52
    xor  r9d, r9d                     ; carry
    xor  r10d, r10d                   ; the limb in progress
    COL2P

    ; ---- Core's reduction of P, shared with the ADX body ------------------
    mov  rdi, [rsp]
    lea  rsi, [rbx+IF_P]
    call num3072_fold_adx
    add  rsp, 0x2058
    pop  rbp
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; num3072_cpu_has_ifma() -> eax = 1 if num3072_mul_ifma can run here:
;   BMI2 and ADX (num3072_cpu_has_adx: the shared fold is mulx/adcx), then
;   CPUID.1:ECX bit 27 (OSXSAVE, so XGETBV is legal), CPUID.(EAX=7,ECX=0):
;   EBX bit 16 (AVX512F) and bit 21 (AVX512IFMA), and XGETBV(0) reporting
;   XCR0 bits 1,2,5,6,7 (SSE, AVX, opmask, ZMM_Hi256, Hi16_ZMM) all set --
;   the OS must have enabled ZMM state, or the first zmm instruction faults
;   on a CPU that has every feature bit. The leaf-7 read is gated on the max
;   basic leaf inside num3072_cpu_has_adx.
; ============================================================================
global num3072_cpu_has_ifma
num3072_cpu_has_ifma:
    push rbx
    call num3072_cpu_has_adx
    test eax, eax
    jz   .no
    mov  eax, 1
    xor  ecx, ecx
    cpuid
    bt   ecx, 27                      ; OSXSAVE
    jnc  .no
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    mov  eax, ebx
    shr  eax, 16                      ; bit 16: AVX512F
    and  eax, 1
    shr  ebx, 21                      ; bit 21: AVX512IFMA
    and  ebx, 1
    and  eax, ebx
    jz   .no
    xor  ecx, ecx
    xgetbv                            ; edx:eax = XCR0
    and  eax, 0xE6
    cmp  eax, 0xE6
    jne  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
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

section .bss
align 8
; num3072_mul's cached CPUID verdict: 0 unprobed, 1 ADX, 2 generic, 3 IFMA.
num3072_mul_path: resb 1
