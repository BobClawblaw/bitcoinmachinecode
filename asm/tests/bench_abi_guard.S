/* tests/bench_abi_guard.S -- a callee-saved-register firewall for benchmark
 * harnesses, plus the probe that measures which registers a function destroys.
 *
 * WHY THIS EXISTS (found 2026-08-22 while building BENCHMARKS.md tier 1):
 * three functions on this project's hot paths violate the System V AMD64 ABI
 * by returning with callee-saved registers holding something other than what
 * the caller put there. Two of them do it by placing stack locals ON TOP of
 * their own pushed register saves, so the epilogue `pop`s digest bytes:
 *
 *   ripemd160 (ripemd160.asm) -- prologue is
 *       push rbp / mov rbp,rsp / push rbx,r12,r13,r14,r15 / sub rsp,0x120
 *     which puts saved r14 at rbp-0x20 and saved r15 at rbp-0x28. The five
 *     state words h0..h4 are then written to rbp-0x30,-0x2c,-0x28,-0x24,-0x20,
 *     so h2/h3 land on saved r15 and h4 on the low half of saved r14. On
 *     return r15 == (h3<<32)|h2 and r14's low 32 bits == h4. Reproduced at
 *     input lengths 0, 20, 64 and 1,000,000.
 *
 *   hash160 (bitcoin_addr.asm) -- saves only rbx,r12,r13,r14 (never r15) and
 *     then uses a 32-byte SHA-256 buffer at rbp-0x30, i.e. bytes
 *     rbp-0x30..rbp-0x11, which covers saved r13 (rbp-0x18) and saved r14
 *     (rbp-0x20). Its nested ripemd160 call then destroys r15 unopposed. On
 *     return r13, r14 and r15 are all wrong.
 *
 *   pow_check (bitcoin_hash.asm) -- saves rbx,r12,r13 (r13 at rbp-0x18) and
 *     then hands block_hash a 32-byte output buffer at rbp-0x30, i.e. bytes
 *     rbp-0x30..rbp-0x11, which covers saved r13. On return r13 holds header
 *     hash bytes. cons_verify (bitcoin_cons.asm) inherits this: its own frame
 *     is correct (it saves only rbx, at rbp-8, and starts locals at rbp-0x10),
 *     but it calls pow_check, so it too returns with r13 destroyed.
 *
 * All three are the SAME mistake: a digest buffer placed at rbp-0x30 or
 * similar, on a frame whose callee-saved pushes happen AFTER `mov rbp,rsp` and
 * therefore occupy rbp-0x08 .. rbp-0x28.
 *
 * sha256_full, sha256d, sha1_full, sha512_full, tx_parse, merkle_root and
 * block_hash were probed identically and are clean.
 *
 * This file does NOT fix any of them. BENCHMARKS.md is measurement
 * infrastructure; repairing a consensus-path primitive belongs in its own
 * change with its own tests. What this file does is (a) let a benchmark call
 * an affected function without the harness's own state being corrupted -- which
 * is how the bug surfaced, tests/bench_hash_core.c spun forever because
 * ripemd160 rewrote a register holding a loop bound -- and (b) keep the exact
 * experiment that proved it, so the next person does not rebuild it from
 * scratch. tests/bench_abi_audit.c drives (b) over every primitive the
 * benchmark suite times.
 *
 * Cost of the guard: six push/pop pairs around the call. Against the ~3 ms a
 * 1,000,000-byte RIPEMD-160 takes that is under one part in a million. It
 * would NOT be negligible around a 36 ns call, so only the rows that need it
 * are guarded, and BENCHMARKS.md marks them.
 *
 *   long bench_call_guarded(void* fn, const unsigned long args[6]);
 *       Calls fn with args[0..5] in rdi,rsi,rdx,rcx,r8,r9 and restores every
 *       callee-saved register afterwards no matter what fn did. Returns rax.
 *       Passing fewer than six real arguments is fine -- the extra registers
 *       are simply set and ignored, exactly as a varargs-free C call would.
 *
 *   long bench_abi_probe(void* fn, const unsigned long args[6],
 *                        unsigned long got[6]);
 *       Loads six distinct sentinels into rbx,rbp,r12,r13,r14,r15, calls
 *       fn(args...), writes the observed register values to got[0..5] in that
 *       order, and returns how many came back changed.
 */
    .text

    .globl bench_call_guarded
    .type  bench_call_guarded, @function
/* rdi = fn, rsi = args[6] */
bench_call_guarded:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    /* 6 pushes + return address = 56 bytes, so rsp is 8 mod 16 here; one more
     * push realigns it to 0 mod 16 for the call. */
    push %rax
    mov  %rdi, %rax               /* fn */
    mov  %rsi, %r10               /* args -- r10 is caller-saved, but nothing
                                   * reads it after the loads below */
    mov   0(%r10), %rdi
    mov   8(%r10), %rsi
    mov  16(%r10), %rdx
    mov  24(%r10), %rcx
    mov  32(%r10), %r8
    mov  40(%r10), %r9
    call *%rax
    pop  %r10                     /* discard the alignment slot */
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbp
    pop  %rbx
    ret
    .size bench_call_guarded, .-bench_call_guarded

    .globl bench_abi_probe
    .type  bench_abi_probe, @function
/* rdi = fn, rsi = args[6], rdx = got[6] -> long (count of clobbered regs) */
bench_abi_probe:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    push %rdx                     /* got; also realigns rsp to 0 mod 16 */
    mov  %rdi, %rax               /* fn */
    mov  %rsi, %r10               /* args */
    mov   0(%r10), %rdi
    mov   8(%r10), %rsi
    mov  16(%r10), %rdx
    mov  24(%r10), %rcx
    mov  32(%r10), %r8
    mov  40(%r10), %r9
    movabs $0x1111111111111111, %rbx
    movabs $0x2222222222222222, %rbp
    movabs $0x3333333333333333, %r12
    movabs $0x4444444444444444, %r13
    movabs $0x5555555555555555, %r14
    movabs $0x6666666666666666, %r15
    call *%rax
    pop  %r10                     /* got */
    mov  %rbx,  0(%r10)
    mov  %rbp,  8(%r10)
    mov  %r12, 16(%r10)
    mov  %r13, 24(%r10)
    mov  %r14, 32(%r10)
    mov  %r15, 40(%r10)
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbp
    pop  %rbx
    /* Count the mismatches here so no caller has to duplicate the sentinels. */
    xor  %eax, %eax
    movabs $0x1111111111111111, %r11
    cmp  %r11,  0(%r10)
    je   1f
    inc  %rax
1:  movabs $0x2222222222222222, %r11
    cmp  %r11,  8(%r10)
    je   2f
    inc  %rax
2:  movabs $0x3333333333333333, %r11
    cmp  %r11, 16(%r10)
    je   3f
    inc  %rax
3:  movabs $0x4444444444444444, %r11
    cmp  %r11, 24(%r10)
    je   4f
    inc  %rax
4:  movabs $0x5555555555555555, %r11
    cmp  %r11, 32(%r10)
    je   5f
    inc  %rax
5:  movabs $0x6666666666666666, %r11
    cmp  %r11, 40(%r10)
    je   6f
    inc  %rax
6:  ret
    .size bench_abi_probe, .-bench_abi_probe

    .section .note.GNU-stack,"",@progbits
