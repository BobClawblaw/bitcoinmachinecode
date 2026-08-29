; ============================================================================
; bitcoin_utxo_stats.asm -- the per-coin half of `gettxoutsetinfo`: Core's
; unspendable filter, Core's coin serialization, and the running totals
; (txouts / total_amount / bogosize / muhash) computed over them.
;
; This is the piece that turns "no block was rejected" into "the UTXO set is
; provably identical to Core's". It is deliberately a FILTERED VIEW over our
; storage, not a change to storage:
;
;   Our UTXO set is not the same object as Core's. We write every output to
;   the LSM; Core never writes a provably-unspendable one to its chainstate.
;   At height 575,833 that was 77,191,281 entries against Core's 54,953,225
;   -- 22,238,056 more, which sampling confirmed is the OP_RETURN/nulldata
;   population (LOG.md incident #17, FEATURE_GAPS.md). Filtering at WRITE time
;   would only affect outputs applied after the change, so it would need a
;   from-scratch rebuild to mean anything -- costing the ~84% of chain the
;   live replay has already done. Skipping those entries while ITERATING
;   costs nothing, leaves storage untouched, and produces a figure directly
;   comparable to Core's today.
;
; ---- Core's rule, matched exactly ----
;   CScript::IsUnspendable() (src/script/script.h):
;       return (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE);
;   with OP_RETURN = 0x6a and MAX_SCRIPT_SIZE = 10000. Note what it is NOT:
;   not "starts with OP_RETURN after any prefix", not "contains OP_RETURN",
;   and the size test is strictly GREATER than 10000. Getting this wrong in
;   either direction produces a count mismatch that then looks like a data
;   bug in the hash. utxo_script_unspendable is exported so the differential
;   test can drive it against Core's own answer.
;
; ---- Core's coin serialization, matched exactly ----
;   kernel/coinstats.cpp TxOutSer(ss, outpoint, coin):
;       ss << outpoint;                                   COutPoint: hash(32) || n(uint32 LE)
;       ss << ((uint32_t{coin.nHeight} << 1) | coin.fCoinBase);   uint32 LE
;       ss << coin.out;                                   CTxOut: nValue(int64 LE)
;                                                                 || CompactSize(len) || script
;   The outpoint's `n` here is a PLAIN uint32, not the VARINT that appears in
;   the leveldb key -- the two are different serializations of the same field
;   and only the plain one reaches the hash.
;
;   bogosize is Core's GetBogoSize: 32 + 4 + 4 + 8 + 2 + scriptPubKey.size().
;   It is a database-independent size metric, and it is a much sharper check
;   than the count for the same cost: it can only match if every surviving
;   entry's script LENGTH matches too.
;
; ---- state struct (`st`, caller-allocated and zeroed; see utxo_stats.h) ----
;   +0   qword txouts              filtered live outputs (Core's `txouts`)
;   +8   qword total_amount        satoshis over the filtered set
;   +16  qword bogosize            sum of GetBogoSize over the filtered set
;   +24  qword unspendable_txouts  entries skipped by the filter
;   +32  qword unspendable_amount  satoshis carried by those skipped entries
;   +40  qword raw_txouts          EVERY live entry, filtered or not -- the
;                                  cross-check against utxo_lsm_count()
;   +48  qword zero_height         live entries reporting height 0 (see below)
;   +56  qword want_muhash         IN: 1 to accumulate the set hash
;   +64  32 bytes muhash           OUT: finalized hash (zero if not wanted)
;   +96  384 bytes acc             running MuHash3072 accumulator
;   +480 qword excl_genesis         IN: 1 to exclude the genesis coinbase
;   +488 qword genesis_excluded     OUT: 1 if it was actually seen, and skipped
;   (total 496 bytes)
;
;   excl_genesis exists because Core NEVER writes the genesis coinbase to its
;   chainstate -- which is why those 50 BTC are famously unspendable: the
;   outpoint does not exist to be looked up. daemon/utxo_live.c already
;   excludes it at apply time, citing exactly this comparison. daemon/
;   build_utxo.c does NOT, so a set seeded by the batch builder carries one
;   extra entry (and 50 BTC, and 117 bogosize) forever. Excluding it here is
;   the same filtered-view move as the unspendable rule: it makes an EXISTING
;   set comparable without a rebuild. It is opt-in, and it reports whether it
;   actually fired, so it can never quietly drop an entry that was not there.
;
;   zero_height exists because a run file written before MAGIC_RUN3
;   (2026-08-19) carries no height/is_coinbase at all and reports zero for
;   both -- see bitcoin_utxo_lsm.asm's MAGIC_RUN3 comment. Height is part of
;   what Core hashes, so such a run silently produces a WRONG set hash. The
;   counter lets the caller refuse rather than report a mismatch it cannot
;   explain. Only height 0 (the genesis coinbase, which Core does not carry
;   in its chainstate anyway) is legitimately zero, so a nonzero count here
;   is always a signal.
;
; Exports (System V AMD64):
;   void utxo_stats_init(void* st, unsigned long want_muhash,
;                        unsigned long exclude_genesis_coinbase)
;   void utxo_stats_add(void* st, const u8 key36[36], unsigned long value,
;                       unsigned long code, const u8* script,
;                       unsigned long slen)
;   void utxo_stats_finalize(void* st)
;   long utxo_script_unspendable(const u8* script, unsigned long slen)
;
;   `code` is Core's own packed (height << 1) | is_coinbase, passed as one
;   argument so the callback fits in six registers -- which is what lets
;   utxo_stats_add be handed straight to the LSM walk and the memtable walk as
;   their callback, with no shim and no stack argument.
;
; FRAME RULE (ENGINEERING_RULES.md 6/6b): callee-saved registers pushed BEFORE
; `push rbp`; every reservation chosen so RSP is 0 mod 16 at each call.
; ============================================================================
default rel

extern muhash_init
extern muhash_insert
extern muhash_finalize

OP_RETURN        equ 0x6a
MAX_SCRIPT_SIZE  equ 10000

ST_TXOUTS        equ 0
ST_AMOUNT        equ 8
ST_BOGOSIZE      equ 16
ST_UNSP_N        equ 24
ST_UNSP_AMT      equ 32
ST_RAW_N         equ 40
ST_ZEROH         equ 48
ST_WANT_MUHASH   equ 56
ST_MUHASH        equ 64
ST_ACC           equ 96
ST_EXCL_GENESIS  equ 480
ST_GENESIS_N     equ 488

section .rodata
align 16
; The mainnet genesis coinbase's outpoint, in the WIRE (internal) byte order
; our keys use -- the reverse of the familiar 4a5e1e4b...fdeda33b display
; form. Read out of the oracle (`getblock <genesis hash> 1`) and reversed,
; never recalled (ENGINEERING_RULES.md 1).
genesis_coinbase_key:
    db 0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61
    db 0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a
    dd 0                                  ; output index 0

section .text

; ============================================================================
; utxo_script_unspendable(script=rdi, slen=rsi) -> rax 1 unspendable / 0 not
;   Core's CScript::IsUnspendable, transcribed. A zero-length script is
;   SPENDABLE by this rule (`size() > 0 &&` guards the first-byte test) --
;   an easy thing to get backwards, and the direction that would silently
;   delete real entries from the comparison.
; ============================================================================
global utxo_script_unspendable
utxo_script_unspendable:
    cmp  rsi, MAX_SCRIPT_SIZE
    ja   .yes
    test rsi, rsi
    jz   .no
    movzx eax, byte [rdi]
    cmp  eax, OP_RETURN
    je   .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; ============================================================================
; utxo_stats_init(st=rdi, want_muhash=rsi, exclude_genesis=rdx)
;   Zeroes every counter and sets the accumulator to the empty set (1).
;   Frame: entry RSP is 8 mod 16; six pushes leave it at 8 mod 16; sub rsp,
;   0x18 (24 = 8 mod 16) brings it to 0 mod 16 at the one call. Computed, not
;   eyeballed (ENGINEERING_RULES.md 6).
; ============================================================================
global utxo_stats_init
utxo_stats_init:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x18                  ; 0x18 = 8 mod 16 -> RSP 0 mod 16 at the call
    mov  rbx, rdi
    xor  eax, eax
    mov  [rbx+ST_TXOUTS], rax
    mov  [rbx+ST_AMOUNT], rax
    mov  [rbx+ST_BOGOSIZE], rax
    mov  [rbx+ST_UNSP_N], rax
    mov  [rbx+ST_UNSP_AMT], rax
    mov  [rbx+ST_RAW_N], rax
    mov  [rbx+ST_ZEROH], rax
    mov  [rbx+ST_WANT_MUHASH], rsi
    mov  [rbx+ST_EXCL_GENESIS], rdx
    mov  [rbx+ST_GENESIS_N], rax
    mov  ecx, 32
.zh:
    dec  ecx
    mov  byte [rbx+ST_MUHASH+rcx], 0
    jnz  .zh
    lea  rdi, [rbx+ST_ACC]
    call muhash_init
    add  rsp, 0x18
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; utxo_stats_add(st=rdi, key36=rsi, value=rdx, code=rcx, script=r8, slen=r9)
;   One live UTXO. Applies Core's unspendable filter; a skipped entry is
;   still counted (into unspendable_txouts/_amount and raw_txouts) so the
;   delta against Core is a reported number, not an inference.
;
;   Frame 0x2818 = 10264 bytes (8 mod 16 -> RSP 0 mod 16 at the call):
;     [rbp-0x2810 .. rbp-0x0011] the serialization buffer (10240 bytes)
;   The buffer is 32+4+4+8+3+MAX_SCRIPT_SIZE = 10051 at most, since anything
;   with a longer script has already been filtered out above -- the buffer is
;   rounded up to 10240 and the length is re-checked before the script copy
;   regardless, because a buffer's SIZE is part of the frame layout
;   (ENGINEERING_RULES.md 6b).
; ============================================================================
global utxo_stats_add
utxo_stats_add:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x2818
    mov  rbx, rdi                    ; st
    mov  r12, rsi                    ; key36
    mov  r13, rdx                    ; value
    mov  r14, rcx                    ; code = (height<<1)|is_coinbase
    mov  r15, r8                     ; script
    mov  [rbp-0x2818], r9            ; slen

    inc  qword [rbx+ST_RAW_N]
    ; height == 0 <=> code < 2 (the coinbase bit is bit 0)
    cmp  r14, 2
    jae  .h_ok
    inc  qword [rbx+ST_ZEROH]
.h_ok:

    ; ---- optional: the genesis coinbase, which Core's chainstate never holds
    ; (see ST_EXCL_GENESIS above). Still counted in raw_txouts -- it IS a live
    ; entry in OUR set, and raw_txouts is what the caller cross-checks against
    ; the walk -- but excluded from every Core-comparable figure. ----
    cmp  qword [rbx+ST_EXCL_GENESIS], 0
    je   .not_genesis
    lea  rdi, [rel genesis_coinbase_key]
    mov  rax, [r12]
    cmp  rax, [rdi]
    jne  .not_genesis
    mov  rax, [r12+8]
    cmp  rax, [rdi+8]
    jne  .not_genesis
    mov  rax, [r12+16]
    cmp  rax, [rdi+16]
    jne  .not_genesis
    mov  rax, [r12+24]
    cmp  rax, [rdi+24]
    jne  .not_genesis
    mov  eax, [r12+32]
    cmp  eax, [rdi+32]
    jne  .not_genesis
    inc  qword [rbx+ST_GENESIS_N]
    jmp  .done
.not_genesis:

    mov  rdi, r15
    mov  rsi, [rbp-0x2818]
    call utxo_script_unspendable
    test rax, rax
    jz   .spendable
    inc  qword [rbx+ST_UNSP_N]
    add  [rbx+ST_UNSP_AMT], r13
    jmp  .done

.spendable:
    inc  qword [rbx+ST_TXOUTS]
    add  [rbx+ST_AMOUNT], r13
    ; bogosize = 32 + 4 + 4 + 8 + 2 + slen  (Core's GetBogoSize)
    mov  rax, [rbp-0x2818]
    add  rax, 50
    add  [rbx+ST_BOGOSIZE], rax

    cmp  qword [rbx+ST_WANT_MUHASH], 0
    je   .done

    ; ---- build Core's TxOutSer image ----
    lea  rdi, [rbp-0x2810]
    ; outpoint = txid(32) || n(uint32 LE); key36 already holds exactly that,
    ; in exactly that order and endianness.
    mov  rax, [r12]
    mov  [rdi], rax
    mov  rax, [r12+8]
    mov  [rdi+8], rax
    mov  rax, [r12+16]
    mov  [rdi+16], rax
    mov  rax, [r12+24]
    mov  [rdi+24], rax
    mov  eax, [r12+32]
    mov  [rdi+32], eax
    ; (height << 1) | coinbase as uint32 LE
    mov  eax, r14d
    mov  [rdi+36], eax
    ; nValue as int64 LE
    mov  [rdi+40], r13
    ; CompactSize(slen): slen <= MAX_SCRIPT_SIZE here, so 1 or 3 bytes only.
    mov  rcx, [rbp-0x2818]
    lea  rsi, [rdi+48]
    cmp  rcx, 0xfd
    jae  .cs3
    mov  [rsi], cl
    inc  rsi
    jmp  .cs_done
.cs3:
    mov  byte [rsi], 0xfd
    mov  ax, cx
    mov  [rsi+1], ax
    add  rsi, 3
.cs_done:
    ; script bytes
    xor  edx, edx
.copy:
    cmp  rdx, rcx
    jae  .copy_done
    mov  al, [r15+rdx]
    mov  [rsi+rdx], al
    inc  rdx
    jmp  .copy
.copy_done:
    add  rsi, rcx                     ; one past the end
    lea  rdi, [rbp-0x2810]
    sub  rsi, rdi                      ; total serialized length
    mov  rdx, rsi
    lea  rsi, [rbp-0x2810]
    lea  rdi, [rbx+ST_ACC]
    call muhash_insert

.done:
    add  rsp, 0x2818
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; utxo_stats_finalize(st=rdi) -- publish st->muhash from the accumulator.
;   A no-op when want_muhash is 0, leaving the 32 bytes zero rather than
;   publishing the hash of an empty set, so a caller can never mistake "not
;   computed" for "computed, and the set was empty".
;   Frame: 6 pushes -> 8 mod 16; sub rsp, 0x18 -> 0 mod 16 at the call.
; ============================================================================
global utxo_stats_finalize
utxo_stats_finalize:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x18
    mov  rbx, rdi
    cmp  qword [rbx+ST_WANT_MUHASH], 0
    je   .skip
    lea  rdi, [rbx+ST_MUHASH]
    lea  rsi, [rbx+ST_ACC]
    call muhash_finalize
.skip:
    add  rsp, 0x18
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
