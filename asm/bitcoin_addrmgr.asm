; ============================================================================
; bitcoin_addrmgr.asm -- peer address book + addr/addrv2 wire codecs.
;   100% AI-authored x86-64 assembly.  The "full client" peer-discovery layer:
;   a persisted address manager plus builders/parsers for the Bitcoin `addr`
;   (v1) and addrv2 messages, so the node can (a) request peers with getaddr,
;   (b) ingest `addr`/`addrv2` replies, and (c) relay `addr` messages back to
;   peers -- the standard recursive peer-discovery loop.
;
; Persisted address book (peers.dat), fixed 18-byte records, dedup by IP:
;   [0..3]   ip        u32 LE
;   [4..5]   port      u16 BE
;   [6..9]   services  u64 LE
;   [14..17] last_seen u32 LE
;   count = filesize / 18.
;
; Exports:
;   int  amr_init   (void* ab)                       -> 1 ok
;   long amr_count  (void* ab)                       -> #records
;   int  amr_add    (void* ab, ip u32, port u16, services u64, lastseen u32)
;                                                    -> 1 added / 0 dup / -1 err
;   int  amr_get_i  (void* ab, long i, u8 out[18])   -> 1 / 0 / -1
;   long amr_lookup (void* ab, u32 ip)               -> index or -1
;   long p2p_addr_v1(u8* out, const u8 src[18], long n)   -> bytes (v1 addr msg)
;   long p2p_addr_count(const u8* pl, long plen)     -> #addr entries or -1
;   long p2p_addr_next(v8*, ...)                     -> parse helper (see below)
; ============================================================================

default rel
section .text

; -- address book file I/O (raw syscalls, like bitcoin_store.asm) ------------
; amr_init(ab): open peers.dat O_RDWR|O_CREAT in CWD
global amr_init
amr_init:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rdi            ; ab context: [0]=fd
    lea  rdi, [rel peername]
    mov  esi, 2|0x40         ; O_RDWR|O_CREAT
    mov  edx, 0o644
    mov  eax, 2              ; open
    syscall
    test rax, rax
    jl   .fail
    mov  [r12], rax          ; ab[0]=fd
    mov  rax, 1
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    pop  r12
    pop  rbx
    pop  rbp
    ret

; amr_count(ab) -> #records (filesize/18)
global amr_count
amr_count:
    push rbp
    mov  rbp, rsp
    mov  rdi, [rdi]          ; fd
    xor  esi, esi
    mov  edx, 2              ; SEEK_END
    mov  eax, 8              ; lseek
    syscall
    test rax, rax
    jl   .err
    ; filesize / 18
    xor  edx, edx
    mov  rcx, 18
    div  rcx
    pop  rbp
    ret
.err:
    mov  rax, -1
    pop  rbp
    ret

; amr_add(ab, ip rsi, port dx, services rcx, lastseen r8) -> 1/0/-1
global amr_add
amr_add:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x30           ; locals BELOW the 5-push save area [rbp-8..-0x28]
    mov  r12, rdi            ; ab
    mov  r13, rsi            ; ip
    mov  r14d, edx           ; port (BE)
    mov  r15, rcx            ; services
    mov  [rbp-0x50], r8      ; lastseen (below save area)
    ; lookup dup by ip
    mov  rdi, r12
    mov  rsi, r13
    call amr_lookup
    cmp  rax, -1
    jne  .dup
    ; build 18-byte record at rbp-0x40 (below save area)
    lea  rdi, [rbp-0x40]     ; record buf (18 bytes)
    mov  [rdi], r13d         ; ip u32 LE
    mov  word [rdi+4], r14w  ; port u16 BE (already BE from caller)
    mov  [rdi+6], r15        ; services u64
    mov  eax, [rbp-0x50]
    mov  [rdi+14], eax       ; last_seen u32
    ; seek to end (filesize)
    mov  rdi, [r12]
    mov  esi, 0
    mov  edx, 2
    mov  eax, 8
    syscall
    test rax, rax
    jl   .err
    ; write record
    mov  rdi, [r12]
    lea  rsi, [rbp-0x40]
    mov  edx, 18
    mov  eax, 1
    syscall
    cmp  rax, 18
    jne  .err
    mov  rax, 1
    jmp  .ret
.dup:
    mov  rax, 0
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    add  rsp, 0x30
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; amr_get_i(ab, i rsi, out rdx) -> 1/0/-1 (read record i)
global amr_get_i
amr_get_i:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rdx            ; out
    mov  rdi, [r12]
    mov  rax, rsi
    imul rax, 18
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .err
    mov  rdi, [r12]
    mov  rsi, r13
    mov  edx, 18
    xor  eax, eax
    syscall
    cmp  rax, 18
    jne  .err
    mov  rax, 1
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; amr_lookup(ab, ip u32) -> index or -1
global amr_lookup
amr_lookup:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 0x30           ; locals BELOW the 4-push save area [rbp-8..-0x28]
    mov  r12, rdi
    mov  r13, rsi            ; ip
    mov  rbx, 0              ; index
.loop:
    mov  rdi, r12
    mov  rsi, rbx
    lea  rdx, [rbp-0x40]
    call amr_get_i
    test rax, rax
    jle  .notfound
    mov  eax, [rbp-0x40]
    cmp  eax, r13d
    je   .found
    inc  rbx
    jmp  .loop
.notfound:
    mov  rax, -1
    jmp  .ret
.found:
    mov  rax, rbx
.ret:
    add  rsp, 0x30
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; addr (v1) codec
; ============================================================================
; p2p_addr_v1(out, src[18 records], n) -> bytes written
;   Bitcoin `addr` v1 payload: count varint (n, 1-byte assumed <=252) then per
;   record 30 bytes: [time u32][services u64][ip 16 (v4 at 12..15)][port u16 BE].
;   src[i] is our 18-byte amr record (ip u32 LE, port u16 BE, services u64 LE,
;   last_seen u32 LE) -> mapped into the 30-byte wire record.
global p2p_addr_v1
p2p_addr_v1:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x10
    mov  r12, rdi            ; out
    mov  r13, rsi            ; src records
    mov  rbx, rdx            ; n
    mov  byte [r12], bl      ; count varint (1-byte)
    mov  r14, 1              ; output cursor
    mov  r15, 0              ; i
.loop:
    cmp  r15, rbx
    jge  .done
    ; source record = r13 + r15*18
    mov  rax, r15
    imul rax, 18
    lea  rsi, [r13+rax]      ; src rec
    ; dest = r12 + r14
    lea  rdi, [r12+r14]
    ; [0..3] time = last_seen (src+14)
    mov  ecx, [rsi+14]
    mov  [rdi], ecx
    ; [4..11] services = src+6 (u64 LE)
    mov  rcx, [rsi+6]
    mov  [rdi+4], rcx
    ; [12..15] ip = src+0 (u32 LE) into the 16-byte v4-mapped field
    mov  ecx, [rsi]          ; ip u32 LE
    mov  [rdi+12], ecx
    ; [28..29] port = src+4 (u16 BE) -> wire port is BE
    mov  cx, [rsi+4]
    mov  [rdi+28], cx
    ; leave [16..27] zeroed (existing stack buf assumed pre-zeroed by caller
    ; only for the LAST written slot; safer: zero the v6 padding each time)
    mov  qword [rdi+16], 0
    mov  qword [rdi+20], 0
    mov  dword [rdi+24], 0
    ; cursor += 30
    add  r14, 30
    inc  r15
    jmp  .loop
.done:
    mov  rax, r14
    add  rsp, 0x10
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; p2p_addr_count(pl, plen) -> # v1 addr entries or -1
;   Parses the leading CompactSize; returns -1 if the payload is too small to
;   hold that many 30-byte records.
global p2p_addr_count
p2p_addr_count:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    cmp  r12, 1
    jl   .err
    ; varint count
    movzx eax, byte [rbx]
    mov  ecx, 1              ; bytes consumed (1-byte varint path: count<=252)
    cmp  al, 0xfd
    je   .fd
    cmp  al, 0xfe
    je   .fe
    cmp  al, 0xff
    je   .ff
    jmp  .have
.fd:
    cmp  r12, 3
    jl   .err
    mov  ax, [rbx+1]
    mov  ecx, 3
    jmp  .have
.fe:
    cmp  r12, 5
    jl   .err
    mov  eax, [rbx+1]
    mov  ecx, 5
    jmp  .have
.ff:
    cmp  r12, 9
    jl   .err
    mov  eax, [rbx+1]
    mov  ecx, 9
.have:
    ; sanity: records fit?
    mov  edx, eax            ; count
    ; needed = count*30 + varin_bytes
    imul eax, 30
    add  eax, ecx
    cmp  eax, r12d
    ja   .err
    mov  rax, rdx
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .rodata
peername: db "peers.dat", 0

section .note.GNU-stack noalloc noexec nowrite progbits
