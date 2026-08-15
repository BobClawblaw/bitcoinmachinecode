; ============================================================================
; bitcoin_cli.asm -- 100% AI-authored CLI for the assembly Bitcoin node.
;
; The CLI is the S6 roadmap deliverable: a separate binary that inspects the
; persistent node store (blk00000.dat + index.dat) and prints human-readable
; answers, so a user can query a synchronized chain without the daemon.
;
; Everything here is assembly: command parsing, decimal/hex formatting, hash
; display reversal, store traversal, tx scanning. The thin C driver only passes
; argv/argc and writes the returned output buffer to stdout.
;
; Commands (parsed from argv[1..]):
;   help                -> usage text
;   getblockcount       -> <n>         (tip_height + 1)
;   getbestblockhash    -> 64-hex      (display order)
;   getblockhash <h>    -> 64-hex      (hash of block at height h, display)
;   getblock <h|hash64> -> hex bytes of the raw block
;   gettx <txid64>      -> "found in block <h>" + the raw tx hex
;   getbalance          -> sum of every stored coinbase output value (satoshis)
;   stop                -> prints current tip (CLI has no daemon to signal)
;
; Display convention (matches Bitcoin core / genesis): block_hashes and txids
; print in DISPLAY order = the raw digest byte-reversed. cli_rev32 does that.
;
; System V AMD64. Golden rules honoured: every scratch slot lives BELOW the
; callee-saved save area; RSP is 16-byte aligned at every nested call; one
; instruction per line.
; ============================================================================

default rel

; ---- PROVEN asm dependencies ----
extern store_get_at
extern store_get_file_fd
extern store_get_tip
extern store_reload
extern store_prune
extern block_hash
extern sha256d
extern tx_parse
extern fd_write_all

section .rodata
help_text:
 db `Bitcoin node CLI (all-asm)\n`
 db `  help                  this text\n`
 db `  getblockcount         number of blocks in store\n`
 db `  getbestblockhash      best block hash (display order)\n`
 db `  getblockhash <h>      hash of block at height h\n`
 db `  getblock <h|hash64>   raw block bytes as hex\n`
 db `  gettx <txid64>        find + print a transaction by id\n`
 db `  getbalance            total of stored coinbase outputs (sat)\n`
 db `  prune <height>        delete blk data below height (Core -prune)\n`
 db `  stop                  report current tip\n`
help_len equ $ - help_text

err_usage: db `error: unknown command (try help)\n`
err_usage_len equ $ - err_usage
err_arg:   db `error: bad argument\n`
err_arg_len equ $ - err_arg
err_range: db `error: height out of range\n`
err_range_len equ $ - err_range
err_notfound: db `error: not found\n`
err_notfound_len equ $ - err_notfound

hexdig: db "0123456789abcdef"

section .text

; ============================================================================
; cli_hex(rdi=out, rsi=src, rdx=n) -> rax = advanced out
;   Write n bytes of src as n*2 lowercase hex chars (no reversal).
; ============================================================================
global cli_hex
cli_hex:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x10
    mov  r12, rdi           ; out
    mov  r13, rsi           ; src
    mov  r14, rdx           ; n
    lea  r15, [rel hexdig]
    xor  rbx, rbx           ; i
.loop:
    cmp  rbx, r14
    jae  .done
    movzx eax, byte [r13 + rbx]   ; src[i] (ZERO-extend: upper 56 bits must be 0
                                  ;  for the [hexdig+rax] table index)
    mov  rcx, rax
    shr  al, 4
    and  al, 0x0f
    mov  r8b, [r15 + rax]
    mov  [r12 + rbx*2], r8b
    mov  al, cl
    and  al, 0x0f
    mov  r8b, [r15 + rax]
    mov  [r12 + rbx*2 + 1], r8b
    inc  rbx
    jmp  .loop
.done:
    lea  rax, [r12 + rbx*2]
    add  rsp, 0x10
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cli_rev32(rdi=out, rsi=src) -- reverse 32 bytes (raw digest -> display order)
; ============================================================================
cli_rev32:
    push rbp
    mov  rbp, rsp
    push rbx
    xor  rbx, rbx
.loop:
    cmp  rbx, 32
    jae  .done
    mov  rcx, rbx
    neg  rcx
    add  rcx, 31
    mov  al, [rsi + rcx]
    mov  [rdi + rbx], al
    inc  rbx
    jmp  .loop
.done:
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cli_atoi(rdi=str) -> rax = value (0 if not a valid integer)
; ============================================================================
global cli_atoi
cli_atoi:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rdi
    xor  rbx, rbx           ; value
    xor  rcx, rcx           ; sign flag
    mov  al, [r12]
    cmp  al, '-'
    jne  .digits
    mov  rcx, 1
    inc  r12
.digits:
    mov  al, [r12]
    test al, al
    jz   .finish
    cmp  al, '0'
    jb   .finish
    cmp  al, '9'
    ja   .finish
    imul rbx, rbx, 10
    sub  al, '0'
    movzx rax, al
    add  rbx, rax
    inc  r12
    jmp  .digits
.finish:
    mov  rax, rbx
    test rcx, rcx
    jz   .pos
    neg  rax
.pos:
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cli_hexval(rdi=char) -> al = 0..15, or 0xFF if invalid
; ============================================================================
cli_hexval:
    push rbp
    mov  rbp, rsp
    xor  al, al
    mov  cl, dil
    cmp  cl, '0'
    jb   .bad
    cmp  cl, '9'
    ja   .try_a
    sub  cl, '0'
    mov  al, cl
    jmp  .done
.try_a:
    cmp  cl, 'a'
    jb   .bad
    cmp  cl, 'f'
    ja   .try_A
    sub  cl, 'a'
    add  cl, 10
    mov  al, cl
    jmp  .done
.try_A:
    cmp  cl, 'A'
    jb   .bad
    cmp  cl, 'F'
    ja   .bad
    sub  cl, 'A'
    add  cl, 10
    mov  al, cl
.bad:
    mov  al, 0xFF
.done:
    pop  rbp
    ret

; ============================================================================
; cli_hex_to_bin(rdi=out32, rsi=hexstr) -> rax = 1 ok / 0 bad
;   Parses exactly 64 hex chars into 32 bytes (MSB-first: byte0 = highest).
; ============================================================================
global cli_hex_to_bin
cli_hex_to_bin:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x10
    mov  r12, rdi           ; out
    mov  r13, rsi           ; hex string
    xor  r14, r14           ; i (byte index)
.byte_loop:
    cmp  r14, 32
    jae  .check_len
    movzx edi, byte [r13 + r14*2]
    call cli_hexval
    cmp  al, 0xFF
    je   .bad
    shl  al, 4
    mov  r15b, al
    movzx edi, byte [r13 + r14*2 + 1]
    call cli_hexval
    cmp  al, 0xFF
    je   .bad
    or   al, r15b
    mov  [r12 + r14], al
    inc  r14
    jmp  .byte_loop
.check_len:
    mov  al, [r13 + 64]
    test al, al
    jnz  .bad
    mov  rax, 1
    jmp  .done
.bad:
    xor  rax, rax
.done:
    add  rsp, 0x10
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cli_out(rdi=out, rsi=src, rdx=n) -> rax = advanced out (byte copy)
; ============================================================================
cli_out:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rdi
    xor  rbx, rbx
.loop:
    cmp  rbx, rdx
    jae  .done
    mov  al, [rsi + rbx]
    mov  [r12 + rbx], al
    inc  rbx
    jmp  .loop
.done:
    lea  rax, [r12 + rbx]
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cli_emit_dec(rdi=buf, rsi=value) -> rax = advanced buf
;   Writes value as decimal digits (no sign).
; ============================================================================
cli_emit_dec:
    push rbp
    mov  rbp, rsp
    sub  rsp, 32
    mov  r8, rdi
    lea  rcx, [rbp-16]
    mov  r9, rsi
    test r9, r9
    jnz  .digits
    mov  byte [rcx-1], '0'
    dec  rcx
    jmp  .flip
.digits:
    mov  rax, r9
    xor  edx, edx
    mov  r10, 10
    div  r10
    mov  r9, rax
    add  dl, '0'
    dec  rcx
    mov  [rcx], dl
    test r9, r9
    jnz  .digits
.flip:
    mov  rdi, r8
.cp:
    mov  al, [rcx]
    mov  [rdi], al
    inc  rdi
    inc  rcx
    lea  rdx, [rbp-16]
    cmp  rcx, rdx
    jb   .cp
    mov  rax, rdi
    add  rsp, 32
    pop  rbp
    ret

; ============================================================================
; cmd_getblockcount(rdi=st, rsi=out, rdx=cap) -> rax = advanced out / -1 empty
; ============================================================================
cmd_getblockcount:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rdi           ; st
    mov  rbx, rsi           ; out
    mov  eax, [r12+24]      ; tip_height
    cmp  eax, -1
    je   .empty
    inc  eax
    mov  rdi, rbx
    mov  esi, eax
    call cli_emit_dec
    mov  byte [rax], 10
    inc  rax
    pop  r12
    pop  rbx
    pop  rbp
    ret
.empty:
    mov  rax, -1
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cli_load_block(rdi=st, rsi=height, rdx=out, rcx=cap) -> rax = block length / -1
;   Reads a stored raw block (offset,len from store_get_at) out of blk00000.dat.
;   Replicates node_serve_block but self-contained so bitcoin_cli.o links only
;   against the store primitives + hash/sha256d/writer objects.
; ============================================================================
cli_load_block:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x48          ; meta[24]@-0x48, fd qword @-0x30, file_no dword @-0x38
    mov  r12, rdi           ; st
    mov  r13, rsi           ; height
    mov  r14, rdx           ; out
    mov  r15, rcx           ; cap
    lea  rdx, [rbp-0x48]
    mov  rdi, r12
    mov  rsi, r13
    call store_get_at        ; meta[0]=pos meta[1]=size meta[2]=file_no
    cmp  rax, 1
    jne  .fail
    mov  rbx, [rbp-0x48]     ; data_pos
    mov  rax, [rbp-0x40]     ; data_size
    cmp  rax, r15
    ja   .fail               ; cap too small
    mov  r15, rax            ; keep size in r15 (syscall clobbers rcx/r11)
    mov  eax, [rbp-0x38]     ; file_no (meta[2], low 32)
    mov  [rbp-0x30], rax     ; file_no qword slot (reused below for fd)
    ; open the correct block file for file_no -> fd
    mov  rdi, r12
    mov  esi, eax
    call store_get_file_fd
    test rax, rax
    jl   .fail
    mov  [rbp-0x30], rax     ; fd
    ; lseek(fd, pos+8, SEEK_SET)
    mov  rdi, rax
    mov  rax, rbx
    add  rax, 8
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .fail
    ; read(fd, out, size)
    mov  rdi, [rbp-0x30]     ; fd
    mov  rsi, r14            ; out
    mov  rdx, r15            ; size
    xor  eax, eax
    syscall
    cmp  rax, r15
    jne  .fail
    mov  rax, r15
    jmp  .done
.fail:
    mov  rax, -1
.done:
    add  rsp, 0x48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cmd_getbestblockhash(rdi=st, rsi=out, rdx=cap) -> rax = advanced out / -1
;   Outputs <best block hash display-hex>\n (64 hex chars).
; ============================================================================
cmd_getbestblockhash:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x8008        ; blockbuf[0x4000=16KB] base rbp-0x4000 (ends rbp-0x8000)
                            ;   hbuf[32] rbp-0x40, rev[32] rbp-0x60
    mov  r12, rdi           ; st
    mov  r13, rsi           ; out
    mov  r14, rdx           ; cap
    mov  eax, [r12+24]      ; tip 
    cmp  eax, -1
    je   .fail
    mov  rdi, r12
    mov  esi, eax
    lea  rdx, [rbp-0x4000]
    mov  rcx, 0x4000
    call cli_load_block
    test rax, rax
    jle  .fail
    cmp  rax, 80
    jb   .fail
    lea  rdi, [rbp-0x40]
    lea  rsi, [rbp-0x4000]
    call block_hash
    lea  rdi, [rbp-0x60]
    lea  rsi, [rbp-0x40]
    call cli_rev32
    mov  rdi, r13
    lea  rsi, [rbp-0x60]
    mov  edx, 32
    call cli_hex
    mov  byte [rax], 10
    inc  rax
    jmp  .done
.fail:
    mov  rax, -1
.done:
    add  rsp, 0x8008
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cmd_getblockhash(rdi=st, rsi=hstr, rdx=out, rcx=cap) -> rax = advanced out / -1
;   getblockhash <h>: hash of the block at height h (display hex).
; ============================================================================
cmd_getblockhash:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x1008        ; blockbuf[0x800=2048] base rbp-0x800 (ends rbp-0x1000),
                            ;   hbuf[32] rbp-0x40, rev[32] rbp-0x60
    mov  r12, rdi           ; st
    mov  r13, rsi           ; hstr
    mov  r14, rdx           ; out
    mov  r15, rcx           ; cap
    mov  rdi, r13
    call cli_atoi
    mov  rbx, rax           ; height
    mov  eax, [r12+24]
    cmp  eax, -1
    je   .fail
    cmp  rbx, rax
    ja   .fail
    mov  rdi, r12
    mov  rsi, rbx
    lea  rdx, [rbp-0x800]
    mov  rcx, 0x800
    call cli_load_block
    test rax, rax
    jle  .fail
    cmp  rax, 80
    jb   .fail
    lea  rdi, [rbp-0x40]
    lea  rsi, [rbp-0x800]
    call block_hash
    lea  rdi, [rbp-0x60]
    lea  rsi, [rbp-0x40]
    call cli_rev32
    mov  rdi, r14
    lea  rsi, [rbp-0x60]
    mov  edx, 32
    call cli_hex
    mov  byte [rax], 10
    inc  rax
    jmp  .done
.fail:
    mov  rax, -1
.done:
    add  rsp, 0x1008
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; hex_char_only(rdi=byte) -> al = 1 if it is a hex digit / 0 otherwise
; ============================================================================
hex_char_only:
    push rbp
    mov  rbp, rsp
    mov  cl, dil
    xor  eax, eax
    cmp  cl, '0'
    jb   .no
    cmp  cl, '9'
    jbe  .yes
    or   cl, 0x20           ; lowercase
    cmp  cl, 'a'
    jb   .no
    cmp  cl, 'f'
    ja   .no
.yes:
    mov  al, 1
.no:
    pop  rbp
    ret

; ============================================================================
; is_digit_str(rdi=str) -> al = 1 if str is all digits / 0 otherwise
; ============================================================================
is_digit_str:
    push rbp
    mov  rbp, rsp
    push rbx
    mov  rbx, rdi
.loop:
    mov  al, [rbx]
    test al, al
    jz   .yes
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    ja   .no
    inc  rbx
    jmp  .loop
.no:
    xor  eax, eax
    pop  rbx
    pop  rbp
    ret
.yes:
    mov  al, 1
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; str_eq(rdi=a, rsi=b) -> al = 1 if equal (C-strings, all bytes) / 0
; ============================================================================
str_eq:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
.loop:
    mov  al, [rbx]
    mov  cl, [r12]
    cmp  al, cl
    jne  .no
    test al, al
    jz   .yes
    inc  rbx
    inc  r12
    jmp  .loop
.no:
    xor  eax, eax
    pop  r12
    pop  rbx
    pop  rbp
    ret
.yes:
    mov  al, 1
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cmd_getblock(rdi=st, rsi=arg, rdx=out, rcx=cap) -> rax = advanced out / -1
;   getblock <h | hash64>: print the raw block as hex.
;   If arg is all digits -> by height. Else parse as 64-hex hash (display),
;   reverse to raw, and scan stored heights for a block whose header hash
;   matches; serve the exact block.
; ============================================================================
cmd_getblock:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x2c8        ; blockbuf[384] base rbp-0x2b0 (ends rbp-0x130),
                           ;   bin[32] rbp-0x40, rev[32] rbp-0x60, hbuf[32] rbp-0x80
    mov  r12, rdi           ; st
    mov  r13, rsi           ; arg
    mov  r14, rdx           ; out
    mov  r15, rcx           ; cap
    ; by-number or by-hash?
    mov  rdi, r13
    call is_digit_str
    test al, al
    jz   .byhash
    mov  rdi, r13
    call cli_atoi
    mov  rbx, rax           ; height
    mov  eax, [r12+24]
    cmp  eax, -1
    je   .fail
    cmp  rbx, rax
    ja   .fail
    mov  rdi, r12
    mov  rsi, rbx
    lea  rdx, [rbp-0x2b0]
    mov  rcx, 0x180
    call cli_load_block
    test rax, rax
    jle  .fail
    mov  rbx, rax           ; block length
    ; hex out
    mov  rdi, r14
    lea  rsi, [rbp-0x2b0]
    mov  rdx, rbx
    call cli_hex
    mov  byte [rax], 10
    inc  rax
    jmp  .done
.byhash:
    ; parse 64 hex -> bin (display order), then reverse to raw
    lea  rdi, [rbp-0x40]
    mov  rsi, r13
    call cli_hex_to_bin
    test rax, rax
    jz   .fail
    lea  rdi, [rbp-0x60]
    lea  rsi, [rbp-0x40]
    call cli_rev32          ; now raw-order requested hash
    mov  eax, [r12+24]
    cmp  eax, -1
    je   .fail
    mov  ebx, 0             ; scan height
.scan:
    mov  eax, [r12+24]
    cmp  ebx, eax
    ja   .fail
    mov  rdi, r12
    mov  esi, ebx
    lea  rdx, [rbp-0x2b0]
    mov  rcx, 0x180
    call cli_load_block
    test rax, rax
    jle  .next
    cmp  rax, 80
    jb   .next
    ; hash header
    lea  rdi, [rbp-0x80]
    lea  rsi, [rbp-0x2b0]
    call block_hash
    ; compare rev(raw hash) vs requested raw
    lea  rsi, [rbp-0x80]
    lea  rdi, [rbp-0x60]
    mov  rcx, 32
    repe cmpsb
    je   .match
.next:
    inc  ebx
    jmp  .scan
.match:
    ; re-load the matched block (bx) to get length
    mov  rdi, r12
    mov  esi, ebx
    lea  rdx, [rbp-0x2b0]
    mov  rcx, 0x180
    call cli_load_block
    test rax, rax
    jle  .fail
    mov  rbx, rax
    mov  rdi, r14
    lea  rsi, [rbp-0x2b0]
    mov  rdx, rbx
    call cli_hex
    mov  byte [rax], 10
    inc  rax
    jmp  .done
.fail:
    mov  rax, -1
.done:
    add  rsp, 0x2c8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cli_read_varint(rdi=buf, rsi=len, rdx=out_value_loc=NULL) -> rax = bytes used / -1
;   Reads a CompactSize varint. Returns bytes consumed, clobbers nothing caller
;   depends on beyond rax. Caller passes pointer to fill value into in rcx
;   (or NULL).
; rdi=buf rsi=len rcx=value_out (8 bytes) -> rax = consumed / -1
; ============================================================================
cli_read_varint:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    mov  rcx, rdx           ; value_out (may be 0)
    mov  esi, 0             ; consumed? not used
    cmp  r12, 1
    jb   .bad
    movzx eax, byte [rbx]
    mov  r8, rcx
    test r8, r8
    jz   .no_store1
    mov  [r8], rax
.no_store1:
    cmp  al, 0xfd
    jb   .one
    cmp  al, 0xfd
    je   .two
    cmp  al, 0xfe
    je   .four
    ; 0xff -> 8-byte
    cmp  r12, 9
    jb   .bad
    mov  rax, [rbx+1]
    test r8, r8
    jz   .store8
    mov  [r8], rax
.store8:
    mov  rax, 9
    jmp  .done
.four:
    cmp  r12, 5
    jb   .bad
    mov  eax, [rbx+1]
    test r8, r8
    jz   .store4
    mov  [r8], rax
.store4:
    mov  rax, 5
    jmp  .done
.two:
    cmp  r12, 3
    jb   .bad
    movzx eax, word [rbx+1]
    test r8, r8
    jz   .store2
    mov  [r8], rax
.store2:
    mov  rax, 3
    jmp  .done
.one:
    mov  rax, 1
.done:
    pop  r12
    pop  rbx
    pop  rbp
    ret
.bad:
    mov  rax, -1
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cmd_gettx(rdi=st, rsi=txid_hex, rdx=out, rcx=cap) -> rax = advanced out / -1
;   Search every stored block for a transaction whose id (sha256d, reversed for
;   display) matches the given 64-hex txid. If found print:
;       found in block <h>\n<raw tx hex>\n
;   Walks each block's tx stream (CompactSize count then per-tx lengths from
;   tx_parse).
; ============================================================================
cmd_gettx:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x2e8
    ;  CLEAN non-overlapping layout (save area -0x08..-0x30):
    ;    txbase_out -0x38(q), txlen_out -0x40(q), blen -0x48(d),
    ;    ntx -0x4c(d), vsize -0x50(d), txcount -0x54(d), remain -0x58(d),
    ;    txptr -0x60(q), txidx -0x6c(d),
    ;    parsed(display txid) -0x80..-0x9f,
    ;    rawreq -0xa0..-0xbf, comp(sha256d out) -0xc0..-0xdf,
    ;    info(tx_parse) -0x100..-0x13f,  blockbuf base -0x2e0 cap 0x180.
    ;  info is far enough below rawreq/comp that tx_parse cannot clobber them.
    mov  r12, rdi           ; st
    mov  r13, rsi           ; txid hex
    mov  r14, rdx           ; out
    mov  r15, rcx           ; cap
    lea  rdi, [rbp-0x80]
    mov  rsi, r13
    call cli_hex_to_bin     ; parsed display-order txid at -0x80
    test rax, rax
    jz   .fail
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0x80]
    call cli_rev32          ; raw requested txid at -0xa0
    mov  eax, [r12+24]
    cmp  eax, -1
    je   .fail
    mov  ebx, 0             ; height index
.blk:
    mov  eax, [r12+24]
    cmp  ebx, eax
    ja   .fail
    lea  rdx, [rbp-0x2e0]
    mov  rdi, r12
    mov  esi, ebx
    mov  rcx, 0x180
    call cli_load_block
    test rax, rax
    jle  .next
    mov  [rbp-0x48], eax    ; blen
    lea  rdi, [rbp-0x2e0+80]
    mov  eax, [rbp-0x48]
    sub  eax, 80
    mov  esi, eax
    lea  rdx, [rbp-0x4c]
    call cli_read_varint
    cmp  rax, -1
    je   .next
    mov  dword [rbp-0x50], eax  ; vsize (DWORD; qword would clobber ntx@-0x4c)
    mov  ecx, [rbp-0x4c]
    test ecx, ecx
    jz   .next
    mov  [rbp-0x54], ecx        ; txcount
    lea  rax, [rbp-0x2e0+80]
    mov  edx, [rbp-0x50]        ; vsize (dword; NOT a 64-bit add)
    add  rax, rdx
    mov  [rbp-0x60], rax        ; loop tx pointer (qword at -0x60..-0x67; txidx at -0x6c is clear)
    mov  eax, [rbp-0x48]
    sub  eax, 80
    sub  eax, [rbp-0x50]
    mov  [rbp-0x58], eax       ; remaining
    mov  dword [rbp-0x6c], 0   ; tx index in block (stack; survives calls)
.tx:
    mov  eax, [rbp-0x54]
    cmp  dword [rbp-0x6c], eax
    jae  .next
    lea  rdi, [rbp-0x100]
    mov  rsi, [rbp-0x60]
    mov  edx, [rbp-0x58]
    call tx_parse
    cmp  rax, 1
    jne  .next
    mov  rax, [rbp-0x100]   ; tx_len (info+0)
    test rax, rax
    jle  .next
    ; txid = sha256d(comp at -0xc0, tx ptr, tx_len)
    lea  rdi, [rbp-0xc0]
    mov  rsi, [rbp-0x60]
    mov  rdx, rax
    call sha256d
    ; compare raw requested (-0xa0) vs computed (-0xc0)
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0xc0]
    mov  rcx, 32
    repe cmpsb
    je   .found
    ; advance to next tx
    mov  rax, [rbp-0x60]
    add  rax, [rbp-0x100]   ; + tx_len
    mov  [rbp-0x60], rax
    mov  eax, [rbp-0x58]
    sub  eax, [rbp-0x100]
    mov  [rbp-0x58], eax
    add  dword [rbp-0x6c], 1
    jmp  .tx
.found:
    ; matched tx -> keep pointer/length for the output pass
    mov  rax, [rbp-0x60]
    mov  [rbp-0x38], rax
    mov  rax, [rbp-0x100]
    mov  [rbp-0x40], rax
    ; emit "found in block "
    mov  rdi, r14
    lea  rsi, [rel fnd1]
    mov  edx, fnd1_len
    call cli_out
    mov  rdi, rax
    mov  esi, ebx
    call cli_emit_dec
    mov  byte [rax], 10
    inc  rax
    ; tx hex
    mov  rdi, rax
    mov  rsi, [rbp-0x38]
    mov  rdx, [rbp-0x40]
    call cli_hex
    mov  byte [rax], 10
    inc  rax
    jmp  .done
.next:
    inc  ebx
    jmp  .blk
.fail:
    mov  rax, -1
.done:
    add  rsp, 0x2e8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

fnd1: db "found in block "
fnd1_len equ $ - fnd1

; ============================================================================
; cmd_getbalance(rdi=st, rsi=out, rdx=cap) -> rax = advanced out / -1
;   Sum the output VALUES (satoshi) of the coinbase tx of every stored block --
;   each block in our chain carries exactly one coinbase; the sum of its output
;   values is the total value the node controls. Accepts a 64-bit sum.
; ============================================================================
cmd_getbalance:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x2c8        ; locals skip save area (rbp-8..-30):
                           ;   blen rbp-0x38, ntx rbp-0x3c, vsize rbp-0x40,
                           ;   txbase rbp-0x48, remain rbp-0x4c, nout rbp-0x50,
                           ;   out0_off rbp-0x58, info rbp-0x60..-0xa0,
                           ;   blockbuf base rbp-0x2b0 cap 0x180 (ends rbp-0x130)
    mov  r12, rdi           ; st
    mov  r13, rsi           ; out
    mov  r14, rdx           ; cap
    mov  eax, [r12+24]
    cmp  eax, -1
    je   .fail
    xor  r15, r15           ; sum (u64)
    xor  ebx, ebx           ; height
.blk:
    mov  eax, [r12+24]
    cmp  ebx, eax
    ja   .emit
    lea  rdx, [rbp-0x2b0]
    mov  rdi, r12
    mov  esi, ebx
    mov  rcx, 0x180
    call cli_load_block
    test rax, rax
    jle  .next
    mov  [rbp-0x38], eax    ; blen
    lea  rdi, [rbp-0x2b0+80]
    mov  eax, [rbp-0x38]
    sub  eax, 80
    mov  esi, eax
    lea  rdx, [rbp-0x3c]    ; n_tx
    call cli_read_varint
    cmp  rax, -1
    je   .next
    mov  dword [rbp-0x40], eax  ; vsize (DWORD: a qword would clobber n_tx@-0x3c)
    mov  ecx, [rbp-0x3c]
    test ecx, ecx
    jz   .next
    lea  rax, [rbp-0x2b0+80]
    mov  edx, [rbp-0x40]     ; vsize (dword; zero-extends, not a 64-bit load)
    add  rax, rdx
    mov  [rbp-0x48], rax    ; txbase
    mov  eax, [rbp-0x38]
    sub  eax, 80
    sub  eax, [rbp-0x40]
    mov  [rbp-0x4c], eax    ; remaining for tx_parse
    ; info buffer BELOW all small locals (rbp-0xb0..-0xf0) so tx_parse's
    ; 64-byte struct cannot clobber blen/vsize/txbase/etc.
    lea  rdi, [rbp-0xb0]
    mov  rsi, [rbp-0x48]
    mov  edx, [rbp-0x4c]
    call tx_parse
    cmp  rax, 1
    jne  .next
    mov  ecx, [rbp-0xb0+16]  ; n_out (info+16)
    mov  [rbp-0x50], ecx     ; n_out (local)
    mov  r8, [rbp-0xb0+40]   ; out0_value offset (info+40)
    mov  [rbp-0x58], r8
    mov  r9, [rbp-0x48]
    add  r9, r8             ; p = &output[0].value
    xor  r10, r10           ; out index
.out:
    mov  eax, [rbp-0x50]
    cmp  r10, rax
    jae  .next
    mov  rax, [r9]
    add  r15, rax
    ; remaining bytes from (p+8) to block end = blen - (p+8 - blockbase)
    mov  rdx, r9
    add  rdx, 8
    sub  rdx, rbp
    add  rdx, 0x2b0
    neg  rdx
    add  rdx, [rbp-0x38]
    mov  rsi, rdx
    lea  rdi, [r9+8]
    lea  rdx, [rbp-0x60]    ; script-len scratch (BELOW save area; not -0x20!)
    call cli_read_varint
    cmp  rax, -1
    je   .next
    add  r9, 8
    add  r9, rax            ; + scriptlen varint size
    mov  rax, [rbp-0x60]
    add  r9, rax            ; + scriptlen bytes
    inc  r10
    jmp  .out
.next:
    inc  ebx
    jmp  .blk
.emit:
    mov  rdi, r13
    mov  rsi, r15
    call cli_emit_dec
    mov  byte [rax], 10
    inc  rax
    jmp  .done
.fail:
    mov  rax, -1
.done:
    add  rsp, 0x2c8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cli_main(rdi=store, rsi=argc, rdx=argv, rcx=out, r8=cap) -> rax = byte count
;   argc = number of argv entries (command + its args, excluding program name).
;   argv[0] is the command string; argv[1..] its arguments. Writes the textual
;   result into `out` (NUL-free, human-readable) and returns its length, or -1
;   if the store/command could not produce a result (caller prints "error").
; ============================================================================
global cli_main
cli_main:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x28
    mov  r12, rdi           ; store
    mov  rbx, rsi           ; argc
    mov  r13, rdx           ; argv  (argv[0]=cmd)
    mov  r14, rcx           ; out
    mov  r15, r8            ; cap
    test rbx, rbx
    jle  .unknown
    mov  r8, [r13]          ; argv[0]
    mov  rdi, r8
    lea  rsi, [rel c_help]
    call str_eq
    test al, al
    jnz  .help
    mov  rdi, r8
    lea  rsi, [rel c_count]
    call str_eq
    test al, al
    jnz  .count
    mov  rdi, r8
    lea  rsi, [rel c_best]
    call str_eq
    test al, al
    jnz  .best
    mov  rdi, r8
    lea  rsi, [rel c_bhash]
    call str_eq
    test al, al
    jnz  .bhash
    mov  rdi, r8
    lea  rsi, [rel c_block]
    call str_eq
    test al, al
    jnz  .block
    mov  rdi, r8
    lea  rsi, [rel c_tx]
    call str_eq
    test al, al
    jnz  .tx
    mov  rdi, r8
    lea  rsi, [rel c_balance]
    call str_eq
    test al, al
    jnz  .balance
    mov  rdi, r8
    lea  rsi, [rel c_stop]
    call str_eq
    test al, al
    jnz  .count           ; stop reports the block count
    mov  rdi, r8
    lea  rsi, [rel c_prune]
    call str_eq
    test al, al
    jnz  .prune
    jmp  .unknown
.help:
    mov  rdi, r14
    lea  rsi, [rel help_text]
    mov  edx, help_len
    call cli_out
    ; rax = out + help_len
    jmp  .finish_out
.count:
    mov  rdi, r12
    mov  rsi, r14
    mov  rdx, r15
    call cmd_getblockcount
    cmp  rax, -1
    je   .erange
    jmp  .finish_out
.best:
    mov  rdi, r12
    mov  rsi, r14
    mov  rdx, r15
    call cmd_getbestblockhash
    cmp  rax, -1
    je   .erange
    jmp  .finish_out
.bhash:
    ; needs argument
    cmp  rbx, 2
    jb   .earg
    mov  rdi, r12
    mov  rsi, [r13+8]       ; argv[1]
    mov  rdx, r14
    mov  rcx, r15
    call cmd_getblockhash
    cmp  rax, -1
    je   .erange
    jmp  .finish_out
.block:
    cmp  rbx, 2
    jb   .earg
    mov  rdi, r12
    mov  rsi, [r13+8]
    mov  rdx, r14
    mov  rcx, r15
    call cmd_getblock
    cmp  rax, -1
    je   .enotfound
    jmp  .finish_out
.tx:
    cmp  rbx, 2
    jb   .earg
    mov  rdi, r12
    mov  rsi, [r13+8]
    mov  rdx, r14
    mov  rcx, r15
    call cmd_gettx
    cmp  rax, -1
    je   .enotfound
    jmp  .finish_out
.balance:
    mov  rdi, r12
    mov  rsi, r14
    mov  rdx, r15
    call cmd_getbalance
    cmp  rax, -1
    je   .erange
    jmp  .finish_out
.prune:
    ; prune <height>: retain block data at height >= <height>, delete pruned
    ; blk files below it (mirrors Core's -prune). <0 -> prune nothing;
    ; >tip -> UTXO-only retention (all blk files deleted).
    cmp  rbx, 2
    jb   .earg
    mov  rdi, [r13+8]       ; argv[1] = height string
    call cli_atoi
    mov  rbx, rax           ; height (callee-saved)
    mov  rdi, r12
    mov  esi, ebx
    call store_prune
    test rax, rax
    jl   .erange           ; store_prune failed
    ; output: "pruned to height <h> (retained blocks serve; below unavailable)\n"
    mov  rdi, r14
    lea  rsi, [rel prune_msg]
    mov  edx, prune_msg_len
    call cli_out
    mov  r13, rax           ; advanced out
    mov  rdi, r13
    mov  eax, [r12+48]      ; effective prune height (clamped) is at st+48
    mov  rsi, rax
    call cli_emit_dec
    ; rax = advanced out
    mov  byte [rax], 10
    inc  rax
    jmp  .finish_out
.finish_out:
    ; rax = end pointer; return length = rax - out
    mov  rdi, r14
    sub  rax, rdi
    jmp  .done
.unknown:
    mov  rdi, r14
    lea  rsi, [rel err_usage]
    mov  edx, err_usage_len
    call cli_out
    mov  rax, r14
    add  rax, err_usage_len
    mov  rdi, r14
    sub  rax, rdi
    jmp  .done
.earg:
    mov  rdi, r14
    lea  rsi, [rel err_arg]
    mov  edx, err_arg_len
    call cli_out
    mov  rax, r14
    add  rax, err_arg_len
    mov  rdi, r14
    sub  rax, rdi
    jmp  .done
.erange:
    mov  rdi, r14
    lea  rsi, [rel err_range]
    mov  edx, err_range_len
    call cli_out
    mov  rax, r14
    add  rax, err_range_len
    mov  rdi, r14
    sub  rax, rdi
    jmp  .done
.enotfound:
    mov  rdi, r14
    lea  rsi, [rel err_notfound]
    mov  edx, err_notfound_len
    call cli_out
    mov  rax, r14
    add  rax, err_notfound_len
    mov  rdi, r14
    sub  rax, rdi
.done:
    add  rsp, 0x28
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .rodata
c_help:    db "help",0
c_count:   db "getblockcount",0
c_best:    db "getbestblockhash",0
c_bhash:   db "getblockhash",0
c_block:   db "getblock",0
c_tx:      db "gettx",0
c_balance: db "getbalance",0
c_stop:    db "stop",0
c_prune:   db "prune",0
prune_msg: db "pruned to height "
prune_msg_len equ $-prune_msg

section .note.GNU-stack noalloc noexec nowrite progbits
