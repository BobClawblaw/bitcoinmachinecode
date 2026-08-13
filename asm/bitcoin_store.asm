; ============================================================================
; bitcoin_store.asm -- persistent multi-file block storage + block index,
;   modeled on Bitcoin Core's layout (multiple 128MB rollover blkXXXXX.dat
;   files + a positional index that maps height -> (file_no, data_pos, size)).
;   100% AI-authored x86-64 assembly.
;
; Files (created in the current working directory):
;   blk00000.dat, blk00001.dat, ...  -- each <= MAX_FILE (128 MiB = 0x08000000);
;       each block framed as [u32 len LE][u32 magic f9beb4d9][raw block bytes]
;       written at a FILE-LOCAL offset (data_pos).
;       The writer rolls to the next blk%05d.dat whenever the current file
;       would exceed MAX_FILE (Bitcoin's MAX_BLOCKFILE_SIZE behaviour).
;   index.dat     -- one 48-byte record per block, positional by height:
;                       [0..31]  block hash
;                       [32..35] file_no u32      (which blkXXXXX.dat)
;                       [36..43] data_pos u64     (offset of [len][magic] frame
;                                                  within that file)
;                       [44..47] data_size u32    (block payload bytes)
;
; State struct (caller supplies), offsets:
;   +0    qword cur_blk_fd      (open fd of the CURRENT block file)
;   +8    qword idx_fd          (open fd of index.dat)
;   +16   qword idx_len         (bytes in index.dat; height = idx_len/48 - 1)
;   +24   dword tip_height      (0-indexed highest stored height; -1 when empty)
;   +28   dword cur_file_no     (current block file number)
;   +32   dword cur_file_pos    (bytes written in the current block file so far)
;   +36   dword magic           (mainnet 0xd9b4bef9)
;   +40   dword pad             (reserved / alignment)
;
; Exports:
;   int store_init(void* st)                    -> 1 ok / -errno
;   int store_reload(void* st)                  -> 1 ok
;   int store_append(void* st, const u8 hash[32], const void* raw, u64 len)
;                                               -> new height or -1
;   int store_get_at(void* st, u64 height, u64 out_meta[3])
;          out_meta[0]=data_pos, out_meta[1]=data_size, out_meta[2]=file_no
;                                               -> 1 ok / -2 out-of-range / -1 err
;   int store_get_tip(void* st, u64 out_meta[3]) -> 1 ok / -1 (empty)
;   int store_get_file_fd(void* st, u32 file_no) -> fd (open/reopen blk%05d.dat)
;                                               -> >=0 or -1
;
; Every function frame: callee-saved save area is [rbp-8 .. -(8*nsaved)], so
; ALL stack locals live strictly BELOW it and never overwrite the save slots.
; ============================================================================

default rel
section .text

MAX_FILE equ 0x08000000      ; 128 MiB per blk file (Bitcoin MAX_BLOCKFILE_SIZE)

; ============================================================================
; helpers (file-name formatting + open by number)
;   fmt_blkname(buf12, file_no): writes "blk%05u.dat" (12 bytes incl NUL) to buf
; ============================================================================
fmt_blkname:                 ; rdi=buf(>=13), esi=file_no
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    sub  rsp, 0x10
    mov  r12, rdi
    ; "blk"
    mov  byte [r12+0], 'b'
    mov  byte [r12+1], 'l'
    mov  byte [r12+2], 'k'
    ; build %05u into r12+3 .. r12+7
    mov  eax, esi
    xor  edx, edx
    mov  ebx, 10000
    div  ebx
    add  al, '0'
    mov  [r12+3], al        ; ten-thousands
    mov  eax, edx
    xor  edx, edx
    mov  ebx, 1000
    div  ebx
    add  al, '0'
    mov  [r12+4], al        ; thousands
    mov  eax, edx
    xor  edx, edx
    mov  ebx, 100
    div  ebx
    add  al, '0'
    mov  [r12+5], al        ; hundreds
    mov  eax, edx
    xor  edx, edx
    mov  ebx, 10
    div  ebx
    add  al, '0'
    mov  [r12+6], al        ; tens
    mov  eax, edx
    add  al, '0'
    mov  [r12+7], al        ; ones
    ; ".dat" then NUL terminator (must write the 0 explicitly -- a dword
    ; store only covers 4 bytes, so [r12+12] would otherwise hold stale
    ; stack garbage and open() would read a corrupted long filename)
    mov  dword [r12+8], 0x7461642E  ; ".dat" -> 2E 64 61 74
    mov  byte  [r12+12], 0          ; NUL terminator
    add  rsp, 0x10
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_init(st)
;   Opens index.dat O_RDWR|O_CREAT, sets empty state (no blk file opened yet).
; ============================================================================
global store_init
store_init:
    push rbp
    mov  rbp, rsp
    push r12
    mov  r12, rdi
    lea  rdi, [rel idxname]
    mov  esi, 2 | 0x40          ; O_RDWR | O_CREAT
    mov  edx, 0o644
    mov  eax, 2                 ; open
    syscall
    test rax, rax
    jl   .fail
    mov  [r12+8], rax           ; idx_fd
    mov  qword [r12+0], -1      ; cur_blk_fd = none yet
    mov  qword [r12+16], 0      ; idx_len = 0
    mov  dword [r12+24], -1     ; tip_height = -1 (empty)
    mov  dword [r12+28], 0      ; cur_file_no = 0
    mov  dword [r12+32], 0      ; cur_file_pos = 0
    mov  dword [r12+36], 0xd9b4bef9
    mov  dword [r12+40], 0
    mov  rax, 1
    pop  r12
    pop  rbp
    ret
.fail:
    mov  rax, -1
    pop  r12
    pop  rbp
    ret

; ============================================================================
; open_file(st, file_no) -> fd (in rax); also sets st->cur_blk_fd if >=0
;   rdi=st, esi=file_no
; ============================================================================
open_file:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 0x40            ; name[16] at rbp-0x40 (BELOW the 5-push save area)
    mov  r12, rdi
    mov  r13d, esi
    ; fmt name into rbp-0x40
    lea  rdi, [rbp-0x40]
    mov  esi, r13d
    call fmt_blkname
    ; open(name, O_RDWR|O_CREAT, 0644)
    lea  rdi, [rbp-0x40]
    mov  esi, 2 | 0x40
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .ret
    mov  [r12], rax           ; cur_blk_fd = fd
    mov  r14, rax
    mov  rax, r14
.ret:
    add  rsp, 0x40
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_get_file_fd(st, file_no) -> fd (reopen blk%05d.dat), so a reader that
;   has a (file_no,pos) from the index can read from that exact file.
; ============================================================================
global store_get_file_fd
store_get_file_fd:
    push rbp
    mov  rbp, rsp
    ; open_file(st, file_no)
    call open_file
    pop  rbp
    ret

; ============================================================================
; store_reload(st) -- re-sync idx_len/tip + reopen the last block file.
; ============================================================================
global store_reload
store_reload:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 0x50           ; record[48] at rbp-0x50
    mov  r12, rdi
    mov  rdi, [r12+8]        ; idx_fd
    xor  esi, esi
    mov  edx, 2              ; SEEK_END
    mov  eax, 8              ; lseek
    syscall
    test rax, rax
    jl   .err
    mov  [r12+16], rax       ; idx_len = size
    cmp  rax, 48
    jb   .empty
    ; tip = idx_len/48 - 1 ; read last record
    mov  rcx, rax
    xor  edx, edx
    mov  rax, rcx
    mov  r8, 48
    div  r8
    sub  rax, 1
    ; read last record at (idx_len-48)
    mov  rbx, rax            ; tip height (callee-saved)
    sub  rcx, 48
    mov  rdi, [r12+8]
    mov  rsi, rcx
    xor  edx, edx
    mov  eax, 8
    syscall
    mov  rdi, [r12+8]
    lea  rsi, [rbp-0x50]
    mov  edx, 48
    xor  eax, eax
    syscall
    cmp  rax, 48
    jne  .err
    ; file_no = rec[32..35]
    mov  eax, [rbp-0x50+32]
    mov  dword [r12+28], eax      ; cur_file_no
    ; data_pos, data_size -> cur_file_pos = pos + 8 + size
    mov  rax, [rbp-0x50+36]
    add  rax, 8
    mov  edx, [rbp-0x50+44]
    add  rax, rdx
    mov  [r12+32], eax            ; cur_file_pos
    ; tip_height = rbx (the tip computed above); reopen the current block file
    mov  dword [r12+24], ebx
    mov  rdi, r12
    mov  esi, [r12+28]
    call open_file
    test rax, rax
    jl   .err
    mov  rax, 1
    add  rsp, 0x50
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.empty:
    mov  dword [r12+24], -1     ; tip_height = -1 (empty)
    mov  dword [r12+28], 0      ; cur_file_no = 0
    mov  dword [r12+32], 0      ; cur_file_pos = 0
    mov  qword [r12+0], -1
    mov  rax, 1
    add  rsp, 0x50
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.err:
    mov  rax, -1
    add  rsp, 0x50
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_get_at(st, height, out_meta[3])  (rdi, rsi, rdx)
;   out_meta[0]=data_pos, out_meta[1]=data_size, out_meta[2]=file_no
; ============================================================================
global store_get_at
store_get_at:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub  rsp, 0x80           ; record[48] at rbp-0x78 (BELOW the 5-push save area)
    mov  r12, rdi
    mov  r13, rsi            ; height
    mov  r14, rdx            ; out_meta
    ; tip = idx_len/48 - 1
    mov  rax, [r12+16]
    xor  edx, edx
    mov  rcx, 48
    div  rcx
    sub  rax, 1
    cmp  rax, -1
    je   .oor                ; empty
    cmp  r13, rax
    ja   .oor
    ; seek index to height*48, read 48
    mov  rax, r13
    imul rax, 48
    mov  rdi, [r12+8]
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .err
    mov  rdi, [r12+8]
    lea  rsi, [rbp-0x78]
    mov  edx, 48
    xor  eax, eax
    syscall
    cmp  rax, 48
    jne  .err
    mov  rax, [rbp-0x78+36]   ; data_pos
    mov  [r14], rax
    mov  eax, [rbp-0x78+44]   ; data_size
    mov  [r14+8], rax
    mov  eax, [rbp-0x78+32]   ; file_no
    mov  [r14+16], rax
    mov  rax, 1
    add  rsp, 0x80
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret
.oor:
    mov  rax, -2
    add  rsp, 0x80
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret
.err:
    mov  rax, -1
    add  rsp, 0x80
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; store_get_tip(st, out_meta[3]) -> 1 ok / -1 empty
; ============================================================================
global store_get_tip
store_get_tip:
    push rbp
    mov  rbp, rsp
    push r12
    push rbx
    mov  r12, rsi           ; out_meta
    ; tip = idx_len/48 - 1
    mov  rax, [rdi+16]
    xor  edx, edx
    mov  rcx, 48
    div  rcx
    sub  rax, 1
    cmp  rax, -1
    je   .empty
    ; store_get_at(st, tip, out_meta); rax=1 ok
    mov  esi, eax           ; height
    mov  rdx, r12           ; out_meta
    call store_get_at
    cmp  rax, 1
    jne  .err
    mov  rax, 1
    jmp  .ret
.empty:
    mov  rax, -1
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    pop  rbx
    pop  r12
    pop  rbp
    ret

; ============================================================================
; store_append(st, hash[32], raw, len)
; ============================================================================
global store_append
store_append:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub  rsp, 0x80           ; header scratch @ rbp-0x80, idx record @ rbp-0x78
    mov  r12, rdi            ; st
    mov  r13, rsi            ; hash
    mov  r14, rdx            ; raw
    mov  r15, rcx            ; len
    ; if no blk file open, open cur_file_no
    mov  rax, [r12]          ; cur_blk_fd
    test rax, rax
    jns  .have_fd
    mov  rdi, r12
    mov  esi, [r12+28]       ; cur_file_no
    call open_file
    test rax, rax
    jl   .err
.have_fd:
    ; rollover check: if cur_file_pos + 8+len > MAX_FILE, roll to next file
    mov  eax, [r12+32]       ; cur_file_pos
    add  eax, 8
    mov  edx, r15d
    add  eax, edx
    cmp  eax, MAX_FILE
    jbe  .no_roll
    ; close current, file_no++, open new, pos=0
    mov  rdi, [r12]
    mov  eax, 3
    syscall
    mov  dword [r12+0], -1
    mov  eax, [r12+28]
    add  eax, 1
    mov  [r12+28], eax       ; cur_file_no++
    mov  dword [r12+32], 0   ; cur_file_pos = 0
    mov  rdi, r12
    mov  esi, eax
    call open_file
    test rax, rax
    jl   .err
.no_roll:
    ; record file_no / pos before appending
    mov  eax, [r12+32]       ; data_pos = cur_file_pos (dword, zero-extends into rax)
    mov  [rbp-0x38], rax     ; save pos (qword) -- BELOW the idx-record region
    mov  eax, [r12+28]       ; cur_file_no
    mov  [rbp-0x40], eax     ; save file_no (dword) -- BELOW the idx-record region
    ; write frame header [u32 len][u32 magic] at cur_file_pos
    mov  dword [rbp-0x80], r15d
    mov  eax, [r12+36]       ; magic
    mov  [rbp-0x7c], eax
    ; lseek(cur_blk_fd, cur_file_pos)
    mov  rdi, [r12]
    mov  eax, [r12+32]
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .err
    mov  rdi, [r12]
    lea  rsi, [rbp-0x80]
    mov  edx, 8
    mov  eax, 1
    syscall
    cmp  rax, 8
    jne  .err
    ; write raw block
    mov  rdi, [r12]
    mov  rsi, r14
    mov  rdx, r15
    mov  eax, 1
    syscall
    cmp  rax, r15
    jne  .err
    ; advance cur_file_pos by 8+len
    mov  eax, [r12+32]
    add  eax, 8
    add  eax, r15d
    mov  [r12+32], eax
    ; new height = idx_len/48 (append)
    mov  rax, [r12+16]
    xor  edx, edx
    mov  rcx, 48
    div  rcx
    mov  ebx, eax            ; new height (callee-saved)
    ; build index record at rbp-0x78: hash, file_no, pos, size
    lea  rdi, [rbp-0x78]
    mov  rsi, r13
    mov  rcx, 32
    rep  movsb
    mov  eax, [rbp-0x40]     ; file_no (saved)
    mov  [rbp-0x78+32], eax
    mov  rax, [rbp-0x38]     ; pos (saved; u64)
    mov  [rbp-0x78+36], rax
    mov  eax, r15d           ; size
    mov  [rbp-0x78+44], eax
    ; append at idx_len
    mov  rdi, [r12+8]
    mov  rax, [r12+16]
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8
    syscall
    mov  rdi, [r12+8]
    lea  rsi, [rbp-0x78]
    mov  edx, 48
    mov  eax, 1
    syscall
    cmp  rax, 48
    jne  .err
    mov  rax, [r12+16]
    add  rax, 48
    mov  [r12+16], rax       ; idx_len += 48
    mov  dword [r12+24], ebx ; tip_height = new height (rbx)
    mov  rax, rbx
    add  rsp, 0x80
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret
.err:
    mov  rax, -1
    add  rsp, 0x80
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

section .rodata
blkname: db "blk00000.dat", 0   ; (fmt_blkname builds actual names at runtime)
idxname: db "index.dat", 0

section .note.GNU-stack noalloc noexec nowrite progbits
