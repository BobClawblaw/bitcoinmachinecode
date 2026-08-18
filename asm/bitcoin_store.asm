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
;   +40   dword pad             (reserved; store_append_shared uses as flock fd)
;   +48   dword prune_height    (PRUNING: first height whose block data is
;                                retained; heights below are deleted/unavailable.
;                                Default 0 = no pruning. Persisted to prune.dat
;                                and reloaded by store_init on restart.)
;
; PRUNING (mirrors Bitcoin Core's -prune): store_prune(st, prune_height) retains
;   only the UTXO set + block data at height >= prune_height, unlinks the fully
;   pruned blk%05d.dat files, compacts the one boundary file, and updates the
;   index. Above the prune point blocks are still served; below returns
;   unavailable (store_get_at returns -3). store_set_prune(st, h) configures +
;   persists the gate without deleting. prune.dat holds the 4-byte LE gate.
;
; Exports:
;   int store_init(void* st)                    -> 1 ok / -errno
;   int store_reload(void* st)                  -> 1 ok
;   int store_append(void* st, const u8 hash[32], const void* raw, u64 len)
;                                               -> new height or -1
;   int store_get_at(void* st, u64 height, u64 out_meta[3])
;          out_meta[0]=data_pos, out_meta[1]=data_size, out_meta[2]=file_no
;                                               -> 1 ok / -2 out-of-range
;                                                  / -3 pruned(unavailable) / -1 err
;   int store_get_tip(void* st, u64 out_meta[3]) -> 1 ok / -1 (empty)
;   int store_get_file_fd(void* st, u32 file_no) -> fd (open/reopen blk%05d.dat)
;                                               -> >=0 or -1
;   int store_set_prune(void* st, int h)        -> 1 ok (config+persist gate)
;   int store_prune(void* st, int h)            -> 1 ok (persist + delete files)
;
;   -- Stage A reorg/fork-choice primitives (WIRED IN AS OF STAGE B -- see
;      daemon/reorg.c and the longer note further down this file) --
;   int store_get_tip_hash(void* st, u8 out_hash[32]) -> 1 ok / -1 (empty)
;          Reads the CURRENT tip's block hash straight from its index.dat
;          record (same technique daemon/main.c's anchor_locator already
;          uses, for the same reason: robust even right after an append).
;   int store_validates_prevhash(void* st, const u8 block_header[80])
;                                               -> 1 match / 0 mismatch / -1 (empty store)
;          Compares header bytes [4..35] (the wire-order prevhash field)
;          against store_get_tip_hash's result. Stage B gates every
;          reorg-RECONNECTED block on this; the ordinary append path still
;          does not check it.
;   int store_truncate_to(void* st, long target_height) -> 1 ok / -1 err
;          Rollback/undo primitive: drops every block ABOVE target_height
;          (index.dat + the relevant blk%05u.dat files ftruncate'd, later
;          blk files removed outright) and updates st's in-memory
;          idx_len/tip_height/cur_file_no/cur_file_pos so the store is
;          immediately re-appendable. target_height==-1 truncates to a
;          fully empty store; target_height >= the current tip is a no-op
;          success. Caller must still call idx_build_from_file afterward to
;          rebuild any in-memory hash->height index (bitcoin_idx.asm) --
;          this primitive only touches on-disk/state-struct truncation.
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
; fmt_blkname is exported so bitcoin_store_fast.asm's read-fd cache can build
; the same filenames without duplicating the formatter.
global fmt_blkname
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
    push rbx
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
    mov  dword [r12+40], 0      ; pad / flock fd (set by shared-append caller)
    mov  dword [r12+48], 0      ; prune_height = 0 (no pruning by default)
    ; ---- load persisted prune height from prune.dat (if present) ----
    ; If a previous run pruned, the block store is missing blk files below the
    ; persisted prune height; restoring it in-memory is what keeps store_get_at
    ; returning "pruned/unavailable" (-3) instead of mis-serving from a deleted
    ; file after restart.
    lea  rdi, [rel prunename]
    xor  esi, esi               ; O_RDONLY
    mov  edx, 0o644
    mov  eax, 2                 ; open
    syscall
    test rax, rax
    jl   .noprune
    mov  rbx, rax               ; fd (callee-saved)
    ; read 4 bytes into rsp scratch
    mov  rdi, rbx               ; fd
    lea  rsi, [rsp-8]
    mov  edx, 4
    xor  eax, eax               ; read
    syscall
    cmp  rax, 4
    jne  .prcls
    mov  eax, [rsp-8]
    mov  [r12+48], eax          ; prune_height
.prcls:
    mov  rdi, rbx
    mov  eax, 3                 ; close
    syscall
.noprune:
    mov  rax, 1
    pop  r12
    pop  rbx
    pop  rbp
    ret
.fail:
    mov  rax, -1
    pop  r12
    pop  rbx
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
    ; Close any previously-open block file first. open_file leaks an fd on every
    ; call otherwise: node_serve_block opens the block file anew for EACH block
    ; served, so without this every serve leaks a descriptor and the process
    ; hits EMFILE (~1024) after a few hundred blocks -> serving breaks. This is
    ; what truncated getheaders (and any multi-block serve) at ~1016 headers.
    mov  rax, [r12]           ; cur_blk_fd
    cmp  rax, -1
    je   .noclose
    mov  rdi, rax
    mov  eax, 3              ; close
    syscall
.noclose:
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
    ; ---- pruning gate: height below the configured prune height is
    ; unavailable (its blk file has been deleted). Return -3 (pruned) so
    ; node_serve_block/cli_load_block surface it as unavailable, distinct
    ; from -2 out-of-range and -1 err. ----
    mov  eax, [r12+48]       ; prune_height
    cmp  r13d, eax
    jl   .pruned
    ; ---- read the 48-byte index record at height*48 with ONE pread ----
    ; Was lseek(idx_fd, h*48) + read(48). pread halves the syscall count and,
    ; more importantly, does not touch idx_fd's shared file offset -- which is
    ; what makes concurrent readers safe. Nothing else in the tree depends on
    ; the index fd's offset being left anywhere in particular.
    ; pread64(rdi=fd, rsi=buf, rdx=count, r10=offset)
    mov  rax, r13
    imul rax, 48
    mov  rdi, [r12+8]
    lea  rsi, [rbp-0x78]
    mov  edx, 48
    mov  r10, rax
    mov  eax, 17              ; pread64
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
.pruned:
    mov  rax, -3
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
; PRUNING MODE  (mirrors Bitcoin Core's -prune)
;   Retain the UTXO set + the last M blocks / last N MB of block data; delete
;   pruned blk%05d.dat files. Blocks at height >= prune_height are still
;   served; blocks below are unavailable (store_get_at returns -3 for them).
;
;   prune_height (st+48): the first height whose block data is RETAINED.
;   Everything below it is deleted. Default 0 (no pruning). Persisted to
;   prune.dat so a restart restores the same gate.
;
;   store_set_prune(st, prune_height)  -> configures + persists the gate only.
;   store_prune(st, prune_height)      -> configures + persists + PHYSICALLY
;       deletes the pruned blk files. Uses the "last M blocks" model: caller
;       passes the absolute prune height, or tip+1 to retain UTXO-only.
;   Returns 1 on success, -1 on error.
;
;   Deletion rule: a blk file is a contiguous run of heights (height is
;   monotonic non-decreasing in file_no). Files numbered below the file of the
;   first retained height contain ONLY pruned blocks -> unlink them wholesale.
;   The one file that straddles prune_height (contains both pruned and retained
;   blocks) is compacted IN-PLACE: retained blocks are re-packed from offset 0
;   (safe: each write lands strictly below its read, since new_off == old_off -
;   pruned_prefix_len) and their index records' data_pos is updated; the file is
;   then ftruncate()d to the new length to reclaim the pruned prefix bytes.
; ============================================================================

; ----------------------------------------------------------------------------
; store_set_prune(st, prune_height) -> 1 / -1
;   Persist the prune gate (no physical deletion). Useful as the config path.
; ----------------------------------------------------------------------------
global store_set_prune
store_set_prune:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    sub  rsp, 0x10
    mov  r12, rdi            ; st
    mov  eax, esi
    mov  [r12+48], eax       ; prune_height
    ; persist to prune.dat (4-byte LE)
    lea  rdi, [rel prunename]
    mov  esi, 2 | 0x40 | 0x200   ; O_RDWR | O_CREAT | O_TRUNC
    mov  edx, 0o644
    mov  eax, 2              ; open
    syscall
    test rax, rax
    jl   .setfail
    mov  rbx, rax            ; fd
    mov  eax, [r12+48]
    mov  [rsp-8], eax
    mov  rdi, rbx
    lea  rsi, [rsp-8]
    mov  edx, 4
    mov  eax, 1              ; write
    syscall
    cmp  rax, 4
    jne  .setwfail
    mov  rdi, rbx
    mov  eax, 3              ; close
    syscall
    mov  rax, 1
    add  rsp, 0x10
    pop  r12
    pop  rbx
    pop  rbp
    ret
.setwfail:
    mov  rdi, rbx
    mov  eax, 3
    syscall
.setfail:
    mov  rax, -1
    add  rsp, 0x10
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; unlink_blk(st, file_no)  -- remove blk%05d.dat (ignores ENOENT).
;   frame: rbx,r12,r13,push save area [rbp-8..-0x20]; name buf below.
; ----------------------------------------------------------------------------
unlink_blk:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    sub  rsp, 0x30           ; name[16] below save area
    mov  r12, rdi
    mov  r13d, esi
    lea  rdi, [rbp-0x30]
    mov  esi, r13d
    call fmt_blkname
    lea  rdi, [rbp-0x30]
    mov  eax, 87             ; unlink
    syscall
    add  rsp, 0x30
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; store_prune(st, prune_height) -> 1 / -1
;   Set + persist the prune gate and physically delete pruned blk files.
; ----------------------------------------------------------------------------
global store_prune
store_prune:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; Frame / align: 6 pushes (rbp + 5 callee-saved) occupy rbp-0x08..-0x28.
    ; ALL locals MUST live strictly BELOW that save area (>= -0x30) or a
    ; 48-byte record buffer would clobber the saved callee-saved regs -- the
    ; classic collision this file guards against. 64KB copy buffer sits at
    ; rbp-0x20000..rbp-0x30000. sub 0x30008 keeps rsp under the buffer bottom
    ; and 16-aligned (0x28 pushes + 0x30008 -> rsp ≡ 0 mod 16).
    sub  rsp, 0x30008
    mov  r12, rdi            ; st (callee-saved across calls)
    ; Local map (all below rbp-0x30):
    ;   -0x100 recA[48]  -0x140 recB[48]
    ;   -0x168 tip  -0x16c eff  -0x170 first_retained_file
    ;   -0x174 h  -0x178 old_off  -0x17c size  -0x180 remaining  -0x184 chunk
    ; ---- clamp prune height into [0, tip+1] ----
    mov  eax, [r12+24]       ; tip
    cmp  eax, -1
    je   .empty
    mov  [rbp-0x168], eax    ; tip
    mov  eax, esi            ; requested prune_height
    test eax, eax
    jns  .nonneg
    xor  eax, eax            ; clamp negatives to 0
.nonneg:
    mov  ecx, [rbp-0x168]    ; tip
    add  ecx, 1              ; tip+1
    cmp  eax, ecx
    jbe  .clamped
    mov  eax, ecx            ; clamp to tip+1 (UTXO-only retention)
.clamped:
    mov  [r12+48], eax       ; prune_height
    mov  [rbp-0x16c], eax    ; eff
    test eax, eax
    jz   .persist_only       ; eff 0 -> nothing deleted, just persist gate
    ; ---- persist gate first (store_set_prune writes prune.dat) ----
    mov  rdi, r12
    mov  esi, [rbp-0x16c]
    call store_set_prune
    ; ---- delete fully-pruned blk files ----
    ; If eff == tip+1 there is no retained block -> delete ALL files.
    mov  eax, [rbp-0x16c]
    mov  ecx, [rbp-0x168]
    add  ecx, 1
    cmp  eax, ecx
    je   .prune_all
    ; first_retained_file = file_no of the block at height=eff
    mov  rdi, r12
    mov  esi, eax            ; eff
    lea  rdx, [rbp-0x100]    ; rec A
    call read_idx_rec
    test rax, rax
    jl   .prfail
    mov  [rbp-0x170], eax    ; first_retained_file
    ; delete files 0 .. first_retained_file-1
    xor  ebx, ebx
.delfiles:
    mov  eax, [rbp-0x170]
    cmp  ebx, eax
    jae  .deldone
    mov  rdi, r12
    mov  esi, ebx
    call unlink_blk
    inc  ebx
    jmp  .delfiles
.deldone:
    ; ---- compact the boundary file (first_retained_file) in place ----
    mov  rdi, r12
    mov  esi, [rbp-0x170]
    call open_file           ; open boundary; sets cur_blk_fd
    test rax, rax
    jl   .prfail
    mov  rbx, rax            ; fd (callee-saved)
    xor  r13d, r13d          ; new_off (callee-saved)
    mov  eax, [rbp-0x16c]
    mov  [rbp-0x174], eax    ; h = eff
.cmploop:
    ; stop when h passes the tip (boundary file is the last file)
    mov  eax, [rbp-0x174]
    cmp  eax, [rbp-0x168]    ; h > tip?
    ja   .cmpdone
    mov  rdi, r12
    mov  esi, [rbp-0x174]
    lea  rdx, [rbp-0x100]    ; rec A
    call read_idx_rec
    test rax, rax
    jl   .prfail
    cmp  eax, [rbp-0x170]    ; rec file_no == boundary?
    jne  .cmpdone
    mov  eax, [rbp-0x100+36]
    mov  [rbp-0x178], eax    ; old_off = rec.pos
    mov  eax, [rbp-0x100+44]
    mov  [rbp-0x17c], eax    ; size
    ; copy (8+size) bytes old_off -> new_off; in-place SAFE because each write
    ; lands at new_off = old_off - pruned_prefix_len (< the read offset).
    ; The whole [len][magic] frame + payload (8+size bytes) is copied from the
    ; OLD frame start (old_off) to the NEW frame start (new_off); reading from
    ; the frame start keeps the read range inside the file for the last block.
    ; The inner chunk loop makes only syscalls (no calls), so r14/r15 safely
    ; hold the byte offsets as clean 64-bit pointers across the syscalls.
    movsxd r14, dword [rbp-0x178]  ; old_ptr = old frame start
    mov  r15, r13                 ; new_ptr = new frame start
    mov  eax, [rbp-0x17c]
    add  eax, 8
    mov  [rbp-0x180], eax    ; remaining (bytes, kept as dword local)
.cpychunk:
    mov  eax, [rbp-0x180]
    test eax, eax
    jbe  .cpydone
    ; chunk = min(remaining, 0x10000)
    mov  edx, eax
    cmp  edx, 0x10000
    jbe  .chunkok
    mov  edx, 0x10000
.chunkok:
    mov  [rbp-0x184], edx    ; chunk (dword)
    ; lseek(fd, old_ptr, SEEK_SET); read(fd, buf, chunk)
    mov  rdi, rbx
    mov  rsi, r14
    xor  edx, edx
    mov  eax, 8              ; lseek
    syscall
    test rax, rax
    jl   .prfail
    mov  rdi, rbx
    lea  rsi, [rbp-0x20000]  ; copy buf
    mov  edx, [rbp-0x184]    ; chunk (zero-extends)
    xor  eax, eax            ; read
    syscall
    cmp  eax, [rbp-0x184]
    jne  .prfail
    ; lseek(fd, new_ptr, SEEK_SET); write(fd, buf, chunk)
    mov  rdi, rbx
    mov  rsi, r15
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .prfail
    mov  rdi, rbx
    lea  rsi, [rbp-0x20000]
    mov  edx, [rbp-0x184]
    mov  eax, 1              ; write
    syscall
    cmp  eax, [rbp-0x184]
    jne  .prfail
    ; advance pointers / remaining
    mov  edx, [rbp-0x184]
    add  r14, rdx
    add  r15, rdx
    mov  eax, [rbp-0x180]
    sub  eax, edx
    mov  [rbp-0x180], eax
    jmp  .cpychunk
.cpydone:
    ; copy rec A -> rec B, set data_pos := new_off (r13d), write to index
    lea  rsi, [rbp-0x100]
    lea  rdi, [rbp-0x140]
    mov  rcx, 48
    rep  movsb
    mov  eax, r13d
    mov  [rbp-0x140+36], eax ; new data_pos
    mov  rdi, r12
    mov  esi, [rbp-0x174]
    lea  rdx, [rbp-0x140]
    call write_idx_rec
    test rax, rax
    jl   .prfail
    ; new_off += size+8 ; h++
    mov  eax, [rbp-0x17c]
    add  eax, 8
    add  r13d, eax
    inc  dword [rbp-0x174]
    jmp  .cmploop
.cmpdone:
    ; ftruncate(fd, new_off) drops the pruned prefix bytes
    mov  rdi, rbx
    mov  rsi, r13
    mov  eax, 77             ; ftruncate
    syscall
    test rax, rax
    jl   .prfail
    mov  rax, 1
    jmp  .prdone
.prune_all:
    xor  ebx, ebx
.pall_loop:
    mov  eax, [r12+28]       ; cur_file_no
    cmp  ebx, eax
    ja   .prdone_ok
    mov  rdi, r12
    mov  esi, ebx
    call unlink_blk
    inc  ebx
    jmp  .pall_loop
.prdone_ok:
    mov  rax, 1
    jmp  .prdone
.persist_only:
    mov  rdi, r12
    xor  esi, esi
    call store_set_prune
    mov  rax, 1
    jmp  .prdone
.empty:
    mov  dword [r12+48], 0
    mov  rdi, r12
    xor  esi, esi
    call store_set_prune
    mov  rax, 1
    jmp  .prdone
.prfail:
    mov  rax, -1
.prdone:
    add  rsp, 0x30008
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; read_idx_rec(st, height, buf)  -> file_no in rax (or -1 on error); fills buf.
;   Reads the 48-byte index record at height*48 into buf.
; ----------------------------------------------------------------------------
read_idx_rec:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 0x10
    mov  r12, rdi            ; st
    mov  r13, rsi            ; height
    mov  r14, rdx            ; buf (callee-saved across syscall)
    ; lseek(idx_fd, height*48)
    mov  rdi, [r12+8]
    mov  rax, r13
    imul rax, 48
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .rerr
    mov  rdi, [r12+8]
    mov  rsi, r14            ; buf
    mov  edx, 48
    xor  eax, eax
    syscall
    cmp  rax, 48
    jne  .rerr
    mov  eax, [r14+32]       ; file_no
    jmp  .rok
.rerr:
    mov  rax, -1
.rok:
    add  rsp, 0x10
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; write_idx_rec(st, height, buf) -> 1 ok / -1 err
;   Writes the 48-byte record in buf at index offset height*48.
; ----------------------------------------------------------------------------
write_idx_rec:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 0x10
    mov  r12, rdi            ; st
    mov  r13, rsi            ; height
    mov  r14, rdx            ; buf
    ; lseek(idx_fd, height*48)
    mov  rdi, [r12+8]
    mov  rax, r13
    imul rax, 48
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .werr
    mov  rdi, [r12+8]
    mov  rsi, r14            ; buf
    mov  edx, 48
    mov  eax, 1              ; write
    syscall
    cmp  rax, 48
    jne  .werr
    mov  rax, 1
    jmp  .wok
.werr:
    mov  rax, -1
.wok:
    add  rsp, 0x10
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
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

; ============================================================================
; store_append_shared(st, height, hash[32], raw, len) -- CONCURRENT-SAFE append
;   into ONE shared store from many processes (used to write directly into the
;   single archive with NO per-worker shard directories).
;   st+40 = flock fd on <dir>/append.lock (caller opens it). Each append runs
;   entirely under that flock, so parallel workers can never interleave a frame.
;   The block is written at the TRUE current end of the block file (lseek
;   SEEK_END under the lock) and the 48-byte index record at height*48 -- so
;   workers writing DISJOINT heights land each record at its own slot and the
;   block payload at a consistent sequential offset. Index.dat must be
;   PRE-SIZED to (end+1)*48 by the caller.
;   Returns height on success, -1 on error.
;   Frame: 5 pushes (rbx,r12-r15) -> save area rbp-8..-0x28; locals below.
; ============================================================================
global store_append_shared
store_append_shared:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x120           ; locals BELOW the 5-push save area [rbp-8..-0x28]
    mov  r12, rdi            ; st
    mov  r13, rsi            ; height
    mov  r14, rdx            ; hash
    mov  r15, rcx            ; raw
    mov  [rbp-0x30], r8      ; len (below save area)
    ; ---- acquire shared append lock ----
    mov  rdi, [r12+40]
    test rdi, rdi
    js   .hlock
    mov  eax, 73             ; flock (x86-64 syscall #73, not fcntl #72!)
    mov  esi, 2              ; LOCK_EX
    syscall
.hlock:
    ; ---- ensure idx_fd/blk_fd open ----
    mov  rax, [r12+8]
    test rax, rax
    jns  .hidx
    mov  rdi, r12
    call open_idx_close      ; (defined below: reopen index.dat)
.hidx:
    mov  rax, [r12]
    test rax, rax
    jns  .hblk
    mov  rdi, r12
    mov  esi, [r12+28]
    call open_file
    test rax, rax
    jl   .herr
.hblk:
    ; ---- find TRUE end of current blk file (self-healing position) ----
.repos:
    mov  rdi, [r12]
    xor  esi, esi
    mov  edx, 2              ; SEEK_END
    mov  eax, 8
    syscall
    test rax, rax
    jl   .herr
.roll_ck:
    mov  [rbp-0x38], rax     ; true file length
    ; if cur_file_pos (len of this file) + 8 + len > MAX_FILE -> roll
    mov  eax, [rbp-0x38]
    mov  ecx, [rbp-0x30]
    lea  eax, [rax+rcx+8]
    cmp  eax, MAX_FILE
    jbe  .nroll
    ; close current, cur_file_no++, reopen new file, goto repos (new file len=0)
    mov  rdi, [r12]
    mov  eax, 3
    syscall
    mov  dword [r12], -1
    mov  eax, [r12+28]
    add  eax, 1
    mov  [r12+28], eax
    mov  rdi, r12
    mov  esi, eax
    call open_file
    test rax, rax
    jl   .herr
    jmp  .repos
.nroll:
    mov  rax, [rbp-0x38]
    mov  [rbp-0x40], rax     ; data_pos = true end
    ; save file_no for the index record
    mov  eax, [r12+28]
    mov  [rbp-0x48], eax
    ; build frame header [u32 len][u32 magic] at rbp-0x60
    mov  eax, [rbp-0x30]
    mov  dword [rbp-0x60], eax
    mov  eax, [r12+36]
    mov  [rbp-0x5c], eax
    ; lseek(blk_fd, data_pos); write frame (8); write raw
    mov  rdi, [r12]
    mov  rax, [rbp-0x40]
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .herr
    mov  rdi, [r12]
    lea  rsi, [rbp-0x60]
    mov  edx, 8
    mov  eax, 1
    syscall
    cmp  rax, 8
    jne  .herr
    mov  rdi, [r12]
    mov  rsi, r15
    mov  edx, [rbp-0x30]
    mov  eax, 1
    syscall
    cmp  rax, [rbp-0x30]
    jne  .herr
    ; ---- write index record at height*48: [hash32][file_no u32][pos u64][size u32]
    lea  rdi, [rbp-0x90]
    mov  rsi, r14
    mov  rcx, 32
    rep  movsb
    mov  eax, [rbp-0x48]
    mov  [rbp-0x90+32], eax
    mov  rax, [rbp-0x40]
    mov  [rbp-0x90+36], rax
    mov  eax, [rbp-0x30]
    mov  [rbp-0x90+44], eax
    mov  rdi, [r12+8]
    mov  rax, r13
    imul rax, 48
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8
    syscall
    test rax, rax
    jl   .herr
    mov  rdi, [r12+8]
    lea  rsi, [rbp-0x90]
    mov  edx, 48
    mov  eax, 1
    syscall
    cmp  rax, 48
    jne  .herr
    ; ---- release lock ----
    mov  rdi, [r12+40]
    test rdi, rdi
    js   .hlkdone
    mov  eax, 73             ; flock
    mov  esi, 8              ; LOCK_UN
    syscall
.hlkdone:
    mov  rax, r13
    jmp  .hret
.herr:
    mov  rdi, [r12+40]
    test rdi, rdi
    js   .hlkerr2
    mov  eax, 73             ; flock
    mov  esi, 8
    syscall
.hlkerr2:
    mov  rax, -1
.hret:
    add  rsp, 0x120
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; open_idx_close(st): reopen index.dat (used when idx_fd is stale).
open_idx_close:
    push rbp
    mov  rbp, rsp
    push r12
    sub  rsp, 0x20
    mov  r12, rdi
    lea  rdi, [rel idxname]
    mov  esi, 2 | 0x40
    mov  edx, 0o644
    mov  eax, 2
    syscall
    test rax, rax
    jl   .oer
    mov  [r12+8], rax
.oer:
    add  rsp, 0x20
    pop  r12
    pop  rbp
    ret

; ============================================================================
; STAGE A: reorg/fork-choice primitives #3 (prevhash validation gate) and #4
;   (store truncate/rollback).
;
;   STAGE B UPDATE -- ALL THREE ARE NOW LIVE, via daemon/reorg.c:
;     store_truncate_to        rolls the block store back to the fork point
;                              during a reorg (reorg_execute).
;     store_get_tip_hash       reports the post-reorg tip for logging.
;     store_validates_prevhash gates every block RECONNECTED after a
;                              rollback, so a replacement branch can never be
;                              appended out of order.
;   They are still NOT wired into the ordinary append path: an inbound serve
;   child's .do_block continues to append without a prevhash check. See this
;   stage's report -- that remains an open item.
;   tests/test_prevhash.c and tests/test_truncate.c still cover them in
;   isolation; tests/test_reorg.c covers them wired into a real reorg.
; ============================================================================

; ----------------------------------------------------------------------------
; store_get_tip_hash(st, out_hash[32]) -> 1 ok / -1 (empty store)
;   Reads the CURRENT tip's block hash directly from its 48-byte index.dat
;   record (the hash occupies its first 32 bytes) -- the same "read straight
;   from the index record, not via node_serve_block" approach
;   daemon/main.c's anchor_locator already uses (see its own header comment:
;   node_serve_block on a just-appended tip can transiently return a short
;   read; a direct index.dat read cannot misfire that way).
; ----------------------------------------------------------------------------
global store_get_tip_hash
store_get_tip_hash:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rdi            ; st
    mov  rbx, rsi             ; out_hash
    mov  eax, [r12+24]         ; tip_height (signed dword; -1 = empty)
    cmp  eax, -1
    je   .fail
    movsxd rax, eax
    imul rax, 48
    mov  rdi, [r12+8]           ; idx_fd
    mov  rsi, rbx                ; out_hash
    mov  edx, 32
    mov  r10, rax
    mov  eax, 17                  ; pread64
    syscall
    cmp  rax, 32
    jne  .fail
    mov  rax, 1
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; store_validates_prevhash(st, block_header[80]) -> 1 match / 0 mismatch / -1
;   (empty store -- nothing to validate against). Compares header bytes
;   [4..35] (the raw wire-order prevhash field) against the current tip's
;   hash from store_get_tip_hash -- both are already in the SAME byte order
;   (this codebase's block_hash() raw digest / index.dat storage order; see
;   daemon/main.c's anchor_locator, which forwards/compares hashes in this
;   exact order with no reversal anywhere in that path either).
;   Frame: 3 pushes (rbp,rbx,r12) -> sub amount must be ~=0 mod16; 0x30
;   covers the 32-byte tip_hash local with margin.
; ----------------------------------------------------------------------------
global store_validates_prevhash
store_validates_prevhash:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    sub  rsp, 0x30
    mov  r12, rdi             ; st
    mov  rbx, rsi              ; header
    mov  rdi, r12
    lea  rsi, [rbp-0x30]         ; tip_hash[32]
    call store_get_tip_hash
    cmp  rax, 1
    jne  .err
    lea  rdi, [rbx+4]             ; header+4 = prevhash field
    lea  rsi, [rbp-0x30]
    mov  rcx, 32
    repe cmpsb
    je   .match
    xor  eax, eax
    jmp  .ret
.match:
    mov  eax, 1
    jmp  .ret
.err:
    mov  eax, -1
.ret:
    add  rsp, 0x30
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; store_truncate_to(st, target_height) -> 1 ok / -1 err
;   See this file's header comment for the full contract. Frame: 6 pushes
;   (rbp,rbx,r12,r13,r14,r15) -> save area is [rbp-0x28, rbp) (40 bytes:
;   rbx,r12,r13,r14,r15). Locals must start at rbp-0x28-size or deeper --
;   see bitcoin_chainwork.asm's block_work for the save-area-clearance bug
;   this exact pattern caused there; re-auditing this function on that
;   discovery found the SAME bug here (a naive rec[48] at rbp-0x30 would
;   have spanned all the way up through rbp, fully overlapping the entire
;   40-byte save area). rec[48] now at -0x58 (spans [-88,-40), clear of the
;   save area), stash at -0x60 (clear of rec too). sub amount must be ~=8
;   mod16; 0x68 covers the deepest local (-0x60) with margin.
; ----------------------------------------------------------------------------
global store_truncate_to
store_truncate_to:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x68
    mov  r12, rdi              ; st
    mov  r13, rsi               ; target_height (signed 64-bit)
    mov  eax, [r12+24]           ; current tip_height
    cmp  eax, -1
    je   .noop                    ; store already empty -> nothing to do
    movsxd rax, eax
    cmp  r13, rax
    jge  .noop                     ; target >= tip -> nothing to drop
    cmp  r13, -1
    je   .full_empty                ; target_height==-1 -> wipe everything

    ; ---- read index record at (target_height+1)*48 to learn the new
    ;      end-of-data (file_no, data_pos) ----
    mov  rax, r13
    add  rax, 1
    imul rax, 48
    mov  rdi, [r12+8]              ; idx_fd
    lea  rsi, [rbp-0x58]             ; rec[48]
    mov  edx, 48
    mov  r10, rax
    mov  eax, 17                       ; pread64
    syscall
    cmp  rax, 48
    jne  .err
    mov  r14d, [rbp-0x58+32]             ; boundary_file_no
    mov  r15, [rbp-0x58+36]                ; boundary_data_pos (u64)

    ; ---- ftruncate index.dat to (target_height+1)*48 ----
    mov  rax, r13
    add  rax, 1
    imul rax, 48
    mov  rdi, [r12+8]
    mov  rsi, rax
    mov  eax, 77                          ; ftruncate
    syscall
    test rax, rax
    js   .err

    ; ---- ftruncate the boundary blk file to boundary_data_pos ----
    ; open_file(st, boundary_file_no): local helper defined earlier in this
    ; file; also sets st's cur_blk_fd, which is exactly the fd store_append
    ; will keep using afterward.
    mov  rdi, r12
    mov  esi, r14d
    call open_file
    test rax, rax
    js   .err
    mov  rbx, rax                          ; boundary fd (callee-saved)
    mov  rdi, rbx
    mov  rsi, r15
    mov  eax, 77                              ; ftruncate
    syscall
    test rax, rax
    js   .err

    ; ---- delete any LATER blk files (file_no > boundary_file_no) ----
    mov  eax, [r12+28]                        ; orig cur_file_no
    mov  [rbp-0x60], eax                        ; stash (survives calls below)
    cmp  eax, r14d
    jbe  .no_later_files
    mov  ebx, r14d
    inc  ebx                                      ; first file_no to delete
.dellater:
    cmp  ebx, [rbp-0x60]
    ja   .no_later_files
    mov  rdi, r12
    mov  esi, ebx
    call unlink_blk
    inc  ebx
    jmp  .dellater
.no_later_files:

    ; ---- update in-memory state to match ----
    mov  [r12+28], r14d                            ; cur_file_no
    mov  eax, r15d
    mov  [r12+32], eax                               ; cur_file_pos
    mov  rax, r13
    add  rax, 1
    imul rax, 48
    mov  [r12+16], rax                                ; idx_len
    mov  eax, r13d
    mov  [r12+24], eax                                 ; tip_height
    mov  rax, 1
    jmp  .ret

.noop:
    mov  rax, 1
    jmp  .ret

.full_empty:
    mov  rdi, [r12+8]
    xor  esi, esi
    mov  eax, 77                                        ; ftruncate index.dat to 0
    syscall
    test rax, rax
    js   .err
    mov  eax, [r12+28]
    mov  [rbp-0x60], eax
    xor  ebx, ebx
.dellall:
    cmp  ebx, [rbp-0x60]
    ja   .empty_done
    mov  rdi, r12
    mov  esi, ebx
    call unlink_blk
    inc  ebx
    jmp  .dellall
.empty_done:
    mov  qword [r12+16], 0
    mov  dword [r12+24], -1
    mov  dword [r12+28], 0
    mov  dword [r12+32], 0
    mov  qword [r12+0], -1                                ; cur_blk_fd = none
    mov  rax, 1
    jmp  .ret

.err:
    mov  rax, -1
.ret:
    add  rsp, 0x68
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .rodata
blkname: db "blk00000.dat", 0   ; (fmt_blkname builds actual names at runtime)
idxname: db "index.dat", 0
prunename: db "prune.dat", 0

section .note.GNU-stack noalloc noexec nowrite progbits
