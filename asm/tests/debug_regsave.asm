; throwaway: call tx_parse / tx_txid with sentinel values loaded into every
; callee-saved register, then dump those registers to a caller buffer to
; check the ABI is honored (rbx, rbp, r12-r15 must survive unchanged).
default rel
section .text

extern tx_parse
extern tx_txid

; void probe_tx_parse(void* info, const void* tx, unsigned long txlen, unsigned long out[7])
; args: rdi=info, rsi=tx, rdx=txlen, rcx=out
global probe_tx_parse
probe_tx_parse:
    push rbp                ; entry rsp%16==8 -> after this, %16==0
    push rbx                ; %16==8
    push r12                ; %16==0
    push r13                ; %16==8
    push r14                ; %16==0
    push r15                ; %16==8
    push rcx                 ; save out ptr; %16==0  <-- correct alignment for the call

    mov rbx, 0x1111111111111111
    mov rbp, 0x2222222222222222
    mov r12, 0x3333333333333333
    mov r13, 0x4444444444444444
    mov r14, 0x5555555555555555
    mov r15, 0x6666666666666666

    call tx_parse

    pop r9                   ; out ptr back
    mov [r9+0*8], rbx
    mov [r9+1*8], rbp
    mov [r9+2*8], r12
    mov [r9+3*8], r13
    mov [r9+4*8], r14
    mov [r9+5*8], r15
    mov [r9+6*8], rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; void probe_tx_txid(void* out32, const void* tx, unsigned long txlen, void* buf, unsigned long buflen, unsigned long regs_out[6])
; args: rdi=out32, rsi=tx, rdx=txlen, rcx=buf, r8=buflen, r9=regs_out
global probe_tx_txid
probe_tx_txid:
    push rbp                ; entry rsp%16==8 -> %16==0
    push rbx                ; %16==8
    push r12                ; %16==0
    push r13                ; %16==8
    push r14                ; %16==0
    push r15                ; %16==8
    push r9                  ; save regs_out (caller-saved, must stash before clobbering); %16==0

    mov rbx, 0x1111111111111111
    mov rbp, 0x2222222222222222
    mov r12, 0x3333333333333333
    mov r13, 0x4444444444444444
    mov r14, 0x5555555555555555
    mov r15, 0x6666666666666666

    call tx_txid

    pop r10                  ; regs_out back
    mov [r10+0*8], rbx
    mov [r10+1*8], rbp
    mov [r10+2*8], r12
    mov [r10+3*8], r13
    mov [r10+4*8], r14
    mov [r10+5*8], r15

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
