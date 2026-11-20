; win_prelude.inc -- prepended to every bmc .asm by tools/asm_xform.py (bmc_win)
extern __bmc_sys_sv          ; winsys/ws_stub.asm: the syscall bridge
extern _tls_start            ; winsys/ws_entry.c: start of the PE TLS template
