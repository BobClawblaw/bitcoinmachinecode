; data_bounds.asm -- ELF's __data_start / _end for bmc_win.
; lld merges .bss into the tail of .data, so all writable static data is one
; section: __data_start is the first thing in it (this object is linked
; first) and _end sits in ".bss$zzzz", which sorts after every other .bss.
global __data_start
global _end
global __bss_start
section .data
__data_start:
    dq 0
section .bss$zzzz bss
__bss_start:
_end:
    resq 1

; etext / _etext: the end of the code. ".text$~~~~" sorts after every other
; .text piece ('~' is above any name character). __executable_start is
; __ImageBase, by /alternatename at the link (build.py).
global etext
global _etext
section .text$~~~~ code
etext:
_etext:
    int3
