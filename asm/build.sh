#!/usr/bin/env bash
# ============================================================================
# build.sh — 100% AI-generated build/verify driver for the assembly Bitcoin
#            core.  Assembles every .asm source into an ELF64 object, then
#            builds and runs each C harness that proves the machine code
#            against known-good vectors / a Python oracle.
#
#   Exit code 0 == every verification stage passed.
#
# Requires: nasm, gcc
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# --- 1. Build + run the full verification suite -----------------------------
# BLD-4 (audit 2026-09-03): this used to hand-assemble every .asm with a bare
# `nasm -f elf64`, which dropped BOTH -I. and -Werror -- so the whole tree was
# built without the warning gate the Makefile defines in NASMFLAGS.
#
# Worse than the missing flags: the loop rewrote every .o with a FRESH mtime,
# so the `make test` that followed found nothing to rebuild and the -Werror
# path never ran at all. Removing the loop fixes both at once -- `make test`
# already builds every object it needs, through the rules that carry the flags.
echo "== make test =="
make test

# --- 3. Build the shared field/scalar libraries (ctypes stress targets) -----
echo "== Building shared libs for ctypes stress =="
gcc -shared -fPIC -o libsecpfe.so secp256k1_fe.o
gcc -shared -fPIC -o libsecpscalar.so secp256k1_scalar.o

echo
echo "All assembly verify steps completed (exit 0)."
