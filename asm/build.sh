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

# --- 1. Assemble all sources ------------------------------------------------
echo "== Assembling all .asm sources =="
for src in *.asm; do
    obj="${src%.asm}.o"
    echo "  nasm -f elf64 -o $obj $src"
    nasm -f elf64 -o "$obj" "$src"
done

# --- 2. Build + run the full verification suite -----------------------------
echo "== make test =="
make test

# --- 3. Build the shared field/scalar libraries (ctypes stress targets) -----
echo "== Building shared libs for ctypes stress =="
gcc -shared -fPIC -o libsecpfe.so secp256k1_fe.o
gcc -shared -fPIC -o libsecpscalar.so secp256k1_scalar.o

echo
echo "All assembly verify steps completed (exit 0)."
