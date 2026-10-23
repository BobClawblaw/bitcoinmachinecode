#!/bin/bash
# build.sh -- build the real objects in this worktree's asm/ and the formal
# harness artefacts under formal/secp/build/ (git-ignored).
#   ASM=<dir>  build from a different asm tree (the mutation runs use a scratch copy)
#   B=<dir>    output directory
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
ASM=${ASM:-$ROOT/asm}
B=${B:-$HERE/build}
mkdir -p "$B"
OBJS="secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_point.o secp256k1_point_ct.o
      secp256k1_glv_c.o secp256k1_ecdsa.o bitcoin_keys.o bip340_sign.o crypto_fe_sqrt.o sha256.o"
nice -n10 make -s -C "$ASM" -j4 $OBJS
nice -n10 nasm -f elf64 -I"$ASM"/ -Werror -o "$B/fe_inline_wrap.o" "$HERE/src/fe_inline_wrap.asm"
# copies with three LOCAL labels made global, for the C driver only (code bytes unchanged)
objcopy --globalize-symbol=ecdsa_in_range "$ASM/secp256k1_ecdsa.o" "$B/ecdsa_g.o"
objcopy --globalize-symbol=sc_half_ct "$ASM/secp256k1_point_ct.o" "$B/point_ct_g.o"
objcopy --globalize-symbol=reduce_n --globalize-symbol=cneg_n "$ASM/bip340_sign.o" "$B/bip340_g.o"
LIFT="$ASM/secp256k1_fe.o $ASM/secp256k1_scalar.o $ASM/secp256k1_scalar_c.o $ASM/secp256k1_point.o
      $ASM/secp256k1_point_ct.o $ASM/secp256k1_ecdsa.o $ASM/bitcoin_keys.o $ASM/bip340_sign.o
      $ASM/crypto_fe_sqrt.o $B/fe_inline_wrap.o"
# the image the lifter decodes: the real objects linked at a fixed address
ld -o "$B/img.elf" -Ttext=0x400000 -e 0 --unresolved-symbols=ignore-all $LIFT
nice -n10 gcc -O1 -no-pie -Wall -Werror -o "$B/drv" "$HERE/src/drv.c" \
    "$ASM/secp256k1_fe.o" "$ASM/secp256k1_scalar.o" "$ASM/secp256k1_scalar_c.o" "$ASM/secp256k1_point.o" \
    "$B/point_ct_g.o" "$ASM/secp256k1_glv_c.o" "$B/ecdsa_g.o" "$ASM/bitcoin_keys.o" "$B/bip340_g.o" \
    "$ASM/crypto_fe_sqrt.o" "$ASM/sha256.o" "$B/fe_inline_wrap.o"
