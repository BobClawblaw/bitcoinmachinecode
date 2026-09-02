#!/bin/bash
# build_shim.sh -- rebuild parity_out/verify_p2sh_shim against the CURRENT
# objects. The sweep reuses an existing shim binary, so after touching any
# .S/.c the verifier drives (bitcoin_interp.S opcount, scriptverify, ...)
# this must be rerun or shim-driven tests measure stale code
# (test_multisig_opcount sat on an 18:34 shim while bitcoin_interp.o was
# 19:10 -- the nkeys opcount charge never ran).
set -e
cd "$(dirname "$0")"
eval $(grep "^DAEMONOBJS=" build_daemon.sh)
OBJS=$(for m in $DAEMONOBJS; do echo "${m}.o"; done)
source <(grep -E "^DAEMONSRCS=|^RPCSRCS=|^NEWSRCS=" build_daemon.sh)
SRCS=$(echo "$DAEMONSRCS $RPCSRCS $NEWSRCS" | tr ' ' '\n' | grep -v "daemon/main.c" | tr '\n' ' ')
gcc -no-pie -O2 -lpthread -I../../asm -I../../asm/daemon -I../.. \
    -o parity_out/verify_p2sh_shim ../../asm/tests/verify_p2sh_shim.c \
    $SRCS ../../asm/wallet_core.c $OBJS
echo "shim rebuilt: parity_out/verify_p2sh_shim"
