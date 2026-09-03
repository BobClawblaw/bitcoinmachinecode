#!/bin/bash
# A/B the WITNESS_V0 FAD corner: pre-fix (HEAD) vs post-fix (working tree) interp,
# through verify_p2sh_shim's WITVERIFY. Swaps ONLY bitcoin_interp.o.
set -e
cd /repo/port/arm64
TX=02000000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffffe803000000000000220020ab019379b5297378067f8d4a51290f8fd2b6ba11fe3df5fc9640bbd6b926e00c024c59304402202110c692b5a3612cefd8385561d4d9cb4e4f64da67036d7100cdccbd3e1842b0022073154903f5ca8230bea0f93ad96ea9d52d68211f51538c830bcf7f1450781f360305050505050505050505050505050505055a210239b258200c8047edb728f48b3c2f93c397281f230bd71c2a071c82e8864f44e200000000
SPK=0020ab019379b5297378067f8d4a51290f8fd2b6ba11fe3df5fc9640bbd6b926e00c
CASE="WITVERIFY f815 0 $TX 1000 $SPK"

swap_shim() {  # $1 = interp .S file to build from
  cp "$1" /tmp/interp_swap.S
  gcc -march=armv8.2-a+sha2 -c -o bitcoin_interp.o /tmp/interp_swap.S
  bash build_shim.sh >/dev/null
}

echo "== PRE-FIX (HEAD bitcoin_interp.S) =="
git -C /repo show HEAD:port/arm64/bitcoin_interp.S > /tmp/interp_head.S
swap_shim /tmp/interp_head.S
echo "$CASE
QUIT" | ./parity_out/verify_p2sh_shim

echo "== POST-FIX (working tree, BASE gate) =="
swap_shim /repo/port/arm64/bitcoin_interp.S
echo "$CASE
QUIT" | ./parity_out/verify_p2sh_shim
