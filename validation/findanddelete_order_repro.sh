#!/bin/sh
# findanddelete_order_repro.sh -- minimal reproducer for the one error-code
# divergence left by the 2026-09-03 ARM verify differential (SIG_DER here vs
# SCRIPT_ERR_SIG_FINDANDDELETE in Core; the VERDICT agrees, so this is a
# diagnostic-order gap, not a consensus one).
#
# SHAPE. A bare script guarding a P2PK with OP_CHECKSEQUENCEVERIFY:
#
#     025faf00 b2 75  21<pubkey> ac
#     ^push 5faf  CSV DROP       ^CHECKSIG
#
# The input's scriptSig pushes a single 2-byte value 5faf, which the CSV/DROP
# pair leaves sitting in the signature slot at OP_CHECKSIG -- deliberately
# wrong (it is not a signature and CHECKSIG must reject), but legal as script
# bytes. What makes this interesting is that 5faf is ALSO a literal of the
# script itself: Core's EvalChecksigPreTapscript builds
#
#     FindAndDelete(scriptCode, CScript() << vchSig)     /* interpreter.cpp:330 */
#     if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
#         return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
#
# BEFORE CheckSignatureEncoding, so the needle 025faf is found at offset 0 of
# the very scriptCode being executed, and Core never looks at the encoding.
# Ours runs the search inside the C checker callback (asm/bitcoin_scriptverify.c
# :186), which the interpreter reaches only AFTER interp_sig_encoding_ok -- so a
# non-DER signature that also occurs inside its own scriptCode is reported as
# SIG_DER. Same reject, different reason string.
#
# NOT A PORT BUG: asm/bitcoin_interp.asm's interp_checksig (x86) has the same
# order, and the search is shared C. Fixing it means doing the
# CONST_SCRIPTCODE search on the ERROR path of interp_checksig on both
# architectures -- nothing on the accept path needs to move, because when the
# encoding checks pass, the callback's existing -5 already matches Core.
#
# Expected until that fix lands everywhere: ours 24 (SIG_DER), core 54
# (SIG_FINDANDDELETE), both rejecting. When the two agree at 54 this script
# exits 0; it exits 1 while the divergence is present, so it can be dropped
# into a regression run as soon as main takes the ordering change.
#
# Case source: tests/fuzz_verify_diff.c seed 0x3ee41b08, case 10911
# (tmpl=bare mut=flip-script-byte), found on AArch64 2026-09-03 over 60,000
# whole-input cases; 0 verdict mismatches in the same run.
#
# Usage:  BMC_SHIM=<verify shim> BMC_ORACLE=<core verify oracle> ./this.sh
# Both speak the same line protocol; the shim's VERIFY wants the scriptSig
# separated, the oracle's verify takes it out of the tx itself.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SHIM=${BMC_SHIM:-$HERE/../asm/tests/verify_p2sh_shim}
ORACLE=${BMC_ORACLE:-$HERE/core_verify_oracle}

FLAGS=1fffff          # every script flag, incl. CONST_SCRIPTCODE (bit 16)
TX=02000000032cde440217af23b16880ba2e72239549b0796420261269d440b0dedb942df0ab000000004847304402202110c692b5a3612cefd8385561d4d9cb4e4f64da67036d7100cdccbd3e1842b0022073154903f5ca8230bea0f93ad96ea9d52d68211f51538c830bcf7f1450781f36035eaf0c00719533707f743c72453b6e776788959c55d10816aa77113efb3533ef848a353d0200000000e951060087b02f4b9a65ea74d95c5da2a8ed1f504a31fd302f57944f7a2c4ecda59fcb41000000000047ab020002dd883b01000000001976a914dfc49f39049d35cb24f6f026b1a70bc72426701288ac483230000000000016001492e6898a3c081dc07d24a1b2b461dd151e3615d1ac44f40e
IDX=0
SS=47304402202110c692b5a3612cefd8385561d4d9cb4e4f64da67036d7100cdccbd3e1842b0022073154903f5ca8230bea0f93ad96ea9d52d68211f51538c830bcf7f1450781f3603
SPK=025faf00b27521039b258200c8047edb728f48b3c2f93c397281f230bd71c2a071c82e8864f44e29ac
# all three spent outputs as [8-byte LE amount][compact-size][spk], which is
# what the oracle's prevout list wants (BIP143/341 sign the amounts)
PREVOUTS=40fd07030000000029025faf00b27521039b258200c8047edb728f48b3c2f93c397281f230bd71c2a071c82e8864f44e29ac6e5cc101000000001976a91492e6898a3c081dc07d24a1b2b461dd151e3615d188acc7bdc600000000001976a914627ef9ca8afb9a15aa297691e4616986573168c788ac

for p in "$SHIM" "$ORACLE"; do
    [ -x "$p" ] || { echo "missing engine: $p (set BMC_SHIM / BMC_ORACLE)"; exit 2; }
done

# ours: the production verifier through the shim. The tx is non-segwit, so the
# shim's witness-strip pass leaves it alone and both engines hash the same bytes.
OURS=$(printf 'VERIFY %s %s %s %s %s\n' "$FLAGS" "$IDX" "$TX" "$SS" "$SPK" | "$SHIM")
# Core: same tx, prevouts carried separately (BIP143/341 need the amounts).
CORE=$(printf 'verify %s %s %s %s\n' "$FLAGS" "$TX" "$IDX" "$PREVOUTS" | "$ORACLE")

OACC=$(echo "$OURS" | awk '{print $2}'); OERR=$(echo "$OURS" | awk '{print $3}')
CERR=$(echo "$CORE"  | awk '{print $2}')
echo "ours: accept=$OACC err=$OERR    core: accept=$(echo "$CORE" | awk '{print $1}') err=$CERR"

[ "$OACC" = "0" ] || { echo "UNEXPECTED: the case no longer rejects -- harness drift, not the bug"; exit 2; }
if [ "$OERR" = "$CERR" ]; then
    echo "AGREE at $OERR: the CONST_SCRIPTCODE search now precedes the encoding checks."
    exit 0
fi
echo "DIVERGE: ours $OERR (SIG_DER=24) vs core $CERR (SIG_FINDANDDELETE=54);"
echo "verdicts agree, so no consensus risk. See the header for the ordering fix."
exit 1
