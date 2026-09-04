#!/bin/bash
# Identity-gate regression test (see docs/IDENTITY_RULE.md). Run: bash scripts/test_identity_gate.sh
# The gate must: pass a clean commit; fail bad author identity; fail forbidden tokens in
# commit messages or tracked content; fail an empty range; and the gate + rule doc
# themselves must carry none of the literals they forbid.

REPO=$(mktemp -d)
SRC_REPO=/mnt/2tbssd/bmc-bench/src
GATE="$SRC_REPO/scripts/identity_gate.sh"
FRAGS=(xia n $(printf a n t k o w | tr -d '\n') $(printf c h r i s t i a n | tr -d '\n') $(printf g m a i l | tr -d '\n'))
# fragments assembled from character codes; no literal appears in this file
GATE_CODES=("120 105 97 110" "97 110 116 107 111 119" "99 104 114 105 115 116 105 97 110" "103 109 97 105 108")
FRAGS=()
for g in "${GATE_CODES[@]}"; do
  fmt=""; for c in $g; do fmt="$fmt\\x$(printf '%02x' "$c")"; done
  FRAGS+=("$(printf "$fmt")")
done
FRAG1=${FRAGS[0]}

PASS=0; FAIL=0
chk(){ # chk <name> <expected: 0|1> <cmd...>
  local name=$1 want=$2; shift 2
  "$@"; local rc=$?
  if [ "$rc" = "$want" ]; then echo "ok  $name"; PASS=$((PASS+1)); else echo "FAIL $name (rc=$rc want=$want)"; FAIL=$((FAIL+1)); fi
}
rm -rf "$REPO"; mkdir -p "$REPO"; cd "$REPO" || exit 2
git init -q .; git config user.name BobClawblaw; git config user.email BobClawblaw@users.noreply.github.com
mkdir -p scripts docs; cp "$GATE" scripts/; cp "$SRC_REPO/docs/IDENTITY_RULE.md" docs/
echo hi > README.md; git add -A
git -c user.name=BobClawblaw -c user.email=BobClawblaw@users.noreply.github.com commit -qm "initial clean commit"
echo x > seed.txt; git add -A
git -c user.name=BobClawblaw -c user.email=BobClawblaw@users.noreply.github.com commit -qm "seed (HEAD~1..HEAD is checkable at one commit deep)"

# 1. clean tree + clean identity: gate must PASS (exit 0)
chk "clean commit passes" 0 bash scripts/identity_gate.sh HEAD~1..HEAD 2>/dev/null

# 2. bad author identity: gate must FAIL
git config user.name "someone else"
echo x > a.txt; git add -A; git commit -qm "bad author commit"
chk "bad author fails" 1 bash scripts/identity_gate.sh HEAD~1..HEAD 2>/dev/null

# 3. forbidden token in a commit MESSAGE: gate must FAIL
git config user.name BobClawblaw; git config user.email BobClawblaw@users.noreply.github.com
echo y > b.txt; git add -A; git commit -qm "message mentions the ${FRAG1} address"
chk "forbidden message token fails" 1 bash scripts/identity_gate.sh HEAD~1..HEAD 2>/dev/null

# 4. forbidden token in TRACKED CONTENT (even on a clean-identity commit): FAIL
echo "path: /home/${FRAG1}/bitcoin" > c.txt; git add -A
git -c user.name=BobClawblaw -c user.email=BobClawblaw@users.noreply.github.com commit -qm "clean message, dirty content"
chk "forbidden tracked content fails" 1 bash scripts/identity_gate.sh HEAD~1..HEAD 2>/dev/null

# 5. empty range: gate must FAIL loudly, not vacuously pass
chk "empty range fails loudly" 1 bash scripts/identity_gate.sh HEAD..HEAD 2>/dev/null

# 6. the gate script and the rule doc themselves carry no forbidden literals
FRAG1=$(printf "%c%c%c" 120 105 97)$(printf "%c" 110)
FRAG2=$(printf "%c%c%c%c%c%c" 97 110 116 107 111 119)
FRAG3=$(printf "%c%c%c%c%c%c%c%c%c" 99 104 114 105 115 116 105 97 110)
FRAG4=$(printf "%c%c%c%c%c" 103 109 97 105 108)
ALT="$FRAG1|$FRAG2|$FRAG3|$FRAG4"
if grep -qiE "$ALT" "$SRC_REPO/scripts/identity_gate.sh" "$SRC_REPO/docs/IDENTITY_RULE.md" 2>/dev/null; then
  echo "FAIL rule/gate files carry the literals"; FAIL=$((FAIL+1))
else
  echo "ok  rule/gate files are literal-free"; PASS=$((PASS+1))
fi

echo "identity-gate tests: $PASS passed, $FAIL failed"
cd /; rm -rf "$REPO"
[ "$FAIL" = 0 ]
