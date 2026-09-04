#!/bin/bash
# identity_gate.sh [<rev-range>]  — hard pre-push check per docs/IDENTITY_RULE.md.
# Default range: HEAD~1..HEAD (the commit about to ship). With a range, checks
# every commit in it. Fails (exit 1) on:
#   - any author/committer outside the canonical identity
#   - any forbidden token in commit messages or diff content
#   - any forbidden token anywhere in the tracked tree (content scan)
set -u
RANGE=${1:-HEAD~1..HEAD}
cd "$(git rev-parse --show-toplevel)"
# forbidden fragments, assembled from character codes so this file carries no
# literal: codes = per-fragment groups joined to an alternation
FRAG_CODES=("120 105 97 110" "97 110 116 107 111 119" "99 104 114 105 115 116 105 97 110" "103 109 97 105 108")
FRAG=""
for g in "${FRAG_CODES[@]}"; do
  fmt=""; for c in $g; do fmt="$fmt\\x$(printf '%02x' "$c")"; done
  w=$(printf "$fmt")
  FRAG="${FRAG:+$FRAG|}$w"
done
BAD="$FRAG"
fail=0
N=$(git rev-list --count "$RANGE" 2>/dev/null || echo "")
if [ -z "$N" ]; then echo "IDENTITY-GATE: cannot resolve range '$RANGE'"; exit 1; fi
if [ "$N" = "0" ]; then echo "IDENTITY-GATE: empty range (nothing checked)"; exit 1; fi
while IFS='|' read -r an ae cn ce; do
  [ "$an $ae" = "BobClawblaw BobClawblaw@users.noreply.github.com" ] || { echo "IDENTITY-GATE: bad author: $an <$ae>"; fail=1; }
  [ "$cn $ce" = "BobClawblaw BobClawblaw@users.noreply.github.com" ] || { echo "IDENTITY-GATE: bad committer: $cn <$ce>"; fail=1; }
done < <(git log "$RANGE" --format="%an|%ae|%cn|%ce" | sort -u)
if git log "$RANGE" --format="%B" | grep -qiE "$BAD"; then
  echo "IDENTITY-GATE: forbidden reference in commit messages:"
  git log "$RANGE" --format="%H %B" | grep -iE "$BAD" | head -5
  fail=1
fi
# content scan: the tree at HEAD (what actually ships)
if git grep -qiE "$BAD" HEAD 2>/dev/null; then
  echo "IDENTITY-GATE: forbidden reference in tracked content:"
  git grep -l -iE "$BAD" HEAD | head -5
  fail=1
fi
[ $fail -eq 0 ] && { echo "IDENTITY-GATE: OK ($N commits, tree clean)"; exit 0; }
exit 1
