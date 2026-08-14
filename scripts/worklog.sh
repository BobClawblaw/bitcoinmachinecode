#!/usr/bin/env bash
# worklog.sh -- open (and create if missing) today's daily worklog file.
#   scripts/worklog.sh              -> worklog/$(date +%F).md
#   scripts/worklog.sh 2026-08-20   -> worklog/2026-08-20.md
# If the file is new it is seeded with the header below; then EDITOR ($EDITOR
# or vim) is opened on it. Exits 0.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
day="${1:-$(date +%F)}"
# validate YYYY-MM-DD shape (loose)
case "$day" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;; *) echo "bad date $day" >&2; exit 2 ;;
esac
f="$repo/worklog/$day.md"
if [[ ! -f "$f" ]]; then
  cat > "$f" <<EOF
# DAILY WORKLOG — $day

Bitcoin Machine Code (x86-64 NASM node). One file per day; newest top.
EOF
  echo "created $f"
fi
echo "$f"
"${EDITOR:-vim}" "$f"
