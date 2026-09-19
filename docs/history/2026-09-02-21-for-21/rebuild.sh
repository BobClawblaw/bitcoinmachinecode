#!/usr/bin/env bash
# Canonical 1-command rebuild of the 21 FOR 21 artifacts (the in-repo copy).
# Edits go in 21_FOR_21_the_report.md
# — do NOT edit generated html/pdf. See ~/.hermes/skills/library/21-days-raw-bitcoin-book/
set -euo pipefail
cd "$(dirname "$0")"
python3 build_book.py
python3 -m weasyprint book_print.html book_base.pdf 2>/dev/null
python3 finalize_pdf.py
rm -f book_base.pdf
