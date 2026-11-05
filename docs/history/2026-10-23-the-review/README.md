# The Review

**Bitcoin Machine Code, 2026-10-23.** A security and code review of everything
since the 09-03 audit found 9 HIGH, 18 MEDIUM and 36 LOW findings, five of the
HIGHs consensus splits from Core. All were fixed in seven batches. Formal
verification of four areas (consensus arithmetic, the secp256k1 assembly, the
UTXO store's crash consistency, the parsers of untrusted input) then found a
proof-of-work encoding defect, six crash-consistency holes in the store and
seven parser divergences. Fixing those turned up a comma expression that had
disabled two boot checks since 2026-09-05, and seven `getblocks` defects. The
final build passes the 474-test gate and a from-genesis sync whose UTXO set is
MuHash-identical to Core v31.1's at height 972,848. The fixes are PRs #424 to
#435.

- [`THE_REVIEW.md`](THE_REVIEW.md): source of truth (about 5,700 words)
- [`THE_REVIEW.pdf`](THE_REVIEW.pdf): A4 edition, 22 pages, clickable contents and bookmarks
- The audit itself: [`docs/audits/SECURITY_AUDIT_2026-10-23.md`](../../audits/SECURITY_AUDIT_2026-10-23.md)

Edit the `.md`, then rebuild with `python3 make_pdf.py` (python3, weasyprint,
PyMuPDF).
