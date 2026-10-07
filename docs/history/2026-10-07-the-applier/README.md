# The Applier

**Bitcoin Machine Code, days 41 to 57 (2026-09-21 to 2026-10-07).** The node went
from 5.9% ahead of Bitcoin Core v31.1 on a link-bound sync to 2.6× ahead on a
repaired one: run 41 had every index at the tip in 3 h 48 m 22 s, against Core
rerun #7's 9 h 50 m 04 s, with the UTXO set MuHash-identical. A fully logged pair
showed the lead had come from downloading and applying at once, while bmc's
per-block apply was 23% *slower* than Core's. The report follows the work that
made the applier 11% faster than Core's. It also covers the two production
outages and what each added to "a verified deploy", Core ignoring every
transaction bmc relayed, and the bench rows and labels that had to be
corrected.

- [`THE_APPLIER.md`](THE_APPLIER.md): source of truth (about 6,200 words)
- [`THE_APPLIER.pdf`](THE_APPLIER.pdf): A4 edition, 21 pages, clickable contents and bookmarks
- `THE_APPLIER.bbcode`: the forum edition, one post (about 39,500 characters)

Edit the `.md`, then rebuild with `python3 make_pdf.py` (python3, weasyprint,
PyMuPDF) and `python3 make_bbcode.py`.
