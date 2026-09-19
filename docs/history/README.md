# History: the long-form reports

Book-length accounts of the project, written from its own records (the git
history, the worklogs, docs/devlog, docs/reports, the registers and the audits),
with every quote verbatim and every figure sourced. They are the narrative layer
over everything else in docs/: what happened, why, and what it taught.

| report | covers | status |
|---|---|---|
| [21 FOR 21](2026-09-02-21-for-21/) | 2026-08-11 to 2026-09-02: from SHA-256 in assembly to a mainnet node whose UTXO set is MuHash-identical to Core's | published |
| [The Measuring Equipment](2026-09-19-the-measuring-equipment/) | 2026-09-02 to 2026-09-19: parity with Core v31.1, and making the benchmarks true | awaiting the Core v31.1 rerun and run 28 |

Each directory holds the Markdown source (the single source of truth), the
rendered editions (PDF, and for forum posting BBCode) and the scripts that
build them. Edit the `.md`, then rebuild:

- 21 FOR 21: `./rebuild.sh` (python3, weasyprint, PyMuPDF)
- The Measuring Equipment: `python3 make_pdf.py` and `python3 make_bbcode.py`

21 FOR 21 was first published from `/storage/bmc-book` on the project's host,
where the original is still served. The copy here rebuilds to the same PDF
(checked 2026-09-19: 64 pages, a 55-entry outline, identical text).
