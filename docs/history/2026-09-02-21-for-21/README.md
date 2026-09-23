# 21 FOR 21

**Twenty-One Days. Twenty-One Million Sats. Zero Human Lines.**

The post-mortem of the **Bitcoin Machine Code** experiment — building a full
validating Bitcoin node for Linux x86-64 entirely in hand-crafted assembly,
every line authored by AI (seven models, one operator), with zero human-typed
code.

**Read it:**
- [`21_FOR_21_the_report.pdf`](21_FOR_21_the_report.pdf) — A4 print edition, 64 pages, clickable TOC + bookmarks
- [`21_FOR_21_the_report.html`](21_FOR_21_the_report.html) — web edition
- [`21_FOR_21_the_report.md`](21_FOR_21_the_report.md) — source of truth

**What's inside:** eleven parts and 38 chapters covering the incident-driven
path from SHA-256 in assembly to a mainnet node whose UTXO set is MuHash-identical
to Bitcoin Core's at height 963,967 — the false-accept horizon, the 2,596
resurrected coins, the awk command that froze the host, two independent
security audits, the human-AI authorization contract, a chapter naming the
seven models that wrote the code, and the numbers (with methods) behind the
title.

**Rebuild it:** edit the `.md`, run `./rebuild.sh` in this directory
(needs python3 + weasyprint + PyMuPDF).

The code the report describes lives at
[BobClawblaw/bitcoinmachinecode](https://github.com/BobClawblaw/bitcoinmachinecode).
