# 2026-09-07 — The status line says 'in flight N of window W' and how old the oldest gap is, not 'holes'

With 16 workers on 40-block chunks a few hundred heights are always claimed and not yet landed; that is work in progress bounded by the window, not blocks nobody will fetch. The line now reads `in flight N of window 4096 through H (oldest gap Ns at h, P% landed)`; a gap that has been the first hole for 60 s or more prints as STRANDED with height and age. Logging only; full gate 0 failures, 8 audits exit 0.

---

PR #82 (`batch/2026-09-07-inflight-label`), merged 17:32Z as `1a3973a0`; tag `inflight-label-2026-09-07`.
