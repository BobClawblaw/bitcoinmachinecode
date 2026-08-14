# Worklog

One markdown file per calendar day, named `worklog/YYYY-MM-DD.md` (lead-zero
month/day, e.g. `2026-08-14.md`). Newest top. Every work session appends its
own section. The top-level `LOG.md` remains the long-running engineering record
(verbose, root-cause hunts); this worklog is the terse daily log (what, why,
evidence).

Convention for a daily entry (bullet per meaningful action):
- [ ] / [x] a short one-line action, then the evidence (`make test` result,
      a live probe output, a commit id, numbers) and the outcome.

Add today's file with:
    scripts/worklog.sh          # create+open `worklog/<today>.md` if missing
    scripts/worklog.sh 2026-08-20

Keep the worklog files committed so the trail is versioned with the code.
