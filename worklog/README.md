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

**Practice since 2026-09-25 (recorded 2026-10-07).** The daily file is still
the default, but three other shapes have joined it. Name each with its date:

- `YYYY-MM-DD-resume.md`: a hand-off written when a session ends mid-task,
  saying what is running, what is pending and how to pick it up (09-30 to
  10-03).
- `YYYY-MM-DD-<topic>.md`: a plan or design that outlives one day, appended
  with dated sections as it lands. Examples are `2026-10-04-logged-ibd-runs-plan.md`,
  `2026-10-05-b3-b4-design.md` and `2026-10-05-performance-holes-plan.md`.
  The last is the register for plan items A1–A8, B1–B13 and M1, with a
  status table at the top.
- `YYYY-MM-DD-note-for-x86*.md`: notes from the macOS tree (`bmc_osx`)
  for this one.

From 10-04 to 10-07 the work was recorded mainly in the performance plan and
in the PRs, release notes and stage reports it points to. `2026-10-07.md`
resumes the daily file.
