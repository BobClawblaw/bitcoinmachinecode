# 2026-09-08 — The first continuity test: a restart mid-sync deadlocked the downloader trigger

Run 17 was stopped at 134,409 blocks and restarted on its own datadir,
the first time a sync had been resumed rather than started over since
the window and retry ring landed. Three things had to hold: the headers
stay, the stored blocks above the in-flight holes stay, and the download
picks up where it stopped. The first two did (829,846 linked headers kept
ahead of the archive; the index trimmed only its empty tail). The third
did not.

The far-behind trigger that starts the parallel downloader has an
apply-first rule: while the archive holds more than 500 blocks the
connect has not applied yet, let the connect catch up before fetching
more. It computed that backlog as archive tip minus applied height, which
after a restart counts the holes the stopped run's in-flight chunks left
behind. The backlog read 523, the connect was stuck on the hole at
135,639, which only the downloader could fill, and the trigger said
"apply first" once a second, forever.

The backlog is now what the connect can actually apply, the contiguous
prefix up to the first hole. Four checks in `test_parallel_trigger`, one
of them the exact numbers of the deadlock. The hole warning that
flooded the log prints once per height. And the dashed tick line no
longer prints the rate unit twice.

Restarted on the fixed binary, the run resumed in 70 seconds: the
downloader started, the connect passed the hole, and the log shows no
warning. The cost of the continuity test was the run's benchmark clock,
which now straddles builds; its number is not comparable to Core.

## The incident before it

Run 16 was at 704,169 blocks after nine hours when the operator asked to
"relaunch with updated binary". The relaunch procedure used since run 10
wipes the benchmark datadir, because a benchmark number is a fresh sync,
and the operator meant a resume. The datadir was gone before the
difference surfaced. The procedure is now: a relaunch reuses the datadir
unless the operator asks for a fresh run.
