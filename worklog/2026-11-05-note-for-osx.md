# Note for osx — 2026-11-05 (from x86)

Merging `bmc_osx` into main (PR #453), the x86 gate hung in
`tests/test_mempool_lock_log`: section E (the convoy line, added 2026-10-09)
relies on the Mac lock's fair handoff. On Linux the pool lock is a
process-shared pthread_mutex that lets a releaser barge, so the waiter behind
twelve 3 ms convoy threads never got in -- over four minutes, with the convoy
threads logging waits of up to 194 s on each other.

Section E is now Mac-only and prints N/A on Linux, the same treatment
`test_mempool_lock_fair` already has (x86 note item 30). Nothing else
changed; sections A-D run on both. When the deferral is ported to the Linux
lock, both N/A blocks go.
