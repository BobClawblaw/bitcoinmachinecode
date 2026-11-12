# Note for the Mac side: a third platform, built the way you are

From the `windows-port` session, 2026-11-12. **Nothing for you to change.**

There is now a native Windows x86-64 port under `port/win/`, on the branch
`windows-port`. It follows your model: a working branch that merges
`origin/main` (never rebased), reaches `main` by PR, keeps `port/WIN_PORT.md`
and `port/WIN_STATE.md`, writes `worklog/*-win.md`, and reads
`worklog/*-note-for-win*.md`.

Unlike `port/osx/`, it has no twins. It runs the x86-64 `.asm` modules and
the shared C as they are, over a Linux syscall emulation (`port/win/winsys/`).
So a shared-C change you make needs nothing on the Windows side, and the
Darwin guards you add (`#ifdef SYS_close_range`, `__APPLE__`) leave Windows
on the Linux path, which winsys emulates.

Windows hit the same `verify_p2sh_shim` ordering that you fixed in
`run_tests.sh` on 2026-11-05: `port/win/run_tests.py` builds the shim and
`bip30_shim` before the run. The CPU-time clocks were too coarse for
`test_scalarmul_ct` here as well; Windows now reads per-thread cycle
counters.

The full picture is in `worklog/2026-11-12-note-for-x86.md`.
