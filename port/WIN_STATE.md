# WINDOWS PORT STATE: durable snapshot

Updated whenever the status materially changes. The newest section is at
the top. Companion to [`WIN_PORT.md`](WIN_PORT.md), which covers the design,
the build, the gate and the branch model.

## 2026-11-12: into the pipeline

The port now follows the Mac's model. `windows-port` is the working
branch: it merges `origin/main` (merged through #496 today, 9d34527d) and
reaches `main` by PR. This file, `WIN_PORT.md`, `worklog/*-win.md` and the
`note-for-*` files in `worklog/` are how the sides keep each other
informed.

**The gate.** `port/win/run_tests.py` now exits 0 only on a pass. It runs
the `./tests/...` lines of `asm/Makefile`'s `test:` recipe, then the port's
own `port/win/tests/test_win_*.c`.
- Four tests are N/A, for reasons the platform imposes:
  - `test_cli_prompt` needs a pty. One of its cases also passes a
    40,000-byte argument, longer than the Windows command line allows.
  - `test_sd_watchdog` uses systemd's AF_UNIX datagram socket.
  - `test_drop_appends` measures page-cache residency through `mincore` on a
    fresh mapping.
  - `test_mpool_get_once` uses ptrace.
- One timing test is retried up to three times, as `port/osx` does:
  `test_rpc_responsive`, whose "< 0.5 ms CPU per `getindexinfo`" bound was
  set on Linux. The call does two `CreateFileW` here, and those cost about
  0.4 ms (0.34 to 0.76 ms over 10 runs, against about 0.025 ms on Linux and
  the Mac).

**Gate run 15 (this branch, merged with main through #496):** 494 PASS,
8 SKIP, 4 N/A, 0 FAIL, 0 TIMEOUT over 506 commands: the 481 recipe lines
plus 25 port tests. The SKIP rows are recipe lines with shell syntax.
`test_rpc_responsive` passed on its first attempt. `test_win_asmconnect`
built only after the rest of the run: port tests can now name the `asm/`
modules they link, with a `port-link:` line. It was re-run on its own and
passes.

**Fixed since run 13 (2026-11-11: 464 PASS, 8 SKIP, 10 FAIL):**
- *Symlinks* are WSL-style reparse points (`IO_REPARSE_TAG_LX_SYMLINK`).
  An unprivileged user can create them; NTFS symlinks need Developer Mode
  or admin. WSL and Cygwin read them. Paths follow a link at the last
  component, lazily: only where Windows reports a reparse point, so an
  ordinary path costs nothing extra. `lstat`, `readlink`, `O_NOFOLLOW`,
  `O_CREAT|O_EXCL`, `readdir`'s `DT_LNK` and `link()` (hard links) behave
  as on Linux. This fixed `test_wallet_txlog`, `test_wallet_pass`,
  `test_utxo_manifest_bad`, `test_dumptxoutset_path` and
  `test_store_rollover_fd`, which plant symlinks to prove the code refuses
  them. Pinned by `test_win_symlink` (30 checks).
- `/proc/self/smaps` `Rss` is the part of a mapping in the working set
  (`QueryWorkingSetEx`), not its whole size. This fixed
  `test_lsm_reads_pread`: pread reads leave 3% of the run files resident,
  the mapped path 83%.
- `/dev/tty` is the console, and `tcsetattr` switches its echo. Before
  this, `wallet_cli`'s passphrase prompt (echo off through `/dev/tty`) gave
  up without asking on Windows. Pinned by `test_win_tty`.
- `fork` waits out threads in DLL thread-detach (08c761f5).
  `test_dlc_header_probe` hung about 1 run in 40 when a thread was exiting
  through Winsock's detach while the fork held the heap lock. Gating both
  thread exits (return and `exit(2)`) fixed it: 0 hangs in 50.
- **A shared-C fix, `fix/2026-11-12-shutdown-scan-race`** (bea1572c, a PR
  of its own, also on this branch as 6f657390). `shutdown_wait_lock_released`
  read "the worker is gone" after its lock scan, so a worker reaped during
  the scan turned the scan's list (the worker and its exiting fold worker)
  into "orphans" to SIGTERM. The `/proc` walk takes about 70 ms here, so
  `test_stop_waits_for_worker` failed about 1 run in 12. With the fix it
  passed 30 of 30. It has not been run through the x86 gate; see
  `worklog/2026-11-12-note-for-x86.md`.

**The node.** A signet node runs natively from this branch
(`bmcbitcoind serve`, RPC on 8888). It is synced, following the tip with
about 11 peers, and was restarted on the 2026-11-11 build. Earlier, a
`chainwork.dat` written by an early build with wrong per-header work (a
port bug, fixed in 4fe324b3) made it refuse a valid reorg as below
`-minimumchainwork`. `bmc_chainwork_build` rebuilt the file. The daemon
does not check that file against the headers, on any platform (noted for
x86).

## 2026-11-11: the daemon syncs signet natively

`bmcbitcoind` syncs signet to the tip and follows it on Windows.
- `fork` is `RtlCloneUserProcess`, with the clone hazards handled in
  `ws_fork.c`:
  - ntdll's inherited address-wait tables hold "ghost" waiters (parent
    threads blocked at the fork);
  - critical sections and SRW locks may be held at the fork; the child
    resets the process heap's lock, the PEB lock and the loader lock;
  - MADV_DONTFORK ranges are dropped in the child.
- Signals reach any winsys process through named signal boxes.
- `/proc` covers our own process and others: `fd`, `stat`, `task`,
  `smaps`. `kcmp` works too.
- Sockets are AFD with Linux semantics: shutdown(SHUT_RD), a lingering
  close, TCP_INFO, SO_SNDTIMEO, SCM_RIGHTS.
- seccomp BPF filters, eventfd, and per-thread CPU clocks from cycle
  counters.

Gate run 13: 464 PASS, 8 SKIP, 10 FAIL, 0 TIMEOUT (482 commands).
