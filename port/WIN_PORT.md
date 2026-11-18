# Windows (x86-64) port: design, branch model and gate

`port/win/` builds the node natively for Windows 10/11 on x86-64: no WSL,
no Cygwin, no MSYS runtime, and no MSVC C runtime. `bmcbitcoind`, the CLI
tools and the repo's test harness run as ordinary Win64 processes.

State and dated evidence: [`WIN_STATE.md`](WIN_STATE.md) (newest first).
The Windows side's daily trail: `worklog/*-win.md`.

## Design: the Linux build, retargeted

The x86-64 assembly and the shared C are the same code that Linux runs, and
they keep their Linux view of the world (LP64, the SysV calling convention,
Linux syscall numbers, musl's libc):

- **C** (the daemon, RPC, tests and a static musl 1.2.5) is compiled for
  `x86_64-linux` to LLVM IR. `tools/retarget.py` moves the IR to
  `x86_64-windows-msvc` and keeps the SysV calling convention on every
  function, then clang generates COFF code. C semantics (`long` is 64 bits,
  struct layouts, varargs) are the Linux build's.
- **Assembly** (`asm/*.asm`) is assembled by NASM with `-f win64` after
  `tools/asm_xform.py` makes two rewrites. Each `syscall` instruction becomes
  a call to the emulation, and the ELF TLS access macro becomes PE TLS. The
  instructions and the data layout are otherwise untouched.
- **winsys** (`port/win/winsys/`, about 11k lines of C) is the only code
  with the Win64 ABI. It provides the process entry, the TLS directory and
  the stack probe, and it emulates the Linux syscalls the tree uses on
  Win32/NT: files, mappings, sockets (AFD), pipes, futexes, signals, `/proc`,
  `fork` (`RtlCloneUserProcess`, with the clone hazards written down in
  `ws_fork.c`), `exec`, seccomp, eventfd, symlinks (WSL-style reparse points,
  so no privilege is needed), `AF_UNIX` datagram sockets (mailslots, path
  and abstract names; `ws_uxdgram.c`), and more.
- **rt** (`port/win/rt/`) holds the few libc pieces musl's Linux build
  cannot supply on Windows: thread start, malloc over the private heap,
  `posix_spawn`, the resolver and `backtrace`.

So a change to shared C or to an `.asm` module needs no Windows twin. It
builds on Windows as it is, unless it calls a syscall (or a flag of one)
that winsys does not emulate yet. In that case the call returns `ENOSYS` or
`EINVAL` at run time, and the Windows gate shows the test that depends on it.

## Building

Requirements:
- LLVM/clang with `lld-link`, `llvm-lib` and `llvm-objcopy` (tested with
  LLVM 23).
- NASM 2.16 or later.
- The Windows SDK import libraries (`kernel32.lib` and the others), from
  the Visual Studio Build Tools or a standalone Windows SDK. No MSVC
  compiler or CRT is used.
- Python 3.
- For the gate's shell-script tests: Git for Windows (its `sh.exe`,
  found automatically or named with `BMC_WIN_SH`).

`build.py` downloads musl 1.2.5 once and checks its SHA-256.

```bat
python port\win\build.py daemon:bmcbitcoind daemon:bmc_cli daemon:bmc_wallet_cli
python port\win\run_tests.py              :: the Windows gate (exit 0 = pass)
python port\win\run_tests.py --only test_reorg,test_win_fork
```

The output lands in `port/win/out/bin/` (or in `$BMC_WIN_OUT/bin`). Build
outside your user profile (for example under `C:\src`) so that the debug
info embeds no personal path.

Run the daemon exactly as on Linux, with a Windows or `/c/...` datadir:

```bat
port\win\out\bin\bmcbitcoind.exe serve C:\bmc-data
```

## The gate

`run_tests.py` runs the `./tests/...` lines of `asm/Makefile`'s `test:`
recipe, so a test added to the recipe on `main` is in the Windows gate
without any change here. It builds and installs the daemon tools the tests
exec (`asm/daemon/*.exe`, gitignored) and then runs the port's own tests
(`port/win/tests/test_win_*.c`). The exit status is 0 only when every test
passes or is a known Windows limit (`KNOWN` in `run_tests.py`, reported
N/A, the way the Mac reports its x86-only tests).

The harness expands the recipe's make variables (`$(VAR)`,
`$(shell seq a b)`, `$(wildcard ...)`, with the environment taking
precedence, as in make) and drops a `< /dev/null`, since the tests run with
stdin on `/dev/null` anyway. A line with any other shell syntax is reported
SKIP; today there are none. Two inputs live outside the repo, as on Linux:
- `CORE_BENCH_BLOCK`, Bitcoin Core's `src/bench/data/block413567.raw`. Set
  it to the file's path to add the real-block cases to the four `*_diff`
  parsers and `bench_abi_audit`. Without it they run their synthetic cases
  and say so.
- The taproot fixtures of `test_taproot_block_diff`, which `make fixtures`
  fetches from the x86 side's Core oracle. Without them the test skips its
  36 heights, loudly.

The known limits, the only N/A rows:
- `test_cli_prompt` needs a pty (`forkpty`). One of its cases also passes a
  40,000-byte argument through `sh`, longer than the 32,767-character
  Windows command line.
- `test_drop_appends` measures page-cache residency through `mincore` on a
  fresh mapping. Windows has no unprivileged query for that.
- `test_mpool_get_once` uses ptrace.
- `test_elf_hardening` checks PIE, RELRO and NX in ELF headers. The
  Windows binaries are PE.

## Branch model (the same as the Mac's)

- `main` is the tree every platform builds from: Linux x86-64
  (`asm/Makefile`), macOS arm64 (`port/osx/`) and Windows x86-64
  (`port/win/`).
- `windows-port` is the Windows working branch. Windows work lands there
  first and reaches `main` through PRs. `origin/main` is merged into it as
  `main` advances. Never rebase it: the merge points stay visible.
- Syncing after `main` advances:

      git checkout windows-port
      git fetch origin
      git merge origin/main
      python port\win\run_tests.py      # the gate, in full, before the sync is done

  A merge that brings in a new syscall shows up as a failing test. The fix
  goes into winsys on `windows-port`.
- The port touches no shared file, apart from the `.gitignore` lines for
  the installed `.exe` tools. A shared-C fix found on Windows goes to `main`
  as a PR of its own, cherry-picked onto `origin/main` without the `port/`
  files, as the Mac does.
- Notes between the sides: `worklog/*-note-for-x86*.md` and
  `*-note-for-osx*.md` from the Windows side, and `*-note-for-win*.md` to it.

## Layout

- `port/win/build.py`: the build driver. Targets are `daemon:<name>`,
  `test:<name>`, `port:<name>`, `musl`, `rt` and `winsys`. It takes the
  compile and link rules from `asm/Makefile` (`tools/mkrules.py`), so a
  file added to a Makefile link list is picked up on Windows too.
- `port/win/run_tests.py`: the gate.
- `port/win/winsys/`: the syscall emulation. `winsys.h` is its interface,
  `ws_*.c` one area each.
- `port/win/rt/`, `port/win/include/`: the libc pieces and headers musl
  needs on Windows.
- `port/win/asm/`, `port/win/link/`: the assembly prelude (setjmp, TLS
  fallback) and the link-time data bounds.
- `port/win/tools/`: `retarget.py`, `asm_xform.py` and `mkrules.py` (the
  build); `stackscan.py` and `prof_report.py` (debugging and profiling).
- `port/win/tests/`: the port's own tests, one per emulated behaviour
  that went wrong once.

## Debugging knobs (environment)

`BMC_WIN_STRACE=1|2` (with `BMC_WIN_STRACE_LOG=<file>`), `BMC_WIN_NETDEBUG`,
`BMC_WIN_CRASHLOG` (a crash report on a fault), `BMC_WIN_PROF=<file>` (the
sampling profiler; `tools/prof_report.py` reads it), `BMC_WIN_FORKDEBUG`
and `BMC_WIN_EXITDEBUG`. To backtrace a hung process, attach lldb with
`thread backtrace all`. Do not attach to a live daemon: on detach, Windows
kills the processes it forked.
