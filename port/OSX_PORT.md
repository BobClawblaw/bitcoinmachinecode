# macOS / Apple Silicon port — branch & sync model

This branch is `bmc_osx`, a long-lived port of the x86-64 assembly Bitcoin
core to Apple silicon (AArch64 + Darwin/Mach-O), so the project builds and
runs NATIVELY on macOS hosts (development machine: M1 Max).

`main` remains the x86-64 development tree. **Do not develop against main**;
it is touched only to merge new features into `bmc_osx`.

> **CURRENT STATUS (2026-09-28): the port is complete and in production.**
> Every x86 assembly module the daemon runs has an AArch64 `.S` in
> `port/osx/` (the 37 C twins of the first two weeks were converted on
> 09-26; x86's later additions — safegcd inversion, the square-root chain,
> the comb / window / GLV multiplies, SHA-1's two bodies — followed within a
> day of landing). The repo's gate runs natively through
> `port/osx/run_tests.sh`: 417 PASS, 10 SKIP, 14 N/A (x86-only shadow-twin
> diffs), 0 FAIL. A mainnet and a signet node run from this branch on an
> M-series Mac at Core's tip. Dated evidence: [`OSX_STATE.md`](OSX_STATE.md)
> (newest top); per-module: [`OSX_ROADMAP.md`](OSX_ROADMAP.md) (status
> summary at its top); the daily trail: `worklog/*-osx.md`.
>
> The branch is also where shared-C fixes found on the Mac are made first
> and sent to `main` as PRs (#322, #325, #337, #340), and `main` is merged
> in as it advances — the two sides exchange `worklog/*-note-for-osx*.md`
> and `worklog/*-note-for-x86*.md`.

## Branch model
- `main`   : upstream x86-64 development tree. x86 is where features land.
- `bmc_osx`: our port branch, kept in sync by periodically merging
  `origin/main` into it. Never rebase (merge points stay visible), same
  model the arm-port branch used.

## Keeping in sync (do after upstream `main` advances)
    git checkout bmc_osx   # (we are already here in ~/bmc_osx/bitcoinmachinecode)
    git fetch origin
    git merge origin/main
    # C daemon + tests usually merge clean; asm/Makefile edits may conflict.
    # ANY new/changed upstream .asm module needs its port/osx/<name>.S
    # brought level -- a new export the shared C calls fails the link, which
    # is the signal -- and port/osx/run_tests.sh in full before the sync is
    # done. A shared-C fix made here goes to main as a PR (cherry-pick onto
    # origin/main; drop the port/ files).

## Why a fresh port instead of reusing arm-port
The `arm-port` branch (kept on origin as reference) produces AArch64 code
that makes **Linux raw syscalls** (`svc #0` with Linux syscall numbers).
Darwin has a different syscall table, different conventions (syscall
number in x16, no NZCV on return — carry flags in arm-port code do not
transfer), Mach-O object format instead of ELF, and different ABI details
(platform register x28 is reserved, `.note.GNU-stack` sections do not
exist, stack must stay 16-byte aligned with LR on the stack at callsites).
The arm-port is a good *algorithm* reference (all 63 modules were
differential-verified there), but every syscall-touching line must be
reworked for Mach-O. The syscall-heavy modules are the heavy lift:
bitcoin_utxo_lsm (66 svc), bitcoin_store (42), bitcoin_utxo_store (30),
bitcoin_idxscan (19), bitcoin_undo (18), bitcoin_store_fast (17).

## Layout (this branch)
- `asm/`              — upstream x86-64 NASM modules (~50k LOC) + arch-neutral C.
- `port/osx/<name>.S` — macOS AArch64 rewrite of each `asm/<name>.asm`, SAME
  public symbols so C harnesses/daemon link unchanged (mirrors arm-port layout).
- `port/OSX_ROADMAP.md` — per-module status + verification method (READ FIRST).
- `port/OSX_STATE.md` — durable port state snapshot, updated whenever status
  materially changes.
- `worklog/YYYY-MM-DD-osx.md` — the Mac side's dated session logs (the x86
  side owns `worklog/YYYY-MM-DD.md`; separate files so the two sides' merges
  never conflict on a day file). `worklog/*-note-for-x86*.md` are the notes
  the Mac side leaves for x86 (shared-C findings, what to take), and
  `*-note-for-osx*.md` the reverse.
- `port/osx/test_support/*_twin.c` — the retired C twins, kept as the
  differential oracles for the `.S` modules.
- `docs/devlog/LOG.md` — long-running engineering record; port entries are
  appended there for durable developer memory, same as x86 does.

## Developer memory convention (inherited from x86/arm-port)
- Every work session appends a section to `worklog/YYYY-MM-DD-osx.md` (UTC
  date; `OSX_STATE.md` carries the durable version of the same events).
  Terse bullets: action → evidence (test result, probe output, commit id).
- Meaningful engineering events (bug hunts, root causes, decisions) also go
  into `docs/devlog/LOG.md`.
- Durable rules learned go into `docs/ENGINEERING_RULES.md`, each citing the
  incident that produced it.
- Per-module status lives in `port/OSX_ROADMAP.md` and is only flipped to
  DONE when the repo's own suite + differential verification pass natively.
- Worklogs are committed so the trail is versioned with the code.
