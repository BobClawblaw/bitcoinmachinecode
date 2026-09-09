# macOS / Apple Silicon port — branch & sync model

This branch is `bmc_osx`, a long-lived port of the x86-64 assembly Bitcoin
core to Apple silicon (AArch64 + Darwin/Mach-O), so the project builds and
runs NATIVELY on macOS hosts (development machine: M1 Max).

`main` remains the x86-64 development tree. **Do not develop against main**;
it is touched only to merge new features into `bmc_osx`.

> **CURRENT STATUS (2026-09-09): fresh start, no ported code yet.** See
> [`port/OSX_ROADMAP.md`](OSX_ROADMAP.md) for the per-module plan and
> [`worklog/`](../../worklog/) for the daily trail.

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
    # ANY new/changed upstream .asm module needs a macOS twin below, verified,
    # before considering the sync done.

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
- `worklog/YYYY-MM-DD.md` — dated session logs (repo root, x86 convention).
- `docs/devlog/LOG.md` — long-running engineering record; port entries are
  appended there for durable developer memory, same as x86 does.

## Developer memory convention (inherited from x86/arm-port)
- Every work session appends a section to `worklog/YYYY-MM-DD.md` (UTC date).
  Terse bullets: action → evidence (test result, probe output, commit id).
- Meaningful engineering events (bug hunts, root causes, decisions) also go
  into `docs/devlog/LOG.md`.
- Durable rules learned go into `docs/ENGINEERING_RULES.md`, each citing the
  incident that produced it.
- Per-module status lives in `port/OSX_ROADMAP.md` and is only flipped to
  DONE when the repo's own suite + differential verification pass natively.
- Worklogs are committed so the trail is versioned with the code.
