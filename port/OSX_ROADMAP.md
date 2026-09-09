# macOS / Apple Silicon Port Roadmap — bitcoinmachinecode

Goal: run this project NATIVELY on Apple silicon (AArch64 + macOS/Darwin) by
rewriting the 62 x86-64 assembly modules (~50k LOC) in Apple-clang AArch64
assembly, one at a time, each validated against the repo's own C oracles /
test vectors / differential fuzz. The daemon C is portable and links these
modules, so once the symbols the daemon uses exist as Mach-O AArch64
objects, the daemon links and runs natively on macOS.

Read `port/OSX_PORT.md` first for the branch/sync model. Worklog:
`worklog/YYYY-MM-DD.md`; long-form engineering record: `docs/devlog/LOG.md`.

## Toolchain (verified 2026-09-09)
- Apple clang 21.0.0 (`cc`) — assembles .S with Mach-O AArch64.
- Build target: `port/osx/` objects + repo C, linked against the repo
  harnesses. Keep names/symbols identical to upstream so nothing else
  changes.

## Method (inherited, proven on arm-port)
1. Read the upstream `asm/<name>.asm` to capture the EXACT public ABI +
   semantics (SysV amd64 rdi/rsi/rdx -> AAPCS64 x0/x1/x2; bswap -> rev).
2. Write `port/osx/<name>.S` exposing identical symbols so existing C
   harnesses / daemon link UNCHANGED.
3. Build native: `cc -c <name>.S` (Mach-O), link the repo C harness, run it.
4. Differential-verify against the C twin / Python oracle over thousands of
   random vectors.
5. Mark DONE only when the repo's suite + differential checks pass natively.

## Darwin vs Linux-AArch64 deltas (the reason this is a fresh port, not arm-port)
- Mach-O, not ELF: no `.note.GNU-stack`, different section directives
  (`.section __TEXT,__text`), symbol scaffolding (`_` prefix on symbols,
  `.globl _name`).
- Syscalls: Linux `svc #0` (nr in x8, args x0-x5, carry-flag error
  convention) -> Darwin `svc #0x80` (nr in x16, args x0-x7, returns
  +errno in x0 with carry bit set on error via `b.cs`). Library calls via
  `bl _symbol` preferred where possible.
- x28 is the platform register (APFS/TSD) — never use it as a callee-saved
  work register (arm-port used x28-based frames).
- x18 reserved (platform); red zone differs; stack 16-byte aligned and LR
  must be saved at callsites (Mach-O contract).
- PIC required: page-relative adrp/add + GOT loads for extern symbols.

## Status
(No modules ported yet. Copy the arm-port module list as the checklist and
mark each with: -> IN PROGRESS -> DONE (date, verification evidence).)

## Verification gates before any merge/deploy
- Native build of touched module + repo harness run.
- Differential fuzz vs C twin / Python oracle (thousands of vectors).
- Relevant arm-port parity notes used as the expected-behavior reference.
- Worklog + OSX_ROADMAP updated in the same commit as status changes.
