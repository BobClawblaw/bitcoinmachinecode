# Strategy: getting the x86 node onto Apple silicon (bmc_osx)

Written 2026-09-09, before any porting. This is the plan-of-record; per-module
status lives in `OSX_ROADMAP.md`, branch rules in `OSX_PORT.md`.

## The core decision: port, don't emulate

Two ways to run the x86 tree on Apple silicon:

1. **Emulation/transpilation** (Rosetta is x86->Apple-silicon binary
   translation but is macOS-on-Apple-silicon only for *existing Mac x86
   binaries* — there is no Rosetta for Linux ELF; boxes like Box64/FEX
   translate Linux x86-64 userland on AArch64). This would run the node
   unmodified but: slow (usually 2-6x), syscall-shimmed, and the project's
   whole point is hand-authored machine code running natively. Rejected as
   the end state; useful only as a *verification cross-check* later
   (run x86 tests under Box64 in an arm64 Linux container and diff behavior).
2. **Native port of the assembly to AArch64 + Darwin** — same model as the
   arm-port branch: rewrite each `asm/<name>.asm` as `port/osx/<name>.S`
   exposing identical public symbols so the ~166 arch-neutral C files
   (daemon + harnesses) link unchanged. This is the chosen path.

The arm-port already proved the *method* on Linux AArch64 (all 63 modules
differential-verified). bmc_osx repeats it with two extra deltas — Mach-O
object format and the Darwin syscall layer.

## Measured port surface (2026-09-09)

- Assembly: 62 .asm modules, ~50k LOC, 238 raw `syscall` instructions.
  Heaviest syscall users: bitcoin_utxo_lsm 65, bitcoin_store 51,
  bitcoin_utxo_store 31, bitcoin_idxscan 19, bitcoin_undo 17,
  bitcoin_store_fast 15. The remaining ~46 modules are mostly pure compute
  (crypto, script, consensus math) — those port fastest and verify hardest.
- C layer: 113 daemon .c + 53 asm .c are arch-neutral POSIX; only two files
  touch a genuinely Linux-only API: `coinstats_index.c` and `log_ts.h` use
  `prctl(PR_SET_PDEATHSIG/PR_GET_NAME)` (macOS replacements: poll
  getppid() after fork, `pthread_getname_np`). No epoll/eventfd/io_uring
  anywhere — the socket layer is plain poll()/pthread, which macOS has.
- Locking: no futex anywhere (asm or C) — pthread/mutex only in C, which
  macOS has. Verified 2026-09-09. The socket layer in asm is raw syscalls
  too (`bitcoin_net.asm`: socket/connect/sendto/recvfrom/setsockopt with
  the x86 `R10 = arg4` convention — the Darwin port must use x3 natively
  and re-check every arg register shift).

## Layered plan (PR-per-layer, each merged --no-ff into bmc_osx)

Work happens in short-lived branches off `bmc_osx`, one PR each, merged back
with `--no-ff` after the gate. `main` is x86-only and never receives these.

### Phase 0 — build bridge (PRs: `osx/p0-*`)
Prove Mach-O AArch64 can build repo C + a trivial .S and run a harness.
- `port/osx/build.sh` mirroring asm/Makefile's rules with Apple clang:
  `.section __TEXT,__text`, `_`-prefixed symbols, adrp/add GOT loads.
- Shim header `port/osx/darwin_compat.h` for the C side (prctl -> pthread
  names, etc.) so C compiles on macOS without touching upstream C in place.
- Deliverable: one pure-compute module (sha256) builds, links, and passes
  its harness natively. This de-risks the toolchain before any real module.

### Phase 1 — pure-compute consensus/crypto modules (PRs: `osx/p1-<module>`)
~46 modules with few/no syscalls: sha256/blake2/muhash, secp256k1 field/EC,
bip340, bech32/base32, aes/hmac/chacha, bip143/341/342, sighash, interp,
scriptcodec, multisig, cons, chainwork, pubkey, keys, headers (compute parts).
Ordering: crypto primitives -> script VM -> consensus aggregation. Each PR:
port .S, link repo harness, differential-fuzz vs C twin/Python oracle, flip
the module line in OSX_ROADMAP.md, worklog entry.

### Phase 2 — I/O and storage syscall layer (PRs: `osx/p2-<module>`)
The syscall-heavy six (utxo_lsm, store, utxo_store, idxscan, undo,
store_fast) plus net/p2p/addrmgr/idx/idxscan/headers(syscalls)/cli/serve.
Darwin syscall deltas per module: `svc #0x80`, nr in x16, errno convention,
no SYS_fcntl64-style split, `F_FULLFSYNC` instead of fdatasync where the
code means durability (apple fsync lies on some fs), pread/pwrite offsets
differ, vDSO-equivalents (gettimeofday) via platform libs. Where a Linux
syscall has no Darwin twin, add a tiny C shim in `port/osx/shims/` and call
it with `bl _bmcshim_*` — correctness over purity; note every shim in
OSX_ROADMAP.md.

### Phase 3 — daemon assembly + native run (PRs: `osx/p3-daemon`)
Link all modules + daemon C into a macOS `bmcbitcoind`, fix remaining
link/ABI gaps (16-byte stack alignment with LR on stack, x18/x28 reserved,
no red-zone assumptions), run regtest IBD, then signet/testnet4.

### Phase 4 — verification parity (PRs: `osx/p4-*`)
Run the repo's parity sweep + differential oracles natively; cross-check
against an x86 run of the same tests (Linux container on this Mac, native
x86 via Rosetta or Box64 in arm64 Docker) and diff outputs. Only then
consider mainnet IBD on Apple silicon.

## Why PR-per-work-branch fits this repo
Matches the x86 tree's existing cadence (PR #127 etc., --no-ff merges, green
gate before merge). Each port module lands reviewable and revertable; the
merge history on `bmc_osx` stays a line of audit points exactly like main's.

## Risks, stated up front
- Darwin syscall errno/flag semantics differ in corners (e.g. EINTR on
  signals is more aggressive; SIGPIPE default-on for sockets) — every
  syscall site gets a differential test, not just a build.
- The arm-port's Linux .S is an *algorithm reference only*; copying it
  wholesale imports Linux-isms (x28 frames, flag-based error checks) that
  will fault on macOS.
- `F_FULLFSYNC`/fsync semantics affect the store's durability invariants —
  verify crash-consistency assumptions, not just bit-correctness.
