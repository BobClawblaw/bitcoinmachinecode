# ARM port — branch & sync model

This branch is `arm-port`, a long-lived port of the x86-64 assembly Bitcoin
core to AArch64 so the project builds and runs NATIVELY on ARM64 hosts.

> **CURRENT STATUS (2026-09-08): PAUSED, and looking for a new host.** The port
> is feature-live — a fresh mainnet archive is complete on `xspark04` and the
> node reached the tip under arm-14 — but the box was taken back for an LLM
> workload and the ARM node's systemd units are `disabled`. The next round is
> planned on a Raspberry Pi. **Read
> [`ARM_STATE_2026-09-08.md`](ARM_STATE_2026-09-08.md) before anything else in
> this directory**: it holds the exact state at the halt, the ranked open
> defects (starting with the radix flush sort that has been SUSPENDED, not
> fixed), and what a Pi can vs cannot carry.

## Where to read what

| question | answer |
|---|---|
| what state is the port in, right now, on which machine | [`ARM_STATE_2026-09-08.md`](ARM_STATE_2026-09-08.md) |
| what should the next session work on | `TODO.md` ("Open") + the ranked list in `ARM_STATE_2026-09-08.md` |
| per-module port status and how each module was verified | [`PORT_ROADMAP.md`](PORT_ROADMAP.md) |
| how the day actually went, with the failed hypotheses | `worklog/YYYY-MM-DD.md` (root of repo) |
| deploy history, rollbacks, the "no sane human runs this" preamble | [`../docs/devlog/DEPLOYMENT_HISTORY.md`](../docs/devlog/DEPLOYMENT_HISTORY.md) |
| daily port-specific narrative (older convention, through 08-31) | [`worklog/`](worklog/) |

## Branch model
- `main`  : tracks upstream (github.com/BobClawblaw/bitcoinmachinecode). x86-64.
- `arm-port` : our port branch, kept in sync by periodically merging
  `origin/main` into it. Never rebased (we want merge points visible).

## Keeping in sync (do after upstream `main` advances)
    git checkout arm-port
    git fetch origin
    git merge origin/main
    # C daemon + tests usually merge clean; asm/Makefile OBJS edits may conflict.
    # ANY new/changed upstream .asm module needs an AArch64 twin ported below,
    # then re-verified native + differential before considering the sync done.

## Layout
- `arm64/<name>.S`  — AArch64 GNU-as rewrite of asm/<name>.asm, SAME public
                      symbols so shared C harnesses/daemon link unchanged.
- `arm64/Makefile`  — builds each port + runs its harness (add targets per
                      module). `make -C port/arm64 abi-a64-check` gates the
                      AArch64 ABI auditor (callee-saved preservation and
                      save-area aliasing over the whole .S tree);
                      `abi-a64-audit` prints the findings plus, per function,
                      the reason any frame was not followed.
- `arm64/parity_sweep.sh` — the whole gate (434 plan rows; baseline round 44b:
                      pass 376 / fail 4 env-only / 398 compared). This is the
                      first thing to re-run on any new machine.
- `arm64/build_daemon.sh` — builds `daemon_out/bmcbitcoind` (links to
                      `.bmcbitcoind.new`, adopts with `mv(2)`; in-place gcc is
                      ETXTBSY against a running daemon).
- `PORT_ROADMAP.md` — per-module port status + verification method.
- `daemon_out/rollback/` — every retired build, one `cp` + restart from undoing
                      a deploy.

## Running it on another host (the Pi, or a fresh ARM box)
1. `git clone` + `git checkout arm-port`, install `gcc`, `make`, `python3`.
2. `make -C port/arm64 abi-a64-check`, then `bash port/arm64/parity_sweep.sh`
   and diff the verdict counts against the round-44b baseline. A new host earns
   trust by reproducing the sweep, not by booting the daemon.
3. `port/arm64/build_daemon.sh`, then run with
   `config/bitcoin-arm-stability.conf` edited for the host: it still carries
   `addnode=127.0.0.1` (a loopback Core oracle that exists on neither box any
   more) and `bmc.utxocompactthreshold=3` (the 09-08 compaction-tuning fix).
4. Run the node as a non-root user, always. The unit that shipped as
   `User=root` was demoted to `User=xian` on 2026-09-08 after a parser SEGV
   during boot made it a privilege question.
5. Do NOT plan to rebuild the 746 GB mainnet UTXO set on a Pi. Size the host to
   the job: sweep + differentials on the Pi, chain-scale work only on a box
   with the archive and the RAM.

## Pushing to GitHub
`origin` here is upstream (read-only from our side). To share/PR the arm-port
branch, create your own fork and:
    git remote add mine git@github.com:<you>/<fork>.git
    git push mine arm-port
Then open a PR from mine:arm-port -> upstream:main when a milestone is ready.
(In practice `arm-port` is pushed straight to `origin` and PRs are opened from
it; `git push origin arm-port` works with the credentials on the dev box.)
