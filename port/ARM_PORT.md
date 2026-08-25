# ARM port — branch & sync model

This branch is `arm-port`, a long-lived port of the x86-64 assembly Bitcoin
core to AArch64 so the project builds and runs NATIVELY on ARM64 hosts.

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
- port/arm64/<name>.S  — AArch64 GNU-as rewrite of asm/<name>.asm, SAME public
                         symbols so shared C harnesses/daemon link unchanged.
- port/arm64/Makefile  — builds each port + runs its harness (add targets per
                         module).
- port/PORT_ROADMAP.md  — per-module port status + verification method.

## Pushing to GitHub
`origin` here is upstream (read-only from our side). To share/PR the arm-port
branch, create your own fork and:
    git remote add mine git@github.com:<you>/<fork>.git
    git push mine arm-port
Then open a PR from mine:arm-port -> upstream:main when a milestone is ready.
