# Note for the bmc_osx session: next merge of main

From the x86 side, for the next time bmc_osx merges main.

This applies once `batch/2026-09-24-mux-dial-gate` lands on main (x86's version of `5e71979a`; its gate is running now). I did a trial merge of that branch into bmc_osx at `9433520c`. It conflicts in three files.

## 1. `asm/daemon/tx_verify.c`: keep bmc_osx's side for the whole file (`git checkout --ours`)

Main has the `182c0d87` condvar pool without `ad4f0d9b`'s per-thread pools. Your workers read their pools from the slot (`w->spk_pool`), and one conflict hunk holds the line that fills those fields at dispatch:

```c
slot->spk_pool=&g_spk_pool; slot->tap_pool=&g_tap_pool; slot->tapdesc=g_tapdesc;
```

Main's side of that hunk doesn't have it. Take main's side and the slot pointers stay NULL while the pools are `__thread`: every parallel block verify crashes. Main changed nothing else in this file, so keeping yours whole loses nothing.

## 2. `asm/daemon/main.c`: take main's side hunk by hunk. Not the whole file

All five hunks are in the `mux_next_peer` dial gate. Main replaces your single `MANUAL_RETRY_FLOOR_MS` (60 s) with Core's per-kind rates:

- `CONNECT_RETRY_FLOOR_MS 5500`: Core v31.1 `ThreadOpenConnections`, net.cpp:2553
- `ADDNODE_RETRY_FLOOR_MS 60000`: `ThreadOpenAddedConnections`, net.cpp:3026

`node_config_manual_kind()` tells the two apart; `node_config.c` auto-merges. Main also logs each refusal at most once per slot per minute (your deploy logged "no dial candidate is free" 5,866 times).

Taking main's whole `main.c` with `--theirs` deletes 175 lines of osx-only code. Resolved per hunk, the change against bmc_osx is +44/-55, all in that section. It passes `gcc -Wall -Werror -fsyntax-only`, and the old constant and the duplicate `g_leg_manual_next_dial` definition are both gone.

## 3. `asm/Makefile`: union the tokens on the `test:` line

Main adds `tests/test_mux_dial_gate`.

## A likely macOS snag (not verified on a Mac)

`test_mux_dial_gate` dials 127.0.0.1 to 127.0.0.4 on a closed port. Linux routes all of 127/8 to loopback; macOS only answers on 127.0.0.1 unless you add aliases:

```sh
sudo ifconfig lo0 alias 127.0.0.2 up   # and .3, .4
```

Without them the dials may run into the 10 s connect bound, and the test's in-flight checks (`dh_inflight_for`) can come out wrong.

## Still open from #297, for you to decide

- `dbg_txv_parse` (from `b4cb4e55`) has unused `nin` (:618) and `k` (:634). `tx_verify.c` doesn't build under gcc `-Werror` until that's fixed, which blocks main ever merging bmc_osx.
- `ad4f0d9b`: reproducing the failure at 124,864 before any revert is the right order.
- If `ad4f0d9b` stays: it made about a dozen `__thread` caps and counters non-`static` (`g_txv_in_cap`, `g_flat_cap`, `g_tx_sigops_n`, ...). `static __thread` works for the pools themselves, so they can go back to `static`.
