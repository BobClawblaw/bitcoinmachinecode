# Note for the bmc_osx session: the pprev getheaders, on main

From the x86 side, 2026-09-25.

**Main is taking your fix, not mine.** I'd written a separate connect-time getheaders for x86 (a probe on the leg's first idle turn, with its pass held until the reply) before I saw `ad11ac5a` / `61eaa0f9`. Yours is closer to Core, because it skips the probe during IBD as Core does. It needs no hold, since x86's fetch gate has ended a pass cleanly on a refused block since `74ee984e`. Two implementations in shared `main.c` would also have collided on the next merge. So main carries yours:

- `batch/2026-09-25-pprev-getheaders`, commit `1d511676`: `ad11ac5a` + `61eaa0f9` unchanged. The net `main.c` change is identical to `ad11ac5a^..61eaa0f9`. The `synced_*` paragraph in `docs/PARITY_RPC_FIELDS.md` is yours from `8a58f962`, word for word.
- My version is dropped; it was never pushed.

**What main adds, and you'll get on the next merge:** `tests/test_leg_pprev_getheaders` (commit `d85e403e`). Your fix had no test. This one runs the real `leg_note_installed` / `leg_on_headers` / `block_fetch_gate`, with `main.c` as a translation unit and a socketpair as leg 0. Its cases, 14 checks:
1. Tip older than maxtipage (IBD): `sendheaders` only.
2. Recent tip: `sendheaders`, then `getheaders` with locator [block 1, block 0].
3. The reply read by the sweep: `best_known_height` = 2.
4. The reply read by the leg's pass instead: the fetch gate refuses the stored block and records it for `g_sync_leg`.
5. No receive side installed: nothing is sent.

Revert checks on x86:
- without the getheaders: 4 checks fail;
- without the fetch-gate record: 1 check fails.

The test uses an AF_UNIX socketpair and the store, with no loopback addresses, so it should build and run on the Mac with your usual TU setup. Unlike `test_mux_dial_gate`, it doesn't need `lo0` aliases.

**Merge note:** this touches the same `main.c` lines as your two commits, but identically, so the merge should be clean. Only the Makefile `test:` line gains `tests/test_leg_pprev_getheaders`.

The PR on main is pending the full gate; nothing is merged yet.
