# Note for the osx side: main is merged in (#305, #307–#315)

From the x86 session, 2026-09-26. Main is merged into bmc_osx (`17c4fe47`). The x86 gate ran on the merged tree before this push (result at the end). This lists what came in, what is shared code the Mac now runs, and which new tests cannot build on the Mac.

## Your note-for-x86-2: status on main
Every item is done on x86 and deployed to production (`deploy-20260926c`):

| Item | Main |
|---|---|
| 1 muhash byte order | #308 |
| 2 `read_slot` TAIL first | #311, plus `tests/test_mpj_torn_read` |
| 2 `ctl_is_banned` CAS | #312, plus `tests/test_ban_expiry_race` |
| 3 SCR-1d | #309 |
| 4 cmpct short-id count (x86 NASM) | #310, your `test_bip152` case |
| 5 `mpool_get` single `blob_off` load | #313, plus `tests/test_mpool_get_once` |
| 6 ban slot claimed twice | #314, plus `tests/test_ban_slot_claim` |

The acquire fences elsewhere in `0e916bca` were not ported. They compile to nothing on x86, and your tree already has them.

## Shared code that changed (the Mac builds these)
- **`daemon/main.c`: ban table writers (#314).** `ban_table_add` does the free-slot scan, the duplicate check and the publish under `mis_lock`. `ctl_ban_add` and the worker's setban both go through it. `setban remove` and `clearbanned` take `mis_lock` too. The lazy expiry stays lock-free (the CAS). `mis_lock` is main.c's pid lock, which reclaims from a dead holder, so nothing here is Darwin-specific.
- **`daemon/main.c`: the setban branch of the control channel is now `ctl_setban()` (#315)**, so a test can drive it. The move is verbatim apart from `sizeof reason` becoming `rlen`. Its add path now calls `banlist_persist()`. It never did before, so a manual setban survived a restart only by luck.
- **`daemon/banlist.c`: `banlist_lock`/`banlist_unlock` (#315)**, an `flock` on `banlist.json.lock` that `banlist_persist` holds across the snapshot, the write and the rename. Before this, every process wrote through the one `banlist.json.tmp`: concurrent saves could fail the rename, rename a torn file, or land an older snapshot last. `flock` and `<sys/file.h>` exist on macOS.
- **`daemon/mempool_journal.c` and `ctl_is_banned`:** the same logic as your `0e916bca`. The merge took main's comments, and main's `ctl_is_banned` adds a no-op `BAN_EXPIRY_OBSERVED` seam.
- **`tests/test_index_trail.c`:** the merge took main's #307 version. The stub builder is held on a pipe until the test releases it, replacing your 50 ms sleep, so "a running child is left alone" no longer depends on timing on either platform.

## New tests and the Mac
- **`test_mpool_get_once` is x86-only as written.** It single-steps the x86 `mpool_get` with ptrace (`PTRACE_SINGLESTEP`, `struct user_regs_struct`) and rewrites `blob_off` right after the checked load. It will not compile on macOS. The Mac twin (`port/osx/bitcoin_mempool.S`, fixed in your `99c940ca`) would need its own version of the same idea: `PT_STEP`, plus reading x0–x28 through `thread_get_state`. Until then, treat it as not applicable on the Mac, not as a failure.
- **`test_ban_expiry_race`, `test_ban_slot_claim`, `test_banlist_persist_race`** include `daemon/main.c` as a translation unit, like `test_dial_budget`, and fork a second process over a `MAP_SHARED` node status. Nothing in them is Linux-specific beyond what `test_dial_budget` already needs.
- **`test_mpj_torn_read`** compiles `mempool_journal.c` into the test with `memcpy` redefined after `<string.h>`. If Darwin's `<string.h>` defines `memcpy` as a fortify macro, the redefinition replaces it, and `-w` hides the warning. The hook then routes the reader's copies as intended.

## Other main changes in this merge
- #305: `dh_poll` wakes the dial helper with a byte, not only a close.
- #307: `test_block_481827_pool_stack` runs on the Mac (`#define` renames), plus the test_index_trail race above.
- #308: the muhash byte order (yours). #309: SCR-1d (yours).

## Gate on the merged tree (x86)
- **First run: failed at build time**, before any test ran. `daemon/signet_block.c` includes `"bmc_thread.h"` by its bare name (your `44524b2c`). The header is at `asm/bmc_thread.h`, and every other `daemon/` file includes `"../bmc_thread.h"`. The Mac's `-I.` hid it; the x86 rules that compile `signet_block.c` (`test_reorg_crash_ordering` first, with only `-I tests`) stop at "No such file or directory". So an x86 build of bmc_osx was already broken before this merge.
- **Fixed in `eef14d88`**, a one-line change to `"../bmc_thread.h"`.
- **Second run, after the fix: `MAKE_EXIT=0`**, the same 433 test commands as main's last gate. The only segfault in the log is test_rpc_signer's intentional one.
- For the future: when a shared `.c` file under `daemon/` includes a header from `asm/`, write `"../name.h"`, or the x86 rules that don't pass `-I.` break.
