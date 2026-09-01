# Incident 2026-09-01 — boot header sync accepted a genesis-first answer; catch-up re-downloaded 11,516 blocks under fake heights

**Severity:** high (production node down ~1 h; derived index files corrupted; no block data lost).
**Detected:** 11:21 UTC by the operator, from this line in `logs/main/bitcoin.main.log`:

```
2026-09-01 11:21:07 [dlc] == elapsed 0:01:30 | overall: 968673/1931687 stored (50.15% of real tip) | 282 holes in [0,968954] reached so far (99.97% gap-free) ==
```

## Timeline (UTC)

| time | event |
|---|---|
| 10:00:51 | deploy `n` boots. Boot header sync: `headers +1 from 91.92.199.207 (total 965018)` — correct. |
| 10:01–11:15 | `n` runs. The download worker advances the archive 965,018 → 965,029 through its leg sync. **`headers.dat` is not updated by that path** (only the boot sync and `submitblock` write the header mirror), so it stays at 965,018 records while `index.dat` reaches 965,030. |
| 11:15:55 | clean stop of `n` (mempool saved 16,669). |
| 11:15:59 | deploy `o` boots (the signer build; no networking change). |
| 11:16:44 | boot catch-up probes 114 live peers. |
| 11:16:44–11:19:37 | `dlc_headers_try` asks `93.115.26.6` for headers with a **single-hash locator** = the header mirror's stale tip (block 965,017). The peer answers **from genesis**. `node_ibd_headers` pages through the reply and appends **966,669 headers** — mainnet blocks 1, 2, 3, … — at positions 965,018 and up, checking only that consecutive received headers link to each other, never that the first one links to the block we asked from. Log: `headers +5029 from 93.115.26.6:8333 (total 1931687)`. |
| 11:19:37 | `dlc_span` extends `index.dat` with zero (hole) records up to the header count (1,931,687 records, 92.7 MB) and starts 16 workers to "fill the holes" `[965030, 1931686]`. |
| 11:19:47–11:30:06 | the workers fetch real early blocks by those hashes from honest peers and append 11,516 frames (2.67 MB) into the tail slack of `blk00000.dat` … `blk00041.dat`, recording them in the junk index records. |
| 11:21 | operator notices. |
| 11:31 | `systemctl stop` hangs: the catch-up's worker-wait loop ignores SIGTERM (known since 08-22). |
| 11:36 | all `o` processes SIGKILLed by PID. Node down. |
| 11:40–12:30 | investigation (below); `index.dat`/`headers.dat`/`chainwork.dat` copied to `incident-20260901/` before anything else. |

## What was damaged, and what was not

- **Block data: intact.** Every junk frame was appended past the last real frame of its file (overlap test over all 11,516 junk records against all real records of files 0–41: **0 overlaps**; each file's junk start == its real end). `daemon/pverify` over `[0, 221022]` (every real block living in the touched files) and `[964900, 965029]`: **CHAIN VERIFIED** (hash-match, chain-link, PoW, full consensus).
- **`index.dat`: junk tail.** Records 965,030 … 1,931,686 (966,657 records; 11,516 of them point at the appended frames, the rest are zero holes). Records 0 … 965,029 untouched and correct.
- **`headers.dat`: junk tail.** Positions 965,018 … 1,931,686 are mainnet blocks 1, 2, 3, … (self-consistent, real headers — just at the wrong heights). Positions 0 … 965,017 correct.
- **`chainwork.dat`: untouched** (still exactly 965,030 records; the catch-up never got to extend it).
- **UTXO set: untouched** (nothing was applied; `utxo_applied_height` still 965,029 from 11:02).
- **mempool.dat: safe** (16,669 entries saved at the 11:15 stop).
- **2.67 MB of junk bytes** remain in the tail of `blk00000..41` — harmless (unreferenced once the index is trimmed; a future `-reindex` treats them as duplicates of blocks 1..11,516 and keeps one copy).

## Root causes

1. **No linkage check on a header-sync answer.** `dlc_headers_try` appended whatever `node_ibd_headers` fetched. A `getheaders` reply is only a continuation of our chain if its first header's `hashPrevBlock` is the block we asked from. It was not checked.
2. **Single-hash locator.** `dlc_headers` sends only the mirror's tip hash. Any peer that does not know that hash (an IBD peer, a peer behind the tip, a peer on another chain) legitimately answers from its genesis. Core sends an exponential locator so the reply starts at the last common block.
3. **Header mirror lags the archive.** The worker's leg sync stores blocks without appending their headers to `headers.dat`; only the boot sync and `submitblock` do. So every boot asks peers from a stale point, widening the window for (2).
4. **No sanity bound on the header count.** One boot sync appended 966,669 headers, ~1000× the largest plausible gap, and nothing questioned it before the index was extended and 16 workers started writing.
5. **The catch-up ignores SIGTERM** (`dl_catchup`'s worker-wait loop; documented on 08-22, never fixed), so the stop hung and a SIGKILL was needed.

Contributing: the boot's dial pool was largely a swarm of `172.x` Linode-range peers advertising no `NODE_WITNESS` (dropped one by one at handshake). Not the cause — the header peer was a different one — but it slowed the boot and made the log noisy. The address book records `services = 0` for gossip entries, so the pool cannot pre-filter them.

## Why it had never happened before

The failure needs a header peer that does not know our (stale) mirror tip. Boot syncs before today always hit a synced peer that knew the block and answered correctly from the stale point. The 12-block mirror lag made the asked-from block a 75-minute-old height; it was still a matter of which peer answered.

## Fixes (all in commit(s) referenced below)

| # | fix | where | test |
|---|---|---|---|
| 1 | A header-sync answer whose first header does not connect to the tip we asked from is discarded, the header store rolled back, the peer treated as failed. | `dlc_headers_try` (`daemon/main.c`) | `test_dialhelper` §5 |
| 2 | Sanity cap: a boot sync that would add more than `DLC_HDR_SANE_MAX` headers to a non-empty store is refused the same way (loud log). | `dlc_headers_try` | `test_dialhelper` §5 |
| 3 | The header mirror is topped up **from the archive** (the blocks' own headers) at boot before any peer is asked, and after the worker stores new blocks — the mirror can no longer lag. | `dl_header_mirror_topup` | boot line `header mirror +12 from the archive` on the `s` boot |
| 4 | Boot self-heal: `index.dat` is cut at the first record above the chainwork-backed height whose block does not hash to its record or link to the height below (a block appended just before a crash is kept), trailing empty records are trimmed, `headers.dat` is cut at its first disagreement with the index, and over-long `chainwork.dat` is cut to the index — each with a log line. This is how the production node repaired this incident's leftovers on its next start; no archive file was edited by hand. | `archive_trim_derived_tails` (`daemon/archive_verify.c`) | `test_archive_trim` |
| 5 | The catch-up's worker-wait loop honours SIGTERM: workers are signalled, then killed, and the boot returns (every stop in the resolution sequence above was clean). | `dl_catchup` | `test_archive_trim` (structural pin) |

## Lessons

- **Trust nothing a peer sends as a continuation of state you hold unless it provably connects to that state.** The block path always had this property (PoW + prev-hash + consensus); the header mirror did not, because it was "just a mirror".
- **Derived files must be derived.** `headers.dat` is recomputable from the archive; anything recomputable should be topped up from the source of truth, not from the network.
- **Bound what one step may change.** A boot that grows the index by 1M entries should stop and say so, not start 16 workers.
- **A stop that hangs turns a mistake into an outage.** Every long loop in the daemon must check the shutdown flag (the reload path got this on 09-01 morning; the catch-up should have had it since 08-22).
- **Keep copies before repairing** (`incident-20260901/` holds the three corrupted files) and **verify before declaring** (overlap test + `pverify`), as the project's verification rule says.

## Resolution sequence (what actually happened, including the missteps)

| build | outcome |
|---|---|
| `p` (linkage guard + zero-tail trim + cap + mirror top-up + SIGTERM) | Booted and trimmed only the **all-zero** tail: the 11,516 junk records carry real hashes, so the index still ended at fake height 976,831 and the mirror kept its 12 bogus headers. Stopped by hand before the UTXO apply reached 965,030. |
| `q` (chain-aware trim: link check from the chainwork-backed height; mirror cut at first divergence) | Trimmed the production files correctly (index 965,030 records, mirror cut at 965,018) — then **SEGV** in the new mirror top-up: `store_read_at` returns the whole block into what was a 128-byte stack buffer. Crash-looped under `Restart=on-failure`; stopped. |
| `r` (4 MB scratch) | Still **SEGV**: `store_get_tip` was declared in C with one argument but the asm takes `(st, out_meta[3])`; the top-up used the one-arg form. Stopped. |
| `s` (tip read from the store's field) | Clean boot 11:57: `header mirror +12 from the archive (now 965030)`; the linkage guard fired on this very boot against another peer (`headers from 79.116.38.44 do not connect to our tip -- discarding 3 header(s)`); `already current (total 965030)`; catch-up wrote 0 blocks; RPC up in 16 s; UTXO reload `applied_height=965029 live=165727862`, identical to the pre-incident count. Tip advanced to 965,032 within a minute. |

Two of the four builds crashed on contracts that the C side had wrong (`store_read_at` reads a whole block; `store_get_tip` takes two arguments — the one-arg extern had never been used). Both are now declared correctly and commented at the call sites. The archive itself was never at risk during these boots (the self-heal runs before the store opens; the crashes were in the top-up, after the trim and before any network write).

## Operator notes

- The permission layer blocked the assistant's attempt to `truncate` the two derived files by hand; the repair therefore shipped as the product's own boot self-heal (fix 4), which is the better outcome. `incident-20260901/` (next to the datadir) keeps the three corrupted files as evidence.
- The signer build (`o`) itself was unrelated; it is live as `s` together with these fixes. The 2.67 MB of junk frames in the tail slack of `blk00000..41` are unreferenced and harmless.
- Commits: `2a98daa` (linkage guard), `7370316` (cap, mirror top-up, self-heal v1, SIGTERM, this report), `c5868d7` (chain-aware self-heal), `c5d8fa5` and `29a34a6` (the two top-up crashes).
