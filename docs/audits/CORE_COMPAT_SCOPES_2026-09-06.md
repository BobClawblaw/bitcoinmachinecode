# Core behavioral compatibility — scopes for every remaining item

**Date:** 2026-09-06. **Parent:** `docs/CORE_BEHAVIORAL_COMPAT.md` (the
register). Each section below is a scoping report in the shape of
`NET-10_ADDRMAN_SCOPE.md`: what Core does with the reference, what exists here
with file and line, the design against *this* architecture, the files to
touch, the tests including the negative control, the risks, and the size.
Every claim about the tree was checked against `asm/` this morning.

**Corrections to the register, found while scoping** (applied to
`CORE_BEHAVIORAL_COMPAT.md` in this commit):

- Inbound onion service and inbound I2P are **wired at boot**:
  `serve_mux(..., tor_onion_listener(port), i2p_inbound_start())`
  (`main.c:8271`, `8296`). `FEATURE_GAPS.md`'s 2026-08-28 note ("not yet
  called at boot", "not yet wired to the serve loop") is stale. Row → DONE;
  the item leaves the work list.
- BIP23 proposal mode is **implemented** (`rpc_node_submit_proposal`,
  `rpc_node.c:1521`, hooked at `main.c:6431`). Row → DONE.
- Minimum chain work **exists at reorg time** (`minchainwork.c`,
  `reorg.c:708`, floor from `chainparams.c`). What is absent is the
  headers-sync half. Row split.
- Coin selection is **BnB** (`wallet_bnb.c`), not "basic"; knapsack and SRD
  are absent. Row reworded.
- `getaddressinfo` wallet-context fields are real (`rpc_wallet_ops.c:1957`).
  Row dropped.

**Architecture facts every scope leans on**

| fact | where |
|---|---|
| One process per inbound connection, forked from the serve parent; its loop is `bitcoin_serve.asm`, which calls C hooks (`g_serve_tx_gate`, `g_serve_mempool_hook`, `g_serve_violation_hook`, `serve_cfilters`, ...) | `main.c:7198` fork site; asm `extern` list |
| The inbound loop's `p2p_read` is timed (`SO_RCVTIMEO` from `peer_inbound_deadline`, `main.c:547`), so the loop already *ticks* on a quiet socket — a periodic task has a place to run | `bitcoind.asm:617-662` timeout semantics |
| The inbound loop already records the peer's `feefilter` (`s_peerfee`, `bitcoin_serve.asm:154`) and whether we sent ours | |
| The download worker owns the outbound legs (`mux_out_*` arrays, `MUX_MAX_OUT` 64, `MUX_WANT_OUT()`), announces txs to them from `tx_relay.c` (`txrelay_announce`, Poisson 2 s mean, `txr_leg_pend` per leg, never back to the sender), and runs the block-download loop `serve_loop(fd,lfd)` (`main.c:782`) | |
| All processes share one `MAP_SHARED` status block `g_node_status` (`rpc_node.h`): the 128-slot peer table (`rpc_peer_t`: `used inbound addr proto services subver start_height conn_time bytes_* last_send last_recv relaytxes perms pid nodeid`) and a sequenced ZMQ ring (`zmq_seq`, `zmq_ring[RPC_ZMQ_RING]`) fed by `zmqn_tx_accepted` from every accept path (`tx_accept.c:924, 1004, 1061`) | the precedent for a shared, sequenced feed |
| Our version message's `fRelay` is a global byte set by `main.c` before each handshake (`node_relay_flag`, `bitcoind.asm:2163`) — per-connection already, just never varied | |
| Compact-block *serve* side exists in asm: `bip152_shortid`, `cmpctblock_build`, `p2p_blocktxn_build` (`bitcoin_cmpct.asm`) | reuse for the receive side |
| `-stopatheight` is honoured on every download path (`main.c:3135`); `assumevalid=0` is mode 2 | CC-8 needs nothing new in the daemon |

---

## CC-1 — Transaction relay to and from inbound peers

**Core.** Every peer that negotiated relay (`fRelay`, `wtxidrelay`) gets
`inv` announcements of every transaction accepted to the mempool, from a
per-peer set flushed on a Poisson timer — mean 5 s for inbound
(`INBOUND_INVENTORY_BROADCAST_INTERVAL`), 2 s outbound — filtered by the
peer's `feefilter`, never back to the peer it came from, and with the
per-peer `m_tx_inventory_known_filter`. (`net_processing.cpp`
`PeerManagerImpl::SendMessages`, "Determine transactions to relay".)

**Here.** Inbound peers receive **no** transaction invs: the asm loop
answers `mempool` (BIP35) and `getdata`, nothing unsolicited. Transactions
we accept from an inbound peer enter the shared pool and are announced to
the outbound legs only when the worker next sees them — and today it does
not: `txrelay_poll_leg` is called only for `mux_out_fd[i]` (`main.c:5789`)
and `txr_ann_add` is fed only from the worker's own accept paths. So a
transaction from an inbound peer reaches nobody.

**Design.** A shared, sequenced **announce ring** beside the ZMQ ring, fed
from the same three accept sites:

```
rpc_node.h   ann_ring[RPC_ANN_RING] { u8 wtxid[32]; u8 txid[32]; u64 fee_per_kvb; int src_slot; }  + ann_seq
tx_accept.c  at each zmqn_tx_accepted(): also ann_push(wtxid, txid, feerate, g_my_peer_slot)
```

*Inbound side* (`bitcoin_serve.asm` + a new `serve_txann.c`): each child
keeps a cursor `my_seq`. On every loop tick — a received message or the
`SO_RCVTIMEO` timeout — it calls `serve_txann_tick(fd, now)`: drain
`ann_seq - my_seq` new entries (cap: if the child lapped by more than the
ring, resync the cursor and log once, as the ZMQ ring does), skip
`src_slot == my_slot`, skip `fee_per_kvb < s_peerfee`, skip entries already
in a small per-child known set, append to a pending batch; when
`now >= next_send` (Poisson, mean 5000 ms, same generator as
`tx_relay.c:400-414`) write one `inv` of up to 35 `MSG_WTX` (wtxidrelay
negotiated) or `MSG_TX` entries and draw the next time. One asm change: a
`call serve_txann_tick` in the timeout branch and after each dispatched
message, with the fd and the relay-negotiated flag.

*Outbound side*: `txrelay_announce` already fans out `txr_ann[]`; add a
worker-side drain of the same ring into `txr_ann_add(txid, -1)` at the top
of each rotation, so an inbound-accepted transaction reaches the outbound
legs too. The `src_slot` is not an outbound fd, so "not back to the sender"
is handled by the slot check in the inbound side and is moot here.

**Files.** `rpc_node.h` (ring + seq, and `g_my_peer_slot` for the serve
child), `tx_accept.c` (3 sites), new `daemon/serve_txann.c`,
`bitcoin_serve.asm` (2 call sites, `s_relay_ok` flag from the handshake),
`main.c` (worker drain), `Makefile` (rule + gate), `tests/`.

**Tests.** `test_serve_txann` (gated): (a) an accept with `src_slot = 3`
is announced to slots 1, 2, 4 and not 3; (b) an entry below a slot's
`feefilter` is withheld from that slot and sent to another; (c) the batch
cap of 35 and the Poisson draw bounds; (d) lapping: 2×ring accepts, the
cursor resyncs, no crash, one log line. **Negative control** (the finding):
with the tick disabled, a mock inbound peer that sends `version` with
`fRelay=1` receives zero `inv` in 30 s of accepts. **End to end** (the proof
the register wants): regtest, real Core connected *to us* as our inbound
peer; a transaction submitted to a third node reaches Core's mempool through
us within 15 s; and the mirror — Core as the sender, a third node as the
receiver.

**Risks.** The child count is unbounded by design (one process per inbound),
so the ring reader must be lock-free and cheap: a 64-bit seq read and a
bounded drain. `MSG_WTX` requires `wtxidrelay` negotiated in *both*
directions; the handshake already tracks it. A serve child that dies leaves
no state behind (cursor is per-process). Layout change to `g_node_status` is
safe: every mapper is the same binary and the block is not persisted.

**Size.** Medium. ~400 lines C, ~30 lines asm, one gated test, one regtest
script. The design is the outbound one mirrored; nothing novel.

---

## CC-2 — BIP152 compact block receive

**Core.** After `sendcmpct`, a peer sends `cmpctblock` (header + nonce +
short ids + prefilled txs). The receiver reconstructs from its mempool and
`blockreconstructionextratxn`, requests the rest with `getblocktxn`, receives
`blocktxn`, validates, and in high-bandwidth mode sends `sendcmpct(1)` to up
to 3 peers so they push unsolicited. (`blockencodings.cpp`,
`net_processing.cpp` `ProcessMessage` "cmpctblock"/"blocktxn".)

**Here.** Serve side complete (`bitcoin_cmpct.asm`: short ids, build,
`blocktxn` build; `sendcmpct` negotiated inbound). Receive side absent: the
download loop `serve_loop` (`main.c:782-936`) fetches every block with
`getdata MSG_BLOCK`, and never sends `sendcmpct` on an outbound leg, so peers
never push compact blocks to us; one that does is ignored.

**Design.** In the download worker only (it owns the legs and the mempool
via `txsub_pool()`):

1. Handshake on each outbound leg: send `sendcmpct(version=2, hb=0)` after
   `verack` (low-bandwidth first; high-bandwidth to the 3 best legs is a
   follow-up once the receive path is proven).
2. On `inv MSG_BLOCK` or `headers` for an unknown block from a leg that
   negotiated `sendcmpct`: `getdata MSG_CMPCT_BLOCK` instead of `MSG_BLOCK`.
3. `cmpctblock` handler (new `daemon/cmpct_recv.c`): parse; compute
   `bip152_shortid` (existing asm, SipHash-2-4 with the header+nonce key)
   for every mempool wtxid via one pass over the pool (`mpool_*` iteration —
   the pool has no iterator today; add `mpool_for_each`); fill; collect
   missing indices; if none, assemble and hand to the existing
   `cons_verify → store_append` path at `main.c:855-905` as if it had
   arrived as `block`; else `getblocktxn` and park the partial (one at a
   time per leg, 4 MB cap).
4. `blocktxn` handler: fill, assemble, same handoff. Any mismatch (short-id
   collision, bad count) → fall back to `getdata MSG_BLOCK` on the same leg,
   score nothing (Core does not penalise collisions).
5. `blockreconstructionextratxn` (default 100): a small ring of recently
   evicted/rejected transactions kept only for this purpose.

**Files.** new `daemon/cmpct_recv.c/.h`, `main.c` (handshake, dispatch in
`serve_loop`, the two handlers), `bitcoin_mempool.asm` or a C shim for
`mpool_for_each`, `Makefile`, `tests/`.

**Tests.** `test_cmpct_recv` (gated): vectors built with the *serve-side*
builder (so encoder and decoder are the same code's two halves): (a) all txs
in pool → reconstructed byte-identical, no `getblocktxn`; (b) 3 missing →
`getblocktxn` lists exactly those indices, `blocktxn` completes; (c) forged
short-id collision → fallback to full block; (d) oversized/short-id-count
mismatch refused. **Negative control**: handler disabled → a pushed
`cmpctblock` produces a full `getdata`, as today. **End to end**: regtest,
Core mines with our mempool primed; the log shows `cmpctblock` reconstructed
with zero `getblocktxn`; then with the mempool cleared, one `getblocktxn`.
**Bandwidth proof**: mainnet, bytes received per block over an hour, before
and after.

**Risks.** The block handoff at `main.c:855` assumes a contiguous block
buffer from `p2p_read`; reconstruction must produce the same. Witness: a
reconstructed block uses mempool transactions *with* witness (wtxid short
ids), which is what `cons_verify` expects. Memory: one parked partial per
leg. High-bandwidth mode is deliberately excluded from this batch.

**Size.** Medium-large. ~700 lines C, one gated test, one regtest script.

---

## CC-3 — Inbound eviction (`AttemptToEvictConnection`)

**Core.** When inbound slots are full, before refusing, pick a victim among
inbound peers after *protecting*: the 4 with lowest min-ping, 8 that most
recently sent us a tx, 4 that most recently sent a novel block, half of the
remainder by longest connection time, and a share per network group; then
evict, from the largest netgroup, the youngest connection. Peers with
`NoBan` permission are never evicted. (`net.cpp` `SelectNodeToEvict`,
`AttemptToEvictConnection`.)

**Here.** A 20-minute inactivity bound (NET-3). `inbound_slot_claim`
(`main.c:1290`) walks the 64 inbound slots and returns −1 when none is
free; the serve child then *runs anyway, unrecorded* (`main.c:7198-7206`:
`node_serve_loop` is entered regardless of the slot result). So under
pressure the node neither evicts nor refuses — it serves an unbounded number
of inbound peers and reports only 64. That is a finding in its own right.

**Design.** Add to `rpc_peer_t` (`rpc_node.h`): `min_ping_us`,
`last_tx_time`, `last_block_time`, `net_group` (u32, same function as
NET-10's), written by the serve child at ping/pong, tx accept, and block
receive. In the accept path, when `inbound_slot_claim` returns −1: call
`inbound_select_victim()` (new, `daemon/inbound_evict.c`) implementing
Core's protection rounds over the shared table, and if it returns a slot,
mark it `evict_requested`; the victim child checks the flag on its next
tick (the same tick CC-1 adds) and exits cleanly; the new connection claims
the freed slot. If no victim (all protected), **refuse**: close after
`version` with no `verack`, as Core does. Never serve unrecorded.

**Files.** `rpc_node.h`, new `daemon/inbound_evict.c/.h`, `main.c` (accept
path, slot claim, the three writers), `bitcoin_serve.asm` (one flag check
per tick), `Makefile`, `tests/`.

**Tests.** `test_inbound_evict` (gated), 20 synthetic full tables: the
victim matches Core's rules on each (transcribed from `net_peer_eviction_tests.cpp`
where they apply); NoBan is never chosen; an all-protected table yields "no
victim". **Negative control**: today's behavior — with eviction disabled and
64 slots full, a 65th connection is served and `getpeerinfo` shows 64.
**End to end**: regtest with `maxconnections` small, 65 inbound mock peers;
the evicted one is the youngest of the largest netgroup, and
`getpeerinfo` count equals the cap.

**Risks.** Cross-process eviction needs the victim to *notice*; the tick
exists once CC-1 lands, so CC-3 depends on CC-1's tick (not its ring).
Adding fields to the shared struct is safe for the reason given in CC-1.

**Size.** Medium. ~350 lines C, one gated test. **Do after CC-1.**

---

## CC-4 — Block-relay-only outbound + `anchors.dat`

**Core.** 8 full-relay outbound plus 2 block-relay-only connections that
send `fRelay=0`, ignore `addr`, and never announce transactions — an
attacker who controls all 8 full-relay peers still cannot eclipse the block
view. On shutdown the two block-relay-only peers are written to
`anchors.dat`; on start they are dialed first. (`net.cpp`
`ThreadOpenConnections`, `DumpAnchors`, `ReadAnchors`.)

**Here.** N full-relay legs (`MUX_WANT_OUT()`), all identical; no anchors.
The reserved-leg mechanism for anonymity networks (`dh_reserved_pick`,
`main.c:6203-6209`) is the template: a leg kind chosen before dial.

**Design.** A `mux_out_kind[]` array beside the other `mux_out_*` arrays:
`FULL` or `BLOCK_ONLY`. Two `BLOCK_ONLY` legs wanted in addition to
`MUX_WANT_OUT()`. For a `BLOCK_ONLY` leg: set `node_relay_flag = 0` before
the handshake (the byte is already per-connection), do not send `sendaddrv2`
or `getaddr`, drop `addr`/`addrv2` received, and exclude the fd from
`txrelay_announce`'s fds and from `txrelay_poll_leg` (the worker already
builds those fd lists per rotation; filter by kind). Anchors: at the
`g_shutdown_requested` break (`main.c:5747`) write the two current
`BLOCK_ONLY` hosts to `<datadir>/<chain>/anchors.dat` (Core's
format: v2 address serialisation, so Core's file is readable if ever
copied); at boot, before the pool fill, read it, dial those first as
`BLOCK_ONLY`, then delete the file (Core deletes on read so a crash loop
does not pin the same peers).

**Files.** `main.c` (kind array, want count, handshake flag, fd-list filters,
anchors read/write), `tx_relay.c` (no change if the fd lists are filtered
upstream), `Makefile`, `tests/`.

**Tests.** `test_anchors` (gated): round-trip of the file format against a
Core-written `anchors.dat` fixture; read deletes the file. **Negative
control**: with kind forced `FULL`, a mock peer receives `fRelay=1` and tx
invs. **End to end**: regtest, two mock peers dialed as `BLOCK_ONLY` see
`fRelay=0` and receive no `inv MSG_TX` over 60 s of accepts while a `FULL`
mock does; restart the node, the same two are the first dialed.

**Risks.** `MUX_MAX_OUT` is 64; two more legs fit. Peer-quality metrics
(NET-10's `ab2_mark_tried`) still apply to block-only legs. Reserved legs for
anon nets and block-only legs must not double-count toward the want.

**Size.** Medium. ~300 lines C, one gated test, one regtest script.

---

## CC-5 — Headers sync anti-DoS (presync / low-work headers)

**Core.** Since 24.0, headers from a peer are not stored until the chain
they form exceeds `nMinimumChainWork`; during that "presync" phase only a
compact commitment (one bit per header, salted) is kept, and the peer must
re-send the same headers, which are verified against the commitments before
they are committed to memory. A peer that feeds a long low-work chain costs
us nothing. (`headerssync.cpp`, `net_processing.cpp` `TryLowWorkHeadersSync`.)

**Here.** `reorg_work_meets_minimum` (`minchainwork.c`) is applied when a
*fork candidate* is evaluated (`reorg.c:708`) — so the node never *switches*
to a low-work chain. But `dlc_fetch_headers` (`main.c:3315`) → `hst_append`
stores every PoW-valid header it is given (VAL-5 gates PoW per header, not
cumulative work), so a peer can make the boot header fetch store an
arbitrarily long valid-PoW low-work chain before the reorg check ever runs.

**Design.** Two stages, the first sufficient on its own:

1. **Cumulative-work gate on the boot fetch**: track the candidate chain's
   work as headers arrive (`chainwork_build.c` has the arithmetic); if after
   `N` headers (Core: any point where the chain is about to be committed) the
   accumulated work is below `min_chain_work` *and* the chain is longer than
   our stored tip's height, keep fetching into a bounded scratch (not `hst`)
   and abandon the leg after a cap (e.g. 4 × 2000 headers with no
   min-work crossing). Only a chain that crosses the floor is appended.
2. **Presync commitments** (Core's exact scheme) — deferred; stage 1 bounds
   the attack at the scratch cap, which is what matters.

**Files.** `main.c` (`dlc_fetch_headers`), `chainwork_build.c` (an
incremental accumulator API), `Makefile`, `tests/`.

**Tests.** `test_hdr_lowwork` (gated): a synthetic 8,000-header regtest-PoW
chain below the mainnet floor is *not* appended to `hst`; a chain that
crosses the floor at header 5,000 is appended in full; the scratch cap
disconnects. **Negative control**: gate off → the 8,000 low-work headers are
stored. **Perf**: the accumulator adds <1 µs per header (measure).

**Risks.** Regtest and signet have floors of 0; the gate must be chain-aware
(it is: `min_chain_work_hex` is per chain). A real peer mid-IBD on a fresh
node has a tip *below* the floor for the first ~400k headers — the gate must
compare *accumulated* work, not per-header work, and the boot fetch must not
abandon an honest slow peer: the cap is on headers-without-crossing on a
chain *longer than ours*, not on time.

**Size.** Medium. ~250 lines C, one gated test.

---

## CC-6 — Extra outbound on stale tip

**Status: CLOSED (`c6598b5`).** As designed below; test `test_stale_tip` gated, negative control = the switch off.

**Core.** If no block has arrived for >30 min (`TIP_STALE_TIMEOUT`... the
check is "tip older than 3× the block interval"), open one extra full-relay
outbound; drop it once the tip is fresh. (`net_processing.cpp`
`CheckForStaleTipAndEvictPeers`, `net.cpp` `m_try_another_outbound_peer`.)

**Here.** The worker knows the tip time (`tx_accept_set_tip_time`,
`main.c:6131-6134`); the top-up loop (`main.c:6216`) wants exactly
`MUX_WANT_OUT()` legs; nothing reacts to staleness.

**Design.** `int extra_outbound = (now - tip_time > 30*60 && !ibd) ? 1 : 0;`
folded into the want count at the top-up, and a matching drop of the
*youngest* leg when it returns to 0. Log one line on each transition.

**Files.** `main.c` (one function, two call sites). **Tests.** `test_stale_tip`
(gated): with a faked tip time, the want count is `N+1`; fresh, `N`.
**Negative control**: the feature flag off, want stays `N` at any tip age.
**End to end**: regtest partition for 35 minutes with `mocktime`-equivalent
(we have none — use a fake tip time env hook the test already has:
`tx_accept_set_tip_time`).

**Size.** Small. ~60 lines.

---

## CC-7 — `-peertimeout`

**Status: CLOSED (`c6598b5`).** As designed below; test `test_peer_timeout` gated, negative control = no deadline (the silent peer holds the socket past the guard).

**Core.** The time a peer has after connection to complete the version
handshake before it is disconnected; default 60 s
(`DEFAULT_PEER_CONNECT_TIMEOUT`).

**Here.** Parsed into `g_cfg.peer_timeout_s` (`node_config.c:662`, default
60); **no reader** (`main.c:544` says so). Inbound has `peer_inbound_deadline`
(`SO_RCVTIMEO` from `PEER_IDLE_SECS_DEFAULT` / `BMC_PEER_IDLE_SECS`), which
is the *idle* bound, not the handshake bound; outbound has
`connect_timeout_ms` (Core's `-timeout`).

**Design.** In both handshake paths (inbound: the version/verack exchange
before `node_serve_loop`; outbound: `outbound_connect`'s post-connect
exchange), arm a deadline of `peer_timeout_s` from socket open to `verack`
received; on expiry, close and, for outbound, mark the address as
failed. Remove the "unwired" comment at `main.c:544`.

**Files.** `main.c` (two sites), `tests/`. **Tests.** `test_peertimeout`
(gated, fork+alarm harness as in `test_scr_interp_bounds`): a mock peer that
sends `version` and then nothing is dropped at `peer_timeout_s`; one that
completes in time is kept. **Negative control**: unwired → the silent peer is
held until the idle bound (20 min) instead. **Size.** Small. ~80 lines.

---

## CC-8 — Full-verification replay (`assumevalid=0`)

**What it proves.** Today's "byte-identical UTXO set" was produced with
Core's default assumevalid, so scripts below block 890,000-ish were never
executed by this node. The 2026-09-05 interpreter review found two consensus
false-accepts *in that region*. This run executes every script in history
and ends at the same MuHash — or does not, and names the block.

**Here.** Everything needed exists: `assumevalid=0` (mode 2, all paths),
`-stopatheight` (`main.c:3135`), `validation/fresh_install_ibd.sh` (fresh
clone → build → sync → compare), `validation/muhash_vs_core.sh`, and the
oracle with `coinstatsindex` for any height.

**Plan.**

1. Second scratch datadir on `/storage` (1.6 TB free; a full datadir is
   ~850 GB — the bench datadir on `/mnt/2tbssd` cannot host another).
2. `bitcoin.conf`: `assumevalid=0`, `stopatheight=<H>` with `H` = a height
   the oracle can answer and that is above every consensus-relevant
   activation (choose the oracle's current tip minus 100 at launch), `port=`
   distinct from 8332/8333/8433, `rpcport=` distinct from 8331/8335,
   `listen=0` (no inbound: this is a verifier, not a peer), `dnsseed=0` +
   `connect=` the bench node and the live node so it syncs from local peers
   and does not load the network.
3. Launch under `nohup` with the log to `/storage`, record start time.
4. Wall-clock is unmeasured for this mode; the default-mode bench sync
   completed between 2026-09-04 and 2026-09-05 (deploy record). Expect a
   multiple of that: every pre-890k script now runs. Measure; that number is
   itself a deliverable (`docs/reports/`).
5. On stop: `validation/muhash_vs_core.sh` at `H`; identical → the claim is
   upgraded in `README.md` and `FEATURE_GAPS.md` with the run's log hash;
   any rejected block → that block's txid set becomes a differential vector
   immediately, and the finding is filed before anything else.

**Tests.** The run *is* the test. Its negative control: the same datadir
with `assumevalid` default must finish faster and match too (already known
from the bench).

**Risks.** Disk (fine), time (days, unattended: the script already handles
that), and the one that matters — a mismatch is a consensus bug, which is
the point. **Size.** Wall-clock only; one config file and one launch.

---

## CC-9 — BIP331 package relay wire protocol

**Core.** `sendpackages` negotiation, `ancpkginfo` to describe a package,
`pkgtxns`/`getpkgtxns` to fetch it, used to relay 1p1c packages whose
parent alone is below the peer's feefilter. (`net_processing.cpp`
BIP331 handlers; still gated behind `-packagerelay` in Core as of v30 —
**verify the current default before building**.)

**Here.** Package *acceptance* is real (`submitpackage`, 1p1c in
`tx_accept.c`, orphan resolution in `tx_relay.c:653-685`). The wire
protocol is not built; `sendpackages` is recognised and ignored.

**Design.** Only worth doing if Core ships it on by default; otherwise
parity by absence. If yes: negotiate `sendpackages(version=1)`; on an orphan
whose parent is below feefilter, send `getpkgtxns` for the ancestor set;
serve `ancpkginfo`/`pkgtxns` for our own low-fee parents.

**Size.** Medium, **conditional**. Scoped, not scheduled.

---

## CC-10 — Completeness items

| item | here | design | size |
|---|---|---|---|
| `invalidateblock` / `reconsiderblock` | absent | an RPC that marks a block hash invalid in the header index, triggers the existing reorg path to the best remaining tip, and persists the mark; `reconsiderblock` clears it | small-medium |
| MuSig2 in tapscript **leaf** scripts | key-path only (`rpc_commands.c`) | leaf signing = the same partial-sig flow keyed by the leaf's sighash; the descriptor side already parses `musig()` | medium |
| BIP389 multipath | parsed (`descriptor.c:212`, `allow_mp`) | derive both branches, expose in `getdescriptorinfo`/`deriveaddresses` | small |
| Knapsack + SRD coin selection with the waste metric | BnB only (`wallet_bnb.c`) | Core's three-way race; SRD is 40 lines, knapsack ~150; the waste comparator picks | medium |

---

## Order and dependencies

```
CC-1 (inbound tx relay)  ─┬─> CC-3 (eviction: needs CC-1's tick)
CC-2 (compact receive)    │
CC-4 (block-only + anchors)
CC-5 (low-work headers)
CC-6 (stale tip)  small
CC-7 (peertimeout) small
CC-8 (replay)  — launch first: it runs unattended for days
CC-9 conditional; CC-10 completeness
```

**Recommended start:** launch CC-8 today (it costs nothing but disk and
runs while everything else is built), then CC-1, then CC-6 and CC-7 as
warm-ups for the same code region, then CC-3, CC-2, CC-4, CC-5.
