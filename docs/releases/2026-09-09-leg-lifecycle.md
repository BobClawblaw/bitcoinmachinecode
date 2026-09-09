# 2026-09-09 — Outbound legs: every close says whose it is, a failed dial is remembered, the streak is per peer, pongs within one pass

Production's outbound legs lived a minute or two. Measured on the running node (deploy-20260909f, boot 08:50:57Z; the process that "started 16:00:49" is its coinstats fold worker, a fork) with a passive packet capture on the box, 16:30-16:55Z, restricted to the addresses the node itself dialled:

| legs opened in 25 min | 49 |
|---|---|
| closed by us | 22, lifetimes 50-364 s, median 156 s |
| closed by the peer within 2 s | 12 |
| closed by the peer at 54-98 s | 7, six of them at 61 s |
| still open at the end | 8 |
| ping answered after | 0 s, 0 s, 75 s |

**Closed by us, unlogged.** `do_outbound_sync` closed a leg after three failing sync passes with no line at all, and the streak lived in the SLOT, never reset when the slot changed hands: a fresh leg whose first pass failed was closed as the third strike of two predecessors, 50 s after connecting. Eight of the 22 were that. The rest were the 60-second pass budget, whose line named the leg "?" because the alarm handler had already shut the socket.

**Closed by the peer.** A Core-shaped client on a fresh socket got exactly the same treatment from the same addresses: eight flapping addresses refuse within a second (inbound-full nodes evicting their newest peer, or refusing at accept) and a few listeners hang up at 61 s having sent only version and verack, answering no getheaders. Not our version bytes, then -- though ours carry a fixed nonce, a fixed timestamp and start_height 0, which is its own batch. What was ours: nothing remembered any of it, so every rotation dialled the same addresses again -- 27 handshake refusals an hour, 100-200 connect timeouts an hour, one anchor every rotation for eight hours -- and a pong waited for its leg's turn in the rotation, so at an inbound-full node we were never among the protected lowest-ping peers.

**"Operation now in progress" is a timed-out connect, not an attempt in flight.** `tcp_connect_ip` connects BLOCKING under a 10 s `SO_SNDTIMEO`; when that expires the kernel reports EINPROGRESS. The dial was never abandoned mid-flight; the address was dead or blackholed. The text says "connect timed out (10s)" now.

- **Every deliberate close is labelled** `connection closed ours/<reason> after Ns`: sync-failed-3x (with the failure code and the pass duration), sync-budget, probe-budget, blocksonly-violation; the operator's disconnectnode/ban/network-off lines already named theirs. The remaining `revents` path is `closed theirs (revents 0x..) after Ns; unread: <the message types the peer left in the socket, a reject's text>`.
- **The dial memory** (`daemon/dial_memory.c`, one MAP_SHARED table for the worker and its dial helpers): a connect failure, a handshake refusal, or a hang-up within 3 minutes puts the address off the candidate list for 10 minutes, doubling per consecutive failure to 6 hours; a leg that lived 10 minutes clears it; lacking NODE_WITNESS is permanent for the run. Consulted by the leg re-dial, the top-up, and the background helper's pick; the heartbeat reports how many candidates it skipped. What Core's addrman does with nLastTry/nAttempts.
- **The streak is per peer** (`leg_note_installed`), and a closed slot re-dials on the next rotation instead of after the dead-slot backoff.
- **The only live leg gets four times the pass budget** (240 s) before it is replaced; the alarm still ends the pass either way, because a trickling peer resets `SO_RCVTIMEO` on every partial read and the pass would never return on its own (the first cut skipped the shutdown for a sole leg and `test_sync_budget` caught it: the budget's whole point is that the pass ends). Recycling the only path to the network every 60 s was a starvation loop (bmcmonitor: connections median 1, sub-minute flicker).
- **Pongs within one pass**: after each leg's pass the worker drains what every other leg has buffered (a ping used to wait a whole rotation, 75 s measured).

Answers to the brief's questions. The budget measures wall-clock from the start of one sync pass on one leg (`alarm(60)` around `do_outbound_sync`); nothing resets it; a pass at the tip normally takes 1-5 s (getheaders answered in under a second) and blows the budget only when the peer answers nothing or a block fetch stalls. It fired on the only leg because it never counted legs. It is per pass; a sole leg now gets 240 s, with company 60 s.

`test_dial_memory` (new): the schedule, the host key, the permanent case, the clearing, a full table. `test_dialhelper`: EINPROGRESS reads as a timeout (**watched to fail**). Gate `make -j8 -k test`: see the trailer.

**Acceptance is measured after the restart, not asserted here**: the median leg lifetime, the number of `theirs` closes and their unread text, connections at the configured budget for an hour, `sync_failing=0`, the tip against mempool.space. The node was not restarted for this note; snapshot `deploy-20260909h` is staged.
