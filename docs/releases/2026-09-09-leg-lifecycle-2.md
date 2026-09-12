# 2026-09-09 — Legs, second pass: the peer's half-close is seen at once, and the drains get the patience they were designed with

The first hour of close labels on production (snapshot i, boot 18:38:24Z) showed 17 closes in twenty minutes and named them:

| label | count | what it was |
|---|---|---|
| ours/sync-failed-3x, where=4 in 0.0 s | 8 | the peer had sent FIN; a half-close raises POLLRDHUP, which the rotation's poll did not ask for, so the leg sat dead for three rotations while each pass failed on an immediate EOF |
| ours/sync-failed-3x, where=3 in 2.4 s | 7 | "no headers": the leg's socket kept its dial-time 300 ms read timeout, so the headers drain's eight ticks gave a peer 2.4 s, not the 24 s the count was written for |
| theirs (revents 0x19) | 2 | nothing left unread |
| budget kills | 0 | |

- **Half-close is a hang-up.** The rotation polls `POLLIN|POLLRDHUP` (`leg_peer_hung_up`), and a sync pass that hits EOF on its first read is logged `closed theirs (EOF on the first read)`, the address remembered if the leg was young, the slot re-dialled on the next rotation. It was `ours/sync-failed-3x` three rotations later.
- **3-second ticks after the handshake** (`leg_settle_socket`): the headers drain waits up to 24 s of silence and the block drain 60 s, as their comments say; the 300 ms timeout stays for the dial and handshake only, where it bounds a trickling peer.
- **A leg retired by the three-strike streak feeds the dial memory** like an early drop. The LAN capture (19:00-19:14Z, the interface the oracle is not on) showed that every leg we retired that way was one of a handful of cloud-hosted listeners which complete the handshake and never answer a `getheaders`; one was dialled seven times in fifteen minutes because this was the one close not remembered. Nothing we send precedes any peer's FIN.
- **A permanent dial-memory entry** (no witness) answers -1 on a later failure instead of "10 min".

`test_dialhelper`: a quiet socketpair is not a hang-up, the peer's `shutdown(SHUT_WR)` is (POLLRDHUP), its close still is, a settled socket reads in 3 s ticks (was 300 ms). `test_dial_memory`: the permanent case (**watched to fail**). Gate: see the trailer.

The capture also closes the last open question from the first batch: the peers that FIN us at 2 to 15 minutes had sent nothing after their verack and answered no `getheaders`; they are the same non-serving listeners, and the memory now holds them off.

---

**Amended 20:2xZ, PR #149:** the 3 s tick did not hold on snapshot k -- five legs still failed "no headers" at 2.4 s -- because the dial path re-applied its 300 ms bound after the handshake, at the very end of `outbound_connect_raw`, past the point where `leg_settle_socket` had set 3 s. That re-application is gone; the socket stays at 3 s.

PR #146 (`batch/2026-09-09-leg-lifecycle-2`), merged 19:3xZ as `a7fd883b`; tag `leg-lifecycle-2-2026-09-09`. Gate MAKE_EXIT 0, 344 passes. Staged as `deploy-20260909k`, the live link; not yet running on production.

The amendment: PR #149 (`batch/2026-09-09-leg-read-tick`), merged 20:2xZ as `1b2ff97f`; tag `leg-read-tick-2026-09-09`; staged as `deploy-20260909m`.
