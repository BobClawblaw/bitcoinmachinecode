# 2026-09-09 — The header phase refuses a chain far below what the pool announces

The parallel downloader took the first ranked peer's header chain that crossed -minimumchainwork. On the bench that peer was stuck on a real 8-block stale branch 4,500 blocks below the tip; the whole branch was downloaded, applied, and the run sat there for four hours (`2026-09-09-chain-selection.md` has the recovery side).

- **Announced height.** The ranking pass already handshakes every live peer; it now records each one's `start_height` (parsed as `getpeerinfo` does, through `rpc_peer_from_version`, since the relay byte follows it) in a shared array aligned with the ranked list, and logs the pool's claim: the SECOND-highest of the claims, so one peer cannot move it.
- **The rule** (`daemon/dlc_rules.h`, header-only): a fetched chain ending more than `DLC_HDR_BEHIND_MAX` (144) below the announced height is a peer that is behind or on a stale branch; the fetch is rolled back and the next candidate tried, including a peer that answers "already current" at such a tip. When every candidate falls short the longest is taken and the log says so -- the announcement may be the liar, or every reachable peer may be behind.

`test_dlc_rules` (new, **watched to fail** against an always-accept rule): the second-highest claim; a single claim; a lone 969,817 among 966,06x does not move it; 144 short accepted, 145 short refused, at or above accepted; no announcement, nothing falls short.
