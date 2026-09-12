# 2026-09-09 — The download worker's picker: a dead-marked peer never clears the bar, not even a fresh sync's unknown bar

Run 19 stalled at block 560 eleven minutes in. Two peers accepted the handshake and closed the socket on every `getdata` for the early chain; the two workers holding them went back to the same two peers 200 times each while the in-order committer waited on their chunk and fourteen workers idled.

The 2026-09-07 rule marks a peer that fails a fetch with 1.0 bytes/s -- "tried, worthless", ranked below any measured peer and never offered as untried. It works under a known bar. On a fresh sync the pool median is unknown, the bar is 0, and the picker's first rule read bar 0 as "anything with speed history clears it": the dead mark outranked every untried peer. The chunk would have been abandoned after 400 attempts (13 minutes) and the next chunk those workers claimed would have stalled the same way.

- **The dead mark never clears a bar.** `DLC_EMA_DEAD_MARK` (1.0) names the value; a peer at or below it ranks below the untried under any bar, including 0. A measured peer under an unknown bar is picked as before.

`test_dialhelper`: ema [1.0, 0.5, untried, untried] with bar 0 picks an untried peer (**watched to fail**: the dead mark), the least-failed mark when nobody is untried, a measured peer with bar 0 as before.

Run 19 was restarted from scratch a second time on this build; its two earlier starts are kept under `bench-logs/run19a-20260909` (the second-highest announced-height rule, PR #140) and `run19b-20260909` (this stall).
