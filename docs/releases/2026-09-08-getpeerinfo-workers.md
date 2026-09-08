# 2026-09-08 — Getpeerinfo lists the parallel download's peers with their chunk in flight; getnettotals counts the download's bytes

Core's getpeerinfo during IBD is where an operator watches the sync. This node's sixteen download workers are forked processes whose sockets the RPC server never saw: getpeerinfo showed the five legs, getnettotals read 3 KB against a 50 GB archive. The catch-up parent now publishes each worker's peer into the shared status page every tick (address, handshake facts, connect time, bytes on that peer, the chunk in flight); getpeerinfo appends them (ids 100000+, Core's inflight list, connection_type outbound-full-relay, plus bmc_download_worker) and getnettotals adds the download's byte total. When the download ends the entries leave and the total stays. test_rpc_node +5. Live on run 17: 22 entries (6 legs + 16 workers), 1,029 MB received. Full gate 0 failures; 8 audits exit 0.

---

PR #95 (`batch/2026-09-08-getpeerinfo-workers`), merged 04:42Z as `f42d493e`; tag `getpeerinfo-workers-2026-09-08`.
