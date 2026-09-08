# 2026-09-08 — Rpcthreads defaults to Core's 4, not 16

Core's DEFAULT_HTTP_THREADS is 4 (workqueue 64, server timeout 30). This node defaulted to 16 threads and the 2026-09-06 defaults audit had Core's value wrong. Fixed in node_config.c and rpc_server.c; test_core_parity pins all three RPC defaults (watched to fail on 16); test_node_config had itself pinned 16 and is corrected. Sample conf and README stop claiming the pool is unconfigurable or unimplemented. Full gate 0 failures; 8 audits exit 0.

---

PR #88 (`batch/2026-09-08-rpcthreads-default`), merged 00:39Z as `abdc04bd`; tag `rpcthreads-default-2026-09-08`.
