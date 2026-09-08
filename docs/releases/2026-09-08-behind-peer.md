# 2026-09-08 — A header page that ends below our tip means the peer is behind us

Production's 11:58Z header phase ranked a node ~100k blocks behind the tip as its fastest peer. That peer answers a getheaders from the deepest locator hash it knows and sends the 2,000 headers after it, every one a header we hold. `dlc_take_page` verified the overlap and appended nothing, the full page counted as progress, the locator (rebuilt from our unchanged tip) asked the same question and the peer gave the same page: 415 identical pages, 67 MB, 25 minutes, the tip loop waiting throughout.

- `dlc_fetch_headers` checks, before the low-work hold, whether the page ends below what the store holds. If so the peer is behind us: a log line, -1, and `dlc_headers` tries the next candidate.
- A short page of known headers used to read as "already current"; it is the same refusal now.
- test_dialhelper +1: a page from an earlier locator point that ends below our tip is refused with -1 and the store is unchanged. Watched to fail on the old loop, which returned 0.

Gate: `make -j8 test` MAKE_EXIT=0; the eight static audits pass (gate-log-check flags test_rpc_signer's intentional segfault, as always).

---

PR #110 (`batch/2026-09-08-behind-peer`), merged 12:43Z as `b74b72fb`; tag `behind-peer-2026-09-08`.
