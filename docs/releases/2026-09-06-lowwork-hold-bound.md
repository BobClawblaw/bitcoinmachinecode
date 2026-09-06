# 2026-09-06 — CC-5's low-work hold is bounded by memory, not by four pages

This morning's CC-5 (PR #19) stopped storing header pages whose chain has
less work than `-minimumchainwork`, holding them until the chain proves its
work. It held at most four pages and abandoned the chain on the fifth. An
honest mainnet chain is below the floor for its first ~880,000 headers, so
the rule abandoned every fresh sync and every resume from below that
height. Nothing in the gate could see it: the test crossed the floor at
header 5,000, and the live node is at the tip, where a fetch is a few
headers above the floor.

It was found at 04:59Z when the CC-8 replay was restarted on the first
binary that carried the rule: its header phase gave up 0.3 s after it
started, the parallel downloader saw an "already complete" archive, and
the node fell back to its serial leg.

The hold is now 1,000 pages (2,000,000 headers) in a 162 MB anonymous
mapping made on the first held page and unmapped on release, abandon or
the next fetch. An honest sync from genesis touches ~71 MB of it once; a
peer feeding junk costs one fetch's mapping and nothing on disk. Core's
presync keeps bit commitments and re-downloads instead; that stage is
still not done. `test_hdr_lowwork` now crosses the floor on the tenth page
and was watched to fail on the four-page module first.
