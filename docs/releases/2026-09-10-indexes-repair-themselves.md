# 2026-09-10 — The block filter index and the address history repair themselves

Inventory row 2 (history indexes). Core builds and repairs txindex, coinstatsindex and blockfilterindex inside the daemon and `-reindex` rebuilds them all. Here the coinstats history has repaired itself since 2026-09-08: when its base is absent or broken the daemon spawns the offline builder beside its own executable at nice 10, backs off six hours between failures, gives up after three, waits for initial block download to end, and adopts the result. The block filter index and the address history needed an operator: production's filter index sat at 966,181 for a day, and the daemon did not even maintain it because `blockfilterindex=1` was not in the config.

- **One supervisor, one instance per index** (`daemon/index_repair.c`, the coinstats shape as a module): the caller says whether the index needs a build and to what height; the module spawns, reaps, backs off, gives up, words its state, and never runs two builders for one index. A spawn seam lets the test drive it with a stub.
- **The block filter index** needs a build when the daemon has not adopted it and the files are absent or more than 144 blocks behind the archive tip. The builder runs to the tip; when it ends the live tail adopts within 144 blocks and closes the remainder from undo data, as it already did. Gated on `blockfilterindex=1`, Core's key.
- **The address history** needs a build when its base is absent; the live address tail carries it forward from there. Gated on `addrindex=1`.
- Both tick once per heartbeat beside the coinstats supervisor and log under `[bfilter] repair:` and `[addrhist] repair:`.

`test_index_repair`: no spawn when nothing is needed or during initial block download; a spawn to the target when needed; no second spawn while one runs; adoption when the builder ends and the index is current; backoff, a second and third attempt after six hours each, then give up for the boot; disabled by config; a missing builder.

**On production**, `blockfilterindex=1` is now set; on the next restart the daemon adopts the 966,181-record index (within 144 of the tip) and closes the gap from undo, and would spawn the builder if it were further behind.
