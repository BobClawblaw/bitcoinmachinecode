# 2026-09-08 — The committer syncs once per chunk

Run 18, the first fresh sync on the in-order committer, showed in its
first minutes what had paced every run's early chain: 103 chunks staged
(the whole 4,096-block window) and the committer at 96 blocks a second,
waiting in `jbd2_log_wait_commit`. `store_append_shared` does an
`fdatasync` after every block (STO-11: the bytes are durable before the
record that points at them), so a single sequential writer is one ext4
journal commit per block, and the early chain, where blocks are a few
hundred bytes, ran at the SSD's commit rate whatever the network offered.
The sixteen workers had the same limit, serialized under `append.lock`,
which is why every run's first five minutes looked alike.

The committer is the one place that can batch it. The per-block sync is
switched off in the committer process only (it is a fork; the switch is a
per-process global) and the chunk's block file and index file are
`fdatasync`'d once after its forty appends. ext4's `data=ordered` keeps
STO-11's order at the commit boundary: an extending write's data is
flushed before the commit that names it. A crash loses at most the last
chunk's appends; the boot check cuts the index at the first record whose
body is missing and the download fetches the chunk again. The daemon's
own appends at the tip keep the per-block sync.

## Measured

Run 18, resumed on this build at 45,481 blocks (05:48:22Z), against the
same run's first five minutes on the per-block sync:

| | blocks per 10 s tick | network receive | staged chunks |
|---|---|---|---|
| per-block sync (05:42 to 05:47) | 950 to 2,900 | 67 to 187 KB/s | 102 to 103 (the window, full) |
| per-chunk sync (05:48 on) | 3,440 to 17,800 | 8.6 to 11.4 MB/s (the link) | 67 and falling |

It reached 144,841 blocks 66 seconds after the switch. The previous build
took five minutes to reach 44,497, and run 9 reached 86,000 at five
minutes. The early chain is now paced by the network, as the rest of the
sync already was.

## Tests

`test_dialhelper`'s committer-loop check counts the sync callback: once
per committed chunk (2), not once per block (80).
`test_sto11_append_durability` is untouched and passes.

Gate `make -j8 test`: 0 failures (the one expected test_rpc_signer
segfault); 8 static audits exit 0.
