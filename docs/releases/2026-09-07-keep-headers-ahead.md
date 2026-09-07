# 2026-09-07 — Headers ahead of the archive are kept across a restart

The boot self-heal from the 2026-09-01 incident cut `headers.dat` back to
the archive tip on every boot. That rule was written for `index.dat`'s
empty tail; headers ahead of blocks is what headers-first means. The cost
showed on today's scratch node: a restart in the middle of a sync
refetched every header above the archive, 71 MB on mainnet and the whole
held region below the minimum-chainwork floor again, about ten minutes on
that link.

A record past the tip is now kept while it hashes to its own record and
links to the one below. The mirror is cut at the first break, so a torn
write still cannot leave junk in it. Every record was PoW-gated by the
fetch that wrote it; this check guards against corruption, not against a
peer. `chainwork.dat` stays tied to the applied blocks, unchanged.

`test_archive_trim` gains six checks and was watched to fail on the old
rule with four failures. On the scratch datadir the boot line read
"headers.dat runs 816,167 linked record(s) ahead of the archive tip
(headers-first): kept", and the first download status line came 90
seconds after start against about 600 before.

## Seen on the same boot, not changed here

Two more lines from the same self-heal on that restart:

- `index.dat carried 815,601 empty record(s) past the tip -- trimmed`.
  The download pre-sizes the index toward the header count, and the boot
  cuts it back. Harmless; the file is re-extended when the download
  resumes.
- `index.dat carried 566 record(s) beyond the linked chain (height 149,772
  does not continue height 149,771) -- trimmed`. The chain-continuation
  walk stops at the first hole, and everything stored above that hole is
  discarded even though those blocks were valid out-of-order arrivals
  from chunks in flight when the node stopped. With 16 workers on 40-block
  chunks that is up to about 640 blocks per restart, around a gigabyte on
  the tail. The safe rule would keep a record above a hole when the
  linked header chain has the same hash at that height. Recorded for its
  own fix.
