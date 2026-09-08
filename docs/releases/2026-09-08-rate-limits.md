# 2026-09-08 — Three node-wide rate limits

Core has one throttle, `maxuploadtarget`, and it is a budget: MiB per
rolling day, after which historical blocks are refused to peers that are
not whitelisted. This node has had that key, with Core's semantics, since
the serve side was metered. Today it gains three rates, all its own
(`bmc.` keys), all off by default, all node-wide: one clock file in the
datadir, three cells, shared by every process the node forks, so the
ceiling is on the node and not on each worker.

| key | unit | what it paces |
|---|---|---|
| `bmc.dialratelimit` | attempts per second | every remote outbound connection attempt: the download workers, the header fetch, both liveness probe rounds, the running node's legs, the clearnet, SOCKS5, onion and I2P dialer paths, the address crawlers. Not loopback, not the local SAM bridge. |
| `bmc.downloadratelimit` | KB/s | every block message the parallel download receives, wanted or not, and every header page the boot fetch receives. The ranking probes are exempt, because pacing them would corrupt the ranking, and so are the keep-up legs at the tip. |
| `bmc.uploadratelimit` | KB/s | every message the node sends, on both transports: `p2p_write` gained a hook called before the write with the fd and the payload length, installed when the key is set and inherited by every forked serve child. |

A dial reserves the next slot on the clock, 1000/N ms apart, and sleeps
to it, so there are no bursts. Bytes are charged as a debt the next read
or write waits out; an idle clock never owes the past.

Tests pin the parsing and clamping of all three keys, the two pacers'
arithmetic, the fetcher's bytes hook, and the assembly hook on a
socketpair (called once, before the write, with the right fd and length;
every byte still arrives; a cleared hook is not called). The abi and
callee-saved audits pass on the new assembly. The boot config line prints
all three.
