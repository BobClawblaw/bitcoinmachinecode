#!/usr/bin/env python3
"""ibd_stage_report.py -- per-segment, per-stage timing of a logged Core IBD
and a logged bmc IBD, from their logs only (no RPC, no node needed).

Plan: worklog/2026-10-04-logged-ibd-runs-plan.md. The runs are produced by
validation/logged_pair_run.sh:
  Core v31.1 with config/core-bench/bitcoin.logged.conf (debug=bench,
  debug=coindb, logtimemicros=1), watched by validation/core_bench_watch.sh
  (IBD_END, READY_TIP, READY_INDEXES in watch.log);
  bmc via validation/fresh_ibd_run.sh with BENCHLOG=1 DLSHAPE=core
  (bmc.benchlog=1 lines, IBD_END and READY in phase.log).

USAGE
  ibd_stage_report.py --core-dir /srv/nvme8tb/bench/core31 \
                      --bmc-dir  /srv/nvme8tb/bench/run34  > report.md
  (--core-dir D = D/debug.log, D/BENCH_START.txt, D/watch.log;
   --bmc-dir  R = R/data/main/debug.log, R/epoch.start, R/phase.log.)
  Or name the pieces: --core-log/--core-start/--core-watch,
  --bmc-log/--bmc-start/--bmc-phase. A start is epoch seconds, an ISO/UTC
  time, or @FILE holding either. Either side may be left out.
  --segment N   segment size in heights (default 100000).

SELF-TEST (make-free; also run by validation/test_ibd_harness.sh, which the
asm `make test` gate runs):
  python3 validation/ibd_stage_report.py --selftest     # last line: SELFTEST PASSED

WHAT IS PARSED
Core (validation.cpp, v31.1). Per connected block, in this order:
  "  - Load block from disk: X ms"  (preceded by "  - Using cached block" when cached)
  "    - Sanity checks" | "    - Fork checks" | "      - Connect N transactions"
  | "    - Verify N txins" | "    - Write undo data" | "    - Index writing"
  "  - Connect total" | "  - Flush" | "  - Writing chainstate"
  UpdateTip: ... height=H ...      (the block's height, and its wall clock)
  "  - Connect postprocess" | "- Connect block"   (closes the block)
  Each line carries a [bench] tag; each block's lines are attributed to the
  UpdateTip that falls between its "Writing chainstate" and "Connect block".
  NOTE "Verify N txins" is timed from the SAME start as "Connect N
  transactions" (time_4 - time_2 in ConnectBlock), so it CONTAINS the connect
  time. The report shows "verify wait" = verify - connect: the time spent
  waiting on the script-check threads after the inputs were connected.
  Timer lines "<func>: write coins cache to disk (...) completed (X ms)" (the
  UTXO flush, BatchWrite), "write block index to disk", "write block and
  undo data to disk"; and [coindb] "Writing chainstate to disk: flush mode=M".
  Core's txindex / coinstatsindex / blockfilterindex run on their own threads
  from validation-interface callbacks; no per-block timer covers them.
bmc (bmc.benchlog=1, asm/daemon):
  "[bench] block H: N tx, M txin | read X | idx X | verify X | get X | put X
   | ckpt X | flush X | csi X | total X ms"
  "[bench] index H: txindex X | txospender X | bfilter X | addr X | zmq X ms"
  any other "[bench] <kind> ..." line (memtable flushes): counted per kind,
  with its "total X ms" or last "X ms" summed;
  "[dlc] chunk ..." per-chunk lines: key=value tokens, parsed defensively
  (units ms/s, B/KB/MB/GB); "[ready] all indexes at height N";
  "[dlc] catch-up done"; and, when there are no [bench] block lines,
  "[utxo_live] catchup progress: height=N" for the milestones.

The segments' wall times are end-to-end differences (the first segment from
the run's start, so header sync counts there), so they sum to the total.
"""
import calendar
import os
import re
import sys
import tempfile

SEG_DEFAULT = 100000

CORE_STAGES = [
    # key, label
    ("load", "load"), ("sanity", "sanity"), ("fork", "fork"),
    ("connect", "connect txs"), ("verify_wait", "verify wait"),
    ("undo", "undo"), ("index", "index writing"), ("flush", "flush"),
    ("chainstate", "write chainstate"), ("postprocess", "postprocess"),
]
BMC_STAGES = ["read", "idx", "verify", "get", "put", "ckpt", "flush", "csi"]
BMC_INDEX = ["txindex", "txospender", "bfilter", "addr", "zmq"]


# ---------------------------------------------------------------- time ----
def parse_ts(s):
    """'2026-10-04T13:48:36.123456Z', '2026-10-04T13:48:36Z',
    '2026-10-03 23:45:36.245' or '2026-10-03 23:45:36' (all UTC) -> float."""
    s = s.strip().rstrip("Z")
    if len(s) < 19 or s[4] != "-" or s[10] not in "T ":
        return None
    try:
        t = calendar.timegm((int(s[0:4]), int(s[5:7]), int(s[8:10]),
                             int(s[11:13]), int(s[14:16]), int(s[17:19]), 0, 0, 0))
    except ValueError:
        return None
    if len(s) > 20 and s[19] == ".":
        try:
            t += float("0" + s[19:])
        except ValueError:
            pass
    return float(t)


def parse_start(v):
    if v is None:
        return None
    v = v.strip()
    if v.startswith("@"):
        try:
            with open(v[1:]) as f:
                v = f.read().strip()
        except OSError:
            return None
    if re.fullmatch(r"\d{9,11}(\.\d+)?", v):
        return float(v)
    return parse_ts(v.replace(" UTC", ""))


def hms(sec):
    if sec is None:
        return "--"
    # Truncated, not rounded: ibd_milestones.sh and the published tables drop
    # the fraction (mktime on whole seconds), and this must reproduce them.
    sign = "-" if sec < 0 else ""
    sec = int(abs(sec))
    return "%s%d:%02d:%02d" % (sign, sec // 3600, sec % 3600 // 60, sec % 60)


def fs(x):
    return "--" if x is None else ("%.1f" % x)


def open_log(path):
    return open(path, "r", encoding="utf-8", errors="replace")


# ------------------------------------------------------------ segments ----
class Seg:
    def __init__(self):
        self.st = {}          # stage -> ms
        self.blocks = 0
        self.tx = 0
        self.txin = 0
        self.extra = {}       # misc counters

    def add(self, k, v):
        self.st[k] = self.st.get(k, 0.0) + v

    def inc(self, k, v=1):
        self.extra[k] = self.extra.get(k, 0) + v


class Side:
    def __init__(self, name):
        self.name = name
        self.log = None
        self.start = None
        self.tip_ts = {}      # height -> first time seen (UpdateTip / bench block)
        self.segs = {}        # seg index -> Seg
        self.max_h = -1
        self.ibd_end = None
        self.ready = {}       # label -> ts
        self.ready_h = None
        self.notes = []
        self.misc = {}        # run-level counters
        self.chunks = []      # dict per chunk line
        self.other_bench = {}  # kind -> [count, ms]
        self.lines = 0

    def seg(self, h, size):
        k = h // size
        s = self.segs.get(k)
        if s is None:
            s = self.segs[k] = Seg()
        return s

    def mark_height(self, h, ts):
        if ts is not None and h not in self.tip_ts:
            self.tip_ts[h] = ts
        if h > self.max_h:
            self.max_h = h

    def inc(self, k, v=1):
        self.misc[k] = self.misc.get(k, 0) + v


# ---------------------------------------------------------------- Core ----
RE_NUM_MS = re.compile(r":\s*([\d.]+)ms")
RE_UPDATETIP_H = re.compile(r" height=(\d+) ")
RE_CONNECT_N = re.compile(r"^- Connect (\d+) transactions: ([\d.]+)ms")
RE_VERIFY_N = re.compile(r"^- Verify (\d+) txins: ([\d.]+)ms")
RE_TIMER = re.compile(r"^(\w+): (.+?) completed \(([\d.]+)ms\)")
RE_FLUSHMODE = re.compile(r"Writing chainstate to disk: flush mode=(\w+)")
RE_COMMITTED = re.compile(r"Committed (\d+) changed transaction outputs")

CORE_SIMPLE = [
    ("- Load block from disk:", "load"),
    ("- Sanity checks:", "sanity"),
    ("- Fork checks:", "fork"),
    ("- Write undo data:", "undo"),
    ("- Index writing:", "index"),
    ("- Connect total:", "connect_total"),
    ("- Flush:", "flush"),
    ("- Writing chainstate:", "chainstate"),
    ("- Connect postprocess:", "postprocess"),
]


def core_ts(line):
    i = line.find(" ")
    return parse_ts(line[:i]) if i > 0 else None


def parse_core(path, size, side=None):
    side = side or Side("Core")
    side.log = path
    pending = {}
    pend_tx = pend_txin = 0
    cur_h = None
    unattributed = 0
    with open_log(path) as f:
        for line in f:
            side.lines += 1
            if "\x00" in line:
                line = line.replace("\x00", "")
            b = line.find("[bench] ")
            if b >= 0:
                text = line[b + 8:].strip()
                if text.startswith("- Connect block:"):
                    m = RE_NUM_MS.search(text)
                    if m:
                        pending["block"] = pending.get("block", 0.0) + float(m.group(1))
                    if cur_h is None:
                        unattributed += 1
                    else:
                        s = side.seg(cur_h, size)
                        for k, v in pending.items():
                            if k.endswith("_n"):
                                s.inc(k, v)
                            else:
                                s.add(k, v)
                        if "verify" in pending:
                            s.add("verify_wait", max(0.0, pending["verify"] - pending.get("connect", 0.0)))
                        s.blocks += 1
                        s.tx += pend_tx
                        s.txin += pend_txin
                    pending = {}
                    pend_tx = pend_txin = 0
                    continue
                m = RE_CONNECT_N.match(text)
                if m:
                    pend_tx += int(m.group(1))
                    pending["connect"] = pending.get("connect", 0.0) + float(m.group(2))
                    continue
                m = RE_VERIFY_N.match(text)
                if m:
                    pend_txin += int(m.group(1))
                    pending["verify"] = pending.get("verify", 0.0) + float(m.group(2))
                    continue
                hit = False
                for pfx, key in CORE_SIMPLE:
                    if text.startswith(pfx):
                        m = RE_NUM_MS.search(text)
                        if m:
                            pending[key] = pending.get(key, 0.0) + float(m.group(1))
                        hit = True
                        break
                if hit:
                    continue
                if text.startswith("- Using cached block"):
                    pending["cached"] = pending.get("cached", 0.0) + 1
                    continue
                if text.startswith("- Disconnect block"):
                    side.inc("disconnects")
                    continue
                m = RE_TIMER.match(text)
                if m:
                    title, ms = m.group(2), float(m.group(3))
                    if title.startswith("write coins cache to disk"):
                        key = "coins_flush"
                    elif title.startswith("write block index to disk"):
                        key = "blockindex_flush"
                    elif title.startswith("write block and undo data to disk"):
                        key = "blockfile_flush"
                    else:
                        key = "timer:" + title
                    # Into the block being connected (a flush inside its
                    # "Writing chainstate"); a periodic flush between blocks
                    # lands on the next block.
                    pending[key] = pending.get(key, 0.0) + ms
                    pending[key + "_n"] = pending.get(key + "_n", 0) + 1
                    side.inc(key + "_n")
                    side.inc(key + "_ms", ms)
                    continue
                side.inc("bench_other_lines")
                continue
            if "UpdateTip: new best=" in line:
                if "background validation" in line:
                    continue
                m = RE_UPDATETIP_H.search(line)
                if m:
                    cur_h = int(m.group(1))
                    side.mark_height(cur_h, core_ts(line))
                continue
            if "[coindb] " in line:
                m = RE_FLUSHMODE.search(line)
                if m:
                    side.inc("coindb_writes")
                    side.inc("coindb_mode:" + m.group(1))
                    continue
                m = RE_COMMITTED.search(line)
                if m:
                    side.inc("coindb_committed_txouts", int(m.group(1)))
                continue
            if side.ibd_end is None and "Leaving InitialBlockDownload" in line:
                side.ibd_end = core_ts(line)
    if unattributed:
        side.notes.append("%d Core block(s) closed before any UpdateTip line (not attributed)" % unattributed)
    return side


def parse_core_watch(path, side):
    try:
        f = open_log(path)
    except OSError:
        return
    with f:
        for line in f:
            p = line.split()
            if len(p) < 3:
                continue
            if p[1] in ("READY_TIP", "READY_INDEXES", "IBD_END"):
                ts = parse_ts(p[2])
                if ts is None:
                    continue
                if p[1] == "IBD_END":
                    if side.ibd_end is None:
                        side.ibd_end = ts
                else:
                    side.ready.setdefault(p[1], ts)
                m = re.search(r"height=(\d+)", line)
                if p[1] == "READY_TIP" and m:
                    side.ready_h = int(m.group(1))


# ----------------------------------------------------------------- bmc ----
RE_BMC_BLOCK = re.compile(r"\[bench\] block (\d+):(.*)$")
RE_BMC_INDEX = re.compile(r"\[bench\] index (\d+):(.*)$")
RE_BMC_OTHER = re.compile(r"\[bench\] (\S+)(.*)$")
RE_PART = re.compile(r"^\s*([A-Za-z_][\w-]*)\s+([\d.]+)\s*(ms|s|us)?\s*$")
RE_TXCOUNTS = re.compile(r"(\d+)\s*tx\b.*?(\d+)\s*txin")
RE_MS_ANY = re.compile(r"([\d.]+)\s*ms\b")
RE_TOTAL_MS = re.compile(r"total[ =:]+([\d.]+)\s*ms")
RE_PROGRESS = re.compile(r"\[utxo_live\] catchup progress: height=(\d+)")
RE_READY = re.compile(r"\[ready\] all indexes at height (\d+)")
RE_KV = re.compile(r"([A-Za-z_][\w]*)=([^\s,|]+)")
RE_DLC_SUMMARY = re.compile(r"\[dlc\] -- recv ([\d.]+[KMG]?B/s) \(avg ([\d.]+[KMG]?B/s)\) \| pool idle (\d+)%")
RE_DLC_PEER = re.compile(r"\[dlc\]\s+w(\d+) (\S+)\s+chunks=(\d+)\s+blocks=(\d+)")
# 2026-10-04: the format daemon/dlc_benchlog.c actually prints (bmc.benchlog):
# "[bench] chunk w3 peer 1.2.3.4:8333: blocks 800000..800015 (16) | wall 1234 ms
#  | wait 56 ms | 12.34 MB (10.00 MB/s) | inflight max 16"
RE_BENCH_CHUNK = re.compile(r"\[bench\] chunk w(\d+) peer (\S+): blocks (\d+)\.\.(\d+) \((\d+)\) \| wall (\d+) ms \| wait (\d+) ms \| ([\d.]+) MB \([\d.]+ MB/s\) \| inflight max (\d+)")


def to_ms(v, unit):
    v = float(v)
    if unit == "s":
        return v * 1000.0
    if unit == "us":
        return v / 1000.0
    return v


def parse_parts(body):
    """'read 1.2 | idx 0.3 | ... | total 9.9 ms' -> {name: ms}. A unit on the
    last part applies to the unitless ones (the line writes 'ms' once)."""
    out = {}
    parts = body.split("|")
    unit = None
    for p in parts:
        m = RE_PART.match(p)
        if m and m.group(3):
            unit = m.group(3)
    for p in parts:
        m = RE_PART.match(p)
        if m:
            out[m.group(1)] = to_ms(m.group(2), m.group(3) or unit or "ms")
    return out


def bmc_ts(line):
    return parse_ts(line[:23]) if len(line) >= 23 else None


UNIT_BYTES = {"B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "KIB": 1024, "MIB": 1048576, "GIB": 1073741824}


def kv_value(v):
    """'123ms' -> ('s', 0.123); '4.5s' -> ('s', 4.5); '1.2MB' -> ('B', 1.2e6);
    '17' -> ('', 17.0); anything else -> (None, raw)."""
    m = re.fullmatch(r"([\d.]+)(ms|s|us|B|KB|MB|GB|KiB|MiB|GiB)?", v)
    if not m:
        return None, v
    x = float(m.group(1))
    u = m.group(2) or ""
    if u == "ms":
        return "s", x / 1000.0
    if u == "us":
        return "s", x / 1e6
    if u == "s":
        return "s", x
    if u:
        return "B", x * UNIT_BYTES[u.upper()]
    return "", x


def parse_bmc(path, size, side=None):
    side = side or Side("bmc")
    side.log = path
    progress_seen = {}
    have_block_lines = False
    peers = {}
    with open_log(path) as f:
        for line in f:
            side.lines += 1
            if "\x00" in line:
                line = line.replace("\x00", "")
            if "[bench] " in line:
                m = RE_BMC_BLOCK.search(line)
                if m:
                    have_block_lines = True
                    h = int(m.group(1))
                    head, _, rest = m.group(2).partition("|")
                    parts = parse_parts(rest)
                    s = side.seg(h, size)
                    for k, v in parts.items():
                        s.add(k, v)
                    tc = RE_TXCOUNTS.search(head)
                    if tc:
                        s.tx += int(tc.group(1))
                        s.txin += int(tc.group(2))
                    s.blocks += 1
                    side.mark_height(h, bmc_ts(line))
                    continue
                m = RE_BMC_INDEX.search(line)
                if m:
                    h = int(m.group(1))
                    s = side.seg(h, size)
                    for k, v in parse_parts(m.group(2)).items():
                        s.add("ix:" + k, v)
                    s.inc("index_lines")
                    continue
                m = RE_BENCH_CHUNK.search(line)
                if m:
                    side.chunks.append({"_ts": bmc_ts(line), "w": m.group(1), "peer": m.group(2).rstrip(":"),
                                        "h": "[%s,%s]" % (m.group(3), m.group(4)), "n": m.group(5),
                                        "wall": m.group(6) + "ms", "wait": m.group(7) + "ms",
                                        "bytes": m.group(8) + "MB", "inflight": m.group(9)})
                    continue
                m = RE_BMC_OTHER.search(line)
                if m:
                    kind = m.group(1).rstrip(":")
                    rest = m.group(2)
                    t = RE_TOTAL_MS.search(rest)
                    ms = float(t.group(1)) if t else None
                    if ms is None:
                        a = RE_MS_ANY.findall(rest)
                        ms = float(a[-1]) if a else 0.0
                    e = side.other_bench.setdefault(kind, [0, 0.0])
                    e[0] += 1
                    e[1] += ms
                continue
            if "[dlc]" in line:
                if "[dlc] chunk" in line:
                    d = {"_ts": bmc_ts(line)}
                    for k, v in RE_KV.findall(line):
                        d[k] = v
                    side.chunks.append(d)
                    continue
                if "[dlc] catch-up done" in line and side.ibd_end is None:
                    side.ibd_end = bmc_ts(line)
                    continue
                m = RE_DLC_SUMMARY.search(line)
                if m:
                    side.misc["dlc_last_summary"] = "recv %s (avg %s), pool idle %s%%" % m.groups()
                    continue
                m = RE_DLC_PEER.search(line)
                if m:
                    peers[m.group(2)] = (int(m.group(3)), int(m.group(4)))
                continue
            if "[ready] all indexes" in line:
                m = RE_READY.search(line)
                if m and "READY" not in side.ready:
                    side.ready["READY"] = bmc_ts(line)
                    side.ready_h = int(m.group(1))
                continue
            if "catchup progress: height=" in line:
                m = RE_PROGRESS.search(line)
                if m:
                    h = int(m.group(1))
                    if h not in progress_seen:
                        progress_seen[h] = bmc_ts(line)
    if not have_block_lines and progress_seen:
        side.notes.append("no [bench] block lines: milestones and segment walls come from "
                          "'[utxo_live] catchup progress' lines (one every ~30 s), stages are empty")
        for h, ts in progress_seen.items():
            side.mark_height(h, ts)
    if peers:
        side.misc["dlc_peers_seen"] = len(peers)
        side.misc["dlc_peer_status_blocks"] = sum(b for _, b in peers.values())
    return side


def parse_bmc_phase(path, side):
    try:
        f = open_log(path)
    except OSError:
        return
    with f:
        for line in f:
            m = re.search(r" (IBD_END|READY) (\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)", line)
            if not m:
                continue
            ts = parse_ts(m.group(2))
            if m.group(1) == "IBD_END":
                if side.ibd_end is None:
                    side.ibd_end = ts
            else:
                side.ready.setdefault("READY", ts)
                h = re.search(r"height=(\d+)", line)
                if h and side.ready_h is None:
                    side.ready_h = int(h.group(1))


# ------------------------------------------------------------- figures ----
def first_time_at_or_past(side, target):
    """Time of the first height >= target (by height order, then the earliest
    time among heights that reach it; heights arrive in order on both sides)."""
    best = None
    for h, ts in side.tip_ts.items():
        if h >= target and (best is None or ts < best):
            best = ts
    return best


def seg_ends(side, size):
    """{k: end time of segment k} = time of the last height in it."""
    last = {}
    for h, ts in side.tip_ts.items():
        k = h // size
        if k not in last or h > last[k][0]:
            last[k] = (h, ts)
    return {k: v[1] for k, v in last.items()}


def seg_walls(side, size):
    ends = seg_ends(side, size)
    out = {}
    prev = side.start
    for k in sorted(ends):
        out[k] = (ends[k] - prev) if prev is not None else None
        prev = ends[k]
    return out


def seg_label(k, size, max_h):
    lo, hi = k * size, min((k + 1) * size - 1, max_h)
    return "%s-%s" % (fmt_h(lo), fmt_h(hi))


def fmt_h(h):
    return "{:,}".format(h)


def milestones(sides, size):
    top = max([s.max_h for s in sides if s] + [0])
    ms = list(range(size, top + 1, size))
    if not ms or ms[-1] != top:
        ms.append(top)
    return ms


# -------------------------------------------------------------- report ----
def ready_rows(side):
    rows = []
    el = lambda t: hms(t - side.start) if (t is not None and side.start is not None) else "--"
    rows.append(("IBD end", el(side.ibd_end)))
    for k in sorted(side.ready):
        rows.append((k, el(side.ready[k])))
    return rows


def render(core, bmc, size):
    sides = [s for s in (core, bmc) if s]
    out = []
    P = out.append
    P("# IBD stage report: Core v31.1 vs bmc")
    P("")
    P("Segments of %s heights. Times are seconds unless written h:mm:ss; elapsed "
      "times are from each run's own start." % fmt_h(size))
    P("")
    P("## Runs")
    P("")
    P("| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |")
    P("|---|---|---|---|---|---|---|---|")
    for s in sides:
        nb = sum(g.blocks for g in s.segs.values())
        st = "--"
        if s.start is not None:
            import time
            st = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(s.start))
        rk = "READY_INDEXES" if s.name == "Core" else "READY"
        rdy = s.ready.get(rk)
        rdy_s = hms(rdy - s.start) if (rdy is not None and s.start is not None) else "--"
        if s.name == "Core" and "READY_TIP" in s.ready and s.start is not None:
            rdy_s += " (tip %s)" % hms(s.ready["READY_TIP"] - s.start)
        ie = hms(s.ibd_end - s.start) if (s.ibd_end is not None and s.start is not None) else "--"
        P("| %s | `%s` | %s | %s | %s | %s | %s | %s |" % (
            s.name, s.log, st, fmt_h(max(s.max_h, 0)), fmt_h(nb), ie, rdy_s,
            fmt_h(s.ready_h) if s.ready_h is not None else "--"))
    P("")
    P("Core: IBD end = \"Leaving InitialBlockDownload\"; ready = READY_INDEXES (the first "
      "getindexinfo after READY_TIP with every index at that height), READY_TIP = its "
      "UpdateTip at the oracle's tip. bmc: IBD end = \"[dlc] catch-up done\" (or phase.log "
      "IBD_END); ready = \"[ready] all indexes at height N\".")
    P("")

    P("## Milestones (elapsed to the first block at or past each height)")
    P("")
    P("| height | " + " | ".join(s.name for s in sides) + (" | bmc/Core |" if core and bmc else " |"))
    P("|---|" + "---|" * len(sides) + ("---|" if core and bmc else ""))
    for m in milestones(sides, size):
        cells = []
        vals = []
        for s in sides:
            t = first_time_at_or_past(s, m)
            v = (t - s.start) if (t is not None and s.start is not None) else None
            vals.append(v)
            cells.append(hms(v))
        ratio = ""
        if core and bmc:
            ratio = " %s |" % (("%.2f" % (vals[1] / vals[0])) if (vals[0] and vals[1] is not None) else "--")
        P("| %s | %s |%s" % (fmt_h(m), " | ".join(cells), ratio))
    P("")

    walls = {s.name: seg_walls(s, size) for s in sides}
    keys = sorted(set(k for s in sides for k in walls[s.name]))
    top = max(s.max_h for s in sides)
    P("## Wall time per segment")
    P("")
    P("| segment | " + " | ".join(s.name + " wall" for s in sides) + (" | bmc/Core |" if core and bmc else " |"))
    P("|---|" + "---|" * len(sides) + ("---|" if core and bmc else ""))
    for k in keys:
        vs = [walls[s.name].get(k) for s in sides]
        ratio = ""
        if core and bmc:
            ratio = " %s |" % (("%.2f" % (vs[1] / vs[0])) if (vs[0] and vs[1] is not None) else "--")
        P("| %s | %s |%s" % (seg_label(k, size, top), " | ".join(fs(v) for v in vs), ratio))
    P("")

    if core and not any(g.blocks for g in core.segs.values()):
        P("## Core: stages per segment")
        P("")
        P("No [bench] stage lines in this log (a run without debug=bench).")
        P("")
    elif core:
        P("## Core: stages per segment (sum over blocks, seconds)")
        P("")
        cols = [("wall", None), ("blocks", None), ("connect block", "block")] + \
               [(lab, key) for key, lab in CORE_STAGES] + \
               [("outside connect", None), ("UTXO flushes", None)]
        P("| segment | " + " | ".join(c[0] for c in cols) + " |")
        P("|---|" + "---|" * len(cols))
        tot = Seg()
        twall = 0.0
        for k in sorted(core.segs):
            g = core.segs[k]
            wall = walls["Core"].get(k)
            row = [fs(wall), fmt_h(g.blocks), fs(g.st.get("block", 0) / 1000)]
            row += [fs(g.st.get(key, 0) / 1000) for key, _ in CORE_STAGES]
            row.append(fs(wall - g.st.get("block", 0) / 1000) if wall is not None else "--")
            row.append("%d / %s" % (g.extra.get("coins_flush_n", 0), fs(g.st.get("coins_flush", 0) / 1000)))
            P("| %s | %s |" % (seg_label(k, size, top), " | ".join(row)))
            for kk, v in g.st.items():
                tot.add(kk, v)
            for kk, v in g.extra.items():
                tot.inc(kk, v)
            tot.blocks += g.blocks
            twall += wall or 0.0
        row = [fs(twall), fmt_h(tot.blocks), fs(tot.st.get("block", 0) / 1000)]
        row += [fs(tot.st.get(key, 0) / 1000) for key, _ in CORE_STAGES]
        row.append(fs(twall - tot.st.get("block", 0) / 1000))
        row.append("%d / %s" % (tot.extra.get("coins_flush_n", 0), fs(tot.st.get("coins_flush", 0) / 1000)))
        P("| **total** | %s |" % " | ".join(row))
        P("")
        P("connect block = Core's own per-block total (load .. postprocess). verify wait = "
          "\"Verify\" minus \"Connect N transactions\" (Verify is timed from the same start). "
          "outside connect = wall minus connect block: waiting for blocks to arrive, header "
          "sync, and anything ActivateBestChain does between blocks (index callbacks run on "
          "their own threads). UTXO flushes = count / seconds of \"write coins cache to disk\" "
          "(already inside write chainstate when IF_NEEDED; periodic ones fall between blocks).")
        P("")
        m = core.misc
        P("Core flush and coindb lines: %d chainstate writes (%s); %s txouts committed; "
          "block index writes %d (%.1f s); block/undo file flushes %d (%.1f s); disconnects %d." % (
              m.get("coindb_writes", 0),
              ", ".join("%s %d" % (k.split(":", 1)[1], v) for k, v in sorted(m.items()) if k.startswith("coindb_mode:")) or "none",
              fmt_h(int(m.get("coindb_committed_txouts", 0))),
              m.get("blockindex_flush_n", 0), m.get("blockindex_flush_ms", 0) / 1000,
              m.get("blockfile_flush_n", 0), m.get("blockfile_flush_ms", 0) / 1000,
              m.get("disconnects", 0)))
        P("")

    if bmc and not any(g.blocks for g in bmc.segs.values()):
        P("## bmc: stages per segment")
        P("")
        P("No [bench] block lines in this log (a run without bmc.benchlog=1).")
        P("")
    elif bmc:
        P("## bmc: stages per segment (sum over blocks, seconds)")
        P("")
        seen = []
        for g in bmc.segs.values():
            for k in g.st:
                if not k.startswith("ix:") and k != "total" and k not in seen:
                    seen.append(k)
        stages = [k for k in BMC_STAGES if k in seen] + [k for k in seen if k not in BMC_STAGES]
        if not stages:
            stages = list(BMC_STAGES)
        ixs = []
        for g in bmc.segs.values():
            for k in g.st:
                if k.startswith("ix:") and k[3:] not in ixs:
                    ixs.append(k[3:])
        ixcols = [k for k in BMC_INDEX if k in ixs] + [k for k in ixs if k not in BMC_INDEX]
        if not ixcols:
            ixcols = list(BMC_INDEX)
        cols = ["wall", "blocks", "total"] + stages + ["other"] + ["ix " + k for k in ixcols] + ["outside"]
        P("| segment | " + " | ".join(cols) + " |")
        P("|---|" + "---|" * len(cols))
        tot = Seg()
        twall = 0.0
        for k in sorted(bmc.segs):
            g = bmc.segs[k]
            wall = walls["bmc"].get(k)
            total = g.st.get("total", 0)
            parts = sum(g.st.get(x, 0) for x in stages)
            ixsum = sum(g.st.get("ix:" + x, 0) for x in ixcols)
            row = [fs(wall), fmt_h(g.blocks), fs(total / 1000)]
            row += [fs(g.st.get(x, 0) / 1000) for x in stages]
            row.append(fs((total - parts) / 1000))
            row += [fs(g.st.get("ix:" + x, 0) / 1000) for x in ixcols]
            row.append(fs(wall - (total + ixsum) / 1000) if wall is not None else "--")
            P("| %s | %s |" % (seg_label(k, size, top), " | ".join(row)))
            for kk, v in g.st.items():
                tot.add(kk, v)
            tot.blocks += g.blocks
            twall += wall or 0.0
        total = tot.st.get("total", 0)
        parts = sum(tot.st.get(x, 0) for x in stages)
        ixsum = sum(tot.st.get("ix:" + x, 0) for x in ixcols)
        row = [fs(twall), fmt_h(tot.blocks), fs(total / 1000)]
        row += [fs(tot.st.get(x, 0) / 1000) for x in stages]
        row.append(fs((total - parts) / 1000))
        row += [fs(tot.st.get("ix:" + x, 0) / 1000) for x in ixcols]
        row.append(fs(twall - (total + ixsum) / 1000))
        P("| **total** | %s |" % " | ".join(row))
        P("")
        P("total = the block line's own total; other = total minus the named stages. "
          "ix = the choke-point index work outside the block total ([bench] index lines). "
          "outside = wall minus (total + ix): download waits and everything off the apply "
          "path. bmc applies on a pipeline, so outside is not idle time by itself.")
        P("")
    if bmc:
        if bmc.other_bench:
            P("Other bmc [bench] lines: " + "; ".join(
                "%s x%d (%.1f s)" % (k, v[0], v[1] / 1000) for k, v in sorted(bmc.other_bench.items())))
            P("")
        P(chunk_summary(bmc))
        P("")

    notes = [n for s in sides for n in ("%s: %s" % (s.name, x) for x in s.notes)]
    if notes:
        P("## Notes")
        P("")
        for n in notes:
            P("- " + n)
        P("")
    return "\n".join(out)


def chunk_summary(side):
    parts = []
    if side.chunks:
        n = len(side.chunks)
        sums = {}
        secs = {}
        for d in side.chunks:
            for k, v in d.items():
                if k.startswith("_"):
                    continue
                u, x = kv_value(v)
                if u == "B":
                    sums[k] = sums.get(k, 0.0) + x
                elif u == "s":
                    secs.setdefault(k, []).append(x)
        s = "Download chunks ([dlc] chunk lines): %d" % n
        for k, v in sorted(sums.items()):
            s += "; %s %.2f GB" % (k, v / 1e9)
        for k, v in sorted(secs.items()):
            v.sort()
            s += "; %s sum %.0f s, p50 %.2f s, p90 %.2f s, max %.2f s" % (
                k, sum(v), v[len(v) // 2], v[min(len(v) - 1, int(len(v) * 0.9))], v[-1])
        peers = set(d.get("peer") for d in side.chunks if d.get("peer"))
        if peers:
            s += "; %d distinct peers" % len(peers)
        parts.append(s + ".")
    else:
        parts.append("Download chunks: no [dlc] chunk lines in this log.")
    if "dlc_last_summary" in side.misc:
        parts.append("Last download summary: %s." % side.misc["dlc_last_summary"])
    if "dlc_peers_seen" in side.misc:
        parts.append("Peer status lines named %d distinct peers." % side.misc["dlc_peers_seen"])
    return " ".join(parts)


# ---------------------------------------------------------------- main ----
def build(args):
    size = SEG_DEFAULT
    a = dict(args)
    if a.get("segment"):
        size = int(a["segment"])
    core = bmc = None
    if a.get("core-dir"):
        d = a["core-dir"]
        a.setdefault("core-log", os.path.join(d, "debug.log"))
        a.setdefault("core-start", "@" + os.path.join(d, "BENCH_START.txt"))
        a.setdefault("core-watch", os.path.join(d, "watch.log"))
    if a.get("bmc-dir"):
        d = a["bmc-dir"]
        a.setdefault("bmc-log", os.path.join(d, "data", "main", "debug.log"))
        a.setdefault("bmc-start", "@" + os.path.join(d, "epoch.start"))
        a.setdefault("bmc-phase", os.path.join(d, "phase.log"))
    if a.get("core-log"):
        core = parse_core(a["core-log"], size)
        core.start = parse_start(a.get("core-start"))
        if a.get("core-watch"):
            parse_core_watch(a["core-watch"], core)
        if core.start is None:
            core.notes.append("no start time: elapsed figures are blank (pass --core-start)")
    if a.get("bmc-log"):
        bmc = parse_bmc(a["bmc-log"], size)
        bmc.start = parse_start(a.get("bmc-start"))
        if a.get("bmc-phase"):
            parse_bmc_phase(a["bmc-phase"], bmc)
        if bmc.start is None:
            bmc.notes.append("no start time: elapsed figures are blank (pass --bmc-start)")
    return core, bmc, size


def parse_args(argv):
    out = {}
    i = 0
    known = {"core-dir", "core-log", "core-start", "core-watch", "bmc-dir", "bmc-log",
             "bmc-start", "bmc-phase", "segment"}
    while i < len(argv):
        k = argv[i]
        if not k.startswith("--"):
            raise SystemExit("unexpected argument %r (see --help)" % k)
        k = k[2:]
        if "=" in k:
            k, v = k.split("=", 1)
        else:
            i += 1
            if i >= len(argv):
                raise SystemExit("--%s needs a value" % k)
            v = argv[i]
        if k not in known:
            raise SystemExit("unknown option --%s (see --help)" % k)
        out[k] = v
        i += 1
    return out


# ------------------------------------------------------------ selftest ----
SAMPLE_CORE = """\
2026-10-05T00:00:00.000000Z Bitcoin Core version v31.1 (release build)
2026-10-05T00:00:01.000000Z UpdateTip: new best=000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f height=0 version=0x00000001 log2_work=32.000022 tx=1 date='2009-01-03T18:15:05Z' progress=0.000000 cache=0.3MiB(0txo)
2026-10-05T00:00:10.000000Z [bench]   - Load block from disk: 1.00ms
2026-10-05T00:00:10.000100Z [bench]     - Sanity checks: 0.50ms [0.00s (0.50ms/blk)]
2026-10-05T00:00:10.000200Z [bench]     - Fork checks: 0.25ms [0.00s (0.25ms/blk)]
2026-10-05T00:00:10.000300Z [bench]       - Connect 2 transactions: 3.00ms (1.500ms/tx, 3.000ms/txin) [0.00s (3.00ms/blk)]
2026-10-05T00:00:10.000400Z [bench]     - Verify 1 txins: 5.00ms (5.000ms/txin) [0.01s (5.00ms/blk)]
2026-10-05T00:00:10.000500Z [bench]     - Write undo data: 0.40ms [0.00s (0.40ms/blk)]
2026-10-05T00:00:10.000600Z [bench]     - Index writing: 0.10ms [0.00s (0.10ms/blk)]
2026-10-05T00:00:10.000700Z [bench]   - Connect total: 6.30ms [0.01s (6.30ms/blk)]
2026-10-05T00:00:10.000800Z [bench]   - Flush: 0.70ms [0.00s (0.70ms/blk)]
2026-10-05T00:00:10.000900Z [bench]   - Writing chainstate: 0.05ms [0.00s (0.05ms/blk)]
2026-10-05T00:00:10.001000Z UpdateTip: new best=00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048 height=1 version=0x00000001 log2_work=33.000022 tx=3 date='2009-01-09T02:54:25Z' progress=0.000000 cache=0.3MiB(1txo)
2026-10-05T00:00:10.001100Z [bench]   - Connect postprocess: 0.20ms [0.00s (0.20ms/blk)]
2026-10-05T00:00:10.001200Z [bench] - Connect block: 8.55ms [0.01s (8.55ms/blk)]
2026-10-05T00:00:20.000000Z [bench]   - Using cached block
2026-10-05T00:00:20.000000Z [bench]   - Load block from disk: 0.00ms
2026-10-05T00:00:20.000100Z [bench]     - Sanity checks: 1.00ms [0.00s (0.75ms/blk)]
2026-10-05T00:00:20.000200Z [bench]     - Fork checks: 0.00ms [0.00s (0.12ms/blk)]
2026-10-05T00:00:20.000300Z [bench]       - Connect 10 transactions: 7.00ms (0.700ms/tx, 0.700ms/txin) [0.01s (5.00ms/blk)]
2026-10-05T00:00:20.000400Z [bench]     - Verify 10 txins: 20.00ms (2.000ms/txin) [0.03s (12.50ms/blk)]
2026-10-05T00:00:20.000500Z [bench]     - Write undo data: 1.00ms [0.00s (0.70ms/blk)]
2026-10-05T00:00:20.000600Z [bench]     - Index writing: 0.00ms [0.00s (0.05ms/blk)]
2026-10-05T00:00:20.000700Z [bench]   - Connect total: 22.00ms [0.03s (14.15ms/blk)]
2026-10-05T00:00:20.000800Z [bench]   - Flush: 2.00ms [0.00s (1.35ms/blk)]
2026-10-05T00:00:20.000850Z [coindb] Writing chainstate to disk: flush mode=IF_NEEDED, prune=0, large=0, critical=1, periodic=0
2026-10-05T00:00:20.000860Z [bench] FlushStateToDisk: write block and undo data to disk started
2026-10-05T00:00:20.010860Z [bench] FlushStateToDisk: write block and undo data to disk completed (10.00ms)
2026-10-05T00:00:20.010870Z [bench] FlushStateToDisk: write block index to disk started
2026-10-05T00:00:20.015870Z [bench] FlushStateToDisk: write block index to disk completed (5.00ms)
2026-10-05T00:00:20.015880Z [bench] BatchWrite: write coins cache to disk (12 out of 12 cached coins) started
2026-10-05T00:00:20.016000Z [coindb] Writing final batch of 0.01 MiB
2026-10-05T00:00:20.016100Z [coindb] Committed 12 changed transaction outputs (out of 12) to coin database...
2026-10-05T00:00:20.515880Z [bench] BatchWrite: write coins cache to disk (12 out of 12 cached coins) completed (500.00ms)
2026-10-05T00:00:20.600000Z [bench]   - Writing chainstate: 600.00ms [0.60s (300.02ms/blk)]
2026-10-05T00:00:20.600100Z UpdateTip: new best=000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd height=2 version=0x00000001 log2_work=33.584985 tx=13 date='2009-01-09T02:55:44Z' progress=0.000000 cache=0.3MiB(12txo)
2026-10-05T00:00:20.600200Z [bench]   - Connect postprocess: 0.30ms [0.00s (0.25ms/blk)]
2026-10-05T00:00:20.600300Z [bench] - Connect block: 625.30ms [0.63s (316.93ms/blk)]
2026-10-05T00:00:30.000000Z [bench]   - Load block from disk: 2.00ms
2026-10-05T00:00:30.000100Z [bench]     - Sanity checks: 0.10ms [0.00s (0.53ms/blk)]
2026-10-05T00:00:30.000200Z [bench]     - Fork checks: 0.10ms [0.00s (0.12ms/blk)]
2026-10-05T00:00:30.000300Z [bench]       - Connect 1 transactions: 0.10ms (0.100ms/tx, 0.000ms/txin) [0.01s (3.37ms/blk)]
2026-10-05T00:00:30.000400Z [bench]     - Verify 0 txins: 0.20ms (0.000ms/txin) [0.03s (8.40ms/blk)]
2026-10-05T00:00:30.000500Z [bench]     - Write undo data: 0.10ms [0.00s (0.50ms/blk)]
2026-10-05T00:00:30.000600Z [bench]     - Index writing: 0.10ms [0.00s (0.07ms/blk)]
2026-10-05T00:00:30.000700Z [bench]   - Connect total: 0.60ms [0.03s (9.63ms/blk)]
2026-10-05T00:00:30.000800Z [bench]   - Flush: 0.10ms [0.00s (0.93ms/blk)]
2026-10-05T00:00:30.000900Z [bench]   - Writing chainstate: 0.10ms [0.60s (200.05ms/blk)]
2026-10-05T00:00:30.001000Z UpdateTip: new best=0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449 height=3 version=0x00000001 log2_work=34.000022 tx=14 date='2009-01-09T03:02:53Z' progress=0.000000 cache=0.3MiB(13txo)
2026-10-05T00:00:30.001100Z [bench]   - Connect postprocess: 0.10ms [0.00s (0.20ms/blk)]
2026-10-05T00:00:30.001200Z [bench] - Connect block: 2.90ms [0.64s (213.58ms/blk)]
2026-10-05T00:00:30.500000Z Leaving InitialBlockDownload (latching to false)
"""
SAMPLE_CORE_WATCH = """\
2026-10-05T00:00:00Z START watching /x/core31 (rpc :8340); bench started 2026-10-05T00:00:00Z; ready step on
2026-10-05T00:01:00Z IBD_END 2026-10-05T00:00:30.500000Z (from the log) elapsed=30s = 0 h 0 m 30 s
2026-10-05T00:02:00Z READY_TIP 2026-10-05T00:00:30.001000Z (from the log) height=3 node_log_tip=3 oracle=3 elapsed=30s = 0 h 0 m 30 s
2026-10-05T00:02:00Z GETINDEXINFO #1 rc=0 {"txindex":{"synced":true,"best_block_height":2}}
2026-10-05T00:02:00Z WAIT index(es) below 3: txindex@2 -- next getindexinfo in 60 s
2026-10-05T00:03:00Z READY_INDEXES 2026-10-05T00:03:00Z (getindexinfo #2) every index at >= 3 elapsed=180s = 0 h 3 m 0 s
"""
SAMPLE_BMC = """\
2026-10-05 01:00:00.000 [boot] logging to /x/run34/data/main/debug.log (debuglogfile)
2026-10-05 01:00:05.000 [dlc] chunk w0 peer=1.2.3.4:8333 h=[0,15] wall=1500ms wait=200ms bytes=2.5MB inflight=16
2026-10-05 01:00:06.000 [dlc] chunk w1 peer=5.6.7.8:8333 h=[16,31] wall=2.5s wait=0.5s bytes=1.5MB inflight=16
2026-10-05 01:00:07.000 [bench] chunk w2 peer 9.9.9.9:8333: blocks 32..47 (16) | wall 1000 ms | wait 10 ms | 1.00 MB (1.00 MB/s) | inflight max 16
2026-10-05 01:00:10.000 [bench] block 1: 1 tx, 0 txin | read 0.5 | idx 0.1 | verify 0.0 | get 0.0 | put 0.2 | ckpt 0.0 | flush 0.0 | csi 0.1 | total 1.0 ms
2026-10-05 01:00:10.001 [bench] index 1: txindex 0.2 | txospender 0.1 | bfilter 0.3 | addr 0.0 | zmq 0.4 ms
some line with a NUL \x00 in it
2026-10-05 01:00:20.000 [bench] block 2: 10 tx, 10 txin | read 1.0 | idx 1.0 | verify 4.0 | get 2.0 | put 1.0 | ckpt 0.0 | flush 500.0 | csi 0.5 | total 510.0 ms
2026-10-05 01:00:20.001 [bench] index 2: txindex 1.0 | txospender 1.0 | bfilter 2.0 | addr 0.5 | zmq 0.5 ms
2026-10-05 01:00:20.002 [bench] memflush: 1000 records, 2 MB in 480.0 ms
2026-10-05 01:00:25.000 [utxo_live] catchup progress: height=2/3 (66.7%) 0.1 blk/s
2026-10-05 01:00:30.000 [bench] block 3: 1 tx, 0 txin | read 0.1 | idx 0.1 | verify 0.0 | get 0.0 | put 0.1 | ckpt 0.0 | flush 0.0 | csi 0.0 | total 0.4 ms
2026-10-05 01:00:30.001 [bench] index 3: txindex 0.1 | txospender 0.0 | bfilter 0.1 | addr 0.0 | zmq 0.1 ms
2026-10-05 01:00:31.000 [dlc] catch-up done: 3 new blocks written
2026-10-05 01:00:45.678 [ready] all indexes at height 3 (utxo 3, txindex 3, bfilter 3, coinstats 3) -- 15s
"""
SAMPLE_BMC_PHASE = """\
2026-10-05T01:00:00Z START host=agent
2026-10-05T01:05:00Z IBD_END 2026-10-05 01:00:31 UTC (from the log) elapsed=31s -- applied=3 stored=3/3 oracle=3
2026-10-05T01:05:30Z READY 2026-10-05 01:00:45 UTC (from the log) height=3 elapsed=45s after_ibd_end=14s -- [ready] all indexes at height 3
"""
SAMPLE_PROGRESS_ONLY = """\
2026-10-03 23:47:11.508 [utxo_live] catchup progress: height=0/969778 (0.0%) 0.0 blk/s (avg 0.0) eta --:--:--:-- | read 12% idx 0%
2026-10-03 23:47:42.620 [utxo_live] catchup progress: height=12561/969778 (1.3%) 0.0 blk/s (avg 0.0) eta --:--:--:-- | read 13% idx 7%
2026-10-03 23:47:57.213 [utxo_live] catchup progress: height=20000/969778 (2.1%) 20800.0 blk/s (avg 20800.0) eta 00:00:00:45 | read 1% idx 1%
2026-10-04 05:44:51.124 [dlc] -- recv 0.1MB/s (avg 50.3MB/s) | pool idle 5% | write 0.1MB/s (avg 50.2MB/s) | flow
2026-10-04 05:44:51.200 [dlc]   w3 1.2.3.4:8333  chunks=40 blocks=640  (+0 blk/s, 0.0MB/s idle=1%)
"""


def selftest():
    fails = []

    def ck(name, got, want):
        ok = (abs(got - want) < 1e-6) if isinstance(want, float) and got is not None else (got == want)
        print("%s: %s%s" % ("ok  " if ok else "FAIL", name, "" if ok else "  (want %r got %r)" % (want, got)))
        if not ok:
            fails.append(name)

    tmp = tempfile.mkdtemp(prefix="ibd_stage_report_selftest.")
    try:
        def w(name, text):
            p = os.path.join(tmp, name)
            with open(p, "w") as f:
                f.write(text)
            return p
        cl = w("core.log", SAMPLE_CORE)
        cw = w("watch.log", SAMPLE_CORE_WATCH)
        bl = w("bmc.log", SAMPLE_BMC)
        bp = w("phase.log", SAMPLE_BMC_PHASE)
        pl = w("progress.log", SAMPLE_PROGRESS_ONLY)
        bs = w("BENCH_START.txt", "2026-10-05T00:00:00Z\n")

        print("== time parsing ==")
        ck("Core stamp with microseconds", parse_ts("2026-10-05T00:00:10.001200Z"), 1791158410.0012)
        ck("Core stamp to the second", parse_ts("2026-10-05T00:00:10Z"), 1791158410.0)
        ck("bmc stamp", parse_ts("2026-10-05 00:00:10.250"), 1791158410.25)
        ck("start from @file", parse_start("@" + bs), 1791158400.0)
        ck("start from epoch", parse_start("1791158400"), 1791158400.0)
        ck("not a stamp", parse_ts("INFO node start"), None)

        print("== Core (segment size 2) ==")
        c = parse_core(cl, 2)
        c.start = parse_start("@" + bs)
        parse_core_watch(cw, c)
        s0, s1 = c.segs.get(0), c.segs.get(1)
        ck("blocks 1 in segment 0 (heights 0-1)", s0.blocks, 1)
        ck("blocks 2,3 in segment 1 (heights 2-3)", s1.blocks, 2)
        ck("a block's lines go to the UpdateTip between chainstate and Connect block (load of h=2 is 0.00)",
           s1.st.get("load"), 2.0)
        ck("connect txs, seg 1", s1.st.get("connect"), 7.1)
        ck("verify wait = verify - connect, seg 0", s0.st.get("verify_wait"), 2.0)
        ck("verify wait, seg 1 (13.0 + 0.1)", s1.st.get("verify_wait"), 13.1)
        ck("writing chainstate, seg 1", s1.st.get("chainstate"), 600.1)
        ck("connect block, seg 1", s1.st.get("block"), 628.2)
        ck("tx and txin counts, seg 1", (s1.tx, s1.txin), (11, 10))
        ck("cached-block lines counted", s1.st.get("cached"), 1.0)
        ck("the UTXO flush timer is read (BatchWrite ... completed)", s1.st.get("coins_flush"), 500.0)
        ck("...and counted", s1.extra.get("coins_flush_n"), 1)
        ck("block index write timer", c.misc.get("blockindex_flush_ms"), 5.0)
        ck("coindb chainstate writes by mode", c.misc.get("coindb_mode:IF_NEEDED"), 1)
        ck("coindb committed txouts", c.misc.get("coindb_committed_txouts"), 12)
        ck("IBD end from 'Leaving InitialBlockDownload'", c.ibd_end, parse_ts("2026-10-05T00:00:30.5Z"))
        ck("READY_TIP from watch.log", c.ready.get("READY_TIP"), parse_ts("2026-10-05T00:00:30.001Z"))
        ck("READY_INDEXES from watch.log", c.ready.get("READY_INDEXES"), parse_ts("2026-10-05T00:03:00Z"))
        ck("ready height", c.ready_h, 3)
        walls = seg_walls(c, 2)
        ck("segment 0 wall = start .. UpdateTip h=1", walls[0], 10.001)
        ck("segment 1 wall = h=1 .. h=3", walls[1], 20.0)
        ck("milestone 2 = first UpdateTip >= 2", first_time_at_or_past(c, 2) - c.start, 20.6001)

        print("== bmc (segment size 2) ==")
        b = parse_bmc(bl, 2)
        b.start = parse_ts("2026-10-05 01:00:00")
        parse_bmc_phase(bp, b)
        g0, g1 = b.segs.get(0), b.segs.get(1)
        ck("bmc block lines per segment", (g0.blocks, g1.blocks), (1, 2))
        ck("bmc stage 'flush' seg 1", g1.st.get("flush"), 500.0)
        ck("bmc total seg 1", g1.st.get("total"), 510.4)
        ck("a NUL byte does not hide the next line (block 2 read)", g1.st.get("read"), 1.1)
        ck("bmc index line txindex seg 1", g1.st.get("ix:txindex"), 1.1)
        ck("bmc index line zmq seg 0", g0.st.get("ix:zmq"), 0.4)
        ck("bmc tx/txin seg 1", (g1.tx, g1.txin), (11, 10))
        ck("other [bench] kinds counted with their ms", b.other_bench.get("memflush"), [1, 480.0])
        ck("chunk lines parsed (both formats)", len(b.chunks), 3)
        ck("chunk wall in seconds (ms and s units)", sorted(kv_value(d["wall"])[1] for d in b.chunks), [1.0, 1.5, 2.5])
        ck("chunk bytes", sum(kv_value(d["bytes"])[1] for d in b.chunks), 5.0e6)
        ck("the [bench] chunk line's peer", [d["peer"] for d in b.chunks][2], "9.9.9.9:8333")
        ck("IBD end from catch-up done", b.ibd_end, parse_ts("2026-10-05 01:00:31"))
        ck("READY from the [ready] line (log's own ms kept)", b.ready.get("READY"), parse_ts("2026-10-05 01:00:45.678"))
        ck("ready height", b.ready_h, 3)
        ck("block lines win over catchup progress for heights", b.tip_ts.get(2), parse_ts("2026-10-05 01:00:20"))

        print("== bmc, progress lines only (today's format) ==")
        p = parse_bmc(pl, 10000)
        ck("milestones fall back to catchup progress", p.tip_ts.get(20000), parse_ts("2026-10-03 23:47:57.213"))
        ck("no stage lines -> no blocks counted", sum(g.blocks for g in p.segs.values()), 0)
        ck("the fallback is noted", len(p.notes), 1)
        ck("the download summary line is read", p.misc.get("dlc_last_summary"), "recv 0.1MB/s (avg 50.3MB/s), pool idle 5%")
        ck("peer status lines are read", p.misc.get("dlc_peers_seen"), 1)

        print("== render ==")
        md = render(c, b, 2)
        ck("report has the Core stage table", "## Core: stages per segment" in md, True)
        ck("report has the bmc stage table", "## bmc: stages per segment" in md, True)
        ck("report has milestones", "## Milestones" in md, True)
        ck("Core ready column shows READY_INDEXES and the tip", "0:03:00 (tip 0:00:30)" in md, True)
        ck("bmc ready elapsed, truncated like ibd_milestones.sh (45.678 s)", "| 0:00:45 |" in md, True)
        ck("hms truncates", hms(3599.99), "0:59:59")
        ck("bmc/Core ratio column present", "bmc/Core" in md, True)
        md2 = render(None, p, 10000)
        ck("one side alone renders", "## bmc: stages per segment" in md2 and "## Core" not in md2, True)
    finally:
        for n in os.listdir(tmp):
            os.unlink(os.path.join(tmp, n))
        os.rmdir(tmp)
    print()
    if fails:
        print("%d FAILED: %s" % (len(fails), ", ".join(fails)))
        print("SELFTEST FAILED")
        return 1
    print("SELFTEST PASSED")
    return 0


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--selftest":
        return selftest()
    args = parse_args(argv)
    core, bmc, size = build(args)
    if not core and not bmc:
        raise SystemExit("nothing to report: give --core-dir/--core-log and/or --bmc-dir/--bmc-log")
    print(render(core, bmc, size))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
