#!/usr/bin/env python3
"""Interop check for the publisher's per-subscriber queue (MEM-22) with REAL
libzmq subscribers. Run against `tests/zmq_pub_drill <addr> <secs> queue`.

Production 2026-09-19: a pyzmq subscriber got ZERO rawblock over two blocks
and was disconnected at every block, because a 1-2 MB message could not fit
the ~256 KB socket buffer the publisher used as its only queue.

Asserts what Core's libzmq PUB gives a subscriber:
  1. a subscriber that keeps up receives every 2 MB rawblock, byte-exact,
     with every per-topic sequence contiguous, and is never disconnected
  2. a subscriber that stops reading loses messages -- visible as a gap in
     the rawtx sequence -- but is NOT disconnected, and receives again once
     it resumes
Disconnects are counted from libzmq's own socket monitor, not inferred.

  zmq_pub_drill tcp://127.0.0.1:19415 12 queue &
  zmq_queue_interop.py tcp://127.0.0.1:19415 8

The drill must outlive the subscribers (seconds + 4), or its exit is counted
as a disconnect. Against the pre-queue publisher this reports 0 rawblock and
a disconnect at every block, which is what production showed.
"""
import struct
import sys
import threading
import time

import zmq
from zmq.utils.monitor import recv_monitor_message

ADDR = sys.argv[1] if len(sys.argv) > 1 else "tcp://127.0.0.1:28332"
SECS = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0

BLK = bytes(((j * 7 + 3) & 0xFF) for j in range(2 * 1024 * 1024))
failures = []


def watch_disconnects(ctx, sock, out, stop):
    mon = sock.get_monitor_socket(zmq.EVENT_DISCONNECTED | zmq.EVENT_CONNECTED)
    mon.setsockopt(zmq.RCVTIMEO, 200)
    while not stop.is_set():
        try:
            ev = recv_monitor_message(mon)
        except zmq.Again:
            continue
        if ev["event"] == zmq.EVENT_DISCONNECTED:
            out["disc"] += 1
        elif ev["event"] == zmq.EVENT_CONNECTED:
            out["conn"] += 1
    sock.disable_monitor()
    mon.close()


def subscriber(ctx, name, stall_s, result):
    s = ctx.socket(zmq.SUB)
    if stall_s:
        s.setsockopt(zmq.RCVHWM, 10)
        s.setsockopt(zmq.RCVBUF, 65536)
    s.setsockopt(zmq.RCVTIMEO, 500)
    ev = {"disc": 0, "conn": 0}
    stop = threading.Event()
    mt = threading.Thread(target=watch_disconnects, args=(ctx, s, ev, stop))
    mt.start()
    s.connect(ADDR)
    for t in (b"hashblock", b"rawblock", b"rawtx"):
        s.setsockopt(zmq.SUBSCRIBE, t)
    seqs = {}
    raw_ok = raw_n = 0
    t0 = time.time()
    if stall_s:
        time.sleep(stall_s)            # read nothing: the publisher's queue fills
    while time.time() - t0 < SECS + 1.5:
        try:
            parts = s.recv_multipart()
        except zmq.Again:
            continue
        if len(parts) != 3:
            failures.append(f"{name}: {len(parts)}-part message")
            continue
        topic, body, sq = parts
        seqs.setdefault(topic, []).append(struct.unpack("<I", sq)[0])
        if topic == b"rawblock":
            raw_n += 1
            idx = struct.unpack("<I", body[:4])[0]
            if len(body) == len(BLK) and body[4:] == BLK[4:] and idx == seqs[topic][-1]:
                raw_ok += 1
    stop.set()
    mt.join()
    s.close()
    result.update(seqs=seqs, raw_n=raw_n, raw_ok=raw_ok, disc=ev["disc"], conn=ev["conn"])


def gaps(seq):
    return sum(1 for a, b in zip(seq, seq[1:]) if b != a + 1)


ctx = zmq.Context()
fast, slow = {}, {}
tf = threading.Thread(target=subscriber, args=(ctx, "fast", 0, fast))
ts = threading.Thread(target=subscriber, args=(ctx, "slow", SECS / 2, slow))
tf.start(); ts.start(); tf.join(); ts.join()
ctx.term()

# 1. the subscriber that keeps up
if fast["raw_n"] < 3:
    failures.append(f"fast: only {fast['raw_n']} rawblock received")
if fast["raw_ok"] != fast["raw_n"]:
    failures.append(f"fast: {fast['raw_n'] - fast['raw_ok']} rawblock not byte-exact")
for t, sq in fast["seqs"].items():
    if gaps(sq):
        failures.append(f"fast: {t.decode()} sequence has {gaps(sq)} gap(s)")
if fast["disc"]:
    failures.append(f"fast: disconnected {fast['disc']} time(s)")

# 2. the subscriber that stalled
rawtx = slow["seqs"].get(b"rawtx", [])
if not gaps(rawtx):
    failures.append("slow: no gap in rawtx -- the stall never overran the high-water mark")
if slow["disc"]:
    failures.append(f"slow: disconnected {slow['disc']} time(s) -- libzmq keeps a slow subscriber")
if slow["raw_ok"] != slow["raw_n"]:
    failures.append("slow: a rawblock was not byte-exact")
if not rawtx or rawtx[-1] < max(fast["seqs"].get(b"rawtx", [0])) - 1000:
    failures.append("slow: did not resume receiving current messages after the stall")

print(f"fast: rawblock {fast['raw_n']} (exact {fast['raw_ok']}), rawtx {len(fast['seqs'].get(b'rawtx', []))}, "
      f"gaps {sum(gaps(s) for s in fast['seqs'].values())}, disconnects {fast['disc']}")
print(f"slow: rawblock {slow['raw_n']}, rawtx {len(rawtx)} with {gaps(rawtx)} gap(s), "
      f"disconnects {slow['disc']}")
if failures:
    print("ZMQ QUEUE INTEROP FAILED")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print(f"ZMQ QUEUE INTEROP OK -- libzmq {zmq.zmq_version()}: 2 MB rawblocks intact and "
      f"contiguous for a subscriber that keeps up; a stalled one sees sequence gaps "
      f"and stays connected")
