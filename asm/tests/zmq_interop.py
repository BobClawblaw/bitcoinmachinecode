#!/usr/bin/env python3
"""Interop check: a REAL libzmq subscriber against daemon/zmq_pub.c.

Run against tests/zmq_pub_drill, which publishes a fixed pattern. This is the
evidence that the hand-written ZMTP publisher speaks the actual protocol and
not merely a self-consistent reading of it -- see zmq_pub_drill.c.

Asserts, in order of what would break a real deployment first:
  1. libzmq completes greeting + READY with us at all
  2. messages arrive as Core's three parts: [topic][body][sequence u32 LE]
  3. topic filtering is honoured PUBLISHER-side (subscribing to one topic
     does not deliver the others)
  4. a 5000-byte body survives -- the ZMTP LONG frame path (8-byte
     big-endian length), which is what every real block uses
  5. the per-topic sequence counter increments by exactly 1

Exits non-zero with a reason on any failure. Needs pyzmq.
"""
import socket
import struct
import sys
import time

import zmq

ADDR = sys.argv[1] if len(sys.argv) > 1 else "tcp://127.0.0.1:28332"
TIMEOUT_MS = 15000

HASH = bytes(range(32))
BIG = bytes(((i * 7 + 3) & 0xFF) for i in range(5000))
EXPECT = {b"hashblock": HASH, b"hashtx": HASH, b"rawblock": BIG, b"rawtx": BIG}

failures = []


def collect(topics, n):
    """Subscribe to `topics`, return the first n messages as (topic, body, seq)."""
    ctx = zmq.Context()
    s = ctx.socket(zmq.SUB)
    s.setsockopt(zmq.RCVTIMEO, TIMEOUT_MS)
    s.connect(ADDR)
    for t in topics:
        s.setsockopt(zmq.SUBSCRIBE, t)
    out = []
    try:
        while len(out) < n:
            parts = s.recv_multipart()
            if len(parts) != 3:
                failures.append(f"expected 3 parts, got {len(parts)}: "
                                f"{[p[:16] for p in parts]}")
                break
            topic, body, seqb = parts
            if len(seqb) != 4:
                failures.append(f"sequence part is {len(seqb)} bytes, expected 4")
                break
            out.append((topic, body, struct.unpack("<I", seqb)[0]))
    except zmq.Again:
        failures.append(f"timed out after {len(out)}/{n} messages on {topics} "
                        f"-- handshake or framing rejected by libzmq")
    finally:
        s.close()
        ctx.term()
    return out


# 1+2+4: every topic arrives, with the right body. rawblock/rawtx are the
# LONG-frame cases; a wrong length encoding shows up as a truncated body or a
# stalled stream rather than a clean error, so compare the bytes exactly.
msgs = collect([b""], 8)
seen = {}
for topic, body, seq in msgs:
    if topic not in EXPECT:
        failures.append(f"unknown topic {topic!r}")
        continue
    if body != EXPECT[topic]:
        failures.append(f"{topic.decode()}: body mismatch "
                        f"(got {len(body)} bytes, expected {len(EXPECT[topic])}; "
                        f"first difference at "
                        f"{next((i for i, (a, b) in enumerate(zip(body, EXPECT[topic])) if a != b), 'length only')})")
    seen.setdefault(topic, []).append(seq)

for t in EXPECT:
    if t not in seen:
        failures.append(f"topic {t.decode()} never delivered")

# 5: per-topic sequence increments by exactly 1
for t, seqs in seen.items():
    for a, b in zip(seqs, seqs[1:]):
        if b != a + 1:
            failures.append(f"{t.decode()}: sequence jumped {a} -> {b}")

# 3: publisher-side filtering, checked ON THE WIRE.
#
# This one CANNOT be checked through a libzmq SUB socket, and an earlier
# version of this file wrongly thought it could. libzmq filters on RECEIVE as
# well as on send, so a publisher that ignores subscriptions entirely and
# floods every topic looks identical from the subscriber's API: the unwanted
# messages are simply discarded on arrival. That check passed against a
# deliberately broken publisher, which is how the flaw was found.
#
# So this check reads raw bytes off a TCP socket, speaking just enough ZMTP to
# subscribe. The framing it relies on is already independently confirmed
# correct by the libzmq subscriber above; what it adds is the factual question
# libzmq cannot answer -- did these bytes cross the wire at all?
def raw_wire_topics(subscribe_to, seconds=6.0):
    """Hand-rolled ZMTP subscriber: returns the set of topics actually SENT."""
    host_port = ADDR.split("//")[1]
    host, port = host_port.rsplit(":", 1)
    sock = socket.create_connection((host, int(port)), timeout=seconds)
    sock.settimeout(seconds)

    greeting = b"\xff" + b"\x00" * 8 + b"\x7f" + b"\x03\x01" + \
               b"NULL" + b"\x00" * 16 + b"\x00" + b"\x00" * 31
    assert len(greeting) == 64, len(greeting)
    sock.sendall(greeting)

    buf = b""

    def need(n):
        nonlocal buf
        while len(buf) < n:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("publisher closed during handshake")
            buf += chunk
        out, buf = buf[:n], buf[n:]
        return out

    need(64)                                     # their greeting
    ready = b"\x05READY" + b"\x0bSocket-Type" + struct.pack(">I", 3) + b"SUB"
    sock.sendall(bytes([0x04, len(ready)]) + ready)

    sub = b"\x09SUBSCRIBE" + subscribe_to
    sock.sendall(bytes([0x04, len(sub)]) + sub)

    topics, deadline = set(), time.time() + seconds
    # The topic is the FIRST frame of each multipart message -- not merely a
    # short frame with MORE set, which is also true of the 32-byte hash body
    # and would misreport payloads as topics. Track where we are in the
    # message: once a frame arrives with MORE clear, the next one starts a
    # new message.
    at_message_start = True
    try:
        while time.time() < deadline:
            flags = need(1)[0]
            if flags & 0x02:
                size = struct.unpack(">Q", need(8))[0]
            else:
                size = need(1)[0]
            body = need(size) if size else b""
            if flags & 0x04:            # a command, not part of a message
                continue
            if at_message_start:
                topics.add(bytes(body))
            at_message_start = not (flags & 0x01)   # MORE clear ends the message
    except (socket.timeout, TimeoutError, ConnectionError):
        pass
    finally:
        sock.close()
    return topics


try:
    on_wire = raw_wire_topics(b"hashtx")
except Exception as exc:                                   # noqa: BLE001
    failures.append(f"raw ZMTP subscriber could not complete a handshake: {exc!r}")
else:
    unwanted = {t for t in on_wire if not t.startswith(b"hashtx")}
    if unwanted:
        failures.append(
            f"subscribed to hashtx alone, but the publisher put "
            f"{sorted(t.decode(errors='replace') for t in unwanted)} on the wire "
            f"-- publisher-side filtering not applied (libzmq would hide this "
            f"by discarding them on receive)")
    elif not on_wire:
        failures.append("raw subscriber saw no topics at all for hashtx")

if failures:
    print("ZMQ INTEROP FAILED")
    for f in failures:
        print("  -", f)
    sys.exit(1)

topics = ", ".join(sorted(t.decode() for t in seen))
print(f"ZMQ INTEROP OK -- libzmq {zmq.zmq_version()} subscriber received "
      f"{len(msgs)} messages [{topics}], 5000-byte LONG frames intact, "
      f"per-topic sequence contiguous, publisher-side filtering honoured")
