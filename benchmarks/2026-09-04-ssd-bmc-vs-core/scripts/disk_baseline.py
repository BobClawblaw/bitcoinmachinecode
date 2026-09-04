#!/usr/bin/env python3
# Raw disk baseline for /mnt/2tbssd: sequential write/read + 4k random write.
import os, time, sys
MNT = '/mnt/2tbssd'
res = {}

def fsync_close(f):
    f.flush(); os.fsync(f.fileno()); f.close()

# sequential write 8 GiB (uncached)
p = MNT + '/.seqtest'
buf = os.urandom(1 << 20)
t0 = time.time(); f = open(p, 'wb')
for i in range(8192):
    f.write(buf)
fsync_close(f)
dt = time.time() - t0
print(f"seq write 8GiB: {dt:.1f}s = {8.0/dt:.2f} GiB/s")

# drop caches then sequential read 8 GiB (cold)
os.system('sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true')
t0 = time.time(); f = open(p, 'rb'); n = 0
while True:
    b = f.read(1 << 20)
    if not b: break
    n += len(b)
f.close()
dt = time.time() - t0
print(f"seq read cold {n/2**30:.1f}GiB: {dt:.1f}s = {(n/2**30)/dt:.2f} GiB/s")
os.unlink(p)

# 4k random writes, O_SYNC, 256 MiB total
p = MNT + '/.randtest'
f = open(p, 'wb'); f.truncate(256 << 20); os.fsync(f.fileno())
import random
random.seed(1)
blocks = 256 << 10  # 65536 blocks of 4KiB
t0 = time.time()
for i in range(20000):
    f.seek(random.randrange(blocks) << 12)
    f.write(os.urandom(4096)); f.flush(); os.fsync(f.fileno())
dt = time.time() - t0
print(f"4k random O_SYNC writes: 20000 in {dt:.1f}s = {20000/dt:.0f} IOPS")
f.close(); os.unlink(p)
print("baseline done", time.strftime('%FT%TZ', time.gmtime()))
