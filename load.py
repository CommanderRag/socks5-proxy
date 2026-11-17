"""Load test for the SOCKS5 proxy: opens N simultaneous tunnels and reports latency.

Usage (three terminals, from this folder):
    python3 proxy.py                       # 1: the proxy
    python3 target.py                      # 2: the target web server
    ulimit -n 4096 && python3 load.py 500  # 3: this script
"""
import asyncio
import socket
import statistics
import struct
import sys
import time
from collections import Counter

PROXY = ("127.0.0.1", 9000)
TARGET = ("127.0.0.1", 8000)
USER, PW = b"user", b"pass"
HOLD = 5  # keep every tunnel open this long so they are truly concurrent


async def _one():
    t = time.perf_counter()
    try:
        r, w = await asyncio.open_connection(*PROXY)
        w.write(b"\x05\x01\x02")
        assert await r.readexactly(2) == b"\x05\x02", "method rejected"
        w.write(b"\x01" + bytes([len(USER)]) + USER + bytes([len(PW)]) + PW)
        assert await r.readexactly(2) == b"\x01\x00", "auth failed"
        w.write(b"\x05\x01\x00\x01" + socket.inet_aton(TARGET[0]) + struct.pack("!H", TARGET[1]))
        rep = (await r.readexactly(10))[1]
        assert rep == 0, f"connect reply {rep}"
        w.write(b"GET / HTTP/1.0\r\n\r\n")
        assert await r.read(1), "no data from target"
        lat = time.perf_counter() - t
        await asyncio.sleep(HOLD)
        w.close()
        return lat, None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


async def one():
    try:
        return await asyncio.wait_for(_one(), HOLD + 20)
    except asyncio.TimeoutError:
        return None, f"TimeoutError: tunnel stuck >{HOLD + 20}s"


async def main(n):
    print(f"opening {n} tunnels...", flush=True)
    start = time.perf_counter()
    res = await asyncio.gather(*[one() for _ in range(n)])
    total = time.perf_counter() - start
    lats = sorted(l for l, _ in res if l is not None)
    errs = Counter(e for _, e in res if e)
    print(f"tunnels={n} ok={len(lats)} failed={n - len(lats)} total={total:.1f}s")
    if lats:
        print("p50 %.0f ms   p95 %.0f ms   max %.0f ms" % (
            statistics.median(lats) * 1e3,
            lats[max(0, int(len(lats) * .95) - 1)] * 1e3,
            lats[-1] * 1e3))
    for e, c in errs.most_common(5):
        print(f"  {c}x {e}")


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 100))
