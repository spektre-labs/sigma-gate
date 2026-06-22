"""Reproduce the throughput claim. Run: python tests/bench.py"""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from guard import guard

SAMPLE = ("Quarterly summary: revenue up 12%. Contact ops@example.com. "
          "Reminder: rotate ghp_16C7e42F292c6912E7710c838347Ae178B4a.")
N = 20000
guard(SAMPLE)  # warm
t0 = time.perf_counter()
for _ in range(N):
    guard(SAMPLE)
dt = time.perf_counter() - t0
print(f"{N} calls in {dt:.3f}s  ->  {dt/N*1e6:.1f} µs/call  ({N/dt:,.0f} calls/sec)")
