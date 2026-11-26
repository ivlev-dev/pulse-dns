#!/usr/bin/env python3
"""Resolver phase only, using the RD=1 loadgen variant (shipped loadgen emits RD=0)."""
import json
import time

import bench
import harness

harness.LOADGEN = "/tmp/opencode/compare/loadgen-rd/target/release/pulse-loadgen"

raw, med = [], []
t0 = time.time()
up, dt, rss = harness.start("pulsed", f"{harness.ROOT}/logs/bench-upstream-rd.log")
print(f"upstream ready {dt:.2f}s rss {rss}KB", flush=True)
try:
    bench.phase(bench.RES_SERVERS, bench.RES_SCEN, raw)
finally:
    harness.stop(up)
for sid in bench.RES_SERVERS:
    for sname in bench.RES_SCEN:
        med.append(bench.median_record(sid, sname, [r for r in raw if r["server"] == sid and r["scenario"] == sname]))
meta = {
    "reps": bench.REPS, "loadgen": harness.LOADGEN, "rd": 1,
    "server_cpus": "0-3", "client_cpus": "4-7", "threads": 4,
    "loadavg_start": harness.loadavg(), "loadavg_end": harness.loadavg(),
    "elapsed_s": time.time() - t0,
}
with open(f"{harness.ROOT}/results/bench-res.json", "w") as f:
    json.dump({"meta": meta, "median": med, "raw": raw}, f, indent=2)
print(f"done in {meta['elapsed_s']:.0f}s")
