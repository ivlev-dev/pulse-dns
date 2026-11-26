import json, time
import bench, harness
harness.LOADGEN = "/tmp/opencode/compare/loadgen-rd/target/release/pulse-loadgen"
bench.REPS = 5
raw = []
t0 = time.time()
bench.phase(bench.AUTH_SERVERS, bench.AUTH_SCEN, raw)
med = []
for sid in bench.AUTH_SERVERS:
    for sname in bench.AUTH_SCEN:
        med.append(bench.median_record(sid, sname, [r for r in raw if r["server"] == sid and r["scenario"] == sname]))
meta = {"reps": 5, "loadgen": harness.LOADGEN, "rd": 1, "server_cpus": "0-3",
        "client_cpus": "4-7", "threads": 4, "loadavg_start": harness.loadavg(),
        "loadavg_end": harness.loadavg(), "elapsed_s": time.time() - t0}
json.dump({"meta": meta, "median": med, "raw": raw}, open("/tmp/opencode/compare/results/bench-auth5.json", "w"), indent=2)
print("done", meta["elapsed_s"])
