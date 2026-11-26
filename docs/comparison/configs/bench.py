#!/usr/bin/env python3
"""Benchmark pulsed/pulseresolved against BIND, Unbound and PowerDNS.

Server taskset 0-3, client (pulse-loadgen) taskset 4-7, 3 reps per scenario,
median reported. All servers serve the same two zones:
  example.com.        100000 A records
  z0.bench.test.      100000 mixed A/AAAA/MX/TXT records
"""
import json
import os
import statistics
import sys
import time

import harness

ROOT = harness.ROOT
REPS = int(os.environ.get("REPS", "3"))

AUTH_SERVERS = ["pulsed", "pulsed-cache", "bind", "unbound", "pdns", "pdns-cache"]
RES_SERVERS = ["pulseresolved", "unbound-res", "bind-res", "pdns-rec"]

MIX = "a=40,aaaa=20,mx=15,txt=10,nx=15"
NX_MIX = "a=0,aaaa=0,mx=0,txt=0,nx=100"

AUTH_SCEN = {
    "auth-open-10k": dict(qps=10000, window=16, duration=10, warmup=3),
    "auth-closed-64": dict(qps=0, window=64, duration=10, warmup=3),
}
RES_SCEN = {
    "res-warm-16": dict(qps=0, window=16, duration=10, warmup=3),
    "res-warm-64": dict(qps=0, window=64, duration=10, warmup=3),
    "res-cold-64": dict(qps=0, window=64, duration=10, warmup=0),
    "res-nx-warm-16": dict(qps=0, window=16, duration=10, warmup=3, mix=NX_MIX),
}

NUM = ["client_qps", "startup_s", "rss_kb", "rss_start_kb", "cpu_user_pct",
       "cpu_sys_pct", "cpu_total_pct", "loadavg_1m", "sent", "received",
       "timeouts", "errors", "invalid", "suppressed", "p50_us", "p99_us",
       "p999_us", "max_us"]


def run_one(sid, scen_name, cfg):
    spec = harness.SERVERS[sid]
    log = f"{ROOT}/logs/bench-{sid}-{scen_name}.log"
    open(log, "w").close()
    p, startup, rss0 = harness.start(sid, log)
    try:
        la0 = harness.loadavg()
        u0, s0 = harness.proc_cpu(p.pid)
        t0 = time.monotonic()
        out = f"{ROOT}/results/raw-{sid}-{scen_name}-{int(time.time()*1000)}.json"
        j = harness.loadgen(spec["port"], out, **cfg)
        wall = time.monotonic() - t0
        u1, s1 = harness.proc_cpu(p.pid)
        rss1 = harness.rss_kb(p.pid)
        la1 = harness.loadavg()
        hz = harness.ticks()
        lat = j["latency"]
        rec = {
            "server": sid, "scenario": scen_name, "rep": None,
            "client_qps": j["client_qps"], "startup_s": startup,
            "rss_start_kb": rss0, "rss_kb": rss1,
            "cpu_user_pct": (u1 - u0) / hz / wall * 100,
            "cpu_sys_pct": (s1 - s0) / hz / wall * 100,
            "cpu_total_pct": (u1 - u0 + s1 - s0) / hz / wall * 100,
            "loadavg_1m": float(la1[0]), "loadavg_before": float(la0[0]),
            "sent": j["sent"], "received": j["received"],
            "timeouts": j["timeouts"], "errors": j["errors"],
            "invalid": j["invalid"], "suppressed": j["suppressed"],
            "p50_us": lat["p50"] / 1000.0, "p99_us": lat["p99"] / 1000.0,
            "p999_us": lat["p999"] / 1000.0, "max_us": lat["max"] / 1000.0,
            "wall_s": wall, "rcvbuf_errors_delta":
                j["kernel"]["nstat_rcvbuf_after"] - j["kernel"]["nstat_rcvbuf_before"],
            "json": out,
        }
        os.unlink(out)
        return rec
    finally:
        harness.stop(p)


def phase(servers, scenarios, raw):
    for sid in servers:
        for sname, cfg in scenarios.items():
            for rep in range(1, REPS + 1):
                try:
                    rec = run_one(sid, sname, cfg)
                    rec["rep"] = rep
                    raw.append(rec)
                    print(f"{sid:14} {sname:16} rep{rep} qps={rec['client_qps']:9.1f} "
                          f"p50={rec['p50_us']:8.1f} p99={rec['p99_us']:9.1f} "
                          f"rss={rec['rss_kb']/1024:7.1f}M cpu={rec['cpu_total_pct']:6.1f}% "
                          f"start={rec['startup_s']:.2f}s la={rec['loadavg_1m']:.2f}", flush=True)
                except Exception as e:
                    print(f"{sid} {sname} rep{rep} FAILED: {e}", flush=True)
                    raw.append({"server": sid, "scenario": sname, "rep": rep, "error": str(e)})


def median_record(server, scenario, rows):
    good = [r for r in rows if "error" not in r]
    if not good:
        return {"server": server, "scenario": scenario, "reps": 0, "error": "all reps failed"}
    m = {"server": server, "scenario": scenario, "reps": len(good)}
    for key in NUM:
        m[key] = statistics.median(r[key] for r in good if r.get(key) is not None)
    m["min_qps"] = min(r["client_qps"] for r in good)
    m["max_qps"] = max(r["client_qps"] for r in good)
    return m


def main():
    raw, med = [], []
    t_start = time.time()
    meta = {
        "reps": REPS,
        "mix": MIX,
        "nx_mix": NX_MIX,
        "server_cpus": "0-3",
        "client_cpus": "4-7",
        "threads": 4,
        "zones": {"example.com.": 100000, "z0.bench.test.": 100000},
        "host": harness.subprocess.run(["uname", "-a"], capture_output=True, text=True).stdout.strip(),
        "cpu": harness.subprocess.run(["lscpu"], capture_output=True, text=True).stdout,
        "loadavg_start": harness.loadavg(),
    }
    phase(AUTH_SERVERS, AUTH_SCEN, raw)
    up, dt, rss = harness.start("pulsed", f"{ROOT}/logs/bench-upstream.log")
    print(f"upstream pulsed ready {dt:.2f}s rss {rss}KB", flush=True)
    try:
        phase(RES_SERVERS, RES_SCEN, raw)
    finally:
        harness.stop(up)
    for sid in AUTH_SERVERS:
        for sname in AUTH_SCEN:
            med.append(median_record(sid, sname, [r for r in raw if r["server"] == sid and r["scenario"] == sname]))
    for sid in RES_SERVERS:
        for sname in RES_SCEN:
            med.append(median_record(sid, sname, [r for r in raw if r["server"] == sid and r["scenario"] == sname]))
    meta["loadavg_end"] = harness.loadavg()
    meta["elapsed_s"] = time.time() - t_start
    with open(f"{ROOT}/results/bench.json", "w") as f:
        json.dump({"meta": meta, "median": med, "raw": raw}, f, indent=2)
    print(f"done in {meta['elapsed_s']:.0f}s")


if __name__ == "__main__":
    main()
