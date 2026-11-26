#!/usr/bin/env python3
"""Cross-server answer equivalence check for authoritative and resolver roles."""
import json

import dnsq
import harness

AUTH = ["pulsed", "bind", "unbound", "pdns", "pulsed-cache", "pdns-cache"]
RES = ["pulseresolved", "unbound-res", "bind-res", "pdns-rec"]
QUERIES = [
    ("host000001.example.com.", "A"),
    ("host050000.example.com.", "A"),
    ("host100000.example.com.", "A"),
    ("example.com.", "SOA"),
    ("r0000000.z0.bench.test.", "A"),
    ("r0000001.z0.bench.test.", "AAAA"),
    ("r0000002.z0.bench.test.", "MX"),
    ("r0000003.z0.bench.test.", "TXT"),
    ("r0099999.z0.bench.test.", "TXT"),
    ("z0.bench.test.", "SOA"),
    ("nx0000001.z0.bench.test.", "A"),
    ("absent.example.com.", "A"),
    ("nx99999.z0.bench.test.", "A"),
]


def norm(r):
    # Positive/negative answer content is the contract. BIND adds the zone NS
    # to AUTHORITY on positive authoritative answers; that policy difference is
    # recorded in the report, not treated as a mismatch.
    return {
        "rcode": r["rcode"],
        "answers": sorted((a["name"].lower(), a["type"], str(a["value"])) for a in r["answers"]),
    }


def collect(sid, rd):
    port = harness.SERVERS[sid]["port"]
    p, dt, rss = harness.start(sid, f"logs/verify-{sid}.log")
    try:
        rows = {}
        for q, t in QUERIES:
            rows[f"{q} {t}"] = norm(dnsq.query(q, t, "127.0.0.1", port, rd=rd, timeout=3))
        return rows
    finally:
        harness.stop(p)


def main():
    results = {}
    for sid in AUTH:
        results[sid] = collect(sid, False)
    # The resolver phase needs an upstream; it is the same pulsed config/port,
    # so authoritative runs are fully finished before it starts.
    up, dt, rss = harness.start("pulsed", "logs/verify-upstream.log")
    try:
        for sid in RES:
            results[sid] = collect(sid, True)
    finally:
        harness.stop(up)

    ref_auth = results["pulsed"]
    ref_res = results["pulseresolved"]
    out = {"queries": [f"{q} {t}" for q, t in QUERIES], "servers": {}}
    ok = True
    for sid, rows in results.items():
        ref = ref_res if sid in RES else ref_auth
        diffs = []
        for q in rows:
            if rows[q] != ref[q]:
                diffs.append({"query": q, "got": rows[q], "want": ref[q]})
        out["servers"][sid] = {"match": not diffs, "diffs": diffs}
        print(f"{sid:14} {'MATCH' if not diffs else 'DIFF ' + str(len(diffs))}")
        for d in diffs[:2]:
            print("   ", d["query"], "got", d["got"]["rcode"], "want", d["want"]["rcode"])
        ok = ok and not diffs
    with open("results/verify.json", "w") as f:
        json.dump(out, f, indent=2)
    print("ALL_MATCH" if ok else "MISMATCHES")


if __name__ == "__main__":
    main()
