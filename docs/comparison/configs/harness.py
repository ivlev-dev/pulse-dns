#!/usr/bin/env python3
"""Server start/stop, readiness, resource sampling and loadgen invocation."""
import json
import os
import signal
import subprocess
import time

import dnsq

ROOT = "/tmp/opencode/compare"
PULSE = "/home/ivlev_dev/Проекты/PC/pulse-dns/target/release"
LOADGEN = f"{PULSE}/pulse-loadgen"
BIND = f"{ROOT}/dist/bind"
UNBOUND = f"{ROOT}/dist/unbound"
PDNS = f"{ROOT}/dist/pdns"
REC = f"{ROOT}/dist/pdns-recursor"


def spec(**kw):
    return kw


SERVERS = {
    "pulsed": spec(kind="auth", port=5301, argv=[
        f"{PULSE}/pulsed", "--config", f"{ROOT}/etc/pulsed-auth.toml"]),
    "pulsed-cache": spec(kind="auth", port=5305, argv=[
        f"{PULSE}/pulsed", "--config", f"{ROOT}/etc/pulsed-auth-cache.toml"]),
    "bind": spec(kind="auth", port=5302, argv=[
        f"{BIND}/sbin/named", "-g", "-n", "4", "-c", f"{ROOT}/etc/named-auth.conf"]),
    "unbound": spec(kind="auth", port=5303, argv=[
        f"{UNBOUND}/sbin/unbound", "-d", "-c", f"{ROOT}/etc/unbound-auth.conf"]),
    "pdns": spec(kind="auth", port=5304, argv=[
        f"{PDNS}/sbin/pdns_server", f"--config-dir={ROOT}/etc", "--config-name=auth",
        "--daemon=no"], env={"LD_LIBRARY_PATH": f"{PDNS}/lib"}),
    "pdns-cache": spec(kind="auth", port=5306, argv=[
        f"{PDNS}/sbin/pdns_server", f"--config-dir={ROOT}/etc", "--config-name=auth-cache",
        "--daemon=no"], env={"LD_LIBRARY_PATH": f"{PDNS}/lib"}),
    "pulseresolved": spec(kind="resolver", port=5401, argv=[
        f"{PULSE}/pulseresolved", "--config", f"{ROOT}/etc/pulseresolved.toml"]),
    "unbound-res": spec(kind="resolver", port=5402, argv=[
        f"{UNBOUND}/sbin/unbound", "-d", "-c", f"{ROOT}/etc/unbound-resolver.conf"]),
    "bind-res": spec(kind="resolver", port=5403, argv=[
        f"{BIND}/sbin/named", "-g", "-n", "4", "-c", f"{ROOT}/etc/named-resolver.conf"]),
    "pdns-rec": spec(kind="resolver", port=5404, argv=[
        f"{REC}/sbin/pdns_recursor",
        "--local-address=127.0.0.1", "--local-port=5404", "--threads=4",
        "--forward-zones-recurse=.=127.0.0.1:5301", "--dnssec=off",
        "--daemon=no", "--write-pid=no", "--disable-syslog=yes",
        "--log-timestamp=yes", "--loglevel=3", "--quiet=yes",
        f"--socket-dir={ROOT}/run/pdns-rec", "--allow-from=127.0.0.0/8"],
        env={"LD_LIBRARY_PATH": f"{REC}/lib"}),
}

READY_Q = ("r0000000.z0.bench.test.", "A")


def query_ok(port, rd, timeout=0.25):
    try:
        r = dnsq.query(READY_Q[0], READY_Q[1], "127.0.0.1", port, timeout=timeout, rd=rd)
        return r["rcode"] in ("NOERROR", "NXDOMAIN")
    except Exception:
        return False


def read_stat(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().split()
    return int(parts[13]), int(parts[14])


def rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def start(sid, log):
    s = SERVERS[sid]
    env = os.environ.copy()
    env.update(s.get("env", {}))
    out = open(log, "ab")
    t0 = time.monotonic()
    p = subprocess.Popen(["taskset", "-c", "0-3"] + s["argv"], stdout=out,
                         stderr=subprocess.STDOUT, env=env, start_new_session=True)
    ready = False
    while time.monotonic() - t0 < 120:
        if p.poll() is not None:
            break
        if query_ok(s["port"], s["kind"] == "resolver", timeout=0.1):
            ready = True
            break
        time.sleep(0.02)
    dt = time.monotonic() - t0
    if not ready:
        stop(p)
        raise RuntimeError(f"{sid}: not ready in {dt:.1f}s, see {log}")
    return p, dt, rss_kb(p.pid)


def stop(p):
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait(timeout=5)


def loadgen(port, out_json, qps=0, window=64, duration=10, warmup=3,
            mix="a=40,aaaa=20,mx=15,txt=10,nx=15", threads=4):
    cmd = ["taskset", "-c", "4-7", LOADGEN, "--server", f"127.0.0.1:{port}",
           "--mode", "udp", "--threads", str(threads), "--window", str(window),
           "--duration", str(duration), "--warmup", str(warmup), "--mix", mix,
           "--zones", "1", "--rrsets-per-zone", "100000", "--client-cpus", "4-7",
           "--json-out", out_json, "--quiet"]
    if qps:
        cmd += ["--qps", str(qps)]
    t0 = time.monotonic()
    cp = subprocess.run(cmd, capture_output=True, text=True)
    wall = time.monotonic() - t0
    if cp.returncode != 0:
        raise RuntimeError(f"loadgen failed: {cp.stderr[-2000:]}")
    with open(out_json) as f:
        j = json.load(f)
    j["wall_secs"] = wall
    return j


def loadavg():
    with open("/proc/loadavg") as f:
        return f.read().split()[:3]


def proc_cpu(pid):
    u, s = read_stat(pid)
    return u, s


def ticks():
    return os.sysconf("SC_CLK_TCK")
