#!/usr/bin/env python3
"""Generate the shared benchmark zones.

example.com.  : 100000 A records host000001..host100000 (plus SOA/NS)
z0.bench.test.: 100000 records r0000000..r0099999, type = index % 4
                (A, AAAA, MX, TXT) so pulse-loadgen's query mix is exact.
"""
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/opencode/compare/zones"
N = 100000


def ip(i):
    return f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"


def gen_example(path):
    with open(path, "w") as f:
        f.write("$ORIGIN example.com.\n$TTL 86400\n")
        f.write("@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026112601 3600 900 604800 86400 )\n")
        f.write("@ IN NS ns1.example.com.\n")
        f.write("ns1 IN A 127.0.0.1\n")
        for i in range(1, N + 1):
            f.write(f"host{i:06d} IN A {ip(i)}\n")


def gen_bench(path):
    with open(path, "w") as f:
        f.write("$ORIGIN z0.bench.test.\n$TTL 86400\n")
        f.write("@ IN SOA ns1.z0.bench.test. hostmaster.z0.bench.test. ( 2026112601 3600 900 604800 86400 )\n")
        f.write("@ IN NS ns1.z0.bench.test.\n")
        f.write("ns1 IN A 127.0.0.1\n")
        for i in range(N):
            name = f"r{i:07d}"
            k = i % 4
            if k == 0:
                f.write(f"{name} IN A {ip(i)}\n")
            elif k == 1:
                f.write(f"{name} IN AAAA 2001:db8:{i >> 16:x}:{i & 0xffff:x}::1\n")
            elif k == 2:
                f.write(f"{name} IN MX 10 mail.example.com.\n")
            else:
                f.write(f'{name} IN TXT "bench-{i:07d}-payload"\n')


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    gen_example(os.path.join(OUT, "example.com.zone"))
    gen_bench(os.path.join(OUT, "z0.bench.test.zone"))
    for n in ("example.com.zone", "z0.bench.test.zone"):
        p = os.path.join(OUT, n)
        print(n, os.path.getsize(p), "bytes")
