#!/usr/bin/env python3
"""Minimal DNS client for verification and readiness checks."""
import random
import socket
import struct
import sys

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
RTYPES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def decode_name(buf, off):
    labels = []
    while True:
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            sub, _ = decode_name(buf, ptr)
            labels.append(sub)
            off += 2
            return ".".join(labels), off
        labels.append(buf[off + 1:off + 1 + n].decode(errors="replace"))
        off += 1 + n
    return ".".join(labels), off


def parse_rr(buf, off):
    name, off = decode_name(buf, off)
    rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", buf, off)
    off += 10
    rdata = buf[off:off + rdlen]
    off += rdlen
    val = None
    t = RTYPES.get(rtype, str(rtype))
    if rtype == 1 and rdlen == 4:
        val = ".".join(str(b) for b in rdata)
    elif rtype == 28 and rdlen == 16:
        val = ":".join(f"{struct.unpack_from('!H', rdata, i)[0]:x}" for i in range(0, 16, 2))
    elif rtype == 15:
        pref = struct.unpack_from("!H", rdata, 0)[0]
        host, _ = decode_name(buf, off - rdlen + 2)
        val = f"{pref} {host}."
    elif rtype == 16:
        ln = rdata[0]
        val = rdata[1:1 + ln].decode(errors="replace")
    elif rtype == 6:
        mname, p = decode_name(buf, off - rdlen)
        rname, p = decode_name(buf, p)
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", buf, p)
        val = f"{mname}. {rname}. {serial} {refresh} {retry} {expire} {minimum}"
    elif rtype == 2:
        ns, _ = decode_name(buf, off - rdlen)
        val = ns + "."
    elif rtype == 5:
        cn, _ = decode_name(buf, off - rdlen)
        val = cn + "."
    return {"name": name, "type": t, "ttl": ttl, "value": val}, off


def query(name, qtype="A", server="127.0.0.1", port=53, timeout=2.0, rd=False, tcp=False):
    qid = random.randrange(0, 65536)
    flags = 0x0100 if rd else 0
    msg = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", TYPES[qtype], 1)
    if tcp:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, port))
        s.sendall(struct.pack("!H", len(msg)) + msg)
        ln = struct.unpack("!H", s.recv(2))[0]
        data = b""
        while len(data) < ln:
            data += s.recv(ln - len(data))
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, (server, port))
        data = s.recv(65535)
        s.close()
    rid, rflags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    assert rid == qid, "id mismatch"
    off = 12
    for _ in range(qd):
        _, off = decode_name(data, off)
        off += 4
    answers = []
    for _ in range(an):
        rr, off = parse_rr(data, off)
        answers.append(rr)
    authority = []
    for _ in range(ns):
        rr, off = parse_rr(data, off)
        authority.append(rr)
    additional = []
    for _ in range(ar):
        rr, off = parse_rr(data, off)
        additional.append(rr)
    return {
        "rcode": RCODES.get(rflags & 0xF, str(rflags & 0xF)),
        "aa": bool(rflags & 0x0400),
        "tc": bool(rflags & 0x0200),
        "answers": answers,
        "authority": authority,
        "additional": additional,
    }


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("name")
    p.add_argument("qtype", nargs="?", default="A")
    p.add_argument("--server", default="127.0.0.1")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--rd", action="store_true")
    p.add_argument("--tcp", action="store_true")
    a = p.parse_args()
    r = query(a.name, a.qtype, a.server, a.port, rd=a.rd, tcp=a.tcp)
    print(r["rcode"], "AA" if r["aa"] else "--")
    for rr in r["answers"]:
        print(f"  {rr['name']} {rr['ttl']} {rr['type']} {rr['value']}")
