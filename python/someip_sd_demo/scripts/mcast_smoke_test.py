"""Standalone diagnostic (not part of the demo): confirms two separate
OS processes can exchange a raw IPv6 multicast UDP datagram on this host
(or, run via docker-compose's "smoketest" profile, two containers on a
shared bridge network), independent of pysomeip/asyncio. Used to isolate
CI failures, and to validate a new environment (e.g. rootless Docker on a
no-sudo host) before trusting the full demo to it.

Usage: python3 mcast_smoke_test.py recv   (prints RECEIVED: ... and exits 0)
       python3 mcast_smoke_test.py send   (sends a few packets)

Interface defaults to "lo"; override with the MCAST_IFACE env var (the
docker-compose smoketest profile sets it to "eth0").
"""
import os
import socket
import struct
import sys
import time

GROUP = "ff14::4:0"
PORT = 30490
IFACE = os.environ.get("MCAST_IFACE", "lo")


def if_index():
    return socket.if_nametoindex(IFACE)


def recv():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((GROUP, PORT))
    mreq = struct.pack("16sI", socket.inet_pton(socket.AF_INET6, GROUP), if_index())
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    sock.settimeout(15)
    print("recv: joined, waiting...", flush=True)
    try:
        data, addr = sock.recvfrom(1024)
        print(f"RECEIVED: {data!r} from {addr}", flush=True)
        sys.exit(0)
    except socket.timeout:
        print("TIMEOUT: nothing received", flush=True)
        sys.exit(1)


def send():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, if_index())
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    # IPV6_MULTICAST_LOOP governs whether a sent datagram is delivered to
    # ANY local group member on this interface (not just "back to the
    # sender" despite the name) -- testing whether it defaults to off here.
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
    print("send: IPV6_MULTICAST_LOOP explicitly set to 1", flush=True)
    for i in range(10):
        sock.sendto(f"hello-{i}".encode(), (GROUP, PORT))
        print(f"send: sent hello-{i}", flush=True)
        time.sleep(1)


if __name__ == "__main__":
    {"recv": recv, "send": send}[sys.argv[1]]()
