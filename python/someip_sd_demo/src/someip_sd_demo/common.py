"""Shared constants and helpers for the SOME/IP-SD server/client demo.

Both server.py and client.py are independent scripts (each drives its own
someip.sd.ServiceDiscoveryProtocol instance); this module only holds the
config both sides must agree on out-of-band -- exactly like two real ECUs
agree on service/instance/eventgroup IDs via their ARXML, not over the wire.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct

from someip.sd import ServiceDiscoveryProtocol

# --- SOME/IP service identity (arbitrary demo values; the real vendor IDs
# come from the tshark/ARXML reverse-engineering work, not from here) ---
SERVICE_ID = 0x1234
INSTANCE_ID = 0x0001
MAJOR_VERSION = 1
MINOR_VERSION = 0
EVENTGROUP_ID = 0x0001

# --- SD control plane ---
SD_PORT = 30490  # AUTOSAR well-known SOME/IP-SD port
SD_MULTICAST_ADDR = "ff14::930:490"  # arbitrary demo SD multicast group
INTERFACE = "lo"

# Running two SD participants as two processes on ONE host means they'd
# normally collide trying to each bind a unicast SD socket to the same
# (::1, 30490): SO_REUSEPORT would then load-balance packets between them
# unpredictably instead of routing them correctly (see create_split_endpoints
# below and the README). Two *real* ECUs don't have this problem because
# each has its own IP address; here we sidestep it by giving each role its
# own unicast SD port while still sharing the multicast port (30490) that SD
# itself requires everyone to use.
SERVER_LOCAL_ADDR = "::1"
SERVER_SD_UNICAST_PORT = 30490
CLIENT_LOCAL_ADDR = "::1"
CLIENT_SD_UNICAST_PORT = 30491

# --- sensor data plane ---
DATA_MULTICAST_ADDR = "ff14::5"
DATA_PORT = 30510

# The five sensor source addresses from the real vehicle network. In this
# demo they're carried as payload metadata (which simulated sensor an event
# belongs to), not used as socket source addresses -- see the plan/README
# for why (it would require provisioning 5 more loopback addresses for no
# protocol-relevant benefit; SD subscription is per-eventgroup, not per
# source address).
SENSORS = [
    (0x0001, "fd53:7cb8:383:2::bd"),
    (0x0002, "fd53:7cb8:383:2::56"),
    (0x0003, "fd53:7cb8:383:2::bb"),
    (0x0004, "fd53:7cb8:383:2::be"),
    (0x0005, "fd53:7cb8:383:2::bc"),
]

# event_id(H), sequence(I), synthetic reading(f)
SENSOR_PAYLOAD = struct.Struct("!HIf")


def configure_logging(role: str, level: int = logging.INFO) -> logging.Logger:
    """Configure logging for this process and return the app-level logger.

    Turns on pysomeip's own loggers too (someip.sd and children), since a
    lot of the SD state machine's interesting behaviour -- Offer/Find/
    Subscribe/Ack -- is only visible through the library's own log lines.
    """
    logging.basicConfig(
        level=level,
        format=f"%(asctime)s.%(msecs)03d {role:6s} %(name)-24s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("someip.sd").setLevel(level)
    return logging.getLogger(f"demo.{role}")


async def create_split_endpoints(
    *,
    local_addr: str,
    unicast_port: int,
    multicast_addr: str = SD_MULTICAST_ADDR,
    multicast_port: int = SD_PORT,
    multicast_interface: str = INTERFACE,
    ttl: int = 1,
    family: socket.AddressFamily = socket.AF_INET6,
    loop: asyncio.AbstractEventLoop | None = None,
) -> tuple[asyncio.DatagramTransport, asyncio.DatagramTransport, ServiceDiscoveryProtocol]:
    """Like ServiceDiscoveryProtocol.create_endpoints, but with the unicast
    and multicast sockets bound to independently chosen ports.

    pysomeip's own create_endpoints() uses a single `port` for both the
    unicast SD socket and the multicast join/send -- correct for real
    hosts, each with their own address, but unworkable for two SD
    participants sharing one loopback address (see SERVER_SD_UNICAST_PORT
    above). The multicast leg must still use the shared SD port (that's
    where every participant's Offers/Finds actually get sent); only the
    unicast leg's port is split out here.
    """
    if loop is None:
        loop = asyncio.get_event_loop()
    if not ipaddress.ip_address(multicast_addr).is_multicast:
        raise ValueError("multicast_addr is not multicast")

    prot = ServiceDiscoveryProtocol((multicast_addr, multicast_port))

    # order matters (see pysomeip's own create_endpoints): create the
    # unicast socket first so unicast traffic isn't captured by the
    # multicast socket on platforms where that matters.
    trsp_u = await ServiceDiscoveryProtocol._create_endpoint(
        loop,
        prot,
        family,
        local_addr,
        unicast_port,
        multicast_interface=multicast_interface,
        ttl=ttl,
    )
    trsp_m = await ServiceDiscoveryProtocol._create_endpoint(
        loop,
        prot,
        family,
        local_addr,
        multicast_port,
        multicast_addr=multicast_addr,
        multicast_interface=multicast_interface,
        ttl=ttl,
    )
    prot.transport = trsp_u

    return trsp_u, trsp_m, prot


def if_index(interface: str) -> int:
    return socket.if_nametoindex(interface)


def open_data_send_socket(interface: str = INTERFACE, ttl: int = 1) -> socket.socket:
    """A plain send-only IPv6 UDP socket for streaming sensor payloads to
    the data-plane multicast group. Deliberately outside pysomeip: the SD
    negotiation is the protocol-critical part; once a subscription is
    confirmed, the data itself is just sendto() to the address the Offer
    already advertised.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, if_index(interface))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
    sock.setblocking(False)
    return sock


def open_data_recv_socket(
    multicast_addr: str = DATA_MULTICAST_ADDR,
    port: int = DATA_PORT,
    interface: str = INTERFACE,
) -> socket.socket:
    """A plain receive socket joined to the data-plane multicast group."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("::", port))
    mreq = struct.pack("16sI", socket.inet_pton(socket.AF_INET6, multicast_addr), if_index(interface))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    sock.setblocking(False)
    return sock
