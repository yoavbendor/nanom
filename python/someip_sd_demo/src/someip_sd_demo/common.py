"""Shared constants and helpers for the SOME/IP-SD server/client demo.

Both server.py and client.py are independent scripts (each drives its own
someip.sd.ServiceDiscoveryProtocol instance); this module only holds the
config both sides must agree on out-of-band -- exactly like two real ECUs
agree on service/instance/eventgroup IDs via their ARXML, not over the wire.

Values below come from a real vSomeIP-based LRR sensor simulator / QNX ECU
integration doc (service IDs, eventgroup IDs, multicast addresses and ports
all confirmed there -- ff14::4:0 for SD also independently matches what the
tshark reverse-engineering pass found in a real capture). Two pieces are
NOT in that doc and are placeholders until confirmed: the two events' own
method/event IDs (the doc gives service/eventgroup IDs, not method IDs).
"""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import logging
import socket
import struct

from someip.sd import DatagramProtocolAdapter, ServiceDiscoveryProtocol

INSTANCE_ID = 0x0001
MAJOR_VERSION = 1
MINOR_VERSION = 0


@dataclasses.dataclass(frozen=True)
class SensorService:
    """One of the sensor's offered services: one SOME/IP service, one
    eventgroup, one dedicated IPv6 multicast group for its event data.
    """

    name: str
    service_id: int
    eventgroup_id: int
    event_id: int  # TODO: placeholder -- doc gives service/eventgroup IDs, not this
    multicast_addr: str
    payload_size: int  # fixed size used for this demo's synthetic payload
    cycle_ms: int  # nominal notification cadence
    static_session_id: int | None  # None = normal incrementing session id


# Real service/eventgroup IDs, real per-eventgroup multicast groups, real
# data-plane port (42809, "ECU" / subscriber side) -- see README's network
# configuration table.
MEASUREMENTS = SensorService(
    name="Measurements",
    service_id=0x60D4,
    eventgroup_id=0x8002,
    event_id=0x8004,  # TODO: placeholder method/event ID, not given by the doc
    multicast_addr="ff14::4:5",
    payload_size=64,  # real payload is 1444+ bytes, TP-segmented; see README
    cycle_ms=65,
    static_session_id=None,
)
STATUS = SensorService(
    name="Status",
    service_id=0x60D6,
    eventgroup_id=0x8001,
    event_id=0x8006,  # TODO: placeholder method/event ID, not given by the doc
    multicast_addr="ff14::4:3",
    payload_size=116,  # real Status notification is exactly 116 bytes
    cycle_ms=65,  # sent ~30ms after each Measurements notification
    static_session_id=0x0000,  # real sensor uses a static session id here
)
SERVICES = (MEASUREMENTS, STATUS)

DATA_PORT = 42809  # ECU's data port: destination for both eventgroups' streams
SENSOR_DATA_SRC_PORT = 42810  # sensor's own source port for outgoing data

# --- SD control plane ---
SD_PORT = 30490  # AUTOSAR well-known SOME/IP-SD port
SD_MULTICAST_ADDR = "ff14::4:0"  # real SD multicast group (confirmed against a live capture)
INTERFACE = "lo"

# The real network's actual addresses, for reference / for pointing this
# demo directly at the real VLAN once reachable (pass these as --local-addr;
# real hosts don't need --unicast-port, since they don't share an address).
REAL_SENSOR_ADDR = "fd53:7cb8:383:2::56"
REAL_ECU_ADDR = "fd53:7cb8:383:2::1:117"

# Running two SD participants as two processes on ONE host means they'd
# normally collide trying to each bind a unicast SD socket to the same
# (::1, 30490): SO_REUSEPORT would then load-balance packets between them
# unpredictably instead of routing them correctly (see create_split_endpoints
# below and the README). Two *real* hosts don't have this problem because
# each has its own IP address; here we sidestep it by giving each role its
# own unicast SD port while still sharing the multicast port (30490) that SD
# itself requires everyone to use.
SERVER_LOCAL_ADDR = "::1"
SERVER_SD_UNICAST_PORT = 30490
CLIENT_LOCAL_ADDR = "::1"
CLIENT_SD_UNICAST_PORT = 30491

# event_id(H), session_id(H), sequence(I), synthetic reading(f), padding to
# the service's real payload_size.
_PAYLOAD_HEADER = struct.Struct("!HHIf")


def pack_payload(service: SensorService, session_id: int, seq: int, value: float) -> bytes:
    head = _PAYLOAD_HEADER.pack(service.event_id, session_id, seq, value)
    pad = service.payload_size - len(head)
    if pad < 0:
        raise ValueError(f"{service.name}: payload_size too small for header ({len(head)} bytes)")
    return head + b"\x00" * pad


def unpack_payload(data: bytes) -> tuple[int, int, int, float]:
    event_id, session_id, seq, value = _PAYLOAD_HEADER.unpack(data[: _PAYLOAD_HEADER.size])
    return event_id, session_id, seq, value


def service_by_event_id(event_id: int) -> SensorService | None:
    return next((s for s in SERVICES if s.event_id == event_id), None)


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

    trsp_u = await ServiceDiscoveryProtocol._create_endpoint(
        loop,
        prot,
        family,
        local_addr,
        unicast_port,
        multicast_interface=multicast_interface,
        ttl=ttl,
    )

    # The multicast socket is built ourselves rather than via pysomeip's
    # own _create_endpoint, for two reasons found the hard way (via CI,
    # each fix here undoing a real failure):
    #
    # 1. pysomeip's _create_endpoint binds to "<addr>%<interface>" on
    #    Linux, and glibc's getaddrinfo only accepts a zone-id suffix for
    #    LINK-LOCAL scope addresses (ff02::/16) -- EAI_NONAME for any
    #    other scope, including the admin-local ff14::/16 this project's
    #    real SD multicast group actually uses. Building the socket
    #    directly and joining via IPV6_JOIN_GROUP + if_nametoindex (no
    #    address-string parsing involved) works for every scope.
    # 2. The traditional way multiple processes share one multicast group
    #    on one port -- so each gets a copy of every datagram -- is
    #    SO_REUSEADDR *and* binding to the specific group address, not a
    #    wildcard "::" bind (which EADDRINUSEs on the second process even
    #    with SO_REUSEADDR set: that allowance is for identical-address
    #    binds, not two different wildcard binds racing for the same
    #    port). SO_REUSEPORT was tried first and rejected: on Linux it
    #    switches delivery to per-flow load-balancing (one recipient,
    #    chosen by a hash of the datagram's fixed src/dst tuple) -- and
    #    since every SD send here keeps the same source port for the
    #    whole run, that hash is constant, so one side was silently and
    #    deterministically starved of the other's Offers/Finds for the
    #    entire run (no errors, just total silence).
    mc_sock = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    mc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mc_sock.bind((multicast_addr, multicast_port))
    mreq = struct.pack(
        "16sI", socket.inet_pton(family, multicast_addr), if_index(multicast_interface)
    )
    mc_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    mc_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, if_index(multicast_interface))
    mc_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
    mc_sock.setblocking(False)
    trsp_m, _ = await loop.create_datagram_endpoint(
        lambda: DatagramProtocolAdapter(prot, is_multicast=True),
        sock=mc_sock,
    )

    prot.transport = trsp_u

    return trsp_u, trsp_m, prot


async def create_unicast_sd_endpoint(
    *,
    local_addr: str,
    local_port: int,
    peer_addr: str,
    peer_port: int,
    family: socket.AddressFamily = socket.AF_INET6,
    loop: asyncio.AbstractEventLoop | None = None,
) -> tuple[asyncio.DatagramTransport, ServiceDiscoveryProtocol]:
    """CI-only fallback: run SD purely unicast, point-to-point with a known
    peer, instead of via multicast discovery.

    GitHub-hosted Actions runners do not deliver IPv6 multicast traffic on
    `lo` between processes at all (confirmed with a raw, pysomeip-independent
    socket smoke test: joined, correct route, correct IPV6_MULTICAST_LOOP,
    still zero packets received -- a runner/hypervisor networking limitation,
    not something fixable from inside the VM). This sidesteps multicast
    entirely: `ServiceDiscoveryProtocol`'s `default_addr` (its fallback
    destination whenever a send doesn't pass an explicit `remote=`) is set to
    the peer's address instead of a multicast group, so the server's cyclic
    Offers and the client's FindService both go directly, unicast, to each
    other -- still 100% real sockets/asyncio/pysomeip SD code, just not real
    multicast fan-out (which this environment can't do regardless of how the
    demo is written). The default (no peer given) path stays multicast-based
    via create_split_endpoints, matching the real vendor deployment, for
    local/self-hosted use where multicast actually works.
    """
    if loop is None:
        loop = asyncio.get_event_loop()

    prot = ServiceDiscoveryProtocol((peer_addr, peer_port))
    trsp, _ = await loop.create_datagram_endpoint(
        lambda: DatagramProtocolAdapter(prot, is_multicast=False),
        local_addr=(local_addr, local_port),
        family=family,
    )
    prot.transport = trsp
    return trsp, prot


def open_unicast_data_send_socket(local_addr: str, src_port: int = SENSOR_DATA_SRC_PORT) -> socket.socket:
    """CI-only fallback data-plane send socket: plain unicast, no multicast
    options needed since it targets a single known peer directly.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((local_addr, src_port))
    sock.setblocking(False)
    return sock


def open_unicast_data_recv_socket(local_addr: str, port: int = DATA_PORT) -> socket.socket:
    """CI-only fallback data-plane receive socket: plain unicast bind, no
    multicast group join.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((local_addr, port))
    sock.setblocking(False)
    return sock


def if_index(interface: str) -> int:
    return socket.if_nametoindex(interface)


def open_data_send_socket(
    local_addr: str, src_port: int = SENSOR_DATA_SRC_PORT, interface: str = INTERFACE, ttl: int = 1
) -> socket.socket:
    """A plain send-only IPv6 UDP socket for streaming sensor payloads to
    the data-plane multicast groups. Deliberately outside pysomeip: the SD
    negotiation is the protocol-critical part; once a subscription is
    confirmed, the data itself is just sendto() to the address the Offer
    already advertised. Bound to the real sensor's own documented source
    port (42810) for fidelity, even though nothing here depends on it.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((local_addr, src_port))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, if_index(interface))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
    sock.setblocking(False)
    return sock


def open_data_recv_socket(
    multicast_addrs: tuple[str, ...],
    port: int = DATA_PORT,
    interface: str = INTERFACE,
) -> socket.socket:
    """A plain receive socket bound once to the shared data port and joined
    to every multicast group listed (both eventgroups' streams arrive on
    the same port, distinguished only by which group they were sent to).
    """
    # SO_REUSEADDR only -- see create_split_endpoints's mc_sock comment on
    # why SO_REUSEPORT is deliberately avoided for multicast group members.
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("::", port))
    for addr in multicast_addrs:
        mreq = struct.pack("16sI", socket.inet_pton(socket.AF_INET6, addr), if_index(interface))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    sock.setblocking(False)
    return sock
