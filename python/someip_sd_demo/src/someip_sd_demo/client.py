"""SOME/IP-SD client ("the QNX ECU stand-in"): finds both real sensor
services (Measurements 0x60d4, Status 0x60d6), auto-subscribes to each
eventgroup per the real AUTOSAR SD state machine (via pysomeip), joins
both advertised IPv6 multicast groups on the shared data port, and logs
every notification it receives -- decoded as a real SOME/IP header, so
the documented static session-id quirk on Status is directly visible.
"""

from __future__ import annotations

import argparse
import asyncio
import logging

import someip.header as h
from someip.config import Eventgroup, Service
from someip.header import L4Protocols
from someip.sd import ClientServiceListener, format_address

from someip_sd_demo.common import (
    CLIENT_LOCAL_ADDR,
    CLIENT_SD_UNICAST_PORT,
    DATA_PORT,
    INSTANCE_ID,
    INTERFACE,
    MAJOR_VERSION,
    SERVER_SD_UNICAST_PORT,
    SERVICES,
    configure_logging,
    create_split_endpoints,
    create_unicast_sd_endpoint,
    open_data_recv_socket,
    open_unicast_data_recv_socket,
    unpack_payload,
)


class LoggingServiceListener(ClientServiceListener):
    """Just logs Offer/StopOffer -- the actual subscribe is automatic
    (AutoSubscribeServiceListener, wired up by find_subscribe_eventgroup).
    """

    def __init__(self, log: logging.Logger):
        self.log = log

    def service_offered(self, service: Service, source) -> None:
        self.log.info(
            "discovered service=0x%04x instance=0x%04x major=%d from %s: %s",
            service.service_id,
            service.instance_id,
            service.major_version,
            format_address(source),
            service,
        )

    def service_stopped(self, service: Service, source) -> None:
        self.log.info(
            "service=0x%04x instance=0x%04x from %s stopped offering",
            service.service_id,
            service.instance_id,
            format_address(source),
        )


async def run(args: argparse.Namespace) -> None:
    log = configure_logging("client", level=getattr(logging, args.log_level.upper()))

    unicast_mode = args.peer_addr is not None
    trsp_m = None
    if unicast_mode:
        log.info(
            "--peer-addr given: running SD unicast, point-to-point with %s "
            "(CI-only fallback -- see README's CI section)",
            args.peer_addr,
        )
        trsp_u, sd_prot = await create_unicast_sd_endpoint(
            local_addr=args.local_addr,
            local_port=args.unicast_port,
            peer_addr=args.peer_addr,
            peer_port=SERVER_SD_UNICAST_PORT,
        )
    else:
        trsp_u, trsp_m, sd_prot = await create_split_endpoints(
            local_addr=args.local_addr, unicast_port=args.unicast_port, multicast_interface=args.interface
        )

    timings = sd_prot.timings
    timings.INITIAL_DELAY_MIN = 0.1
    timings.INITIAL_DELAY_MAX = 0.3
    timings.REPETITIONS_MAX = 3
    timings.REPETITIONS_BASE_DELAY = 0.2
    timings.FIND_TTL = 3
    timings.SUBSCRIBE_TTL = 5
    timings.SUBSCRIBE_REFRESH_INTERVAL = 3

    sd_prot.start()

    watch_listener = LoggingServiceListener(log)
    for service in SERVICES:
        watched = Service(service.service_id, INSTANCE_ID, MAJOR_VERSION)
        sd_prot.discovery.watch_service(watched, watch_listener)

        eventgroup = Eventgroup(
            service_id=service.service_id,
            instance_id=INSTANCE_ID,
            major_version=MAJOR_VERSION,
            eventgroup_id=service.eventgroup_id,
            sockname=trsp_u.get_extra_info("sockname"),
            protocol=L4Protocols.UDP,
        )
        sd_prot.discovery.find_subscribe_eventgroup(eventgroup)
        log.info(
            "%s: watching for service=0x%04x instance=0x%04x; will auto-subscribe "
            "eventgroup=0x%04x and join [%s]:%d for its data",
            service.name,
            service.service_id,
            INSTANCE_ID,
            service.eventgroup_id,
            service.multicast_addr,
            DATA_PORT,
        )

    if unicast_mode:
        data_sock = open_unicast_data_recv_socket(args.local_addr)
    else:
        data_sock = open_data_recv_socket(tuple(s.multicast_addr for s in SERVICES), interface=args.interface)
    by_service_id = {s.service_id: s for s in SERVICES}
    loop = asyncio.get_event_loop()

    async def receive_loop() -> None:
        while True:
            data = await loop.sock_recv(data_sock, 4096)
            try:
                msg, rest = h.SOMEIPHeader.parse(data)
            except h.ParseError as exc:
                log.warning("failed to parse notification (%d bytes): %r", len(data), exc)
                continue
            service = by_service_id.get(msg.service_id)
            if service is None:
                log.warning("notification for unknown service=0x%04x", msg.service_id)
                continue
            event_id, payload_session, seq, value = unpack_payload(msg.payload)
            log.info(
                "%s: received notification seq=%d header_session=0x%04x "
                "payload_session=0x%04x value=%.2f (%d bytes)%s",
                service.name,
                seq,
                msg.session_id,
                payload_session,
                value,
                len(data),
                " [static session id, as documented]" if service.static_session_id is not None else "",
            )

    try:
        await receive_loop()
    except asyncio.CancelledError:
        pass
    finally:
        log.info("shutting down: unsubscribing and closing sockets")
        for service in SERVICES:
            eventgroup = Eventgroup(
                service_id=service.service_id,
                instance_id=INSTANCE_ID,
                major_version=MAJOR_VERSION,
                eventgroup_id=service.eventgroup_id,
                sockname=trsp_u.get_extra_info("sockname"),
                protocol=L4Protocols.UDP,
            )
            sd_prot.discovery.stop_find_subscribe_eventgroup(eventgroup)
        sd_prot.stop()
        data_sock.close()
        trsp_u.close()
        if trsp_m is not None:
            trsp_m.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-addr", default=CLIENT_LOCAL_ADDR)
    parser.add_argument("--unicast-port", type=int, default=CLIENT_SD_UNICAST_PORT)
    parser.add_argument(
        "--peer-addr",
        default=None,
        help="CI-only fallback: run SD+data unicast, point-to-point with this "
        "server address, instead of multicast (see README's CI section)",
    )
    parser.add_argument(
        "--interface",
        default=INTERFACE,
        help="interface to join/send multicast on (default: %(default)s; e.g. eth0 in a container)",
    )
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
