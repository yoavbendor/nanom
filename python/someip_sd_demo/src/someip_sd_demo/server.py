"""SOME/IP-SD server ("the LRR sensor simulator"): offers two real
services -- Measurements (0x60d4) and Status (0x60d6) -- each with its
own eventgroup and dedicated IPv6 multicast option, answers
FindService/Subscribe per the real AUTOSAR SD state machine (via
pysomeip), and once each eventgroup has a subscriber, streams that
service's notifications to its advertised multicast group.

Service IDs, eventgroup IDs, multicast addresses/ports and the two
documented real-sensor quirks (Status's static session id, Measurements'
large/TP-segmented payload) come from a real vSomeIP LRR sensor
simulator / QNX ECU integration doc -- see README.md.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging

import someip.header as h
from someip.config import Service
from someip.header import IPv6EndpointOption, IPv6MulticastOption, L4Protocols
from someip.sd import EventgroupSubscription, ServiceInstance, ServerServiceListener, format_address

from someip_sd_demo.common import (
    CLIENT_SD_UNICAST_PORT,
    DATA_PORT,
    INSTANCE_ID,
    MAJOR_VERSION,
    MINOR_VERSION,
    SERVER_LOCAL_ADDR,
    SERVER_SD_UNICAST_PORT,
    SERVICES,
    SensorService,
    configure_logging,
    create_split_endpoints,
    create_unicast_sd_endpoint,
    open_data_send_socket,
    open_unicast_data_send_socket,
    pack_payload,
)


class SensorEventgroupListener(ServerServiceListener):
    """Logs Subscribe/Unsubscribe for one service and gates whether the
    data loop sends that service's notifications.
    """

    def __init__(self, service: SensorService, log: logging.Logger):
        self.service = service
        self.log = log
        self.active = 0

    def client_subscribed(self, subscription: EventgroupSubscription, source) -> None:
        self.active += 1
        self.log.info(
            "%s: SubscribeEventgroup accepted from %s (eventgroup=0x%04x ttl=%d) "
            "-> %d active subscriber(s)",
            self.service.name,
            format_address(source),
            subscription.id,
            subscription.ttl,
            self.active,
        )

    def client_unsubscribed(self, subscription: EventgroupSubscription, source) -> None:
        self.active = max(0, self.active - 1)
        self.log.info(
            "%s: client %s unsubscribed/expired -> %d active subscriber(s)",
            self.service.name,
            format_address(source),
            self.active,
        )


def build_offered_service(service: SensorService, local_addr: str, unicast_port: int) -> Service:
    return Service(
        service.service_id,
        INSTANCE_ID,
        MAJOR_VERSION,
        MINOR_VERSION,
        options_1=(
            # the service's own (conventional) unicast SD endpoint
            IPv6EndpointOption(
                address=ipaddress.IPv6Address(local_addr), l4proto=L4Protocols.UDP, port=unicast_port
            ),
            # the actual point of this demo: an IPv6 multicast option
            # telling subscribers where this eventgroup's data will be sent
            IPv6MulticastOption(
                address=ipaddress.IPv6Address(service.multicast_addr),
                l4proto=L4Protocols.UDP,
                port=DATA_PORT,
            ),
        ),
        eventgroups=frozenset({service.eventgroup_id}),
    )


async def run(args: argparse.Namespace) -> None:
    log = configure_logging("server", level=getattr(logging, args.log_level.upper()))

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
            peer_port=CLIENT_SD_UNICAST_PORT,
        )
    else:
        trsp_u, trsp_m, sd_prot = await create_split_endpoints(
            local_addr=args.local_addr, unicast_port=args.unicast_port
        )

    # Shortened AUTOSAR SD timing so the Initial-Wait/Repetition/Main phases
    # are all visible in a demo run lasting a few seconds rather than minutes.
    timings = sd_prot.timings
    timings.INITIAL_DELAY_MIN = 0.2
    timings.INITIAL_DELAY_MAX = 0.5
    timings.REPETITIONS_MAX = 3
    timings.REPETITIONS_BASE_DELAY = 0.2
    timings.CYCLIC_OFFER_DELAY = 3.0
    timings.ANNOUNCE_TTL = 6
    timings.SUBSCRIBE_TTL = 5

    listeners: dict[int, SensorEventgroupListener] = {}
    instances: list[ServiceInstance] = []
    for service in SERVICES:
        offered = build_offered_service(service, args.local_addr, args.unicast_port)
        listener = SensorEventgroupListener(service, log)
        listeners[service.service_id] = listener
        instance = ServiceInstance(offered, listener, sd_prot.announcer, timings)
        sd_prot.announcer.announce_service(instance)
        instances.append(instance)
        log.info(
            "offering %s: service=0x%04x instance=0x%04x eventgroup=0x%04x "
            "-> data multicast [%s]:%d once subscribed",
            service.name,
            service.service_id,
            INSTANCE_ID,
            service.eventgroup_id,
            service.multicast_addr,
            DATA_PORT,
        )

    sd_prot.start()

    if unicast_mode:
        data_sock = open_unicast_data_send_socket(args.local_addr)
    else:
        data_sock = open_data_send_socket(args.local_addr)
    session_ids = {service.service_id: 1 for service in SERVICES}
    seq = 0
    try:
        while True:
            await asyncio.sleep(SERVICES[0].cycle_ms / 1000.0)
            seq += 1
            for i, service in enumerate(SERVICES):
                if listeners[service.service_id].active <= 0:
                    log.debug("%s: no active subscribers yet, not sending", service.name)
                    continue
                if service.static_session_id is not None:
                    session_id = service.static_session_id
                else:
                    session_id = session_ids[service.service_id]
                    session_ids[service.service_id] = (session_id % 0xFFFF) + 1

                value = 20.0 + service.service_id % 16 + 0.1 * (seq % 10)
                payload = pack_payload(service, session_id, seq, value)
                msg = h.SOMEIPHeader(
                    service_id=service.service_id,
                    method_id=service.event_id,
                    client_id=0,
                    session_id=session_id,
                    interface_version=MAJOR_VERSION,
                    message_type=h.SOMEIPMessageType.NOTIFICATION,
                    return_code=h.SOMEIPReturnCode.E_OK,
                    payload=payload,
                )
                wire = msg.build()
                # stagger Status ~30ms after Measurements, as documented
                if i > 0:
                    await asyncio.sleep(0.03)
                dest = args.peer_addr if unicast_mode else service.multicast_addr
                data_sock.sendto(wire, (dest, DATA_PORT))
                log.info(
                    "%s: sent notification seq=%d session=0x%04x value=%.2f "
                    "(%d bytes) -> [%s]:%d",
                    service.name,
                    seq,
                    session_id,
                    value,
                    len(wire),
                    dest,
                    DATA_PORT,
                )
    except asyncio.CancelledError:
        pass
    finally:
        log.info("shutting down: sending StopOffer and closing sockets")
        for instance in instances:
            sd_prot.announcer.stop_announce_service(instance)
        sd_prot.stop()
        data_sock.close()
        trsp_u.close()
        if trsp_m is not None:
            trsp_m.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-addr", default=SERVER_LOCAL_ADDR)
    parser.add_argument("--unicast-port", type=int, default=SERVER_SD_UNICAST_PORT)
    parser.add_argument(
        "--peer-addr",
        default=None,
        help="CI-only fallback: run SD+data unicast, point-to-point with this "
        "client address, instead of multicast (see README's CI section)",
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
