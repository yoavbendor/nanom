"""SOME/IP-SD server ("the sensor gateway"): offers a service with one
eventgroup carrying an IPv6 multicast option, answers FindService/
Subscribe per the real AUTOSAR SD state machine (via pysomeip), and once
at least one client has subscribed, streams 5 synthetic sensor events to
the advertised multicast group.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging

from someip.config import Service
from someip.header import IPv6EndpointOption, IPv6MulticastOption, L4Protocols
from someip.sd import EventgroupSubscription, ServiceInstance, ServerServiceListener, format_address

from someip_sd_demo.common import (
    DATA_MULTICAST_ADDR,
    DATA_PORT,
    EVENTGROUP_ID,
    INSTANCE_ID,
    MAJOR_VERSION,
    MINOR_VERSION,
    SENSOR_PAYLOAD,
    SENSORS,
    SERVER_LOCAL_ADDR,
    SERVER_SD_UNICAST_PORT,
    SERVICE_ID,
    configure_logging,
    create_split_endpoints,
    open_data_send_socket,
)


class SensorEventgroupListener(ServerServiceListener):
    """Logs Subscribe/Unsubscribe and gates whether the data loop sends."""

    def __init__(self, log: logging.Logger):
        self.log = log
        self.active = 0

    def client_subscribed(self, subscription: EventgroupSubscription, source) -> None:
        self.active += 1
        self.log.info(
            "SubscribeEventgroup accepted from %s (eventgroup=0x%04x ttl=%d) "
            "-> %d active subscriber(s)",
            format_address(source),
            subscription.id,
            subscription.ttl,
            self.active,
        )

    def client_unsubscribed(self, subscription: EventgroupSubscription, source) -> None:
        self.active = max(0, self.active - 1)
        self.log.info(
            "client %s unsubscribed/expired (eventgroup=0x%04x) -> %d active subscriber(s)",
            format_address(source),
            subscription.id,
            self.active,
        )


async def run(args: argparse.Namespace) -> None:
    log = configure_logging("server", level=getattr(logging, args.log_level.upper()))

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

    service = Service(
        SERVICE_ID,
        INSTANCE_ID,
        MAJOR_VERSION,
        MINOR_VERSION,
        options_1=(
            # the service's own (conventional) unicast SD endpoint
            IPv6EndpointOption(
                address=ipaddress.IPv6Address(args.local_addr),
                l4proto=L4Protocols.UDP,
                port=args.unicast_port,
            ),
            # the actual point of this demo: an IPv6 multicast option
            # telling subscribers where the sensor data will be sent
            IPv6MulticastOption(
                address=ipaddress.IPv6Address(DATA_MULTICAST_ADDR),
                l4proto=L4Protocols.UDP,
                port=DATA_PORT,
            ),
        ),
        eventgroups=frozenset({EVENTGROUP_ID}),
    )

    listener = SensorEventgroupListener(log)
    instance = ServiceInstance(service, listener, sd_prot.announcer, timings)
    sd_prot.announcer.announce_service(instance)
    sd_prot.start()

    log.info(
        "offering service=0x%04x instance=0x%04x eventgroup=0x%04x; "
        "sensor data will multicast to [%s]:%d once subscribed",
        SERVICE_ID,
        INSTANCE_ID,
        EVENTGROUP_ID,
        DATA_MULTICAST_ADDR,
        DATA_PORT,
    )

    data_sock = open_data_send_socket()
    seq = 0
    try:
        while True:
            await asyncio.sleep(1.0)
            if listener.active <= 0:
                log.debug("no active subscribers yet, not sending sensor data")
                continue
            seq += 1
            for event_id, source_addr in SENSORS:
                value = 20.0 + event_id + 0.1 * (seq % 10)
                payload = SENSOR_PAYLOAD.pack(event_id, seq, value)
                data_sock.sendto(payload, (DATA_MULTICAST_ADDR, DATA_PORT))
                log.info(
                    "sent sensor event=0x%04x (sensor=%s) seq=%d value=%.2f -> [%s]:%d",
                    event_id,
                    source_addr,
                    seq,
                    value,
                    DATA_MULTICAST_ADDR,
                    DATA_PORT,
                )
    except asyncio.CancelledError:
        pass
    finally:
        log.info("shutting down: sending StopOffer and closing sockets")
        sd_prot.announcer.stop_announce_service(instance)
        sd_prot.stop()
        data_sock.close()
        trsp_u.close()
        trsp_m.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-addr", default=SERVER_LOCAL_ADDR)
    parser.add_argument("--unicast-port", type=int, default=SERVER_SD_UNICAST_PORT)
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
