"""SOME/IP-SD client ("the MCU stand-in"): finds the offered service,
auto-subscribes to its eventgroup per the real AUTOSAR SD state machine
(via pysomeip), joins the IPv6 multicast group advertised in the Offer,
and logs every sensor event it receives.
"""

from __future__ import annotations

import argparse
import asyncio
import logging

from someip.config import Eventgroup, Service
from someip.header import L4Protocols
from someip.sd import ClientServiceListener, format_address

from someip_sd_demo.common import (
    CLIENT_LOCAL_ADDR,
    CLIENT_SD_UNICAST_PORT,
    DATA_MULTICAST_ADDR,
    DATA_PORT,
    EVENTGROUP_ID,
    INSTANCE_ID,
    MAJOR_VERSION,
    SENSOR_PAYLOAD,
    SENSORS,
    SERVICE_ID,
    configure_logging,
    create_split_endpoints,
    open_data_recv_socket,
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

    trsp_u, trsp_m, sd_prot = await create_split_endpoints(
        local_addr=args.local_addr, unicast_port=args.unicast_port
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

    service = Service(SERVICE_ID, INSTANCE_ID, MAJOR_VERSION)
    watch_listener = LoggingServiceListener(log)
    sd_prot.discovery.watch_service(service, watch_listener)

    eventgroup = Eventgroup(
        service_id=SERVICE_ID,
        instance_id=INSTANCE_ID,
        major_version=MAJOR_VERSION,
        eventgroup_id=EVENTGROUP_ID,
        sockname=trsp_u.get_extra_info("sockname"),
        protocol=L4Protocols.UDP,
    )
    sd_prot.discovery.find_subscribe_eventgroup(eventgroup)

    log.info(
        "watching for service=0x%04x instance=0x%04x; will auto-subscribe "
        "eventgroup=0x%04x and join [%s]:%d for sensor data",
        SERVICE_ID,
        INSTANCE_ID,
        EVENTGROUP_ID,
        DATA_MULTICAST_ADDR,
        DATA_PORT,
    )

    data_sock = open_data_recv_socket()
    loop = asyncio.get_event_loop()

    async def receive_loop() -> None:
        while True:
            data = await loop.sock_recv(data_sock, 2048)
            if len(data) != SENSOR_PAYLOAD.size:
                log.warning("received %d bytes of unexpected size on data multicast group", len(data))
                continue
            event_id, seq, value = SENSOR_PAYLOAD.unpack(data)
            label = next((addr for eid, addr in SENSORS if eid == event_id), "unknown")
            log.info(
                "received sensor event=0x%04x (sensor=%s) seq=%d value=%.2f",
                event_id,
                label,
                seq,
                value,
            )

    try:
        await receive_loop()
    except asyncio.CancelledError:
        pass
    finally:
        log.info("shutting down: unsubscribing and closing sockets")
        sd_prot.discovery.stop_find_subscribe_eventgroup(eventgroup)
        sd_prot.stop()
        data_sock.close()
        trsp_u.close()
        trsp_m.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-addr", default=CLIENT_LOCAL_ADDR)
    parser.add_argument("--unicast-port", type=int, default=CLIENT_SD_UNICAST_PORT)
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
