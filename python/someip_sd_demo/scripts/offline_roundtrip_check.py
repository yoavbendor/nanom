"""Offline sanity check: build the same SD entries/messages server.py and
client.py build, and confirm they round-trip correctly through pysomeip's
own SD serialize/parse -- no sockets, no networking, so it runs anywhere
(including this project's CI, and any sandbox with no IPv6 support at
all). Exits non-zero on any assertion failure.
"""
import ipaddress

import someip.header as h
from someip.config import Eventgroup, Service
from someip.header import IPv6EndpointOption, IPv6MulticastOption, L4Protocols, SOMEIPSDHeader

from someip_sd_demo.common import (
    DATA_PORT,
    INSTANCE_ID,
    MAJOR_VERSION,
    MINOR_VERSION,
    SERVICES,
    pack_payload,
    unpack_payload,
)


def main() -> None:
    entries = []
    for service in SERVICES:
        offered = Service(
            service.service_id,
            INSTANCE_ID,
            MAJOR_VERSION,
            MINOR_VERSION,
            options_1=(
                IPv6EndpointOption(address=ipaddress.IPv6Address("::1"), l4proto=L4Protocols.UDP, port=30490),
                IPv6MulticastOption(
                    address=ipaddress.IPv6Address(service.multicast_addr),
                    l4proto=L4Protocols.UDP,
                    port=DATA_PORT,
                ),
            ),
            eventgroups=frozenset({service.eventgroup_id}),
        )
        entries.append(offered.create_offer_entry(ttl=6))

    wire = SOMEIPSDHeader(flag_reboot=True, flag_unicast=True, entries=tuple(entries)).assign_option_indexes().build()
    parsed = SOMEIPSDHeader.parse(wire)[0].resolve_options()
    assert len(parsed.entries) == len(SERVICES)
    for entry, service in zip(parsed.entries, SERVICES):
        assert entry.service_id == service.service_id
        mc = next(o for o in entry.options_1 if isinstance(o, IPv6MulticastOption))
        assert str(mc.address) == service.multicast_addr and mc.port == DATA_PORT
        print(f"OK: {service.name} OfferService + IPv6MulticastOption round-trips")

    for service in SERVICES:
        eg = Eventgroup(
            service_id=service.service_id,
            instance_id=INSTANCE_ID,
            major_version=MAJOR_VERSION,
            eventgroup_id=service.eventgroup_id,
            sockname=("::1", 30491),
            protocol=L4Protocols.UDP,
        )
        sub = eg.create_subscribe_entry(ttl=5)
        assert sub.eventgroup_id == service.eventgroup_id
        print(f"OK: {service.name} Subscribe entry (eventgroup=0x{sub.eventgroup_id:04x})")

    for service in SERVICES:
        session_id = service.static_session_id if service.static_session_id is not None else 42
        payload = pack_payload(service, session_id, seq=7, value=23.5)
        assert len(payload) == service.payload_size
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
        wire_msg = msg.build()
        parsed_msg, rest = h.SOMEIPHeader.parse(wire_msg)
        assert rest == b"" and parsed_msg.payload == payload and parsed_msg.session_id == session_id
        event_id, payload_session, seq, value = unpack_payload(parsed_msg.payload)
        assert event_id == service.event_id and payload_session == session_id and seq == 7
        print(f"OK: {service.name} data notification round-trips ({len(wire_msg)} bytes)")

    print("\nALL OFFLINE CHECKS PASSED")


if __name__ == "__main__":
    main()
