# someip-sd-sim

A local SOME/IP Service Discovery (SD) demo: an independent server process
and client process, both built on [pysomeip](https://github.com/afflux/pysomeip)
(`someip` on PyPI), negotiating a real AUTOSAR SD handshake over IPv6
loopback and logging every step. This is a rehearsal for the C++
`nanom_someip_sd` sensor simulator (planned in
[nanom](https://github.com/yoavbendor/nanom)), not the simulator itself.

[![CI](https://github.com/yoavbendor/someip-sd-sim/actions/workflows/ci.yml/badge.svg)](https://github.com/yoavbendor/someip-sd-sim/actions/workflows/ci.yml)

## Real network configuration this demo models

Service IDs, eventgroup IDs, multicast addresses/ports and two real-sensor
quirks below come from a vSomeIP-based LRR sensor simulator / QNX ECU
integration doc. The SD multicast address (`ff14::4:0`) independently
matches what the tshark reverse-engineering pass found in a live capture,
which is good corroboration that these are the real, deployed values.

| Role | Address | Port | Notes |
|---|---|---|---|
| Sensor simulator (server) | `fd53:7cb8:383:2::56` | 42810 | source port for all its data |
| ECU (client) | `fd53:7cb8:383:2::1:117` | 42809 | destination for all sensor data |
| SD multicast | `ff14::4:0` | 30490 | Service Discovery announcements |
| Measurements multicast | `ff14::4:5` | 42809 | service 0x60d4, eventgroup 0x8002 |
| Status multicast | `ff14::4:3` | 42809 | service 0x60d6, eventgroup 0x8001 |

Two services are offered, each with its own eventgroup and its own
dedicated multicast group (`common.py`'s `SERVICES`):

- **Measurements** (`0x60d4` / eventgroup `0x8002`): the real notification
  is 1444+ variable bytes and SOME/IP-TP segmented, sent roughly every
  65ms. pysomeip has no TP support, so this demo uses a small fixed-size
  synthetic payload instead -- TP segmentation is a C++-port concern (see
  the project plan).
- **Status** (`0x60d6` / eventgroup `0x8001`): a fixed 116-byte
  notification sent ~30ms after each Measurements notification, using a
  **static session ID of `0x0000`** on every message (the real sensor does
  this; a stock vSomeIP increments it, requiring a patch -- see below).
  This demo replicates the static session ID directly, since it's just a
  field value, not a structural limitation.

Both services' notifications are real `someip.header.SOMEIPHeader`-framed
messages (service_id/method_id/session_id/message_type=NOTIFICATION), not
raw bytes -- so the client's log shows the actual on-wire session ID,
making the Status quirk directly visible in the transcript.

**Not yet confirmed:** the two events' own method/event IDs. The source
doc gives service and eventgroup IDs, not method IDs; `common.py` marks
its `event_id` values as placeholders (`# TODO`) until the tshark/ARXML
work turns up the real ones.

## Why the six vSomeIP patches don't need replicating here

The source doc also describes six patches applied to vSomeIP 3.5.9 to get
its own C++ sensor simulator working. Most are specific to vSomeIP's own
implementation, not to the AUTOSAR protocol, so this pysomeip-based demo
doesn't need them:

- **Multi-IP SD / routing / endpoints** (patches 1-3): needed because
  vSomeIP defaults to sending all SD from one global source IP even when
  services are configured on different IPs. The real sensor simulator box
  only uses one IP (`::56`) for all its services, so this doesn't apply
  here (or to it, really -- the patch was about vSomeIP's own
  architecture assuming one-IP-per-process in a place this deployment
  didn't want that).
- **Session ID override** (patch 5) and **reboot detection** (part of
  patch 1): the session ID quirk is replicated directly above; reboot
  detection isn't exercised by this demo (both processes start once, no
  restart-mid-run scenario).
- **IPv6 multicast fix** (patch 4) -- `if_nametoindex(device)` instead of
  `scope_id()` for choosing the multicast join interface -- **is** a real,
  protocol-adjacent networking concern (getting multicast to join on the
  correct VLAN interface rather than whatever `scope_id()` happens to
  return for a global address), just not one that affects this loopback
  demo. `common.py`'s socket helpers already join/send via an explicit
  `if_nametoindex(interface)` for the same reason. This is worth carrying
  forward as a known requirement for the C++ `nanom_someip_sd` port.

## Running it

Linux's `lo` interface gets no IPv6 multicast route (`ff00::/8`) by
default, so any multicast `sendto()` over loopback fails with
`ENETUNREACH` until you add one (real network interfaces don't need
this -- it's loopback-testing-only, and it's what CI does too):

```sh
sudo ip -6 route add ff00::/8 dev lo
```

```sh
uv sync
uv run sd-server        # terminal 1
uv run sd-client         # terminal 2
```

Expected log sequence: server's Initial-Wait delay, its first `Offer` for
each service, repetition-phase offers, the client's `Find` (or immediate
discovery if it starts after the first Offer), `Subscribe`/`SubscribeAck`
for each eventgroup logged on both sides, then Measurements and Status
notifications arriving at the client roughly every 65ms (Status ~30ms
after Measurements). Stop either process with Ctrl+C; the server logs its
`StopOffer`s and the client logs its unsubscribes.

## Why two different SD unicast ports (`--unicast-port`)

Two real hosts each have their own IP address, so both can bind their SD
socket to the same well-known port (UDP/30490) without conflict. Running
both roles as two processes on **one** loopback address doesn't have that
luxury: if both bound a unicast socket to `(::1, 30490)`, the kernel's
`SO_REUSEPORT` load-balancing would deliver packets to whichever of the
two sockets it hashes to -- not necessarily the right one -- since every
packet in this demo happens to hash to the same 4-tuple. `common.py`
sidesteps this by giving the server and client independent unicast SD
ports (30490 / 30491) while keeping the multicast leg on the shared SD
port 30490, which every participant must use to see each other's
Offers/Finds. This is a loopback-demo-only wrinkle; against real hosts
each side just uses 30490.

If you'd rather demo it with genuinely separate addresses (closer to how
the real sensor/ECU pair looks), add a second loopback address instead
and drop `--unicast-port`:

```sh
sudo ip -6 addr add fd00::1/128 dev lo   # server identity
sudo ip -6 addr add fd00::2/128 dev lo   # client identity
uv run sd-server --local-addr fd00::1 --unicast-port 30490
uv run sd-client --local-addr fd00::2 --unicast-port 30490
```

(Requires `CAP_NET_ADMIN`; not available in every sandboxed environment.)

### Pointing this demo at the real network

Once the real VLAN is reachable, run each role bound to its real address
on the real interface (see `REAL_SENSOR_ADDR`/`REAL_ECU_ADDR` in
`common.py`), with `INTERFACE` in `common.py` changed from `"lo"` to the
real interface (`enp1s0f1.2` per the doc):

```sh
uv run sd-server --local-addr fd53:7cb8:383:2::56   --unicast-port 30490
uv run sd-client --local-addr fd53:7cb8:383:2::1:117 --unicast-port 30490
```

## CI

`.github/workflows/ci.yml` runs on every push/PR:

1. **Offline SD wire round-trip check** (`scripts/offline_roundtrip_check.py`)
   -- builds the same OfferService/Subscribe entries and data notifications
   the demo builds and confirms they round-trip through pysomeip's own SD
   serialize/parse. No networking, runs anywhere.
2. **A live run of `sd-server`/`sd-client`** as real background processes,
   over real IPv6 sockets on the runner's loopback -- but **unicast**, via
   `--peer-addr ::1` on both, not the demo's default multicast. GitHub-hosted
   `ubuntu-latest` runners were found, empirically, not to deliver IPv6
   multicast traffic on `lo` between processes **at all** -- confirmed with
   a raw, pysomeip-independent socket test (`scripts/mcast_smoke_test.py`,
   still run as a non-blocking diagnostic in CI): join succeeds, send
   succeeds, receive times out with zero packets, even with the multicast
   route added and `IPV6_MULTICAST_LOOP` explicitly enabled. That's a
   runner/hypervisor networking limitation, not something fixable from
   inside the VM. `--peer-addr` (see `create_unicast_sd_endpoint` in
   `common.py`) sidesteps it entirely: `ServiceDiscoveryProtocol`'s
   `default_addr` is pointed at the known peer instead of a multicast
   group, so every send that would otherwise go to the multicast group goes
   directly to that peer -- still 100% real sockets/asyncio/pysomeip SD
   code and the real timing state machine, just not real multicast fan-out.
   The demo's default (no `--peer-addr`) behavior is untouched and stays
   multicast-based, matching the real vendor deployment, for local or
   self-hosted-runner use where multicast actually works.
3. Both logs are grepped for the expected sequence -- `Offer`, `Subscribe`,
   `SubscribeAck`, and at least one received notification for each of
   Measurements and Status. The job fails (and uploads all logs as
   artifacts) if any expected line is missing within the timeout.

## Verifying against nanom_shark's own SOME/IP-SD decoder

For an independent sanity check that the wire bytes this demo produces are
actually spec-correct SOME/IP-SD, capture the loopback traffic and decode
it with [nanom_shark's](https://github.com/yoavbendor/nanom) decoder
(clone that repo separately -- it's not a dependency of this one):

```sh
tcpdump -i lo -w /tmp/sd_demo.pcap 'udp port 30490 or udp port 42809' &
# run the demo for a few seconds, then stop tcpdump
git clone https://github.com/yoavbendor/nanom /tmp/nanom
cmake -B /tmp/nanom/build -S /tmp/nanom && cmake --build /tmp/nanom/build --target nanom_shark_cli -j
/tmp/nanom/build/nanom_shark_cli /tmp/sd_demo.pcap --json /tmp/sd_demo.ndjson
```

## Relationship to the C++ port

This demo is deliberately throwaway/reference code: once the two
placeholder event IDs are confirmed (from the tshark/ARXML
reverse-engineering work against the actual vendor MCU), this Python
server becomes the initial simulator's SD negotiator for real integration
testing. Only after that does the C++ rewrite (`nanom_someip_sd`, a
sibling repo to this one) begin -- carrying forward the multicast-join-
interface lesson from the vSomeIP patches above, and adding real
SOME/IP-TP segmentation support for the Measurements payload, neither of
which this Python demo needed to implement.
