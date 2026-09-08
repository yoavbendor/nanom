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
`common.py`) via `--interface`, e.g. `enp1s0f1.2` per the doc:

```sh
uv run sd-server --local-addr fd53:7cb8:383:2::56    --unicast-port 30490 --interface enp1s0f1.2
uv run sd-client --local-addr fd53:7cb8:383:2::1:117 --unicast-port 30490 --interface enp1s0f1.2
```

## Running it under rootless Docker (no sudo required)

If your dev host doesn't give you `sudo` for `ip -6 addr add`/`ip -6 route
add` (both used above for loopback testing), running the two roles as
separate **containers on their own Docker bridge network** sidesteps that
entirely: each container gets its own real IPv6 address, so none of the
loopback-sharing workarounds (`--unicast-port`, the multicast route, extra
addresses on `lo`) are needed -- `docker-compose.yml` runs the demo at its
real addresses (`fd53:7cb8:383:2::56` / `::1:117`) with plain `--unicast-port
30490` on both, exactly as a real deployment would.

```sh
module load docker-rootless/<version>   # however your site activates it; check `module avail docker-rootless`
docker compose build
```

**Validate the environment first** (30 seconds, no sudo, no image beyond
what you just built): confirms this Docker setup actually delivers IPv6
multicast between containers on the bridge, using the same standalone
script CI uses to diagnose GitHub-hosted runners (which, unlike a normal
Docker bridge, turned out not to support this at all -- see the CI
section below). Exits 0 if the multicast packet was received, 1 if not:

```sh
docker compose --profile smoketest up --abort-on-container-exit --exit-code-from mcast-recv
```

Then run the real demo:

```sh
docker compose up --build
```

Expected log sequence is the same as the plain `uv run` case above, just
prefixed with each container's name. Stop with Ctrl+C or `docker compose down`.

**If the smoke test fails** (some rootless Docker network backends restrict
multicast more than others): fall back to the CI-only unicast mode --
add `--peer-addr fd53:7cb8:383:2::1:117` to `sd-server`'s command and
`--peer-addr fd53:7cb8:383:2::56` to `sd-client`'s in `docker-compose.yml`.
Since each container already has its own real address (unlike the loopback
case CI runs in), this needs none of the port-splitting either --
`create_unicast_sd_endpoint` in `common.py` still exercises the full real
SD negotiation and timing state machine, just point-to-point instead of via
multicast.

**Why this should work in rootless mode, and what I could and couldn't
verify:** container-to-container traffic on a shared Docker bridge network
is ordinary Linux bridging inside the daemon's own network namespace --
unlike loopback multicast on a virtualized CI runner, and unlike the
host<->container path, it doesn't go through slirp4netns/pasta (those only
mediate the bridge's uplink to the outside world), so the same bridge-level
multicast delivery that works in rootful Docker should work in rootless
mode too. I could not run this end-to-end myself, for a simpler reason than
Docker specifics: this session's own sandbox kernel has **no IPv6 support at
all** (`socket.socket(AF_INET6, ...)` itself fails with `EAFNOSUPPORT`,
confirmed independently several times this session, including via Docker's
own `--ipv6` bridge creation failing here the same way) -- so nothing IPv6,
containerized or not, is testable in this specific environment, regardless
of Docker/rootless behavior. That's a property of this sandbox, not of your
dev host, which almost certainly has ordinary IPv6 support. The smoke test
above is the fast way to get a real answer on your host before trusting the
full demo to it -- please let me know what it reports so this section can
be corrected if rootless Docker's multicast support turns out to be more
restricted than reasoned here.

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
