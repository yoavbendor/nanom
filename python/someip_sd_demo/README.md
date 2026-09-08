# someip-sd-demo

A local SOME/IP Service Discovery (SD) demo: an independent server process
and client process, both built on [pysomeip](https://github.com/afflux/pysomeip)
(`someip` on PyPI), negotiating a real AUTOSAR SD handshake over IPv6
loopback and logging every step. This is a rehearsal for the C++
`nanom_someip_sd` sensor simulator, not the simulator itself -- see the
project plan for the bigger picture.

## What it demonstrates

- **server.py** offers a SOME/IP service with one eventgroup whose
  OfferService entry carries a real `IPv6MulticastOption` -- the exact
  AUTOSAR mechanism a sensor uses to tell an ECU "subscribe to this
  eventgroup and I'll stream you data on `[ff14::5]:30510`".
- The server runs the **real AUTOSAR SD timing state machine** (Initial
  Wait → Repetition → Main phase, via pysomeip's `ServiceInstance`), and
  answers `FindService`/`SubscribeEventgroup` reactively.
- **client.py** finds the service, auto-subscribes to its eventgroup, joins
  the advertised IPv6 multicast group, and logs every sensor event it
  receives.
- Once subscribed, the server streams 5 synthetic sensor readings (one
  per event ID, modeling the project's 5 real sensor source addresses --
  see `common.py`) to the multicast group every second.

## Why pysomeip for both sides (not two different libraries)

The other candidate, [someipy](https://github.com/chrizog/someipy), is
hardcoded to IPv4 at its socket layer and can't run an IPv6 demo at all.
No other maintained, IPv6-capable pure-Python SOME/IP-SD implementation
was found. Using one library for both roles trades away "two independent
implementations can't silently agree on a bug" in exchange for actually
having a working IPv6 demo now -- an explicit, accepted tradeoff (see the
project plan for the full writeup).

## Running it

```sh
uv sync
uv run sd-server        # terminal 1
uv run sd-client         # terminal 2
```

Expected log sequence: server's Initial-Wait delay, its first `Offer`,
repetition-phase offers, the client's `Find` (or immediate discovery if it
starts after the first Offer), `Subscribe`, `SubscribeAck` logged on both
sides, then sensor events arriving at the client every second. Stop either
process with Ctrl+C; the server logs its `StopOffer` and the client logs
its unsubscribe.

## Why two different SD unicast ports (`--unicast-port`)

Two real ECUs each have their own IP address, so both can bind their SD
socket to the same well-known port (UDP/30490) without conflict. Running
both roles as two processes on **one** loopback address doesn't have that
luxury: if both bound a unicast socket to `(::1, 30490)`, the kernel's
`SO_REUSEPORT` load-balancing would deliver packets to whichever of the
two sockets it hashes to -- not necessarily the right one -- since every
packet in this demo happens to hash to the same 4-tuple. `common.py`
sidesteps this by giving the server and client independent unicast SD
ports (30490 / 30491) while keeping the multicast leg on the shared SD
port 30490, which every participant must use to see each other's
Offers/Finds. This is a loopback-demo-only wrinkle; against a real MCU
each side just uses 30490.

If you'd rather demo it with genuinely separate addresses (closer to how
two real ECUs look), add a second loopback address instead and drop
`--unicast-port`:

```sh
sudo ip -6 addr add fd00::1/128 dev lo   # server identity
sudo ip -6 addr add fd00::2/128 dev lo   # client identity
uv run sd-server --local-addr fd00::1 --unicast-port 30490
uv run sd-client --local-addr fd00::2 --unicast-port 30490
```

(Requires `CAP_NET_ADMIN`; not available in every sandboxed environment.)

## Sensor topology

The five real sensor addresses (`fd53:7cb8:383:2::bd/56/bb/be/bc`) map to
**one** SOME/IP service/instance/eventgroup with a single multicast
option -- SD subscription is per-eventgroup, not per-event, and this also
matches the pattern seen in the real vendor capture (many signals sharing
one multicast group). Each address becomes one event ID multiplexed onto
that eventgroup; see `common.py`'s `SENSORS` list. The addresses are
carried as payload metadata in this demo (logged alongside each event),
not used as actual socket source addresses.

## Verifying against nanom_shark's own SOME/IP-SD decoder

For an independent sanity check that the wire bytes this demo produces are
actually spec-correct SOME/IP-SD, capture the loopback traffic and decode
it with this repo's own decoder:

```sh
tcpdump -i lo -w /tmp/sd_demo.pcap 'udp port 30490 or udp port 30510' &
# run the demo for a few seconds, then stop tcpdump
cmake -B ../../build -S ../.. && cmake --build ../../build --target nanom_shark_cli -j
../../build/nanom_shark_cli /tmp/sd_demo.pcap --json /tmp/sd_demo.ndjson
```

## Relationship to the C++ port

This demo is deliberately throwaway/reference code: once real
service/instance/eventgroup IDs and SD timing are known (from the
tshark/ARXML reverse-engineering work against the actual vendor MCU), this
Python server becomes the initial simulator's SD negotiator for real
integration testing. Only after that does the C++ rewrite
(`nanom_someip_sd`, a sibling repo to this one) begin.
