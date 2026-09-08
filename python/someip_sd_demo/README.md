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

### Running it on WSL2 (confirmed working, `--peer-addr` required)

**Confirmed end-to-end on a WSL2 Ubuntu host running as root:** a real
IPv6 kernel is present there (unlike some bare-metal dev hosts -- see the
Docker section's prerequisite check below), so the plain `uv run` path
above works with one change: WSL2's virtualized network stack, like
GitHub-hosted CI runners, does **not** deliver loopback IPv6 multicast
between two separate processes (confirmed by running both roles at
`--log-level DEBUG` for 20s+ with zero SD traffic received on either
side, despite both processes being alive and sending). This is the exact
same limitation the CI job already works around -- see the CI section
below -- so the fix is the same: add `--peer-addr` to run SD unicast,
point-to-point, instead of the default multicast:

```sh
cd ~/someip-sd-sim
git pull
uv sync

# no sudo needed if you're already root; harmless if the route exists already
ip -6 route add ff00::/8 dev lo

uv run sd-server --peer-addr ::1 --log-level DEBUG > /tmp/sd-server.log 2>&1 &
SERVER_PID=$!
sleep 2
uv run sd-client --peer-addr ::1 --log-level DEBUG > /tmp/sd-client.log 2>&1 &
CLIENT_PID=$!

sleep 45   # give the Subscribe/SubscribeAck cycle time to settle, like CI does
kill $SERVER_PID $CLIENT_PID
grep -E "Subscribe|Offer|Find|sent notification" /tmp/sd-*.log
```

This has been run and confirmed on WSL2: real `FindService`/`OfferService`
exchange with the real vendor service/eventgroup IDs and multicast
options, `Subscribe`/`SubscribeAck` for both eventgroups, and Status/
Measurements notifications streaming afterward (including the real
static-session-id-`0x0000` quirk on Status) -- the full SD negotiation,
end to end, no containers involved. No `--unicast-port` split is needed
here since both roles use their own real default ports against `::1`;
`--peer-addr` alone is what routes around the multicast gap.

If you don't have a working IPv6 kernel or aren't running as root on your
WSL2 (or other) host, fall back to the rootless-Docker/Podman path below
instead -- but note its own caveat: Podman 4.2.1's CNI backend has a
separate, unrelated IPv6-assignment bug documented in that section.

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

**Prerequisite, check this first (5 seconds, no sudo):** the host kernel
itself needs IPv6 support, independent of Docker/rootless entirely --
nothing here (or anywhere else in this demo) can create an `AF_INET6`
socket without it, in a container or otherwise. Confirmed missing on at
least one real site so far, and the failure mode is specific enough to
recognize immediately:

```sh
python3 -c "import socket; socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)"
# OSError: [Errno 97] Address family not supported by protocol
cat /proc/sys/net/ipv6/conf/all/disable_ipv6   # "No such file or directory"
ip -6 addr show                                 # prints nothing, not even ::1
```

That combination means the `ipv6` kernel module isn't loaded on the host
at all (not a sysctl toggle, not a rootless-netns quirk -- the whole IPv6
stack is absent from the running kernel), which needs `modprobe ipv6` --
root, so not fixable from a rootless setup. If you hit this: ask your
site admin to enable IPv6 on the host, or find a different host that has
it (a colleague's machine, a VM, or eventually the real target VLAN,
which almost certainly already has IPv6 since that's what the actual
AUTOSAR system runs on). In the meantime, `scripts/offline_roundtrip_check.py`
needs no networking at all, and CI is your live, verified proof of the
networked behavior -- both the loopback and Docker-bridge-multicast jobs
are green (see the CI section below).

If your dev host doesn't give you `sudo` for `ip -6 addr add`/`ip -6 route
add` (both used above for loopback testing), running the two roles as
separate **containers on their own Docker bridge network** sidesteps that
entirely: each container gets its own real IPv6 address, so none of the
loopback-sharing workarounds (`--unicast-port`, the multicast route, extra
addresses on `lo`) are needed -- both roles run at their real addresses
(`fd53:7cb8:383:2::56` / `::1:117`) with plain `--unicast-port 30490` on
both, exactly as a real deployment would.

```sh
module load docker-rootless   # however your site activates it; check `module avail docker-rootless`
```

**Which tooling you have varies by site** -- some rootless Docker installs
ship the `docker compose` CLI plugin, some ship the older standalone
`docker-compose` binary instead, and some (e.g. a bare `docker` from a
module with no plugins layered on) ship neither. Check once:

```sh
docker compose version    # CLI plugin?
which docker-compose      # standalone binary?
```

**If either exists**, use `docker-compose.yml` in this repo (same commands
either way -- swap `docker compose` for `docker-compose` if that's what you
have):

```sh
docker compose build
docker compose --profile smoketest up --abort-on-container-exit --exit-code-from mcast-recv   # validate first, see below
docker compose up --build       # then the real demo
docker compose down             # stop
```

**If neither exists** (confirmed the case on at least one real site so
far: `docker` with no `compose` subcommand and no standalone binary),
`scripts/docker_run_demo.sh` and friends do the exact same thing with
plain `docker build`/`network create`/`run` -- no compose needed at all:

```sh
scripts/docker_smoke_test.sh    # validate first, see below
scripts/docker_run_demo.sh      # then the real demo
docker logs -f sd-server        # tail either container's log
docker logs -f sd-client
scripts/docker_stop_demo.sh     # stop and clean up
```

**Validate the environment first** (30 seconds, no sudo, no image beyond
what you just built): confirms this Docker setup actually delivers IPv6
multicast between containers on the bridge, using the same standalone
probe script (`scripts/mcast_smoke_test.py`) either path runs. CI's own
Docker job (`docker-compose-multicast` in `.github/workflows/ci.yml`)
confirmed this works end-to-end on GitHub-hosted runners -- a genuinely
different result from bare loopback multicast on the same runners, which
doesn't work at all (see the CI section below): a Docker bridge is a real
L2 device between two containers, whose traffic never leaves the VM's own
kernel netns, unlike loopback's special-cased handling. That's real (if
rootful) evidence the underlying mechanism works; the smoke test confirms
it also holds for your specific rootless setup. Exits 0 if the multicast
packet was received, 1 if not.

Expected log sequence, either path, is the same as the plain `uv run` case
above, just prefixed with each container's name.

**If the smoke test fails** (some rootless Docker network backends restrict
multicast more than others): fall back to the CI-only unicast mode --
add `--peer-addr fd53:7cb8:383:2::1:117` to the server command and
`--peer-addr fd53:7cb8:383:2::56` to the client command (in
`docker-compose.yml`, or in `docker_run_demo.sh` if you're on the
plain-`docker` path). Since each container already has its own real
address (unlike the loopback case CI runs in), this needs none of the
port-splitting either -- `create_unicast_sd_endpoint` in `common.py` still
exercises the full real SD negotiation and timing state machine, just
point-to-point instead of via multicast.

**Why this should work in rootless mode, and what's actually confirmed:**
container-to-container traffic on a shared Docker bridge network is
ordinary Linux bridging inside the daemon's own network namespace --
unlike loopback multicast on a virtualized CI runner, and unlike the
host<->container path, it doesn't go through slirp4netns/pasta (those only
mediate the bridge's uplink to the outside world). CI has since confirmed
this reasoning holds in practice, not just in theory: GitHub Actions'
`docker-compose-multicast` job runs this exact `docker-compose.yml` in its
default (multicast) mode on a fresh `ubuntu-latest` runner and it passes --
hundreds of real notifications exchanged, genuine multicast SD traffic
logged -- on the very same class of runner where bare loopback multicast
does not work at all. That's rootful Docker, though, not rootless: I
couldn't verify the rootless case myself (this session's own sandbox
kernel has no IPv6 support whatsoever -- confirmed independently several
times, including Docker's own `--ipv6` bridge creation failing here the
same way -- so nothing IPv6 was testable here regardless of Docker/rootless
specifics). The smoke test above is the fast way to get a real answer for
rootless specifically on your host; please let me know what it reports so
this section can be corrected if rootless Docker's multicast support turns
out to be more restricted than rootful.

### Podman instead of Docker

`scripts/docker_run_demo.sh`, `docker_smoke_test.sh` and
`docker_stop_demo.sh` all work with Podman too -- set `CONTAINER_ENGINE=podman`
(they default to `docker`; Podman's CLI is close enough to Docker's that
the exact same `build`/`network create`/`run`/`wait`/`logs` calls apply):

```sh
module load podman/<version>   # however your site activates it
export CONTAINER_ENGINE=podman
scripts/docker_smoke_test.sh    # validate first
scripts/docker_run_demo.sh      # then the real demo
podman logs -f sd-server
podman logs -f sd-client
scripts/docker_stop_demo.sh     # stop and clean up
```

If your site's Podman ships `podman-compose` or a `podman compose`
subcommand, `docker-compose.yml` works there too (same commands as the
Docker case, swap `docker compose`/`docker-compose` for `podman
compose`/`podman-compose`).

Podman doesn't change anything about the IPv6 prerequisite above:
containers share the host kernel's network stack directly regardless of
which engine manages them, so if `AF_INET6` socket creation fails on the
host, it fails identically under Podman -- this isn't a Docker-specific
gap. Podman is, if anything, slightly better suited to the no-sudo
constraint (it's rootless by design, not rootless-as-a-mode-on-top-of-a
normally-rootful-daemon like Docker), so once the host kernel has IPv6,
it's a reasonable first thing to try.

**Confirmed broken on Podman 4.2.1's CNI network backend specifically:**
IPv6 static address assignment (`--network NET:ip6=ADDR`) silently does
nothing on this Podman version -- the container's `eth0` only ever gets
the kernel's automatic link-local address (`fe80::...`), never the
requested global address, which then makes any `sendto()` to a
global/ULA-scoped destination fail with `OSError: [Errno 99] Cannot
assign requested address` (`EADDRNOTAVAIL`), since the interface has no
source address in that scope at all. Confirmed directly:

```sh
podman run --rm --network "someip-sd-net:ip6=fd53:7cb8:383:2::99" \
  --entrypoint cat someip-sd-sim /proc/net/if_inet6
# only fe80:: (eth0) and ::1 (lo) -- the requested ::99 never shows up
```

This lines up with the recurring `plugin firewall does not support
config version "1.0.0"` warning Podman 4.2.1 prints on every network
command -- its bundled CNI plugin config is generating a config version
its installed CNI plugin binaries don't understand, and it's plausible
that's breaking more than just the named `firewall` plugin (the IPAM
plugin included). This is a Podman/CNI installation issue, not something
`docker_run_demo.sh`/`docker_smoke_test.sh` can work around by changing
flags -- the network namespace genuinely has no usable address. Fixing
it for real needs either a newer Podman (the `netavark` backend replaces
CNI and doesn't have this bug) or matching/upgrading the host's
`containernetworking-plugins` package to what Podman 4.2.1 expects.

If you're already running as root and the host kernel has IPv6 (check
the prerequisite above) -- e.g. exactly this WSL2-as-root case -- skip
containers entirely and use the plain `uv run` path from "Running it"
above instead: it needs neither Docker's IPv6-bridge support nor
Podman's CNI networking, and is already the most-verified path (proven
locally and in CI).

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

A second job, `docker-compose-multicast`, answers a different question:
does a **Docker bridge** fare better than bare loopback for multicast on
the same class of runner? It builds `docker-compose.yml`, runs the smoke
test between two throwaway containers, then runs the real demo in its
**default multicast mode** (no `--peer-addr`) and checks the same
sequence. Yes, it does: this job passes, with real multicast SD traffic
and hundreds of notifications exchanged between the two containers --
good evidence for the reasoning in the Docker section above.
`continue-on-error` at the job level, so it's informational and can never
block the primary (already green) job.

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
