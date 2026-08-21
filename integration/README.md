# Privileged integration lab

The lab builds the NestWG binary and uses `nestwg up` to construct a complete
three-hop mixed IPv4/IPv6 WireGuard chain using eight Linux network namespaces inside a disposable
privileged container:

```text
client-physical -> entry -> middle -> exit -> destination
             |         encrypted nested paths
             +-> transit-1 -> transit-2 -> payload
```

It verifies persistent `up`, `status`, and `down` lifecycle behavior,
application connectivity, and captures packets at both tunnel
boundaries. The entry and middle captures must contain only the next opaque
WireGuard flow, not the final destination. The exit capture must contain the
final destination but must not contain the client's underlay address.

The lab also runs `doctor`, checks the resolver file visible through `exec`,
requires live handshakes before accepting `status` as ready, and injects a
namespace collision before setup. An integration-only build then forces
failures after every major state, namespace, WireGuard, address, link, and route
operation and verifies complete rollback. It separately breaks rollback itself
to prove that recovery state remains usable, and forces each teardown phase to
prove `down` is safely retryable. Release binaries omit the failpoint code.
The first two public endpoints use IPv4 and the innermost endpoint uses IPv6,
exercising mixed-family route and MTU planning.

It additionally attaches IPv4 and IPv6 host CIDRs, verifies ordinary host
traffic remains unchanged, exercises both routes through all three tunnels,
and then moves the
exposed WireGuard device away from the host to prove the unreachable backup
prevents default-route fallback. It verifies that `down` refuses protected
routes and that explicit `detach` restores the device and ordinary routing.

Run it on a Linux Docker host:

```sh
docker compose -f integration/docker-compose.yml up \
  --build --abort-on-container-exit --exit-code-from lab
```

The build uses Go's default TLS settings. If a Docker bridge drops the larger
hybrid-TLS handshake, dependency fetching retries with classical TLS; module
content remains authenticated by TLS and `go.sum`. WireGuard runtime traffic
and NestWG's cryptographic behavior are unaffected by this build-only fallback.

The container requires privileged mode because it creates network namespaces,
veth devices, WireGuard interfaces, forwarding rules, and packet captures. It
uses only project-prefixed namespaces inside the container and deletes those
exact namespaces on exit.

If `ip link add type wireguard` fails, ensure the host kernel has WireGuard
support and that `/lib/modules` is available to the container. The lab tests
the kernel data plane used in production; it intentionally does not fall back
to `wireguard-go`.
