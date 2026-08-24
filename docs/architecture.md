# Architecture

## Data-plane model

`nestwg` uses a Linux-specific WireGuard property: a WireGuard UDP socket
remains in the network namespace where its interface was created, even after
the interface is moved to another namespace.

For a two-hop chain, the topology is:

```text
host namespace
  physical interface
  socket owned by wg-entry
        |
        v
transit namespace
  wg-entry interface and decrypted outer packets
  socket owned by wg-exit
        |
        v
payload namespace
  wg-exit interface and application traffic
```

The outer interface is created in the host namespace and moved into the
transit namespace. The inner interface is created in the transit namespace and
moved into the payload namespace. Consequently, the inner WireGuard socket
uses the transit namespace's default route through the outer tunnel.

The construction repeats for additional hops. Hop `n` is created in the
plaintext namespace exposed by hop `n-1`, then moved one namespace inward.

## Packet transformation

For an entry and exit chain:

```text
payload namespace:
  IP(destination) -> WG-exit[IP(destination)]

transit namespace:
  UDP(exit endpoint, WG-exit ciphertext)
    -> WG-entry[UDP(exit endpoint, WG-exit ciphertext)]

physical network:
  UDP(entry endpoint, WG-entry ciphertext)
```

The entry observes the client network address and the exit WireGuard endpoint.
It does not receive the application packet or final destination address. The
exit receives application traffic but observes the entry's public address, not
the client's address.

## Control-plane phases

The implementation separates planning from mutation:

1. Parse and validate the chain document.
2. Import and validate each WireGuard configuration.
3. Resolve all public endpoints before namespace changes.
4. Calculate namespace names, pinned endpoints, routes, and per-layer MTUs.
5. Display or serialize the same plan consumed by execution.
6. Acquire an exclusive chain lock.
7. Apply operations transactionally from the outermost hop inward.
8. Verify handshakes without permitting payload traffic to bypass the chain.
9. Move the innermost interface onto the host and install the selected or
   default host-routing policy.
10. Remove host policy and nested resources in reverse order during `down`.

State required for cleanup is written atomically beneath `/run/nestwg` with an
exclusive per-chain lock. A `creating` recovery record is durable before the
first kernel mutation and changes to `active` only after setup succeeds.
Private keys are never copied into the state file or printed in plans.

All planned namespace names are collision-checked before the creating-phase
record reserves them. If automatic rollback is incomplete, NestWG retains that
record and instructs the operator to retry with `down`; it never reports the
partial chain as active.

## Routing invariants

- In isolated diagnostic mode, the payload namespace contains only loopback
  and the innermost WireGuard interface.
- Every transit namespace routes the next hop's WireGuard socket through the
  immediately preceding WireGuard interface.
- Public endpoints are resolved and pinned before setup. Transit namespaces do
  not resolve endpoint hostnames.
- Chain DNS is applied to the host-visible interface through `resolvconf` or
  systemd-resolved and restored during `down`.
- Failure of a hop leaves no route around the nested chain.
- Host routing moves the innermost WireGuard interface into the host
  namespace. Its UDP socket remains in its original transit namespace, so
  encryption still exits through every preceding VPN layer.
- Every selected host CIDR has a live route through that WireGuard device and
  a lower-priority unreachable route. Loss of the device removes the live
  route but leaves the unreachable route to prevent default-route fallback.
- Existing exact selected routes are never replaced.
- Default mode uses a dedicated routing table. A policy rule preserves
  non-default routes from the main table, sends unmarked traffic through the
  final interface, and lets the marked outer WireGuard socket retain the
  physical default route.
- Default-mode OUTPUT firewall rules reject non-local traffic that would leave
  outside the visible VPN interface without the outer socket's mark.
- `down` deliberately removes DNS, host routes, rules, and firewall state
  before returning the final interface and deleting internal namespaces.

## MTU calculation

WireGuard adds 60 bytes when transported over IPv4 and 80 bytes over IPv6:

```text
IPv4: 20 IP + 8 UDP + 32 WireGuard = 60 bytes
IPv6: 40 IP + 8 UDP + 32 WireGuard = 80 bytes
```

Starting from a configured or discovered physical path MTU, each inward
interface subtracts the overhead of its outer transport. A two-hop IPv4 chain
over a 1500-byte path therefore has a maximum calculated payload MTU of 1380.
The runtime will eventually support path-MTU discovery and a configurable
safety margin for cellular and other constrained networks.

## Privilege model

Creating network namespaces and configuring WireGuard requires root or
equivalent capabilities. The CLI is short-lived and has no privileged daemon.
It validates names, paths, addresses, routes, and endpoints before mutation and
uses netlink APIs for devices, addresses, routes, and policy rules. Default
routing uses narrowly scoped iptables/ip6tables OUTPUT rules. Host DNS is
changed only through `resolvconf` or systemd-resolved. No forwarding or NAT is
needed for host routing.
