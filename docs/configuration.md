# Configuration and provider compatibility

## Supported hop sources

A chain may contain any mixture of:

- self-hosted WireGuard servers;
- commercial providers exporting standard WireGuard configurations;
- configurations provisioned by an external tool;
- different servers from the same provider, with a weaker independence claim.

The core does not log in to providers or purchase service. Provider adapters
may later automate configuration retrieval without changing the chain model.

## Required provider behavior

Every non-final hop must behave as a normal Internet VPN exit for the next
hop's UDP endpoint. In practice it must:

- allow outbound UDP to the next WireGuard endpoint;
- provide working return-path NAT or routing;
- avoid blocking nested VPN traffic;
- allow a sufficiently low MTU;
- keep the client's WireGuard key active for the lifetime of the chain.

Port-forwarding support is not required. The inner WireGuard client initiates
its handshake outbound through the preceding hop.

Providers that restrict destinations, block VPN protocols, require a
proprietary client, or do not expose peer public keys and endpoints may not be
usable.

## Chain document

The initial API is deliberately small:

```yaml
apiVersion: nestwg.io/v1alpha1
kind: Chain
metadata:
  name: mixed-example
spec:
  baseMTU: 1500
  dns:
    - 10.64.0.1
  hops:
    - name: home-entry
      wireguardConfig: /etc/nestwg/home.conf
      outerFamily: ipv4
    - name: commercial-exit
      wireguardConfig: /etc/nestwg/provider.conf
      outerFamily: ipv4
```

Fields:

- `metadata.name` identifies runtime resources and must be unique on the host.
- `spec.baseMTU` is the starting path MTU. It defaults to 1500.
- `spec.dns` lists resolvers made available only inside the payload namespace.
- `spec.hops` is ordered from outermost/entry to innermost/exit.
- `wireguardConfig` points to a standard WireGuard or `wg-quick` configuration.
- `outerFamily` records whether that hop's public endpoint is reached over
  IPv4 or IPv6 and determines encapsulation overhead.

Relative configuration paths are resolved relative to the chain document, not
the caller's current working directory.

## WireGuard configuration handling

The importer validates interface keys, addresses, peer keys, endpoint, allowed
IPs, optional preshared key, and persistent keepalive. The initial format
requires exactly one peer per hop. It does not execute
arbitrary `PreUp`, `PostUp`, `PreDown`, or `PostDown` commands from imported
files. Provider DNS settings on intermediate hops are ignored; application DNS
is an explicit chain-level decision.

Private key files and chain files should be readable only by their owner.
Plans, logs, status output, and runtime state must redact private and preshared
keys.

NestWG enforces owner-only permissions on every imported WireGuard file because
it contains a private key. The exit peer's `AllowedIPs` must route every
chain-level DNS resolver; otherwise planning fails before networking changes.
Endpoint hostnames are resolved on the host and pinned to the requested outer
address family in the displayed executable plan.

The importer is continuously tested against a sanitized corpus of common
export shapes: minimal hostname endpoints, IPv4 split routes, dual-stack
addresses and routes, preshared keys, disabled keepalives, and `wg-quick`
metadata and hooks. Fixtures use synthetic keys and do not imply endorsement
or certification by any provider.

## Selective host routes

Host attachment is configured at runtime, independently of the chain file:

```sh
sudo nestwg up --wait 10s mixed-example.yaml
sudo nestwg attach mixed-example --route 10.0.0.0/8 --route 203.0.113.7/32
```

Every requested CIDR must be wholly contained by an `AllowedIPs` prefix on the
final WireGuard peer. NestWG canonicalizes CIDRs, rejects duplicates, and
refuses to replace an existing exact host route. Less-specific routes,
including the ordinary default route, are left intact.

The attachment applies to destination routing for all host applications. It
does not select traffic by process, user, domain name, or port. An explicit
`nestwg detach mixed-example` removes both the active VPN routes and their
fail-closed unreachable alternatives. The preview rejects IPv4 and IPv6
default routes in attachment mode; use `connect` for a fail-closed full-tunnel
session. While attached, run applications normally on the host; `exec` and
`shell` resume after `detach` returns the exit device to the payload network.
