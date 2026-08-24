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
  hostRouting:
    mode: selected
    routes:
      - 10.0.0.0/8
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

A bare command-line chain name is loaded from `/etc/nestwg/<name>.yaml`.
Explicit relative or absolute paths are also accepted. For example,
`nestwg up office` and `nestwg up /etc/nestwg/office.yaml` select the same
configuration. `down` accepts either the active chain name or a YAML path and
uses its `metadata.name`.
- `spec.baseMTU` is the starting path MTU. It defaults to 1500.
- `spec.dns` lists host resolvers installed while the VPN is up. NestWG uses
  `resolvconf` or systemd-resolved's `resolvectl` and restores the previous
  resolver state during `down`. Omitting it leaves host DNS unchanged; in
  default mode that may disclose queries outside the VPN. It is rejected with
  isolated mode because no host interface consumes it.
- `spec.hostRouting.mode` is `default`, `selected`, or `isolated`.
- `spec.hostRouting.routes` is required only for `selected` mode.
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
files. Provider DNS settings on intermediate hops are ignored; host DNS
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

## Host routing

Default mode sends every supported address family through the nested VPN:

```yaml
hostRouting:
  mode: default
```

The final peer must contain `0.0.0.0/0`, `::/0`, or both in `AllowedIPs`.
NestWG installs a dedicated policy-routing table rather than replacing the
host's existing default route. The outer WireGuard socket receives the same
firewall mark as that table, allowing its encrypted packets to retain the
physical route. Unmarked non-local traffic that does not leave through the
visible NestWG interface is rejected by an OUTPUT kill switch.

Selected mode routes only explicit destinations:

```yaml
hostRouting:
  mode: selected
  routes:
    - 10.0.0.0/8
    - 203.0.113.7/32
```

Every requested CIDR must be wholly contained by an `AllowedIPs` prefix on the
final WireGuard peer. NestWG canonicalizes CIDRs, rejects duplicates, and
refuses to replace an existing exact host route. Less-specific routes,
including the ordinary default route, remain intact. Each active selected
route has a lower-priority unreachable alternative so interface loss remains
fail-closed.

Host routing applies to all applications. It does not select traffic by
process, user, domain name, or port. `nestwg down` removes the host interface,
active routes, policy rules, firewall rules, DNS configuration, and internal
namespaces transactionally.

Isolated mode constructs the chain without exposing it to host traffic. It is
intended for diagnostics and integration work:

```yaml
hostRouting:
  mode: isolated
```

The configured mode can be overridden for one invocation with
`--default-route`, repeated `--route CIDR`, or `--isolated`. These options are
mutually exclusive.
