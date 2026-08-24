# nestwg

[![CI](https://github.com/mcrmck/nestwg/actions/workflows/ci.yml/badge.svg)](https://github.com/mcrmck/nestwg/actions/workflows/ci.yml)
[![Security](https://github.com/mcrmck/nestwg/actions/workflows/security.yml/badge.svg)](https://github.com/mcrmck/nestwg/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`nestwg` is a Linux VPN client that sends ordinary host traffic through two or
more WireGuard VPNs in sequence. It presents one WireGuard interface to the
host while keeping the preceding tunnel interfaces in internal network
namespaces.

```text
application packet
  -> WireGuard(exit)
    -> WireGuard(entry)
      -> physical network
```

It is provider-neutral. A VPN can combine self-hosted
servers and commercial VPN providers as long as every hop supplies a standard
WireGuard client configuration and permits traffic to the next hop.

## Status

This repository is a pre-release technical preview. The primary workflow feels
like `wg-quick`: `up` connects the nested chain and changes host routing, normal
applications use it, and `down` restores the previous routing state.

## Design goals

- Linux kernel WireGuard for the data plane
- no custom cryptography
- two or more independently configured hops
- safe composition of self-hosted and commercial peers
- default-route and selected-CIDR host routing with leak protection
- transactional setup and cleanup
- inspectable plans before any privileged changes
- explicit threat model and conservative privacy claims

## Quick start

```sh
sudo install -d -m 755 /etc/nestwg
sudo install -m 600 chain.yaml /etc/nestwg/example.yaml
sudo nestwg doctor
nestwg validate example
sudo nestwg up example
```

NestWG configures every VPN hop, exposes the final device, and returns to the
existing shell:

```text
VPN "example" is up as nwg-example (default host routing)
```

Continue using the same shell and applications. `ip address` shows the
host-visible device and `curl https://icanhazip.com` should show the final VPN
hop's public address. Disconnect with:

```sh
sudo nestwg down example
```

`spec.hostRouting.mode` selects `default`, `selected`, or `isolated`. Default
mode uses a dedicated policy table, marks the outer WireGuard socket so it
continues to use the physical route, and installs an OUTPUT kill switch.
Selected mode installs only the configured CIDRs plus lower-priority
unreachable routes. In either host-routing mode, loss of the VPN interface
cannot silently fall back to the ordinary Internet route.

Set `spec.dns` when the host resolver should follow the VPN. Omitting it leaves
the existing host DNS configuration unchanged and may leak DNS queries in
default-route mode.

Routing can be overridden for one invocation:

```sh
sudo nestwg up --default-route chain.yaml
sudo nestwg up --route 10.0.0.0/8 --route 203.0.113.7/32 chain.yaml
sudo nestwg up --isolated chain.yaml  # diagnostics only; no host traffic
```

Like `wg-quick`, a bare name resolves through a conventional configuration
directory: `nestwg up example` loads `/etc/nestwg/example.yaml`. An explicit
path works everywhere a chain is accepted, and the same reference may be used
for teardown (`nestwg down ./chain.yaml`). Add `--verbose` (or `-v`) to `up`
or `down` to show lifecycle progress; normal output stays concise. Every
command supports `--help`, for example `nestwg up --help`.

Every routed CIDR must be covered by the final peer's `AllowedIPs`. Selected
routes are destination based and affect every host process using the normal
routing table; NestWG does not select by process, user, domain, or port.

Use `nestwg plan chain.yaml` to preview resolved endpoints, interfaces, routes,
and MTUs without changing the host. `sudo nestwg recover example` is available
for conservative cleanup after externally lost runtime state.

The lifecycle is functional but remains pre-release. `up` initiates every
nested handshake and waits up to ten seconds by default. `--wait 0` skips the
readiness check. A pre-mutation recovery record lets `down` finish interrupted
cleanup, while `recover` conservatively removes process-free orphan resources
after externally lost state. Do not rely on this preview as a security or
anonymity boundary yet.

An initial VPN configuration looks like:

```yaml
apiVersion: nestwg.io/v1alpha1
kind: Chain
metadata:
  name: example
spec:
  baseMTU: 1500
  dns:
    - 1.1.1.1
  hostRouting:
    mode: default
  hops:
    - name: entry
      wireguardConfig: ./entry.conf
      outerFamily: ipv4
    - name: exit
      wireguardConfig: ./exit.conf
      outerFamily: ipv4
```

`entry.conf` and `exit.conf` may come from different commercial providers,
self-hosted servers, or any mixture of the two. See
[configuration.md](docs/configuration.md) for interoperability constraints.

## Development prerequisites

- Go 1.27 or newer when building from source
- Linux with network namespace support
- `iproute2`
- `wireguard-tools`
- `iptables` and `ip6tables`
- `resolvconf` or `resolvectl` when `spec.dns` is configured
- Docker with Compose for the privileged integration lab

The integration test container requires `CAP_NET_ADMIN` and access to the
host's WireGuard support. See [integration/README.md](integration/README.md).

## Installation

Tagged releases are configured to publish static Linux binaries and native
Debian packages for amd64 and arm64. Release assets include SHA-256 checksums
and GitHub build-provenance attestations. Verify the downloaded artifacts
before installing them.

Install a release package with:

```sh
sudo dpkg -i nestwg_<version>_<architecture>.deb
```

To build and install from source:

```sh
git clone https://github.com/mcrmck/nestwg.git
cd nestwg
make check
make build
sudo make install
```

Maintainers can build a local Debian package with `make package-deb`; set
`PACKAGE_VERSION` and `PACKAGE_ARCH` when producing a release candidate.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Configuration and provider compatibility](docs/configuration.md)
- [Supported platforms](docs/supported-platforms.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Release process](docs/releasing.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
