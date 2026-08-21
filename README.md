# nestwg

[![CI](https://github.com/mcrmck/nestwg/actions/workflows/ci.yml/badge.svg)](https://github.com/mcrmck/nestwg/actions/workflows/ci.yml)
[![Security](https://github.com/mcrmck/nestwg/actions/workflows/security.yml/badge.svg)](https://github.com/mcrmck/nestwg/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`nestwg` is a Linux VPN client that sends your terminal traffic through two or
more WireGuard VPNs in sequence. Connect once, use your usual shell commands,
and type `exit` when you want to disconnect.

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

This repository is a pre-release technical preview. The primary workflow is a
VPN terminal that connects every configured WireGuard hop and disconnects
automatically when the terminal exits. Persistent connections, one-command
execution, and selective host CIDR routing are also available.

## Design goals

- Linux kernel WireGuard for the data plane
- no custom cryptography
- two or more independently configured hops
- safe composition of self-hosted and commercial peers
- terminal traffic that cannot fall back to the normal Internet connection
- transactional setup and cleanup
- inspectable plans before any privileged changes
- explicit threat model and conservative privacy claims

## Quick start

```sh
sudo nestwg doctor
nestwg validate chain.yaml
sudo nestwg connect chain.yaml
```

NestWG configures every VPN hop and opens your normal shell:

```text
VPN "example" ready through 2 hops
VPN terminal started; type `exit` to disconnect
```

Commands run in that terminal use the nested VPN. For example, `ip route`
shows the VPN routing table and `curl https://icanhazip.com` should show the
final VPN hop's public address. The environment variables `NESTWG_VPN=1` and
`NESTWG_CHAIN=example` identify the VPN terminal. Type `exit` to close the
terminal and automatically disconnect the VPN.

Root privileges are required to configure the VPN, but NestWG drops the shell
back to the user who invoked `sudo`. Internal interface and isolation details
do not need to be managed by the user.

## Persistent and advanced use

Keep a VPN connected across multiple terminal sessions with:

```sh
sudo nestwg up --wait 10s chain.yaml
sudo nestwg status example
sudo nestwg shell example
sudo nestwg exec example -- curl https://example.com
sudo nestwg down example
```

To send selected destinations from ordinary host applications through the
nested VPN while leaving all other host traffic unchanged:

```sh
sudo nestwg up --wait 10s chain.yaml
sudo nestwg attach example \
  --route 203.0.113.0/24 \
  --route 2001:db8:1234::/48
sudo nestwg status example
sudo nestwg diagnose example
```

`attach` exposes the innermost WireGuard device to the host and installs only
the requested routes. The device's encrypted UDP socket remains inside the
previous VPN layer, preserving the nested path without NAT or packet
forwarding.

Each live VPN route has a lower-priority unreachable alternative. If the
device or VPN path disappears, the protected CIDR remains blocked instead of
falling back to the host's normal default route. `down` therefore refuses an
attached VPN. Restoring ordinary routing is explicit:

```sh
sudo nestwg detach example
sudo nestwg down example
```

Every attached CIDR must be covered by the final peer's `AllowedIPs`. CIDRs
are destination based: all host processes using the normal routing table are
affected. Existing exact routes are never replaced. The preview rejects `/0`
attachments; use `connect` for an isolated full-tunnel session.

While attached, use applications normally on the host. `nestwg exec` and
`nestwg shell` are disabled because the exit device is host-visible rather
than inside the isolated VPN terminal; `detach` restores those workflows.

Use `nestwg plan chain.yaml` to preview resolved endpoints, interfaces, routes,
and MTUs without changing the host. `sudo nestwg recover example` is available
for conservative cleanup after externally lost runtime state.

The lifecycle is functional but remains pre-release. VPN commands receive a
private resolver configuration, `status` reads live handshake and transfer
information, and a pre-mutation recovery record lets `down` clean up an
interrupted `up`. If a state file is externally deleted, `recover` can remove
strictly named, process-free orphan resources. `up` can return before every
handshake is ready unless `--wait` is requested. `connect` safely initiates the
nested handshakes and waits up to 10 seconds by default; use
`connect --wait 0` to open the terminal immediately. Do not rely on this
pre-release version as a security or anonymity boundary yet.

`up --wait 10s` waits for every hop to complete a WireGuard handshake. Without
`--wait`, `up` returns as soon as the persistent interfaces are configured and
`status` reports `connecting` until handshakes occur.

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
