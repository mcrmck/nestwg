# nestwg

[![CI](https://github.com/mcrmck/nestwg/actions/workflows/ci.yml/badge.svg)](https://github.com/mcrmck/nestwg/actions/workflows/ci.yml)
[![Security](https://github.com/mcrmck/nestwg/actions/workflows/security.yml/badge.svg)](https://github.com/mcrmck/nestwg/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`nestwg` is a Linux-only tool for composing WireGuard tunnels inside one
another. The client constructs every encryption layer, so an intermediate hop
removes only the layer addressed to it and forwards the still-encrypted tunnel
to the next hop.

```text
application packet
  -> WireGuard(exit)
    -> WireGuard(entry)
      -> physical network
```

The project is intentionally provider-neutral. A chain can combine self-hosted
servers and commercial VPN providers as long as every hop supplies a standard
WireGuard client configuration and permits traffic to the next hop.

## Status

This repository is a pre-release technical preview. The `validate` and `plan`
commands inspect configuration without changing the host. On Linux, `up` and
`down` create and remove a persistent nested WireGuard chain, and `exec` or
`shell` runs applications through its isolated, fail-closed payload network.

## Design goals

- Linux kernel WireGuard for the data plane
- no custom cryptography
- two or more independently configured hops
- safe composition of self-hosted and commercial peers
- applications launched in a naturally fail-closed network namespace
- transactional setup and cleanup
- inspectable plans before any privileged changes
- explicit threat model and conservative privacy claims

## CLI

```sh
nestwg validate chain.yaml
nestwg plan chain.yaml
sudo nestwg up --wait 10s chain.yaml
sudo nestwg status
sudo nestwg exec example -- curl https://example.com
sudo nestwg down example
sudo nestwg doctor
sudo nestwg recover example
```

Root privileges are currently required for lifecycle and payload commands.
When invoked through `sudo`, NestWG drops the launched application's user and
group identity back to the invoking user. The namespace and interface layout
is an internal implementation detail; users manage one logical named chain.

The lifecycle is functional but remains pre-release. Payload commands receive
an isolated resolver configuration, `status` reads live handshake and transfer
information, and a pre-mutation recovery record lets `down` clean up an
interrupted `up`. If a state file is externally deleted, `recover` can remove
strictly named, process-free orphan namespaces. Unless `--wait` is requested,
`up` returns before every handshake is necessarily ready. Do not rely on this
pre-release version as a security or anonymity boundary yet.

`up --wait 10s` waits for every hop to complete a WireGuard handshake. Without
`--wait`, `up` returns as soon as the persistent interfaces are configured and
`status` reports `connecting` until handshakes occur.

An initial chain looks like:

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
