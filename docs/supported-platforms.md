# Supported platforms

NestWG is Linux-only because its isolation model depends on named network and
mount namespaces plus the kernel WireGuard and netlink APIs.

## Preview support tiers

| Tier | Platform | Evidence |
| --- | --- | --- |
| Tested | Ubuntu 22.04 and 24.04, x86-64 | Race tests, vet, builds, and the privileged three-hop integration lab run in GitHub Actions. |
| Build-tested | Linux arm64 | Every tagged release cross-builds a static binary and a Debian package; artifact structure is checked before release. |
| Expected | Other current Linux distributions with kernel WireGuard and named network namespaces | Host routing also requires iptables-compatible tooling; configured DNS requires `resolvconf` or systemd-resolved. These combinations are not yet CI-certified. |
| Unsupported | macOS, Windows, BSD, containers without the required kernel capabilities | The fail-closed namespace design is not implemented on these platforms. |

Linux 5.6 or newer is the supported kernel baseline because WireGuard is part
of the upstream kernel from that release onward. A distribution kernel with a
backported WireGuard module may work, but is not part of the preview support
contract.

Run `sudo nestwg doctor` before creating a chain. It checks root privileges,
netlink access, kernel WireGuard interface creation, iptables/ip6tables,
policy-routing sysctls, and runtime-state security. A passing result establishes prerequisites, not
provider reachability or anonymity.

## Reporting compatibility

Include the NestWG version, distribution, `uname -a`, architecture, container
or virtualization environment, and sanitized `doctor` output. Never include
private keys, preshared keys, provider credentials, or identifying captures.
