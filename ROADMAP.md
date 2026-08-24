# Roadmap

NestWG aims to be a provider-neutral, fail-closed Linux VPN client for routing
host traffic through nested WireGuard hops. Milestones describe required
outcomes rather than promised dates.

## v0.1 — trustworthy preview

- `wg-quick`-style `up`, `down`, and `status` lifecycle with one host-visible
  interface and internal nested hops;
- default-route policy routing with an outer-socket mark and OUTPUT kill switch;
- selective host CIDR routing with fail-closed fallback routes;
- route- and handshake-aware `diagnose` output;
- pinned and inspectable endpoints, routes, namespaces, and MTUs;
- host DNS integration through resolvconf and systemd-resolved;
- transactional rollback and crash-recoverable state;
- three-hop mixed IPv4/IPv6 integration tests proving the entry/middle/exit
  privacy split;
- stale-resource discovery with conservative, process-aware recovery;
- shell completions and a documented manual page;
- reproducible amd64 and arm64 Debian packages;
- a sanitized compatibility corpus for common WireGuard export shapes;
- signed release binaries with checksums and provenance.

## v0.2 — compatibility and recovery

- provider-reported compatibility cases and expanded support tiers;
- additional distribution packages and repository metadata.
- reboot-persistent host-routing policy and service integration;
- application/cgroup-based routing built on the selected-route model;

## v1.0 — stable operational contract

- expanded native-arm64 and distribution/kernel compatibility evidence;
- stable chain format with a migration policy;
- failure injection across every privileged operation;
- external security review and resolved findings;
- reproducible, signed packages and a maintained vulnerability policy.

Provider account APIs, graphical interfaces, domain-based routing, and
non-Linux clients remain later possibilities. They must not weaken leak
protection or expand the privileged core without a clear security argument.
