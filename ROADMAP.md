# Roadmap

NestWG aims to be a provider-neutral, fail-closed Linux VPN client for routing
a terminal through nested WireGuard hops. Milestones describe required
outcomes rather than promised dates.

## v0.1 — trustworthy preview

- one-command `connect` terminal workflow plus persistent `up`, `down`,
  `status`, `exec`, and `shell` lifecycle;
- selective host CIDR attachment with explicit detach and fail-closed fallback
  routes;
- route- and handshake-aware `diagnose` output;
- pinned and inspectable endpoints, routes, namespaces, and MTUs;
- private payload DNS and invoking-user privilege restoration;
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
- reboot-persistent attachment policy and service integration;
- application/cgroup-based routing built on the selective attachment model;

## v1.0 — stable operational contract

- expanded native-arm64 and distribution/kernel compatibility evidence;
- stable chain format with a migration policy;
- failure injection across every privileged operation;
- external security review and resolved findings;
- reproducible, signed packages and a maintained vulnerability policy.

Provider account APIs, graphical interfaces, domain-based routing, and
non-Linux clients remain later possibilities. They must not weaken the
isolated mode or expand the privileged core without a clear security argument.
