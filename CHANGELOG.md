# Changelog

All notable changes will be documented here. NestWG follows Semantic
Versioning once the first version is tagged.

## Unreleased

- Add wg-quick-style bare-name lookup in `/etc/nestwg`, config-path teardown,
  readable host interface names, command-specific help, and optional verbose
  lifecycle output.

- Reworked the lifecycle to expose one ordinary host WireGuard interface while
  preserving every preceding hop in an internal namespace.
- Added chain-configured and CLI-overridable `default`, `selected`, and
  `isolated` host-routing modes.
- Added default-route policy tables, an outer WireGuard socket mark, IPv4/IPv6
  OUTPUT kill switches, and automatic cleanup through `down`.
- Added selected CIDR routing with per-route unreachable fallbacks.
- Added host DNS integration through resolvconf and systemd-resolved.
- Removed terminal-scoped `connect`, `exec`, and `shell` and the separate
  `attach`/`detach` lifecycle.
- Added `diagnose` checks for runtime construction, handshakes, the visible host
  device, live routes, and mode-specific leak protection.
- Added chain and WireGuard configuration validation with secret-safe errors.
- Added inspectable plans with pinned endpoints, routes, namespaces, and MTUs.
- Added persistent `up`, `down`, and `status` commands.
- Added transactional Linux netlink/WireGuard setup and recovery state.
- Added live handshake status and `doctor` checks.
- Added optional handshake readiness waiting with `up --wait`.
- Added conservative orphan recovery that refuses namespaces with processes.
- Hardened runtime-state loading against symlinks, unsafe ownership and modes,
  oversized files, and resolver-content injection; deletions are now synced.
- Added namespace ownership preflight and recovery-state retention when
  automatic rollback is incomplete.
- Added a runtime-driven three-hop mixed IPv4/IPv6 integration lab with
  selected/default host-routing, leak-protection, and rollback assertions.
- Added integration-only failure injection across privileged setup, rollback,
  and retryable teardown stages, tested on Ubuntu 22.04 and 24.04 runners.
- Added reproducible amd64 and arm64 Debian packages to tagged releases.
- Added a sanitized compatibility corpus covering common minimal, split-route,
  dual-stack, preshared-key, keepalive, and `wg-quick` metadata shapes.
- Raised the source-build floor to Go 1.27 and refreshed dependencies.
- Updated the CI supply chain to Ubuntu 26.04, setup-go 7.0.0, CodeQL
  4.37.7, Scorecard 2.4.4, and build-provenance attestation 4.2.2.
- Switched CodeQL to an explicit Go 1.27 build and removed duplicate
  govulncheck checkout and cache setup.
