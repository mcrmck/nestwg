# Changelog

All notable changes will be documented here. NestWG follows Semantic
Versioning once the first version is tagged.

## Unreleased

- Added a VPN-first `connect` command that initiates and verifies every nested
  handshake, opens the user's terminal with VPN identity variables, and
  disconnects on exit.
- Added chain and WireGuard configuration validation with secret-safe errors.
- Added inspectable plans with pinned endpoints, routes, namespaces, and MTUs.
- Added persistent `up`, `down`, `status`, `exec`, and `shell` commands.
- Added transactional Linux netlink/WireGuard setup and recovery state.
- Added private payload DNS, live handshake status, and `doctor` checks.
- Added optional handshake readiness waiting with `up --wait`.
- Added conservative orphan recovery that refuses namespaces with processes.
- Hardened runtime-state loading against symlinks, unsafe ownership and modes,
  oversized files, and resolver-content injection; deletions are now synced.
- Added namespace ownership preflight and recovery-state retention when
  automatic rollback is incomplete.
- Added a runtime-driven three-hop mixed IPv4/IPv6 integration lab with leak,
  lifecycle-lock, identity-restoration, DNS, and rollback assertions.
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
