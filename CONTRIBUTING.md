# Contributing

`nestwg` is Linux-focused by design. Proposals should preserve a small trusted
surface, provider neutrality, inspectable network changes, and conservative
privacy claims.

Before submitting changes:

```sh
make check
make package-deb PACKAGE_VERSION=0.0.0-local
docker compose -f integration/docker-compose.yml up --build --abort-on-container-exit
```

Building from source requires Go 1.27 or newer. Changes to lifecycle, state,
or namespace ownership must include a focused failure or adversarial test in
addition to the privileged integration lab.

Privileged integration tests must use project-specific namespace and interface
names and clean up only resources they created. Tests must not change the
developer host's default route.

Security issues must not initially be filed as public exploit reports. Follow
the private reporting process in `SECURITY.md`.

Maintainers preparing a tag must follow the review, verification, provenance,
and incident-handling checklist in `docs/releasing.md`.
