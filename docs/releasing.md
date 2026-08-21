# Release process

NestWG releases are built by GitHub Actions from an immutable signed tag. The
workflow produces static Linux tarballs and Debian packages for amd64 and
arm64, SHA-256 checksums, and GitHub build-provenance attestations.

## Before tagging

1. Confirm `CHANGELOG.md` describes the candidate and the working tree contains
   no unreviewed generated files.
2. Run `make check` with Go 1.27 or newer.
3. Run `make package-deb PACKAGE_VERSION=<version>` and inspect the package with
   `dpkg-deb --info` and `dpkg-deb --contents`.
4. Run the exact privileged command documented in `integration/README.md` on a
   supported Linux kernel.
5. Run `govulncheck ./...` and assess module-only findings even when no called
   symbol is vulnerable.
6. Obtain review for runtime, packaging, workflow, or cryptographic-boundary
   changes. Never release directly from an unreviewed local tree.

Create a signed annotated tag only after those gates pass:

```sh
git tag -s v0.1.0 -m 'NestWG v0.1.0'
git push origin v0.1.0
```

Tags are immutable. Correct a bad release with a new patch version; do not
delete and recreate a published tag.

## Verifying published artifacts

Download every asset into an empty directory, then verify checksums and
provenance before announcing the release:

```sh
sha256sum -c checksums.txt
gh attestation verify nestwg_0.1.0_linux_amd64.tar.gz --repo mcrmck/nestwg
gh attestation verify nestwg_0.1.0_amd64.deb --repo mcrmck/nestwg
```

Extract a tarball and Debian package, run `nestwg version`, and confirm the
reported version matches the tag. Install the Debian package on a disposable
supported host and run `sudo nestwg doctor`.

## Release incident handling

If an artifact, attestation, or security property is wrong, stop promotion,
mark the GitHub release as withdrawn, and publish a patch release after the fix
passes the full gates. Follow `SECURITY.md` for private coordination when the
issue could affect confidentiality, isolation, privilege dropping, or cleanup.
