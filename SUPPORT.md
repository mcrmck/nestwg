# Support

NestWG is maintained as a community open-source project without guaranteed
response times or commercial support.

- Use [GitHub Discussions](https://github.com/mcrmck/nestwg/discussions) for
  setup questions and provider interoperability reports.
- Use the bug template for reproducible defects. Include the NestWG version,
  Linux distribution and kernel version, sanitized `doctor` output, and a
  redacted chain shape.
- Use the feature template for design proposals.
- Report suspected vulnerabilities privately as described in `SECURITY.md`.

Never post WireGuard private keys, preshared keys, provider credentials, public
IP addresses tied to an account, or identifying packet captures. Replace them
with synthetic documentation addresses and keys before sharing diagnostics.

The supported interface is the documented CLI and chain format. Directly
editing `/run/nestwg`, entering NestWG-owned namespaces, or moving its network
interfaces is unsupported and can defeat lifecycle recovery guarantees.
