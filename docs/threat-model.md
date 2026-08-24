# Threat model

## Intended guarantee

Assuming non-colluding hops and a trustworthy client, no individual
intermediate relay can associate both the client's public IP address and the
application's final destination.

For a two-hop chain:

| Observer | Client IP | Exit endpoint | Final destination | Plaintext application data |
| --- | --- | --- | --- | --- |
| Local network | Yes | No | No | No |
| Entry | Yes | Yes | No | No |
| Exit | No; sees entry | N/A | Yes | Only when the application itself is unencrypted |
| Destination | No; sees exit | N/A | Itself | According to the application protocol |

Application-layer encryption such as TLS remains necessary. Nesting
WireGuard does not make plaintext HTTP confidential from the exit.

## Assumptions

- The client host, kernel, executable, and configuration files are trusted.
- WireGuard's cryptographic and protocol guarantees hold.
- At least the entry and exit are operated independently and do not share
  identifying control-plane records.
- The client obtains authentic relay public keys.
- A selected commercial provider permits UDP forwarding to the next endpoint.

## In-scope adversaries

- A malicious or logging entry relay.
- A malicious or logging exit relay.
- A local network observer.
- Opportunistic observers with visibility of only part of the path.
- Configuration mistakes that could otherwise leak DNS or payload traffic.

Default routing does not implicitly replace host DNS. Operators must configure
`spec.dns` when DNS queries also need to traverse the VPN; leaving it empty is
an explicit leak-prone configuration choice.

For selected routing, the fail-closed guarantee applies to configured
destination CIDRs while NestWG's runtime state and unreachable backup routes
remain installed. For default routing, it depends on the policy rules, marked
outer WireGuard socket, and OUTPUT kill switch remaining intact. `down`
deliberately restores ordinary routing and DNS. Root can still alter or delete
routes, firewall rules, state, and namespaces; protection against a malicious
or mistaken root operator is outside the model. Runtime state under `/run` does
not survive reboot, so reboot-persistent routing policy is not yet claimed.

Authenticated inner WireGuard packets prevent an entry from reading or
silently modifying application packets. An entry can still delay, replay, or
drop opaque packets; WireGuard rejects invalid modifications and replays, but
availability and timing manipulation remain possible.

## Explicit non-goals

`nestwg` does not claim protection against:

- a global passive observer watching both ends of the chain;
- timing, volume, website-fingerprinting, or long-lived-flow correlation;
- collusion between entry and exit operators;
- a provider or broker that can link account issuance to every selected hop;
- compromised client kernels, root users, or destination applications;
- browser, device, or application fingerprinting;
- malicious destinations;
- denial of service by a relay;
- legal or operational relationships hidden behind nominally different brands.

Additional hops do not automatically defeat these attacks. Operator, hosting
provider, ASN, and jurisdiction diversity can improve resistance to partial
observers, but low-latency tunnelling cannot provide mixnet-like metadata
protection without substantial performance tradeoffs.

## Control-plane privacy

Commercial credentials can create linkability outside the data plane. If one
account purchases both entry and exit service, or a central API records the
complete selected chain, layered encryption alone does not provide the desired
split-trust property. Future provider adapters must document their credential,
payment, directory, and telemetry behavior separately from tunnel security.
