# UQOS CLIOM-Ω Mesh

An authenticated QUIC telemetry receiver with a real-time WebSocket dashboard.

## Security-first implementation

This workspace replaces the original demonstration's prefix-only packet check with actual identity and replay controls:

- QUIC with TLS 1.3 and mandatory mutual TLS client certificates.
- Custom ALPN: \`uqos-cliom/1\` (this is a telemetry protocol, not HTTP/3).
- Ed25519 signatures over a versioned, structured telemetry envelope.
- Per-node public-key allowlist.
- Five-minute timestamp freshness window.
- Persistent per-node sequence numbers to reject replayed and out-of-order packets.
- 16 KiB maximum telemetry stream, 16 concurrent uni/bidirectional streams per connection, and 128 concurrent connections per endpoint.
- Dashboard displays only events that pass validation; rejected events are separately logged.
- Dashboard binds to loopback by default and refuses a non-loopback bind. Put an authenticated TLS reverse proxy in front of it if remote access is required.

The \`963Hz\` value is accepted only as an optional metadata tag. It is not a cryptographic check, physical measurement, or proof of harmonic alignment.

## Important multipath boundary

The receiver supports multiple configured QUIC ingress sockets through \`UQOS_QUIC_BINDS\`, and standard QUIC connection migration may support a client changing network paths. That is **not** simultaneous multipath for one QUIC connection.

The IETF multipath extension specifies path identifiers, per-path connection IDs and packet-number spaces, and additional packet-protection behavior. This workspace does not implement that extension because the selected Quinn transport does not expose those multipath protocol mechanisms. Do not describe this build as RFC 10069 multipath QUIC. A true implementation requires a compatible transport stack or a separately tested protocol implementation.

## Requirements

- Rust 1.82+
- A UDP-reachable host for the QUIC receiver
- A dashboard browser on the host, or an authenticated TLS reverse proxy
- Secure storage for generated CA, server, and node private keys

## Provision local development identities

From this directory:

\`\`\`bash
cargo run --bin provision-certs -- localhost
\`\`\`

This creates:
- \`certs/ca.pem\` and \`certs/ca-key.pem\`
- \`certs/server.pem\` and \`certs/server-key.pem\`
- \`certs/client.pem\` and \`certs/client-key.pem\`
- \`certs/node-signing.key\` and \`certs/node-signing.pub\`
- \`authorized_nodes.json\`

The CA private key and all private keys are ignored by Git. The provisioning tool refuses to overwrite an existing CA. Back up keys securely. To add another device, run `cargo run --bin provision-node -- <node-id>`. This creates a separate client certificate and Ed25519 signing key and adds its public key to the allowlist. Transfer that device's credentials securely. When sending from a non-default node, set `CLIOM_CLIENT_CERT`, `CLIOM_CLIENT_KEY`, and `CLIOM_NODE_SIGNING_KEY` to that node's files.

## Run

\`\`\`bash
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo run
\`\`\`

Dashboard: \`http://127.0.0.1:8080\`

QUIC receiver: \`0.0.0.0:4433/UDP\`

For one-click local setup:

\`\`\`bash
chmod +x deploy.sh
./deploy.sh
\`\`\`

The script provisions certificates only if they do not already exist, builds release binaries, and starts the service. It does not update your Rust toolchain or install paid services.

## Send a signed test packet

In a second terminal:

\`\`\`bash
cargo run --bin cliom-send -- 127.0.0.1:4433 localhost cliom-node-1 1 "CLIOM authenticated telemetry test"
\`\`\`

Change the sequence number for every message. The sender authenticates with its client certificate and signs the telemetry envelope with the node's Ed25519 key. A valid message appears as **VERIFIED** in the dashboard. Altered signatures, unauthorized node keys, stale timestamps, repeated sequence numbers, malformed JSON, and oversized streams are rejected.

Optional tag:

\`\`\`bash
CLIOM_FREQUENCY_TAG=963Hz cargo run --bin cliom-send -- 127.0.0.1:4433 localhost cliom-node-1 2 "Tagged telemetry"
\`\`\`

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| \`UQOS_QUIC_BINDS\` | \`0.0.0.0:4433\` | Comma-separated QUIC UDP bind addresses |
| \`UQOS_DASHBOARD_BIND\` | \`127.0.0.1:8080\` | Dashboard address; must be loopback |
| \`UQOS_SERVER_CERT\` | \`certs/server.pem\` | Server certificate chain |
| \`UQOS_SERVER_KEY\` | \`certs/server-key.pem\` | Server private key |
| \`UQOS_CLIENT_CA\` | \`certs/ca.pem\` | CA used to authenticate node client certificates |
| \`UQOS_NODE_ALLOWLIST\` | \`authorized_nodes.json\` | Node ID to Ed25519 public-key map |
| \`UQOS_SEQUENCE_FILE\` | \`state/node-sequences.json\` | Persistent replay-protection state |
| \`CLIOM_CA_CERT\` | \`certs/ca.pem\` | Sender's trusted server CA |
| \`CLIOM_CLIENT_CERT\` | \`certs/client.pem\` | Sender's mTLS certificate |
| \`CLIOM_CLIENT_KEY\` | \`certs/client-key.pem\` | Sender's mTLS private key |
| \`CLIOM_NODE_SIGNING_KEY\` | \`certs/node-signing.key\` | Sender's Ed25519 node key |
| \`CLIOM_FREQUENCY_TAG\` | unset | Optional metadata tag |

For a public deployment, provision a certificate with the actual DNS name clients use, protect private keys, open the UDP receiver port, and keep the dashboard behind an authenticated TLS reverse proxy. The local development CA is not a publicly trusted CA.

## Protocol

A node sends one JSON \`TelemetryEnvelope\` per QUIC unidirectional stream. The signed fields are version, node ID, sequence, timestamp, optional frequency tag, and message. The receiver checks the signature against the allowlisted public key before advancing the persisted sequence number.

The dashboard uses WebSocket events and renders all node-supplied content using \`textContent\`; it does not insert untrusted messages as HTML.

## Operational limits

- This is an early, single-process node. Sequence state is local to one shared filesystem.
- Run one active writer per sequence-state file; do not mount the same state file across independent replicas.
- Certificate revocation and automated key rotation are not implemented.
- TLS protects the QUIC channel; application signatures independently bind each message to an allowlisted node key.
- The dashboard is not intended for direct public exposure.

## License

Apache-2.0.
