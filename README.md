# Aethelgard Mesh

**An open-source foundation for inspectable execution and cryptographically verifiable agent evidence.**

Aethelgard Mesh combines a bounded Rust execution core with a small HTTP API. Each accepted execution is recorded as a versioned manifest, SHA-256 digest, Ed25519 signature, and link to the preceding audit record.

> **Status: early development.** The signed execution and local audit-chain features are implemented and tested in CI. This is not a formal proof system, distributed consensus protocol, or fully hardened internet-facing service.

## Implemented

- Bounded adjacency-matrix validation and deterministic shortest-path execution.
- Ed25519-signed execution manifests.
- SHA-256 digest of each manifest.
- Append-only JSONL audit records linked by the previous record digest.
- Startup verification of the complete existing audit chain; startup fails closed if a record, signature, or chain link is invalid.
- Persistent local signing key generated on first start, or supplied through environment configuration.
- Bearer-token requirement for non-loopback network binds.
- HTTP body-size limit and GitHub Actions checks.

## Trust model

The service signs execution records. A verifier must obtain and pin the expected public key through a trusted, independent channel. The public key embedded in a record is not sufficient to establish trust by itself.

A valid signature proves that the corresponding private key signed the record and that the signed bytes have not changed. It does **not** prove that the algorithm is correct, the input is truthful, or the result is a formal mathematical proof. The current graph operation is ordinary deterministic software execution.

The local audit chain is tamper-evident relative to the configured key and retained chain history. It is not remote immutable storage; an attacker who controls both the host and signing key can rewrite the local file.

## Quick start

Requirements: Rust 1.82 or newer.

```bash
git clone https://github.com/kalkinfts/Aethelgard-Mesh.git
cd Aethelgard-Mesh
cargo test
cargo run
```

The default bind is `127.0.0.1:3000`. On first start, the service creates a signing key at `.aethelgard/signing.key` and an audit log at `.aethelgard/audit.jsonl`. Keep the key private and back it up securely. Both paths are ignored by Git.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `AETHELGARD_BIND` | `127.0.0.1:3000` | Listen address |
| `AETHELGARD_API_TOKEN` | unset | Required for non-loopback binds |
| `AETHELGARD_SIGNING_KEY` | generated key file | Optional 32-byte Ed25519 seed encoded as 64 hex characters |
| `AETHELGARD_KEY_FILE` | `.aethelgard/signing.key` | Private signing-key path |
| `AETHELGARD_AUDIT_FILE` | `.aethelgard/audit.jsonl` | Append-only audit file |

For a network bind, set a strong random token before starting:

```bash
export AETHELGARD_BIND=0.0.0.0:3000
export AETHELGARD_API_TOKEN="$(openssl rand -hex 32)"
cargo run --release
```

Do not commit secrets or expose the signing key. Terminate TLS at a trusted reverse proxy before sending traffic over an untrusted network. The service does not itself provide TLS.

## API

All routes require a bearer token when the server binds to a non-loopback address.

### Health

```bash
curl http://127.0.0.1:3000/health
```

### Public key

```bash
curl http://127.0.0.1:3000/v1/public-key
```

Pin this value out-of-band before trusting signatures from the node.

### Execute and receive signed evidence

```bash
curl -X POST http://127.0.0.1:3000/v1/execute \
  -H 'content-type: application/json' \
  -d '{"graph":[[0,4,0],[4,0,8],[0,8,0]],"start":0,"end":2}'
```

The response contains `distance` and a signed `execution` object. The example distance is `12`.

### Verify a signed record

Save the response's `execution` object to `record.json`, then verify locally with the pinned public key:

```bash
cargo run --bin aethelgard-verify -- <TRUSTED_PUBLIC_KEY_HEX> record.json
```

The CLI exits non-zero if the signature, digest, or key does not match. You can also send the object in a POST body as `{"execution": {...}}` to `/v1/verify`; that endpoint checks against this node's configured public key.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

See [docs/architecture.md](docs/architecture.md), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- Independent verifier CLI and key rotation procedure.
- Remote append-only audit replication and retention policy.
- Policy configuration and explicit capability grants.
- Authentication options suitable for service-to-service deployment.
- Optional formal proof adapters with independent proof checking.
- Agent orchestration after the trust and isolation model is specified.

Roadmap items are not current capabilities. They will be marked implemented only after code, tests, and documentation support the claim.

## Additional workspace: UQOS CLIOM-Ω

A separate Rust workspace for authenticated QUIC telemetry ingress and a live WebSocket dashboard is available in [`uqos_cliom_omega_mesh/`](uqos_cliom_omega_mesh/README.md). It uses mutual TLS, Ed25519 node signatures, allowlisting, timestamp freshness, and replay protection. It is standard QUIC with multiple configured ingress sockets—not simultaneous RFC 10069 multipath QUIC.

## License

Apache-2.0. See [LICENSE](LICENSE).
