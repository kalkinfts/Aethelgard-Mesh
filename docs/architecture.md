# Architecture

## Request path

1. Axum enforces a 1 MiB request-body limit.
2. Non-loopback binds require a bearer token. Token comparison uses constant-time equality for equal-length values.
3. The execution core validates the graph dimensions, node indices, and configured maximum.
4. The deterministic Dijkstra routine computes the shortest path.
5. A versioned manifest captures the operation, timestamp, policy version, input digest, and result.
6. Ed25519 signs the SHA-256 digest of the serialized manifest.
7. The signed record is appended to a JSONL audit chain and synced before the API returns it.

## Signed evidence

The signed record contains:
- manifest schema version;
- execution identifier and timestamp;
- policy version and operation name;
- SHA-256 digest of the serialized request;
- result;
- previous record digest;
- manifest digest, public key, and Ed25519 signature.

The verifier recomputes the manifest digest, compares the embedded key with an independently trusted key, and verifies the signature. The embedded key alone is not a trust anchor.

## Audit chain

At startup, the service reads each existing JSONL record in order. It verifies the signature and digest and checks that each record's previous digest equals the preceding record digest. Any invalid record or broken link prevents startup.

This is tamper-evident local storage, not immutable remote storage. Host compromise or private-key compromise defeats the local trust boundary. Key rotation and remote replication are future work.

## Security boundaries

- Default listener: loopback only.
- Non-loopback listener: refused unless `AETHELGARD_API_TOKEN` is configured.
- Request body: maximum 1 MiB.
- Private key: generated locally on first start or loaded from a configured 32-byte seed; default file permissions are owner-only on Unix.
- TLS: not provided by this service; use a trusted TLS-terminating reverse proxy for remote traffic.
- Proofs: no Lean, Z3, theorem prover, or formal proof artifact is currently integrated.

A signature proves key possession and byte integrity under the key trust model. It does not establish semantic correctness or formal proof.
