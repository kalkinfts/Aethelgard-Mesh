# Aethelgard Mesh

**An open-source, developer-first foundation for auditable AI and agent execution.**

Aethelgard Mesh begins with a small, inspectable execution core: validated graph inputs, deterministic shortest-path execution, an HTTP API, tests, and continuous integration. The architecture is intended to grow toward signed manifests, tamper-evident execution records, policy enforcement, and agent orchestration.

> **Status: early development.** The current code does not implement formal proof verification, signed requests, distributed consensus, Wasm sandboxing, or production authentication. Do not treat the current API as a production security boundary.

## Current capabilities

- Rust library with a bounded, validated adjacency-matrix graph model.
- Deterministic Dijkstra shortest-path calculation.
- Explicit errors for malformed graphs, invalid indices, oversized graphs, and distance overflow.
- HTTP health and execution endpoints.
- GitHub Actions checks for formatting, linting, and tests.

## Trust vocabulary

Validation, execution evidence, cryptographic integrity, authentication, and formal proof are different guarantees. A hash or digital signature can establish integrity or origin under defined assumptions; it does not by itself prove that a computation is logically correct. The current milestone implements input validation and execution only.

## Quick start

Requirements: stable Rust toolchain (Rust 1.82 or newer recommended).

```bash
git clone https://github.com/kalkinfts/Aethelgard-Mesh.git
cd Aethelgard-Mesh
cargo test
cargo run
```

The server binds to `127.0.0.1:3000` by default. Set `AETHELGARD_BIND` to change the address.

### Health check

```bash
curl http://127.0.0.1:3000/health
```

### Execute a shortest-path request

The graph is a square adjacency matrix. A weight of `0` means no edge; positive weights represent directed edges.

```bash
curl -X POST http://127.0.0.1:3000/v1/execute \
  -H 'content-type: application/json' \
  -d '{"graph":[[0,4,0],[4,0,8],[0,8,0]],"start":0,"end":2}'
```

The shortest-path distance in this example is `12`.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Process health response |
| POST | `/v1/execute` | Validate a graph and calculate a shortest-path distance |

A successful execution returns `distance` (a number, or `null` when no path exists) and `execution_time_ms`. Invalid graph input returns HTTP 400.

## Architecture

```text
Client -> Axum HTTP API -> input validation -> Rust execution core -> JSON response
```

See [docs/architecture.md](docs/architecture.md) for design boundaries and the roadmap.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Security-sensitive reports should follow [SECURITY.md](SECURITY.md).

## Roadmap

1. Core correctness: validated data types, deterministic execution, tests, and CI.
2. Execution evidence: versioned request and response envelopes and reproducible audit records.
3. Cryptographic integrity: canonical manifests, key handling, signatures, and verification tests.
4. Policy layer: explicit permissions and fail-closed execution controls.
5. Formal methods: optional proof backends with independently checked proof artifacts.
6. Agent mesh: orchestration adapters and distributed execution after the trust model is defined.

Roadmap items are not current capabilities. Each will be marked implemented only when code, tests, and documentation support the claim.

## License

Apache-2.0. See [LICENSE](LICENSE).
