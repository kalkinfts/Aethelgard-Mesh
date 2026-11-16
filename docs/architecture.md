# Architecture

## Current implementation

The first milestone is a small Rust service:

1. **HTTP boundary** — Axum accepts JSON requests and returns structured responses.
2. **Validation boundary** — the core checks graph size, matrix shape, and node indices before execution.
3. **Execution core** — a pure Rust Dijkstra implementation calculates a shortest-path distance.
4. **Test boundary** — unit tests cover valid results and important invalid-input cases.

The default listener is loopback-only (`127.0.0.1:3000`). This is a safe development default, not a deployment recipe. A publicly reachable deployment needs authentication, authorization, rate limiting, observability, and an explicit threat model before exposure.

## Trust and proof vocabulary

- **Validation** means an input passed specified checks.
- **Execution evidence** records what the service received and returned.
- **Integrity** means data can be checked for unauthorized modification under a defined cryptographic scheme.
- **Authentication** identifies or verifies a caller under a defined key and trust model.
- **Formal proof** means a proof artifact is checked by a specified proof system.

These terms are not interchangeable. The current milestone implements input validation and execution; it does not implement cryptographic authentication, tamper-evident logs, or formal proof checking.

## Planned layers

- Versioned request and response envelopes.
- Canonical serialization and signed manifests.
- Append-only, hash-linked execution records.
- Policy evaluation and explicit capability boundaries.
- Optional Lean4/Z3 proof adapters with reproducible proof checking.
- Agent orchestration adapters and distributed execution.

Each layer must have tests and documented security assumptions before it is described as implemented.
