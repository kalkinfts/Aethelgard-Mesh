# Security Policy

## Current posture

Aethelgard Mesh is early-stage software. It provides signed execution records, a local hash-linked audit file, a body-size limit, and bearer-token gating for non-loopback binds. It is not yet a hardened public multi-tenant service.

The service does not currently provide TLS, rate limiting, key rotation, remote immutable audit storage, distributed consensus, sandboxing, or formal proof verification. Keep the default loopback bind unless you have configured a trusted TLS reverse proxy and a strong bearer token.

## Key handling

- Never commit `.aethelgard/signing.key`, API tokens, or private key material.
- Back up the signing key securely; loss of the key prevents verification of old records.
- The local audit file is not immutable against an attacker who controls the host and key.
- Public keys must be distributed and pinned through a trusted independent channel.

## Reporting a vulnerability

Do not publish exploitable details in a public issue. Use GitHub's private vulnerability reporting feature if enabled. Otherwise contact the maintainers privately before sharing sensitive details.

Include the affected commit or release, reproduction steps, impact, and relevant logs with secrets removed. Never include live credentials, private keys, or personal data.
