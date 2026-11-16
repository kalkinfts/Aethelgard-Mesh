# Security Policy

## Current security posture

Aethelgard Mesh is early-stage software and is not yet suitable as a production security boundary. The current HTTP service has no authentication or authorization. It binds to loopback by default; do not expose it to an untrusted network.

The project does not currently implement signed requests, cryptographic audit logs, formal proof verification, or a Wasm sandbox.

## Reporting a vulnerability

Please do not publish exploitable details in a public issue. Use GitHub's private vulnerability reporting feature if it is enabled for this repository. If it is not enabled, contact the maintainers through a private channel before sharing sensitive details.

Include the affected commit or release, reproduction steps and impact, and relevant logs or proof of concept with secrets removed. Do not include live credentials, private keys, or personal data in reports.
