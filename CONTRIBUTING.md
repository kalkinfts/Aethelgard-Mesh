# Contributing

Thanks for helping improve Aethelgard Mesh.

## Before opening a pull request

1. Open an issue for substantial changes so the design can be discussed.
2. Keep changes focused and document externally visible behavior.
3. Add tests for new behavior and regression tests for fixes.
4. Avoid claims of cryptographic security or formal verification unless the implementation and tests support them.

## Local checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

## Pull requests

Describe the problem, the chosen approach, security implications, and the checks you ran. Do not include secrets, generated credentials, or unrelated formatting changes.
