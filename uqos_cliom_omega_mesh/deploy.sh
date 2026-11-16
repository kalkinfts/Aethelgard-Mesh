#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust and Cargo are required. Install the stable Rust toolchain first." >&2
  exit 1
fi

if [[ ! -f certs/ca.pem ]]; then
  server_name="${UQOS_SERVER_NAME:-localhost}"
  echo "[1/3] Provisioning local CA, server certificate, and node identity for ${server_name}"
  cargo run --bin provision-certs -- "${server_name}"
else
  echo "[1/3] Existing certificate set found; keeping it unchanged."
fi

echo "[2/3] Building CLIOM-Ω in release mode"
cargo build --release

echo "[3/3] Starting authenticated QUIC receiver and dashboard"
export RUST_LOG="${RUST_LOG:-info}"
exec ./target/release/uqos-cliom-omega-mesh
