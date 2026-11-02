set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

default:
  @just --list

# Inner loop. Example: just test-rust rg-core store
test-rust crate *args:
  cargo test -p "{{crate}}" {{args}}

# All workspace tests, for publishing.
test:
  cargo test --workspace --release

# Needs a circuit directory: just test-proof data/artifacts
test-proof artifacts:
  RG_ARTIFACTS_DIR="{{artifacts}}" cargo test --release -p rg-tx -- --ignored

format:
  cargo fmt --all

lint:
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --features rg-sync/rpc,rg-poi/rpc,rg-prover/wasmtime

# Example: just wallet arbitrum https://arb1.arbitrum.io/rpc data/chain mnemonic.txt balance
wallet *args:
  cargo run --release -p rg-core --example wallet -- "$@"
