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
  RG_ARTIFACTS_DIR="{{absolute_path(artifacts)}}" cargo test --release -p rg-tx -- --ignored

format:
  cargo fmt --all
  swiftformat crates/rg-uniffi/tests/swift

lint:
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --features rg-sync/rpc,rg-poi/rpc,rg-prover/wasmtime
  swiftformat --lint crates/rg-uniffi/tests/swift
  swiftlint lint --strict --quiet

# Example: just wallet arbitrum https://arb1.arbitrum.io/rpc data/chain mnemonic.txt balance
wallet *args:
  cargo run --release -p rg-core --example wallet -- "$@"

# Swift and Kotlin bindings into build/bindings.
ffi:
  bash scripts/ffi.sh

# Also the XCFramework for macOS, iOS and the iOS simulator.
ffi-apple:
  bash scripts/ffi.sh xcframework

# Also the JNI libraries in build/android/jniLibs. Needs ANDROID_NDK_HOME and cargo-ndk.
ffi-android:
  bash scripts/ffi.sh android

# Runs the Kotlin smoke test on the JVM. Needs Gradle. Set RG_MNEMONIC_FILE for the live part.
test-kotlin: ffi
  gradle -p crates/rg-uniffi/tests/kotlin run

# Compiles the bindings with the smoke test and runs it. Set RG_MNEMONIC_FILE for the live part.
test-swift: ffi
  swiftc -O -o build/smoke crates/rg-uniffi/tests/swift/*.swift build/bindings/RailgunCore.swift \
    -I build/bindings/Headers -L target/release -lrg_uniffi
  DYLD_LIBRARY_PATH=target/release build/smoke
