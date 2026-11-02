#!/usr/bin/env bash
# Builds rg-uniffi and generates Swift bindings into build/bindings. `xcframework` also wraps macOS, iOS and iOS simulator static libraries.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bindings="$root/build/bindings"
headers="$bindings/Headers"
lib=librg_uniffi.a

cd "$root"
cargo build --release -p rg-uniffi
mkdir -p "$headers"
target/release/uniffi-bindgen generate \
  --library target/release/librg_uniffi.dylib \
  --language swift \
  --out-dir "$bindings" \
  --config crates/rg-uniffi/uniffi.toml
cp "$bindings/RailgunFFI.h" "$headers/"
cp "$bindings/RailgunFFI.modulemap" "$headers/module.modulemap"

if [[ "${1:-}" == xcframework ]]; then
  args=(-library "target/release/$lib" -headers "$headers")
  for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    cargo build --release -p rg-uniffi --no-default-features --target "$target"
    args+=(-library "target/$target/release/$lib" -headers "$headers")
  done
  rm -rf build/RailgunFFI.xcframework
  xcodebuild -create-xcframework "${args[@]}" -output build/RailgunFFI.xcframework
fi
