#!/bin/sh
# Regenerate the Swift binding from the built library (UniFFI library mode).
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
profile=${CITADEL_RUST_PROFILE:-debug}
cd "$root"
cargo build -p citadel-ffi --features cli ${CITADEL_RUST_PROFILE:+--release}
cargo run -q -p citadel-ffi --features cli --bin uniffi-bindgen -- generate \
  --library "target/$profile/libcitadel_ffi.dylib" --language swift --out-dir "$here/Generated"
cp "$here/Generated/citadel_ffiFFI.h" "$here/Sources/CitadelFFI/include/"
cp "$here/Generated/citadel_ffiFFI.modulemap" "$here/Sources/CitadelFFI/include/module.modulemap"
cp "$here/Generated/citadel_ffi.swift" "$here/Sources/Citadel/"
echo "bindings regenerated"
