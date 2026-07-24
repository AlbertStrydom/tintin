#!/usr/bin/env bash
# ===========================================================================
# Build Rust libraries for iOS targets
# ===========================================================================
# Run this script from the `tintin-ios/` directory to cross-compile the
# Rust core for all supported iOS architectures, then create an XCFramework
# that Xcode can link.
#
# Prerequisites:
#   brew install xcodegen
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# Usage:
#   cd tintin-ios/
#   ./build_rust.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/lib"

echo "==> Building tintin-ffi for iOS targets..."

cd "$WORKSPACE_DIR"

# Architectures to build for
TARGETS=(
  "aarch64-apple-ios"         # Physical device (arm64)
  "aarch64-apple-ios-sim"     # Simulator on Apple Silicon
  "x86_64-apple-ios"          # Simulator on Intel Macs
)

for target in "${TARGETS[@]}"; do
  echo "  → Building for $target ..."
  cargo build -p tintin-ffi --release --target "$target"
done

# Combine simulator libraries into a single XCFramework
echo "==> Creating XCFramework..."

mkdir -p "$OUTPUT_DIR"

# Device library
DEVICE_LIB="$WORKSPACE_DIR/target/aarch64-apple-ios/release/libtintin_core.a"

# Simulator libraries (merge into a multi-arch static lib)
SIM_ARM_LIB="$WORKSPACE_DIR/target/aarch64-apple-ios-sim/release/libtintin_core.a"
SIM_X86_LIB="$WORKSPACE_DIR/target/x86_64-apple-ios/release/libtintin_core.a"
SIM_MERGED="$OUTPUT_DIR/libtintin_core_sim.a"

# If both simulator arches exist, lipo them together
if [ -f "$SIM_ARM_LIB" ] && [ -f "$SIM_X86_LIB" ]; then
  lipo -create "$SIM_ARM_LIB" "$SIM_X86_LIB" -output "$SIM_MERGED"
  echo "  → Merged simulator libraries into $SIM_MERGED"
elif [ -f "$SIM_ARM_LIB" ]; then
  cp "$SIM_ARM_LIB" "$SIM_MERGED"
fi

# Copy device library
cp "$DEVICE_LIB" "$OUTPUT_DIR/libtintin_core_device.a"
echo "  → Device library copied to $OUTPUT_DIR"

# Copy the C header so Xcode can find it
cp "$WORKSPACE_DIR/tintin-ffi/tintin_core.h" "$SCRIPT_DIR/TinTin/Bridge/tintin_core.h"

echo ""
echo "==> Done! Rust libraries are in $OUTPUT_DIR"
echo ""
echo "Next steps on your Mac:"
echo "  1. cd tintin-ios"
echo "  2. xcodegen generate   (creates TinTin.xcodeproj)"
echo "  3. open TinTin.xcodeproj"
echo "  4. Select your team in Signing & Capabilities"
echo "  5. Build and run on your device or simulator"
