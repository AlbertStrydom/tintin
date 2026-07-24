#!/usr/bin/env bash
# ===========================================================================
# Build Rust library for Android targets
# ===========================================================================
# Run this from the `tintin-android/` directory.
#
# Prerequisites:
#   - Android NDK (set ANDROID_NDK_HOME)
#   - cargo install cargo-ndk
#   - rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#
# Usage:
#   cd tintin-android/
#   ./build_rust.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/app/src/main/jniLibs"

echo "==> Building tintin-jni for Android targets..."
cd "$WORKSPACE_DIR"

# Architectures supported by the NDK
TARGETS=(
  "aarch64-linux-android"   # arm64-v8a
  "armv7-linux-androideabi" # armeabi-v7a
  "x86_64-linux-android"    # x86_64 (emulator)
)

for target in "${TARGETS[@]}"; do
  echo "  → Building for $target ..."
  cargo ndk --target "$target" --platform 26 build -p tintin-jni --release
done

echo "==> Copying .so files to jniLibs..."
mkdir -p "$OUTPUT_DIR"

# Map Rust target triples to Android ABI directories
declare -A ABI_MAP
ABI_MAP["aarch64-linux-android"]="arm64-v8a"
ABI_MAP["armv7-linux-androideabi"]="armeabi-v7a"
ABI_MAP["x86_64-linux-android"]="x86_64"

for target in "${TARGETS[@]}"; do
  abi="${ABI_MAP[$target]}"
  mkdir -p "$OUTPUT_DIR/$abi"
  cp "$WORKSPACE_DIR/target/$target/release/libtintin_android.so" "$OUTPUT_DIR/$abi/"
  echo "  → Copied $abi/libtintin_android.so"
done

echo ""
echo "==> Done! .so files placed in $OUTPUT_DIR"
echo ""
echo "Next steps:"
echo "  1. Open tintin-android/ in Android Studio"
echo "  2. Let Gradle sync complete"
echo "  3. Run on device or emulator (min API 26)"
