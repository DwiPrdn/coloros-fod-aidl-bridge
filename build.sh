#!/usr/bin/env bash
set -euo pipefail

: "${NDK_DIR:?Set NDK_DIR to your Android NDK r27c root}"
: "${BINDER_NDK:?Set BINDER_NDK to ColorOS/Android 17 system/lib64/libbinder_ndk.so}"

TC="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin"
CXX="$TC/aarch64-linux-android31-clang++"
STRIP="$TC/llvm-strip"
READELF="$TC/llvm-readelf"

OUT="vendor/bin/hw/android.hardware.biometrics.fingerprint-service.tanzanite"
mkdir -p "$(dirname "$OUT")"

"$CXX" -O2 -std=c++17 -Wall -Wextra -fPIE -pie -static-libstdc++ \
  -Wl,--allow-shlib-undefined \
  src/fod_bridge.cpp "$BINDER_NDK" -llog -ldl \
  -o "$OUT"

"$STRIP" --strip-unneeded "$OUT"
chmod 0755 "$OUT"

if "$READELF" -d "$OUT" | grep -q 'libc++_shared'; then
  echo "ERROR: $OUT unexpectedly links libc++_shared.so!" >&2
  exit 1
fi

echo "Built $OUT successfully:"
"$READELF" -d "$OUT" | grep NEEDED
