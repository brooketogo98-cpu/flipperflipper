#!/bin/bash

# Real Build Script for Native Payloads
set -e

echo "========================================"
echo "   NATIVE PAYLOAD BUILD - REAL VERSION"
echo "========================================"

# Directories
SRC_DIR="/workspace/native_payloads"
BUILD_DIR="$SRC_DIR/build"
OUTPUT_DIR="$SRC_DIR/output"

# Clean and create directories
rm -rf $BUILD_DIR $OUTPUT_DIR
mkdir -p $BUILD_DIR $OUTPUT_DIR

# Compiler settings
CC=${CC:-gcc}
CFLAGS="-O2 -Wall -Wextra -I$SRC_DIR/core -I$SRC_DIR/crypto -I$SRC_DIR/network"
LDFLAGS=""

# Platform detection
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
    CFLAGS="$CFLAGS -DPLATFORM_LINUX"
    LDFLAGS="$LDFLAGS -lpthread"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    CFLAGS="$CFLAGS -DPLATFORM_MACOS"
elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]]; then
    PLATFORM="windows"
    CFLAGS="$CFLAGS -DPLATFORM_WINDOWS"
    LDFLAGS="$LDFLAGS -lws2_32 -lwininet -lcrypt32"
fi

echo "Platform: $PLATFORM"
echo "Compiler: $CC"
echo ""

# Source files
SOURCES="
    $SRC_DIR/core/main_real.c
    $SRC_DIR/core/utils.c
    $SRC_DIR/core/commands.c
    $SRC_DIR/crypto/aes.c
    $SRC_DIR/crypto/sha256.c
    $SRC_DIR/network/protocol_real.c
"

# Platform-specific sources
if [ "$PLATFORM" = "windows" ]; then
    SOURCES="$SOURCES $SRC_DIR/windows/winapi.c"
elif [ "$PLATFORM" = "linux" ]; then
    SOURCES="$SOURCES $SRC_DIR/linux/linux_impl.c"
fi

echo "[*] Compiling native payload..."

# Compile with error checking
if $CC $CFLAGS $SOURCES $LDFLAGS -o $OUTPUT_DIR/payload_native 2>$BUILD_DIR/compile.log; then
    echo "✓ Compilation successful!"
    
    # Strip symbols
    strip --strip-all $OUTPUT_DIR/payload_native 2>/dev/null || true
    
    # Get size
    SIZE=$(stat -c%s "$OUTPUT_DIR/payload_native" 2>/dev/null || stat -f%z "$OUTPUT_DIR/payload_native" 2>/dev/null || echo "unknown")
    echo "✓ Binary size: $SIZE bytes"
    
    # Try UPX if available
    if command -v upx &> /dev/null; then
        echo "[*] Compressing with UPX..."
        upx --best --lzma $OUTPUT_DIR/payload_native 2>/dev/null || true
        NEW_SIZE=$(stat -c%s "$OUTPUT_DIR/payload_native" 2>/dev/null || stat -f%z "$OUTPUT_DIR/payload_native" 2>/dev/null || echo "unknown")
        echo "✓ Compressed size: $NEW_SIZE bytes"
    fi
    
    echo ""
    echo "========================================"
    echo "BUILD SUCCESSFUL!"
    echo "Output: $OUTPUT_DIR/payload_native"
    echo "========================================"
    
else
    echo "✗ Compilation failed! See $BUILD_DIR/compile.log for errors"
    cat $BUILD_DIR/compile.log
    exit 1
fi