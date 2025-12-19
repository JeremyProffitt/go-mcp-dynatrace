#!/bin/bash

# Build script for go-mcp-dynatrace
# Builds for multiple platforms

set -e

APP_NAME="go-mcp-dynatrace"
VERSION="1.0.0"
BUILD_DIR="dist"

echo "Building $APP_NAME v$VERSION..."

# Clean build directory
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# Build for multiple platforms
PLATFORMS=(
    "darwin/amd64"
    "darwin/arm64"
    "linux/amd64"
    "linux/arm64"
    "windows/amd64"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM#*/}
    OUTPUT_NAME="${APP_NAME}-${GOOS}-${GOARCH}"

    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME="${OUTPUT_NAME}.exe"
    fi

    echo "Building for $GOOS/$GOARCH..."

    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w -X main.Version=$VERSION" -o "$BUILD_DIR/$OUTPUT_NAME" .

    echo "  -> $BUILD_DIR/$OUTPUT_NAME"
done

# Create macOS universal binary
echo "Creating macOS universal binary..."
if command -v lipo &> /dev/null; then
    lipo -create -output "$BUILD_DIR/${APP_NAME}-darwin-universal" \
        "$BUILD_DIR/${APP_NAME}-darwin-amd64" \
        "$BUILD_DIR/${APP_NAME}-darwin-arm64"
    echo "  -> $BUILD_DIR/${APP_NAME}-darwin-universal"
else
    echo "  (skipped - lipo not available)"
fi

echo ""
echo "Build complete! Binaries are in $BUILD_DIR/"
ls -la $BUILD_DIR/
