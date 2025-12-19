# Build script for go-mcp-dynatrace (Windows PowerShell)
# Builds for multiple platforms

$ErrorActionPreference = "Stop"

$APP_NAME = "go-mcp-dynatrace"
$VERSION = "1.0.0"
$BUILD_DIR = "dist"

Write-Host "Building $APP_NAME v$VERSION..."

# Clean build directory
if (Test-Path $BUILD_DIR) {
    Remove-Item -Recurse -Force $BUILD_DIR
}
New-Item -ItemType Directory -Path $BUILD_DIR | Out-Null

# Build for multiple platforms
$platforms = @(
    @{GOOS="darwin"; GOARCH="amd64"},
    @{GOOS="darwin"; GOARCH="arm64"},
    @{GOOS="linux"; GOARCH="amd64"},
    @{GOOS="linux"; GOARCH="arm64"},
    @{GOOS="windows"; GOARCH="amd64"}
)

foreach ($platform in $platforms) {
    $GOOS = $platform.GOOS
    $GOARCH = $platform.GOARCH
    $OUTPUT_NAME = "$APP_NAME-$GOOS-$GOARCH"

    if ($GOOS -eq "windows") {
        $OUTPUT_NAME = "$OUTPUT_NAME.exe"
    }

    Write-Host "Building for $GOOS/$GOARCH..."

    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH

    go build -ldflags="-s -w -X main.Version=$VERSION" -o "$BUILD_DIR/$OUTPUT_NAME" .

    Write-Host "  -> $BUILD_DIR/$OUTPUT_NAME"
}

# Reset environment variables
Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Build complete! Binaries are in $BUILD_DIR/"
Get-ChildItem $BUILD_DIR
