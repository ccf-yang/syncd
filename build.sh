#!/usr/bin/env bash
# Build syncd cross-platform binaries into ./bin/
#   linux/amd64, linux/arm64, windows/amd64, darwin/amd64 (Intel mac),
#   darwin/arm64 (Apple Silicon)
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
OUT=bin
mkdir -p "$OUT"

build() {
    local goos=$1 goarch=$2 ext=${3:-}
    echo "==> building syncd-${goos}-${goarch}${ext}"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
        go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o "${OUT}/syncd-${goos}-${goarch}${ext}" .
}

build linux   amd64
build linux   arm64
build windows amd64 .exe
build darwin  amd64   # Intel mac
build darwin  arm64   # Apple Silicon (bonus)

echo
echo "Done. Binaries in ${OUT}/:"
ls -lh "$OUT"
