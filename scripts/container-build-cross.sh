#!/usr/bin/env bash
# Cross-compile the statusbar-core Debian package for arm64 inside a native
# amd64 container — no qemu emulation. Produces a .deb stamped
# Architecture: arm64; ctest is not run because the binaries cannot execute
# on the build host.
#
# For test execution use the emulated path (scripts/container-build.sh) —
# this script is the production-build fast path.
set -euo pipefail

PKG="core"
DEBIAN_VERSION="${DEBIAN_VERSION:-trixie}"
TARGET_ARCH="${TARGET_ARCH:-arm64}"
ENGINE="${CONTAINER_ENGINE:-podman}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TREE_DIR="$(dirname "$SCRIPT_DIR")"
EXPORT_ROOT="$(dirname "$TREE_DIR")"
DEB_OUTPUT="${DEB_OUTPUT:-$EXPORT_ROOT/deb-output}"
IMAGE="localhost/statusbar-deb-builder-cross:$DEBIAN_VERSION-$TARGET_ARCH"

MOUNT_OPT=""
if [ "$(uname -s)" = "Linux" ]; then
  MOUNT_OPT=",z"
fi

mkdir -p "$DEB_OUTPUT"

# Rebuild the cross builder image when it is missing or its Containerfile
# changed — the image records the Containerfile checksum in a label at build
# time. The tag is shared by all statusbar packages, whose Containerfiles are
# kept byte-identical so any package can (re)build the image for the others.
CF_SUM="$(cksum "$TREE_DIR/Containerfile.cross" | cut -d' ' -f1)"
if [ "$("$ENGINE" image inspect \
         --format '{{index .Config.Labels "statusbar.containerfile"}}' \
         "$IMAGE" 2>/dev/null)" != "$CF_SUM" ]; then
  echo "=== building cross builder image $IMAGE ==="
  "$ENGINE" build -t "$IMAGE" \
    --platform linux/amd64 \
    --build-arg "DEBIAN_VERSION=$DEBIAN_VERSION" \
    --build-arg "TARGET_ARCH=$TARGET_ARCH" \
    --label "statusbar.containerfile=$CF_SUM" \
    -f "$TREE_DIR/Containerfile.cross" "$TREE_DIR"
fi

echo "=== cross-building statusbar-$PKG .deb (target $TARGET_ARCH) ==="
"$ENGINE" run --rm \
  --platform linux/amd64 \
  -v "$TREE_DIR:/src:ro$MOUNT_OPT" \
  -v "$DEB_OUTPUT:/debs:rw$MOUNT_OPT" \
  -v "statusbar-deb-ccache-cross-$TARGET_ARCH:/root/.ccache" \
  -e "PKG=$PKG" \
  -e "TARGET_ARCH=$TARGET_ARCH" \
  "$IMAGE" bash -euo pipefail -c '
    cmake -Wno-dev -S /src -B /build -G Ninja \
      --toolchain /src/cmake/toolchain-clang-aarch64.cmake \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DCMAKE_C_COMPILER_LAUNCHER=ccache \
      -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
      -DCPACK_DEBIAN_PACKAGE_ARCHITECTURE="$TARGET_ARCH"
    cmake --build /build
    ( cd /build && cpack -G DEB )
    rm -f /debs/statusbar-"$PKG"_*_"$TARGET_ARCH".deb \
          /debs/statusbar-"$PKG"-dev_*_"$TARGET_ARCH".deb
    cp -v /build/*.deb /debs/
  '

echo "=== statusbar-$PKG packages in $DEB_OUTPUT ==="
ls -1 "$DEB_OUTPUT"/statusbar-"$PKG"_*_"$TARGET_ARCH".deb \
      "$DEB_OUTPUT"/statusbar-"$PKG"-dev_*_"$TARGET_ARCH".deb 2>/dev/null || true
