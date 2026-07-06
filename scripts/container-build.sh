#!/usr/bin/env bash
# Build the Debian packages for statusbar-core inside a container.
#
# Compiles in a Debian container and writes .deb files to the shared
# output directory (DEB_OUTPUT, default <export-root>/deb-output).
# Dependency packages must already be built there — the top-level
# container-build.sh builds a package together with its dependencies,
# rebuilding only what changed.
set -euo pipefail

PKG="core"
DEPS=""
DEBIAN_VERSION="${DEBIAN_VERSION:-trixie}"
TARGET_PLATFORM="${TARGET_PLATFORM:-linux/arm64}"
ENGINE="${CONTAINER_ENGINE:-podman}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TREE_DIR="$(dirname "$SCRIPT_DIR")"
EXPORT_ROOT="$(dirname "$TREE_DIR")"
DEB_OUTPUT="${DEB_OUTPUT:-$EXPORT_ROOT/deb-output}"
TARGET_ARCH="${TARGET_PLATFORM##*/}"
IMAGE="localhost/statusbar-deb-builder:$DEBIAN_VERSION-$TARGET_ARCH"

# Debian package revision: a monotonic build id appended as the package's Debian
# revision (version becomes 1.2.0-<rev>), so every rebuild produces a
# strictly-newer package and `apt-get install` always upgrades it instead of
# skipping a same-version reinstall. The upstream version (1.2.0) is bumped only
# on real releases. Overridable; the umbrella container-build.sh sets one shared
# value per run so a multi-package build gets a consistent revision.
DEB_REVISION="${STATUSBAR_DEB_REVISION:-$(date -u +%Y%m%d%H%M%S)}"

# Cross-arch builds (e.g. linux/arm64 on an x86_64 host) need qemu-user-static
# registered with the kernel's binfmt_misc. Detect and explain instead of
# letting the container die with a cryptic "exec format error".
case "$TARGET_ARCH" in
  arm64) KERNEL_ARCH="aarch64" ;;
  amd64) KERNEL_ARCH="x86_64" ;;
  *)     KERNEL_ARCH="$TARGET_ARCH" ;;
esac
# macOS reports arm64 / x86_64; Linux reports aarch64 / x86_64. Normalize the
# host name to the kernel-arch convention before comparing, otherwise a native
# build on Apple Silicon ("arm64" vs "aarch64") is mistaken for cross-arch.
case "$(uname -m)" in
  arm64|aarch64) HOST_ARCH="aarch64" ;;
  amd64|x86_64)  HOST_ARCH="x86_64" ;;
  *)             HOST_ARCH="$(uname -m)" ;;
esac
if [ "$HOST_ARCH" != "$KERNEL_ARCH" ] \
   && ! ls /proc/sys/fs/binfmt_misc/qemu-"$KERNEL_ARCH"* >/dev/null 2>&1; then
  echo "error: host $(uname -m) cannot run $TARGET_PLATFORM containers." >&2
  echo "       qemu-user-static binfmt_misc handler is not registered. Install:" >&2
  echo "         Debian/Ubuntu: sudo apt install qemu-user-static binfmt-support" >&2
  echo "         Fedora/RHEL:   sudo dnf install qemu-user-static" >&2
  echo "         Generic:       $ENGINE run --rm --privileged \\" >&2
  echo "                          docker.io/multiarch/qemu-user-static --reset -p yes" >&2
  exit 1
fi

# On SELinux hosts (Fedora, RHEL, ...) bind mounts must be relabelled or the
# container cannot read them; the ",z" flag is a harmless no-op elsewhere.
MOUNT_OPT=""
if [ "$(uname -s)" = "Linux" ]; then
  MOUNT_OPT=",z"
fi

mkdir -p "$DEB_OUTPUT"

# Rebuild the builder image when it is missing or its Containerfile changed —
# the image records the Containerfile checksum in a label at build time. The
# tag is shared by all statusbar packages, whose Containerfiles are kept
# byte-identical so any package can (re)build the image for the others.
CF_SUM="$(cksum "$TREE_DIR/Containerfile" | cut -d' ' -f1)"
if [ "$("$ENGINE" image inspect \
         --format '{{index .Config.Labels "statusbar.containerfile"}}' \
         "$IMAGE" 2>/dev/null)" != "$CF_SUM" ]; then
  echo "=== building builder image $IMAGE ==="
  "$ENGINE" build -t "$IMAGE" \
    --platform "$TARGET_PLATFORM" \
    --build-arg "DEBIAN_VERSION=$DEBIAN_VERSION" \
    --label "statusbar.containerfile=$CF_SUM" \
    -f "$TREE_DIR/Containerfile" "$TREE_DIR"
fi

# Verify the bind-mount paths are reachable by the container engine. On
# macOS the engine runs in a VM that mounts only some host directories; a
# path outside them fails the bind mount with a cryptic
# "statfs ... no such file" error — probe up front and explain instead.
check_mountable() {
  if ! "$ENGINE" run --rm --platform "$TARGET_PLATFORM" \
       -v "$1:/_mountcheck:ro$MOUNT_OPT" "$IMAGE" true >/dev/null 2>&1; then
    echo "error: $ENGINE cannot bind-mount '$1' — it is not under a host" >&2
    echo "       directory the $ENGINE VM mounts. Move the export under a" >&2
    echo "       mounted path (commonly /Volumes/... on macOS), or add it:" >&2
    echo "         $ENGINE machine stop && $ENGINE machine rm &&" >&2
    echo "         $ENGINE machine init -v \"$1:$1\" && $ENGINE machine start" >&2
    exit 1
  fi
}
check_mountable "$TREE_DIR"
check_mountable "$DEB_OUTPUT"

for d in $DEPS; do
  if ! ls "$DEB_OUTPUT"/statusbar-"$d"-dev_*.deb >/dev/null 2>&1; then
    echo "error: dependency statusbar-$d is not built (no .deb in $DEB_OUTPUT)" >&2
    echo "       build dependencies first via the top-level container-build.sh" >&2
    exit 1
  fi
done

echo "=== building statusbar-$PKG .deb packages (Debian $DEBIAN_VERSION) ==="
"$ENGINE" run --rm \
  --platform "$TARGET_PLATFORM" \
  -v "$TREE_DIR:/src:ro$MOUNT_OPT" \
  -v "$DEB_OUTPUT:/debs:rw$MOUNT_OPT" \
  -v "statusbar-deb-ccache-$TARGET_ARCH:/root/.ccache" \
  -e "DEPS=$DEPS" \
  -e "PKG=$PKG" \
  -e "DEB_REVISION=$DEB_REVISION" \
  -e "EXTRA_CMAKE_ARGS=${EXTRA_CMAKE_ARGS:-}" \
  "$IMAGE" bash -euo pipefail -c '
    debs=()
    for d in $DEPS; do
      debs+=(/debs/statusbar-"$d"_*.deb /debs/statusbar-"$d"-dev_*.deb)
    done
    if [ "${#debs[@]}" -gt 0 ]; then
      apt-get update -qq
      apt-get install -y --no-install-recommends "${debs[@]}"
    fi
    cmake -Wno-dev -S /src -B /build -G Ninja \
      --toolchain /src/cmake/toolchain-clang.cmake \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DENABLE_FUZZING=OFF \
      -DCMAKE_C_COMPILER_LAUNCHER=ccache \
      -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
      ${EXTRA_CMAKE_ARGS}
    cmake --build /build
    ( cd /build && cpack -G DEB -D CPACK_DEBIAN_PACKAGE_RELEASE="$DEB_REVISION" )
    rm -f /debs/statusbar-"$PKG"_*.deb /debs/statusbar-"$PKG"-dev_*.deb
    cp -v /build/*.deb /debs/
  '
echo "=== statusbar-$PKG packages in $DEB_OUTPUT ==="
ls -1 "$DEB_OUTPUT"/statusbar-"$PKG"_*.deb \
      "$DEB_OUTPUT"/statusbar-"$PKG"-dev_*.deb 2>/dev/null || true
