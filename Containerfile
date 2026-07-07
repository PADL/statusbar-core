# Debian builder image for statusbar exported packages.
#
# DEBIAN_VERSION selects the base image; the container-build scripts pass
# it through and tag the built image accordingly.
ARG DEBIAN_VERSION=trixie
FROM docker.io/library/debian:${DEBIAN_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang clang-tools lld \
    libc++-dev libc++abi-dev libclang-rt-dev \
    cmake ninja-build ccache pkg-config \
    dpkg-dev file ca-certificates \
    python3 python3-jsonschema \
    libasound2-dev libbpf-dev libxdp-dev libelf-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
