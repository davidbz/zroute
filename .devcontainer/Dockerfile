FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    xz-utils \
    git \
    build-essential \
    gdb \
    lldb \
    strace \
    ltrace \
    procps \
    linux-tools-common \
    linux-tools-generic \
    && rm -rf /var/lib/apt/lists/*

ARG ZIG_VERSION=0.16.0

# Install Zig — arch-agnostic so this works on x86_64 and aarch64 hosts
RUN ARCH=$(uname -m) && \
    curl -fL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${ARCH}-${ZIG_VERSION}.tar.xz" \
    -o /tmp/zig.tar.xz \
    && tar xf /tmp/zig.tar.xz -C /opt \
    && mv "/opt/zig-linux-${ARCH}-${ZIG_VERSION}" /opt/zig \
    && ln -s /opt/zig/zig /usr/local/bin/zig \
    && rm /tmp/zig.tar.xz

RUN zig version
