FROM mcr.microsoft.com/devcontainers/base:ubuntu

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

# Install Zig
RUN curl -L https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz \
    -o zig.tar.xz \
    && tar xf zig.tar.xz \
    && mv zig-x86_64-linux-${ZIG_VERSION} /opt/zig \
    && ln -s /opt/zig/zig /usr/local/bin/zig \
    && rm zig.tar.xz

# Verify install
RUN zig version