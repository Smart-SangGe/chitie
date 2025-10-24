#!/bin/bash
# 多架构编译脚本

set -e

echo "Building chitie for multiple architectures..."

# x86_64
echo "==> Building for x86_64-unknown-linux-musl"
cargo build --release --target x86_64-unknown-linux-musl

# aarch64 (ARM64)
echo "==> Building for aarch64-unknown-linux-musl"
cargo build --release --target aarch64-unknown-linux-musl

# 显示编译结果
echo ""
echo "Build complete! Binaries:"
ls -lh target/x86_64-unknown-linux-musl/release/chitie
ls -lh target/aarch64-unknown-linux-musl/release/chitie

# 检查是否静态链接
echo ""
echo "==> Checking x86_64 binary dependencies:"
ldd target/x86_64-unknown-linux-musl/release/chitie || echo "Static binary (good!)"

echo ""
echo "==> Binary sizes:"
du -h target/x86_64-unknown-linux-musl/release/chitie
du -h target/aarch64-unknown-linux-musl/release/chitie
