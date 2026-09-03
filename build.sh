#!/bin/bash
# ============================================================================
# build.sh — KCC 二进制构建（amd64 / arm64 静态 musl 二进制）
#
# 用法:
#   ./build.sh              # 构建当前主机架构的二进制
#   ./build.sh amd64        # 指定架构；与主机不同时用 cross 交叉编译
#   ./build.sh arm64
#
# 原生构建（架构与主机一致）需要:
#   - rustup target add <target>     （脚本自动执行）
#   - Debian/Ubuntu: apt install musl-tools（编译 vendored OpenSSL 用）
# 交叉构建（架构与主机不同）需要:
#   - cargo install cross，且本机可运行 Docker（详见 Cross.toml）
#
# 产物: target/<target>/release/kcc
# ============================================================================
set -euo pipefail

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)             echo "unknown" ;;
  esac
}

HOST_ARCH="$(detect_arch)"
[ "$HOST_ARCH" != "unknown" ] || { echo "无法识别的架构: $(uname -m)"; exit 1; }

ARCH="${1:-$HOST_ARCH}"
case "$ARCH" in
  amd64) TARGET="x86_64-unknown-linux-musl" ;;
  arm64) TARGET="aarch64-unknown-linux-musl" ;;
  *) echo "用法: $0 [amd64|arm64]"; exit 1 ;;
esac

echo "==> 目标架构: $ARCH（target: $TARGET）"

if [ "$ARCH" = "$HOST_ARCH" ]; then
  # 真机原生构建
  rustup target add "$TARGET" >/dev/null 2>&1 || true
  cargo build --release --target "$TARGET" ${CARGO_BUILD_JOBS:+-j $CARGO_BUILD_JOBS}
else
  # 交叉构建（容器方式）
  command -v cross >/dev/null 2>&1 || { echo "交叉构建需要 cross: cargo install cross"; exit 1; }
  cross build --release --target "$TARGET"
fi

BIN="target/$TARGET/release/kcc"
file "$BIN"
echo ""
echo "构建完成 ✅: $BIN"
