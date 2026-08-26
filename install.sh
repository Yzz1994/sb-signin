#!/bin/sh
# 烧饼论坛（sb.sb）签到助手 一键部署脚本（Linux / macOS）
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/USER/REPO/main/install.sh | sh
#
# 可选参数/环境变量：
#   REPO          GitHub 仓库，如 yourname/sb-signin（或作为第一个参数传入）
#   INSTALL_DIR   安装目录（默认 ~/.local/bin）

set -e

# GitHub 仓库（可用环境变量 REPO 覆盖）
REPO="${REPO:-${1:-Yzz1994/sb-signin}}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="sb-signin"

detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "✗ 不支持的架构: $ARCH" >&2; exit 1 ;;
  esac
  case "$OS" in
    linux|darwin) ;;
    *) echo "✗ 不支持的系统: $OS（Windows 请用 install.ps1）" >&2; exit 1 ;;
  esac
}

main() {
  detect_platform

  FILE="sb-signin-${OS}-${ARCH}"
  URL="https://github.com/$REPO/releases/latest/download/$FILE"

  echo ">> 平台: $OS/$ARCH"
  echo ">> 仓库: $REPO"
  echo ">> 下载: $URL"

  mkdir -p "$INSTALL_DIR"
  curl -fL --retry 3 -o "$INSTALL_DIR/$BIN_NAME" "$URL"
  chmod +x "$INSTALL_DIR/$BIN_NAME"

  echo ""
  echo "✅ 安装完成: $INSTALL_DIR/$BIN_NAME"
  echo ""
  echo "启动签到服务："
  echo "  $INSTALL_DIR/$BIN_NAME"
  echo ""
  echo "首次运行会生成安全码并打印在控制台，"
  echo "之后浏览器访问 http://127.0.0.1:8080 输入安全码即可管理。"
  echo ""
  echo "提示：请确认 $INSTALL_DIR 在你的 PATH 中；"
  echo "若不是，可运行： export PATH=\"\$PATH:$INSTALL_DIR\""
}

main
