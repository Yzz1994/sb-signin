#!/bin/sh
# 烧饼论坛（sb.sb）签到助手 - Linux 一键安装（systemd 服务）
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/Yzz1994/sb-signin/main/install.sh | sudo sh
#
# 自定义端口（三种方式任选）：
#   curl -fsSL .../install.sh | sudo sh -s -- 9000
#   curl -fsSL .../install.sh | sudo PORT=9000 sh
#   或导出 PORT=9000 后运行脚本

set -e

REPO="Yzz1994/sb-signin"
BIN="/usr/local/bin/sb-signin"
DATA_DIR="/var/lib/sb-signin"
DATA_FILE="$DATA_DIR/data.json"
SERVICE_FILE="/etc/systemd/system/sb-signin.service"
PORT="${PORT:-8080}"
# 第一个位置参数作为端口（优先级高于 PORT 环境变量）
if [ -n "${1:-}" ]; then
  PORT="$1"
fi

# 校验端口
case "$PORT" in
  ''|*[!0-9]*) echo "✗ 端口必须是数字: $PORT" >&2; exit 1 ;;
  *) ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "✗ 端口范围错误（1-65535）: $PORT" >&2; exit 1
fi

# 需要 root
if [ "$(id -u)" -ne 0 ]; then
  echo "需要 root 权限，请重新运行："
  echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo sh"
  exit 1
fi

# 仅支持 Linux（systemd）
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
  echo "✗ 本脚本仅支持 Linux（systemd）。"
  exit 1
fi

# 检测架构
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "✗ 不支持的架构: $ARCH" >&2; exit 1 ;;
esac

FILE="sb-signin-linux-$ARCH"
URL="https://github.com/$REPO/releases/latest/download/$FILE"

echo ">> 平台: linux/$ARCH"
echo ">> 下载: $URL"

# 先下载到临时文件，避免覆盖正在运行的二进制（Text file busy）
TMP_BIN="$(mktemp /tmp/sb-signin.XXXXXX)"
trap 'rm -f "$TMP_BIN"' EXIT
curl -fL --retry 3 -o "$TMP_BIN" "$URL"
chmod +x "$TMP_BIN"

# 停止旧服务（若已安装），再原子替换二进制
if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^sb-signin\.service'; then
  echo ">> 停止旧服务..."
  systemctl stop sb-signin 2>/dev/null || true
fi
mv -f "$TMP_BIN" "$BIN"
trap - EXIT

# 数据目录
mkdir -p "$DATA_DIR"

# 安全码：已有则保留，没有则生成
TOKEN=$("$BIN" -data "$DATA_FILE" -show-token 2>/dev/null | grep -oE '[A-Za-z0-9]{6,}' | tail -1 || true)
if [ -z "$TOKEN" ]; then
  "$BIN" -data "$DATA_FILE" -reset-token >/dev/null 2>&1 || true
  TOKEN=$("$BIN" -data "$DATA_FILE" -show-token 2>/dev/null | grep -oE '[A-Za-z0-9]{6,}' | tail -1 || true)
fi

# 写入 systemd 服务
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SB.SB Signin Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DATA_DIR
ExecStart=$BIN -data $DATA_FILE -port $PORT
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sb-signin

# 获取本机 IP（优先非回环网卡）
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$LOCAL_IP" ] || [ "$LOCAL_IP" = "127.0.0.1" ]; then
  LOCAL_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
fi
[ -z "$LOCAL_IP" ] && LOCAL_IP="127.0.0.1"

echo ""
echo "✅ 安装完成，签到服务已启动"
echo ""
echo "  管理页面: http://$LOCAL_IP:$PORT"
if [ "$LOCAL_IP" != "127.0.0.1" ]; then
  echo "  本机访问: http://127.0.0.1:$PORT"
fi
echo "  安全码:   $TOKEN"
echo ""
echo "  常用命令："
echo "    查看状态: systemctl status sb-signin"
echo "    查看日志: journalctl -u sb-signin -f"
echo "    停止服务: systemctl stop sb-signin"
echo "    卸载:     systemctl disable --now sb-signin; rm -f $SERVICE_FILE $BIN"
echo ""
echo "首次使用：浏览器打开管理页面，输入上面的安全码即可。"
