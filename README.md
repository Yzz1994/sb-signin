# 烧饼论坛（sb.sb）自动签到助手

Go 实现的常驻签到服务，**支持多账号 + Web 可视化配置 + 浏览器扩展一键获取 Cookie**。

该论坛的签到机制是「登录后访问 `https://sb.sb/signin/` 即完成签到」，签到按 UTC 计算、UTC+8 时区每日 08:00 更新。

## 功能

- ✅ 多账号：每个账号独立 Cookie、启用开关、签到统计（连续/本月/累计/最长）
- ✅ Web 管理页面：可视化增删改查账号、手动签到、配置签到时间、查看日志
- ✅ 定时签到：常驻运行，每天到点自动签到所有启用账号
- ✅ 微信通知：通过 Server酱 推送签到结果到微信（成功/失败/失效均推送）
- ✅ Telegram 通知：通过 Telegram Bot 推送签到结果（与微信独立开关，可同时启用），支持自动获取 Chat ID
- ✅ 安全码：访问 Web 页面、浏览器插件上传 Cookie 均需安全码验证
- ✅ Cookie 辅助获取：
  - 浏览器扩展（推荐）：一键读取 sb.sb 登录 Cookie（含 HttpOnly）并回传本地服务
  - 手动粘贴：支持粘贴整段 `Cookie: name=value; ...` 或 `Copy as cURL` 命令，自动解析

## 安全码

程序**首次运行会自动生成安全码**并打印在控制台，用于登录 Web 页面和浏览器扩展。

```bash
# 查看当前安全码
./sb-signin.exe -show-token

# 重置安全码（随机生成新值）
./sb-signin.exe -reset-token

# 重置为自定义安全码（至少 6 位）
./sb-signin.exe -reset-token 你的自定义值
./sb-signin.exe -reset-token=你的自定义值   # 等号写法

# 查看帮助
./sb-signin.exe -help
```

> 安全码保存在 `data.json` 的 `access_token` 字段。忘记时用 `-show-token` 查看即可。

## 发布与一键部署

### 发布到 GitHub Release（自动化）

已配置好 GitHub Actions（`.github/workflows/release.yml`），推送 tag 即自动打包多平台 Release：

```bash
git tag v1.0.0
git push origin v1.0.0
```

自动构建产物（Windows/Linux/macOS × amd64/arm64 共 6 个）+ 浏览器扩展 `extension.zip`，并生成 Release 说明。

> ⚠️ 发布前请确认：`.gitignore` 已忽略 `data.json`（含 Cookie 和安全码，绝不能提交）。
> 仓库名已配置为 `Yzz1994/sb-signin`，如换了仓库请同步修改 `install.sh` 里的仓库名。

### 让别人一键部署（Linux 系统服务）

```bash
curl -fsSL https://raw.githubusercontent.com/Yzz1994/sb-signin/main/install.sh | sudo sh
```

脚本会自动：下载对应架构二进制 → 安装到 `/usr/local/bin` → 创建并启动 `systemd` 服务 → 输出安全码。

安装完成后：
- 管理页面：`http://127.0.0.1:8080`（安全码在安装输出里）
- 查看状态：`systemctl status sb-signin`
- 查看日志：`journalctl -u sb-signin -f`
- 卸载：`systemctl disable --now sb-signin; rm -f /etc/systemd/system/sb-signin.service /usr/local/bin/sb-signin`

## 快速开始

### 1. 启动服务

```bash
cd sb-signin
go build -o sb-signin.exe .   # 或直接运行已编译的 sb-signin.exe
./sb-signin.exe -port 8080
```

参数：
- `-port` Web 端口，默认 `8080`
- `-data` 数据文件，默认 `data.json`

启动后打开浏览器访问 **http://127.0.0.1:8080**

### 2. 添加账号（二选一）

**方式 A：浏览器扩展（一键，推荐）**

1. 打开 `chrome://extensions`（Edge 为 `edge://extensions`），开启右上角「开发者模式」
2. 点「加载已解压的扩展程序」，选择本项目的 `extension` 目录
3. 浏览器登录 `https://sb.sb/`，点击工具栏上的「烧饼论坛签到 Cookie 助手」图标
4. 确认服务地址为 `http://127.0.0.1:8080`，填上**安全码**，点「获取并发送 Cookie」即可

**方式 B：手动粘贴**

1. 浏览器登录 `sb.sb`，按 `F12` → 应用/Application → Cookies → `sb.sb`
2. 复制 `__Host-bbs_session` 和 `__Host-bbs_csrf` 的值（或整段 Cookie 头）
3. 在 Web 页面点「+ 添加账号」，粘贴到输入框，自动解析后保存

### 3. 配置签到时间

点页面右上角「⚙ 设置」，设置每日签到时间（默认 UTC+8 08:05）。

### 4. 配置微信通知（可选）

1. 打开 `https://sct.ftqq.com/`，用微信扫码登录，关注「Server酱」公众号
2. 在「SendKey」页面复制你的密钥（`SCT` 开头）
3. 在 Web 页面「⚙ 设置」里勾选「启用微信通知」，粘贴 SendKey，保存

配置后，每次签到（定时/手动）完成后都会推送到微信：
- ✅ 成功：列出各账号签到结果和连续天数
- ❌ 失效/失败：立即告警，提醒你更新 Cookie

> 免费版 Server酱 每日有发送条数上限，个人使用足够。

### 5. 配置 Telegram 通知（可选）

1. 在 Telegram 搜索 `@BotFather`，发 `/newbot`，按提示创建一个 Bot，拿到 **Bot Token**（形如 `123456:ABC...`）
2. 在 Telegram 里给你刚创建的 Bot 发任意一条消息
3. 浏览器访问 `https://api.telegram.org/bot<你的Token>/getUpdates`，从返回的 JSON 里找到 `chat.id`（一串数字）
4. 在 Web 页面「⚙ 设置」里勾选「启用 Telegram 通知」，填入 Bot Token 和 Chat ID，保存

微信和 Telegram 两个渠道相互独立，可以只用一个，也可以同时启用。

## 数据存储

所有配置保存在 `data.json`（安全码、账号 Cookie、设置、日志），程序启动时自动创建。文件含登录凭证，**请勿上传到公开仓库**。

## 开机自启

**Windows**：任务计划程序 → 新建任务 → 触发器选「登录时」→ 操作选启动 `sb-signin.exe`（起始目录设为程序所在目录）。

**Linux/macOS（systemd）**：

```ini
[Unit]
Description=sb.sb signin
After=network-online.target

[Service]
WorkingDirectory=/path/to/sb-signin
ExecStart=/path/to/sb-signin/sb-signin
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## 常见问题

- **登录态失效**：账号显示「失效」，重新用扩展或粘贴方式更新 Cookie。
- **签到失败**：查看日志，多数是网络问题，下一天会自动重试。
- **改了端口扩展连不上**：扩展弹窗里的「服务地址」改成对应端口（扩展的 manifest 已预授权 8080；若改其它端口需同步修改 `extension/manifest.json` 的 `host_permissions` 并重新加载扩展）。
