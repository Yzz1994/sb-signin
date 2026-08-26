# 烧饼论坛（sb.sb）签到助手 一键部署脚本（Windows）
#
# 用法（PowerShell）：
#   powershell -ExecutionPolicy Bypass -File install.ps1
#   或带仓库名：
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Repo "yourname/sb-signin"

param(
  [string]$Repo = "USER/REPO",   # TODO: 发布前替换为你的 GitHub 仓库
  [string]$OutFile = "sb-signin.exe"
)

$ErrorActionPreference = "Stop"

# 检测架构
$arch = "amd64"
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
  $arch = "arm64"
}

$url = "https://github.com/$Repo/releases/latest/download/sb-signin-windows-$arch.exe"

Write-Host ">> 平台: windows/$arch"
Write-Host ">> 仓库: $Repo"
Write-Host ">> 下载: $url"

Invoke-WebRequest -Uri $url -OutFile $OutFile -UseBasicParsing

Write-Host ""
Write-Host "✅ 下载完成: $OutFile"
Write-Host ""
Write-Host "启动签到服务："
Write-Host "  .\$OutFile"
Write-Host ""
Write-Host "首次运行会生成安全码并打印在控制台，"
Write-Host "之后浏览器访问 http://127.0.0.1:8080 输入安全码即可管理。"
