# Claude Code StatusLine 一键配置脚本 (Windows)
# 用法: powershell -ExecutionPolicy Bypass -File setup.ps1

$ErrorActionPreference = "Stop"

$claudeDir = "$env:USERPROFILE\.claude"
$target = "$claudeDir\statusline-command.ps1"
$settings = "$claudeDir\settings.json"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# 确保 ~/.claude 目录存在
if (-not (Test-Path $claudeDir)) {
    New-Item -ItemType Directory -Path $claudeDir | Out-Null
}

# 复制状态栏脚本
Copy-Item "$scriptDir\statusline-command.ps1" -Destination $target -Force

# 更新 settings.json
$statusLine = @{
    type    = "command"
    command = "powershell -NoProfile -File `"$target`""
}

if (Test-Path $settings) {
    $config = Get-Content $settings -Raw | ConvertFrom-Json
    $config | Add-Member -NotePropertyName "statusLine" -NotePropertyValue $statusLine -Force
} else {
    $config = @{ statusLine = $statusLine }
}

$config | ConvertTo-Json -Depth 10 | Set-Content $settings -Encoding UTF8

Write-Host "Done! 重启 Claude Code 即可看到状态栏:" -ForegroundColor Green
Write-Host '  Opus 4.6 | [███░░░░░░░░░░░░░░░░░] 36k/200k (18%) | $0.65 |  main'
