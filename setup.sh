#!/bin/bash
# Claude Code StatusLine 一键配置脚本 (macOS)
# 用法: bash ~/legend/cc-nice/setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="$HOME/.claude/statusline-command.sh"

# 确保 ~/.claude 目录存在
mkdir -p "$HOME/.claude"

# 复制脚本（用 cat 避免 CRLF 问题）
cat "$SCRIPT_DIR/statusline-command.sh" > "$TARGET"
chmod +x "$TARGET"

# 写入 settings.json（保留已有配置，仅更新 statusLine 字段）
SETTINGS="$HOME/.claude/settings.json"
if [ -f "$SETTINGS" ]; then
    # 已有配置文件，用 jq 合并
    tmp=$(mktemp)
    jq '. + {"statusLine": {"type": "command", "command": "bash ~/.claude/statusline-command.sh"}}' "$SETTINGS" > "$tmp"
    mv "$tmp" "$SETTINGS"
else
    # 新建配置文件
    echo '{"statusLine":{"type":"command","command":"bash ~/.claude/statusline-command.sh"}}' | jq . > "$SETTINGS"
fi

echo "Done! 重启 Claude Code 即可看到状态栏:"
echo "  Opus 4.6 | [███░░░░░░░░░░░░░░░░░] 36k/200k (18%) | \$0.65 |  main"
