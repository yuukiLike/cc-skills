#!/bin/bash
# Install statusLine configuration for Claude Code
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDE_DIR="$HOME/.claude"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
TARGET_SCRIPT="$CLAUDE_DIR/statusline-command.sh"

# Ensure ~/.claude exists
mkdir -p "$CLAUDE_DIR"

# Copy statusline script
cp "$SCRIPT_DIR/statusline-command.sh" "$TARGET_SCRIPT"
chmod +x "$TARGET_SCRIPT"
echo "Installed statusline-command.sh -> $TARGET_SCRIPT"

# Update settings.json with statusLine config
STATUSLINE_CONFIG='{"type":"command","command":"bash ~/.claude/statusline-command.sh"}'

if [ -f "$SETTINGS_FILE" ]; then
    # Merge statusLine into existing settings
    tmp=$(mktemp)
    jq --argjson sl "$STATUSLINE_CONFIG" '.statusLine = $sl' "$SETTINGS_FILE" > "$tmp" && mv "$tmp" "$SETTINGS_FILE"
    echo "Updated statusLine in $SETTINGS_FILE"
else
    # Create new settings.json
    echo "{\"statusLine\":$STATUSLINE_CONFIG}" | jq . > "$SETTINGS_FILE"
    echo "Created $SETTINGS_FILE with statusLine config"
fi

echo "Done! Restart Claude Code to apply."
