#!/bin/bash
input=$(cat)

# Check if there's a conversation yet
used_pct=$(echo "$input" | jq -r '.context_window.used_percentage // empty')

# Before any conversation, just show "-"
if [ -z "$used_pct" ] || [ "$used_pct" = "0" ]; then
    printf "\n-"
    exit 0
fi

g="\033[32m"
r="\033[0m"

model_name=$(echo "$input" | jq -r '.model.display_name // "Unknown"')
ctx_size=$(echo "$input" | jq -r '.context_window.context_window_size // 0')
cost=$(echo "$input" | jq -r '.cost.total_cost_usd // 0')
cwd=$(echo "$input" | jq -r '.workspace.current_dir // .cwd')

# Token counts in K
used_k=$(echo "scale=0; $ctx_size * $used_pct / 100 / 1000" | bc 2>/dev/null)
[ -z "$used_k" ] && used_k=0

# Format cost
cost_fmt=$(printf "%.2f" "$cost" 2>/dev/null)
[ -z "$cost_fmt" ] && cost_fmt="0.00"

# Git branch
branch=""
if git -C "$cwd" rev-parse --git-dir >/dev/null 2>&1; then
    branch=$(git -C "$cwd" --no-optional-locks rev-parse --abbrev-ref HEAD 2>/dev/null)
fi

printf "\n🪴 %s ${g}│${r} 🍀 %sk (%.0f%%) ${g}│${r} 🌱 \$%s" "$model_name" "$used_k" "$used_pct" "$cost_fmt"
[ -n "$branch" ] && printf " ${g}│${r} 🍃 %s" "$branch"
