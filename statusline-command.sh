#!/bin/bash
input=$(cat)

model_name=$(echo "$input" | jq -r '.model.display_name // "Unknown"')
used_pct=$(echo "$input" | jq -r '.context_window.used_percentage // 0')
ctx_size=$(echo "$input" | jq -r '.context_window.context_window_size // 0')
cost=$(echo "$input" | jq -r '.cost.total_cost_usd // 0')
cwd=$(echo "$input" | jq -r '.workspace.current_dir // .cwd')

# Context bar
bar_width=20
used_bars=$(echo "scale=0; $used_pct * $bar_width / 100" | bc)
[ -z "$used_bars" ] && used_bars=0
bar=""
for ((i=0; i<bar_width; i++)); do
    if [ $i -lt $used_bars ]; then bar+="█"; else bar+="░"; fi
done

# Token counts in K
total_k=$(echo "scale=0; $ctx_size / 1000" | bc)
used_k=$(echo "scale=0; $ctx_size * $used_pct / 100 / 1000" | bc)

# Format cost with leading zero
cost_fmt=$(printf "%.2f" "$cost")

# Git branch
branch=""
if git -C "$cwd" rev-parse --git-dir >/dev/null 2>&1; then
    branch=$(git -C "$cwd" --no-optional-locks rev-parse --abbrev-ref HEAD 2>/dev/null)
fi

printf "%s | [%s] %sk/%sk (%.0f%%) | \$%s" "$model_name" "$bar" "$used_k" "$total_k" "$used_pct" "$cost_fmt"
[ -n "$branch" ] && printf " |  %s" "$branch"
