$input = $input | ConvertFrom-Json

$modelName = if ($input.model.display_name) { $input.model.display_name } else { "Unknown" }
$usedPct = if ($input.context_window.used_percentage) { [double]$input.context_window.used_percentage } else { 0 }
$ctxSize = if ($input.context_window.context_window_size) { [long]$input.context_window.context_window_size } else { 0 }
$cost = if ($input.cost.total_cost_usd) { [double]$input.cost.total_cost_usd } else { 0 }
$cwd = if ($input.workspace.current_dir) { $input.workspace.current_dir } else { $input.cwd }

# Context bar
$barWidth = 20
$usedBars = [math]::Floor($usedPct * $barWidth / 100)
$bar = ("█" * $usedBars) + ("░" * ($barWidth - $usedBars))

# Token counts in K
$totalK = [math]::Floor($ctxSize / 1000)
$usedK = [math]::Floor($ctxSize * $usedPct / 100 / 1000)

# Format cost
$costFmt = $cost.ToString("F2")

# Git branch
$branch = ""
try {
    $branch = git -C $cwd --no-optional-locks rev-parse --abbrev-ref HEAD 2>$null
} catch {}

$output = "$modelName | [$bar] ${usedK}k/${totalK}k ($([math]::Round($usedPct))%) | `$$costFmt"
if ($branch) { $output += " |  $branch" }

Write-Output $output
