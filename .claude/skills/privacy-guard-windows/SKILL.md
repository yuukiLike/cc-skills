# Windows 隐私卫士 — 监控检测技能

> 检测 Windows 设备上可能存在的监控软件、间谍程序、异常网络活动和隐私侵害行为。

## 目的

以资深安全取证分析师身份行动。系统性地检查 Windows 设备上是否存在监控行为，包括但不限于：商业间谍软件、键盘记录器、屏幕截图程序、网络流量监控、中间人证书注入、隐蔽后门等。所有操作均为**保护用户自身隐私的防御性检测**。

## 使用方式

当此技能被激活时，按以下顺序执行全面扫描：

1. **进程检测** — 识别可疑进程和隐藏进程
2. **持久化检测** — 检查启动项、服务、计划任务
3. **网络检测** — 分析异常连接、可疑端口、DNS 配置
4. **文件系统检测** — 扫描已知监控软件的文件特征
5. **证书检测** — 检查中间人攻击证书
6. **权限检测** — 审计敏感权限和策略
7. **报告** — 输出检测结果和处置建议

---

## 第一阶段：可疑进程检测

### 1.1 已知监控软件进程名

```powershell
# PowerShell — 检查已知商业监控/间谍软件进程

Write-Host "=== 已知监控软件进程扫描 ===" -ForegroundColor Yellow

$spywareNames = @(
    # 商业间谍软件
    "flexispy", "mspy", "spyrix", "cocospy", "kidlogger",
    "refog", "hoverwatch", "spyera", "thetruthspy",
    "ikeymonitor", "clevguard", "eyezy", "webwatcher",
    "pcpandora", "spytech", "netspy", "realtime-spy",
    "spector", "SpectorSoft",
    # 企业监控
    "activtrak", "ActivTrakAgent",
    "teramind", "TeramindAgent",
    "hubstaff", "HubstaffClient",
    "timedoctor", "TimeDoctorPro",
    "desktime", "DesktimeClient",
    "veriato", "Veriato360",
    "interguard", "InterGuardAgent",
    "workpuls", "WorkpulsAgent",
    "sneakpeek", "SneakPeekAgent",
    "staffcop", "StaffCop",
    "controlio", "Controlio",
    # 键盘记录器
    "keylogger", "keystroke", "keycapture",
    "ardamax", "ArdamaxKeylogger",
    "revealer", "RevealerKeylogger",
    "shadowlogger", "bestlogger", "perfectkeylogger",
    "actual-spy", "actualspy",
    "allincapture", "kl-detector",
    # 远程访问工具
    "anydesk", "AnyDesk",
    "rustdesk",
    "teamviewer", "TeamViewer",
    "splashtop", "SplashtopStreamer",
    "bomgar", "BeyondTrust",
    "screenconnect", "ConnectWiseControl",
    "ammyy", "AmmyyAdmin",
    "ultraviewer", "UltraViewer",
    "supremo", "SupremoService",
    "remotepc", "RemotePC"
)

$foundProcesses = @()
$runningProcesses = Get-Process | Select-Object -Property Name, Id, Path, Company

foreach ($spy in $spywareNames) {
    $matches = $runningProcesses | Where-Object {
        $_.Name -like "*$spy*" -or $_.Path -like "*$spy*"
    }
    if ($matches) {
        Write-Host "[警告] 发现可疑进程: $spy" -ForegroundColor Red
        $matches | Format-Table Name, Id, Path -AutoSize
        $foundProcesses += $matches
    }
}

if ($foundProcesses.Count -eq 0) {
    Write-Host "[✓] 未发现已知监控软件进程" -ForegroundColor Green
}
```

### 1.2 可疑进程特征检测

```powershell
# 检查无描述、无公司信息、无签名的后台进程（可疑特征）
Write-Host "=== 无数字签名的后台进程 ===" -ForegroundColor Yellow

Get-Process | Where-Object { $_.MainWindowHandle -eq 0 } | ForEach-Object {
    $path = $_.Path
    if ($path) {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
        if ($sig.Status -ne "Valid") {
            [PSCustomObject]@{
                进程名 = $_.Name
                PID    = $_.Id
                路径   = $path
                签名   = $sig.Status
            }
        }
    }
} | Format-Table -AutoSize

# 检查从临时目录或用户目录运行的进程（常见恶意软件行为）
Write-Host "=== 从可疑路径运行的进程 ===" -ForegroundColor Yellow
Get-Process | Where-Object {
    $_.Path -and (
        $_.Path -like "*\Temp\*" -or
        $_.Path -like "*\AppData\Local\Temp\*" -or
        $_.Path -like "*\Downloads\*" -or
        $_.Path -like "*\Desktop\*" -or
        $_.Path -like "*\Public\*"
    )
} | Select-Object Name, Id, Path | Format-Table -AutoSize
```

### 1.3 隐藏窗口进程

```powershell
# 监控软件通常以隐藏窗口运行
Write-Host "=== 隐藏窗口但占用 CPU 的进程 ===" -ForegroundColor Yellow
Get-Process | Where-Object {
    $_.MainWindowHandle -eq 0 -and
    $_.CPU -gt 10 -and
    $_.Path -and
    $_.Path -notlike "*\Windows\*" -and
    $_.Path -notlike "*\Microsoft*"
} | Select-Object Name, Id, CPU, Path | Sort-Object CPU -Descending | Format-Table -AutoSize
```

---

## 第二阶段：持久化机制检测

### 2.1 注册表启动项

```powershell
Write-Host "=== 注册表启动项检查 ===" -ForegroundColor Yellow

# 所有关键的自启动注册表位置
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    # WoW64 注册表（64位系统上的 32 位程序）
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($items) {
            Write-Host "`n[$path]" -ForegroundColor Cyan
            $items.PSObject.Properties | Where-Object {
                $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSProvider")
            } | ForEach-Object {
                Write-Host "  $($_.Name) = $($_.Value)"
            }
        }
    }
}
```

### 2.2 Windows 服务

```powershell
Write-Host "=== 非 Microsoft 的自动启动服务 ===" -ForegroundColor Yellow

Get-WmiObject Win32_Service | Where-Object {
    $_.StartMode -eq "Auto" -and
    $_.PathName -and
    $_.PathName -notlike "*\Windows\*" -and
    $_.PathName -notlike "*Microsoft*"
} | Select-Object Name, DisplayName, State, PathName, StartName |
  Format-Table -AutoSize -Wrap

# 检查最近创建的服务
Write-Host "=== 最近 30 天创建的服务 ===" -ForegroundColor Yellow
Get-WinEvent -LogName "System" -FilterXPath "*[System[EventID=7045]]" -MaxEvents 20 -ErrorAction SilentlyContinue |
  ForEach-Object {
    [PSCustomObject]@{
        时间     = $_.TimeCreated
        服务名   = $_.Properties[0].Value
        可执行文件 = $_.Properties[1].Value
        启动类型   = $_.Properties[3].Value
    }
  } | Format-Table -AutoSize
```

### 2.3 计划任务

```powershell
Write-Host "=== 非 Microsoft 的计划任务 ===" -ForegroundColor Yellow

Get-ScheduledTask | Where-Object {
    $_.Author -and
    $_.Author -notlike "*Microsoft*" -and
    $_.Author -notlike "*Apple*" -and
    $_.State -ne "Disabled"
} | ForEach-Object {
    $actions = ($_.Actions | ForEach-Object { $_.Execute }) -join ", "
    [PSCustomObject]@{
        任务名 = $_.TaskName
        作者   = $_.Author
        状态   = $_.State
        执行   = $actions
        路径   = $_.TaskPath
    }
} | Format-Table -AutoSize -Wrap
```

### 2.4 WMI 事件订阅（高级持久化）

```powershell
# WMI 持久化是高级恶意软件/监控软件的常用手段
Write-Host "=== WMI 事件订阅（高级持久化）===" -ForegroundColor Yellow

Write-Host "事件过滤器:" -ForegroundColor Cyan
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -ErrorAction SilentlyContinue |
  Select-Object Name, Query | Format-Table -AutoSize

Write-Host "事件消费者:" -ForegroundColor Cyan
Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
  Select-Object Name, CommandLineTemplate | Format-Table -AutoSize

Get-WmiObject -Namespace "root\subscription" -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue |
  Select-Object Name, ScriptText | Format-Table -AutoSize

Write-Host "绑定关系:" -ForegroundColor Cyan
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
  Select-Object Filter, Consumer | Format-Table -AutoSize
```

### 2.5 Startup 文件夹

```powershell
Write-Host "=== 启动文件夹内容 ===" -ForegroundColor Yellow

$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $startupPaths) {
    Write-Host "`n[$path]" -ForegroundColor Cyan
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Force | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize
    } else {
        Write-Host "  目录不存在"
    }
}
```

---

## 第三阶段：网络检测

### 3.1 异常端口和连接

```powershell
Write-Host "=== 当前监听的端口 ===" -ForegroundColor Yellow
Get-NetTCPConnection -State Listen |
  Select-Object LocalPort, OwningProcess,
    @{Name='进程名'; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
  Sort-Object LocalPort | Format-Table -AutoSize

Write-Host "=== 已建立的外部连接 ===" -ForegroundColor Yellow
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.)" } |
  Select-Object RemoteAddress, RemotePort, OwningProcess,
    @{Name='进程名'; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
  Sort-Object RemoteAddress | Format-Table -AutoSize

# 检查可疑端口
Write-Host "=== 可疑端口检测 ===" -ForegroundColor Yellow
$suspiciousPorts = @(4444, 4445, 1337, 31337, 5555, 6666, 7777, 12345, 54321,
                     5900, 5901, # VNC
                     3389)       # 如果不是你开启的 RDP
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalPort -in $suspiciousPorts } |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "[警告] 可疑端口 $($_.LocalPort) 正在监听 (进程: $($proc.Name), PID: $($_.OwningProcess))" -ForegroundColor Red
  }
```

### 3.2 DNS 配置检查

```powershell
Write-Host "=== DNS 服务器配置 ===" -ForegroundColor Yellow
Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } |
  Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize

Write-Host "=== DNS 缓存中的可疑域名 ===" -ForegroundColor Yellow
# 查找可能与监控相关的 DNS 解析记录
$suspiciousDomains = "spy|monitor|track|keylog|capture|surveil|sniff|intercept"
Get-DnsClientCache | Where-Object { $_.Entry -match $suspiciousDomains } |
  Select-Object Entry, Data | Format-Table -AutoSize

Write-Host "=== hosts 文件可疑条目 ===" -ForegroundColor Yellow
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" |
  Where-Object { $_ -notmatch "^#" -and $_ -notmatch "^\s*$" -and $_ -notmatch "localhost" }
```

### 3.3 代理设置检查

```powershell
Write-Host "=== 系统代理设置 ===" -ForegroundColor Yellow

# IE/系统代理
$proxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($proxy.ProxyEnable -eq 1) {
    Write-Host "[警告] 系统代理已启用！" -ForegroundColor Red
    Write-Host "  代理服务器: $($proxy.ProxyServer)"
    Write-Host "  绕过列表: $($proxy.ProxyOverride)"
} else {
    Write-Host "[✓] 系统代理未启用" -ForegroundColor Green
}

# 检查 PAC 自动配置
if ($proxy.AutoConfigURL) {
    Write-Host "[警告] 检测到 PAC 自动代理配置: $($proxy.AutoConfigURL)" -ForegroundColor Red
}

# 环境变量代理
Write-Host "`n=== 环境变量代理 ===" -ForegroundColor Yellow
@("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY") | ForEach-Object {
    $val = [Environment]::GetEnvironmentVariable($_, "User")
    if ($val) { Write-Host "[信息] $_ = $val" -ForegroundColor Cyan }
    $val = [Environment]::GetEnvironmentVariable($_, "Machine")
    if ($val) { Write-Host "[信息] $_ (系统级) = $val" -ForegroundColor Cyan }
}
```

### 3.4 防火墙状态

```powershell
Write-Host "=== 防火墙配置 ===" -ForegroundColor Yellow
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize

# 检查可疑的防火墙允许规则
Write-Host "=== 最近添加的入站允许规则 ===" -ForegroundColor Yellow
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
  Where-Object { $_.DisplayName -notlike "*Windows*" -and $_.DisplayName -notlike "*Microsoft*" -and $_.DisplayName -notlike "*Core Networking*" } |
  Select-Object DisplayName, Profile, Direction,
    @{Name='程序'; Expression={($_ | Get-NetFirewallApplicationFilter).Program}} |
  Format-Table -AutoSize -Wrap
```

### 3.5 网络嗅探检测

```powershell
# 检查混杂模式和抓包工具
Write-Host "=== 网络嗅探检测 ===" -ForegroundColor Yellow

# 检查抓包进程
$sniffers = @("Wireshark", "tshark", "tcpdump", "npcap", "WinPcap",
              "mitmproxy", "Fiddler", "Charles", "Burp", "HttpAnalyzer",
              "NetworkMiner", "SmartSniff", "Capsa")
$found = Get-Process | Where-Object { $_.Name -in $sniffers }
if ($found) {
    Write-Host "[警告] 发现网络抓包程序正在运行：" -ForegroundColor Red
    $found | Select-Object Name, Id, Path | Format-Table -AutoSize
} else {
    Write-Host "[✓] 未发现网络抓包程序" -ForegroundColor Green
}

# 检查 Npcap/WinPcap 驱动（抓包前提）
Write-Host "=== 网络捕获驱动 ===" -ForegroundColor Yellow
Get-WindowsDriver -Online -ErrorAction SilentlyContinue |
  Where-Object { $_.OriginalFileName -like "*npcap*" -or $_.OriginalFileName -like "*npf*" -or $_.OriginalFileName -like "*winpcap*" } |
  Select-Object Driver, OriginalFileName, ProviderName | Format-Table -AutoSize
```

---

## 第四阶段：文件系统检测

### 4.1 可疑目录和文件扫描

```powershell
Write-Host "=== 扫描可疑安装目录 ===" -ForegroundColor Yellow

$suspectPaths = @(
    "$env:ProgramFiles\FlexiSPY",
    "$env:ProgramFiles\mSpy",
    "$env:ProgramFiles\Spyrix",
    "$env:ProgramFiles\Refog",
    "$env:ProgramFiles\Hoverwatch",
    "$env:ProgramFiles\ClevGuard",
    "$env:ProgramFiles\ActivTrak",
    "$env:ProgramFiles\Teramind",
    "$env:ProgramFiles\Veriato",
    "$env:ProgramFiles\InterGuard",
    "$env:ProgramFiles\StaffCop",
    "$env:ProgramFiles\Controlio",
    "$env:ProgramFiles (x86)\FlexiSPY",
    "$env:ProgramFiles (x86)\Spyrix",
    "$env:ProgramFiles (x86)\Refog",
    "$env:ProgramFiles (x86)\Ardamax Keylogger",
    "$env:ProgramFiles (x86)\Revealer Keylogger",
    "$env:LOCALAPPDATA\Spyware",
    "$env:APPDATA\.hidden",
    "$env:TEMP\.monitor",
    "C:\ProgramData\.hidden"
)

foreach ($path in $suspectPaths) {
    if (Test-Path $path) {
        Write-Host "[警告] 发现可疑目录: $path" -ForegroundColor Red
        Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue |
          Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize
    }
}

# 查找隐藏的可执行文件
Write-Host "=== AppData 下的隐藏可执行文件 ===" -ForegroundColor Yellow
Get-ChildItem -Path $env:APPDATA, $env:LOCALAPPDATA -Recurse -Force -Filter "*.exe" -ErrorAction SilentlyContinue |
  Where-Object { $_.Attributes -match "Hidden" } |
  Select-Object FullName, LastWriteTime, Length | Format-Table -AutoSize -Wrap
```

### 4.2 最近安装的程序

```powershell
Write-Host "=== 最近 30 天安装的程序 ===" -ForegroundColor Yellow
$cutoff = (Get-Date).AddDays(-30)

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                 HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object { $_.InstallDate -and [datetime]::ParseExact($_.InstallDate, "yyyyMMdd", $null) -gt $cutoff } |
  Select-Object DisplayName, Publisher, InstallDate, InstallLocation |
  Sort-Object InstallDate -Descending | Format-Table -AutoSize
```

### 4.3 异常 DLL 检测

```powershell
# 检查常见的 DLL 注入（键盘记录常用手段）
Write-Host "=== 可疑的全局钩子 DLL ===" -ForegroundColor Yellow

# 检查 AppInit_DLLs（经典 DLL 注入路径）
$appInit = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
if ($appInit.AppInit_DLLs) {
    Write-Host "[警告] AppInit_DLLs 不为空: $($appInit.AppInit_DLLs)" -ForegroundColor Red
}

# 检查 64 位
$appInit64 = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
if ($appInit64.AppInit_DLLs) {
    Write-Host "[警告] AppInit_DLLs (WOW64) 不为空: $($appInit64.AppInit_DLLs)" -ForegroundColor Red
}

# Image File Execution Options（IFEO 劫持）
Write-Host "=== IFEO 调试器劫持 ===" -ForegroundColor Yellow
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $debugger = (Get-ItemProperty $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
    if ($debugger) {
      Write-Host "[警告] $($_.PSChildName) 被劫持到: $debugger" -ForegroundColor Red
    }
  }
```

---

## 第五阶段：证书检测（中间人攻击）

### 5.1 可疑根证书

```powershell
Write-Host "=== 非标准根证书检测 ===" -ForegroundColor Yellow

# 已知可信的根证书颁发者关键词
$trustedIssuers = @(
    "Microsoft", "DigiCert", "VeriSign", "GlobalSign", "Comodo",
    "Let's Encrypt", "GeoTrust", "Entrust", "Sectigo", "Baltimore",
    "Starfield", "Amazon", "Google Trust", "ISRG", "QuoVadis",
    "Thawte", "Certum", "Buypass", "SwissSign", "T-Systems",
    "Visa", "Wells Fargo", "Apple", "AAA Certificate"
)

$rootCerts = Get-ChildItem Cert:\LocalMachine\Root
foreach ($cert in $rootCerts) {
    $isTrusted = $false
    foreach ($issuer in $trustedIssuers) {
        if ($cert.Issuer -like "*$issuer*" -or $cert.Subject -like "*$issuer*") {
            $isTrusted = $true
            break
        }
    }
    if (-not $isTrusted) {
        Write-Host "[检查] 非标准根证书:" -ForegroundColor Yellow
        Write-Host "  主题: $($cert.Subject)"
        Write-Host "  颁发者: $($cert.Issuer)"
        Write-Host "  有效期: $($cert.NotBefore) 到 $($cert.NotAfter)"
        Write-Host "  指纹: $($cert.Thumbprint)"
        Write-Host ""
    }
}

# 检查用户级根证书（更可疑）
Write-Host "=== 用户级根证书 ===" -ForegroundColor Yellow
$userRootCerts = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue
foreach ($cert in $userRootCerts) {
    $isTrusted = $false
    foreach ($issuer in $trustedIssuers) {
        if ($cert.Subject -like "*$issuer*") { $isTrusted = $true; break }
    }
    if (-not $isTrusted) {
        Write-Host "[警告] 用户级非标准根证书: $($cert.Subject)" -ForegroundColor Red
    }
}
```

### 5.2 HTTPS 中间人检测

```powershell
Write-Host "=== HTTPS 中间人检测 ===" -ForegroundColor Yellow

$testSites = @("google.com", "microsoft.com", "github.com")
$suspiciousIssuers = "corporate|enterprise|proxy|firewall|security|filter|inspect|decrypt|mitm|zscaler|fortinet|paloalto|bluecoat|symantec.*proxy|checkpoint|barracuda|cisco.*umbrella|forcepoint"

foreach ($site in $testSites) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient($site, 443)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false,
            { param($s, $c, $ch, $e) return $true })
        $ssl.AuthenticateAsClient($site)
        $cert = $ssl.RemoteCertificate
        $issuer = $cert.Issuer

        if ($issuer -match $suspiciousIssuers) {
            Write-Host "[警告] $site 证书被企业代理签发: $issuer" -ForegroundColor Red
        } else {
            Write-Host "[✓] $site 证书正常: $issuer" -ForegroundColor Green
        }

        $ssl.Close()
        $tcp.Close()
    } catch {
        Write-Host "[错误] 无法连接 $site : $_" -ForegroundColor Red
    }
}
```

---

## 第六阶段：系统策略和权限检测

### 6.1 组策略检查

```powershell
Write-Host "=== 影响隐私的组策略 ===" -ForegroundColor Yellow

# 检查审计策略（是否在记录你的操作）
Write-Host "审计策略:" -ForegroundColor Cyan
auditpol /get /category:* 2>$null | Where-Object { $_ -match "成功|失败|Success|Failure" }

# 检查是否限制了你的操作
Write-Host "`n受限策略:" -ForegroundColor Cyan
$policies = @{
    "禁用任务管理器" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr"
    "禁用注册表编辑器" = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools"
    "禁用命令提示符" = "HKCU:\Software\Policies\Microsoft\Windows\System\DisableCMD"
}

foreach ($item in $policies.GetEnumerator()) {
    $parent = Split-Path $item.Value
    $name = Split-Path $item.Value -Leaf
    $val = Get-ItemProperty -Path $parent -Name $name -ErrorAction SilentlyContinue
    if ($val.$name -eq 1) {
        Write-Host "[警告] $($item.Key) 已被启用！" -ForegroundColor Red
    }
}
```

### 6.2 远程桌面检测

```powershell
Write-Host "=== 远程桌面状态 ===" -ForegroundColor Yellow

$rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
if ($rdp.fDenyTSConnections -eq 0) {
    Write-Host "[警告] 远程桌面已启用！他人可能可以远程访问此电脑" -ForegroundColor Red

    # 检查最近的 RDP 登录
    Write-Host "最近的 RDP 登录记录:" -ForegroundColor Cyan
    Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue |
      Where-Object { $_.Id -eq 21 -or $_.Id -eq 25 } |
      Select-Object TimeCreated, Message | Format-Table -AutoSize -Wrap
} else {
    Write-Host "[✓] 远程桌面已禁用" -ForegroundColor Green
}
```

### 6.3 共享文件夹检查

```powershell
Write-Host "=== 网络共享文件夹 ===" -ForegroundColor Yellow
Get-SmbShare | Where-Object {
    $_.Name -notlike "*$" -or $_.Name -eq "C$" -or $_.Name -eq "ADMIN$"
} | Select-Object Name, Path, Description | Format-Table -AutoSize

# 管理共享
Write-Host "=== 管理共享（如果不需要应禁用）===" -ForegroundColor Yellow
Get-SmbShare | Where-Object { $_.Name -like "*$" } |
  Select-Object Name, Path | Format-Table -AutoSize
```

### 6.4 剪贴板和屏幕截图检测

```powershell
# 检查是否有程序在监控剪贴板
Write-Host "=== 剪贴板监控检测 ===" -ForegroundColor Yellow

# 检查是否启用了剪贴板历史（Windows 10+）
$clipHistory = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue
if ($clipHistory.EnableClipboardHistory -eq 1) {
    Write-Host "[信息] 剪贴板历史已启用（Win+V 可查看），注意不要复制敏感信息" -ForegroundColor Cyan
}

# 检查是否启用了跨设备剪贴板同步
$clipSync = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableCloudClipboard" -ErrorAction SilentlyContinue
if ($clipSync.EnableCloudClipboard -eq 1) {
    Write-Host "[警告] 剪贴板云同步已启用！你的剪贴板内容会被上传到 Microsoft 服务器" -ForegroundColor Red
}
```

---

## 第七阶段：综合一键扫描脚本

```powershell
# Windows 隐私卫士 — 综合监控检测脚本
# 用途：检测 Windows 上可能存在的监控软件和隐私侵害
# 使用方法：以管理员权限运行 PowerShell，执行此脚本
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

param(
    [string]$ReportPath = "$env:USERPROFILE\Desktop\privacy_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

$alerts = 0

function Write-Section($text) {
    $msg = "`n========== $text =========="
    Write-Host $msg -ForegroundColor Yellow
    $msg | Out-File -FilePath $ReportPath -Append
}

function Write-Alert($text) {
    $script:alerts++
    $msg = "[!] 警告: $text"
    Write-Host $msg -ForegroundColor Red
    $msg | Out-File -FilePath $ReportPath -Append
}

function Write-Ok($text) {
    $msg = "[✓] $text"
    Write-Host $msg -ForegroundColor Green
    $msg | Out-File -FilePath $ReportPath -Append
}

function Write-Info($text) {
    $msg = "[*] $text"
    Write-Host $msg -ForegroundColor Cyan
    $msg | Out-File -FilePath $ReportPath -Append
}

# 报告头部
$header = @"
Windows 隐私卫士扫描报告
扫描时间: $(Get-Date)
计算机名: $env:COMPUTERNAME
用户名: $env:USERNAME
系统版本: $((Get-CimInstance Win32_OperatingSystem).Caption)
"@
$header | Out-File -FilePath $ReportPath
Write-Host $header

# 1. 进程扫描
Write-Section "1. 可疑进程扫描"
$spyNames = "flexispy|mspy|spyrix|cocospy|kidlogger|refog|hoverwatch|spyera|clevguard|eyezy|webwatcher|activtrak|teramind|hubstaff|veriato|interguard|workpuls|staffcop|controlio|keylogger|keystroke|ardamax|actualspy"
$spyProcs = Get-Process | Where-Object { $_.Name -match $spyNames -or ($_.Path -and $_.Path -match $spyNames) }
if ($spyProcs) {
    Write-Alert "发现已知监控软件进程！"
    $spyProcs | ForEach-Object { Write-Info "  $($_.Name) (PID: $($_.Id)) -> $($_.Path)" }
} else {
    Write-Ok "未发现已知监控软件进程"
}

# 2. 持久化检测
Write-Section "2. 持久化机制检测"
$runKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
             "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        $items.PSObject.Properties | Where-Object {
            $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSProvider")
        } | ForEach-Object {
            Write-Info "启动项: $($_.Name) = $($_.Value)"
        }
    }
}

# 3. 网络检测
Write-Section "3. 网络连接检测"
$listenPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
$suspPorts = $listenPorts | Where-Object { $_.LocalPort -in @(4444,4445,1337,31337,5555,5900,5901) }
foreach ($p in $suspPorts) {
    $proc = (Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue).Name
    Write-Alert "可疑端口 $($p.LocalPort) 正在监听 (进程: $proc)"
}

$proxy = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue)
if ($proxy.ProxyEnable -eq 1) {
    Write-Alert "系统代理已启用: $($proxy.ProxyServer)"
}

# 4. 证书检测
Write-Section "4. TLS 证书检测"
foreach ($site in @("google.com", "github.com")) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient($site, 443)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { return $true })
        $ssl.AuthenticateAsClient($site)
        $issuer = $ssl.RemoteCertificate.Issuer
        $ssl.Close(); $tcp.Close()
        if ($issuer -match "corporate|enterprise|proxy|firewall|zscaler|fortinet|paloalto|bluecoat|checkpoint") {
            Write-Alert "$site 证书由企业代理签发: $issuer"
        } else {
            Write-Ok "$site 证书正常"
        }
    } catch { Write-Info "无法检测 $site" }
}

# 5. 远程桌面
Write-Section "5. 远程访问检测"
$rdp = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections
if ($rdp -eq 0) { Write-Alert "远程桌面已启用" } else { Write-Ok "远程桌面已禁用" }

# 总结
Write-Section "扫描总结"
if ($alerts -eq 0) {
    Write-Ok "未发现明显的监控迹象"
} else {
    Write-Alert "共发现 $alerts 个警告项，请仔细审查上述报告"
}

Write-Host "`n完整报告已保存至: $ReportPath" -ForegroundColor Green
```

---

## 报告格式

对每个发现，按以下格式输出：

```
### [风险等级] 发现标题

- **类型**：进程/持久化/网络/证书/权限/文件
- **位置**：具体路径或进程名
- **详情**：发现了什么

**风险说明**：这意味着什么。

**处置建议**：如何消除威胁。
```

风险等级：严重 > 高危 > 中危 > 低危 > 信息

---

## 处置指南

### 发现监控软件后的操作步骤

```
1. 不要惊慌，不要立即删除（保留证据）
2. 截图/记录所有发现
3. 如果是企业设备：
   - 了解公司监控政策
   - 不要在工作设备上处理私人事务
4. 如果是个人设备被入侵：
   - 断开网络
   - 导出重要数据到安全的外部存储
   - 修改所有密码（在另一台安全设备上进行）
   - 启用所有账户的两步验证
   - 考虑重装系统（最彻底的方式）
5. 加固措施：
   - 启用 BitLocker 全盘加密
   - 启用 Windows Defender 防火墙
   - 启用 Windows Defender 实时保护
   - 定期检查「设置 > 隐私和安全性」
   - 保持系统更新
   - 不要安装来源不明的软件
   - 设置强密码和 Windows Hello
   - 禁用不需要的远程桌面
   - 检查「设置 > 账户 > 其他用户」是否有陌生账户
```

---

## 参考资料

详见 `references/` 目录中的检测规则和已知监控软件数据库。
