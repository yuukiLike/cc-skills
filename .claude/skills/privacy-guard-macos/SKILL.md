# macOS 隐私卫士 — 监控检测技能

> 检测 macOS 设备上可能存在的监控软件、间谍程序、异常网络活动和隐私侵害行为。

## 目的

以资深安全取证分析师身份行动。系统性地检查 macOS 设备上是否存在监控行为，包括但不限于：商业间谍软件、键盘记录器、屏幕截图程序、网络流量监控、中间人证书注入、隐蔽后门等。所有操作均为**保护用户自身隐私的防御性检测**。

## 使用方式

当此技能被激活时，按以下顺序执行全面扫描：

1. **进程检测** — 识别可疑进程和隐藏进程
2. **持久化检测** — 检查启动项、守护进程、计划任务
3. **网络检测** — 分析异常连接、可疑端口、DNS 配置
4. **文件系统检测** — 扫描已知监控软件的文件特征
5. **证书检测** — 检查中间人攻击证书
6. **权限检测** — 审计敏感权限授予情况
7. **报告** — 输出检测结果和处置建议

---

## 第一阶段：可疑进程检测

### 1.1 已知监控软件进程名

```bash
# 检查已知商业监控/间谍软件进程
# 包含：FlexiSPY、mSpy、Spyrix、Cocospy、Kidlogger、Refog 等

echo "=== 已知监控软件进程扫描 ==="
KNOWN_SPYWARE=(
  # 商业间谍软件
  "flexispy"
  "mspy"
  "spyrix"
  "cocospy"
  "kidlogger"
  "refog"
  "hoverwatch"
  "spyera"
  "thetruthspy"
  "iKeyMonitor"
  "ikeymonitor"
  "clevguard"
  "eyezy"
  "parentalcontrol"
  "webwatcher"
  # 企业监控
  "activtrak"
  "teramind"
  "hubstaff"
  "timedoctor"
  "desktime"
  "veriato"
  "interguard"
  "workpuls"
  # 键盘记录器
  "keylogger"
  "keystroke"
  "keycapture"
  "logkext"
  "aobo"
  "amac"
  "easemon"
  # 远程访问/控制
  "anydesk"
  "rustdesk"
  "teamviewer"
  "splashtop"
  "bomgar"
  "screenconnect"
  "connectwise"
  "ammyy"
  "vnc"          # 需要确认是否用户自己安装
  "tightvnc"
  "ultravnc"
  "realvnc"
)

for name in "${KNOWN_SPYWARE[@]}"; do
  result=$(ps aux | grep -i "$name" | grep -v grep)
  if [ -n "$result" ]; then
    echo "[警告] 发现可疑进程: $name"
    echo "$result"
  fi
done
```

### 1.2 隐藏进程检测

```bash
# 比较 ps 输出和 /proc 信息，寻找隐藏进程
echo "=== 隐藏进程检测 ==="

# 检查所有进程，重点关注无路径或路径可疑的进程
ps aux | awk '$11 !~ /^\[/ && $11 !~ /^\/usr/ && $11 !~ /^\/System/ && $11 !~ /^\/sbin/ && $11 !~ /^\/Library\/Apple/' | head -50

# 查找以 root 运行但不属于系统的可疑进程
echo "=== 非系统 root 进程 ==="
ps aux | awk '$1 == "root" && $11 !~ /^\/usr/ && $11 !~ /^\/System/ && $11 !~ /^\/sbin/ && $11 !~ /^\/Library\/Apple/ && $11 !~ /kernel/'
```

### 1.3 CPU/内存异常检测

```bash
# 查找 CPU 或内存占用异常的进程（监控软件可能消耗资源）
echo "=== 资源异常进程（CPU > 10% 或内存 > 5%）==="
ps aux | awk 'NR>1 && ($3 > 10.0 || $4 > 5.0) {print $0}'

# 查找长期运行但不认识的进程
echo "=== 长期运行的非系统进程 ==="
ps -eo pid,etime,user,comm | sort -k2 -r | head -30
```

---

## 第二阶段：持久化机制检测

### 2.1 Launch Agents & Daemons

```bash
# 这是 macOS 上最常见的持久化方式
# 监控软件几乎都会在这里注册

echo "=== 用户级 Launch Agents ==="
ls -la ~/Library/LaunchAgents/ 2>/dev/null
echo ""

echo "=== 系统级 Launch Agents ==="
ls -la /Library/LaunchAgents/ 2>/dev/null
echo ""

echo "=== 系统级 Launch Daemons ==="
ls -la /Library/LaunchDaemons/ 2>/dev/null
echo ""

echo "=== Apple 系统 Launch Daemons（仅检查非 Apple 的）==="
ls -la /System/Library/LaunchDaemons/ 2>/dev/null | grep -v "com.apple"
echo ""

# 详细检查每个 plist 的内容，寻找可疑程序
echo "=== 检查非 Apple Launch Agent/Daemon 内容 ==="
for plist in ~/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
  if [ -f "$plist" ]; then
    label=$(defaults read "$plist" Label 2>/dev/null)
    program=$(defaults read "$plist" Program 2>/dev/null || defaults read "$plist" ProgramArguments 2>/dev/null)
    # 过滤掉已知安全的
    if [[ "$label" != com.apple.* ]]; then
      echo "[检查] $plist"
      echo "  标签: $label"
      echo "  程序: $program"
      echo ""
    fi
  fi
done
```

### 2.2 Login Items（登录项）

```bash
# 检查登录时自动启动的项目
echo "=== 登录项 ==="
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null

# 使用 sfltool 检查（macOS 13+）
echo "=== 后台登录项（macOS 13+）==="
sfltool dumpbtm 2>/dev/null | head -100
```

### 2.3 Cron Jobs

```bash
echo "=== 当前用户 Cron 任务 ==="
crontab -l 2>/dev/null || echo "无 cron 任务"

echo "=== 系统级 Cron 任务 ==="
ls -la /etc/cron.d/ 2>/dev/null
ls -la /var/at/jobs/ 2>/dev/null

echo "=== /etc/periodic 任务 ==="
ls -la /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null
```

### 2.4 内核扩展（Kext）

```bash
# 监控软件可能安装内核扩展来隐藏自身
echo "=== 第三方内核扩展 ==="
kextstat 2>/dev/null | grep -v "com.apple" | grep -v "Loaded"

echo "=== 系统扩展 ==="
systemextensionsctl list 2>/dev/null
```

### 2.5 配置描述文件（Profiles）

```bash
# MDM 或监控软件可能安装配置描述文件来控制设备
echo "=== 已安装的配置描述文件 ==="
profiles list 2>/dev/null

# 检查是否被 MDM 管理
echo "=== MDM 注册状态 ==="
profiles status -type enrollment 2>/dev/null
```

---

## 第三阶段：网络检测

### 3.1 异常端口和连接

```bash
# 检查所有监听端口
echo "=== 当前监听的端口 ==="
lsof -i -P -n | grep LISTEN | sort -t: -k2 -n

# 检查所有已建立的外部连接
echo "=== 已建立的外部连接 ==="
lsof -i -P -n | grep ESTABLISHED | grep -v "127.0.0.1" | grep -v "::1"

# 检查可疑的外部连接（非标准端口）
echo "=== 非标准端口的外部连接 ==="
netstat -an | grep ESTABLISHED | grep -v ":443 " | grep -v ":80 " | grep -v ":53 " | grep -v "127.0.0.1" | grep -v "::1"
```

### 3.2 DNS 配置检查

```bash
# 检查 DNS 是否被篡改（可能用于流量监控）
echo "=== DNS 配置 ==="
scutil --dns | grep "nameserver" | sort -u

echo "=== /etc/resolv.conf ==="
cat /etc/resolv.conf 2>/dev/null

echo "=== /etc/hosts 可疑条目 ==="
cat /etc/hosts | grep -v "^#" | grep -v "^$" | grep -v "localhost" | grep -v "broadcasthost"
```

### 3.3 VPN/代理检查

```bash
# 检查是否被强制通过代理（流量可能被监控）
echo "=== 系统代理设置 ==="
networksetup -getwebproxy Wi-Fi 2>/dev/null
networksetup -getsecurewebproxy Wi-Fi 2>/dev/null
networksetup -getsocksfirewallproxy Wi-Fi 2>/dev/null

echo "=== 环境变量代理 ==="
echo "HTTP_PROXY=$HTTP_PROXY"
echo "HTTPS_PROXY=$HTTPS_PROXY"
echo "ALL_PROXY=$ALL_PROXY"

echo "=== 活跃的 VPN/隧道接口 ==="
ifconfig | grep -A1 "utun\|tap\|tun\|ppp" 2>/dev/null

echo "=== 网络服务列表 ==="
networksetup -listallnetworkservices 2>/dev/null
```

### 3.4 防火墙状态

```bash
echo "=== 应用防火墙状态 ==="
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null

echo "=== pf 防火墙状态 ==="
sudo pfctl -s info 2>/dev/null | head -5

echo "=== 防火墙允许的应用 ==="
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null
```

### 3.5 网络流量嗅探检测

```bash
# 检查是否有进程在进行网络嗅探
echo "=== 混杂模式检测（网卡嗅探）==="
ifconfig 2>/dev/null | grep -i "promisc"

echo "=== 可能在抓包的进程 ==="
ps aux | grep -i "tcpdump\|wireshark\|tshark\|ngrep\|ettercap\|mitmproxy\|charles\|fiddler\|proxyman\|burp" | grep -v grep
```

---

## 第四阶段：文件系统检测

### 4.1 可疑目录扫描

```bash
# 检查常见的监控软件安装路径
echo "=== 扫描可疑目录 ==="
SUSPECT_DIRS=(
  "/Library/Application Support/JAMF"
  "/Library/Application Support/Kandji"
  "/Library/Application Support/Mosyle"
  "/Library/Application Support/FleetDM"
  "$HOME/.flexispy"
  "$HOME/.mspy"
  "$HOME/.spyware"
  "/usr/local/spyware"
  "/Library/Application Support/ClevGuard"
  "/Library/Application Support/Spyrix"
  "$HOME/Library/Application Support/.hidden"
  "/opt/.hidden"
  "/tmp/.hidden"
  "/var/tmp/.hidden"
)

for dir in "${SUSPECT_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    echo "[警告] 发现可疑目录: $dir"
    ls -la "$dir"
  fi
done

# 查找隐藏目录（以 . 开头的非标准目录）
echo "=== /Library 下的隐藏目录 ==="
find /Library -maxdepth 2 -name ".*" -type d 2>/dev/null

echo "=== 用户目录下的可疑隐藏目录 ==="
find "$HOME/Library/Application Support" -maxdepth 1 -name ".*" -type d 2>/dev/null
```

### 4.2 最近修改的可疑文件

```bash
# 查找最近 7 天内在敏感位置修改的文件
echo "=== 最近 7 天修改的 Launch 配置 ==="
find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons -mtime -7 -type f 2>/dev/null

echo "=== 最近 7 天修改的可执行文件（/usr/local）==="
find /usr/local/bin /usr/local/sbin -mtime -7 -type f 2>/dev/null

echo "=== 最近 24 小时新创建的隐藏文件 ==="
find /tmp /var/tmp "$HOME" -maxdepth 2 -name ".*" -newer /tmp -mtime -1 -type f 2>/dev/null
```

### 4.3 Accessibility（辅助功能）权限滥用检测

```bash
# 很多监控软件需要辅助功能权限来记录键盘输入
echo "=== 拥有辅助功能权限的应用 ==="
# TCC.db 存储了权限授予记录
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceAccessibility'" 2>/dev/null

echo "=== 拥有屏幕录制权限的应用 ==="
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture'" 2>/dev/null

echo "=== 拥有输入监控权限的应用 ==="
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent'" 2>/dev/null

echo "=== 拥有完全磁盘访问权限的应用 ==="
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceSystemPolicyAllFiles'" 2>/dev/null
```

---

## 第五阶段：证书检测（中间人攻击）

### 5.1 系统钥匙串检查

```bash
# 检查是否安装了可疑的根证书（用于 HTTPS 中间人监听）
echo "=== 非 Apple 的自定义根证书 ==="
security find-certificate -a -p /Library/Keychains/System.keychain | \
  openssl x509 -noout -subject -issuer 2>/dev/null | \
  grep -v "Apple" | grep -v "DigiCert" | grep -v "VeriSign" | \
  grep -v "GlobalSign" | grep -v "Comodo" | grep -v "Let's Encrypt" | \
  grep -v "GeoTrust" | grep -v "Entrust" | grep -v "Sectigo" | \
  grep -v "Baltimore" | grep -v "AAA Certificate" | grep -v "Starfield" | \
  grep -v "Amazon" | grep -v "Google Trust" | grep -v "ISRG"

echo "=== 用户钥匙串中的根证书 ==="
security find-certificate -a -p "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null | \
  openssl x509 -noout -subject 2>/dev/null

echo "=== 管理员添加的信任证书 ==="
security dump-trust-settings -d 2>/dev/null | head -50
```

### 5.2 证书透明度检查

```bash
# 快速测试是否存在 SSL 中间人
echo "=== 测试主要网站的证书（检测 MITM）==="
for site in "google.com" "apple.com" "github.com"; do
  echo "--- $site ---"
  echo | openssl s_client -connect "$site:443" -servername "$site" 2>/dev/null | \
    openssl x509 -noout -issuer -subject -dates 2>/dev/null
  echo ""
done
```

---

## 第六阶段：浏览器和输入设备检测

### 6.1 浏览器扩展检查

```bash
# Chrome 扩展
echo "=== Chrome 扩展 ==="
if [ -d "$HOME/Library/Application Support/Google/Chrome/Default/Extensions" ]; then
  for ext_dir in "$HOME/Library/Application Support/Google/Chrome/Default/Extensions"/*/; do
    manifest="$ext_dir/*/manifest.json"
    if [ -f $manifest ]; then
      name=$(python3 -c "import json; print(json.load(open('$manifest'))['name'])" 2>/dev/null)
      perms=$(python3 -c "import json; print(json.load(open('$manifest')).get('permissions', []))" 2>/dev/null)
      echo "  扩展: $name"
      echo "  权限: $perms"
      echo ""
    fi
  done
fi

# Safari 扩展
echo "=== Safari 扩展 ==="
pluginkit -mA 2>/dev/null | grep "safari"

# Firefox 扩展
echo "=== Firefox 扩展 ==="
find "$HOME/Library/Application Support/Firefox/Profiles" -name "extensions.json" -exec cat {} \; 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for ext in data.get('addons', []):
        if ext.get('type') == 'extension':
            print(f\"  {ext.get('defaultLocale', {}).get('name', 'Unknown')}: {ext.get('id', 'N/A')}\")
except: pass
" 2>/dev/null
```

### 6.2 输入设备检查

```bash
# 检查是否有异常的 HID 设备（可能是硬件键盘记录器）
echo "=== USB HID 设备 ==="
system_profiler SPUSBDataType 2>/dev/null | grep -A5 "Human Interface"

echo "=== 蓝牙连接设备 ==="
system_profiler SPBluetoothDataType 2>/dev/null | grep -A3 "Name\|Address\|Connected"
```

### 6.3 摄像头和麦克风使用检测

```bash
# 检查哪些进程在使用摄像头
echo "=== 正在使用摄像头的进程 ==="
lsof | grep "AppleCamera\|VDC\|iSight" 2>/dev/null

# 检查哪些进程在使用麦克风
echo "=== 正在使用音频输入的进程 ==="
lsof | grep "CoreAudio" 2>/dev/null | head -20

echo "=== 拥有摄像头权限的应用 ==="
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceCamera'" 2>/dev/null

echo "=== 拥有麦克风权限的应用 ==="
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceMicrophone'" 2>/dev/null
```

---

## 第七阶段：综合一键扫描脚本

将以上所有检查整合为一个可执行脚本：

```bash
#!/bin/bash
# macOS 隐私卫士 — 综合监控检测脚本
# 用途：检测 macOS 上可能存在的监控软件和隐私侵害
# 使用方法：chmod +x privacy_guard_macos.sh && ./privacy_guard_macos.sh

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

REPORT_FILE="$HOME/Desktop/privacy_scan_$(date +%Y%m%d_%H%M%S).txt"
ALERTS=0

log() { echo -e "$1" | tee -a "$REPORT_FILE"; }
alert() { ((ALERTS++)); log "${RED}[!] 警告: $1${NC}"; }
info() { log "${BLUE}[*] $1${NC}"; }
ok() { log "${GREEN}[✓] $1${NC}"; }
section() { log "\n${YELLOW}========== $1 ==========${NC}"; }

log "macOS 隐私卫士扫描报告"
log "扫描时间: $(date)"
log "主机名: $(hostname)"
log "系统版本: $(sw_vers -productVersion)"
log "用户: $(whoami)"
log ""

# --- 1. 进程扫描 ---
section "1. 可疑进程扫描"
SPYWARE_NAMES="flexispy|mspy|spyrix|cocospy|kidlogger|refog|hoverwatch|spyera|thetruthspy|ikeymonitor|clevguard|eyezy|webwatcher|activtrak|teramind|hubstaff|veriato|interguard|workpuls|keylogger|keystroke|keycapture|logkext|aobo|amac|easemon"
FOUND=$(ps aux | grep -iE "$SPYWARE_NAMES" | grep -v grep || true)
if [ -n "$FOUND" ]; then
  alert "发现已知监控软件进程！"
  log "$FOUND"
else
  ok "未发现已知监控软件进程"
fi

# --- 2. 持久化检测 ---
section "2. 持久化机制检测"

info "非 Apple 的 LaunchAgents/Daemons："
for dir in ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons; do
  if [ -d "$dir" ]; then
    while IFS= read -r plist; do
      [ -z "$plist" ] && continue
      label=$(defaults read "$plist" Label 2>/dev/null || echo "无法读取")
      if [[ "$label" != com.apple.* ]]; then
        program=$(defaults read "$plist" Program 2>/dev/null || defaults read "$plist" ProgramArguments 2>/dev/null || echo "无法读取")
        info "  $label -> $program"
      fi
    done < <(find "$dir" -name "*.plist" 2>/dev/null)
  fi
done

info "MDM 注册状态："
MDM_STATUS=$(profiles status -type enrollment 2>/dev/null || echo "无法检查")
log "$MDM_STATUS"
if echo "$MDM_STATUS" | grep -qi "enrolled"; then
  alert "此设备已注册 MDM（移动设备管理），管理员可能有能力监控此设备！"
fi

# --- 3. 网络检测 ---
section "3. 网络连接检测"

info "当前监听端口："
lsof -i -P -n 2>/dev/null | grep LISTEN | while read line; do
  port=$(echo "$line" | awk '{print $9}' | rev | cut -d: -f1 | rev)
  proc=$(echo "$line" | awk '{print $1}')
  # 标记可疑端口
  case "$port" in
    5900|5901) alert "VNC 远程桌面端口 $port 正在监听（进程: $proc）" ;;
    4444|4445|1337|31337) alert "常见后门端口 $port 正在监听（进程: $proc）" ;;
    8080|8888|9090) info "  代理常用端口 $port 正在监听（进程: $proc），请确认是否为你自己的服务" ;;
    *) ;;
  esac
done

info "已建立的外部连接数：$(lsof -i -P -n 2>/dev/null | grep ESTABLISHED | grep -v '127.0.0.1' | grep -v '::1' | wc -l | tr -d ' ')"

info "系统代理设置："
WEB_PROXY=$(networksetup -getwebproxy Wi-Fi 2>/dev/null || echo "无法检查")
if echo "$WEB_PROXY" | grep -q "Enabled: Yes"; then
  alert "HTTP 代理已启用！你的流量可能被监控"
  log "$WEB_PROXY"
fi

HTTPS_PROXY_SET=$(networksetup -getsecurewebproxy Wi-Fi 2>/dev/null || echo "无法检查")
if echo "$HTTPS_PROXY_SET" | grep -q "Enabled: Yes"; then
  alert "HTTPS 代理已启用！你的加密流量可能被解密监控"
  log "$HTTPS_PROXY_SET"
fi

# --- 4. 证书检测 ---
section "4. TLS 证书检测（中间人攻击）"

info "测试 HTTPS 连接是否被劫持："
for site in "google.com" "apple.com" "github.com"; do
  issuer=$(echo | openssl s_client -connect "$site:443" -servername "$site" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
  if echo "$issuer" | grep -qiE "corporate|enterprise|proxy|firewall|security|filter|inspect|decrypt|mitm|zscaler|fortinet|paloalto|bluecoat|symantec.*proxy|checkpoint|barracuda|cisco.*umbrella|forcepoint"; then
    alert "$site 的证书由企业/代理签发: $issuer —— HTTPS 流量可能被解密！"
  else
    ok "$site 证书正常: $issuer"
  fi
done

# --- 5. 权限检测 ---
section "5. 敏感权限审计"

TCC_DB="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
if [ -f "$TCC_DB" ]; then
  for service_info in "kTCCServiceAccessibility:辅助功能（可记录键盘）" "kTCCServiceScreenCapture:屏幕录制" "kTCCServiceCamera:摄像头" "kTCCServiceMicrophone:麦克风" "kTCCServiceListenEvent:输入监控" "kTCCServiceSystemPolicyAllFiles:完全磁盘访问"; do
    service=$(echo "$service_info" | cut -d: -f1)
    desc=$(echo "$service_info" | cut -d: -f2)
    apps=$(sqlite3 "$TCC_DB" "SELECT client FROM access WHERE service='$service' AND auth_value=2" 2>/dev/null || echo "")
    if [ -n "$apps" ]; then
      info "拥有「${desc}」权限的应用："
      echo "$apps" | while read app; do
        log "    $app"
      done
    fi
  done
else
  info "TCC 数据库不可读（可能需要完全磁盘访问权限）"
fi

# --- 6. 混杂模式和抓包 ---
section "6. 网络嗅探检测"
PROMISC=$(ifconfig 2>/dev/null | grep -i "promisc" || true)
if [ -n "$PROMISC" ]; then
  alert "检测到网卡处于混杂模式！可能有人在嗅探你的网络流量"
else
  ok "网卡未处于混杂模式"
fi

SNIFFERS=$(ps aux | grep -iE "tcpdump|wireshark|tshark|mitmproxy|charles|proxyman|fiddler|burp" | grep -v grep || true)
if [ -n "$SNIFFERS" ]; then
  alert "发现网络抓包程序正在运行："
  log "$SNIFFERS"
fi

# --- 总结 ---
section "扫描总结"
if [ "$ALERTS" -eq 0 ]; then
  ok "未发现明显的监控迹象"
else
  alert "共发现 $ALERTS 个警告项，请仔细审查上述报告"
fi
log "\n完整报告已保存至: $REPORT_FILE"
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
   - 导出重要数据到安全存储
   - 修改所有密码（在另一台安全设备上）
   - 启用所有账户的两步验证
   - 考虑重装系统（最彻底的方式）
5. 加固措施：
   - 启用 FileVault 全盘加密
   - 启用防火墙
   - 定期审查系统偏好设置 > 隐私与安全性
   - 保持系统更新
   - 不要安装来源不明的软件
```

---

## 参考资料

详见 `references/` 目录中的检测规则和已知监控软件数据库。
