# 蓝队安全技能

> 针对使用 Node.js、Go、Rust、Electron、Vue、React、TypeScript、MySQL、PostgreSQL、MongoDB 构建的 Web 应用的防御加固与安全防护技能。

## 目的

以 Google Cloud Security 级别的高级蓝队工程师身份行动。系统性地加固目标代码库，实施纵深防御，建立监控体系，并构建事件响应能力。所有建议遵循**最小权限原则**和**纵深防御**策略。

## 使用方式

当此技能被激活时，按以下顺序执行：

1. **安全基线** — 评估当前安全态势
2. **加固** — 逐层实施加固措施
3. **安全编码** — 审查并修复代码层漏洞
4. **监控** — 实施检测与告警
5. **响应计划** — 编写事件响应流程文档

---

## 第一阶段：安全基线评估

### 1.1 配置审计

```
逐层检查：

服务器/操作系统：
- [ ] 防火墙规则（仅开放必要端口）
- [ ] SSH 加固（仅密钥登录、禁止 root 登录）
- [ ] 启用自动安全更新
- [ ] 应用使用非 root 服务账户运行
- [ ] 文件权限（无全局可写文件）
- [ ] 磁盘加密

应用层：
- [ ] 使用环境变量存储密钥（非硬编码）
- [ ] 启用生产模式（无调试输出）
- [ ] 错误消息不泄露堆栈信息
- [ ] CORS 配置正确
- [ ] 启用速率限制
- [ ] 设置请求大小限制

数据库：
- [ ] 不暴露在公网
- [ ] 使用最小权限的读写分离用户
- [ ] 连接加密（TLS）
- [ ] 启用认证（特别是 MongoDB！）
- [ ] 定期备份且已验证恢复流程
```

### 1.2 依赖健康度

```bash
# 生成软件物料清单（SBOM）
# Node.js
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Go
go list -m -json all

# Rust
cargo tree --format "{p} {l}"

# 检查已知漏洞
npm audit
govulncheck ./...
cargo audit
```

---

## 第二阶段：分层加固

### 2.1 HTTP 安全响应头

每个 Web 应用都**必须**设置以下响应头：

```typescript
// Node.js（Express/Fastify）
// 推荐：使用 helmet 中间件

// 必要的安全响应头：
const securityHeaders = {
  // 防止 MIME 类型嗅探
  'X-Content-Type-Options': 'nosniff',

  // 防止点击劫持
  'X-Frame-Options': 'DENY',

  // XSS 过滤器（旧版浏览器）
  'X-XSS-Protection': '0',  // 禁用，依赖 CSP 替代

  // 强制 HTTPS
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',

  // 控制 Referrer 信息
  'Referrer-Policy': 'strict-origin-when-cross-origin',

  // 限制浏览器功能
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',

  // 内容安全策略（根据应用定制）
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",        // 禁止内联脚本和 eval
    "style-src 'self' 'unsafe-inline'",  // 尽可能收紧
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self'",       // API 端点
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "upgrade-insecure-requests"
  ].join('; ')
};
```

```go
// Go（net/http 中间件）
func SecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        w.Header().Set("Permissions-Policy",
            "camera=(), microphone=(), geolocation=()")
        w.Header().Set("Content-Security-Policy",
            "default-src 'self'; script-src 'self'; frame-ancestors 'none'")
        next.ServeHTTP(w, r)
    })
}
```

### 2.2 输入验证与过滤

#### 验证策略：白名单 > 黑名单

```typescript
// Node.js：在每个入口点使用 zod / joi / class-validator

import { z } from 'zod';

// 定义严格的 Schema
const CreateUserSchema = z.object({
  username: z.string()
    .min(3).max(30)
    .regex(/^[a-zA-Z0-9_-]+$/),  // 白名单字符
  email: z.string().email().max(254),
  password: z.string().min(12).max(128),
  age: z.number().int().min(13).max(150).optional(),
});

// 在控制器层验证
app.post('/api/users', (req, res) => {
  const result = CreateUserSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({
      error: '验证失败',
      // 生产环境不要返回原始 zod 错误给客户端
      details: result.error.issues.map(i => i.message)
    });
  }
  // 使用 result.data（已类型化和过滤）
  createUser(result.data);
});
```

```go
// Go：使用结构体标签 + validator
import "github.com/go-playground/validator/v10"

type CreateUserRequest struct {
    Username string `json:"username" validate:"required,min=3,max=30,alphanumunicode"`
    Email    string `json:"email" validate:"required,email,max=254"`
    Password string `json:"password" validate:"required,min=12,max=128"`
}

var validate = validator.New()

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
    var req CreateUserRequest
    if err := json.NewDecoder(
        http.MaxBytesReader(w, r.Body, 1<<20), // 1MB 限制
    ).Decode(&req); err != nil {
        http.Error(w, "无效请求", http.StatusBadRequest)
        return
    }
    if err := validate.Struct(req); err != nil {
        http.Error(w, "验证失败", http.StatusBadRequest)
        return
    }
    // req 已通过验证
}
```

```rust
// Rust：使用 serde + validator crate
use serde::Deserialize;
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 3, max = 30))]
    #[validate(regex(path = "RE_USERNAME"))]
    pub username: String,

    #[validate(email)]
    #[validate(length(max = 254))]
    pub email: String,

    #[validate(length(min = 12, max = 128))]
    pub password: String,
}

lazy_static! {
    static ref RE_USERNAME: regex::Regex =
        regex::Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
}
```

### 2.3 数据库安全

#### 参数化查询（强制要求）

```typescript
// Node.js + MySQL（mysql2）
// 绝对不要：`SELECT * FROM users WHERE id = ${id}`
// 必须这样写：
const [rows] = await pool.execute(
  'SELECT * FROM users WHERE id = ?',
  [userId]
);

// Node.js + PostgreSQL（pg）
const result = await pool.query(
  'SELECT * FROM users WHERE id = $1',
  [userId]
);

// Node.js + MongoDB（mongoose）
// 绝对不要：User.find({ username: req.body.username })
// 因为 req.body.username 可能是 {"$gt":""} 这样的对象
// 必须过滤或转换类型：
const username = String(req.body.username);
const user = await User.findOne({ username });
// 或使用 mongo-sanitize：
import sanitize from 'express-mongo-sanitize';
app.use(sanitize());
```

```go
// Go + MySQL/PostgreSQL（database/sql）
// 必须使用占位符
row := db.QueryRowContext(ctx,
    "SELECT id, username FROM users WHERE email = $1",
    email,
)

// Go + sqlx
var user User
err := db.GetContext(ctx, &user,
    "SELECT * FROM users WHERE id = $1", id)
```

```rust
// Rust + sqlx
let user = sqlx::query_as!(User,
    "SELECT * FROM users WHERE id = $1",
    user_id
)
.fetch_one(&pool)
.await?;

// Rust + diesel（编译时查询安全）
users::table.filter(users::id.eq(user_id))
    .first::<User>(&mut conn)?;
```

#### 数据库加固清单

```sql
-- MySQL 加固
-- 创建最小权限的应用用户
CREATE USER 'app_readonly'@'app-server-ip' IDENTIFIED BY '强随机密码';
GRANT SELECT ON mydb.* TO 'app_readonly'@'app-server-ip';

CREATE USER 'app_readwrite'@'app-server-ip' IDENTIFIED BY '强随机密码';
GRANT SELECT, INSERT, UPDATE, DELETE ON mydb.* TO 'app_readwrite'@'app-server-ip';
-- 绝对不要给应用用户授予 ALL PRIVILEGES

-- PostgreSQL 加固
-- 使用行级安全（RLS）实现多租户
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_documents ON documents
  USING (owner_id = current_setting('app.current_user_id')::int);
```

```javascript
// MongoDB 加固
// 启用认证（mongod.conf）
// security:
//   authorization: "enabled"

// 创建最小权限用户
db.createUser({
  user: "appReadOnly",
  pwd: "强随机密码",
  roles: [{ role: "read", db: "myapp" }]
});

// 使用 Schema 验证来强制文档结构
db.createCollection("users", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["username", "email"],
      properties: {
        username: { bsonType: "string", maxLength: 30 },
        email: { bsonType: "string", pattern: "^.+@.+\\..+$" }
      }
    }
  }
});
```

### 2.4 认证与会话安全

```typescript
// 密码哈希：必须使用 bcrypt/scrypt/argon2
import bcrypt from 'bcrypt';
const SALT_ROUNDS = 12; // 最低 10

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash); // 常数时间比较
}

// JWT 最佳实践
import jwt from 'jsonwebtoken';

const JWT_CONFIG = {
  algorithm: 'RS256',           // 使用非对称算法，不用 HS256
  expiresIn: '15m',             // 短生命周期的访问令牌
  issuer: 'your-app-name',
};

// 访问令牌：短生命周期（15分钟）
// 刷新令牌：较长生命周期（7天），存储在 httpOnly cookie 中
// 令牌轮换：每次刷新时签发新的刷新令牌

// 会话 Cookie 配置
const SESSION_CONFIG = {
  httpOnly: true,     // 防止 JavaScript 访问
  secure: true,       // 仅 HTTPS
  sameSite: 'strict', // CSRF 防护
  maxAge: 900000,     // 15 分钟
  path: '/',
  domain: '.yourdomain.com',
};
```

```go
// Go：使用 bcrypt 进行密码哈希
import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword(
        []byte(password), 12) // 成本因子 12
    return string(bytes), err
}

func CheckPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword(
        []byte(hash), []byte(password))
    return err == nil // 常数时间比较
}
```

### 2.5 速率限制与 DDoS 防护

```typescript
// Node.js 速率限制（express-rate-limit）
import rateLimit from 'express-rate-limit';

// 通用 API 速率限制
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 分钟
  max: 100,                   // 每个窗口 100 次请求
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: '请求过于频繁，请稍后再试' },
});

// 认证端点的严格限制
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,                     // 15 分钟内最多 5 次尝试
  skipSuccessfulRequests: true,
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/reset-password', authLimiter);

// 请求体大小限制
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: false }));
```

```go
// Go：使用 golang.org/x/time/rate 或 ulule/limiter
import "golang.org/x/time/rate"

// 基于 IP 的速率限制器
type IPRateLimiter struct {
    mu       sync.RWMutex
    limiters map[string]*rate.Limiter
    rate     rate.Limit
    burst    int
}

func (rl *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    limiter, exists := rl.limiters[ip]
    if !exists {
        limiter = rate.NewLimiter(rl.rate, rl.burst)
        rl.limiters[ip] = limiter
    }
    return limiter
}
```

### 2.6 CORS 配置

```typescript
// 生产环境绝对不要使用：cors({ origin: '*' })

import cors from 'cors';

const ALLOWED_ORIGINS = [
  'https://yourdomain.com',
  'https://app.yourdomain.com',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS 策略不允许'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400, // 24 小时预检缓存
}));
```

### 2.7 Electron 加固

```typescript
// Electron BrowserWindow — 安全默认配置
const mainWindow = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,        // 必须为 false
    contextIsolation: true,        // 必须为 true
    sandbox: true,                 // 启用沙箱
    webSecurity: true,             // 必须为 true
    allowRunningInsecureContent: false,
    enableRemoteModule: false,     // 已弃用，保持禁用
    preload: path.join(__dirname, 'preload.js'),
  },
});

// Electron 的 CSP 配置
mainWindow.webContents.session.webRequest.onHeadersReceived(
  (details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        ],
      },
    });
  }
);

// 安全的 preload 脚本 — 仅暴露最小 API
// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // 仅暴露特定的、经过验证的通道
  getData: (id) => ipcRenderer.invoke('get-data', String(id)),
  saveData: (data) => ipcRenderer.invoke('save-data', data),
  // 绝对不要直接暴露 ipcRenderer.send 或 ipcRenderer.on
});

// 主进程 — 验证所有 IPC 输入
ipcMain.handle('get-data', async (event, id) => {
  // 验证发送者
  if (event.senderFrame.url !== expectedURL) {
    throw new Error('未授权');
  }
  // 验证输入
  if (typeof id !== 'string' || id.length > 36) {
    throw new Error('无效输入');
  }
  return fetchData(id);
});

// 阻止导航到不受信任的 URL
mainWindow.webContents.on('will-navigate', (event, url) => {
  const parsedUrl = new URL(url);
  if (parsedUrl.origin !== 'https://yourdomain.com') {
    event.preventDefault();
  }
});

// 打开外部 URL 前必须验证
const { shell } = require('electron');
// 绝对不要：shell.openExternal(userProvidedUrl)
// 必须验证：
function safeOpenExternal(url) {
  const parsed = new URL(url);
  if (['https:', 'mailto:'].includes(parsed.protocol)) {
    shell.openExternal(url);
  }
}
```

### 2.8 Vue.js / React 前端加固

```typescript
// Vue.js 安全
// 绝对不要对用户数据使用 v-html。如确有必要：
import DOMPurify from 'dompurify';
const sanitized = DOMPurify.sanitize(userInput);
// <div v-html="sanitized" />

// 绑定 URL 前必须验证
function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ['https:', 'http:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

// React 安全
// 避免使用 dangerouslySetInnerHTML。如确有必要：
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{
  __html: DOMPurify.sanitize(userInput)
}} />

// TypeScript：利用类型系统增强安全性
// 使用品牌类型（branded types）标记已验证数据
type SafeHTML = string & { readonly __brand: 'SafeHTML' };
function sanitizeHTML(input: string): SafeHTML {
  return DOMPurify.sanitize(input) as SafeHTML;
}
```

---

## 第三阶段：密钥管理

```bash
# 绝对不要将密钥提交到 git

# .gitignore（必须包含的条目）
.env
.env.*
*.pem
*.key
*.p12
credentials.json
service-account.json

# 使用 pre-commit hook 防止密钥泄露
# 推荐使用 gitleaks 或 trufflehog
# .pre-commit-config.yaml
# repos:
#   - repo: https://github.com/gitleaks/gitleaks
#     rev: v8.18.0
#     hooks:
#       - id: gitleaks

# 如果密钥曾被提交过：
# 1. 立即轮换所有已暴露的密钥
# 2. 使用 git-filter-repo 从历史中删除
# 3. 协调团队后强制推送
```

```typescript
// 环境变量加载模式
// 绝对不要：const secret = "硬编码的密钥"
// 必须这样写：
function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`缺少必需的环境变量：${key}`);
  }
  return value;
}

const config = {
  dbPassword: requireEnv('DB_PASSWORD'),
  jwtSecret: requireEnv('JWT_SECRET'),
  apiKey: requireEnv('API_KEY'),
};
```

---

## 第四阶段：日志与监控

### 4.1 安全事件日志

```typescript
// 应该记录的内容（安全事件）：
// - 认证尝试（成功和失败都要记录）
// - 授权失败（403）
// - 输入验证失败
// - 触发速率限制
// - 数据库错误
// - 应用错误（500）
// - 管理员操作
// - 数据访问模式

// 绝对不要记录的内容：
// - 密码或凭证
// - 完整的信用卡号
// - 会话令牌或 API 密钥
// - 超出必要范围的个人数据（PII）

// 结构化日志（Node.js 使用 pino/winston）
import pino from 'pino';

const logger = pino({
  level: 'info',
  redact: ['req.headers.authorization', 'req.body.password'],
});

// 安全事件日志记录
function logSecurityEvent(event: {
  type: 'auth_failure' | 'auth_success' | 'authz_failure' |
        'rate_limit' | 'input_validation' | 'suspicious_activity';
  userId?: string;
  ip: string;
  details: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}) {
  logger.warn({ security_event: event }, `安全事件：${event.type}`);
}

// 示例：记录登录失败
logSecurityEvent({
  type: 'auth_failure',
  ip: req.ip,
  details: `邮箱登录失败：${maskEmail(email)}`,
  severity: 'medium',
});
```

```go
// Go 结构化日志（slog）
import "log/slog"

func LogSecurityEvent(eventType string, severity string,
    ip string, details string) {
    slog.Warn("安全事件",
        slog.String("type", eventType),
        slog.String("severity", severity),
        slog.String("ip", ip),
        slog.String("details", details),
        slog.Time("timestamp", time.Now()),
    )
}
```

### 4.2 入侵检测模式

```typescript
// 在中间件中检测常见攻击模式

function detectAttackPatterns(req: Request): string[] {
  const alerts: string[] = [];
  const allInput = JSON.stringify({
    query: req.query,
    body: req.body,
    params: req.params,
  });

  // SQL 注入模式
  if (/('|--|;|\/\*|\*\/|union\s+select|or\s+1\s*=\s*1)/i.test(allInput)) {
    alerts.push('sql_injection_attempt');
  }

  // XSS 模式
  if (/<script|javascript:|on\w+\s*=/i.test(allInput)) {
    alerts.push('xss_attempt');
  }

  // 路径穿越
  if (/\.\.\//g.test(allInput)) {
    alerts.push('path_traversal_attempt');
  }

  // NoSQL 注入
  if (/\$gt|\$ne|\$regex|\$where/i.test(allInput)) {
    alerts.push('nosql_injection_attempt');
  }

  // 命令注入
  if (/[;|`$()]/.test(allInput) && /(cat |ls |rm |wget |curl )/i.test(allInput)) {
    alerts.push('command_injection_attempt');
  }

  return alerts;
}

// 中间件
app.use((req, res, next) => {
  const attacks = detectAttackPatterns(req);
  if (attacks.length > 0) {
    logSecurityEvent({
      type: 'suspicious_activity',
      ip: req.ip,
      details: `检测到攻击模式：${attacks.join(', ')}`,
      severity: 'high',
    });
    // 可选择拦截：return res.status(403).json({ error: '禁止访问' });
  }
  next();
});
```

### 4.3 健康检查与监控端点

```typescript
// 暴露健康检查（不暴露敏感数据）
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    // 不要暴露：版本、依赖、内部 IP
  });
});

// 指标端点（必须加认证！）
app.get('/metrics', authMiddleware, adminOnly, (req, res) => {
  res.json({
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    activeConnections: server.connections,
    requestRate: rateMeter.rate(),
  });
});
```

---

## 第五阶段：事件响应手册

### 5.1 准备工作

```
维护以下内容：
- [ ] 资产清单（所有服务、数据库、域名）
- [ ] 联系人名单（团队负责人、安全人员、法务、主机提供商）
- [ ] 备份验证（每月测试恢复）
- [ ] 常见事件处置手册
- [ ] 访问凭证存放于安全保险库（不在 git 和邮件中）
```

### 5.2 响应流程

```
1. 检测
   - 监控/日志告警
   - 用户报告
   - 指标异常

2. 遏制（前 15 分钟）
   - [ ] 隔离受影响系统（必要时在网络层隔离）
   - [ ] 撤销已泄露的凭证
   - [ ] 启用增强日志
   - [ ] 不要关机（保留证据）

3. 调查
   - [ ] 时间线：什么时候开始的？
   - [ ] 范围：哪些系统/数据受影响？
   - [ ] 攻击向量：攻击者如何进入的？
   - [ ] 收集日志、内存转储、磁盘镜像
   - [ ] 检查持久化机制（cron、SSH 密钥、新用户）

4. 清除
   - [ ] 移除攻击者访问权限（所有后门）
   - [ ] 修补漏洞
   - [ ] 轮换所有密钥（不仅是被泄露的）
   - [ ] 必要时从已知安全状态重建

5. 恢复
   - [ ] 必要时从干净备份恢复
   - [ ] 部署修补后的版本
   - [ ] 密切监控是否再次被入侵
   - [ ] 逐步恢复服务

6. 事后复盘
   - [ ] 编写事件报告（无责复盘）
   - [ ] 更新检测规则
   - [ ] 分享经验教训
   - [ ] 更新本手册
```

### 5.3 应急命令

```bash
# 快速取证（首先保留证据）

# 检查活跃连接
ss -tlnp
netstat -tlnp

# 检查运行中的进程
ps auxf

# 检查最近登录记录
last -a
lastb

# 检查所有用户的 cron 任务
for user in $(cut -f1 -d: /etc/passwd); do
  echo "=== $user ==="; crontab -l -u $user 2>/dev/null;
done

# 检查最近修改的文件
find /var/www -mtime -1 -type f -ls

# 检查 SSH 授权密钥
find / -name "authorized_keys" -type f -ls 2>/dev/null

# 检查新增/修改的系统用户
awk -F: '$3 >= 1000' /etc/passwd

# 捕获网络连接用于分析
ss -tunap > /tmp/connections_$(date +%Y%m%d_%H%M%S).txt

# 立即封禁某个 IP
iptables -I INPUT -s 攻击者IP -j DROP
```

---

## 第六阶段：自动化安全检查（CI/CD）

```yaml
# GitHub Actions 安全流水线示例
name: 安全检查
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      # 密钥扫描
      - uses: gitleaks/gitleaks-action@v2

      # Node.js 依赖审计
      - run: npm audit --audit-level=high

      # Go 漏洞检查
      - run: govulncheck ./...

      # Rust 安全审计
      - run: cargo audit

      # 静态分析（SAST）
      - uses: github/codeql-action/analyze@v3

      # 容器扫描（如使用 Docker）
      - uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'CRITICAL,HIGH'
```

---

## 快速参考：代码审查安全清单

```
每次 PR 都要检查：
- [ ] 无硬编码的密钥/凭证
- [ ] 所有用户输入都使用白名单验证
- [ ] 所有数据库查询都使用参数化
- [ ] 没有对用户输入使用 eval()/exec()
- [ ] 没有对未过滤数据使用 v-html/dangerouslySetInnerHTML
- [ ] 所有新端点都有认证/授权
- [ ] 错误响应不泄露敏感信息
- [ ] 已审查新依赖的安全性
- [ ] 为安全相关操作添加了日志
- [ ] 没有新的 Electron nodeIntegration 或 contextIsolation 变更
- [ ] 文件上传已验证（类型、大小、文件名）
- [ ] 服务端请求前已验证 URL（防 SSRF）
```

---

## 参考资料

详见 `references/` 目录中各技术栈的加固指南。
