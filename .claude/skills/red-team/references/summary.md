# 红队安全技能 — 摘要

## 目的
针对 Web 应用的攻击性安全测试。通过静态代码分析、攻击面映射和漏洞利用模拟，系统性地发现系统漏洞。

## 目标技术栈
- **后端**：Node.js（Express/Koa/Fastify）、Go（Gin/Echo/Fiber）、Rust（Actix/Axum）
- **前端**：Vue.js、React、TypeScript
- **桌面端**：Electron
- **数据库**：MySQL、PostgreSQL、MongoDB

## 方法论
1. 侦察与攻击面映射
2. 语言特有漏洞模式的静态分析
3. OWASP Top 10 审计（注入、XSS、SSRF、认证绕过等）
4. 依赖供应链分析
5. 结构化漏洞报告（含 PoC 和修复建议）

## 核心能力
- SQL/NoSQL 注入检测
- XSS 模式识别（Vue v-html、React dangerouslySetInnerHTML）
- Electron XSS 到 RCE 的升级路径
- 认证/授权绕过测试
- 竞态条件识别
- 原型链污染检测
- 命令注入发现
- SSRF 攻击面映射
