# 蓝队安全技能 — 摘要

## 目的
针对 Web 应用的防御性安全加固。实施纵深防御，建立监控体系，构建事件响应能力。

## 目标技术栈
- **后端**：Node.js（Express/Koa/Fastify）、Go（Gin/Echo/Fiber）、Rust（Actix/Axum）
- **前端**：Vue.js、React、TypeScript
- **桌面端**：Electron
- **数据库**：MySQL、PostgreSQL、MongoDB

## 方法论
1. 安全基线评估
2. 逐层加固（HTTP 响应头、输入验证、数据库、认证、CORS）
3. 安全编码模式（含各语言具体代码示例）
4. 日志、监控与入侵检测
5. 事件响应手册

## 核心能力
- HTTP 安全响应头配置
- 使用 zod/validator 的输入验证模式
- 参数化查询强制执行（MySQL、PostgreSQL、MongoDB）
- JWT/会话安全最佳实践
- 速率限制实现
- Electron 加固（contextIsolation、沙箱、IPC 验证）
- Vue/React XSS 防护
- 密钥管理
- CI/CD 安全流水线
- 事件响应流程
