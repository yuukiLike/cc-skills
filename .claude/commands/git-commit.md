---
allowed-tools: Task
description: 智能 Git Commit - 使用 haiku 子代理自动分析变更生成规范提交
---

使用 Task 工具启动一个 haiku 子代理完成 git 提交。直接执行，不要额外分析。

```
Task(
  subagent_type: "Bash",
  model: "haiku",
  prompt: 下方完整 prompt
)
```

## 子代理 Prompt

你是一个 Git Commit 助手。请在当前仓库中执行以下步骤：

### 1. 分析变更

依次执行：
```bash
git status --porcelain
git diff HEAD --name-only
git diff HEAD --stat
git diff HEAD
```

如果没有任何变更，输出"无变更，跳过提交"并结束。

### 2. 识别关键改动

- 优先识别功能性改动：添加/删除 await、修改逻辑、新增/删除代码等
- 区分格式化改动：缩进、换行、空格等
- **关键改动优先**：即使只有 1 行功能改动 + 100 行格式化，也要以功能改动为主
- 常见功能性改动：
  * 添加/删除 await、async
  * 修改函数调用、参数
  * 新增/删除变量、属性
  * 修改条件判断、循环逻辑
  * 修改 import/export

### 3. 生成 Commit Message（Conventional Commits + Emoji）

格式：`emoji type(scope): 描述`

| emoji | type | 场景 |
|-------|------|------|
| ✨ | feat | 新功能、新特性 |
| 🐛 | fix | 修复 bug |
| 📚 | docs | 文档修改 |
| 🎨 | style | 纯格式化（无逻辑改动） |
| 🔄 | refactor | 代码重构（非 bug 修复） |
| ✅ | test | 测试相关 |
| ⚡ | perf | 性能优化 |
| 🔧 | chore | 构建、配置、依赖等 |

**不需要 AI 署名（不要加 Co-Authored-By）。**

### 4. 执行提交

```bash
git add .
git commit -m "生成的规范消息"
```

### 5. 验证结果

```bash
git log -1 --oneline
```

### 6. 输出摘要

用以下格式输出结果：

```
📊 变更分析：N个文件 (+X/-Y行)
✨ type(scope): 描述
✅ 提交成功：hash message
```
