# CLAUDE.md

本仓库是 Aaron 的作品集项目：端到端加密的文件分享服务。服务器永远看不到文件内容和文件名。这是一个安全方向的作品，安全文档和代码同等重要。

## 开工前必读

1. `docs/SPEC.md`：需求、加密方案、接口
2. `docs/security/THREAT_MODEL.md`：威胁模型，任何功能改动都要回头检查它
3. `docs/TASKS.md`：从第一个未勾选的里程碑开始
4. `docs/DECISIONS.md`：已做出的决定

## 目录结构

```
server/   Go 后端 (cmd/vaultd, internal/...)
web/      React + TypeScript + Vite 前端，加密逻辑在 web/src/crypto
docs/     规格、决策、安全文档
```

## 工作方式

- 每个里程碑先出计划，等 Aaron 确认
- 一个任务一次提交，Conventional Commits 英文格式
- 完成后在 TASKS.md 打勾，新决定写入 DECISIONS.md
- 每个里程碑结束时总结：做了什么，引入了什么新的攻击面，如何防护

## 常用命令

```bash
cd server && go test -race ./... && go vet ./...
cd server && gosec ./... && govulncheck ./...
cd web && npm test && npm run lint && npm audit
docker compose up --build
```

## 安全硬性规则

- 不要自己发明加密算法。只用 Web Crypto API（AES-256-GCM、HKDF）和成熟库（Argon2id）
- 加密密钥只能出现在 URL 片段（`#` 之后），禁止通过任何请求发送到服务器，禁止写入日志
- 每个 AES-GCM 加密块使用唯一随机 nonce，禁止复用
- 服务端口令哈希用 Argon2id，比较用常量时间函数
- 所有输入都要校验长度和格式；所有 SQL 用参数化查询
- 日志中禁止出现密钥、令牌、口令、文件内容
- 依赖要固定版本；新增依赖前说明理由
- 发现安全问题时，先停下来告诉 Aaron，并记入 `docs/security/FINDINGS.md`
- 安全测试只针对本项目自己部署的实例
