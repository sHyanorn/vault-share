# vault-share 项目规格

## 1. 一句话介绍

一个零知识的端到端加密文件分享服务：文件在浏览器里加密后才上传，分享链接里带着密钥，服务器只保存密文，支持限时、限次和阅后即焚。

## 2. 要证明的能力

| 能力 | 体现在哪里 |
|---|---|
| 密码学应用 | 分块 AES-GCM、HKDF 密钥派生、口令保护、URL 片段传密钥 |
| 后端开发 | Go 服务、流式上传下载、数据库、定时清理、Docker 部署 |
| 安全工程 | 威胁模型、安全响应头、限流、审计日志、依赖扫描 |
| 安全测试 | 按 OWASP Top 10 自测并出报告 |

## 3. 功能范围

### 必做

- 匿名上传：选择文件，浏览器内加密，上传密文，得到分享链接
- 分享链接格式：`https://host/f/{fileId}#{key}`，`#` 后的密钥浏览器不会发给服务器
- 设置过期时间（1 小时、1 天、7 天）和最大下载次数（1 到 100）
- 阅后即焚：下载次数用完立即删除密文
- 可选口令保护：口令在浏览器里派生出包裹密钥，服务器同样看不到
- 删除令牌：上传者拿到一个删除链接，可提前删除
- 文件名和类型也加密，服务器只知道密文大小
- 后台定时清理过期文件
- 单文件大小上限 1 GB（可配置），大文件分块流式处理，不在内存里一次性加载

### 选做

- 用户账户：Argon2id 口令哈希、HttpOnly 会话 Cookie、CSRF 防护、TOTP 两步验证
- 登录用户查看和管理自己上传的文件
- 一次分享多个文件

### 不做

- 文件预览
- 移动端原生应用

## 4. 加密方案

参考 Firefox Send 的公开设计，自己实现时必须对照理解每一步。

### 上传

1. 浏览器生成 16 字节随机主密钥 `secret`
2. 用 HKDF-SHA256 从 `secret` 派生三把密钥：
   - `fileKey`：加密文件内容
   - `metaKey`：加密文件名、类型等元数据
   - `authKey`：下载时向服务器证明持有链接（服务器只保存其验证值）
3. 文件按 64 KB 分块，每块用 AES-256-GCM 加密；nonce 由随机基值加块序号构成；最后一块带结束标记，防止截断攻击
4. 元数据 JSON 用 `metaKey` 加密
5. 上传密文、加密元数据和 `authKey` 的验证值
6. 链接为 `/f/{id}#{base64url(secret)}`

### 口令保护（可选）

- 用 Argon2id（浏览器端 WebAssembly 实现）从口令和随机盐派生包裹密钥
- 用包裹密钥加密 `secret`，链接里不再直接带 `secret`
- 下载者输入口令后解出 `secret`

### 下载

1. 浏览器从 URL 片段读出 `secret`，派生出三把密钥
2. 用 `authKey` 对服务器给的随机挑战签名，证明持有链接
3. 服务器校验通过后，流式返回密文，并原子地扣减下载次数
4. 浏览器边下载边解密，用 Streams API 直接保存，不在内存堆积

### 已知局限（写进威胁模型和 README）

- 网页版的加密代码由服务器下发，如果服务器被攻破，攻击者可以下发恶意代码。缓解：子资源完整性、严格 CSP、可复现构建，并在文档中坦诚说明
- 链接泄露等于文件泄露，这是链接分享模式的固有特性

## 5. 架构

```
浏览器 (React)                       服务器 (Go)                 存储
┌──────────────┐  HTTPS  ┌─────────────────────────┐
│ crypto/      │────────▶│ 中间件：限流、安全头、日志   │
│  Web Crypto  │ 只传密文 │ handlers：上传、下载、删除   │──▶ SQLite 或 PostgreSQL（元数据）
│  Streams API │◀────────│ 清理任务（定时）            │──▶ 本地磁盘或 S3 兼容存储（密文）
└──────────────┘         └─────────────────────────┘
```

服务端技术：Go 标准库 `net/http` 加 `chi` 路由，`sqlc` 或手写参数化 SQL，`slog` 结构化日志。存储层定义接口，先实现本地磁盘，再实现 S3 兼容存储（用 MinIO 测试）。

## 6. 数据模型

```
files
  id               TEXT PRIMARY KEY  -- 128 位随机，base64url
  size_bytes       INTEGER
  meta_ciphertext  BLOB
  auth_verifier    BLOB
  owner_token_hash BLOB              -- 删除令牌的哈希
  has_password     BOOLEAN
  password_salt    BLOB NULL
  downloads_left   INTEGER
  expires_at       TIMESTAMP
  created_at       TIMESTAMP

audit_log
  id, event_type, file_id, ip_hash, user_agent_hash, created_at
```

审计日志中的 IP 只存加盐哈希，兼顾追溯与隐私。

## 7. 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/files` | 创建上传，返回 id 和上传地址 |
| PUT | `/api/v1/files/{id}/content` | 流式上传密文 |
| GET | `/api/v1/files/{id}/meta` | 返回加密元数据和认证挑战 |
| POST | `/api/v1/files/{id}/download` | 提交挑战签名，返回一次性下载令牌 |
| GET | `/api/v1/files/{id}/content?token=` | 流式下载密文 |
| DELETE | `/api/v1/files/{id}` | 用删除令牌删除 |
| GET | `/healthz` | 健康检查 |

所有错误统一返回 `{"error":{"code":"...","message":"..."}}`。不存在、已过期、令牌错误返回同样的 404，避免泄露文件是否存在。

## 8. 安全控制清单

- HTTPS（本地用 Caddy 自动证书或自签证书）
- 安全响应头：严格 CSP（禁止内联脚本）、HSTS、X-Content-Type-Options、Referrer-Policy: no-referrer、Permissions-Policy
- 限流：按 IP 的令牌桶，上传和下载认证分别设限
- 下载认证失败多次后锁定该文件一段时间
- 请求体大小限制和超时设置
- 文件 id 和令牌使用加密安全随机数
- CI 中运行 gosec、govulncheck、npm audit、Semgrep，以及 OWASP ZAP 基线扫描
- 容器以非 root 用户运行，只读文件系统，最小镜像

## 9. 安全文档（交付重点）

- `docs/security/THREAT_MODEL.md`：用 STRIDE 方法分析，列出资产、信任边界、威胁、缓解措施、残余风险
- `docs/security/TEST_REPORT.md`：按 OWASP Top 10 最新版逐项自测，写测试方法、结果、证据截图、修复情况
- `docs/security/FINDINGS.md`：开发中发现的问题和修复记录
- `SECURITY.md`：漏洞报告方式

## 10. 测试策略

- Go 单元测试和集成测试（含过期、次数用完、并发下载扣减的竞态测试）
- 前端加密模块单元测试：加密后解密得到原文；篡改任意字节解密失败；截断密文解密失败
- 端到端测试（Playwright）：上传、分享、下载、阅后即焚完整流程
- 已知测试向量：HKDF 和 AES-GCM 用标准测试向量验证

## 11. 交付物

- Docker compose 一键启动
- 公开演示站点（限制文件大小和保留时间）
- 英文 README：一句话介绍、加密流程图、演示 GIF、威胁模型摘要、已知局限
- 第 9 节的全部安全文档

## 12. 面试准备

- 为什么密钥放在 URL 片段里是安全的？在什么情况下会泄露？
- AES-GCM 的 nonce 复用会导致什么后果？你怎么避免？
- 为什么要分块加密？如何防止分块被重排或截断？
- 为什么口令要用 Argon2id，而不是 SHA-256？
- 服务器被完全攻破时，攻击者能拿到什么，拿不到什么？
- 下载次数扣减在并发下如何保证正确？
- 你的 OWASP 自测发现了什么问题？
