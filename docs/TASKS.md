# 任务清单

## M0 初始化
- [ ] 用 Vite 创建 `web/`（React + TypeScript），配置 ESLint、Prettier、Vitest
- [ ] 服务端目录结构：`internal/{api,store,blob,audit,config}`
- [ ] 配置读取（环境变量）与 `.env.example`
- [ ] CI 增加前端测试和依赖扫描
- [ ] docker compose：服务、Caddy 反向代理（HTTPS）

## M1 加密模块（前端，最先做，最重要）
- [ ] HKDF 派生 fileKey、metaKey、authKey
- [ ] 分块 AES-GCM 加密和解密（Streams API）
- [ ] nonce 构造与结束标记
- [ ] 元数据加密
- [ ] 测试：往返正确、篡改失败、截断失败、重排失败、标准测试向量
- [ ] 在 DECISIONS.md 写清楚密文格式

## M2 后端核心
- [ ] 数据库表与迁移
- [ ] 存储接口与本地磁盘实现
- [ ] 创建上传、流式上传接口，带大小限制
- [ ] 元数据、挑战、下载令牌、流式下载接口
- [ ] 下载次数原子扣减与并发测试
- [ ] 删除令牌
- [ ] 过期清理任务

## M3 前端页面
- [ ] 上传页：拖拽、进度条、过期和次数选项、复制链接
- [ ] 下载页：读取片段密钥、解密进度、保存文件
- [ ] 错误状态：链接无效、已过期、口令错误
- [ ] 苹果风简洁界面

## M4 安全加固
- [ ] 安全响应头与严格 CSP
- [ ] 限流中间件与认证失败锁定
- [ ] 审计日志
- [ ] 日志脱敏检查
- [ ] 可选口令保护（Argon2id WebAssembly）
- [ ] CI 加入 gosec、govulncheck、Semgrep、ZAP 基线扫描
- [ ] 更新威胁模型的状态列

## M5 安全测试与报告
- [ ] 按 OWASP Top 10 逐项自测，写 `docs/security/TEST_REPORT.md`
- [ ] 修复发现的问题，记录到 FINDINGS.md
- [ ] 写 SECURITY.md

## M6 展示与部署
- [ ] S3 兼容存储实现（MinIO 测试）
- [ ] Playwright 端到端测试
- [ ] 部署公开演示站点（限制大小和保留时间）
- [ ] 英文 README：加密流程图、GIF、威胁模型摘要、已知局限

## 选做 M7 用户账户
- [ ] 注册登录、Argon2id、会话 Cookie、CSRF
- [ ] TOTP 两步验证
- [ ] 我的文件列表
