# 路线图

## 版本规划

```
v0.1.0 ─── v0.2.0 ─── v0.3.0 ─── v1.0.0 ─── v1.1.0 ─── v2.0.0
 MVP      完整Vault   生产就绪   稳定版     AD CS      社区反馈
```

---

## Phase 1 — MVP（v0.1.0）

> 目标：跑通核心流程，验证设计可行性

### 功能

- [ ] **项目骨架**：Go module 初始化、目录结构、Makefile
- [ ] **CLI 框架**：`certmaid run` 命令，基于 cobra
- [ ] **配置加载**：YAML 配置文件解析（`config.yaml`），基本验证
- [ ] **Vault ACME 后端**：
  - 通过 `go-acme/lego` 连接 Vault ACME directory
  - 支持 HTTP-01 challenge（内置 HTTP server 在 80 端口）
  - 支持 EAB（External Account Binding）
- [ ] **证书写入**：将获取的证书和私钥写入磁盘指定路径
- [ ] **Nginx reload**：证书写入成功后自动 `nginx -t && nginx -s reload`
- [ ] **自定义 hook**：支持续签后执行自定义命令/脚本
- [ ] **日志**：基础结构化日志（zap）

### 非功能

- [ ] 示例配置文件 `config.example.yaml`
- [ ] README 快速开始指南
- [ ] 基本错误处理（网络超时、Vault 不可达等）
- [ ] Go 版本：1.22+

### 交付物

- 单二进制文件（`certmaid`）
- 示例配置
- 用户手册（README 级别）
- 手动运行验证通过

---

## Phase 2 — 完整 Vault 支持（v0.2.0）

> 目标：覆盖 Vault 的各种使用场景

### 功能

- [ ] **Vault API 直连模式**（备用路径）：
  - AppRole 认证
  - Token 认证
  - TLS 证书认证
  - 直接调用 `POST /v1/pki/issue/:role`
- [ ] **多证书管理**：配置中定义多份证书，依次检查和续签
- [ ] **续签策略**：
  - 基于 `NotAfter` 的到期检查
  - `renew_before` 提前续签窗口
  - 强制续签模式（`renew --force`）
- [ ] **certmaid 目录结构**：`archive/` + `live/` 符号链接模式
- [ ] **备份机制**：续签前自动备份旧证书

### 非功能

- [ ] 单元测试（config、backend、writer、hook）
- [ ] 集成测试（Vault dev mode + mock CA）
- [ ] 配置文件验证命令（`certmaid config validate`）

### 交付物

- 完整测试覆盖率 ≥ 70%
- 多证书场景验证通过
- Vault API 直连模式验证通过

---

## Phase 3 — 生产就绪（v0.3.0）

> 目标：支持无人值守的生产环境部署

### 功能

- [ ] **systemd 集成**：
  - `certmaid install --timer` 自动安装 service + timer 单元
  - Timer 单元支持 `OnUnitActiveSec` 周期性触发
- [ ] **健康检查**：`certmaid health` 命令检查所有证书状态
- [ ] **配置文件环境变量替换**：`${VAR}` 语法
- [ ] **日志轮转**：内置日志文件管理（lumberjack）
- [ ] **优雅关闭**：SIGTERM/SIGINT 处理
- [ ] **Dry-run 模式**：`certmaid run --dry-run` 不写文件不触发 hook

### 非功能

- [ ] 安全审计（token 不写入日志、权限最小化）
- [ ] 性能测试（多证书场景下的内存和耗时）
- [ ] 完整用户手册（包含 systemd 部署指南）

### 交付物

- systemd unit 文件（`.service` + `.timer`）
- 完整用户手册
- RPM / DEB 打包脚本（可选）

---

## Phase 4 — 稳定版（v1.0.0）

> 目标：API 稳定，向后兼容承诺

### 功能

- [ ] **API 稳定性承诺**：配置文件格式、CLI 接口保证向后兼容
- [ ] **监控与告警**：
  - 续签失败告警（执行自定义告警 hook）
  - 证书即将过期告警（不等待续签窗口）
- [ ] **统计信息**：`certmaid status` 显示所有证书状态表格
- [ ] **更好的错误恢复**：部分证书续签失败不影响其他证书

### 非功能

- [ ] 端到端测试（Vault + Nginx + 真实证书）
- [ ] 文档完整度审查
- [ ] 发布到 GitHub Releases

### 交付物

- GitHub Release v1.0.0
- 完整的 godoc 文档
- CI/CD pipeline（GitHub Actions）

---

## Phase 5 — AD CS 支持（v1.1.0）

> 目标：支持 Windows Active Directory Certificate Services

### 功能

- [ ] **AD CS 后端**：
  - 支持 DCOM / WinRM 或 HTTP API（如 certsrv）
  - 支持 Kerberos 或 NTLM 认证（Go SSPI 或 gokrb5）
  - CSR 自动生成
  - 证书下载和存储
- [ ] **AD CS 配置**：`backends.adcs` 配置段
- [ ] **文档**：AD CS 配置指南

### 交付物

- AD CS 后端实现
- AD CS 配置示例
- 集成测试（Windows 环境）

---

## Phase 6+ — 远期规划（v2.0.0+）

> 目标：社区驱动的功能增强

### 候选功能

- [ ] **DNS-01 验证**：
  - 支持主流 DNS 提供商 API（Cloudflare、Route53、阿里云 DNS 等）
  - 自动添加/删除 TXT 记录
  - 支持通配符证书
- [ ] **更多 Web 服务器支持**：
  - Apache HTTPD
  - Caddy
  - HAProxy
- [ ] **证书透明度（CT）日志**：提交证书到 CT log
- [ ] **OCSP Stapling**：自动获取 OCSP 响应并写入文件
- [ ] **Webhook 通知**：Slack、钉钉、企业微信等
- [ ] **Prometheus metrics**：暴露证书过期时间、续签结果等指标
- [ ] **多 CA 后端负载均衡**：自动选择可用的 CA 后端
- [ ] **证书吊销**：`certmaid revoke <name>`
- [ ] **配置文件热加载**：修改配置后无需重启

---

## 里程碑时间线

| 版本 | 预计时间 | 核心交付 |
|------|----------|----------|
| v0.1.0 | 第 1-2 周 | MVP：Vault ACME + HTTP-01 + Nginx |
| v0.2.0 | 第 3-4 周 | 完整 Vault 支持 + 多证书 + 测试 |
| v0.3.0 | 第 5-6 周 | systemd 集成 + 生产就绪 |
| v1.0.0 | 第 7-8 周 | 稳定版发布 |
| v1.1.0 | 待定 | AD CS 支持 |
| v2.0.0 | 待定 | DNS-01 + 社区功能 |
