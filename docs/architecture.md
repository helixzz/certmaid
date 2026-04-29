# 架构设计

## 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        systemd timer                            │
│                    (每 N 小时触发一次)                             │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     certmaid run                                 │
│                                                                  │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────────────┐  │
│  │  Config  │───▶│  Certificate │───▶│  Certificate Writer   │  │
│  │  Loader  │    │   Manager    │    │  (原子写入 + 备份)      │  │
│  └──────────┘    └──────┬───────┘    └───────────┬───────────┘  │
│                          │                       │              │
│                          ▼                       ▼              │
│                   ┌──────────────┐    ┌───────────────────────┐  │
│                   │ CA Backend   │    │   Post-renewal Hook   │  │
│                   │ (Vault PKI)   │    │  (Nginx reload /      │  │
│                   │              │    │   custom script)      │  │
│                   └──────┬───────┘    └───────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│                   ┌──────────────┐                               │
│                   │ ACME Client  │                               │
│                   │ (go-acme/lego)│                              │
│                   └──────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

## 核心概念

### Certificate Spec（证书规格）

一个 certificate spec 描述一份需要管理的证书：

- **域名列表**（SANs）：证书覆盖的域名
- **CA 后端**：使用哪个 CA 来签发（Vault / AD CS）
- **验证方式**：HTTP-01 / DNS-01
- **输出路径**：证书文件、私钥文件写入磁盘的位置
- **续签策略**：提前多久续签、私钥类型/长度
- **后续动作**：续签后执行什么操作（reload Nginx、执行脚本等）

### 运行模式

| 模式 | 说明 |
|------|------|
| `run` | 检查所有证书状态，对即将过期的证书执行续签 |
| `run --dry-run` | 同上，但不写入文件、不执行 hook |
| `renew <name>` | 强制续签指定证书（忽略过期时间检查） |
| `install --timer` | 安装 systemd service + timer 单元 |

## 组件详解

### 1. Config Loader

- 读取 `/etc/certmaid/config.yaml`
- 验证配置完整性（必填字段、路径合法性、权限检查）
- 支持环境变量覆盖（`${VAR}` 语法）
- 解析为强类型 Go struct

### 2. Certificate Manager

核心调度逻辑：

1. 遍历配置中所有 certificate spec
2. 对每个 spec，读取磁盘上已有的证书文件
3. 解析证书，检查 `NotAfter` 到期时间
4. 若 `time.Until(notAfter) < renewBefore` → 触发续签
5. 调用 CA Backend 获取新证书
6. 调用 Certificate Writer 写入磁盘
7. 执行 Post-renewal Hook

### 3. CA Backend（后端抽象）

```go
// Backend 接口定义
type Backend interface {
    // Issue 申请新证书，返回 PEM 编码的证书链、私钥
    Issue(ctx context.Context, spec CertificateSpec) (*CertificateBundle, error)
}

type CertificateBundle struct {
    Certificate    []byte   // 叶子证书 PEM
    PrivateKey     []byte   // 私钥 PEM
    IssuingCA      []byte   // 签发 CA 证书 PEM
    CAChain        [][]byte // 完整证书链
}
```

#### Vault PKI 后端实现

certmaid 支持两种方式与 Vault PKI 交互：

**方式 A：ACME 模式（推荐，Vault 1.14+）**

利用 Vault 内置的 ACME 支持。Vault 1.14+ 的 PKI secrets engine 可启用 ACME 协议，certmaid 通过标准 ACME 客户端与之交互：

- 使用 `go-acme/lego`（成熟稳定，9k+ stars）或 `mholt/acmez`（更轻量，零核心依赖）作为 ACME 客户端
- 将 Vault 的 ACME directory URL 配置为 `CADirURL`
- HTTP-01 challenge 由客户端内置的 HTTP provider 处理
- 完全复用 ACME 协议流程，无需理解 Vault 专有 API
- 支持 EAB（External Account Binding）认证

```go
// lego 方式
config := lego.NewConfig(&myUser)
config.CADirURL = "https://vault.example.com:8200/v1/pki/acme/directory"
client, _ := lego.NewClient(config)
client.Challenge.SetHTTP01Provider(
    http01.NewProviderServer("", "80"),
)
certs, _ := client.Certificate.Obtain(certificate.ObtainRequest{
    Domains: []string{"example.com"},
    Bundle:  true,
})
// certs.Certificate, certs.PrivateKey, certs.IssuerCertificate (PEM bytes)
```

**方式 B：Vault API 直连模式（备用）**

当 Vault ACME 不可用时，直接调用 Vault PKI API：

- 端点：`POST /v1/{mount}/issue/{role}`
- 响应包含：`certificate`（PEM）、`private_key`（PEM）、`issuing_ca`（PEM）、`ca_chain`（数组）、`serial_number`（冒号分隔十六进制）、`expiration`（Unix 时间戳字符串）
- 通过 Vault Go SDK（`github.com/hashicorp/vault/api`）调用
- 认证方式按优先级：AppRole → Token（文件/环境变量 `VAULT_TOKEN`）→ TLS 证书认证
- Vault 不保存私钥，certmaid 必须在申请后立即持久化到磁盘

```go
// Vault API 直连方式
client, _ := api.NewClient(api.DefaultConfig())
client.SetToken(token)

secret, _ := client.Logical().Write("pki/issue/server-certs", map[string]interface{}{
    "common_name": "example.com",
    "ttl":         "720h",
    "alt_names":   "www.example.com",
})

certPEM  := secret.Data["certificate"].(string)
keyPEM   := secret.Data["private_key"].(string)
caChain  := secret.Data["ca_chain"].([]interface{})
expUnix, _ := strconv.ParseInt(secret.Data["expiration"].(string), 10, 64)
```

### 4. Certificate Writer

安全写入证书文件：

```
/etc/certmaid/
├── archive/                     # 历史版本归档
│   └── example.com/
│       ├── cert-20260429.pem
│       ├── key-20260429.pem
│       └── chain-20260429.pem
├── live/                        # 当前生效版本（symlink → archive）
│   └── example.com/
│       ├── cert.pem  → ../../archive/example.com/cert-20260429.pem
│       ├── key.pem   → ../../archive/example.com/key-20260429.pem
│       └── chain.pem → ../../archive/example.com/chain-20260429.pem
```

写入流程：
1. 将新证书写入 `archive/<name>/cert-YYYYMMDD.pem`（在同一目录创建临时文件，`fsync` 后 `os.Rename`）
2. 设置正确的文件权限（证书 `0644`，私钥 `0600`）
3. 原子替换 `live/<name>/cert.pem` 符号链接（`os.Symlink` → `os.Rename`）
4. 保留最近 N 个历史版本，自动清理过期归档

### 5. Post-renewal Hook

Hook 系统支持多个触发点：

```yaml
hooks:
  pre_renew:                    # 续签前（检查磁盘空间、连通性等）
    - /usr/local/bin/pre-check.sh
  post_renew:                   # 续签成功后
    nginx_reload: true          # 内置：nginx -t && nginx -s reload
    command: "curl -X POST https://status.example.com/api/cert-updated"
    script: "/etc/certmaid/hooks/post-renew.sh"
  on_error:                     # 续签失败时
    - "/usr/local/bin/alert-admins.sh"
```

Hook 脚本接收环境变量：
- `CERTMAID_ACTION` — `renew` | `deploy`
- `CERTMAID_CERT_PATH` — 新证书路径
- `CERTMAID_KEY_PATH` — 新私钥路径
- `CERTMAID_DOMAINS` — 证书覆盖的域名（空格分隔）

Nginx reload 流程：
1. `nginx -t -q` 测试配置（静默模式）
2. 若测试通过 → `nginx -s reload`
3. 若测试失败 → 记录 stderr、回滚符号链接

## 目录结构

```
certmaid/
├── cmd/
│   └── certmaid/
│       └── main.go              # 入口
├── internal/
│   ├── config/
│   │   ├── config.go            # 配置结构体定义
│   │   └── loader.go            # YAML 加载与验证
│   ├── backend/
│   │   ├── backend.go           # Backend 接口
│   │   ├── vault.go             # Vault PKI 后端
│   │   └── vault_test.go
│   ├── manager/
│   │   ├── manager.go           # 证书管理器
│   │   └── manager_test.go
│   ├── writer/
│   │   ├── writer.go            # 证书安全写入
│   │   └── writer_test.go
│   └── hook/
│       ├── hook.go              # Hook 执行器
│       └── nginx.go             # Nginx 相关操作
├── go.mod
├── go.sum
├── config.example.yaml          # 示例配置
├── certmaid.service             # systemd service 单元
├── certmaid.timer               # systemd timer 单元
├── Makefile
├── README.md
└── docs/
    ├── architecture.md
    ├── configuration.md
    ├── roadmap.md
    └── user-guide.md
```

## 依赖

| 依赖 | 用途 | 版本 |
|------|------|------|
| `github.com/go-acme/lego/v4` | ACME 客户端（HTTP-01 验证、EAB、ARI） | v4.x |
| `github.com/mholt/acmez` | 轻量备选 ACME 客户端（可选） | v3.x |
| `github.com/hashicorp/vault/api` | Vault Go SDK（API 直连模式） | v1.22+ |
| `gopkg.in/yaml.v3` | YAML 配置解析 | v3 |
| `github.com/spf13/cobra` | CLI 框架 | v1.x |
| `github.com/spf13/viper` | 配置管理（多路径、环境变量覆盖） | v1.x |
| `go.uber.org/zap` | 结构化日志 | v1.x |
| `github.com/google/renameio/v2` | 原子文件写入（可选） | v2 |

## 关键技术细节

### HTTP-01 Challenge 实现

ACME HTTP-01 验证要求：

1. CA 在 80 端口请求 `http://{domain}/.well-known/acme-challenge/{token}`
2. 响应体必须是 **key authorization** 字符串：
   ```
   keyAuthorization = token + "." + base64url(SHA256(JWK_Thumbprint(accountPublicKey)))
   ```
3. `Content-Type: text/plain`
4. Lego 的 `http01.NewProviderServer("", "80")` 实现此逻辑

### Vault PKI 关键数据格式

| 字段 | 格式 | 示例 |
|------|------|------|
| `serial_number` | 冒号分隔十六进制 | `39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58` |
| `expiration` | Unix epoch 字符串 | `"1654105687"` |
| `certificate` | PEM 字符串 | `-----BEGIN CERTIFICATE-----\n...` |
| `private_key` | PEM 字符串 | `-----BEGIN RSA PRIVATE KEY-----\n...` |
| `ca_chain` | PEM 字符串数组 | `["-----BEGIN CERTIFICATE-----\n..."]` |

读取证书时，`/v1/pki/cert/:serial` 的 `:serial` 必须用**连字符**格式（如 `39-dd-2e-...`），需从冒号格式转换：
```go
serialHyphen := strings.ReplaceAll(strings.ToLower(serial), ":", "-")
resp, _ := client.Logical().Read("pki/cert/" + serialHyphen)
```

## 安全设计

- **最小权限**：仅需读取 Vault token（文件或环境变量）、写入证书目录、bind 80 端口（HTTP-01）、执行 nginx reload 的权限
- **Token 不可见**：Vault token 不写入配置文件，从 `VAULT_TOKEN` 环境变量或指定文件中读取，权限 `0400`
- **私钥保护**：私钥文件 `0600`，仅 owner 可读写。证书目录 `0700`
- **原子操作杜绝竞态**：`fsync` + `os.Rename`，Nginx 不会读到不完整文件
- **验证先行**：`nginx -t -q` 通过后才 reload，reload 失败自动回滚符号链接
- **权限分离**：证书文件 `0644`（Nginx worker 可读），私钥 `0600`（仅 certmaid/root 可读）
- **日志脱敏**：结构化日志不包含私钥内容和完整 token
- **systemd 加固**：service 单元使用 `PrivateTmp=true`、`ProtectSystem=full`、`NoNewPrivileges=true`

## systemd 集成详情

```ini
# certmaid.service
[Unit]
Description=CertMaid Certificate Renewal
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/certmaid run --config /etc/certmaid/config.yaml
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/etc/certmaid /etc/nginx/ssl /var/log/certmaid
NoNewPrivileges=true

# certmaid.timer
[Unit]
Description=CertMaid Periodic Certificate Check

[Timer]
OnCalendar=daily
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
```

关键设计：
- `Type=oneshot`：运行完即退出，不常驻
- `RandomizedDelaySec=12h`：错峰分散 CA 负载
- `Persistent=true`：若机器在计划时间关机，下次开机立即触发
- `ProtectSystem=full` + `ReadWritePaths`：白名单外文件系统只读
