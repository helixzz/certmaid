# 配置参考

## 配置文件位置

certmaid 按以下优先级查找配置文件：

1. 命令行参数 `-c` / `--config` 指定的路径
2. 当前目录的 `config.yaml`
3. `/etc/certmaid/config.yaml`（推荐位置）

## 完整配置结构

```yaml
# ============================================
# certmaid 全局配置
# ============================================

# 全局默认值（可被每个 certificate spec 覆盖）
defaults:
  # 续签策略
  renew_before: 720h            # 证书到期前多久开始续签（默认 720h = 30天）
  check_interval: 12h           # 定时检查间隔（systemd timer 模式下使用）
  
  # 私钥配置
  key_type: RSA2048             # 私钥类型: RSA2048 | RSA4096 | ECDSA256 | ECDSA384
  key_algorithm: rsa            # 算法: rsa | ecdsa
  
  # 验证方式
  challenge: http-01            # 验证方式: http-01（dns-01 远期支持）
  
  # 输出目录权限
  cert_dir_mode: 0750           # 证书目录权限
  cert_file_mode: 0640          # 证书文件权限
  cert_group: certmaid           # 证书文件属组（留空则使用当前用户组）

# CA 后端配置
backends:
  # HashiCorp Vault
  vault:
    # ACME 模式（推荐，Vault 1.14+）
    acme:
      enabled: true
      directory_url: "https://vault.example.com:8200/v1/pki/acme/directory"
      # Vault ACME 需要 EAB（External Account Binding）时配置
      eab:
        kid: ""                  # EAB Key ID
        hmac_key: ""             # EAB HMAC Key（支持环境变量: ${VAULT_EAB_HMAC_KEY}）
    
    # 直连 API 模式（备用，当 Vault ACME 不可用时）
    api:
      enabled: false
      address: "https://vault.example.com:8200"
      # 认证方式（选一种）
      auth:
        # Token 认证
        token:
          token_file: "/etc/certmaid/vault-token"   # token 文件路径
          # 或使用环境变量: ${VAULT_TOKEN}
        # AppRole 认证
        approle:
          role_id_file: "/etc/certmaid/vault-role-id"
          secret_id_file: "/etc/certmaid/vault-secret-id"
        # TLS 证书认证
        tls_cert:
          cert_file: "/etc/certmaid/vault-client.pem"
          key_file: "/etc/certmaid/vault-client-key.pem"
          role_name: "certmaid"
      
      # TLS 配置（当 Vault 使用自签名证书时）
      tls:
        ca_cert_file: "/etc/certmaid/vault-ca.pem"
        insecure_skip_verify: false   # 仅测试环境使用！
      
      # PKI 参数
      pki:
        mount_path: "pki"          # PKI secrets engine 挂载路径
        role: "server-certs"       # 要使用的 role 名称

  # Active Directory CS（远期规划）
  # adcs:
  #   enabled: false
  #   ...

# 输出路径全局配置
output:
  # certmaid 管理的证书目录结构
  # 证书写入: <base_dir>/<name>/cert.pem
  # 私钥写入: <base_dir>/<name>/key.pem
  # 链证书写入: <base_dir>/<name>/chain.pem
  base_dir: "/etc/certmaid/certs"
  
  # 其他输出方式（直接指定路径）
  custom:
    enabled: false
    paths: []

# 全局 Hook
hooks:
  # 续签前执行的命令/脚本
  pre_renew:
    command: ""
    script: ""
  
  # 续签后执行的命令/脚本
  post_renew:
    # Nginx 自动 reload（内置支持）
    nginx_reload: true
    nginx_config_test: true       # reload 前先执行 nginx -t
    
    # 自定义命令
    command: ""
    
    # 自定义脚本
    script: "/etc/certmaid/hooks/post-renew.sh"

# 日志配置
logging:
  level: info                     # debug | info | warn | error
  format: json                    # json | text
  file: "/var/log/certmaid/certmaid.log"
  max_size: 100                   # MB，日志文件最大大小
  max_backups: 7                  # 保留的旧日志文件数

# ============================================
# 证书规格列表
# ============================================
certificates:
  # 示例 1：一个基本证书
  - name: example-web            # 唯一标识符
    domains:
      - example.com
      - www.example.com
    backend: vault                # 使用哪个 CA 后端: vault | adcs
    
    # 可选覆盖默认值
    renew_before: 240h            # 覆盖全局 renew_before（10天）
    key_type: ECDSA256            # 覆盖全局 key_type
    
    # 可选：指定输出路径
    output:
      cert_path: "/etc/nginx/ssl/example.com.crt"
      key_path: "/etc/nginx/ssl/example.com.key"
      chain_path: "/etc/nginx/ssl/example.com.chain.crt"
    
    # 可选：为这个证书单独配置 hook
    hooks:
      post_renew:
        command: "curl -X POST https://status.example.com/api/ssl-updated"
        nginx_reload: true
  
  # 示例 2：另一个证书，使用不同的 role
  - name: api-internal
    domains:
      - api.internal.example.com
    backend: vault
    backend_config:
      vault:
        pki:
          role: "internal-certs"  # 使用不同的 Vault PKI role
  
  # 示例 3：通配符证书（需要 DNS-01，远期支持）
  # - name: wildcard-web
  #   domains:
  #     - "*.example.com"
  #   backend: vault
  #   challenge: dns-01
  #   dns:
  #     provider: cloudflare
  #     ...
```

## 配置字段说明

### defaults

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `renew_before` | duration | `720h` | 证书到期前多少小时开始续签 |
| `check_interval` | duration | `12h` | systemd timer 的检查间隔 |
| `key_type` | string | `RSA2048` | 私钥类型 |
| `key_algorithm` | string | `rsa` | 算法 |
| `challenge` | string | `http-01` | ACME 验证方式 |
| `cert_dir_mode` | octal | `0750` | 证书目录权限 |
| `cert_file_mode` | octal | `0640` | 证书文件权限 |

### certificates[*]

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | ✅ | 唯一标识符 |
| `domains` | []string | ✅ | 证书覆盖的域名列表 |
| `backend` | string | ✅ | CA 后端（`vault`） |
| `renew_before` | duration | ❌ | 覆盖全局 renew_before |
| `key_type` | string | ❌ | 覆盖全局 key_type |
| `output` | object | ❌ | 自定义输出路径 |
| `backend_config` | object | ❌ | 覆盖后端配置 |
| `hooks` | object | ❌ | 覆盖全局 hook |

## 环境变量支持

配置中的字符串值支持 `${VAR}` 语法引用环境变量：

```yaml
backends:
  vault:
    acme:
      eab:
        hmac_key: "${VAULT_EAB_HMAC_KEY}"
```

## 验证配置

```bash
# 验证配置文件语法和完整性
certmaid config validate

# 输出解析后的完整配置（合并默认值后，脱敏处理）
certmaid config show
```
