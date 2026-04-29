# 用户手册

## 1. 安装

### 源码编译

```bash
git clone https://github.com/helixzz/certmaid.git
cd certmaid
make build
sudo make install
```

安装路径：
- 二进制：`/usr/local/bin/certmaid`
- 配置目录：`/etc/certmaid/`
- 日志目录：`/var/log/certmaid/`

### 预编译二进制（Release）

```bash
# 下载最新 Release
VERSION=$(curl -s https://api.github.com/repos/helixzz/certmaid/releases/latest | grep tag_name | cut -d '"' -f 4)
curl -LO "https://github.com/helixzz/certmaid/releases/download/${VERSION}/certmaid-linux-amd64"
sudo install -m 755 certmaid-linux-amd64 /usr/local/bin/certmaid
```

---

## 2. 前置条件

### Vault 配置

确保 Vault 已启用 PKI secrets engine 并配置 ACME：

```bash
# 在 Vault 服务器上执行
vault secrets enable pki
vault write pki/config/acme enabled=true
vault write pki/roles/server-certs \
    allowed_domains="example.com" \
    allow_subdomains=true \
    max_ttl="2160h"  # 90 天
```

获取 ACME directory URL：
```
https://<vault-address>:8200/v1/pki/acme/directory
```

### 本机环境

- 防火墙开放 80 端口（用于 HTTP-01 验证）
- Nginx 已安装（如需自动 reload）
- certmaid 运行用户对证书输出目录有写权限

---

## 3. 编写配置

1. 复制示例配置：

```bash
sudo cp config.example.yaml /etc/certmaid/config.yaml
```

2. 编辑配置，修改以下必填项：

```yaml
backends:
  vault:
    acme:
      directory_url: "https://你的Vault地址:8200/v1/pki/acme/directory"

certificates:
  - name: my-website
    domains:
      - 你的域名.com
      - www.你的域名.com
    output:
      cert_path: "/etc/nginx/ssl/你的域名.com.crt"
      key_path: "/etc/nginx/ssl/你的域名.com.key"
```

3. 验证配置：

```bash
certmaid config validate
```

---

## 4. 首次运行

### 测试运行（dry-run）

```bash
sudo certmaid run --dry-run
```

这会模拟证书申请流程，但不写入任何文件。观察日志确认流程正确。

### 正式运行

```bash
sudo certmaid run
```

成功后会看到类似输出：

```
INFO  certmaid 开始检查 1 个证书
INFO  my-website  证书不存在，开始申请
INFO  my-website  创建 ACME 订单
INFO  my-website  等待 HTTP-01 challenge 验证
INFO  my-website  验证通过，下载证书
INFO  my-website  证书已写入 /etc/nginx/ssl/你的域名.com.crt
INFO  my-website  私钥已写入 /etc/nginx/ssl/你的域名.com.key
INFO  my-website  执行 post-renew hook: nginx reload
INFO  my-website  Nginx 配置测试通过
INFO  my-website  Nginx 已 reload
INFO  certmaid  完成：1/1 成功
```

---

## 5. 配置 Nginx 使用证书

在 Nginx 配置中引用证书：

```nginx
server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    # 引用 certmaid 写入的证书
    ssl_certificate     /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;

    # 建议的 SSL 配置
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    location / {
        # 你的应用配置
    }
}

# HTTP → HTTPS 重定向
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}
```

> **注意**：因为 certmaid 需要 80 端口做 HTTP-01 验证，Nginx 不能独占 80 端口。有两种解决方案：
>
> **方案 A（推荐）**：certmaid 内置 challenge server 占用 80 端口，Nginx 监听其他端口再反向代理。
>
> **方案 B**：Nginx 占用 80 端口，配置 `.well-known/acme-challenge/` 路径指向 certmaid 的 webroot。

---

## 6. 配置自动续签（systemd timer）

### 安装 systemd 单元

```bash
sudo certmaid install --timer
```

这会创建：
- `/etc/systemd/system/certmaid.service`
- `/etc/systemd/system/certmaid.timer`

### 手动管理

```bash
# 查看 timer 状态
systemctl status certmaid.timer

# 查看最近运行日志
journalctl -u certmaid.service -f

# 手动触发一次续签
systemctl start certmaid.service

# 禁用自动续签
systemctl disable --now certmaid.timer
```

### Timer 配置

默认每 12 小时检查一次。可在配置中修改：

```yaml
defaults:
  check_interval: 6h   # 改为每 6 小时检查
```

---

## 7. 常用命令

```bash
# 查看所有证书状态
certmaid status

# 强制续签指定证书（忽略到期检查）
certmaid renew my-website

# 强制续签 + 覆盖策略
certmaid renew my-website --force

# 验证配置文件
certmaid config validate

# 查看解析后的配置
certmaid config show

# 安装/卸载 systemd timer
certmaid install --timer
certmaid uninstall --timer

# 查看版本
certmaid version
```

---

## 8. 自定义 Hook 示例

### 续签后钉钉通知

```bash
# /etc/certmaid/hooks/post-renew.sh
#!/bin/bash
set -e

DOMAIN="$1"       # certmaid 传入域名
STATUS="$2"       # success / failure

if [ "$STATUS" = "success" ]; then
    curl -s -X POST "https://oapi.dingtalk.com/robot/send?access_token=xxx" \
        -H "Content-Type: application/json" \
        -d "{\"msgtype\":\"text\",\"text\":{\"content\":\"SSL 证书续签成功: $DOMAIN\"}}"
fi
```

在配置中引用：

```yaml
hooks:
  post_renew:
    script: "/etc/certmaid/hooks/post-renew.sh"
```

### 续签后重启服务

```yaml
certificates:
  - name: my-api
    domains:
      - api.example.com
    hooks:
      post_renew:
        command: "systemctl restart my-api-service"
```

---

## 9. 故障排查

### 证书申请失败

```bash
# 查看详细日志
sudo certmaid run --log-level debug

# 常见原因：
# 1. Vault 不可达：检查网络和防火墙
# 2. 80 端口被占用：netstat -tlnp | grep :80
# 3. 域名 DNS 未指向本机：dig example.com
# 4. Vault PKI role 不允许该域名
```

### Nginx reload 失败

```bash
# 手动测试 Nginx 配置
sudo nginx -t

# 查看 Nginx 错误日志
sudo tail -f /var/log/nginx/error.log

# 回滚证书（从 archive 目录恢复）
sudo ls /etc/certmaid/certs/archive/my-website/
# 手动恢复符号链接指向旧版本
```

### 权限问题

```bash
# 确保运行用户对输出目录有写权限
sudo chown -R root:certmaid /etc/nginx/ssl/
sudo chmod 750 /etc/nginx/ssl/

# Vault token 文件权限应为 0400
sudo chmod 400 /etc/certmaid/vault-token
```

---

## 10. 安全建议

1. **Vault token 安全**：
   - 使用只读权限最小的 token（仅需要 `pki/issue/:role` 的 write 权限）
   - 定期轮换 token
   - Token 文件权限 `0400`

2. **证书私钥安全**：
   - 私钥文件权限 `0600`（仅 root 可读写）
   - 不要将私钥提交到版本控制

3. **运行用户**：
   - 建议使用专用的非 root 用户运行（但需要 80 端口和 reload Nginx 的权限）
   - 可配合 sudo 规则实现最小权限

4. **日志安全**：
   - 日志不包含私钥内容
   - 日志不包含完整 token
