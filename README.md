# certmaid

**certmaid** 是一个运行在 Linux 环境的命令行工具，用于向企业内部 CA 自动申请和续签 SSL 证书，并将证书写入本机指定位置。支持自动配置 Nginx、在证书更新后触发自定义命令或脚本。

## 设计目标

- **单二进制文件**：Go 编译，无运行时依赖
- **配置驱动**：所有参数通过 YAML 配置文件声明，一份配置覆盖所有场景
- **无人值守**：配合 systemd timer 实现周期性自动续签
- **安全写入**：原子写入证书文件，备份旧证书，权限可控
- **后端可扩展**：当前支持 HashiCorp Vault PKI（1.15+），远期支持 Active Directory CS
- **验证方式可扩展**：当前支持 HTTP-01 ACME，远期支持 DNS-01

## 快速开始

```bash
# 1. 安装
sudo cp certmaid /usr/local/bin/
sudo mkdir -p /etc/certmaid

# 2. 编写配置文件
sudo vim /etc/certmaid/config.yaml

# 3. 测试运行（dry-run 模式，不写入文件）
certmaid run --dry-run

# 4. 正式运行
certmaid run

# 5. 安装 systemd timer（每 12 小时检查一次）
sudo certmaid install --timer
```

## 支持的 CA 后端

| 后端 | 状态 | 验证方式 |
|------|------|----------|
| HashiCorp Vault PKI（1.15+） | ✅ 一期支持 | HTTP-01 ACME |
| Active Directory CS（NDES/SCEP） | ✅ v1.1.0 | SCEP |

## 支持的验证方式

| 方式 | 状态 | 说明 |
|------|------|------|
| HTTP-01 ACME | ✅ 一期支持 | 本机开放 80 端口完成验证 |
| DNS-01 ACME | 🔲 远期规划 | 需自动化 DNS TXT 记录管理 |

## 文档

- [架构设计](docs/architecture.md)
- [配置参考](docs/configuration.md)
- [路线图](docs/roadmap.md)
- [用户手册](docs/user-guide.md)

## 许可证

MIT

---

> GitHub: [github.com/helixzz/certmaid](https://github.com/helixzz/certmaid)
