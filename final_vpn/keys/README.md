# Keys 目录说明

此目录用于存储 VPN 服务端的密钥对。

## 文件说明

- `server_private.key` - 服务端私钥（敏感信息，已加入 .gitignore）
- `server_public.key` - 服务端公钥（客户端需要此文件进行身份验证）

## 密钥生成

首次运行服务端时会自动生成密钥对：

```bash
cargo run --bin vpn_server
```

服务端会在启动时输出公钥信息，客户端需要该公钥文件来验证服务端身份。

## 安全提示

⚠️ **重要**: 
- `server_private.key` 必须妥善保管，不要提交到版本控制系统
- 如果私钥泄露，请立即重新生成密钥对
- 客户端必须拥有正确的 `server_public.key` 才能连接
