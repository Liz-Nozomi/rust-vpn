# 🛡️ Rust VPN - 轻量级点对点 VPN 实现

基于 Rust 的安全、高性能 VPN 解决方案，采用现代加密算法和简洁的架构设计。

## 📋 项目概述

这是一个教学和实验性质的 VPN 项目，实现了完整的加密通信通道，支持多客户端同时连接。项目采用 Workspace 架构，代码清晰易懂，适合学习网络编程和密码学应用。

### ✨ 核心特性

- ✅ **安全握手协议**：基于 X25519 ECDH + Ed25519 数字签名的密钥协商
- ✅ **服务端认证**：使用 Ed25519 公钥验证服务端身份，防止中间人攻击
- ✅ **强加密传输**：ChaCha20-Poly1305 AEAD 加密算法
- ✅ **会话管理**：为每个客户端维护独立的会话密钥
- ✅ **跨平台支持**：支持 macOS 和 Linux
- ✅ **路由学习**：自动建立虚拟 IP 到物理地址的映射
- ✅ **TUN 设备管理**：自动创建和配置虚拟网卡

## 🏗️ 架构设计

```
┌─────────────────┐         握手 + 加密数据          ┌─────────────────┐
│   Client A      │◄────────────────────────────────►│   VPN Server    │
│  (10.0.0.2)     │         UDP (Internet)          │  (0.0.0.0:9000) │
│  验证服务端签名   │                                  │  Ed25519 签名    │
└─────────────────┘                                  └─────────────────┘
        ▲                                                      ▲
        │                                                      │
        │                                            ┌─────────┴─────────┐
        │                                            │   Client B        │
        └────────────────────────────────────────────│  (10.0.0.3)       │
                  路由转发 (加密)                     └───────────────────┘
```

### 项目结构

```
final_vpn/
├── keys/              # 密钥存储目录
│   ├── .gitignore            # 私钥保护配置
│   ├── README.md             # 密钥说明文档
│   ├── server_private.key    # 服务端私钥（运行时生成）
│   └── server_public.key     # 服务端公钥（运行时生成）
├── vpn_core/          # 核心库
│   ├── src/
│   │   ├── lib.rs            # 模块导出
│   │   ├── symmetric.rs      # 对称加密 (ChaCha20-Poly1305)
│   │   ├── handshake.rs      # 握手协议 (X25519 ECDH)
│   │   ├── asymmetric.rs     # 非对称加密 (Ed25519 签名)
│   │   └── local_tun.rs      # TUN 设备管理
│   └── Cargo.toml
├── vpn_server/        # 服务端
│   ├── src/main.rs           # UDP 监听、会话管理、包转发
│   └── Cargo.toml
├── vpn_client/        # 客户端
│   ├── src/main.rs           # TUN 读写、加密通信
│   └── Cargo.toml
└── Cargo.toml         # Workspace 配置
```

## 🔐 安全机制

### 握手协议流程

```
Client                          Server
  │                               │
  ├──── ClientHello ────────────►│
  │   (临时公钥 + 客户端ID)        │
  │                               │ 生成临时密钥对
  │                               │ 使用 Ed25519 私钥签名
  │◄──── ServerHello ─────────────┤
  │     (临时公钥 + Ed25519签名)   │
  │                               │
  │ 验证签名 ✅                     │
  ├─ ECDH 计算会话密钥              ├─ ECDH 计算会话密钥
  │  KDF(ECDH)                    │  KDF(ECDH)
  │                               │
  └──── 使用会话密钥加密数据 ────────┘
```

### 加密栈

| 层级     | 算法              | 说明                    |
| -------- | ----------------- | ----------------------- |
| 身份认证 | Ed25519           | 服务端数字签名验证      |
| 密钥协商 | X25519 ECDH       | 椭圆曲线 Diffie-Hellman |
| 密钥派生 | BLAKE3            | 高性能哈希函数          |
| 数据加密 | ChaCha20-Poly1305 | AEAD 认证加密           |

## 📦 安装与编译

### 前置要求

- Rust 1.70+ (推荐使用 rustup)
- macOS 或 Linux 操作系统
- sudo 权限（创建 TUN 设备需要）

### 编译

```bash
# 克隆项目
git clone <repository-url>
cd final_vpn

# 编译所有组件
cargo build --release

# 或分别编译
cargo build --release --bin vpn_server
cargo build --release --bin vpn_client
```

编译后的二进制文件位于 `target/release/` 目录。

## 🚀 使用方法

### 首次运行 - 生成密钥

服务端首次启动会自动生成 Ed25519 密钥对：

```bash
cargo run --release --bin vpn_server
```

密钥文件保存在 `keys/` 目录：

- `server_private.key` - 服务端私钥（保密）
- `server_public.key` - 服务端公钥（需分发给客户端）

### 场景 1：本地测试（单机多客户端）

**终端 1 - 启动服务端：**

```bash
cargo run --release --bin vpn_server
```

**终端 2 - 启动客户端 A：**

```bash
sudo cargo run --release --bin vpn_client 10.0.0.2
```

**终端 3 - 启动客户端 B：**

```bash
sudo cargo run --release --bin vpn_client 10.0.0.3
```

**终端 2 - 测试连通性：**

```bash
ping 10.0.0.3
```

### 场景 2：跨网络部署

#### 在服务器上（假设公网 IP: `1.2.3.4`）

```bash
# 1. 上传代码
scp -r final_vpn user@1.2.3.4:~/

# 2. SSH 登录并编译
ssh user@1.2.3.4
cd final_vpn
cargo build --release

# 3. 运行服务端（首次会生成密钥）
./target/release/vpn_server

# 4. 下载公钥到本地
# 在本地执行：
scp user@1.2.3.4:~/final_vpn/keys/server_public.key ./keys/
```

#### 在客户端

**客户端 A（你的电脑）：**

```bash
sudo ./target/release/vpn_client 10.0.0.2 1.2.3.4:9000
```

**客户端 B（另一台电脑）：**

```bash
sudo ./target/release/vpn_client 10.0.0.3 1.2.3.4:9000
```

**测试连通：**

```bash
# 在客户端 A
ping 10.0.0.3

# 在客户端 B
ping 10.0.0.2
```

## 📝 命令行参数

### vpn_server

```bash
vpn_server
# 监听在 0.0.0.0:9000 (UDP)
```

### vpn_client

```bash
vpn_client <虚拟IP> [服务器地址]

# 示例：
vpn_client 10.0.0.2                    # 连接本地服务器
vpn_client 10.0.0.2 192.168.1.100:9000  # 指定局域网服务器
vpn_client 10.0.0.2 example.com:9000    # 连接远程服务器（支持域名）
```

**参数说明：**

- `虚拟IP`：客户端在虚拟网络中的 IP 地址（建议使用 10.0.0.x）
- `服务器地址`：VPN 服务器地址，格式为 `host:port`（默认：127.0.0.1:9000）

## 🔧 配置说明

### 密钥管理

**服务端：**

- 首次启动自动生成 Ed25519 密钥对
- 私钥保存在 `keys/server_private.key`（32字节，必须保密）
- 公钥保存在 `keys/server_public.key`（32字节，需分发给客户端）
- 重启时自动加载已有密钥

**客户端：**

- 需要预先获取 `server_public.key`
- 握手时使用公钥验证服务端签名
- 验证失败则拒绝连接

⚠️ **重要**：如果服务端私钥泄露，请立即重新生成密钥对并重新分发公钥！

### 修改监听端口

编辑 [vpn_server/src/main.rs](vpn_server/src/main.rs)：

```rust
const LISTEN_ADDR: &str = "0.0.0.0:9000";  // 改为你想要的端口
```

### 修改虚拟网段

编辑 [vpn_client/src/main.rs](vpn_client/src/main.rs)：

```rust
let tun_mask = "255.255.255.0";
let target_cidr = "10.0.0.0/24";  // 修改为你的虚拟网段
```

## 🧪 技术实现细节

### 核心模块

#### 1. `vpn_core::asymmetric` - 非对称加密

- Ed25519 数字签名算法
- 服务端身份认证
- 密钥生成和管理

#### 2. `vpn_core::symmetric` - 对称加密

- 使用 ChaCha20-Poly1305 AEAD
- 自动生成随机 Nonce（12 字节）
- 输出格式：`[Nonce 12B] + [密文 + MAC 16B]`

#### 3. `vpn_core::handshake` - 握手协议

- X25519 临时密钥对生成
- ECDH 共享密钥计算
- BLAKE3 密钥派生函数
- Ed25519 签名集成
- Bincode 消息序列化

#### 4. `vpn_core::local_tun` - TUN 设备

- 跨平台 TUN 设备创建
- 自动配置 IP 和路由
- 处理 macOS/Linux 数据包头部差异

#### 5. `vpn_server` - 服务端

- 会话管理（SessionMap）
- 路由表（PeerMap）
- 握手消息识别与处理
- 身份认证（Ed25519 签名）
- 数据包解密、转发、重新加密

#### 6. `vpn_client` - 客户端

- TUN 设备读写
- 握手流程
- 服务端签名验证
- 上行/下行异步任务
- 平台适配（macOS 4 字节头部）

## 📊 项目进度

| 功能模块                     | 状态      | 说明               |
| ---------------------------- | --------- | ------------------ |
| 对称加密 (ChaCha20-Poly1305) | ✅ 完成   | 性能优秀，安全可靠 |
| 握手协议 (X25519 ECDH)       | ✅ 完成   | 前向安全性保证     |
| 身份认证 (Ed25519)           | ✅ 完成   | 服务端签名验证     |
| TUN 设备管理                 | ✅ 完成   | 支持 macOS/Linux   |
| 客户端实现                   | ✅ 完成   | 命令行可配置       |
| 服务端实现                   | ✅ 完成   | 多客户端会话管理   |
| 路由学习                     | ✅ 完成   | 握手时自动建立映射 |
| 跨平台支持                   | ✅ 完成   | macOS, Linux       |
| 单元测试                     | ✅ 完成   | 核心模块有测试覆盖 |
| 重连机制                     | ⚪ 待实现 | 断线自动重连       |
| NAT 穿透                     | ⚪ 待实现 | UDP 打洞           |
| 配置文件                     | ⚪ 待实现 | TOML/YAML 配置     |

## 🐛 已知问题与限制

1. **密钥轮转**：会话密钥在整个连接期间不变
2. **无重连机制**：网络断开后需要手动重启客户端
3. **日志过多**：调试日志较多，可根据需要精简
4. **单一服务器**：目前不支持服务器集群

## 🛠️ 开发与调试

### 运行测试

```bash
# 运行所有测试
cargo test

# 运行核心库测试
cargo test --package vpn_core

# 详细输出
cargo test -- --nocapture
```

### 抓包调试

```bash
# 监听 TUN 设备
sudo tcpdump -i utun8 -n -vv

# 监听 UDP 流量
sudo tcpdump -i any port 9000 -n -X
```

### 查看 TUN 设备状态

```bash
# macOS
ifconfig utun8

# Linux
ip addr show tun0
ip route
```

## 🔒 安全建议

### 生产环境部署

1. **保护私钥**：确保 `server_private.key` 权限设置为 600
   ```bash
   chmod 600 keys/server_private.key
   ```
2. **安全分发公钥**：通过安全渠道分发 `server_public.key` 给客户端
3. **防火墙配置**：
   ```bash
   # 仅开放 VPN 端口
   sudo ufw allow 9000/udp
   sudo ufw enable
   ```
4. **限制源 IP**：可在服务端代码中添加 IP 白名单
5. **监控日志**：使用 systemd 或 syslog 管理日志
6. **定期更新**：及时更新依赖库

### 性能优化

- 使用 `--release` 编译以获得最佳性能
- 调整 MTU 大小（当前默认 1500）
- 考虑使用 `async-std` 或 `tokio` 的性能调优选项

## 📚 依赖库

| 库               | 版本 | 用途          |
| ---------------- | ---- | ------------- |
| tokio            | 1.x  | 异步运行时    |
| tun              | 0.6  | TUN 设备创建  |
| chacha20poly1305 | 0.10 | AEAD 加密     |
| x25519-dalek     | 2.x  | ECDH 密钥交换 |
| ed25519-dalek    | 2.x  | 数字签名      |
| blake3           | 1.5  | 密钥派生      |
| serde + bincode  | 1.x  | 消息序列化    |
| anyhow           | 1.0  | 错误处理      |

## 📖 参考资料

- [ChaCha20-Poly1305 RFC 8439](https://tools.ietf.org/html/rfc8439)
- [X25519 RFC 7748](https://tools.ietf.org/html/rfc7748)
- [Ed25519 RFC 8032](https://tools.ietf.org/html/rfc8032)
- [WireGuard Protocol](https://www.wireguard.com/protocol/)
- [Rust Async Book](https://rust-lang.github.io/async-book/)

## 🤝 贡献说明

本项目部分代码是通过 AI 辅助编程完成的。欢迎提交 Issue 和 Pull Request。

## 📄 许可证

本项目仅用于学习和研究目的。使用本代码时请遵守当地法律法规。

## ⚠️ 免责声明

本项目为教学和实验性质，未经过充分的安全审计。**不建议在生产环境中直接使用**。使用本项目所产生的任何风险由使用者自行承担。

---

**作者**：Liz
**最后更新**：2025年12月23日
