# 🦀 rust-vpn

### 一个Rust课程作业，一个后量子安全的轻量级VPN

支持现代非对称加密、后量子密码混合密钥交换（X25519+ML-KEM），并全流量对称加密的高性能VPN demo。实际上能用，但是实现各处还是比较绿皮的，也有不完善的部分，所以称为demo。目前服务端支持Linux，客户端支持🍎macOS和🐧Linux。

## 🏗️ 功能设计

### 1. 💻 - 💻 异地组网模式（side to side VPN，类似Hamachi）

<img src="Mermaid Chart - Create complex, visual diagrams with text.-2025-12-25-121104.png" alt="Mermaid Chart - Create complex, visual diagrams with text.-2025-12-25-121104" style="zoom:10%;" />


✅客户端可以相互通信

❌没有公网访问权限

🎮可以用来游戏组网、内网传输等功能

### 2. 💻 - 🌍 代理服务器（Proxy，类似某ShadowSocks）

<img src="Mermaid Chart - Create complex, visual diagrams with text.-2025-12-25-121610.png" alt="Mermaid Chart - Create complex, visual diagrams with text.-2025-12-25-121610" style="zoom:10%;" />

比较符合我们对VPN的传统认知，一个服务端充当了转发器，可以作为代理，转发所有流量。

同时，这个模式也保留了异地组网的能力。

#### 3. 项目结构

```graph
final_vpn/
├── keys/            
│   ├── .gitignore          
│   ├── README.md             # 密钥说明文档
│   ├── server_private.key  
│   └── server_public.key   
├── vpn_core/          # 核心库
│   ├── src/
│   │   ├── lib.rs            # 模块导出
│   │   ├── symmetric.rs      # 对称加密 (ChaCha20-Poly1305)
│   │   ├── handshake.rs      # 握手协议 (X25519 + ML-KEM)
│   │   ├── asymmetric.rs     # 非对称加密 (Ed25519 签名)
│   │   ├── local_tun.rs      # TUN 设备管理
│   │   └── gateway.rs        # 网关功能（IP转发、NAT）
│   └── Cargo.toml
├── vpn_server/        # 服务端
│   ├── src/main.rs           # UDP 监听、会话管理、包转发、网关
│   └── Cargo.toml
└── vpn_client/        # 客户端
    ├── src/main.rs           # TUN 读写、加密通信、路由配置
    └── Cargo.toml
```

## 🛡️ 安全机制

### 1. 混合密钥交换协议

本项目采用混合密钥交换机制，结合经典椭圆曲线密码学（X25519）和后量子密码学（ML-KEM-768），提供双重安全保障：

- **X25519 ECDH**：提供当前最高水平的经典安全性，已广泛应用于 TLS 1.3、WireGuard 等。同时它的密钥非常小。
- **ML-KEM-768**：NIST 标准化的后量子密钥封装机制（原 Kyber-768），抵御量子计算攻击
- **混合模式**：即使其中一种算法被破解，另一种仍能保护通信安全

### 2. 为什么需要密文巨大的后量子密码？

现在的量子计算机还没做完，Shor算法还没成型，但是进度已经相当快了。如果量子Shor算法横空出世，那么基于大整数分解和离散对数的RSA、ECC、ECDH的安全性都将归零。ML-KEM基于格，其中包含了一个最短向量的NP-Hard问题，目前被认为能抵御量子攻击。

目前的对称加密算法，如AES或者Chacha20-Poly1305算法在量子计算机下强度下降一半，所以位数

### 3. 协议设计

<img src="Mermaid Chart - Create complex, visual diagrams with text.-2025-12-25-123053.png" alt="Mermaid Chart - Create complex, visual diagrams with text.-2025-12-25-123053" />

### 4. 加密栈

| 层级      | 算法              | 密钥长度 | 说明                           |
| --------- | ----------------- | -------- | ------------------------------ |
| 身份认证  | Ed25519           | 256-bit  | 服务端数字签名验证             |
| 密钥协商  | X25519 ECDH       | 256-bit  | 经典椭圆曲线 Diffie-Hellman    |
| 后量子KEM | ML-KEM-768        | 256-bit  | NIST标准后量子密钥封装机制     |
| 密钥派生  | BLAKE3            | 256-bit  | 高性能哈希函数（混合密钥派生） |
| 数据加密  | ChaCha20-Poly1305 | 256-bit  | AEAD 认证加密                  |

### 5. 安全性分析

#### 5.1 混合模式的优势

1. **防御未知漏洞**：即使 X25519 或 ML-KEM 之一存在未发现的漏洞，攻击者仍需同时破解两种算法
2. **平滑过渡**：保持与经典密码系统的兼容性，同时提前部署抗量子能力
3. **双重信任**：X25519 经过多年实战检验，ML-KEM 通过 NIST 标准化审查

#### 5.2 攻击模型防护

- ✅ **中间人攻击**：Ed25519 签名验证服务端身份
- ✅ **重放攻击**：每次握手使用新的临时密钥对（前向安全）
- ✅ **量子计算攻击**：ML-KEM-768 提供后量子安全性
- ✅ **密钥泄露风险**：临时密钥用后即弃，PSK 增强认证
- ⚠️ **侧信道攻击**：依赖底层密码库的实现（pqc_kyber、x25519-dalek）

## 🗃️ 编译

```bash
git clone https://github.com/Liz-Nozomi/rust-vpn
cd final_vpn

# 编译所有组件
cargo build --release

# 或分别编译
cargo build --release --bin vpn_server
cargo build --release --bin vpn_client
```

二进制文件都放在 `rust_vpn/final_vpn/target/release` 里面。

## 🔗使用方法

### 1. 首次运行

在server和client上都clone好项目。随后，首次运行，服务端会生成密钥对。

```bash
./target/release/vpn_server
```

密钥对存放在 `/keys`中，

# `<u>`**一定不要泄漏自己的私钥**`</u>`

公钥是可以随意传播的。从服务器上把这个公钥下载下来（如果愿意折磨自己写入十六进制文件我也没意见），然后放到客户端的keys里面。

### 2. 点对点模式（异地组网）

#### 场景一：本地测试

```bash
./target/release/vpn_server
sudo ./target/release/vpn_client 10.0.0.2 127.0.0.1:9000
sudo ./target/release/vpn_client 10.0.0.3 127.0.0.1:9000
ping 10.0.0.3
```

建议是开四个终端来完成测试。能ping通就是能跑。

#### 场景二：跨网络部署

服务端（假设ip为114.51.4.191）：

```bash
./target/release/vpn_server
```

客户端：

```bash
sudo ./target/release/vpn_client 10.0.0.2 114.51.4.191:9000
```

另一台机：

```bash
sudo ./target/release/vpn_client 10.0.0.3 114.51.4.191:9000
```

然后互ping就行了。如果真的要传输一些数据，需要改写一下路由表。

sudo是用来开tun接口的，这个是必须的。

### 3. 代理模式

服务端：

```bash
sudo ./target/release/vpn_server --gateway
```

程序会自动：

程序会自动：

- 创建 TUN 设备（tun0）
- 启用 IP 转发（`/proc/sys/net/ipv4/ip_forward = 1`）
- 检测外网接口（如 eth0）
- 配置 iptables NAT 规则

客户端：

1. 全隧道模式（对应常用VPN的“全局”）

   ```bash
   sudo ./target/release/vpn_client 10.0.0.2 114.51.4.191:9000 --full-tunnel
   ```

   - 默认路由指向 VPN
   - 所有网络流量通过服务器
   - 公网 IP 变为服务器 IP
2. 分流模式（对应“规则”，当然在这里实现一个RULE实在是没那么多时间写）

   ```bash
   sudo ./target/release/vpn_client 10.0.0.2 <服务器IP>:9000
   ```

   - 仅 10.0.0.0/24 走 VPN
   - 其他流量走本地网关
   - 适合需要同时访问内网和 VPN 的场景

## 🙅 故障排除

### 🚪 权限错误

**问题：**

```bash
❌ 启用IP转发失败: Permission denied
```

**解决：**
必须使用 `sudo` 运行：

```bash
sudo ./target/release/vpn_server --gateway
sudo ./target/release/vpn_client 10.0.0.2 <服务器IP>:9000
```

### 🚗 全隧道模式导致连接中断

**问题：**
使用 `--full-tunnel` 后无法连接服务器。

**原因：**
默认路由修改后，到服务器的连接也被路由到 VPN，形成死循环。

**解决方案 A：添加服务器路由例外（推荐）**

```bash
# 在启动客户端前，添加服务器路由
# 假设服务器是 192.168.1.100，本地网关是 192.168.1.1

# Linux
sudo ip route add 192.168.1.100 via 192.168.1.1

# macOS
sudo route add 192.168.1.100 192.168.1.1
```

**解决方案 B：使用分流模式**
不使用 `--full-tunnel`，手动添加需要的路由：

```bash
# 只让特定网段走 VPN
sudo route add 8.8.8.0/24 10.0.0.1
```

### 🔒 客户端无法连接服务端

**问题：**
客户端启动后无法建立连接。

**排查步骤：**

1. **检查防火墙：**

   ```bash
   # Linux（允许 UDP 9000 端口）
   sudo ufw allow 9000/udp
   sudo ufw enable
   
   # macOS（在系统偏好设置中配置）
   ```
2. **确认服务端已启动：**

   ```bash
   # 查看是否监听 9000 端口
   # Linux
   sudo ss -tunlp | grep 9000
   ```
3. **检查网络连通性：**

   ```bash
   # Ping 服务器
   ping <服务器IP>
   
   # 测试 UDP 连接（需要 nc 工具）
   nc -u <服务器IP> 9000
   ```
4. **确认公钥文件存在：**

   ```bash
   ls -l keys/server_public.key
   ```
5. **在云服务商的防火墙规则里，放通9000端口。**

## ⚠️ 免责声明

本项目为教学和实验性质，未经过充分的安全审计。**不建议在生产环境中直接使用**。使用本项目所产生的任何风险由使用者自行承担。

### 生产环境部署可能可以采取的安全措施：

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
