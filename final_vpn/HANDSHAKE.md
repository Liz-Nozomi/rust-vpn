# VPN 握手协议说明

## 概述

本项目实现了一个基于 **X25519 ECDH + PSK** 的握手协议，用于在客户端和服务端之间安全地协商会话密钥。

## 协议设计

### 安全特性

1. **前向安全性 (Forward Secrecy)**：使用临时的 X25519 密钥对，每次连接的会话密钥都不同
2. **身份认证**：通过预共享密钥（PSK）防止中间人攻击
3. **密钥派生**：使用 BLAKE3 哈希函数从 ECDH 共享密钥和 PSK 派生会话密钥

### 握手流程

```
客户端                                服务端
  |                                     |
  | 1. ClientHello                      |
  |    { client_pubkey[32] }           |
  |------------------------------------>|
  |                                     | 生成临时密钥对
  |                                     | 计算共享密钥
  | 2. ServerHello                      |
  |    { server_pubkey[32] }           |
  |<------------------------------------|
  |                                     |
  | 计算相同的共享密钥                   |
  | session_key = KDF(ECDH || PSK)      |
  |                                     |
  | 3. 使用 session_key 加密通信        |
  |<===================================>|
```

### 消息格式

#### 1. ClientHello
```rust
HandshakeMessage::ClientHello {
    client_pubkey: [u8; 32],  // X25519 公钥
    client_id: String,         // 客户端标识（用于日志）
}
```

#### 2. ServerHello
```rust
HandshakeMessage::ServerHello {
    server_pubkey: [u8; 32],  // X25519 公钥
}
```

### 密钥派生函数（KDF）

```
session_key = BLAKE3("VPN_SESSION_KEY_V1" || ECDH_shared || PSK)[:32]
```

其中：
- `ECDH_shared`: X25519 密钥交换产生的共享密钥（32字节）
- `PSK`: 预共享密钥（32字节）
- 最终取 BLAKE3 输出的前 32 字节作为会话密钥

## 代码结构

### 核心模块 (vpn_core/src/handshake.rs)

- **ClientHandshake**: 客户端握手状态机
  - `new(psk)`: 初始化并生成临时密钥对
  - `create_client_hello()`: 生成 ClientHello 消息
  - `process_server_hello()`: 处理 ServerHello 并计算会话密钥

- **ServerHandshake**: 服务端握手状态机
  - `new(psk)`: 初始化并生成临时密钥对
  - `process_client_hello()`: 处理 ClientHello 并生成 ServerHello
  - `compute_session_key()`: 计算会话密钥

### 客户端集成 (vpn_client/src/main.rs)

```rust
// 1. 创建 UDP Socket
let socket = UdpSocket::bind("0.0.0.0:0").await?;

// 2. 执行握手
let session_key = perform_handshake(&socket, server_addr, client_id).await?;

// 3. 使用会话密钥创建加密器
let cipher = Cipher::new(&session_key)?;

// 4. 开始加密通信
```

### 服务端集成 (vpn_server/src/main.rs)

```rust
loop {
    let (len, src_addr) = socket.recv_from(&mut buf).await?;
    
    // 尝试识别是否为握手消息
    if let Ok(handshake_msg) = deserialize_message(&buf[..len]) {
        // 处理握手
        handle_handshake(&socket, src_addr, handshake_msg, &sessions).await;
    } else {
        // 处理加密数据包
        handle_data_packet(&socket, src_addr, &buf[..len], &peers, &sessions).await;
    }
}
```

## 安全考虑

### 已实现
- ✅ 临时密钥：每次连接使用新的 ECDH 密钥对
- ✅ 前向安全：旧会话密钥泄露不影响历史通信
- ✅ 认证机制：PSK 防止中间人攻击

### 待改进（生产环境建议）
- ⚠️ 重放攻击防护：添加 nonce 或时间戳
- ⚠️ 会话超时：实现会话过期和重新握手
- ⚠️ 证书认证：替换 PSK 为基于证书的认证
- ⚠️ 更完整的握手确认：实现 ClientFinish/ServerFinish 消息

## 使用方法

### 1. 配置 PSK
客户端和服务端必须使用相同的 PSK：

```rust
// 客户端和服务端都需要配置
const PSK: &[u8; 32] = b"your_32_byte_preshared_key!!";
```

### 2. 启动服务端
```bash
cargo run --bin vpn_server
```

### 3. 启动客户端
```bash
# 客户端1 (10.0.0.2)
sudo cargo run --bin vpn_client 10.0.0.2

# 客户端2 (10.0.0.3)
sudo cargo run --bin vpn_client 10.0.0.3
```

### 4. 测试连通性
```bash
# 在客户端1
ping 10.0.0.3
```

## 技术栈

- **X25519**: 椭圆曲线 Diffie-Hellman 密钥交换
- **BLAKE3**: 快速安全的哈希函数
- **ChaCha20-Poly1305**: AEAD 对称加密
- **Bincode**: 消息序列化

## 扩展性

当前设计已为将来扩展预留了接口：

1. **算法可替换**：握手模块独立，可替换为其他密钥交换算法（如 RSA、ECDSA）
2. **协议可扩展**：HandshakeMessage 枚举可添加新的消息类型
3. **认证可升级**：可从 PSK 升级到证书或公钥基础设施（PKI）

## 参考资料

- [X25519-Dalek 文档](https://docs.rs/x25519-dalek/)
- [BLAKE3 规范](https://github.com/BLAKE3-team/BLAKE3)
- [RFC 7748 - Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
