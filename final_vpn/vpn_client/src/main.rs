// vpn_client/src/main.rs

#[cfg(target_os = "macos")]
const TUN_READ_OFFSET: usize = 4; // macOS 读出来的头 4 字节是 header

#[cfg(target_os = "linux")]
const TUN_READ_OFFSET: usize = 0; // Linux 配置了 no_pi，所以是 0

use std::env; // 引入环境模块读取参数
use std::sync::Arc;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tun::Device; // 这一行可能需要依赖具体的 tun 库导出，如果报错可尝试删掉或检查 vpn_core

// === 引用核心库 (Workspace 改动) ===
use vpn_core::local_tun; 
use vpn_core::symmetric::Cipher;
use vpn_core::handshake::{ClientHandshake, HandshakeMessage, serialize_message, deserialize_message};
use vpn_core::asymmetric::{ClientVerifier, get_keys_dir};

// 预共享密钥 (PSK) - 用于握手认证
// 注意：服务端必须使用完全相同的 PSK！
const PSK: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

/// 执行握手协议，获取会话密钥
async fn perform_handshake(
    socket: &UdpSocket,
    server_addr: &str,
    client_id: String,
    virtual_ip: String,
) -> Result<[u8; 32], Box<dyn Error>> {
    println!("🤝 开始握手...");
    
    // 0. 加载服务端公钥
    let keys_dir = get_keys_dir()?;
    let public_key_path = keys_dir.join("server_public.key");
    
    if !public_key_path.exists() {
        return Err(format!(
            "❗ 找不到服务端公钥文件: {}\n\n请先启动服务端生成密钥对！",
            public_key_path.display()
        ).into());
    }
    
    let verifier = ClientVerifier::load_from_file(&public_key_path)?;
    println!("   🔑 已加载服务端公钥");
    
    // 1. 创建客户端握手实例
    let client_handshake = ClientHandshake::new(PSK);
    
    // 2. 发送 ClientHello
    let client_hello = client_handshake.create_client_hello(client_id, virtual_ip);
    
    // 保存 client_pubkey 用于验证
    let client_pubkey = match &client_hello {
        HandshakeMessage::ClientHello { client_pubkey, .. } => *client_pubkey,
        _ => unreachable!(),
    };
    
    let hello_data = serialize_message(&client_hello)?;
    socket.send_to(&hello_data, server_addr).await?;
    println!("   📤 已发送 ClientHello ({} 字节)", hello_data.len());
    
    // 3. 接收 ServerHello（增加超时时间并添加重试）
    let mut buf = [0u8; 1024];
    println!("   ⏳ 等待 ServerHello 响应（超时 30 秒）...");
    let (n, from_addr) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        socket.recv_from(&mut buf)
    ).await??;
    
    println!("   📥 收到数据包: {} 字节，来自 {}", n, from_addr);
    
    let server_hello = deserialize_message(&buf[..n])?;
    let (server_pubkey, mlkem_ciphertext, signature) = match server_hello {
        HandshakeMessage::ServerHello { server_pubkey, mlkem_ciphertext, signature } => (server_pubkey, mlkem_ciphertext, signature),
        _ => return Err("预期收到 ServerHello".into()),
    };
    println!("   📥 收到 ServerHello");
    
    // 3.5. 验证服务端签名
    let message_to_verify = [
        &server_pubkey[..],
        &client_pubkey[..],
    ].concat();
    
    verifier.verify(&message_to_verify, &signature)?;
    println!("   ✅ 服务端身份验证成功！");
    
    // 4. 计算会话密钥（混合：X25519 + ML-KEM，消耗 client_handshake）
    let session_key = client_handshake.process_server_hello(server_pubkey, &mlkem_ciphertext)?;
    println!("   🔑 会话密钥协商成功（X25519 + ML-KEM-768）");
    
    // 注意：这里简化了协议，省略了 ClientFinish/ServerFinish
    // 完整实现应该继续发送确认消息    
    Ok(session_key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // === 1. 获取命令行参数 ===
    let args: Vec<String> = env::args().collect();
    
    // 用法: ./vpn_client <虚拟IP> [服务器地址] [--full-tunnel]
    // 示例: ./vpn_client 10.0.0.2 example.com:9000 --full-tunnel
    let tun_ip = if args.len() > 1 { args[1].clone() } else { "10.0.0.1".to_string() };
    let server_addr = if args.len() > 2 { 
        args[2].clone()
    } else { 
        "127.0.0.1:9000".to_string()
    };
    
    // 检查是否启用全隧道模式（所有流量走VPN）
    let full_tunnel = args.contains(&"--full-tunnel".to_string());
    
    println!("🛡️ VPN Client Starting...");
    println!("📍 虚拟 IP: {}", tun_ip);
    println!("🌐 服务器: {}", server_addr);
    if full_tunnel {
        println!("🌍 全隧道模式：所有流量将通过VPN");
    } else {
        println!("🔗 分流模式：仅VPN网段流量走VPN");
    }
    
    // === 配置 ===
    let tun_mask = "255.255.255.0";
    let target_cidr = if full_tunnel {
        "0.0.0.0/0" // 默认路由，所有流量
    } else {
        "10.0.0.0/24" // 仅VPN网段
    };

    // === 3. 创建 UDP Socket（握手前需要先创建） ===
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    println!("📡 UDP Socket: {}", socket.local_addr()?);
    
    // === 执行握手，获取会话密钥 ===
    let session_key = perform_handshake(&socket, &server_addr, format!("client_{}", tun_ip), tun_ip.clone()).await?;
    
    // === 使用会话密钥初始化加密模块 ===
    let cipher = Arc::new(Cipher::new(&session_key)?);
    println!("🔐 加密通道已建立");

    // === 2. 创建 TUN 设备 ===
    let dev = local_tun::create_device(&tun_ip, tun_mask)?;
    let dev_name = dev.get_ref().name()?; 
    
    // === 路由配置 (容错处理) ===
    match local_tun::configure_route(&dev_name, target_cidr) {
        Ok(_) => {
            if full_tunnel {
                println!("✅ 默认路由已设置（所有流量走VPN）");
                println!("   ⚠️  注意：这会中断当前网络连接！按 Ctrl+C 退出时会自动恢复");
            } else {
                println!("✅ 路由配置成功");
            }
        }
        Err(e) => eprintln!("⚠️ 路由配置警告 (本地多开时可忽略): {}", e),
    }
    
    println!("🚀 TUN 设备 {} 就绪", dev_name);

    // === Socket 已在握手前创建，这里转为 Arc ===
    let socket = Arc::new(socket);

    // === 4. 分离资源 ===
    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);
    
    let socket_uplink = socket.clone();
    let socket_downlink = socket.clone();

    let cipher_uplink = cipher.clone();
    let cipher_downlink = cipher.clone();
    
    // 克隆 server_addr 用于 uplink task
    let server_addr_uplink = server_addr.clone();

    // === 5. 上行任务 (TUN -> Encrypt -> UDP) ===
    let uplink_task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        println!("⬆️ 上行任务启动...");
        
        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("❌ TUN 读取错误: {}", e);
                    break;
                }
            };
            if n == 0 { break; }

            // 过滤坏包
            if n <= TUN_READ_OFFSET { 
                continue; 
            }
            
            // 提取纯 IP 数据
            let ip_packet = &buf[TUN_READ_OFFSET..n];
            
            // 打印 IP 包信息（仅 ICMP）
            if ip_packet.len() >= 20 {
                let proto = ip_packet[9];
                if proto == 1 { // ICMP
                    let src = format!("{}.{}.{}.{}", ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
                    let dst = format!("{}.{}.{}.{}", ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
                    println!("📮 [发送] {} -> {} (ICMP)", src, dst);
                }
            }

            // 加密
            let encrypted_packet = match cipher_uplink.encrypt(ip_packet) {
                Ok(data) => data,
                Err(e) => { eprintln!("❌ 加密失败: {}", e); continue; }
            };

            // 发送给 Server
            if let Err(e) = socket_uplink.send_to(&encrypted_packet, &server_addr_uplink).await {
                eprintln!("❌ UDP 发送错误: {}", e);
            }
        }
    });

    // === 6. 下行任务 (UDP -> Decrypt -> TUN) ===
    let downlink_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048]; 
        println!("⬇️ 下行任务启动...");

        loop {
            let (n, src_addr) = match socket_downlink.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(_) => break,
            };
            
            println!("📦 收到 UDP 包: {} 字节，来自 {}", n, src_addr);

            // 解密
            let decrypted_ip_packet = match cipher_downlink.decrypt(&buf[..n]) {
                Ok(data) => data,
                Err(e) => { 
                    eprintln!("❌ 解密失败: {}", e); 
                    continue; 
                }
            };

            // === 日志: 打印 ICMP 信息 ===
            if decrypted_ip_packet.len() >= 20 {
                let p = &decrypted_ip_packet;
                let proto = p[9]; 
                
                // 仅打印 ICMP (Ping) 包
                if proto == 1 {
                    let src = format!("{}.{}.{}.{}", p[12], p[13], p[14], p[15]);
                    let dst = format!("{}.{}.{}.{}", p[16], p[17], p[18], p[19]);
                    println!("📨 [收到] {} -> {} (ICMP)", src, dst);
                }
            }

            // 适配 macOS/Linux 头部差异
            #[cfg(target_os = "macos")]
            let data_to_write = {
                // macOS utun 需要 4 字节协议头
                // AF_INET (2) 的网络字节序 (大端)
                let mut out = Vec::with_capacity(4 + decrypted_ip_packet.len());
                out.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // AF_INET = 2
                out.extend_from_slice(&decrypted_ip_packet);
                out
            };

            #[cfg(target_os = "linux")]
            let data_to_write = decrypted_ip_packet;

            // 写入 TUN
            if let Err(e) = tun_writer.write_all(&data_to_write).await {
                eprintln!("❌ TUN 写入错误: {}", e);
                break;
            }
        }
    });

    let _ = tokio::join!(uplink_task, downlink_task);
    Ok(())
}