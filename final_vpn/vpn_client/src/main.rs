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

// 2. 定义一个硬编码的密钥 (32字节)
// 注意：服务端必须使用完全相同的密钥！
const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef"; 

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // === 1. 获取命令行参数 (动态 IP) ===
    let args: Vec<String> = env::args().collect();
    
    // 如果没有参数，默认用 10.0.0.1
    // 运行方式: ./target/debug/vpn_client 10.0.0.2
    let tun_ip = if args.len() > 1 { &args[1] } else { "10.0.0.1" };
    
    println!("🛡️ VPN Client Starting...");
    println!("📍 配置 IP: {}", tun_ip);
    
    // === 配置 ===
    let tun_mask = "255.255.255.0";
    let target_cidr = "10.0.0.0/24"; 
    let server_addr = "127.0.0.1:9000"; 

    // === 初始化加密模块 ===
    let cipher = Arc::new(Cipher::new(KEY)?);

    // === 2. 创建 TUN 设备 ===
    let dev = local_tun::create_device(tun_ip, tun_mask)?;
    let dev_name = dev.get_ref().name()?; 
    
    // === 路由配置 (容错处理) ===
    // 在本地双开测试时，第二个客户端配置路由可能会冲突，我们允许它失败并继续
    match local_tun::configure_route(&dev_name, target_cidr) {
        Ok(_) => println!("✅ 路由配置成功"),
        Err(e) => eprintln!("⚠️ 路由配置警告 (本地多开时可忽略): {}", e),
    }
    
    println!("🚀 TUN 设备 {} 就绪", dev_name);

    // === 3. 创建 UDP Socket ===
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    println!("UDP Socket 绑定成功: {}", socket.local_addr()?);
    let socket = Arc::new(socket);

    // === 4. 分离资源 ===
    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);
    
    let socket_uplink = socket.clone();
    let socket_downlink = socket.clone();

    let cipher_uplink = cipher.clone();
    let cipher_downlink = cipher.clone();

    // === 5. 上行任务 (TUN -> Encrypt -> UDP) ===
    let uplink_task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        println!("⬆️ 上行任务启动...");
        
        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 { break; }

            // 过滤坏包
            if n <= TUN_READ_OFFSET { continue; }
            
            // 提取纯 IP 数据
            let ip_packet = &buf[TUN_READ_OFFSET..n];

            // 加密
            let encrypted_packet = match cipher_uplink.encrypt(ip_packet) {
                Ok(data) => data,
                Err(e) => { eprintln!("加密失败: {}", e); continue; }
            };

            // 发送给 Server
            if let Err(e) = socket_uplink.send_to(&encrypted_packet, server_addr).await {
                eprintln!("UDP Send Error: {}", e);
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
            
            // 简单验证来源 (生产环境可以去掉或加强验证)
            if src_addr.to_string() != server_addr { 
                // eprintln!("收到非 Server 数据: {}", src_addr);
                continue; 
            }

            // 解密
            let decrypted_ip_packet = match cipher_downlink.decrypt(&buf[..n]) {
                Ok(data) => data,
                Err(e) => { eprintln!("解密失败: {}", e); continue; }
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
                let mut out = Vec::with_capacity(4 + decrypted_ip_packet.len());
                out.extend_from_slice(&[0, 0, 0, 2]); 
                out.extend_from_slice(&decrypted_ip_packet);
                out
            };

            #[cfg(target_os = "linux")]
            let data_to_write = decrypted_ip_packet;

            // 写入 TUN
            if let Err(e) = tun_writer.write_all(&data_to_write).await {
                eprintln!("TUN Write Error: {}", e);
                break;
            }
        }
    });

    let _ = tokio::join!(uplink_task, downlink_task);
    Ok(())
}