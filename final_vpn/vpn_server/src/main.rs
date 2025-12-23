// vpn_server/src/main.rs

use tokio::net::UdpSocket;
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex; // 用于多线程/异步任务间共享 Map
use anyhow::Result;

// 引入核心库
use vpn_core::symmetric::Cipher;

// 硬编码密钥 (需与 Client 一致)
const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
// 监听端口
const LISTEN_ADDR: &str = "0.0.0.0:9000";

/// 定义 PeerMap: 记录 虚拟IP (10.0.0.x) -> 真实 UDP 地址 的映射
type PeerMap = Arc<Mutex<HashMap<Ipv4Addr, SocketAddr>>>;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 初始化
    println!("🚀 VPN Server 启动中...");
    let socket = UdpSocket::bind(LISTEN_ADDR).await?;
    println!("📡 正在监听 UDP: {}", socket.local_addr()?);
    
    // 用 Arc 包裹 Socket 和 Cipher 以便在闭包中使用（虽然目前是单循环，但养成好习惯）
    let socket = Arc::new(socket);
    let cipher = Arc::new(Cipher::new(KEY)?);
    
    // 初始化空的 Peer 表
    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));

    let mut buf = [0u8; 4096]; // 接收缓冲区

    loop {
        // 2. 接收 UDP 数据
        // recv_from 返回 (字节数, 来源地址)
        let (len, src_addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("接收错误: {}", e);
                continue;
            }
        };

        let encrypted_data = &buf[..len];

        // 3. 解密
        // 只有解密成功，我们才认为这是一个合法的 VPN 包
        let ip_packet = match cipher.decrypt(encrypted_data) {
            Ok(data) => data,
            Err(_) => {
                // 解密失败通常意味着干扰流量或错误密钥，静默丢弃或打印日志
                // eprintln!("来自 {} 的数据解密失败", src_addr);
                continue;
            }
        };

        // 4. 解析 IP 头 (获取源 IP 和 目的 IP)
        // 这是一个纯粹的字节操作，不需要复杂的库
        let (src_ip, dst_ip) = match parse_ipv4_header(&ip_packet) {
            Ok(ips) => ips,
            Err(e) => {
                eprintln!("无效的 IP 包: {}", e);
                continue;
            }
        };

        // 5. 【核心逻辑】: 学习与更新路由表
        // 只要能解密且 IP 格式正确，就认为这个物理地址属于这个虚拟 IP
        {
            let mut map = peers.lock().await;
            // 如果是新客户端，或者地址变了，打印一下
            if map.get(&src_ip) != Some(&src_addr) {
                println!("🔗 客户端上线/更新: {} -> {}", src_ip, src_addr);
                map.insert(src_ip, src_addr);
            }
        }

        // 6. 转发逻辑
        let target_peer = {
            let map = peers.lock().await;
            map.get(&dst_ip).cloned()
        };

        // ❌ 之前写错了: match target_addr
        // ✅ 改成这样:
        match target_peer {
            Some(addr) => {
                // 目标在线 -> 转发
                match cipher.encrypt(&ip_packet) {
                    Ok(new_packet) => {
                        socket.send_to(&new_packet, addr).await?;
                        println!("🔁 转发: {} -> {}", src_ip, dst_ip);
                    }
                    Err(e) => eprintln!("加密转发失败: {}", e),
                }
            }
            None => {
                // 目标不在表里
                println!("🚫 丢弃: {} -> {} (目标未上线)", src_ip, dst_ip);
            }
        }

    }
}

/// 简单的 IPv4 头解析器
/// 只需要提取 Source IP (Byte 12-15) 和 Dest IP (Byte 16-19)
fn parse_ipv4_header(data: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr), &'static str> {
    // IPv4 头最小 20 字节
    if data.len() < 20 {
        return Err("数据包太短");
    }

    // 检查版本号 (Byte 0 的高 4 位)
    if data[0] >> 4 != 4 {
        return Err("不是 IPv4 包");
    }

    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    Ok((src, dst))
}