// vpn_server/src/main.rs

use tokio::net::UdpSocket;
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex; // 用于多线程/异步任务间共享 Map
use anyhow::Result;

// 引入核心库
use vpn_core::symmetric::Cipher;
use vpn_core::handshake::{ServerHandshake, HandshakeMessage, serialize_message, deserialize_message};
use vpn_core::asymmetric::{ServerIdentity, get_keys_dir};

// 预共享密钥 (PSK) - 需与客户端一致
const PSK: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
// 监听端口
const LISTEN_ADDR: &str = "0.0.0.0:9000";

/// 定义 PeerMap: 记录 虚拟IP (10.0.0.x) -> 真实 UDP 地址 的映射
type PeerMap = Arc<Mutex<HashMap<Ipv4Addr, SocketAddr>>>;

/// 会话信息：记录每个客户端的会话密钥和状态
struct Session {
    session_key: [u8; 32],
    #[allow(dead_code)]
    peer_addr: SocketAddr,
}

/// 会话表：UDP地址 -> Session
type SessionMap = Arc<Mutex<HashMap<SocketAddr, Session>>>;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 初始化
    println!("🚀 VPN Server 启动中...");
    
    // 加载或生成服务端密钥对
    let keys_dir = get_keys_dir()?;
    let server_identity = ServerIdentity::load_or_generate(&keys_dir)?;
    server_identity.print_public_key();
    let server_identity = Arc::new(server_identity);
    
    let socket = UdpSocket::bind(LISTEN_ADDR).await?;
    println!("📡 正在监听 UDP: {}", socket.local_addr()?);
    
    let socket = Arc::new(socket);
    
    // 初始化空的 Peer 表和会话表
    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    let mut buf = [0u8; 4096]; // 接收缓冲区

    loop {
        // 2. 接收 UDP 数据
        let (len, src_addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("接收错误: {}", e);
                continue;
            }
        };

        let raw_data = &buf[..len];
        
        // 3. 尝试识别是握手消息还是数据包
        // 握手消息可以通过 bincode 反序列化成 HandshakeMessage
        if let Ok(handshake_msg) = deserialize_message(raw_data) {
            // 这是握手消息
            handle_handshake(
                &socket,
                src_addr,
                handshake_msg,
                &sessions,
                &peers,
                &server_identity,
            ).await;
            continue;
        }
        
        // 4. 否则，这是加密的数据包
        handle_data_packet(
            &socket,
            src_addr,
            raw_data,
            &peers,
            &sessions,
        ).await;
    }
}

/// 处理握手消息
async fn handle_handshake(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    msg: HandshakeMessage,
    sessions: &SessionMap,
    peers: &PeerMap,
    server_identity: &ServerIdentity,
) {
    match msg {
        HandshakeMessage::ClientHello { client_pubkey, client_mlkem_pk, client_id, virtual_ip } => {
            println!("🤝 收到握手请求: {} ({}) IP: {}", client_id, client_addr, virtual_ip);
            
            // 创建服务端握手实例
            let server_handshake = ServerHandshake::new(PSK);
            
            // 生成 ServerHello（使用ML-KEM封装，返回密文和共享密钥）
            let (mut server_hello, mlkem_shared) = match server_handshake.process_client_hello(client_pubkey, &client_mlkem_pk) {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("❌ ML-KEM封装失败: {}", e);
                    return;
                }
            };
            
            // 对握手消息签名：签名内容 = server_pubkey || client_pubkey
            if let HandshakeMessage::ServerHello { server_pubkey, ref mut signature, .. } = server_hello {
                let message_to_sign = [
                    &server_pubkey[..],
                    &client_pubkey[..],
                ].concat();
                
                *signature = server_identity.sign(&message_to_sign);
                println!("   ✍️  已对握手消息签名");
            }
            
            // 计算会话密钥（混合：X25519 + ML-KEM，消耗 server_handshake）
            let session_key = match server_handshake.compute_session_key(client_pubkey, &mlkem_shared) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("❌ 密钥计算失败: {}", e);
                    return;
                }
            };
            println!("   🔑 会话密钥协商成功（X25519 + ML-KEM-768）");
            
            // 保存会话
            {
                let mut map = sessions.lock().await;
                map.insert(client_addr, Session {
                    session_key,
                    peer_addr: client_addr,
                });
            }
            
            // 立即建立路由映射（解析虚拟 IP）
            if let Ok(vip) = virtual_ip.parse::<Ipv4Addr>() {
                let mut peer_map = peers.lock().await;
                peer_map.insert(vip, client_addr);
                println!("   🗺️  路由映射: {} -> {}", vip, client_addr);
            }
            
            // 发送 ServerHello
            if let Ok(response) = serialize_message(&server_hello) {
                if let Err(e) = socket.send_to(&response, client_addr).await {
                    eprintln!("发送 ServerHello 失败: {}", e);
                } else {
                    println!("   ✅ 握手完成，会话已建立");
                }
            }
        }
        _ => {
            // 其他握手消息类型（ClientFinish等）暂不实现
        }
    }
}

/// 处理加密数据包
async fn handle_data_packet(
    socket: &UdpSocket,
    src_addr: SocketAddr,
    encrypted_data: &[u8],
    peers: &PeerMap,
    sessions: &SessionMap,
) {
    // 1. 查找会话
    let session_key = {
        let map = sessions.lock().await;
        match map.get(&src_addr) {
            Some(session) => session.session_key,
            None => {
                // 未握手的客户端，静默丢弃
                return;
            }
        }
    };
    
    // 2. 解密
    let cipher = match Cipher::new(&session_key) {
        Ok(c) => c,
        Err(_) => return,
    };
    
    let ip_packet = match cipher.decrypt(encrypted_data) {
        Ok(data) => data,
        Err(_) => {
            // 解密失败，可能是错误的数据
            return;
        }
    };

    // 3. 解析 IP 头
    let (src_ip, dst_ip) = match parse_ipv4_header(&ip_packet) {
        Ok(ips) => ips,
        Err(_) => return,
    };

    // 4. 更新路由表
    {
        let mut map = peers.lock().await;
        if map.get(&src_ip) != Some(&src_addr) {
            println!("🔗 客户端上线/更新: {} -> {}", src_ip, src_addr);
            map.insert(src_ip, src_addr);
        }
    }

    // 5. 转发逻辑
    let target_peer = {
        let map = peers.lock().await;
        map.get(&dst_ip).cloned()
    };

    match target_peer {
        Some(target_addr) => {
            // 查找目标的会话密钥
            let target_session_key = {
                let map = sessions.lock().await;
                match map.get(&target_addr) {
                    Some(s) => s.session_key,
                    None => return, // 目标未握手
                }
            };
            
            // 用目标的会话密钥重新加密
            let target_cipher = match Cipher::new(&target_session_key) {
                Ok(c) => c,
                Err(_) => return,
            };
            
            match target_cipher.encrypt(&ip_packet) {
                Ok(new_packet) => {
                    let _ = socket.send_to(&new_packet, target_addr).await;
                    println!("🔁 转发: {} -> {}", src_ip, dst_ip);
                }
                Err(e) => eprintln!("加密转发失败: {}", e),
            }
        }
        None => {
            println!("🚫 丢弃: {} -> {} (目标未上线)", src_ip, dst_ip);
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