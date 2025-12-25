// vpn_server/src/main.rs

use tokio::net::UdpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex; // 用于多线程/异步任务间共享 Map
use anyhow::Result;
use tun::Device; // 导入 Device trait

// 引入核心库
use vpn_core::symmetric::Cipher;
use vpn_core::handshake::{ServerHandshake, HandshakeMessage, serialize_message, deserialize_message};
use vpn_core::asymmetric::{ServerIdentity, get_keys_dir};
use vpn_core::local_tun;
use vpn_core::gateway;

// 预共享密钥 (PSK) - 需与客户端一致
const PSK: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
// 监听端口
const LISTEN_ADDR: &str = "0.0.0.0:9000";
// 服务端TUN设备配置
const SERVER_TUN_IP: &str = "10.0.0.1";
const SERVER_TUN_MASK: &str = "255.255.255.0";

#[cfg(target_os = "macos")]
const TUN_READ_OFFSET: usize = 4;

#[cfg(target_os = "linux")]
const TUN_READ_OFFSET: usize = 0;

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
    println!("⚠️  注意：网关模式需要 sudo 权限！");
    
    // 检测参数：是否启用网关模式
    let args: Vec<String> = std::env::args().collect();
    let enable_gateway = args.contains(&"--gateway".to_string());
    
    if enable_gateway {
        println!("🌐 启用网关模式（NAT转发到互联网）");
    } else {
        println!("🔗 点对点模式（仅客户端间互联）");
        println!("   提示：使用 --gateway 参数启用互联网转发");
    }
    
    // 加载或生成服务端密钥对
    let keys_dir = get_keys_dir()?;
    let server_identity = ServerIdentity::load_or_generate(&keys_dir)?;
    server_identity.print_public_key();
    let server_identity = Arc::new(server_identity);
    
    // 创建 TUN 设备
    let tun_dev = local_tun::create_device(SERVER_TUN_IP, SERVER_TUN_MASK)?;
    let tun_name = tun_dev.get_ref().name()?;
    println!("✅ TUN 设备创建成功: {}", tun_name);
    
    // 配置路由
    match local_tun::configure_route(&tun_name, "10.0.0.0/24") {
        Ok(_) => println!("✅ 路由配置成功"),
        Err(e) => println!("⚠️  路由配置警告: {}", e),
    }
    
    // 如果启用网关模式，配置IP转发和NAT
    if enable_gateway {
        println!("\n🔧 配置网关功能...");
        
        // 启用IP转发
        if let Err(e) = gateway::enable_ip_forwarding() {
            eprintln!("❌ 启用IP转发失败: {}", e);
            eprintln!("   请使用 sudo 运行服务端");
            return Err(anyhow::anyhow!("IP转发失败"));
        }
        
        // 检测外网接口
        let external_if = match gateway::detect_default_interface() {
            Ok(iface) => {
                println!("   🔍 检测到外网接口: {}", iface);
                iface
            }
            Err(e) => {
                eprintln!("⚠️  无法自动检测外网接口: {}", e);
                println!("   请手动指定外网接口（如 eth0, en0, wlan0）");
                return Err(anyhow::anyhow!("无法检测外网接口"));
            }
        };
        
        // 配置NAT
        if let Err(e) = gateway::setup_nat(&tun_name, &external_if) {
            eprintln!("⚠️  NAT配置失败: {}", e);
            #[cfg(target_os = "macos")]
            println!("   macOS 用户需要手动配置 pfctl（参考上方提示）");
        }
        
        println!("✅ 网关配置完成\n");
    }
    
    let socket = UdpSocket::bind(LISTEN_ADDR).await?;
    println!("📡 正在监听 UDP: {}", socket.local_addr()?);
    
    let socket = Arc::new(socket);
    
    // 初始化空的 Peer 表和会话表
    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    // 分离 TUN 设备读写
    let (mut tun_reader, tun_writer) = tokio::io::split(tun_dev);
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    // 启动 TUN -> UDP 任务（从TUN读取，发送到客户端）
    let socket_tun_to_udp = socket.clone();
    let peers_tun_to_udp = peers.clone();
    let sessions_tun_to_udp = sessions.clone();
    
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        println!("⬆️  TUN->UDP 任务启动");
        
        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("TUN 读取错误: {}", e);
                    break;
                }
            };
            
            if n <= TUN_READ_OFFSET {
                continue;
            }
            
            let ip_packet = &buf[TUN_READ_OFFSET..n];
            
            // 解析目标IP
            if ip_packet.len() < 20 {
                continue;
            }
            
            let dst_ip = Ipv4Addr::new(
                ip_packet[16],
                ip_packet[17],
                ip_packet[18],
                ip_packet[19],
            );
            
            // 查找目标客户端
            let target_addr = {
                let map = peers_tun_to_udp.lock().await;
                map.get(&dst_ip).cloned()
            };
            
            if let Some(addr) = target_addr {
                // 获取目标的会话密钥
                let session_key = {
                    let map = sessions_tun_to_udp.lock().await;
                    match map.get(&addr) {
                        Some(s) => s.session_key,
                        None => continue,
                    }
                };
                
                // 加密并发送
                if let Ok(cipher) = Cipher::new(&session_key) {
                    if let Ok(encrypted) = cipher.encrypt(ip_packet) {
                        let _ = socket_tun_to_udp.send_to(&encrypted, addr).await;
                        println!("🔁 [TUN->客户端] {} ({} 字节)", dst_ip, n);
                    }
                }
            }
        }
    });

    // UDP 接收循环
    let mut buf = [0u8; 4096];

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
            &tun_writer,
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
    tun_writer: &Arc<Mutex<tokio::io::WriteHalf<tun::AsyncDevice>>>,
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

    // 5. 转发逻辑：优先客户端互联，其次转发到TUN（网关模式）
    let target_peer = {
        let map = peers.lock().await;
        map.get(&dst_ip).cloned()
    };

    match target_peer {
        Some(target_addr) => {
            // 目标是另一个客户端，直接转发
            let target_session_key = {
                let map = sessions.lock().await;
                match map.get(&target_addr) {
                    Some(s) => s.session_key,
                    None => return,
                }
            };
            
            let target_cipher = match Cipher::new(&target_session_key) {
                Ok(c) => c,
                Err(_) => return,
            };
            
            match target_cipher.encrypt(&ip_packet) {
                Ok(new_packet) => {
                    let _ = socket.send_to(&new_packet, target_addr).await;
                    println!("🔁 [客户端互联] {} -> {}", src_ip, dst_ip);
                }
                Err(e) => eprintln!("加密转发失败: {}", e),
            }
        }
        None => {
            // 目标不是客户端，尝试转发到TUN（互联网）
            // 检查目标IP是否是本地VPN网段
            if dst_ip.octets()[0] == 10 && dst_ip.octets()[1] == 0 && dst_ip.octets()[2] == 0 {
                // 仍然是10.0.0.x，但客户端不在线，丢弃
                println!("🚫 丢弃: {} -> {} (目标不在线)", src_ip, dst_ip);
            } else {
                // 目标是外网IP，写入TUN设备
                #[cfg(target_os = "macos")]
                let data_to_write = {
                    let mut out = Vec::with_capacity(4 + ip_packet.len());
                    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
                    out.extend_from_slice(&ip_packet);
                    out
                };
                
                #[cfg(target_os = "linux")]
                let data_to_write = ip_packet.clone();
                
                let mut writer = tun_writer.lock().await;
                if let Err(e) = writer.write_all(&data_to_write).await {
                    eprintln!("TUN 写入失败: {}", e);
                } else {
                    println!("🌐 [转发到互联网] {} -> {}", src_ip, dst_ip);
                }
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